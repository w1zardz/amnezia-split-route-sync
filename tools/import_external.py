#!/usr/bin/env python3
"""Импорт внешних списков российских сетей как кандидатов — с проверкой по IP→ASN.

Публичных репозиториев с «российскими IP» много, но брать их содержимое как есть
нельзя: в белом списке мобильных операторов больше половины записей — зарубежные
сети, а один такой CIDR в direct уводит чужой трафик мимо VPN с домашнего адреса,
причём молча. Поэтому чужие данные попадают сюда только как кандидаты.

Механика:
  1. качаем таблицу IP→ASN+страна (iptoasn.com, один файл, без ключей и лимитов);
  2. качаем источники из config/external-sources.json;
  3. каждую сеть проверяем: весь диапазон в одном ASN, ASN не из deny-листа глобальных
     CDN, страна RU — и главное, ASN уже известен по data/prefixes.json или
     config/asn-expand.json;
  4. принятые сети пишем в data/external.json, всё отсеянное — в отчёт.

Пункт 3 и есть смысл всей затеи: внешние списки углубляют покрытие сервисов,
которые мы уже ведём (ловят префиксы, которых сейчас нет в DNS), но не приносят
адресное пространство региональных провайдеров — иначе мимо VPN уехал бы весь
Ростелеком, ровно как при развороте ASN операторов связи.

Новые поддомены сервисов ручного каталога дополняют полный список. Остальные
домены сохраняются с источниками в отчёт кандидатов для ручной проверки.
"""

from __future__ import annotations

import argparse
import bisect
import concurrent.futures
import gzip
import io
import ipaddress
import json
import sys
from datetime import date
from pathlib import Path

import catalog

ROOT = catalog.ROOT
SOURCES_FILE = ROOT / "config" / "external-sources.json"
ASN_EXPAND_FILE = ROOT / "config" / "asn-expand.json"
REPORT_FILE = ROOT / "data" / "external-report.md"
CANDIDATES_FILE = ROOT / "data" / "external-candidates.json"
MAX_SOURCE_BYTES = 8_388_608
MAX_TABLE_BYTES = 33_554_432
MAX_TABLE_UNPACKED_BYTES = 134_217_728
DOWNLOAD_WORKERS = 4
# Amnezia начинает подтормаживать на нескольких тысячах записей, а внешних
# кандидатов приходит больше, чем нужно: держим потолок и пишем в отчёт, что
# именно не влезло.
DEFAULT_LIMIT = 1600
REPORT_ASN_LIMIT = 40
REPORT_DOMAIN_LIMIT = 200
# Граница между контентной площадкой и оператором связи, проведённая по размеру
# анонсируемого пространства. Замер по таблице: контентные ASN каталога держат
# от 256 адресов (Сбербанк-АСТ) до 219 648 (Yandex.Cloud), операторы начинаются
# с 280 576 (Selectel) и доходят до 9 169 152 у Ростелекома. Брать адреса
# операторов во внешний слой нельзя по той же причине, по которой их ASN никогда
# не разворачиваются целиком: мимо VPN уехала бы половина Ростелекома.
MAX_ASN_ADDRESSES = 262_144
# Одна запись из чужого списка не должна превращаться в сеть шире /16.
WIDEN_FLOOR = 16


class ImportError_(RuntimeError):
    pass


class AsnTable:
    """IP→(ASN, страна, имя AS) по диапазонам из ip2asn-v4."""

    __slots__ = ("_starts", "_rows", "announced")

    def __init__(self, rows: list[tuple[int, int, int, str, str]]) -> None:
        ordered = sorted(rows)
        self._starts = [row[0] for row in ordered]
        self._rows = ordered
        # Сколько адресов анонсирует каждый ASN — по этому размеру отличаем
        # контентную площадку от оператора связи.
        self.announced: dict[int, int] = {}
        for start, end, asn, _country, _name in ordered:
            self.announced[asn] = self.announced.get(asn, 0) + (end - start + 1)
        if any(left[1] >= right[0] for left, right in zip(ordered, ordered[1:])):
            raise ImportError_("таблица IP→ASN содержит перекрывающиеся диапазоны")

    def __len__(self) -> int:
        return len(self._rows)

    @classmethod
    def from_tsv(cls, text: str) -> "AsnTable":
        rows: list[tuple[int, int, int, str, str]] = []
        for line in text.splitlines():
            fields = line.split("\t")
            if len(fields) < 5:
                continue
            try:
                start = int(ipaddress.IPv4Address(fields[0]))
                end = int(ipaddress.IPv4Address(fields[1]))
            except (ipaddress.AddressValueError, ValueError):
                continue
            if end < start or not fields[2].isdigit():
                continue
            rows.append((start, end, int(fields[2]), fields[3].strip(), fields[4].strip()))
        if len(rows) < 100_000:
            raise ImportError_(f"таблица IP→ASN подозрительно мала: {len(rows)} строк")
        return cls(rows)

    def lookup(self, address: int) -> tuple[int, int, int, str, str] | None:
        """(начало диапазона, конец, ASN, страна, имя AS) для адреса."""
        index = bisect.bisect_right(self._starts, address) - 1
        if index < 0:
            return None
        row = self._rows[index]
        if not row[0] <= address <= row[1] or row[2] == 0:
            return None
        return row

    def covering_rows(self, network: ipaddress.IPv4Network) -> list[tuple]:
        """Все диапазоны сети; пустой результат при любом пробеле в таблице."""
        cursor, end = int(network.network_address), int(network.broadcast_address)
        index = bisect.bisect_right(self._starts, cursor) - 1
        rows = []
        while cursor <= end:
            if index < 0 or index >= len(self._rows):
                return []
            row = self._rows[index]
            if not row[0] <= cursor <= row[1] or row[2] == 0:
                return []
            rows.append(row)
            cursor = row[1] + 1
            index += 1
        return rows


class NetworkIndex:
    """Проверка покрытия за O(log N) вместо перебора всех сетей снапшота."""

    def __init__(self, networks) -> None:
        self.ranges = [
            (int(net.network_address), int(net.broadcast_address))
            for net in ipaddress.collapse_addresses(networks)
        ]
        self.starts = [start for start, _end in self.ranges]

    def contains(self, network: ipaddress.IPv4Network) -> bool:
        index = bisect.bisect_right(self.starts, int(network.network_address)) - 1
        return index >= 0 and int(network.broadcast_address) <= self.ranges[index][1]


def covering_prefix(row: tuple[int, int, int, str, str], address: int) -> ipaddress.IPv4Network:
    """CIDR внутри диапазона IP→ASN; диапазон может объединять несколько BGP-анонсов."""
    start, end = row[0], row[1]
    host = ipaddress.IPv4Address(address)
    for length in range(WIDEN_FLOOR, catalog.MAX_PREFIXLEN + 1):
        network = ipaddress.ip_network(f"{host}/{length}", strict=False)
        if start <= int(network.network_address) and int(network.broadcast_address) <= end:
            return network
    return ipaddress.ip_network(f"{host}/{catalog.MAX_PREFIXLEN}", strict=False)


def load_sources() -> tuple[str, list[dict[str, str]]]:
    if not SOURCES_FILE.exists():
        raise ImportError_(f"нет {SOURCES_FILE.relative_to(ROOT)}")
    document = json.loads(SOURCES_FILE.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("version") != 1:
        raise ImportError_("config/external-sources.json: ожидается объект с version=1")
    table = document.get("asn_table")
    if not isinstance(table, dict) or not isinstance(table.get("url"), str):
        raise ImportError_("config/external-sources.json: нет asn_table.url")
    entries = document.get("sources")
    if not isinstance(entries, list) or not entries:
        raise ImportError_("config/external-sources.json: пустой список sources")
    sources: list[dict[str, str]] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ImportError_("config/external-sources.json: источник должен быть объектом")
        identifier = entry.get("id")
        url = entry.get("url")
        kind = entry.get("kind")
        if not isinstance(identifier, str) or identifier in seen:
            raise ImportError_(f"config/external-sources.json: некорректный id {identifier!r}")
        seen.add(identifier)
        if not isinstance(url, str) or not url.startswith("https://"):
            raise ImportError_(f"{identifier}: url должен быть https")
        if kind not in ("cidr", "domains", "amnezia"):
            raise ImportError_(f"{identifier}: kind должен быть cidr, domains или amnezia")
        if entry.get("enabled") is False:
            continue
        sources.append({"id": identifier, "url": url, "kind": kind, "note": entry.get("note", "")})
    if not sources:
        raise ImportError_("все источники отключены")
    return table["url"], sources


def known_asns() -> tuple[dict[int, int], set[int]]:
    """ASN, которые мы уже считаем своими: вес — сколько префиксов в снапшоте."""
    weight: dict[int, int] = {}
    for meta in catalog.load_prefixes().values():
        if meta.get("source") == "external":
            continue  # прошлый импорт не может сам себе выдавать доверие
        asn = meta.get("asn")
        if isinstance(asn, int):
            weight[asn] = weight.get(asn, 0) + 1
    expand: set[int] = set()
    if ASN_EXPAND_FILE.exists():
        document = json.loads(ASN_EXPAND_FILE.read_text(encoding="utf-8"))
        entries = document.get("asn", {}) if isinstance(document, dict) else {}
        expand = {int(key) for key in entries if str(key).isdigit()}
    for asn in expand:
        weight.setdefault(asn, 0)
    return weight, expand


def parse_networks(text: str) -> list[ipaddress.IPv4Network]:
    networks = []
    for line in text.splitlines():
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if network.version == 4:
            networks.append(network)
    return networks


def parse_domains(text: str) -> list[str]:
    domains = []
    for line in text.splitlines():
        value = line.split("#", 1)[0].strip()
        for prefix in ("domain:", "full:", "*."):
            if value.startswith(prefix):
                value = value[len(prefix):]
        if not value:
            continue
        try:
            domain = catalog.normalize_hostname(value, "внешний источник")
            if domain.endswith((".arpa", ".local", ".localhost", ".lan", ".internal", ".home", ".invalid", ".test", ".example")):
                continue
            domains.append(domain)
        except catalog.CatalogError:
            continue
    return domains


def parse_source(text: str, kind: str) -> tuple[list, list[str]]:
    if kind == "cidr":
        return parse_networks(text), []
    if kind == "domains":
        return [], parse_domains(text)
    document = json.loads(text)
    if not isinstance(document, list):
        raise ImportError_("Amnezia: ожидается JSON-массив")
    domains, networks = [], []
    for entry in document:
        if not isinstance(entry, dict) or not isinstance(entry.get("hostname"), str):
            raise ImportError_("Amnezia: запись должна содержать hostname")
        hostname = entry["hostname"]
        nets = parse_networks(hostname)
        if nets:
            networks.extend(nets)
        else:
            domains.extend(parse_domains(hostname))
        ips = entry.get("ips", [])
        if not isinstance(ips, list) or not all(isinstance(ip, str) for ip in ips):
            raise ImportError_("Amnezia: ips должен быть списком строк")
        single = entry.get("ip", "")
        if not isinstance(single, str):
            raise ImportError_("Amnezia: ip должен быть строкой")
        for value in [single, *ips]:
            networks.extend(parse_networks(value))
    return networks, domains


def download_inputs(table_url: str, sources: list[dict], local_table: Path | None) -> tuple[bytes, dict]:
    """До четырёх HTTPS-запросов одновременно; сбой любого источника останавливает импорт."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as executor:
        table = None if local_table else executor.submit(
            catalog.http_get, table_url, MAX_TABLE_BYTES, 120
        )
        pending = {
            source["id"]: executor.submit(catalog.http_get, source["url"], MAX_SOURCE_BYTES)
            for source in sources
        }
        payload = local_table.read_bytes() if local_table else table.result()
        texts = {key: future.result().decode("utf-8-sig") for key, future in pending.items()}
    if len(payload) > MAX_TABLE_UNPACKED_BYTES:
        raise ImportError_("таблица IP→ASN превышает лимит размера")
    if payload[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(payload)) as stream:
            payload = stream.read(MAX_TABLE_UNPACKED_BYTES + 1)
        if len(payload) > MAX_TABLE_UNPACKED_BYTES:
            raise ImportError_("распакованная таблица IP→ASN превышает лимит размера")
    return payload, texts


def widen_to_minimum(network: ipaddress.IPv4Network) -> ipaddress.IPv4Network:
    """Записи вида /32 расширяем до охватывающей /24: одиночный адрес не переживёт ротацию."""
    if network.prefixlen <= catalog.MAX_PREFIXLEN:
        return network
    return ipaddress.ip_network(
        f"{network.network_address}/{catalog.MAX_PREFIXLEN}", strict=False
    )


ACCEPT = "accept"
UNKNOWN_ASN = "ASN не обслуживает ни один сервис каталога"
NOT_RUSSIAN = "не российская сеть"
OPERATOR_ASN = "адресное пространство оператора связи"


def classify(
    network: ipaddress.IPv4Network,
    table: AsnTable,
    weight: dict[int, int],
    expand: set[int],
) -> tuple[str, tuple[int, int, int, str, str] | None]:
    """Вердикт по сети: ACCEPT либо причина отказа, пригодная как ключ отчёта."""
    if not network.is_global:
        return "не публичная сеть", None
    if network.prefixlen < catalog.MIN_PREFIXLEN:
        return f"шире допустимой /{catalog.MIN_PREFIXLEN}", None
    rows = table.covering_rows(network)
    if not rows:
        return "нет в таблице IP→ASN или сеть не анонсируется", None
    first = rows[0]
    if any(row[2] != first[2] for row in rows):
        return "сеть пересекает разные ASN", None
    asn, country, name = first[2], first[3], first[4]
    if asn in catalog.DENY_ASN:
        return "глобальный CDN или облако", first
    if any(not catalog.is_russian(row[2], row[3], row[4]) for row in rows):
        return NOT_RUSSIAN, first
    if asn not in weight:
        return UNKNOWN_ASN, first
    # Контентные ASN из asn-expand.json прошли ручной отбор — размер им прощаем.
    if asn not in expand and table.announced.get(asn, 0) > MAX_ASN_ADDRESSES:
        return OPERATOR_ASN, first
    return ACCEPT, first


def build_report(
    sources: list[dict[str, str]],
    stats: dict[str, dict[str, int]],
    rejected: dict[str, int],
    unknown_asn: dict[tuple[int, str], int],
    foreign: dict[str, int],
    new_domains: list[str],
    accepted: int,
    dropped_by_limit: int,
    limit: int,
) -> str:
    lines = [
        "# Внешние источники — отчёт импорта",
        "",
        f"Сборка {date.today().isoformat()}. Файл генерируется "
        "`tools/import_external.py`, правки руками бессмысленны.",
        "",
        "## Источники",
        "",
        "| Источник | Уникальных IP/CIDR | Принято IP/CIDR | Домены | Новые поддомены |",
        "|---|---:|---:|---:|---:|",
    ]
    for source in sources:
        entry = stats.get(source["id"], {})
        lines.append(
            f"| `{source['id']}` | {entry.get('networks', 0)} | {entry.get('accepted', 0)} "
            f"| {entry.get('domains', 0)} | {entry.get('accepted_domains', 0)} |"
        )
    lines += [
        "",
        f"После объединения внутри проверенных диапазонов IP→ASN принято сетей: **{accepted}** "
        f"(потолок {limit}).",
        "",
    ]
    if dropped_by_limit:
        lines += [
            f"⚠️ Потолок срезал **{dropped_by_limit}** сетей, прошедших проверку. "
            "Подними `--limit`, если Amnezia переваривает список, или сузь источники.",
            "",
        ]
    lines += [
        "## Почему отсеяно",
        "",
        "| Причина | Сетей |",
        "|---|---|",
    ]
    for reason, count in sorted(rejected.items(), key=lambda item: -item[1]):
        lines.append(f"| {reason} | {count} |")
    if foreign:
        top = sorted(foreign.items(), key=lambda item: -item[1])[:12]
        lines += [
            "",
            "Зарубежные сети по странам: "
            + ", ".join(f"{code} — {count}" for code, count in top)
            + ". Именно ради этих записей и написан фильтр: попади они в direct, "
            "часть трафика ушла бы мимо VPN с домашнего адреса.",
        ]
    lines += [
        "",
        "## Российские ASN, которых нет в каталоге",
        "",
        "Сети этих ASN отклонены, потому что ни один сервис каталога на них не "
        "живёт. Если среди них окажется CDN российского сервиса — его место в "
        "`config/asn-expand.json`, а не здесь. ASN операторов связи не добавляем "
        "никогда: их адресное пространство огромно и в direct не нужно.",
        "",
        "| ASN | Имя | Сетей |",
        "|---|---|---|",
    ]
    for (asn, name), count in sorted(unknown_asn.items(), key=lambda item: -item[1])[
        :REPORT_ASN_LIMIT
    ]:
        lines.append(f"| AS{asn} | {name} | {count} |")
    lines += [
        "",
        f"## Домены вне каталога — {len(new_domains)}",
        "",
        "Новые поддомены сервисов каталога добавлены в полный список автоматически; "
        "их источники указаны в `data/external.json`. Ниже — остальные кандидаты "
        "для ручной проверки. Полный список без обрезки, с происхождением каждой "
        "записи: [`external-candidates.json`](external-candidates.json).",
        "",
    ]
    if new_domains:
        lines.append("```")
        lines.extend(new_domains[:REPORT_DOMAIN_LIMIT])
        if len(new_domains) > REPORT_DOMAIN_LIMIT:
            lines.append(f"… ещё {len(new_domains) - REPORT_DOMAIN_LIMIT}")
        lines.append("```")
    else:
        lines.append("Нет — каталог покрывает все домены источников.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=catalog.EXTERNAL_FILE)
    parser.add_argument("--report", type=Path, default=REPORT_FILE)
    parser.add_argument("--candidates", type=Path, default=CANDIDATES_FILE)
    parser.add_argument("--asn-table", type=Path, help="локальный ip2asn-v4.tsv(.gz) вместо загрузки")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="потолок принятых сетей")
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()

    try:
        if arguments.limit < 1:
            raise ImportError_("--limit должен быть положительным")
        table_url, sources = load_sources()
        weight, expand = known_asns()
        if not weight:
            raise ImportError_("нет data/prefixes.json — сначала запусти tools/refresh_prefixes.py")
        print(f"каталог знает {len(weight)} ASN, из них {len(expand)} разворачиваются целиком")

        payload, texts = download_inputs(table_url, sources, arguments.asn_table)
        table = AsnTable.from_tsv(payload.decode("utf-8"))
        print(f"таблица IP→ASN: {len(table)} диапазонов")

        # Сверяемся только с тем, что снапшот добыл сам: прошлый импорт уже лежит
        # в prefixes.json со source=external, и учитывать его — значит на втором
        # прогоне отбросить собственный результат и потерять все внешние сети.
        existing = NetworkIndex([
            ipaddress.ip_network(value)
            for value, meta in catalog.load_prefixes().items()
            if meta.get("source") != "external"
        ])
        catalog_domains = set(catalog.catalog_domains(catalog.load_catalog()))

        stats: dict[str, dict[str, int]] = {}
        previous_sources = {}
        if arguments.output.exists():
            previous_sources = json.loads(arguments.output.read_text(encoding="utf-8")).get("sources", {})
        rejected: dict[str, int] = {}
        unknown_asn: dict[tuple[int, str], int] = {}
        foreign: dict[str, int] = {}
        candidates: dict[str, dict] = {}
        external_domains: dict[str, set[str]] = {}
        imported_domains: dict[str, dict] = {}
        classified: dict[ipaddress.IPv4Network, tuple] = {}

        for source in sources:
            raw_networks, raw_domains = parse_source(texts[source["id"]], source["kind"])
            networks = sorted(set(raw_networks))
            domains = sorted(set(raw_domains))
            if not networks and not domains:
                raise ImportError_(f"{source['id']}: источник пуст или формат изменился")
            previous = previous_sources.get(source["id"], {})
            if previous.get("url") == source["url"] and len(raw_networks) + len(raw_domains) < previous.get("parsed", 0) * 0.5:
                raise ImportError_(f"{source['id']}: источник потерял больше половины записей")
            accepted_domains = 0
            for domain in domains:
                external_domains.setdefault(domain, set()).add(source["id"])
                parent = catalog.external_domain_parent(domain, catalog_domains)
                if parent:
                    imported_domains.setdefault(domain, {"parent": parent, "sources": []})["sources"].append(source["id"])
                    accepted_domains += 1
            accepted_here = 0
            for network in networks:
                network = widen_to_minimum(network)
                if network not in classified:
                    classified[network] = classify(network, table, weight, expand)
                verdict, record = classified[network]
                if verdict != ACCEPT or record is None:
                    rejected[verdict] = rejected.get(verdict, 0) + 1
                    if record is not None and verdict == UNKNOWN_ASN:
                        key = (record[2], record[4][:60])
                        unknown_asn[key] = unknown_asn.get(key, 0) + 1
                    if record is not None and verdict == NOT_RUSSIAN:
                        code = record[3] or "??"
                        foreign[code] = foreign.get(code, 0) + 1
                    continue
                broader = covering_prefix(record, int(network.network_address))
                # Не теряем хвост исходной сети, пересекающей несколько диапазонов
                # одного ASN: расширять разрешено, сужать принятый CIDR — нет.
                if network.subnet_of(broader):
                    network = broader
                if existing.contains(network):
                    rejected["уже покрыто снапшотом"] = rejected.get("уже покрыто снапшотом", 0) + 1
                    continue
                value = str(network)
                entry = candidates.setdefault(
                    value,
                    {
                        "asn": record[2],
                        "as_name": record[4],
                        "cc": record[3],
                        "sources": [],
                        "source": "external",
                    },
                )
                if source["id"] not in entry["sources"]:
                    entry["sources"].append(source["id"])
                accepted_here += 1
            stats[source["id"]] = {
                "parsed": len(raw_networks) + len(raw_domains),
                "networks": len(networks), "domains": len(domains),
                "accepted": accepted_here, "accepted_domains": accepted_domains,
            }
            print(f"{source['id']}: {len(networks)} IP/CIDR → {accepted_here}, "
                  f"{len(domains)} доменов → {accepted_domains} новых поддоменов")

        if len(imported_domains) > catalog.MAX_EXTERNAL_DOMAINS:
            raise ImportError_(f"новых поддоменов слишком много: {len(imported_domains)}")
        imported_domains = dict(sorted(imported_domains.items()))
        for meta in imported_domains.values():
            meta["sources"] = sorted(meta["sources"])
        print(f"классифицировано {len(classified)} уникальных сетей; "
              f"новых поддоменов {len(imported_domains)}")

        # Ранжируем перед обрезкой: сперва контентные ASN из asn-expand, затем те,
        # за которыми в снапшоте больше префиксов, затем более широкие сети.
        ordered = sorted(
            candidates.items(),
            key=lambda item: (
                0 if item[1]["asn"] in expand else 1,
                -weight.get(item[1]["asn"], 0),
                ipaddress.ip_network(item[0]).prefixlen,
                int(ipaddress.ip_network(item[0]).network_address),
            ),
        )
        dropped_by_limit = max(0, len(ordered) - arguments.limit)
        kept = dict(
            sorted(
                ordered[: arguments.limit],
                key=lambda item: ipaddress.ip_network(item[0]),
            )
        )
        for entry in kept.values():
            entry["sources"] = sorted(entry["sources"])

        total = sum(ipaddress.ip_network(value).num_addresses for value in kept)
        print(
            f"итого принято {len(kept)} сетей, {total} адресов; "
            f"отклонено {sum(rejected.values())}"
            + (f", срезано потолком {dropped_by_limit}" if dropped_by_limit else "")
        )

        new_domains = sorted(set(external_domains) - catalog_domains - set(imported_domains))
        payload_document = {
            "version": 1,
            "updated": date.today().isoformat(),
            "source": "внешние списки, проверенные по таблице IP→ASN",
            "asn_table": table_url,
            "prefix_count": len(kept),
            "rejected_count": sum(rejected.values()),
            "dropped_by_limit": dropped_by_limit,
            "domain_count": len(imported_domains),
            "sources": {
                source["id"]: {"url": source["url"], **stats.get(source["id"], {})}
                for source in sources
            },
            "prefixes": kept,
            "domains": imported_domains,
        }
        report = build_report(
            sources, stats, rejected, unknown_asn, foreign, new_domains,
            len(kept), dropped_by_limit, arguments.limit,
        )

        if arguments.dry_run:
            for reason, count in sorted(rejected.items(), key=lambda item: -item[1])[:10]:
                print(f"  drop {count}: {reason}")
            print(f"  доменов вне каталога: {len(new_domains)}")
            return 0

        catalog.atomic_write(arguments.output, catalog.json_bytes(payload_document))
        catalog.atomic_write(arguments.report, report.encode("utf-8"))
        catalog.atomic_write(arguments.candidates, catalog.json_bytes({
            "version": 1, "updated": date.today().isoformat(),
            "domains": {domain: {"sources": sorted(external_domains[domain])} for domain in new_domains},
        }))
        print(
            f"записаны {arguments.output}, {arguments.report} и {arguments.candidates}"
        )
        return 0
    except (catalog.CatalogError, ImportError_, OSError, ValueError, EOFError) as exc:
        print(f"ОШИБКА: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
