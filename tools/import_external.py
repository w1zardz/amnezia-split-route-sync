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

Новые поддомены сервисов ручного каталога дополняют полный список. Домены вне
каталога из источников с флагом "roots" резолвятся: корень принимается, только
если у него есть IPv4 и все его адреса российские и не принадлежат глобальным
CDN. Остальные домены сохраняются с источниками (и причиной отказа) в отчёт
кандидатов для ручной проверки.

Источник с флагом "optional" — мелкий сторонний репозиторий: его сбой или
пустой файл даёт предупреждение и строку в отчёте, импорт идёт без него.
"""

from __future__ import annotations

import argparse
import bisect
import concurrent.futures
import ipaddress
import json
import re
import sys
import urllib.parse
from datetime import date
from pathlib import Path
from typing import Any, Callable

import catalog
import resolve_domains

ROOT = catalog.ROOT
SOURCES_FILE = catalog.SOURCES_FILE
ASN_EXPAND_FILE = ROOT / "config" / "asn-expand.json"
REPORT_FILE = ROOT / "data" / "external-report.md"
CANDIDATES_FILE = ROOT / "data" / "external-candidates.json"
MAX_SOURCE_BYTES = 8_388_608
DOWNLOAD_WORKERS = 4
KINDS = ("cidr", "domains", "amnezia", "v2fly")
# v2fly/domain-list-community: include разворачивается рекурсивно, category-ru
# тянет за собой десятки файлов. Потолок — страховка от цикла и разрастания.
V2FLY_MAX_FILES = 200
V2FLY_NAME = re.compile(r"[a-z0-9][a-z0-9!._-]{0,80}")
# Amnezia начинает подтормаживать на нескольких тысячах записей, а внешних
# кандидатов приходит больше, чем нужно: держим потолок и пишем в отчёт, что
# именно не влезло. Потолок завязан на MAX_ROUTES=1500 сборщика и апдейтеров:
# замер 2026-09-10 — 1000 внешних сетей дают 1356 маршрутов после схлопывания,
# 1200 уже 1526 и ломают сборку. Каждая лишняя сеть к тому же вытесняет корень
# из полного списка (потолок 3900 записей).
DEFAULT_LIMIT = 1000
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


# Таблица общая с tools/resolve_domains.py и живёт в catalog.
AsnTable = catalog.AsnTable


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


def load_sources() -> tuple[str, list[dict[str, Any]]]:
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
    sources: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ImportError_("config/external-sources.json: источник должен быть объектом")
        identifier = entry.get("id")
        kind = entry.get("kind")
        # У v2fly вместо одного файла — каталог и список категорий.
        url = entry.get("base_url") if kind == "v2fly" else entry.get("url")
        if not isinstance(identifier, str) or identifier in seen:
            raise ImportError_(f"config/external-sources.json: некорректный id {identifier!r}")
        seen.add(identifier)
        if not isinstance(url, str) or not url.startswith("https://"):
            raise ImportError_(f"{identifier}: url должен быть https")
        if kind not in KINDS:
            raise ImportError_(f"{identifier}: kind должен быть одним из {', '.join(KINDS)}")
        for flag in ("enabled", "roots", "optional"):
            if not isinstance(entry.get(flag, False), bool):
                raise ImportError_(f"{identifier}: {flag} должен быть true или false")
        source: dict[str, Any] = {
            "id": identifier, "url": url, "kind": kind, "note": entry.get("note", ""),
            "roots": entry.get("roots", False), "optional": entry.get("optional", False),
        }
        if kind == "v2fly":
            categories = entry.get("categories")
            if not url.endswith("/") or not isinstance(categories, list) or not categories or not all(
                isinstance(name, str) and V2FLY_NAME.fullmatch(name) for name in categories
            ):
                raise ImportError_(f"{identifier}: для v2fly нужны base_url с / на конце и categories")
            source["categories"] = categories
        if entry.get("enabled") is False:
            continue
        sources.append(source)
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
            if domain.endswith(catalog.LOCAL_SUFFIXES):
                continue
            domains.append(domain)
        except catalog.CatalogError:
            continue
    return domains


def parse_v2fly(text: str) -> tuple[list[str], list[str]]:
    """Файл domain-list-community → (доменные правила, имена из include:)."""
    rules: list[str] = []
    includes: list[str] = []
    for line in text.splitlines():
        tokens = line.split("#", 1)[0].split()
        if not tokens:
            continue
        rule = tokens[0]
        # @ads — рекламные и трекинговые домены: в direct их не несём, как и
        # include, отбирающий только их. Прочие атрибуты (@cn, @!cn) отрезаем.
        if "@ads" in tokens[1:]:
            continue
        if rule.startswith("include:"):
            includes.append(rule[len("include:"):])
            continue
        for prefix in ("domain:", "full:"):
            if rule.startswith(prefix):
                rule = rule[len(prefix):]
                break
        else:
            if ":" in rule:
                continue  # regexp:, keyword: и неизвестные типы правил
        rules.append(rule)
    return rules, includes


def expand_v2fly(categories: list[str], fetch_many: Callable[[list[str]], dict[str, str]]) -> list[str]:
    """Рекурсивно разворачивает include:X по уровням; каждый файл читается один раз."""
    seen: set[str] = set()
    pending = list(categories)
    rules: list[str] = []
    while pending:
        batch = sorted(set(pending) - seen)
        pending = []
        if not batch:
            break
        for name in batch:
            if not V2FLY_NAME.fullmatch(name):
                raise ImportError_(f"v2fly: некорректное имя списка {name!r}")
        seen.update(batch)
        if len(seen) > V2FLY_MAX_FILES:
            raise ImportError_(f"v2fly: include разворачивается больше чем в {V2FLY_MAX_FILES} файлов")
        texts = fetch_many(batch)
        for name in batch:
            found, includes = parse_v2fly(texts[name])
            rules.extend(found)
            pending.extend(includes)
    return rules


def fetch_v2fly(source: dict[str, Any]) -> str:
    base = source["url"]

    def fetch_many(names: list[str]) -> dict[str, str]:
        with concurrent.futures.ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as executor:
            payloads = executor.map(
                lambda name: catalog.http_get(base + urllib.parse.quote(name), MAX_SOURCE_BYTES),
                names,
            )
            return {name: payload.decode("utf-8-sig") for name, payload in zip(names, payloads)}

    return "\n".join(expand_v2fly(source["categories"], fetch_many))


def fetch_source(source: dict[str, Any]) -> str:
    if source.get("kind") == "v2fly":
        return fetch_v2fly(source)
    return catalog.http_get(source["url"], MAX_SOURCE_BYTES).decode("utf-8-sig")


def parse_source(text: str, kind: str) -> tuple[list, list[str]]:
    if kind == "cidr":
        return parse_networks(text), []
    if kind in ("domains", "v2fly"):
        # fetch_v2fly уже развернул include и выбросил regexp/keyword/@ads.
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


def download_inputs(
    table_url: str, sources: list[dict], local_table: Path | None
) -> tuple[bytes, dict[str, str | None], dict[str, str]]:
    """До четырёх HTTPS-запросов одновременно.

    Сбой обязательного источника останавливает импорт; optional-источник
    получает текст None и причину в третьем словаре.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as executor:
        table = None if local_table else executor.submit(
            catalog.http_get, table_url, catalog.MAX_TABLE_BYTES, 120
        )
        pending = {source["id"]: executor.submit(fetch_source, source) for source in sources}
        payload = local_table.read_bytes() if local_table else table.result()
        texts: dict[str, str | None] = {}
        failures: dict[str, str] = {}
        for source in sources:
            try:
                texts[source["id"]] = pending[source["id"]].result()
            except (catalog.CatalogError, ImportError_, UnicodeError) as exc:
                if not source.get("optional"):
                    raise
                texts[source["id"]] = None
                failures[source["id"]] = f"не загрузился: {exc}"[:300]
    return payload, texts, failures


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


ROOT_NO_ANSWER = "нет ответа DNS"
ROOT_UNRESOLVED = "не резолвится (NXDOMAIN или нет A-записей)"
ROOT_LIMIT = f"не влез в потолок {catalog.MAX_EXTERNAL_ROOTS} корней"


def root_verdict(answer: resolve_domains.Answer, table: AsnTable) -> tuple[str, list[int]]:
    """ACCEPT и ASN корня, либо причина отказа и ASN проблемных адресов."""
    if answer.status == resolve_domains.FAIL:
        return ROOT_NO_ANSWER, []
    if not answer.addresses:
        return ROOT_UNRESOLVED, []
    good: set[int] = set()
    bad: dict[str, set[int]] = {}
    for address in answer.addresses:
        verdict, record = resolve_domains.address_verdict(address, table)
        if verdict == resolve_domains.ACCEPT:
            good.add(record[2])
        else:
            bad.setdefault(verdict, set()).update([record[2]] if record else [])
    # Корень целиком мимо VPN — значит, мимо VPN все его адреса. Один зарубежный
    # IP в ротации — и часть соединений ушла бы с домашнего адреса за границу.
    if bad:
        reason = min(bad, key=resolve_domains.REASON_ORDER.index)
        return reason, sorted(bad[reason])
    return ACCEPT, sorted(good)


def select_roots(
    candidates: dict[str, set[str]], table: AsnTable, previous: dict[str, dict]
) -> tuple[dict[str, dict], dict[str, tuple[str, list[int]]], int]:
    """(принятые корни, отказы с причинами, сколько срезано потолком)."""
    if not candidates:
        return {}, {}, 0
    answers = resolve_domains.resolve_many(candidates)
    answered = sum(1 for answer in answers.values() if answer.status != resolve_domains.FAIL)
    print(f"корни: {len(candidates)} кандидатов, DNS ответил по {answered}")
    if answered < len(candidates) * resolve_domains.MIN_RESOLVED_SHARE:
        raise ImportError_("DNS ответил меньше чем по 60% кандидатов в корни — похоже на троттлинг")
    accepted: dict[str, dict] = {}
    rejected: dict[str, tuple[str, list[int]]] = {}
    for domain in sorted(candidates):
        sources = sorted(candidates[domain])
        answer = answers.get(domain, resolve_domains.Answer(resolve_domains.FAIL, ()))
        if answer.status == resolve_domains.FAIL and domain in previous:
            # Резолверы промолчали — не выкидываем корень, принятый вчера.
            accepted[domain] = {"sources": sources, "asn": previous[domain]["asn"]}
            continue
        verdict, asns = root_verdict(answer, table)
        if verdict == ACCEPT:
            accepted[domain] = {"sources": sources, "asn": asns}
        else:
            rejected[domain] = (verdict, asns)
    ordered = sorted(accepted, key=lambda domain: (-len(accepted[domain]["sources"]), domain))
    for domain in ordered[catalog.MAX_EXTERNAL_ROOTS:]:
        rejected[domain] = (ROOT_LIMIT, [])
    kept = {domain: accepted[domain] for domain in sorted(ordered[: catalog.MAX_EXTERNAL_ROOTS])}
    return kept, rejected, max(0, len(ordered) - catalog.MAX_EXTERNAL_ROOTS)


def build_report(
    sources: list[dict[str, Any]],
    stats: dict[str, dict[str, Any]],
    rejected: dict[str, int],
    unknown_asn: dict[tuple[int, str], int],
    foreign: dict[str, int],
    new_domains: list[str],
    accepted: int,
    dropped_by_limit: int,
    limit: int,
    roots: dict[str, dict] | None = None,
    root_rejected: dict[str, tuple[str, list[int]]] | None = None,
    roots_dropped: int = 0,
) -> str:
    roots = roots or {}
    root_rejected = root_rejected or {}
    lines = [
        "# Внешние источники — отчёт импорта",
        "",
        f"Сборка {date.today().isoformat()}. Файл генерируется "
        "`tools/import_external.py`, правки руками бессмысленны.",
        "",
        "## Источники",
        "",
        "| Источник | Уникальных IP/CIDR | Принято IP/CIDR | Домены | Новые поддомены | Корни |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    skipped = []
    for source in sources:
        entry = stats.get(source["id"], {})
        if entry.get("skipped"):
            skipped.append(f"- ⚠️ `{source['id']}` пропущен: {entry['skipped']}")
            lines.append(f"| `{source['id']}` | — | — | — | — | — |")
            continue
        lines.append(
            f"| `{source['id']}` | {entry.get('networks', 0)} | {entry.get('accepted', 0)} "
            f"| {entry.get('domains', 0)} | {entry.get('accepted_domains', 0)} "
            f"| {entry.get('roots', 0)} |"
        )
    if skipped:
        lines += [
            "",
            "Необязательные источники, не давшие данных в этот раз (импорт прошёл без них):",
            "",
            *skipped,
        ]
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
    reasons: dict[str, int] = {}
    for reason, _asns in root_rejected.values():
        reasons[reason] = reasons.get(reason, 0) + 1
    lines += [
        "",
        f"## Корневые домены — принято {len(roots)}",
        "",
        "Домены вне каталога из источников с флагом `roots`. Корень принимается, "
        "только если у него есть IPv4 и все адреса российские и не принадлежат "
        "глобальным CDN; такие корни идут только в полный список, не в lite. "
        f"Потолок — {catalog.MAX_EXTERNAL_ROOTS}"
        + (f", срезано **{roots_dropped}**" if roots_dropped else "")
        + ". Отказы по каждому домену — в `external-candidates.json`, поле `reason`.",
        "",
        "| Причина отказа | Доменов |",
        "|---|---:|",
    ]
    for reason, count in sorted(reasons.items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"| {reason} | {count} |")
    if not reasons:
        lines.append("| — | 0 |")
    lines += [
        "",
        f"## Домены вне каталога — {len(new_domains)}",
        "",
        "Новые поддомены сервисов каталога и принятые корни добавлены в полный список "
        "автоматически; их источники указаны в `data/external.json`. Ниже — остальные "
        "кандидаты для ручной проверки. Полный список без обрезки, с происхождением "
        "каждой записи: [`external-candidates.json`](external-candidates.json).",
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

        payload, texts, failures = download_inputs(table_url, sources, arguments.asn_table)
        table = catalog.unpack_asn_table(payload)
        print(f"таблица IP→ASN: {len(table)} диапазонов")

        # Сверяемся только с тем, что снапшот добыл сам: прошлый импорт уже лежит
        # в prefixes.json со source=external, и учитывать его — значит на втором
        # прогоне отбросить собственный результат и потерять все внешние сети.
        existing = NetworkIndex([
            ipaddress.ip_network(value)
            for value, meta in catalog.load_prefixes().items()
            if meta.get("source") != "external"
        ])
        services = catalog.load_catalog()
        catalog_domains = set(catalog.catalog_domains(services))

        stats: dict[str, dict[str, Any]] = {}
        previous_sources = {}
        previous_roots: dict[str, dict] = {}
        if arguments.output.exists():
            previous_sources = json.loads(arguments.output.read_text(encoding="utf-8")).get("sources", {})
            try:
                previous_roots = catalog.load_external_roots(services, arguments.output)
            except catalog.CatalogError:
                previous_roots = {}  # битый прошлый снапшот не должен блокировать импорт
        rejected: dict[str, int] = {}
        unknown_asn: dict[tuple[int, str], int] = {}
        foreign: dict[str, int] = {}
        candidates: dict[str, dict] = {}
        external_domains: dict[str, set[str]] = {}
        imported_domains: dict[str, dict] = {}
        root_candidates: dict[str, set[str]] = {}
        classified: dict[ipaddress.IPv4Network, tuple] = {}

        for source in sources:
            previous = previous_sources.get(source["id"], {})
            problem = failures.get(source["id"])
            raw_networks, raw_domains = [], []
            if problem is None:
                try:
                    raw_networks, raw_domains = parse_source(texts[source["id"]], source["kind"])
                except (ImportError_, ValueError) as exc:
                    if not source.get("optional"):
                        raise
                    problem = f"формат не распознан: {exc}"[:300]
            networks = sorted(set(raw_networks))
            domains = sorted(set(raw_domains))
            if problem is None and not networks and not domains:
                problem = "источник пуст или формат изменился"
            if problem is None and previous.get("url") == source["url"] and len(raw_networks) + len(raw_domains) < previous.get("parsed", 0) * 0.5:
                problem = "источник потерял больше половины записей"
            if problem is not None:
                if not source.get("optional"):
                    raise ImportError_(f"{source['id']}: {problem}")
                print(f"ПРЕДУПРЕЖДЕНИЕ: {source['id']} пропущен — {problem}", file=sys.stderr)
                # Прошлый parsed храним, чтобы проверка «потерял половину» не обнулилась.
                stats[source["id"]] = {
                    "skipped": problem,
                    "parsed": previous.get("parsed", 0) if previous.get("url") == source["url"] else 0,
                }
                continue
            accepted_domains = 0
            for domain in domains:
                external_domains.setdefault(domain, set()).add(source["id"])
                parent = catalog.external_domain_parent(domain, catalog_domains)
                if parent:
                    imported_domains.setdefault(domain, {"parent": parent, "sources": []})["sources"].append(source["id"])
                    accepted_domains += 1
                elif source.get("roots") and domain not in catalog_domains:
                    root_candidates.setdefault(domain, set()).add(source["id"])
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

        roots, root_rejected, roots_dropped = select_roots(root_candidates, table, previous_roots)
        for meta in roots.values():
            for identifier in meta["sources"]:
                stats[identifier]["roots"] = stats[identifier].get("roots", 0) + 1
        print(f"корни: принято {len(roots)}, отклонено {len(root_rejected)}"
              + (f", срезано потолком {roots_dropped}" if roots_dropped else ""))

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

        new_domains = sorted(set(external_domains) - catalog_domains - set(imported_domains) - set(roots))
        payload_document = {
            "version": 1,
            "updated": date.today().isoformat(),
            "source": "внешние списки, проверенные по таблице IP→ASN",
            "asn_table": table_url,
            "prefix_count": len(kept),
            "rejected_count": sum(rejected.values()),
            "dropped_by_limit": dropped_by_limit,
            "domain_count": len(imported_domains),
            "root_count": len(roots),
            "roots_dropped": roots_dropped,
            "sources": {
                source["id"]: {"url": source["url"], **stats.get(source["id"], {})}
                for source in sources
            },
            "prefixes": kept,
            "domains": imported_domains,
            "roots": roots,
        }
        report = build_report(
            sources, stats, rejected, unknown_asn, foreign, new_domains,
            len(kept), dropped_by_limit, arguments.limit,
            roots=roots, root_rejected=root_rejected, roots_dropped=roots_dropped,
        )

        def candidate(domain: str) -> dict[str, Any]:
            entry: dict[str, Any] = {"sources": sorted(external_domains[domain])}
            if domain in root_rejected:
                reason, asns = root_rejected[domain]
                entry["reason"] = reason
                if asns:
                    entry["asn"] = asns
            return entry

        if arguments.dry_run:
            for reason, count in sorted(rejected.items(), key=lambda item: -item[1])[:10]:
                print(f"  drop {count}: {reason}")
            reasons: dict[str, int] = {}
            for reason, _asns in root_rejected.values():
                reasons[reason] = reasons.get(reason, 0) + 1
            for reason, count in sorted(reasons.items(), key=lambda item: -item[1]):
                print(f"  корень drop {count}: {reason}")
            print(f"  доменов вне каталога: {len(new_domains)}")
            return 0

        catalog.atomic_write(arguments.output, catalog.json_bytes(payload_document))
        catalog.atomic_write(arguments.report, report.encode("utf-8"))
        catalog.atomic_write(arguments.candidates, catalog.json_bytes({
            "version": 1, "updated": date.today().isoformat(),
            "domains": {domain: candidate(domain) for domain in new_domains},
        }))
        print(
            f"записаны {arguments.output}, {arguments.report} и {arguments.candidates}"
        )
        return 0
    except (catalog.CatalogError, ImportError_, resolve_domains.ResolveError, OSError, ValueError, EOFError) as exc:
        print(f"ОШИБКА: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
