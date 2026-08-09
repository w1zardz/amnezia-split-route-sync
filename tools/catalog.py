#!/usr/bin/env python3
"""Загрузка и валидация каталога российских сервисов (data/services/*.json)."""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parent.parent
SERVICES_DIR = ROOT / "data" / "services"
PREFIXES_FILE = ROOT / "data" / "prefixes.json"
EXTERNAL_FILE = ROOT / "data" / "external.json"

TIERS = ("core", "extended")
HOSTNAME = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)
# Шире /12 не пускаем: такая сеть означала бы «пол-интернета мимо VPN».
MIN_PREFIXLEN = 12
MAX_PREFIXLEN = 24
MAX_ADDRESSES = 40_000_000

# Глобальные CDN/облака: их адреса не должны идти мимо VPN.
DENY_ASN = {
    13335,  # Cloudflare
    15169, 396982, 19527,  # Google
    16509, 14618, 8987,  # Amazon
    8075, 8068, 8069,  # Microsoft
    20940, 16625, 12222, 21342, 32787,  # Akamai
    54113,  # Fastly
    32934,  # Meta
    2906,  # Netflix
    13414,  # X/Twitter
    36459,  # GitHub
    14061,  # DigitalOcean
    24940,  # Hetzner
    16276,  # OVH
    63949, 20473,  # Akamai/Linode, Vultr
    60068, 9009,  # Datacamp/M247
}
# Российские anti-DDoS/скрабберы: юрлицо не в РФ, но за префиксами стоят RU-сайты.
ALLOW_ASN = {
    209671, 211112, 200449,  # Qrator Labs
    59796,  # StormWall
    57724, 262254,  # DDoS-Guard
    208972,  # Servicepipe
}


class CatalogError(RuntimeError):
    pass


def is_russian(asn: int, country: str, as_name: str) -> bool:
    """RU-принадлежность: страна IP, либо страна юрлица AS, либо RU anti-DDoS."""
    if asn in ALLOW_ASN:
        return True
    if country == "RU":
        return True
    # Cymru отдаёт имя вида "OZON-BANK-AS - LLC OZON BANK, RU" — хвост это страна юрлица.
    return as_name.rstrip().upper().endswith(", RU")


def http_get(url: str, max_bytes: int, timeout: int = 70) -> bytes:
    """HTTPS-загрузка через curl: только https, с потолком по размеру и времени."""
    curl = shutil.which("curl")
    if curl is None:
        raise CatalogError("нужен curl")
    try:
        process = subprocess.run(
            [
                curl, "--fail", "--silent", "--show-error", "--location",
                "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
                "--max-filesize", str(max_bytes),
                "--connect-timeout", "10", "--max-time", str(timeout - 10),
                "--retry", "2",
                "--user-agent", "amnezia-split-route-sync/2.0",
                url,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CatalogError(f"запрос не удался: {url}") from exc
    if process.returncode != 0:
        raise CatalogError(f"HTTP-ошибка при запросе {url}: {process.stderr.decode()[:200]}")
    if len(process.stdout) > max_bytes:
        raise CatalogError(f"ответ {url} больше лимита {max_bytes} байт")
    return process.stdout


class Service:
    __slots__ = ("id", "title", "tier", "category", "category_title", "domains", "cidrs", "notes")

    def __init__(self, **kwargs: Any) -> None:
        for name in self.__slots__:
            setattr(self, name, kwargs[name])

    def as_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__slots__}


def normalize_hostname(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise CatalogError(f"{where}: домен должен быть строкой")
    hostname = value.strip().lower().rstrip(".")
    if not HOSTNAME.fullmatch(hostname):
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise CatalogError(f"{where}: некорректный домен {value!r}") from exc
    if not HOSTNAME.fullmatch(hostname) or len(hostname) > 253:
        raise CatalogError(f"{where}: некорректный домен {value!r}")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return hostname
    raise CatalogError(f"{where}: {value!r} — это IP, его место в cidrs")


def parse_network(value: Any, where: str) -> ipaddress.IPv4Network:
    if not isinstance(value, str):
        raise CatalogError(f"{where}: CIDR должен быть строкой")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise CatalogError(f"{where}: некорректный CIDR {value!r}") from exc
    if network.version != 4:
        raise CatalogError(f"{where}: поддерживается только IPv4, получено {value!r}")
    if network.prefixlen < MIN_PREFIXLEN:
        raise CatalogError(f"{where}: сеть {value} слишком широкая")
    if not network.is_global:
        raise CatalogError(f"{where}: сеть {value} не является публичной")
    return network


def load_catalog(directory: Path = SERVICES_DIR) -> list[Service]:
    files = sorted(directory.glob("*.json"), key=lambda path: (len(path.name), path.name))
    if not files:
        raise CatalogError(f"каталог пуст: {directory}")
    services: list[Service] = []
    seen_ids: set[str] = set()
    for path in files:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CatalogError(f"{path.name}: не читается ({exc})") from exc
        if not isinstance(document, dict) or document.get("version") != 1:
            raise CatalogError(f"{path.name}: ожидается объект с version=1")
        category = document.get("category")
        category_title = document.get("title")
        entries = document.get("services")
        if not isinstance(category, str) or not isinstance(category_title, str):
            raise CatalogError(f"{path.name}: нет category/title")
        if not isinstance(entries, list) or not entries:
            raise CatalogError(f"{path.name}: пустой список services")
        for entry in entries:
            if not isinstance(entry, dict):
                raise CatalogError(f"{path.name}: сервис должен быть объектом")
            service_id = entry.get("id")
            title = entry.get("title")
            tier = entry.get("tier")
            where = f"{path.name}:{service_id}"
            if not isinstance(service_id, str) or not re.fullmatch(r"[a-z0-9-]{2,40}", service_id):
                raise CatalogError(f"{path.name}: некорректный id сервиса {service_id!r}")
            if service_id in seen_ids:
                raise CatalogError(f"{path.name}: дублирующийся id сервиса {service_id}")
            seen_ids.add(service_id)
            if not isinstance(title, str) or not title.strip():
                raise CatalogError(f"{where}: нет title")
            if tier not in TIERS:
                raise CatalogError(f"{where}: tier должен быть core или extended")
            domains = entry.get("domains", [])
            cidrs = entry.get("cidrs", [])
            if not isinstance(domains, list) or not isinstance(cidrs, list):
                raise CatalogError(f"{where}: domains и cidrs должны быть списками")
            if not domains and not cidrs:
                raise CatalogError(f"{where}: сервис без доменов и без CIDR")
            parsed_domains = sorted({normalize_hostname(value, where) for value in domains})
            parsed_cidrs = sorted(
                {str(parse_network(value, where)) for value in cidrs},
                key=lambda value: ipaddress.ip_network(value),
            )
            services.append(
                Service(
                    id=service_id,
                    title=title.strip(),
                    tier=tier,
                    category=category,
                    category_title=category_title,
                    domains=parsed_domains,
                    cidrs=parsed_cidrs,
                    notes=entry.get("notes", ""),
                )
            )
    return services


def catalog_domains(services: Iterable[Service], tiers: Iterable[str] = TIERS) -> list[str]:
    allowed = set(tiers)
    return sorted({
        domain
        for service in services
        if service.tier in allowed
        for domain in service.domains
    })


def domain_owner(services: Iterable[Service]) -> dict[str, list[str]]:
    owners: dict[str, list[str]] = {}
    for service in services:
        for domain in service.domains:
            owners.setdefault(domain, []).append(service.id)
    return owners


def load_prefixes(path: Path = PREFIXES_FILE) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogError(f"{path.name}: не читается ({exc})") from exc
    if not isinstance(document, dict) or document.get("version") != 1:
        raise CatalogError(f"{path.name}: ожидается объект с version=1")
    prefixes = document.get("prefixes")
    if not isinstance(prefixes, dict):
        raise CatalogError(f"{path.name}: нет объекта prefixes")
    result: dict[str, dict[str, Any]] = {}
    for value, meta in prefixes.items():
        network = parse_network(value, path.name)
        if not isinstance(meta, dict):
            raise CatalogError(f"{path.name}: метаданные {value} должны быть объектом")
        result[str(network)] = meta
    return result


def collapse(networks: Iterable[ipaddress.IPv4Network]) -> list[ipaddress.IPv4Network]:
    collapsed = sorted(
        ipaddress.collapse_addresses(list(networks)),
        key=lambda network: (int(network.network_address), network.prefixlen),
    )
    total = sum(network.num_addresses for network in collapsed)
    if total > MAX_ADDRESSES:
        raise CatalogError(f"суммарное покрытие {total} адресов превышает лимит {MAX_ADDRESSES}")
    return collapsed


def json_bytes(payload: Any) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)


if __name__ == "__main__":
    catalog = load_catalog()
    print(
        f"OK: {len(catalog)} сервисов, "
        f"{len(catalog_domains(catalog))} доменов, "
        f"{sum(len(service.cidrs) for service in catalog)} ручных CIDR"
    )
