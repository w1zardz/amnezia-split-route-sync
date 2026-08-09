#!/usr/bin/env python3
"""Обновляет data/prefixes.json: домены каталога → IP → анонсируемые BGP-префиксы.

Механика:
  1. резолвим все домены каталога (A-записи);
  2. один bulk-запрос в Team Cymru (whois.cymru.com:43) отдаёт ASN, страну
     и реальный анонсируемый префикс для каждого IP;
  3. оставляем только RU-префиксы (плюс явный allow-list ASN), выкидывая
     глобальные CDN — иначе мимо VPN уехал бы весь Cloudflare;
  4. по желанию разворачиваем целые ASN из config/asn-expand.json через RIPEstat.

Смысл: Amnezia резолвит импортированные домены один раз, а VK/Яндекс/WB крутят
CDN — поэтому в список едут не /32 из локального DNS, а сети целиком.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import shutil
import socket
import subprocess
import sys
from datetime import date
from pathlib import Path
from typing import Iterable

import catalog

ROOT = catalog.ROOT
ASN_EXPAND_FILE = ROOT / "config" / "asn-expand.json"
CYMRU_HOST = "whois.cymru.com"
CYMRU_PORT = 43
CYMRU_CHUNK = 500
RIPESTAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
MAX_RIPESTAT_BYTES = 4_194_304

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
MIN_PREFIXLEN = 12
MAX_PREFIXLEN = 24


class RefreshError(RuntimeError):
    pass


def resolve_all(domains: Iterable[str], workers: int = 48) -> dict[str, list[str]]:
    domain_list = list(domains)

    def resolve_one(hostname: str) -> tuple[str, list[str]]:
        try:
            answers = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        except (socket.gaierror, UnicodeError, OSError):
            return hostname, []
        addresses = set()
        for answer in answers:
            try:
                address = ipaddress.ip_address(answer[4][0])
            except ValueError:
                continue
            if address.version == 4 and address.is_global:
                addresses.add(str(address))
        return hostname, sorted(addresses)

    result: dict[str, list[str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for hostname, addresses in executor.map(resolve_one, domain_list):
            result[hostname] = addresses
    return result


def cymru_lookup(addresses: Iterable[str]) -> dict[str, tuple[int, str, str, str]]:
    """IP → (ASN, префикс, страна, имя AS)."""
    unique = sorted(set(addresses))
    mapping: dict[str, tuple[int, str, str, str]] = {}
    for start in range(0, len(unique), CYMRU_CHUNK):
        chunk = unique[start : start + CYMRU_CHUNK]
        query = "begin\nverbose\n" + "\n".join(chunk) + "\nend\n"
        try:
            with socket.create_connection((CYMRU_HOST, CYMRU_PORT), timeout=45) as connection:
                connection.sendall(query.encode("ascii"))
                buffer = bytearray()
                while True:
                    piece = connection.recv(65536)
                    if not piece:
                        break
                    buffer.extend(piece)
        except OSError as exc:
            raise RefreshError(f"Team Cymru недоступен: {exc}") from exc
        for line in buffer.decode("utf-8", "replace").splitlines():
            if "|" not in line or line.lower().startswith("bulk mode"):
                continue
            fields = [field.strip() for field in line.split("|")]
            if len(fields) < 7 or not fields[0].isdigit():
                continue
            asn = int(fields[0])
            address, prefix, country, as_name = fields[1], fields[2], fields[3], fields[6]
            if not prefix or prefix == "NA":
                continue
            previous = mapping.get(address)
            # Один IP может вернуться под несколькими ASN — берём самый узкий префикс.
            if previous is None or (
                ipaddress.ip_network(prefix).prefixlen
                > ipaddress.ip_network(previous[1]).prefixlen
            ):
                mapping[address] = (asn, prefix, country, as_name)
    return mapping


def is_russian(asn: int, country: str, as_name: str) -> bool:
    """RU-принадлежность: страна IP, либо страна юрлица AS, либо RU anti-DDoS."""
    if asn in ALLOW_ASN:
        return True
    if country == "RU":
        return True
    # Cymru отдаёт имя вида "OZON-BANK-AS - LLC OZON BANK, RU" — хвост это страна юрлица.
    return as_name.rstrip().upper().endswith(", RU")


def fetch_json(url: str) -> dict:
    curl = shutil.which("curl")
    if curl is None:
        raise RefreshError("нужен curl")
    try:
        process = subprocess.run(
            [
                curl, "--fail", "--silent", "--show-error", "--location",
                "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
                "--max-filesize", str(MAX_RIPESTAT_BYTES),
                "--connect-timeout", "10", "--max-time", "60",
                "--retry", "2",
                "--user-agent", "amnezia-split-route-sync/2.0",
                url,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=70,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RefreshError(f"запрос не удался: {url}") from exc
    if process.returncode != 0:
        raise RefreshError(f"HTTP-ошибка при запросе {url}: {process.stderr.decode()[:200]}")
    try:
        return json.loads(process.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RefreshError(f"ответ {url} не является JSON") from exc


def announced_prefixes(asn: int) -> list[str]:
    document = fetch_json(RIPESTAT_URL.format(asn=asn))
    data = document.get("data") if isinstance(document, dict) else None
    entries = data.get("prefixes") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise RefreshError(f"RIPEstat вернул неожиданный ответ для AS{asn}")
    prefixes = []
    for entry in entries:
        value = entry.get("prefix") if isinstance(entry, dict) else None
        if not isinstance(value, str) or ":" in value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if MIN_PREFIXLEN <= network.prefixlen <= MAX_PREFIXLEN and network.is_global:
            prefixes.append(str(network))
    return sorted(set(prefixes))


def load_asn_expand() -> dict[int, str]:
    if not ASN_EXPAND_FILE.exists():
        return {}
    document = json.loads(ASN_EXPAND_FILE.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("version") != 1:
        raise RefreshError("config/asn-expand.json: ожидается объект с version=1")
    entries = document.get("asn", {})
    if not isinstance(entries, dict):
        raise RefreshError("config/asn-expand.json: нет объекта asn")
    result: dict[int, str] = {}
    for key, value in entries.items():
        if not str(key).isdigit() or not isinstance(value, str):
            raise RefreshError(f"config/asn-expand.json: некорректная запись {key!r}")
        number = int(key)
        if number in DENY_ASN:
            raise RefreshError(f"AS{number} в deny-листе, разворачивать нельзя")
        result[number] = value
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=catalog.PREFIXES_FILE)
    parser.add_argument("--no-expand", action="store_true", help="без разворота ASN через RIPEstat")
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()

    try:
        services = catalog.load_catalog()
        domains = catalog.catalog_domains(services)
        owners = catalog.domain_owner(services)
        print(f"каталог: {len(services)} сервисов, {len(domains)} доменов")

        answers = resolve_all(domains)
        resolved = {domain: ips for domain, ips in answers.items() if ips}
        addresses = {address for ips in resolved.values() for address in ips}
        print(f"резолв: {len(resolved)}/{len(domains)} доменов, {len(addresses)} уникальных IP")
        if len(resolved) < len(domains) * 0.5:
            raise RefreshError("резолвится меньше половины каталога — сеть или DNS сломаны")

        cymru = cymru_lookup(addresses)
        print(f"Cymru: {len(cymru)} IP сопоставлены с BGP-префиксами")

        prefixes: dict[str, dict] = {}
        dropped: dict[str, str] = {}
        for domain, ips in resolved.items():
            for address in ips:
                record = cymru.get(address)
                if record is None:
                    continue
                asn, prefix, country, as_name = record
                network = ipaddress.ip_network(prefix, strict=False)
                if asn in DENY_ASN:
                    dropped[prefix] = f"AS{asn} {as_name} — глобальный CDN"
                    continue
                if not is_russian(asn, country, as_name):
                    dropped[prefix] = f"AS{asn} {as_name} — страна {country}"
                    continue
                if not (MIN_PREFIXLEN <= network.prefixlen <= MAX_PREFIXLEN):
                    dropped[prefix] = f"префикс /{network.prefixlen} вне допустимого диапазона"
                    continue
                entry = prefixes.setdefault(
                    str(network),
                    {"asn": asn, "as_name": as_name, "cc": country, "services": [], "source": "dns"},
                )
                for service_id in owners.get(domain, []):
                    if service_id not in entry["services"]:
                        entry["services"].append(service_id)

        expand = {} if arguments.no_expand else load_asn_expand()
        for asn, reason in sorted(expand.items()):
            values = announced_prefixes(asn)
            print(f"AS{asn} ({reason}): {len(values)} анонсируемых префиксов")
            for value in values:
                entry = prefixes.setdefault(
                    value,
                    {"asn": asn, "as_name": reason, "cc": "RU", "services": [], "source": "asn"},
                )
                if entry.get("source") == "asn":
                    entry["asn"] = asn

        for entry in prefixes.values():
            entry["services"] = sorted(entry["services"])

        payload = {
            "version": 1,
            "updated": date.today().isoformat(),
            "source": "Team Cymru bulk whois + RIPEstat announced-prefixes",
            "prefix_count": len(prefixes),
            "resolved_domains": len(resolved),
            "catalog_domains": len(domains),
            "prefixes": dict(
                sorted(prefixes.items(), key=lambda item: ipaddress.ip_network(item[0]))
            ),
        }
        total = sum(ipaddress.ip_network(value).num_addresses for value in prefixes)
        print(f"итого: {len(prefixes)} префиксов, {total} адресов; отброшено {len(dropped)}")
        if arguments.dry_run:
            for value, reason in sorted(dropped.items())[:20]:
                print(f"  drop {value}: {reason}")
            return 0
        catalog.atomic_write(arguments.output, catalog.json_bytes(payload))
        print(f"записан {arguments.output.relative_to(ROOT)}")
        return 0
    except (catalog.CatalogError, RefreshError) as exc:
        print(f"ОШИБКА: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
