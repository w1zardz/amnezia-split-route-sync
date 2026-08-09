#!/usr/bin/env python3
"""Собирает готовые списки RU Direct из каталога сервисов и снапшота BGP-префиксов.

На выходе (каталог dist/):
  amnezia-ru-direct.json       — полный список для импорта в AmneziaVPN (домены + сети)
  amnezia-ru-direct-lite.json  — только ядро: самые популярные сервисы
  ru-direct-domains.txt        — домены построчно
  ru-direct-ipv4.txt           — сети построчно (для скриптов и macOS-синка)
  happ-ru-direct.json          — фрагмент профиля маршрутизации Happ
  manifest.json                — счётчики, sha256, разбивка по сервисам
  RELEASE_NOTES.md             — что вошло в сборку, по категориям
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any, Iterable

import catalog

ROOT = catalog.ROOT
DIST = ROOT / "dist"
# Amnezia переваривает несколько тысяч записей, но UI начинает подтормаживать —
# держим потолок, чтобы список оставался быстрым.
MAX_ENTRIES = 4_000
MIN_ENTRIES = 300


class BuildError(RuntimeError):
    pass


def import_entries(values: Iterable[str]) -> list[dict[str, str]]:
    return [{"hostname": value, "ip": ""} for value in values]


def sort_networks(values: Iterable[str]) -> list[str]:
    return [
        str(network)
        for network in sorted(
            {ipaddress.ip_network(value) for value in values},
            key=lambda item: (int(item.network_address), item.prefixlen),
        )
    ]


def load_personal(path: Path) -> tuple[list[str], list[str], list[str]]:
    """Личный довесок: {"domains": [...], "cidrs": [...], "protected_ips": [...]}."""
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise BuildError(f"{path}: ожидается объект JSON")
    domains = sorted({
        catalog.normalize_hostname(value, str(path))
        for value in document.get("domains", [])
    })
    cidrs = sort_networks(
        str(catalog.parse_network(value, str(path))) for value in document.get("cidrs", [])
    )
    protected = [str(ipaddress.ip_address(value)) for value in document.get("protected_ips", [])]
    return domains, cidrs, protected


def build(
    services: list[catalog.Service],
    prefixes: dict[str, dict[str, Any]],
    tiers: tuple[str, ...],
    extra_domains: Iterable[str] = (),
    extra_cidrs: Iterable[str] = (),
) -> tuple[list[str], list[str]]:
    allowed_ids = {service.id for service in services if service.tier in tiers}
    domains = sorted({
        domain
        for service in services
        if service.id in allowed_ids
        for domain in service.domains
    } | set(extra_domains))
    networks = [
        ipaddress.ip_network(value)
        for service in services
        if service.id in allowed_ids
        for value in service.cidrs
    ]
    for value, meta in prefixes.items():
        owners = meta.get("services") or []
        # Префиксы из разворота ASN не привязаны к конкретному сервису — они всегда в ядре.
        if meta.get("source") == "asn" or not owners or any(owner in allowed_ids for owner in owners):
            networks.append(ipaddress.ip_network(value))
    networks.extend(ipaddress.ip_network(value) for value in extra_cidrs)
    collapsed = [str(network) for network in catalog.collapse(networks)]
    return domains, collapsed


def guard(domains: list[str], cidrs: list[str], protected: Iterable[str], label: str) -> None:
    total = len(domains) + len(cidrs)
    if not MIN_ENTRIES <= total <= MAX_ENTRIES:
        raise BuildError(f"{label}: {total} записей вне допустимого диапазона")
    networks = [ipaddress.ip_network(value) for value in cidrs]
    for value in protected:
        address = ipaddress.ip_address(value)
        if any(address in network for network in networks):
            raise BuildError(f"{label}: список накрывает защищённый IP {value}")


def release_notes(services: list[catalog.Service], counts: dict[str, Any]) -> str:
    lines = [
        f"# RU Direct — сборка {counts['built']}",
        "",
        "## 👉 Качай `amnezia-ru-direct.json`",
        "",
        "**Один и тот же файл для всех устройств: iPhone, iPad, Android, "
        "Windows, macOS, Linux.** Отдельных версий под платформы нет — "
        "AmneziaVPN везде читает один формат.",
        "",
        "Не знаешь, какой выбрать → бери `amnezia-ru-direct.json`. Это правильный ответ "
        "для Windows, для macOS и для айфона.",
        "",
        f"`amnezia-ru-direct-lite.json` — запасной вариант: {counts['lite_entries']} записей "
        f"вместо {counts['entries']}, только самые популярные сервисы. Бери его, только если "
        "на старом телефоне список тормозит интерфейс Amnezia.",
        "",
        "Остальные файлы для импорта в Amnezia **не нужны** — они для скриптов, Happ и роутеров.",
        "",
        "## Как импортировать",
        "",
        "AmneziaVPN → **Настройки → Раздельное туннелирование сайтов** → "
        "«Адреса из списка не должны открываться через VPN» → ⋮ → "
        "**Заменить список с сайтами** → выбрать `amnezia-ru-direct.json` → переподключить VPN.",
        "",
        "На iPhone файл сначала сохрани в «Файлы» (Safari → «Загрузить»), потом выбирай его в Amnezia.",
        "",
        "---",
        "",
        f"**{counts['services']}** сервисов · **{counts['domains']}** доменов · "
        f"**{counts['cidrs']}** сетей IPv4 · покрытие **{counts['addresses']:,}** адресов".replace(",", " "),
        "",
        "Всё, что открывается только с российского IP, идёт напрямую, остальной трафик — через VPN.",
        "",
        "| Файл | Кому нужен |",
        "|---|---|",
        "| **`amnezia-ru-direct.json`** | **всем — это основной файл** |",
        "| `amnezia-ru-direct-lite.json` | слабые и старые устройства |",
        "| `ru-direct-domains.txt` | свои скрипты, AdGuard Home, dnsmasq |",
        "| `ru-direct-ipv4.txt` | роутеры, ipset, свой роутинг |",
        "| `happ-ru-direct.json` | профиль маршрутизации Happ |",
        "| `manifest.json` | счётчики и SHA-256 |",
        "",
        "## Что вошло",
        "",
    ]
    grouped: dict[str, list[catalog.Service]] = {}
    for service in services:
        grouped.setdefault(service.category_title, []).append(service)
    for title, entries in grouped.items():
        lines.append(f"### {title}")
        lines.append("")
        for service in entries:
            mark = "★" if service.tier == "core" else "·"
            lines.append(f"- {mark} **{service.title}** — {len(service.domains)} доменов")
        lines.append("")
    lines += [
        "★ — входит и в полный список, и в lite.",
        "",
        "---",
        "",
        "Не хочешь возиться с импортом — тот же роутинг в один тап есть у "
        "[MATRIX VPN](https://mtrxvpn.com/happ-ru-direct): профиль ставится по ссылке "
        "`happ://` за 30 секунд и обновляется сам.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DIST)
    parser.add_argument("--personal", type=Path, help="личный довесок, в публичный репозиторий не коммитится")
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()

    try:
        services = catalog.load_catalog()
        prefixes = catalog.load_prefixes()
        if not prefixes:
            raise BuildError("нет data/prefixes.json — сначала запусти tools/refresh_prefixes.py")

        personal_domains: list[str] = []
        personal_cidrs: list[str] = []
        protected: list[str] = []
        if arguments.personal:
            personal_domains, personal_cidrs, protected = load_personal(arguments.personal)

        full_domains, full_cidrs = build(
            services, prefixes, ("core", "extended"), personal_domains, personal_cidrs
        )
        lite_domains, lite_cidrs = build(
            services, prefixes, ("core",), personal_domains, personal_cidrs
        )
        guard(full_domains, full_cidrs, protected, "полный список")
        guard(lite_domains, lite_cidrs, protected, "lite-список")

        full_entries = import_entries(full_domains + full_cidrs)
        lite_entries = import_entries(lite_domains + lite_cidrs)
        happ = {
            "DirectSites": [f"domain:{domain}" for domain in full_domains],
            "DirectIp": full_cidrs,
        }
        addresses = sum(ipaddress.ip_network(value).num_addresses for value in full_cidrs)
        counts = {
            "built": date.today().isoformat(),
            "services": len(services),
            "core_services": sum(1 for service in services if service.tier == "core"),
            "domains": len(full_domains),
            "cidrs": len(full_cidrs),
            "addresses": addresses,
            "entries": len(full_entries),
            "lite_domains": len(lite_domains),
            "lite_cidrs": len(lite_cidrs),
            "lite_entries": len(lite_entries),
            "prefix_snapshot": len(prefixes),
            "personal_domains": len(personal_domains),
            "personal_cidrs": len(personal_cidrs),
        }

        if arguments.dry_run:
            print(json.dumps(counts, ensure_ascii=False, indent=2))
            return 0

        outputs: dict[str, bytes] = {
            "amnezia-ru-direct.json": catalog.json_bytes(full_entries),
            "amnezia-ru-direct-lite.json": catalog.json_bytes(lite_entries),
            "ru-direct-domains.txt": ("\n".join(full_domains) + "\n").encode("utf-8"),
            "ru-direct-ipv4.txt": ("\n".join(full_cidrs) + "\n").encode("utf-8"),
            "happ-ru-direct.json": catalog.json_bytes(happ),
        }
        counts["sha256"] = {
            name: hashlib.sha256(payload).hexdigest() for name, payload in outputs.items()
        }
        outputs["manifest.json"] = catalog.json_bytes(counts)
        outputs["RELEASE_NOTES.md"] = release_notes(services, counts).encode("utf-8")
        for name, payload in outputs.items():
            catalog.atomic_write(arguments.output_dir / name, payload)

        print(
            f"собрано: {counts['entries']} записей "
            f"({counts['domains']} доменов + {counts['cidrs']} сетей), "
            f"lite — {counts['lite_entries']}"
        )
        if arguments.personal:
            print(
                f"личный довесок: {counts['personal_domains']} доменов, "
                f"{counts['personal_cidrs']} сетей"
            )
        return 0
    except (catalog.CatalogError, BuildError, OSError, json.JSONDecodeError) as exc:
        print(f"ОШИБКА: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
