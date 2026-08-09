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
# Столько же маршрутов принимают установленные апдейтеры Windows и macOS
# ($MaximumRoutes / MAX_TOTAL_ROUTES). Список, который они отвергнут, нельзя
# публиковать: у пользователя обновление просто перестанет применяться.
MAX_ROUTES = 1_500


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
        source = meta.get("source")
        if source == "external":
            # Сети из внешних списков углубляют покрытие, но в lite не идут:
            # он существует ровно ради короткого списка для слабых устройств.
            if "extended" in tiers:
                networks.append(ipaddress.ip_network(value))
            continue
        # Префиксы из разворота ASN не привязаны к конкретному сервису — они всегда в ядре.
        if source == "asn" or not owners or any(owner in allowed_ids for owner in owners):
            networks.append(ipaddress.ip_network(value))
    networks.extend(ipaddress.ip_network(value) for value in extra_cidrs)
    collapsed = [str(network) for network in catalog.collapse(networks)]
    return domains, collapsed


def guard(domains: list[str], cidrs: list[str], protected: Iterable[str], label: str) -> None:
    total = len(domains) + len(cidrs)
    if not MIN_ENTRIES <= total <= MAX_ENTRIES:
        raise BuildError(f"{label}: {total} записей вне допустимого диапазона")
    if len(cidrs) > MAX_ROUTES:
        raise BuildError(
            f"{label}: {len(cidrs)} сетей — апдейтеры принимают не больше {MAX_ROUTES}. "
            "Сузь внешние источники (tools/import_external.py --limit)"
        )
    networks = [ipaddress.ip_network(value) for value in cidrs]
    for value in protected:
        address = ipaddress.ip_address(value)
        if any(address in network for network in networks):
            raise BuildError(f"{label}: список накрывает защищённый IP {value}")


NON_ROUTABLE = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
)


def invert_networks(cidrs: list[str]) -> list[str]:
    """0.0.0.0/0 минус российские сети и приватные диапазоны.

    Результат кладётся в AllowedIPs конфига WireGuard/AmneziaWG: туннель просто
    не забирает эти адреса, поэтому раздельное туннелирование работает даже там,
    где клиент такой функции не даёт.
    """
    exclude = list(
        ipaddress.collapse_addresses(
            [ipaddress.ip_network(value) for value in cidrs]
            + [ipaddress.ip_network(value) for value in NON_ROUTABLE]
        )
    )
    remaining = [ipaddress.ip_network("0.0.0.0/0")]
    for network in exclude:
        following: list[ipaddress.IPv4Network] = []
        for current in remaining:
            if network.subnet_of(current):
                following.extend(current.address_exclude(network))
            elif not current.overlaps(network):
                following.append(current)
        remaining = following
    return [str(network) for network in ipaddress.collapse_addresses(remaining)]


def release_notes(services: list[catalog.Service], counts: dict[str, Any]) -> str:
    lines = [
        f"# RU Direct — сборка {counts['built']}",
        "",
        "## 👉 Какой файл качать",
        "",
        "### 🪟 Windows и 🤖 Android — `amnezia-ru-direct.json`",
        "",
        "**Для Windows и Android** — полный список: домены + сети.",
        "",
        "### 🍏 iPhone, iPad, macOS и Linux — `amnezia-ru-direct-ip.json`",
        "",
        "У этих платформ Amnezia умеет раздельное туннелирование "
        "[**только по IP-адресам**](https://docs.amnezia.org/ru/documentation/instructions/vpn-split-tunneling/) — "
        "домены она молча игнорирует. Полный список там не сработает: "
        f"из {counts['entries']} записей применятся только {counts['ip_entries']}, "
        "и то не всегда. Поэтому для них собран отдельный файл — "
        f"**{counts['ip_entries']} сетей IPv4, ни одного домена**.",
        "",
        "На Amnezia Free раздельное туннелирование по IP недоступно — нужен обычный AmneziaVPN.",
        "",
        "### 🔧 Клиент не умеет split tunneling — `wg-allowed-ips.txt`",
        "",
        f"Готовая строка `AllowedIPs` из {counts['allowed_ips']} префиксов: весь IPv4 "
        "минус российские сети и приватные диапазоны. Вставляется в секцию `[Peer]` "
        "конфига WireGuard или AmneziaWG вместо `0.0.0.0/0`. Туннель просто не забирает "
        "российские адреса — раздельное туннелирование работает на уровне конфига, "
        "без всякой поддержки со стороны клиента.",
        "",
        f"`amnezia-ru-direct-lite.json` — запасной вариант для Windows и Android: "
        f"{counts['lite_entries']} записей вместо {counts['entries']}, только самые популярные "
        "сервисы. Бери его, если список тормозит интерфейс Amnezia.",
        "",
        "Остальные файлы для импорта в Amnezia **не нужны** — они для скриптов, Happ и роутеров.",
        "",
        "## Как импортировать",
        "",
        "AmneziaVPN → **Настройки → Раздельное туннелирование сайтов** → "
        "«Адреса из списка не должны открываться через VPN» → ⋮ → "
        "**Заменить список с сайтами** → выбрать JSON → **переподключить VPN**.",
        "",
        "На iPhone сначала сохрани файл в «Файлы» (Safari → «Загрузить»), потом выбирай его оттуда.",
        "",
        "Проверка: при включённом VPN открой [yandex.ru/internet](https://yandex.ru/internet) — "
        "должен показать домашний российский IP. Сайты вне списка (2ip.ru и подобные "
        "зарубежные) продолжат показывать IP сервера, так и задумано.",
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
        # iOS/macOS/Linux-клиенты Amnezia принимают в split tunneling только IP-адреса,
        # домены там молча игнорируются — им нужен список без единого имени хоста.
        ip_entries = import_entries(full_cidrs)
        allowed_ips = invert_networks(full_cidrs)
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
            "ip_entries": len(ip_entries),
            "allowed_ips": len(allowed_ips),
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
            "amnezia-ru-direct-ip.json": catalog.json_bytes(ip_entries),
            "ru-direct-domains.txt": ("\n".join(full_domains) + "\n").encode("utf-8"),
            "ru-direct-ipv4.txt": ("\n".join(full_cidrs) + "\n").encode("utf-8"),
            "wg-allowed-ips.txt": ("AllowedIPs = " + ", ".join(allowed_ips) + "\n").encode("utf-8"),
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
