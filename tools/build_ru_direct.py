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

Доменные записи несут снимок IPv4 из data/domain-ips.json (tools/resolve_domains.py):
Amnezia при импорте JSON домены не резолвит, AmneziaWG и мобильные клиенты строят
маршруты только из полей ips/ip. Сама сборка сеть не трогает.
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
# 4000 зашито в уже установленные апдейтеры (MAX_TOTAL_ENTRIES / $MaximumEntries):
# список больше просто перестанет у них применяться. Полный список держим с запасом.
MAX_FULL_ENTRIES = 3_900
MIN_ENTRIES = 300
# Столько же маршрутов принимают установленные апдейтеры Windows и macOS
# ($MaximumRoutes / MAX_TOTAL_ROUTES). Список, который они отвергнут, нельзя
# публиковать: у пользователя обновление просто перестанет применяться.
MAX_ROUTES = 1_500


class BuildError(RuntimeError):
    pass


def import_entries(
    domains: Iterable[str], cidrs: Iterable[str] = (), ips: dict[str, list[str]] | None = None
) -> list[dict[str, Any]]:
    """Записи импорта Amnezia. С ips домен несёт снимок адресов, иначе ip пустой."""
    entries: list[dict[str, Any]] = []
    for domain in domains:
        if ips is None:
            entries.append({"hostname": domain, "ip": ""})
            continue
        addresses = ips.get(domain, [])
        entries.append({"hostname": domain, "ips": addresses, "ip": addresses[0] if addresses else ""})
    entries.extend({"hostname": value, "ip": ""} for value in cidrs)
    return entries


def rank_external(entries: dict[str, dict]) -> list[str]:
    """Больше источников — выше; при равенстве по алфавиту, чтобы обрезка была детерминированной."""
    return sorted(entries, key=lambda domain: (-len(entries[domain].get("sources", [])), domain))


def fit_full_list(
    base_domains: list[str],
    cidrs: list[str],
    external_domains: dict[str, dict],
    roots: dict[str, dict],
    limit: int = MAX_FULL_ENTRIES,
) -> tuple[list[str], list[str], list[str], int, int]:
    """Сперва поддомены каталога, затем корни — пока полный список не упрётся в потолок.

    → (домены, принятые поддомены, принятые корни, срезано поддоменов, срезано корней)
    """
    present = set(base_domains)
    room = limit - len(present) - len(cidrs)
    if room < 0:
        raise BuildError(f"полный список без внешних доменов уже {len(present) + len(cidrs)} записей — больше {limit}")
    subdomains = [domain for domain in rank_external(external_domains) if domain not in present]
    kept_subdomains = subdomains[:room]
    present.update(kept_subdomains)
    room -= len(kept_subdomains)
    candidates = [domain for domain in rank_external(roots) if domain not in present]
    kept_roots = candidates[:room]
    present.update(kept_roots)
    return (
        sorted(present), kept_subdomains, kept_roots,
        len(subdomains) - len(kept_subdomains), len(candidates) - len(kept_roots),
    )


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


def guard(
    domains: list[str], cidrs: list[str], protected: Iterable[str], label: str, limit: int = MAX_ENTRIES
) -> None:
    total = len(domains) + len(cidrs)
    if not MIN_ENTRIES <= total <= min(limit, MAX_ENTRIES):
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
        "## Сначала проверьте подключение",
        "",
        "**Amnezia Free: импорт этого JSON не включит раздельное туннелирование по IP.** "
        "Для этого сценария на серверах Amnezia нужна действующая подписка **Amnezia Premium**. "
        "Наши списки и скрипты не включают Premium и не снимают ограничение Free.",
        "",
        "**Свой сервер (Amnezia Self-hosted): Premium покупать не требуется**, "
        "но подключение должно поддерживать раздельное туннелирование по IP. "
        "Бесплатное приложение AmneziaVPN и подключение Amnezia Free — разные вещи. "
        "Основание: [инструкция Amnezia](https://docs.amnezia.org/ru/documentation/instructions/vpn-split-tunneling/) "
        "и [условия Self-hosted](https://amnezia.org/ru/self-hosted). Сверено 8 сентября 2026 года.",
        "",
        "## 👉 Какой файл качать",
        "",
        "### 🪟 Windows и 🤖 Android — `amnezia-ru-direct.json`",
        "",
        "**Для Windows и Android** — полный список: домены + сети.",
        "",
        "### 🍏 iPhone, iPad, macOS и Linux — `amnezia-ru-direct-ip.json`",
        "",
        f"Рекомендуемый файл для этих платформ — **{counts['ip_entries']} готовых сетей IPv4**. "
        "Он не зависит от преобразования доменных записей в IP самим клиентом. "
        "Наш macOS-updater использует его по умолчанию. IP-список подходит и для Windows/Android.",
        "",
        *(
            [
                f"Доменные записи несут снимок IPv4 на день сборки (поля `ips` и `ip`): "
                f"адреса есть у **{counts['domains_with_ips']}** из {counts['domains']} доменов "
                f"полного списка и у {counts['lite_domains_with_ips']} из {counts['lite_domains']} в lite, "
                "только российские сети. Amnezia при импорте домены не резолвит, поэтому без этого "
                "снимка доменная запись не дала бы маршрута в AmneziaWG и на мобильных клиентах. "
                "Адреса между сборками меняются; в полном списке для Windows их регулярно "
                "обновляет наш updater.",
            ]
            if counts.get("domains_with_ips")
            else [
                "Один импорт доменов не обеспечивает обновление их IPv4. "
                "В полном списке для Windows текущие адреса регулярно заполняет наш updater.",
            ]
        ),
        "",
        "### 🔧 Клиент не умеет split tunneling — `wg-allowed-ips.txt`",
        "",
        f"Готовая строка `AllowedIPs` из {counts['allowed_ips']} префиксов: весь IPv4 "
        "минус российские сети и приватные диапазоны. Вставляется в секцию `[Peer]` "
        "конфига WireGuard или AmneziaWG вместо `0.0.0.0/0`. Нужны рабочий доступ к серверу "
        "и клиент с возможностью редактирования `AllowedIPs`. Для своего конфига Premium "
        "не требуется; этот файл не снимает ограничения подключения Amnezia Free.",
        "",
        f"`amnezia-ru-direct-lite.json` — запасной вариант для Windows и Android: "
        f"{counts['lite_entries']} записей вместо {counts['entries']}, только самые популярные "
        "сервисы. Бери его, если список тормозит интерфейс Amnezia.",
        "",
        "Остальные файлы для импорта в Amnezia **не нужны** — они для скриптов, Happ и роутеров.",
        "",
        "## Как импортировать",
        "",
        "Сначала выберите совместимое подключение: Premium с активной подпиской или свой сервер. "
        "Убедитесь, что раздельное туннелирование сайтов доступно.",
        "",
        "AmneziaVPN → **Настройки → Раздельное туннелирование сайтов** → "
        "«Адреса из списка не должны открываться через VPN» → включить функцию → ⋮ → "
        "**Заменить список с сайтами** → выбрать JSON → **переподключить VPN**. "
        "Замена удаляет прежний список; для сохранения своих записей выберите добавление к существующим.",
        "",
        "На iPhone сначала сохрани файл в «Файлы» (Safari → «Загрузить»), потом выбирай его оттуда.",
        "",
        "Успешный импорт подтверждает чтение файла, а не работу маршрутов. "
        "Для проверки откройте [yandex.ru/internet](https://yandex.ru/internet): "
        "при применившемся исключении он покажет IP обычного интернет-подключения. "
        "Это проверка одного соединения. За пределами России список не создаёт российский IP.",
        "",
        "---",
        "",
        f"**{counts['services']}** сервисов · **{counts['domains']}** доменов · "
        f"**{counts['cidrs']}** сетей IPv4 · покрытие **{counts['addresses']:,}** адресов".replace(",", " "),
        "",
        *(
            [
                f"Из внешних списков в полный список добавлено **{counts['external_roots']}** "
                "корневых доменов вне каталога — только те, у которых все IPv4 российские; "
                "в lite они не входят."
                + (
                    f" Ещё {counts['external_roots_dropped']} не влезли в потолок "
                    f"{MAX_FULL_ENTRIES} записей."
                    if counts.get("external_roots_dropped")
                    else ""
                ),
                "",
            ]
            if counts.get("external_roots")
            else []
        ),
        "При включённом режиме исключений адреса из списка идут напрямую, остальной трафик — через VPN.",
        "",
        "| Файл | Кому нужен |",
        "|---|---|",
        "| **`amnezia-ru-direct.json`** | Windows/Android: домены + сети |",
        "| **`amnezia-ru-direct-ip.json`** | iOS/macOS/Linux; также Windows/Android, если нужны только сети |",
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
        "`happ://` и обновляется сам.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DIST)
    parser.add_argument("--personal", type=Path, help="личный довесок, в публичный репозиторий не коммитится")
    parser.add_argument("--no-external", action="store_true", help="без внешних поддоменов, корней и сетей")
    parser.add_argument("--no-ips", action="store_true", help="доменные записи без снимка IPv4 (ip пустой)")
    parser.add_argument("--domain-ips", type=Path, default=catalog.DOMAIN_IPS_FILE)
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()

    try:
        services = catalog.load_catalog()
        prefixes = catalog.load_prefixes()
        if not prefixes:
            raise BuildError("нет data/prefixes.json — сначала запусти tools/refresh_prefixes.py")
        external_domains = {} if arguments.no_external else catalog.load_external_domains(services)
        external_roots = {} if arguments.no_external else catalog.load_external_roots(services)
        if arguments.no_external:
            prefixes = {value: meta for value, meta in prefixes.items() if meta.get("source") != "external"}
        # Нет снимка — доменные записи как раньше, с пустым ip; лишние домены снимка не нужны.
        domain_ips = (
            None if arguments.no_ips or not arguments.domain_ips.exists()
            else catalog.load_domain_ips(arguments.domain_ips)
        )

        personal_domains: list[str] = []
        personal_cidrs: list[str] = []
        protected: list[str] = []
        if arguments.personal:
            personal_domains, personal_cidrs, protected = load_personal(arguments.personal)

        base_domains, full_cidrs = build(
            services, prefixes, ("core", "extended"), personal_domains, personal_cidrs
        )
        full_domains, kept_subdomains, kept_roots, subdomains_dropped, roots_dropped = fit_full_list(
            base_domains, full_cidrs, external_domains, external_roots
        )
        lite_domains, lite_cidrs = build(
            services, prefixes, ("core",), personal_domains, personal_cidrs
        )
        guard(full_domains, full_cidrs, protected, "полный список", MAX_FULL_ENTRIES)
        guard(lite_domains, lite_cidrs, protected, "lite-список")

        full_entries = import_entries(full_domains, full_cidrs, domain_ips)
        lite_entries = import_entries(lite_domains, lite_cidrs, domain_ips)
        # Экспорт готовых сетей не зависит от DNS-обработки доменных записей клиентом.
        ip_entries = import_entries((), full_cidrs)
        with_ips = domain_ips or {}
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
            "external_domains": len(kept_subdomains),
            "external_domains_dropped": subdomains_dropped,
            "external_roots": len(kept_roots),
            "external_roots_dropped": roots_dropped,
            "domains_with_ips": sum(1 for domain in full_domains if with_ips.get(domain)),
            "lite_domains_with_ips": sum(1 for domain in lite_domains if with_ips.get(domain)),
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
