#!/usr/bin/env python3
"""Обновляет RU Direct CIDR в split tunneling AmneziaVPN на macOS."""

from __future__ import annotations

import argparse
import concurrent.futures
import fcntl
import hashlib
import ipaddress
import json
import os
import plistlib
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, NamedTuple


APP_DOMAIN = "org.amneziavpn.AmneziaVPN"
APP_BUNDLE = Path("/Applications/AmneziaVPN.app")
APP_INFO_PLIST = APP_BUNDLE / "Contents/Info.plist"
SUPPORTED_APP_MAJOR = 5
PROTECTED_IPS: set[ipaddress.IPv4Address] = set()
RAW_BASE = "https://raw.githubusercontent.com/GrimbirdUsers/ru-routing-dat/main/data-geoip"
SOURCES = {
    "ru-yandex": 10,
    "ru-ozon": 8,
    "ru-vk": 3,
    "ru-wildberries": 5,
    "ru-banks": 5,
    "ru-payments": 3,
    "ru-cdn": 1,
}
MIN_PREFIX_LENGTH = 16
MIN_TOTAL_ROUTES = 40
MAX_TOTAL_ROUTES = 256
MAX_TOTAL_ADDRESSES = 1_000_000
STATE_DIR = Path.home() / "Library/Application Support/AmneziaRouteSync"
PREFS_ROUTE_KEY = "Conf.ExceptSites"
PREFS_MODE_KEY = "Conf.routeMode"
PREFS_ENABLED_KEY = "Conf.sitesSplitTunnelingEnabled"
ROUTE_MODE_VPN_ALL_EXCEPT_SITES = 2
POLICY_FILENAME = "route-policy.json"
CUSTOM_HOST_POLICY_FILENAME = "custom-host-policy.json"
PENDING_FILENAME = ".route-transaction.json"
AMNEZIA_GUI_PROCESS = "AmneziaVPN"
AMNEZIA_TUNNEL_PROCESS = "amneziawg-go"


class UpdateError(RuntimeError):
    pass


class SessionChanged(UpdateError):
    pass


def fetch_text(url: str) -> str:
    process = subprocess.run(
        [
            "/usr/bin/curl",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--max-filesize",
            "1048576",
            "--connect-timeout",
            "10",
            "--max-time",
            "30",
            "--user-agent",
            "Amnezia-Split-Route-Sync/1.0",
            url,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        message = process.stderr.decode(errors="replace").strip()
        raise UpdateError(f"не удалось скачать {url}: {message}")
    if len(process.stdout) > 1_048_576:
        raise UpdateError(f"{url}: ответ превышает 1 MiB")
    try:
        return process.stdout.decode("utf-8")
    except UnicodeError as exc:
        raise UpdateError(f"{url}: ответ не является UTF-8") from exc


def parse_source(name: str, text: str, minimum_count: int) -> list[ipaddress.IPv4Network]:
    networks: list[ipaddress.IPv4Network] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        value = raw_line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise UpdateError(f"{name}:{line_number}: некорректная сеть") from exc
        if network.version == 6:
            continue
        if network.prefixlen < MIN_PREFIX_LENGTH:
            raise UpdateError(f"{name}: слишком широкая сеть")
        networks.append(network)

    if len(networks) < minimum_count:
        raise UpdateError(f"{name}: получено только {len(networks)} IPv4 CIDR, ожидалось >= {minimum_count}")
    return networks


def load_policy(path: Path) -> dict[str, list[ipaddress.IPv4Network]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        raw_sources = document["sources"]
    except (OSError, KeyError, json.JSONDecodeError, TypeError) as exc:
        raise UpdateError(f"не удалось прочитать trusted policy {path}: {exc}") from exc
    if (
        not isinstance(raw_sources, dict)
        or document.get("version") != 1
        or set(raw_sources) != set(SOURCES)
    ):
        raise UpdateError("trusted policy имеет неизвестную версию или набор источников")

    policy: dict[str, list[ipaddress.IPv4Network]] = {}
    for name, raw_networks in raw_sources.items():
        if not isinstance(raw_networks, list) or not raw_networks:
            raise UpdateError(f"trusted policy для {name} пуста")
        try:
            networks = [ipaddress.ip_network(value, strict=True) for value in raw_networks]
        except (TypeError, ValueError) as exc:
            raise UpdateError(f"trusted policy для {name} содержит неверный CIDR") from exc
        if any(
            network.version != 4 or network.prefixlen < MIN_PREFIX_LENGTH
            for network in networks
        ):
            raise UpdateError(f"trusted policy для {name} содержит недопустимо широкую сеть")
        if any(ip in network for network in networks for ip in PROTECTED_IPS):
            raise UpdateError(f"trusted policy для {name} содержит protected IP")
        policy[name] = networks
    return policy


def load_custom_host_policy(path: Path) -> list[dict[str, Any]]:
    global PROTECTED_IPS
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        raw_groups = document["groups"]
        raw_protected_ips = document["protected_ips"]
    except (OSError, KeyError, json.JSONDecodeError, TypeError) as exc:
        raise UpdateError(f"не удалось прочитать custom host policy {path}: {exc}") from exc
    if (
        document.get("version") != 1
        or not isinstance(raw_groups, list)
        or not isinstance(raw_protected_ips, list)
        or not raw_protected_ips
    ):
        raise UpdateError("custom host policy должен содержать version=1, groups и protected_ips")
    try:
        protected_ips = {ipaddress.ip_address(value) for value in raw_protected_ips}
    except (TypeError, ValueError) as exc:
        raise UpdateError("custom host policy содержит неверный protected IP") from exc
    if any(ip.version != 4 for ip in protected_ips):
        raise UpdateError("protected_ips поддерживает только IPv4")
    PROTECTED_IPS = protected_ips

    policy: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()
    for raw_group in raw_groups:
        if not isinstance(raw_group, dict):
            raise UpdateError("custom host policy содержит неверную группу")
        name = raw_group.get("name")
        hosts = raw_group.get("hosts")
        raw_networks = raw_group.get("allowed_networks")
        optional_hosts = raw_group.get("optional_hosts")
        minimum_unique_ipv4 = raw_group.get("minimum_unique_ipv4")
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(hosts, list)
            or not hosts
            or not isinstance(raw_networks, list)
            or not raw_networks
            or not isinstance(optional_hosts, list)
            or not isinstance(minimum_unique_ipv4, int)
            or minimum_unique_ipv4 < 1
        ):
            raise UpdateError(f"custom host policy group {name!r} имеет неверный формат")
        normalized_hosts: list[str] = []
        for host in hosts:
            if (
                not isinstance(host, str)
                or host != host.lower()
                or host.startswith(".")
                or host.endswith(".")
                or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-." for character in host)
            ):
                raise UpdateError(f"custom host policy содержит неверный hostname {host!r}")
            if host in seen_hosts:
                raise UpdateError(f"custom host policy повторяет hostname {host}")
            seen_hosts.add(host)
            normalized_hosts.append(host)
        if (
            any(not isinstance(host, str) for host in optional_hosts)
            or len(set(optional_hosts)) != len(optional_hosts)
            or not set(optional_hosts).issubset(normalized_hosts)
        ):
            raise UpdateError(f"custom host policy group {name} имеет неверные optional_hosts")
        try:
            allowed_networks = [
                ipaddress.ip_network(value, strict=True) for value in raw_networks
            ]
        except (TypeError, ValueError) as exc:
            raise UpdateError(f"custom host policy group {name} содержит неверный CIDR") from exc
        if any(
            network.version != 4 or network.prefixlen < MIN_PREFIX_LENGTH
            for network in allowed_networks
        ):
            raise UpdateError(f"custom host policy group {name} содержит широкую сеть")
        if any(ip in network for network in allowed_networks for ip in PROTECTED_IPS):
            raise UpdateError(f"custom host policy group {name} содержит protected IP")
        policy.append(
            {
                "name": name,
                "hosts": normalized_hosts,
                "optional_hosts": set(optional_hosts),
                "allowed_networks": allowed_networks,
                "minimum_unique_ipv4": minimum_unique_ipv4,
            }
        )
    return policy


def _resolve_ipv4_host(host: str) -> list[ipaddress.IPv4Address]:
    try:
        process = subprocess.run(
            ["/usr/bin/dig", "+short", "+time=2", "+tries=1", "A", host],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
    except subprocess.TimeoutExpired as exc:
        raise UpdateError(f"DNS lookup {host} не завершился за 5 секунд") from exc
    if process.returncode != 0:
        raise UpdateError(
            f"DNS lookup {host} завершился с ошибкой: {process.stderr.strip()}"
        )
    addresses: set[ipaddress.IPv4Address] = set()
    for value in process.stdout.splitlines():
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError:
            continue  # dig также может напечатать промежуточный CNAME.
        if address.version == 4:
            addresses.add(address)
    return sorted(addresses)


def resolve_ipv4_hosts(
    hosts: Iterable[str],
) -> dict[str, list[ipaddress.IPv4Address]]:
    host_list = list(hosts)
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        futures = {host: executor.submit(_resolve_ipv4_host, host) for host in host_list}
        return {host: futures[host].result() for host in host_list}


def resolve_custom_routes(
    policy: Iterable[dict[str, Any]],
    resolver: Any = resolve_ipv4_hosts,
) -> tuple[list[ipaddress.IPv4Network], dict[str, int]]:
    networks: list[ipaddress.IPv4Network] = []
    group_counts: dict[str, int] = {}
    for group in policy:
        raw_answers = resolver(group["hosts"])
        if not isinstance(raw_answers, dict) or set(raw_answers) != set(group["hosts"]):
            raise UpdateError(f"{group['name']}: DNS resolver вернул неполный ответ")
        addresses: list[ipaddress.IPv4Address] = []
        for host in group["hosts"]:
            try:
                host_addresses = [ipaddress.ip_address(str(value)) for value in raw_answers[host]]
            except (TypeError, ValueError) as exc:
                raise UpdateError(
                    f"{group['name']}: DNS resolver вернул неверный IP для {host}"
                ) from exc
            if not host_addresses and host not in group["optional_hosts"]:
                raise UpdateError(f"{group['name']}: обязательный hostname {host} не дал IPv4")
            for address in host_addresses:
                if address.version != 4 or not any(
                    address in envelope for envelope in group["allowed_networks"]
                ):
                    raise UpdateError(
                        f"{group['name']}: DNS {host} вернул адрес вне allowlist; "
                        "обновление отклонено без изменения AmneziaVPN"
                    )
            addresses.extend(host_addresses)
        unique_addresses = sorted(set(addresses))
        if len(unique_addresses) < group["minimum_unique_ipv4"]:
            raise UpdateError(
                f"{group['name']}: DNS вернул только {len(unique_addresses)} уникальных IPv4, "
                f"ожидалось >= {group['minimum_unique_ipv4']}"
            )
        for address in unique_addresses:
            networks.append(ipaddress.ip_network(f"{address}/32"))
        group_counts[group["name"]] = len(unique_addresses)
    return networks, group_counts


def validate_source_policy(
    name: str,
    networks: Iterable[ipaddress.IPv4Network],
    allowed_networks: Iterable[ipaddress.IPv4Network],
) -> None:
    allowed = list(allowed_networks)
    for network in networks:
        if not any(network.subnet_of(envelope) for envelope in allowed):
            raise UpdateError(
                f"{name}: новая сеть вне проверенного allowlist; "
                "обновление отклонено без изменения AmneziaVPN"
            )


def validate_and_collapse(networks: Iterable[ipaddress.IPv4Network]) -> list[ipaddress.IPv4Network]:
    collapsed = list(ipaddress.collapse_addresses(networks))
    if not MIN_TOTAL_ROUTES <= len(collapsed) <= MAX_TOTAL_ROUTES:
        raise UpdateError(
            f"подозрительное число маршрутов: {len(collapsed)} "
            f"(допустимо {MIN_TOTAL_ROUTES}..{MAX_TOTAL_ROUTES})"
        )
    covered_addresses = sum(network.num_addresses for network in collapsed)
    if covered_addresses > MAX_TOTAL_ADDRESSES:
        raise UpdateError(f"список покрывает слишком много IPv4-адресов: {covered_addresses}")
    for network in collapsed:
        protected_inside = [ip for ip in PROTECTED_IPS if ip in network]
        if protected_inside:
            raise UpdateError("итоговый маршрут покрывает protected IP")
    return sorted(collapsed, key=lambda network: (int(network.network_address), network.prefixlen))


def merge_except_sites(
    current: dict[str, Any], previous_managed: Iterable[str], new_managed: Iterable[str]
) -> dict[str, Any]:
    previous = set(previous_managed)
    merged = {key: value for key, value in current.items() if key not in previous}
    for cidr in new_managed:
        merged[cidr] = []
    return merged


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    file_descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(file_descriptor, "wb") as temporary_file:
            temporary_file.write(data)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.chmod(temporary_name, mode)
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def load_string_list(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UpdateError(f"не удалось прочитать state {path}: {exc}") from exc
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise UpdateError(f"неверный формат state {path}")
    return value


def export_preferences() -> tuple[bytes, dict[str, Any]]:
    process = subprocess.run(
        ["/usr/bin/defaults", "export", APP_DOMAIN, "-"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.returncode != 0:
        message = process.stderr.decode(errors="replace").strip()
        raise UpdateError(f"не удалось экспортировать Preferences AmneziaVPN: {message}")
    try:
        preferences = plistlib.loads(process.stdout)
    except plistlib.InvalidFileException as exc:
        raise UpdateError("Preferences AmneziaVPN не являются валидным plist") from exc
    if not isinstance(preferences, dict):
        raise UpdateError("Preferences AmneziaVPN имеют неожиданный формат")
    return process.stdout, preferences


def protected_settings_hash(preferences: dict[str, Any]) -> str:
    protected = {key: value for key, value in preferences.items() if key.startswith("Servers.")}
    return hashlib.sha256(plistlib.dumps(protected, fmt=plistlib.FMT_BINARY)).hexdigest()


def route_state(preferences: dict[str, Any]) -> dict[str, Any]:
    sites = preferences.get(PREFS_ROUTE_KEY, {})
    if not isinstance(sites, dict):
        raise UpdateError(f"{PREFS_ROUTE_KEY} имеет неожиданный формат")
    return {
        "sites": sites,
        "mode": preferences.get(PREFS_MODE_KEY),
        "enabled": preferences.get(PREFS_ENABLED_KEY),
    }


def run_helper(helper_path: Path, state_path: Path) -> None:
    process = subprocess.run(
        [str(helper_path), "--domain", APP_DOMAIN, "--state", str(state_path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if process.returncode != 0:
        raise UpdateError(f"helper не применил routing Preferences: {process.stderr.strip()}")


def process_ids(name: str) -> list[int]:
    process = subprocess.run(
        ["/usr/bin/pgrep", "-x", name],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if process.returncode not in (0, 1):
        raise UpdateError(f"pgrep не смог проверить процесс {name}")
    return [int(value) for value in process.stdout.split()]


def wait_for_process(name: str, running: bool, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if bool(process_ids(name)) is running:
            return True
        time.sleep(0.25)
    return bool(process_ids(name)) is running


class AmneziaSession(NamedTuple):
    was_running: bool
    was_connected: bool
    auto_connect: bool
    default_server_index: int


def inspect_amnezia(preferences: dict[str, Any]) -> AmneziaSession:
    gui_pids = process_ids(AMNEZIA_GUI_PROCESS)
    tunnel_running = bool(process_ids(AMNEZIA_TUNNEL_PROCESS))
    return AmneziaSession(
        was_running=bool(gui_pids),
        was_connected=tunnel_running,
        auto_connect=preferences.get("Conf.autoConnect") is True,
        default_server_index=int(preferences.get("Servers.defaultServerIndex", 0)),
    )


def session_document(session: AmneziaSession) -> dict[str, Any]:
    return {
        "was_running": session.was_running,
        "was_connected": session.was_connected,
        "auto_connect": session.auto_connect,
        "default_server_index": session.default_server_index,
    }


def load_session(value: Any) -> AmneziaSession:
    if not isinstance(value, dict):
        raise UpdateError("transaction journal не содержит Amnezia session")
    try:
        session = AmneziaSession(
            was_running=value["was_running"],
            was_connected=value["was_connected"],
            auto_connect=value["auto_connect"],
            default_server_index=value["default_server_index"],
        )
    except KeyError as exc:
        raise UpdateError("transaction journal содержит неполную Amnezia session") from exc
    if not all(isinstance(item, bool) for item in session[:3]) or not isinstance(
        session.default_server_index, int
    ):
        raise UpdateError("transaction journal содержит неверную Amnezia session")
    return session


def stop_amnezia(session: AmneziaSession) -> None:
    gui_pids = process_ids(AMNEZIA_GUI_PROCESS)
    tunnel_running = bool(process_ids(AMNEZIA_TUNNEL_PROCESS))
    if bool(gui_pids) != session.was_running or tunnel_running != session.was_connected:
        raise SessionChanged("состояние AmneziaVPN изменилось во время подготовки; повторите запуск")
    if tunnel_running and not gui_pids:
        raise UpdateError("AmneziaWG активен без GUI; безопасная запись Preferences невозможна")
    if not gui_pids:
        return

    for pid in gui_pids:
        try:
            os.kill(pid, 15)
        except ProcessLookupError:
            pass
    if not wait_for_process(AMNEZIA_GUI_PROCESS, False, 20):
        raise UpdateError("AmneziaVPN не завершилась за 20 секунд; Preferences не изменены")
    if not wait_for_process(AMNEZIA_TUNNEL_PROCESS, False, 20):
        raise UpdateError("AmneziaWG не отключился за 20 секунд; Preferences не изменены")


def relaunch_amnezia(session: AmneziaSession) -> None:
    if not session.was_running:
        return
    gui_running = bool(process_ids(AMNEZIA_GUI_PROCESS))
    tunnel_running = bool(process_ids(AMNEZIA_TUNNEL_PROCESS))
    if gui_running and (not session.was_connected or tunnel_running):
        return
    if gui_running and session.was_connected and not tunnel_running:
        raise UpdateError(
            "AmneziaVPN уже открыта без AmneziaWG-туннеля; "
            "автоматический relaunch отменён"
        )
    if gui_running:
        current_session = inspect_amnezia(export_preferences()[1])
        stop_amnezia(current_session)
    command = ["/usr/bin/open", "-a", APP_BUNDLE.stem]
    if session.was_connected and not session.auto_connect:
        command.extend(["--args", "--connect", str(session.default_server_index)])
    process = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.returncode != 0:
        message = process.stderr.decode(errors="replace").strip()
        raise UpdateError(f"настройки записаны, но AmneziaVPN не запустилась: {message}")
    if not wait_for_process(AMNEZIA_GUI_PROCESS, True, 20):
        raise UpdateError("настройки записаны, но процесс AmneziaVPN не появился")
    if session.was_connected and not wait_for_process(AMNEZIA_TUNNEL_PROCESS, True, 40):
        raise UpdateError("настройки записаны, но AmneziaWG не переподключился за 40 секунд")


def verify_app_version() -> str:
    try:
        with APP_INFO_PLIST.open("rb") as plist_file:
            info = plistlib.load(plist_file)
        version = str(info["CFBundleShortVersionString"])
        major = int(version.split(".", 1)[0])
    except (OSError, KeyError, ValueError, plistlib.InvalidFileException) as exc:
        raise UpdateError("не удалось определить версию AmneziaVPN") from exc
    if major != SUPPORTED_APP_MAJOR:
        raise UpdateError(
            f"AmneziaVPN {version} не поддерживается updater'ом; ожидается major {SUPPORTED_APP_MAJOR}"
        )
    return version


def apply_preferences(
    helper_path: Path,
    state_dir: Path,
    managed_path: Path,
    previous_managed: list[str],
    cidrs: list[str],
) -> tuple[bool, int]:
    _, preferences = export_preferences()
    current_state = route_state(preferences)
    current_sites = current_state["sites"]
    desired_sites = merge_except_sites(current_sites, previous_managed, cidrs)
    manual_count = len(desired_sites) - len(cidrs)
    desired_state = {
        "sites": desired_sites,
        "mode": ROUTE_MODE_VPN_ALL_EXCEPT_SITES,
        "enabled": True,
    }
    needs_change = current_state != desired_state
    if not needs_change:
        atomic_write(managed_path, json_bytes(cidrs))
        return False, manual_count

    pending_path = state_dir / PENDING_FILENAME
    session = inspect_amnezia(preferences)
    if session.was_running and not session.was_connected:
        raise UpdateError(
            "AmneziaVPN открыта без обнаруженного AmneziaWG-туннеля; "
            "обновление отложено до закрытия GUI или подключения AmneziaWG"
        )
    atomic_write(
        pending_path,
        json_bytes({"phase": "stopping", "session": session_document(session)}),
    )
    stop_attempted = False
    route_resolved = False
    try:
        stop_attempted = True
        try:
            stop_amnezia(session)
        except SessionChanged:
            stop_attempted = False
            pending_path.unlink()
            raise
        # После полного выхода приложение сбрасывает cached QSettings на диск.
        _, preferences = export_preferences()
        current_state = route_state(preferences)
        desired_sites = merge_except_sites(current_state["sites"], previous_managed, cidrs)
        desired_state = {
            "sites": desired_sites,
            "mode": ROUTE_MODE_VPN_ALL_EXCEPT_SITES,
            "enabled": True,
        }
        manual_count = len(desired_sites) - len(cidrs)

        pending = {
            "phase": "writing",
            "session": session_document(session),
            "previous_managed": previous_managed,
            "desired_managed": cidrs,
            "previous_state": current_state,
            "desired_state": desired_state,
        }
        atomic_write(pending_path, json_bytes(pending))
        desired_path = state_dir / ".desired-routing-state.json"
        previous_path = state_dir / ".previous-routing-state.json"
        atomic_write(desired_path, json_bytes(desired_state))
        atomic_write(previous_path, json_bytes(current_state))
        protected_hash_before = protected_settings_hash(preferences)

        try:
            run_helper(helper_path, desired_path)
            _, verified = export_preferences()
            if route_state(verified) != desired_state:
                raise UpdateError("routing Preferences после записи не совпали с ожидаемыми")
            if protected_settings_hash(verified) != protected_hash_before:
                raise UpdateError("helper изменил защищённые настройки серверов")
            atomic_write(managed_path, json_bytes(cidrs))
            route_resolved = True
        except Exception:
            try:
                run_helper(helper_path, previous_path)
                _, rolled_back = export_preferences()
                if route_state(rolled_back) != current_state:
                    raise UpdateError("routing rollback не восстановил исходное состояние")
                if protected_settings_hash(rolled_back) != protected_hash_before:
                    raise UpdateError("routing rollback изменил защищённые настройки серверов")
                atomic_write(managed_path, json_bytes(previous_managed))
                route_resolved = True
            except Exception as rollback_error:
                raise UpdateError(
                    f"АВАРИЯ: routing rollback не удался; journal сохранён: {rollback_error}"
                ) from rollback_error
            raise
        finally:
            desired_path.unlink(missing_ok=True)
            previous_path.unlink(missing_ok=True)
    finally:
        if stop_attempted:
            relaunch_amnezia(session)
        if route_resolved:
            pending_path.unlink(missing_ok=True)

    return True, manual_count


def recover_pending_transaction(helper_path: Path, state_dir: Path, managed_path: Path) -> None:
    pending_path = state_dir / PENDING_FILENAME
    if not pending_path.exists():
        return
    try:
        pending = json.loads(pending_path.read_text(encoding="utf-8"))
        phase = pending["phase"]
        saved_session = load_session(pending["session"])
    except (OSError, KeyError, json.JSONDecodeError, TypeError) as exc:
        raise UpdateError(f"повреждён transaction journal {pending_path}: {exc}") from exc
    if phase == "stopping":
        relaunch_amnezia(saved_session)
        pending_path.unlink()
        print("Восстановлена AmneziaVPN после прерванной подготовки")
        return
    if phase != "writing":
        raise UpdateError(f"transaction journal содержит неизвестную фазу {phase!r}")
    try:
        previous_managed = pending["previous_managed"]
        desired_managed = pending["desired_managed"]
        previous_state = pending["previous_state"]
        desired_state = pending["desired_state"]
    except KeyError as exc:
        raise UpdateError("transaction journal содержит неполный routing state") from exc
    if not all(isinstance(items, list) for items in (previous_managed, desired_managed)):
        raise UpdateError("transaction journal содержит неверный managed state")

    _, preferences = export_preferences()
    current_state = route_state(preferences)
    current_session = inspect_amnezia(preferences)
    if current_session.was_running and not current_session.was_connected:
        raise UpdateError(
            "Recovery отложен: AmneziaVPN открыта без обнаруженного "
            "AmneziaWG-туннеля"
        )
    if current_state == desired_state:
        atomic_write(managed_path, json_bytes(desired_managed))
        relaunch_amnezia(saved_session)
        pending_path.unlink()
        print("Восстановлен commit незавершённой routing-транзакции")
        return
    if current_state == previous_state:
        atomic_write(managed_path, json_bytes(previous_managed))
        relaunch_amnezia(saved_session)
        pending_path.unlink()
        print("Отменена незавершённая routing-транзакция")
        return

    recovery_session = current_session if current_session.was_running else saved_session
    rollback_path = state_dir / ".recovery-routing-state.json"
    route_resolved = False
    stop_attempted = False
    try:
        stop_attempted = True
        try:
            stop_amnezia(current_session)
        except SessionChanged:
            stop_attempted = False
            raise
        atomic_write(rollback_path, json_bytes(previous_state))
        run_helper(helper_path, rollback_path)
        _, verified = export_preferences()
        if route_state(verified) != previous_state:
            raise UpdateError("recovery rollback не восстановил исходный routing state")
        atomic_write(managed_path, json_bytes(previous_managed))
        route_resolved = True
        print("Выполнен rollback незавершённой routing-транзакции")
    finally:
        rollback_path.unlink(missing_ok=True)
        if stop_attempted:
            relaunch_amnezia(recovery_session)
        if route_resolved:
            pending_path.unlink(missing_ok=True)


def download_routes(
    policy: dict[str, list[ipaddress.IPv4Network]],
    custom_host_policy: Iterable[dict[str, Any]],
) -> tuple[list[str], dict[str, int]]:
    all_networks: list[ipaddress.IPv4Network] = []
    source_counts: dict[str, int] = {}
    for name, minimum_count in SOURCES.items():
        url = f"{RAW_BASE}/{name}.txt"
        parsed = parse_source(name, fetch_text(url), minimum_count)
        validate_source_policy(name, parsed, policy[name])
        source_counts[name] = len(parsed)
        all_networks.extend(parsed)
    custom_networks, custom_counts = resolve_custom_routes(custom_host_policy)
    all_networks.extend(custom_networks)
    source_counts.update(custom_counts)
    networks = validate_and_collapse(all_networks)
    return [str(network) for network in networks], source_counts


def update(
    dry_run: bool = False, recover_only: bool = False, state_dir: Path = STATE_DIR
) -> int:
    if sys.platform != "darwin":
        raise UpdateError("скрипт предназначен только для macOS")
    if not APP_BUNDLE.is_dir():
        raise UpdateError(f"не найдена {APP_BUNDLE}")
    if recover_only:
        helper_path = Path(__file__).with_name("set-amnezia-routes")
        if not helper_path.is_file() or not os.access(helper_path, os.X_OK):
            raise UpdateError(f"не найден исполняемый helper {helper_path}")
        state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock_path = state_dir / "update.lock"
        with lock_path.open("a+") as lock_file:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise UpdateError("другой updater ещё работает") from exc
            recover_pending_transaction(
                helper_path, state_dir, state_dir / "managed-cidrs.json"
            )
        print("Recovery завершён; незавершённых routing-транзакций нет")
        return 0
    app_version = verify_app_version()
    custom_host_policy = load_custom_host_policy(
        Path(__file__).with_name(CUSTOM_HOST_POLICY_FILENAME)
    )
    policy_path = Path(__file__).with_name(POLICY_FILENAME)
    policy = load_policy(policy_path)

    if dry_run:
        cidrs, _ = download_routes(policy, custom_host_policy)
        print(
            f"Проверено {len(cidrs)} уникальных IPv4 CIDR из "
            f"{len(SOURCES)} RU-источников и пользовательских DNS "
            f"для AmneziaVPN {app_version}"
        )
        return 0

    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_dir, 0o700)
    helper_path = Path(__file__).with_name("set-amnezia-routes")
    if not helper_path.is_file() or not os.access(helper_path, os.X_OK):
        raise UpdateError(f"не найден исполняемый helper {helper_path}")

    lock_path = state_dir / "update.lock"
    with lock_path.open("a+") as lock_file:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("Другой updater уже работает, пропускаю запуск")
            return 0

        managed_path = state_dir / "managed-cidrs.json"
        # Recovery не зависит от сети: сначала обязательно вернуть VPN/session.
        recover_pending_transaction(helper_path, state_dir, managed_path)
        cidrs, source_counts = download_routes(policy, custom_host_policy)
        print(
            f"Проверено {len(cidrs)} уникальных IPv4 CIDR из "
            f"{len(SOURCES)} RU-источников и пользовательских DNS "
            f"для AmneziaVPN {app_version}"
        )
        previous_managed = load_string_list(managed_path)
        changed, manual_count = apply_preferences(
            helper_path, state_dir, managed_path, previous_managed, cidrs
        )

        import_payload = [{"hostname": cidr, "ip": ""} for cidr in cidrs]
        atomic_write(state_dir / "amnezia-split-routes.json", json_bytes(import_payload))
        status = {
            "changed": changed,
            "cidr_count": len(cidrs),
            "manual_entries_preserved": manual_count,
            "source_counts": source_counts,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        atomic_write(state_dir / "status.json", json_bytes(status))

    if changed:
        print(
            f"AmneziaVPN обновлена: {len(cidrs)} CIDR, сохранено ручных записей: {manual_count}. "
            "GUI и AmneziaWG безопасно перезапущены."
        )
    else:
        print(f"AmneziaVPN уже содержит актуальные {len(cidrs)} CIDR")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="скачать и проверить без записи")
    parser.add_argument("--recover-only", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--state-dir", type=Path, default=STATE_DIR, help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    try:
        return update(
            dry_run=arguments.dry_run,
            recover_only=arguments.recover_only,
            state_dir=arguments.state_dir,
        )
    except UpdateError as exc:
        print(f"ОШИБКА: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
