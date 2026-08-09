#!/usr/bin/env python3
"""Generate an AmneziaVPN IPv4 split-routing import without changing the app."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import multiprocessing
import os
import shutil
import socket
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = ROOT / "config/route-policy.json"
DEFAULT_CONFIG = ROOT / "config/custom-host-policy.json"
DEFAULT_OUTPUT = ROOT / "dist/ip-list.json"
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
MAX_DOWNLOAD_BYTES = 1_048_576


class RouteError(RuntimeError):
    pass


def fetch_text(url: str) -> str:
    if not url.startswith("https://"):
        raise RouteError("only HTTPS sources are allowed")
    curl = shutil.which("curl")
    if curl is None:
        raise RouteError("curl is required to download route sources")
    try:
        process = subprocess.run(
            [
                curl,
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
                str(MAX_DOWNLOAD_BYTES),
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
            timeout=35,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RouteError("failed to run curl for a route source") from exc
    if process.returncode != 0:
        raise RouteError("failed to download or validate a route source")
    payload = process.stdout
    if len(payload) > MAX_DOWNLOAD_BYTES:
        raise RouteError("route source is larger than 1 MiB")
    try:
        return payload.decode("utf-8")
    except UnicodeError as exc:
        raise RouteError("route source is not UTF-8") from exc


def parse_network(value: Any, label: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value, strict=True)
    except (TypeError, ValueError) as exc:
        raise RouteError(f"{label} contains an invalid CIDR") from exc
    if network.version != 4 or network.prefixlen < MIN_PREFIX_LENGTH:
        raise RouteError(f"{label} contains an unsupported or overly broad network")
    return network


def load_configuration(path: Path) -> tuple[set[ipaddress.IPv4Address], list[dict[str, Any]]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        raw_protected = document["protected_ips"]
        raw_groups = document["groups"]
    except (OSError, KeyError, json.JSONDecodeError, TypeError) as exc:
        raise RouteError("cannot read the local configuration; copy and edit the example first") from exc
    if document.get("version") != 1 or not isinstance(raw_protected, list) or not raw_protected:
        raise RouteError("configuration must contain version=1 and at least one protected IP")
    if not isinstance(raw_groups, list):
        raise RouteError("configuration groups must be an array")
    try:
        protected = {ipaddress.ip_address(value) for value in raw_protected}
    except (TypeError, ValueError) as exc:
        raise RouteError("replace the protected IP placeholder with your VPN server IPv4") from exc
    if any(address.version != 4 for address in protected):
        raise RouteError("protected_ips supports IPv4 only")

    groups: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()
    for raw_group in raw_groups:
        if not isinstance(raw_group, dict):
            raise RouteError("a custom group is not an object")
        name = raw_group.get("name")
        hosts = raw_group.get("hosts")
        optional_hosts = raw_group.get("optional_hosts")
        raw_envelopes = raw_group.get("allowed_networks")
        minimum = raw_group.get("minimum_unique_ipv4")
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(hosts, list)
            or not hosts
            or not isinstance(optional_hosts, list)
            or not isinstance(raw_envelopes, list)
            or not raw_envelopes
            or not isinstance(minimum, int)
            or minimum < 1
        ):
            raise RouteError("a custom group has an invalid schema")
        normalized_hosts: list[str] = []
        for host in hosts:
            if (
                not isinstance(host, str)
                or host != host.lower()
                or host.startswith(".")
                or host.endswith(".")
                or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-." for character in host)
                or host in seen_hosts
            ):
                raise RouteError("a custom group contains an invalid or duplicate hostname")
            seen_hosts.add(host)
            normalized_hosts.append(host)
        if (
            any(not isinstance(host, str) for host in optional_hosts)
            or len(set(optional_hosts)) != len(optional_hosts)
            or not set(optional_hosts).issubset(normalized_hosts)
        ):
            raise RouteError("optional_hosts must be a unique subset of hosts")
        envelopes = [parse_network(value, "custom allowed_networks") for value in raw_envelopes]
        if any(address in network for network in envelopes for address in protected):
            raise RouteError("a custom allowed network contains a protected VPN endpoint")
        groups.append(
            {
                "name": name,
                "hosts": normalized_hosts,
                "optional_hosts": set(optional_hosts),
                "allowed_networks": envelopes,
                "minimum_unique_ipv4": minimum,
            }
        )
    return protected, groups


def load_policy(
    path: Path, protected: set[ipaddress.IPv4Address]
) -> dict[str, list[ipaddress.IPv4Network]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        raw_sources = document["sources"]
    except (OSError, KeyError, json.JSONDecodeError, TypeError) as exc:
        raise RouteError("cannot read the reviewed route policy") from exc
    if document.get("version") != 1 or not isinstance(raw_sources, dict):
        raise RouteError("route policy has an unsupported schema")
    if set(raw_sources) != set(SOURCES):
        raise RouteError("route policy contains an unexpected source set")
    policy: dict[str, list[ipaddress.IPv4Network]] = {}
    for name, values in raw_sources.items():
        if not isinstance(values, list) or not values:
            raise RouteError("route policy contains an empty source envelope")
        networks = [parse_network(value, "route policy") for value in values]
        if any(address in network for network in networks for address in protected):
            raise RouteError("route policy contains a protected VPN endpoint")
        policy[name] = networks
    return policy


def parse_source(name: str, text: str, minimum: int) -> list[ipaddress.IPv4Network]:
    result: list[ipaddress.IPv4Network] = []
    for raw_line in text.splitlines():
        value = raw_line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise RouteError(f"{name} contains an invalid network") from exc
        if network.version == 6:
            continue
        if network.prefixlen < MIN_PREFIX_LENGTH:
            raise RouteError(f"{name} contains an overly broad network")
        result.append(network)
    if len(result) < minimum:
        raise RouteError(f"{name} returned too few IPv4 networks")
    return result


def _dns_worker(hosts: list[str], connection) -> None:
    try:
        answers: dict[str, list[str]] = {}
        for host in hosts:
            try:
                values = {
                    item[4][0]
                    for item in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
                }
            except socket.gaierror:
                values = set()
            answers[host] = sorted(values)
        connection.send({"answers": answers})
    except Exception as exc:
        connection.send({"error": str(exc)})
    finally:
        connection.close()


def resolve_hosts(hosts: list[str], timeout: int = 30) -> dict[str, list[ipaddress.IPv4Address]]:
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=_dns_worker, args=(hosts, send))
    process.start()
    send.close()
    try:
        if not receive.poll(timeout):
            process.terminate()
            process.join(5)
            raise RouteError("DNS resolution timed out")
        payload = receive.recv()
    finally:
        receive.close()
        if process.is_alive():
            process.terminate()
        process.join(5)
    if "error" in payload:
        raise RouteError("DNS resolution failed for a configured host")
    return {
        host: [ipaddress.ip_address(value) for value in values]
        for host, values in payload["answers"].items()
    }


def custom_routes(groups: Iterable[dict[str, Any]]) -> tuple[list[ipaddress.IPv4Network], int]:
    networks: list[ipaddress.IPv4Network] = []
    resolved_count = 0
    for group in groups:
        answers = resolve_hosts(group["hosts"])
        if set(answers) != set(group["hosts"]):
            raise RouteError("DNS returned an incomplete custom-host result")
        addresses: set[ipaddress.IPv4Address] = set()
        for host in group["hosts"]:
            host_addresses = answers[host]
            if not host_addresses and host not in group["optional_hosts"]:
                raise RouteError("a required custom host has no IPv4 address")
            for address in host_addresses:
                if not any(address in envelope for envelope in group["allowed_networks"]):
                    raise RouteError("custom DNS returned an address outside its reviewed envelope")
                addresses.add(address)
        if len(addresses) < group["minimum_unique_ipv4"]:
            raise RouteError("a custom group returned too few unique IPv4 addresses")
        networks.extend(ipaddress.ip_network(f"{address}/32") for address in addresses)
        resolved_count += len(addresses)
    return networks, resolved_count


def validate_and_collapse(
    networks: Iterable[ipaddress.IPv4Network], protected: set[ipaddress.IPv4Address]
) -> list[ipaddress.IPv4Network]:
    collapsed = list(ipaddress.collapse_addresses(networks))
    if not MIN_TOTAL_ROUTES <= len(collapsed) <= MAX_TOTAL_ROUTES:
        raise RouteError("route count is outside the safe range")
    if sum(network.num_addresses for network in collapsed) > MAX_TOTAL_ADDRESSES:
        raise RouteError("routes cover too many IPv4 addresses")
    if any(address in network for network in collapsed for address in protected):
        raise RouteError("generated routes contain a protected VPN endpoint")
    return sorted(collapsed, key=lambda item: (int(item.network_address), item.prefixlen))


def build_routes(
    policy: dict[str, list[ipaddress.IPv4Network]],
    protected: set[ipaddress.IPv4Address],
    groups: list[dict[str, Any]],
) -> tuple[list[str], dict[str, int], int]:
    networks: list[ipaddress.IPv4Network] = []
    counts: dict[str, int] = {}
    for name, minimum in SOURCES.items():
        parsed = parse_source(name, fetch_text(f"{RAW_BASE}/{name}.txt"), minimum)
        if any(not any(network.subnet_of(envelope) for envelope in policy[name]) for network in parsed):
            raise RouteError(f"{name} changed outside its reviewed envelope")
        counts[name] = len(parsed)
        networks.extend(parsed)
    extra, custom_count = custom_routes(groups)
    networks.extend(extra)
    collapsed = validate_and_collapse(networks, protected)
    return [str(network) for network in collapsed], counts, custom_count


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()
    try:
        protected, groups = load_configuration(arguments.config)
        policy = load_policy(arguments.policy, protected)
        routes, source_counts, custom_count = build_routes(policy, protected, groups)
        payload = json_bytes([{"hostname": route, "ip": ""} for route in routes])
        if arguments.dry_run:
            print(f"validated {len(routes)} IPv4 CIDR; no files changed")
            return 0
        atomic_write(arguments.output, payload)
        manifest = {
            "version": 1,
            "cidr_count": len(routes),
            "custom_ipv4_count": custom_count,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "source_counts": source_counts,
        }
        atomic_write(arguments.output.with_suffix(".manifest.json"), json_bytes(manifest))
        print(f"generated {len(routes)} IPv4 CIDR; sha256={manifest['sha256']}")
        return 0
    except RouteError as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
