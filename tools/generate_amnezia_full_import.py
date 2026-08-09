#!/usr/bin/env python3
"""Generate one AmneziaVPN JSON import with reviewed CIDRs and community domains."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

import generate_routes


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = ROOT / "config/route-policy.json"
DEFAULT_CONFIG = ROOT / "config/custom-host-policy.json"
DEFAULT_OUTPUT = ROOT / "dist/amnezia-full-import.json"
COMMUNITY_REPOSITORY = "https://github.com/kozlovartem20201/amnezia-vpn-russia"
COMMUNITY_COMMIT = "e2de603048f58fd65289b36284e6fea125c1ae97"
COMMUNITY_URL = (
    "https://raw.githubusercontent.com/kozlovartem20201/amnezia-vpn-russia/"
    f"{COMMUNITY_COMMIT}/tunneling-list.json"
)
COMMUNITY_SHA256 = "e4af74a1fa3758605521cbf5f5359dba174c9d50f8acc88b5433d1a3422cfd8c"
COMMUNITY_ENTRY_COUNT = 858
MAX_COMMUNITY_BYTES = 262_144
MIN_RESOLVED_COMMUNITY_HOSTS = 700
MIN_COMMUNITY_IPV4 = 700
MAX_COMMUNITY_IPV4 = 4_096
MAX_FULL_IMPORT_ROUTES = 2_048
HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class ImportError(RuntimeError):
    pass


def fetch_bytes(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ImportError("only HTTPS community sources are allowed")
    curl = shutil.which("curl")
    if curl is None:
        raise ImportError("curl is required to download the community list")
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
                str(MAX_COMMUNITY_BYTES),
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
        raise ImportError("failed to run curl for the community list") from exc
    if process.returncode != 0:
        raise ImportError("failed to download the pinned community list")
    if len(process.stdout) > MAX_COMMUNITY_BYTES:
        raise ImportError("community list is larger than the accepted limit")
    return process.stdout


def normalize_hostname(value: Any) -> str:
    if not isinstance(value, str) or value != value.strip().lower():
        raise ImportError("community list contains a malformed hostname")
    try:
        hostname = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ImportError("community list contains an invalid IDN hostname") from exc
    labels = hostname.split(".")
    if (
        len(hostname) > 253
        or len(labels) < 2
        or any(HOST_LABEL.fullmatch(label) is None for label in labels)
    ):
        raise ImportError("community list contains an invalid hostname")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return hostname
    raise ImportError("community list must not contain literal IP addresses")


def parse_community_payload(payload: bytes, expected_sha256: str) -> list[str]:
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ImportError("community list SHA-256 does not match the reviewed snapshot")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ImportError("community list is not valid UTF-8 JSON") from exc
    if not isinstance(document, list) or len(document) != COMMUNITY_ENTRY_COUNT:
        raise ImportError("community list has an unexpected entry count")
    hostnames: list[str] = []
    for item in document:
        if not isinstance(item, dict) or set(item) != {"hostname", "ip"} or item["ip"] != "":
            raise ImportError("community list has an unexpected Amnezia JSON schema")
        hostnames.append(normalize_hostname(item["hostname"]))
    if len(hostnames) != len(set(hostnames)):
        raise ImportError("community list contains duplicate hostnames")
    return hostnames


def resolve_community_ipv4(
    domains: Iterable[str],
    resolver: Any = socket.getaddrinfo,
) -> tuple[list[ipaddress.IPv4Network], int]:
    domain_list = list(domains)

    def resolve_one(hostname: str) -> tuple[str, list[ipaddress.IPv4Address]]:
        try:
            answers = resolver(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        except socket.gaierror:
            return hostname, []
        addresses = sorted({ipaddress.ip_address(answer[4][0]) for answer in answers})
        return hostname, [address for address in addresses if address.version == 4]

    answers: dict[str, list[ipaddress.IPv4Address]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        futures = {executor.submit(resolve_one, hostname): hostname for hostname in domain_list}
        for future in concurrent.futures.as_completed(futures):
            hostname, addresses = future.result()
            answers[hostname] = addresses
    resolved_hosts = sum(bool(answers.get(hostname)) for hostname in domain_list)
    if resolved_hosts < MIN_RESOLVED_COMMUNITY_HOSTS:
        raise ImportError("too few community domains resolved to IPv4; keeping last-good output")
    unique_addresses = sorted({address for values in answers.values() for address in values})
    if any(not address.is_global for address in unique_addresses):
        raise ImportError("community DNS returned a non-global IPv4 address")
    if not MIN_COMMUNITY_IPV4 <= len(unique_addresses) <= MAX_COMMUNITY_IPV4:
        raise ImportError("community DNS returned an unsafe IPv4 count")
    return [ipaddress.ip_network(f"{address}/32") for address in unique_addresses], resolved_hosts


def collapse_full_routes(
    cidrs: Iterable[str],
    community_networks: Iterable[ipaddress.IPv4Network],
    protected: set[ipaddress.IPv4Address],
) -> list[str]:
    networks = [ipaddress.ip_network(value, strict=True) for value in cidrs]
    networks.extend(community_networks)
    collapsed = list(ipaddress.collapse_addresses(networks))
    if not generate_routes.MIN_TOTAL_ROUTES <= len(collapsed) <= MAX_FULL_IMPORT_ROUTES:
        raise ImportError("full import route count is outside the safe range")
    if sum(network.num_addresses for network in collapsed) > generate_routes.MAX_TOTAL_ADDRESSES:
        raise ImportError("full import covers too many IPv4 addresses")
    if any(address in network for network in collapsed for address in protected):
        raise ImportError("full import contains a protected VPN endpoint")
    return [
        str(network)
        for network in sorted(
            collapsed, key=lambda item: (int(item.network_address), item.prefixlen)
        )
    ]


def import_entries(cidrs: Iterable[str]) -> list[dict[str, str]]:
    values = sorted(set(cidrs), key=lambda value: ipaddress.ip_network(value))
    return [{"hostname": value, "ip": ""} for value in values]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()
    try:
        protected, groups = generate_routes.load_configuration(arguments.config)
        policy = generate_routes.load_policy(arguments.policy, protected)
        cidrs, source_counts, custom_ipv4_count = generate_routes.build_routes(
            policy, protected, groups
        )
        community_domains = parse_community_payload(
            fetch_bytes(COMMUNITY_URL), COMMUNITY_SHA256
        )
        community_networks, resolved_community_hosts = resolve_community_ipv4(
            community_domains
        )
        full_cidrs = collapse_full_routes(cidrs, community_networks, protected)
        entries = import_entries(full_cidrs)
        payload = generate_routes.json_bytes(entries)
        manifest = {
            "version": 1,
            "entry_count": len(entries),
            "cidr_count": len(full_cidrs),
            "base_cidr_count": len(cidrs),
            "community_source_hostname_count": len(community_domains),
            "community_resolved_hostname_count": resolved_community_hosts,
            "community_ipv4_count": len(community_networks),
            "custom_ipv4_count": custom_ipv4_count,
            "community_repository": COMMUNITY_REPOSITORY,
            "community_commit": COMMUNITY_COMMIT,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "source_counts": source_counts,
        }
        if arguments.dry_run:
            print(
                f"validated {len(entries)} Amnezia entries: "
                f"{len(community_networks)} community IPv4 from "
                f"{resolved_community_hosts}/{len(community_domains)} domains + "
                f"{len(cidrs)} base CIDR; "
                "no files changed"
            )
            return 0
        generate_routes.atomic_write(arguments.output, payload)
        generate_routes.atomic_write(
            arguments.output.with_suffix(".manifest.json"),
            generate_routes.json_bytes(manifest),
        )
        print(f"generated {len(entries)} Amnezia entries; sha256={manifest['sha256']}")
        return 0
    except (generate_routes.RouteError, ImportError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    generate_routes.multiprocessing.freeze_support()
    raise SystemExit(main())
