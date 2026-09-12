#!/usr/bin/env python3
"""Summarize Amnezia logs without printing server keys, URLs or raw log lines.

Usage: python tools/analyze_amnezia_log.py client.log service.log
The combined timeline uses UTC timestamps; overlapping log copies count twice.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime
import ipaddress
import json
from pathlib import Path
import re
from typing import Iterable


STAMP = re.compile(r"^\[([^]]+)\]")
EXCLUSION = re.compile(r"Adding exclusion route for\s+(\S+)")
CAPTURE = re.compile(r"Capturing route to\s+(\S+)")
ERROR = re.compile(r"Failed to update route:\s*(\d+)")


def analyze(lines: Iterable[str]) -> dict:
    events: dict[str, list[datetime]] = {}
    routes: list[ipaddress.IPv4Network] = []
    captures: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    invalid = 0
    changes = 0
    for line in lines:
        match = STAMP.match(line)
        if not match:
            continue
        try:
            stamp = datetime.fromisoformat(match[1].replace("Z", "+00:00"))
        except ValueError:
            continue
        for event, marker in (
            ("connection_started", "Trying to connect to VPN"),
            ("tunnel_started", "Startup complete"),
            ("handshake_received", "Received handshake response"),
            ("client_connected", "Parse command: connected"),
            ("route_changes", "WindowsRouteMonitor : Routes changed"),
            ("exclusions", "Adding exclusion route for"),
        ):
            if marker in line:
                events.setdefault(event, []).append(stamp)
        if "WindowsRouteMonitor : Routes changed" in line:
            changes += 1
        if match := ERROR.search(line):
            errors[match[1]] += 1
        if match := CAPTURE.search(line):
            try:
                captures[str(ipaddress.ip_network(match[1]))] += 1
            except ValueError:
                pass
        if match := EXCLUSION.search(line):
            try:
                network = ipaddress.ip_network(match[1])
                if network.version == 4:
                    routes.append(network)
            except ValueError:
                invalid += 1

    def duration(start: str, end: str) -> float | None:
        # Only compare first events when their order makes sense. Multiple
        # attempts are identified in event counts and need separate log slices.
        if not events.get(start) or not events.get(end):
            return None
        seconds = (min(events[end]) - min(events[start])).total_seconds()
        return round(seconds, 3) if seconds >= 0 else None

    return {
        "events": {
            name: {"count": len(times), "first": min(times).isoformat(), "last": max(times).isoformat()}
            for name, times in sorted(events.items())
        },
        "first_connection_seconds": duration("connection_started", "client_connected"),
        "first_handshake_to_connected_seconds": duration("handshake_received", "client_connected"),
        "route_change_notifications": changes,
        "route_update_errors": dict(errors.most_common()),
        "most_captured_routes": dict(captures.most_common(10)),
        "route_candidates": len(routes),
        "unique_routes": len(set(routes)),
        "compacted_routes": len(list(ipaddress.collapse_addresses(routes))),
        "invalid_route_additions": invalid,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logs", nargs="+", type=Path)
    args = parser.parse_args()

    def lines():
        for path in args.logs:
            with path.open(encoding="utf-8-sig", errors="replace") as stream:
                yield from stream

    try:
        print(json.dumps(analyze(lines()), ensure_ascii=False, indent=2))
    except OSError as exc:
        parser.exit(1, f"Cannot read log: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
