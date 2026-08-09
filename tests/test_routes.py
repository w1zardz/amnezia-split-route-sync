from __future__ import annotations

import importlib.util
import hashlib
import ipaddress
import json
import socket
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = load_module("route_generator", ROOT / "tools/generate_routes.py")
mac_updater = load_module("mac_updater", ROOT / "macos/update_amnezia_routes.py")
full_import = load_module(
    "full_import_generator", ROOT / "tools/generate_amnezia_full_import.py"
)


class GeneratorPolicyTests(unittest.TestCase):
    def test_placeholder_must_be_replaced(self) -> None:
        with self.assertRaises(generator.RouteError):
            generator.load_configuration(ROOT / "config/custom-host-policy.example.json")

    def test_empty_custom_groups_are_valid(self) -> None:
        protected, groups = generator.load_configuration(
            ROOT / "tests/fixtures/custom-host-policy.json"
        )
        self.assertEqual({ipaddress.ip_address("192.0.2.10")}, protected)
        self.assertEqual([], groups)

    def test_protected_endpoint_is_rejected_after_collapse(self) -> None:
        protected = {ipaddress.ip_address("192.0.2.10")}
        networks = [
            ipaddress.ip_network(f"192.0.2.{index * 2}/32") for index in range(40)
        ]
        with self.assertRaises(generator.RouteError):
            generator.validate_and_collapse(networks, protected)

    def test_custom_dns_must_stay_inside_reviewed_envelope(self) -> None:
        group = {
            "name": "example",
            "hosts": ["api.example.com"],
            "optional_hosts": set(),
            "allowed_networks": [ipaddress.ip_network("198.51.100.0/24")],
            "minimum_unique_ipv4": 1,
        }
        with mock.patch.object(
            generator,
            "resolve_hosts",
            return_value={"api.example.com": [ipaddress.ip_address("203.0.113.5")]},
        ):
            with self.assertRaises(generator.RouteError):
                generator.custom_routes([group])

    def test_dns_worker_returns_empty_answer_for_nxdomain(self) -> None:
        class Connection:
            payload = None

            def send(self, value):
                self.payload = value

            def close(self):
                pass

        connection = Connection()
        with mock.patch.object(generator.socket, "getaddrinfo", side_effect=socket.gaierror()):
            generator._dns_worker(["optional.example.com"], connection)
        self.assertEqual({"answers": {"optional.example.com": []}}, connection.payload)

    def test_manifest_payload_has_cidrs_only(self) -> None:
        payload = generator.json_bytes(
            [{"hostname": "198.51.100.0/24", "ip": ""}]
        ).decode("utf-8")
        self.assertNotIn("192.0.2.10", payload)
        self.assertNotIn("example.com", payload)


class MacMergeTests(unittest.TestCase):
    def test_manual_entries_are_preserved(self) -> None:
        current = {
            "manual.example.com": ["198.51.100.7"],
            "198.51.100.0/24": [],
        }
        merged = mac_updater.merge_except_sites(
            current,
            ["198.51.100.0/24"],
            ["203.0.113.0/24"],
        )
        self.assertEqual(["198.51.100.7"], merged["manual.example.com"])
        self.assertNotIn("198.51.100.0/24", merged)
        self.assertEqual([], merged["203.0.113.0/24"])

    def test_public_policy_rejects_protected_endpoint(self) -> None:
        mac_updater.PROTECTED_IPS = {ipaddress.ip_address("84.201.130.1")}
        with self.assertRaises(mac_updater.UpdateError):
            mac_updater.load_policy(ROOT / "config/route-policy.json")


class FullImportTests(unittest.TestCase):
    def test_community_payload_is_validated_and_idn_is_normalized(self) -> None:
        document = [
            {"hostname": f"service-{index}.example.ru", "ip": ""}
            for index in range(full_import.COMMUNITY_ENTRY_COUNT - 1)
        ]
        document.append({"hostname": "минздрав.рф", "ip": ""})
        payload = json.dumps(document, ensure_ascii=False).encode("utf-8")
        result = full_import.parse_community_payload(
            payload, hashlib.sha256(payload).hexdigest()
        )
        self.assertIn("xn--80aeelexi0a.xn--p1ai", result)

    def test_community_domains_are_resolved_to_ipv4_routes(self) -> None:
        def resolver(hostname, *_args):
            index = int(hostname.split("-", 1)[1].split(".", 1)[0])
            return [(None, None, None, None, (f"8.{index // 250}.{index % 250 + 1}.1", 0))]

        domains = [f"service-{index}.example.ru" for index in range(700)]
        networks, resolved = full_import.resolve_community_ipv4(domains, resolver)
        self.assertEqual(700, resolved)
        self.assertEqual(700, len(networks))

    def test_community_dns_rejects_one_ip_sinkhole(self) -> None:
        domains = [f"service-{index}.example.ru" for index in range(700)]

        def resolver(_hostname, *_args):
            return [(None, None, None, None, ("8.8.8.8", 0))]

        with self.assertRaises(full_import.ImportError):
            full_import.resolve_community_ipv4(domains, resolver)

    def test_full_import_contains_only_cidrs_without_endpoint_or_domains(self) -> None:
        entries = full_import.import_entries(["198.51.100.0/24", "203.0.113.7/32"])
        payload = generator.json_bytes(entries).decode("utf-8")
        self.assertIn("198.51.100.0/24", payload)
        self.assertNotIn("example.ru", payload)
        self.assertNotIn("192.0.2.10", payload)

    def test_full_import_rejects_protected_endpoint_from_community_dns(self) -> None:
        with self.assertRaises(full_import.ImportError):
            full_import.collapse_full_routes(
                ["198.51.100.0/24"],
                [ipaddress.ip_network("192.0.2.10/32")],
                {ipaddress.ip_address("192.0.2.10")},
            )


if __name__ == "__main__":
    unittest.main()
