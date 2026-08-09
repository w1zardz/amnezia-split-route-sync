from __future__ import annotations

import importlib.util
import ipaddress
import socket
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = load_module("route_generator", ROOT / "tools/generate_routes.py")
mac_updater = load_module("mac_updater", ROOT / "macos/update_amnezia_routes.py")


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


if __name__ == "__main__":
    unittest.main()
