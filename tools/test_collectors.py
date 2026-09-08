"""Regression tests for source filtering and the shared Windows/macOS artifacts."""

import contextlib
import importlib.util
import io
import ipaddress
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import build_ru_direct as builder
import catalog
import import_external as importer
import refresh_prefixes as refresh


def row(first, last, asn=64501, country="RU"):
    return (int(ipaddress.ip_address(first)), int(ipaddress.ip_address(last)), asn, country, "Test AS")


class NetworkTests(unittest.TestCase):
    def verdict(self, rows, network="8.8.8.0/24"):
        return importer.classify(ipaddress.ip_network(network), importer.AsnTable(rows), {64501: 1}, set())[0]

    def test_foreign_asn_between_matching_endpoints_is_rejected(self):
        rows = [row("8.8.8.0", "8.8.8.63"), row("8.8.8.64", "8.8.8.127", 13335), row("8.8.8.128", "8.8.8.255")]
        self.assertNotEqual(self.verdict(rows), importer.ACCEPT)

    def test_unannounced_hole_is_rejected(self):
        self.assertNotEqual(self.verdict([row("8.8.8.0", "8.8.8.63"), row("8.8.8.128", "8.8.8.255")]), importer.ACCEPT)

    def test_country_of_every_range_is_checked(self):
        rows = [row("8.8.8.0", "8.8.8.63"), row("8.8.8.64", "8.8.8.127", country="US"), row("8.8.8.128", "8.8.8.255")]
        self.assertNotEqual(self.verdict(rows), importer.ACCEPT)

    def test_contiguous_same_owner_ranges_are_accepted(self):
        self.assertEqual(self.verdict([row("8.8.8.0", "8.8.8.127"), row("8.8.8.128", "8.8.8.255")]), importer.ACCEPT)

    def test_overlapping_table_is_rejected(self):
        with self.assertRaises(importer.ImportError_):
            importer.AsnTable([row("8.8.8.0", "8.8.8.127"), row("8.8.8.100", "8.8.8.255")])

    def test_denied_unknown_and_operator_asns_are_rejected(self):
        for asn, first, last in [(13335, "8.8.8.0", "8.8.8.255"), (64502, "8.8.8.0", "8.8.8.255"), (64501, "8.0.0.0", "8.255.255.255")]:
            self.assertNotEqual(self.verdict([row(first, last, asn)]), importer.ACCEPT)

    def test_interval_index_handles_adjacent_prefixes_and_partial_overlap(self):
        index = importer.NetworkIndex(map(ipaddress.ip_network, ["8.8.8.0/25", "8.8.8.128/25", "9.9.9.0/24"]))
        for value, expected in [("8.8.8.0/24", True), ("8.8.8.0/23", False), ("9.9.9.128/25", True), ("1.1.1.0/24", False)]:
            self.assertEqual(index.contains(ipaddress.ip_network(value)), expected)

    def test_previous_external_import_does_not_grant_asn_trust(self):
        with patch.object(catalog, "load_prefixes", return_value={"8.8.8.0/24": {"asn": 64501, "source": "external"}}):
            self.assertNotIn(64501, importer.known_asns()[0])


class SourceTests(unittest.TestCase):
    def test_exact_parent_boundary(self):
        trusted = {"example.ru"}
        self.assertEqual(catalog.external_domain_parent("api.example.ru", trusted), "example.ru")
        for value in ["example.ru", "evil-example.ru", "example.ru.evil.com", "ru"]:
            self.assertIsNone(catalog.external_domain_parent(value, trusted))

    def test_plain_domains_and_rules(self):
        self.assertEqual(importer.parse_domains("# comment\ndomain:api.example.ru\nfull:login.example.ru\n*.img.example.ru\nregexp:.*\ninclude:category-ru\n8.8.8.8"), ["api.example.ru", "login.example.ru", "img.example.ru"])

    def test_amnezia_domains_and_both_ip_fields(self):
        nets, domains = importer.parse_source(json.dumps([{"hostname": "example.ru", "ip": "8.8.8.8", "ips": ["9.9.9.9", "::1"]}, {"hostname": "1.1.1.0/24"}]), "amnezia")
        self.assertEqual(domains, ["example.ru"])
        self.assertEqual(set(map(str, nets)), {"8.8.8.8/32", "9.9.9.9/32", "1.1.1.0/24"})

    def test_import_preserves_entire_candidate_and_domain_provenance(self):
        services = catalog.load_catalog()
        parent = catalog.catalog_domains(services)[0]
        domain = "new-subdomain." + parent
        sources = [{"id": "test-a", "kind": "cidr", "url": "https://example.com/a"}, {"id": "test-b", "kind": "domains", "url": "https://example.com/b"}]
        table = importer.AsnTable([row("8.8.8.0", "8.8.8.255"), row("8.8.9.0", "8.8.9.255")])
        with tempfile.TemporaryDirectory() as temporary:
            output, report, candidates = [Path(temporary) / name for name in ("external.json", "report.md", "candidates.json")]
            args = ["import", "--output", str(output), "--report", str(report), "--candidates", str(candidates)]
            with patch.object(sys, "argv", args), patch.object(importer, "load_sources", return_value=("https://example.com/table", sources)), patch.object(importer, "known_asns", return_value=({64501: 1}, set())), patch.object(importer, "download_inputs", return_value=(b"table", {"test-a": "8.8.8.0/23\n8.8.8.0/23", "test-b": domain + "\nnew-independent.ru"})), patch.object(importer.AsnTable, "from_tsv", return_value=table), patch.object(catalog, "load_prefixes", return_value={}), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(importer.main(), 0)
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(list(result["prefixes"]), ["8.8.8.0/23"])
            self.assertEqual(result["sources"]["test-a"]["networks"], 1)
            self.assertEqual(catalog.load_external_domains(services, output)[domain], {"parent": parent, "sources": ["test-b"]})
            self.assertIn("new-independent.ru", json.loads(candidates.read_text())["domains"])
            result["domains"][domain]["parent"] = "untrusted.example"
            output.write_bytes(catalog.json_bytes(result))
            with self.assertRaises(catalog.CatalogError):
                catalog.load_external_domains(services, output)

    def test_download_failure_does_not_produce_partial_source_set(self):
        with patch.object(catalog, "http_get", side_effect=catalog.CatalogError("unavailable")):
            with self.assertRaises(catalog.CatalogError):
                importer.download_inputs("https://example.com/table", [{"id": "source", "url": "https://example.com/list"}], None)

    def test_foreign_external_snapshot_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "external.json"
            path.write_bytes(catalog.json_bytes({"version": 1, "prefixes": {"8.8.8.0/24": {"asn": 64501, "cc": "US", "as_name": "Test"}}}))
            with self.assertRaises(refresh.RefreshError):
                refresh.load_external(path)


class ArtifactTests(unittest.TestCase):
    def test_announced_asn_keeps_external_dns_prefix_in_lite(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "prefixes.json"
            with patch.object(sys, "argv", ["refresh", "--output", str(path)]), patch.object(catalog, "catalog_domains", return_value=["base.ru"]), patch.object(catalog, "load_external_domains", return_value={"new.base.ru": {"sources": ["test"]}}), patch.object(refresh, "resolve_all", return_value={"base.ru": ["1.1.1.1"], "new.base.ru": ["8.8.8.8"]}), patch.object(refresh, "cymru_lookup", return_value={"1.1.1.1": (13335, "1.1.1.0/24", "US", "Cloudflare"), "8.8.8.8": (64501, "8.8.8.0/24", "RU", "Test")}), patch.object(refresh, "load_asn_expand", return_value={64501: "Test"}), patch.object(refresh, "announced_prefixes", return_value=["8.8.8.0/24"]), patch.object(refresh, "load_external", return_value={}), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(refresh.main(), 0)
            prefixes = json.loads(path.read_text(encoding="utf-8"))["prefixes"]
            self.assertEqual(builder.build([], prefixes, ("core",))[1], ["8.8.8.0/24"])

    def test_incomplete_cymru_preserves_previous_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "prefixes.json"
            path.write_bytes(b"previous snapshot")
            with patch.object(sys, "argv", ["refresh", "--output", str(path), "--no-external"]), patch.object(catalog, "catalog_domains", return_value=["base.ru"]), patch.object(refresh, "resolve_all", return_value={"base.ru": ["1.1.1.1"]}), patch.object(refresh, "cymru_lookup", return_value={}), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(refresh.main(), 1)
            self.assertEqual(path.read_bytes(), b"previous snapshot")

    def test_external_prefixes_stay_out_of_lite(self):
        prefixes = {"8.8.8.0/24": {"source": "external"}}
        self.assertEqual(builder.build([], prefixes, ("core",))[1], [])
        self.assertEqual(builder.build([], prefixes, catalog.TIERS)[1], ["8.8.8.0/24"])

    @unittest.skipIf(sys.platform == "win32", "fcntl доступен на Linux/macOS; проверяется в Actions")
    def test_current_full_list_is_accepted_by_macos_and_ip_export_agrees(self):
        spec = importlib.util.spec_from_file_location("mac_updater", catalog.ROOT / "macos/update_amnezia_routes.py")
        updater = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(updater)
        dist = catalog.ROOT / "dist"
        domains, networks = updater.parse_import_list((dist / "amnezia-ru-direct.json").read_bytes(), "test")
        collapsed = updater.validate_and_collapse(networks)
        ip_domains, ip_networks = updater.parse_import_list((dist / "amnezia-ru-direct-ip.json").read_bytes(), "test")
        self.assertFalse(ip_domains)
        self.assertTrue(domains)
        self.assertEqual(set(map(str, collapsed)), set(map(str, updater.validate_and_collapse(ip_networks))))
        self.assertLessEqual(len(collapsed), builder.MAX_ROUTES)


if __name__ == "__main__":
    unittest.main()
