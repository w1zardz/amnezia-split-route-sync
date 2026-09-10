"""Regression tests for source filtering and the shared Windows/macOS artifacts."""

import contextlib
import importlib.util
import io
import ipaddress
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import urllib.parse
from unittest.mock import patch

import build_ru_direct as builder
import catalog
import import_external as importer
import refresh_prefixes as refresh
import resolve_domains as resolver


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
        with self.assertRaises(catalog.CatalogError):
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
            with patch.object(sys, "argv", args), patch.object(importer, "load_sources", return_value=("https://example.com/table", sources)), patch.object(importer, "known_asns", return_value=({64501: 1}, set())), patch.object(importer, "download_inputs", return_value=(b"table", {"test-a": "8.8.8.0/23\n8.8.8.0/23", "test-b": domain + "\nnew-independent.ru"}, {})), patch.object(importer.AsnTable, "from_tsv", return_value=table), patch.object(catalog, "load_prefixes", return_value={}), contextlib.redirect_stdout(io.StringIO()):
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


def ru_table():
    return catalog.AsnTable([
        row("8.8.8.0", "8.8.8.255", 64502, "US"),
        row("95.213.0.0", "95.213.255.255", 64501, "RU"),
        row("104.16.0.0", "104.16.255.255", 13335, "RU"),
    ])


def answer(status, *addresses):
    return resolver.Answer(status, tuple(addresses))


class V2flyTests(unittest.TestCase):
    def test_include_cycle_attributes_and_rule_types(self):
        files = {
            "alpha": "include:beta\n# comment\ndomain:alpha.ru\nfull:login.alpha.ru @cn\nads.alpha.ru @ads\n"
                     "regexp:^x\\.ru$\nkeyword:alpha\nbare-alpha.ru # tail\ninclude:gamma @ads\nru\n",
            "beta": "include:alpha\nbeta.ru &affiliation\next:foo:bar\n",
        }
        requested = []

        def fetch_many(names):
            requested.append(list(names))
            return {name: files[name] for name in names}

        rules = importer.expand_v2fly(["alpha"], fetch_many)
        self.assertEqual(sorted(importer.parse_source("\n".join(rules), "v2fly")[1]), ["alpha.ru", "bare-alpha.ru", "beta.ru", "login.alpha.ru"])
        # Цикл alpha↔beta не перечитывает файлы, include только ради @ads не качается.
        self.assertEqual(requested, [["alpha"], ["beta"]])

    def test_include_explosion_and_bad_names_are_rejected(self):
        with self.assertRaises(importer.ImportError_):
            importer.expand_v2fly(["n0"], lambda names: {name: f"include:n{int(name[1:]) + 1}" for name in names})
        with self.assertRaises(importer.ImportError_):
            importer.expand_v2fly(["a"], lambda names: {name: "include:../secret" for name in names})


class RouteBatTests(unittest.TestCase):
    def test_route_add_masks_and_junk_lines(self):
        text = "\n".join([
            "@echo off", "rem route add 1.1.1.0 mask 255.255.255.0 0.0.0.0", ":: comment", "", "pause",
            "route add 87.240.128.0 mask 255.255.192.0 0.0.0.0",
            "route ADD 82.202.188.0 MASK 255.255.255.0 0.0.0.0\r",
            "  route -p add 5.188.150.7 mask 255.255.255.255 0.0.0.0 metric 5",
            "route add 10.0.0.0 mask 255.0.255.0 0.0.0.0",     # несплошная маска
            "route add 10.1.0.0 mask 0.0.0.255 0.0.0.0",       # hostmask, не netmask
            "route add 10.2.0.0 mask 0.0.0.0 0.0.0.0",         # /0
            "route add 10.3.0.0 mask 255.255.300.0 0.0.0.0",   # битая маска
            "route add 999.1.1.0 mask 255.255.255.0 0.0.0.0",  # битый адрес
            "route delete 9.9.9.0 mask 255.255.255.0",
            "echo route add 8.8.8.0 mask 255.255.255.0 0.0.0.0",
        ])
        networks, domains = importer.parse_source(text, "routebat")
        self.assertEqual(list(map(str, networks)), ["87.240.128.0/18", "82.202.188.0/24", "5.188.150.7/32"])
        self.assertEqual(domains, [])

    def test_domain_files_and_encoded_paths(self):
        files = {
            "vk/vk.bat": b"@echo off\r\nroute add 87.240.128.0 mask 255.255.192.0 0.0.0.0\r\n",
            "vk/vk_domain": "vk.com\r\n\r\n# comment\nm.vk.com\n*.userapi.com\nмвд.рф\n8.8.8.8\n".encode(),
            "мвд.рф.bat": "rem \xcf\xf0\xe8\xe2\xe5\xf2\n".encode("latin-1") + b"route add 82.202.190.0 mask 255.255.252.0 0.0.0.0\n",
        }
        base = "https://example.com/RU-RU/"
        requested = []

        def http_get(url, _limit):
            requested.append(url)
            return files[urllib.parse.unquote(url[len(base):])]

        source = {"id": "rb", "kind": "routebat", "url": base, "files": list(files)}
        with patch.object(catalog, "http_get", side_effect=http_get):
            networks, domains = importer.parse_source(importer.fetch_routebat(source), "routebat")
        # Адрес с битами хоста нормализуется до сети, как в parse_networks.
        self.assertEqual(list(map(str, networks)), ["87.240.128.0/18", "82.202.188.0/22"])
        self.assertEqual(domains, ["vk.com", "m.vk.com", "userapi.com", "xn--b1aew.xn--p1ai"])
        # Кириллица кодируется, / между каталогом и файлом остаётся.
        self.assertIn(base + "vk/vk_domain", requested)
        self.assertIn(base + "%D0%BC%D0%B2%D0%B4.%D1%80%D1%84.bat", requested)

    def test_bad_file_paths_are_rejected(self):
        for path in ["../secret.bat", "vk/list.txt", "/abs.bat", "a//b.bat", "a\\b.bat", 5]:
            self.assertFalse(importer.valid_routebat_path(path), path)
        self.assertTrue(importer.valid_routebat_path("wildberries/wildberries_domain"))


class DnsTests(unittest.TestCase):
    def test_compressed_cname_chain_and_foreign_owner(self):
        question = resolver.build_query("www.example.ru", 0x1234)[12:]
        cname = b"\x03cdn\xc0\x10"  # cdn + указатель на example.ru в вопросе
        target = 12 + len(question) + 12  # смещение rdata первой записи
        packet = (
            struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 3, 0, 0) + question
            + b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(cname)) + cname
            + struct.pack("!H", 0xC000 | target) + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([95, 213, 1, 1])
            + b"\x04evil\x02ru\x00" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([8, 8, 8, 8])
        )
        self.assertEqual(resolver.parse_dns_response(packet, 0x1234, "www.example.ru"), (0, ["95.213.1.1"]))

    def test_nxdomain_mismatch_truncation_and_pointer_loop(self):
        question = resolver.build_query("example.ru", 7)[12:]
        self.assertEqual(resolver.parse_dns_response(struct.pack("!HHHHHH", 7, 0x8183, 1, 0, 0, 0) + question, 7, "example.ru"), (3, []))
        with self.assertRaises(resolver.DnsMismatch):
            resolver.parse_dns_response(struct.pack("!HHHHHH", 8, 0x8180, 1, 0, 0, 0) + question, 7, "example.ru")
        with self.assertRaises(ValueError):
            resolver.parse_dns_response(struct.pack("!HHHHHH", 7, 0x8380, 1, 0, 0, 0) + question, 7, "example.ru")
        loop = struct.pack("!HHHHHH", 7, 0x8180, 1, 1, 0, 0) + question
        loop += struct.pack("!H", 0xC000 | len(loop)) + struct.pack("!HHIH", 1, 1, 60, 4) + bytes(4)
        with self.assertRaises(ValueError):
            resolver.parse_dns_response(loop, 7, "example.ru")

    def test_nxdomain_is_final_and_servfail_is_retried(self):
        for rcode, status, calls in [(3, resolver.EMPTY, 1), (2, resolver.FAIL, resolver.RETRIES + 1)]:
            probe = resolver.Resolver("test", doh=("example.com", "/q"))
            with patch.object(resolver.Resolver, "query", return_value=(rcode, [])) as query, patch.object(resolver.time, "sleep"):
                self.assertEqual(probe.ask("example.ru", 0)[0], status)
            self.assertEqual(query.call_count, calls)

    def test_answers_merge_addresses_and_finality(self):
        self.assertEqual(resolver.merge_answers([answer(resolver.FAIL), answer(resolver.EMPTY)]).status, resolver.EMPTY)
        self.assertEqual(resolver.merge_answers([answer(resolver.FAIL), answer(resolver.FAIL)]).status, resolver.FAIL)
        self.assertEqual(resolver.merge_answers([answer(resolver.OK, "95.213.0.9"), answer(resolver.OK, "95.213.0.10", "95.213.0.9")]), answer(resolver.OK, "95.213.0.9", "95.213.0.10"))

    def test_address_filter_keeps_only_russian_non_cdn_ipv4(self):
        table = ru_table()
        verdicts = {address: resolver.address_verdict(address, table)[0] for address in ["95.213.0.1", "104.16.0.1", "8.8.8.8", "10.0.0.1", "1.1.1.1"]}
        self.assertEqual(verdicts, {"95.213.0.1": resolver.ACCEPT, "104.16.0.1": resolver.GLOBAL_CDN, "8.8.8.8": resolver.FOREIGN, "10.0.0.1": resolver.NOT_PUBLIC, "1.1.1.1": resolver.NO_ROW})
        many = [f"95.213.0.{index}" for index in range(20, 0, -1)] + ["8.8.8.8"]
        self.assertEqual(resolver.ru_addresses(many, table), [f"95.213.0.{index}" for index in range(1, 9)])

    def test_snapshot_keeps_stale_ips_and_refuses_throttled_run(self):
        domains = ["a.ru", "b.ru", "c.ru", "d.ru", "e.ru"]
        good = {"a.ru": answer(resolver.OK, "95.213.0.1", "8.8.8.8"), "b.ru": answer(resolver.FAIL), "c.ru": answer(resolver.EMPTY), "d.ru": answer(resolver.OK, "104.16.0.1"), "e.ru": answer(resolver.OK, "95.213.0.7")}
        throttled = {domain: answer(resolver.FAIL) for domain in domains}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "domain-ips.json"
            path.write_bytes(catalog.json_bytes({"version": 1, "domains": {"b.ru": ["95.213.0.5"], "c.ru": ["95.213.0.6"]}}))
            for answers, code in [(good, 0), (throttled, 1)]:
                with patch.object(sys, "argv", ["resolve", "--output", str(path)]), patch.object(resolver, "full_list_domains", return_value=domains), patch.object(catalog, "asn_table_url", return_value="https://example.com/table"), patch.object(catalog, "load_asn_table", return_value=ru_table()), patch.object(resolver, "resolve_many", return_value=answers), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(resolver.main(), code)
            result = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(result["domains"], {"a.ru": ["95.213.0.1"], "b.ru": ["95.213.0.5"], "e.ru": ["95.213.0.7"]})
            self.assertEqual((result["resolved"], result["total"]), (3, 5))
            self.assertEqual(catalog.load_domain_ips(path)["b.ru"], ["95.213.0.5"])


class ExternalRootTests(unittest.TestCase):
    def run_import(self, temporary, sources, texts, answers, failures=None):
        output, report, candidates = [Path(temporary) / name for name in ("external.json", "report.md", "candidates.json")]
        args = ["import", "--output", str(output), "--report", str(report), "--candidates", str(candidates)]
        with patch.object(sys, "argv", args), patch.object(importer, "load_sources", return_value=("https://example.com/table", sources)), patch.object(importer, "known_asns", return_value=({64501: 1}, set())), patch.object(importer, "download_inputs", return_value=(b"table", texts, failures or {})), patch.object(importer.AsnTable, "from_tsv", return_value=ru_table()), patch.object(catalog, "load_prefixes", return_value={}), patch.object(resolver, "resolve_many", return_value=answers), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = importer.main()
        return code, output, report, candidates

    def test_root_needs_every_address_russian(self):
        services = catalog.load_catalog()
        parent = catalog.catalog_domains(services)[0]
        sources = [{"id": "roots-src", "kind": "domains", "url": "https://example.com/r", "roots": True}, {"id": "plain", "kind": "domains", "url": "https://example.com/p"}]
        texts = {"roots-src": "goodroot-test.ru\nmixedroot-test.ru\ndeadroot-test.ru\ncdnroot-test.ru\nsub." + parent, "plain": "plainonly-test.ru"}
        answers = {"goodroot-test.ru": answer(resolver.OK, "95.213.0.1"), "mixedroot-test.ru": answer(resolver.OK, "95.213.0.1", "8.8.8.8"), "deadroot-test.ru": answer(resolver.EMPTY), "cdnroot-test.ru": answer(resolver.OK, "104.16.0.1")}
        with tempfile.TemporaryDirectory() as temporary:
            code, output, report, candidates = self.run_import(temporary, sources, texts, answers)
            self.assertEqual(code, 0)
            roots = catalog.load_external_roots(services, output)
            self.assertEqual(roots, {"goodroot-test.ru": {"sources": ["roots-src"], "asn": [64501]}})
            self.assertIn("sub." + parent, json.loads(output.read_text(encoding="utf-8"))["domains"])
            rejected = json.loads(candidates.read_text(encoding="utf-8"))["domains"]
            self.assertEqual(rejected["mixedroot-test.ru"], {"sources": ["roots-src"], "reason": resolver.FOREIGN, "asn": [64502]})
            self.assertEqual(rejected["cdnroot-test.ru"]["reason"], resolver.GLOBAL_CDN)
            self.assertEqual(rejected["deadroot-test.ru"]["reason"], importer.ROOT_UNRESOLVED)
            self.assertNotIn("reason", rejected["plainonly-test.ru"])  # без флага roots домен не проверяется
            self.assertIn("Корневые домены — принято 1", report.read_text(encoding="utf-8"))

            # Молчание DNS не выкидывает вчерашний корень.
            answers["goodroot-test.ru"] = answer(resolver.FAIL)
            self.assertEqual(self.run_import(temporary, sources, texts, answers)[0], 0)
            self.assertIn("goodroot-test.ru", catalog.load_external_roots(services, output))

            document = json.loads(output.read_text(encoding="utf-8"))
            for tampered in [{"sub2." + parent: {"sources": ["x"], "asn": [64501]}}, {"cf-test.ru": {"sources": ["x"], "asn": [13335]}}]:
                output.write_bytes(catalog.json_bytes({**document, "roots": tampered}))
                with self.assertRaises(catalog.CatalogError):
                    catalog.load_external_roots(services, output)

    def test_throttled_dns_does_not_rewrite_roots(self):
        sources = [{"id": "roots-src", "kind": "domains", "url": "https://example.com/r", "roots": True}]
        with tempfile.TemporaryDirectory() as temporary:
            code, output, _report, _candidates = self.run_import(temporary, sources, {"roots-src": "a-test.ru\nb-test.ru"}, {"a-test.ru": answer(resolver.FAIL), "b-test.ru": answer(resolver.FAIL)})
            self.assertEqual(code, 1)
            self.assertFalse(output.exists())

    def test_optional_source_failure_is_a_warning(self):
        sources = [{"id": "required", "kind": "cidr", "url": "https://example.com/a"}, {"id": "gone", "kind": "amnezia", "url": "https://example.com/b", "optional": True}, {"id": "empty", "kind": "domains", "url": "https://example.com/c", "optional": True}, {"id": "broken", "kind": "amnezia", "url": "https://example.com/d", "optional": True}]
        texts = {"required": "95.213.0.0/24", "gone": None, "empty": "# ничего", "broken": "{not json"}
        with tempfile.TemporaryDirectory() as temporary:
            code, output, report, _candidates = self.run_import(temporary, sources, texts, {}, {"gone": "не загрузился: HTTP 404"})
            self.assertEqual(code, 0)
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(list(result["prefixes"]), ["95.213.0.0/16"])  # расширено до диапазона IP→ASN
            self.assertEqual({key for key, value in result["sources"].items() if "skipped" in value}, {"gone", "empty", "broken"})
            self.assertEqual(report.read_text(encoding="utf-8").count("пропущен"), 3)
        for source in sources:
            source["optional"] = False  # тот же сбой у обязательного источника — остановка
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(self.run_import(temporary, sources[:3], {**texts, "gone": "95.213.1.0/24"}, {})[0], 1)

    def test_download_of_optional_source_does_not_stop_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            table = Path(temporary) / "table.tsv"
            table.write_bytes(b"table")
            with patch.object(catalog, "http_get", side_effect=catalog.CatalogError("HTTP 404")):
                _payload, texts, failures = importer.download_inputs("https://example.com/table", [{"id": "opt", "url": "https://example.com/list", "optional": True}], table)
        self.assertEqual(texts, {"opt": None})
        self.assertIn("HTTP 404", failures["opt"])


class DomainIpBuildTests(unittest.TestCase):
    def build(self, temporary, snapshot, *flags):
        ips = Path(temporary) / "domain-ips.json"
        if snapshot is not None:
            ips.write_bytes(catalog.json_bytes({"version": 1, "domains": snapshot}))
        roots = {"rootone-test.ru": {"sources": ["a", "b"], "asn": [64501]}}
        args = ["build", "--output-dir", temporary, "--domain-ips", str(ips), *flags]
        with patch.object(sys, "argv", args), patch.object(catalog, "load_external_domains", return_value={}), patch.object(catalog, "load_external_roots", return_value=roots), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return builder.main()

    def test_domain_entries_carry_ips_and_roots_stay_out_of_lite(self):
        services = catalog.load_catalog()
        core = catalog.catalog_domains(services, ("core",))[0]
        snapshot = {core: ["95.213.0.1", "95.213.0.2"], "rootone-test.ru": ["95.213.0.3"], "not-in-list.ru": ["95.213.0.9"]}
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(self.build(temporary, snapshot), 0)
            dist = Path(temporary)
            full = {entry["hostname"]: entry for entry in json.loads((dist / "amnezia-ru-direct.json").read_text(encoding="utf-8"))}
            lite = {entry["hostname"]: entry for entry in json.loads((dist / "amnezia-ru-direct-lite.json").read_text(encoding="utf-8"))}
            manifest = json.loads((dist / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(full[core], {"hostname": core, "ips": ["95.213.0.1", "95.213.0.2"], "ip": "95.213.0.1"})
            self.assertEqual(full["rootone-test.ru"]["ips"], ["95.213.0.3"])
            self.assertNotIn("rootone-test.ru", lite)
            self.assertNotIn("not-in-list.ru", full)
            self.assertEqual(lite[core]["ips"], ["95.213.0.1", "95.213.0.2"])
            unresolved = next(entry for name, entry in full.items() if "/" not in name and name not in snapshot)
            self.assertEqual((unresolved["ips"], unresolved["ip"]), ([], ""))
            networks = [entry for name, entry in full.items() if "/" in name]
            self.assertTrue(networks)
            self.assertTrue(all(set(entry) == {"hostname", "ip"} for entry in networks))
            self.assertEqual((manifest["domains_with_ips"], manifest["lite_domains_with_ips"], manifest["external_roots"]), (2, 1, 1))
            self.assertIn("rootone-test.ru", (dist / "ru-direct-domains.txt").read_text(encoding="utf-8").split())
            self.assertIn("domain:rootone-test.ru", json.loads((dist / "happ-ru-direct.json").read_text(encoding="utf-8"))["DirectSites"])
            self.assertIn("корневых доменов", (dist / "RELEASE_NOTES.md").read_text(encoding="utf-8"))

            self.assertEqual(self.build(temporary, snapshot, "--no-ips"), 0)
            entries = json.loads((dist / "amnezia-ru-direct.json").read_text(encoding="utf-8"))
            self.assertTrue(all(set(entry) == {"hostname", "ip"} and entry["ip"] == "" for entry in entries))
            self.assertEqual(self.build(temporary, {core: ["10.0.0.1"]}), 1)

    def test_missing_snapshot_keeps_old_entry_format(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual(self.build(temporary, None), 0)
            entries = json.loads((Path(temporary) / "amnezia-ru-direct.json").read_text(encoding="utf-8"))
            self.assertTrue(all(set(entry) == {"hostname", "ip"} for entry in entries))

    def test_full_list_cap_prefers_subdomains_then_ranked_roots(self):
        self.assertLess(builder.MAX_FULL_ENTRIES, builder.MAX_ENTRIES)
        base, cidrs = ["a.ru", "b.ru", "c.ru", "d.ru", "e.ru"], ["95.213.0.0/24", "95.213.1.0/24"]
        subs = {"s1.a.ru": {"sources": ["x"]}, "s2.a.ru": {"sources": ["x", "y"]}}
        roots = {"r1.ru": {"sources": ["x"]}, "r3.ru": {"sources": ["x", "y"]}, "r2.ru": {"sources": ["x", "y"]}}
        domains, kept_subs, kept_roots, dropped_subs, dropped_roots = builder.fit_full_list(base, cidrs, subs, roots, limit=10)
        self.assertEqual((kept_subs, kept_roots, dropped_subs, dropped_roots), (["s2.a.ru", "s1.a.ru"], ["r2.ru"], 0, 2))
        self.assertEqual(len(domains) + len(cidrs), 10)
        _domains, kept_subs, kept_roots, dropped_subs, _ = builder.fit_full_list(base, cidrs, subs, roots, limit=8)
        self.assertEqual((kept_subs, kept_roots, dropped_subs), (["s2.a.ru"], [], 1))
        with self.assertRaises(builder.BuildError):
            builder.fit_full_list(base, cidrs, subs, roots, limit=6)
        with self.assertRaises(builder.BuildError):
            builder.guard([f"d{index}.ru" for index in range(builder.MAX_FULL_ENTRIES + 1)], [], [], "test", builder.MAX_FULL_ENTRIES)


if __name__ == "__main__":
    unittest.main()
