"""Regression tests for replacing managed routes without touching the real Mac."""

from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "macos_updater", Path(__file__).with_name("update_amnezia_routes.py")
)
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


class ManagedRouteReplacementTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.state_dir = root / "state"
        app = root / "AmneziaVPN.app"
        app.mkdir()
        helper = root / "set-amnezia-routes"
        helper.write_text("mock helper; never executed", encoding="utf-8")
        helper.chmod(0o700)
        self.manual = {"manual.example": ["203.0.113.20"]}
        self.preferences = {
            updater.PREFS_ROUTE_KEY: deepcopy(self.manual),
            updater.PREFS_MODE_KEY: updater.ROUTE_MODE_VPN_ALL_EXCEPT_SITES,
            updater.PREFS_ENABLED_KEY: True,
            "Servers.testConfiguration": {"unchanged": True},
        }
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(redirect_stdout(io.StringIO()))
        stack.enter_context(patch.object(updater.sys, "platform", "darwin"))
        stack.enter_context(patch.object(updater, "APP_BUNDLE", app))
        stack.enter_context(patch.object(updater, "__file__", str(root / "updater.py")))
        stack.enter_context(patch.object(updater, "verify_app_version", return_value="5.0"))
        stack.enter_context(patch.object(updater, "load_protected_ips"))
        stack.enter_context(patch.object(updater, "warn_broken_ipv6"))
        stack.enter_context(patch.object(
            updater, "export_preferences", side_effect=lambda: (b"", deepcopy(self.preferences))
        ))
        stack.enter_context(patch.object(
            updater, "inspect_amnezia", return_value=updater.AmneziaSession(True, True, True, 2)
        ))
        self.stop = stack.enter_context(patch.object(updater, "stop_amnezia"))
        self.relaunch = stack.enter_context(patch.object(updater, "relaunch_amnezia"))
        self.helper = stack.enter_context(patch.object(updater, "run_helper", side_effect=self.apply_state))
        self.download = stack.enter_context(patch.object(updater, "download_list"))

    def apply_state(self, helper_path, state_path):
        state = json.loads(state_path.read_text(encoding="utf-8"))
        for state_key, preference_key in (
            ("sites", updater.PREFS_ROUTE_KEY),
            ("mode", updater.PREFS_MODE_KEY),
            ("enabled", updater.PREFS_ENABLED_KEY),
        ):
            self.preferences[preference_key] = state[state_key]

    def run_update(self, domains, cidrs, with_domains=False):
        self.download.return_value = (domains, cidrs)
        self.assertEqual(updater.update(
            state_dir=self.state_dir,
            source="https://example.com/routes.json",
            with_domains=with_domains,
        ), 0)

    def read_json(self, filename):
        return json.loads((self.state_dir / filename).read_text(encoding="utf-8"))

    def test_successive_lists_remove_stale_cidrs_and_domains_but_keep_manual_entries(self):
        self.run_update(
            ["old.example", "shared.example"], ["8.8.8.0/24", "1.1.1.0/24"], True
        )
        self.preferences[updater.PREFS_ROUTE_KEY]["shared.example"] = ["203.0.113.31"]
        self.run_update(
            ["shared.example", "new.example"], ["1.1.1.0/24", "9.9.9.0/24"], True
        )
        self.assertEqual(self.preferences[updater.PREFS_ROUTE_KEY], {
            **self.manual,
            "shared.example": ["203.0.113.31"],
            "new.example": [],
            "1.1.1.0/24": [],
            "9.9.9.0/24": [],
        })
        self.assertEqual(self.read_json("managed-cidrs.json"), [
            "shared.example", "new.example", "1.1.1.0/24", "9.9.9.0/24"
        ])

        # Switching to the default IP-only policy also removes previously managed names.
        self.run_update(["ignored.example"], ["9.9.9.0/24", "8.8.4.0/24"])
        self.assertEqual(self.preferences[updater.PREFS_ROUTE_KEY], {
            **self.manual, "9.9.9.0/24": [], "8.8.4.0/24": []
        })
        self.assertEqual(self.read_json("managed-cidrs.json"), ["9.9.9.0/24", "8.8.4.0/24"])
        self.assertEqual(self.read_json("status.json")["manual_entries_preserved"], 1)
        self.assertEqual(self.preferences["Servers.testConfiguration"], {"unchanged": True})

    def test_unchanged_list_does_not_restart_app_or_discard_resolved_values(self):
        self.run_update(["shared.example"], ["1.1.1.0/24"], True)
        self.preferences[updater.PREFS_ROUTE_KEY]["shared.example"] = ["203.0.113.31"]
        before = deepcopy(self.preferences)
        for mock in (self.stop, self.relaunch, self.helper):
            mock.reset_mock()

        self.run_update(["shared.example"], ["1.1.1.0/24"], True)

        self.assertEqual(self.preferences, before)
        self.assertFalse(self.read_json("status.json")["changed"])
        self.stop.assert_not_called()
        self.relaunch.assert_not_called()
        self.helper.assert_not_called()

    def test_failed_application_restores_routes_ownership_and_previous_local_list(self):
        self.run_update(["old.example"], ["8.8.8.0/24"], True)
        before_preferences = deepcopy(self.preferences)
        before_files = {path.name: path.read_bytes() for path in self.state_dir.iterdir()}
        for mock in (self.stop, self.relaunch, self.helper):
            mock.reset_mock()

        def fail_after_first_write(helper_path, state_path):
            self.apply_state(helper_path, state_path)
            if self.helper.call_count == 1:
                raise updater.UpdateError("simulated failure after preference write")

        self.helper.side_effect = fail_after_first_write
        with self.assertRaisesRegex(updater.UpdateError, "simulated failure"):
            self.run_update([], ["9.9.9.0/24"])

        self.assertEqual(self.preferences, before_preferences)
        self.assertEqual(
            {path.name: path.read_bytes() for path in self.state_dir.iterdir()}, before_files
        )
        self.assertEqual(self.helper.call_count, 2)
        self.stop.assert_called_once()
        self.relaunch.assert_called_once()

    def test_local_list_and_state_are_overwritten_without_accumulating_versions(self):
        expected_filenames = {
            "managed-cidrs.json", "amnezia-split-routes.json", "status.json", "update.lock"
        }
        for cidrs in (["8.8.8.0/24", "1.1.1.0/24"], ["9.9.9.0/24"], ["8.8.4.0/24"]):
            with self.subTest(cidrs=cidrs):
                self.run_update([], cidrs)
                self.assertEqual({path.name for path in self.state_dir.iterdir()}, expected_filenames)
                self.assertEqual(self.read_json("managed-cidrs.json"), cidrs)
                self.assertEqual(self.read_json("amnezia-split-routes.json"), [
                    {"hostname": cidr, "ip": ""} for cidr in cidrs
                ])
                status = self.read_json("status.json")
                self.assertEqual(status["entry_count"], len(cidrs))
                self.assertEqual(status["cidr_count"], len(cidrs))
                self.assertEqual(status["manual_entries_preserved"], 1)


if __name__ == "__main__":
    unittest.main()
