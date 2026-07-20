from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PYTHON_CLI_PATH = ROOT / "scripts" / "hotdeal_focus_cli.py"
POWERSHELL_CLI_PATH = ROOT / "scripts" / "adguard_windows_cli.ps1"
BROWSER_PROBE_PATH = ROOT / "scripts" / "probe_adguard_csp.mjs"
CSP_PROBE_USERSCRIPT_PATH = ROOT / "scripts" / "csp-probe.user.js"
SPEC = importlib.util.spec_from_file_location(
    "hotdeal_focus_cli_csp_probe", PYTHON_CLI_PATH
)
assert SPEC and SPEC.loader
cli = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cli
SPEC.loader.exec_module(cli)


def inspection(state_sha: str = "a" * 64) -> dict[str, object]:
    return {
        "command": "csp-probe-inspect",
        "ok": True,
        "state_sha256": state_sha,
        "read_1_sha256": state_sha,
        "read_2_sha256": state_sha,
        "two_read_stable": True,
        "probe_present": False,
        "probe_count": 0,
        "probe_name": "AdGuard Hotdeal Focus CSP Probe",
        "probe_version": "1.2.0",
        "probe_source_sha256": cli.CSP_PROBE_SOURCE_SHA256,
        "endpoint": cli.CSP_PROBE_ENDPOINT,
        "adguard_configuration_changed": False,
    }


def browser_proof() -> dict[str, object]:
    value: dict[str, object] = {
        key: True
        for key in cli.CSP_PROBE_BROWSER_KEYS
        if key not in {"schema_version", "command", "computed_custom_property"}
    }
    value.update({
        "schema_version": 2,
        "command": "adguard-csp-browser-probe",
        "computed_custom_property": "hdf-gm-style-pass",
    })
    return value


class CspProbeSourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ps_source = POWERSHELL_CLI_PATH.read_text(encoding="utf-8")
        cls.node_source = BROWSER_PROBE_PATH.read_text(encoding="utf-8")
        cls.probe_source = CSP_PROBE_USERSCRIPT_PATH.read_text(encoding="utf-8")
        cls.python_source = PYTHON_CLI_PATH.read_text(encoding="utf-8")

    def test_fixed_userscript_source_and_raw_hash_are_exact(self) -> None:
        userscript = CSP_PROBE_USERSCRIPT_PATH.read_bytes()
        self.assertEqual(
            hashlib.sha256(userscript).hexdigest(),
            cli.CSP_PROBE_SOURCE_SHA256,
        )
        decoded = userscript.decode("utf-8")
        metadata = decoded.split("// ==/UserScript==", 1)[0]
        self.assertEqual(
            metadata.count(
                "// @match        https://testcases.agrd.dev/userscripts-csp/"
                "header-csp-default-src-none"
            ),
            1,
        )
        self.assertEqual(metadata.count("// @grant        GM_addElement"), 1)
        self.assertIn("// @run-at       document-start", metadata)
        for directive in (
            "@connect", "@downloadURL", "@exclude", "@include", "@require",
            "@resource", "@updateURL",
        ):
            self.assertNotIn(directive, metadata)
        for network_api in (
            "fetch(", "GM_xmlhttpRequest", "navigator.sendBeacon", "WebSocket(",
            "XMLHttpRequest",
        ):
            self.assertNotIn(network_api, decoded)
        loader_start = self.ps_source.index("function Get-CspProbeUserscriptText")
        loader_end = self.ps_source.index(
            "function Get-CspProbeUserscriptSource", loader_start
        )
        loader = self.ps_source[loader_start:loader_end]
        self.assertIn("Join-Path $PSScriptRoot 'csp-probe.user.js'", loader)
        self.assertIn("FileAttributes]::ReparsePoint", loader)

    def test_gm_add_element_call_does_not_supply_engine_attributes(self) -> None:
        source = self.probe_source
        call_start = source.index('GM_addElement(parent, "style", {')
        call_end = source.index("      });", call_start)
        call = source[call_start:call_end]
        self.assertIn("textContent,", call)
        self.assertIn('"data-hdf-csp-probe-style": "1"', call)
        self.assertNotIn('"nonce":', call)
        self.assertNotIn('"data-source":', call)
        self.assertIn(
            'data-hdf-csp-probe-raw-engine-attributes-absent', source
        )
        self.assertIn('data-hdf-csp-probe-raw-applied', source)
        self.assertNotIn('data-hdf-csp-probe-raw-blocked', source)

    def test_probe_promotes_authenticated_source_to_executable_custom_class(self) -> None:
        regular_start = self.ps_source.index("function Get-UserscriptSource")
        probe_start = self.ps_source.index("function Get-CspProbeUserscriptText")
        filter_start = self.ps_source.index("function Get-FilterSource", probe_start)
        regular = self.ps_source[regular_start:probe_start]
        probe = self.ps_source[probe_start:filter_start]
        self.assertNotIn("InstallAsCustom", regular)
        self.assertNotIn("InstallAsCustom", probe)
        prepare_start = self.ps_source.index("function Prepare-UserscriptMeta")
        prepare_end = self.ps_source.index("function Compare-Version", prepare_start)
        prepare = self.ps_source[prepare_start:prepare_end]
        self.assertIn("$Source.Meta.IsCustom = $true", prepare)
        self.assertLess(
            prepare.index("differs from the authenticated source"),
            prepare.index("$Source.Meta.IsCustom = $true"),
        )

    def test_userscript_exits_before_dom_mutation_when_exact_url_differs(self) -> None:
        source = self.probe_source
        literal = f'const EXPECTED_URL = "{cli.CSP_PROBE_ENDPOINT}";'
        literal_index = source.index(literal)
        guard_index = source.index('if (location.href !== EXPECTED_URL) {')
        return_index = source.index("return;", guard_index)
        first_dom_mutation = source.index('document.createElement("style")')
        self.assertLess(literal_index, guard_index)
        self.assertLess(guard_index, return_index)
        self.assertLess(return_index, first_dom_mutation)

    def test_endpoint_is_identical_and_is_the_official_exact_html_testcase(self) -> None:
        ps_start = self.ps_source.index("$script:CspProbeEndpoint =")
        ps_end = self.ps_source.index("$script:CspProbeSourceSha256", ps_start)
        ps_endpoint = "".join(
            part.split("'", 2)[1]
            for part in self.ps_source[ps_start:ps_end].splitlines()
            if "'" in part
        )
        node_match = re.search(
            r'const PROBE_URL\s*=\s*\n?\s*"(?P<url>https://[^"]+)";',
            self.node_source,
        )
        self.assertIsNotNone(node_match)
        node_endpoint = node_match.group("url")
        self.assertEqual(ps_endpoint, cli.CSP_PROBE_ENDPOINT)
        self.assertEqual(node_endpoint, cli.CSP_PROBE_ENDPOINT)
        self.assertEqual(
            cli.CSP_PROBE_ENDPOINT,
            "https://testcases.agrd.dev/userscripts-csp/"
            "header-csp-default-src-none",
        )
        self.assertIn(
            '"text/html;charset=UTF-8"', self.node_source
        )

    def test_browser_output_never_reads_or_emits_nonce_value(self) -> None:
        self.assertNotIn('getAttribute("nonce")', self.node_source)
        self.assertNotIn("nonce_value", self.node_source.lower())
        self.assertIn('hasAttribute("nonce")', self.node_source)
        self.assertIn("engine_nonce_present", self.node_source)

    def test_browser_proof_waits_for_bounded_adguard_reload_convergence(self) -> None:
        self.assertIn("const BROWSER_PROBE_ATTEMPT_LIMIT = 6;", self.node_source)
        self.assertIn("async function runBrowserAttempt(browser)", self.node_source)
        self.assertIn(
            "attemptIndex < BROWSER_PROBE_ATTEMPT_LIMIT", self.node_source
        )
        self.assertIn("const context = await browser.newContext", self.node_source)
        self.assertIn("await context.close().catch(() => {});", self.node_source)
        self.assertIn("result.ok = resultIsExact(result);", self.node_source)
        self.assertIn("await delay(BROWSER_PROBE_RETRY_DELAY_MS);", self.node_source)
        self.assertIn("timeout_seconds=150", self.python_source)

    def test_probe_has_no_arbitrary_source_argument(self) -> None:
        parser = cli.build_parser()
        parsed = parser.parse_args([
            "adguard", "csp-probe", "--apply", "--json",
            "--evidence-dir", "evidence",
        ])
        self.assertEqual(parsed.action, "csp-probe")
        with self.assertRaises(cli.UsageFailure):
            parser.parse_args([
                "adguard", "csp-probe", "--probe-source", "evil.user.js", "--json"
            ])
        for command in (
            "'csp-probe-inspect'", "'csp-probe-install'", "'csp-probe-restore'"
        ):
            self.assertIn(command, self.ps_source)


class CspProbeOrchestrationTests(unittest.TestCase):
    def args(self, *, apply: bool = True) -> mock.Mock:
        return mock.Mock(
            action="csp-probe",
            manifest_source=cli.DEFAULT_PAGES_MANIFEST,
            backup_path=None,
            evidence_dir=None,
            approve_exclusive_target_migration=False,
            apply=apply,
        )

    @staticmethod
    def create_backup(root: Path) -> Path:
        backup = root / "20260720T000000.000Z-deadbeef"
        backup.mkdir()
        for name in (
            "backup-complete.json",
            "backup-manifest.json",
            "transaction-plan.json",
            "transaction-plan.complete.json",
        ):
            (backup / name).write_text("{}", encoding="utf-8")
        return backup

    def powershell(self, root: Path, *, restore_failure: bool = False,
                   install_failure: bool = False):
        calls: list[str] = []
        backup: Path | None = None

        def invoke(argv, *, apply_mutation, rollback):
            nonlocal backup
            del apply_mutation, rollback
            action = argv[argv.index("-File") + 2]
            calls.append(action)
            if action == "csp-probe-inspect":
                return inspection()
            if action == "csp-probe-install":
                backup = self.create_backup(root)
                if install_failure:
                    raise cli.MutationFailure(
                        "ambiguous install", rollback_complete=False
                    )
                return {
                    "command": "csp-probe-install",
                    "ok": True,
                    "changed": True,
                    "backup": str(backup),
                    "pre_state_sha256": "a" * 64,
                    "installed_state_sha256": "b" * 64,
                    "probe_present": True,
                    "probe_source_sha256": cli.CSP_PROBE_SOURCE_SHA256,
                    "endpoint": cli.CSP_PROBE_ENDPOINT,
                    "is_custom": True,
                    "is_style": False,
                }
            if action == "csp-probe-restore":
                if restore_failure:
                    raise cli.MutationFailure(
                        "restore timeout", rollback_complete=False
                    )
                return {
                    "command": "csp-probe-restore",
                    "ok": True,
                    "verified": True,
                    "probe_present": False,
                    "state_sha256": "a" * 64,
                    "probe_source_sha256": cli.CSP_PROBE_SOURCE_SHA256,
                    "idempotent": True,
                }
            raise AssertionError(action)

        return calls, invoke

    def test_success_restores_before_two_post_inspections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls, powershell = self.powershell(root)
            with mock.patch.object(
                cli, "_powershell_json", side_effect=powershell
            ), mock.patch.object(
                cli, "_create_csp_probe_backup_root", return_value=root
            ), mock.patch.object(
                cli, "_run_csp_browser_probe", return_value=browser_proof()
            ), mock.patch.object(cli, "_try_source_sha", return_value="c" * 40):
                result = cli._command_adguard_csp_probe(
                    self.args(), POWERSHELL_CLI_PATH
                )
        self.assertTrue(result["ok"])
        self.assertFalse(result["mutationApplied"])
        self.assertTrue(result["transientMutationApplied"])
        self.assertEqual(
            calls,
            ["csp-probe-inspect", "csp-probe-install", "csp-probe-restore",
             "csp-probe-inspect", "csp-probe-inspect"],
        )

    def test_browser_failure_and_timeout_both_restore_in_finally(self) -> None:
        for browser_error in (
            cli.VerificationFailure("browser assertion"),
            cli.TransientFailure("browser timeout"),
        ):
            with self.subTest(error=type(browser_error).__name__), \
                    tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                calls, powershell = self.powershell(root)
                with mock.patch.object(
                    cli, "_powershell_json", side_effect=powershell
                ), mock.patch.object(
                    cli, "_create_csp_probe_backup_root", return_value=root
                ), mock.patch.object(
                    cli, "_run_csp_browser_probe", side_effect=browser_error
                ):
                    with self.assertRaises(cli.MutationFailure) as caught:
                        cli._command_adguard_csp_probe(
                            self.args(), POWERSHELL_CLI_PATH
                        )
                self.assertEqual(caught.exception.exit_code, cli.EXIT_MUTATION_ROLLED_BACK)
                self.assertIn("csp-probe-restore", calls)
                self.assertEqual(calls[-2:], ["csp-probe-inspect"] * 2)
                self.assertIn("operationError", caught.exception.details)

    def test_ambiguous_install_is_restored_from_discovered_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls, powershell = self.powershell(root, install_failure=True)
            with mock.patch.object(
                cli, "_powershell_json", side_effect=powershell
            ), mock.patch.object(
                cli, "_create_csp_probe_backup_root", return_value=root
            ):
                with self.assertRaises(cli.MutationFailure) as caught:
                    cli._command_adguard_csp_probe(
                        self.args(), POWERSHELL_CLI_PATH
                    )
        self.assertEqual(caught.exception.exit_code, cli.EXIT_MUTATION_ROLLED_BACK)
        self.assertIn("csp-probe-restore", calls)

    def test_restore_failure_retries_then_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls, powershell = self.powershell(root, restore_failure=True)
            with mock.patch.object(
                cli, "_powershell_json", side_effect=powershell
            ), mock.patch.object(
                cli, "_create_csp_probe_backup_root", return_value=root
            ), mock.patch.object(
                cli, "_run_csp_browser_probe", return_value=browser_proof()
            ):
                with self.assertRaises(cli.MutationFailure) as caught:
                    cli._command_adguard_csp_probe(
                        self.args(), POWERSHELL_CLI_PATH
                    )
        self.assertEqual(caught.exception.exit_code, cli.EXIT_ROLLBACK_INCOMPLETE)
        self.assertEqual(calls.count("csp-probe-restore"), 2)
        recovery = caught.exception.details["adguardRecovery"]
        self.assertEqual(recovery["commandArgv"][-4], "csp-probe-restore")

    def test_dry_run_is_nonmutating_and_does_not_launch_browser(self) -> None:
        plan = {
            "command": "csp-probe-install",
            "ok": True,
            "what_if": True,
            "probe_present": False,
            "probe_source_sha256": cli.CSP_PROBE_SOURCE_SHA256,
            "endpoint": cli.CSP_PROBE_ENDPOINT,
            "is_custom": True,
            "is_style": False,
            "parsed_meta": dict(cli.CSP_PROBE_PARSED_META_CONTRACT),
            "order": [
                "validated-backup-restore",
                "two-independent-stable-post-inspections",
            ],
            "adguard_configuration_changed": False,
        }
        with mock.patch.object(
            cli, "_powershell_json", return_value=plan
        ) as powershell, mock.patch.object(
            cli, "_create_csp_probe_backup_root"
        ) as backup, mock.patch.object(
            cli, "_run_csp_browser_probe"
        ) as browser, mock.patch.object(cli, "_try_source_sha", return_value="d" * 40):
            result = cli._command_adguard_csp_probe(
                self.args(apply=False), POWERSHELL_CLI_PATH
            )
        self.assertEqual(result["status"], "dry-run")
        self.assertIn("-WhatIf", powershell.call_args.args[0])
        backup.assert_not_called()
        browser.assert_not_called()

    def test_browser_failure_contract_does_not_echo_untrusted_nonce(self) -> None:
        capture = cli.ExecutionCapture(
            "adguard-csp-browser-proof",
            ("node",),
            1,
            json.dumps({
                "schema_version": 2,
                "command": "adguard-csp-browser-probe",
                "ok": False,
                "failure_kind": "proof-failed",
                "origin_status_exact": True,
                "probe_state_complete": False,
                "root_state": "missing",
                "nonce_value": "DO-NOT-PRINT",
            }).encode("utf-8"),
            b"",
        )
        with mock.patch.object(cli, "_capture_command", return_value=capture):
            with self.assertRaises(cli.VerificationFailure) as caught:
                cli._run_csp_browser_probe(BROWSER_PROBE_PATH)
        self.assertNotIn("DO-NOT-PRINT", json.dumps(caught.exception.details))
        safe = caught.exception.details["browserProbe"]
        self.assertTrue(safe["origin_status_exact"])
        self.assertFalse(safe["probe_state_complete"])
        self.assertEqual(safe["root_state"], "missing")
        self.assertEqual(safe["schema_version"], 2)


if __name__ == "__main__":
    unittest.main()
