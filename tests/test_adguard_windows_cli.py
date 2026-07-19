from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLI_PATH = ROOT / "scripts" / "adguard_windows_cli.ps1"


class AdGuardWindowsCliContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = CLI_PATH.read_text(encoding="utf-8")

    def test_has_explicit_reversible_legacy_migration(self) -> None:
        self.assertIn("'migrate-legacy'", self.source)
        self.assertIn("DisableFilterRules", self.source)
        self.assertIn("EnableFilterRules", self.source)
        self.assertIn("Assert-LegacyMigrationPlanCurrent", self.source)
        self.assertIn("Assert-LegacyMigrationPostState", self.source)
        self.assertIn("Restore-LegacyMigration", self.source)

    def test_deploy_order_is_backup_userscript_migration_filter(self) -> None:
        deploy = self.source[self.source.index("        'deploy' {") :]
        backup = deploy.index("New-StateBackup")
        userscript = deploy.index("Invoke-UserscriptMutation")
        migration = deploy.index("Invoke-LegacyMigration")
        marker_filter = deploy.index("Invoke-FilterMutation")
        self.assertLess(backup, userscript)
        self.assertLess(userscript, migration)
        self.assertLess(migration, marker_filter)

    def test_user_filter_migration_is_disable_only_and_transactional(self) -> None:
        forbidden = (
            "AddUserFilterRules",
            "RemoveUserFilterRules",
            "Stop-Service",
            "Stop-Process",
            "StopProtection",
            "Set-Acl",
            "icacls",
            "takeown",
        )
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, self.source)
        self.assertIn("protected_ordered_sha256", self.source)
        self.assertIn("Test-ExactStringSequence", self.source)
        self.assertIn("Test-ExactStringMultiset", self.source)

    def test_every_explicit_disconnect_keeps_service_running(self) -> None:
        calls = re.findall(r"\.Disconnect\(([^)]*)\)", self.source)
        self.assertGreaterEqual(len(calls), 3)
        self.assertTrue(all(call.replace(" ", "") == "$false,$true" for call in calls))

    def test_historical_snapshot_is_never_authoritative(self) -> None:
        self.assertIn("historical-only-non-authoritative", self.source)
        self.assertIn("historical_snapshot_is_authoritative = $false", self.source)
        self.assertIn("historical_snapshot_mismatch_is_blocking = $false", self.source)

    def test_mutating_commands_require_apply_or_what_if(self) -> None:
        self.assertIn("function Assert-MutationAuthorized", self.source)
        self.assertIn("if (-not $Apply -and -not $WhatIfPreference)", self.source)
        self.assertIn("-WhatIf will not start a process", self.source)

    def test_scope_based_migration_requires_separate_explicit_approval(self) -> None:
        self.assertIn("[switch] $ApproveExclusiveTargetMigration", self.source)
        self.assertIn("function Assert-ExclusiveTargetMigrationAuthorized", self.source)
        self.assertIn("scope alone does not prove", self.source)
        deploy = self.source[self.source.index("        'deploy' {") :]
        migrate = self.source[self.source.index("        'migrate-legacy' {") :]
        self.assertIn("Assert-ExclusiveTargetMigrationAuthorized -Plan $migrationPlan", deploy)
        self.assertIn("Assert-ExclusiveTargetMigrationAuthorized -Plan $migrationPlan", migrate)
        self.assertIn("migration_approval_required", deploy)
        self.assertIn("approval_required", migrate)

    def test_restore_backup_is_versioned_preconditioned_and_idempotent(self) -> None:
        for token in (
            "'restore-backup'",
            "backup-complete.json",
            "transaction-plan.complete.json",
            "Get-ValidatedBackup",
            "Get-BackupRestorePlan",
            "Invoke-BackupRestore",
            "IsAlreadyRestored",
            "Current User filter Rules digest differs",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.source)

    def test_filter_mutations_require_both_remote_and_installed_hashes(self) -> None:
        preflight = self.source[
            self.source.index("if ($Command -in @('install-userscript', 'install-filter'") :
            self.source.index("    if ($UserscriptSource)")
        ]
        self.assertIn("requires -ExpectedFilterSha256", preflight)
        self.assertIn("requires -ExpectedInstalledFilterRulesSha256", preflight)
        self.assertIn("'verify'", preflight)

    def test_release_contract_consumes_both_raw_and_canonical_manifest_hashes(self) -> None:
        for token in (
            "canonicalTextSha256",
            "installedRulesSha256",
            "UserscriptRawSha256",
            "UserscriptCanonicalTextSha256",
            "FilterInstalledRulesSha256",
            "Assert-ReleaseInputsMatchManifest",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.source)

    def test_mutation_flow_uses_completed_backup_as_unique_before_state(self) -> None:
        for command in ("install-userscript", "install-filter", "deploy"):
            section = self.source[self.source.index(f"        '{command}' {{") :]
            backup = section.index("New-StateBackup")
            validated = section.index("Get-ValidatedBackup", backup)
            prewrite = section.index("Assert-CurrentStateEqualsBackup", validated)
            mutation_name = {
                "install-userscript": "Invoke-UserscriptMutation",
                "install-filter": "Invoke-FilterMutation",
                "deploy": "Invoke-UserscriptMutation",
            }[command]
            mutation = section.index(mutation_name, prewrite)
            self.assertLess(backup, validated)
            self.assertLess(validated, prewrite)
            self.assertLess(prewrite, mutation)

    def test_every_forward_mutation_substep_has_durable_intent(self) -> None:
        for event in (
            "intent-userscript-update-code",
            "intent-userscript-update-gm",
            "intent-userscript-install",
            "intent-userscript-enable",
            "intent-legacy-disable-rule",
            "intent-filter-install",
            "intent-filter-activate",
            "intent-filter-disable-prior",
        ):
            with self.subTest(event=event):
                self.assertIn(event, self.source)

    def test_filter_and_userscript_verification_expose_all_state_hashes(self) -> None:
        for token in (
            "InstalledCodeSha256",
            "InstalledGmSha256",
            "DisabledRuleCount",
            "DisabledRulesSha256",
            'throw "Installed custom filter contains disabled rules"',
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.source)

    def test_mixed_target_rules_block_verified_deployment(self) -> None:
        self.assertIn("has_enabled_conflict = $enabledTargetAll.Count -gt 0", self.source)
        self.assertIn("migration_blocked_by_mixed_scope = $enabledMixedAll.Count -gt 0", self.source)
        self.assertIn("Enabled mixed-target User filter rules are preserved", self.source)

    def test_mutation_failures_emit_recovery_coordinates(self) -> None:
        self.assertIn("$failure.backup_path = $script:RecoveryBackupPath", self.source)
        self.assertIn("$failure.recovery_command = $script:RecoveryCommand", self.source)
        self.assertIn("recovery_command_contains_credentials", self.source)

    @unittest.skipUnless(shutil.which("powershell.exe"), "Windows PowerShell is unavailable")
    def test_state_machine_contract_harness(self) -> None:
        harness = ROOT / "tests" / "adguard_cli_contract_harness.ps1"
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(harness),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        self.assertIn('"ok":  true', completed.stdout)

    @unittest.skipUnless(shutil.which("powershell.exe"), "Windows PowerShell is unavailable")
    def test_verify_preflight_rejects_each_missing_release_input_before_ipc(self) -> None:
        userscript = str(ROOT / "hotdeal-focus.user.js")
        filter_url = "https://heelee912.github.io/adguard-hotdeal-focus/filter.txt"
        digest = "a" * 64
        cases = (
            (["verify"], "requires -UserscriptSource"),
            (["verify", "-UserscriptSource", userscript], "requires -FilterUrl"),
            (
                ["verify", "-UserscriptSource", userscript, "-FilterUrl", filter_url],
                "requires -ExpectedUserscriptSha256",
            ),
            (
                [
                    "verify",
                    "-UserscriptSource",
                    userscript,
                    "-FilterUrl",
                    filter_url,
                    "-ExpectedUserscriptSha256",
                    digest,
                ],
                "requires -ExpectedFilterSha256",
            ),
            (
                [
                    "verify",
                    "-UserscriptSource",
                    userscript,
                    "-FilterUrl",
                    filter_url,
                    "-ExpectedUserscriptSha256",
                    digest,
                    "-ExpectedFilterSha256",
                    digest,
                ],
                "requires -ExpectedInstalledFilterRulesSha256",
            ),
        )
        for arguments, expected in cases:
            with self.subTest(expected=expected):
                completed = subprocess.run(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(CLI_PATH),
                        *arguments,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                output = completed.stdout + completed.stderr
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(expected, output)

    def test_actual_filter_title_matches_cli_default_ascii_contract(self) -> None:
        filter_text = (ROOT / "filter.txt").read_text(encoding="utf-8")
        title = re.search(r"(?m)^!\s*Title:\s*(.+?)\s*$", filter_text)
        self.assertIsNotNone(title)
        self.assertEqual(title.group(1), "AdGuard Hotdeal Focus Marker Gate")
        self.assertRegex(self.source, r"\$script:ToolVersion = '\d+\.\d+\.\d+'")

    def test_userscript_placeholder_check_does_not_reject_runtime_globals(self) -> None:
        userscript_reader = self.source[
            self.source.index("function Get-UserscriptSource") :
            self.source.index("function Get-FilterSource")
        ]
        self.assertNotIn(".Contains('__HOTDEAL_FOCUS_')", userscript_reader)
        for placeholder in (
            "__HOTDEAL_FOCUS_DOWNLOAD_URL__",
            "__HOTDEAL_FOCUS_UPDATE_URL__",
            "__HOTDEAL_FOCUS_OWNER__",
        ):
            with self.subTest(placeholder=placeholder):
                self.assertIn(placeholder, userscript_reader)


if __name__ == "__main__":
    unittest.main()
