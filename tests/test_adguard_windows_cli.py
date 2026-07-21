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
        invoke = self.source[
            self.source.index("function Invoke-LegacyMigration") :
            self.source.index("function Assert-Sha256Value")
        ]
        userscript = invoke.index("Assert-UserscriptInstalled")
        current_plan = invoke.index("Assert-LegacyMigrationPlanCurrent")
        first_write = invoke.index("DisableFilterRules")
        self.assertLess(userscript, current_plan)
        self.assertLess(current_plan, first_write)
        self.assertIn("[Parameter(Mandatory = $true)] $DesiredUserscript", invoke)

    def test_deploy_order_is_backup_userscript_then_filter_inventory_proof(self) -> None:
        deploy = self.source[self.source.index("        'deploy' {") :]
        backup = deploy.index("New-StateBackup")
        userscript = deploy.index("Invoke-UserscriptMutation")
        protected_postcondition = deploy.index(
            "Assert-DeploymentVerified", userscript
        )
        self.assertLess(backup, userscript)
        self.assertLess(userscript, protected_postcondition)
        for forbidden in (
            "Invoke-LegacyMigration", "Invoke-FilterMutation",
            "Assert-FilterInstalled", "Assert-NoLegacyHotdealConflict",
        ):
            self.assertNotIn(forbidden, deploy)

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
        migrate = self.source[
            self.source.index("        'migrate-legacy' {") :
            self.source.index("        'install-filter' {")
        ]
        self.assertIn("Assert-ExclusiveTargetMigrationAuthorized -Plan $migrationPlan", migrate)
        self.assertIn("approval_required", migrate)
        initial_userscript_check = migrate.index("Assert-UserscriptInstalled")
        backup = migrate.index("New-StateBackup")
        backup_userscript_check = migrate.index(
            "Assert-BackupUserscriptMatchesDesired"
        )
        prewrite_state_check = migrate.index("Assert-CurrentStateEqualsBackup")
        mutation = migrate.index("Invoke-LegacyMigration")
        userscript_postcondition = migrate.index(
            "Assert-LegacyMigrationUserscriptUnchanged"
        )
        transaction_complete = migrate.index("-Event 'transaction-complete'")
        what_if_plan = migrate.index("Get-LegacyMigrationPlan -Client $client")
        final_what_if_userscript_check = migrate.rindex("Assert-UserscriptInstalled")
        self.assertLess(initial_userscript_check, backup)
        self.assertLess(initial_userscript_check, what_if_plan)
        self.assertLess(backup, backup_userscript_check)
        self.assertLess(backup_userscript_check, prewrite_state_check)
        self.assertLess(prewrite_state_check, mutation)
        self.assertLess(mutation, userscript_postcondition)
        self.assertLess(userscript_postcondition, transaction_complete)
        self.assertLess(what_if_plan, final_what_if_userscript_check)
        self.assertIn("-DesiredUserscript $desiredUserscript", migrate)
        deploy = self.source[self.source.index("        'deploy' {") :]
        self.assertNotIn("ApproveExclusiveTargetMigration", deploy)

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

    def test_normal_deployment_rejects_every_filter_install_input(self) -> None:
        preflight = self.source[
            self.source.index("if ($requiresAuthenticatedStandaloneUserscript -and") :
            self.source.index("    if ($UserscriptSource)")
        ]
        for token in (
            "'FilterUrl'", "'ExpectedFilterSha256'",
            "'ExpectedInstalledFilterRulesSha256'",
            "'ApproveExclusiveTargetMigration'",
            'is Userscript-only and rejects',
        ):
            self.assertIn(token, preflight)

    def test_release_contract_is_schema_v2_userscript_only(self) -> None:
        for token in (
            "schema-v2",
            "ReleaseUserscriptUrl",
            "InstallUrl",
            "canonicalTextSha256",
            "UserscriptRawSha256",
            "UserscriptCanonicalTextSha256",
            "ReaderGateGrants",
            "Assert-ReleaseInputsMatchManifest",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.source)

    def test_mutation_flow_uses_completed_backup_as_unique_before_state(self) -> None:
        for command in ("install-userscript", "deploy"):
            section = self.source[self.source.index(f"        '{command}' {{") :]
            backup = section.index("New-StateBackup")
            validated = section.index("Get-ValidatedBackup", backup)
            prewrite = section.index("Assert-CurrentStateEqualsBackup", validated)
            mutation_name = {
                "install-userscript": "Invoke-UserscriptMutation",
                "deploy": "Invoke-UserscriptMutation",
            }[command]
            mutation = section.index(mutation_name, prewrite)
            self.assertLess(backup, validated)
            self.assertLess(validated, prewrite)
            self.assertLess(prewrite, mutation)

    def test_every_forward_mutation_substep_has_durable_intent(self) -> None:
        for event in (
            "intent-userscript-update-code",
            "intent-userscript-install",
            "intent-userscript-reclassification-remove",
            "intent-userscript-reclassification-restore-gm",
            "intent-userscript-enable",
            "intent-legacy-disable-rule",
            "intent-filter-install",
            "intent-filter-activate",
            "intent-filter-disable-prior",
        ):
            with self.subTest(event=event):
                self.assertIn(event, self.source)
        forward = self.source[
            self.source.index("function Invoke-UserscriptMutation") :
            self.source.index("function Restore-UserscriptSnapshot")
        ]
        self.assertIn("UpdateUserscriptGmProperties", forward)
        self.assertIn("if ($replacementRequired)", forward)
        self.assertNotIn("intent-userscript-update-gm", forward)

    def test_userscript_verification_exposes_protected_filter_state_hashes(self) -> None:
        for token in (
            "InstalledCodeSha256",
            "InstalledGmPropertiesSha256",
            "VisibilityObservationCount",
            "UserFilterSha256",
            "SubscriptionInventorySha256",
            "Assert-ProtectedFilterStateEqualsBackup",
            "subscription_inventory_unchanged",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.source)

    def test_adguard_cache_visibility_uses_bounded_exact_convergence(self) -> None:
        for token in (
            "$script:AdGuardStateVisibilityMaxObservations = 20",
            "$script:AdGuardStateVisibilityDelayMilliseconds = 250",
            "$script:AdGuardStateVisibilityRequiredConsecutiveReads = 2",
            "stability_observation_count",
            "Start-Sleep -Milliseconds $RetryDelayMilliseconds",
            "userscript-install-accepted",
            "AdGuard userscript installation receipt differs from the exact source",
            "Assert-ReaderGateSnapshotOwnership",
            "Assert-UserscriptAbsent",
            "Assert-UserscriptSnapshotConverged",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.source)
        stable = self.source[
            self.source.index("function Get-StableCompleteTargetStateSnapshot") :
            self.source.index("function Get-CspProbeInspectionReport")
        ]
        installed = self.source[
            self.source.index("function Assert-UserscriptInstalled") :
            self.source.index("function Prepare-FilterMetaSet")
        ]
        self.assertIn("$consecutiveReads -ge $RequiredConsecutiveReads", stable)
        self.assertIn("$consecutiveReads -ge $RequiredConsecutiveReads", installed)
        self.assertIn("$installedCodeHash -cne $desiredHash", installed)
        self.assertIn("$installedGmPropertiesHash -cne", installed)
        self.assertIn("$ExpectedPostState.GmPropertiesSha256", installed)
        self.assertIn(
            "[bool] $targets[0].IsCustom -ne $expectedIsCustom",
            installed,
        )

    def test_userscript_classification_is_bound_to_authenticated_source_policy(self) -> None:
        plan = self.source[
            self.source.index("function Initialize-TransactionJournal") :
            self.source.index("function Read-StrictJsonFile")
        ]
        backup = self.source[
            self.source.index("function Assert-CspProbeBackupContract") :
            self.source.index("function Test-UserscriptSnapshotExact")
        ]
        desired_backup = self.source[
            self.source.index("function Assert-BackupUserscriptMatchesDesired") :
            self.source.index("function Invoke-UserscriptMutation")
        ]
        receipt = self.source[
            self.source.index("function Invoke-UserscriptMutation") :
            self.source.index("function Restore-UserscriptSnapshot")
        ]
        self.assertIn("Get-ExpectedUserscriptPostState", plan)
        self.assertIn("is_custom = [bool] $expectedPostState.IsCustom", plan)
        self.assertIn("is_style = [bool] $expectedPostState.IsStyle", plan)
        self.assertIn("gm_properties_sha256", plan)
        userscript_plan = plan[: plan.index("$filterAfter = $null")]
        self.assertNotIn("is_custom = $true", userscript_plan)
        self.assertIn("$expectedPostState.IsCustom", backup)
        self.assertIn("$Snapshot.Info.IsCustom", desired_backup)
        self.assertIn("$Snapshot.Info.IsStyle", desired_backup)
        self.assertIn("$installReceipt.Meta.IsCustom", receipt)
        regular_source = self.source[
            self.source.index("function Get-UserscriptSource") :
            self.source.index("function Get-CspProbeUserscriptText")
        ]
        probe_source = self.source[
            self.source.index("function Get-CspProbeUserscriptText") :
            self.source.index("function Get-FilterSource")
        ]
        prepare = self.source[
            self.source.index("function Prepare-UserscriptMeta") :
            self.source.index("function Compare-Version")
        ]
        self.assertNotIn("InstallAsCustom", regular_source)
        self.assertNotIn("InstallAsCustom", probe_source)
        self.assertIn("$Source.Meta.IsCustom = $true", prepare)
        self.assertIn("differs from the authenticated source", prepare)
        self.assertLess(
            prepare.index("differs from the authenticated source"),
            prepare.index("$Source.Meta.IsCustom = $true"),
        )
        self.assertIn("-not [bool] $Source.Meta.IsCustom", prepare)

    def test_source_metadata_and_gm_value_store_are_separate_domains(self) -> None:
        source_parser = self.source[
            self.source.index("function Get-UserscriptSource") :
            self.source.index("function Get-CspProbeUserscriptText")
        ]
        forward = self.source[
            self.source.index("function Invoke-UserscriptMutation") :
            self.source.index("function Restore-UserscriptSnapshot")
        ]
        restore = self.source[
            self.source.index("function Restore-UserscriptSnapshot") :
            self.source.index("function Assert-UserscriptInstalled")
        ]
        self.assertIn("MetadataBlock = $metadata", source_parser)
        self.assertIn("FreshInstallGmProperties", source_parser)
        self.assertIn("intent-userscript-reclassification-restore-gm", forward)
        self.assertIn("UpdateUserscriptGmProperties", forward)
        self.assertIn("UpdateUserscriptGmProperties", restore)

    def test_classification_replacement_and_rollback_are_exactly_resumable(self) -> None:
        preconditions = self.source[
            self.source.index("function Assert-UserscriptRestorePreconditions") :
            self.source.index("function Test-FilterStateExact")
        ]
        mutation = self.source[
            self.source.index("function Invoke-UserscriptMutation") :
            self.source.index("function Restore-UserscriptSnapshot")
        ]
        restore = self.source[
            self.source.index("function Restore-UserscriptSnapshot") :
            self.source.index("function Assert-UserscriptInstalled")
        ]
        for token in (
            "replacement_required",
            "fresh_install_gm_properties_sha256",
            "Current userscript is not an enumerated rollback-prefix state",
            "if ($replacementRequired) { return $true }",
        ):
            with self.subTest(token=token):
                self.assertIn(token, preconditions)
        self.assertLess(
            mutation.index("RemoveUserscript"),
            mutation.index("Assert-UserscriptAbsent"),
        )
        self.assertLess(
            mutation.index("Assert-UserscriptAbsent"),
            mutation.index("InstallUserscriptFromMeta"),
        )
        self.assertLess(
            mutation.index("InstallUserscriptFromMeta"),
            mutation.index("UpdateUserscriptGmProperties"),
        )
        self.assertLess(
            mutation.index("UpdateUserscriptGmProperties"),
            mutation.index("SetUserscriptStatus"),
        )
        for intent, write in (
            ("intent-userscript-reclassification-remove", "RemoveUserscript"),
            ("intent-userscript-install", "InstallUserscriptFromMeta"),
            (
                "intent-userscript-reclassification-restore-gm",
                "UpdateUserscriptGmProperties",
            ),
            ("intent-userscript-enable", "SetUserscriptStatus"),
        ):
            with self.subTest(intent=intent):
                self.assertLess(mutation.index(intent), mutation.index(write))
        for token in (
            "Get-UserscriptMetaForSnapshotRestore",
            "intent-rollback-userscript-reclassification-remove",
            "intent-rollback-userscript-reclassification-install",
            "Assert-UserscriptInstallReceipt",
            "Assert-UserscriptSnapshotConverged",
        ):
            with self.subTest(token=token):
                self.assertIn(token, restore)
        for intent, write in (
            (
                "intent-rollback-userscript-reclassification-remove",
                "RemoveUserscript",
            ),
            (
                "intent-rollback-userscript-reclassification-install",
                "InstallUserscriptFromMeta",
            ),
            ("intent-rollback-userscript-gm", "UpdateUserscriptGmProperties"),
            ("intent-rollback-userscript-status", "SetUserscriptStatus"),
        ):
            with self.subTest(intent=intent):
                self.assertLess(restore.index(intent), restore.index(write))

    def test_mixed_or_legacy_user_rules_do_not_block_or_change_normal_deployment(self) -> None:
        deploy = self.source[self.source.index("        'deploy' {") :]
        for forbidden in (
            "Get-LegacyMigrationPlan", "Enabled mixed-target User filter rules",
            "Invoke-LegacyMigration", "DisableFilterRules",
        ):
            self.assertNotIn(forbidden, deploy)
        self.assertIn("user_filter_will_change = $false", deploy)
        self.assertIn("subscription_inventory_will_change = $false", deploy)

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
        digest = "a" * 64
        cases = (
            (["verify"], "requires -UserscriptSource"),
            (
                ["verify", "-UserscriptSource", userscript],
                "requires -ExpectedUserscriptSha256",
            ),
            (
                [
                    "verify",
                    "-UserscriptSource",
                    userscript,
                    "-ExpectedUserscriptSha256",
                    digest,
                    "-FilterUrl",
                    "https://example.com/filter.txt",
                ],
                "is Userscript-only and rejects -FilterUrl",
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

    @unittest.skipUnless(shutil.which("powershell.exe"), "Windows PowerShell is unavailable")
    def test_migration_preflight_requires_authenticated_userscript_release_inputs(self) -> None:
        userscript = str(ROOT / "hotdeal-focus.user.js")
        manifest = str(ROOT / "release-manifest.json")
        digest = "a" * 64
        required = [
            "migrate-legacy",
            "-UserscriptSource",
            userscript,
            "-ExpectedUserscriptSha256",
            digest,
            "-ReleaseManifestSource",
            manifest,
            "-WhatIf",
        ]
        cases = (
            (["migrate-legacy", "-WhatIf"], "requires -UserscriptSource"),
            (
                ["migrate-legacy", "-UserscriptSource", userscript, "-WhatIf"],
                "requires -ExpectedUserscriptSha256",
            ),
            (
                [
                    "migrate-legacy",
                    "-UserscriptSource",
                    userscript,
                    "-ExpectedUserscriptSha256",
                    digest,
                    "-WhatIf",
                ],
                "requires -ReleaseManifestSource",
            ),
            (
                required[:-1]
                + ["-FilterUrl", "https://example.com/filter.txt", "-WhatIf"],
                "rejects filter input: -FilterUrl",
            ),
            (
                required[:-1]
                + ["-FilterName", "Not the standalone gate", "-WhatIf"],
                "rejects filter input: -FilterName",
            ),
            (
                required[:-1]
                + ["-ExpectedFilterSha256", digest, "-WhatIf"],
                "rejects filter input: -ExpectedFilterSha256",
            ),
            (
                required[:-1]
                + ["-ExpectedInstalledFilterRulesSha256", digest, "-WhatIf"],
                "rejects filter input: -ExpectedInstalledFilterRulesSha256",
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

    def test_standalone_userscript_title_matches_cli_default_contract(self) -> None:
        userscript_text = (ROOT / "hotdeal-focus.user.js").read_text(
            encoding="utf-8"
        )
        title = re.search(r"(?m)^//\s+@name\s+(.+?)\s*$", userscript_text)
        self.assertIsNotNone(title)
        self.assertEqual(title.group(1), "AdGuard Hotdeal Focus Reader Gate")
        deployment_verifier = self.source[
            self.source.index("function Assert-DeploymentVerified") :
            self.source.index("function Invoke-Rollback")
        ]
        self.assertNotIn("Assert-FilterInstalled", deployment_verifier)
        self.assertIn("userscript_only = $true", deployment_verifier)
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
