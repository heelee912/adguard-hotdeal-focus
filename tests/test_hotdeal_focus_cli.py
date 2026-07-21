from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CLI_PATH = ROOT / "scripts" / "hotdeal_focus_cli.py"
SPEC = importlib.util.spec_from_file_location("hotdeal_focus_cli", CLI_PATH)
assert SPEC and SPEC.loader
cli = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cli
SPEC.loader.exec_module(cli)


def empty_high_water_prefix() -> dict[str, object]:
    prefix_bytes = cli.canonical_json_bytes(
        {
            "bundleFormat": "hdf-public-bundle-v1",
            "records": [],
            "schemaVersion": 1,
        }
    )
    return {
        "bytes": len(prefix_bytes),
        "mode": "append-only-prefix-v1",
        "recordCount": 0,
        "sha256": hashlib.sha256(prefix_bytes).hexdigest(),
    }


def release_bundle():
    userscript = b"""// ==UserScript==
// @name         AdGuard Hotdeal Focus Reader Gate
// @version      1.2.3
// @match        https://www.algumon.com/*
// @match        https://*.clien.net/*
// @match        https://*.ppomppu.co.kr/*
// @match        https://*.ruliweb.com/*
// @match        https://*.quasarzone.com/*
// @match        https://*.eomisae.co.kr/*
// @match        https://*.zod.kr/*
// @match        https://*.arca.live/*
// @run-at       document-start
// @grant        GM_addElement
// @grant        window.onurlchange
// @downloadURL  https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
// @updateURL    https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
// @noframes
// ==/UserScript==
const PROTOCOL_VERSION = "2";
const ATTR = {
  lock: "data-hotdeal-focus-lock",
  ready: "data-hotdeal-focus-ready",
  keep: "data-hotdeal-focus-keep",
  protocol: "data-hotdeal-focus-protocol",
  shell: "data-hotdeal-focus-shell",
  deep: "data-hotdeal-focus-deep",
  role: "data-hotdeal-focus-role",
  state: "data-hotdeal-focus-state",
  status: "data-hotdeal-focus-status",
};
const CLASSES = "hdf-v2-lock hdf-v2-ready hdf-v2-keep hdf-v2-shell hdf-v2-deep hdf-v2-role-";
const runtimeStyleSelector = `style[data-hotdeal-focus-runtime-style="${PROTOCOL_VERSION}"]`;
const diagnostics = { protocolVersion: Number(PROTOCOL_VERSION) };
document.documentElement.setAttribute(ATTR.protocol, PROTOCOL_VERSION);
GM_addElement(document.documentElement, "style", {
  textContent: "html.hdf-v2-lock{display:none!important}",
  "data-hotdeal-focus-runtime-style": PROTOCOL_VERSION,
});
"""
    manifest = {
        "schemaVersion": 2,
        "status": "release-ready",
        "releaseVersion": "1.2.3",
        "protocolVersion": 2,
        "installUrl": cli.RELEASE_USERSCRIPT_URL,
        "generatorVersion": "1.2.3",
        "rollback_of": None,
        "configSha256": "c" * 64,
        "coverage": {},
        "promotion": None,
        "artifacts": {
            "hotdeal-focus.user.js": {
                "version": "1.2.3",
                "bytes": len(userscript),
                "sha256": hashlib.sha256(userscript).hexdigest(),
                "canonicalTextSha256": hashlib.sha256(
                    cli.canonical_text_bytes(userscript)
                ).hexdigest(),
            },
        },
        "sourceIntegrity": {
            "state/release-high-water.json": empty_high_water_prefix(),
        },
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
    return manifest, manifest_bytes, {
        "hotdeal-focus.user.js": userscript,
    }


def gate_absence_capture():
    payload = {"data": {"repository": {"release": None}}}
    return cli.ExecutionCapture(
        "gate-release-definitive-absence",
        ("gh",),
        0,
        json.dumps(payload).encode("utf-8"),
        b"",
    )


class ParserAndOutputContractTests(unittest.TestCase):
    def run_main(self, arguments):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(arguments)
        lines = stdout.getvalue().splitlines()
        self.assertEqual(len(lines), 1, stdout.getvalue())
        return code, json.loads(lines[0]), stderr.getvalue()

    def test_unknown_workflow_is_usage_error_json(self):
        code, payload, _ = self.run_main(
            ["cloud", "status", "--repo", "owner/repo", "--workflow", "evil.yml", "--json"]
        )
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["status"], "usage-error")

    def test_missing_json_switch_is_usage_error_json(self):
        code, payload, _ = self.run_main(["doctor"])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertEqual(payload["command"], "doctor")

    def test_help_does_not_break_single_json_contract(self):
        code, payload, _ = self.run_main(["doctor", "--help"])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertEqual(payload["status"], "usage-error")

    def test_doctor_writes_one_json_document(self):
        with mock.patch.object(cli, "_command_exists", return_value=True), mock.patch.object(
            cli, "shutil"
        ) as mocked_shutil, mock.patch.object(cli, "_try_source_sha", return_value="a" * 40):
            mocked_shutil.which.side_effect = lambda value: f"/tools/{value}"
            code, payload, _ = self.run_main(["doctor", "--json"])
        self.assertEqual(code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["sourceSha"], "a" * 40)

    def test_doctor_separates_read_only_adguard_inspection_from_verified_deployment(self):
        available = {"python", "node", "npm", "git", "powershell.exe"}
        with mock.patch.object(
            cli, "_command_exists", side_effect=lambda value: value in available
        ), mock.patch.object(cli, "shutil") as mocked_shutil, mock.patch.object(
            cli.sys, "platform", "win32"
        ), mock.patch.object(cli, "_try_source_sha", return_value="b" * 40):
            mocked_shutil.which.side_effect = lambda value: (
                f"C:/tools/{value}" if value in available else None
            )
            code, payload, _ = self.run_main(["doctor", "--json"])
        self.assertEqual(code, 0)
        self.assertTrue(payload["capabilities"]["adguardWindowsInspect"])
        self.assertTrue(payload["capabilities"]["adguardWindowsDeployment"])
        self.assertNotIn("immutableGateRelease", payload["capabilities"])

    def test_exception_exit_taxonomy_is_stable(self):
        cases = [
            (cli.UsageFailure("x"), 2),
            (cli.PrerequisiteFailure("x"), 3),
            (cli.VerificationFailure("x"), 4),
            (cli.IntegrityFailure("x"), 5),
            (cli.TransientFailure("x"), 6),
            (cli.MutationFailure("x", rollback_complete=True), 7),
            (cli.MutationFailure("x", rollback_complete=False), 8),
        ]
        for failure, expected in cases:
            with self.subTest(expected=expected), mock.patch.object(
                cli, "build_parser"
            ) as parser_factory:
                parsed = mock.Mock(
                    top_command="doctor", evidence_dir=None,
                    execute=mock.Mock(side_effect=failure),
                )
                parser_factory.return_value.parse_args.return_value = parsed
                code, payload, _ = self.run_main(["doctor", "--json"])
                self.assertEqual(code, expected)
                self.assertFalse(payload["ok"])


class SubprocessContractTests(unittest.TestCase):
    def test_subprocess_always_uses_argument_array_and_no_shell(self):
        completed = subprocess.CompletedProcess(["node"], 0, stdout=b"ok", stderr=b"")
        with mock.patch.object(cli, "_command_exists", return_value=True), mock.patch.object(
            cli.subprocess, "run", return_value=completed
        ) as run:
            capture = cli._capture_command(("node", "--check", "safe.js"), label="syntax")
        self.assertEqual(capture.returncode, 0)
        positional, keywords = run.call_args
        self.assertIsInstance(positional[0], list)
        self.assertIs(keywords["shell"], False)
        self.assertTrue(keywords["capture_output"])

    def test_binary_gh_download_streams_without_shell_or_output_option(self):
        def execute(argv, **keywords):
            keywords["stdout"].write(b"zip-bytes")
            return subprocess.CompletedProcess(argv, 0, stdout=None, stderr=b"")

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            cli, "_command_exists", return_value=True
        ), mock.patch.object(cli.subprocess, "run", side_effect=execute) as run:
            destination = Path(temporary) / "artifact.zip"
            capture = cli._download_gh_archive(
                ("gh", "api", "repos/owner/repo/actions/artifacts/1/zip"),
                destination,
                label="download",
            )
        self.assertEqual(capture.returncode, 0)
        positional, keywords = run.call_args
        self.assertNotIn("--output", positional[0])
        self.assertIs(keywords["shell"], False)

    def test_verification_command_list_is_fixed_and_complete(self):
        labels = [item[0] for item in cli._verification_steps("release")]
        self.assertEqual(
            labels,
            [
                "syntax-auditor", "syntax-userscript", "unit", "network",
                "build-check", "integrity", "oracle", "tamper", "behavior",
            ],
        )
        commands = {label: argv for label, argv, _timeout in cli.RELEASE_STEPS}
        self.assertEqual(commands["network"], ("npm", "run", "test:network"))
        self.assertEqual(commands["oracle"], ("npm", "run", "test:oracle"))
        live = cli._verification_steps("live")
        self.assertEqual(
            live[-1][1], (
                "node", "scripts/audit_pages.mjs", "--discover-algumon",
                "--require-algumon-discovery",
            )
        )

    def test_verification_failure_maps_to_exit_four(self):
        captures = []
        for label, argv, _ in cli.FAST_STEPS:
            captures.append(cli.ExecutionCapture(label, argv, 1 if label == "unit" else 0, b"", b""))
        with mock.patch.object(cli, "_capture_command", side_effect=captures):
            with self.assertRaises(cli.VerificationFailure) as caught:
                cli._execute_verification("fast")
        self.assertEqual(caught.exception.exit_code, 4)
        self.assertEqual(caught.exception.details["failedSteps"], ["unit"])


class EvidenceContractTests(unittest.TestCase):
    def test_evidence_directory_is_create_new(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "evidence"
            first = cli._atomic_evidence_directory(destination, {"result.json": b"{}\n"})
            self.assertTrue((destination / "result.json").is_file())
            self.assertEqual(first["files"][0]["sha256"], hashlib.sha256(b"{}\n").hexdigest())
            with self.assertRaises(cli.IntegrityFailure):
                cli._atomic_evidence_directory(destination, {"other.json": b"{}"})

    def test_evidence_rejects_escape_and_duplicate_case(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(cli.IntegrityFailure):
                cli._atomic_evidence_directory(
                    Path(temporary) / "bad", {"../outside": b"x"}
                )
            with self.assertRaises(cli.IntegrityFailure):
                cli._atomic_evidence_directory(
                    Path(temporary) / "dup", {"A.json": b"x", "a.json": b"y"}
                )

    def test_release_evidence_binds_sha_and_manifest_hashes(self):
        manifest, manifest_bytes, artifacts = release_bundle()
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary) / "project"
            temporary_root.mkdir()
            (temporary_root / "release-manifest.json").write_bytes(manifest_bytes)
            for name, content in artifacts.items():
                (temporary_root / name).write_bytes(content)
            with mock.patch.object(cli, "PROJECT_ROOT", temporary_root), mock.patch.object(
                cli, "_git_source_binding", return_value="b" * 40
            ), mock.patch.object(
                cli, "_execute_verification", return_value=[{"id": "unit", "exitCode": 0}]
            ):
                args = mock.Mock(
                    source_ref="b" * 40,
                    output_dir=str(Path(temporary) / "sealed"),
                )
                result = cli.command_release_evidence(args)
                evidence = json.loads(
                    (Path(temporary) / "sealed" / "release-evidence.json").read_text("utf-8")
                )
        self.assertTrue(result["ok"])
        self.assertEqual(evidence["sourceSha"], "b" * 40)
        self.assertEqual(evidence["releaseVersion"], manifest["releaseVersion"])
        self.assertRegex(evidence["releaseManifest"]["canonicalJsonSha256"], r"^[0-9a-f]{64}$")


class ReleaseIntegrityTests(unittest.TestCase):
    def test_json_decoder_rejects_duplicate_members_and_nonfinite_numbers(self):
        for content in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.subTest(content=content), self.assertRaises(cli.IntegrityFailure):
                cli._decode_json(content, "test")

    def test_release_bundle_accepts_exact_hashes(self):
        manifest, manifest_bytes, artifacts = release_bundle()
        actual_manifest, records = cli._verify_release_files(manifest_bytes, artifacts)
        self.assertEqual(actual_manifest, manifest)
        self.assertEqual([item["path"] for item in records], [
            "hotdeal-focus.user.js", "release-manifest.json"
        ])

    def test_release_bundle_rejects_raw_hash_mismatch(self):
        _, manifest_bytes, artifacts = release_bundle()
        artifacts["hotdeal-focus.user.js"] += b"tamper"
        with self.assertRaises(cli.IntegrityFailure):
            cli._verify_release_files(manifest_bytes, artifacts)

    def test_release_bundle_rejects_manifest_byte_count_mismatch(self):
        manifest, _, artifacts = release_bundle()
        manifest["artifacts"]["hotdeal-focus.user.js"]["bytes"] += 1
        with self.assertRaisesRegex(cli.IntegrityFailure, "bytes"):
            cli._verify_release_files(json.dumps(manifest).encode(), artifacts)

    def test_gate_lock_pins_bytes_rules_version_protocol_and_url(self):
        gate_bytes = (ROOT / "filter.txt").read_bytes()
        raw_sha = hashlib.sha256(gate_bytes).hexdigest()
        rules_sha = cli.installed_filter_rules_sha256(gate_bytes)
        rule_count = sum(
            1 for line in cli.canonical_text_bytes(gate_bytes).decode().splitlines()
            if line.strip() and not line.lstrip().startswith("!")
        )
        manifest = {
            "protocolVersion": 2,
            "gateArtifactVersion": "2.0.2",
            "filterSubscriptionUrl": cli.GATE_LOCK_SUBSCRIPTION_URL,
            "artifacts": {"filter.txt": {
                "version": "2.0.2",
                "bytes": len(gate_bytes),
                "sha256": raw_sha,
                "installedRulesSha256": rules_sha,
            }},
        }
        lock = {
            "schemaVersion": 1,
            "protocolVersion": 2,
            "gateArtifactVersion": "2.0.2",
            "filterSubscriptionUrl": manifest["filterSubscriptionUrl"],
            "artifact": {
                "path": "filter.txt",
                "bytes": len(gate_bytes),
                "sha256": raw_sha,
                "installedRulesSha256": rules_sha,
            },
        }
        with mock.patch.multiple(
            cli,
            GATE_LOCK_PROTOCOL_VERSION=2,
            GATE_LOCK_ARTIFACT_VERSION="2.0.2",
            GATE_LOCK_SUBSCRIPTION_URL=manifest["filterSubscriptionUrl"],
            GATE_LOCK_BYTES=len(gate_bytes),
            GATE_LOCK_SHA256=raw_sha,
            GATE_LOCK_INSTALLED_RULES_SHA256=rules_sha,
            GATE_LOCK_RULE_COUNT=rule_count,
        ):
            actual = cli._validate_gate_artifact_lock(
                manifest, gate_bytes, json.dumps(lock).encode()
            )
            self.assertEqual(actual, lock)
            tampered = json.loads(json.dumps(lock))
            tampered["artifact"]["sha256"] = "0" * 64
            with self.assertRaises(cli.IntegrityFailure):
                cli._validate_gate_artifact_lock(
                    manifest, gate_bytes, json.dumps(tampered).encode()
                )

    def test_release_manifest_rejects_extra_public_artifact(self):
        manifest, _, _ = release_bundle()
        manifest["artifacts"]["README.md"] = {"sha256": "a" * 64}
        with self.assertRaises(cli.IntegrityFailure):
            cli._manifest_contract(json.dumps(manifest).encode())


class PagesSourceContractTests(unittest.TestCase):
    def test_pages_manifest_requires_exact_repo_binding(self):
        self.assertEqual(
            cli._validate_pages_manifest_url(cli.DEFAULT_PAGES_MANIFEST)[:2],
            ("heelee912", "adguard-hotdeal-focus"),
        )
        invalid = [
            "http://heelee912.github.io/adguard-hotdeal-focus/release-manifest.json",
            "https://user:pass@heelee912.github.io/adguard-hotdeal-focus/release-manifest.json",
            "https://heelee912.github.io/adguard-hotdeal-focus/release-manifest.json#x",
            "https://evil.example/adguard-hotdeal-focus/release-manifest.json",
            "https://heelee912.github.io/other/path/release-manifest.json",
            "https://heelee912.github.io/adguard-hotdeal-focus/Release-Manifest.json",
            "https://heelee912.github.io:invalid/adguard-hotdeal-focus/release-manifest.json",
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(cli.CliFailure):
                cli._validate_pages_manifest_url(value)

    def test_gate_subscription_url_rejects_repo_dot_segments(self):
        for repo_name in (".", ".."):
            value = (
                f"https://github.com/owner/{repo_name}/releases/download/"
                "gate-v1.0.0/filter.txt"
            )
            with self.subTest(repo=repo_name), self.assertRaises(cli.IntegrityFailure):
                cli._gate_subscription_coordinates(value, "1.0.0")

    def test_public_bundle_rejects_downloaded_hash_mismatch(self):
        manifest, manifest_bytes, artifacts = release_bundle()
        responses = {
            "release-manifest.json": manifest_bytes,
            "hotdeal-focus.user.js": artifacts["hotdeal-focus.user.js"] + b"tamper",
        }

        def read(url, binding):
            return responses[url.rsplit("/", 1)[1]], url

        with mock.patch.object(cli, "_read_bounded_https", side_effect=read):
            with self.assertRaises(cli.IntegrityFailure):
                cli._public_release_bundle(cli.DEFAULT_PAGES_MANIFEST)

    def test_gate_release_requires_immutable_metadata_and_verified_download(self):
        gate_bytes = b"! Version: 1.0.0\nexample.com##body\n"
        repo = "heelee912/adguard-hotdeal-focus"
        tag = "gate-v1.0.0"
        url = (
            "https://github.com/heelee912/adguard-hotdeal-focus/releases/download/"
            f"{tag}/filter.txt"
        )
        release = {
            "tag_name": tag,
            "draft": False,
            "prerelease": False,
            "immutable": True,
            "published_at": "2026-07-19T00:00:00Z",
            "assets": [{
                "id": 7,
                "name": "filter.txt",
                "state": "uploaded",
                "size": len(gate_bytes),
                "digest": f"sha256:{hashlib.sha256(gate_bytes).hexdigest()}",
                "browser_download_url": url,
            }],
        }

        def command(argv, *, label, timeout_seconds=cli.COMMAND_TIMEOUT_SECONDS, cwd=cli.PROJECT_ROOT):
            del timeout_seconds, cwd
            if label == "immutable-gate-asset-download":
                destination = Path(argv[argv.index("--dir") + 1]) / "filter.txt"
                destination.write_bytes(gate_bytes)
            return cli.ExecutionCapture(label, tuple(argv), 0, b"{}", b"")

        with mock.patch.object(cli, "_command_exists", return_value=True), \
                mock.patch.object(cli, "_gh_json", return_value=release), \
                mock.patch.object(cli, "_remote_gate_tag_commit", return_value="c" * 40), \
                mock.patch.object(cli, "_capture_command", side_effect=command):
            proof = cli._verify_immutable_gate_release(repo, tag, url, gate_bytes)
        self.assertTrue(proof["immutable"])
        self.assertEqual(proof["assetSha256"], hashlib.sha256(gate_bytes).hexdigest())

        invalid_releases = []
        mutable = json.loads(json.dumps(release))
        mutable["immutable"] = False
        invalid_releases.append(mutable)
        extra_asset = json.loads(json.dumps(release))
        extra_asset["assets"].append(dict(extra_asset["assets"][0], id=8, name="extra"))
        invalid_releases.append(extra_asset)
        wrong_digest = json.loads(json.dumps(release))
        wrong_digest["assets"][0]["digest"] = "sha256:" + "0" * 64
        invalid_releases.append(wrong_digest)
        wrong_url = json.loads(json.dumps(release))
        wrong_url["assets"][0]["browser_download_url"] = url + "?mutable=1"
        invalid_releases.append(wrong_url)
        for invalid_release in invalid_releases:
            with self.subTest(release=invalid_release), mock.patch.object(
                cli, "_command_exists", return_value=True
            ), mock.patch.object(cli, "_gh_json", return_value=invalid_release), \
                    mock.patch.object(
                        cli, "_remote_gate_tag_commit", return_value="c" * 40
                    ):
                with self.assertRaises(cli.IntegrityFailure):
                    cli._verify_immutable_gate_release(repo, tag, url, gate_bytes)

        def failed_attestation(argv, *, label, timeout_seconds=cli.COMMAND_TIMEOUT_SECONDS, cwd=cli.PROJECT_ROOT):
            del timeout_seconds, cwd
            return cli.ExecutionCapture(label, tuple(argv), 1, b"", b"failed")

        with mock.patch.object(cli, "_command_exists", return_value=True), \
                mock.patch.object(cli, "_gh_json", return_value=release), \
                mock.patch.object(cli, "_remote_gate_tag_commit", return_value="c" * 40), \
                mock.patch.object(cli, "_capture_command", side_effect=failed_attestation):
            with self.assertRaises(cli.IntegrityFailure):
                cli._verify_immutable_gate_release(repo, tag, url, gate_bytes)


class CloudContractTests(unittest.TestCase):
    def setUp(self):
        self.head_lease = mock.patch.object(
            cli,
            "_require_cloud_head_lease",
            side_effect=lambda repo, branch, source, phase: {
                "phase": phase,
                "branch": branch,
                "expectedSha": source,
                "observedSha": source,
                "exact": True,
            },
        )
        self.head_lease.start()
        self.addCleanup(self.head_lease.stop)

    @staticmethod
    def _source_authority():
        source_sha = "a" * 40
        return {
            "sourceSha": source_sha,
            "defaultBranch": "main",
            "workflows": [],
            "verify": {"exact": True},
            "headLeases": [{
                "phase": "initial-authority",
                "branch": "main",
                "expectedSha": source_sha,
                "observedSha": source_sha,
                "exact": True,
            }],
            "exact": True,
        }

    @staticmethod
    def _workflow_states(*states):
        values = states or (("active",) * len(cli.WORKFLOW_FILES))
        return {
            workflow: {
                "id": index + 1,
                "path": f".github/workflows/{workflow}",
                "state": values[index],
            }
            for index, workflow in enumerate(cli.WORKFLOW_FILES)
        }

    @classmethod
    def _cloud_state(
        cls,
        *,
        state_commits=True,
        pages_publish=True,
        pages_workflow=True,
        actions=None,
        workflow_states=None,
        automation_push_identity=None,
        branch_governance=None,
    ):
        secure_actions = {
            "enabled": True,
            "allowedActions": "selected",
            "shaPinningRequired": True,
            "selectedActions": {
                "githubOwnedAllowed": True,
                "verifiedAllowed": False,
                "patternsAllowed": [],
            },
            "defaultWorkflowPermissions": "read",
            "canApprovePullRequestReviews": False,
        }
        secure_identity = {
            "scopeRepository": "owner/repo",
            "environmentName": cli.MAIN_AUTOMATION_ENVIRONMENT,
            "secretName": cli.AUTOMATION_PUSH_SECRET_NAME,
            "environmentSecretPresent": True,
            "repositorySecretPresent": False,
            "fingerprintVariableName": cli.AUTOMATION_PUSH_FINGERPRINT_VARIABLE,
            "configuredFingerprint": "SHA256:" + ("A" * 43),
            "deployKeyTitle": cli.AUTOMATION_PUSH_DEPLOY_KEY_TITLE,
            "deployKeys": [{
                "id": 1,
                "title": cli.AUTOMATION_PUSH_DEPLOY_KEY_TITLE,
                "readOnly": False,
                "verified": True,
                "keyType": "ssh-ed25519",
                "fingerprint": "SHA256:" + ("A" * 43),
                "ed25519Exact": True,
            }],
            "writeKeyCount": 1,
            "reservedTitleKeyCount": 1,
            "keyExact": True,
            "exact": True,
        }
        secure_governance = {
            "target": "~DEFAULT_BRANCH",
            "namedRulesets": {
                name: {
                    "present": True,
                    "id": index + 1,
                    "exact": True,
                    "contract": contract,
                }
                for index, (name, contract) in enumerate(
                    cli._required_branch_ruleset_contracts().items()
                )
            },
            "repositoryRulesetCount": 2,
            "extraRulesets": [],
            "unprovenApplicableRulesets": [],
            "classicBranchProtection": {"present": False, "compatible": True},
            "exact": True,
        }
        secure_environments = {
            environment: {
                "name": environment,
                "present": True,
                "customBranchPolicy": True,
                "branchPolicies": [{"id": index + 1, "name": "main", "type": "branch"}],
                "exact": True,
            }
            for index, environment in enumerate((
                cli.MAIN_AUTOMATION_ENVIRONMENT,
                cli.PAGES_ENVIRONMENT,
            ))
        }
        return {
            "enableStateCommits": state_commits,
            "enablePagesPublish": pages_publish,
            "pagesWorkflow": pages_workflow,
            "actions": actions or secure_actions,
            "workflows": workflow_states or cls._workflow_states(),
            "pages": {
                "exists": pages_workflow,
                "buildType": "workflow" if pages_workflow else None,
            },
            "privilegedEnvironments": secure_environments,
            "automationPushIdentity": (
                automation_push_identity or secure_identity
            ),
            "branchGovernance": branch_governance or secure_governance,
        }

    def test_cloud_usage_errors_precede_remote_preflight(self):
        invalid = (
            mock.Mock(
                action="status", repo="owner/repo", workflow="verify.yml",
                run_id=None, output_root=None, evidence_dir=None, apply=True,
            ),
            mock.Mock(
                action="dispatch", repo="owner/repo", workflow="verify.yml",
                run_id="1", output_root=None, evidence_dir=None, apply=True,
            ),
            mock.Mock(
                action="download-evidence", repo="owner/repo", workflow="verify.yml",
                run_id=None, output_root=None, evidence_dir=None, apply=False,
            ),
        )
        with mock.patch.object(cli, "_cloud_preflight") as preflight:
            for args in invalid:
                with self.subTest(action=args.action), self.assertRaises(cli.UsageFailure):
                    cli.command_cloud(args)
        preflight.assert_not_called()

    def test_pages_state_distinguishes_absent_from_workflow_hosting(self):
        absent = cli.ExecutionCapture(
            "github-pages-state",
            ("gh",),
            1,
            b"HTTP/2.0 404 Not Found\nContent-Type: application/json\n\n{}\n",
            b"gh: Not Found (HTTP 404)\n",
        )
        workflow = cli.ExecutionCapture(
            "github-pages-state",
            ("gh",),
            0,
            (
                b"HTTP/2.0 200 OK\nContent-Type: application/json\n\n"
                b'{"build_type":"workflow"}\n'
            ),
            b"",
        )
        with mock.patch.object(cli, "_capture_command", return_value=absent):
            self.assertEqual(
                cli._github_pages_state("owner/repo"),
                {"exists": False, "buildType": None},
            )
        with mock.patch.object(cli, "_capture_command", return_value=workflow):
            self.assertEqual(
                cli._github_pages_state("owner/repo"),
                {"exists": True, "buildType": "workflow"},
            )

    def test_cloud_configuration_is_dry_run_then_exactly_post_verified(self):
        broad_actions = {
            "enabled": False,
            "allowedActions": "all",
            "shaPinningRequired": False,
            "selectedActions": None,
            "defaultWorkflowPermissions": "write",
            "canApprovePullRequestReviews": True,
        }
        before = self._cloud_state(
            state_commits=False,
            pages_publish=False,
            pages_workflow=False,
            actions=broad_actions,
            workflow_states=self._workflow_states(
                "disabled_manually", "disabled_inactivity"
            ),
        )
        after = self._cloud_state()
        with mock.patch.object(cli, "_gate_policy_repository"), mock.patch.object(
            cli, "_cloud_operating_state", return_value=before
        ), mock.patch.object(cli, "_capture_command") as mutation, mock.patch.object(
            cli, "_try_source_sha", return_value="a" * 40
        ):
            dry = cli._configure_cloud("owner/repo", False, None)
        self.assertEqual(dry["status"], "dry-run")
        mutation.assert_not_called()

        accepted = cli.ExecutionCapture("configure", ("gh",), 0, b"", b"")
        with mock.patch.object(cli, "_gate_policy_repository"), mock.patch.object(
            cli, "_cloud_operating_state", side_effect=(before, after)
        ), mock.patch.object(
            cli, "_github_actions_permissions_state",
            return_value={**after["actions"], "enabled": False},
        ), mock.patch.object(
            cli, "_capture_command", return_value=accepted
        ) as mutation, mock.patch.object(cli, "_try_source_sha", return_value="a" * 40):
            applied = cli._configure_cloud(
                "owner/repo", True, None, source_authority=self._source_authority()
            )
        self.assertEqual(applied["status"], "configured")
        self.assertTrue(applied["mutationApplied"])
        self.assertTrue(cli._cloud_configuration_is_exact(applied["configuration"]))
        self.assertEqual(mutation.call_count, 9)
        mutation_labels = [call.kwargs["label"] for call in mutation.call_args_list]
        for workflow in cli.WORKFLOW_FILES:
            self.assertIn(f"enable-workflow-{workflow}", mutation_labels)

    def test_cloud_configuration_does_not_mutate_an_already_secure_repo(self):
        secure = self._cloud_state()
        repository = {
            "nameWithOwner": "owner/repo",
            "visibility": "PUBLIC",
            "viewerPermission": "ADMIN",
        }
        with mock.patch.object(
            cli, "_gate_policy_repository", return_value=repository
        ), mock.patch.object(
            cli, "_cloud_operating_state", return_value=secure
        ), mock.patch.object(cli, "_capture_command") as mutation, mock.patch.object(
            cli, "_try_source_sha", return_value="a" * 40
        ):
            result = cli._configure_cloud(
                "owner/repo", True, None, source_authority=self._source_authority()
            )
        self.assertEqual(result["status"], "already-configured")
        self.assertFalse(result["mutationApplied"])
        self.assertEqual(result["repository"], repository)
        mutation.assert_not_called()

    def test_enabled_incomparable_actions_policy_is_rejected_before_mutation(self):
        for actions in (
            {
                "enabled": True,
                "allowedActions": "local_only",
                "shaPinningRequired": True,
                "selectedActions": None,
                "defaultWorkflowPermissions": "read",
                "canApprovePullRequestReviews": False,
            },
            {
                "enabled": True,
                "allowedActions": "selected",
                "shaPinningRequired": True,
                "selectedActions": {
                    "githubOwnedAllowed": False,
                    "verifiedAllowed": False,
                    "patternsAllowed": [],
                },
                "defaultWorkflowPermissions": "read",
                "canApprovePullRequestReviews": False,
            },
        ):
            with self.subTest(policy=actions["allowedActions"]), mock.patch.object(
                cli, "_gate_policy_repository"
            ), mock.patch.object(
                cli, "_cloud_operating_state",
                return_value=self._cloud_state(actions=actions),
            ), mock.patch.object(cli, "_capture_command") as mutation:
                with self.assertRaisesRegex(cli.IntegrityFailure, "cannot be broadened"):
                    cli._configure_cloud(
                        "owner/repo", True, None,
                        source_authority=self._source_authority(),
                    )
            mutation.assert_not_called()

    def test_actions_and_workflow_state_parsers_reject_malformed_remote_state(self):
        malformed_actions = {
            "enabled": "true",
            "allowed_actions": "selected",
            "sha_pinning_required": True,
        }
        with mock.patch.object(cli, "_gh_json", return_value=malformed_actions):
            with self.assertRaisesRegex(cli.IntegrityFailure, "policy is malformed"):
                cli._github_actions_permissions_state("owner/repo")

        malformed_workflow = {
            "id": 1,
            "path": ".github/workflows/not-allowlisted.yml",
            "state": "active",
        }
        with mock.patch.object(cli, "_gh_json", return_value=malformed_workflow):
            with self.assertRaisesRegex(cli.IntegrityFailure, "workflow state is malformed"):
                cli._github_workflow_states("owner/repo")

    def test_all_supported_workflow_states_are_observed_without_guessing(self):
        payloads = [
            {
                "id": index + 11,
                "path": f".github/workflows/{workflow}",
                "state": state,
            }
            for index, (workflow, state) in enumerate(zip(
                cli.WORKFLOW_FILES,
                ("active", "disabled_manually"),
            ))
        ]
        with mock.patch.object(cli, "_gh_json", side_effect=payloads):
            observed = cli._github_workflow_states("owner/repo")
        self.assertEqual(
            [observed[name]["state"] for name in cli.WORKFLOW_FILES],
            ["active", "disabled_manually"],
        )

    def test_api_mutation_writes_exact_typed_json_to_a_temporary_file(self):
        observed = {}

        def capture(argv, **kwargs):
            payload_path = Path(argv[argv.index("--input") + 1])
            observed["payload"] = payload_path.read_bytes()
            observed["argv"] = tuple(argv)
            return cli.ExecutionCapture(kwargs["label"], tuple(argv), 0, b"", b"")

        payload = {
            "github_owned_allowed": True,
            "verified_allowed": False,
            "patterns_allowed": [],
        }
        with mock.patch.object(cli, "_capture_command", side_effect=capture):
            cli._github_api_mutation(
                "repos/owner/repo/actions/permissions/selected-actions",
                "typed-json",
                payload=payload,
            )
        self.assertEqual(observed["payload"], cli.canonical_json_bytes(payload) + b"\n")
        self.assertIn(cli.GITHUB_API_VERSION_HEADER, observed["argv"])

    def test_ed25519_public_key_parser_derives_the_official_sha256_fingerprint(self):
        public_key = (
            "ssh-ed25519 "
            "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
        )
        record = cli._openssh_public_key_record(public_key)
        self.assertEqual(record["keyType"], "ssh-ed25519")
        self.assertTrue(record["ed25519Exact"])
        self.assertEqual(
            record["fingerprint"],
            "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
        )
        with self.assertRaises(cli.IntegrityFailure):
            cli._openssh_public_key_record(public_key.replace("ssh-ed25519", "ssh-rsa"))

    def test_active_cloud_contract_excludes_tag_and_filter_authority(self):
        required = cli._required_cloud_configuration()
        self.assertEqual(cli.WORKFLOW_FILES, ("verify.yml", "watch-dom.yml"))
        self.assertEqual(
            set(required["privilegedEnvironments"]),
            {cli.MAIN_AUTOMATION_ENVIRONMENT, cli.PAGES_ENVIRONMENT},
        )
        self.assertEqual(
            set(required["branchGovernance"]),
            {"immutableFastForwardHistory", "prAndVerifiedCi"},
        )
        serialized = json.dumps(required, sort_keys=True).casefold()
        self.assertNotIn("publish-gate", serialized)
        self.assertNotIn("immutablegatetag", serialized)
        self.assertNotIn("filter", serialized)

    def test_cloud_status_observes_only_two_active_environments_and_no_tag(self):
        environment_calls = []

        def environment_state(_repo, environment, _branch):
            environment_calls.append(environment)
            return {"name": environment, "present": True, "exact": True}

        with mock.patch.object(
            cli, "_github_environment_state", side_effect=environment_state
        ):
            environments = cli._github_privileged_environments_state(
                "owner/repo", "main"
            )
        self.assertEqual(
            environment_calls,
            [cli.MAIN_AUTOMATION_ENVIRONMENT, cli.PAGES_ENVIRONMENT],
        )

        exact = self._cloud_state()
        with mock.patch.object(
            cli, "_repository_variables", return_value={
                "ENABLE_STATE_COMMITS": "true",
                "ENABLE_PAGES_PUBLISH": "true",
            }
        ), mock.patch.object(
            cli, "_github_pages_state", return_value=exact["pages"]
        ), mock.patch.object(
            cli, "_github_privileged_environments_state", return_value=environments
        ), mock.patch.object(
            cli, "_github_actions_permissions_state", return_value=exact["actions"]
        ), mock.patch.object(
            cli, "_github_workflow_states", return_value=exact["workflows"]
        ), mock.patch.object(
            cli, "_automation_push_identity_state",
            return_value=exact["automationPushIdentity"],
        ), mock.patch.object(
            cli, "_github_branch_governance_state",
            return_value=exact["branchGovernance"],
        ), mock.patch.object(
            cli, "_immutable_gate_tag_state",
            side_effect=AssertionError("cloud status must not inspect an archival tag"),
        ) as tag_observation:
            observed = cli._cloud_operating_state("owner/repo", "main")

        self.assertNotIn("immutableGateTag", observed)
        self.assertEqual(
            set(observed["privilegedEnvironments"]),
            {cli.MAIN_AUTOMATION_ENVIRONMENT, cli.PAGES_ENVIRONMENT},
        )
        tag_observation.assert_not_called()

    def test_deploy_key_read_uses_pinned_api_and_never_returns_raw_key(self):
        public_key = (
            "ssh-ed25519 "
            "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
        )
        with mock.patch.object(
            cli,
            "_gh_json",
            return_value=[{
                "id": 7,
                "title": cli.AUTOMATION_PUSH_DEPLOY_KEY_TITLE,
                "read_only": False,
                "verified": True,
                "key": public_key,
            }],
        ) as github:
            records = cli._github_deploy_keys_state("owner/repo")
        argv = github.call_args.args[0]
        self.assertIn(cli.GITHUB_JSON_ACCEPT_HEADER, argv)
        self.assertIn(cli.GITHUB_API_VERSION_HEADER, argv)
        self.assertNotIn("key", records[0])
        self.assertNotIn(public_key, json.dumps(records))

    def test_automation_identity_requires_one_bound_verified_write_key_and_secret(self):
        fingerprint = "SHA256:" + ("A" * 43)
        key = {
            "id": 41,
            "title": cli.AUTOMATION_PUSH_DEPLOY_KEY_TITLE,
            "readOnly": False,
            "verified": True,
            "keyType": "ssh-ed25519",
            "fingerprint": fingerprint,
            "ed25519Exact": True,
        }
        variables = {cli.AUTOMATION_PUSH_FINGERPRINT_VARIABLE: fingerprint}
        with mock.patch.object(
            cli, "_repository_secret_names",
            return_value=frozenset(),
        ), mock.patch.object(
            cli, "_environment_secret_names",
            return_value=frozenset({cli.AUTOMATION_PUSH_SECRET_NAME}),
        ), mock.patch.object(cli, "_github_deploy_keys_state", return_value=[key]):
            state = cli._automation_push_identity_state("owner/repo", variables)
        self.assertTrue(state["exact"])
        self.assertNotIn("publicKey", state)
        self.assertNotIn("key", state["deployKeys"][0])

        with mock.patch.object(
            cli, "_repository_secret_names", return_value=frozenset()
        ), mock.patch.object(
            cli, "_environment_secret_names", return_value=frozenset()
        ), mock.patch.object(cli, "_github_deploy_keys_state", return_value=[key]):
            missing_secret = cli._automation_push_identity_state("owner/repo", variables)
        self.assertFalse(missing_secret["exact"])

        with mock.patch.object(
            cli, "_repository_secret_names", return_value=frozenset()
        ), mock.patch.object(
            cli, "_environment_secret_names"
        ) as environment_secrets, mock.patch.object(
            cli, "_github_deploy_keys_state", return_value=[]
        ):
            absent_environment = cli._automation_push_identity_state(
                "owner/repo", variables, environment_exists=False
            )
        environment_secrets.assert_not_called()
        self.assertFalse(absent_environment["environmentSecretPresent"])
        self.assertFalse(absent_environment["exact"])

        with mock.patch.object(
            cli, "_repository_secret_names",
            return_value=frozenset({cli.AUTOMATION_PUSH_SECRET_NAME}),
        ), mock.patch.object(
            cli, "_environment_secret_names",
            return_value=frozenset({cli.AUTOMATION_PUSH_SECRET_NAME}),
        ), mock.patch.object(cli, "_github_deploy_keys_state", return_value=[key]):
            duplicate_scope = cli._automation_push_identity_state(
                "owner/repo", variables
            )
        self.assertTrue(duplicate_scope["keyExact"])
        self.assertTrue(duplicate_scope["repositorySecretPresent"])
        self.assertFalse(duplicate_scope["exact"])

    def test_privileged_environment_requires_one_exact_default_branch_policy(self):
        environment = cli.MAIN_AUTOMATION_ENVIRONMENT
        value = {
            "name": environment,
            "protection_rules": [],
            "can_admins_bypass": True,
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
        }
        policies = {
            "total_count": 1,
            "branch_policies": [{"id": 4, "name": "main", "type": "branch"}],
        }
        with mock.patch.object(cli, "_gh_included_json", return_value=(200, value)), \
                mock.patch.object(cli, "_gh_json", return_value=policies):
            state = cli._github_environment_state("owner/repo", environment, "main")
        self.assertTrue(state["exact"])

        policies["branch_policies"][0]["type"] = "tag"
        with mock.patch.object(cli, "_gh_included_json", return_value=(200, value)), \
                mock.patch.object(cli, "_gh_json", return_value=policies):
            wrong_type = cli._github_environment_state(
                "owner/repo", environment, "main"
            )
        self.assertFalse(wrong_type["exact"])

    def test_ruleset_contract_layers_deploy_key_bypass_below_unbypassable_history(self):
        contracts = cli._required_branch_ruleset_contracts()
        self.assertEqual(
            set(contracts), {"prAndVerifiedCi", "immutableFastForwardHistory"}
        )
        pr = contracts["prAndVerifiedCi"]
        history = contracts["immutableFastForwardHistory"]
        for contract in (pr, history):
            self.assertEqual(contract["target"], "branch")
            self.assertEqual(contract["enforcement"], "active")
            self.assertEqual(
                contract["conditions"],
                {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
            )
        self.assertEqual(
            pr["bypass_actors"],
            [{"actor_id": None, "actor_type": "DeployKey", "bypass_mode": "always"}],
        )
        self.assertEqual(history["bypass_actors"], [])
        self.assertEqual(
            [rule["type"] for rule in history["rules"]],
            ["deletion", "non_fast_forward", "required_linear_history"],
        )
        pull_request = pr["rules"][0]
        self.assertEqual(pull_request["type"], "pull_request")
        self.assertEqual(
            pull_request["parameters"]["required_approving_review_count"], 0
        )
        self.assertTrue(
            pull_request["parameters"]["required_review_thread_resolution"]
        )
        self.assertEqual(
            pull_request["parameters"]["allowed_merge_methods"],
            ["squash", "rebase"],
        )
        status_parameters = pr["rules"][1]["parameters"]
        self.assertTrue(status_parameters["strict_required_status_checks_policy"])
        self.assertFalse(status_parameters["do_not_enforce_on_create"])
        status = status_parameters["required_status_checks"]
        self.assertEqual(
            status,
            [{"context": "verify", "integration_id": 15368}],
        )
        mutation_payload = cli._ruleset_mutation_payload(pr)
        self.assertNotIn(
            "required_reviewers", mutation_payload["rules"][0]["parameters"]
        )

    def test_unrelated_branch_and_every_tag_ruleset_are_proven_irrelevant(self):
        unrelated_branch = {
            "target": "branch",
            "conditions": {"ref_name": {"include": ["refs/heads/archive"], "exclude": []}},
        }
        unrelated_tag = {
            "target": "tag",
            "conditions": {"ref_name": {"include": ["~ALL"], "exclude": []}},
        }
        self.assertFalse(cli._ruleset_ref_scope(unrelated_branch, "main")["relevant"])
        tag_scope = cli._ruleset_ref_scope(unrelated_tag, "main")
        self.assertFalse(tag_scope["relevant"])
        self.assertEqual(tag_scope["reason"], "active-automation-does-not-write-tags")
        for target in ("push", "repository"):
            with self.subTest(target=target):
                self.assertTrue(cli._ruleset_ref_scope(
                    {"target": target, "conditions": {}}, "main"
                )["relevant"])

    def test_unproven_extra_or_classic_governance_refuses_every_mutation(self):
        cases = (
            {
                "unprovenApplicableRulesets": [{"id": 44, "target": "push"}],
                "classicBranchProtection": {"present": False, "compatible": True},
            },
            {
                "unprovenApplicableRulesets": [],
                "classicBranchProtection": {"present": True, "compatible": False},
            },
        )
        for governance_override in cases:
            with self.subTest(state=governance_override):
                state = self._cloud_state()
                state["branchGovernance"] = {
                    **state["branchGovernance"],
                    **governance_override,
                    "exact": False,
                }
                with mock.patch.object(cli, "_gate_policy_repository"), \
                        mock.patch.object(cli, "_cloud_operating_state", return_value=state), \
                        mock.patch.object(cli, "_github_api_mutation") as api_mutation, \
                        mock.patch.object(cli, "_capture_command") as command_mutation:
                    with self.assertRaises(cli.IntegrityFailure):
                        cli._configure_cloud(
                            "owner/repo", True, None,
                            source_authority=self._source_authority(),
                        )
                api_mutation.assert_not_called()
                command_mutation.assert_not_called()

    def test_first_remote_mutation_is_preceded_by_a_fresh_source_head_lease(self):
        before = self._cloud_state(actions={
            **self._cloud_state()["actions"],
            "shaPinningRequired": False,
        })
        after = self._cloud_state()
        events = []
        accepted = cli.ExecutionCapture("accepted", ("gh",), 0, b"", b"")

        def lease(_repo, _branch, source, phase):
            events.append(f"lease:{phase}")
            return {
                "phase": phase, "branch": "main", "expectedSha": source,
                "observedSha": source, "exact": True,
            }

        def mutation(_endpoint, label, **_kwargs):
            events.append(f"mutation:{label}")
            return accepted

        with mock.patch.object(cli, "_require_cloud_head_lease", side_effect=lease), \
                mock.patch.object(cli, "_gate_policy_repository", return_value={}), \
                mock.patch.object(cli, "_cloud_operating_state", side_effect=(before, after)), \
                mock.patch.object(cli, "_github_api_mutation", side_effect=mutation), \
                mock.patch.object(cli, "_capture_command", return_value=accepted), \
                mock.patch.object(cli, "_github_actions_permissions_state", return_value=after["actions"]):
            result = cli._configure_cloud(
                "owner/repo", True, None, source_authority=self._source_authority()
            )
        self.assertTrue(result["ok"])
        self.assertLess(
            events.index("lease:immediately-before-first-mutation"),
            events.index("mutation:narrow-github-actions-policy"),
        )

    def test_verify_job_authority_allows_only_pages_to_fail(self):
        source_sha = "a" * 40
        run = {"id": 77, "conclusion": "failure", "event": "push"}
        verify_job = {
            "id": 88,
            "name": "verify",
            "status": "completed",
            "conclusion": "success",
            "check_run_url": "https://api.github.com/repos/owner/repo/check-runs/99",
        }
        pages_job = {
            "id": 89, "name": "publish-pages", "status": "completed",
            "conclusion": "failure",
        }
        check = {
            "id": 99,
            "name": "verify",
            "status": "completed",
            "conclusion": "success",
            "app": {"id": 15368},
            "details_url": "https://github.com/owner/repo/actions/runs/77/job/88",
            "head_sha": source_sha,
        }
        with mock.patch.object(
            cli, "_gh_json",
            return_value={"total_count": 2, "jobs": [verify_job, pages_job]},
        ):
            authority = cli._verify_run_jobs_authority("owner/repo", run, [check])
        self.assertTrue(authority["exact"])
        self.assertEqual(authority["allowedFailedJobs"], ["publish-pages"])

        bad_job = {**pages_job, "name": "unexpected-failure"}
        with mock.patch.object(
            cli, "_gh_json",
            return_value={"total_count": 2, "jobs": [verify_job, bad_job]},
        ):
            self.assertIsNone(cli._verify_run_jobs_authority("owner/repo", run, [check]))

    def test_source_authority_accepts_a_red_workflow_only_for_pages_failure(self):
        source_sha = "a" * 40
        run = {
            "id": 77,
            "path": ".github/workflows/verify.yml",
            "head_sha": source_sha,
            "head_branch": "main",
            "event": "push",
            "status": "completed",
            "conclusion": "failure",
        }
        jobs = {
            "total_count": 2,
            "jobs": [
                {
                    "id": 88, "name": "verify", "status": "completed",
                    "conclusion": "success",
                    "check_run_url": "https://api.github.com/repos/owner/repo/check-runs/99",
                },
                {
                    "id": 89, "name": "publish-pages", "status": "completed",
                    "conclusion": "failure",
                },
            ],
        }
        check = {
            "id": 99, "name": "verify", "status": "completed",
            "conclusion": "success", "app": {"id": 15368},
            "details_url": "https://github.com/owner/repo/actions/runs/77/job/88",
        }
        responses = (
            {"total_count": 1, "workflow_runs": [run]},
            {"total_count": 1, "check_runs": [check]},
            jobs,
        )
        with mock.patch.object(cli, "_gh_json", side_effect=responses):
            authority = cli._verify_check_authority("owner/repo", "main", source_sha)
        self.assertTrue(authority["exact"])
        self.assertEqual(authority["runConclusion"], "failure")
        self.assertEqual(authority["allowedFailedJobs"], ["publish-pages"])

        wrong_app = {**check, "app": {"id": 1}}
        responses = (
            {"total_count": 1, "workflow_runs": [run]},
            {"total_count": 1, "check_runs": [wrong_app]},
            jobs,
        )
        with mock.patch.object(cli, "_gh_json", side_effect=responses):
            with self.assertRaisesRegex(cli.IntegrityFailure, "no exact"):
                cli._verify_check_authority("owner/repo", "main", source_sha)

    def test_workflow_blob_authority_rejects_local_remote_byte_drift(self):
        local = cli.ExecutionCapture("local", ("git",), 0, b"local\n", b"")
        remote = {
            "type": "file",
            "path": ".github/workflows/verify.yml",
            "encoding": "base64",
            "size": len(b"remote\n"),
            "content": "cmVtb3RlCg==",
        }
        with mock.patch.object(cli, "_capture_command", return_value=local), \
                mock.patch.object(cli, "_gh_json", return_value=remote):
            with self.assertRaisesRegex(cli.IntegrityFailure, "differs"):
                cli._workflow_blob_authority("owner/repo", "verify.yml", "a" * 40)

    def test_duplicate_reserved_ruleset_name_is_rejected_before_any_mutation(self):
        listing = [
            {
                "id": identifier,
                "name": cli.BRANCH_GOVERNANCE_PR_RULESET_NAME,
                "source_type": "Repository",
                "source": "owner/repo",
            }
            for identifier in (10, 11)
        ]
        with mock.patch.object(cli, "_gh_json", return_value=listing) as github:
            with self.assertRaisesRegex(cli.IntegrityFailure, "ambiguous"):
                cli._github_branch_governance_state("owner/repo")
        argv = github.call_args.args[0]
        self.assertIn(cli.GITHUB_JSON_ACCEPT_HEADER, argv)
        self.assertIn(cli.GITHUB_API_VERSION_HEADER, argv)

    def test_unknown_write_deploy_key_rejects_configuration_before_mutation(self):
        unbound = {
            "scopeRepository": "owner/repo",
            "secretPresent": False,
            "configuredFingerprint": None,
            "deployKeys": [{"id": 9, "title": "unknown", "readOnly": False}],
            "writeKeyCount": 1,
            "reservedTitleKeyCount": 0,
            "exact": False,
        }
        state = self._cloud_state(automation_push_identity=unbound)
        with mock.patch.object(cli, "_gate_policy_repository"), mock.patch.object(
            cli, "_cloud_operating_state", return_value=state
        ), mock.patch.object(cli, "_capture_command") as mutation, mock.patch.object(
            cli, "_generated_automation_push_identity"
        ) as generator:
            with self.assertRaisesRegex(cli.IntegrityFailure, "unknown or unbound"):
                cli._configure_cloud(
                    "owner/repo", True, None,
                    source_authority=self._source_authority(),
                )
        mutation.assert_not_called()
        generator.assert_not_called()

    def test_private_stdin_runner_never_copies_secret_into_argv_or_capture(self):
        private_value = b"-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-material\n"
        completed = mock.Mock(returncode=0, stderr=b"")
        with tempfile.TemporaryDirectory() as temporary:
            private_path = Path(temporary) / "identity"
            private_path.write_bytes(private_value)
            with mock.patch.object(cli, "_command_exists", return_value=True), \
                    mock.patch.object(cli.subprocess, "run", return_value=completed) as run:
                capture = cli._capture_command_with_private_stdin_file(
                    ("gh", "secret", "set", cli.AUTOMATION_PUSH_SECRET_NAME),
                    private_path,
                    label="secret-input",
                )
        self.assertNotIn(private_value.decode(), " ".join(capture.argv))
        self.assertEqual(capture.stdout, b"")
        self.assertNotIn(private_value, capture.stderr)
        self.assertNotIn("input", run.call_args.kwargs)
        self.assertEqual(run.call_args.kwargs["stdout"], cli.subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["stderr"], cli.subprocess.DEVNULL)
        self.assertNotIn("private-material", json.dumps(capture.summary()))

    def test_governance_is_proven_before_missing_identity_is_created(self):
        missing_identity = {
            "scopeRepository": "owner/repo",
            "environmentName": cli.MAIN_AUTOMATION_ENVIRONMENT,
            "secretName": cli.AUTOMATION_PUSH_SECRET_NAME,
            "environmentSecretPresent": False,
            "repositorySecretPresent": False,
            "fingerprintVariableName": cli.AUTOMATION_PUSH_FINGERPRINT_VARIABLE,
            "configuredFingerprint": None,
            "deployKeyTitle": cli.AUTOMATION_PUSH_DEPLOY_KEY_TITLE,
            "deployKeys": [],
            "writeKeyCount": 0,
            "reservedTitleKeyCount": 0,
            "exact": False,
        }
        missing_governance = {
            "target": "~DEFAULT_BRANCH",
            "namedRulesets": {
                name: {"present": False, "id": None, "exact": False, "contract": None}
                for name in cli._required_branch_ruleset_contracts()
            },
            "repositoryRulesetCount": 0,
            "extraRulesets": [],
            "unprovenApplicableRulesets": [],
            "classicBranchProtection": {"present": False, "compatible": True},
            "exact": False,
        }
        before = self._cloud_state(
            automation_push_identity=missing_identity,
            branch_governance=missing_governance,
        )
        after = self._cloud_state()
        fingerprint = "SHA256:" + ("B" * 43)
        after["automationPushIdentity"]["configuredFingerprint"] = fingerprint
        after["automationPushIdentity"]["deployKeys"][0]["fingerprint"] = fingerprint
        required_contracts = cli._required_branch_ruleset_contracts()

        def governance_state(exact_names=()):
            exact_name_set = set(exact_names)
            named = {}
            for index, (name, contract) in enumerate(required_contracts.items()):
                if name in exact_name_set:
                    named[name] = {
                        "present": True,
                        "id": index + 1,
                        "exact": True,
                        "contract": contract,
                    }
                else:
                    named[name] = {
                        "present": False,
                        "id": None,
                        "exact": False,
                        "contract": None,
                    }
            return {
                "target": "~DEFAULT_BRANCH",
                "namedRulesets": named,
                "repositoryRulesetCount": sum(
                    1 for item in named.values() if item["present"]
                ),
                "extraRulesets": [],
                "unprovenApplicableRulesets": [],
                "classicBranchProtection": {"present": False, "compatible": True},
                "exact": exact_name_set == set(required_contracts),
            }

        governance_observations = iter((
            governance_state(("immutableFastForwardHistory",)),
            governance_state(("immutableFastForwardHistory", "prAndVerifiedCi")),
        ))

        def observe_governance(*_args):
            return next(governance_observations, after["branchGovernance"])

        operations = []
        prerequisite_checks = []
        accepted = cli.ExecutionCapture("accepted", ("gh",), 0, b"", b"")

        def capture(argv, **kwargs):
            operations.append(kwargs["label"])
            return cli.ExecutionCapture(kwargs["label"], tuple(argv), 0, b"", b"")

        def api_mutation(endpoint, label, **kwargs):
            operations.append(label)
            if label == "create-automation-push-deploy-key":
                payload = kwargs["payload"]
                self.assertTrue(payload["key"].startswith("ssh-ed25519 "))
                self.assertNotIn("PRIVATE", payload["key"])
                self.assertFalse(payload["read_only"])
            return cli.ExecutionCapture(label, ("gh",), 0, b"", b"")

        def command_exists(command):
            prerequisite_checks.append(command)
            return command == "ssh-keygen"

        with tempfile.TemporaryDirectory() as temporary:
            private_path = Path(temporary) / "identity"
            private_path.write_text("private-material", encoding="utf-8")
            generated = {
                "privatePath": private_path,
                "publicKey": (
                    "ssh-ed25519 "
                    "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
                ),
                "fingerprint": fingerprint,
            }
            with mock.patch.object(
                cli,
                "_gate_policy_repository",
                return_value={
                    "nameWithOwner": "owner/repo",
                    "visibility": "PUBLIC",
                    "viewerPermission": "ADMIN",
                },
            ), mock.patch.object(
                cli, "_cloud_operating_state", side_effect=(before, after)
            ), mock.patch.object(
                cli, "_generated_automation_push_identity",
                return_value=contextlib.nullcontext(generated),
            ), mock.patch.object(
                cli, "_capture_command_with_private_stdin_file",
                side_effect=lambda argv, path, **kwargs: (
                    operations.append(kwargs["label"]) or accepted
                ),
            ), mock.patch.object(
                cli, "_capture_command", side_effect=capture
            ), mock.patch.object(
                cli, "_github_api_mutation", side_effect=api_mutation
            ), mock.patch.object(
                cli, "_repository_variables",
                return_value={
                    "ENABLE_STATE_COMMITS": "false",
                    cli.AUTOMATION_PUSH_FINGERPRINT_VARIABLE: fingerprint,
                },
            ), mock.patch.object(
                cli, "_repository_secret_names",
                return_value=frozenset(),
            ), mock.patch.object(
                cli, "_environment_secret_names",
                return_value=frozenset({cli.AUTOMATION_PUSH_SECRET_NAME}),
            ), mock.patch.object(
                cli, "_automation_push_identity_state",
                side_effect=(
                    missing_identity,
                    missing_identity,
                    after["automationPushIdentity"],
                ),
            ), mock.patch.object(
                cli, "_github_branch_governance_state",
                side_effect=observe_governance,
            ), mock.patch.object(
                cli, "_github_actions_permissions_state", return_value=after["actions"]
            ), mock.patch.object(
                cli, "_command_exists", side_effect=command_exists
            ), mock.patch.object(cli, "_try_source_sha", return_value="a" * 40):
                result = cli._configure_cloud(
                    "owner/repo", True, None,
                    source_authority=self._source_authority(),
                )
        self.assertTrue(result["ok"])
        self.assertTrue(result["activationPrecondition"]["proven"])
        self.assertLess(
            operations.index("configure-ruleset-immutableFastForwardHistory"),
            operations.index("configure-ruleset-prAndVerifiedCi"),
        )
        self.assertLess(
            operations.index("configure-ruleset-prAndVerifiedCi"),
            operations.index("set-automation-push-private-key-secret"),
        )
        self.assertLess(
            operations.index("set-automation-push-private-key-secret"),
            operations.index("create-automation-push-deploy-key"),
        )
        self.assertFalse(any("tag" in operation.casefold() for operation in operations))
        self.assertEqual(prerequisite_checks, ["ssh-keygen"])
        self.assertNotIn("private-material", json.dumps(result))

    def test_exact_identity_never_observes_or_binds_an_archival_gate_tag(self):
        exact = self._cloud_state()
        with mock.patch.object(
            cli, "_gate_policy_repository", return_value={}
        ), mock.patch.object(
            cli, "_cloud_operating_state", return_value=exact
        ), mock.patch.object(
            cli, "_immutable_gate_tag_state",
            side_effect=AssertionError("archival tag state must be unreachable"),
        ) as tag_observation, mock.patch.object(
            cli, "_bind_immutable_gate_tag",
            side_effect=AssertionError("archival tag binding must be unreachable"),
        ) as tag_binding, mock.patch.object(
            cli, "_generated_automation_push_identity"
        ) as identity_generator, mock.patch.object(
            cli, "_capture_command"
        ) as mutation:
            result = cli._configure_cloud(
                "owner/repo", True, None,
                source_authority=self._source_authority(),
            )

        self.assertEqual(result["status"], "already-configured")
        self.assertNotIn("immutableGateTag", result["configuration"])
        tag_observation.assert_not_called()
        tag_binding.assert_not_called()
        identity_generator.assert_not_called()
        mutation.assert_not_called()

    def test_ambiguous_secret_write_cannot_be_proved_by_secret_name_presence(self):
        missing_identity = {
            "writeKeyCount": 0,
            "reservedTitleKeyCount": 0,
            "exact": False,
        }
        before = self._cloud_state(
            automation_push_identity=missing_identity,
        )
        fingerprint = "SHA256:" + ("C" * 43)
        rejected_secret = cli.ExecutionCapture(
            "set-secret", ("gh",), 1, b"", b"ambiguous timeout"
        )
        accepted = cli.ExecutionCapture("accepted", ("gh",), 0, b"", b"")
        with tempfile.TemporaryDirectory() as temporary:
            private_path = Path(temporary) / "identity"
            private_path.write_text("private-material", encoding="utf-8")
            generated = {
                "privatePath": private_path,
                "publicKey": (
                    "ssh-ed25519 "
                    "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
                ),
                "fingerprint": fingerprint,
            }
            with mock.patch.object(cli, "_gate_policy_repository"), mock.patch.object(
                cli, "_cloud_operating_state", return_value=before
            ), mock.patch.object(
                cli, "_generated_automation_push_identity",
                return_value=contextlib.nullcontext(generated),
            ), mock.patch.object(
                cli, "_capture_command_with_private_stdin_file",
                return_value=rejected_secret,
            ), mock.patch.object(
                cli, "_capture_command", return_value=accepted
            ), mock.patch.object(
                cli, "_repository_variables",
                return_value={cli.AUTOMATION_PUSH_FINGERPRINT_VARIABLE: fingerprint},
            ), mock.patch.object(
                cli, "_repository_secret_names",
                return_value=frozenset({cli.AUTOMATION_PUSH_SECRET_NAME}),
            ), mock.patch.object(
                cli, "_automation_push_identity_state", return_value=missing_identity
            ), mock.patch.object(
                cli, "_github_branch_governance_state",
                return_value=before["branchGovernance"],
            ), mock.patch.object(
                cli, "_github_actions_permissions_state", return_value=before["actions"]
            ), mock.patch.object(
                cli, "_github_api_mutation"
            ) as api_mutation, mock.patch.object(
                cli, "_try_source_sha", return_value="a" * 40
            ), mock.patch.object(cli.time, "sleep"):
                result = cli._configure_cloud(
                    "owner/repo", True, None,
                    source_authority=self._source_authority(),
                )
        self.assertFalse(result["ok"])
        self.assertFalse(result["activationPrecondition"]["proven"])
        api_mutation.assert_not_called()

    def test_unproven_governance_skips_every_automation_key_mutation(self):
        missing_identity = {
            "writeKeyCount": 0,
            "reservedTitleKeyCount": 0,
            "exact": False,
        }
        missing_governance = {
            "namedRulesets": {
                name: {"id": None, "exact": False}
                for name in cli._required_branch_ruleset_contracts()
            },
            "extraRulesets": [],
            "unprovenApplicableRulesets": [],
            "classicBranchProtection": {"present": False, "compatible": True},
            "exact": False,
        }
        before = self._cloud_state(
            automation_push_identity=missing_identity,
            branch_governance=missing_governance,
        )
        rejected = cli.ExecutionCapture(
            "ruleset", ("gh",), 1, b"", b"remote state unknown"
        )
        with mock.patch.object(cli, "_gate_policy_repository"), mock.patch.object(
            cli, "_cloud_operating_state", side_effect=[before] * 7
        ), mock.patch.object(
            cli, "_github_api_mutation", return_value=rejected
        ) as ruleset_mutation, mock.patch.object(
            cli, "_github_branch_governance_state", return_value=missing_governance
        ), mock.patch.object(
            cli, "_generated_automation_push_identity"
        ) as identity_generator, mock.patch.object(
            cli, "_capture_command_with_private_stdin_file"
        ) as secret_mutation, mock.patch.object(
            cli, "_github_actions_permissions_state", return_value=before["actions"]
        ), mock.patch.object(
            cli, "_try_source_sha", return_value="a" * 40
        ), mock.patch.object(cli.time, "sleep"):
            result = cli._configure_cloud(
                "owner/repo", True, None, source_authority=self._source_authority()
            )

        self.assertFalse(result["ok"])
        self.assertFalse(result["activationPrecondition"]["proven"])
        self.assertIn(
            "governance was not proven",
            result["activationPrecondition"]["identityObservationError"],
        )
        self.assertEqual(ruleset_mutation.call_count, 1)
        self.assertEqual(
            ruleset_mutation.call_args.args[1],
            "configure-ruleset-immutableFastForwardHistory",
        )
        identity_generator.assert_not_called()
        secret_mutation.assert_not_called()

    def test_accepted_but_unobserved_history_rule_stops_before_pr_bypass(self):
        missing_identity = {
            "writeKeyCount": 0,
            "reservedTitleKeyCount": 0,
            "exact": False,
        }
        missing_governance = {
            "namedRulesets": {
                name: {"id": None, "exact": False, "contract": None}
                for name in cli._required_branch_ruleset_contracts()
            },
            "extraRulesets": [],
            "unprovenApplicableRulesets": [],
            "classicBranchProtection": {"present": False, "compatible": True},
            "exact": False,
        }
        before = self._cloud_state(
            automation_push_identity=missing_identity,
            branch_governance=missing_governance,
        )
        accepted = cli.ExecutionCapture("ruleset", ("gh",), 0, b"", b"")
        with mock.patch.object(cli, "_gate_policy_repository"), mock.patch.object(
            cli, "_cloud_operating_state", side_effect=[before] * 7
        ), mock.patch.object(
            cli, "_github_api_mutation", return_value=accepted
        ) as ruleset_mutation, mock.patch.object(
            cli, "_github_branch_governance_state", return_value=missing_governance
        ), mock.patch.object(
            cli, "_generated_automation_push_identity"
        ) as identity_generator, mock.patch.object(
            cli, "_capture_command_with_private_stdin_file"
        ) as secret_mutation, mock.patch.object(
            cli, "_github_actions_permissions_state", return_value=before["actions"]
        ), mock.patch.object(
            cli, "_try_source_sha", return_value="a" * 40
        ), mock.patch.object(cli.time, "sleep"):
            result = cli._configure_cloud(
                "owner/repo", True, None, source_authority=self._source_authority()
            )

        self.assertFalse(result["ok"])
        self.assertEqual(ruleset_mutation.call_count, 1)
        self.assertEqual(
            ruleset_mutation.call_args.args[1],
            "configure-ruleset-immutableFastForwardHistory",
        )
        self.assertIn(
            "was not observed exact",
            result["activationPrecondition"]["governanceObservationError"],
        )
        identity_generator.assert_not_called()
        secret_mutation.assert_not_called()

    def test_archival_tag_ruleset_is_irrelevant_to_exact_branch_governance(self):
        repo = "owner/repo"
        required = cli._required_branch_ruleset_contracts()
        required_details = []
        listing = []
        for identifier, contract in enumerate(required.values(), start=10):
            listing.append({
                "id": identifier,
                "name": contract["name"],
                "source_type": "Repository",
                "source": repo,
            })
            required_details.append({
                "id": identifier,
                "source_type": "Repository",
                "source": repo,
                **contract,
            })
        legacy_tag = {
            "id": 99,
            "name": cli.GATE_TAG_FREEZE_RULESET_NAME,
            "source_type": "Repository",
            "source": repo,
            "target": "tag",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {"include": ["refs/tags/gate-v2.0.2"], "exclude": []}
            },
            "rules": [{"type": "deletion"}],
        }
        listing.append({key: legacy_tag[key] for key in (
            "id", "name", "source_type", "source"
        )})
        with mock.patch.object(
            cli, "_gh_json",
            side_effect=(listing, *required_details, legacy_tag),
        ), mock.patch.object(
            cli, "_github_classic_branch_protection_state",
            return_value={"present": False, "compatible": True},
        ):
            governance = cli._github_branch_governance_state(repo)

        self.assertTrue(governance["exact"])
        self.assertEqual(governance["unprovenApplicableRulesets"], [])
        self.assertEqual(len(governance["extraRulesets"]), 1)
        self.assertEqual(
            governance["extraRulesets"][0]["scope"],
            {"relevant": False, "reason": "active-automation-does-not-write-tags"},
        )

    def test_write_key_race_is_rechecked_immediately_before_key_provisioning(self):
        missing_identity = {
            "writeKeyCount": 0,
            "reservedTitleKeyCount": 0,
            "exact": False,
        }
        raced_identity = {
            "writeKeyCount": 1,
            "reservedTitleKeyCount": 0,
            "exact": False,
        }
        before = self._cloud_state(automation_push_identity=missing_identity)
        with mock.patch.object(cli, "_gate_policy_repository"), mock.patch.object(
            cli, "_cloud_operating_state", side_effect=[before] * 7
        ), mock.patch.object(
            cli, "_github_branch_governance_state",
            return_value=before["branchGovernance"],
        ), mock.patch.object(
            cli, "_automation_push_identity_state", return_value=raced_identity
        ), mock.patch.object(
            cli, "_generated_automation_push_identity"
        ) as identity_generator, mock.patch.object(
            cli, "_capture_command_with_private_stdin_file"
        ) as secret_mutation, mock.patch.object(
            cli, "_github_actions_permissions_state", return_value=before["actions"]
        ), mock.patch.object(
            cli, "_try_source_sha", return_value="a" * 40
        ), mock.patch.object(cli.time, "sleep"):
            result = cli._configure_cloud(
                "owner/repo", True, None, source_authority=self._source_authority()
            )

        self.assertFalse(result["ok"])
        self.assertIn(
            "unknown or unbound write deploy key",
            result["activationPrecondition"]["identityObservationError"],
        )
        identity_generator.assert_not_called()
        secret_mutation.assert_not_called()

    def test_unproven_actions_policy_skips_every_automation_key_mutation(self):
        missing_identity = {
            "writeKeyCount": 0,
            "reservedTitleKeyCount": 0,
            "exact": False,
        }
        broad_actions = {
            "enabled": True,
            "allowedActions": "all",
            "shaPinningRequired": False,
            "selectedActions": None,
            "defaultWorkflowPermissions": "write",
            "canApprovePullRequestReviews": True,
        }
        before = self._cloud_state(
            automation_push_identity=missing_identity,
            actions=broad_actions,
        )
        accepted = cli.ExecutionCapture("accepted", ("gh",), 0, b"", b"")
        with mock.patch.object(cli, "_gate_policy_repository"), mock.patch.object(
            cli, "_cloud_operating_state", side_effect=[before] * 7
        ), mock.patch.object(
            cli, "_capture_command", return_value=accepted
        ), mock.patch.object(
            cli, "_github_branch_governance_state",
            return_value=before["branchGovernance"],
        ), mock.patch.object(
            cli, "_automation_push_identity_state", return_value=missing_identity
        ), mock.patch.object(
            cli, "_github_actions_permissions_state", return_value=broad_actions
        ), mock.patch.object(
            cli, "_generated_automation_push_identity"
        ) as identity_generator, mock.patch.object(
            cli, "_capture_command_with_private_stdin_file"
        ) as secret_mutation, mock.patch.object(
            cli, "_try_source_sha", return_value="a" * 40
        ), mock.patch.object(cli.time, "sleep"):
            result = cli._configure_cloud(
                "owner/repo", True, None, source_authority=self._source_authority()
            )

        self.assertFalse(result["ok"])
        self.assertIn(
            "Actions policy, privileged environments, or source lease was not proven",
            result["activationPrecondition"]["identityObservationError"],
        )
        identity_generator.assert_not_called()
        secret_mutation.assert_not_called()

    def test_disabled_actions_are_not_enabled_until_every_permission_is_exact(self):
        broad_actions = {
            "enabled": False,
            "allowedActions": "all",
            "shaPinningRequired": False,
            "selectedActions": None,
            "defaultWorkflowPermissions": "write",
            "canApprovePullRequestReviews": True,
        }
        before = self._cloud_state(actions=broad_actions)
        accepted = cli.ExecutionCapture("accepted", ("gh",), 0, b"", b"")
        with mock.patch.object(cli, "_gate_policy_repository"), mock.patch.object(
            cli, "_cloud_operating_state", side_effect=[before] + ([before] * 6)
        ), mock.patch.object(
            cli, "_github_actions_permissions_state", return_value=broad_actions
        ), mock.patch.object(
            cli, "_capture_command", return_value=accepted
        ) as mutations, mock.patch.object(
            cli, "_try_source_sha", return_value="a" * 40
        ), mock.patch.object(cli.time, "sleep"):
            result = cli._configure_cloud(
                "owner/repo", True, None, source_authority=self._source_authority()
            )
        self.assertFalse(result["ok"])
        self.assertTrue(result["ambiguousSubsteps"])
        labels = [call.kwargs["label"] for call in mutations.call_args_list]
        self.assertNotIn("enable-github-actions", labels)
        self.assertFalse(result["activationPrecondition"]["proven"])
        self.assertIn(
            "activation substeps were skipped",
            result["activationPrecondition"]["error"],
        )

    def test_failed_policy_narrowing_skips_every_activation_substep(self):
        broad_actions = {
            "enabled": True,
            "allowedActions": "all",
            "shaPinningRequired": False,
            "selectedActions": None,
            "defaultWorkflowPermissions": "write",
            "canApprovePullRequestReviews": True,
        }
        before = self._cloud_state(
            state_commits=False,
            pages_publish=False,
            pages_workflow=False,
            actions=broad_actions,
            workflow_states=self._workflow_states(
                "disabled_manually", "disabled_inactivity"
            ),
        )
        observed_labels = []

        def capture(argv, **kwargs):
            label = kwargs["label"]
            observed_labels.append(label)
            if label == "narrow-github-actions-policy":
                raise cli.TransientFailure("policy update timed out")
            return cli.ExecutionCapture(label, tuple(argv), 0, b"", b"")

        with mock.patch.object(cli, "_gate_policy_repository"), mock.patch.object(
            cli, "_cloud_operating_state", side_effect=[before] + ([before] * 6)
        ), mock.patch.object(
            cli, "_github_actions_permissions_state", return_value=broad_actions
        ), mock.patch.object(
            cli, "_capture_command", side_effect=capture
        ), mock.patch.object(
            cli, "_try_source_sha", return_value="a" * 40
        ), mock.patch.object(cli.time, "sleep"):
            result = cli._configure_cloud(
                "owner/repo", True, None, source_authority=self._source_authority()
            )

        self.assertFalse(result["ok"])
        self.assertEqual(result["_processExitCode"], cli.EXIT_ROLLBACK_INCOMPLETE)
        self.assertFalse(result["activationPrecondition"]["proven"])
        self.assertEqual(
            observed_labels,
            [
                "narrow-github-actions-policy",
                "narrow-selected-actions-policy",
                "narrow-workflow-token-permissions",
            ],
        )

    def test_ambiguous_policy_update_proceeds_only_after_exact_remote_proof(self):
        broad_actions = {
            "enabled": True,
            "allowedActions": "all",
            "shaPinningRequired": False,
            "selectedActions": None,
            "defaultWorkflowPermissions": "write",
            "canApprovePullRequestReviews": True,
        }
        before = self._cloud_state(
            state_commits=False,
            pages_publish=False,
            pages_workflow=False,
            actions=broad_actions,
            workflow_states=self._workflow_states(
                "disabled_manually", "disabled_inactivity"
            ),
        )
        after = self._cloud_state()
        observed_labels = []

        def capture(argv, **kwargs):
            label = kwargs["label"]
            observed_labels.append(label)
            if label == "narrow-github-actions-policy":
                raise cli.TransientFailure("ambiguous timeout after request")
            return cli.ExecutionCapture(label, tuple(argv), 0, b"", b"")

        with mock.patch.object(cli, "_gate_policy_repository"), mock.patch.object(
            cli, "_cloud_operating_state", side_effect=(before, after)
        ), mock.patch.object(
            cli, "_github_actions_permissions_state", return_value=after["actions"]
        ), mock.patch.object(
            cli, "_capture_command", side_effect=capture
        ), mock.patch.object(
            cli, "_try_source_sha", return_value="a" * 40
        ):
            result = cli._configure_cloud(
                "owner/repo", True, None, source_authority=self._source_authority()
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "configured-after-ambiguous-client-result")
        self.assertTrue(result["activationPrecondition"]["proven"])
        self.assertIsNone(result["mutationApplied"])
        self.assertIn("enable-enable-state-commits", observed_labels)
        self.assertIn("enable-enable-pages-publish", observed_labels)
        self.assertIn("enable-github-pages-workflow", observed_labels)
        for workflow in cli.WORKFLOW_FILES:
            self.assertIn(f"enable-workflow-{workflow}", observed_labels)

    def test_cloud_configuration_preserves_confirmed_partial_mutation(self):
        incomplete = self._cloud_state(
            state_commits=True, pages_publish=False, pages_workflow=False
        )
        before = self._cloud_state(
            state_commits=False, pages_publish=False, pages_workflow=False
        )
        accepted = cli.ExecutionCapture("one", ("gh",), 0, b"", b"")
        mutation_results = (accepted, cli.TransientFailure("timeout"), cli.TransientFailure("timeout"))
        with mock.patch.object(cli, "_gate_policy_repository"), mock.patch.object(
            cli, "_cloud_operating_state", side_effect=[before] + ([incomplete] * 6)
        ), mock.patch.object(
            cli, "_github_actions_permissions_state", return_value=before["actions"]
        ), mock.patch.object(
            cli, "_capture_command", side_effect=mutation_results
        ), mock.patch.object(cli, "_try_source_sha", return_value="a" * 40), \
                mock.patch.object(cli.time, "sleep"):
            result = cli._configure_cloud(
                "owner/repo", True, None, source_authority=self._source_authority()
            )
        self.assertFalse(result["ok"])
        self.assertTrue(result["mutationApplied"])
        self.assertEqual(result["mutationState"], "partially-applied-unverified")
        self.assertEqual(result["_processExitCode"], cli.EXIT_ROLLBACK_INCOMPLETE)

    def test_repo_parser_rejects_options_and_non_repo_values(self):
        for value in ("--repo", "owner", "owner/repo/extra", "owner/re po"):
            with self.subTest(value=value), self.assertRaises(cli.UsageFailure):
                cli._require_repo(value)

    def test_run_metadata_requires_exact_workflow_path(self):
        payload = {
            "id": 12,
            "head_sha": "c" * 40,
            "path": ".github/workflows/watch-dom.yml@refs/heads/main",
        }
        with mock.patch.object(cli, "_gh_json", return_value=payload):
            with self.assertRaises(cli.IntegrityFailure):
                cli._run_metadata("owner/repo", 12, "verify.yml")

    def test_artifact_inventory_rejects_unallowlisted_artifact(self):
        listing = {
            "total_count": 1,
            "artifacts": [{
                "id": 9,
                "name": "arbitrary-secret-dump",
                "digest": "sha256:" + "a" * 64,
                "size_in_bytes": 10,
                "expired": False,
            }],
        }
        with mock.patch.object(cli, "_gh_json", return_value=listing):
            with self.assertRaises(cli.IntegrityFailure):
                cli._artifact_inventory("owner/repo", "verify.yml", 77)

    def test_pages_artifact_name_is_explicitly_allowlisted(self):
        self.assertTrue(cli._artifact_name_allowed("github-pages", "verify.yml", 77))
        self.assertTrue(cli._artifact_name_allowed("github-pages", "watch-dom.yml", 77))
        self.assertFalse(
            cli._artifact_name_allowed("github-pages", "publish-gate.yml", 77)
        )
        self.assertFalse(
            cli._artifact_name_allowed(
                "gate-release-evidence-77", "publish-gate.yml", 77
            )
        )

    def test_candidate_artifact_name_uses_the_signed_queue_fingerprint_width(self):
        fingerprint = "a" * 24
        for prefix in ("candidate-result", "candidate-json", "candidate-screenshots"):
            with self.subTest(prefix=prefix):
                self.assertTrue(
                    cli._artifact_name_allowed(
                        f"{prefix}-77-{fingerprint}", "watch-dom.yml", 77
                    )
                )
                self.assertFalse(
                    cli._artifact_name_allowed(
                        f"{prefix}-77-{'a' * 64}", "watch-dom.yml", 77
                    )
                )
                self.assertFalse(
                    cli._artifact_name_allowed(
                        f"{prefix}-78-{fingerprint}", "watch-dom.yml", 77
                    )
                )

    def test_safe_zip_rejects_traversal_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            traversal = root / "traversal.zip"
            with zipfile.ZipFile(traversal, "w") as archive:
                archive.writestr("../escape.txt", "bad")
            with self.assertRaises(cli.IntegrityFailure):
                cli._safe_extract_zip(traversal, root / "traversal-out")

            link = root / "link.zip"
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = (stat_mode_symlink() << 16)
            with zipfile.ZipFile(link, "w") as archive:
                archive.writestr(info, "target")
            with self.assertRaises(cli.IntegrityFailure):
                cli._safe_extract_zip(link, root / "link-out")

    def test_safe_zip_rejects_windows_drive_unc_ads_and_reserved_paths(self):
        unsafe_names = (
            "D:/escape.txt",
            "C:drive-relative.txt",
            "//server/share/escape.txt",
            "safe/file.txt:alternate-stream",
            "safe/CON.txt",
            "safe/COM¹.log",
            "safe/trailing-dot.",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, unsafe_name in enumerate(unsafe_names):
                with self.subTest(name=unsafe_name):
                    archive_path = root / f"unsafe-{index}.zip"
                    with zipfile.ZipFile(archive_path, "w") as archive:
                        archive.writestr(unsafe_name, "bad")
                    with self.assertRaises(cli.IntegrityFailure):
                        cli._safe_extract_zip(archive_path, root / f"unsafe-out-{index}")

    def test_safe_zip_accepts_permission_only_regular_entry_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_path = root / "safe.zip"
            info = zipfile.ZipInfo("proof/data.json")
            info.create_system = 3
            info.external_attr = 0o600 << 16
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(info, "{}")
            records = cli._safe_extract_zip(archive_path, root / "out")
            self.assertEqual(records[0]["path"], "proof/data.json")

    def test_cloud_download_rejects_archive_digest_mismatch(self):
        run = {"id": 44, "head_sha": "d" * 40, "path": ".github/workflows/verify.yml"}
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w") as archive:
            archive.writestr("proof.json", "{}")
        archive_bytes = archive_buffer.getvalue()
        item = {
            "id": 5,
            "name": "filter-integrity-44",
            "digest": "sha256:" + "0" * 64,
            "size_in_bytes": len(archive_bytes),
            "expired": False,
        }

        def download(argv, archive_path, *, label):
            archive_path.write_bytes(archive_bytes)
            return cli.ExecutionCapture(label, tuple(argv), 0, b"", b"")

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            cli, "_artifact_inventory", return_value=[item]
        ), mock.patch.object(cli, "_download_gh_archive", side_effect=download):
            with self.assertRaises(cli.IntegrityFailure):
                cli._download_cloud_evidence(
                    "owner/repo", "verify.yml", run, Path(temporary) / "cloud"
                )
            self.assertFalse((Path(temporary) / "cloud" / "run-44").exists())

    def test_cloud_download_shares_byte_and_entry_budgets_across_artifacts(self):
        run = {"id": 44, "head_sha": "d" * 40, "path": ".github/workflows/verify.yml"}
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w") as archive:
            archive.writestr("proof.json", "abc")
        archive_bytes = archive_buffer.getvalue()
        digest = hashlib.sha256(archive_bytes).hexdigest()
        items = [{
            "id": identifier,
            "name": name,
            "digest": f"sha256:{digest}",
            "size_in_bytes": len(archive_bytes),
            "expired": False,
        } for identifier, name in (
            (5, "filter-integrity-44"),
            (6, "release-draft-44"),
        )]

        def download(argv, archive_path, *, label):
            archive_path.write_bytes(archive_bytes)
            return cli.ExecutionCapture(label, tuple(argv), 0, b"", b"")

        budget_cases = (
            ("MAX_EXTRACTED_BYTES", 5),
            ("MAX_EXTRACTED_ENTRIES", 1),
        )
        for constant_name, limit in budget_cases:
            with self.subTest(budget=constant_name), tempfile.TemporaryDirectory() as temporary, \
                    mock.patch.object(cli, "_artifact_inventory", return_value=items), \
                    mock.patch.object(cli, "_download_gh_archive", side_effect=download), \
                    mock.patch.object(cli, constant_name, limit):
                output_root = Path(temporary) / "cloud"
                with self.assertRaises(cli.IntegrityFailure):
                    cli._download_cloud_evidence(
                        "owner/repo", "verify.yml", run, output_root
                    )
                self.assertFalse((output_root / "run-44").exists())
                self.assertEqual(list(output_root.glob(".run-44.*.tmp")), [])

    def test_dispatch_success_without_observable_run_preserves_applied_state(self):
        preflight = {
            "repo": "owner/repo",
            "workflow": "verify.yml",
            "defaultBranch": "main",
        }
        accepted = cli.ExecutionCapture("github-dispatch", ("gh",), 0, b"", b"")
        with mock.patch.object(cli, "_gh_json", return_value={"sha": "a" * 40}), \
                mock.patch.object(cli, "_latest_runs", side_effect=[[]] + ([[]] * 10)), \
                mock.patch.object(cli, "_capture_command", return_value=accepted), \
                mock.patch.object(cli.time, "sleep"):
            result = cli._dispatch_cloud(preflight, True)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "dispatch-applied-unverified")
        self.assertTrue(result["mutationApplied"])
        self.assertEqual(result["_processExitCode"], cli.EXIT_ROLLBACK_INCOMPLETE)

    def test_dispatch_expected_source_drift_fails_before_listing_or_mutation(self):
        preflight = {
            "repo": "owner/repo",
            "workflow": "watch-dom.yml",
            "defaultBranch": "main",
        }
        with mock.patch.object(
            cli, "_gh_json", return_value={"sha": "b" * 40}
        ), mock.patch.object(cli, "_latest_runs") as runs, mock.patch.object(
            cli, "_capture_command"
        ) as mutation:
            with self.assertRaisesRegex(cli.IntegrityFailure, "changed"):
                cli._dispatch_cloud(
                    preflight, True, expected_source_sha="a" * 40
                )
        runs.assert_not_called()
        mutation.assert_not_called()

    def test_dispatch_timeout_without_observable_run_preserves_unknown_state(self):
        preflight = {
            "repo": "owner/repo",
            "workflow": "verify.yml",
            "defaultBranch": "main",
        }
        with mock.patch.object(cli, "_gh_json", return_value={"sha": "a" * 40}), \
                mock.patch.object(cli, "_latest_runs", side_effect=[[]] + ([[]] * 10)), \
                mock.patch.object(
                    cli, "_capture_command", side_effect=cli.TransientFailure("timeout")
                ), mock.patch.object(cli.time, "sleep"):
            result = cli._dispatch_cloud(preflight, True)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "dispatch-terminal-state-unknown")
        self.assertIsNone(result["mutationApplied"])
        self.assertEqual(result["_processExitCode"], cli.EXIT_ROLLBACK_INCOMPLETE)

    def test_dispatch_does_not_claim_a_concurrent_run_without_its_nonce(self):
        preflight = {
            "repo": "owner/repo",
            "workflow": "verify.yml",
            "defaultBranch": "main",
        }
        concurrent = {
            "id": 2,
            "head_sha": "a" * 40,
            "event": "workflow_dispatch",
            "display_title": "hotdeal-focus-verify-someone-else",
        }
        accepted = cli.ExecutionCapture("github-dispatch", ("gh",), 0, b"", b"")
        with mock.patch.object(cli, "_gh_json", return_value={"sha": "a" * 40}), \
                mock.patch.object(
                    cli, "_latest_runs", side_effect=[[]] + ([[concurrent]] * 10)
                ), mock.patch.object(cli, "_capture_command", return_value=accepted), \
                mock.patch.object(cli.uuid, "uuid4", return_value=mock.Mock(hex="1" * 32)), \
                mock.patch.object(cli.time, "sleep"):
            result = cli._dispatch_cloud(preflight, True)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "dispatch-applied-unverified")

    def test_dispatch_claims_only_the_exact_nonce_bound_run(self):
        preflight = {
            "repo": "owner/repo",
            "workflow": "verify.yml",
            "defaultBranch": "main",
        }
        run = {
            "id": 3,
            "head_sha": "a" * 40,
            "event": "workflow_dispatch",
            "display_title": "hotdeal-focus-verify-" + ("1" * 32),
            "path": ".github/workflows/verify.yml",
            "status": "queued",
            "conclusion": None,
            "html_url": "https://github.com/owner/repo/actions/runs/3",
        }
        accepted = cli.ExecutionCapture("github-dispatch", ("gh",), 0, b"", b"")
        with mock.patch.object(cli, "_gh_json", return_value={"sha": "a" * 40}), \
                mock.patch.object(cli, "_latest_runs", side_effect=[[], [run]]), \
                mock.patch.object(cli, "_run_metadata", return_value=run), \
                mock.patch.object(cli, "_capture_command", return_value=accepted), \
                mock.patch.object(cli.uuid, "uuid4", return_value=mock.Mock(hex="1" * 32)):
            result = cli._dispatch_cloud(preflight, True)
        self.assertTrue(result["ok"])
        self.assertEqual(result["run"]["runId"], 3)
        self.assertEqual(result["dispatchNonce"], "1" * 32)


class GateReleaseCommandTests(unittest.TestCase):
    def setUp(self):
        tag_lease = mock.patch.object(
            cli,
            "_require_gate_tag_lease",
            side_effect=lambda _repo, tag, source_sha: {
                "tag": tag,
                "expectedCommit": source_sha,
                "observedCommit": source_sha,
                "exact": True,
            },
        )
        tag_lease.start()
        self.addCleanup(tag_lease.stop)

    @staticmethod
    def _exact_default_head(source_sha):
        return {
            "branch": "main",
            "expectedSourceCommit": source_sha,
            "observedHead": source_sha,
            "exact": True,
        }

    @staticmethod
    def _gate_v2_publish_inputs():
        repo = "heelee912/adguard-hotdeal-focus"
        source_sha = "d" * 40
        manifest = {
            "gateArtifactVersion": "2.0.2",
            "filterSubscriptionUrl": (
                "https://github.com/heelee912/adguard-hotdeal-focus/releases/"
                "download/gate-v2.0.2/filter.txt"
            ),
        }
        args = mock.Mock(
            action="publish",
            repo=repo,
            evidence_dir=None,
            apply=True,
            source_ref=source_sha,
        )
        repository = {
            "nameWithOwner": repo,
            "visibility": "PUBLIC",
            "defaultBranchRef": {"name": "main"},
        }
        return repo, source_sha, manifest, args, repository

    @staticmethod
    def _exact_publisher_environment(repo, source_sha):
        return {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": repo,
            "GITHUB_SHA": source_sha,
            "GITHUB_WORKFLOW_SHA": source_sha,
            "GITHUB_WORKFLOW_REF": (
                f"{repo}/.github/workflows/publish-gate.yml@refs/heads/main"
            ),
            "GITHUB_JOB": "publish",
            "HDF_PRIVILEGED_ENVIRONMENT": cli.MAIN_AUTOMATION_ENVIRONMENT,
        }

    @staticmethod
    def _exact_gate_creation_precondition():
        return {
            "branchGovernance": {"exact": True},
            "automationPushIdentity": {"exact": True},
            "exact": True,
        }

    def test_github_publisher_context_requires_the_exact_secret_bearing_job(self):
        repo = "heelee912/adguard-hotdeal-focus"
        source_sha = "d" * 40
        exact_environment = self._exact_publisher_environment(repo, source_sha)
        with mock.patch.dict(os.environ, exact_environment, clear=True):
            self.assertTrue(cli._github_gate_publisher_context(repo, source_sha))

        invalid_contexts = (
            {"GITHUB_JOB": "record-publisher-checkpoint"},
            {"HDF_PRIVILEGED_ENVIRONMENT": cli.RELEASE_PUBLISHER_ENVIRONMENT},
            {"GITHUB_WORKFLOW_SHA": "e" * 40},
            {"GITHUB_EVENT_NAME": "push"},
            {"GITHUB_REPOSITORY": "other/repo"},
        )
        for replacement in invalid_contexts:
            candidate = {**exact_environment, **replacement}
            with self.subTest(replacement=replacement), mock.patch.dict(
                os.environ, candidate, clear=True
            ):
                self.assertFalse(cli._github_gate_publisher_context(repo, source_sha))

    def test_workflow_tag_creation_evidence_controls_publication_mutation_record(self):
        repo, source_sha, manifest, args, repository = self._gate_v2_publish_inputs()
        exact_environment = {
            **self._exact_publisher_environment(repo, source_sha),
            "HDF_GATE_TAG_CREATED": "true",
            "HDF_GATE_TAG_SOURCE_SHA": source_sha,
        }
        observed_tag = {
            "verified": True,
            "status": "already-bound",
            "sourceCommit": source_sha,
            "mutationApplied": False,
        }
        ambiguous_release_client = cli.ExecutionCapture(
            "publish-immutable-gate-release", ("gh",), 1, b"", b"ambiguous"
        )
        proof = {"immutable": True, "sourceCommit": source_sha}
        with mock.patch.dict(os.environ, exact_environment, clear=True), \
                mock.patch.object(cli, "_command_exists", return_value=True), \
                mock.patch.object(cli, "_validate_locked_gate_bytes"), \
                mock.patch.object(cli, "_local_release_contract", return_value=(manifest, [])), \
                mock.patch.object(cli, "_git_source_binding", return_value=source_sha), \
                mock.patch.object(cli, "_gh_json", side_effect=(repository, {"sha": source_sha})), \
                mock.patch.object(cli, "_gate_release_view", return_value=None), \
                mock.patch.object(cli, "_immutable_release_policy", return_value={"enabled": True}), \
                mock.patch.object(
                    cli,
                    "_require_remote_default_head",
                    return_value=self._exact_default_head(source_sha),
                ), mock.patch.object(
                    cli, "_ensure_remote_gate_tag", return_value=observed_tag
                ), mock.patch.object(
                    cli, "_capture_command", return_value=ambiguous_release_client
                ), mock.patch.object(
                    cli, "_verify_gate_release_with_retry", return_value=proof
                ):
            result = cli.command_gate_release(args)

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "published-after-ambiguous-client-result")
        self.assertEqual(result["gateTag"]["workflowCreationState"], "true")
        self.assertTrue(result["gateTag"]["mutationApplied"])
        self.assertTrue(result["mutationApplied"])

    def test_local_publish_dispatches_the_protected_workflow_with_exact_source(self):
        repo, source_sha, _manifest, args, _repository = self._gate_v2_publish_inputs()
        preflight = {
            "repo": repo,
            "workflow": "publish-gate.yml",
            "defaultBranch": "main",
        }
        authority = {
            "sourceSha": source_sha,
            "defaultBranch": "main",
            "headLeases": [],
            "exact": True,
        }
        lease = {
            "phase": "immediately-before-gate-workflow-dispatch",
            "branch": "main",
            "expectedSha": source_sha,
            "observedSha": source_sha,
            "exact": True,
        }
        dispatched = {
            "ok": True,
            "status": "dispatched",
            "sourceCommit": source_sha,
            "mutationApplied": True,
        }
        with mock.patch.object(cli, "_github_gate_publisher_context", return_value=False), \
                mock.patch.object(cli, "_cloud_preflight", return_value=preflight), \
                mock.patch.object(cli, "_cloud_source_authority", return_value=authority), \
                mock.patch.object(cli, "_require_cloud_head_lease", return_value=lease), \
                mock.patch.object(cli, "_dispatch_cloud", return_value=dispatched) as dispatch:
            result = cli.command_gate_release_entry(args)
        dispatch.assert_called_once_with(
            preflight, True, expected_source_sha=source_sha
        )
        self.assertTrue(result["ok"])
        self.assertFalse(result["directPublication"])

    def test_unobserved_protected_dispatch_is_not_reported_as_success(self):
        repo, source_sha, _manifest, args, _repository = self._gate_v2_publish_inputs()
        preflight = {
            "repo": repo,
            "workflow": "publish-gate.yml",
            "defaultBranch": "main",
        }
        authority = {
            "sourceSha": source_sha,
            "defaultBranch": "main",
            "headLeases": [],
            "exact": True,
        }
        dispatched = {
            "ok": False,
            "status": "dispatch-applied-unverified",
            "mutationApplied": True,
            "mutationState": "applied-unverified",
            "_processExitCode": cli.EXIT_ROLLBACK_INCOMPLETE,
        }
        with mock.patch.object(cli, "_github_gate_publisher_context", return_value=False), \
                mock.patch.object(cli, "_cloud_preflight", return_value=preflight), \
                mock.patch.object(cli, "_cloud_source_authority", return_value=authority), \
                mock.patch.object(cli, "_require_cloud_head_lease", return_value={}), \
                mock.patch.object(cli, "_dispatch_cloud", return_value=dispatched):
            result = cli.command_gate_release_entry(args)
        self.assertFalse(result["ok"])
        self.assertEqual(result["_processExitCode"], cli.EXIT_ROLLBACK_INCOMPLETE)

    def test_publish_head_checks_surround_tag_and_release_in_exact_order(self):
        repo, source_sha, manifest, args, repository = self._gate_v2_publish_inputs()
        events = []

        def head(*_args):
            events.append("head")
            return {
                "branch": "main",
                "expectedSourceCommit": source_sha,
                "observedHead": source_sha,
                "exact": True,
            }

        def tag(*_args, **_kwargs):
            events.append("tag")
            return {
                "verified": True,
                "status": "created",
                "sourceCommit": source_sha,
                "mutationApplied": True,
            }

        def release(argv, **kwargs):
            del argv
            self.assertEqual(kwargs["label"], "publish-immutable-gate-release")
            events.append("release")
            return cli.ExecutionCapture(kwargs["label"], ("gh",), 0, b"", b"")

        def verify(*_args):
            events.append("verify")
            return {"immutable": True, "sourceCommit": source_sha}

        with mock.patch.object(cli, "_command_exists", return_value=True), \
                mock.patch.object(cli, "_validate_locked_gate_bytes"), \
                mock.patch.object(cli, "_local_release_contract", return_value=(manifest, [])), \
                mock.patch.object(cli, "_git_source_binding", return_value=source_sha), \
                mock.patch.object(cli, "_gh_json", side_effect=(repository, {"sha": source_sha})), \
                mock.patch.object(cli, "_gate_release_view", return_value=None), \
                mock.patch.object(cli, "_immutable_release_policy", return_value={"enabled": True}), \
                mock.patch.object(cli, "_require_remote_default_head", side_effect=head), \
                mock.patch.object(cli, "_ensure_remote_gate_tag", side_effect=tag), \
                mock.patch.object(cli, "_capture_command", side_effect=release), \
                mock.patch.object(cli, "_verify_gate_release_with_retry", side_effect=verify):
            result = cli.command_gate_release(args)

        self.assertTrue(result["ok"])
        self.assertEqual(events, ["tag", "head", "head", "release", "verify", "head"])
        self.assertEqual(
            [item["phase"] for item in result["defaultHeadObservations"]],
            ["frozen-tag-commit-point", "after-tag-before-release", "after-release"],
        )
        self.assertTrue(result["immutableReleasePublished"])

    def test_default_head_observation_has_no_legacy_success_fallback(self):
        with mock.patch.object(cli, "_require_remote_default_head", return_value=None):
            with self.assertRaisesRegex(cli.IntegrityFailure, "observation is malformed"):
                cli._gate_default_head_observation(
                    "owner/repo", "main", "d" * 40, "immediately-before-tag"
                )

    def test_default_head_lease_uses_the_pinned_github_api_contract(self):
        source_sha = "d" * 40
        with mock.patch.object(
            cli, "_gh_json", return_value={"sha": source_sha}
        ) as github:
            observation = cli._require_remote_default_head(
                "owner/repo", "main", source_sha
            )
        argv = github.call_args.args[0]
        self.assertIn(cli.GITHUB_JSON_ACCEPT_HEADER, argv)
        self.assertIn(cli.GITHUB_API_VERSION_HEADER, argv)
        self.assertEqual(observation, self._exact_default_head(source_sha))

    def test_head_drift_after_tag_completes_from_the_frozen_commit_point(self):
        repo, source_sha, manifest, args, repository = self._gate_v2_publish_inputs()
        exact = {
            "branch": "main",
            "expectedSourceCommit": source_sha,
            "observedHead": source_sha,
            "exact": True,
        }
        drift = cli.IntegrityFailure(
            "gate release source is not the current default-branch head",
            details={
                "defaultHeadObservation": {
                    **exact,
                    "observedHead": "e" * 40,
                    "exact": False,
                }
            },
        )
        tag = {
            "verified": True,
            "status": "created",
            "sourceCommit": source_sha,
            "mutationApplied": True,
        }
        creation = cli.ExecutionCapture(
            "publish-immutable-gate-release", ("gh",), 0, b"", b""
        )
        proof = {"immutable": True, "sourceCommit": source_sha}
        with mock.patch.object(cli, "_command_exists", return_value=True), \
                mock.patch.object(cli, "_validate_locked_gate_bytes"), \
                mock.patch.object(cli, "_local_release_contract", return_value=(manifest, [])), \
                mock.patch.object(cli, "_git_source_binding", return_value=source_sha), \
                mock.patch.object(cli, "_gh_json", side_effect=(repository, {"sha": source_sha})), \
                mock.patch.object(cli, "_gate_release_view", return_value=None), \
                mock.patch.object(cli, "_immutable_release_policy", return_value={"enabled": True}), \
                mock.patch.object(
                    cli, "_require_remote_default_head", side_effect=(exact, drift, drift)
                ), mock.patch.object(
                    cli, "_ensure_remote_gate_tag", return_value=tag
                ), mock.patch.object(
                    cli, "_capture_command", return_value=creation
                ) as release, mock.patch.object(
                    cli, "_verify_gate_release_with_retry", return_value=proof
                ):
            result = cli.command_gate_release(args)

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "published-after-default-head-drift")
        self.assertTrue(result["immutableReleasePublished"])
        self.assertTrue(result["defaultHeadDriftObserved"])
        release.assert_called_once()

    def test_head_recheck_outage_after_tag_does_not_wedge_release(self):
        repo, source_sha, manifest, args, repository = self._gate_v2_publish_inputs()
        tag = {
            "verified": True,
            "status": "created",
            "sourceCommit": source_sha,
            "mutationApplied": True,
        }
        creation = cli.ExecutionCapture(
            "publish-immutable-gate-release", ("gh",), 0, b"", b""
        )
        proof = {"immutable": True, "sourceCommit": source_sha}
        outage = cli.TransientFailure("default head temporarily unavailable")
        with mock.patch.object(cli, "_command_exists", return_value=True), \
                mock.patch.object(cli, "_validate_locked_gate_bytes"), \
                mock.patch.object(cli, "_local_release_contract", return_value=(manifest, [])), \
                mock.patch.object(cli, "_git_source_binding", return_value=source_sha), \
                mock.patch.object(cli, "_gh_json", side_effect=(repository, {"sha": source_sha})), \
                mock.patch.object(cli, "_gate_release_view", return_value=None), \
                mock.patch.object(cli, "_immutable_release_policy", return_value={"enabled": True}), \
                mock.patch.object(
                    cli,
                    "_require_remote_default_head",
                    side_effect=(
                        self._exact_default_head(source_sha),
                        outage,
                        outage,
                    ),
                ), mock.patch.object(
                    cli, "_ensure_remote_gate_tag", return_value=tag
                ), mock.patch.object(
                    cli, "_capture_command", return_value=creation
                ) as release, mock.patch.object(
                    cli, "_verify_gate_release_with_retry", return_value=proof
                ):
            result = cli.command_gate_release(args)

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "published-after-default-head-drift")
        self.assertEqual(result["gateTag"], tag)
        self.assertIsNone(result["defaultHeadObservations"][-1]["observedHead"])
        self.assertIn("temporarily unavailable", result["defaultHeadObservations"][-1]["error"])
        release.assert_called_once()

    def test_unverified_tag_binding_still_records_post_tag_head(self):
        repo, source_sha, manifest, args, repository = self._gate_v2_publish_inputs()
        exact = self._exact_default_head(source_sha)
        tag = {
            "verified": False,
            "status": "terminal-state-unknown",
            "sourceCommit": None,
            "expectedSourceCommit": source_sha,
            "mutationApplied": None,
        }
        with mock.patch.object(cli, "_command_exists", return_value=True), \
                mock.patch.object(cli, "_validate_locked_gate_bytes"), \
                mock.patch.object(cli, "_local_release_contract", return_value=(manifest, [])), \
                mock.patch.object(cli, "_git_source_binding", return_value=source_sha), \
                mock.patch.object(cli, "_gh_json", side_effect=(repository, {"sha": source_sha})), \
                mock.patch.object(cli, "_gate_release_view", return_value=None), \
                mock.patch.object(cli, "_immutable_release_policy", return_value={"enabled": True}), \
                mock.patch.object(
                    cli, "_require_remote_default_head", side_effect=(exact, exact)
                ), mock.patch.object(
                    cli, "_ensure_remote_gate_tag", return_value=tag
                ), mock.patch.object(cli, "_capture_command") as release:
            result = cli.command_gate_release(args)

        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "gate-tag-binding-unverified")
        self.assertEqual(
            [item["phase"] for item in result["defaultHeadObservations"]],
            ["frozen-tag-commit-point"],
        )
        self.assertFalse(result["immutableReleasePublished"])
        release.assert_not_called()

    def test_head_drift_after_immutable_release_is_successfully_evidenced(self):
        repo, source_sha, manifest, args, repository = self._gate_v2_publish_inputs()
        exact = {
            "branch": "main",
            "expectedSourceCommit": source_sha,
            "observedHead": source_sha,
            "exact": True,
        }
        drift = cli.IntegrityFailure(
            "gate release source is not the current default-branch head",
            details={
                "defaultHeadObservation": {
                    **exact,
                    "observedHead": "e" * 40,
                    "exact": False,
                }
            },
        )
        tag = {
            "verified": True,
            "status": "created",
            "sourceCommit": source_sha,
            "mutationApplied": True,
        }
        creation = cli.ExecutionCapture(
            "publish-immutable-gate-release", ("gh",), 0, b"", b""
        )
        proof = {"immutable": True, "sourceCommit": source_sha}
        with mock.patch.object(cli, "_command_exists", return_value=True), \
                mock.patch.object(cli, "_validate_locked_gate_bytes"), \
                mock.patch.object(cli, "_local_release_contract", return_value=(manifest, [])), \
                mock.patch.object(cli, "_git_source_binding", return_value=source_sha), \
                mock.patch.object(cli, "_gh_json", side_effect=(repository, {"sha": source_sha})), \
                mock.patch.object(cli, "_gate_release_view", return_value=None), \
                mock.patch.object(cli, "_immutable_release_policy", return_value={"enabled": True}), \
                mock.patch.object(
                    cli, "_require_remote_default_head", side_effect=(exact, exact, drift)
                ), mock.patch.object(
                    cli, "_ensure_remote_gate_tag", return_value=tag
                ), mock.patch.object(
                    cli, "_capture_command", return_value=creation
                ), mock.patch.object(
                    cli, "_verify_gate_release_with_retry", return_value=proof
                ):
            result = cli.command_gate_release(args)

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "published-after-default-head-drift")
        self.assertTrue(result["immutableReleasePublished"])
        self.assertEqual(result["gateRelease"], proof)
        self.assertEqual(result["defaultHeadObservations"][-1]["observedHead"], "e" * 40)
        self.assertTrue(result["defaultHeadDriftObserved"])

    def test_head_drift_after_ambiguous_create_recovers_from_the_frozen_tag(self):
        repo, source_sha, manifest, args, repository = self._gate_v2_publish_inputs()
        exact = self._exact_default_head(source_sha)
        drift = cli.IntegrityFailure(
            "gate release source is not the current default-branch head",
            details={
                "defaultHeadObservation": {
                    **exact,
                    "observedHead": "e" * 40,
                    "exact": False,
                }
            },
        )
        tag = {
            "verified": True,
            "status": "created",
            "sourceCommit": source_sha,
            "mutationApplied": True,
        }
        creation = cli.ExecutionCapture(
            "publish-immutable-gate-release", ("gh",), 1, b"", b"ambiguous"
        )
        proof = {"immutable": True, "sourceCommit": source_sha}
        recovery = {
            "ok": True,
            "status": "recovered-exact-draft",
            "proof": proof,
            "mutationApplied": True,
            "mutationState": "applied",
        }
        with mock.patch.object(cli, "_command_exists", return_value=True), \
                mock.patch.object(cli, "_validate_locked_gate_bytes"), \
                mock.patch.object(cli, "_local_release_contract", return_value=(manifest, [])), \
                mock.patch.object(cli, "_git_source_binding", return_value=source_sha), \
                mock.patch.object(cli, "_gh_json", side_effect=(repository, {"sha": source_sha})), \
                mock.patch.object(cli, "_gate_release_view", return_value=None), \
                mock.patch.object(cli, "_immutable_release_policy", return_value={"enabled": True}), \
                mock.patch.object(
                    cli, "_require_remote_default_head",
                    side_effect=(exact, exact, drift, drift),
                ), mock.patch.object(
                    cli, "_ensure_remote_gate_tag", return_value=tag
                ), mock.patch.object(
                    cli, "_capture_command", return_value=creation
                ), mock.patch.object(
                    cli,
                    "_verify_gate_release_with_retry",
                    side_effect=cli.IntegrityFailure("release is not observable"),
                ), mock.patch.object(
                    cli, "_resume_gate_draft_after_ambiguous_create",
                    return_value=recovery,
                ) as recover:
            result = cli.command_gate_release(args)

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "recovered-exact-draft")
        self.assertEqual(result["gateTag"], tag)
        self.assertTrue(result["immutableReleasePublished"])
        recover.assert_called_once()

    def test_gate_tag_is_peeled_to_one_exact_commit(self):
        tag = "gate-v1.0.0"
        source_sha = "a" * 40
        body = json.dumps({
            "ref": f"refs/tags/{tag}",
            "object": {"type": "commit", "sha": source_sha},
        }).encode()
        capture = cli.ExecutionCapture(
            "gate-tag-reference",
            ("gh",),
            0,
            b"HTTP/2.0 200 OK\nContent-Type: application/json\n\n" + body,
            b"",
        )
        with mock.patch.object(cli, "_capture_command", return_value=capture):
            self.assertEqual(
                cli._remote_gate_tag_commit("owner/repo", tag), source_sha
            )

    def test_preexisting_gate_tag_on_another_commit_is_rejected(self):
        with mock.patch.object(
            cli, "_remote_gate_tag_commit", return_value="b" * 40
        ), mock.patch.object(cli, "_capture_command") as mutation:
            with self.assertRaisesRegex(
                cli.IntegrityFailure, "pre-existing gate tag"
            ):
                cli._ensure_remote_gate_tag(
                    "owner/repo", "gate-v1.0.0", "a" * 40
                )
        mutation.assert_not_called()

    def test_missing_prebound_tag_never_falls_back_to_github_token_creation(self):
        with mock.patch.object(
            cli, "_remote_gate_tag_commit", return_value=None
        ), mock.patch.object(cli.time, "sleep"), mock.patch.object(
            cli, "_capture_command"
        ) as mutation:
            result = cli._ensure_remote_gate_tag(
                "owner/repo", "gate-v2.0.2", "a" * 40
            )
        self.assertFalse(result["verified"])
        self.assertEqual(result["status"], "prebound-tag-missing")
        self.assertFalse(result["mutationApplied"])
        mutation.assert_not_called()

    def test_publish_does_not_mutate_when_absence_probe_is_forbidden(self):
        source_sha = "d" * 40
        manifest = {
            "gateArtifactVersion": "1.0.0",
            "filterSubscriptionUrl": (
                "https://github.com/heelee912/adguard-hotdeal-focus/releases/download/"
                "gate-v1.0.0/filter.txt"
            ),
        }
        args = mock.Mock(
            action="publish",
            repo="heelee912/adguard-hotdeal-focus",
            evidence_dir=None,
            apply=True,
            source_ref=source_sha,
        )
        api_values = (
            {
                "nameWithOwner": "heelee912/adguard-hotdeal-focus",
                "visibility": "PUBLIC",
                "defaultBranchRef": {"name": "main"},
            },
            {"sha": source_sha},
        )
        captures = (
            cli.ExecutionCapture(
                "gate-release-existence", ("gh",), 1, b"", b"request failed"
            ),
            cli.ExecutionCapture(
                "gate-release-definitive-absence", ("gh",), 1, b"", b"HTTP 403"
            ),
        )
        with mock.patch.object(
            cli, "_command_exists", return_value=True
        ), mock.patch.object(
            cli, "_local_release_contract", return_value=(manifest, [])
        ), mock.patch.object(
            cli, "_git_source_binding", return_value=source_sha
        ), mock.patch.object(
            cli, "_gh_json", side_effect=api_values
        ), mock.patch.object(
            cli, "_immutable_release_policy"
        ) as policy, mock.patch.object(
            cli, "_capture_command", side_effect=captures
        ) as capture, mock.patch.object(
            cli, "_ensure_remote_gate_tag"
        ) as mutation:
            with self.assertRaisesRegex(
                cli.TransientFailure, "absence could not be established"
            ):
                cli.command_gate_release(args)

        mutation.assert_not_called()
        policy.assert_not_called()
        self.assertEqual(
            [call.kwargs["label"] for call in capture.call_args_list],
            ["gate-release-existence", "gate-release-definitive-absence"],
        )

    def test_create_timeout_resumes_exact_draft_in_the_same_invocation(self):
        source_sha = "d" * 40
        manifest = {
            "gateArtifactVersion": "1.0.0",
            "filterSubscriptionUrl": (
                "https://github.com/heelee912/adguard-hotdeal-focus/releases/download/"
                "gate-v1.0.0/filter.txt"
            ),
        }
        args = mock.Mock(
            action="publish",
            repo="heelee912/adguard-hotdeal-focus",
            evidence_dir=None,
            apply=True,
            source_ref=source_sha,
        )
        api_values = (
            {
                "nameWithOwner": "heelee912/adguard-hotdeal-focus",
                "visibility": "PUBLIC",
                "defaultBranchRef": {"name": "main"},
            },
            {"sha": source_sha},
            {"sha": source_sha},
        )
        draft = {"databaseId": 42, "isDraft": True}
        proof = {
            "immutable": True,
            "tag": "gate-v1.0.0",
            "sourceCommit": source_sha,
        }
        recovery = {
            "ok": True,
            "status": "recovered-exact-draft",
            "release": {"databaseId": 42, "draft": True},
            "mutations": [],
            "proof": proof,
            "mutationApplied": True,
            "mutationState": "applied",
        }
        with mock.patch.object(
            cli, "_command_exists", return_value=True
        ), mock.patch.object(
            cli, "_local_release_contract", return_value=(manifest, [])
        ), mock.patch.object(
            cli, "_git_source_binding", return_value=source_sha
        ), mock.patch.object(
            cli, "_gh_json", side_effect=api_values
        ), mock.patch.object(
            cli, "_immutable_release_policy", return_value={"enabled": True}
        ) as policy, mock.patch.object(
            cli, "_require_remote_default_head",
            return_value=self._exact_default_head(source_sha),
        ), mock.patch.object(
            cli, "_gate_release_view", side_effect=(None, draft)
        ), mock.patch.object(
            cli, "_ensure_remote_gate_tag", return_value={
                "verified": True,
                "status": "already-bound",
                "sourceCommit": source_sha,
                "mutationApplied": False,
            }
        ), mock.patch.object(
            cli, "_capture_command", side_effect=cli.TransientFailure(
                "release create timed out"
            )
        ), mock.patch.object(
            cli, "_verify_gate_release_with_retry",
            side_effect=cli.IntegrityFailure("not published yet"),
        ), mock.patch.object(
            cli, "_recover_exact_gate_draft", return_value=recovery
        ) as resume:
            result = cli.command_gate_release(args)

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "recovered-exact-draft")
        self.assertEqual(result["gateRelease"], proof)
        self.assertTrue(result["mutationApplied"])
        self.assertEqual(result["mutationState"], "applied")
        self.assertIn("timed out", result["releaseCreation"]["error"])
        policy.assert_called_once_with("heelee912/adguard-hotdeal-focus")
        resume.assert_called_once()
        self.assertIs(resume.call_args.args[-1], draft)

    def test_enable_policy_is_dry_run_by_default_and_admin_scoped(self):
        args = mock.Mock(
            action="enable-policy",
            repo="heelee912/adguard-hotdeal-focus",
            evidence_dir=None,
            apply=False,
            source_ref=None,
        )
        api_values = (
            {
                "nameWithOwner": "heelee912/adguard-hotdeal-focus",
                "visibility": "PUBLIC",
                "viewerPermission": "ADMIN",
            },
            {"enabled": False},
        )
        with mock.patch.object(cli, "_command_exists", return_value=True), \
                mock.patch.object(cli, "_gh_json", side_effect=api_values), \
                mock.patch.object(cli, "_capture_command") as capture, \
                mock.patch.object(cli, "_try_source_sha", return_value="a" * 40):
            result = cli.command_gate_release(args)
        self.assertEqual(result["status"], "dry-run")
        self.assertFalse(result["mutationApplied"])
        self.assertTrue(result["wouldEnable"])
        capture.assert_not_called()

    def test_enable_policy_applies_and_verifies_exact_remote_state(self):
        args = mock.Mock(
            action="enable-policy",
            repo="heelee912/adguard-hotdeal-focus",
            evidence_dir=None,
            apply=True,
            source_ref=None,
        )
        api_values = (
            {
                "nameWithOwner": "heelee912/adguard-hotdeal-focus",
                "visibility": "PUBLIC",
                "viewerPermission": "ADMIN",
            },
            {"enabled": False},
            {"enabled": True},
        )
        capture = cli.ExecutionCapture(
            "enable-immutable-releases", ("gh",), 0, b"", b""
        )
        with mock.patch.object(cli, "_command_exists", return_value=True), \
                mock.patch.object(cli, "_gh_json", side_effect=api_values), \
                mock.patch.object(cli, "_capture_command", return_value=capture), \
                mock.patch.object(cli, "_try_source_sha", return_value="a" * 40):
            result = cli.command_gate_release(args)
        self.assertEqual(result["status"], "enabled")
        self.assertTrue(result["immutableReleasesEnabled"])
        self.assertTrue(result["mutationApplied"])

    def test_existing_immutable_gate_keeps_its_original_source_commit(self):
        current_sha = "d" * 40
        original_gate_sha = "a" * 40
        manifest = {
            "gateArtifactVersion": "1.0.0",
            "filterSubscriptionUrl": (
                "https://github.com/heelee912/adguard-hotdeal-focus/releases/download/"
                "gate-v1.0.0/filter.txt"
            ),
        }
        args = mock.Mock(
            action="publish",
            repo="heelee912/adguard-hotdeal-focus",
            evidence_dir=None,
            apply=True,
            source_ref=current_sha,
        )
        existing = {"databaseId": 42, "isDraft": False, "isImmutable": True}
        proof = {
            "immutable": True,
            "tag": "gate-v1.0.0",
            "sourceCommit": original_gate_sha,
        }
        api_values = (
            {
                "nameWithOwner": "heelee912/adguard-hotdeal-focus",
                "visibility": "PUBLIC",
                "defaultBranchRef": {"name": "main"},
            },
            {"sha": current_sha},
        )
        with mock.patch.object(
            cli, "_command_exists", return_value=True
        ), mock.patch.object(
            cli, "_local_release_contract", return_value=(manifest, [])
        ), mock.patch.object(
            cli, "_git_source_binding", return_value=current_sha
        ), mock.patch.object(
            cli, "_gh_json", side_effect=api_values
        ), mock.patch.object(
            cli, "_gate_release_view", return_value=existing
        ), mock.patch.object(
            cli, "_immutable_release_policy"
        ) as policy, mock.patch.object(
            cli, "_verify_gate_release_with_retry", return_value=proof
        ) as verify, mock.patch.object(
            cli, "_require_remote_default_head"
        ) as require_default_head, mock.patch.object(
            cli, "_ensure_remote_gate_tag"
        ) as ensure_tag, mock.patch.object(
            cli, "_recover_exact_gate_draft"
        ) as recover_draft, mock.patch.object(
            cli, "_capture_command"
        ) as mutation:
            result = cli.command_gate_release(args)

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "already-published")
        self.assertFalse(result["mutationApplied"])
        self.assertEqual(result["sourceSha"], current_sha)
        self.assertEqual(result["gateRelease"]["sourceCommit"], original_gate_sha)
        self.assertEqual(len(verify.call_args.args), 4)
        self.assertEqual(verify.call_args.kwargs, {})
        policy.assert_not_called()
        require_default_head.assert_not_called()
        ensure_tag.assert_not_called()
        recover_draft.assert_not_called()
        mutation.assert_not_called()

    def test_invalid_existing_release_never_falls_through_to_policy_or_mutation(self):
        current_sha = "d" * 40
        manifest = {
            "gateArtifactVersion": "1.0.0",
            "filterSubscriptionUrl": (
                "https://github.com/heelee912/adguard-hotdeal-focus/releases/download/"
                "gate-v1.0.0/filter.txt"
            ),
        }
        args = mock.Mock(
            action="publish",
            repo="heelee912/adguard-hotdeal-focus",
            evidence_dir=None,
            apply=True,
            source_ref=current_sha,
        )
        api_values = (
            {
                "nameWithOwner": "heelee912/adguard-hotdeal-focus",
                "visibility": "PUBLIC",
                "defaultBranchRef": {"name": "main"},
            },
            {"sha": current_sha},
        )
        with mock.patch.object(
            cli, "_command_exists", return_value=True
        ), mock.patch.object(
            cli, "_local_release_contract", return_value=(manifest, [])
        ), mock.patch.object(
            cli, "_git_source_binding", return_value=current_sha
        ), mock.patch.object(
            cli, "_gh_json", side_effect=api_values
        ), mock.patch.object(
            cli, "_gate_release_view",
            return_value={"databaseId": 42, "isDraft": False},
        ), mock.patch.object(
            cli, "_verify_gate_release_with_retry",
            side_effect=cli.IntegrityFailure("existing release is not immutable"),
        ), mock.patch.object(
            cli, "_immutable_release_policy"
        ) as policy, mock.patch.object(
            cli, "_require_remote_default_head"
        ) as require_default_head, mock.patch.object(
            cli, "_ensure_remote_gate_tag"
        ) as ensure_tag, mock.patch.object(
            cli, "_recover_exact_gate_draft"
        ) as recover_draft, mock.patch.object(
            cli, "_capture_command"
        ) as mutation:
            with self.assertRaisesRegex(
                cli.IntegrityFailure, "not immutable"
            ):
                cli.command_gate_release(args)

        policy.assert_not_called()
        require_default_head.assert_not_called()
        ensure_tag.assert_not_called()
        recover_draft.assert_not_called()
        mutation.assert_not_called()

    def test_draft_or_absent_gate_requires_policy_before_every_mutation(self):
        source_sha = "d" * 40
        repo = "heelee912/adguard-hotdeal-focus"
        manifest = {
            "gateArtifactVersion": "1.0.0",
            "filterSubscriptionUrl": (
                "https://github.com/heelee912/adguard-hotdeal-focus/releases/download/"
                "gate-v1.0.0/filter.txt"
            ),
        }
        args = mock.Mock(
            action="publish",
            repo=repo,
            evidence_dir=None,
            apply=True,
            source_ref=source_sha,
        )
        repository = {
            "nameWithOwner": repo,
            "visibility": "PUBLIC",
            "defaultBranchRef": {"name": "main"},
        }
        draft = {"databaseId": 42, "isDraft": True, "isImmutable": False}
        outcomes = (
            (
                cli.PrerequisiteFailure("immutable policy is not readable"),
                cli.PrerequisiteFailure,
            ),
            ({"enabled": False}, cli.IntegrityFailure),
        )
        for existing in (None, draft):
            for outcome, expected_error in outcomes:
                policy = mock.Mock()
                if isinstance(outcome, BaseException):
                    policy.side_effect = outcome
                else:
                    policy.return_value = outcome
                with self.subTest(existing=existing, outcome=outcome), \
                        mock.patch.object(cli, "_command_exists", return_value=True), \
                        mock.patch.object(
                            cli, "_local_release_contract", return_value=(manifest, [])
                        ), mock.patch.object(
                            cli, "_git_source_binding", return_value=source_sha
                        ), mock.patch.object(
                            cli, "_gh_json", side_effect=(repository, {"sha": source_sha})
                        ), mock.patch.object(
                            cli, "_gate_release_view", return_value=existing
                        ), mock.patch.object(
                            cli, "_immutable_release_policy", policy
                        ), mock.patch.object(
                            cli, "_require_remote_default_head"
                        ) as require_default_head, mock.patch.object(
                            cli, "_ensure_remote_gate_tag"
                        ) as ensure_tag, mock.patch.object(
                            cli, "_recover_exact_gate_draft"
                        ) as recover_draft, mock.patch.object(
                            cli, "_capture_command"
                        ) as mutation:
                    with self.assertRaises(expected_error):
                        cli.command_gate_release(args)

                policy.assert_called_once_with(repo)
                require_default_head.assert_not_called()
                ensure_tag.assert_not_called()
                recover_draft.assert_not_called()
                mutation.assert_not_called()

    def test_existing_draft_recovers_after_main_moves_past_the_frozen_tag(self):
        source_sha = "d" * 40
        manifest = {
            "gateArtifactVersion": "1.0.0",
            "filterSubscriptionUrl": (
                "https://github.com/heelee912/adguard-hotdeal-focus/releases/download/"
                "gate-v1.0.0/filter.txt"
            ),
        }
        args = mock.Mock(
            action="publish",
            repo="heelee912/adguard-hotdeal-focus",
            evidence_dir=None,
            apply=True,
            source_ref=source_sha,
        )
        draft = {"databaseId": 42, "isDraft": True, "isImmutable": False}
        tag = {
            "verified": True,
            "status": "frozen-source-recovery",
            "sourceCommit": source_sha,
            "mutationApplied": False,
        }
        proof = {"immutable": True, "sourceCommit": source_sha}
        recovery = {
            "ok": True,
            "status": "recovered-exact-draft",
            "proof": proof,
            "mutationApplied": True,
            "mutationState": "applied",
        }
        api_values = (
            {
                "nameWithOwner": "heelee912/adguard-hotdeal-focus",
                "visibility": "PUBLIC",
                "defaultBranchRef": {"name": "main"},
            },
            {"sha": source_sha},
        )
        with mock.patch.object(
            cli, "_command_exists", return_value=True
        ), mock.patch.object(
            cli, "_local_release_contract", return_value=(manifest, [])
        ), mock.patch.object(
            cli, "_git_source_binding", return_value=source_sha
        ), mock.patch.object(
            cli, "_gh_json", side_effect=api_values
        ), mock.patch.object(
            cli, "_gate_release_view", return_value=draft
        ), mock.patch.object(
            cli, "_immutable_release_policy", return_value={"enabled": True}
        ) as policy, mock.patch.object(
            cli, "_ensure_remote_gate_tag", return_value=tag
        ), mock.patch.object(
            cli, "_require_remote_default_head",
            side_effect=cli.IntegrityFailure("not current default-branch head"),
        ) as require_default_head, mock.patch.object(
            cli, "_recover_exact_gate_draft", return_value=recovery
        ) as recover_draft:
            result = cli.command_gate_release(args)

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "recovered-exact-draft")
        self.assertTrue(result["immutableReleasePublished"])
        self.assertGreaterEqual(require_default_head.call_count, 1)
        policy.assert_called_once_with("heelee912/adguard-hotdeal-focus")
        recover_draft.assert_called_once()

    def test_publish_preserves_created_and_unknown_terminal_states(self):
        source_sha = "d" * 40
        manifest = {
            "gateArtifactVersion": "1.0.0",
            "filterSubscriptionUrl": (
                "https://github.com/heelee912/adguard-hotdeal-focus/releases/download/"
                "gate-v1.0.0/filter.txt"
            ),
        }
        args = mock.Mock(
            action="publish",
            repo="heelee912/adguard-hotdeal-focus",
            evidence_dir=None,
            apply=True,
            source_ref=source_sha,
        )
        repository_calls = (
            {
                "nameWithOwner": "heelee912/adguard-hotdeal-focus",
                "visibility": "PUBLIC",
                "defaultBranchRef": {"name": "main"},
            },
            {"sha": source_sha},
            {"sha": source_sha},
        )
        for (
            creation_code,
            verification_error,
            tag_applied,
            expected_status,
            expected_applied,
            expected_mutation_state,
        ) in (
            (
                0,
                cli.IntegrityFailure("attestation unavailable"),
                False,
                "published-unverified",
                True,
                "applied-unverified",
            ),
            (
                0,
                PermissionError("temporary proof write denied"),
                False,
                "published-unverified",
                True,
                "applied-unverified",
            ),
            (
                1,
                cli.IntegrityFailure("attestation unavailable"),
                False,
                "publication-terminal-state-unknown",
                None,
                "unknown",
            ),
            (
                1,
                cli.IntegrityFailure("attestation unavailable"),
                True,
                "publication-terminal-state-unknown",
                True,
                "partially-applied-unverified",
            ),
        ):
            captures = [
                cli.ExecutionCapture(
                    "gate-release-existence", ("gh",), 1, b"", b"not found"
                ),
                gate_absence_capture(),
                cli.ExecutionCapture(
                    "publish-immutable-gate-release",
                    ("gh",),
                    creation_code,
                    b"",
                    b"uncertain" if creation_code else b"",
                ),
            ]
            with self.subTest(creation_code=creation_code), mock.patch.object(
                cli, "_command_exists", return_value=True
            ), mock.patch.object(
                cli, "_local_release_contract", return_value=(manifest, [])
            ), mock.patch.object(
                cli, "_git_source_binding", return_value=source_sha
            ), mock.patch.object(
                cli, "_ensure_remote_gate_tag", return_value={
                    "verified": True,
                    "status": "created" if tag_applied else "already-bound",
                    "sourceCommit": source_sha,
                    "mutationApplied": tag_applied,
                }
            ), mock.patch.object(
                cli, "_gh_json", side_effect=repository_calls
            ), mock.patch.object(
                cli, "_immutable_release_policy", return_value={"enabled": True}
            ), mock.patch.object(
                cli, "_require_remote_default_head",
                return_value=self._exact_default_head(source_sha),
            ), mock.patch.object(
                cli, "_capture_command", side_effect=captures
            ) as capture_command, mock.patch.object(
                cli,
                "_verify_gate_release_with_retry",
                side_effect=verification_error,
            ) as verify, mock.patch.object(
                cli, "_resume_gate_draft_after_ambiguous_create", return_value=None
            ):
                result = cli.command_gate_release(args)
            self.assertFalse(result["ok"])
            self.assertEqual(result["status"], expected_status)
            self.assertEqual(result["mutationApplied"], expected_applied)
            self.assertEqual(result["mutationState"], expected_mutation_state)
            self.assertEqual(result["gateTag"]["mutationApplied"], tag_applied)
            self.assertEqual(result["sourceSha"], source_sha)
            self.assertEqual(result["_processExitCode"], cli.EXIT_ROLLBACK_INCOMPLETE)
            release_argv = next(
                call.args[0]
                for call in capture_command.call_args_list
                if call.kwargs.get("label") == "publish-immutable-gate-release"
            )
            self.assertIn("--verify-tag", release_argv)
            self.assertNotIn("--target", release_argv)
            self.assertEqual(len(verify.call_args.args), 5)
            self.assertEqual(verify.call_args.args[-1], source_sha)

    def test_publish_preflight_requires_the_cloud_bound_immutable_tag(self):
        source_sha = "d" * 40
        manifest = {
            "gateArtifactVersion": "1.0.0",
            "filterSubscriptionUrl": (
                "https://github.com/heelee912/adguard-hotdeal-focus/releases/download/"
                "gate-v1.0.0/filter.txt"
            ),
        }
        args = mock.Mock(
            action="prepare-publish",
            repo="heelee912/adguard-hotdeal-focus",
            evidence_dir=None,
            apply=False,
            source_ref=source_sha,
        )
        api_values = (
            {
                "nameWithOwner": "heelee912/adguard-hotdeal-focus",
                "visibility": "PUBLIC",
                "defaultBranchRef": {"name": "main"},
            },
            {"sha": source_sha},
            {"sha": "e" * 40},
        )
        captures = (
            cli.ExecutionCapture(
                "gate-release-existence", ("gh",), 1, b"", b"not found"
            ),
            gate_absence_capture(),
        )
        with mock.patch.object(cli, "_command_exists", return_value=True), \
                mock.patch.object(
                    cli, "_local_release_contract", return_value=(manifest, [])
                ), mock.patch.object(
                    cli, "_git_source_binding", return_value=source_sha
                ), mock.patch.object(
                    cli, "_remote_gate_tag_commit", return_value=None
                ), mock.patch.object(
                    cli,
                    "_gate_creation_governance_precondition",
                    return_value=self._exact_gate_creation_precondition(),
                ) as governance, mock.patch.object(
                    cli, "_gh_json", side_effect=api_values
                ), mock.patch.object(
                    cli, "_immutable_release_policy", return_value={"enabled": True}
                ), mock.patch.object(
                    cli, "_capture_command", side_effect=captures
                ) as capture:
            with self.assertRaisesRegex(
                cli.IntegrityFailure, "must be bound by cloud configure"
            ):
                cli.command_gate_release(args)
        self.assertEqual(capture.call_count, 2)
        governance.assert_not_called()

    def test_publish_preflight_never_reads_admin_identity_when_tag_is_missing(self):
        repo, source_sha, manifest, args, repository = self._gate_v2_publish_inputs()
        args.action = "prepare-publish"
        args.apply = False
        with mock.patch.object(cli, "_command_exists", return_value=True), \
                mock.patch.object(cli, "_validate_locked_gate_bytes"), \
                mock.patch.object(cli, "_local_release_contract", return_value=(manifest, [])), \
                mock.patch.object(cli, "_git_source_binding", return_value=source_sha), \
                mock.patch.object(cli, "_gh_json", side_effect=(repository, {"sha": source_sha})), \
                mock.patch.object(cli, "_gate_release_view", return_value=None), \
                mock.patch.object(cli, "_immutable_release_policy", return_value={"enabled": True}), \
                mock.patch.object(cli, "_remote_gate_tag_commit", return_value=None), \
                mock.patch.object(
                    cli,
                    "_gate_creation_governance_precondition",
                    return_value=self._exact_gate_creation_precondition(),
                ) as governance, \
                mock.patch.object(
                    cli, "_require_remote_default_head"
                ) as default_head:
            with self.assertRaisesRegex(
                cli.IntegrityFailure, "must be bound by cloud configure"
            ):
                cli.command_gate_release(args)

        governance.assert_not_called()
        default_head.assert_not_called()

    def test_gate_creation_precondition_reobserves_exact_rules_and_identity(self):
        repo = "heelee912/adguard-hotdeal-focus"
        governance = {
            "exact": True,
            "unprovenApplicableRulesets": [],
            "classicBranchProtection": {"compatible": True},
        }
        identity = {
            "exact": True,
            "writeKeyCount": 1,
            "keyExact": True,
            "reservedTitleKeyCount": 1,
        }
        with mock.patch.object(
            cli, "_github_branch_governance_state", return_value=governance
        ) as observe_rules, mock.patch.object(
            cli, "_automation_push_identity_state", return_value=identity
        ) as observe_identity:
            result = cli._gate_creation_governance_precondition(repo, "main")

        self.assertTrue(result["exact"])
        observe_rules.assert_called_once_with(repo, "main")
        observe_identity.assert_called_once_with(repo)

        with mock.patch.object(
            cli,
            "_github_branch_governance_state",
            return_value={**governance, "exact": False},
        ), mock.patch.object(
            cli, "_automation_push_identity_state", return_value=identity
        ) as skipped_identity:
            with self.assertRaisesRegex(cli.IntegrityFailure, "governance is not exact"):
                cli._gate_creation_governance_precondition(repo, "main")
        skipped_identity.assert_not_called()

        with mock.patch.object(
            cli, "_github_branch_governance_state", return_value=governance
        ), mock.patch.object(
            cli,
            "_automation_push_identity_state",
            return_value={**identity, "exact": False},
        ):
            with self.assertRaisesRegex(cli.IntegrityFailure, "one exact automation"):
                cli._gate_creation_governance_precondition(repo, "main")

    def test_publish_preflight_recovers_an_exact_frozen_source_after_main_moves(self):
        repo, source_sha, manifest, args, repository = self._gate_v2_publish_inputs()
        args.action = "prepare-publish"
        args.apply = False
        frozen_sha = "c" * 40
        authority = {
            "tag": "gate-v2.0.2",
            "sourceCommit": frozen_sha,
            "filterBytes": 70270,
            "filterSha256": "7" * 64,
            "exact": True,
        }
        drift = cli.IntegrityFailure(
            "gate release source is not the current default-branch head",
            details={
                "defaultHeadObservation": {
                    "branch": "main",
                    "expectedSourceCommit": source_sha,
                    "observedHead": "e" * 40,
                    "exact": False,
                }
            },
        )
        with mock.patch.object(cli, "_command_exists", return_value=True), \
                mock.patch.object(cli, "_validate_locked_gate_bytes"), \
                mock.patch.object(cli, "_local_release_contract", return_value=(manifest, [])), \
                mock.patch.object(cli, "_git_source_binding", return_value=source_sha), \
                mock.patch.object(cli, "_gh_json", side_effect=(repository, {"sha": source_sha})), \
                mock.patch.object(cli, "_gate_release_view", return_value=None), \
                mock.patch.object(cli, "_immutable_release_policy", return_value={"enabled": True}), \
                mock.patch.object(cli, "_remote_gate_tag_commit", return_value=frozen_sha), \
                mock.patch.object(
                    cli, "_gate_tag_source_authority", return_value=authority
                ), mock.patch.object(
                    cli, "_require_remote_default_head", side_effect=drift
                ):
            result = cli.command_gate_release(args)

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "ready-to-recover")
        self.assertTrue(result["tagPresent"])
        self.assertEqual(result["tagSourceCommit"], frozen_sha)
        self.assertEqual(result["tagSourceAuthority"], authority)
        self.assertNotIn("tagCreationPrecondition", result)
        self.assertFalse(result["defaultHeadObservation"]["exact"])

    def test_publish_timeout_preserves_unknown_terminal_state(self):
        source_sha = "d" * 40
        manifest = {
            "gateArtifactVersion": "1.0.0",
            "filterSubscriptionUrl": (
                "https://github.com/heelee912/adguard-hotdeal-focus/releases/download/"
                "gate-v1.0.0/filter.txt"
            ),
        }
        args = mock.Mock(
            action="publish",
            repo="heelee912/adguard-hotdeal-focus",
            evidence_dir=None,
            apply=True,
            source_ref=source_sha,
        )
        api_values = (
            {
                "nameWithOwner": "heelee912/adguard-hotdeal-focus",
                "visibility": "PUBLIC",
                "defaultBranchRef": {"name": "main"},
            },
            {"sha": source_sha},
            {"sha": source_sha},
        )

        def capture(argv, *, label, timeout_seconds=cli.COMMAND_TIMEOUT_SECONDS,
                    cwd=cli.PROJECT_ROOT):
            del argv, timeout_seconds, cwd
            if label == "gate-release-existence":
                return cli.ExecutionCapture(label, ("gh",), 1, b"", b"not found")
            if label == "gate-release-definitive-absence":
                return gate_absence_capture()
            raise cli.TransientFailure("release create timed out")

        with mock.patch.object(cli, "_command_exists", return_value=True), \
                mock.patch.object(
                    cli, "_local_release_contract", return_value=(manifest, [])
                ), mock.patch.object(
                    cli, "_git_source_binding", return_value=source_sha
                ), mock.patch.object(
                    cli, "_ensure_remote_gate_tag", return_value={
                        "verified": True,
                        "status": "already-bound",
                        "sourceCommit": source_sha,
                        "mutationApplied": False,
                    }
                ), mock.patch.object(
                    cli, "_gh_json", side_effect=api_values
                ), mock.patch.object(
                    cli, "_immutable_release_policy", return_value={"enabled": True}
                ), mock.patch.object(
                    cli, "_require_remote_default_head",
                    return_value=self._exact_default_head(source_sha),
                ), mock.patch.object(cli, "_capture_command", side_effect=capture), \
                mock.patch.object(
                    cli, "_verify_gate_release_with_retry",
                    side_effect=cli.IntegrityFailure("not observable"),
                ):
            result = cli.command_gate_release(args)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "publication-terminal-state-unknown")
        self.assertIsNone(result["mutationApplied"])
        self.assertEqual(result["_processExitCode"], cli.EXIT_ROLLBACK_INCOMPLETE)

    def test_ambiguous_publish_preserves_verified_state_when_evidence_write_fails(self):
        source_sha = "d" * 40
        manifest = {
            "gateArtifactVersion": "1.0.0",
            "filterSubscriptionUrl": (
                "https://github.com/heelee912/adguard-hotdeal-focus/releases/download/"
                "gate-v1.0.0/filter.txt"
            ),
        }
        args = mock.Mock(
            action="publish",
            repo="heelee912/adguard-hotdeal-focus",
            evidence_dir="proof",
            apply=True,
            source_ref=source_sha,
        )
        api_values = (
            {
                "nameWithOwner": "heelee912/adguard-hotdeal-focus",
                "visibility": "PUBLIC",
                "defaultBranchRef": {"name": "main"},
            },
            {"sha": source_sha},
            {"sha": source_sha},
        )
        captures = (
            cli.ExecutionCapture("gate-release-existence", ("gh",), 1, b"", b"missing"),
            gate_absence_capture(),
            cli.ExecutionCapture("publish-immutable-gate-release", ("gh",), 1, b"", b"race"),
        )
        proof = {"immutable": True, "tag": "gate-v1.0.0"}
        with mock.patch.object(cli, "_command_exists", return_value=True), \
                mock.patch.object(cli, "_assert_new_directory"), mock.patch.object(
                    cli, "_local_release_contract", return_value=(manifest, [])
                ), mock.patch.object(
                    cli, "_git_source_binding", return_value=source_sha
                ), mock.patch.object(
                    cli, "_ensure_remote_gate_tag", return_value={
                        "verified": True,
                        "status": "already-bound",
                        "sourceCommit": source_sha,
                        "mutationApplied": False,
                    }
                ), mock.patch.object(
                    cli, "_gh_json", side_effect=api_values
                ), mock.patch.object(
                    cli, "_immutable_release_policy", return_value={"enabled": True}
                ), mock.patch.object(
                    cli, "_require_remote_default_head",
                    return_value=self._exact_default_head(source_sha),
                ), mock.patch.object(
                    cli, "_capture_command", side_effect=captures
                ), mock.patch.object(
                    cli, "_verify_gate_release_with_retry", return_value=proof
                ), mock.patch.object(
                    cli, "_attach_command_evidence",
                    side_effect=PermissionError("denied"),
                ):
            result = cli.command_gate_release(args)
        self.assertFalse(result["ok"])
        self.assertIn("evidence-failed", result["status"])
        self.assertIsNone(result["mutationApplied"])
        self.assertEqual(result["mutationState"], "observed-exact")
        self.assertEqual(result["gateRelease"], proof)


class GateDraftRecoveryTests(unittest.TestCase):
    repo = "heelee912/adguard-hotdeal-focus"
    tag = "gate-v1.0.0"
    source_sha = "a" * 40
    subscription_url = (
        "https://github.com/heelee912/adguard-hotdeal-focus/releases/download/"
        "gate-v1.0.0/filter.txt"
    )
    gate_bytes = b"exact locked gate\n"

    def test_gate_tag_lease_rejects_a_last_moment_tag_move(self):
        with mock.patch.object(cli, "_remote_gate_tag_commit", return_value="b" * 40):
            with self.assertRaisesRegex(cli.IntegrityFailure, "immediately before"):
                cli._require_gate_tag_lease(
                    "owner/repo", "gate-v2.0.2", "a" * 40
                )

    def draft(self, assets):
        return {
            "databaseId": 42,
            "tagName": self.tag,
            "name": cli.GATE_RELEASE_TITLE,
            "body": cli.GATE_RELEASE_NOTES,
            "isDraft": True,
            "isPrerelease": False,
            "isImmutable": False,
            "publishedAt": None,
            "targetCommitish": "main",
            "assets": assets,
        }

    def exact_asset(self):
        return {
            "name": "filter.txt",
            "state": "uploaded",
            "size": len(self.gate_bytes),
            "digest": "sha256:" + hashlib.sha256(self.gate_bytes).hexdigest(),
            "url": self.subscription_url,
        }

    def test_exact_empty_draft_is_uploaded_and_published_without_delete(self):
        initial = self.draft([])
        with_asset = self.draft([self.exact_asset()])
        invocations = []

        def capture(argv, *, label, timeout_seconds=cli.COMMAND_TIMEOUT_SECONDS,
                    cwd=cli.PROJECT_ROOT):
            del timeout_seconds, cwd
            invocations.append((label, tuple(argv)))
            if label == "recover-gate-draft-asset":
                upload_path = Path(argv[4])
                self.assertEqual(upload_path.name, "filter.txt")
                self.assertEqual(upload_path.read_bytes(), self.gate_bytes)
                self.assertNotEqual(
                    upload_path.resolve(), (cli.PROJECT_ROOT / "filter.txt").resolve()
                )
            return cli.ExecutionCapture(label, tuple(argv), 0, b"", b"")

        download = cli.ExecutionCapture(
            "recover-gate-draft-asset-download", ("gh",), 0, b"", b""
        )
        proof = {"immutable": True, "tag": self.tag, "sourceCommit": self.source_sha}
        with mock.patch.object(
            cli, "_remote_gate_tag_commit", return_value=self.source_sha
        ), mock.patch.object(
            cli, "_gate_release_view", return_value=with_asset
        ), mock.patch.object(
            cli, "_capture_command", side_effect=capture
        ), mock.patch.object(
            cli, "_download_exact_gate_asset", return_value=download
        ), mock.patch.object(
            cli, "_verify_gate_release_with_retry", return_value=proof
        ):
            result = cli._recover_exact_gate_draft(
                self.repo,
                self.tag,
                self.subscription_url,
                self.gate_bytes,
                self.source_sha,
                initial,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "recovered-exact-draft")
        self.assertTrue(result["mutationApplied"])
        labels = [label for label, _ in invocations]
        self.assertEqual(
            labels,
            ["recover-gate-draft-asset", "publish-recovered-gate-draft"],
        )
        flattened = [argument for _, argv in invocations for argument in argv]
        self.assertNotIn("--clobber", flattened)
        self.assertNotIn("delete", flattened)
        publish_argv = invocations[-1][1]
        self.assertIn("--draft=false", publish_argv)
        self.assertIn("--latest=false", publish_argv)
        self.assertIn("--verify-tag", publish_argv)

    def test_exact_populated_draft_skips_upload_and_publishes(self):
        initial = self.draft([self.exact_asset()])
        invocations = []

        def capture(argv, *, label, timeout_seconds=cli.COMMAND_TIMEOUT_SECONDS,
                    cwd=cli.PROJECT_ROOT):
            del timeout_seconds, cwd
            invocations.append((label, tuple(argv)))
            return cli.ExecutionCapture(label, tuple(argv), 0, b"", b"")

        proof = {"immutable": True, "tag": self.tag, "sourceCommit": self.source_sha}
        with mock.patch.object(
            cli, "_remote_gate_tag_commit", return_value=self.source_sha
        ), mock.patch.object(
            cli, "_capture_command", side_effect=capture
        ), mock.patch.object(
            cli, "_download_exact_gate_asset", return_value=cli.ExecutionCapture(
                "recover-gate-draft-asset-download", ("gh",), 0, b"", b""
            )
        ), mock.patch.object(
            cli, "_verify_gate_release_with_retry", return_value=proof
        ):
            result = cli._recover_exact_gate_draft(
                self.repo,
                self.tag,
                self.subscription_url,
                self.gate_bytes,
                self.source_sha,
                initial,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "recovered-exact-draft")
        self.assertEqual(
            [label for label, _ in invocations], ["publish-recovered-gate-draft"]
        )

    def test_ambiguous_publish_is_idempotently_accepted_only_after_exact_proof(self):
        initial = self.draft([self.exact_asset()])
        publish = cli.ExecutionCapture(
            "publish-recovered-gate-draft", ("gh",), 1, b"", b"connection lost"
        )
        proof = {"immutable": True, "tag": self.tag, "sourceCommit": self.source_sha}
        with mock.patch.object(
            cli, "_remote_gate_tag_commit", return_value=self.source_sha
        ), mock.patch.object(
            cli, "_capture_command", return_value=publish
        ), mock.patch.object(
            cli, "_download_exact_gate_asset", return_value=cli.ExecutionCapture(
                "recover-gate-draft-asset-download", ("gh",), 0, b"", b""
            )
        ), mock.patch.object(
            cli, "_verify_gate_release_with_retry", return_value=proof
        ):
            result = cli._recover_exact_gate_draft(
                self.repo,
                self.tag,
                self.subscription_url,
                self.gate_bytes,
                self.source_sha,
                initial,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(
            result["status"], "recovered-exact-draft-after-ambiguous-client-result"
        )
        self.assertIsNone(result["mutationApplied"])
        self.assertEqual(result["mutationState"], "observed-exact")

    def test_wrong_or_incomplete_draft_asset_is_never_mutated(self):
        wrong_asset = self.exact_asset()
        wrong_asset["state"] = "starter"
        initial = self.draft([wrong_asset])
        with mock.patch.object(
            cli, "_remote_gate_tag_commit", return_value=self.source_sha
        ), mock.patch.object(cli, "_capture_command") as mutation:
            with self.assertRaisesRegex(cli.IntegrityFailure, "deletion is forbidden"):
                cli._recover_exact_gate_draft(
                    self.repo,
                    self.tag,
                    self.subscription_url,
                    self.gate_bytes,
                    self.source_sha,
                    initial,
                )
        mutation.assert_not_called()


class AdGuardContractTests(unittest.TestCase):
    def args(self, **overrides):
        values = {
            "action": "deploy",
            "manifest_source": cli.DEFAULT_PAGES_MANIFEST,
            "backup_path": None,
            "evidence_dir": None,
            "apply": False,
        }
        values.update(overrides)
        return mock.Mock(**values)

    def windows_context(self):
        return contextlib.ExitStack()

    def test_deploy_delegates_only_the_userscript_release_contract(self):
        manifest, _, artifact_bytes = release_bundle()
        records = [{"path": name, "sha256": hashlib.sha256(content).hexdigest()}
                   for name, content in artifact_bytes.items()]
        urls = {
            "hotdeal-focus.user.js": "https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js",
            "release-manifest.json": cli.DEFAULT_PAGES_MANIFEST,
        }
        captured_argv = []

        def powershell(argv, *, apply_mutation, rollback):
            captured_argv.append(list(argv))
            return {"ok": True}

        with mock.patch.object(cli.sys, "platform", "win32"), mock.patch.object(
            cli, "_command_exists", return_value=True
        ), mock.patch.object(cli, "_public_release_bundle", return_value=(
            manifest, artifact_bytes, records, urls
        )), mock.patch.object(cli, "_powershell_json", side_effect=powershell), mock.patch.object(
            cli, "_try_source_sha", return_value="e" * 40
        ):
            dry = cli.command_adguard(self.args())
            applied = cli.command_adguard(self.args(apply=True))
        self.assertIn("-WhatIf", captured_argv[0])
        self.assertIn("-Apply", captured_argv[1])
        for forbidden in (
            "-FilterUrl", "-ExpectedFilterSha256",
            "-ExpectedInstalledFilterRulesSha256",
            "-ApproveExclusiveTargetMigration",
        ):
            self.assertNotIn(forbidden, captured_argv[0])
            self.assertNotIn(forbidden, captured_argv[1])
        self.assertEqual(
            captured_argv[1][captured_argv[1].index("-UserscriptSource") + 1],
            manifest["installUrl"],
        )
        self.assertEqual(applied["installUrl"], manifest["installUrl"])
        self.assertNotIn("gateRelease", applied)
        self.assertFalse(dry["mutationApplied"])
        self.assertTrue(applied["mutationApplied"])

    def test_removed_gate_release_and_migration_switch_are_usage_errors(self):
        parser = cli.build_parser()
        with self.assertRaises(cli.UsageFailure):
            parser.parse_args([
                "adguard", "deploy", "--approve-exclusive-target-migration", "--json"
            ])
        with self.assertRaises(cli.UsageFailure):
            parser.parse_args([
                "gate-release", "verify", "--repo", "owner/repo", "--json"
            ])

    def test_plaintext_rule_fields_are_redacted(self):
        value = {
            "plan": {
                "rules": ["example.com##.secret"],
                "candidates": [{"one_based_index": 1, "rule_sha256": "a" * 64}],
            },
            "token": "do-not-print",
        }
        public = cli._public_value(value)
        self.assertNotIn("example.com", json.dumps(public))
        self.assertNotIn("do-not-print", json.dumps(public))
        self.assertEqual(public["plan"]["rules"]["count"], 1)

    def test_ipc_key_names_and_error_phrases_never_expose_credentials(self):
        public = cli._public_value({
            "Key": "SUPERSECRET",
            "api_key": "ANOTHER",
            "nested": {"ipc-key": "THIRD"},
        })
        serialized = json.dumps(public)
        for credential in ("SUPERSECRET", "ANOTHER", "THIRD"):
            self.assertNotIn(credential, serialized)
        for message in (
            "Authorization: Bearer SUPERSECRET",
            "IPC key is SUPERSECRET",
            "Bearer SUPERSECRET",
        ):
            with self.subTest(message=message):
                self.assertNotIn("SUPERSECRET", cli._safe_error(message))

    def test_mutation_failure_distinguishes_incomplete_rollback(self):
        failure = subprocess.CompletedProcess(
            ["powershell.exe"], 1,
            stdout=b'{"error":"rollback was incomplete","backup_path":"opaque-backup"}',
            stderr=b"",
        )
        capture = cli.ExecutionCapture(
            "adguard-delegation", ("powershell.exe",), 1, failure.stdout, failure.stderr
        )
        with mock.patch.object(cli, "_capture_command", return_value=capture):
            with self.assertRaises(cli.MutationFailure) as caught:
                cli._powershell_json(("powershell.exe",), apply_mutation=True, rollback=False)
        self.assertEqual(caught.exception.exit_code, cli.EXIT_ROLLBACK_INCOMPLETE)
        self.assertEqual(
            caught.exception.details["adguardRecovery"]["backup_path"],
            "opaque-backup",
        )

    def test_apply_preflight_failure_is_not_misreported_as_rollback(self):
        capture = cli.ExecutionCapture(
            "adguard-delegation", ("powershell.exe",), 1,
            b'{"error":"cannot connect"}', b"",
        )
        with mock.patch.object(cli, "_capture_command", return_value=capture):
            with self.assertRaises(cli.VerificationFailure) as caught:
                cli._powershell_json(("powershell.exe",), apply_mutation=True, rollback=False)
        self.assertEqual(caught.exception.exit_code, cli.EXIT_VERIFICATION)

    def test_success_json_followed_by_cleanup_failure_preserves_applied_state(self):
        capture = cli.ExecutionCapture(
            "adguard-delegation",
            ("powershell.exe",),
            1,
            b'{"command":"deploy","backup":"C:/backup","verified":true}',
            b"cleanup failed",
        )
        with mock.patch.object(cli, "_capture_command", return_value=capture):
            with self.assertRaises(cli.MutationFailure) as caught:
                cli._powershell_json(
                    ("powershell.exe",), apply_mutation=True, rollback=False
                )
        self.assertEqual(caught.exception.exit_code, cli.EXIT_ROLLBACK_INCOMPLETE)
        self.assertTrue(caught.exception.details["mutationApplied"])
        self.assertEqual(
            caught.exception.details["adguardRecovery"]["backup"],
            "C:/backup",
        )

    def test_apply_timeout_and_non_json_failure_are_rollback_incomplete(self):
        cases = (
            cli.TransientFailure("timeout"),
            cli.ExecutionCapture(
                "adguard-delegation", ("powershell.exe",), 1, b"", b"abrupt exit"
            ),
        )
        for failure in cases:
            with self.subTest(failure=type(failure).__name__), mock.patch.object(
                cli,
                "_capture_command",
                side_effect=failure if isinstance(failure, Exception) else None,
                return_value=None if isinstance(failure, Exception) else failure,
            ):
                with self.assertRaises(cli.MutationFailure) as caught:
                    cli._powershell_json(
                        ("powershell.exe",), apply_mutation=True, rollback=False
                    )
                self.assertEqual(
                    caught.exception.exit_code,
                    cli.EXIT_ROLLBACK_INCOMPLETE,
                )

    def test_apply_malformed_zero_exit_output_is_rollback_incomplete(self):
        capture = cli.ExecutionCapture(
            "adguard-delegation", ("powershell.exe",), 0, b"not-json", b""
        )
        with mock.patch.object(cli, "_capture_command", return_value=capture):
            with self.assertRaises(cli.MutationFailure) as caught:
                cli._powershell_json(
                    ("powershell.exe",), apply_mutation=True, rollback=False
                )
        self.assertEqual(caught.exception.exit_code, cli.EXIT_ROLLBACK_INCOMPLETE)

    def test_post_mutation_evidence_failure_preserves_applied_state_and_exit(self):
        applied = cli._base_result(
            "adguard.deploy",
            ok=True,
            status="deployed",
            source_sha="a" * 40,
            mutationApplied=True,
            adguard={"backup": "opaque-backup"},
        )
        degraded = None
        for evidence_error in (
            cli.IntegrityFailure("evidence destination race"),
            PermissionError("evidence write denied"),
            OSError(28, "evidence device full"),
        ):
            with self.subTest(error=type(evidence_error).__name__), mock.patch.object(
                cli,
                "_attach_command_evidence",
                side_effect=evidence_error,
            ):
                degraded = cli._attach_post_mutation_evidence(applied, "evidence")
            self.assertFalse(degraded["ok"])
            self.assertTrue(degraded["mutationApplied"])
            self.assertEqual(degraded["adguard"]["backup"], "opaque-backup")
            self.assertEqual(degraded["status"], "deployed-evidence-failed")

        assert degraded is not None
        parsed = mock.Mock(top_command="adguard", action="deploy")
        parsed.execute = lambda _: dict(degraded)
        parser = mock.Mock()
        parser.parse_args.return_value = parsed
        stdout = io.StringIO()
        with mock.patch.object(cli, "build_parser", return_value=parser), \
                contextlib.redirect_stdout(stdout):
            exit_code = cli.main(["adguard", "deploy"])
        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, cli.EXIT_INTEGRITY)
        self.assertTrue(payload["mutationApplied"])
        self.assertEqual(payload["adguard"]["backup"], "opaque-backup")


def stat_mode_symlink() -> int:
    # POSIX symlink mode with broad permissions, encoded in ZipInfo.external_attr.
    return 0o120777


if __name__ == "__main__":
    unittest.main()
