from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IMMUTABLE_FILTER = (ROOT / "filter.txt").read_bytes()
CLI_PATH = ROOT / "scripts" / "hotdeal_focus_cli.py"
SPEC = importlib.util.spec_from_file_location("hotdeal_focus_cli_reader_v2", CLI_PATH)
assert SPEC and SPEC.loader
cli = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cli
SPEC.loader.exec_module(cli)


VALID_USERSCRIPT = b"""// ==UserScript==
// @name         AdGuard Hotdeal Focus Reader Gate
// @version      2.1.0
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

VALID_FILTER = b"""! Title: AdGuard Hotdeal Focus Marker Gate
! Version: 2.0.2
! Hotdeal-Focus-Protocol: 2
example.com##html.hdf-v2-lock:not(.hdf-v2-ready[data-hotdeal-focus-ready="1"][data-hotdeal-focus-protocol="2"][data-hotdeal-focus-state="ready"][data-hotdeal-focus-status="ready"]) .hdf-v2-keep
example.com##[data-hotdeal-focus-ready][data-hotdeal-focus-keep][data-hotdeal-focus-shell][data-hotdeal-focus-deep][data-hotdeal-focus-role="body"].hdf-v2-shell.hdf-v2-deep.hdf-v2-role-body
"""


def manifest_bytes(
    userscript: bytes = VALID_USERSCRIPT,
    filter_source: bytes = IMMUTABLE_FILTER,
) -> bytes:
    manifest = {
        "schemaVersion": 1,
        "status": "release-ready",
        "releaseVersion": "2.1.0",
        "protocolVersion": 2,
        "gateArtifactVersion": "2.0.2",
        "filterSubscriptionUrl": cli.GATE_LOCK_SUBSCRIPTION_URL,
        "artifacts": {
            "filter.txt": {
                "version": "2.0.2",
                "bytes": len(filter_source),
                "sha256": hashlib.sha256(filter_source).hexdigest(),
                "installedRulesSha256": cli.installed_filter_rules_sha256(
                    filter_source
                ),
            },
            "hotdeal-focus.user.js": {
                "version": "2.1.0",
                "bytes": len(userscript),
                "sha256": hashlib.sha256(userscript).hexdigest(),
                "canonicalTextSha256": hashlib.sha256(
                    cli.canonical_text_bytes(userscript)
                ).hexdigest(),
            },
        },
    }
    return json.dumps(manifest, sort_keys=True).encode("utf-8")


class ReaderGateV2DeploymentContractTests(unittest.TestCase):
    def test_exact_protocol_two_bundle_is_accepted(self) -> None:
        manifest, records = cli._verify_release_files(
            manifest_bytes(),
            {
                "filter.txt": IMMUTABLE_FILTER,
                "hotdeal-focus.user.js": VALID_USERSCRIPT,
            },
        )
        self.assertEqual(manifest["protocolVersion"], 2)
        self.assertEqual(manifest["gateArtifactVersion"], "2.0.2")
        self.assertEqual(cli._reader_gate_v2_contract(VALID_USERSCRIPT), 2)
        self.assertEqual(cli._marker_gate_v2_contract(IMMUTABLE_FILTER), 2)
        self.assertEqual(
            [record["path"] for record in records],
            ["filter.txt", "hotdeal-focus.user.js", "release-manifest.json"],
        )

    def test_userscript_rejects_none_extra_grant_and_protocol_one(self) -> None:
        invalid_sources = {
            "grant none": VALID_USERSCRIPT.replace(
                b"// @grant        GM_addElement", b"// @grant        none"
            ),
            "extra grant": VALID_USERSCRIPT.replace(
                b"// @grant        GM_addElement",
                b"// @grant        GM_addElement\n// @grant        none",
            ),
            "protocol one": VALID_USERSCRIPT.replace(
                b'const PROTOCOL_VERSION = "2";',
                b'const PROTOCOL_VERSION = "1";',
            ),
            "diagnostics one": VALID_USERSCRIPT.replace(
                b"protocolVersion: Number(PROTOCOL_VERSION)", b"protocolVersion: 1"
            ),
            "missing runtime selector": VALID_USERSCRIPT.replace(
                b'style[data-hotdeal-focus-runtime-style="${PROTOCOL_VERSION}"]',
                b"style[data-removed]",
            ),
        }
        for label, source in invalid_sources.items():
            with self.subTest(label=label), self.assertRaises(cli.IntegrityFailure):
                cli._reader_gate_v2_contract(source)

    def test_filter_rejects_protocol_one_and_missing_core_marker(self) -> None:
        invalid_sources = {
            "header protocol one": VALID_FILTER.replace(
                b"! Hotdeal-Focus-Protocol: 2", b"! Hotdeal-Focus-Protocol: 1"
            ),
            "rule protocol one": VALID_FILTER.replace(
                b'data-hotdeal-focus-protocol="2"',
                b'data-hotdeal-focus-protocol="1"',
            ),
            "missing core class": VALID_FILTER.replace(
                b"hdf-v2-deep", b"hdf-removed-deep"
            ),
        }
        for label, source in invalid_sources.items():
            with self.subTest(label=label), self.assertRaises(cli.IntegrityFailure):
                cli._marker_gate_v2_contract(source)

    def test_manifest_rejects_every_v1_and_cross_version_binding(self) -> None:
        baseline = json.loads(manifest_bytes())
        invalid_manifests = []
        for field, value in (
            ("protocolVersion", 1),
            ("protocolVersion", "2"),
            ("gateArtifactVersion", "1.0.0"),
            (
                "filterSubscriptionUrl",
                "https://github.com/heelee912/adguard-hotdeal-focus/releases/"
                "download/gate-v1.0.0/filter.txt",
            ),
        ):
            candidate = json.loads(json.dumps(baseline))
            candidate[field] = value
            invalid_manifests.append((field, candidate))
        for label, candidate in invalid_manifests:
            with self.subTest(label=label), self.assertRaises(cli.IntegrityFailure):
                cli._manifest_contract(json.dumps(candidate).encode("utf-8"))

    def test_semantic_contract_is_checked_before_artifact_digest(self) -> None:
        invalid = VALID_USERSCRIPT.replace(
            b"// @grant        GM_addElement", b"// @grant        none"
        )
        with self.assertRaisesRegex(
            cli.IntegrityFailure, "exactly one @grant GM_addElement"
        ):
            cli._verify_release_files(
                manifest_bytes(),
                {"filter.txt": IMMUTABLE_FILTER, "hotdeal-focus.user.js": invalid},
            )

    @unittest.skipUnless(sys.platform == "win32", "PowerShell harness is Windows-only")
    def test_windows_installer_rejects_v1_before_adguard_connection(self) -> None:
        powershell = shutil.which("pwsh") or shutil.which("powershell.exe")
        self.assertIsNotNone(powershell)
        completed = subprocess.run(
            [
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(ROOT / "tests" / "adguard_release_v2_contract_harness.ps1"),
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["cross_version_rejected"])

        source = (ROOT / "scripts" / "adguard_windows_cli.ps1").read_text(
            encoding="utf-8-sig"
        )
        self.assertLess(
            source.index("Assert-ReleaseInputsMatchManifest -ManifestContract"),
            source.index("$session = Connect-AdGuardSession"),
        )


if __name__ == "__main__":
    unittest.main()
