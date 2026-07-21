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
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_deleteValue
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


def manifest_bytes(
    userscript: bytes = VALID_USERSCRIPT,
) -> bytes:
    manifest = {
        "schemaVersion": 2,
        "status": "release-ready",
        "releaseVersion": "2.1.0",
        "protocolVersion": 2,
        "installUrl": cli.RELEASE_USERSCRIPT_URL,
        "generatorVersion": "2.1.0",
        "rollback_of": None,
        "configSha256": "a" * 64,
        "coverage": {},
        "promotion": None,
        "artifacts": {
            "hotdeal-focus.user.js": {
                "version": "2.1.0",
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
    return json.dumps(manifest, sort_keys=True).encode("utf-8")


class ReaderGateV2DeploymentContractTests(unittest.TestCase):
    def test_exact_standalone_protocol_two_bundle_is_accepted(self) -> None:
        manifest, records = cli._verify_release_files(
            manifest_bytes(),
            {"hotdeal-focus.user.js": VALID_USERSCRIPT},
        )
        self.assertEqual(manifest["protocolVersion"], 2)
        self.assertEqual(manifest["installUrl"], cli.RELEASE_USERSCRIPT_URL)
        self.assertEqual(cli._reader_gate_v2_contract(VALID_USERSCRIPT), 2)
        self.assertEqual(
            [record["path"] for record in records],
            ["hotdeal-focus.user.js", "release-manifest.json"],
        )

    def test_userscript_rejects_none_extra_grant_and_protocol_one(self) -> None:
        invalid_sources = {
            "grant none": VALID_USERSCRIPT.replace(
                b"// @grant        GM_addElement", b"// @grant        none"
            ),
            "extra grant": VALID_USERSCRIPT.replace(
                b"// @grant        window.onurlchange",
                b"// @grant        window.onurlchange\n// @grant        none",
            ),
            "missing urlchange grant": VALID_USERSCRIPT.replace(
                b"// @grant        window.onurlchange\n", b""
            ),
            "mutable update url": VALID_USERSCRIPT.replace(
                cli.RELEASE_USERSCRIPT_URL.encode(),
                b"https://example.com/mutable.user.js",
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

    def test_manifest_rejects_legacy_filter_and_wrong_install_binding(self) -> None:
        baseline = json.loads(manifest_bytes())
        invalid_manifests = []
        for field, value in (
            ("schemaVersion", 1),
            ("protocolVersion", 1),
            ("protocolVersion", "2"),
            ("installUrl", "https://example.com/mutable.user.js"),
        ):
            candidate = json.loads(json.dumps(baseline))
            candidate[field] = value
            invalid_manifests.append((field, candidate))
        with_filter = json.loads(json.dumps(baseline))
        with_filter["artifacts"]["filter.txt"] = {"sha256": "b" * 64}
        invalid_manifests.append(("legacy filter artifact", with_filter))
        for label, candidate in invalid_manifests:
            with self.subTest(label=label), self.assertRaises(cli.IntegrityFailure):
                cli._manifest_contract(json.dumps(candidate).encode("utf-8"))

    def test_semantic_contract_is_checked_before_artifact_digest(self) -> None:
        invalid = VALID_USERSCRIPT.replace(
            b"// @grant        GM_addElement", b"// @grant        none"
        )
        with self.assertRaisesRegex(
            cli.IntegrityFailure, "exact ordered grants"
        ):
            cli._verify_release_files(
                manifest_bytes(),
                {"hotdeal-focus.user.js": invalid},
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
