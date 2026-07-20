from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLI_PATH = ROOT / "scripts" / "hotdeal_focus_cli.py"
SPEC = importlib.util.spec_from_file_location("hotdeal_focus_cli_gate_v2", CLI_PATH)
assert SPEC and SPEC.loader
cli = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cli
SPEC.loader.exec_module(cli)

EXPECTED_URL = (
    "https://github.com/heelee912/adguard-hotdeal-focus/releases/download/"
    "gate-v2.0.2/filter.txt"
)
V1_URL = (
    "https://github.com/heelee912/adguard-hotdeal-focus/releases/download/"
    "gate-v1.0.0/filter.txt"
)
EXPECTED_BYTES = 70270
EXPECTED_RAW_SHA256 = "778c88297473f1aa94564e24780cdcc763164e6de9a7c6ab5ffd42df0e18ae38"
EXPECTED_RULES_SHA256 = (
    "a7619be2bebf35f6f502366627697c19690c81adb6833c7cdaf7440066b593bb"
)
EXPECTED_RULE_COUNT = 91


def generated_gate() -> bytes:
    return subprocess.check_output(
        [sys.executable, "scripts/build_gate_filter.py", "--stdout"],
        cwd=ROOT,
    )


def independently_canonicalized_rules(content: bytes) -> bytes:
    text = content.decode("utf-8").lstrip("\ufeff")
    text = text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
    return "\n".join(
        line
        for line in text.split("\n")
        if line.strip() and not line.lstrip().startswith("!")
    ).encode("utf-8")


def exact_manifest(gate_bytes: bytes) -> dict[str, object]:
    return {
        "protocolVersion": 2,
        "gateArtifactVersion": "2.0.2",
        "filterSubscriptionUrl": EXPECTED_URL,
        "artifacts": {
            "filter.txt": {
                "version": "2.0.2",
                "bytes": len(gate_bytes),
                "sha256": hashlib.sha256(gate_bytes).hexdigest(),
                "installedRulesSha256": hashlib.sha256(
                    independently_canonicalized_rules(gate_bytes)
                ).hexdigest(),
            },
        },
    }


class ActiveGateV2TrustRootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.gate_bytes = generated_gate()
        cls.lock_bytes = (ROOT / "config" / "gate-artifacts.json").read_bytes()
        cls.lock = json.loads(cls.lock_bytes)

    def test_generator_lock_and_cli_constants_are_one_exact_v2_trust_root(self) -> None:
        rules = independently_canonicalized_rules(self.gate_bytes)
        rule_count = len(rules.decode("utf-8").splitlines())

        self.assertEqual(len(self.gate_bytes), EXPECTED_BYTES)
        self.assertEqual(hashlib.sha256(self.gate_bytes).hexdigest(), EXPECTED_RAW_SHA256)
        self.assertEqual(hashlib.sha256(rules).hexdigest(), EXPECTED_RULES_SHA256)
        self.assertEqual(rule_count, EXPECTED_RULE_COUNT)
        self.assertEqual(
            self.lock,
            {
                "schemaVersion": 1,
                "protocolVersion": 2,
                "gateArtifactVersion": "2.0.2",
                "filterSubscriptionUrl": EXPECTED_URL,
                "artifact": {
                    "path": "filter.txt",
                    "bytes": EXPECTED_BYTES,
                    "sha256": EXPECTED_RAW_SHA256,
                    "installedRulesSha256": EXPECTED_RULES_SHA256,
                },
            },
        )
        self.assertEqual(cli.GATE_LOCK_PROTOCOL_VERSION, 2)
        self.assertEqual(cli.GATE_LOCK_ARTIFACT_VERSION, "2.0.2")
        self.assertEqual(cli.GATE_LOCK_SUBSCRIPTION_URL, EXPECTED_URL)
        self.assertEqual(cli.GATE_LOCK_BYTES, EXPECTED_BYTES)
        self.assertEqual(cli.GATE_LOCK_SHA256, EXPECTED_RAW_SHA256)
        self.assertEqual(cli.GATE_LOCK_INSTALLED_RULES_SHA256, EXPECTED_RULES_SHA256)
        self.assertEqual(cli.GATE_LOCK_RULE_COUNT, EXPECTED_RULE_COUNT)
        self.assertEqual(
            cli._validate_gate_artifact_lock(
                exact_manifest(self.gate_bytes), self.gate_bytes, self.lock_bytes
            ),
            self.lock,
        )

    def test_v1_release_url_is_not_accepted_by_the_active_trust_root(self) -> None:
        manifest = exact_manifest(self.gate_bytes)
        manifest["filterSubscriptionUrl"] = V1_URL
        with self.assertRaisesRegex(cli.IntegrityFailure, "immutable gate lock"):
            cli._validate_gate_artifact_lock(
                manifest, self.gate_bytes, self.lock_bytes
            )

    def test_publish_workflow_targets_only_v2(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "publish-gate.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("group: hotdeal-focus-release-state", workflow)
        self.assertIn("Publish or exactly verify gate-v2.0.2", workflow)
        self.assertNotIn("gate-v1", workflow)

    def test_adguard_deployment_example_uses_only_the_v2_release_url(self) -> None:
        powershell = (ROOT / "scripts" / "adguard_windows_cli.ps1").read_text(
            encoding="utf-8-sig"
        )
        example = powershell.rsplit(".EXAMPLE", 1)[-1].split("#>", 1)[0]
        self.assertIn(EXPECTED_URL, example)
        self.assertNotIn(V1_URL, example)

    def test_v2_release_notes_preserve_v1_as_immutable_predecessor(self) -> None:
        self.assertIn("gate-v1.0.0", cli.GATE_RELEASE_NOTES)
        self.assertIn("never overwritten", cli.GATE_RELEASE_NOTES)
        self.assertIn("fallback are not accepted", cli.GATE_RELEASE_NOTES)


if __name__ == "__main__":
    unittest.main()
