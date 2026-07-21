from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import build_release  # noqa: E402
from build_filter import ConfigError  # noqa: E402


class ReleaseHighWaterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config_bytes = build_release.DEFAULT_CONFIG_PATH.read_bytes()
        cls.config = json.loads(cls.config_bytes)
        cls.static_bytes = build_release.STATIC_FILTER_PATH.read_bytes()
        cls.userscript_bytes = build_release.USERSCRIPT_PATH.read_bytes()
        cls.package_bytes = build_release.PACKAGE_PATH.read_bytes()
        cls.package_lock_bytes = build_release.PACKAGE_LOCK_PATH.read_bytes()
        cls.high_water_bytes = build_release.HIGH_WATER_PATH.read_bytes()

    def render(self, **overrides: bytes) -> tuple[bytes, bytes]:
        values = {
            "static_bytes": self.static_bytes,
            "userscript_bytes": self.userscript_bytes,
            "config_bytes": self.config_bytes,
            "package_bytes": self.package_bytes,
            "package_lock_bytes": self.package_lock_bytes,
            "high_water_bytes": self.high_water_bytes,
        }
        values.update(overrides)
        return build_release.render_materialized_release_set(**values)

    def test_current_release_rebuild_is_byte_idempotent(self) -> None:
        manifest_bytes, high_water_bytes = self.render()
        self.assertEqual(build_release.MANIFEST_PATH.read_bytes(), manifest_bytes)
        self.assertEqual(self.high_water_bytes, high_water_bytes)
        second_manifest, second_high_water = self.render(
            high_water_bytes=high_water_bytes,
        )
        self.assertEqual(manifest_bytes, second_manifest)
        self.assertEqual(high_water_bytes, second_high_water)

    def test_version_bump_appends_one_record_and_then_is_idempotent(self) -> None:
        old_version = self.config["metadata"]["version"]
        major, minor, patch = (int(part) for part in old_version.split("."))
        new_version = f"{major}.{minor}.{patch + 1}"

        config = copy.deepcopy(self.config)
        config["metadata"]["version"] = new_version
        config_bytes = (json.dumps(config, ensure_ascii=False, indent=2) + "\n").encode()
        static_bytes = self.static_bytes.replace(
            f"! Version: {old_version}".encode(),
            f"! Version: {new_version}".encode(),
            1,
        )
        userscript_bytes = self.userscript_bytes.replace(
            f"// @version      {old_version}".encode(),
            f"// @version      {new_version}".encode(),
            1,
        )
        package = json.loads(self.package_bytes)
        package["version"] = new_version
        package_bytes = (json.dumps(package, ensure_ascii=False, indent=2) + "\n").encode()
        package_lock = json.loads(self.package_lock_bytes)
        package_lock["version"] = new_version
        package_lock["packages"][""]["version"] = new_version
        package_lock_bytes = (
            json.dumps(package_lock, ensure_ascii=False, indent=2) + "\n"
        ).encode()

        manifest_bytes, high_water_bytes = self.render(
            static_bytes=static_bytes,
            userscript_bytes=userscript_bytes,
            config_bytes=config_bytes,
            package_bytes=package_bytes,
            package_lock_bytes=package_lock_bytes,
        )
        previous = json.loads(self.high_water_bytes)
        current = json.loads(high_water_bytes)
        self.assertEqual(previous["records"], current["records"][:-1])
        self.assertEqual(new_version, current["records"][-1]["releaseVersion"])
        self.assertEqual(
            build_release.public_bundle_sha256(manifest_bytes, userscript_bytes),
            current["records"][-1]["bundleSha256"],
        )
        self.assertEqual(
            len(previous["records"]),
            json.loads(manifest_bytes)["sourceIntegrity"][
                "state/release-high-water.json"
            ]["recordCount"],
        )

        second_manifest, second_high_water = build_release.render_materialized_release_set(
            static_bytes=static_bytes,
            userscript_bytes=userscript_bytes,
            config_bytes=config_bytes,
            package_bytes=package_bytes,
            package_lock_bytes=package_lock_bytes,
            high_water_bytes=high_water_bytes,
        )
        self.assertEqual(manifest_bytes, second_manifest)
        self.assertEqual(high_water_bytes, second_high_water)

    def test_same_version_manifest_only_change_is_rejected(self) -> None:
        package = json.loads(self.package_bytes)
        package["description"] = f"{package['description']} (tampered)"
        package_bytes = (json.dumps(package, ensure_ascii=False, indent=2) + "\n").encode()
        with self.assertRaisesRegex(ConfigError, "same-version public bundle differs"):
            self.render(package_bytes=package_bytes)

    def test_config_mapping_cannot_disagree_with_config_bytes(self) -> None:
        forged = copy.deepcopy(self.config)
        forged["metadata"]["version"] = "9.9.9"
        with self.assertRaisesRegex(ConfigError, "must match config_bytes exactly"):
            build_release.render_materialized_release_manifest(
                forged,
                static_bytes=self.static_bytes,
                userscript_bytes=self.userscript_bytes,
                config_bytes=self.config_bytes,
                package_bytes=self.package_bytes,
                package_lock_bytes=self.package_lock_bytes,
                high_water_bytes=self.high_water_bytes,
            )


if __name__ == "__main__":
    unittest.main()
