#!/usr/bin/env python3
"""Atomically build filters and their deterministic release manifest."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from build_filter import (
    ConfigError,
    DEFAULT_CONFIG_PATH,
    PROJECT_ROOT,
    load_config,
    render_filter,
    validate_config,
)
from build_gate_filter import (
    GATE_ARTIFACT_VERSION,
    GENERATOR_VERSION,
    PROTOCOL_VERSION,
    render_gate_filter,
)


GATE_FILTER_PATH = PROJECT_ROOT / "filter.txt"
STATIC_FILTER_PATH = PROJECT_ROOT / "filter-static.txt"
USERSCRIPT_PATH = PROJECT_ROOT / "hotdeal-focus.user.js"
PACKAGE_PATH = PROJECT_ROOT / "package.json"
PACKAGE_LOCK_PATH = PROJECT_ROOT / "package-lock.json"
MANIFEST_PATH = PROJECT_ROOT / "release-manifest.json"
APPROVED_STATE_PATH = PROJECT_ROOT / "state" / "approved-variants.json"
GATE_ARTIFACT_LOCK_PATH = PROJECT_ROOT / "config" / "gate-artifacts.json"
FIXTURE_PATHS = (
    PROJECT_ROOT / "tests" / "fixtures" / "dom-regressions.json",
    PROJECT_ROOT / "tests" / "fixtures" / "behavior-baseline.json",
)
USERSCRIPT_VERSION_PATTERN = re.compile(r"^//\s*@version\s+([^\s]+)\s*$", re.MULTILINE)
FILTER_VERSION_PATTERN = re.compile(r"^! Version:\s+([^\s]+)\s*$", re.MULTILINE)
RELEASE_USERSCRIPT_URL = (
    "https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js"
)
GATE_RELEASE_TAG = f"gate-v{GATE_ARTIFACT_VERSION}"
GATE_FILTER_SUBSCRIPTION_URL = (
    "https://github.com/heelee912/adguard-hotdeal-focus/releases/download/"
    f"{GATE_RELEASE_TAG}/filter.txt"
)


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def canonical_text_bytes(content: bytes) -> bytes:
    """Mirror the Windows installer canonical-text hash contract exactly."""
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ConfigError("release text artifact must be strict UTF-8") from error
    canonical = text.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    return canonical.rstrip("\n").encode("utf-8")


def canonical_text_sha256(content: bytes) -> str:
    return sha256_bytes(canonical_text_bytes(content))


def installed_filter_rules_sha256(content: bytes) -> str:
    """Hash the ordered, non-comment rules as AdGuard installation verifies them."""
    canonical_text = canonical_text_bytes(content).decode("utf-8")
    rules = [
        line
        for line in canonical_text.split("\n")
        if line.strip() and not line.lstrip().startswith("!")
    ]
    if not rules:
        raise ConfigError("filter.txt must contain installable non-comment rules")
    return canonical_text_sha256("\n".join(rules).encode("utf-8"))


def relative_path(path: Path) -> str:
    return path.relative_to(PROJECT_ROOT).as_posix()


def semantic_version_core(version: str) -> tuple[int, int, int]:
    core = version.split("-", 1)[0].split("+", 1)[0]
    try:
        major, minor, patch = (int(part) for part in core.split("."))
    except (TypeError, ValueError) as error:
        raise ConfigError(f"invalid release version: {version}") from error
    return major, minor, patch


def read_required_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError as error:
        raise ConfigError(f"required release artifact is missing: {relative_path(path)}") from error


def userscript_version(content: bytes) -> str:
    match = USERSCRIPT_VERSION_PATTERN.search(content.decode("utf-8"))
    if not match:
        raise ConfigError("hotdeal-focus.user.js has no @version metadata")
    return match.group(1)


def filter_version(content: bytes, artifact_name: str) -> str:
    match = FILTER_VERSION_PATTERN.search(content.decode("utf-8"))
    if not match:
        raise ConfigError(f"{artifact_name} has no Version header")
    return match.group(1)


def validate_userscript_release_metadata(content: bytes) -> None:
    source = content.decode("utf-8")
    for placeholder in (
        "__HOTDEAL_FOCUS_DOWNLOAD_URL__",
        "__HOTDEAL_FOCUS_UPDATE_URL__",
        "__HOTDEAL_FOCUS_OWNER__",
    ):
        if placeholder in source:
            raise ConfigError(f"userscript contains unresolved release placeholder: {placeholder}")
    for key in ("downloadURL", "updateURL"):
        values = re.findall(rf"^//\s*@{key}\s+(.+?)\s*$", source, re.MULTILINE)
        if values != [RELEASE_USERSCRIPT_URL]:
            raise ConfigError(f"userscript @{key} must use the immutable GitHub Pages URL")


def coverage_manifest(config: Mapping[str, Any]) -> dict[str, Any]:
    sites = []
    route_count = 0
    layout_count = 0
    variant_count = 0
    for site in sorted(config["sites"], key=lambda item: item["id"]):
        layouts = []
        for layout in sorted(site["layouts"], key=lambda item: item["id"]):
            paths = sorted(layout.get("paths") or [layout["path"]])
            route_count += len(paths)
            layout_count += 1
            variants = []
            for variant in sorted(layout.get("variants", []), key=lambda item: item["id"]):
                variant_count += 1
                variant_paths = sorted(variant["paths"])
                route_count += len(variant_paths)
                variants.append(
                    {
                        "id": variant["id"],
                        "paths": variant_paths,
                        "applicableProfiles": sorted(variant["applicable_profiles"]),
                        "proofProfiles": sorted(variant["proof_profiles"]),
                        "requiredRoles": sorted(variant["required_roles"]),
                    }
                )
            layouts.append(
                {
                    "id": layout["id"],
                    "domain": layout["domain"],
                    "paths": paths,
                    "applicableProfiles": sorted(layout["applicable_profiles"]),
                    "requiredRoles": sorted(layout["required_roles"]),
                    "variants": variants,
                }
            )
        sites.append({"id": site["id"], "layouts": layouts})
    return {
        "siteCount": len(sites),
        "layoutCount": layout_count,
        "layoutFamilyCount": layout_count,
        "contractCount": layout_count + variant_count,
        "routeCount": route_count,
        "sites": sites,
    }


def _config_variant_contracts(
    config: Mapping[str, Any],
) -> dict[tuple[str, str, str], dict[str, Any]]:
    contracts: dict[tuple[str, str, str], dict[str, Any]] = {}
    for site in config["sites"]:
        for layout in site["layouts"]:
            for variant in layout.get("variants", []):
                key = (site["id"], layout["id"], variant["id"])
                contracts[key] = {
                    "siteId": site["id"],
                    "layoutId": layout["id"],
                    "variantId": variant["id"],
                    "pageRoot": variant["page_root"],
                    "paths": sorted(variant["paths"]),
                    "sampleUrls": sorted(variant["sample_urls"]),
                    "proofProfiles": sorted(variant["proof_profiles"]),
                    "requiredRoles": sorted(variant["required_roles"]),
                    "roles": {
                        role: sorted(selectors)
                        for role, selectors in sorted(variant["required_groups"].items())
                    },
                    "roleProjection": copy.deepcopy(variant["role_projection"]),
                    "commentItems": sorted(variant["comment_contract"]["items"]),
                    "commentControls": sorted(variant["comment_contract"]["controls"]),
                    "commentIgnored": sorted(variant["comment_contract"]["ignored"]),
                    "allowEmptyComments": variant["comment_contract"]["allow_empty"],
                    "candidateSha256": variant["candidate_sha256"],
                }
    return contracts


def _state_variant_contracts(
    approved_variants: Sequence[Mapping[str, Any]],
) -> dict[tuple[str, str, str], dict[str, Any]]:
    contracts: dict[tuple[str, str, str], dict[str, Any]] = {}
    expected_keys = {
        "siteId", "layoutId", "variantId", "pageRoot", "paths", "sampleUrls",
        "proofProfiles", "requiredRoles", "roles", "roleProjection", "commentItems",
        "commentControls", "commentIgnored", "allowEmptyComments",
        "candidateSha256", "evidenceSha256", "releaseVersion",
        "draftArtifactSetSha256",
    }
    for index, value in enumerate(approved_variants):
        if not isinstance(value, Mapping) or set(value) != expected_keys:
            raise ConfigError(
                f"approved state variant {index} has unexpected or missing fields"
            )
        try:
            key = (value["siteId"], value["layoutId"], value["variantId"])
            if not all(isinstance(part, str) and part for part in key):
                raise TypeError
            roles = value["roles"]
            if not isinstance(roles, Mapping):
                raise TypeError
            contract = {
                "siteId": key[0],
                "layoutId": key[1],
                "variantId": key[2],
                "pageRoot": value["pageRoot"],
                "paths": sorted(value["paths"]),
                "sampleUrls": sorted(value["sampleUrls"]),
                "proofProfiles": sorted(value["proofProfiles"]),
                "requiredRoles": sorted(value["requiredRoles"]),
                "roles": {
                    role: sorted(selectors)
                    for role, selectors in sorted(roles.items())
                },
                "roleProjection": copy.deepcopy(value["roleProjection"]),
                "commentItems": sorted(value["commentItems"]),
                "commentControls": sorted(value["commentControls"]),
                "commentIgnored": sorted(value["commentIgnored"]),
                "allowEmptyComments": value["allowEmptyComments"],
                "candidateSha256": value["candidateSha256"],
            }
        except (KeyError, TypeError, ValueError) as error:
            raise ConfigError(f"approved state variant {index} is malformed") from error
        if key in contracts:
            raise ConfigError(f"approved state contains duplicate variant {'/'.join(key)}")
        contracts[key] = contract
    return contracts


def artifact_entry(content: bytes) -> dict[str, Any]:
    return {"sha256": sha256_bytes(content), "bytes": len(content)}


def public_artifact_entry(path: str, content: bytes) -> dict[str, Any]:
    entry = artifact_entry(content)
    if path == relative_path(USERSCRIPT_PATH):
        entry["version"] = userscript_version(content)
        entry["canonicalTextSha256"] = canonical_text_sha256(content)
    if path == relative_path(GATE_FILTER_PATH):
        entry["version"] = filter_version(content, "filter.txt")
        entry["installedRulesSha256"] = installed_filter_rules_sha256(content)
    return entry


def validate_gate_artifact_lock(gate_bytes: bytes) -> tuple[dict[str, Any], bytes]:
    lock_bytes = read_required_bytes(GATE_ARTIFACT_LOCK_PATH)
    try:
        lock = json.loads(lock_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConfigError("config/gate-artifacts.json is malformed") from error
    expected_keys = {
        "schemaVersion",
        "protocolVersion",
        "gateArtifactVersion",
        "filterSubscriptionUrl",
        "artifact",
    }
    if not isinstance(lock, dict) or set(lock) != expected_keys:
        raise ConfigError("gate artifact lock root has an unexpected schema")
    artifact = lock.get("artifact")
    if not isinstance(artifact, dict) or set(artifact) != {
        "path", "bytes", "sha256", "installedRulesSha256"
    }:
        raise ConfigError("gate artifact lock entry has an unexpected schema")
    expected_entry = {
        "path": "filter.txt",
        "bytes": len(gate_bytes),
        "sha256": sha256_bytes(gate_bytes),
        "installedRulesSha256": installed_filter_rules_sha256(gate_bytes),
    }
    if (
        lock.get("schemaVersion") != 1
        or lock.get("protocolVersion") != int(PROTOCOL_VERSION)
        or lock.get("gateArtifactVersion") != GATE_ARTIFACT_VERSION
        or lock.get("filterSubscriptionUrl") != GATE_FILTER_SUBSCRIPTION_URL
        or artifact != expected_entry
    ):
        raise ConfigError(
            "filter.txt differs from the immutable gate artifact lock; use a new gate version and URL"
        )
    return lock, lock_bytes


def render_materialized_release_manifest(
    config: Mapping[str, Any],
    *,
    gate_bytes: bytes,
    static_bytes: bytes,
    userscript_bytes: bytes,
    config_bytes: bytes,
    package_bytes: bytes,
    package_lock_bytes: bytes,
    approved_state_bytes: bytes | None = None,
) -> bytes:
    validated_config = validate_config(copy.deepcopy(config))
    gate_lock, gate_lock_bytes = validate_gate_artifact_lock(gate_bytes)
    fixture_bytes = {path: read_required_bytes(path) for path in FIXTURE_PATHS}
    release_version = validated_config["metadata"]["version"]
    try:
        package_version = json.loads(package_bytes.decode("utf-8"))["version"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise ConfigError("package.json must contain a valid version") from error
    try:
        package_lock = json.loads(package_lock_bytes.decode("utf-8"))
        package_lock_versions = {
            package_lock["version"], package_lock["packages"][""]["version"]
        }
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise ConfigError("package-lock.json must contain root versions") from error
    if userscript_version(userscript_bytes) != release_version:
        raise ConfigError("userscript @version must equal config.metadata.version")
    if package_version != release_version:
        raise ConfigError("package.json version must equal config.metadata.version")
    if package_lock_versions != {release_version}:
        raise ConfigError("package-lock.json versions must equal config.metadata.version")
    if filter_version(gate_bytes, "filter.txt") != GATE_ARTIFACT_VERSION:
        raise ConfigError("filter.txt Version must equal the stable gate artifact version")
    if filter_version(static_bytes, "filter-static.txt") != release_version:
        raise ConfigError("filter-static.txt Version must equal config.metadata.version")
    validate_userscript_release_metadata(userscript_bytes)

    content_by_path = {
        relative_path(GATE_FILTER_PATH): gate_bytes,
        relative_path(STATIC_FILTER_PATH): static_bytes,
        relative_path(USERSCRIPT_PATH): userscript_bytes,
        relative_path(DEFAULT_CONFIG_PATH): config_bytes,
        relative_path(PACKAGE_PATH): package_bytes,
        relative_path(PACKAGE_LOCK_PATH): package_lock_bytes,
        relative_path(GATE_ARTIFACT_LOCK_PATH): gate_lock_bytes,
    }
    content_by_path.update(
        {relative_path(path): content for path, content in fixture_bytes.items()}
    )
    approved_variants: list[Mapping[str, Any]] = []
    if approved_state_bytes is not None:
        try:
            approved_state = json.loads(approved_state_bytes.decode("utf-8"))
            approved_variants = approved_state["variants"]
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise ConfigError("approved variant state is malformed") from error
        if approved_state.get("schemaVersion") != 1 or not isinstance(approved_variants, list):
            raise ConfigError("approved variant state must use schemaVersion 1")
        content_by_path[relative_path(APPROVED_STATE_PATH)] = approved_state_bytes
    config_variant_contracts = _config_variant_contracts(validated_config)
    state_variant_contracts = _state_variant_contracts(approved_variants)
    if config_variant_contracts != state_variant_contracts:
        missing_state = sorted(set(config_variant_contracts) - set(state_variant_contracts))
        extra_state = sorted(set(state_variant_contracts) - set(config_variant_contracts))
        mismatched = sorted(
            key
            for key in set(config_variant_contracts) & set(state_variant_contracts)
            if config_variant_contracts[key] != state_variant_contracts[key]
        )
        raise ConfigError(
            "materialized config variants and approved state must match exactly "
            f"(missing={missing_state}, extra={extra_state}, mismatched={mismatched})"
        )
    public_paths = {relative_path(GATE_FILTER_PATH), relative_path(USERSCRIPT_PATH)}
    artifacts = {
        path: public_artifact_entry(path, content_by_path[path])
        for path in sorted(public_paths)
    }
    source_integrity = {
        path: artifact_entry(content)
        for path, content in sorted(content_by_path.items())
        if path not in public_paths
    }
    coverage = coverage_manifest(validated_config)
    coverage["approvedVariantCount"] = len(approved_variants)
    promotion = None
    if approved_variants:
        latest = max(
            approved_variants,
            key=lambda record: semantic_version_core(record["releaseVersion"]),
        )
        if latest.get("releaseVersion") != release_version:
            raise ConfigError("latest approved state release must equal the materialized release")
        promotion = {
            "candidateSha256": latest.get("candidateSha256"),
            "evidenceSha256": latest.get("evidenceSha256"),
            "draftArtifactSetSha256": latest.get("draftArtifactSetSha256"),
        }
        if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in promotion.values()):
            raise ConfigError("latest approved state promotion hashes are invalid")
    manifest = {
        "schemaVersion": 1,
        "status": "release-ready",
        "releaseVersion": release_version,
        "protocolVersion": int(PROTOCOL_VERSION),
        "gateArtifactVersion": gate_lock["gateArtifactVersion"],
        "filterSubscriptionUrl": gate_lock["filterSubscriptionUrl"],
        "generatorVersion": GENERATOR_VERSION,
        "rollback_of": validated_config["metadata"]["rollback_of"],
        "configSha256": source_integrity[relative_path(DEFAULT_CONFIG_PATH)]["sha256"],
        "coverage": coverage,
        "promotion": promotion,
        "artifacts": artifacts,
        "sourceIntegrity": source_integrity,
    }
    return (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def render_release() -> tuple[dict[str, bytes], bytes]:
    config_bytes = read_required_bytes(DEFAULT_CONFIG_PATH)
    try:
        raw_config = json.loads(config_bytes.decode("utf-8"))
    except json.JSONDecodeError as error:
        raise ConfigError("config/sites.json is malformed") from error
    config = load_config(DEFAULT_CONFIG_PATH)
    gate_bytes = render_gate_filter(config).encode("utf-8")
    static_bytes = render_filter(config).encode("utf-8")
    userscript_bytes = read_required_bytes(USERSCRIPT_PATH)
    package_bytes = read_required_bytes(PACKAGE_PATH)
    package_lock_bytes = read_required_bytes(PACKAGE_LOCK_PATH)
    approved_state_bytes = (
        APPROVED_STATE_PATH.read_bytes() if APPROVED_STATE_PATH.exists() else None
    )
    manifest_bytes = render_materialized_release_manifest(
        raw_config,
        gate_bytes=gate_bytes,
        static_bytes=static_bytes,
        userscript_bytes=userscript_bytes,
        config_bytes=config_bytes,
        package_bytes=package_bytes,
        package_lock_bytes=package_lock_bytes,
        approved_state_bytes=approved_state_bytes,
    )
    generated = {
        relative_path(GATE_FILTER_PATH): gate_bytes,
        relative_path(STATIC_FILTER_PATH): static_bytes,
    }
    return generated, manifest_bytes


def load_existing_manifest() -> Mapping[str, Any] | None:
    try:
        value = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as error:
        raise ConfigError("existing release-manifest.json is malformed") from error
    if not isinstance(value, dict):
        raise ConfigError("existing release-manifest.json must be an object")
    return value


def enforce_monotonic_release(manifest_bytes: bytes, check_only: bool) -> None:
    existing = load_existing_manifest()
    if not existing:
        return
    proposed = json.loads(manifest_bytes)
    existing_version = existing.get("releaseVersion")
    proposed_version = proposed["releaseVersion"]
    if not isinstance(existing_version, str):
        raise ConfigError("existing manifest has no releaseVersion")
    existing_core = semantic_version_core(existing_version)
    proposed_core = semantic_version_core(proposed_version)
    existing_gate_version = existing.get("gateArtifactVersion")
    proposed_gate_version = proposed.get("gateArtifactVersion")
    if isinstance(existing_gate_version, str):
        if not isinstance(proposed_gate_version, str):
            raise ConfigError("proposed manifest has no gateArtifactVersion")
        existing_gate_core = semantic_version_core(existing_gate_version)
        proposed_gate_core = semantic_version_core(proposed_gate_version)
        if proposed_gate_core < existing_gate_core:
            raise ConfigError("gate artifact version downgrade is forbidden")
        if proposed_gate_core == existing_gate_core:
            stable_gate_fields = (
                "protocolVersion",
                "gateArtifactVersion",
                "filterSubscriptionUrl",
            )
            if any(existing.get(key) != proposed.get(key) for key in stable_gate_fields) or (
                existing.get("artifacts", {}).get("filter.txt")
                != proposed.get("artifacts", {}).get("filter.txt")
            ):
                raise ConfigError(
                    "an existing gate artifact version is immutable; bump its version and URL"
                )
    if proposed_core < existing_core:
        raise ConfigError("release version downgrade is forbidden")
    if proposed_core == existing_core and existing != proposed and not check_only:
        raise ConfigError(
            "release bytes changed without a version bump; rollback also requires a higher version"
        )


def expected_outputs() -> dict[Path, bytes]:
    generated, manifest_bytes = render_release()
    enforce_monotonic_release(manifest_bytes, check_only=True)
    outputs = {PROJECT_ROOT / path: content for path, content in generated.items()}
    outputs[MANIFEST_PATH] = manifest_bytes
    return outputs


def check_outputs(outputs: Mapping[Path, bytes]) -> bool:
    return all(path.exists() and path.read_bytes() == content for path, content in outputs.items())


def write_outputs_atomically(outputs: Mapping[Path, bytes]) -> None:
    manifest_bytes = outputs[MANIFEST_PATH]
    enforce_monotonic_release(manifest_bytes, check_only=False)
    with tempfile.TemporaryDirectory(prefix=".release-build-", dir=PROJECT_ROOT) as temporary:
        temporary_root = Path(temporary)
        staged: list[tuple[Path, Path]] = []
        for target, content in outputs.items():
            staged_path = temporary_root / target.name
            staged_path.write_bytes(content)
            staged.append((staged_path, target))
        for staged_path, target in staged:
            os.replace(staged_path, target)


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the complete immutable release set.")
    parser.add_argument("--check", action="store_true")
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    options = parse_arguments(arguments)
    try:
        outputs = expected_outputs()
        if options.check:
            if check_outputs(outputs):
                print("release artifacts are byte-identical and current")
                return 0
            print("release artifacts are missing or stale", file=sys.stderr)
            return 1
        write_outputs_atomically(outputs)
    except ConfigError as error:
        print(f"release error: {error}", file=sys.stderr)
        return 2
    print("built filter.txt, filter-static.txt, and release-manifest.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
