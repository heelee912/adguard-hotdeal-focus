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
STATIC_FILTER_PATH = PROJECT_ROOT / "filter-static.txt"
USERSCRIPT_PATH = PROJECT_ROOT / "hotdeal-focus.user.js"
PACKAGE_PATH = PROJECT_ROOT / "package.json"
PACKAGE_LOCK_PATH = PROJECT_ROOT / "package-lock.json"
MANIFEST_PATH = PROJECT_ROOT / "release-manifest.json"
APPROVED_STATE_PATH = PROJECT_ROOT / "state" / "approved-variants.json"
HIGH_WATER_PATH = PROJECT_ROOT / "state" / "release-high-water.json"
FIXTURE_PATHS = (
    PROJECT_ROOT / "tests" / "fixtures" / "dom-regressions.json",
    PROJECT_ROOT / "tests" / "fixtures" / "behavior-baseline.json",
)
USERSCRIPT_VERSION_PATTERN = re.compile(r"^//\s*@version\s+([^\s]+)\s*$", re.MULTILINE)
FILTER_VERSION_PATTERN = re.compile(r"^! Version:\s+([^\s]+)\s*$", re.MULTILINE)
STABLE_SEMANTIC_VERSION_PATTERN = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
READER_PROTOCOL_VERSION = 2
HIGH_WATER_SCHEMA_VERSION = 1
PUBLIC_BUNDLE_FORMAT = "hdf-public-bundle-v1"
HIGH_WATER_PREFIX_MODE = "append-only-prefix-v1"
RELEASE_USERSCRIPT_URL = (
    "https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js"
)
RELEASE_USERSCRIPT_NAME = "AdGuard Hotdeal Focus Reader Gate"
RELEASE_USERSCRIPT_NAMESPACE = (
    "https://github.com/heelee912/adguard-hotdeal-focus"
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


def relative_path(path: Path) -> str:
    return path.relative_to(PROJECT_ROOT).as_posix()


def semantic_version_core(version: str) -> tuple[int, int, int]:
    match = STABLE_SEMANTIC_VERSION_PATTERN.fullmatch(version)
    if not match:
        raise ConfigError(f"invalid stable release version: {version}")
    try:
        major, minor, patch = (int(part) for part in match.groups())
    except (TypeError, ValueError) as error:
        raise ConfigError(f"invalid release version: {version}") from error
    return major, minor, patch


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def high_water_document(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "bundleFormat": PUBLIC_BUNDLE_FORMAT,
        "records": list(records),
        "schemaVersion": HIGH_WATER_SCHEMA_VERSION,
    }


def render_high_water_bytes(records: Sequence[Mapping[str, Any]]) -> bytes:
    return (
        json.dumps(
            high_water_document(records),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _exact_keys(value: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ConfigError(f"{label} fields are not exact")
    return value


def _positive_byte_count(value: Any, label: str) -> int:
    if type(value) is not int or value < 1:
        raise ConfigError(f"{label} must be a positive integer")
    return value


def _sha256_value(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ConfigError(f"{label} must be a lowercase SHA-256 digest")
    return value


def validate_high_water_records(
    records: Any,
    *,
    allow_empty: bool = False,
) -> list[Mapping[str, Any]]:
    if not isinstance(records, list) or (not allow_empty and not records):
        raise ConfigError("release high-water records must be a non-empty list")
    validated: list[Mapping[str, Any]] = []
    for index, raw_record in enumerate(records):
        record = _exact_keys(
            raw_record,
            {"bundleSha256", "manifest", "releaseVersion", "userscript"},
            f"release high-water record {index}",
        )
        version = record["releaseVersion"]
        if not isinstance(version, str):
            raise ConfigError(f"release high-water record {index} has no releaseVersion")
        semantic_version_core(version)
        _sha256_value(record["bundleSha256"], f"release high-water record {index} bundle")
        manifest = _exact_keys(
            record["manifest"],
            {"bytes", "sha256"},
            f"release high-water record {index} manifest",
        )
        _positive_byte_count(manifest["bytes"], f"release high-water record {index} manifest bytes")
        _sha256_value(manifest["sha256"], f"release high-water record {index} manifest")
        userscript = _exact_keys(
            record["userscript"],
            {"bytes", "canonicalTextSha256", "sha256"},
            f"release high-water record {index} userscript",
        )
        _positive_byte_count(
            userscript["bytes"],
            f"release high-water record {index} userscript bytes",
        )
        _sha256_value(
            userscript["sha256"],
            f"release high-water record {index} userscript",
        )
        _sha256_value(
            userscript["canonicalTextSha256"],
            f"release high-water record {index} userscript canonical text",
        )
        if validated and semantic_version_core(version) <= semantic_version_core(
            str(validated[-1]["releaseVersion"])
        ):
            raise ConfigError("release high-water versions must be strictly increasing")
        validated.append(copy.deepcopy(record))
    return validated


def parse_high_water_bytes(content: bytes | None) -> list[Mapping[str, Any]]:
    if content is None:
        return []
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConfigError("release high-water must be strict UTF-8 JSON") from error
    root = _exact_keys(
        value,
        {"bundleFormat", "records", "schemaVersion"},
        "release high-water",
    )
    if (
        root["schemaVersion"] != HIGH_WATER_SCHEMA_VERSION
        or root["bundleFormat"] != PUBLIC_BUNDLE_FORMAT
    ):
        raise ConfigError("release high-water schema is not exact")
    return validate_high_water_records(root["records"])


def high_water_prefix_entry(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    prefix_bytes = canonical_json_bytes(high_water_document(records))
    return {
        "bytes": len(prefix_bytes),
        "mode": HIGH_WATER_PREFIX_MODE,
        "recordCount": len(records),
        "sha256": sha256_bytes(prefix_bytes),
    }


def public_bundle_sha256(manifest_bytes: bytes, userscript_bytes: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(f"{PUBLIC_BUNDLE_FORMAT}\0".encode("ascii"))
    for name, content in (
        ("release-manifest.json", manifest_bytes),
        ("hotdeal-focus.user.js", userscript_bytes),
    ):
        name_bytes = name.encode("utf-8")
        digest.update(len(name_bytes).to_bytes(4, "big"))
        digest.update(name_bytes)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def release_high_water_record(
    release_version: str,
    manifest_bytes: bytes,
    userscript_bytes: bytes,
) -> dict[str, Any]:
    return {
        "bundleSha256": public_bundle_sha256(manifest_bytes, userscript_bytes),
        "manifest": {
            "bytes": len(manifest_bytes),
            "sha256": sha256_bytes(manifest_bytes),
        },
        "releaseVersion": release_version,
        "userscript": {
            "bytes": len(userscript_bytes),
            "canonicalTextSha256": canonical_text_sha256(userscript_bytes),
            "sha256": sha256_bytes(userscript_bytes),
        },
    }


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
            raise ConfigError(f"userscript @{key} must use the exact GitHub Pages URL")
    exact_metadata = {
        "name": RELEASE_USERSCRIPT_NAME,
        "namespace": RELEASE_USERSCRIPT_NAMESPACE,
        "run-at": "document-start",
    }
    for key, expected in exact_metadata.items():
        values = re.findall(rf"^//\s*@{re.escape(key)}\s+(.+?)\s*$", source, re.MULTILINE)
        if values != [expected]:
            raise ConfigError(f"userscript @{key} must be exactly {expected}")
    grants = re.findall(r"^//\s*@grant\s+(.+?)\s*$", source, re.MULTILINE)
    if grants != [
        "GM_addElement",
        "GM_getValue",
        "GM_setValue",
        "GM_deleteValue",
        "window.onurlchange",
    ]:
        raise ConfigError("userscript grants must be the exact standalone contract")
    for forbidden_key in ("connect", "require", "resource"):
        if re.search(rf"^//\s*@{forbidden_key}\s+", source, re.MULTILINE):
            raise ConfigError(f"userscript @{forbidden_key} is forbidden in the standalone release")


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
    return entry


def render_materialized_release_set(
    config: Mapping[str, Any] | None = None,
    *,
    static_bytes: bytes,
    userscript_bytes: bytes,
    config_bytes: bytes,
    package_bytes: bytes,
    package_lock_bytes: bytes,
    approved_state_bytes: bytes | None = None,
    high_water_bytes: bytes | None = None,
) -> tuple[bytes, bytes]:
    try:
        raw_config = json.loads(config_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConfigError("config/sites.json must be strict UTF-8 JSON") from error
    if not isinstance(raw_config, Mapping):
        raise ConfigError("config/sites.json root must be an object")
    validated_config = validate_config(copy.deepcopy(raw_config))
    if config is not None:
        # Validate the caller-supplied mapping first so malformed candidate
        # identities retain their precise fail-closed diagnostic. A different
        # but valid mapping is still rejected before materialization.
        validate_config(copy.deepcopy(config))
        if config != raw_config:
            raise ConfigError("config mapping must match config_bytes exactly")
    fixture_bytes = {path: read_required_bytes(path) for path in FIXTURE_PATHS}
    release_version = validated_config["metadata"]["version"]
    semantic_version_core(release_version)
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
    if filter_version(static_bytes, "filter-static.txt") != release_version:
        raise ConfigError("filter-static.txt Version must equal config.metadata.version")
    validate_userscript_release_metadata(userscript_bytes)

    content_by_path = {
        relative_path(STATIC_FILTER_PATH): static_bytes,
        relative_path(USERSCRIPT_PATH): userscript_bytes,
        relative_path(DEFAULT_CONFIG_PATH): config_bytes,
        relative_path(PACKAGE_PATH): package_bytes,
        relative_path(PACKAGE_LOCK_PATH): package_lock_bytes,
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
    public_paths = {relative_path(USERSCRIPT_PATH)}
    artifacts = {
        path: public_artifact_entry(path, content_by_path[path])
        for path in sorted(public_paths)
    }
    source_integrity = {
        path: artifact_entry(content)
        for path, content in sorted(content_by_path.items())
        if path not in public_paths
    }
    high_water_records = parse_high_water_bytes(high_water_bytes)
    if high_water_records:
        current_version = str(high_water_records[-1]["releaseVersion"])
        comparison = (
            semantic_version_core(release_version)
            > semantic_version_core(current_version)
        ) - (
            semantic_version_core(release_version)
            < semantic_version_core(current_version)
        )
        if comparison < 0:
            raise ConfigError("release version is below the durable high-water floor")
        prefix_records = high_water_records[:-1] if comparison == 0 else high_water_records
    else:
        comparison = 1
        prefix_records = []
    source_integrity[relative_path(HIGH_WATER_PATH)] = high_water_prefix_entry(
        prefix_records
    )
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
        "schemaVersion": 2,
        "status": "release-ready",
        "releaseVersion": release_version,
        "protocolVersion": READER_PROTOCOL_VERSION,
        "installUrl": RELEASE_USERSCRIPT_URL,
        "generatorVersion": release_version,
        "rollback_of": validated_config["metadata"]["rollback_of"],
        "configSha256": source_integrity[relative_path(DEFAULT_CONFIG_PATH)]["sha256"],
        "coverage": coverage,
        "promotion": promotion,
        "artifacts": artifacts,
        "sourceIntegrity": source_integrity,
    }
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    current_record = release_high_water_record(
        release_version,
        manifest_bytes,
        userscript_bytes,
    )
    if comparison == 0:
        if high_water_records[-1] != current_record:
            raise ConfigError(
                "same-version public bundle differs from the durable high-water record"
            )
        materialized_records = high_water_records
    else:
        materialized_records = [*high_water_records, current_record]
    return manifest_bytes, render_high_water_bytes(materialized_records)


def render_materialized_release_manifest(
    config: Mapping[str, Any] | None = None,
    *,
    static_bytes: bytes,
    userscript_bytes: bytes,
    config_bytes: bytes,
    package_bytes: bytes,
    package_lock_bytes: bytes,
    approved_state_bytes: bytes | None = None,
    high_water_bytes: bytes | None = None,
) -> bytes:
    manifest_bytes, _ = render_materialized_release_set(
        config,
        static_bytes=static_bytes,
        userscript_bytes=userscript_bytes,
        config_bytes=config_bytes,
        package_bytes=package_bytes,
        package_lock_bytes=package_lock_bytes,
        approved_state_bytes=approved_state_bytes,
        high_water_bytes=high_water_bytes,
    )
    return manifest_bytes


def render_release() -> tuple[dict[str, bytes], bytes]:
    config_bytes = read_required_bytes(DEFAULT_CONFIG_PATH)
    try:
        raw_config = json.loads(config_bytes.decode("utf-8"))
    except json.JSONDecodeError as error:
        raise ConfigError("config/sites.json is malformed") from error
    config = load_config(DEFAULT_CONFIG_PATH)
    static_bytes = render_filter(config).encode("utf-8")
    userscript_bytes = read_required_bytes(USERSCRIPT_PATH)
    package_bytes = read_required_bytes(PACKAGE_PATH)
    package_lock_bytes = read_required_bytes(PACKAGE_LOCK_PATH)
    approved_state_bytes = (
        APPROVED_STATE_PATH.read_bytes() if APPROVED_STATE_PATH.exists() else None
    )
    existing_high_water_bytes = (
        HIGH_WATER_PATH.read_bytes() if HIGH_WATER_PATH.exists() else None
    )
    manifest_bytes, materialized_high_water_bytes = render_materialized_release_set(
        raw_config,
        static_bytes=static_bytes,
        userscript_bytes=userscript_bytes,
        config_bytes=config_bytes,
        package_bytes=package_bytes,
        package_lock_bytes=package_lock_bytes,
        approved_state_bytes=approved_state_bytes,
        high_water_bytes=existing_high_water_bytes,
    )
    generated = {
        relative_path(STATIC_FILTER_PATH): static_bytes,
        relative_path(HIGH_WATER_PATH): materialized_high_water_bytes,
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
    if proposed_core < existing_core:
        raise ConfigError("release version downgrade is forbidden")
    if proposed_core == existing_core and existing != proposed and not check_only:
        existing_sources = existing.get("sourceIntegrity")
        one_time_high_water_bootstrap = (
            not HIGH_WATER_PATH.exists()
            and isinstance(existing_sources, Mapping)
            and relative_path(HIGH_WATER_PATH) not in existing_sources
            and relative_path(HIGH_WATER_PATH) in proposed.get("sourceIntegrity", {})
        )
        if one_time_high_water_bootstrap:
            return
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
    print(
        "built filter-static.txt, release high-water, and standalone userscript "
        "release-manifest.json"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
