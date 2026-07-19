#!/usr/bin/env python3
"""Validate the site allowlist and build a deterministic AdGuard filter."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "sites.json"
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "dist" / "filter-static.txt"

_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$"
)
_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_BASE_ROLE_NAMES = frozenset({"title", "body", "comments"})
_ALLOWED_ROLE_NAMES = frozenset({"title", "product", "body", "comments"})
_ALLOWED_PROFILES = frozenset({"desktop", "mobile"})
_ROLE_PROJECTION_TITLE_MODE = "seeded-shallow"
_ROLE_PROJECTION_CONTENT_MODE = "atomic-boundary"
_ROLE_PROJECTION_COMMENTS_MODE = "classified-children"
_PRODUCT_CARDINALITIES = frozenset({"zero", "required", "optional"})
_ALGUMON_CONSISTENCY_THRESHOLD = 0.95
_EVIDENCE_MAX_AGE = timedelta(hours=72)
_EVIDENCE_FUTURE_SKEW = timedelta(minutes=5)
_FORBIDDEN_SELECTOR_FRAGMENTS = (
    "##",
    "#?#",
    "#$#",
    "#$?#",
    "$path=",
    "/*",
    "*/",
)
_CANDIDATE_CONTRACT_START = "/* HOTDEAL_FOCUS_CONTRACTS_START */"
_CANDIDATE_CONTRACT_END = "/* HOTDEAL_FOCUS_CONTRACTS_END */"
_CANDIDATE_PROTOCOL_VERSION = 1


class ConfigError(ValueError):
    """Raised when filter configuration cannot produce a safe rule set."""


def _expect_mapping(value: Any, location: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{location} must be an object")
    return value


def _expect_list(value: Any, location: str) -> list[Any]:
    if not isinstance(value, list):
        raise ConfigError(f"{location} must be an array")
    return value


def _expect_text(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{location} must be a non-empty string")
    if value != value.strip() or "\n" in value or "\r" in value:
        raise ConfigError(f"{location} must be trimmed and single-line")
    return value


def _expect_identifier(value: Any, location: str) -> str:
    identifier = _expect_text(value, location)
    if not _IDENTIFIER_PATTERN.fullmatch(identifier):
        raise ConfigError(
            f"{location} must contain only lowercase letters, digits, '_' or '-'"
        )
    return identifier


def _expect_unique_texts(value: Any, location: str) -> list[str]:
    items = _expect_list(value, location)
    texts = [_expect_text(item, f"{location}[{index}]") for index, item in enumerate(items)]
    duplicates = sorted({item for item in texts if texts.count(item) > 1})
    if duplicates:
        raise ConfigError(f"{location} contains duplicate values: {duplicates}")
    return texts


def _has_top_level_comma(selector: str) -> bool:
    parentheses_depth = 0
    brackets_depth = 0
    quote: str | None = None
    escaped = False

    for character in selector:
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if quote:
            if character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
            continue
        if character == "(":
            parentheses_depth += 1
        elif character == ")":
            parentheses_depth -= 1
            if parentheses_depth < 0:
                raise ConfigError(f"selector has an unmatched ')': {selector}")
        elif character == "[":
            brackets_depth += 1
        elif character == "]":
            brackets_depth -= 1
            if brackets_depth < 0:
                raise ConfigError(f"selector has an unmatched ']': {selector}")
        elif character == "," and parentheses_depth == 0 and brackets_depth == 0:
            return True

    if quote:
        raise ConfigError(f"selector has an unterminated quote: {selector}")
    if parentheses_depth:
        raise ConfigError(f"selector has unbalanced parentheses: {selector}")
    if brackets_depth:
        raise ConfigError(f"selector has unbalanced brackets: {selector}")
    if escaped:
        raise ConfigError(f"selector ends with an escape character: {selector}")
    return False


def validate_selector(selector: Any, location: str) -> str:
    selector_text = _expect_text(selector, location)
    if any(fragment in selector_text for fragment in _FORBIDDEN_SELECTOR_FRAGMENTS):
        raise ConfigError(f"{location} contains filter syntax or a CSS comment")
    if any(ord(character) < 32 for character in selector_text):
        raise ConfigError(f"{location} contains a control character")
    if any(character in selector_text for character in "{};"):
        raise ConfigError(f"{location} contains a declaration delimiter")
    if selector_text in {"*", "body", "html", ":root"}:
        raise ConfigError(f"{location} is too broad for an allowlist marker")
    if selector_text[0] in {">", "+", "~"} or re.search(r"[>+~]\s*$", selector_text):
        raise ConfigError(f"{location} has a dangling combinator")
    if _has_top_level_comma(selector_text):
        raise ConfigError(
            f"{location} must contain one selector; use separate array entries"
        )
    return selector_text


def validate_domain(domain: Any, location: str) -> str:
    domain_text = _expect_text(domain, location)
    if domain_text != domain_text.lower() or not _DOMAIN_PATTERN.fullmatch(domain_text):
        raise ConfigError(
            f"{location} must be a lowercase hostname without scheme, port, path or wildcard"
        )
    return domain_text


def validate_path(path: Any, location: str) -> str:
    path_text = _expect_text(path, location)
    if not path_text.startswith("|/"):
        raise ConfigError(f"{location} must start with the AdGuard start anchor '|/'")
    if any(character.isspace() for character in path_text):
        raise ConfigError(f"{location} must not contain whitespace")
    if any(character in path_text for character in "#$\\[]"):
        raise ConfigError(f"{location} contains an unsafe filter delimiter")
    if "|" in path_text[1:]:
        raise ConfigError(f"{location} may contain '|' only as its start anchor")
    if "^" in path_text[:-1] or path_text.count("^") > 1:
        raise ConfigError(f"{location} may contain '^' only as its final separator anchor")
    return path_text


def _path_pattern_matches(url_path_and_query: str, configured_path: str) -> bool:
    requires_separator = configured_path.endswith("^")
    body = configured_path[1:-1] if requires_separator else configured_path[1:]
    pattern = re.escape(body).replace(r"\*", r"[^/?&=]+")
    terminal_wildcard = body.endswith("*")
    wildcard_is_query_token = body.rfind("?") > body.rfind("/")
    if not requires_separator:
        boundary = ""
    elif terminal_wildcard:
        boundary = r"(?:&|$)" if wildcard_is_query_token else r"(?:\?|$)"
    else:
        boundary = r"(?:[^A-Za-z0-9_.%\-]|$)"
    return re.match(f"^{pattern}{boundary}", url_path_and_query) is not None


def validate_sample_url(
    url: Any, domain: str, paths: Sequence[str], location: str
) -> str:
    url_text = _expect_text(url, location)
    parsed = urlsplit(url_text)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not hostname or parsed.username or parsed.password:
        raise ConfigError(f"{location} must be an absolute HTTPS URL without credentials")
    if parsed.port not in {None, 443}:
        raise ConfigError(f"{location} must use the default HTTPS port")
    if hostname != domain and not hostname.endswith(f".{domain}"):
        raise ConfigError(f"{location} is outside the configured domain '{domain}'")
    path_and_query = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    if not any(_path_pattern_matches(path_and_query, path) for path in paths):
        raise ConfigError(
            f"{location} does not contain any configured path pattern: {list(paths)}"
        )
    return url_text


def _validate_selector_list(
    value: Any, location: str, *, allow_empty: bool = False
) -> list[str]:
    selectors = _expect_unique_texts(value, location)
    if not selectors and not allow_empty:
        raise ConfigError(f"{location} must not be empty")
    return [
        validate_selector(selector, f"{location}[{index}]")
        for index, selector in enumerate(selectors)
    ]


def _validate_role_projection(
    value: Any,
    location: str,
    required_groups: Mapping[str, Sequence[str]],
) -> dict[str, Any]:
    projection = _expect_mapping(value, location)
    if set(projection) != {"title", "body", "product", "comments"}:
        raise ConfigError(
            f"{location} must contain title/body/product/comments"
        )
    title = _expect_mapping(projection["title"], f"{location}.title")
    if title != {"mode": _ROLE_PROJECTION_TITLE_MODE}:
        raise ConfigError(f"{location}.title must use seeded-shallow mode")
    comments = _expect_mapping(projection["comments"], f"{location}.comments")
    if comments != {"mode": _ROLE_PROJECTION_COMMENTS_MODE}:
        raise ConfigError(f"{location}.comments must use classified-children mode")
    body = _expect_mapping(projection["body"], f"{location}.body")
    if set(body) != {"mode", "ignored"} or body.get("mode") != _ROLE_PROJECTION_CONTENT_MODE:
        raise ConfigError(f"{location}.body must use atomic-boundary mode with ignored roots")
    body_ignored = sorted(
        _validate_selector_list(
            body.get("ignored"), f"{location}.body.ignored", allow_empty=True
        )
    )
    product = _expect_mapping(projection["product"], f"{location}.product")
    if set(product) != {"mode", "cardinality", "selectors", "ignored"}:
        raise ConfigError(f"{location}.product fields are invalid")
    product_mode = _expect_text(product.get("mode"), f"{location}.product.mode")
    product_cardinality = _expect_text(
        product.get("cardinality"), f"{location}.product.cardinality"
    )
    if product_cardinality not in _PRODUCT_CARDINALITIES:
        raise ConfigError(f"{location}.product.cardinality is invalid")
    product_selectors = sorted(
        _validate_selector_list(
            product.get("selectors"),
            f"{location}.product.selectors",
            allow_empty=product_cardinality == "zero",
        )
    )
    product_ignored = sorted(
        _validate_selector_list(
            product.get("ignored"),
            f"{location}.product.ignored",
            allow_empty=True,
        )
    )
    has_required_product = "product" in required_groups
    if product_cardinality == "zero":
        if product_mode != "absent" or product_selectors or product_ignored or has_required_product:
            raise ConfigError(f"{location}.product zero cardinality must be absent and empty")
    else:
        if product_mode != _ROLE_PROJECTION_CONTENT_MODE:
            raise ConfigError(f"{location}.product must use atomic-boundary mode")
        if product_cardinality == "required":
            if not has_required_product or product_selectors != sorted(required_groups["product"]):
                raise ConfigError(
                    f"{location}.product required selectors must equal required_groups.product"
                )
        elif has_required_product:
            raise ConfigError(
                f"{location}.product optional cardinality must not be a required role"
            )
    if set(body_ignored) & set(required_groups["body"]):
        raise ConfigError(f"{location}.body ignored roots overlap the body boundary")
    if set(product_ignored) & set(product_selectors):
        raise ConfigError(f"{location}.product ignored roots overlap the product boundary")
    return {
        "title": {"mode": _ROLE_PROJECTION_TITLE_MODE},
        "body": {"mode": _ROLE_PROJECTION_CONTENT_MODE, "ignored": body_ignored},
        "product": {
            "mode": product_mode,
            "cardinality": product_cardinality,
            "selectors": product_selectors,
            "ignored": product_ignored,
        },
        "comments": {"mode": _ROLE_PROJECTION_COMMENTS_MODE},
    }


def _validate_materialized_variant(
    variant_value: Any,
    location: str,
    *,
    site_id: str,
    layout_id: str,
    domain: str,
    base_profiles: Sequence[str],
    base_required_roles: Sequence[str],
    base_product_cardinality: str,
) -> dict[str, Any]:
    variant = _expect_mapping(variant_value, location)
    raw_keys = {
        "id",
        "page_root",
        "paths",
        "sample_urls",
        "applicable_profiles",
        "proof_profiles",
        "required_roles",
        "required_groups",
        "role_projection",
        "comment_contract",
        "candidate_sha256",
    }
    derived_keys = {"domain", "ancestor_markers", "preserve_deep", "preserve_shallow"}
    variant_keys = frozenset(variant)
    raw_key_set = frozenset(raw_keys)
    normalized_key_set = frozenset(raw_keys | derived_keys)
    normalized_input = variant_keys == normalized_key_set
    if variant_keys not in {raw_key_set, normalized_key_set}:
        raise ConfigError(f"{location} keys must be: {sorted(raw_keys)}")
    variant_id = _expect_identifier(variant["id"], f"{location}.id")
    paths = _expect_unique_texts(variant["paths"], f"{location}.paths")
    if len(paths) != 1:
        raise ConfigError(f"{location}.paths must own exactly one route")
    paths = [validate_path(paths[0], f"{location}.paths[0]")]
    sample_urls = sorted(
        validate_sample_url(url, domain, paths, f"{location}.sample_urls")
        for url in _expect_unique_texts(
            variant["sample_urls"], f"{location}.sample_urls"
        )
    )
    if len(sample_urls) < 3:
        raise ConfigError(f"{location}.sample_urls requires at least three URLs")
    applicable_profiles = sorted(
        _expect_unique_texts(
            variant["applicable_profiles"], f"{location}.applicable_profiles"
        )
    )
    if set(applicable_profiles) != set(base_profiles):
        raise ConfigError(
            f"{location}.applicable_profiles must equal the base runtime profiles"
        )
    proof_profiles = sorted(
        _expect_unique_texts(
            variant["proof_profiles"], f"{location}.proof_profiles"
        )
    )
    if not proof_profiles or not set(proof_profiles) <= set(base_profiles):
        raise ConfigError(f"{location}.proof_profiles is invalid")
    required_roles = sorted(
        _expect_unique_texts(variant["required_roles"], f"{location}.required_roles")
    )
    if set(required_roles) != set(base_required_roles):
        raise ConfigError(f"{location}.required_roles must equal its base layout")
    group_values = _expect_mapping(
        variant["required_groups"], f"{location}.required_groups"
    )
    if set(group_values) != set(required_roles):
        raise ConfigError(f"{location}.required_groups must match required_roles")
    required_groups = {
        role: sorted(
            _validate_selector_list(
                group_values[role], f"{location}.required_groups.{role}"
            )
        )
        for role in required_roles
    }
    role_projection = _validate_role_projection(
        variant["role_projection"], f"{location}.role_projection", required_groups
    )
    if role_projection["product"]["cardinality"] != base_product_cardinality:
        raise ConfigError(
            f"{location}.role_projection.product.cardinality must equal its base layout"
        )
    comment_value = _expect_mapping(
        variant["comment_contract"], f"{location}.comment_contract"
    )
    if set(comment_value) != {"mount", "items", "controls", "ignored", "allow_empty"}:
        raise ConfigError(f"{location}.comment_contract fields are invalid")
    comment_mount = sorted(
        _validate_selector_list(
            comment_value["mount"], f"{location}.comment_contract.mount"
        )
    )
    comment_items = sorted(
        _validate_selector_list(
            comment_value["items"], f"{location}.comment_contract.items"
        )
    )
    comment_controls = sorted(
        _validate_selector_list(
            comment_value["controls"],
            f"{location}.comment_contract.controls",
            allow_empty=True,
        )
    )
    comment_ignored = sorted(
        _validate_selector_list(
            comment_value["ignored"],
            f"{location}.comment_contract.ignored",
            allow_empty=True,
        )
    )
    classified_overlap = (
        (set(comment_items) & set(comment_controls))
        | (set(comment_items) & set(comment_ignored))
        | (set(comment_controls) & set(comment_ignored))
    )
    if classified_overlap:
        raise ConfigError(f"{location}.comment_contract selectors overlap")
    if comment_value["allow_empty"] is not True:
        raise ConfigError(f"{location}.comment_contract.allow_empty must be true")
    if not set(comment_mount) <= set(required_groups["comments"]):
        raise ConfigError(f"{location}.comment mount is outside the comments role")
    shallow = sorted(
        set(required_groups["title"]) | set(required_groups["comments"])
    )
    deep_role_names = ["body"] + (["product"] if "product" in required_groups else [])
    deep = sorted(
        {
            selector
            for role in deep_role_names
            for selector in required_groups[role]
        }
        | set(role_projection["product"]["selectors"])
        | set(comment_items)
        | set(comment_controls)
    )
    if set(shallow) & set(deep):
        raise ConfigError(f"{location} has deep/shallow selector overlap")
    candidate_sha256 = _expect_text(
        variant["candidate_sha256"], f"{location}.candidate_sha256"
    )
    if not _SHA256_PATTERN.fullmatch(candidate_sha256):
        raise ConfigError(f"{location}.candidate_sha256 is invalid")
    normalized = {
        "id": variant_id,
        "domain": domain,
        "paths": paths,
        "applicable_profiles": applicable_profiles,
        "proof_profiles": proof_profiles,
        "page_root": validate_selector(variant["page_root"], f"{location}.page_root"),
        "sample_urls": sample_urls,
        "ancestor_markers": sorted(set(shallow) | set(deep)),
        "preserve_deep": deep,
        "preserve_shallow": shallow,
        "required_roles": required_roles,
        "required_groups": required_groups,
        "role_projection": role_projection,
        "comment_contract": {
            "mount": comment_mount,
            "items": comment_items,
            "controls": comment_controls,
            "ignored": comment_ignored,
            "allow_empty": True,
        },
        "candidate_sha256": candidate_sha256,
    }
    deployment_payload = {
        "siteId": site_id,
        "layoutId": layout_id,
        "variantId": variant_id,
        "pageRoot": normalized["page_root"],
        "paths": normalized["paths"],
        "sampleUrls": normalized["sample_urls"],
        "proofProfiles": normalized["proof_profiles"],
        "requiredRoles": normalized["required_roles"],
        "roles": normalized["required_groups"],
        "roleProjection": normalized["role_projection"],
        "commentItems": normalized["comment_contract"]["items"],
        "commentControls": normalized["comment_contract"]["controls"],
        "commentIgnored": normalized["comment_contract"]["ignored"],
        "allowEmptyComments": True,
    }
    expected_variant_id = _automatic_variant_id(deployment_payload)
    if variant_id != expected_variant_id:
        raise ConfigError(
            f"{location}.id must equal its canonical deployment identity: "
            f"{expected_variant_id}"
        )
    expected_candidate_sha256 = _sha256_bytes(
        _canonical_json_bytes(deployment_payload)
    )
    if candidate_sha256 != expected_candidate_sha256:
        raise ConfigError(f"{location}.candidate_sha256 differs from its canonical payload")
    if normalized_input:
        for key in derived_keys:
            if variant[key] != normalized[key]:
                raise ConfigError(f"{location}.{key} differs from its derived contract")
    return normalized


def _validate_layout(
    layout_value: Any,
    site_location: str,
    seen_targets: set[tuple[str, str]],
    *,
    site_id: str,
) -> dict[str, Any]:
    layout = _expect_mapping(layout_value, site_location)
    layout_id = _expect_identifier(layout.get("id"), f"{site_location}.id")
    location = f"{site_location}[id={layout_id}]"
    domain = validate_domain(layout.get("domain"), f"{location}.domain")
    has_path = "path" in layout
    has_paths = "paths" in layout
    if has_path == has_paths:
        raise ConfigError(f"{location} must contain exactly one of 'path' or 'paths'")
    if has_path:
        paths = [validate_path(layout.get("path"), f"{location}.path")]
    else:
        raw_paths = _expect_unique_texts(layout.get("paths"), f"{location}.paths")
        if not raw_paths:
            raise ConfigError(f"{location}.paths must not be empty")
        paths = [
            validate_path(path, f"{location}.paths[{index}]")
            for index, path in enumerate(raw_paths)
        ]
    for path in paths:
        target = (domain, path)
        if target in seen_targets:
            raise ConfigError(f"duplicate domain/path target: {domain} {path}")
        seen_targets.add(target)

    applicable_profiles = _expect_unique_texts(
        layout.get("applicable_profiles"), f"{location}.applicable_profiles"
    )
    if not applicable_profiles or not set(applicable_profiles) <= _ALLOWED_PROFILES:
        raise ConfigError(
            f"{location}.applicable_profiles must contain desktop and/or mobile"
        )

    page_root = validate_selector(layout.get("page_root"), f"{location}.page_root")

    markers = _validate_selector_list(
        layout.get("ancestor_markers"), f"{location}.ancestor_markers"
    )
    deep = _validate_selector_list(
        layout.get("preserve_deep"),
        f"{location}.preserve_deep",
        allow_empty=True,
    )
    shallow = _validate_selector_list(
        layout.get("preserve_shallow"),
        f"{location}.preserve_shallow",
        allow_empty=True,
    )
    if not deep and not shallow:
        raise ConfigError(f"{location} must preserve at least one selector")
    overlap = sorted(set(deep) & set(shallow))
    if overlap:
        raise ConfigError(f"{location} has deep/shallow overlap: {overlap}")
    missing_markers = sorted((set(deep) | set(shallow)) - set(markers))
    if missing_markers:
        raise ConfigError(
            f"{location} preserve selectors missing from ancestor_markers: {missing_markers}"
        )

    sample_urls = _expect_unique_texts(layout.get("sample_urls"), f"{location}.sample_urls")
    if not sample_urls:
        raise ConfigError(f"{location}.sample_urls must not be empty")
    validated_urls = [
        validate_sample_url(url, domain, paths, f"{location}.sample_urls[{index}]")
        for index, url in enumerate(sample_urls)
    ]

    required_roles = _expect_unique_texts(
        layout.get("required_roles"), f"{location}.required_roles"
    )
    role_names = set(required_roles)
    if not _BASE_ROLE_NAMES <= role_names or not role_names <= _ALLOWED_ROLE_NAMES:
        raise ConfigError(
            f"{location}.required_roles must include title/body/comments and may add product"
        )
    group_values = _expect_mapping(layout.get("required_groups"), f"{location}.required_groups")
    group_names = set(group_values)
    if group_names != role_names:
        raise ConfigError(
            f"{location}.required_groups must match required_roles: {sorted(role_names)}"
        )
    preserved = set(deep) | set(shallow)
    required_groups: dict[str, list[str]] = {}
    for group_name in sorted(role_names):
        group_selectors = _validate_selector_list(
            group_values[group_name], f"{location}.required_groups.{group_name}"
        )
        outside_allowlist = sorted(set(group_selectors) - preserved)
        if outside_allowlist:
            raise ConfigError(
                f"{location}.required_groups.{group_name} is not preserved: "
                f"{outside_allowlist}"
            )
        required_groups[group_name] = sorted(group_selectors)

    role_projection = _validate_role_projection(
        layout.get("role_projection"),
        f"{location}.role_projection",
        required_groups,
    )
    optional_product_selectors = (
        role_projection["product"]["selectors"]
        if role_projection["product"]["cardinality"] == "optional"
        else []
    )
    optional_product_outside_allowlist = sorted(
        set(optional_product_selectors) - preserved
    )
    if optional_product_outside_allowlist:
        raise ConfigError(
            f"{location}.role_projection.product.selectors are not preserved: "
            f"{optional_product_outside_allowlist}"
        )

    comment_value = _expect_mapping(
        layout.get("comment_contract"), f"{location}.comment_contract"
    )
    if set(comment_value) != {"mount", "items", "controls", "ignored", "allow_empty"}:
        raise ConfigError(
            f"{location}.comment_contract must contain mount/items/controls/ignored/allow_empty"
        )
    comment_mount = _validate_selector_list(
        comment_value["mount"], f"{location}.comment_contract.mount"
    )
    comment_items = _validate_selector_list(
        comment_value["items"], f"{location}.comment_contract.items"
    )
    comment_controls = _validate_selector_list(
        comment_value["controls"],
        f"{location}.comment_contract.controls",
        allow_empty=True,
    )
    comment_ignored = _validate_selector_list(
        comment_value["ignored"],
        f"{location}.comment_contract.ignored",
        allow_empty=True,
    )
    classified_overlap = sorted(
        (set(comment_items) & set(comment_controls))
        | (set(comment_items) & set(comment_ignored))
        | (set(comment_controls) & set(comment_ignored))
    )
    if classified_overlap:
        raise ConfigError(
            f"{location}.comment_contract item/control/ignored selectors overlap: {classified_overlap}"
        )
    if comment_value["allow_empty"] is not True:
        raise ConfigError(f"{location}.comment_contract.allow_empty must be true")
    if not set(comment_mount) <= preserved:
        raise ConfigError(f"{location}.comment_contract.mount must be preserved")
    if not set(comment_mount) <= set(required_groups["comments"]):
        raise ConfigError(
            f"{location}.required_groups.comments must contain every comment mount"
        )

    raw_variants = _expect_list(layout.get("variants", []), f"{location}.variants")
    validated_variants = [
        _validate_materialized_variant(
            variant,
            f"{location}.variants[{index}]",
            site_id=site_id,
            layout_id=layout_id,
            domain=domain,
            base_profiles=applicable_profiles,
            base_required_roles=required_roles,
            base_product_cardinality=role_projection["product"]["cardinality"],
        )
        for index, variant in enumerate(raw_variants)
    ]
    variant_ids = [variant["id"] for variant in validated_variants]
    if len(set(variant_ids)) != len(variant_ids) or layout_id in variant_ids:
        raise ConfigError(f"{location}.variants contains a duplicate or base layout id")

    return {
        "id": layout_id,
        "domain": domain,
        "paths": sorted(paths),
        "applicable_profiles": sorted(applicable_profiles),
        "page_root": page_root,
        "sample_urls": sorted(validated_urls),
        "ancestor_markers": sorted(markers),
        "preserve_deep": sorted(deep),
        "preserve_shallow": sorted(shallow),
        "required_roles": sorted(required_roles),
        "required_groups": required_groups,
        "role_projection": role_projection,
        "comment_contract": {
            "mount": sorted(comment_mount),
            "items": sorted(comment_items),
            "controls": sorted(comment_controls),
            "ignored": sorted(comment_ignored),
            "allow_empty": True,
        },
        "variants": sorted(validated_variants, key=lambda item: item["id"]),
    }


def validate_config(config_value: Any) -> dict[str, Any]:
    config = _expect_mapping(config_value, "config")
    if config.get("schema_version") != 1:
        raise ConfigError("config.schema_version must be 1")

    metadata_value = _expect_mapping(config.get("metadata"), "config.metadata")
    title = _expect_text(metadata_value.get("title"), "config.metadata.title")
    description = _expect_text(
        metadata_value.get("description"), "config.metadata.description"
    )
    version = _expect_text(metadata_value.get("version"), "config.metadata.version")
    if not _VERSION_PATTERN.fullmatch(version):
        raise ConfigError("config.metadata.version must be a semantic version")
    expires_hours = metadata_value.get("expires_hours")
    if isinstance(expires_hours, bool) or not isinstance(expires_hours, int):
        raise ConfigError("config.metadata.expires_hours must be an integer")
    if not 1 <= expires_hours <= 168:
        raise ConfigError("config.metadata.expires_hours must be between 1 and 168")
    license_name = _expect_text(metadata_value.get("license"), "config.metadata.license")
    rollback_value = metadata_value.get("rollback_of")
    rollback_of: dict[str, str] | None = None
    if rollback_value is not None:
        rollback_mapping = _expect_mapping(rollback_value, "config.metadata.rollback_of")
        if set(rollback_mapping) != {"version", "sha256"}:
            raise ConfigError("config.metadata.rollback_of must contain version and sha256")
        rollback_version = _expect_text(
            rollback_mapping.get("version"), "config.metadata.rollback_of.version"
        )
        rollback_sha256 = _expect_text(
            rollback_mapping.get("sha256"), "config.metadata.rollback_of.sha256"
        )
        if not _VERSION_PATTERN.fullmatch(rollback_version):
            raise ConfigError("config.metadata.rollback_of.version must be semantic")
        if not _SHA256_PATTERN.fullmatch(rollback_sha256):
            raise ConfigError("config.metadata.rollback_of.sha256 must be lowercase SHA-256")
        current_core = tuple(int(part) for part in version.split("-", 1)[0].split("+", 1)[0].split("."))
        rollback_core = tuple(
            int(part) for part in rollback_version.split("-", 1)[0].split("+", 1)[0].split(".")
        )
        if current_core <= rollback_core:
            raise ConfigError("rollback releases must use a higher version")
        rollback_of = {"version": rollback_version, "sha256": rollback_sha256}

    sites_value = _expect_list(config.get("sites"), "config.sites")
    if not sites_value:
        raise ConfigError("config.sites must not be empty")

    site_ids: set[str] = set()
    seen_targets: set[tuple[str, str]] = set()
    validated_sites: list[dict[str, Any]] = []
    for site_index, site_value in enumerate(sites_value):
        site = _expect_mapping(site_value, f"config.sites[{site_index}]")
        site_id = _expect_identifier(site.get("id"), f"config.sites[{site_index}].id")
        if site_id in site_ids:
            raise ConfigError(f"duplicate site id: {site_id}")
        site_ids.add(site_id)
        site_name = _expect_text(site.get("name"), f"config.sites[{site_index}].name")
        layouts_value = _expect_list(
            site.get("layouts"), f"config.sites[id={site_id}].layouts"
        )
        if not layouts_value:
            raise ConfigError(f"config.sites[id={site_id}].layouts must not be empty")

        layout_ids: set[str] = set()
        validated_layouts: list[dict[str, Any]] = []
        for layout_index, layout_value in enumerate(layouts_value):
            validated_layout = _validate_layout(
                layout_value,
                f"config.sites[id={site_id}].layouts[{layout_index}]",
                seen_targets,
                site_id=site_id,
            )
            layout_id = validated_layout["id"]
            if layout_id in layout_ids:
                raise ConfigError(f"duplicate layout id in '{site_id}': {layout_id}")
            layout_ids.add(layout_id)
            validated_layouts.append(validated_layout)

        validated_sites.append(
            {
                "id": site_id,
                "name": site_name,
                "layouts": sorted(validated_layouts, key=lambda item: item["id"]),
            }
        )

    return {
        "schema_version": 1,
        "metadata": {
            "title": title,
            "description": description,
            "version": version,
            "expires_hours": expires_hours,
            "license": license_name,
            "rollback_of": rollback_of,
        },
        "sites": sorted(validated_sites, key=lambda item: item["id"]),
    }


def load_config(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as config_file:
            value = json.load(config_file)
    except FileNotFoundError as error:
        raise ConfigError(f"config file not found: {path}") from error
    except json.JSONDecodeError as error:
        raise ConfigError(f"invalid JSON in {path}: {error}") from error
    return validate_config(value)


def build_hide_selector(layout: Mapping[str, Any]) -> str:
    """Build the projected ExtendedCSS selector without domain/path wrappers."""
    selector = "body *"
    for marker in sorted(layout["ancestor_markers"]):
        selector += f":not(:has({marker}))"
    for preserved_selector in sorted(layout["preserve_deep"]):
        selector += f":not({preserved_selector}):not({preserved_selector} *)"
    for preserved_selector in sorted(layout["preserve_shallow"]):
        selector += f":not({preserved_selector})"
    return selector


def build_scope_prefix(domain: str, path: str) -> str:
    return f"[$domain={domain},path={path}]#?#"


def build_rule(layout: Mapping[str, Any], path: str | None = None) -> str:
    resolved_path = path or layout.get("path") or layout["paths"][0]
    return f"{build_scope_prefix(layout['domain'], resolved_path)}{build_hide_selector(layout)}"


def _merge_static_contracts(
    contracts: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Create a content-safe union for contracts that own the same exact route.

    Unconditional per-contract rules would intersect their allowlists and could hide
    valid article content during same-route DOM migrations. A single union rule keeps
    every approved content selector; the runtime ownership gate still enforces the
    exact matching contract and hides everything that it did not explicitly own.
    """
    preserve_deep = {
        selector
        for contract in contracts
        for selector in contract["preserve_deep"]
    }
    preserve_shallow = {
        selector
        for contract in contracts
        for selector in contract["preserve_shallow"]
    } - preserve_deep
    return {
        "domain": contracts[0]["domain"],
        "ancestor_markers": sorted(
            {
                selector
                for contract in contracts
                for selector in contract["ancestor_markers"]
            }
        ),
        "preserve_deep": sorted(preserve_deep),
        "preserve_shallow": sorted(preserve_shallow),
    }


def iter_rules(config: Mapping[str, Any]) -> Iterable[tuple[str, str, str]]:
    route_contracts: dict[
        tuple[str, str], list[tuple[str, str, Mapping[str, Any]]]
    ] = {}
    for site in sorted(config["sites"], key=lambda item: item["id"]):
        for layout in sorted(site["layouts"], key=lambda item: item["id"]):
            contracts = [
                (layout["id"], layout),
                *[
                    (f"{layout['id']}--{variant['id']}", variant)
                    for variant in layout.get("variants", [])
                ],
            ]
            for contract_id, contract in contracts:
                paths = contract.get("paths") or [contract["path"]]
                for path_index, path in enumerate(sorted(paths), start=1):
                    label = (
                        contract_id
                        if len(paths) == 1
                        else f"{contract_id} / route-{path_index}"
                    )
                    route_contracts.setdefault((contract["domain"], path), []).append(
                        (site["name"], label, contract)
                    )
    for (domain, path), owners in sorted(route_contracts.items()):
        site_names = " + ".join(sorted({owner[0] for owner in owners}))
        labels = " + ".join(sorted(owner[1] for owner in owners))
        contracts = [owner[2] for owner in owners]
        static_contract = (
            contracts[0] if len(contracts) == 1 else _merge_static_contracts(contracts)
        )
        if static_contract["domain"] != domain:
            raise ConfigError("static route contract domain mismatch")
        yield site_names, labels, build_rule(static_contract, path)


def render_filter(config_value: Any) -> str:
    config = validate_config(copy.deepcopy(config_value))
    metadata = config["metadata"]
    lines = [
        f"! Title: {metadata['title']}",
        f"! Description: {metadata['description']}",
        f"! Version: {metadata['version']}",
        f"! Expires: {metadata['expires_hours']} hours",
        f"! License: {metadata['license']}",
        "! Generated by scripts/build_filter.py. Do not edit this file directly.",
        "!",
    ]

    rules_seen: set[str] = set()
    for site_name, layout_id, rule in iter_rules(config):
        if rule in rules_seen:
            raise ConfigError(f"duplicate generated rule: {rule}")
        rules_seen.add(rule)
        lines.append(f"! {site_name} / {layout_id}")
        lines.append(rule)
    return "\n".join(lines) + "\n"


def write_filter(output_path: Path, rendered_filter: str) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(f"{output_path.name}.tmp")
    temporary_path.write_text(rendered_filter, encoding="utf-8", newline="\n")
    temporary_path.replace(output_path)


def check_filter(output_path: Path, rendered_filter: str) -> bool:
    try:
        current_filter = output_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return False
    return current_filter.replace("\r\n", "\n") == rendered_filter


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _variant_deployment_identity(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "siteId": payload["siteId"],
        "layoutId": payload["layoutId"],
        "paths": sorted(payload["paths"]),
        "pageRoot": payload["pageRoot"],
        "roles": payload["roles"],
        "roleProjection": payload["roleProjection"],
        "commentItems": payload["commentItems"],
        "commentControls": payload["commentControls"],
        "commentIgnored": payload["commentIgnored"],
    }


def _automatic_variant_id(payload: Mapping[str, Any]) -> str:
    digest = _sha256_bytes(_canonical_json_bytes(_variant_deployment_identity(payload)))
    return f"auto-{digest[:24]}"


def _strictly_newer_version(candidate_version: str, current_version: str) -> bool:
    if not _VERSION_PATTERN.fullmatch(candidate_version):
        return False
    candidate_core = tuple(
        int(part)
        for part in candidate_version.split("-", 1)[0].split("+", 1)[0].split(".")
    )
    current_core = tuple(
        int(part)
        for part in current_version.split("-", 1)[0].split("+", 1)[0].split(".")
    )
    return candidate_core > current_core


def _find_raw_layout(config: Mapping[str, Any], site_id: str, layout_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    site = next((item for item in config["sites"] if item.get("id") == site_id), None)
    if not isinstance(site, dict):
        raise ConfigError(f"candidate references unknown site: {site_id}")
    layout = next(
        (item for item in site.get("layouts", []) if item.get("id") == layout_id),
        None,
    )
    if not isinstance(layout, dict):
        raise ConfigError(f"candidate references unknown layout: {site_id}/{layout_id}")
    return site, layout


def _approved_paths_for_layout(layout: Mapping[str, Any]) -> list[str]:
    paths = set(layout.get("paths") or [layout["path"]])
    variants = layout.get("variants", [])
    if not isinstance(variants, list):
        raise ConfigError("base layout variants must be an array")
    for index, variant_value in enumerate(variants):
        variant = _expect_mapping(variant_value, f"base layout variants[{index}]")
        variant_paths = variant.get("paths") or (
            [variant["path"]] if "path" in variant else []
        )
        if not variant_paths:
            raise ConfigError(f"base layout variants[{index}] has no path ownership")
        paths.update(
            validate_path(path, f"base layout variants[{index}].paths")
            for path in variant_paths
        )
    return sorted(paths)


def _validate_candidate_payload(
    envelope: Mapping[str, Any],
    base_config: Mapping[str, Any],
    base_config_bytes: bytes,
    current_version: str,
) -> tuple[dict[str, Any], Mapping[str, Any], str, str]:
    if envelope.get("schemaVersion") != 1:
        raise ConfigError("candidate must use schemaVersion 1")
    if envelope.get("protocolVersion") != _CANDIDATE_PROTOCOL_VERSION:
        raise ConfigError("candidate protocolVersion does not match the reader gate")
    if envelope.get("baseConfigSha256") != _sha256_bytes(base_config_bytes):
        raise ConfigError("candidate baseConfigSha256 does not match config/sites.json")
    release_version = _expect_text(envelope.get("releaseVersion"), "candidate.releaseVersion")
    if not _strictly_newer_version(release_version, current_version):
        raise ConfigError(
            "candidate releaseVersion must be higher than the base and approved-state releases"
        )

    payload = _expect_mapping(envelope.get("candidate"), "candidate.candidate")
    payload_keys = {
        "siteId",
        "layoutId",
        "variantId",
        "pageRoot",
        "paths",
        "sampleUrls",
        "proofProfiles",
        "requiredRoles",
        "roles",
        "roleProjection",
        "commentItems",
        "commentControls",
        "commentIgnored",
        "allowEmptyComments",
    }
    if set(payload) != payload_keys:
        raise ConfigError(f"candidate payload keys must be: {sorted(payload_keys)}")
    site_id = _expect_identifier(payload["siteId"], "candidate.siteId")
    layout_id = _expect_identifier(payload["layoutId"], "candidate.layoutId")
    variant_id = _expect_identifier(payload["variantId"], "candidate.variantId")
    _site, base_layout = _find_raw_layout(base_config, site_id, layout_id)
    existing_variant_ids = {
        variant.get("id")
        for variant in base_layout.get("variants", [])
        if isinstance(variant, dict)
    }
    if variant_id in existing_variant_ids or variant_id == layout_id:
        raise ConfigError(f"candidate variantId already exists: {variant_id}")
    page_root = validate_selector(payload["pageRoot"], "candidate.pageRoot")
    paths = _expect_unique_texts(payload["paths"], "candidate.paths")
    if len(paths) != 1:
        raise ConfigError("candidate.paths must own exactly one proven route")
    paths = [validate_path(path, f"candidate.paths[{index}]") for index, path in enumerate(paths)]
    approved_paths = set(_approved_paths_for_layout(base_layout))
    approved_target_paths = set(paths) & approved_paths
    additive_paths = set(paths) - approved_paths
    if approved_target_paths and additive_paths:
        raise ConfigError(
            "candidate.paths must target either approved routes or additive routes, never both"
        )
    samples = _expect_unique_texts(payload["sampleUrls"], "candidate.sampleUrls")
    if len(samples) < 3:
        raise ConfigError("candidate.sampleUrls must contain at least three distinct target URLs")
    samples = [
        validate_sample_url(
            sample,
            base_layout["domain"],
            paths,
            f"candidate.sampleUrls[{index}]",
        )
        for index, sample in enumerate(samples)
    ]
    proof_profiles = _expect_unique_texts(
        payload["proofProfiles"], "candidate.proofProfiles"
    )
    if (
        not proof_profiles
        or not set(proof_profiles) <= set(base_layout["applicable_profiles"])
    ):
        raise ConfigError(
            "candidate proofProfiles must be a non-empty subset of the base layout profiles"
        )
    required_roles = _expect_unique_texts(payload["requiredRoles"], "candidate.requiredRoles")
    role_names = set(required_roles)
    if not _BASE_ROLE_NAMES <= role_names or not role_names <= _ALLOWED_ROLE_NAMES:
        raise ConfigError("candidate requiredRoles must include title/body/comments and may add product")
    if role_names != set(base_layout["required_roles"]):
        raise ConfigError("candidate requiredRoles must equal the base layout roles")
    roles_value = _expect_mapping(payload["roles"], "candidate.roles")
    if set(roles_value) != role_names:
        raise ConfigError("candidate roles must exactly match requiredRoles")
    roles = {
        role: sorted(_validate_selector_list(roles_value[role], f"candidate.roles.{role}"))
        for role in sorted(role_names)
    }
    role_projection = _validate_role_projection(
        payload["roleProjection"], "candidate.roleProjection", roles
    )
    base_product_cardinality = _expect_mapping(
        _expect_mapping(
            base_layout.get("role_projection"), "base role_projection"
        ).get("product"),
        "base role_projection.product",
    ).get("cardinality")
    if role_projection["product"]["cardinality"] != base_product_cardinality:
        raise ConfigError(
            "candidate roleProjection.product.cardinality must equal the base layout"
        )
    comment_items = sorted(
        _validate_selector_list(payload["commentItems"], "candidate.commentItems")
    )
    comment_controls = sorted(
        _validate_selector_list(
            payload["commentControls"],
            "candidate.commentControls",
            allow_empty=True,
        )
    )
    comment_ignored = sorted(
        _validate_selector_list(
            payload["commentIgnored"],
            "candidate.commentIgnored",
            allow_empty=True,
        )
    )
    classified_overlap = sorted(
        (set(comment_items) & set(comment_controls))
        | (set(comment_items) & set(comment_ignored))
        | (set(comment_controls) & set(comment_ignored))
    )
    if classified_overlap:
        raise ConfigError(
            f"candidate comment item/control/ignored selectors overlap: {classified_overlap}"
        )
    if payload["allowEmptyComments"] is not True:
        raise ConfigError("candidate.allowEmptyComments must be true")

    normalized_payload = {
        "siteId": site_id,
        "layoutId": layout_id,
        "variantId": variant_id,
        "pageRoot": page_root,
        "paths": sorted(paths),
        "sampleUrls": sorted(samples),
        "proofProfiles": sorted(proof_profiles),
        "requiredRoles": sorted(required_roles),
        "roles": roles,
        "roleProjection": role_projection,
        "commentItems": comment_items,
        "commentControls": comment_controls,
        "commentIgnored": comment_ignored,
        "allowEmptyComments": True,
    }
    expected_variant_id = _automatic_variant_id(normalized_payload)
    if variant_id != expected_variant_id:
        raise ConfigError(
            f"candidate.variantId must equal its canonical deployment identity: "
            f"{expected_variant_id}"
        )
    expected_candidate_hash = _sha256_bytes(_canonical_json_bytes(normalized_payload))
    return normalized_payload, base_layout, release_version, expected_candidate_hash


def _expect_exact_integer(value: Any, expected: int, location: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value != expected:
        raise ConfigError(f"{location} must be the integer {expected}")
    return value


def _expect_nonnegative_integer(value: Any, location: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConfigError(f"{location} must be a nonnegative integer")
    return value


def _expect_score(value: Any, location: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{location} must be a numeric score")
    score = float(value)
    if not 0.0 <= score <= 1.0:
        raise ConfigError(f"{location} must be between 0 and 1")
    return score


def _validate_recent_timestamp(value: Any, location: str) -> str:
    timestamp = _expect_text(value, location)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", timestamp):
        raise ConfigError(f"{location} must be canonical UTC RFC3339 seconds")
    captured = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if captured < now - _EVIDENCE_MAX_AGE or captured > now + _EVIDENCE_FUTURE_SKEW:
        raise ConfigError(f"{location} is stale or unreasonably in the future")
    return timestamp


def _validate_absolute_https_url(value: Any, location: str) -> str:
    url = _expect_text(value, location)
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.port is not None
        or parsed.fragment
    ):
        raise ConfigError(
            f"{location} must be an absolute HTTPS URL without credentials, port or fragment"
        )
    return url


def _derive_single_segment_path_pattern(final_urls: Sequence[str], location: str) -> str:
    path_queries = []
    for url in final_urls:
        parsed = urlsplit(url)
        path_queries.append(parsed.path + (f"?{parsed.query}" if parsed.query else ""))
    tokenized = [re.split(r"([/?&=])", value) for value in path_queries]
    if not tokenized or any(len(tokens) != len(tokenized[0]) for tokens in tokenized):
        raise ConfigError(f"{location} target URLs do not share one delimited route shape")
    output: list[str] = []
    varying_segments = 0
    for index, column in enumerate(zip(*tokenized)):
        if len(set(column)) == 1:
            output.append(column[0])
        elif index % 2 == 0 and all(column) and len(set(column)) == len(column):
            if index + 1 < len(tokenized[0]) and tokenized[0][index + 1] == "=":
                raise ConfigError(f"{location} may not wildcard a query parameter name")
            output.append("*")
            varying_segments += 1
        else:
            raise ConfigError(f"{location} differs outside one whole delimited segment")
    pattern = "|" + "".join(output) + "^"
    if varying_segments != 1:
        raise ConfigError(f"{location} must vary exactly one whole deal-id segment")
    literal_prefix = pattern.split("*", 1)[0]
    anchored_route = pattern[1:-1]
    path_component = anchored_route.split("?", 1)[0]
    query_value_wildcard = "?" in anchored_route and "*" not in path_component
    if (
        pattern in {"|/^", "|/*^", "|/**^"}
        or "**" in pattern
        or len(pattern) < 9
        or (
            pattern.count("/") < 2
            and not (
                query_value_wildcard
                and re.fullmatch(r"/[A-Za-z0-9][A-Za-z0-9._~-]+", path_component)
            )
        )
        or not re.search(r"[A-Za-z]{2,}", literal_prefix)
    ):
        raise ConfigError(f"{location} derived an over-broad route pattern")
    return validate_path(pattern, f"{location}.derivedPattern")


def _validate_route_evidence(
    value: Any,
    payload: Mapping[str, Any],
    base_layout: Mapping[str, Any],
) -> list[dict[str, Any]]:
    route_values = _expect_list(value, "candidate.evidence.routeEvidence")
    approved_paths = set(_approved_paths_for_layout(base_layout))
    new_paths = set(payload["paths"]) - approved_paths
    normalized: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    covered_final_urls: set[str] = set()
    for route_index, raw_route in enumerate(route_values):
        location = f"candidate.evidence.routeEvidence[{route_index}]"
        route = _expect_mapping(raw_route, location)
        if set(route) != {"canonicalPathPattern", "samples"}:
            raise ConfigError(f"{location} must contain canonicalPathPattern and samples")
        pattern = validate_path(route["canonicalPathPattern"], f"{location}.canonicalPathPattern")
        if pattern not in new_paths or pattern in seen_paths:
            raise ConfigError(f"{location}.canonicalPathPattern is not one unique new route")
        seen_paths.add(pattern)
        samples = _expect_list(route["samples"], f"{location}.samples")
        if len(samples) < 3:
            raise ConfigError(f"{location}.samples requires at least three route proofs")
        normalized_samples: list[dict[str, Any]] = []
        deal_ids: set[str] = set()
        final_urls: set[str] = set()
        for sample_index, raw_sample in enumerate(samples):
            sample_location = f"{location}.samples[{sample_index}]"
            sample = _expect_mapping(raw_sample, sample_location)
            sample_keys = {
                "algumonDealId", "algumonEntryUrl", "finalResolvedUrl",
                "redirectChain", "redirectChainSha256", "provenanceSha256",
            }
            if set(sample) != sample_keys:
                raise ConfigError(f"{sample_location} keys must be: {sorted(sample_keys)}")
            deal_id = _expect_text(sample["algumonDealId"], f"{sample_location}.algumonDealId")
            if not deal_id.isdecimal() or deal_id in deal_ids:
                raise ConfigError(f"{sample_location}.algumonDealId must be a distinct decimal id")
            deal_ids.add(deal_id)
            entry_url = _validate_absolute_https_url(
                sample["algumonEntryUrl"], f"{sample_location}.algumonEntryUrl"
            )
            parsed_entry = urlsplit(entry_url)
            if (
                (parsed_entry.hostname or "").lower() not in {"algumon.com", "www.algumon.com"}
                or parsed_entry.path != f"/l/d/{deal_id}"
            ):
                raise ConfigError(f"{sample_location}.algumonEntryUrl does not match its deal id")
            final_url = _validate_absolute_https_url(
                sample["finalResolvedUrl"], f"{sample_location}.finalResolvedUrl"
            )
            parsed_final = urlsplit(final_url)
            final_hostname = (parsed_final.hostname or "").lower()
            if (
                final_hostname != base_layout["domain"]
                and not final_hostname.endswith(f".{base_layout['domain']}")
            ):
                raise ConfigError(f"{sample_location}.finalResolvedUrl is outside the site domain")
            path_query = parsed_final.path + (f"?{parsed_final.query}" if parsed_final.query else "")
            if not _path_pattern_matches(path_query, pattern):
                raise ConfigError(f"{sample_location}.finalResolvedUrl does not match the route pattern")
            if final_url not in set(payload["sampleUrls"]):
                raise ConfigError(f"{sample_location}.finalResolvedUrl is not a candidate sample URL")
            if final_url in final_urls:
                raise ConfigError(f"{sample_location}.finalResolvedUrl must be distinct")
            final_urls.add(final_url)
            covered_final_urls.add(final_url)
            chain = [
                _validate_absolute_https_url(item, f"{sample_location}.redirectChain[{index}]")
                for index, item in enumerate(_expect_list(sample["redirectChain"], f"{sample_location}.redirectChain"))
            ]
            if not chain or chain[0] != entry_url or chain[-1] != final_url:
                raise ConfigError(f"{sample_location}.redirectChain must run from Algumon to final URL")
            chain_hash = _sha256_bytes(_canonical_json_bytes(chain))
            if sample["redirectChainSha256"] != chain_hash:
                raise ConfigError(f"{sample_location}.redirectChainSha256 mismatch")
            provenance = {
                "algumonDealId": deal_id,
                "algumonEntryUrl": entry_url,
                "finalResolvedUrl": final_url,
            }
            provenance_hash = _sha256_bytes(_canonical_json_bytes(provenance))
            if sample["provenanceSha256"] != provenance_hash:
                raise ConfigError(f"{sample_location}.provenanceSha256 mismatch")
            normalized_samples.append(
                {
                    **provenance,
                    "redirectChain": chain,
                    "redirectChainSha256": chain_hash,
                    "provenanceSha256": provenance_hash,
                }
            )
        derived = _derive_single_segment_path_pattern(sorted(final_urls), location)
        if pattern != derived:
            raise ConfigError(f"{location}.canonicalPathPattern is not the minimal derived mask")
        normalized_samples.sort(key=lambda item: (item["algumonDealId"], item["finalResolvedUrl"]))
        normalized.append({"canonicalPathPattern": pattern, "samples": normalized_samples})
    if seen_paths != new_paths:
        raise ConfigError("candidate routeEvidence must cover every and only new add-only route")
    normalized.sort(key=lambda item: item["canonicalPathPattern"])
    return normalized


def _validate_observations(
    value: Any,
    payload: Mapping[str, Any],
    base_layout: Mapping[str, Any],
    *,
    final: bool,
) -> tuple[list[dict[str, Any]], list[str]]:
    observations = _expect_list(value, "candidate.evidence.observations")
    if not observations:
        raise ConfigError("candidate evidence observations must not be empty")
    base_keys = {
        "url", "profile", "capturedAt", "pageRoot", "roles", "algumon",
        "roleProjection", "commentStructure", "selectorStability",
        "oracleExecutionWorld",
    }
    final_keys = {
        "livePassed", "fixturePassed", "visibleLeakCount",
        "baselineNoNewExposure", "approvedVariantCount", "coMatchCount",
    }
    required_keys = base_keys | (final_keys if final else set())
    normalized: list[dict[str, Any]] = []
    seen_profile_urls: set[tuple[str, str]] = set()
    expected_profiles = set(payload["proofProfiles"])
    samples = set(payload["sampleUrls"])

    for index, raw_value in enumerate(observations):
        location = f"candidate.evidence.observations[{index}]"
        observation = _expect_mapping(raw_value, location)
        if set(observation) != required_keys:
            raise ConfigError(f"{location} keys must be: {sorted(required_keys)}")
        url = validate_sample_url(
            observation["url"],
            base_layout["domain"],
            payload["paths"],
            f"{location}.url",
        )
        if url not in samples:
            raise ConfigError(f"{location}.url must be listed in candidate.sampleUrls")
        profile = _expect_text(observation["profile"], f"{location}.profile")
        if profile not in expected_profiles:
            raise ConfigError(f"{location}.profile is not applicable to the base layout")
        profile_url = (profile, url)
        if profile_url in seen_profile_urls:
            raise ConfigError(f"duplicate candidate evidence observation: {profile} {url}")
        seen_profile_urls.add(profile_url)

        page_root = _expect_mapping(observation["pageRoot"], f"{location}.pageRoot")
        if set(page_root) != {"selector", "count"}:
            raise ConfigError(f"{location}.pageRoot must contain selector and count")
        page_root_selector = validate_selector(
            page_root["selector"], f"{location}.pageRoot.selector"
        )
        if page_root_selector != payload["pageRoot"]:
            raise ConfigError(f"{location}.pageRoot.selector does not match the candidate")
        _expect_exact_integer(page_root["count"], 1, f"{location}.pageRoot.count")

        role_values = _expect_mapping(observation["roles"], f"{location}.roles")
        if set(role_values) != set(payload["requiredRoles"]):
            raise ConfigError(f"{location}.roles must exactly cover candidate requiredRoles")
        roles: dict[str, dict[str, Any]] = {}
        for role in sorted(payload["requiredRoles"]):
            metric = _expect_mapping(role_values[role], f"{location}.roles.{role}")
            if set(metric) != {"selector", "count", "containedInPageRoot"}:
                raise ConfigError(
                    f"{location}.roles.{role} must contain selector/count/containedInPageRoot"
                )
            selector = validate_selector(
                metric["selector"], f"{location}.roles.{role}.selector"
            )
            if selector not in payload["roles"][role]:
                raise ConfigError(f"{location}.roles.{role}.selector is not a candidate selector")
            _expect_exact_integer(metric["count"], 1, f"{location}.roles.{role}.count")
            if metric["containedInPageRoot"] is not True:
                raise ConfigError(f"{location}.roles.{role}.containedInPageRoot must be true")
            roles[role] = {
                "selector": selector,
                "count": 1,
                "containedInPageRoot": True,
            }

        role_projection = _validate_role_projection(
            observation["roleProjection"],
            f"{location}.roleProjection",
            payload["roles"],
        )
        if role_projection != payload["roleProjection"]:
            raise ConfigError(
                f"{location}.roleProjection must equal candidate.roleProjection"
            )

        comment_structure = _expect_mapping(
            observation["commentStructure"], f"{location}.commentStructure"
        )
        comment_structure_keys = {
            "mountSelector", "mountCount", "itemSelector", "itemCount",
            "unclassifiedContentCount", "emptyStateSelector", "emptyStateCount",
            "ignoredSelectors", "ignoredCount", "classificationOverlapCount",
        }
        if set(comment_structure) != comment_structure_keys:
            raise ConfigError(
                f"{location}.commentStructure keys must be: {sorted(comment_structure_keys)}"
            )
        mount_selector = validate_selector(
            comment_structure["mountSelector"],
            f"{location}.commentStructure.mountSelector",
        )
        if mount_selector != roles["comments"]["selector"]:
            raise ConfigError(
                f"{location}.commentStructure.mountSelector must equal the comments role selector"
            )
        _expect_exact_integer(
            comment_structure["mountCount"], 1,
            f"{location}.commentStructure.mountCount",
        )
        item_selector = validate_selector(
            comment_structure["itemSelector"],
            f"{location}.commentStructure.itemSelector",
        )
        if item_selector not in payload["commentItems"]:
            raise ConfigError(
                f"{location}.commentStructure.itemSelector is not a candidate comment item selector"
            )
        item_count = _expect_nonnegative_integer(
            comment_structure["itemCount"],
            f"{location}.commentStructure.itemCount",
        )
        _expect_exact_integer(
            comment_structure["unclassifiedContentCount"], 0,
            f"{location}.commentStructure.unclassifiedContentCount",
        )
        ignored_selectors = sorted(
            validate_selector(selector, f"{location}.commentStructure.ignoredSelectors")
            for selector in _expect_unique_texts(
                comment_structure["ignoredSelectors"],
                f"{location}.commentStructure.ignoredSelectors",
            )
        )
        if ignored_selectors != payload["commentIgnored"]:
            raise ConfigError(
                f"{location}.commentStructure.ignoredSelectors must equal candidate.commentIgnored"
            )
        ignored_count = _expect_nonnegative_integer(
            comment_structure["ignoredCount"],
            f"{location}.commentStructure.ignoredCount",
        )
        _expect_exact_integer(
            comment_structure["classificationOverlapCount"], 0,
            f"{location}.commentStructure.classificationOverlapCount",
        )
        empty_state_selector_value = comment_structure["emptyStateSelector"]
        empty_state_count = comment_structure["emptyStateCount"]
        if item_count > 0:
            if empty_state_selector_value is not None:
                raise ConfigError(
                    f"{location}.commentStructure.emptyStateSelector must be null when comments exist"
                )
            _expect_exact_integer(
                empty_state_count, 0, f"{location}.commentStructure.emptyStateCount"
            )
            empty_state_selector = None
        else:
            empty_state_selector = validate_selector(
                empty_state_selector_value,
                f"{location}.commentStructure.emptyStateSelector",
            )
            if empty_state_selector != mount_selector:
                raise ConfigError(
                    f"{location}.commentStructure.emptyStateSelector must equal the unique comments mount"
                )
            _expect_exact_integer(
                empty_state_count, 1, f"{location}.commentStructure.emptyStateCount"
            )

        algumon = _expect_mapping(observation["algumon"], f"{location}.algumon")
        expected_algumon_keys = {
            "titleConsistency",
            "titleConsistencyOk",
            "titleConsistencyMode",
            "titleMetadataSourceCount",
            "titleMetadataSourceKinds",
            "countComparable",
            "countConsistency",
        }
        if set(algumon) != expected_algumon_keys:
            raise ConfigError(
                f"{location}.algumon must contain the exact title evidence and count evidence fields"
            )
        title_consistency = _expect_score(
            algumon["titleConsistency"], f"{location}.algumon.titleConsistency"
        )
        if algumon["titleConsistencyOk"] is not True:
            raise ConfigError(f"{location}.algumon.titleConsistencyOk must be true")
        if title_consistency != 1.0:
            raise ConfigError(
                f"{location}.algumon.titleConsistency must be exactly 1 for accepted evidence"
            )
        title_consistency_mode = _expect_text(
            algumon["titleConsistencyMode"],
            f"{location}.algumon.titleConsistencyMode",
        )
        if "metadata-consensus" not in title_consistency_mode:
            raise ConfigError(
                f"{location}.algumon.titleConsistencyMode must prove metadata consensus"
            )
        title_metadata_source_count = _expect_nonnegative_integer(
            algumon["titleMetadataSourceCount"],
            f"{location}.algumon.titleMetadataSourceCount",
        )
        title_metadata_source_kinds = sorted(_expect_unique_texts(
            algumon["titleMetadataSourceKinds"],
            f"{location}.algumon.titleMetadataSourceKinds",
        ))
        if (
            title_metadata_source_count < 1
            or title_metadata_source_count != len(title_metadata_source_kinds)
            or not set(title_metadata_source_kinds).issubset(
                {"og", "twitter", "schema-article"}
            )
        ):
            raise ConfigError(
                f"{location}.algumon metadata sources must be a non-empty exact supported set"
            )
        count_comparable = algumon["countComparable"]
        if not isinstance(count_comparable, bool):
            raise ConfigError(f"{location}.algumon.countComparable must be a boolean")
        if count_comparable:
            count_consistency: float | None = _expect_score(
                algumon["countConsistency"], f"{location}.algumon.countConsistency"
            )
            if count_consistency < _ALGUMON_CONSISTENCY_THRESHOLD:
                raise ConfigError(
                    f"{location}.algumon count consistency is below the promotion threshold"
                )
        else:
            if algumon["countConsistency"] is not None:
                raise ConfigError(
                    f"{location}.algumon.countConsistency must be null when counts are unavailable"
                )
            count_consistency = None
        selector_stability = _expect_score(
            observation["selectorStability"], f"{location}.selectorStability"
        )
        if selector_stability != 1.0:
            raise ConfigError(f"{location}.selectorStability must be exactly 1")
        oracle_execution_world = _expect_text(
            observation["oracleExecutionWorld"],
            f"{location}.oracleExecutionWorld",
        )
        if oracle_execution_world != "chromium-isolated-v1":
            raise ConfigError(
                f"{location}.oracleExecutionWorld must be chromium-isolated-v1"
            )

        normalized_observation: dict[str, Any] = {
            "url": url,
            "profile": profile,
            "capturedAt": _validate_recent_timestamp(
                observation["capturedAt"], f"{location}.capturedAt"
            ),
            "pageRoot": {"selector": page_root_selector, "count": 1},
            "roles": roles,
            "roleProjection": role_projection,
            "commentStructure": {
                "mountSelector": mount_selector,
                "mountCount": 1,
                "itemSelector": item_selector,
                "itemCount": item_count,
                "unclassifiedContentCount": 0,
                "emptyStateSelector": empty_state_selector,
                "emptyStateCount": empty_state_count,
                "ignoredSelectors": ignored_selectors,
                "ignoredCount": ignored_count,
                "classificationOverlapCount": 0,
            },
            "algumon": {
                "titleConsistency": title_consistency,
                "titleConsistencyOk": True,
                "titleConsistencyMode": title_consistency_mode,
                "titleMetadataSourceCount": title_metadata_source_count,
                "titleMetadataSourceKinds": title_metadata_source_kinds,
                "countComparable": count_comparable,
                "countConsistency": count_consistency,
            },
            "selectorStability": 1.0,
            "oracleExecutionWorld": "chromium-isolated-v1",
        }
        if final:
            if observation["livePassed"] is not True or observation["fixturePassed"] is not True:
                raise ConfigError(f"{location} must pass both live and fixture validation")
            _expect_exact_integer(
                observation["visibleLeakCount"], 0, f"{location}.visibleLeakCount"
            )
            if observation["baselineNoNewExposure"] is not True:
                raise ConfigError(f"{location}.baselineNoNewExposure must be true")
            _expect_exact_integer(
                observation["approvedVariantCount"], 1, f"{location}.approvedVariantCount"
            )
            _expect_exact_integer(observation["coMatchCount"], 0, f"{location}.coMatchCount")
            normalized_observation.update(
                {
                    "livePassed": True,
                    "fixturePassed": True,
                    "visibleLeakCount": 0,
                    "baselineNoNewExposure": True,
                    "approvedVariantCount": 1,
                    "coMatchCount": 0,
                }
            )
        normalized.append(normalized_observation)

    observed_profiles = {profile for profile, _url in seen_profile_urls}
    if observed_profiles != expected_profiles:
        raise ConfigError("candidate evidence must cover exactly the applicable profiles")
    for profile in sorted(expected_profiles):
        profile_observations = [
            observation for observation in normalized
            if observation["profile"] == profile
        ]
        urls = {observation["url"] for observation in profile_observations}
        if len(urls) < 3:
            raise ConfigError(
                f"candidate evidence requires three distinct target URLs for profile '{profile}'"
            )
        structure_selectors = {
            (
                observation["commentStructure"]["mountSelector"],
                observation["commentStructure"]["itemSelector"],
                tuple(observation["commentStructure"]["ignoredSelectors"]),
            )
            for observation in profile_observations
        }
        if len(structure_selectors) != 1:
            raise ConfigError(
                f"candidate comment selectors must be structurally stable for profile '{profile}'"
            )
        if any(
            not observation["algumon"]["countComparable"]
            for observation in profile_observations
        ):
            nonempty_count = sum(
                observation["commentStructure"]["itemCount"] > 0
                for observation in profile_observations
            )
            all_exact_empty = all(
                observation["commentStructure"]["itemCount"] == 0
                and observation["commentStructure"]["emptyStateSelector"] is not None
                and observation["commentStructure"]["emptyStateCount"] == 1
                for observation in profile_observations
            )
            if nonempty_count < 2 and not all_exact_empty:
                raise ConfigError(
                    "unavailable Algumon comment counts require two nonempty structural "
                    f"samples or three exact-empty proofs for profile '{profile}'"
                )
    if len({url for _profile, url in seen_profile_urls}) < 3:
        raise ConfigError("candidate evidence requires at least three distinct target URLs")
    normalized.sort(key=lambda item: (item["profile"], item["url"], item["capturedAt"]))
    return normalized, sorted(expected_profiles)


def _validate_candidate_envelope(
    candidate_value: Any,
    base_config: Mapping[str, Any],
    base_config_bytes: bytes,
    current_version: str,
    *,
    expected_status: str,
) -> dict[str, Any]:
    envelope = _expect_mapping(candidate_value, "candidate-envelope")
    evidence_key = "discovery" if expected_status == "draft" else "proof"
    required_envelope_keys = {
        "schemaVersion", "status", "protocolVersion", "baseConfigSha256",
        "releaseVersion", evidence_key, "candidate",
    }
    if set(envelope) != required_envelope_keys:
        raise ConfigError(f"candidate-envelope keys must be: {sorted(required_envelope_keys)}")
    if envelope["status"] != expected_status:
        raise ConfigError(f"candidate status must be '{expected_status}'")
    payload, base_layout, release_version, candidate_hash = _validate_candidate_payload(
        envelope, base_config, base_config_bytes, current_version
    )
    evidence = _expect_mapping(envelope[evidence_key], f"candidate.{evidence_key}")
    expected_evidence_keys = {
        "candidateSha256", "evidenceSha256", "observations", "routeEvidence"
    }
    if expected_status == "proven":
        expected_evidence_keys.add("draftArtifactSetSha256")
    if set(evidence) != expected_evidence_keys:
        raise ConfigError(
            f"candidate.{evidence_key} keys must be: {sorted(expected_evidence_keys)}"
        )
    if evidence["candidateSha256"] != candidate_hash:
        raise ConfigError(f"candidate {evidence_key} candidateSha256 mismatch")
    observations, profiles = _validate_observations(
        evidence["observations"], payload, base_layout, final=expected_status == "proven"
    )
    route_evidence = _validate_route_evidence(
        evidence["routeEvidence"], payload, base_layout
    )
    observation_urls = {observation["url"] for observation in observations}
    route_urls = {
        sample["finalResolvedUrl"]
        for route in route_evidence
        for sample in route["samples"]
    }
    if not route_urls <= observation_urls:
        raise ConfigError("candidate route final URLs must be present in observations")
    evidence_hash = _sha256_bytes(
        _canonical_json_bytes(
            {"observations": observations, "routeEvidence": route_evidence}
        )
    )
    if evidence["evidenceSha256"] != evidence_hash:
        raise ConfigError(f"candidate {evidence_key} evidenceSha256 mismatch")
    result = {
        "releaseVersion": release_version,
        "payload": payload,
        "candidateSha256": candidate_hash,
        "evidenceSha256": evidence_hash,
        "profiles": profiles,
        "observations": observations,
        "routeEvidence": route_evidence,
    }
    if expected_status == "proven":
        for key in ("draftArtifactSetSha256",):
            digest = _expect_text(evidence[key], f"candidate.proof.{key}")
            if not _SHA256_PATTERN.fullmatch(digest):
                raise ConfigError(f"candidate.proof.{key} must be lowercase SHA-256")
            result[key] = digest
    return result


def validate_promotion_candidate(
    candidate_value: Any,
    base_config: Mapping[str, Any],
    base_config_bytes: bytes,
    current_version: str | None = None,
) -> dict[str, Any]:
    return _validate_candidate_envelope(
        candidate_value,
        base_config,
        base_config_bytes,
        current_version or base_config["metadata"]["version"],
        expected_status="proven",
    )


def _userscript_contracts(source: str) -> tuple[list[dict[str, Any]], int, int]:
    start = source.find(_CANDIDATE_CONTRACT_START)
    end = source.find(_CANDIDATE_CONTRACT_END)
    if start < 0 or end < 0 or end <= start:
        raise ConfigError("userscript contract markers are missing")
    json_start = start + len(_CANDIDATE_CONTRACT_START)
    try:
        contracts = json.loads(source[json_start:end].strip())
    except json.JSONDecodeError as error:
        raise ConfigError("userscript contract block is malformed") from error
    if not isinstance(contracts, list):
        raise ConfigError("userscript contract block must be an array")
    return contracts, json_start, end


def _render_candidate_userscript(
    source: str,
    candidate: Mapping[str, Any],
    domain: str,
    runtime_profiles: Sequence[str],
    release_version: str,
) -> str:
    contracts, json_start, json_end = _userscript_contracts(source)
    compiled = copy.deepcopy(contracts)
    site = next((item for item in compiled if item.get("id") == candidate["siteId"]), None)
    if not isinstance(site, dict) or site.get("domain") != domain:
        raise ConfigError("userscript does not contain the candidate site/domain")
    variant_layout = {
        "id": f"{candidate['layoutId']}--{candidate['variantId']}",
        "paths": candidate["paths"],
        "pageRoot": candidate["pageRoot"],
        "applicableProfiles": sorted(runtime_profiles),
        "proofProfiles": candidate["proofProfiles"],
        "allowEmptyComments": candidate["allowEmptyComments"],
        "requiredRoles": candidate["requiredRoles"],
        "roleProjection": candidate["roleProjection"],
        "hints": {
            **candidate["roles"],
            "commentItems": candidate["commentItems"],
            "commentControls": candidate["commentControls"],
            "commentIgnored": candidate["commentIgnored"],
        },
    }
    existing_layout = next(
        (layout for layout in site["layouts"] if layout.get("id") == variant_layout["id"]),
        None,
    )
    if existing_layout is not None:
        if _canonical_json_bytes(existing_layout) != _canonical_json_bytes(variant_layout):
            raise ConfigError("materialized userscript variant differs from approved state")
    else:
        site["layouts"].append(variant_layout)
    site["layouts"] = sorted(site["layouts"], key=lambda item: item["id"])
    contract_json = json.dumps(compiled, ensure_ascii=False, indent=6, sort_keys=True)
    rendered = source[:json_start] + "\n    " + contract_json + "\n    " + source[json_end:]
    rendered, replacement_count = re.subn(
        r"^(//\s*@version\s+)[^\s]+(\s*)$",
        rf"\g<1>{release_version}\g<2>",
        rendered,
        count=1,
        flags=re.MULTILINE,
    )
    if replacement_count != 1:
        raise ConfigError("userscript @version metadata could not be updated")
    return rendered


def _normalized_state_record(
    payload: Mapping[str, Any],
    candidate_sha256: str,
    evidence_sha256: str,
    profiles: Sequence[str],
    release_version: str,
    draft_artifact_set_sha256: str | None = None,
) -> dict[str, Any]:
    if set(profiles) != set(payload["proofProfiles"]):
        raise ConfigError("approved proof profiles differ from the candidate payload")
    record = {
        **copy.deepcopy(dict(payload)),
        "candidateSha256": candidate_sha256,
        "evidenceSha256": evidence_sha256,
        "releaseVersion": release_version,
    }
    if draft_artifact_set_sha256 is not None:
        record["draftArtifactSetSha256"] = draft_artifact_set_sha256
    return record


def _load_approved_state(
    state_path: Path | None,
    base_config: Mapping[str, Any],
) -> list[dict[str, Any]]:
    if state_path is None:
        return []
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as error:
        raise ConfigError(f"approved state is missing or malformed: {state_path}") from error
    if not isinstance(state, dict) or set(state) != {"schemaVersion", "variants"}:
        raise ConfigError("approved state must contain schemaVersion and variants")
    if state["schemaVersion"] != 1 or not isinstance(state["variants"], list):
        raise ConfigError("approved state schemaVersion must be 1 with a variants array")
    normalized: list[dict[str, Any]] = []
    for index, value in enumerate(state["variants"]):
        location = f"approved-state.variants[{index}]"
        record = _expect_mapping(value, location)
        payload_keys = {
            "siteId", "layoutId", "variantId", "pageRoot", "paths", "sampleUrls",
            "proofProfiles", "requiredRoles", "roles", "commentItems", "commentControls",
            "commentIgnored", "roleProjection",
            "allowEmptyComments",
        }
        proof_keys = {
            "candidateSha256", "evidenceSha256", "releaseVersion",
            "draftArtifactSetSha256",
        }
        if set(record) != payload_keys | proof_keys:
            raise ConfigError(f"{location} has unexpected or missing fields")
        site_id = _expect_identifier(record["siteId"], f"{location}.siteId")
        layout_id = _expect_identifier(record["layoutId"], f"{location}.layoutId")
        variant_id = _expect_identifier(record["variantId"], f"{location}.variantId")
        _site, layout = _find_raw_layout(base_config, site_id, layout_id)
        payload = {
            "siteId": site_id,
            "layoutId": layout_id,
            "variantId": variant_id,
            "pageRoot": validate_selector(record["pageRoot"], f"{location}.pageRoot"),
            "paths": sorted(
                validate_path(path, f"{location}.paths")
                for path in _expect_unique_texts(record["paths"], f"{location}.paths")
            ),
            "sampleUrls": sorted(
                validate_sample_url(url, layout["domain"], record["paths"], f"{location}.sampleUrls")
                for url in _expect_unique_texts(record["sampleUrls"], f"{location}.sampleUrls")
            ),
            "proofProfiles": sorted(
                _expect_unique_texts(
                    record["proofProfiles"], f"{location}.proofProfiles"
                )
            ),
            "requiredRoles": sorted(
                _expect_unique_texts(record["requiredRoles"], f"{location}.requiredRoles")
            ),
            "roles": {},
            "roleProjection": None,
            "commentItems": sorted(
                _validate_selector_list(record["commentItems"], f"{location}.commentItems")
            ),
            "commentControls": sorted(
                _validate_selector_list(
                    record["commentControls"],
                    f"{location}.commentControls",
                    allow_empty=True,
                )
            ),
            "commentIgnored": sorted(
                _validate_selector_list(
                    record["commentIgnored"],
                    f"{location}.commentIgnored",
                    allow_empty=True,
                )
            ),
            "allowEmptyComments": record["allowEmptyComments"],
        }
        role_values = _expect_mapping(record["roles"], f"{location}.roles")
        classified_overlap = (
            (set(payload["commentItems"]) & set(payload["commentControls"]))
            | (set(payload["commentItems"]) & set(payload["commentIgnored"]))
            | (set(payload["commentControls"]) & set(payload["commentIgnored"]))
        )
        if classified_overlap:
            raise ConfigError(f"{location} comment item/control/ignored selectors overlap")
        if payload["allowEmptyComments"] is not True:
            raise ConfigError(f"{location}.allowEmptyComments must be true")
        if (
            not payload["proofProfiles"]
            or not set(payload["proofProfiles"]) <= set(layout["applicable_profiles"])
        ):
            raise ConfigError(f"{location}.proofProfiles is invalid")
        if set(role_values) != set(payload["requiredRoles"]):
            raise ConfigError(f"{location}.roles must match requiredRoles")
        payload["roles"] = {
            role: sorted(_validate_selector_list(selectors, f"{location}.roles.{role}"))
            for role, selectors in sorted(role_values.items())
        }
        payload["roleProjection"] = _validate_role_projection(
            record["roleProjection"], f"{location}.roleProjection", payload["roles"]
        )
        base_product_cardinality = _expect_mapping(
            _expect_mapping(
                layout.get("role_projection"), f"{location}.baseRoleProjection"
            ).get("product"),
            f"{location}.baseRoleProjection.product",
        ).get("cardinality")
        if payload["roleProjection"]["product"]["cardinality"] != base_product_cardinality:
            raise ConfigError(f"{location}.roleProjection product cardinality differs from base")
        expected_variant_id = _automatic_variant_id(payload)
        if variant_id != expected_variant_id:
            raise ConfigError(
                f"{location}.variantId does not match canonical deployment identity"
            )
        expected_hash = _sha256_bytes(_canonical_json_bytes(payload))
        if record["candidateSha256"] != expected_hash:
            raise ConfigError(f"{location}.candidateSha256 mismatch")
        materialized = next(
            (
                variant
                for variant in layout.get("variants", [])
                if isinstance(variant, dict) and variant.get("id") == variant_id
            ),
            None,
        )
        if materialized is not None:
            expected_materialized = {
                "id": variant_id,
                "page_root": payload["pageRoot"],
                "paths": payload["paths"],
                "sample_urls": payload["sampleUrls"],
                "applicable_profiles": sorted(layout["applicable_profiles"]),
                "proof_profiles": payload["proofProfiles"],
                "required_roles": payload["requiredRoles"],
                "required_groups": payload["roles"],
                "role_projection": payload["roleProjection"],
                "comment_contract": {
                    "mount": payload["roles"]["comments"],
                    "items": payload["commentItems"],
                    "controls": payload["commentControls"],
                    "ignored": payload["commentIgnored"],
                    "allow_empty": True,
                },
                "candidate_sha256": expected_hash,
            }
            if _canonical_json_bytes(materialized) != _canonical_json_bytes(expected_materialized):
                raise ConfigError(f"{location} differs from its materialized config variant")
        if not _SHA256_PATTERN.fullmatch(str(record["evidenceSha256"])):
            raise ConfigError(f"{location}.evidenceSha256 is invalid")
        profiles = payload["proofProfiles"]
        release_version = _expect_text(record["releaseVersion"], f"{location}.releaseVersion")
        if not _VERSION_PATTERN.fullmatch(release_version):
            raise ConfigError(f"{location}.releaseVersion is invalid")
        if (
            not _strictly_newer_version(
                release_version, base_config["metadata"]["version"]
            )
            and materialized is None
        ):
            raise ConfigError(
                f"{location}.releaseVersion may be at or below the base release only "
                "when its exact variant is already materialized"
            )
        draft_artifact_set_sha256 = _expect_text(
            record["draftArtifactSetSha256"], f"{location}.draftArtifactSetSha256"
        )
        if not _SHA256_PATTERN.fullmatch(draft_artifact_set_sha256):
            raise ConfigError(f"{location}.draftArtifactSetSha256 is invalid")
        normalized.append(
            _normalized_state_record(
                payload,
                expected_hash,
                record["evidenceSha256"],
                profiles,
                release_version,
                draft_artifact_set_sha256,
            )
        )
    return normalized


def _maximum_release_version(base_version: str, records: Sequence[Mapping[str, Any]]) -> str:
    versions = [base_version, *(str(record["releaseVersion"]) for record in records)]
    return max(
        versions,
        key=lambda version: tuple(
            int(part)
            for part in version.split("-", 1)[0].split("+", 1)[0].split(".")
        ),
    )


def _assert_unique_records(records: Sequence[Mapping[str, Any]]) -> None:
    seen: set[tuple[str, str, str]] = set()
    for record in records:
        key = (record["siteId"], record["layoutId"], record["variantId"])
        if key in seen:
            raise ConfigError(f"approved variant state contains a duplicate: {'/'.join(key)}")
        seen.add(key)


def _render_candidate_core(
    raw_config: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
    release_version: str,
) -> dict[str, bytes]:
    overlay = copy.deepcopy(dict(raw_config))
    userscript_source = (PROJECT_ROOT / "hotdeal-focus.user.js").read_text(encoding="utf-8")
    for record in sorted(
        records, key=lambda item: (item["siteId"], item["layoutId"], item["variantId"])
    ):
        _site, base_layout = _find_raw_layout(overlay, record["siteId"], record["layoutId"])
        variants = base_layout.setdefault("variants", [])
        materialized_variant = {
            "id": record["variantId"],
            "page_root": record["pageRoot"],
            "paths": record["paths"],
            "sample_urls": record["sampleUrls"],
            "applicable_profiles": sorted(base_layout["applicable_profiles"]),
            "proof_profiles": record["proofProfiles"],
            "required_roles": record["requiredRoles"],
            "required_groups": record["roles"],
            "role_projection": record["roleProjection"],
            "comment_contract": {
                "mount": record["roles"]["comments"],
                "items": record["commentItems"],
                "controls": record["commentControls"],
                "ignored": record["commentIgnored"],
                "allow_empty": True,
            },
            "candidate_sha256": record["candidateSha256"],
        }
        existing_variant = next(
            (variant for variant in variants if variant.get("id") == record["variantId"]),
            None,
        )
        if existing_variant is not None:
            if _canonical_json_bytes(existing_variant) != _canonical_json_bytes(materialized_variant):
                raise ConfigError("materialized config variant differs from approved state")
        else:
            variants.append(materialized_variant)
        variants.sort(key=lambda item: item["id"])
        userscript_source = _render_candidate_userscript(
            userscript_source,
            record,
            base_layout["domain"],
            base_layout["applicable_profiles"],
            release_version,
        )
    overlay["metadata"]["version"] = release_version
    overlay_config_bytes = (
        json.dumps(overlay, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    package = json.loads((PROJECT_ROOT / "package.json").read_text(encoding="utf-8"))
    package["version"] = release_version
    package_bytes = (
        json.dumps(package, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    package_lock = json.loads(
        (PROJECT_ROOT / "package-lock.json").read_text(encoding="utf-8")
    )
    package_lock["version"] = release_version
    root_package = package_lock.get("packages", {}).get("")
    if not isinstance(root_package, dict):
        raise ConfigError("package-lock.json has no root package entry")
    root_package["version"] = release_version
    package_lock_bytes = (
        json.dumps(package_lock, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    validated_overlay = validate_config(copy.deepcopy(overlay))
    from build_gate_filter import render_gate_filter

    return {
        "filter.txt": render_gate_filter(validated_overlay).encode("utf-8"),
        "filter-static.txt": render_filter(overlay).encode("utf-8"),
        "hotdeal-focus.user.js": userscript_source.encode("utf-8"),
        "config/sites.json": overlay_config_bytes,
        "package.json": package_bytes,
        "package-lock.json": package_lock_bytes,
    }


def _artifact_entries(bundle: Mapping[str, bytes]) -> dict[str, dict[str, Any]]:
    return {
        path: {"sha256": _sha256_bytes(content), "bytes": len(content)}
        for path, content in sorted(bundle.items())
    }


def _artifact_set_sha256(bundle: Mapping[str, bytes]) -> str:
    return _sha256_bytes(_canonical_json_bytes(_artifact_entries(bundle)))


def _read_candidate_envelope(candidate_path: Path) -> Any:
    try:
        return json.loads(candidate_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as error:
        raise ConfigError(f"candidate file is missing or malformed: {candidate_path}") from error


def build_candidate_draft_bundle(
    candidate_path: Path,
    approved_state_path: Path | None = None,
) -> dict[str, bytes]:
    base_config_bytes = DEFAULT_CONFIG_PATH.read_bytes()
    raw_config = json.loads(base_config_bytes.decode("utf-8"))
    base_config = validate_config(copy.deepcopy(raw_config))
    records = _load_approved_state(approved_state_path, raw_config)
    current_version = _maximum_release_version(base_config["metadata"]["version"], records)
    draft = _validate_candidate_envelope(
        _read_candidate_envelope(candidate_path),
        raw_config,
        base_config_bytes,
        current_version,
        expected_status="draft",
    )
    candidate_record = _normalized_state_record(
        draft["payload"],
        draft["candidateSha256"],
        draft["evidenceSha256"],
        draft["profiles"],
        draft["releaseVersion"],
    )
    draft_records = [*records, candidate_record]
    _assert_unique_records(draft_records)
    core = _render_candidate_core(raw_config, draft_records, draft["releaseVersion"])
    manifest = {
        "schemaVersion": 1,
        "status": "draft-non-promotable",
        "releaseVersion": draft["releaseVersion"],
        "protocolVersion": _CANDIDATE_PROTOCOL_VERSION,
        "baseConfigSha256": _sha256_bytes(base_config_bytes),
        "candidateSha256": draft["candidateSha256"],
        "discoveryEvidenceSha256": draft["evidenceSha256"],
        "proofProfiles": draft["profiles"],
        "artifactSetSha256": _artifact_set_sha256(core),
        "artifacts": _artifact_entries(core),
    }
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    return {**core, "draft-manifest.json": manifest_bytes}


def build_candidate_bundle(
    candidate_path: Path,
    approved_state_path: Path | None = None,
) -> dict[str, bytes]:
    base_config_bytes = DEFAULT_CONFIG_PATH.read_bytes()
    raw_config = json.loads(base_config_bytes.decode("utf-8"))
    base_config = validate_config(copy.deepcopy(raw_config))
    records = _load_approved_state(approved_state_path, raw_config)
    current_version = _maximum_release_version(base_config["metadata"]["version"], records)
    proven = validate_promotion_candidate(
        _read_candidate_envelope(candidate_path),
        raw_config,
        base_config_bytes,
        current_version,
    )
    payload = proven["payload"]
    candidate_record = _normalized_state_record(
        payload,
        proven["candidateSha256"],
        proven["evidenceSha256"],
        proven["profiles"],
        proven["releaseVersion"],
        proven["draftArtifactSetSha256"],
    )
    candidate_records = [*records, candidate_record]
    _assert_unique_records(candidate_records)
    candidate_records.sort(
        key=lambda item: (item["siteId"], item["layoutId"], item["variantId"])
    )
    core = _render_candidate_core(raw_config, candidate_records, proven["releaseVersion"])
    if _artifact_set_sha256(core) != proven["draftArtifactSetSha256"]:
        raise ConfigError("candidate proof does not match the byte-identical draft artifact set")

    approved_state_bytes = (
        json.dumps(
            {"schemaVersion": 1, "variants": candidate_records},
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ) + "\n"
    ).encode("utf-8")
    release_config = json.loads(core["config/sites.json"].decode("utf-8"))
    validate_config(copy.deepcopy(release_config))
    from build_release import render_materialized_release_manifest

    release_manifest_bytes = render_materialized_release_manifest(
        release_config,
        gate_bytes=core["filter.txt"],
        static_bytes=core["filter-static.txt"],
        userscript_bytes=core["hotdeal-focus.user.js"],
        config_bytes=core["config/sites.json"],
        package_bytes=core["package.json"],
        package_lock_bytes=core["package-lock.json"],
        approved_state_bytes=approved_state_bytes,
    )
    manifest_artifacts = _artifact_entries(
        {
            **core,
            "state/approved-variants.json": approved_state_bytes,
            "release-manifest.json": release_manifest_bytes,
        }
    )
    candidate_manifest = {
        "schemaVersion": 1,
        "status": "release-ready",
        "releaseVersion": proven["releaseVersion"],
        "protocolVersion": _CANDIDATE_PROTOCOL_VERSION,
        "baseConfigSha256": _sha256_bytes(base_config_bytes),
        "candidateSha256": proven["candidateSha256"],
        "evidenceSha256": proven["evidenceSha256"],
        "siteId": payload["siteId"],
        "layoutId": payload["layoutId"],
        "variantId": payload["variantId"],
        "approvedVariantCount": len(candidate_records),
        "artifacts": manifest_artifacts,
    }
    candidate_manifest_bytes = (
        json.dumps(candidate_manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    return {
        **core,
        "state/approved-variants.json": approved_state_bytes,
        "release-manifest.json": release_manifest_bytes,
        "candidate-manifest.json": candidate_manifest_bytes,
    }


def write_candidate_bundle(output_directory: Path, bundle: Mapping[str, bytes]) -> None:
    resolved_output = output_directory.resolve()
    if resolved_output == PROJECT_ROOT.resolve():
        raise ConfigError("candidate output directory must not be the repository root")
    if resolved_output.exists() and any(resolved_output.iterdir()):
        raise ConfigError("candidate output directory must be absent or empty")
    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".candidate-build-", dir=resolved_output.parent
    ) as temporary:
        staging = Path(temporary)
        for relative_name, content in bundle.items():
            target = staging / relative_name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        resolved_output.mkdir(parents=True, exist_ok=True)
        for relative_name in sorted(bundle):
            source = staging / relative_name
            target = resolved_output / relative_name
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, target)


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the path-scoped AdGuard Hotdeal Focus filter."
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument(
        "--candidate",
        type=Path,
        help="Build a proven atomic layout variant into an isolated release-ready directory.",
    )
    parser.add_argument(
        "--candidate-draft",
        type=Path,
        help="Build a structurally validated, isolated and non-promotable draft directory.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Isolated destination used only with --candidate.",
    )
    parser.add_argument(
        "--merge-approved-state",
        type=Path,
        help="Optional approved-variant state merged without deleting prior variants.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if the output is missing or differs from a fresh deterministic build.",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print the generated filter instead of writing it.",
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    options = parse_arguments(arguments)
    if options.candidate or options.candidate_draft or options.output_dir or options.merge_approved_state:
        candidate_inputs = [path for path in (options.candidate, options.candidate_draft) if path]
        if len(candidate_inputs) != 1 or not options.output_dir:
            print(
                "configuration error: exactly one of --candidate/--candidate-draft and --output-dir are required",
                file=sys.stderr,
            )
            return 2
        if options.stdout:
            print("configuration error: --stdout is incompatible with candidate builds", file=sys.stderr)
            return 2
        try:
            builder = build_candidate_bundle if options.candidate else build_candidate_draft_bundle
            bundle = builder(candidate_inputs[0], options.merge_approved_state)
            if options.check:
                current = all(
                    (options.output_dir / relative_name).exists() and
                    (options.output_dir / relative_name).read_bytes() == content
                    for relative_name, content in bundle.items()
                )
                if current:
                    print(f"candidate bundle is current: {options.output_dir}")
                    return 0
                print(f"candidate bundle is missing or stale: {options.output_dir}", file=sys.stderr)
                return 1
            write_candidate_bundle(options.output_dir, bundle)
        except ConfigError as error:
            print(f"configuration error: {error}", file=sys.stderr)
            return 2
        print(f"built isolated candidate bundle: {options.output_dir}")
        return 0
    try:
        config = load_config(options.config)
        rendered_filter = render_filter(config)
    except ConfigError as error:
        print(f"configuration error: {error}", file=sys.stderr)
        return 2

    if options.stdout:
        sys.stdout.write(rendered_filter)
        return 0
    if options.check:
        if check_filter(options.output, rendered_filter):
            print(f"up to date: {options.output}")
            return 0
        print(f"out of date: {options.output}", file=sys.stderr)
        return 1

    write_filter(options.output, rendered_filter)
    print(f"built {sum(1 for _ in iter_rules(config))} rules: {options.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
