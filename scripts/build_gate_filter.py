#!/usr/bin/env python3
"""Build the class-triggered AdGuard gate consumed by the userscript."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from build_filter import (
    ConfigError,
    DEFAULT_CONFIG_PATH,
    PROJECT_ROOT,
    check_filter,
    load_config,
    write_filter,
)


DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "dist" / "filter.txt"
PROTOCOL_VERSION = "2"
GENERATOR_VERSION = "0.5.6"
GATE_ARTIFACT_VERSION = "2.0.2"
GATE_GENERATOR_VERSION = "2.0.2"
READY_ATTRIBUTE = "data-hotdeal-focus-ready"
KEEP_ATTRIBUTE = "data-hotdeal-focus-keep"
PROTOCOL_ATTRIBUTE = "data-hotdeal-focus-protocol"
STATE_ATTRIBUTE = "data-hotdeal-focus-state"
STATUS_ATTRIBUTE = "data-hotdeal-focus-status"
SHELL_ATTRIBUTE = "data-hotdeal-focus-shell"
DEEP_ATTRIBUTE = "data-hotdeal-focus-deep"
ROLE_ATTRIBUTE = "data-hotdeal-focus-role"

READY_CLASS = "hdf-v2-ready"
LOCK_CLASS = "hdf-v2-lock"
KEEP_CLASS = "hdf-v2-keep"
SHELL_CLASS = "hdf-v2-shell"
DEEP_CLASS = "hdf-v2-deep"
ROLE_CLASS_PREFIX = "hdf-v2-role-"
VISIBLE_ROLES = (
    "title",
    "title-text",
    "body",
    "product",
    "comment-item",
    "comment-control",
)
TOP_LAYER_PAINT_TARGETS = ("dialog", "[popover]", ":fullscreen")
ROOT_LOCK_DECLARATIONS = (
    "transition: none !important; "
    "animation: none !important; "
    "visibility: hidden !important; "
    "content-visibility: hidden !important; "
    "opacity: 0 !important; "
    "clip-path: inset(50%) !important; "
    "pointer-events: none !important; "
    "caret-color: transparent !important;"
)
TOP_LAYER_LOCK_DECLARATIONS = (
    "transition: none !important; "
    "animation: none !important; "
    "display: none !important; "
    "visibility: hidden !important; "
    "opacity: 0 !important; "
    "pointer-events: none !important;"
)
PROJECTION_HIDE_DECLARATIONS = (
    "transition: none !important; "
    "animation: none !important; "
    "display: none !important; "
    "visibility: hidden !important; "
    "opacity: 0 !important; "
    "pointer-events: none !important;"
)
SHELL_HIDE_DECLARATIONS = "visibility: hidden !important;"
PROJECTION_REVEAL_DECLARATIONS = "visibility: visible !important;"
SURFACE_CLEANUP_DECLARATIONS = (
    "background-image: none !important; box-shadow: none !important;"
)
PSEUDO_CLEANUP_DECLARATIONS = (
    "content: none !important; "
    "display: none !important; "
    "background: none !important; "
    "transition: none !important; "
    "animation: none !important;"
)


def protocol_ready_compound() -> str:
    return (
        f'.{READY_CLASS}'
        f'[{READY_ATTRIBUTE}="1"]'
        f'[{PROTOCOL_ATTRIBUTE}="{PROTOCOL_VERSION}"]'
        f'[{STATE_ATTRIBUTE}="ready"]'
        f'[{STATUS_ATTRIBUTE}="ready"]'
    )


def ready_root_selector() -> str:
    return f"html{protocol_ready_compound()}"


def locked_root_selectors() -> tuple[str, str]:
    return (
        f"html:not({protocol_ready_compound()})",
        f"html.{LOCK_CLASS}",
    )


def top_layer_selectors(
    root_selectors: Sequence[str], *, include_backdrops: bool
) -> tuple[str, ...]:
    selectors: list[str] = []
    for root_selector in root_selectors:
        for target in TOP_LAYER_PAINT_TARGETS:
            selectors.append(f"{root_selector} {target}")
            if include_backdrops:
                selectors.append(f"{root_selector} {target}::backdrop")
    return tuple(selectors)


def cosmetic_rule(
    scope: str,
    marker: str,
    selectors: Sequence[str],
    declarations: str,
) -> str:
    return f"{scope}{marker}{', '.join(selectors)} {{ {declarations} }}"


def owned_selector() -> str:
    return f".{KEEP_CLASS}[{KEEP_ATTRIBUTE}]"


def shell_selector() -> str:
    return (
        f".{KEEP_CLASS}.{SHELL_CLASS}"
        f"[{KEEP_ATTRIBUTE}][{SHELL_ATTRIBUTE}]"
    )


def deep_selector() -> str:
    return (
        f".{KEEP_CLASS}.{DEEP_CLASS}"
        f"[{KEEP_ATTRIBUTE}][{DEEP_ATTRIBUTE}]"
    )


def role_selector(role: str) -> str:
    return (
        f".{KEEP_CLASS}.{ROLE_CLASS_PREFIX}{role}"
        f'[{KEEP_ATTRIBUTE}][{ROLE_ATTRIBUTE}="{role}"]'
    )


def build_gate_rules(domain: str) -> tuple[str, ...]:
    scope = f"[$domain={domain}]"
    ready_root = ready_root_selector()
    locked_roots = locked_root_selectors()
    top_layer_elements = top_layer_selectors(
        locked_roots, include_backdrops=False
    )
    top_layer_paint = top_layer_selectors(locked_roots, include_backdrops=True)
    owned = owned_selector()
    shell = shell_selector()
    reveal_selectors = (deep_selector(),) + tuple(
        role_selector(role) for role in VISIBLE_ROLES
    )
    projection_selector = f"{ready_root} body *:not({owned})"
    shell_projection_selector = f"{ready_root} {shell}"
    reveal_projection_selectors = tuple(
        f"{ready_root} {selector}" for selector in reveal_selectors
    )
    shell_pseudo_selectors = (
        f"{ready_root} {shell}::before",
        f"{ready_root} {shell}::after",
    )
    pseudo_selectors = (
        f"{ready_root}::before",
        f"{ready_root}::after",
        f"{ready_root} body::before",
        f"{ready_root} body::after",
    ) + shell_pseudo_selectors

    standard_rules = (
        cosmetic_rule(
            scope, "#$#", locked_roots, ROOT_LOCK_DECLARATIONS
        ),
        cosmetic_rule(
            scope, "#$#", top_layer_paint, TOP_LAYER_LOCK_DECLARATIONS
        ),
        cosmetic_rule(
            scope, "#$#", (projection_selector,), PROJECTION_HIDE_DECLARATIONS
        ),
        cosmetic_rule(
            scope,
            "#$#",
            (shell_projection_selector,),
            SHELL_HIDE_DECLARATIONS,
        ),
        cosmetic_rule(
            scope,
            "#$#",
            reveal_projection_selectors,
            PROJECTION_REVEAL_DECLARATIONS,
        ),
        cosmetic_rule(
            scope,
            "#$#",
            (ready_root, f"{ready_root} body"),
            SURFACE_CLEANUP_DECLARATIONS,
        ),
        cosmetic_rule(
            scope, "#$#", pseudo_selectors, PSEUDO_CLEANUP_DECLARATIONS
        ),
    )
    extended_rules = (
        cosmetic_rule(
            scope, "#$?#", locked_roots, ROOT_LOCK_DECLARATIONS
        ),
        cosmetic_rule(
            scope,
            "#$?#",
            top_layer_elements,
            TOP_LAYER_LOCK_DECLARATIONS,
        ),
        cosmetic_rule(
            scope,
            "#$?#",
            (projection_selector,),
            PROJECTION_HIDE_DECLARATIONS,
        ),
        cosmetic_rule(
            scope,
            "#$?#",
            (shell_projection_selector,),
            SHELL_HIDE_DECLARATIONS,
        ),
        cosmetic_rule(
            scope,
            "#$?#",
            reveal_projection_selectors,
            PROJECTION_REVEAL_DECLARATIONS,
        ),
        # Do not keep html selected by another ExtendedCSS rule after unlock.
        # ExtendedCSS 2.0.52 otherwise retains the root lock rule in its
        # affected-element rule list instead of restoring the original style.
        cosmetic_rule(
            scope,
            "#$?#",
            (f"{ready_root} body",),
            SURFACE_CLEANUP_DECLARATIONS,
        ),
    )
    return standard_rules + extended_rules


def iter_gate_rules(
    config: Mapping[str, Any],
) -> Iterable[tuple[str, str, str, str]]:
    for site in sorted(config["sites"], key=lambda item: item["id"]):
        domains = sorted({layout["domain"] for layout in site["layouts"]})
        for domain in domains:
            for rule in build_gate_rules(domain):
                yield site["name"], "domain-gate-v2", domain, rule


def render_gate_filter(config: Mapping[str, Any]) -> str:
    metadata = config["metadata"]
    lines = [
        f"! Title: {metadata['title']} Marker Gate",
        "! Description: Class-triggered fail-closed protocol gate for the Hotdeal Focus userscript.",
        f"! Version: {GATE_ARTIFACT_VERSION}",
        f"! Expires: {metadata['expires_hours']} hours",
        f"! License: {metadata['license']}",
        f"! Hotdeal-Focus-Protocol: {PROTOCOL_VERSION}",
        f"! Generator-Version: {GATE_GENERATOR_VERSION}",
        "! Generated by scripts/build_gate_filter.py. Do not edit this file directly.",
        "!",
    ]
    seen: set[str] = set()
    last_context: tuple[str, str, str] | None = None
    for site_name, layout_id, domain, rule in iter_gate_rules(config):
        context = (site_name, layout_id, domain)
        if context != last_context:
            lines.append(f"! {site_name} / {layout_id} / {domain}")
            last_context = context
        if rule in seen:
            raise ConfigError(f"duplicate generated gate rule: {rule}")
        seen.add(rule)
        lines.append(rule)
    return "\n".join(lines) + "\n"


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the class-triggered AdGuard Hotdeal Focus gate filter."
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--stdout", action="store_true")
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    options = parse_arguments(arguments)
    try:
        config = load_config(options.config)
        rendered = render_gate_filter(config)
    except ConfigError as error:
        print(f"configuration error: {error}", file=sys.stderr)
        return 2
    if options.stdout:
        # Text-mode stdout rewrites LF to CRLF on Windows, which made the
        # supposedly deterministic gate bytes depend on the runner OS.  Emit
        # the canonical UTF-8/LF artifact bytes directly instead.
        sys.stdout.buffer.write(rendered.encode("utf-8"))
        return 0
    if options.check:
        if check_filter(options.output, rendered):
            print(f"up to date: {options.output}")
            return 0
        print(f"out of date: {options.output}", file=sys.stderr)
        return 1
    write_filter(options.output, rendered)
    rule_count = sum(1 for _ in iter_gate_rules(config))
    print(f"built {rule_count} marker-gate rules: {options.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
