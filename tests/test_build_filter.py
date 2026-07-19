from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from build_filter import (  # noqa: E402
    ConfigError,
    _derive_single_segment_path_pattern,
    _path_pattern_matches,
    build_hide_selector,
    build_rule,
    check_filter,
    load_config,
    render_filter,
    validate_config,
    validate_selector,
    write_filter,
)


CONFIG_PATH = PROJECT_ROOT / "config" / "sites.json"
EXPECTED_LAYOUTS = {
    "clien": {"jirum"},
    "ppomppu": {"pc", "mobile"},
    "ruliweb": {"hotdeal"},
    "quasarzone": {"market"},
    "eomisae": {"hotdeal"},
    "zod": {"deal"},
    "arcalive": {"hotdeal"},
}


def minimal_layout() -> dict:
    return {
        "id": "article",
        "domain": "example.com",
        "path": "|/deal/",
        "applicable_profiles": ["desktop", "mobile"],
        "page_root": "main",
        "sample_urls": ["https://www.example.com/deal/123"],
        "ancestor_markers": [".title", ".body", ".comment"],
        "preserve_deep": [".body", ".comment"],
        "preserve_shallow": [".title"],
        "required_roles": ["title", "body", "comments"],
        "role_projection": {
            "title": {"mode": "seeded-shallow"},
            "body": {"mode": "atomic-boundary", "ignored": []},
            "product": {
                "mode": "absent",
                "cardinality": "zero",
                "selectors": [],
                "ignored": [],
            },
            "comments": {"mode": "classified-children"},
        },
        "required_groups": {
            "title": [".title"],
            "body": [".body"],
            "comments": [".comment"],
        },
        "comment_contract": {
            "mount": [".comment"],
            "items": [".comment > .item"],
            "controls": [".comment > .more"],
            "ignored": [],
            "allow_empty": True,
        },
    }


def minimal_config() -> dict:
    return {
        "schema_version": 1,
        "metadata": {
            "title": "Test Filter",
            "description": "Deterministic test filter.",
            "version": "1.2.3",
            "expires_hours": 12,
            "license": "MIT",
        },
        "sites": [
            {
                "id": "example",
                "name": "Example",
                "layouts": [minimal_layout()],
            }
        ],
    }


class RepositoryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw_config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        cls.config = load_config(CONFIG_PATH)

    def test_all_seven_sites_and_required_layouts_are_present(self) -> None:
        actual_layouts = {
            site["id"]: {layout["id"] for layout in site["layouts"]}
            for site in self.config["sites"]
        }
        self.assertEqual(EXPECTED_LAYOUTS, actual_layouts)
        self.assertEqual(7, len(actual_layouts))

    def test_every_layout_has_integrity_markers_and_role_coverage(self) -> None:
        for site in self.config["sites"]:
            for layout in site["layouts"]:
                with self.subTest(site=site["id"], layout=layout["id"]):
                    markers = set(layout["ancestor_markers"])
                    preserved = set(layout["preserve_deep"]) | set(
                        layout["preserve_shallow"]
                    )
                    self.assertTrue(markers)
                    self.assertTrue(preserved)
                    self.assertTrue(preserved <= markers)
                    self.assertTrue({"title", "body", "comments"} <= set(layout["required_roles"]))
                    self.assertEqual(set(layout["required_roles"]), set(layout["required_groups"]))
                    for group in layout["required_roles"]:
                        self.assertTrue(layout["required_groups"][group])
                        self.assertTrue(
                            set(layout["required_groups"][group]) <= preserved
                        )

                    self.assertTrue(layout["comment_contract"]["allow_empty"])
                    self.assertTrue(layout["comment_contract"]["mount"])
                    self.assertTrue(layout["comment_contract"]["items"])
                    self.assertIn("controls", layout["comment_contract"])
                    self.assertIn("ignored", layout["comment_contract"])

    def test_generated_filter_covers_every_unique_configured_route(self) -> None:
        rendered = render_filter(self.raw_config)
        rules = [line for line in rendered.splitlines() if "#?#" in line]
        targets = {
            (layout["domain"], path)
            for site in self.config["sites"]
            for layout in site["layouts"]
            for path in layout["paths"]
        }
        self.assertEqual(len(targets), len(rules))
        self.assertEqual(len(rules), len(set(rules)))
        for domain, path in targets:
            self.assertTrue(
                any(rule.startswith(f"[$domain={domain},path={path}]#?#") for rule in rules),
                f"missing generated rule for {domain} {path}",
            )
        eomisae = next(site for site in self.config["sites"] if site["id"] == "eomisae")
        self.assertEqual(
            {"|/rt/", "|/os/", "|/fs/", "|/index.php?document_srl="},
            set(eomisae["layouts"][0]["paths"]),
        )

    def test_rebuild_is_byte_identical_and_detects_direct_modification(self) -> None:
        rendered = render_filter(self.raw_config)
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "filter.txt"
            write_filter(output_path, rendered)
            first_build = output_path.read_bytes()
            write_filter(output_path, render_filter(copy.deepcopy(self.raw_config)))
            self.assertEqual(first_build, output_path.read_bytes())
            self.assertTrue(check_filter(output_path, rendered))

            output_path.write_bytes(first_build + b"! direct edit\n")
            self.assertFalse(check_filter(output_path, rendered))


class RuleGenerationTests(unittest.TestCase):
    def test_path_patterns_are_start_anchored_and_honor_adguard_separator(self) -> None:
        self.assertTrue(
            _path_pattern_matches(
                "/zboard/view.php?id=ppomppu&no=1",
                "|/zboard/view.php?id=ppomppu^",
            )
        )
        self.assertFalse(
            _path_pattern_matches(
                "/zboard/view.php?id=ppomppu2&no=1",
                "|/zboard/view.php?id=ppomppu^",
            )
        )
        self.assertFalse(
            _path_pattern_matches(
                "/redirect/news/board/1020/read/1",
                "|/news/board/1020/read/",
            )
        )
        self.assertTrue(
            _path_pattern_matches(
                "/bbs/qb_saleinfo/views/123", "|/bbs/qb_*/views/"
            )
        )
        for article_token in (
            "3001",
            "550e8400-e29b-41d4-a716-446655440000",
            "summer-sale-slug",
        ):
            with self.subTest(article_token=article_token):
                self.assertTrue(
                    _path_pattern_matches(
                        f"/article/{article_token}", "|/article/*^"
                    )
                )
        self.assertFalse(_path_pattern_matches("/article/", "|/article/*^"))
        self.assertFalse(
            _path_pattern_matches("/article/foo/bar", "|/article/*^")
        )
        self.assertFalse(
            _path_pattern_matches(
                "/article?id=foo&next=bar&fixed=1",
                "|/article?id=*&fixed=1^",
            )
        )
        self.assertFalse(
            _path_pattern_matches("/article?id=foo=bar", "|/article?id=*^")
        )

    def test_derived_route_wildcards_values_but_never_query_parameter_names(self) -> None:
        self.assertEqual(
            "|/article?id=*^",
            _derive_single_segment_path_pattern(
                [
                    "https://example.com/article?id=1001",
                    "https://example.com/article?id=1002",
                    "https://example.com/article?id=summer-sale",
                ],
                "route",
            ),
        )
        with self.assertRaises(ConfigError):
            _derive_single_segment_path_pattern(
                [
                    "https://example.com/article?first=1",
                    "https://example.com/article?second=1",
                    "https://example.com/article?third=1",
                ],
                "route",
            )

    def test_rule_preserves_only_marker_ancestors_deep_trees_and_shallow_nodes(self) -> None:
        layout = minimal_layout()
        selector = build_hide_selector(layout)
        self.assertEqual(
            "body *:not(:has(.body)):not(:has(.comment)):not(:has(.title))"
            ":not(.body):not(.body *)"
            ":not(.comment):not(.comment *)"
            ":not(.title)",
            selector,
        )
        self.assertNotIn(":not(.title *)", selector)
        self.assertEqual(
            f"[$domain=example.com,path=|/deal/]#?#{selector}",
            build_rule(layout),
        )

    def test_render_is_canonical_when_input_order_changes(self) -> None:
        config = minimal_config()
        second_site = copy.deepcopy(config["sites"][0])
        second_site["id"] = "another"
        second_site["name"] = "Another"
        second_site["layouts"][0]["id"] = "second"
        second_site["layouts"][0]["domain"] = "another.example"
        second_site["layouts"][0]["sample_urls"] = [
            "https://another.example/deal/456"
        ]
        config["sites"].append(second_site)

        reordered = copy.deepcopy(config)
        reordered["sites"].reverse()
        for site in reordered["sites"]:
            for layout in site["layouts"]:
                layout["ancestor_markers"].reverse()
                layout["preserve_deep"].reverse()
                layout["sample_urls"].reverse()
                for selectors in layout["required_groups"].values():
                    selectors.reverse()

        self.assertEqual(render_filter(config), render_filter(reordered))
        self.assertNotIn("Generated at", render_filter(config))


class ConfigurationValidationTests(unittest.TestCase):
    def assert_config_error(self, config: dict, message: str | None = None) -> None:
        with self.assertRaises(ConfigError) as raised:
            validate_config(config)
        if message:
            self.assertIn(message, str(raised.exception))

    def test_rejects_duplicate_site_and_layout_targets(self) -> None:
        duplicate_site = minimal_config()
        duplicate_site["sites"].append(copy.deepcopy(duplicate_site["sites"][0]))
        self.assert_config_error(duplicate_site, "duplicate site id")

        duplicate_target = minimal_config()
        second_site = copy.deepcopy(duplicate_target["sites"][0])
        second_site["id"] = "second"
        second_site["name"] = "Second"
        second_site["layouts"][0]["id"] = "second"
        duplicate_target["sites"].append(second_site)
        self.assert_config_error(duplicate_target, "duplicate domain/path target")

    def test_rejects_duplicate_selector_and_deep_shallow_overlap(self) -> None:
        duplicate_selector = minimal_config()
        duplicate_selector["sites"][0]["layouts"][0]["ancestor_markers"].append(
            ".title"
        )
        self.assert_config_error(duplicate_selector, "duplicate values")

        overlap = minimal_config()
        overlap["sites"][0]["layouts"][0]["preserve_deep"].append(".title")
        self.assert_config_error(overlap, "deep/shallow overlap")

    def test_rejects_preserved_or_required_selector_outside_allowlist(self) -> None:
        missing_marker = minimal_config()
        missing_marker["sites"][0]["layouts"][0]["ancestor_markers"].remove(
            ".body"
        )
        self.assert_config_error(missing_marker, "missing from ancestor_markers")

        unpreserved_required = minimal_config()
        layout = unpreserved_required["sites"][0]["layouts"][0]
        layout["required_groups"]["body"] = [".not-preserved"]
        self.assert_config_error(unpreserved_required, "is not preserved")

    def test_rejects_missing_role_or_sample(self) -> None:
        missing_role = minimal_config()
        del missing_role["sites"][0]["layouts"][0]["required_groups"]["comments"]
        self.assert_config_error(missing_role, "must match required_roles")

        missing_sample = minimal_config()
        missing_sample["sites"][0]["layouts"][0]["sample_urls"] = []
        self.assert_config_error(missing_sample, "must not be empty")

    def test_allows_one_preservation_mode_but_rejects_both_empty(self) -> None:
        only_deep = minimal_config()
        layout = only_deep["sites"][0]["layouts"][0]
        layout["preserve_deep"].append(layout["preserve_shallow"].pop())
        validate_config(only_deep)

        no_preservation = minimal_config()
        layout = no_preservation["sites"][0]["layouts"][0]
        layout["preserve_deep"] = []
        layout["preserve_shallow"] = []
        self.assert_config_error(no_preservation, "at least one selector")

    def test_rejects_invalid_domain_path_and_sample_scope(self) -> None:
        invalid_domain = minimal_config()
        invalid_domain["sites"][0]["layouts"][0]["domain"] = "https://example.com"
        self.assert_config_error(invalid_domain, "lowercase hostname")

        invalid_path = minimal_config()
        invalid_path["sites"][0]["layouts"][0]["path"] = "/deal/"
        self.assert_config_error(invalid_path, "start anchor")

        wrong_sample_domain = minimal_config()
        wrong_sample_domain["sites"][0]["layouts"][0]["sample_urls"] = [
            "https://other.example/deal/123"
        ]
        self.assert_config_error(wrong_sample_domain, "outside the configured domain")

        wrong_sample_path = minimal_config()
        wrong_sample_path["sites"][0]["layouts"][0]["sample_urls"] = [
            "https://example.com/other/123"
        ]
        self.assert_config_error(wrong_sample_path, "does not contain")

    def test_rejects_selector_injection_and_malformed_selectors(self) -> None:
        invalid_selectors = (
            ".body, .ad",
            ".body { display: block }",
            ".body#?#.ad",
            ".body:not(.ad",
            ".body >",
            "*",
        )
        for selector in invalid_selectors:
            with self.subTest(selector=selector):
                with self.assertRaises(ConfigError):
                    validate_selector(selector, "selector")


if __name__ == "__main__":
    unittest.main()
