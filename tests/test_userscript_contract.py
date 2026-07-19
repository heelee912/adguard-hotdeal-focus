from __future__ import annotations

import json
import hashlib
import base64
import re
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from build_filter import (  # noqa: E402
    ConfigError,
    _load_approved_state,
    _path_pattern_matches,
    _validate_candidate_payload,
    build_candidate_bundle,
    build_candidate_draft_bundle,
    load_config,
    render_filter,
)
from build_gate_filter import (  # noqa: E402
    GATE_ARTIFACT_VERSION,
    PROTOCOL_VERSION,
    iter_gate_rules,
    render_gate_filter,
)
from build_release import (  # noqa: E402
    GATE_FILTER_SUBSCRIPTION_URL,
    canonical_text_sha256,
    check_outputs,
    installed_filter_rules_sha256,
    render_materialized_release_manifest,
    render_release,
    validate_gate_artifact_lock,
)


USERSCRIPT_PATH = PROJECT_ROOT / "hotdeal-focus.user.js"
CONFIG_PATH = PROJECT_ROOT / "config" / "sites.json"
CONTRACT_PATTERN = re.compile(
    r"/\* HOTDEAL_FOCUS_CONTRACTS_START \*/\s*(\[.*?\])\s*"
    r"/\* HOTDEAL_FOCUS_CONTRACTS_END \*/",
    re.DOTALL,
)


def userscript_text() -> str:
    return USERSCRIPT_PATH.read_text(encoding="utf-8")


def userscript_contracts(source: str) -> list[dict]:
    match = CONTRACT_PATTERN.search(source)
    if not match:
        raise AssertionError("userscript contract JSON markers are missing")
    return json.loads(match.group(1))


def metadata_values(source: str, key: str) -> list[str]:
    pattern = re.compile(rf"^//\s*@{re.escape(key)}\s+(.+?)\s*$", re.MULTILINE)
    return pattern.findall(source)


def raw_layout_paths(layout: dict) -> list[str]:
    return layout.get("paths") or [layout["path"]]


def evaluate_title_cases(cases: list[dict]) -> list[dict]:
    encoded = base64.b64encode(
        json.dumps(cases, ensure_ascii=False).encode("utf-8")
    ).decode("ascii")
    javascript = r"""
const fs = require("fs");
const vm = require("vm");
const moduleRecord = { exports: {} };
const sandbox = {
  module: moduleRecord, URL, Set, Map, Object, Array, String, Number, RegExp,
  JSON, Date, Math, encodeURIComponent, decodeURIComponent, escape, unescape,
  Uint32Array,
};
vm.runInNewContext(fs.readFileSync("hotdeal-focus.user.js", "utf8"), sandbox);
const api = moduleRecord.exports;
const cases = JSON.parse(Buffer.from(process.argv[1], "base64").toString("utf8"));
const element = (value) => ({
  textContent: value,
  getAttribute(name) { return name === "content" ? value : null; },
});
const documentFor = (metadata) => ({
  querySelectorAll(selector) {
    if (selector === 'meta[property="og:title"]') {
      return (metadata.og ?? []).map(element);
    }
    if (selector.includes('twitter:title')) {
      return (metadata.twitter ?? []).map(element);
    }
    return [];
  },
});
const results = cases.map((item) => ({
  core: api.titleConsistency(item.algumon, item.visible),
  evidence: api.titleEvidence(
    documentFor(item.metadata ?? {}),
    item.algumon,
    item.visible,
    { articleHeadlines: item.metadata?.schema ?? [] },
  ),
}));
process.stdout.write(JSON.stringify(results));
"""
    completed = subprocess.run(
        ["node", "-e", javascript, encoded],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return json.loads(completed.stdout)


def evaluate_projection_cardinality(cases: list[dict]) -> list[dict]:
    module_url = (PROJECT_ROOT / "scripts" / "audit_pages.mjs").as_uri()
    javascript = """
const moduleUrl = process.argv[1];
const cases = JSON.parse(process.argv[2]);
const { projectionCardinalityEvidence } = await import(moduleUrl);
process.stdout.write(JSON.stringify(cases.map((item) =>
  projectionCardinalityEvidence(item.structuralOk, item.count))));
"""
    completed = subprocess.run(
        ["node", "--input-type=module", "-e", javascript, module_url, json.dumps(cases)],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return json.loads(completed.stdout)


class UserscriptMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = userscript_text()

    def test_document_start_metadata_and_update_placeholders(self) -> None:
        self.assertEqual(["none"], metadata_values(self.source, "grant"))
        self.assertEqual(["document-start"], metadata_values(self.source, "run-at"))
        self.assertEqual(
            ["https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js"],
            metadata_values(self.source, "downloadURL"),
        )
        self.assertEqual(
            ["https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js"],
            metadata_values(self.source, "updateURL"),
        )
        self.assertIn("RELEASE_URLS", self.source)
        for placeholder in (
            "__HOTDEAL_FOCUS_DOWNLOAD_URL__",
            "__HOTDEAL_FOCUS_UPDATE_URL__",
            "__HOTDEAL_FOCUS_OWNER__",
        ):
            self.assertNotIn(placeholder, self.source)

    def test_algumon_and_all_seven_target_domains_have_https_matches(self) -> None:
        matches = set(metadata_values(self.source, "match"))
        self.assertEqual(
            {
                "https://www.algumon.com/*",
                "https://*.clien.net/*",
                "https://*.ppomppu.co.kr/*",
                "https://*.ruliweb.com/*",
                "https://*.quasarzone.com/*",
                "https://*.eomisae.co.kr/*",
                "https://*.zod.kr/*",
                "https://*.arca.live/*",
            },
            matches,
        )

    def test_release_code_has_no_remote_execution_or_network_api(self) -> None:
        source_without_exact_signed_relay_fetch = self.source.replace(
            "browserRoot.fetch(cacheKey, {", "SIGNED_RELAY_FETCH({", 1
        )
        self.assertEqual(1, self.source.count("browserRoot.fetch(cacheKey, {"))
        forbidden_patterns = {
            "dynamic code": r"\beval\s*\(|\bnew\s+Function\s*\(",
            "network request": r"\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\b|\bEventSource\b|sendBeacon\s*\(",
            "remote module": r"\bimport\s*\(|\brequire\s*\(",
        }
        for label, pattern in forbidden_patterns.items():
            with self.subTest(label=label):
                self.assertIsNone(re.search(pattern, source_without_exact_signed_relay_fetch))

    def test_protocol_markers_and_no_text_diagnostics_are_explicit(self) -> None:
        for token in (
            "data-hotdeal-focus-lock",
            "data-hotdeal-focus-ready",
            "data-hotdeal-focus-keep",
            "data-hotdeal-focus-state",
            "data-hotdeal-focus-role",
            "data-hotdeal-focus-protocol",
            "__HOTDEAL_FOCUS_DIAGNOSTICS__",
            "visibleLeakCount",
        ):
            self.assertIn(token, self.source)
        self.assertIn("protocolVersion: Number(PROTOCOL_VERSION)", self.source)
        diagnostics_function = self.source[
            self.source.index("function publishDiagnostics"):
            self.source.index("function resolveApprovedLayout")
        ]
        self.assertNotIn("resolvedTitle:", diagnostics_function)

    def test_core_dom_identity_is_not_replaced_or_recreated(self) -> None:
        for forbidden in (
            ".replaceWith(",
            ".replaceChildren(",
            ".innerHTML =",
            ".outerHTML =",
            'createElement("span")',
            "insertBefore(",
        ):
            self.assertNotIn(forbidden, self.source)

    def test_multilingual_semantics_are_valid_utf8_without_mojibake(self) -> None:
        for expected in ("댓글", "답글", "광고", "広告", "广告", "评论", "回复"):
            self.assertIn(expected, self.source)
        for mojibake in ("�", "愿묎", "佯껃", "亮욕"):
            self.assertNotIn(mojibake, self.source)


class SemanticContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = userscript_text()
        cls.userscript_sites = userscript_contracts(cls.source)
        cls.raw_config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        cls.config = load_config(CONFIG_PATH)

    def test_compiled_contract_matches_config_routes_roles_roots_and_hints(self) -> None:
        compiled_by_id = {site["id"]: site for site in self.userscript_sites}
        self.assertEqual(
            {site["id"] for site in self.raw_config["sites"]},
            set(compiled_by_id),
        )
        for site in self.raw_config["sites"]:
            compiled_site = compiled_by_id[site["id"]]
            self.assertEqual(site["layouts"][0]["domain"], compiled_site["domain"])
            compiled_layouts = {layout["id"]: layout for layout in compiled_site["layouts"]}
            self.assertEqual({layout["id"] for layout in site["layouts"]}, set(compiled_layouts))
            for layout in site["layouts"]:
                compiled = compiled_layouts[layout["id"]]
                self.assertEqual(set(raw_layout_paths(layout)), set(raw_layout_paths(compiled)))
                self.assertEqual(layout["page_root"], compiled["pageRoot"])
                self.assertEqual(
                    set(layout["applicable_profiles"]),
                    set(compiled["applicableProfiles"]),
                )
                self.assertEqual(set(layout["required_roles"]), set(compiled["requiredRoles"]))
                self.assertEqual(layout["role_projection"], compiled["roleProjection"])
                for role in layout["required_roles"]:
                    self.assertEqual(
                        set(layout["required_groups"][role]),
                        set(compiled["hints"][role]),
                    )
                self.assertEqual(
                    set(layout["comment_contract"]["mount"]),
                    set(compiled["hints"]["comments"]),
                )
                self.assertEqual(
                    set(layout["comment_contract"]["items"]),
                    set(compiled["hints"]["commentItems"]),
                )
                self.assertEqual(
                    set(layout["comment_contract"]["controls"]),
                    set(compiled["hints"]["commentControls"]),
                )
                self.assertEqual(
                    set(layout["comment_contract"]["ignored"]),
                    set(compiled["hints"]["commentIgnored"]),
                )
                self.assertEqual(
                    layout["comment_contract"]["allow_empty"],
                    compiled["allowEmptyComments"],
                )

    def test_runtime_unlock_uses_one_atomic_approved_layout(self) -> None:
        resolver = self.source[
            self.source.index("function resolveApprovedLayout"):self.source.index("function installIntegrityObserver")
        ]
        self.assertIn("pageRoots.length !== 1", resolver)
        self.assertIn("titleCandidates.length !== 1", resolver)
        self.assertIn("bodyCandidates.length !== 1", resolver)
        self.assertIn("commentCandidates.length !== 1", resolver)
        self.assertIn("projectionClasses.length !== 1", resolver)
        self.assertNotIn("selectTitle(document", resolver)
        self.assertNotIn("selectBody(document", resolver)
        self.assertNotIn("decideCandidate", resolver)
        self.assertNotIn("item-fingerprint", resolver)
        self.assertIn('"selector-hint"', self.source)
        self.assertIn("minIndependentSignals: 2", self.source)

    def test_comment_mount_and_items_are_separate_and_empty_is_allowed(self) -> None:
        for site in self.config["sites"]:
            for layout in site["layouts"]:
                self.assertTrue(layout["comment_contract"]["allow_empty"])
                self.assertTrue(layout["comment_contract"]["mount"])
                self.assertTrue(layout["comment_contract"]["items"])
                self.assertIn("controls", layout["comment_contract"])
                self.assertIn("ignored", layout["comment_contract"])
        self.assertIn("roles.commentItems.forEach", self.source)
        self.assertIn("roles.commentControls.forEach", self.source)
        self.assertIn("seed-item-mismatch", self.source)
        resolver = self.source[
            self.source.index("function resolveApprovedLayout"):
            self.source.index("function resolveDocument")
        ]
        self.assertIn("commentItems.concat(commentControls, commentIgnored)", resolver)
        self.assertIn(
            "hasUnclassifiedCommentContent(commentMount, classifiedCommentRoots)",
            resolver,
        )
        self.assertNotIn(
            "commentItems.length === 0 &&\n      hasUnclassifiedCommentContent",
            resolver,
        )

    def test_runtime_path_scope_is_start_anchored_and_separator_aware(self) -> None:
        matcher = self.source[
            self.source.index("function pathPatternMatches"):
            self.source.index("function contractPaths")
        ]
        self.assertIn('configured.startsWith("|/")', matcher)
        self.assertIn("requiresSeparator", matcher)
        self.assertIn('"[^/?&=]+"', matcher)
        self.assertIn("terminalWildcard", matcher)
        self.assertIn("wildcardIsQueryToken", matcher)
        self.assertIn("^${pattern}${boundary}", matcher)
        ruli = next(site for site in self.raw_config["sites"] if site["id"] == "ruliweb")
        self.assertEqual(
            {"|/news/board/1020/read/", "|/market/board/1020/read/"},
            set(raw_layout_paths(ruli["layouts"][0])),
        )

    def test_seed_is_short_lived_public_and_never_a_solo_trusted_signal(self) -> None:
        self.assertIn("SEED_MAX_AGE_MS = 10 * 60 * 1000", self.source)
        self.assertIn("SEED_MAX_BYTES = 1024", self.source)
        self.assertIn('SEED_FRAGMENT_KEY = "hdf-seed"', self.source)
        self.assertIn("function writeSeedFragment", self.source)
        self.assertIn("function readAndClearFragmentSeed", self.source)
        self.assertIn("browserRoot.history.replaceState", self.source)
        self.assertIn('document.addEventListener("auxclick"', self.source)
        self.assertIn('document.addEventListener("keydown"', self.source)
        self.assertIn('event.key === "Enter"', self.source)
        self.assertIn('browserRoot.name = ""', self.source)
        self.assertIn('"seed-title-match"', self.source)
        self.assertIn('"seed-count-match"', self.source)
        self.assertIn("UNTRUSTED_SIGNALS", self.source)
        self.assertNotRegex(self.source, r"seed\.(?:body|content|html|user|email|token)")
        extractor = self.source[
            self.source.index("function extractAlgumonSeed"):
            self.source.index("function installAlgumonSeedCapture")
        ]
        self.assertIn("data-source-comment-count", extractor)
        self.assertIn("data-origin-comment-count", extractor)
        self.assertNotIn('"data-comment-count"', extractor)
        self.assertNotIn("countMatch", extractor)
        self.assertNotIn("cardText.match", extractor)

    def test_projection_cardinality_truth_table_is_fail_closed(self) -> None:
        cases = [
            {"structuralOk": True, "count": 0},
            {"structuralOk": True, "count": 1},
            {"structuralOk": True, "count": 2},
            {"structuralOk": False, "count": 1},
        ]
        self.assertEqual(
            [
                {
                    "semanticProjectionCount": 0,
                    "coMatchCount": 0,
                    "exactApprovedCount": 0,
                },
                {
                    "semanticProjectionCount": 1,
                    "coMatchCount": 0,
                    "exactApprovedCount": 1,
                },
                {
                    "semanticProjectionCount": 2,
                    "coMatchCount": 1,
                    "exactApprovedCount": 0,
                },
                {
                    "semanticProjectionCount": 1,
                    "coMatchCount": 0,
                    "exactApprovedCount": 0,
                },
            ],
            evaluate_projection_cardinality(cases),
        )

    def test_live_title_corpus_requires_algumon_core_and_independent_metadata(self) -> None:
        live_cases = [
            {
                "id": "clien-samwatch",
                "algumon": "SamWatch Analog Fantasy A",
                "visible": "이벤트정보 [WearOS] SamWatch Analog Fantasy A 일시 무료 2",
                "metadata": {"og": ["[WearOS] SamWatch Analog Fantasy A 일시 무료 : 클리앙"]},
                "core_ok": True,
                "evidence_ok": True,
            },
            {
                "id": "clien-luxroom-single-token",
                "algumon": "Luxroom Luxroom",
                "visible": "이벤트정보 [iOS] Luxroom 일시 무료 2",
                "metadata": {"og": ["[iOS] Luxroom 일시 무료 : 클리앙"]},
                "core_ok": False,
                "evidence_ok": True,
            },
            {
                "id": "ppomppu-red-ginseng",
                "algumon": "려원담 홍삼점 에버타임 하이엔드 30포*2박스",
                "visible": "[CJ온스타일] 려원담 홍삼점 에버타임 하이엔드 30포*2박스 (19,800원/무배)",
                "metadata": {
                    "og": ["[CJ온스타일] 려원담 홍삼점 에버타임 하이엔드 30포*2박스 (19,800원/무배)"],
                    "schema": ["[CJ온스타일] 려원담 홍삼점 에버타임 하이엔드 30포*2박스 (19,800원/무배)"],
                },
                "core_ok": True,
                "evidence_ok": True,
            },
            {
                "id": "ppomppu-peach",
                "algumon": "딱딱이 복숭아 2kg",
                "visible": "[카카오] 딱딱이 복숭아 2kg 소과 (9,790원 / 무료배송)",
                "metadata": {"og": ["[카카오] 딱딱이 복숭아 2kg 소과 (9,790원 / 무료배송)"]},
                "core_ok": True,
                "evidence_ok": True,
            },
            {
                "id": "ruliweb-points",
                "algumon": "일일적립, 클릭 132원, 라이브예고 20원",
                "visible": "[네이버페이] 일일적립, 클릭 132원, 라이브예고 20원",
                "metadata": {"og": ["네이버페이 일일적립 클릭 132원 라이브예고 20원"]},
                "core_ok": True,
                "evidence_ok": True,
            },
            {
                "id": "ruliweb-megacoffee-short",
                "algumon": "메가커피 메뉴",
                "visible": "[카톡선물하기,지마켓] 메가커피 메뉴 20~23% 할인 (7/20~26)",
                "metadata": {"og": ["카톡선물하기지마켓 메가커피 메뉴 20~23% 할인 (7/20~26)"]},
                "core_ok": True,
                "evidence_ok": True,
            },
            {
                "id": "quasar-peach",
                "algumon": "천홍 천도복숭아 로얄과 2kg",
                "visible": "진행중 [기타] 천도복숭아 천홍품종 로얄과 2kg (11,900원 / 무배)",
                "metadata": {"og": ["[기타] 천도복숭아 천홍품종 로얄과 2kg (11,900원 / 무배)"]},
                "core_ok": True,
                "evidence_ok": True,
            },
            {
                "id": "quasar-points",
                "algumon": "네이버페이 적립 133원/쇼핑라이브/12원 종합 차트 (26.7.20)",
                "visible": "인기 [네이버] 네이버페이 적립 133원/쇼핑라이브/12원 종합 차트 (26.7.20)",
                "metadata": {"og": ["[네이버] 네이버페이 적립 133원/쇼핑라이브/12원 종합 차트 (26.7.20)"]},
                "core_ok": True,
                "evidence_ok": True,
            },
            {
                "id": "eomisae-boots",
                "algumon": "바버 조공용 레인부츠",
                "visible": "네이버 조공용 바버 레인부츠 6.5발(최대적립 5,492원) 무배",
                "metadata": {"og": ["조공용 바버 레인부츠 6.5발(최대적립 5,492원) 무배 - 패션정보 - 어미새"]},
                "core_ok": True,
                "evidence_ok": True,
            },
            {
                "id": "eomisae-kombucha",
                "algumon": "티젠 콤부차 스트로베리키위 100T",
                "visible": "국내 티젠 콤부차 스트로베리키위 100T 18,280원",
                "metadata": {"og": ["티젠 콤부차 스트로베리키위 100T 18,280원 - 기타정보 - 어미새"]},
                "core_ok": True,
                "evidence_ok": True,
            },
            {
                "id": "zod-points",
                "algumon": "네이버페이 포인트",
                "visible": "[네이버] 네이버페이 포인트 (0원 / 무료)",
                "metadata": {"og": ["[네이버] 네이버페이 포인트 (0원 / 무료) - 특가"]},
                "core_ok": True,
                "evidence_ok": True,
            },
            {
                "id": "zod-truncated",
                "algumon": "롯데 아이스크림 바류 10종 x 5개(아맛나/돼지바/메가톤/와일드바디/빙빙바 등)",
                "visible": "[오늘의집] 롯데 아이스크림 바류 10종 x 5개(아맛나/돼지바/메가톤/와일드바디/빙 (19,440원 / 무료)",
                "metadata": {},
                "core_ok": True,
                "evidence_ok": False,
            },
            {
                "id": "arca-lime",
                "algumon": "티젠 콤부차 청귤라임 5g 100개입",
                "visible": "식품 티젠 콤부차 청귤라임 5g 100개입 (17,270원/무료)",
                "metadata": {"og": ["티젠 콤부차 청귤라임 5g 100개입 (17,270원/무료) - 핫딜 채널"]},
                "core_ok": True,
                "evidence_ok": True,
            },
            {
                "id": "arca-strawberry",
                "algumon": "티젠 콤부차 스트로베리키위 5g 100개입",
                "visible": "식품 티젠 콤부차 스트로베리키위 5g 100개입 (18,280원/무료)",
                "metadata": {"og": ["티젠 콤부차 스트로베리키위 5g 100개입 (18,280원/무료) - 핫딜 채널"]},
                "core_ok": True,
                "evidence_ok": True,
            },
        ]
        results = evaluate_title_cases(live_cases)
        for case, result in zip(live_cases, results, strict=True):
            with self.subTest(case=case["id"]):
                self.assertEqual(case["core_ok"], result["core"]["ok"], result)
                self.assertEqual(case["evidence_ok"], result["evidence"]["ok"], result)
                if case["evidence_ok"]:
                    self.assertEqual(1, result["evidence"]["score"])
                    self.assertGreaterEqual(
                        result["evidence"]["metadata"]["sourceCount"], 1
                    )

    def test_title_evidence_rejects_numeric_model_drift_and_metadata_ambiguity(self) -> None:
        negative_cases = [
            ("티젠 콤부차 100개입", "티젠 콤부차 50개입"),
            ("천도복숭아 로얄과 2kg", "천도복숭아 로얄과 3kg"),
            ("일일적립 클릭 132원", "일일적립 클릭 133원"),
            ("Luxroom Luxroom", "Luxrooms 일시 무료"),
            ("Luxroom Luxroom", "Luxroom 할인 앱"),
            ("iPhone 16 Pro 256GB", "iPhone 16 256GB"),
            ("네이버페이 포인트", "네이버페이 포인트 정책 안내"),
            ("천홍 천도복숭아 로얄과 2kg", "천홍 천도복숭아 농장 광고 2kg"),
            ("메가커피 메뉴", "메가커피 쿠폰"),
            ("Apple AirPods Pro 2", "Pineapple AirPods Pro 2"),
        ]
        cases = [
            {
                "algumon": source,
                "visible": destination,
                "metadata": {"og": [destination]},
            }
            for source, destination in negative_cases
        ]
        cases.append(
            {
                "algumon": "티젠 콤부차 청귤라임 5g 100개입",
                "visible": "티젠 콤부차 청귤라임 5g 100개입",
                "metadata": {
                    "og": [
                        "티젠 콤부차 청귤라임 5g 100개입",
                        "전혀 다른 인기 추천 상품 50개입",
                    ]
                },
            }
        )
        for index, result in enumerate(evaluate_title_cases(cases)):
            with self.subTest(case=index):
                self.assertFalse(result["evidence"]["ok"])

    def test_tamper_and_spa_revalidation_contracts_exist(self) -> None:
        for token in (
            "installBootstrapGuard",
            "verifyOwnedState",
            "ownedElementSet",
            "runtime-style-tamper",
            "installNavigationRevalidation",
            "discoverSemanticContract",
            "__HOTDEAL_FOCUS_AUDIT__",
            '"pushState"',
            '"replaceState"',
            '"popstate"',
            '"pageshow"',
        ):
            self.assertIn(token, self.source)
        bootstrap = self.source[
            self.source.index("function installBootstrapGuard"):
            self.source.index("function installCascadeGuard")
        ]
        self.assertIn("let terminallyBlocked = false", bootstrap)
        self.assertIn("runtime.enterTerminal", bootstrap)
        self.assertIn("runtimeGateStyleIntact", bootstrap)
        self.assertIn("runtime.authorizedReady", bootstrap)
        self.assertIn("canonicalRuntimeCssRules", self.source)
        self.assertIn("installPersistentTerminalGuardian", self.source)
        navigation_start = self.source.index("function activateCurrentLocation")
        navigation = self.source[
            navigation_start:
            self.source.index("installNavigationRevalidation", navigation_start)
        ]
        self.assertIn("activeRuntime.terminallyBlocked", navigation)
        self.assertIn('setAttribute(ATTR.status, "terminal-tamper")', navigation)
        self.assertIn("event.persisted === true", self.source)

    def test_runtime_projection_is_nonce_bound_and_ready_is_committed_last(self) -> None:
        style = self.source[
            self.source.index("function paintLockSelectors"):
            self.source.index("function installRuntimeGateStyle")
        ]
        self.assertIn('const owned = `[${ATTR.keep}="${nonce}"]`', style)
        self.assertIn('const shell = `[${ATTR.shell}="${nonce}"]`', style)
        self.assertNotIn(":not([${ATTR.keep}])", style)
        for paint_lock in (
            "transition: none !important",
            "animation: none !important",
            "content-visibility: hidden !important",
            "visibility: hidden !important",
            "opacity: 0 !important",
            "pointer-events: none !important",
            "clip-path: inset(50%) !important",
            "dialog::backdrop",
            "[popover]::backdrop",
            ":fullscreen::backdrop",
        ):
            self.assertIn(paint_lock, style)
        self.assertNotIn("display: none !important", style.split("if (!nonce)", 1)[0])
        attempt = self.source[
            self.source.index("function attemptResolution"):
            self.source.index("function scheduleAttempt")
        ]
        self.assertLess(
            attempt.index("writeRuntimeGateStyle(styleElement, nonce, runtime)"),
            attempt.index('setAttribute(ATTR.ready, "1")'),
        )

    def test_path_drift_probe_requires_initial_algumon_navigation_evidence(self) -> None:
        start = self.source[
            self.source.index("function start(browserRoot)"):
            self.source.index("return { mode: \"reader-gate\"")
        ]
        self.assertIn("const initialSeed = readAndClearSeed(browserRoot)", start)
        self.assertIn("layouts.length === 0", start)
        self.assertIn("isInitialActivation", start)
        self.assertIn('terminalNavigationBlock("route-unapproved")', start)
        self.assertIn("const evaluationLayouts = layouts", start)
        self.assertNotIn("contract.layouts", start)


class CandidatePromotionContractTests(unittest.TestCase):
    def candidate_payload(self, variant_id: str) -> dict:
        sample_urls = [
            "https://www.clien.net/service/board/jirum/19230509",
            "https://www.clien.net/service/board/jirum/19230510",
            "https://www.clien.net/service/board/jirum/19230511",
        ]
        payload = {
            "siteId": "clien",
            "layoutId": "jirum",
            "variantId": variant_id,
            "pageRoot": ".content_view_v2",
            "paths": ["|/service/board/jirum/"],
            "sampleUrls": sample_urls,
            "proofProfiles": ["desktop", "mobile"],
            "requiredRoles": ["body", "comments", "title"],
            "roles": {
                "body": [".post_article_v2"],
                "comments": [".post_comment_v2"],
                "title": [".post_subject_v2"],
            },
            "roleProjection": {
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
            "commentItems": [".post_comment_v2 > .comment"],
            "commentControls": [".post_comment_v2 .comment_more"],
            "commentIgnored": [".post_comment_v2 > .comment_chrome"],
            "allowEmptyComments": True,
        }
        return payload

    def observations(self, payload: dict, *, final: bool) -> list[dict]:
        captured_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        observations = []
        for profile in ("desktop", "mobile"):
            for url in payload["sampleUrls"]:
                observation = {
                    "url": url,
                    "profile": profile,
                    "capturedAt": captured_at,
                    "pageRoot": {"selector": payload["pageRoot"], "count": 1},
                    "roles": {
                        role: {
                            "selector": payload["roles"][role][0],
                            "count": 1,
                            "containedInPageRoot": True,
                        }
                        for role in payload["requiredRoles"]
                    },
                    "roleProjection": payload["roleProjection"],
                    "commentStructure": {
                        "mountSelector": payload["roles"]["comments"][0],
                        "mountCount": 1,
                        "itemSelector": payload["commentItems"][0],
                        "itemCount": 2,
                        "unclassifiedContentCount": 0,
                        "emptyStateSelector": None,
                        "emptyStateCount": 0,
                        "ignoredSelectors": payload["commentIgnored"],
                        "ignoredCount": 1,
                        "classificationOverlapCount": 0,
                    },
                    "algumon": {
                        "titleConsistency": 1.0,
                        "titleConsistencyOk": True,
                        "titleConsistencyMode": "algumon-exact-core+metadata-consensus",
                        "titleMetadataSourceCount": 1,
                        "titleMetadataSourceKinds": ["og"],
                        "countComparable": False,
                        "countConsistency": None,
                    },
                    "selectorStability": 1.0,
                    "oracleExecutionWorld": "chromium-isolated-v1",
                }
                if final:
                    observation.update(
                        {
                            "livePassed": True,
                            "fixturePassed": True,
                            "visibleLeakCount": 0,
                            "baselineNoNewExposure": True,
                            "approvedVariantCount": 1,
                            "coMatchCount": 0,
                        }
                    )
                observations.append(observation)
        return observations

    @staticmethod
    def digest(value: object) -> str:
        canonical = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def automatic_variant_id(self, payload: dict) -> str:
        stable_identity = {
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
        return f"auto-{self.digest(stable_identity)[:24]}"

    @staticmethod
    def route_owners(layout: dict, url: str) -> list[str]:
        parsed = urlsplit(url)
        path_and_query = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        owners = []
        if any(
            _path_pattern_matches(path_and_query, path)
            for path in raw_layout_paths(layout)
        ):
            owners.append(layout["id"])
        for variant in layout.get("variants", []):
            if any(
                _path_pattern_matches(path_and_query, path)
                for path in raw_layout_paths(variant)
            ):
                owners.append(f"{layout['id']}--{variant['id']}")
        return sorted(owners)

    def draft_envelope(self, variant_id: str, release_version: str) -> dict:
        payload = self.candidate_payload(variant_id)
        payload["variantId"] = self.automatic_variant_id(payload)
        observations = self.observations(payload, final=False)
        return {
            "schemaVersion": 1,
            "status": "draft",
            "protocolVersion": 1,
            "baseConfigSha256": hashlib.sha256(CONFIG_PATH.read_bytes()).hexdigest(),
            "releaseVersion": release_version,
            "discovery": {
                "candidateSha256": self.digest(payload),
                "evidenceSha256": self.digest(
                    {"observations": observations, "routeEvidence": []}
                ),
                "observations": observations,
                "routeEvidence": [],
            },
            "candidate": payload,
        }

    def add_new_route(
        self,
        draft: dict,
        *,
        route_name: str = "newhotdeal",
        article_ids: tuple[int, int, int] = (3001, 3002, 3003),
    ) -> dict:
        pattern = f"|/service/board/{route_name}/*^"
        final_urls = [
            f"https://www.clien.net/service/board/{route_name}/{article_id}"
            for article_id in article_ids
        ]
        draft["candidate"]["paths"] = [pattern]
        draft["candidate"]["sampleUrls"] = final_urls
        draft["candidate"]["variantId"] = self.automatic_variant_id(
            draft["candidate"]
        )
        samples = []
        for index, final_url in enumerate(final_urls, start=9001):
            deal_id = str(index)
            host = "algumon.com" if index == 9001 else "www.algumon.com"
            entry_url = f"https://{host}/l/d/{deal_id}?v=signed-{deal_id}&t=proof"
            chain = [entry_url, final_url]
            provenance = {
                "algumonDealId": deal_id,
                "algumonEntryUrl": entry_url,
                "finalResolvedUrl": final_url,
            }
            samples.append(
                {
                    **provenance,
                    "redirectChain": chain,
                    "redirectChainSha256": self.digest(chain),
                    "provenanceSha256": self.digest(provenance),
                }
            )
        observations = self.observations(draft["candidate"], final=False)
        route_evidence = [{"canonicalPathPattern": pattern, "samples": samples}]
        draft["discovery"] = {
            "candidateSha256": self.digest(draft["candidate"]),
            "evidenceSha256": self.digest(
                {"observations": observations, "routeEvidence": route_evidence}
            ),
            "observations": observations,
            "routeEvidence": route_evidence,
        }
        return draft

    def refresh_draft_hashes(self, draft: dict) -> None:
        draft["candidate"]["variantId"] = self.automatic_variant_id(
            draft["candidate"]
        )
        draft["discovery"]["candidateSha256"] = self.digest(draft["candidate"])
        draft["discovery"]["evidenceSha256"] = self.digest(
            {
                "observations": draft["discovery"]["observations"],
                "routeEvidence": draft["discovery"]["routeEvidence"],
            }
        )

    def proven_envelope(self, draft: dict, artifact_set_sha256: str) -> dict:
        payload = draft["candidate"]
        observations = self.observations(payload, final=True)
        route_evidence = draft["discovery"]["routeEvidence"]
        return {
            **{key: draft[key] for key in (
                "schemaVersion", "protocolVersion", "baseConfigSha256", "releaseVersion", "candidate"
            )},
            "status": "proven",
            "proof": {
                "candidateSha256": self.digest(payload),
                "evidenceSha256": self.digest(
                    {"observations": observations, "routeEvidence": route_evidence}
                ),
                "draftArtifactSetSha256": artifact_set_sha256,
                "observations": observations,
                "routeEvidence": route_evidence,
            },
        }

    @staticmethod
    def write_envelope(path: Path, envelope: dict) -> None:
        path.write_text(json.dumps(envelope), encoding="utf-8")

    def build_pair(
        self,
        root: Path,
        variant_id: str,
        release_version: str,
        state_path: Path | None = None,
    ) -> tuple[dict[str, bytes], dict[str, bytes], dict]:
        draft_envelope = self.draft_envelope(variant_id, release_version)
        return self.build_envelope_pair(root, draft_envelope, state_path)

    def build_envelope_pair(
        self,
        root: Path,
        draft_envelope: dict,
        state_path: Path | None = None,
    ) -> tuple[dict[str, bytes], dict[str, bytes], dict]:
        variant_id = draft_envelope["candidate"]["variantId"]
        draft_path = root / f"{variant_id}-draft.json"
        self.write_envelope(draft_path, draft_envelope)
        draft_bundle = build_candidate_draft_bundle(draft_path, state_path)
        draft_manifest = json.loads(draft_bundle["draft-manifest.json"])
        proven_envelope = self.proven_envelope(
            draft_envelope, draft_manifest["artifactSetSha256"]
        )
        proven_path = root / f"{variant_id}-proven.json"
        self.write_envelope(proven_path, proven_envelope)
        return (
            draft_bundle,
            build_candidate_bundle(proven_path, state_path),
            proven_envelope,
        )

    def test_two_stage_candidate_is_byte_identical_and_release_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            draft_bundle, bundle, proven = self.build_pair(
                temporary_root, "jirum-v2", "0.3.7"
            )
            self.assertEqual("draft-non-promotable", json.loads(
                draft_bundle["draft-manifest.json"]
            )["status"])
            self.assertEqual(
                {
                    "filter.txt",
                    "filter-static.txt",
                    "config/sites.json",
                    "package.json",
                    "package-lock.json",
                    "hotdeal-focus.user.js",
                    "candidate-manifest.json",
                    "state/approved-variants.json",
                    "release-manifest.json",
                },
                set(bundle),
            )
            for core_path in (
                "filter.txt", "filter-static.txt", "hotdeal-focus.user.js",
                "config/sites.json", "package.json", "package-lock.json",
            ):
                self.assertEqual(draft_bundle[core_path], bundle[core_path])
            self.assertIn(b"@version      0.3.7", bundle["hotdeal-focus.user.js"])
            overlay = json.loads(bundle["config/sites.json"])
            clien_layout = overlay["sites"][0]["layouts"][0]
            self.assertEqual("jirum", clien_layout["id"])
            self.assertEqual(
                proven["candidate"]["variantId"],
                clien_layout["variants"][0]["id"],
            )
            manifest = json.loads(bundle["candidate-manifest.json"])
            self.assertEqual("release-ready", manifest["status"])
            self.assertEqual(1, manifest["approvedVariantCount"])
            release_manifest = json.loads(bundle["release-manifest.json"])
            self.assertEqual(
                {"filter.txt", "hotdeal-focus.user.js"},
                set(release_manifest["artifacts"]),
            )
            materialized_config_path = temporary_root / "materialized-sites.json"
            materialized_config_path.write_bytes(bundle["config/sites.json"])
            normalized_overlay = load_config(materialized_config_path)
            self.assertEqual(
                bundle["filter-static.txt"],
                render_filter(normalized_overlay).encode("utf-8"),
            )
            rebuilt_manifest = render_materialized_release_manifest(
                overlay,
                gate_bytes=bundle["filter.txt"],
                static_bytes=bundle["filter-static.txt"],
                userscript_bytes=bundle["hotdeal-focus.user.js"],
                config_bytes=bundle["config/sites.json"],
                package_bytes=bundle["package.json"],
                package_lock_bytes=bundle["package-lock.json"],
                approved_state_bytes=bundle["state/approved-variants.json"],
            )
            self.assertEqual(bundle["release-manifest.json"], rebuilt_manifest)
            self.assertEqual(9, release_manifest["coverage"]["contractCount"])
            self.assertEqual(9, release_manifest["coverage"]["layoutFamilyCount"] + 1)
            self.assertEqual(13, release_manifest["coverage"]["routeCount"])
            same_route_rules = [
                line
                for line in bundle["filter-static.txt"].decode("utf-8").splitlines()
                if line.startswith(
                    "[$domain=clien.net,path=|/service/board/jirum/]#?#"
                )
            ]
            self.assertEqual(1, len(same_route_rules))
            normalized_clien = next(
                site for site in normalized_overlay["sites"] if site["id"] == "clien"
            )
            normalized_jirum = next(
                layout for layout in normalized_clien["layouts"] if layout["id"] == "jirum"
            )
            for selector in (
                normalized_jirum["preserve_deep"]
                + normalized_jirum["variants"][0]["preserve_deep"]
            ):
                self.assertIn(selector, same_route_rules[0])

            tampered_overlay = json.loads(bundle["config/sites.json"])
            tampered_overlay["sites"][0]["layouts"][0]["variants"][0]["id"] = (
                "auto-000000000000000000000000"
            )
            with self.assertRaisesRegex(ConfigError, "canonical deployment identity"):
                render_materialized_release_manifest(
                    tampered_overlay,
                    gate_bytes=bundle["filter.txt"],
                    static_bytes=bundle["filter-static.txt"],
                    userscript_bytes=bundle["hotdeal-focus.user.js"],
                    config_bytes=bundle["config/sites.json"],
                    package_bytes=bundle["package.json"],
                    package_lock_bytes=bundle["package-lock.json"],
                    approved_state_bytes=bundle["state/approved-variants.json"],
                )
            with self.assertRaisesRegex(ConfigError, "must match exactly"):
                render_materialized_release_manifest(
                    overlay,
                    gate_bytes=bundle["filter.txt"],
                    static_bytes=bundle["filter-static.txt"],
                    userscript_bytes=bundle["hotdeal-focus.user.js"],
                    config_bytes=bundle["config/sites.json"],
                    package_bytes=bundle["package.json"],
                    package_lock_bytes=bundle["package-lock.json"],
                    approved_state_bytes=b'{"schemaVersion":1,"variants":[]}',
                )

    def test_approved_state_is_append_only_and_release_version_is_monotonic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            _draft, first_bundle, first_proof = self.build_pair(
                temporary_root, "jirum-v2", "0.3.7"
            )
            state_path = temporary_root / "approved-variants.json"
            state_path.write_bytes(first_bundle["state/approved-variants.json"])
            second_draft = self.add_new_route(
                self.draft_envelope("jirum-v3", "0.3.8"),
                route_name="appenddeal",
                article_ids=(5001, 5002, 5003),
            )
            _draft, second_bundle, second_proof = self.build_envelope_pair(
                temporary_root,
                second_draft,
                state_path,
            )
            state = json.loads(second_bundle["state/approved-variants.json"])
            expected_ids = {
                first_proof["candidate"]["variantId"],
                second_proof["candidate"]["variantId"],
            }
            self.assertEqual(expected_ids, {item["variantId"] for item in state["variants"]})
            self.assertEqual({"0.3.7", "0.3.8"}, {item["releaseVersion"] for item in state["variants"]})
            second_config = json.loads(second_bundle["config/sites.json"])
            second_clien = next(
                site for site in second_config["sites"] if site["id"] == "clien"
            )
            second_layout = next(
                layout for layout in second_clien["layouts"] if layout["id"] == "jirum"
            )
            self.assertEqual(expected_ids, {variant["id"] for variant in second_layout["variants"]})
            compiled_ids = [
                layout["id"]
                for site in userscript_contracts(
                    second_bundle["hotdeal-focus.user.js"].decode("utf-8")
                )
                if site["id"] == "clien"
                for layout in site["layouts"]
                if layout["id"].startswith("jirum--auto-")
            ]
            self.assertEqual(
                {f"jirum--{variant_id}" for variant_id in expected_ids},
                set(compiled_ids),
            )
            second_manifest = json.loads(second_bundle["candidate-manifest.json"])
            self.assertEqual(second_proof["candidate"]["variantId"], second_manifest["variantId"])
            self.assertEqual(2, second_manifest["approvedVariantCount"])

            # After A is committed, its release version equals the new base version.
            # Loading the append-only state must recognize the exact materialized A
            # instead of treating it as stale and rediscovering it forever.
            first_materialized_config = json.loads(first_bundle["config/sites.json"])
            materialized_records = _load_approved_state(
                state_path, first_materialized_config
            )
            self.assertEqual(
                [first_proof["candidate"]["variantId"]],
                [item["variantId"] for item in materialized_records],
            )
            state_path.write_bytes(second_bundle["state/approved-variants.json"])
            next_run_records = _load_approved_state(state_path, second_config)
            self.assertEqual(expected_ids, {item["variantId"] for item in next_run_records})

            stale_draft = self.add_new_route(
                self.draft_envelope("jirum-v4", "0.3.8"),
                route_name="staleroute",
                article_ids=(6001, 6002, 6003),
            )
            stale_path = temporary_root / "stale.json"
            self.write_envelope(stale_path, stale_draft)
            with self.assertRaises(ConfigError):
                build_candidate_draft_bundle(stale_path, state_path)

    def test_new_route_requires_algumon_provenance_and_is_add_only(self) -> None:
        import copy

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            draft = self.add_new_route(self.draft_envelope("jirum-route-v2", "0.3.7"))
            draft_path = root / "route-draft.json"
            self.write_envelope(draft_path, draft)
            draft_bundle = build_candidate_draft_bundle(draft_path)
            rendered_gate = draft_bundle["filter.txt"].decode("utf-8")
            self.assertEqual(2, rendered_gate.count("[$domain=clien.net]"))
            overlay = json.loads(draft_bundle["config/sites.json"])
            clien_layout = overlay["sites"][0]["layouts"][0]
            self.assertEqual(["|/service/board/jirum/"], raw_layout_paths(clien_layout))
            self.assertEqual(
                ["|/service/board/newhotdeal/*^"],
                raw_layout_paths(clien_layout["variants"][0]),
            )
            self.assertEqual(
                ["jirum"],
                self.route_owners(
                    clien_layout,
                    "https://www.clien.net/service/board/jirum/19230509",
                ),
            )
            self.assertEqual(
                [f"jirum--{draft['candidate']['variantId']}"],
                self.route_owners(
                    clien_layout,
                    "https://www.clien.net/service/board/newhotdeal/3001",
                ),
            )
            rendered_static = draft_bundle["filter-static.txt"].decode("utf-8")
            self.assertEqual(render_filter(overlay), rendered_static)
            self.assertEqual(
                1,
                rendered_static.count(
                    "[$domain=clien.net,path=|/service/board/jirum/]#?#",
                ),
            )
            self.assertEqual(
                1,
                rendered_static.count(
                    "[$domain=clien.net,path=|/service/board/newhotdeal/*^]#?#",
                ),
            )

            mutations = {
                "missing proof": lambda value: value["discovery"].__setitem__("routeEvidence", []),
                "forged redirect": lambda value: value["discovery"]["routeEvidence"][0]["samples"][0].__setitem__("redirectChainSha256", "0" * 64),
                "overbroad mask": lambda value: (
                    value["candidate"].__setitem__("paths", ["|/*^"]),
                    value["discovery"]["routeEvidence"][0].__setitem__("canonicalPathPattern", "|/*^")
                ),
                "mixed approved and additive routes": lambda value: value[
                    "candidate"
                ].__setitem__(
                    "paths",
                    ["|/service/board/jirum/", "|/service/board/newhotdeal/*^"],
                ),
                "old-route proof": lambda value: value["discovery"]["routeEvidence"][0].__setitem__("canonicalPathPattern", "|/service/board/jirum/"),
            }
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    bad = copy.deepcopy(draft)
                    mutate(bad)
                    self.refresh_draft_hashes(bad)
                    path = root / f"route-bad-{len(label)}.json"
                    self.write_envelope(path, bad)
                    with self.assertRaises(ConfigError):
                        build_candidate_draft_bundle(path)

    def test_candidate_rejects_multiple_approved_paths(self) -> None:
        base_config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        clien_layout = base_config["sites"][0]["layouts"][0]
        original_path = clien_layout.pop("path")
        clien_layout["paths"] = [original_path, "|/service/board/usedmarket/"]
        base_bytes = (
            json.dumps(base_config, ensure_ascii=False, indent=2) + "\n"
        ).encode("utf-8")
        envelope = self.draft_envelope("jirum-multipath-v2", "0.3.6")
        envelope["baseConfigSha256"] = hashlib.sha256(base_bytes).hexdigest()
        envelope["candidate"]["paths"] = sorted(clien_layout["paths"])
        with self.assertRaisesRegex(ConfigError, "exactly one proven route"):
            _validate_candidate_payload(
                envelope,
                base_config,
                base_bytes,
                "0.3.5",
            )

    def test_candidate_rejects_noncanonical_variant_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            draft = self.draft_envelope("forged-id", "0.3.7")
            draft["candidate"]["variantId"] = "forged-manual-identity"
            path = root / "forged-id.json"
            self.write_envelope(path, draft)
            with self.assertRaisesRegex(ConfigError, "canonical deployment identity"):
                build_candidate_draft_bundle(path)

    def test_proof_profiles_do_not_change_runtime_variant_identity(self) -> None:
        payload = self.candidate_payload("temporary")
        full_profile_id = self.automatic_variant_id(payload)
        full_profile_hash = self.digest(payload)
        payload["proofProfiles"] = ["mobile"]
        self.assertEqual(full_profile_id, self.automatic_variant_id(payload))
        self.assertNotEqual(full_profile_hash, self.digest(payload))

    def test_sequential_same_dom_new_routes_keep_distinct_path_owners(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first = self.add_new_route(
                self.draft_envelope("temporary-first", "0.3.7"),
                route_name="newhotdeal",
                article_ids=(3001, 3002, 3003),
            )
            first["candidate"]["variantId"] = self.automatic_variant_id(
                first["candidate"]
            )
            self.refresh_draft_hashes(first)
            _draft, first_bundle, _proof = self.build_envelope_pair(root, first)
            state_path = root / "approved-variants.json"
            state_path.write_bytes(first_bundle["state/approved-variants.json"])

            second = self.add_new_route(
                self.draft_envelope("temporary-second", "0.3.8"),
                route_name="flashdeal",
                article_ids=(4001, 4002, 4003),
            )
            second["candidate"]["variantId"] = self.automatic_variant_id(
                second["candidate"]
            )
            self.refresh_draft_hashes(second)
            self.assertNotEqual(
                first["candidate"]["variantId"],
                second["candidate"]["variantId"],
            )
            _draft, second_bundle, _proof = self.build_envelope_pair(
                root,
                second,
                state_path,
            )

            state = json.loads(second_bundle["state/approved-variants.json"])
            self.assertEqual(2, len(state["variants"]))
            overlay = json.loads(second_bundle["config/sites.json"])
            clien_layout = overlay["sites"][0]["layouts"][0]
            self.assertEqual(["|/service/board/jirum/"], raw_layout_paths(clien_layout))
            self.assertEqual(
                {
                    "|/service/board/newhotdeal/*^",
                    "|/service/board/flashdeal/*^",
                },
                {
                    raw_layout_paths(variant)[0]
                    for variant in clien_layout["variants"]
                },
            )
            expected_owners = {
                "https://www.clien.net/service/board/jirum/19230509": ["jirum"],
                "https://www.clien.net/service/board/newhotdeal/3001": [
                    f"jirum--{first['candidate']['variantId']}"
                ],
                "https://www.clien.net/service/board/flashdeal/4001": [
                    f"jirum--{second['candidate']['variantId']}"
                ],
            }
            for url, owners in expected_owners.items():
                with self.subTest(url=url):
                    self.assertEqual(owners, self.route_owners(clien_layout, url))

    def test_profile_specific_mobile_variant_does_not_require_desktop_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            draft = self.draft_envelope("jirum-mobile-v2", "0.3.7")
            draft["candidate"]["proofProfiles"] = ["mobile"]
            observations = [
                item for item in draft["discovery"]["observations"]
                if item["profile"] == "mobile"
            ]
            draft["discovery"]["observations"] = observations
            self.refresh_draft_hashes(draft)
            path = root / "mobile-draft.json"
            self.write_envelope(path, draft)
            bundle = build_candidate_draft_bundle(path)
            contracts = userscript_contracts(
                bundle["hotdeal-focus.user.js"].decode("utf-8")
            )
            clien = next(site for site in contracts if site["id"] == "clien")
            variant = next(
                layout for layout in clien["layouts"]
                if layout["id"] == f"jirum--{draft['candidate']['variantId']}"
            )
            self.assertEqual(["desktop", "mobile"], variant["applicableProfiles"])
            self.assertEqual(["mobile"], variant["proofProfiles"])

    def test_unavailable_algumon_count_requires_independent_comment_structure(self) -> None:
        import copy

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            base = self.draft_envelope("jirum-structure-v2", "0.3.7")

            exact_empty = copy.deepcopy(base)
            for observation in exact_empty["discovery"]["observations"]:
                structure = observation["commentStructure"]
                structure["itemCount"] = 0
                structure["emptyStateSelector"] = structure["mountSelector"]
                structure["emptyStateCount"] = 1
            self.refresh_draft_hashes(exact_empty)
            exact_empty_path = root / "exact-empty.json"
            self.write_envelope(exact_empty_path, exact_empty)
            build_candidate_draft_bundle(exact_empty_path)

            forged_empty = copy.deepcopy(exact_empty)
            forged_empty["discovery"]["observations"][0]["commentStructure"][
                "emptyStateSelector"
            ] = ".forged-empty-message"
            self.refresh_draft_hashes(forged_empty)
            forged_empty_path = root / "forged-empty.json"
            self.write_envelope(forged_empty_path, forged_empty)
            with self.assertRaises(ConfigError):
                build_candidate_draft_bundle(forged_empty_path)

            mutations = {
                "fake neutral score": lambda observations: observations[0]["algumon"].__setitem__(
                    "countConsistency", 1.0
                ),
                "unclassified content": lambda observations: observations[0]["commentStructure"].__setitem__(
                    "unclassifiedContentCount", 1
                ),
                "only one nonempty per profile": lambda observations: [
                    structure.update(
                        {
                            "itemCount": 2 if index % 3 == 0 else 0,
                            "emptyStateSelector": None if index % 3 == 0 else structure["mountSelector"],
                            "emptyStateCount": 0 if index % 3 == 0 else 1,
                        }
                    )
                    for index, observation in enumerate(observations)
                    for structure in [observation["commentStructure"]]
                ],
            }
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    invalid = copy.deepcopy(base)
                    mutate(invalid["discovery"]["observations"])
                    self.refresh_draft_hashes(invalid)
                    invalid_path = root / f"invalid-{len(label)}.json"
                    self.write_envelope(invalid_path, invalid)
                    with self.assertRaises(ConfigError):
                        build_candidate_draft_bundle(invalid_path)

    def test_missing_or_forged_proof_dimensions_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            draft = self.draft_envelope("jirum-v2", "0.3.7")
            draft_path = root / "draft.json"
            self.write_envelope(draft_path, draft)
            draft_bundle = build_candidate_draft_bundle(draft_path)
            artifact_hash = json.loads(draft_bundle["draft-manifest.json"])["artifactSetSha256"]
            base_proven = self.proven_envelope(draft, artifact_hash)
            mutations = {
                "candidate hash": lambda value: value["proof"].__setitem__("candidateSha256", "0" * 64),
                "evidence hash": lambda value: value["proof"].__setitem__("evidenceSha256", "0" * 64),
                "draft bytes": lambda value: value["proof"].__setitem__("draftArtifactSetSha256", "0" * 64),
                "base config": lambda value: value.__setitem__("baseConfigSha256", "0" * 64),
                "profile coverage": lambda value: value["proof"]["observations"].__setitem__(
                    slice(None), [item for item in value["proof"]["observations"] if item["profile"] == "desktop"]
                ),
                "stale evidence": lambda value: value["proof"]["observations"][0].__setitem__(
                    "capturedAt", (datetime.now(timezone.utc) - timedelta(days=4)).strftime("%Y-%m-%dT%H:%M:%SZ")
                ),
                "role cardinality": lambda value: value["proof"]["observations"][0]["roles"]["body"].__setitem__("count", 2),
                "role containment": lambda value: value["proof"]["observations"][0]["roles"]["body"].__setitem__("containedInPageRoot", False),
                "algumon threshold": lambda value: value["proof"]["observations"][0]["algumon"].__setitem__("titleConsistency", 0.94),
                "algumon boolean": lambda value: value["proof"]["observations"][0]["algumon"].__setitem__("titleConsistencyOk", False),
                "metadata absent": lambda value: value["proof"]["observations"][0]["algumon"].update({
                    "titleMetadataSourceCount": 0,
                    "titleMetadataSourceKinds": [],
                }),
                "visible leak": lambda value: value["proof"]["observations"][0].__setitem__("visibleLeakCount", 1),
                "baseline exposure": lambda value: value["proof"]["observations"][0].__setitem__("baselineNoNewExposure", False),
                "fixture pass": lambda value: value["proof"]["observations"][0].__setitem__("fixturePassed", False),
                "live pass": lambda value: value["proof"]["observations"][0].__setitem__("livePassed", False),
                "selector stability": lambda value: value["proof"]["observations"][0].__setitem__("selectorStability", 0.9),
                "oracle world": lambda value: value["proof"]["observations"][0].__setitem__(
                    "oracleExecutionWorld", "main-world"
                ),
                "variant cardinality": lambda value: value["proof"]["observations"][0].__setitem__("approvedVariantCount", 2),
                "co-match": lambda value: value["proof"]["observations"][0].__setitem__("coMatchCount", 1),
            }
            import copy
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    candidate = copy.deepcopy(base_proven)
                    mutate(candidate)
                    path = root / f"bad-{len(label)}.json"
                    self.write_envelope(path, candidate)
                    with self.assertRaises(ConfigError):
                        build_candidate_bundle(path)


class FilterAndReleaseContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_config(CONFIG_PATH)

    def test_gate_is_marker_only_and_uses_official_prefix_modifiers(self) -> None:
        rendered = render_gate_filter(self.config)
        rules = [
            line for line in rendered.splitlines()
            if "#?#" in line or "#$#" in line
        ]
        domain_count = len({
            layout["domain"]
            for site in self.config["sites"]
            for layout in site["layouts"]
        })
        self.assertEqual(domain_count * 2, len(rules))
        for rule in rules:
            self.assertRegex(rule, r"^\[\$domain=[^,]+\]#(?:\?#|\$#)")
            self.assertNotIn(",path=", rule)
            self.assertNotIn("$path=", rule)
            self.assertNotRegex(
                rule,
                r"post_|article-body|view_content|comment_view|reply-list|app-article",
            )
        self.assertIn('data-hotdeal-focus-state="ready"', rendered)
        self.assertIn(f'data-hotdeal-focus-protocol="{PROTOCOL_VERSION}"', rendered)
        self.assertIn("visibility: hidden !important", rendered)
        self.assertIn("transition: none !important", rendered)
        self.assertIn("animation: none !important", rendered)
        self.assertIn("content-visibility: hidden !important", rendered)
        self.assertIn("opacity: 0 !important", rendered)
        self.assertIn("pointer-events: none !important", rendered)
        self.assertIn("clip-path: inset(50%) !important", rendered)
        self.assertIn('html[data-hotdeal-focus-lock="1"]', rendered)
        self.assertIn("dialog::backdrop", rendered)
        self.assertIn("[popover]::backdrop", rendered)
        self.assertIn(":fullscreen::backdrop", rendered)
        self.assertEqual(
            "! Title: AdGuard Hotdeal Focus Marker Gate",
            rendered.splitlines()[0],
        )
        self.assertNotIn("�", rendered.splitlines()[0])

    def test_gate_artifact_is_independent_from_semantic_release_versions(self) -> None:
        import copy

        original = render_gate_filter(self.config)
        future = copy.deepcopy(self.config)
        future["metadata"]["version"] = "999.999.999"
        self.assertEqual(original, render_gate_filter(future))
        self.assertIn(f"! Version: {GATE_ARTIFACT_VERSION}", original)
        self.assertEqual(
            GATE_FILTER_SUBSCRIPTION_URL,
            validate_gate_artifact_lock(original.encode("utf-8"))[0][
                "filterSubscriptionUrl"
            ],
        )
        with self.assertRaises(ConfigError):
            validate_gate_artifact_lock(original.replace("Clien", "Changed", 1).encode("utf-8"))

    def test_static_analysis_filter_uses_repeated_has_and_official_scope(self) -> None:
        rendered = render_filter(self.config)
        rules = [line for line in rendered.splitlines() if "#?#" in line]
        self.assertTrue(rules)
        for rule in rules:
            self.assertRegex(rule, r"^\[\$domain=[^,]+,path=\|/[^]]*\]#\?#")
            self.assertNotIn("$path=", rule)
        self.assertNotRegex(rendered, r":has\([^)]*,[^)]*\)")

    def test_release_manifest_is_deterministic_and_hashes_all_inputs(self) -> None:
        generated_one, manifest_one = render_release()
        generated_two, manifest_two = render_release()
        self.assertEqual(generated_one, generated_two)
        self.assertEqual(manifest_one, manifest_two)
        manifest = json.loads(manifest_one)
        self.assertNotIn("release-manifest.json", manifest["artifacts"])
        self.assertEqual(
            {"filter.txt", "hotdeal-focus.user.js"},
            set(manifest["artifacts"]),
        )
        gate_bytes = generated_one["filter.txt"]
        userscript_bytes = USERSCRIPT_PATH.read_bytes()
        gate_entry = manifest["artifacts"]["filter.txt"]
        userscript_entry = manifest["artifacts"]["hotdeal-focus.user.js"]
        self.assertEqual(
            installed_filter_rules_sha256(gate_bytes),
            gate_entry["installedRulesSha256"],
        )
        self.assertEqual(
            canonical_text_sha256(userscript_bytes),
            userscript_entry["canonicalTextSha256"],
        )
        self.assertNotEqual(
            userscript_entry["sha256"], userscript_entry["canonicalTextSha256"]
        )
        installed_rule_lines = [
            line
            for line in gate_bytes.decode("utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("!")
        ]
        self.assertEqual(14, len(installed_rule_lines))
        self.assertEqual(
            {
                "filter-static.txt",
                "config/sites.json",
                "config/gate-artifacts.json",
                "package.json",
                "package-lock.json",
                "tests/fixtures/dom-regressions.json",
                "tests/fixtures/behavior-baseline.json",
            },
            set(manifest["sourceIntegrity"]),
        )
        self.assertEqual(7, manifest["coverage"]["siteCount"])
        self.assertEqual(8, manifest["coverage"]["layoutCount"])
        self.assertGreaterEqual(manifest["coverage"]["routeCount"], 11)

    def test_build_check_rejects_tampered_expected_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_path = Path(temporary_directory) / "release-manifest.json"
            artifact_path.write_bytes(b"expected\n")
            self.assertTrue(check_outputs({artifact_path: b"expected\n"}))
            artifact_path.write_bytes(b"tampered\n")
            self.assertFalse(check_outputs({artifact_path: b"expected\n"}))

    def test_canonical_hash_contract_matches_installer_line_normalization(self) -> None:
        expected = canonical_text_sha256(b"alpha\nbeta")
        self.assertEqual(expected, canonical_text_sha256(b"\xef\xbb\xbfalpha\r\nbeta\r\n"))
        self.assertEqual(expected, canonical_text_sha256(b"alpha\rbeta\r"))


if __name__ == "__main__":
    unittest.main()
