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
    validate_config,
)
from build_release import (  # noqa: E402
    canonical_text_sha256,
    check_outputs,
    render_materialized_release_manifest,
    render_release,
)


USERSCRIPT_PATH = PROJECT_ROOT / "hotdeal-focus.user.js"
CONFIG_PATH = PROJECT_ROOT / "config" / "sites.json"
BASE_RELEASE_VERSION = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))["metadata"][
    "version"
]


def next_patch_version(version: str, increment: int = 1) -> str:
    major, minor, patch = (int(part) for part in version.split("."))
    return f"{major}.{minor}.{patch + increment}"


FIRST_CANDIDATE_VERSION = next_patch_version(BASE_RELEASE_VERSION)
SECOND_CANDIDATE_VERSION = next_patch_version(BASE_RELEASE_VERSION, 2)
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


def evaluate_navigation_identities(cases: list[dict]) -> list[dict]:
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
const results = cases.map((item) => ({
  sourceIdentity: api.articleIdentity(item.source, item.siteId),
  destinationIdentity: api.articleIdentity(item.destination, item.siteId),
  same: api.sameArticleNavigation(item.source, item.destination, item.siteId),
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


class UserscriptMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = userscript_text()

    def test_document_start_metadata_and_update_placeholders(self) -> None:
        self.assertEqual(
            ["GM_addElement", "window.onurlchange"],
            metadata_values(self.source, "grant"),
        )
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
        forbidden_patterns = {
            "dynamic code": r"\beval\s*\(|\bnew\s+Function\s*\(",
            "network request": r"\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\b|\bEventSource\b|sendBeacon\s*\(",
            "remote module": r"\bimport\s*\(|\brequire\s*\(",
        }
        for label, pattern in forbidden_patterns.items():
            with self.subTest(label=label):
                self.assertIsNone(re.search(pattern, self.source))

    def test_algumon_capture_uses_only_the_normal_user_navigation(self) -> None:
        javascript = r"""
const fs = require("fs");
const vm = require("vm");
const moduleRecord = { exports: {} };
const calls = { fetch: 0, xhr: 0, beacon: 0, domWrites: 0, prevented: 0 };
const listeners = {};
const documentRecord = {
  location: { href: "https://www.algumon.com/deals" },
  addEventListener(type, listener) { listeners[type] = listener; },
  createElement() { calls.domWrites += 1; return {}; },
};
let navigationName = "";
const browserRoot = {
  document: documentRecord,
  location: { hostname: "www.algumon.com" },
  crypto: {
    getRandomValues(words) {
      for (let index = 0; index < words.length; index += 1) words[index] = index + 1;
      return words;
    },
  },
  btoa(value) { return Buffer.from(value, "binary").toString("base64"); },
  atob(value) { return Buffer.from(value, "base64").toString("binary"); },
  fetch() { calls.fetch += 1; throw new Error("unexpected fetch"); },
  XMLHttpRequest: function unexpectedXhr() { calls.xhr += 1; },
  navigator: { sendBeacon() { calls.beacon += 1; return false; } },
  get name() { return navigationName; },
  set name(value) { navigationName = String(value); },
};
const sandbox = {
  module: moduleRecord, URL, Set, Map, WeakMap, WeakSet, Object, Array, String,
  Number, RegExp, JSON, Date, Math, encodeURIComponent, decodeURIComponent,
  escape, unescape, Uint32Array, Buffer,
};
vm.runInNewContext(fs.readFileSync("hotdeal-focus.user.js", "utf8"), sandbox);
const api = moduleRecord.exports;
api.start(browserRoot);
const title = { textContent: "Normal user navigation deal", getAttribute() { return null; } };
const card = {
  getAttribute(name) { return name === "data-site-type" ? "clien" : null; },
  querySelector(selector) {
    return selector.includes("data-title") ? title : null;
  },
  querySelectorAll() { return []; },
};
const anchor = {
  nodeType: 1,
  ownerDocument: documentRecord,
  textContent: "Normal user navigation deal",
  getAttribute(name) {
    if (name === "href") {
      return "https://www.algumon.com/l/d/123?v=" + "a".repeat(32) + "&t=" + Date.now();
    }
    return null;
  },
  closest(selector) { return selector === "a[href]" ? anchor : card; },
  setAttribute() { calls.domWrites += 1; },
  removeAttribute() { calls.domWrites += 1; },
};
listeners.click({
  type: "click", isTrusted: true, defaultPrevented: false, button: 0,
  ctrlKey: false, metaKey: false, shiftKey: false, altKey: false, target: anchor,
  preventDefault() { calls.prevented += 1; },
});
process.stdout.write(JSON.stringify({ calls, navigationName, listenerCount: Object.keys(listeners).length }));
"""
        completed = subprocess.run(
            ["node", "-e", javascript],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        result = json.loads(completed.stdout)
        self.assertEqual(3, result["listenerCount"])
        self.assertEqual(
            {"fetch": 0, "xhr": 0, "beacon": 0, "domWrites": 0, "prevented": 0},
            result["calls"],
        )
        self.assertTrue(result["navigationName"].startswith("hdf-provenance:"))
        capture = self.source[
            self.source.index("function installAlgumonSeedCapture"):
            self.source.index("function createRunNonce")
        ]
        for forbidden in (
            ".setAttribute(",
            ".removeAttribute(",
            ".appendChild(",
            "createNativeMutationObserver",
            "GM_addElement",
            "preventDefault",
            "stopImmediatePropagation",
            ".fetch(",
            "XMLHttpRequest",
            "sendBeacon",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, capture)

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
        self.assertIn('const PROTOCOL_VERSION = "2"', self.source)
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
        self.assertIn(
            "containsSemanticNoise(bodyNode, structuralNoiseCache, bodyIgnored)",
            resolver,
        )
        self.assertIn(
            "containsSemanticNoise(productNode, structuralNoiseCache, productIgnored)",
            resolver,
        )
        self.assertIn("!isRendered(commentMount)", resolver)
        self.assertIn("hiddenInitialItem", resolver)
        self.assertIn("commentDormantControls", resolver)
        self.assertIn('configuredProductCardinality !== "zero"', resolver)
        self.assertIn("configuredProductOrder", resolver)
        self.assertNotIn("selectTitle(document", resolver)
        self.assertNotIn("selectBody(document", resolver)
        self.assertNotIn("decideCandidate", resolver)
        self.assertNotIn("item-fingerprint", resolver)
        self.assertIn('"selector-hint"', self.source)
        self.assertIn("minIndependentSignals: 2", self.source)

    def test_ci_semantic_oracle_enumerates_unique_complete_projection_tuples(self) -> None:
        oracle = self.source[
            self.source.index("function titleProofFingerprint"):
            self.source.index("function lowestCommonAncestor")
        ]
        for required_contract in (
            "collapseProvenTitleWrappers",
            "MAX_PROJECTION_ROLE_CANDIDATES",
            "MAX_PROJECTION_TUPLES",
            "MAX_COMMENT_EVIDENCE",
            "validateProjectionTuple",
            "commentsAreExhaustive",
            "precomputeCommentEvidence",
            "semanticProductCardinality",
            "semanticProductOrder",
            '"ambiguous-disconnected-projections"',
            '"ambiguous-projection-tuples"',
            '"no-complete-projection-tuple"',
        ):
            self.assertIn(required_contract, oracle)
        self.assertIn("left.node.contains(right.node)", oracle)
        self.assertIn("leftProof === titleProofFingerprint(right)", oracle)
        self.assertIn("new Set(roleNodes).size !== roleNodes.length", oracle)
        self.assertIn("root === document.documentElement", oracle)
        self.assertIn("const observedProductCardinality", oracle)
        self.assertIn("function containsSemanticNoise", self.source)
        self.assertIn("MAX_PROJECTION_CANDIDATE_EVALUATIONS = 800", self.source)
        self.assertIn("collectBoundedCandidateElements", self.source)
        self.assertIn("const inferredCommentEvidenceCache = new WeakMap()", oracle)
        self.assertNotIn("commentPool.flatMap", oracle)
        self.assertNotIn("evidenceApproved.length !== 1", oracle)

    def test_semantic_product_observation_and_policy_proposal_are_independent(self) -> None:
        oracle = self.source[
            self.source.index("function discoverSemanticContract"):
            self.source.index("function lowestCommonAncestor")
        ]
        proposal = self.source[
            self.source.index("function buildPolicyProposal"):
            self.source.index("function failedSemanticContract")
        ]
        self.assertIn("selectProduct(document, layouts, title.node, body.node)", oracle)
        self.assertIn("const productChoices = [null].concat(productPool)", oracle)
        self.assertIn("observedProductCardinality", oracle)
        self.assertIn("existingProductPolicyCompatible", oracle)
        self.assertIn('source: "independent-projection-tuple"', proposal)
        self.assertIn('requiredProfilesSource: "auditor-layout-contract"', proposal)
        self.assertNotIn('requiredProfiles: Object.freeze(["desktop", "mobile"])', proposal)

    def test_exact_empty_comment_proof_and_control_diagnostics_are_self_contained(self) -> None:
        resolver = self.source[
            self.source.index("function resolveApprovedLayoutWithPublisherStyles"):
            self.source.index("function resolveProjectionClasses")
        ]
        diagnostics = self.source[
            self.source.index("function orderedCommentControls"):
            self.source.index("function applyRoleMarkers")
        ]
        self.assertIn('provenCommentCountSource = "exact-dom-zero"', resolver)
        self.assertIn("documentCommentEvidence.elements.length === 0", resolver)
        for field in (
            "selectors",
            "selectorDigest",
            "initiallyVisibleCount",
            "initiallyDormantCount",
            "projectionEpoch",
            "currentVisibleCount",
            "currentDormantApprovedCount",
            "currentShapeFingerprint",
            "currentProjectionValid",
        ):
            self.assertIn(field, diagnostics)

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

    def test_comment_rendering_is_a_live_fail_closed_invariant(self) -> None:
        verifier = self.source[
            self.source.index("function verifyOwnedState"):
            self.source.index("function publishDiagnostics")
        ]
        observer = self.source[
            self.source.index("function installIntegrityObserver"):
            self.source.index("function installNavigationRevalidation")
        ]
        self.assertIn("!isRendered(state.roles.comments)", verifier)
        self.assertIn("!isRendered(item)", verifier)
        self.assertIn("!isRendered(control)", verifier)
        self.assertIn("withPublisherVisibilityMeasurement(", observer)
        self.assertIn('if (!isRendered(added)) return "hidden-comment-addition"', observer)
        self.assertIn("if (additionFailure)", observer)
        self.assertIn("failureReason = additionFailure", observer)

    def test_known_comment_total_requires_all_individual_items_loaded(self) -> None:
        resolver = self.source[
            self.source.index("function resolveApprovedLayoutWithPublisherStyles"):
            self.source.index("function resolveProjectionClasses")
        ]
        verifier = self.source[
            self.source.index("function verifyOwnedStateWithPublisherStyles"):
            self.source.index("function paintLockSelectors")
        ]
        self.assertIn("commentItems.length < provenCommentCount", resolver)
        self.assertIn('reason: "partial-comment-set"', resolver)
        self.assertIn(
            "currentCommentItems.length !== state.acceptedCommentCount",
            verifier,
        )
        self.assertIn(
            "currentCommentItems.length < state.projectionPolicy.provenCommentCount",
            verifier,
        )
        self.assertIn("commitAuthorizedCommentCountIncrease", self.source)
        self.assertIn('failureReason = "comment-removal"', self.source)
        self.assertIn('failureReason = "comment-count"', self.source)
        self.assertIn("COMMENT_CONTINUATION_PATTERN", self.source)
        self.assertIn("isCommentContinuationControl", self.source)
        self.assertIn("hasVisibleCommentContinuationControl", resolver)
        self.assertIn('reason: "incomplete-comment-control"', resolver)
        self.assertIn("knownCommentTotal", resolver)

    def test_projection_noise_metadata_is_bounded_and_canonicalized(self) -> None:
        noise = self.source[
            self.source.index("function normalizeProjectionTokenText"):
            self.source.index("function collectJsonLd")
        ]
        self.assertIn("MAX_PROJECTION_METADATA_ATTRIBUTES = 64", self.source)
        self.assertIn("replace(/([a-z\\d])([A-Z])/g", noise)
        self.assertIn('name.startsWith("aria-")', noise)
        self.assertIn('name.startsWith("data-")', noise)
        self.assertIn("element.matches(interactiveSelector)", noise)
        self.assertIn("AD_NETWORK_RESOURCE_PATTERN", noise)
        self.assertIn("STRONG_NOISE_TOKEN_PATTERN", noise)

    def test_shadow_and_top_layer_guards_register_and_unsubscribe_native_events(self) -> None:
        native = self.source[
            self.source.index("const NATIVE = Object.freeze"):
            self.source.index("const CSSOM_MUTATION_LISTENERS")
        ]
        observer = self.source[
            self.source.index("function installIntegrityObserver"):
            self.source.index("function createReaderRuntime")
        ]
        stop = self.source[
            self.source.index("runtime.stop = function stopRuntime"):
            self.source.index("installBootstrapGuard", self.source.index("runtime.stop = function stopRuntime"))
        ]
        self.assertIn("EventTarget?.prototype?.addEventListener", native)
        self.assertIn("EventTarget?.prototype?.removeEventListener", native)
        self.assertIn('subscribe(document, "beforetoggle"', observer)
        self.assertIn('subscribe(document, "toggle"', observer)
        self.assertIn('subscribe(document, "fullscreenchange"', observer)
        self.assertIn('target?.matches?.("[popover], dialog")', observer)
        self.assertIn("NATIVE.removeEventListener", observer)
        self.assertIn("runtime.unsubscribeProjectionEvents", stop)
        self.assertIn("initializeShadowTracker", self.source)
        self.assertIn("containsUnprovenShadowBoundary", self.source)

    def test_publisher_visibility_measurement_keeps_the_root_no_paint(self) -> None:
        measurement = self.source[
            self.source.index("function withPublisherVisibilityMeasurement"):
            self.source.index("function semanticTokenText")
        ]
        self.assertIn('html.style.setProperty("opacity", "0", "important")', measurement)
        self.assertIn('html.style.setProperty("transition", "none", "important")', measurement)
        self.assertIn('html.style.setProperty("animation", "none", "important")', measurement)
        self.assertIn('html.style.setProperty("visibility", "hidden", "important")', measurement)
        self.assertIn("BOOTSTRAP_PUBLISHER_INLINE.get(html)?.visibility", measurement)
        self.assertIn("applyInlinePropertySnapshot(html, publisherVisibility)", measurement)
        self.assertIn("bootstrapEngineLockActive", measurement)
        self.assertIn("publisherInlineVisibilityHidden", measurement)
        self.assertIn('publisherRootStyle.visibility !== "visible"', measurement)
        self.assertIn(
            'html.style.setProperty("content-visibility", "hidden", "important")',
            measurement,
        )
        self.assertIn(
            'html.style.setProperty("clip-path", "inset(50%)", "important")',
            measurement,
        )
        self.assertIn("gateStyles[0].sheet.disabled", measurement)
        self.assertIn('rootStyle.clipPath !== "inset(50%)"', measurement)
        self.assertIn('rootStyle.transitionDuration !== "0s"', measurement)
        self.assertIn('rootStyle.animationName !== "none"', measurement)
        self.assertIn("gateSheet.disabled = true", measurement)
        self.assertIn("gateSheet.disabled = previouslyDisabled", measurement)
        self.assertIn(
            'current === element && /^(?:hidden|collapse)$/.test(style.visibility)',
            self.source,
        )
        self.assertIn("html.removeAttribute(ATTR.measure)", measurement)
        self.assertLess(
            measurement.index(
                'html.style.setProperty("content-visibility", "hidden", "important")'
            ),
            measurement.index("html.setAttribute(ATTR.measure, \"1\")"),
        )
        self.assertLess(
            measurement.index("html.setAttribute(ATTR.measure, \"1\")"),
            measurement.index("gateSheet.disabled = true"),
        )
        finally_start = measurement.index("} finally {")
        self.assertLess(
            measurement.index("gateSheet.disabled = previouslyDisabled", finally_start),
            measurement.index("html.removeAttribute(ATTR.measure)", finally_start),
        )

        stable_empty = self.source[
            self.source.index("function isStableZeroAreaCommentMount"):
            self.source.index("function withPublisherVisibilityMeasurement")
        ]
        self.assertIn("current === documentElement", stable_empty)
        self.assertIn("current.getAttribute(ATTR.measure) === \"1\"", stable_empty)
        self.assertIn("!measurementOpacity", stable_empty)

    def test_eomisae_reply_control_survives_both_static_projection_layers(self) -> None:
        eomisae = next(
            site for site in self.raw_config["sites"] if site["id"] == "eomisae"
        )
        layout = next(item for item in eomisae["layouts"] if item["id"] == "hotdeal")
        reply_selector = "#C_ > ._bd .reply"
        self.assertIn(reply_selector, layout["comment_contract"]["controls"])
        self.assertIn(reply_selector, layout["ancestor_markers"])
        self.assertIn(reply_selector, layout["preserve_deep"])

    def test_live_profile_specific_comment_contracts_are_exact(self) -> None:
        sites = {site["id"]: site for site in self.raw_config["sites"]}

        clien_comments = sites["clien"]["layouts"][0]["comment_contract"]
        self.assertIn(".post_comment > .comment-nav", clien_comments["controls"])
        self.assertIn(".post_comment .comment-more", clien_comments["controls"])
        self.assertIn(".post_comment > .comment-msg", clien_comments["ignored"])

        ruli = sites["ruliweb"]["layouts"][0]["comment_contract"]["items"]
        self.assertEqual(
            [".comment_view.normal > table.comment_table > tbody > tr.comment_element"],
            ruli,
        )

        quasar = {
            layout["id"]: layout for layout in sites["quasarzone"]["layouts"]
        }
        self.assertEqual(["desktop"], quasar["market"]["applicable_profiles"])
        self.assertEqual(".left-con-wrap", quasar["market"]["page_root"])
        self.assertEqual(
            ["#ajax-reply-list > li[id^='comment']"],
            quasar["market"]["comment_contract"]["items"],
        )
        self.assertEqual(["mobile"], quasar["market-mobile"]["applicable_profiles"])
        self.assertEqual("#con-body", quasar["market-mobile"]["page_root"])
        self.assertEqual(
            ["#ajax-reply-list > .commnet-main[id^='comment']"],
            quasar["market-mobile"]["comment_contract"]["items"],
        )

        arca_comments = sites["arcalive"]["layouts"][0]["comment_contract"]
        self.assertEqual(
            [".article-comment .comment-wrapper > .comment-item[id^='c_']"],
            arca_comments["items"],
        )
        self.assertIn(
            ".article-comment > .list-area > .newcomment-alert.fetch-comment",
            arca_comments["controls"],
        )
        self.assertEqual(
            {
                ".article-comment > .title",
                ".article-comment > .alert.alert-info",
            },
            set(arca_comments["ignored"]),
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
        self.assertIn('SEED_WINDOW_NAME_PREFIX = "hdf-provenance:"', self.source)
        self.assertIn("function encodeSeedCarrier", self.source)
        self.assertIn("function decodeSeedCarrier", self.source)
        self.assertIn("function readAndClearSeed", self.source)
        self.assertIn('document.addEventListener("auxclick"', self.source)
        self.assertIn('document.addEventListener("keydown"', self.source)
        self.assertIn('event.key === "Enter"', self.source)
        self.assertIn('browserRoot.name = ""', self.source)
        self.assertIn("staysInCurrentBrowsingContext", self.source)
        self.assertNotIn("event.preventDefault()", self.source[
            self.source.index("function installAlgumonSeedCapture"):
            self.source.index("function createRunNonce")
        ])
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

    def test_navigation_identity_normalizes_only_proven_approved_article_aliases(
        self,
    ) -> None:
        positive_cases = [
            {
                "id": "clien-www-to-mobile",
                "siteId": "clien",
                "source": "https://www.clien.net/service/board/jirum/19230509",
                "destination": "https://m.clien.net/service/board/jirum/19230509",
            },
            {
                "id": "ppomppu-desktop-to-mobile-route",
                "siteId": "ppomppu",
                "source": (
                    "https://www.ppomppu.co.kr/zboard/view.php?"
                    "id=ppomppu&no=554433"
                ),
                "destination": (
                    "https://m.ppomppu.co.kr/new/bbs_view.php?"
                    "id=ppomppu&no=554433"
                ),
            },
            {
                "id": "ruliweb-bbs-to-mobile",
                "siteId": "ruliweb",
                "source": "https://bbs.ruliweb.com/news/board/1020/read/105748",
                "destination": "https://m.ruliweb.com/news/board/1020/read/105748",
            },
            {
                "id": "clien-same-article-query-and-hash",
                "siteId": "clien",
                "source": "https://www.clien.net/service/board/jirum/19230509",
                "destination": (
                    "https://www.clien.net/service/board/jirum/19230509"
                    "?view=compact#comments"
                ),
            },
        ]
        for board in ("rt", "os", "fs"):
            positive_cases.append(
                {
                    "id": f"eomisae-index-to-{board}",
                    "siteId": "eomisae",
                    "source": (
                        "https://eomisae.co.kr/index.php?"
                        f"document_srl=778899&mid={board}"
                    ),
                    "destination": f"https://eomisae.co.kr/{board}/778899",
                }
            )
        positive_cases.append(
            {
                "id": "eomisae-unscoped-index-to-os",
                "siteId": "eomisae",
                "source": (
                    "https://eomisae.co.kr/index.php?document_srl=778899"
                ),
                "destination": "https://eomisae.co.kr/os/778899",
            }
        )

        for case, result in zip(
            positive_cases,
            evaluate_navigation_identities(positive_cases),
            strict=True,
        ):
            with self.subTest(case=case["id"]):
                self.assertTrue(result["sourceIdentity"], result)
                self.assertEqual(
                    result["sourceIdentity"], result["destinationIdentity"], result
                )
                self.assertTrue(result["same"], result)

    def test_navigation_identity_rejects_ambiguous_or_unapproved_urls(self) -> None:
        approved = "https://www.clien.net/service/board/jirum/19230509"
        negative_cases = [
            ("different-article", "clien", approved,
             "https://m.clien.net/service/board/jirum/19230510"),
            ("different-board", "clien", approved,
             "https://m.clien.net/service/board/news/19230509"),
            ("different-site", "clien", approved,
             "https://example.com/service/board/jirum/19230509"),
            ("http-scheme", "clien", approved,
             "http://www.clien.net/service/board/jirum/19230509"),
            ("credentials", "clien", approved,
             "https://user@www.clien.net/service/board/jirum/19230509"),
            ("port", "clien", approved,
             "https://www.clien.net:8443/service/board/jirum/19230509"),
            ("unapproved-route", "clien", approved,
             "https://www.clien.net/service/recommend/19230509"),
            (
                "duplicate-article-id",
                "ppomppu",
                "https://www.ppomppu.co.kr/zboard/view.php?id=ppomppu&no=554433",
                (
                    "https://m.ppomppu.co.kr/new/bbs_view.php?"
                    "id=ppomppu&no=554433&no=554434"
                ),
            ),
            (
                "eomisae-conflicting-document-id",
                "eomisae",
                "https://eomisae.co.kr/index.php?document_srl=778899&mid=rt",
                "https://eomisae.co.kr/rt/778899?document_srl=778900",
            ),
            (
                "eomisae-wrong-article-id",
                "eomisae",
                "https://eomisae.co.kr/rt/778899",
                "https://eomisae.co.kr/index.php?document_srl=778900",
            ),
            (
                "eomisae-duplicate-document-id",
                "eomisae",
                "https://eomisae.co.kr/rt/778899",
                (
                    "https://eomisae.co.kr/index.php?"
                    "document_srl=778899&document_srl=778900"
                ),
            ),
            (
                "ruliweb-different-board",
                "ruliweb",
                "https://bbs.ruliweb.com/news/board/1020/read/105748",
                "https://m.ruliweb.com/news/board/1021/read/105748",
            ),
        ]
        cases = [
            {
                "id": case_id,
                "siteId": site_id,
                "source": source,
                "destination": destination,
            }
            for case_id, site_id, source, destination in negative_cases
        ]
        for case, result in zip(
            cases, evaluate_navigation_identities(cases), strict=True
        ):
            with self.subTest(case=case["id"]):
                self.assertFalse(result["same"], result)

    def test_cascade_release_coalesces_pre_ready_mutations_without_weakening_budgets(
        self,
    ) -> None:
        cascade = self.source[
            self.source.index("function installCascadeGuard"):
            self.source.index("function installIntegrityObserver")
        ]
        self.assertIn("let fullScanRequired = true", cascade)
        pre_ready = cascade[
            cascade.index("const queueElement"):
            cascade.index("const exposesUnowned")
        ]
        self.assertLess(
            pre_ready.index('if (runtime.releasePhase !== "released")'),
            pre_ready.index("pendingElements.add(element)"),
        )
        self.assertIn("pendingElements.clear()", pre_ready)
        self.assertIn("fullScanRequired = true", pre_ready)
        self.assertIn("MAX_PENDING_ROOTS = 256", cascade)
        self.assertIn("pendingElements.size > MAX_PENDING_ROOTS", cascade)
        self.assertIn('runtime.enterTerminal("cascade-mutation-budget")', cascade)
        self.assertIn("MAX_BOUNDED_ELEMENTS = 20_000", cascade)
        self.assertIn("candidates.length > MAX_BOUNDED_ELEMENTS", cascade)
        self.assertIn('runtime.enterTerminal("cascade-scan-budget")', cascade)
        self.assertIn("runtime.prepareCascadeRelease", cascade)
        self.assertIn("runtime.verifyCascadeRelease", cascade)
        self.assertIn("runtime.verifyUnlockedCascadeRelease", cascade)
        release_verification = cascade[
            cascade.index("runtime.verifyCascadeRelease"):
            cascade.index("const verifyCascade")
        ]
        self.assertIn("if (fullScanRequired)", release_verification)
        self.assertIn("releaseCandidates = collectBoundedFullScan()", release_verification)
        self.assertIn("exposesUnowned(releaseCandidates)", release_verification)

        attempt = self.source[
            self.source.index("function attemptResolution"):
            self.source.index("function scheduleAttempt")
        ]
        prepare = attempt.index("runtime.prepareCascadeRelease()")
        authorize = attempt.index("runtime.authorizedReady = true")
        unlock = attempt.index("removeAttribute(ATTR.lock)")
        ready = attempt.index('setAttribute(ATTR.ready, "1")')
        ready_class = attempt.index("classList.add(CLASS.ready)")
        proof = attempt.index("return proveStandaloneCascadeRelease(")
        release_callback = attempt.index("function releaseProvedProjection()")
        phase_released = attempt.index('runtime.releasePhase = "released"')
        self.assertLess(prepare, authorize)
        self.assertLess(authorize, ready)
        self.assertLess(ready, ready_class)
        self.assertLess(ready_class, proof)
        self.assertLess(proof, release_callback)
        self.assertLess(release_callback, phase_released)
        self.assertLess(phase_released, unlock)
        unlocked_proof = attempt.index("runtime.verifyUnlockedCascadeRelease()")
        integrity_observer = attempt.index("installIntegrityObserver(")
        self.assertLess(unlock, unlocked_proof)
        self.assertLess(unlocked_proof, integrity_observer)

        unlocked_verification = cascade[
            cascade.index("runtime.verifyUnlockedCascadeRelease"):
            cascade.index("const verifyCascade")
        ]
        self.assertIn("collectBoundedFullScan()", unlocked_verification)
        self.assertIn("verifyOwnedState(document, runtime.projectionState)", unlocked_verification)
        self.assertIn("exposesRootPaint()", unlocked_verification)
        self.assertIn("exposesTopLayer()", unlocked_verification)
        self.assertIn("exposesUnowned(releaseCandidates)", unlocked_verification)
        self.assertIn('runtime.enterTerminal("cascade-visible-leak")', unlocked_verification)

        release_proof = self.source[
            self.source.index("function proveStandaloneCascadeRelease"):
            self.source.index("function installIntegrityObserver")
        ]
        self.assertIn("CASCADE_PROOF_FRAMES = 2", self.source)
        self.assertIn("runtime.verifyCascadeRelease(cascadeSnapshot)", release_proof)
        self.assertIn('probe.style.getPropertyValue("display") === "block"', release_proof)
        self.assertIn('probe.style.getPropertyPriority("display") === ""', release_proof)
        self.assertIn('computed.getPropertyValue("--hdf-v2-cascade-proof")', release_proof)
        self.assertIn('computed.display === "none"', release_proof)
        self.assertNotIn("extendedCss", release_proof)

        activation = self.source[
            self.source.index("function activateCurrentLocation"):
            self.source.index("activateCurrentLocation();")
        ]
        same_identity_return = activation.index("if (!isInitialActivation)")
        runtime_stop = activation.index("activeRuntime.stop()")
        self.assertLess(same_identity_return, runtime_stop)
        self.assertIn('terminalNavigationBlock("navigation-identity")', activation)

    def test_post_ready_changes_relock_or_terminal_by_mutation_class(self) -> None:
        runtime = self.source[
            self.source.index("function createReaderRuntime"):
            self.source.index("function lockWhenHtmlExists")
        ]
        relock = runtime[
            runtime.index("runtime.relockForReprojection"):
            runtime.index("function attemptResolution")
        ]
        self.assertIn('runtime.releasePhase = "relocking"', relock)
        self.assertIn('document.documentElement.classList.add(CLASS.lock)', relock)
        self.assertIn('document.documentElement.setAttribute(ATTR.lock, "1")', relock)
        self.assertIn("writeRuntimeGateStyle(styleElement, null, runtime)", relock)
        self.assertIn("clearProtocolState(document)", relock)
        self.assertIn("claimBootstrapLock(document, false)", relock)
        self.assertIn("runtime.beginDiscovery()", relock)
        self.assertLess(
            relock.index('document.documentElement.classList.add(CLASS.lock)'),
            relock.index("writeRuntimeGateStyle(styleElement, null, runtime)"),
        )
        self.assertLess(
            relock.index("writeRuntimeGateStyle(styleElement, null, runtime)"),
            relock.index("clearProtocolState(document)"),
        )
        self.assertLess(
            relock.index("clearProtocolState(document)"),
            relock.index("runtime.beginDiscovery()"),
        )

        cascade = self.source[
            self.source.index("function installCascadeGuard"):
            self.source.index("function proveStandaloneCascadeRelease")
        ]
        mutation_guard = cascade[
            cascade.index("function keepGateStyleLast"):
            cascade.index("let stylesheetChanged")
        ]
        self.assertIn('runtime.releasePhase === "released"', mutation_guard)
        self.assertIn("runtime.relockForReprojection(", mutation_guard)
        self.assertIn('"post-ready-stylesheet"', mutation_guard)
        self.assertIn('"post-ready-dom"', mutation_guard)
        self.assertIn('"post-ready-cssom"', cascade)
        self.assertIn("subscribeAdoptedStyleSheetMutations", cascade)
        self.assertIn('"post-ready-adopted-stylesheet"', cascade)
        self.assertIn("subscribeStyleSheetStateMutations", cascade)
        self.assertIn('"post-ready-stylesheet-state"', cascade)
        self.assertIn("runtime.discardCascadeRecords", cascade)
        self.assertIn('"open", "popover"', cascade)

        integrity = self.source[
            self.source.index("function installIntegrityObserver"):
            self.source.index("function createReaderRuntime")
        ]
        self.assertIn("COMMENT_CONTROL_STATE_ATTRIBUTES.has(name)", integrity)
        self.assertIn("commentProjectionChanged = true", integrity)
        self.assertIn("terminalBlock(failureReason)", integrity)
        self.assertIn('runtime.enterTerminal("role-projection-top-layer-activation")', integrity)

        navigation = self.source[
            self.source.index("function activateCurrentLocation"):
            self.source.index("activateCurrentLocation();")
        ]
        self.assertIn(
            'activeRuntime.relockForReprojection("same-article-navigation")',
            navigation,
        )
        self.assertIn("characterData: true", runtime)
        self.assertIn("attributes: true", runtime)

        resolver = self.source[
            self.source.index("function resolveApprovedLayoutWithPublisherStyles"):
            self.source.index("function resolveProjectionClasses")
        ]
        self.assertIn("hasVisibleCommentContinuationControl(commentControls)", resolver)
        self.assertIn('reason: "incomplete-comment-control"', resolver)

        stylesheet = self.source[
            self.source.index("function gateStyleText"):
            self.source.index("function installRuntimeGateStyle")
        ]
        self.assertIn(
            '${owned}.${CLASS.deep}[${ATTR.deep}]',
            stylesheet,
        )
        self.assertIn(
            '${owned}.${roleClass("comment-item")}',
            stylesheet,
        )

    def test_first_terminal_navigation_reason_is_immutable(self) -> None:
        start = self.source[
            self.source.index("function start(browserRoot)"):
            self.source.index('return { mode: "reader-gate"')
        ]
        terminal = start[
            start.index("function terminalNavigationBlock"):
            start.index("function activateCurrentLocation")
        ]
        self.assertIn("let navigationTerminalReason = null", start)
        self.assertIn("if (navigationTerminallyBlocked)", terminal)
        self.assertIn("return false", terminal)
        self.assertIn('navigationTerminalReason = reason || "blocked"', terminal)
        activation_prefix = start[
            start.index("function activateCurrentLocation"):
            start.index("if (activeRuntime && activeRuntime.terminallyBlocked)")
        ]
        self.assertIn("if (navigationTerminallyBlocked)", activation_prefix)
        self.assertNotIn("terminalNavigationBlock", activation_prefix)

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
            {
                "id": "quasar-publisher-payment-expansion",
                "algumon": "사파이어 9060 XT PULSE 16GB 외 9070XT NITRO+ 등 이엠텍 기획전",
                "visible": "[SSG] 사파이어 9060 XT PULSE 16GB 외 9070XT NITRO+ 등 이엠텍 기획전 (비씨)",
                "metadata": {
                    "og": ["[SSG] 사파이어 9060 XT PULSE 16GB 외 9070XT NITRO+ 등 이엠텍 기획전 (비씨)"]
                },
                "core_ok": True,
                "evidence_ok": True,
            },
            {
                "id": "clien-bounded-quantity-price-expansion",
                "algumon": "할리스 시그니처 아메리카노 550ml",
                "visible": "선착순) 할리스 시그니처 아메리카노 550ml 12개 8000원",
                "metadata": {
                    "og": ["선착순) 할리스 시그니처 아메리카노 550ml 12개 8000원"]
                },
                "core_ok": True,
                "evidence_ok": True,
            },
            {
                "id": "ruliweb-composite-console-model-expansion",
                "algumon": "PS5 타츠진 익스트림 예약 판매",
                "visible": "겜우리 PS5NS2 타츠진 익스트림 예약 판매 49500원",
                "metadata": {
                    "og": ["겜우리 PS5NS2 타츠진 익스트림 예약 판매 49500원"]
                },
                "core_ok": True,
                "evidence_ok": True,
            },
            {
                "id": "eomisae-korean-number-boundary-expansion",
                "algumon": "배달의민족 2만원권",
                "visible": "배달의민족2만원권 18,400원",
                "metadata": {"og": ["배달의민족2만원권 18,400원 - 기타정보 - 어미새"]},
                "core_ok": True,
                "evidence_ok": True,
            },
            {
                "id": "ruliweb-model-delimiter-metadata-equivalence",
                "algumon": "PS5 타츠진 익스트림 예약 판매",
                "visible": "[겜우리] PS5/NS2 타츠진 익스트림 예약 판매 / 49,500원",
                "metadata": {
                    "og": ["겜우리 PS5NS2 타츠진 익스트림 예약 판매 49500원"],
                    "twitter": ["겜우리 PS5NS2 타츠진 익스트림 예약 판매 49500원"],
                    "schema": ["[겜우리] PS5/NS2 타츠진 익스트림 예약 판매 / 49,500원"],
                },
                "core_ok": True,
                "evidence_ok": True,
            },
            {
                "id": "ruliweb-bounded-store-token-reorder",
                "algumon": "GS25 보먹돼 1Kg 우리카드 할인",
                "visible": "[우리동네GS] 보먹돼 GS25 픽업 1Kg 우리카드 할인 (9,900/0)",
                "metadata": {
                    "og": ["우리동네GS 보먹돼 GS25 픽업 1Kg 우리카드 할인 99000"],
                    "twitter": ["우리동네GS 보먹돼 GS25 픽업 1Kg 우리카드 할인 99000"],
                    "schema": ["[우리동네GS] 보먹돼 GS25 픽업 1Kg 우리카드 할인 (9,900/0)"],
                },
                "core_ok": True,
                "evidence_ok": True,
            },
            {
                "id": "eomisae-bounded-unit-price-expansion",
                "algumon": "더바디샵 바디 미스트, 핑크 그레이프 프룻",
                "visible": "국내 더바디샵 바디 미스트, 핑크 그레이프 프룻, 100ml, 11,760원",
                "metadata": {
                    "og": ["더바디샵 바디 미스트, 핑크 그레이프 프룻, 100ml, 11,760원 - 기타정보 - 어미새"],
                    "twitter": ["더바디샵 바디 미스트, 핑크 그레이프 프룻, 100ml, 11,760원 - 기타정보 - 어미새"],
                    "schema": ["더바디샵 바디 미스트, 핑크 그레이프 프룻, 100ml, 11,760원"],
                },
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
            (
                "사파이어 9060 XT PULSE 16GB 외 9070XT NITRO+ 등 이엠텍 기획전",
                "[SSG] 사파이어 9600 XT PULSE 16GB 외 9070XT NITRO+ 등 이엠텍 기획전 (비씨)",
            ),
            (
                "할리스 시그니처 아메리카노 550ml",
                "선착순) 할리스 시그니처 아메리카노 500ml 12개 8000원",
            ),
            (
                "PS5 타츠진 익스트림 예약 판매",
                "겜우리 PS4NS2 타츠진 익스트림 예약 판매 49500원",
            ),
            ("배달의민족 2만원권", "배달의민족3만원권 18,400원"),
            (
                "GS25 보먹돼 1Kg 우리카드 할인",
                "[우리동네GS] 보먹돼 GS25 픽업 2Kg 우리카드 할인 (9,900/0)",
            ),
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
        cases.append(
            {
                "algumon": "PS5 타츠진 익스트림 예약 판매",
                "visible": "[겜우리] PS5/NS2 타츠진 익스트림 예약 판매 / 49,500원",
                "metadata": {
                    "og": ["겜우리 PS4NS2 타츠진 익스트림 예약 판매 49500원"],
                    "schema": ["[겜우리] PS5/NS2 타츠진 익스트림 예약 판매 / 49,500원"],
                },
            }
        )
        for index, result in enumerate(evaluate_title_cases(cases)):
            with self.subTest(case=index):
                self.assertFalse(result["evidence"]["ok"])

    def test_seed_validation_preserves_protected_title_punctuation(self) -> None:
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
const now = 1784532000000;
const rawTitle = "Synthetic PS5/NS2 marker-style-tamper";
const seed = api.validateSeed({
  v: 1,
  siteType: "clien",
  dealId: "99999000",
  title: rawTitle,
  commentCount: null,
  ts: now,
  relayV: "0".repeat(32),
  relayT: String(now),
  navigationNonce: `hdf-${"a".repeat(28)}`,
  destinationUrl: "https://www.clien.net/service/board/jirum/99999000",
}, now, true);
const carrierSeed = api.validateSeed({
  v: 1,
  siteType: "clien",
  dealId: "99999000",
  title: rawTitle,
  commentCount: null,
  ts: now,
  relayV: "0".repeat(32),
  relayT: String(now),
  navigationNonce: `hdf-${"a".repeat(28)}`,
}, now, true);
process.stdout.write(JSON.stringify({
  title: seed?.title ?? null,
  evidence: seed ? api.titleConsistency(seed.title, rawTitle) : null,
  carrierNavigation: Boolean(carrierSeed?.navigationNonce) && carrierSeed.destinationUrl === null,
}));
"""
        completed = subprocess.run(
            ["node", "-e", javascript],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        result = json.loads(completed.stdout)
        self.assertEqual("Synthetic PS5/NS2 marker-style-tamper", result["title"])
        self.assertTrue(result["evidence"]["ok"], result)
        self.assertTrue(result["carrierNavigation"], result)

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
            '"urlchange"',
            '"hashchange"',
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
        self.assertIn("runtimeGateStyleFailure", bootstrap)
        self.assertIn("runtime.releasePhase", bootstrap)
        self.assertIn("rootShapeIntact", bootstrap)
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
        navigation_guard = self.source[
            self.source.index("function installNavigationRevalidation"):
            self.source.index("function start(browserRoot)")
        ]
        self.assertIn('["urlchange", revalidate, true]', navigation_guard)
        self.assertIn('["hashchange", revalidate, true]', navigation_guard)
        self.assertIn("urlchange event remains the authoritative SPA trigger", navigation_guard)
        self.assertIn("return true", navigation_guard)

        terminal_guardian = self.source[
            self.source.index("function installPersistentTerminalGuardian"):
            self.source.index("function publishDiagnostics")
        ]
        self.assertIn(
            'html.style.getPropertyValue("opacity") !== "0"',
            terminal_guardian,
        )
        self.assertIn(
            'html.style.getPropertyValue("pointer-events") !== "none"',
            terminal_guardian,
        )
        self.assertIn("styleElement?.sheet?.disabled", terminal_guardian)
        self.assertIn("styleElement.sheet.disabled = false", terminal_guardian)
        self.assertIn("html.removeAttribute(ATTR.measure)", terminal_guardian)
        for exact_terminal_lock in (
            'html.style.getPropertyValue("transition") !== "none"',
            'html.style.getPropertyValue("animation") !== "none"',
            'html.style.getPropertyValue("content-visibility") !== "hidden"',
            'html.style.getPropertyValue("clip-path") !== "inset(50%)"',
            'html.style.getPropertyValue("caret-color") !== "transparent"',
        ):
            self.assertIn(exact_terminal_lock, terminal_guardian)

    def test_runtime_projection_is_nonce_bound_and_ready_is_committed_last(self) -> None:
        style = self.source[
            self.source.index("function paintLockSelectors"):
            self.source.index("function installRuntimeGateStyle")
        ]
        self.assertIn(
            'const owned = `.${CLASS.keep}[${ATTR.keep}="${nonce}"]`', style
        )
        self.assertIn(
            'const shell = `.${CLASS.shell}[${ATTR.shell}="${nonce}"]`', style
        )
        self.assertNotIn(":not([${ATTR.keep}])", style)
        for paint_lock in (
            "transition: none !important",
            "animation: none !important",
            "visibility: hidden !important",
            "content-visibility: hidden !important",
            "opacity: 0 !important",
            "clip-path: inset(50%) !important",
            "pointer-events: none !important",
            "dialog::backdrop",
            "[popover]::backdrop",
            ":fullscreen::backdrop",
        ):
            self.assertIn(paint_lock, style)
        lock_rule = style.split("if (!nonce)", 1)[0]
        for geometry_breaker in (
            "display: none !important",
        ):
            self.assertNotIn(geometry_breaker, lock_rule)
        attempt = self.source[
            self.source.index("function attemptResolution"):
            self.source.index("function scheduleAttempt")
        ]
        self.assertLess(
            attempt.index("writeRuntimeGateStyle(styleElement, nonce, runtime)"),
            attempt.index('setAttribute(ATTR.ready, "1")'),
        )
        self.assertLess(
            attempt.index('setAttribute(ATTR.ready, "1")'),
            attempt.index("classList.add(CLASS.ready)"),
        )
        self.assertLess(
            attempt.index("classList.add(CLASS.ready)"),
            attempt.index("proveStandaloneCascadeRelease("),
        )

    def test_reader_gate_v2_uses_only_standalone_gm_style_authority(self) -> None:
        self.assertEqual(
            ["GM_addElement", "window.onurlchange"],
            metadata_values(self.source, "grant"),
        )
        self.assertEqual(1, self.source.count('GM_addElement(parent, "style", {'))
        install = self.source[
            self.source.index("function installRuntimeGateStyle"):
            self.source.index("function canonicalRuntimeCssRules")
        ]
        self.assertIn('"data-hotdeal-focus-runtime-style": "2"', install)
        self.assertNotIn("createElement", install)
        self.assertNotIn('"nonce"', install)
        self.assertNotIn('"data-source"', install)

        integrity = self.source[
            self.source.index("function runtimeGateStyleIntact"):
            self.source.index("function installPersistentTerminalGuardian")
        ]
        proof = self.source[
            self.source.index("function proveStandaloneCascadeRelease"):
            self.source.index("function installIntegrityObserver")
        ]
        for section in (integrity, proof):
            self.assertNotRegex(
                section,
                r'getAttribute\(["\'](?:nonce|data-source)["\']\)',
            )
        self.assertNotIn('styleElement.hasAttribute("nonce")', proof)
        self.assertNotIn('styleElement.hasAttribute("data-source")', proof)
        self.assertIn('authority: "userscript-runtime-style"', proof)
        self.assertIn('computed.getPropertyValue("--hdf-v2-cascade-proof")', proof)
        self.assertIn("inlineStateIntact", proof)
        diagnostics = self.source[
            self.source.index("function publishDiagnostics"):
            self.source.index("function structuralRoleDiagnostics")
        ]
        self.assertIn("standaloneCascadeProof: details.standaloneCascadeProof", diagnostics)

        audit_source = (SCRIPTS_DIR / "audit_pages.mjs").read_text(encoding="utf-8")
        control_source = (SCRIPTS_DIR / "preauthorized_adguard_control.mjs").read_text(
            encoding="utf-8"
        )
        oracle_source = (PROJECT_ROOT / "tests" / "test_projection_tuple_oracle.mjs").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("bypassCSP", audit_source)
        self.assertIn(
            'CONTROL_KIND = "preauthorized-userscript-style-control"',
            control_source,
        )
        self.assertNotIn("extendedCssCallbacks", control_source)
        self.assertNotIn("data-hdf-v2-release-probe", control_source)
        self.assertNotIn("build_gate_filter.py", oracle_source)
        self.assertNotIn("adguardGateCss", oracle_source)
        self.assertNotIn('document.body?.querySelectorAll("*")', control_source)

    def test_reader_gate_v2_bootstrap_and_release_order_are_fail_closed(self) -> None:
        bootstrap = self.source[
            self.source.index("function claimBootstrapLock"):
            self.source.index("function orderedCommentControls")
        ]
        strip = bootstrap.index("removePublisherHdfMarkers(document)")
        lock_class = bootstrap.index("html.classList.add(CLASS.lock)")
        lock_attribute = bootstrap.index('html.setAttribute(ATTR.lock, "1")')
        self.assertLess(strip, lock_class)
        self.assertLess(lock_class, lock_attribute)
        self.assertIn("HDF_ATTRIBUTE_PREFIX", self.source)
        self.assertIn("HDF_CLASS_PATTERN", self.source)
        self.assertIn('["clip-path", BOOTSTRAP_INLINE_LOCK.clipPath]', bootstrap)
        self.assertIn(
            '["content-visibility", BOOTSTRAP_INLINE_LOCK.contentVisibility]',
            bootstrap,
        )
        self.assertIn('["visibility", BOOTSTRAP_INLINE_LOCK.visibility]', bootstrap)

        attempt = self.source[
            self.source.index("function attemptResolution"):
            self.source.index("function scheduleAttempt")
        ]
        marker = attempt.index("applyRoleMarkers(")
        ready_protocol = attempt.index("setAttribute(ATTR.protocol, PROTOCOL_VERSION)")
        ready_class = attempt.index("classList.add(CLASS.ready)")
        remove_lock_attribute = attempt.index("removeAttribute(ATTR.lock)")
        remove_lock_class = attempt.index("classList.remove(CLASS.lock)")
        self.assertLess(marker, ready_protocol)
        self.assertLess(ready_protocol, ready_class)
        self.assertLess(ready_class, remove_lock_attribute)
        self.assertLess(remove_lock_attribute, remove_lock_class)
        self.assertEqual(
            remove_lock_class,
            attempt.rindex("classList.remove(CLASS.lock)"),
        )

    def test_release_probe_is_cleaned_on_terminal_stop_and_spa_revalidation(self) -> None:
        self.assertIn("releaseProbe: null", self.source)
        cleanup = "if (runtime.releaseProbe?.isConnected) runtime.releaseProbe.remove();"
        self.assertGreaterEqual(self.source.count(cleanup), 2)
        navigation = self.source[
            self.source.index("function activateCurrentLocation"):
            self.source.index("installNavigationRevalidation", self.source.index("function activateCurrentLocation"))
        ]
        self.assertIn("activeRuntime.stop()", navigation)
        self.assertIn("html.classList.remove(CLASS.ready)", navigation)

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
            for url_index, url in enumerate(payload["sampleUrls"]):
                product_projection = payload["roleProjection"]["product"]
                configured_cardinality = product_projection["cardinality"]
                observed_cardinality = (
                    "required"
                    if configured_cardinality == "required"
                    or (configured_cardinality == "optional" and url_index < 2)
                    else "zero"
                )
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
                    "productObservation": {
                        "cardinality": observed_cardinality,
                        "selector": (
                            product_projection["selectors"][0]
                            if observed_cardinality == "required"
                            else None
                        ),
                        "count": 1 if observed_cardinality == "required" else 0,
                        "order": (
                            product_projection["order"]
                            if observed_cardinality == "required"
                            else None
                        ),
                    },
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
            "protocolVersion": 2,
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

    def configure_product_cardinality(self, draft: dict, cardinality: str) -> None:
        payload = draft["candidate"]
        if cardinality == "required":
            payload["requiredRoles"] = sorted(
                set(payload["requiredRoles"]) | {"product"}
            )
            payload["roles"]["product"] = [".product_v2"]
            product_projection = {
                "mode": "atomic-boundary",
                "cardinality": "required",
                "order": "before-body",
                "selectors": [".product_v2"],
                "ignored": [],
            }
        elif cardinality == "optional":
            payload["requiredRoles"] = [
                role for role in payload["requiredRoles"] if role != "product"
            ]
            payload["roles"].pop("product", None)
            product_projection = {
                "mode": "atomic-boundary",
                "cardinality": "optional",
                "order": "before-body",
                "selectors": [".product_v2"],
                "ignored": [],
            }
        elif cardinality == "zero":
            payload["requiredRoles"] = [
                role for role in payload["requiredRoles"] if role != "product"
            ]
            payload["roles"].pop("product", None)
            product_projection = {
                "mode": "absent",
                "cardinality": "zero",
                "selectors": [],
                "ignored": [],
            }
        else:
            raise AssertionError(f"unsupported test cardinality: {cardinality}")
        payload["roleProjection"]["product"] = product_projection
        payload["variantId"] = self.automatic_variant_id(payload)
        draft["discovery"]["observations"] = self.observations(payload, final=False)
        self.refresh_draft_hashes(draft)

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

    def test_independent_product_observations_derive_candidate_cardinality(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            for offset, cardinality in enumerate(("zero", "required", "optional"), start=1):
                draft = self.draft_envelope(
                    f"product-{cardinality}",
                    next_patch_version(BASE_RELEASE_VERSION, 20 + offset),
                )
                self.configure_product_cardinality(draft, cardinality)
                path = temporary_root / f"{cardinality}.json"
                self.write_envelope(path, draft)
                build_candidate_draft_bundle(path)

            mismatched = self.draft_envelope(
                "product-mismatched",
                next_patch_version(BASE_RELEASE_VERSION, 30),
            )
            self.configure_product_cardinality(mismatched, "optional")
            for observation in mismatched["discovery"]["observations"]:
                observation["productObservation"] = {
                    "cardinality": "required",
                    "selector": ".product_v2",
                    "count": 1,
                    "order": "before-body",
                }
            self.refresh_draft_hashes(mismatched)
            mismatched_path = temporary_root / "mismatched.json"
            self.write_envelope(mismatched_path, mismatched)
            with self.assertRaisesRegex(
                ConfigError,
                "product cardinality must equal the independent product observations",
            ):
                build_candidate_draft_bundle(mismatched_path)

            malformed_zero = self.draft_envelope(
                "product-malformed-zero",
                next_patch_version(BASE_RELEASE_VERSION, 31),
            )
            first_observation = malformed_zero["discovery"]["observations"][0]
            first_observation["productObservation"]["selector"] = ".forged-product"
            self.refresh_draft_hashes(malformed_zero)
            malformed_path = temporary_root / "malformed-zero.json"
            self.write_envelope(malformed_path, malformed_zero)
            with self.assertRaisesRegex(
                ConfigError,
                "selector must be null for zero cardinality",
            ):
                build_candidate_draft_bundle(malformed_path)

    def test_candidate_protocol_v1_cannot_enter_the_v2_reader_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            draft = self.draft_envelope(
                "legacy-protocol",
                next_patch_version(BASE_RELEASE_VERSION, 32),
            )
            draft["protocolVersion"] = 1
            path = temporary_root / "legacy-protocol.json"
            self.write_envelope(path, draft)
            with self.assertRaisesRegex(
                ConfigError,
                "candidate protocolVersion does not match the reader gate",
            ):
                build_candidate_draft_bundle(path)

    def test_candidate_release_version_requires_stable_x_y_z(self) -> None:
        invalid_versions = (
            f"{FIRST_CANDIDATE_VERSION}-rc.1",
            f"{FIRST_CANDIDATE_VERSION}+build.1",
            f"0{FIRST_CANDIDATE_VERSION}",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for index, invalid_version in enumerate(invalid_versions):
                with self.subTest(release_version=invalid_version):
                    draft = self.draft_envelope(
                        f"unstable-release-{index}", invalid_version
                    )
                    path = root / f"unstable-release-{index}.json"
                    self.write_envelope(path, draft)
                    with self.assertRaisesRegex(
                        ConfigError,
                        "releaseVersion must be a stable x.y.z version",
                    ):
                        build_candidate_draft_bundle(path)

    def test_config_and_rollback_versions_require_stable_x_y_z(self) -> None:
        base_config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        invalid_versions = (
            f"{BASE_RELEASE_VERSION}-rc.1",
            f"{BASE_RELEASE_VERSION}+build.1",
            f"0{BASE_RELEASE_VERSION}",
        )
        for invalid_version in invalid_versions:
            with self.subTest(config_version=invalid_version):
                config = json.loads(json.dumps(base_config))
                config["metadata"]["version"] = invalid_version
                with self.assertRaisesRegex(
                    ConfigError,
                    "metadata.version must be a stable x.y.z version",
                ):
                    validate_config(config)

            with self.subTest(rollback_version=invalid_version):
                config = json.loads(json.dumps(base_config))
                config["metadata"]["rollback_of"] = {
                    "version": invalid_version,
                    "sha256": "0" * 64,
                }
                with self.assertRaisesRegex(
                    ConfigError,
                    "rollback_of.version must be a stable x.y.z version",
                ):
                    validate_config(config)

    def test_comparable_comment_lower_bound_requires_exact_consistency(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            draft = self.draft_envelope(
                "fractional-comment-consistency",
                next_patch_version(BASE_RELEASE_VERSION, 33),
            )
            for observation in draft["discovery"]["observations"]:
                observation["algumon"]["countComparable"] = True
                observation["algumon"]["countConsistency"] = 0.96
            self.refresh_draft_hashes(draft)
            path = temporary_root / "fractional-comment-consistency.json"
            self.write_envelope(path, draft)
            with self.assertRaisesRegex(
                ConfigError,
                "countConsistency must be exactly 1",
            ):
                build_candidate_draft_bundle(path)

    def test_two_stage_candidate_is_byte_identical_and_release_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            draft_bundle, bundle, proven = self.build_pair(
                temporary_root, "jirum-v2", FIRST_CANDIDATE_VERSION
            )
            self.assertEqual("draft-non-promotable", json.loads(
                draft_bundle["draft-manifest.json"]
            )["status"])
            self.assertEqual(
                {
                    "filter-static.txt",
                    "config/sites.json",
                    "package.json",
                    "package-lock.json",
                    "hotdeal-focus.user.js",
                    "candidate-manifest.json",
                    "state/approved-variants.json",
                    "state/release-high-water.json",
                    "release-manifest.json",
                },
                set(bundle),
            )
            for core_path in (
                "filter-static.txt", "hotdeal-focus.user.js",
                "config/sites.json", "package.json", "package-lock.json",
            ):
                self.assertEqual(draft_bundle[core_path], bundle[core_path])
            self.assertNotIn("filter.txt", draft_bundle)
            self.assertNotIn("filter.txt", bundle)
            self.assertIn(
                f"@version      {FIRST_CANDIDATE_VERSION}".encode(),
                bundle["hotdeal-focus.user.js"],
            )
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
                {"hotdeal-focus.user.js"},
                set(release_manifest["artifacts"]),
            )
            materialized_config_path = temporary_root / "materialized-sites.json"
            materialized_config_path.write_bytes(bundle["config/sites.json"])
            normalized_overlay = load_config(materialized_config_path)
            self.assertEqual(
                bundle["filter-static.txt"],
                render_filter(normalized_overlay).encode("utf-8"),
            )
            rebuilt_manifest = json.loads(render_materialized_release_manifest(
                overlay,
                static_bytes=bundle["filter-static.txt"],
                userscript_bytes=bundle["hotdeal-focus.user.js"],
                config_bytes=bundle["config/sites.json"],
                package_bytes=bundle["package.json"],
                package_lock_bytes=bundle["package-lock.json"],
                approved_state_bytes=bundle["state/approved-variants.json"],
                high_water_bytes=bundle["state/release-high-water.json"],
            ))
            rebuilt_manifest["artifacts"] = {
                "hotdeal-focus.user.js": rebuilt_manifest["artifacts"][
                    "hotdeal-focus.user.js"
                ]
            }
            rebuilt_manifest_bytes = (
                json.dumps(
                    rebuilt_manifest,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
            self.assertEqual(bundle["release-manifest.json"], rebuilt_manifest_bytes)
            self.assertEqual(
                release_manifest["coverage"]["layoutFamilyCount"]
                + manifest["approvedVariantCount"],
                release_manifest["coverage"]["contractCount"],
            )
            expected_route_count = sum(
                len(raw_layout_paths(layout))
                + sum(
                    len(raw_layout_paths(variant))
                    for variant in layout.get("variants", [])
                )
                for site in normalized_overlay["sites"]
                for layout in site["layouts"]
            )
            self.assertEqual(
                expected_route_count,
                release_manifest["coverage"]["routeCount"],
            )
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
                    static_bytes=bundle["filter-static.txt"],
                    userscript_bytes=bundle["hotdeal-focus.user.js"],
                    config_bytes=bundle["config/sites.json"],
                    package_bytes=bundle["package.json"],
                    package_lock_bytes=bundle["package-lock.json"],
                    approved_state_bytes=bundle["state/approved-variants.json"],
                    high_water_bytes=bundle["state/release-high-water.json"],
                )
            with self.assertRaisesRegex(ConfigError, "must match exactly"):
                render_materialized_release_manifest(
                    overlay,
                    static_bytes=bundle["filter-static.txt"],
                    userscript_bytes=bundle["hotdeal-focus.user.js"],
                    config_bytes=bundle["config/sites.json"],
                    package_bytes=bundle["package.json"],
                    package_lock_bytes=bundle["package-lock.json"],
                    approved_state_bytes=b'{"schemaVersion":1,"variants":[]}',
                    high_water_bytes=bundle["state/release-high-water.json"],
                )

    def test_approved_state_is_append_only_and_release_version_is_monotonic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            _draft, first_bundle, first_proof = self.build_pair(
                temporary_root, "jirum-v2", FIRST_CANDIDATE_VERSION
            )
            state_path = temporary_root / "approved-variants.json"
            state_path.write_bytes(first_bundle["state/approved-variants.json"])
            second_draft = self.add_new_route(
                self.draft_envelope("jirum-v3", SECOND_CANDIDATE_VERSION),
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
            self.assertEqual(
                {FIRST_CANDIDATE_VERSION, SECOND_CANDIDATE_VERSION},
                {item["releaseVersion"] for item in state["variants"]},
            )
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
                self.draft_envelope("jirum-v4", SECOND_CANDIDATE_VERSION),
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
            draft = self.add_new_route(
                self.draft_envelope("jirum-route-v2", FIRST_CANDIDATE_VERSION)
            )
            draft_path = root / "route-draft.json"
            self.write_envelope(draft_path, draft)
            draft_bundle = build_candidate_draft_bundle(draft_path)
            self.assertNotIn("filter.txt", draft_bundle)
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
        envelope = self.draft_envelope("jirum-multipath-v2", BASE_RELEASE_VERSION)
        envelope["baseConfigSha256"] = hashlib.sha256(base_bytes).hexdigest()
        envelope["candidate"]["paths"] = sorted(clien_layout["paths"])
        with self.assertRaisesRegex(ConfigError, "exactly one proven route"):
            _validate_candidate_payload(
                envelope,
                base_config,
                base_bytes,
                "0.0.0",
            )

    def test_candidate_rejects_noncanonical_variant_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            draft = self.draft_envelope("forged-id", FIRST_CANDIDATE_VERSION)
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
                self.draft_envelope("temporary-first", FIRST_CANDIDATE_VERSION),
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
                self.draft_envelope("temporary-second", SECOND_CANDIDATE_VERSION),
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

    def test_shared_layout_rejects_mobile_only_candidate_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            draft = self.draft_envelope(
                "jirum-mobile-v2", FIRST_CANDIDATE_VERSION
            )
            draft["candidate"]["proofProfiles"] = ["mobile"]
            observations = [
                item for item in draft["discovery"]["observations"]
                if item["profile"] == "mobile"
            ]
            draft["discovery"]["observations"] = observations
            self.refresh_draft_hashes(draft)
            path = root / "mobile-draft.json"
            self.write_envelope(path, draft)
            with self.assertRaisesRegex(
                ConfigError,
                "proofProfiles must equal every applicable base layout profile",
            ):
                build_candidate_draft_bundle(path)

    def test_promotion_requires_three_fresh_algumon_targets_per_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            draft = self.draft_envelope(
                "jirum-three-targets-v2", FIRST_CANDIDATE_VERSION
            )
            draft_path = root / "three-targets-draft.json"
            self.write_envelope(draft_path, draft)
            draft_bundle = build_candidate_draft_bundle(draft_path)
            artifact_hash = json.loads(draft_bundle["draft-manifest.json"])[
                "artifactSetSha256"
            ]
            proven = self.proven_envelope(draft, artifact_hash)
            removed_mobile_url = draft["candidate"]["sampleUrls"][-1]
            proven["proof"]["observations"] = [
                observation
                for observation in proven["proof"]["observations"]
                if not (
                    observation["profile"] == "mobile"
                    and observation["url"] == removed_mobile_url
                )
            ]
            proven["proof"]["evidenceSha256"] = self.digest(
                {
                    "observations": proven["proof"]["observations"],
                    "routeEvidence": proven["proof"]["routeEvidence"],
                }
            )
            proven_path = root / "three-targets-proven.json"
            self.write_envelope(proven_path, proven)
            with self.assertRaisesRegex(
                ConfigError,
                "three distinct target URLs for profile 'mobile'",
            ):
                build_candidate_bundle(proven_path)

    def test_partial_profile_approved_state_has_no_migration_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _draft, bundle, _proven = self.build_pair(
                root, "jirum-state-v2", FIRST_CANDIDATE_VERSION
            )
            state = json.loads(bundle["state/approved-variants.json"])
            state["variants"][0]["proofProfiles"] = ["mobile"]
            state_path = root / "legacy-partial-profile-state.json"
            self.write_envelope(state_path, state)
            materialized_config = json.loads(bundle["config/sites.json"])
            with self.assertRaisesRegex(
                ConfigError,
                "proofProfiles must equal every applicable layout profile",
            ):
                _load_approved_state(state_path, materialized_config)

    def test_approved_state_release_version_has_no_suffix_migration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _draft, bundle, _proven = self.build_pair(
                root, "jirum-state-version-v2", FIRST_CANDIDATE_VERSION
            )
            state = json.loads(bundle["state/approved-variants.json"])
            state["variants"][0]["releaseVersion"] = (
                f"{FIRST_CANDIDATE_VERSION}+legacy"
            )
            state_path = root / "legacy-suffixed-version-state.json"
            self.write_envelope(state_path, state)
            materialized_config = json.loads(bundle["config/sites.json"])
            with self.assertRaisesRegex(
                ConfigError,
                "releaseVersion is invalid",
            ):
                _load_approved_state(state_path, materialized_config)

    def test_unavailable_algumon_count_requires_independent_comment_structure(self) -> None:
        import copy

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            base = self.draft_envelope(
                "jirum-structure-v2", FIRST_CANDIDATE_VERSION
            )

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
            draft = self.draft_envelope("jirum-v2", FIRST_CANDIDATE_VERSION)
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

    def test_static_analysis_filter_is_an_offline_oracle(self) -> None:
        rendered = render_filter(self.config)
        rules = [line for line in rendered.splitlines() if "#?#" in line]
        self.assertTrue(rules)
        for rule in rules:
            self.assertRegex(rule, r"^\[\$domain=[^,]+,path=\|/[^]]*\]#\?#")
            self.assertNotIn("$path=", rule)
        self.assertNotRegex(rendered, r":has\([^)]*,[^)]*\)")

    def test_auditor_has_no_external_marker_filter_authority(self) -> None:
        auditor = (SCRIPTS_DIR / "audit_pages.mjs").read_text(encoding="utf-8")
        for stale_token in (
            "markerFilter",
            "markerSelectorsForUrl",
            "gateArtifactLock",
            "buildLegacyIntegrityManifest",
            "filter.txt",
            "extendedCssCallbacks",
        ):
            self.assertNotIn(stale_token, auditor)
        self.assertIn("standaloneRuntimeCoverage", auditor)
        self.assertIn('exactObjectKeys(releaseManifest.artifacts, ["hotdeal-focus.user.js"])', auditor)
        self.assertIn("userscriptContent", auditor)

    def test_release_manifest_is_deterministic_and_userscript_only(self) -> None:
        generated_one, manifest_one = render_release()
        generated_two, manifest_two = render_release()
        self.assertEqual(generated_one, generated_two)
        self.assertEqual(manifest_one, manifest_two)
        self.assertEqual(
            {"filter-static.txt", "state/release-high-water.json"},
            set(generated_one),
        )

        manifest = json.loads(manifest_one)
        self.assertEqual(
            {
                "schemaVersion",
                "status",
                "releaseVersion",
                "protocolVersion",
                "installUrl",
                "generatorVersion",
                "rollback_of",
                "configSha256",
                "coverage",
                "promotion",
                "artifacts",
                "sourceIntegrity",
            },
            set(manifest),
        )
        self.assertEqual(2, manifest["schemaVersion"])
        self.assertEqual("release-ready", manifest["status"])
        self.assertEqual(
            "https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js",
            manifest["installUrl"],
        )
        self.assertEqual({"hotdeal-focus.user.js"}, set(manifest["artifacts"]))
        self.assertNotIn("filterSubscriptionUrl", manifest)
        self.assertNotIn("gateArtifactVersion", manifest)

        userscript_bytes = USERSCRIPT_PATH.read_bytes()
        userscript_entry = manifest["artifacts"]["hotdeal-focus.user.js"]
        self.assertEqual(
            {"sha256", "bytes", "version", "canonicalTextSha256"},
            set(userscript_entry),
        )
        self.assertEqual(hashlib.sha256(userscript_bytes).hexdigest(), userscript_entry["sha256"])
        self.assertEqual(len(userscript_bytes), userscript_entry["bytes"])
        self.assertEqual(BASE_RELEASE_VERSION, userscript_entry["version"])
        self.assertEqual(
            canonical_text_sha256(userscript_bytes),
            userscript_entry["canonicalTextSha256"],
        )
        self.assertNotEqual(
            userscript_entry["sha256"], userscript_entry["canonicalTextSha256"]
        )

        expected_sources = {
            "filter-static.txt",
            "config/sites.json",
            "package.json",
            "package-lock.json",
            "tests/fixtures/dom-regressions.json",
            "tests/fixtures/behavior-baseline.json",
            "state/release-high-water.json",
        }
        if (PROJECT_ROOT / "state" / "approved-variants.json").exists():
            expected_sources.add("state/approved-variants.json")
        self.assertEqual(expected_sources, set(manifest["sourceIntegrity"]))
        self.assertEqual(7, manifest["coverage"]["siteCount"])
        self.assertEqual(
            sum(len(site["layouts"]) for site in self.config["sites"]),
            manifest["coverage"]["layoutCount"],
        )
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
