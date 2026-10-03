import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { chromium } from "playwright";
import { PREAUTHORIZED_ADGUARD_CONTROL_SOURCE } from
  "../scripts/preauthorized_adguard_control.mjs";
import {
  FIRST_PAINT_PROBE_SOURCE,
  auditCandidateOverlay,
  auditUserscriptGate,
  candidateGenerationAllowed,
  candidateOracleProjectionEvidence,
  candidateOverlayFailures,
  commentControlSelectorDigestsForUrl,
  countExistingApprovedLayoutMatches,
  promotionRetestFailures,
  resultHasZeroLeak,
  selectStableDiscoveryGroups,
  semanticOracle,
  semanticOracleContractFailures,
  semanticOracleEvidence,
  synthesizePromotionDraftForGroup,
  synthesizePromotionProof,
  userscriptGateFailures,
} from "../scripts/audit_pages.mjs";

// All navigation is fulfilled locally. These are registered direct article
// visits; neither an Algumon referrer nor a signed relay/snapshot is supplied.
const productionSource = readFileSync(
  new URL("../hotdeal-focus.user.js", import.meta.url), "utf8",
);
const pathPattern = "|/service/board/jirum/";
const sampleUrls = [101, 102, 103].map(id =>
  `https://www.clien.net/service/board/jirum/${id}`);
const requiredRoles = ["title", "body", "comments"];
const roleProjection = {
  title: { mode: "metadata-shallow" },
  body: { mode: "atomic-boundary", ignored: [] },
  product: { mode: "absent", cardinality: "zero", selectors: [], ignored: [] },
  comments: { mode: "classified-children" },
};
const compiledLayout = {
  id: "jirum", path: pathPattern, paths: [pathPattern], pageRoot: "#post",
  requiredRoles, allowEmptyComments: true, roleProjection,
  hints: {
    title: [".deal-title"], body: [".body-v1"], comments: [".comments"],
    commentItems: [".comments > [itemprop='comment']"],
    commentControls: [], commentIgnored: [],
  },
};
const compiledSite = { id: "clien", domain: "clien.net", layouts: [compiledLayout] };
const layout = {
  id: "jirum", site_id: "clien", domain: "clien.net", paths: [pathPattern],
  page_root: "#post", sample_urls: sampleUrls,
  applicable_profiles: ["desktop", "mobile"], required_roles: requiredRoles,
  role_projection: roleProjection, variants: [],
};
const site = { id: "clien", domain: "clien.net", layouts: [layout] };
const config = { sites: [site] };
const contractsPattern = /(\/\* HOTDEAL_FOCUS_CONTRACTS_START \*\/)[\s\S]*?(\/\* HOTDEAL_FOCUS_CONTRACTS_END \*\/)/u;
assert.match(productionSource, contractsPattern);
function withContracts(contracts) {
  return productionSource.replace(contractsPattern,
    (_whole, start, end) => `${start}\n${JSON.stringify(contracts)}\n${end}`);
}
const baselineSource = withContracts([compiledSite]);
const directTarget = url => ({
  source: "sample", runtimeExpectation: "registered-positive",
  readerRouteRegistered: true, url,
});
const title = "Native Article Monitor Product";
const bodyText = "This is the original complete product description with useful specifications, " +
  "shipping conditions and information for readers who want to purchase the item.";
function fixture({ changed = true, conflictingMetadata = false } = {}) {
  return `<!doctype html><html><head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta property="og:title" content="${conflictingMetadata ? "Completely Different Holiday Destination" : title}">
    <title>${title}</title></head><body><main id="post">
    <h1 class="deal-title">${title}</h1>
    <article class="${changed ? "body-v2" : "body-v1"}"><p>${bodyText}</p>
      <p>A second paragraph preserves the original article context and details.</p></article>
    <section class="comments" aria-label="Comments">
      <div itemprop="comment">Original first complete comment.</div>
      <div itemprop="comment">Original second complete comment.</div>
    </section><aside id="popular" class="popular">Popular unrelated articles</aside>
    </main><aside id="sidebar">Other discussion boards</aside></body></html>`;
}

const articleClassification = { kind: "article-response", candidateEligible: true };
assert.equal(candidateGenerationAllowed("registered-positive", articleClassification, 0), true);
assert.equal(candidateGenerationAllowed("registered-positive", articleClassification, 1), false);
assert.equal(candidateGenerationAllowed("direct-negative", articleClassification, 0), false);
assert.equal(candidateGenerationAllowed("registered-positive", {
  kind: "source-or-infrastructure-failure", candidateEligible: false,
}, 0), false);

const browser = await chromium.launch({ headless: true });
const allRequests = [];
const unauthorizedRequests = [];
async function localPage(profile, options = {}, runtimeSource = null) {
  const context = await browser.newContext({
    viewport: profile === "mobile" ? { width: 390, height: 844 } : { width: 1280, height: 900 },
    serviceWorkers: "block",
  });
  await context.route("**/*", async route => {
    const url = route.request().url();
    allRequests.push(url);
    if (!sampleUrls.includes(url) || !route.request().isNavigationRequest()) {
      unauthorizedRequests.push(url);
      await route.abort("blockedbyclient");
      return;
    }
    await route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: fixture(options) });
  });
  if (runtimeSource) {
    await context.addInitScript(({ source, control, paintProbe }) => {
      (0, eval)(paintProbe);
      (0, eval)(control);
      (0, eval)(source);
    }, { source: runtimeSource, control: PREAUTHORIZED_ADGUARD_CONTROL_SOURCE,
      paintProbe: FIRST_PAINT_PROBE_SOURCE });
  }
  return { context, page: await context.newPage() };
}

try {
  // The intact registered projection remains an exact, non-candidate result.
  const intact = await localPage("desktop", { changed: false });
  try {
    await intact.page.goto(sampleUrls[0]);
    const oracle = semanticOracleEvidence(await semanticOracle(
      intact.page, baselineSource, site.id, layout.id, requiredRoles, directTarget(sampleUrls[0]),
    ), directTarget(sampleUrls[0]));
    assert.equal(oracle.verificationMode, "registered-sample");
    assert.equal(oracle.ok, true, JSON.stringify(oracle));
    assert.equal(oracle.candidateEligible, false);
    assert.equal(oracle.policyProposal, null);
    assert.deepEqual(semanticOracleContractFailures(oracle), []);
  } finally { await intact.context.close(); }

  const discoveries = [];
  for (const profile of ["desktop", "mobile"]) {
    const observed = await localPage(profile);
    try {
      for (const url of sampleUrls) {
        await observed.page.goto(url);
        const target = directTarget(url);
        const approved = await countExistingApprovedLayoutMatches(
          observed.page, layout, baselineSource, null,
        );
        assert.equal(approved.semanticProjectionCount, 0, "the changed body must fail the old tuple");
        const oracle = semanticOracleEvidence(await semanticOracle(
          observed.page, baselineSource, site.id, layout.id, requiredRoles, target,
        ), target);
        assert.equal(oracle.verificationMode, "native-article-discovery");
        assert.equal(oracle.ok, true, JSON.stringify(oracle));
        assert.equal(oracle.algumon.titleConsistencyMode, "native-article+metadata-consensus");
        assert.equal(oracle.algumon.commentComparable, false);
        assert.equal(oracle.algumon.countConsistency, null);
        assert.deepEqual(semanticOracleContractFailures(oracle), []);
        oracle.exactApprovedCount = 0;
        oracle.semanticProjectionCount = 0;
        oracle.coMatchCount = 0;
        oracle.candidateProjection = await candidateOracleProjectionEvidence(
          observed.page, layout, oracle, baselineSource, null, url,
        );
        assert.equal(oracle.candidateProjection.exactCandidateCount, 1);
        discoveries.push({
          siteId: site.id, layoutId: layout.id, profile, source: "sample",
          runtimeExpectation: "registered-positive", requestedUrl: url,
          capturedAt: new Date().toISOString(), approvedRouteMatched: true,
          matchedApprovedPath: pathPattern, passed: false, semanticOracle: oracle,
        });
      }
    } finally { await observed.context.close(); }
  }

  // Conflicting native article metadata must not be laundered into a candidate.
  const contradiction = await localPage("desktop", { conflictingMetadata: true });
  try {
    await contradiction.page.goto(sampleUrls[0]);
    const target = directTarget(sampleUrls[0]);
    const oracle = semanticOracleEvidence(await semanticOracle(
      contradiction.page, baselineSource, site.id, layout.id, requiredRoles, target,
    ), target);
    assert.equal(oracle.ok, false, "native metadata conflict must remain rejected");
  } finally { await contradiction.context.close(); }

  const groups = selectStableDiscoveryGroups({ results: discoveries }, config);
  assert.equal(groups.length, 1, "three direct articles on both profiles must form one candidate");
  assert.deepEqual(groups[0].proofProfiles, ["desktop", "mobile"]);
  assert.deepEqual(selectStableDiscoveryGroups({ results: discoveries.map((result, index) =>
    index === 0 ? { ...result, candidateGenerationAllowed: false } : result,
  ) }, config), [], "a disallowed result must not complete a three-article candidate proof");
  assert.deepEqual(selectStableDiscoveryGroups({ results: discoveries.filter(result =>
    result.requestedUrl !== sampleUrls[2]) }, config), [], "two URLs cannot stand in for three proofs");
  const draft = await synthesizePromotionDraftForGroup(
    { integrity: { releaseManifest: { protocolVersion: 2 } } },
    config, Buffer.from(JSON.stringify(config)), groups[0], "0.6.94",
  );
  assert.equal(draft.status, "draft");
  assert.deepEqual(draft.envelope.discovery.routeEvidence, []);
  const candidate = draft.envelope.candidate;
  assert.deepEqual(candidate.sampleUrls, sampleUrls);
  const candidateLayout = {
    id: `${candidate.layoutId}--${candidate.variantId}`,
    paths: candidate.paths, pageRoot: candidate.pageRoot,
    proofProfiles: candidate.proofProfiles, allowEmptyComments: candidate.allowEmptyComments,
    requiredRoles: candidate.requiredRoles, roleProjection: candidate.roleProjection,
    hints: { ...candidate.roles, commentItems: candidate.commentItems,
      commentControls: candidate.commentControls, commentIgnored: candidate.commentIgnored },
  };
  const candidateSource = withContracts([{
    ...compiledSite, layouts: [compiledLayout, candidateLayout],
  }]);
  const candidateRuntimeLayout = {
    ...layout,
    variants: [{ id: candidate.variantId, paths: candidate.paths,
      comment_contract: { controls: candidate.commentControls } }],
  };
  const provenResults = [];
  for (const profile of ["desktop", "mobile"]) {
    const verified = await localPage(profile, {}, candidateSource);
    try {
      for (const url of sampleUrls) {
        await verified.page.goto(url);
        const gate = await auditUserscriptGate(
          verified.page, requiredRoles, 5000, "registered-positive",
          commentControlSelectorDigestsForUrl(candidateRuntimeLayout, url),
        );
        assert.deepEqual(userscriptGateFailures(gate, requiredRoles), [], JSON.stringify(gate));
        assert.equal(resultHasZeroLeak({ userscript: { gate } }), true);
        const overlay = await auditCandidateOverlay(
          verified.page, layout, candidate, directTarget(url), candidateSource,
        );
        assert.deepEqual(candidateOverlayFailures(overlay, requiredRoles), [], JSON.stringify(overlay));
        assert.equal(overlay.titleConsistencyMode, "native-article+metadata-consensus");
        const contents = await verified.page.evaluate(() => {
          const visible = element => Boolean(element) &&
            getComputedStyle(element).display !== "none" &&
            getComputedStyle(element).visibility !== "hidden" &&
            element.getBoundingClientRect().height > 0;
          return {
            title: document.querySelector("h1").textContent,
            body: document.querySelector("article").textContent,
            comments: [...document.querySelectorAll("[itemprop='comment']")].map(node =>
              ({ text: node.textContent, visible: visible(node) })),
            noiseVisible: ["popular", "sidebar"].filter(id => visible(document.getElementById(id))),
          };
        });
        assert.equal(contents.title, title);
        assert.ok(contents.body.includes(bodyText));
        assert.equal(contents.comments.length, 2);
        assert.ok(contents.comments.every(item => item.visible && item.text.startsWith("Original")));
        assert.deepEqual(contents.noiseVisible, []);
        provenResults.push({
          siteId: site.id, layoutId: layout.id, profile, source: "sample",
          runtimeExpectation: "registered-positive", requestedUrl: url,
          capturedAt: new Date().toISOString(), approvedRouteMatched: true,
          matchedApprovedPath: pathPattern, passed: true,
          candidateOverlay: overlay, userscript: { gate },
        });
      }
    } finally { await verified.context.close(); }
  }

  const report = {
    results: provenResults, integrity: { passed: true },
    syntheticFixture: { passed: true }, regressionFixtures: { passed: true },
    edgeFixtures: { passed: true },
  };
  const proof = synthesizePromotionProof(report, config, draft.envelope, {
    artifactSetSha256: "a".repeat(64),
  });
  assert.equal(proof.status, "proven", JSON.stringify(proof));
  assert.equal(proof.envelope.proof.observations.length, 6);
  assert.deepEqual(proof.envelope.proof.routeEvidence, []);
  const scope = { siteId: site.id, candidateLayoutId: layout.id,
    candidateProfiles: ["desktop", "mobile"], tuples: [] };
  assert.deepEqual(promotionRetestFailures(report, scope), []);
  const missingProof = { ...report, results: provenResults.slice(1) };
  assert.equal(synthesizePromotionProof(missingProof, config, draft.envelope, {
    artifactSetSha256: "a".repeat(64),
  }).status, "rejected");
  assert.ok(promotionRetestFailures(missingProof, scope).length > 0);
  assert.deepEqual(unauthorizedRequests, []);
  assert.ok(allRequests.length > 0);
  assert.ok(allRequests.every(url => sampleUrls.includes(url)));
  console.log("Registered direct monitor: intact tuple preserved; changed DOM on three native articles " +
    "in desktop/mobile produced and proved one candidate with zero Algumon requests; metadata conflicts, " +
    "network failures and incomplete proof sets remain rejected.");
} finally {
  await browser.close();
}
