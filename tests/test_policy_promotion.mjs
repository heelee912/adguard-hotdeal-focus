import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  assertAuditConfig,
  classifyAlgumonInventorySnapshot,
  commentLowerBoundConsistency,
  exactSignedAlgumonDealUrl,
  signedRelayAcquisitionEvidence,
  selectStableDiscoveryGroups,
} from "../scripts/audit_pages.mjs";

const approvedPath = "|/deal/";

assert.equal(commentLowerBoundConsistency(23, 4), 1);
assert.equal(commentLowerBoundConsistency(4, 4), 1);
assert.equal(commentLowerBoundConsistency(3, 4), 0);
assert.equal(commentLowerBoundConsistency(3, null), null);

const exactSevenLabels = [
  "뽐뿌",
  "루리웹",
  "zod",
  "퀘이사존",
  "어미새",
  "클리앙",
  "아카라이브",
];
const inventoryResponse = {
  requestedUrl: "https://www.algumon.com/n/deal",
  finalUrl: "https://www.algumon.com/n/deal",
  status: 200,
  contentType: "text/html; charset=utf-8",
  title: "알구몬",
  bodyText: "latest deals",
};
const validInventoryCard = {
  cardDomId: "deal-123456",
  hrefs: [
    "https://www.algumon.com/l/d/123456" +
      "?v=0123456789abcdef0123456789abcdef&t=1784520000000",
  ],
  iconUrls: ["https://cdn.algumon.com/site-icon/clien.png"],
  sourceLabels: ["클리앙"],
  dataSiteTypes: ["clien"],
  title: "Deal title",
  commentCount: 0,
};
const exactInventory = classifyAlgumonInventorySnapshot({
  response: inventoryResponse,
  dropdowns: [exactSevenLabels],
  cards: [validInventoryCard],
});
assert.equal(exactInventory.status, "ok");
const currentRelayUrl = "https://www.algumon.com/n/d/123456" +
  "?v=0123456789abcdef0123456789abcdef&t=1784520000000" +
  "&enc=v1.ryqcQ5lFYPJIkWIN.aLjGCXx5YJWwQBCJLhF0eA.DXaAJTmx2-oCHTcROqXiljh3lxfXotEaqKXD1XoXhYe8zPoLRSv0y3L--88tVNAeP43o";
assert.equal(exactSignedAlgumonDealUrl(validInventoryCard.hrefs[0], "123456")?.href,
  validInventoryCard.hrefs[0]);
assert.equal(exactSignedAlgumonDealUrl(currentRelayUrl, "123456")?.href, currentRelayUrl);
assert.equal(signedRelayAcquisitionEvidence(currentRelayUrl, "123456", 1784520000100).ageMs, 100);
const currentInventory = classifyAlgumonInventorySnapshot({
  response: inventoryResponse,
  dropdowns: [exactSevenLabels],
  cards: [{
    ...validInventoryCard,
    hrefs: [currentRelayUrl],
    iconUrls: ["https://cdn.algumon.com/site-icon/clien.png?d=16x16"],
    dataSiteTypes: [],
    title: "쌀",
  }],
});
assert.equal(currentInventory.status, "ok");
assert.equal(currentInventory.links[0].href, currentRelayUrl);
assert.equal(currentInventory.links[0].title, "쌀");
const sourcePickerNotRendered = classifyAlgumonInventorySnapshot({
  response: inventoryResponse,
  dropdowns: [],
  cards: [{ ...validInventoryCard, hrefs: [currentRelayUrl] }],
});
assert.equal(sourcePickerNotRendered.status, "ok");
assert.equal(sourcePickerNotRendered.sourceInventoryMode, "source-picker-unavailable");
assert.deepEqual(sourcePickerNotRendered.observedLabels, []);
assert.deepEqual(sourcePickerNotRendered.observedSiteTypes, ["clien"]);
for (const labels of [[...exactSevenLabels, "새 사이트"], [...exactSevenLabels, "클리앙"], ["알 수 없는 사이트"]]) {
  const invalidPicker = classifyAlgumonInventorySnapshot({
    response: inventoryResponse,
    dropdowns: [labels],
    cards: [validInventoryCard],
  });
  assert.equal(invalidPicker.status, "inventory-contract-failure");
}
const unknownSourceWithoutPicker = classifyAlgumonInventorySnapshot({
  response: inventoryResponse,
  dropdowns: [],
  cards: [{
    ...validInventoryCard,
    hrefs: [currentRelayUrl],
    sourceLabels: ["새 사이트"],
    iconUrls: ["https://cdn.algumon.com/site-icon/newsite.png"],
    dataSiteTypes: [],
  }],
});
assert.equal(unknownSourceWithoutPicker.status, "inventory-contract-failure");
assert.equal(unknownSourceWithoutPicker.links.length, 0);
assert.equal(classifyAlgumonInventorySnapshot({
  response: inventoryResponse,
  dropdowns: [],
  cards: [validInventoryCard],
}, "ruliweb").status, "inventory-contract-failure");
for (const [reason, invalidUrl] of [
  ["wrong host", currentRelayUrl.replace("www.algumon.com", "evil.example")],
  ["host suffix", currentRelayUrl.replace("www.algumon.com", "www.algumon.com.evil.example")],
  ["credentials", currentRelayUrl.replace("https://", "https://user@")],
  ["nondefault port", currentRelayUrl.replace(".com/", ".com:444/")],
  ["insecure transport", currentRelayUrl.replace("https:", "http:")],
  ["fragment", `${currentRelayUrl}#forged`],
  ["mismatching ID", currentRelayUrl.replace("/123456?", "/123457?")],
  ["unregistered route", currentRelayUrl.replace("/n/d/", "/n/deal/")],
  ["missing signature", currentRelayUrl.replace("v=0123456789abcdef0123456789abcdef&", "")],
  ["bad signature", currentRelayUrl.replace("v=0123", "v=z123")],
  ["missing encrypted target", currentRelayUrl.split("&enc=")[0]],
  ["duplicate signature", `${currentRelayUrl}&v=0123456789abcdef0123456789abcdef`],
  ["duplicate timestamp", `${currentRelayUrl}&t=1784520000000`],
  ["duplicate encrypted target", `${currentRelayUrl}&enc=v1.a.b.c`],
  ["unknown query", `${currentRelayUrl}&target=https://evil.example`],
  ["unknown encryption version", currentRelayUrl.replace("enc=v1.", "enc=v2.")],
  ["malformed encryption", currentRelayUrl.replace(/&enc=.*$/u, "&enc=v1.a.b")],
  ["encoded target URL", currentRelayUrl.replace(/&enc=.*$/u, "&enc=https%3A%2F%2Fevil.example")],
  ["oversized encryption", currentRelayUrl.replace(/&enc=.*$/u, `&enc=v1.a.b.${"c".repeat(4096)}`)],
  ["legacy route cannot carry new query", currentRelayUrl.replace("/n/d/", "/l/d/")],
]) {
  assert.equal(exactSignedAlgumonDealUrl(invalidUrl, "123456"), null, reason);
}
const contradictedCurrentSource = classifyAlgumonInventorySnapshot({
  response: inventoryResponse,
  dropdowns: [exactSevenLabels],
  cards: [{ ...validInventoryCard, hrefs: [currentRelayUrl], sourceLabels: ["루리웹"] }],
});
assert.equal(contradictedCurrentSource.status, "inventory-contract-failure");
assert.ok(contradictedCurrentSource.failures.includes("card-0:contradictory-source-identity"));
const expandedInventory = classifyAlgumonInventorySnapshot({
  response: inventoryResponse,
  dropdowns: [[...exactSevenLabels, "새 사이트"]],
  cards: [validInventoryCard],
});
assert.equal(expandedInventory.status, "inventory-contract-failure");
assert.ok(expandedInventory.failures.includes("source-dropdown-inventory"));
assert.equal(expandedInventory.links.length, 0);
const missingInventory = classifyAlgumonInventorySnapshot({
  response: inventoryResponse,
  dropdowns: [exactSevenLabels.filter((label) => label !== "아카라이브")],
  cards: [validInventoryCard],
});
assert.equal(missingInventory.status, "inventory-contract-failure");
assert.ok(missingInventory.failures.includes("source-dropdown-inventory"));
assert.equal(missingInventory.links.length, 0);

const productionConfig = JSON.parse(
  readFileSync(new URL("../config/sites.json", import.meta.url), "utf8"),
);
assert.doesNotThrow(() => assertAuditConfig(structuredClone(productionConfig)));
const missingSiteConfig = structuredClone(productionConfig);
missingSiteConfig.sites.pop();
assert.throws(
  () => assertAuditConfig(missingSiteConfig),
  /exact Algumon seven-source contract/u,
);
const extraSiteConfig = structuredClone(productionConfig);
extraSiteConfig.sites.push({
  ...structuredClone(extraSiteConfig.sites[0]),
  id: "unexpected-source",
  name: "Unexpected source",
});
assert.throws(
  () => assertAuditConfig(extraSiteConfig),
  /exact Algumon seven-source contract/u,
);

function baseConfig(productCardinality) {
  const requiredProduct = productCardinality === "required";
  return {
    sites: [{
      id: "example",
      layouts: [{
        id: "deal",
        domain: "example.test",
        paths: [approvedPath],
        applicable_profiles: ["desktop"],
        required_roles: ["title", "body", "comments"].concat(
          requiredProduct ? ["product"] : [],
        ),
        role_projection: {
          title: { mode: "metadata-shallow" },
          body: { mode: "atomic-boundary", ignored: [] },
          product: requiredProduct
            ? {
                mode: "atomic-boundary",
                cardinality: "required",
                order: "before-body",
                selectors: [".old-product"],
                ignored: [],
              }
            : { mode: "absent", cardinality: "zero", selectors: [], ignored: [] },
          comments: { mode: "classified-children" },
        },
      }],
    }],
  };
}

function result(index, productCardinality, options = {}) {
  const requiredProduct = productCardinality === "required";
  const productSelector = options.productSelector ?? ".purchase";
  const order = requiredProduct ? options.order ?? "after-body" : null;
  const bodyIgnored = options.bodyIgnored ?? [".article-ad"];
  const commentIgnored = options.commentIgnored ?? [".comment-promo"];
  const roles = {
    title: ".title",
    body: ".body",
    comments: ".comments",
    ...(requiredProduct ? { product: productSelector } : {}),
  };
  const cardinality = {
    title: 1,
    body: 1,
    comments: 1,
    ...(requiredProduct ? { product: 1 } : {}),
  };
  return {
    siteId: "example",
    layoutId: "deal",
    profile: "desktop",
    source: "algumon-latest",
    requestedUrl: `https://example.test/deal/${index}`,
    capturedAt: "2026-07-20T00:00:00Z",
    approvedRouteMatched: true,
    passed: false,
    matchedApprovedPath: approvedPath,
    routeFamily: "example.test/deal/:article-token",
    routeObservation: null,
    semanticOracle: {
      ok: true,
      structuralOk: true,
      oracleSource: "verified-userscript-export",
      oracleExecutionWorld: "chromium-isolated-v1",
      exactApprovedCount: 0,
      semanticProjectionCount: 0,
      coMatchCount: 0,
      candidateProjection: {
        semanticProjectionCount: 1,
        exactCandidateCount: 1,
        coMatchCount: 0,
        aliases: [["candidate"]],
        oracleExecutionWorld: "chromium-isolated-v1",
      },
      pageRoot: ".root",
      pageRootCount: 1,
      roles,
      cardinality,
      containment: true,
      productOrder: order,
      policyProposal: {
        schemaVersion: 1,
        source: "independent-projection-tuple",
        complete: true,
        pageRoot: ".root",
        pageRootEvidence: "all-role-lowest-common-ancestor",
        product: {
          cardinality: productCardinality,
          order,
          selectors: requiredProduct ? [productSelector] : [],
        },
        bodyIgnored,
        productIgnored: requiredProduct ? [".purchase-ad"] : [],
        commentIgnored,
        safety: {
          strictDescendantsOnly: true,
          strongStructuralNoiseOnly: true,
          meaningfulTextPriceAndPurchaseLinksExcluded: true,
          ...(options.safety ?? {}),
        },
        shapeFingerprint: "projection-policy-v1-0123abcd",
        promotionGate: {
          promotable: false,
          requiredDistinctUrlsPerProfile: 3,
          requiredProfilesSource: "auditor-layout-contract",
          requiredMatchingShapeFingerprint: true,
        },
      },
      commentItems: [".comment"],
      commentControls: [".more"],
      commentIgnored,
      algumon: {
        titleConsistency: 1,
        titleConsistencyOk: true,
        titleConsistencyMode: "metadata-quorum",
        titleMetadataSourceCount: 2,
        titleMetadataSourceKinds: ["document-title", "open-graph"],
        commentComparable: false,
        countConsistency: null,
      },
      commentStructure: {
        mountSelector: ".comments",
        mountCount: 1,
        itemSelector: ".comment",
        itemCount: 2,
        ignoredSelectors: commentIgnored,
        ignoredCount: commentIgnored.length,
        classificationOverlapCount: 0,
        unclassifiedContentCount: 0,
        emptyStateSelector: null,
        emptyStateCount: 0,
      },
    },
  };
}

function oneGroup(config, results) {
  const groups = selectStableDiscoveryGroups({ results }, config);
  assert.equal(groups.length, 1, "one stable policy group must be selected");
  return groups[0];
}

const requiredFromZero = oneGroup(
  baseConfig("zero"),
  [1, 2, 3].map((index) => result(index, "required")),
);
assert.equal(requiredFromZero.roleProjection.product.cardinality, "required");
assert.equal(requiredFromZero.roleProjection.product.order, "after-body");
assert.deepEqual(requiredFromZero.requiredRoles, ["body", "comments", "product", "title"]);
assert.deepEqual(requiredFromZero.roleProjection.body.ignored, [".article-ad"]);
assert.deepEqual(requiredFromZero.roleProjection.product.ignored, [".purchase-ad"]);
assert.deepEqual(requiredFromZero.shape.commentIgnored, [".comment-promo"]);

const zeroFromRequired = oneGroup(
  baseConfig("required"),
  [1, 2, 3].map((index) => result(index, "zero")),
);
assert.equal(zeroFromRequired.roleProjection.product.cardinality, "zero");
assert.deepEqual(zeroFromRequired.requiredRoles, ["body", "comments", "title"]);
assert.equal("product" in zeroFromRequired.shape.roles, false);

const optional = oneGroup(
  baseConfig("required"),
  [result(1, "required"), result(2, "zero"), result(3, "required")],
);
assert.equal(optional.roleProjection.product.cardinality, "optional");
assert.deepEqual(optional.requiredRoles, ["body", "comments", "title"]);
assert.deepEqual(
  new Set(optional.selectedResults.map(
    (item) => item.semanticOracle.policyProposal.product.cardinality,
  )),
  new Set(["required", "zero"]),
  "optional promotion proof must retain both observed cardinalities",
);

assert.deepEqual(
  selectStableDiscoveryGroups({
    results: [
      result(1, "required", { productSelector: ".purchase-a" }),
      result(2, "required", { productSelector: ".purchase-b" }),
      result(3, "required", { productSelector: ".purchase-a" }),
    ],
  }, baseConfig("required")),
  [],
  "conflicting present product shapes must not auto-promote",
);

assert.deepEqual(
  selectStableDiscoveryGroups({
    results: [1, 2, 3].map((index) => result(index, "zero", {
      safety: { meaningfulTextPriceAndPurchaseLinksExcluded: false },
    })),
  }, baseConfig("zero")),
  [],
  "a proposal that may hide authored purchase content must not auto-promote",
);

process.stdout.write(
  "independent policy promotion: inventory, comment lower-bound, and " +
    "required/zero/optional drift proofs passed\n",
);
