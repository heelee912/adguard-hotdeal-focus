import assert from "node:assert/strict";

import {
  AlgumonRequestBudgetExceeded,
  DEFAULT_ALGUMON_REQUEST_START_BUDGET,
  capturedAlgumonTargetsFromReport,
  createAlgumonRequestStartBudget,
  createLowTrafficAlgumonProbePlan,
} from "../scripts/audit_pages.mjs";

function signedRelayUrl(dealId, timestampMs, fill) {
  return `https://www.algumon.com/l/d/${dealId}?v=${fill.repeat(32)}&t=${timestampMs}`;
}

function capturedSnapshotFixture() {
  const timestampMs = Date.now();
  const urls = [
    "https://example.test/article/1001",
    "https://example.test/article/1002",
    "https://example.test/article/1003",
  ];
  const site = {
    id: "example",
    layouts: [{
      id: "article",
      domain: "example.test",
      paths: ["|/article/"],
      applicable_profiles: ["desktop"],
      variants: [],
    }],
  };
  const candidate = {
    siteId: "example",
    layoutId: "article",
    variantId: "candidate-route",
    proofProfiles: ["desktop"],
    sampleUrls: urls,
  };
  const results = urls.map((requestedUrl, index) => {
    const dealId = String(1001 + index);
    const signedUrl = signedRelayUrl(dealId, timestampMs, String(index + 1));
    return {
      siteId: "example",
      layoutId: "article",
      profile: "desktop",
      source: "algumon-latest",
      runtimeExpectation: "relay-positive",
      requestedUrl,
      relayDestinationUrl: requestedUrl,
      relayAcquisition: {
        signedUrl,
        acquiredAt: new Date(timestampMs).toISOString(),
        issuedAt: new Date(timestampMs).toISOString(),
        ageMs: 0,
      },
      algumonSeed: {
        discoveryUrl: "https://www.algumon.com/n/deal?sites=EXAMPLE",
        redirectUrl: signedUrl,
        dealId,
        siteId: "example",
        title: `Deal ${dealId}`,
        commentCount: 0,
        verifiedResolution: {
          relayFetchUrl: signedUrl,
          resolvedDestination: requestedUrl,
          responseStatus: 200,
          responseSha256: "a".repeat(64),
        },
      },
      routeObservation: {
        algumonDealId: dealId,
        algumonEntryUrl: signedUrl,
        finalResolvedUrl: requestedUrl,
        relayFetchUrl: signedUrl,
        resolvedDestination: requestedUrl,
      },
      passed: true,
    };
  });
  return { candidate, capturedReport: { runId: "sealed-run", results }, site };
}

function testLowTrafficProbePlan() {
  assert.equal(DEFAULT_ALGUMON_REQUEST_START_BUDGET, 29);
  assert.deepEqual(createLowTrafficAlgumonProbePlan(7), {
    globalInventoryNavigations: 1,
    siteDiscoveryNavigations: 7,
    signedRelayFetches: 21,
    justInTimeRelayAcquisitions: 0,
    justInTimeSignedRelayFetches: 0,
    totalRequestStarts: 29,
  });
  assert.equal(createLowTrafficAlgumonProbePlan(1).totalRequestStarts, 5);
  assert.throws(() => createLowTrafficAlgumonProbePlan(0), /at least one selected site/);
}

function testHardRequestStartBudget() {
  const budget = createAlgumonRequestStartBudget(2);
  budget.reserve("global-inventory", "https://www.algumon.com/n/deal");
  budget.reserve("site-discovery", "https://algumon.com/n/deal?sites=CLIEN");
  assert.deepEqual(budget.snapshot(), {
    maximumStarts: 2,
    startedCount: 2,
    remainingStarts: 0,
    starts: [
      { ordinal: 1, kind: "global-inventory" },
      { ordinal: 2, kind: "site-discovery" },
    ],
  });
  assert.throws(
    () => budget.reserve("signed-relay-fetch", signedRelayUrl("1001", Date.now(), "a")),
    (error) =>
      error instanceof AlgumonRequestBudgetExceeded &&
      error.maximumStarts === 2 &&
      error.attemptedKind === "signed-relay-fetch",
  );
  assert.equal(budget.snapshot().startedCount, 2, "the rejected start is not recorded");

  const originBudget = createAlgumonRequestStartBudget(1);
  assert.throws(
    () => originBudget.reserve("escaped", "https://not-algumon.example/"),
    /escaped the exact source origin/,
  );
  assert.equal(originBudget.snapshot().startedCount, 0, "an escaped host never consumes budget");
  assert.throws(
    () => createAlgumonRequestStartBudget(DEFAULT_ALGUMON_REQUEST_START_BUDGET + 1),
    /must be an integer/,
  );
}

function testCapturedSnapshotProducesNoSourceRequests() {
  const { candidate, capturedReport, site } = capturedSnapshotFixture();
  const captured = capturedAlgumonTargetsFromReport(capturedReport, candidate, [site]);
  assert.equal(captured.mode, "captured-sealed-relay");
  assert.equal(captured.sourceRunId, "sealed-run");
  assert.equal(captured.targetCount, 3);
  assert.deepEqual(
    captured.targets.map(({ target }) => target.url),
    candidate.sampleUrls,
  );
  assert.deepEqual(
    captured.targets.map(({ target }) => target.relayAcquisition.signedUrl),
    capturedReport.results.map((result) => result.relayAcquisition.signedUrl),
  );
  assert.equal(
    captured.targets.every(({ target }) => target.algumon.verifiedResolution.responseStatus === 200),
    true,
  );

  const historical = structuredClone(capturedReport);
  const historicalTimestamp = Date.now() - (24 * 60 * 60 * 1_000);
  historical.results[0].algumonSeed.redirectUrl = signedRelayUrl(
    "1001",
    historicalTimestamp,
    "1",
  );
  historical.results[0].algumonSeed.verifiedResolution.relayFetchUrl =
    historical.results[0].algumonSeed.redirectUrl;
  historical.results[0].relayAcquisition = {
    signedUrl: historical.results[0].algumonSeed.redirectUrl,
    acquiredAt: new Date(historicalTimestamp).toISOString(),
    issuedAt: new Date(historicalTimestamp).toISOString(),
    ageMs: 0,
  };
  historical.results[0].routeObservation.algumonEntryUrl =
    historical.results[0].algumonSeed.redirectUrl;
  historical.results[0].routeObservation.relayFetchUrl =
    historical.results[0].algumonSeed.redirectUrl;
  assert.equal(
    capturedAlgumonTargetsFromReport(historical, candidate, [site]).targetCount,
    3,
    "offline proof accepts a sealed relay that was fresh when originally acquired",
  );

  const forged = structuredClone(historical);
  forged.results[0].relayAcquisition.acquiredAt = new Date().toISOString();
  assert.throws(
    () => capturedAlgumonTargetsFromReport(forged, candidate, [site]),
    /just-in-time signed relay is not fresh/,
  );
}

testLowTrafficProbePlan();
testHardRequestStartBudget();
testCapturedSnapshotProducesNoSourceRequests();
process.stdout.write("Algumon traffic budget tests passed\n");
