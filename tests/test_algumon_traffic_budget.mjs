import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { runInNewContext } from "node:vm";

import {
  AlgumonRequestBudgetExceeded,
  DEFAULT_ALGUMON_REQUEST_START_BUDGET,
  capturedAlgumonTargetsFromReport,
  classifyAlgumonSourceResponse,
  countExistingApprovedLayoutMatches,
  createAlgumonRequestStartBudget,
  createLowTrafficAlgumonProbePlan,
  navigateAlgumonSourcePage,
  transferAlgumonRelaySession,
} from "../scripts/audit_pages.mjs";

function signedRelayUrl(dealId, timestampMs, fill) {
  return `https://www.algumon.com/l/d/${dealId}?v=${fill.repeat(32)}&t=${timestampMs}`;
}

function capturedSnapshotFixture(currentRelay = false) {
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
    const legacySignedUrl = signedRelayUrl(dealId, timestampMs, String(index + 1));
    const signedUrl = currentRelay
      ? `${legacySignedUrl.replace("/l/d/", "/n/d/")}&enc=v1.fixture_iv.fixture_tag.fixture_ciphertext`
      : legacySignedUrl;
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

function testCurrentEncryptedRelaySnapshotRetainsExactProvenance() {
  const { candidate, capturedReport, site } = capturedSnapshotFixture(true);
  const captured = capturedAlgumonTargetsFromReport(capturedReport, candidate, [site]);
  assert.equal(captured.targetCount, 3);
  assert.deepEqual(
    captured.targets.map(({ target }) => target.algumon.redirectUrl),
    capturedReport.results.map((result) => result.algumonSeed.redirectUrl),
    "the complete encrypted relay URL survives sealed snapshot reuse unchanged",
  );
  const forged = structuredClone(capturedReport);
  forged.results[0].algumonSeed.redirectUrl += "x";
  assert.throws(
    () => capturedAlgumonTargetsFromReport(forged, candidate, [site]),
    /internally inconsistent|contradicts|disagrees|mismatch/u,
    "changing encrypted destination bytes invalidates the recorded provenance",
  );
}

async function testSourceSessionCookiesStayInMemoryAndInScope() {
  const scopedCookies = [{ name: "source-session", value: "fixture", domain: ".algumon.com", path: "/" }];
  const actions = [];
  const source = { cookies: async (urls) => {
    assert.deepEqual(urls, ["https://www.algumon.com/n/d/1", "https://www.algumon.com/l/d/1"]);
    return scopedCookies;
  } };
  const relay = {
    clearCookies: async () => { actions.push("clear"); },
    addCookies: async (cookies) => { actions.push(cookies); },
  };
  assert.equal(await transferAlgumonRelaySession(source, relay), undefined);
  assert.deepEqual(actions, ["clear", scopedCookies]);
  await assert.rejects(
    () => transferAlgumonRelaySession({ cookies: async () => [
      { ...scopedCookies[0], domain: ".algumon.com.evil.example" },
    ] }, relay),
    /escaped the exact Algumon origin/u,
  );
  assert.equal(actions.length, 2, "invalid source cookies never mutate the private relay context");
}

async function testRegisteredArticleProjectionDoesNotRequireLegacySeed() {
  const layout = { id: "jirum", domain: "clien.net", paths: ["/service/board/jirum/"] };
  const oracleSource = `module.exports = {
    SITE_CONTRACTS: [{ id: "clien", domain: "clien.net", layouts: [${JSON.stringify(layout)}] }],
    pathPatternMatches(path, prefix) { return path.startsWith(prefix); },
    resolveProjectionClasses(document, layouts, seed) {
      if (seed !== null && seed.siteType !== "clien") throw Error("wrong seed");
      return { projectionClasses: layouts.map(layout => [{ layoutId: layout.id }]) };
    }
  };`;
  const pageFor = (hostname) => ({ context: () => ({ newCDPSession: async () => ({
    send: async (method, options) => {
      if (method === "Page.getFrameTree") return { frameTree: { frame: { id: "fixture" } } };
      if (method === "Page.createIsolatedWorld") return { executionContextId: 1 };
      if (method === "Runtime.callFunctionOn") {
        const execute = runInNewContext(`(${options.functionDeclaration})`, {
          location: { hostname, pathname: "/service/board/jirum/123", search: "" },
          document: {},
        });
        return { result: { type: "object", value: execute(options.arguments[0].value) } };
      }
      return {};
    },
    detach: async () => {},
  }) }) });
  const registered = await countExistingApprovedLayoutMatches(pageFor("www.clien.net"), layout, oracleSource, null);
  assert.equal(registered.semanticProjectionCount, 1);
  assert.equal(registered.classes[0].canonicalId, "jirum");
  const seeded = await countExistingApprovedLayoutMatches(pageFor("www.clien.net"), layout, oracleSource, {
    siteType: "clien", title: "쌀", commentCount: 0,
  });
  assert.equal(seeded.semanticProjectionCount, 1);
  const wrongHost = await countExistingApprovedLayoutMatches(pageFor("www.clien.net.evil.example"), layout, oracleSource, null, [layout]);
  assert.equal(wrongHost.semanticProjectionCount, 0, "explicit layouts do not override the exact site hostname");
  const wrongSeed = await countExistingApprovedLayoutMatches(pageFor("www.clien.net"), layout, oracleSource, {
    siteType: "ruliweb", title: "쌀", commentCount: 0,
  });
  assert.equal(wrongSeed.semanticProjectionCount, 0, "a supplied contradictory source identity remains rejected");
}

function testSourceUrlMismatchRetainsDiagnosticIdentityWithoutQueryValues() {
  const failure = classifyAlgumonSourceResponse({
    status: 200,
    contentType: "text/html",
    requestedUrl: "https://www.algumon.com/n/deal",
    responseUrl: "https://www.algumon.com/n/deal",
    finalUrl: "https://www.algumon.com/n/deal?session=not-to-be-recorded#feed",
    title: "알구몬", bodyText: "핫딜",
  });
  assert.equal(failure.kind, "source-or-infrastructure-failure");
  assert.equal(failure.exactUrl, false);
  assert.equal(failure.final.pathKind, "deal-feed");
  assert.equal(failure.final.pathSha256, createHash("sha256").update("/n/deal").digest("hex"));
  assert.deepEqual(failure.final.queryKeys, []);
  assert.equal(failure.final.otherQueryKeyCount, 1);
  assert.equal(failure.final.hasFragment, true);
  assert.equal(failure.response.urlSha256, failure.requested.urlSha256);
  assert.equal(JSON.stringify(failure).includes("not-to-be-recorded"), false);
  assert.notEqual(failure.final.urlSha256, failure.requested.urlSha256);
}

function testSourceFailureRedactsRedirectPathsAndUnknownQueryKeys() {
  const secretUrl = "https://private-user:private-password@www.algumon.com/callback/private-path-token?private-query-key=private-query-value&sites=private-site-value#private-fragment";
  const failure = classifyAlgumonSourceResponse({
    status: null, requestedUrl: secretUrl, finalUrl: secretUrl, responseUrl: secretUrl,
  });
  for (const description of [failure.requested, failure.final, failure.response]) {
    assert.equal(description.pathKind, "other");
    assert.equal(description.pathDepth, 2);
    assert.equal(description.trailingSlash, false);
    assert.equal(description.pathSha256, createHash("sha256").update("/callback/private-path-token").digest("hex"));
    assert.deepEqual(description.queryKeys, ["sites"]);
    assert.equal(description.otherQueryKeyCount, 1);
    assert.equal(description.hasFragment, true);
    assert.equal(Object.hasOwn(description, "pathname"), false);
  }
  assert.equal(JSON.stringify(failure).includes("private-"), false);
  assert.equal(JSON.stringify(failure).includes("/callback/"), false);
}

async function testNavigationErrorsPersistOnlyCategoryAndDigest() {
  const requestedUrl = "https://www.algumon.com/n/deal?session=private-query-token";
  for (const [prefix, category] of [
    ["page.goto: Timeout 30000ms exceeded", "timeout"],
    ["page.goto: net::ERR_CONNECTION_RESET", "network"],
    ["page.goto: Target page closed", "navigation-failed"],
  ]) {
    const message = `${prefix}\nCall log:\n- navigating to "${requestedUrl}"\n` +
      "- redirected to https://www.algumon.com/private-navigation-path?token=private-redirect-token";
    const expected = {
      category,
      errorSha256: createHash("sha256").update(message).digest("hex"),
    };
    const page = {
      goto: async () => { throw new Error(message); },
      url: () => "about:blank",
      title: async () => "",
      locator: () => ({ innerText: async () => "" }),
    };
    const response = await navigateAlgumonSourcePage(page, requestedUrl, 30_000);
    assert.deepEqual(response.navigationError, expected, "raw navigation exceptions are removed at capture");
    for (const navigationError of [message, new Error(message), expected, { ...expected, raw: message }]) {
      const failure = classifyAlgumonSourceResponse({ ...response, navigationError });
      assert.deepEqual(failure.navigationError, expected, "classification never forwards unchecked error fields");
      for (const secret of ["private-query-token", "private-navigation-path", "private-redirect-token", "Call log:"]) {
        assert.equal(JSON.stringify(failure).includes(secret), false, secret);
      }
    }
  }
  assert.equal(classifyAlgumonSourceResponse({ status: null }).navigationError, null);
}

testLowTrafficProbePlan();
testHardRequestStartBudget();
testCapturedSnapshotProducesNoSourceRequests();
testCurrentEncryptedRelaySnapshotRetainsExactProvenance();
await testSourceSessionCookiesStayInMemoryAndInScope();
await testRegisteredArticleProjectionDoesNotRequireLegacySeed();
testSourceUrlMismatchRetainsDiagnosticIdentityWithoutQueryValues();
testSourceFailureRedactsRedirectPathsAndUnknownQueryKeys();
await testNavigationErrorsPersistOnlyCategoryAndDigest();
process.stdout.write("Algumon traffic budget tests passed\n");
