import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { runInNewContext } from "node:vm";

import {
  AlgumonRequestBudgetExceeded,
  DEFAULT_ALGUMON_REQUEST_START_BUDGET,
  capturedAlgumonTargetsFromReport,
  classifyAlgumonSourceResponse,
  captureAlgumonSourceFailure,
  clickConfirmedAlgumonCheckboxOnce,
  countExistingApprovedLayoutMatches,
  createAlgumonRequestStartBudget,
  createAlgumonSourceBrowserBudget,
  createLowTrafficAlgumonProbePlan,
  finishAlgumonSourceBrowser,
  navigateAlgumonSourcePage,
  navigateAlgumonSourceSession,
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

function testSourceBrowserKeepsNormalResourcesAndBoundsNavigation() {
  const feed = "https://www.algumon.com/n/deal";
  const budget = createAlgumonSourceBrowserBudget(feed);
  assert.equal(budget.observe(feed, true).allowed, true);
  for (let index = 0; index < 600; index += 1) {
    assert.equal(budget.observe(`https://cdn.algumon.com/asset-${index}.js`, false).allowed, true,
      "normal resources reuse the established network cap, not an arbitrary small source cap");
  }
  assert.equal(budget.observe("https://www.algumon.com/request/check?token=fixture", true).allowed, true);
  assert.equal(budget.observe(feed, true).allowed, true);
  assert.equal(budget.snapshot().requestStarts, 603);
  assert.equal(budget.snapshot().subresourceStarts, 600);
  assert.equal(budget.observe("https://unrelated.example/feed", true).allowed, false);
  assert.deepEqual(budget.snapshot().violations, ["source-browser-navigation-origin-denied"]);
  const looping = createAlgumonSourceBrowserBudget(feed);
  for (let index = 0; index < looping.snapshot().maximumNavigationStarts; index += 1) {
    assert.equal(looping.observe(feed, true).allowed, true);
  }
  assert.equal(looping.observe(feed, true).reason, "source-browser-navigation-budget-exceeded");
  const wrongInitial = createAlgumonSourceBrowserBudget(feed);
  assert.equal(wrongInitial.observe("https://www.algumon.com/request/check", true).allowed, false);
  const deduplicated = createAlgumonSourceBrowserBudget(feed);
  const request = { url: () => feed, isNavigationRequest: () => true,
    frame: () => ({ parentFrame: () => null }) };
  assert.equal(deduplicated.observeRequest(request).allowed, true);
  assert.equal(deduplicated.observeRequest(request).allowed, true);
  assert.equal(deduplicated.snapshot().requestStarts, 1, "request and route observe the same start once");
}

async function testSourceBrowserBudgetSurvivesFailedSeal() {
  const budget = createAlgumonSourceBrowserBudget("https://www.algumon.com/n/deal");
  budget.observe("https://www.algumon.com/n/deal", true);
  budget.observe("https://www.algumon.com/check.js", false);
  const transition = { actual: {} };
  const result = await finishAlgumonSourceBrowser({
    sealNetworkPolicyEvidence: async () => { throw new Error("closed context https://example.test/private-token"); },
    sourceBrowserBudgetSnapshot: () => budget.snapshot(),
  }, { status: "ok", failures: [], links: [{}] }, transition);
  assert.equal(result.status, "source-or-infrastructure-failure");
  assert.deepEqual(result.links, []);
  assert.deepEqual(result.failures, ["source-browser-network-seal-failed"]);
  assert.equal(transition.actual.sourceBrowserRequestStarts, 2);
  assert.equal(transition.actual.sourceBrowserNavigationStarts, 1);
  assert.equal(transition.actual.sourceBrowserSubresourceStarts, 1);
  assert.equal(JSON.stringify(result).includes("private-token"), false);
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

async function testSourceHostIsApprovedBeforeNavigation() {
  for (const requestedUrl of [
    "https://www.algumon.com/n/deal",
    "https://www.algumon.com/n/deal?sites=CLIEN",
  ]) {
    const calls = [];
    const session = {
      approvePublicHost: async (hostname) => {
        calls.push(["approve", hostname]);
        return ["1.1.1.1"];
      },
      page: {
        on: () => {}, off: () => {},
        goto: async (url) => {
          calls.push(["goto", url]);
          throw new Error("fixture navigation ends after approval");
        },
        url: () => "about:blank",
        title: async () => "",
        locator: () => ({ innerText: async () => "" }),
      },
    };
    await navigateAlgumonSourceSession(session, requestedUrl, 1_000);
    assert.deepEqual(calls, [["approve", "www.algumon.com"], ["goto", requestedUrl]]);

    for (const addresses of [[], ["127.0.0.1"], ["1.1.1.1", "::1"]]) {
      calls.length = 0;
      await assert.rejects(navigateAlgumonSourceSession({
        ...session, approvePublicHost: async () => addresses,
      }, requestedUrl, 1_000), /no verified public DNS/);
      assert.deepEqual(calls, [], "unverified addresses must not begin source navigation");
    }
    calls.length = 0;
    await assert.rejects(navigateAlgumonSourceSession(
      session, "https://unrelated.example/n/deal", 1_000,
    ), /priming refused/);
    assert.deepEqual(calls, [], "source priming must not expand navigation domains");
  }
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
      on: () => {}, off: () => {},
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

async function testExplicitSourceCheckboxIsAtMostOnce() {
  for (const mode of ["success", "timeout", "hidden", "disabled", "foreign-frame", "foreign-page"]) {
    let clicks = 0;
    const checkbox = {
      isVisible: async () => mode !== "hidden",
      isEnabled: async () => mode !== "disabled",
      click: async () => {
        clicks += 1;
        if (mode === "timeout") throw new Error("Timeout private-query-token");
      },
    };
    const page = {
      url: () => mode === "foreign-page" ? "https://unrelated.example/" : "https://www.algumon.com/request/check",
      frames: () => [{
        url: () => mode === "foreign-frame" ? "https://unrelated.example/" : "https://challenges.cloudflare.com/widget",
        getByRole: (role) => {
          assert.equal(role, "checkbox");
          return { count: async () => 1, nth: () => checkbox };
        },
      }],
    };
    assert.equal(await clickConfirmedAlgumonCheckboxOnce(page, null), false);
    assert.equal(clicks, 0, "default and scheduled runs do not click");
    const interaction = { confirmed: true, attempted: false };
    await clickConfirmedAlgumonCheckboxOnce(page, interaction);
    await clickConfirmedAlgumonCheckboxOnce(page, interaction);
    assert.equal(clicks, ["success", "timeout"].includes(mode) ? 1 : 0, mode);
    if (mode === "success") assert.equal(interaction.outcome, "clicked");
    if (mode === "timeout") {
      assert.equal(interaction.outcome, "click-failed");
      assert.equal(interaction.error.category, "timeout");
      assert.equal(JSON.stringify(interaction).includes("private-query-token"), false);
    }
  }
}

async function testSourceBrowserLocalFlows() {
  const { chromium } = await import("playwright");
  const browser = await chromium.launch({ headless: true });
  const feed = "https://www.algumon.com/n/deal";
  try {
    for (const mode of ["normal", "reload-loop", "other-origin"]) {
      const context = await browser.newContext();
      const budget = createAlgumonSourceBrowserBudget(feed);
      const requests = [];
      let feedVisits = 0;
      context.on("request", request => {
        const decision = budget.observeRequest(request);
        requests.push(request.url());
        if (!decision.allowed) void context.close().catch(() => {});
      });
      await context.route("**/*", async route => {
        if (!budget.observeRequest(route.request()).allowed) {
          await route.abort().catch(() => {});
          return;
        }
        const url = new URL(route.request().url());
        if (url.pathname === "/verify.js") {
          return route.fulfill({ contentType: "application/javascript", body:
            'setTimeout(() => location.replace("/request/check?step=1"), 25);' });
        }
        if (url.pathname === "/style.css") {
          return route.fulfill({ contentType: "text/css", body: "body { color: rgb(0, 0, 0); }" });
        }
        if (url.pathname === "/logo.svg") {
          return route.fulfill({ contentType: "image/svg+xml", body:
            '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12"><rect width="12" height="12"/></svg>' });
        }
        let body;
        if (url.href === feed) {
          feedVisits += 1;
          body = mode === "reload-loop"
            ? '<script>setTimeout(() => location.reload(), 0)</script>'
            : mode === "other-origin"
              ? '<script>location.replace("https://unrelated.invalid/not-the-feed")</script>'
              : feedVisits === 1
                ? '<link rel="stylesheet" href="/style.css"><img src="/logo.svg"><script src="/verify.js"></script>'
                : '<div class="deal-feed-card" id="deal-1001">정상 핫딜</div>';
        } else if (url.pathname === "/request/check") {
          const next = url.searchParams.get("step") === "1" ? "/request/check?step=2" : "/n/deal";
          body = `<script>setTimeout(() => location.replace(${JSON.stringify(next)}), 30)</script>`;
        } else throw new Error(`unexpected fixture URL: ${url.href}`);
        await route.fulfill({ contentType: "text/html; charset=utf-8",
          body: `<!doctype html><html><head><title>알구몬</title></head><body>${body}</body></html>` });
      });
      const page = await context.newPage();
      // A main-world query may lose its context while the original JS navigates.
      // The next observation must still receive the remaining settlement time.
      if (mode === "normal") {
        const title = page.title.bind(page);
        let interrupted = false;
        page.title = async () => {
          if (!interrupted) { interrupted = true; throw new Error("Execution context was destroyed"); }
          return title();
        };
      }
      try {
        const evidence = await navigateAlgumonSourcePage(page, feed, 3_000);
        assert.equal(budget.snapshot().requestStarts, requests.length,
          `${mode}: observing route and request must not count a browser start twice`);
        if (mode === "normal") {
          assert.equal(classifyAlgumonSourceResponse(evidence), null, JSON.stringify(evidence));
          assert.equal(evidence.finalUrl, feed);
          assert.equal(feedVisits, 2);
          assert.equal(budget.snapshot().navigationStarts, 4);
          for (const path of ["/verify.js", "/style.css", "/logo.svg"]) {
            assert.ok(requests.includes(new URL(path, feed).href), `${path} must load normally`);
          }
        } else {
          assert.notEqual(classifyAlgumonSourceResponse(evidence), null);
          assert.equal(budget.snapshot().blockedStarts, 1);
          assert.deepEqual(budget.snapshot().violations, [mode === "reload-loop"
            ? "source-browser-navigation-budget-exceeded" : "source-browser-navigation-origin-denied"]);
        }
      } finally { await context.close(); }
    }
  } finally { await browser.close(); }
  process.stdout.write("Algumon local browser: normal JS/resource return, reload bound, and foreign-origin rejection passed\n");
}

async function testConfirmedCheckboxBrowserFlow() {
  const { chromium } = await import("playwright");
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext();
    await context.route("**/*", async (route) => {
      const isWidget = new URL(route.request().url()).hostname === "challenges.cloudflare.com";
      await route.fulfill({ contentType: "text/html; charset=utf-8", body: isWidget
        ? '<label><input type="checkbox" onclick="parent.postMessage(\'checked\', \'https://www.algumon.com\')">Confirm fixture</label>'
        : '<body data-clicks="0"><iframe src="https://challenges.cloudflare.com/widget"></iframe><script>addEventListener("message", event => { if (event.origin === "https://challenges.cloudflare.com" && event.data === "checked") document.body.dataset.clicks = String(Number(document.body.dataset.clicks) + 1); });</script></body>',
      });
    });
    const page = await context.newPage();
    await page.goto("https://www.algumon.com/request/check");
    await page.frameLocator("iframe").getByRole("checkbox").waitFor({ state: "visible" });
    await clickConfirmedAlgumonCheckboxOnce(page, null);
    assert.equal(await page.locator("body").getAttribute("data-clicks"), "0");
    const interaction = { confirmed: true, attempted: false };
    await clickConfirmedAlgumonCheckboxOnce(page, interaction);
    await page.waitForFunction(() => document.body.dataset.clicks === "1");
    await clickConfirmedAlgumonCheckboxOnce(page, interaction);
    assert.equal(await page.locator("body").getAttribute("data-clicks"), "1");
    assert.equal(interaction.outcome, "clicked");
  } finally { await browser.close(); }
  process.stdout.write("Confirmed source checkbox: local cross-origin browser click occurred exactly once\n");
}

async function testSourceFailureScreenshotAddsNoNavigation() {
  const calls = [];
  const page = {
    goto: () => { throw new Error("a failure screenshot must not navigate again"); },
    screenshot: async (options) => { calls.push(options); return Buffer.from("fixture-png"); },
  };
  assert.equal(await captureAlgumonSourceFailure(page, null), null);
  assert.equal(calls.length, 0);
  const captured = await captureAlgumonSourceFailure(page, "fixture-output");
  assert.equal(captured.filename, "algumon-global-source-failure.png");
  assert.equal(captured.viewportBounded, true);
  assert.equal(captured.byteLength, 11);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].fullPage, false);
  assert.equal(calls[0].timeout, 10_000);
  const failed = await captureAlgumonSourceFailure({
    screenshot: async () => { throw new Error("Timeout at https://example.com/private-token"); },
  }, "fixture-output");
  assert.equal(failed.filename, null);
  assert.equal(failed.error.category, "timeout");
  assert.equal(JSON.stringify(failed).includes("private-token"), false);
}

testLowTrafficProbePlan();
testHardRequestStartBudget();
testSourceBrowserKeepsNormalResourcesAndBoundsNavigation();
await testSourceBrowserBudgetSurvivesFailedSeal();
testCapturedSnapshotProducesNoSourceRequests();
testCurrentEncryptedRelaySnapshotRetainsExactProvenance();
await testSourceSessionCookiesStayInMemoryAndInScope();
await testRegisteredArticleProjectionDoesNotRequireLegacySeed();
testSourceUrlMismatchRetainsDiagnosticIdentityWithoutQueryValues();
testSourceFailureRedactsRedirectPathsAndUnknownQueryKeys();
await testNavigationErrorsPersistOnlyCategoryAndDigest();
await testExplicitSourceCheckboxIsAtMostOnce();
await testSourceHostIsApprovedBeforeNavigation();
await testSourceFailureScreenshotAddsNoNavigation();
if (process.argv.includes("--browser-fixture")) {
  await testSourceBrowserLocalFlows();
  await testConfirmedCheckboxBrowserFlow();
}
process.stdout.write("Algumon traffic budget tests passed\n");
