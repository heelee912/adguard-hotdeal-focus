import assert from "node:assert/strict";
import vm from "node:vm";
import { EventEmitter } from "node:events";

import {
  FIRST_PAINT_PROBE_SOURCE,
  canonicalArticleIdentity,
  collectRetainedRoleResourceEvidence,
  consumeArticleAccessLease,
  createArticleAccessLease,
  createNetworkPolicyEvidenceRecorder,
  createStylesheetDependencyRecorder,
  isPrivateOrSpecialIp,
  networkFidelityFailures,
  networkRequestDecision,
  networkRequestRedirectEvidence,
  networkResourceUrlSha256,
  observeStylesheetDependencies,
  parseConnectAuthority,
  primeDeclaredArticleNavigation,
  retainUnobservedSessionNetworkPolicy,
  validatePublicDnsAnswers,
} from "../scripts/audit_pages.mjs";

function assertDecision(label, input, expected) {
  assert.deepEqual(
    networkRequestDecision(
      input.url,
      input.isMainNavigation,
      input.allowedNavigationDomains,
      input.allowedResourceDomains,
      input.exactResourceHosts,
      input.allowPublicHttpsSubresources,
    ),
    expected,
    label,
  );
}

function testNetworkPolicyTable() {
  const declared = {
    allowedNavigationDomains: ["example.com"],
    allowedResourceDomains: ["example.com", "static.example.com"],
    exactResourceHosts: ["challenge.example.net"],
  };
  const cases = [
    {
      label: "declared HTTPS main document is allowed",
      input: {
        ...declared,
        url: "https://example.com/deal/1",
        isMainNavigation: true,
        allowPublicHttpsSubresources: true,
      },
      expected: {
        allowed: true,
        reason: "declared-navigation-domain",
        hostname: "example.com",
      },
    },
    {
      label: "declared mobile subdomain is part of the declared domain family",
      input: {
        ...declared,
        url: "https://m.example.com/deal/1",
        isMainNavigation: true,
        allowPublicHttpsSubresources: true,
      },
      expected: {
        allowed: true,
        reason: "declared-navigation-domain",
        hostname: "m.example.com",
      },
    },
    {
      label: "broad public mode never expands top-level navigation",
      input: {
        ...declared,
        url: "https://undeclared.example.net/deal/1",
        isMainNavigation: true,
        allowPublicHttpsSubresources: true,
      },
      expected: {
        allowed: false,
        reason: "top-level-navigation-denied",
        hostname: "undeclared.example.net",
      },
    },
    {
      label: "declared resource host is classified before broad public mode",
      input: {
        ...declared,
        url: "https://static.example.com/image.webp",
        isMainNavigation: false,
        allowPublicHttpsSubresources: true,
      },
      expected: {
        allowed: true,
        reason: "declared-resource-domain",
        hostname: "static.example.com",
      },
    },
    {
      label: "exact challenge host is classified before broad public mode",
      input: {
        ...declared,
        url: "https://challenge.example.net/widget.js",
        isMainNavigation: false,
        allowPublicHttpsSubresources: true,
      },
      expected: {
        allowed: true,
        reason: "exact-challenge-subresource",
        hostname: "challenge.example.net",
      },
    },
    {
      label: "challenge allowance is exact and does not include subdomains",
      input: {
        ...declared,
        url: "https://nested.challenge.example.net/widget.js",
        isMainNavigation: false,
        allowPublicHttpsSubresources: false,
      },
      expected: {
        allowed: false,
        reason: "resource-host-denied",
        hostname: "nested.challenge.example.net",
      },
    },
    {
      label: "undeclared HTTPS subresource is allowed only in bounded live mode",
      input: {
        ...declared,
        url: "https://cdn.example.net/image.webp",
        isMainNavigation: false,
        allowPublicHttpsSubresources: true,
      },
      expected: {
        allowed: true,
        reason: "bounded-public-https-subresource",
        hostname: "cdn.example.net",
      },
    },
    {
      label: "fixture mode rejects undeclared HTTPS subresources",
      input: {
        ...declared,
        url: "https://cdn.example.net/image.webp",
        isMainNavigation: false,
        allowPublicHttpsSubresources: false,
      },
      expected: {
        allowed: false,
        reason: "resource-host-denied",
        hostname: "cdn.example.net",
      },
    },
    {
      label: "WSS is eligible only as a subresource",
      input: {
        ...declared,
        url: "wss://events.example.net/socket",
        isMainNavigation: false,
        allowPublicHttpsSubresources: true,
      },
      expected: {
        allowed: true,
        reason: "bounded-public-https-subresource",
        hostname: "events.example.net",
      },
    },
    {
      label: "insecure WebSocket is rejected",
      input: {
        ...declared,
        url: "ws://events.example.net/socket",
        isMainNavigation: false,
        allowPublicHttpsSubresources: true,
      },
      expected: {
        allowed: false,
        reason: "https-required",
        hostname: "events.example.net",
      },
    },
    {
      label: "HTTP is rejected even for a declared navigation domain",
      input: {
        ...declared,
        url: "http://example.com/deal/1",
        isMainNavigation: true,
        allowPublicHttpsSubresources: true,
      },
      expected: {
        allowed: false,
        reason: "https-required",
        hostname: "example.com",
      },
    },
    {
      label: "non-default authority is rejected",
      input: {
        ...declared,
        url: "https://example.com:444/deal/1",
        isMainNavigation: true,
        allowPublicHttpsSubresources: true,
      },
      expected: {
        allowed: false,
        reason: "credentialed-or-non-default-authority",
        hostname: "example.com",
      },
    },
    {
      label: "credentialed authority is rejected",
      input: {
        ...declared,
        url: "https://user:secret@example.com/deal/1",
        isMainNavigation: true,
        allowPublicHttpsSubresources: true,
      },
      expected: {
        allowed: false,
        reason: "credentialed-or-non-default-authority",
        hostname: "example.com",
      },
    },
    {
      label: "literal public IP is rejected before transport approval",
      input: {
        ...declared,
        url: "https://1.1.1.1/image.webp",
        isMainNavigation: false,
        allowPublicHttpsSubresources: true,
      },
      expected: {
        allowed: false,
        reason: "forbidden-infrastructure",
        hostname: "1.1.1.1",
      },
    },
    {
      label: "about blank remains available for browser bootstrap",
      input: {
        ...declared,
        url: "about:blank",
        isMainNavigation: true,
        allowPublicHttpsSubresources: true,
      },
      expected: {
        allowed: true,
        reason: "local-browser-scheme",
        hostname: null,
      },
    },
    {
      label: "data main-document escape is rejected",
      input: {
        ...declared,
        url: "data:text/html,escape",
        isMainNavigation: true,
        allowPublicHttpsSubresources: true,
      },
      expected: {
        allowed: false,
        reason: "local-top-level-navigation-denied",
        hostname: null,
      },
    },
    {
      label: "blob main-document escape is rejected",
      input: {
        ...declared,
        url: "blob:https://example.com/2a97a76e-2a56-43f8-9bc0-791f67bb9aa3",
        isMainNavigation: true,
        allowPublicHttpsSubresources: true,
      },
      expected: {
        allowed: false,
        reason: "local-top-level-navigation-denied",
        hostname: null,
      },
    },
    {
      label: "invalid URL is rejected",
      input: {
        ...declared,
        url: "not a URL",
        isMainNavigation: false,
        allowPublicHttpsSubresources: true,
      },
      expected: { allowed: false, reason: "invalid-url", hostname: null },
    },
  ];

  for (const { label, input, expected } of cases) {
    assertDecision(label, input, expected);
  }
}

function finishReservation(reservation) {
  reservation.finish();
  reservation.finish();
}

function testRemoteHostBudgetBoundary() {
  const recorder = createNetworkPolicyEvidenceRecorder({
    maximumRemoteHosts: 128,
    maximumRemoteRequests: 4_096,
  });
  for (let index = 0; index < 128; index += 1) {
    const reservation = recorder.reserveRemoteRequest(`host-${index}.example`);
    assert.equal(reservation.allowed, true, `host ${index + 1} should fit the host budget`);
    finishReservation(reservation);
  }
  const overflow = recorder.reserveRemoteRequest("host-128.example");
  assert.equal(overflow.allowed, false);
  assert.equal(overflow.reason, "remote-host-budget-exceeded");
  finishReservation(overflow);

  const evidence = recorder.snapshot();
  assert.equal(evidence.attemptedRemoteHostCount, 128);
  assert.equal(evidence.attemptedRemoteRequestCount, 129);
  assert.equal(evidence.remoteHostBudgetOverflowCount, 1);
  assert.equal(evidence.activeRemoteRequestCount, 0);
}

function testRemoteRequestBudgetBoundary() {
  const recorder = createNetworkPolicyEvidenceRecorder({
    maximumRemoteHosts: 128,
    maximumRemoteRequests: 4_096,
  });
  for (let index = 0; index < 4_096; index += 1) {
    const reservation = recorder.reserveRemoteRequest("one.example");
    assert.equal(reservation.allowed, true, `request ${index + 1} should fit the request budget`);
    finishReservation(reservation);
  }
  const overflow = recorder.reserveRemoteRequest("one.example");
  assert.equal(overflow.allowed, false);
  assert.equal(overflow.reason, "remote-request-budget-exceeded");
  finishReservation(overflow);

  const evidence = recorder.snapshot();
  assert.equal(evidence.attemptedRemoteHostCount, 1);
  assert.equal(evidence.attemptedRemoteRequestCount, 4_097);
  assert.equal(evidence.remoteRequestBudgetOverflowCount, 1);
  assert.equal(evidence.activeRemoteRequestCount, 0);
}

function testConcurrentReservations() {
  const recorder = createNetworkPolicyEvidenceRecorder();
  const first = recorder.reserveRemoteRequest("a.example");
  const second = recorder.reserveRemoteRequest("b.example");
  const third = recorder.reserveRemoteRequest("a.example");

  assert.equal(recorder.snapshot().activeRemoteRequestCount, 3);
  finishReservation(second);
  assert.equal(recorder.snapshot().activeRemoteRequestCount, 2);
  finishReservation(first);
  finishReservation(third);
  assert.equal(recorder.snapshot().activeRemoteRequestCount, 0);
  assert.equal(recorder.snapshot().attemptedRemoteHostCount, 2);
  assert.equal(recorder.snapshot().attemptedRemoteRequestCount, 3);
}

function testOptionalFailuresStayObservedWhileArticleResourcesRemainRequired() {
  const recorder = createNetworkPolicyEvidenceRecorder();
  recorder.recordAllowedRequestFailure(
    "ads.example",
    "script",
    "net::ERR_CONNECTION_RESET",
    false,
    "https://ads.example/collect/private-token?secret=value",
  );
  recorder.recordAllowedResponseFailure("api.example", "fetch", 503, false,
    "https://api.example/analytics?secret=value");

  const evidence = recorder.snapshot();
  assert.deepEqual(evidence.failedAllowedRequestHosts, [{
    hostname: "ads.example",
    count: 1,
    mainNavigationCount: 0,
    requestTypes: ["script"],
    reasons: ["net::ERR_CONNECTION_RESET"],
  }]);
  assert.deepEqual(evidence.failedAllowedResponseHosts, [{
    hostname: "api.example",
    count: 1,
    mainNavigationCount: 0,
    requestTypes: ["fetch"],
    reasons: ["http-503"],
  }]);
  assert.deepEqual(networkFidelityFailures(evidence), [], "unrelated ads and analytics must not reject an article");
  assert.equal(JSON.stringify(evidence).includes("private-token"), false);
  assert.equal(JSON.stringify(evidence).includes("secret=value"), false);
  const failures = networkFidelityFailures(evidence, [], {
    hosts: ["ads.example", "api.example"],
    urlSha256s: [
      networkResourceUrlSha256("https://ads.example/collect/private-token?secret=value"),
      networkResourceUrlSha256("https://api.example/analytics?secret=value"),
    ],
  });
  assert.ok(failures.includes("an allowed remote request failed before a complete response"));
  assert.ok(failures.includes("an allowed remote response returned HTTP 4xx or 5xx"));
  const sameHost = createNetworkPolicyEvidenceRecorder();
  sameHost.recordAllowedResponseFailure("article.example", "script", 404, false,
    "https://article.example/obsolete-analytics.js");
  const articleResources = { hosts: ["article.example"], urlSha256s: [
    networkResourceUrlSha256("https://article.example/product.webp"),
    networkResourceUrlSha256("https://article.example/article.css"),
  ] };
  assert.deepEqual(networkFidelityFailures(sameHost.snapshot(), ["article.example"], articleResources), [],
    "a stale same-origin analytics script must not be confused with an article resource");
  sameHost.recordAllowedRequestFailure("article.example", "image", "net::ERR_ABORTED", false,
    "https://article.example/product.webp#ignored");
  sameHost.recordAllowedResponseFailure("article.example", "stylesheet", 404, false,
    "https://article.example/article.css");
  assert.equal(networkFidelityFailures(sameHost.snapshot(), ["article.example"], articleResources).length, 2);
  const document = createNetworkPolicyEvidenceRecorder();
  document.recordAllowedRequestFailure("article.example", "document", "net::ERR_ABORTED", true,
    "https://article.example/deal/1");
  assert.equal(networkFidelityFailures(document.snapshot()).length, 1,
    "main document failures remain terminal without any role evidence");
}

function redirectRequestChain(urls) {
  return urls.reduce((ancestor, url) => ({ url: () => url, redirectedFrom: () => ancestor }), null);
}

function testRedirectedArticleResourceFailuresRemainRequired() {
  const urls = [
    "https://article.example/private-photo?signature=original-secret",
    "https://images.example/private-hop?signature=intermediate-secret",
    "https://cdn.example/private-final?signature=final-secret#ignored",
  ];
  const request = redirectRequestChain(urls);
  const redirectEvidence = networkRequestRedirectEvidence(request);
  assert.deepEqual(redirectEvidence, {
    ancestorUrlSha256s: urls.slice(0, -1).reverse().map(networkResourceUrlSha256),
    status: "complete",
  });
  const recorder = createNetworkPolicyEvidenceRecorder();
  recorder.recordAllowedRequestFailure("cdn.example", "image", "net::ERR_CONNECTION_RESET", false,
    request.url(), redirectEvidence);
  const snapshot = recorder.snapshot();
  for (const url of urls) {
    assert.deepEqual(networkFidelityFailures(snapshot, [], {
      hosts: [], urlSha256s: [networkResourceUrlSha256(url)],
    }), ["an allowed remote request failed before a complete response"],
    "a retained original, intermediate, or final resource URL must identify a failed redirect chain");
  }
  assert.deepEqual(networkFidelityFailures(snapshot, ["cdn.example"], {
    hosts: ["cdn.example"], urlSha256s: [networkResourceUrlSha256("https://cdn.example/unrelated.webp")],
  }), [], "unrelated redirected advertising remains observed without rejecting the article");
  for (const sensitiveText of ["private-photo", "private-hop", "private-final", "signature=", "secret"]) {
    assert.equal(JSON.stringify(snapshot).includes(sensitiveText), false, sensitiveText);
  }
  snapshot.failedAllowedRequests[0].redirectAncestorUrlSha256s.length = 0;
  assert.equal(recorder.snapshot().failedAllowedRequests[0].redirectAncestorUrlSha256s.length, 2,
    "snapshot consumers cannot mutate recorded ancestry");

  const stylesheet = redirectRequestChain([
    "https://article.example/article.css", "https://cdn.example/article-v2.css",
  ]);
  const responses = createNetworkPolicyEvidenceRecorder();
  responses.recordAllowedResponseFailure("cdn.example", "stylesheet", 503, false,
    stylesheet.url(), networkRequestRedirectEvidence(stylesheet));
  assert.deepEqual(networkFidelityFailures(responses.snapshot(), [], {
    hosts: [], urlSha256s: [networkResourceUrlSha256("https://article.example/article.css")],
  }), ["an allowed remote response returned HTTP 4xx or 5xx"]);
  assert.deepEqual(networkRequestRedirectEvidence(redirectRequestChain([urls[0]])), {
    ancestorUrlSha256s: [], status: "complete",
  });
}

function testRedirectAncestryBoundsAndIncompleteEvidence() {
  const urls = Array.from({ length: 34 }, (_, index) => `https://cdn.example/hop-${index}`);
  const atLimit = networkRequestRedirectEvidence(redirectRequestChain(urls.slice(0, 33)));
  assert.equal(atLimit.status, "complete");
  assert.equal(atLimit.ancestorUrlSha256s.length, 32);
  const overflow = networkRequestRedirectEvidence(redirectRequestChain(urls));
  assert.equal(overflow.status, "overflow");
  assert.equal(overflow.ancestorUrlSha256s.length, 32);
  const cycle = { url: () => urls[0], redirectedFrom: () => cycle };
  const invalid = redirectRequestChain(["not a URL", urls[1]]);
  const unavailable = { url: () => urls[0], redirectedFrom: () => { throw new Error("private-secret"); } };
  for (const [request, status] of [
    [redirectRequestChain(urls), "overflow"], [cycle, "cycle"],
    [invalid, "invalid-url"], [unavailable, "unavailable"],
  ]) {
    const ancestry = networkRequestRedirectEvidence(request);
    assert.equal(ancestry.status, status);
    for (const failureKind of ["request", "response"]) {
      const recorder = createNetworkPolicyEvidenceRecorder();
      if (failureKind === "request") {
        recorder.recordAllowedRequestFailure("cdn.example", "image", "net::ERR_ABORTED", false,
          request.url(), ancestry);
      } else {
        recorder.recordAllowedResponseFailure("cdn.example", "stylesheet", 503, false,
          request.url(), ancestry);
      }
      assert.ok(networkFidelityFailures(recorder.snapshot()).includes(
        "failed resource redirect ancestry was incomplete or cyclic"),
      `${failureKind}: ${status} must not be silently treated as an optional resource`);
      assert.equal(JSON.stringify(recorder.snapshot()).includes("private-secret"), false);
    }
  }
  assert.equal(networkRequestRedirectEvidence(redirectRequestChain([urls[0], urls[0]])).status, "complete",
    "distinct requests sharing one URL are not an object-reference cycle");
}

async function testStylesheetDependenciesPreserveImportedCssAndFonts() {
  const main = "https://article.example/main.css?private=root-token";
  const redirected = "https://styles.example/main.css?private=redirect-token";
  const imported = "https://themes.example/theme.css?private=theme-token";
  const font = "https://fonts.example/article.woff2?private=font-token";
  const event = (url, parent, type = "Stylesheet", frameId = "article-frame") => ({
    frameId, type, request: { url }, initiator: { type: "parser", url: parent },
  });
  const dependencies = createStylesheetDependencyRecorder();
  const session = new EventEmitter();
  const commands = [];
  session.send = async (command) => {
    commands.push(command);
    return command === "Page.getFrameTree" ? { frameTree: { frame: { id: "article-frame" } } } : {};
  };
  session.detach = async () => { commands.push("detach"); };
  const stop = await observeStylesheetDependencies({ newCDPSession: async () => session }, {}, dependencies);
  assert.deepEqual(commands, ["Page.enable", "Page.getFrameTree", "Network.enable"]);
  session.emit("Network.requestWillBeSent", { ...event(redirected, "https://article.example/deal/1"),
    redirectResponse: { url: main } });
  session.emit("Network.requestWillBeSent", event(imported, redirected));
  session.emit("Network.requestWillBeSent", event(font, imported, "Font"));
  // Cyclic CSS imports are harmless to dependency traversal, not an unbounded loop.
  session.emit("Network.requestWillBeSent", event(redirected, imported));
  const optionalUrls = [
    ["https://themes.example/ads.css", "https://ads.example/ad-root.css", "Stylesheet", "article-frame"],
    ["https://fonts.example/ad.woff2", "https://ads.example/ad-root.css", "Font", "article-frame"],
    ["https://themes.example/frame.css", main, "Stylesheet", "ad-frame"],
    ["https://fonts.example/frame.woff2", main, "Font", "ad-frame"],
    ["https://themes.example/analytics", main, "XHR", "article-frame"],
    ["https://fonts.example/analytics.js", main, "Script", "article-frame"],
  ];
  for (const args of optionalUrls) session.emit("Network.requestWillBeSent", event(...args));
  const roleEvidence = { hosts: ["article.example"], urlSha256s: [networkResourceUrlSha256(main)] };
  for (const [url, type] of [[imported, "stylesheet"], [font, "font"]]) {
    const failed = createNetworkPolicyEvidenceRecorder();
    failed.recordAllowedRequestFailure(new URL(url).hostname, type, "net::ERR_CONNECTION_RESET", false, url);
    failed.recordAllowedResponseFailure(new URL(url).hostname, type, 503, false, url);
    const evidence = { ...failed.snapshot(), stylesheetDependencies: dependencies.snapshot() };
    assert.deepEqual(networkFidelityFailures(evidence, [], roleEvidence), [
      "an allowed remote request failed before a complete response",
      "an allowed remote response returned HTTP 4xx or 5xx",
    ], "required cross-origin CSS imports and fonts retain the same failure semantics as their root stylesheet");
  }
  for (const [url, , type] of optionalUrls) {
    const failed = createNetworkPolicyEvidenceRecorder();
    failed.recordAllowedResponseFailure(new URL(url).hostname, type.toLowerCase(), 503, false, url);
    assert.deepEqual(networkFidelityFailures({ ...failed.snapshot(),
      stylesheetDependencies: dependencies.snapshot() }, [], roleEvidence), [],
    "unrelated same-host, other-frame, and non-CSS/font resources stay optional");
  }
  const serialized = JSON.stringify(dependencies.snapshot());
  for (const token of ["private=", "root-token", "redirect-token", "theme-token", "font-token", ".css", ".woff2"]) {
    assert.equal(serialized.includes(token), false, token);
  }
  await stop();
  assert.equal(session.listenerCount("Network.requestWillBeSent"), 0);
  assert.equal(session.listenerCount("Page.frameNavigated"), 0);
  assert.equal(commands.at(-1), "detach", "the CDP session is detached during context cleanup");

  const bounded = createStylesheetDependencyRecorder({ maximumDependencies: 1 });
  bounded.recordRequest(event(imported, main), "article-frame");
  bounded.recordRequest(event(font, imported, "Font"), "article-frame");
  assert.equal(bounded.snapshot().dependencies.length, 1);
  assert.equal(bounded.snapshot().dependencyOverflowCount, 1);
  assert.ok(networkFidelityFailures({ stylesheetDependencies: bounded.snapshot() }, [], roleEvidence)
    .includes("stylesheet dependency evidence was invalid or exceeded its bounded dependency count"));
  const invalid = createStylesheetDependencyRecorder();
  invalid.recordRequest(event(font, "not-a-url", "Font"), "article-frame");
  assert.equal(invalid.snapshot().invalidDependencyCount, 1);
  assert.ok(networkFidelityFailures({ stylesheetDependencies: invalid.snapshot() }, [], roleEvidence)
    .includes("stylesheet dependency evidence was invalid or exceeded its bounded dependency count"));
  const brokenSession = new EventEmitter();
  let detachedAfterFailure = false;
  brokenSession.send = async (command) => {
    if (command === "Network.enable") throw new Error("fixture CDP capture unavailable");
    return command === "Page.getFrameTree" ? { frameTree: { frame: { id: "article-frame" } } } : {};
  };
  brokenSession.detach = async () => { detachedAfterFailure = true; };
  await assert.rejects(() => observeStylesheetDependencies(
    { newCDPSession: async () => brokenSession }, {}, createStylesheetDependencyRecorder()),
  /fixture CDP capture unavailable/u);
  assert.equal(detachedAfterFailure, true);
  assert.equal(brokenSession.listenerCount("Network.requestWillBeSent"), 0);
  assert.equal(brokenSession.listenerCount("Page.frameNavigated"), 0);
}

function testInlineStylesheetDependenciesUseActualDocumentUrl() {
  const documentUrl = "https://article.example/deal/7?private=document-token";
  const baseUri = "https://unrelated.example/private-base/";
  const inlineFont = "https://fonts.example/inline.woff2";
  const inlineStyle = {
    localName: "style", matches: () => false, nextElementSibling: null,
    sheet: { href: null, cssRules: [{ type: 4, cssRules: [
      { type: 5, style: { getPropertyValue: () => `url("${inlineFont}")` } },
    ] }] },
  };
  const roleEvidence = vm.runInNewContext(`(${collectRetainedRoleResourceEvidence.toString()})([])`, {
    document: { URL: documentUrl, baseURI: baseUri, head: { firstElementChild: inlineStyle } },
    performance: { now: () => 0 }, URL,
  });
  assert.deepEqual([...roleEvidence.urls], [documentUrl, inlineFont],
    "the actual document initiator and grouped inline font sources survive a base element");
  const { urls, ...safeEvidence } = roleEvidence;
  safeEvidence.urlSha256s = urls.map(networkResourceUrlSha256);
  const theme = "https://themes.example/inline-theme.css";
  const importedFont = "https://fonts.example/imported.woff2";
  const unrelatedFont = "https://fonts.example/unrelated.woff2";
  const dependencies = createStylesheetDependencyRecorder();
  for (const [url, parent, type] of [
    [theme, documentUrl, "Stylesheet"],
    [importedFont, theme, "Font"],
    [unrelatedFont, baseUri, "Font"],
  ]) {
    dependencies.recordRequest({ frameId: "main", type,
      request: { url }, initiator: { type: "parser", url: parent } }, "main");
  }
  dependencies.recordRequest({ frameId: "main", type: "Font",
    request: { url: inlineFont }, initiator: { type: "other" } }, "main");
  for (const url of [theme, importedFont, inlineFont, unrelatedFont]) {
    const failed = createNetworkPolicyEvidenceRecorder();
    failed.recordAllowedResponseFailure(new URL(url).hostname, url === theme ? "stylesheet" : "font", 503, false, url);
    const actual = networkFidelityFailures({ ...failed.snapshot(), stylesheetDependencies: dependencies.snapshot() }, [], safeEvidence);
    assert.deepEqual(actual, url === unrelatedFont ? [] : ["an allowed remote response returned HTTP 4xx or 5xx"],
      "only document-rooted inline CSS/font dependencies become required");
  }
  const serialized = JSON.stringify({ ...safeEvidence, stylesheetDependencies: dependencies.snapshot() });
  assert.equal(serialized.includes("document-token"), false);
  assert.equal(serialized.includes("/deal/7"), false);
  assert.equal(serialized.includes("private-base"), false);
  inlineStyle.sheet.cssRules = Array.from({ length: 2049 }, () => ({ type: 1 }));
  const overBudget = vm.runInNewContext(`(${collectRetainedRoleResourceEvidence.toString()})([])`, {
    document: { URL: documentUrl, baseURI: baseUri, head: { firstElementChild: inlineStyle } },
    performance: { now: () => 0 }, URL,
  });
  assert.equal(overBudget.stylesheetRuleCount, 2048);
  assert.equal(overBudget.stylesheetRuleOverflowCount, 1);
  assert.ok(networkFidelityFailures({}, [], overBudget)
    .includes("inline stylesheet font evidence was unreadable or exceeded its bounded rule count"));
}

function testRetainedComputedUrlPropertiesExcludeUnrelatedImages() {
  const properties = ["maskImage", "webkitMaskImage", "borderImageSource", "maskBorderSource",
    "webkitMaskBoxImageSource", "cursor", "shapeOutside", "filter", "backdropFilter",
    "webkitBackdropFilter", "clipPath", "offsetPath", "fill", "stroke", "markerStart",
    "markerMid", "markerEnd", "webkitBoxReflect"];
  class FixtureElement {
    localName = "div";
    children = [];
    style = {};
    getAttribute() { return null; }
  }
  const element = new FixtureElement();
  const computedStyle = Object.fromEntries(properties.map((name) => [name,
    `url("https://cdn.example/retained-${name}.svg?private=resource-token#shape")`]));
  computedStyle["--unused-image"] = 'url("https://cdn.example/unused-ad.webp")';
  const { urls, ...roleEvidence } = vm.runInNewContext(
    `(${collectRetainedRoleResourceEvidence.toString()})(["#article"])`, {
      Element: FixtureElement,
      document: { URL: "https://article.example/deal/7", baseURI: "https://article.example/deal/7",
        head: null, querySelector: () => element },
      window: { getComputedStyle: () => computedStyle },
      performance: { now: () => 0 }, URL,
    });
  roleEvidence.urlSha256s = urls.map(networkResourceUrlSha256);
  assert.equal(urls.length, properties.length + 1, "resolved aliases and pseudo-elements are URL-deduplicated");
  for (const property of properties) {
    const recorder = createNetworkPolicyEvidenceRecorder();
    recorder.recordAllowedRequestFailure("cdn.example", "image", "net::ERR_FAILED", false,
      `https://cdn.example/retained-${property}.svg?private=resource-token`);
    assert.deepEqual(networkFidelityFailures(recorder.snapshot(), [], roleEvidence),
      ["an allowed remote request failed before a complete response"], property);
  }
  for (const url of ["https://cdn.example/unused-ad.webp", "https://cdn.example/sidebar-ad.webp"]) {
    const recorder = createNetworkPolicyEvidenceRecorder();
    recorder.recordAllowedRequestFailure("cdn.example", "image", "net::ERR_FAILED", false, url);
    assert.deepEqual(networkFidelityFailures(recorder.snapshot(), [], roleEvidence), [],
      "unused custom properties and non-retained same-host ad images remain optional");
  }
  assert.equal(JSON.stringify(roleEvidence).includes("resource-token"), false);
}

function testRetainedUrlBudgetCountsUniqueNormalizedResources() {
  class FixtureElement {
    localName = "div";
    children = [];
    style = {};
    getAttribute() { return null; }
  }
  const element = new FixtureElement();
  const collect = (values) => vm.runInNewContext(
    `(${collectRetainedRoleResourceEvidence.toString()})(["#article"])`, {
      Element: FixtureElement,
      document: { baseURI: "https://article.example/deal/7", head: null, querySelector: () => element },
      window: { getComputedStyle: (_element, pseudo) => pseudo ? {} : {
        cursor: values.map((value) => `url("${value}")`).join(","),
      } }, performance: { now: () => 0 }, URL,
    });
  const repeated = collect(Array.from({ length: 4096 }, (_, index) => index % 2 === 0
    ? "/shared-cursor.svg#pointer" : "https://article.example/shared-cursor.svg#alternate"));
  assert.equal(repeated.urlCount, 1, "relative/absolute and fragment variants share one resource budget entry");
  assert.equal(repeated.urlOverflowCount, 0, "4096 references to one inherited cursor must not fail");
  assert.deepEqual([...repeated.urls], ["https://article.example/shared-cursor.svg"]);
  const unique = collect(Array.from({ length: 4097 }, (_, index) => `https://cdn.example/cursor-${index}.svg`));
  assert.equal(unique.urlCount, 4096);
  assert.equal(unique.urlOverflowCount, 1, "4097 genuinely different resources still exceed the limit");
  assert.ok(networkFidelityFailures({}, [], unique)
    .includes("semantic role resource traversal exceeded its URL budget"));
}

function testPublicDnsAnswerCardinalityAndPrivacy() {
  const publicRecords = Array.from({ length: 128 }, (_, index) => ({ address: `8.8.8.${index + 1}` }));
  const full = validatePublicDnsAnswers(publicRecords);
  assert.equal(full.reason, "public-addresses-validated");
  assert.equal(full.answerCount, 128);
  assert.equal(full.uniqueAddressCount, 128);
  assert.equal(full.addresses.length, 128);
  const normalCdn = validatePublicDnsAnswers(publicRecords.slice(0, 32));
  assert.equal(normalCdn.addresses.length, 32, "a normal CDN may legitimately have more than sixteen public addresses");
  const duplicates = validatePublicDnsAnswers([...publicRecords.slice(0, 32), ...publicRecords.slice(0, 32)]);
  assert.equal(duplicates.answerCount, 64);
  assert.equal(duplicates.uniqueAddressCount, 32);
  assert.equal(duplicates.addresses.length, 32);
  const tooMany = validatePublicDnsAnswers([...publicRecords, { address: "1.1.1.1" }]);
  assert.equal(tooMany.reason, "dns-answer-budget-exceeded");
  assert.equal(tooMany.uniqueAddressCount, 129);
  assert.deepEqual(tooMany.addresses, []);
  for (const address of ["127.0.0.1", "10.0.0.1", "::1", "::ffff:7f00:1", "invalid"]) {
    const unsafe = validatePublicDnsAnswers([...publicRecords.slice(0, 32), { address }]);
    assert.equal(unsafe.reason, "dns-not-public", address);
    assert.deepEqual(unsafe.addresses, [], "one private answer rejects the entire pinned set");
  }
}

function testArticleLeaseBudgetsOnlyScopedCookies() {
  const now = 1_800_000_000_000;
  const identity = canonicalArticleIdentity("https://example.com/deal/7");
  const binding = { siteId: "example", profileName: "desktop",
    requestedArticleIdentitySha256: identity.sha256,
    resolvedArticleIdentitySha256: identity.sha256, resolvedRouteFamily: identity.routeFamily };
  const cookie = (index, domain = ".example.com", value = "test-value") => ({
    name: `c${index}`, value, domain, path: "/", expires: -1,
    httpOnly: true, secure: true, sameSite: "None",
  });
  const foreign = Array.from({ length: 80 }, (_, index) => cookie(index, ".ads.example.net", "x".repeat(1000)));
  const scoped = Array.from({ length: 64 }, (_, index) => cookie(index));
  const lease = createArticleAccessLease([...foreign, ...scoped], binding, ["example.com"], now);
  assert.equal(lease.evidence.cookieCount, 64);
  assert.deepEqual(lease.storageState.origins, []);
  assert.equal(lease.storageState.cookies.some(entry => entry.domain === ".ads.example.net"), false);
  assert.equal(JSON.stringify(lease.evidence).includes("test-value"), false);
  const consumed = consumeArticleAccessLease(lease, binding, now + 1);
  assert.equal(consumed.cookies.length, 64);
  assert.throws(() => consumeArticleAccessLease(lease, binding, now + 2));
  assert.throws(() => createArticleAccessLease([...scoped, cookie(65)], binding, ["example.com"], now), /cookie count/);
  assert.throws(() => createArticleAccessLease(Array.from({ length: 17 }, (_, i) => cookie(i, ".example.com", "x".repeat(4096))),
    binding, ["example.com"], now), /cookie bytes/);
  assert.throws(() => createArticleAccessLease([cookie(1, ".example.com", "bad\nvalue")], binding, ["example.com"], now), /invalid cookie/);
  const rejected = createArticleAccessLease([
    { ...cookie(1), secure: false }, { ...cookie(2), expires: now / 1000 - 1 }, cookie(3, ".example.com.attacker.test"),
  ], binding, ["example.com"], now);
  assert.equal(rejected.evidence.cookieCount, 0);
}

async function testArticleNavigationPrimingIsScopedAndPublic() {
  const calls = [];
  const session = { approvePublicHost: async hostname => {
    calls.push(hostname);
    return ["8.8.8.8"];
  } };
  await primeDeclaredArticleNavigation(session, "https://www.example.com/deal/7", ["example.com"]);
  assert.deepEqual(calls, ["www.example.com"]);
  for (const url of ["http://example.com/deal/7", "https://evil.example.net/deal/7",
    "https://user:secret@example.com/deal/7", "https://example.com:8443/deal/7", "https://127.0.0.1/deal/7"]) {
    await assert.rejects(primeDeclaredArticleNavigation(session, url, ["example.com"]), /priming refused/);
  }
  assert.deepEqual(calls, ["www.example.com"], "invalid destinations must never reach DNS or approval");
  for (const addresses of [[], ["127.0.0.1"], ["8.8.8.8", "10.0.0.1"]]) {
    await assert.rejects(primeDeclaredArticleNavigation({ approvePublicHost: async () => addresses },
      "https://example.com/deal/7", ["example.com"]), /no verified public/);
  }
}

async function testSealDrainAndLateRequest() {
  const recorder = createNetworkPolicyEvidenceRecorder();
  const active = recorder.reserveRemoteRequest("active.example");
  const sealing = recorder.sealAndDrain({ quietWindowMs: 5, timeoutMs: 500 });
  setTimeout(() => active.finish(), 10);

  const sealedEvidence = await sealing;
  assert.equal(sealedEvidence.sealed, true);
  assert.equal(sealedEvidence.activeRemoteRequestCount, 0);
  assert.equal(sealedEvidence.drainTimeoutCount, 0);

  const late = recorder.reserveRemoteRequest("late.example");
  assert.equal(late.allowed, false);
  assert.equal(late.reason, "network-evidence-sealed");
  finishReservation(late);

  const finalEvidence = recorder.snapshot();
  assert.equal(finalEvidence.lateRequestCount, 1);
  assert.equal(finalEvidence.activeRemoteRequestCount, 0);
  assert.ok(
    networkFidelityFailures(finalEvidence).includes(
      "remote requests appeared after the network evidence seal",
    ),
  );
}

async function testSealDrainTimeoutFailsClosed() {
  const recorder = createNetworkPolicyEvidenceRecorder();
  const stuck = recorder.reserveRemoteRequest("stuck.example");
  const evidence = await recorder.sealAndDrain({ quietWindowMs: 1, timeoutMs: 0 });

  assert.equal(evidence.sealed, true);
  assert.equal(evidence.activeRemoteRequestCount, 1);
  assert.equal(evidence.drainTimeoutCount, 1);
  const failures = networkFidelityFailures(evidence);
  assert.ok(failures.includes("network evidence sealed with active remote requests"));
  assert.ok(
    failures.includes("remote requests did not drain inside the fail-closed deadline"),
  );
  finishReservation(stuck);
}

async function testOptionalLifecycleActivityStaysObservedWithoutFailingArticle() {
  const requiredImage = "https://article.example/product.webp";
  const roleEvidence = { hosts: ["article.example"], urlSha256s: [networkResourceUrlSha256(requiredImage)] };
  const recorder = createNetworkPolicyEvidenceRecorder();
  const pending = Array.from({ length: 3 }, (_, index) => recorder.reserveRemoteRequest("article.example", {
    requestType: "fetch", isMainNavigation: false,
    urlText: `https://article.example/analytics-${index}?private=pending-token`,
  }));
  const sealed = await recorder.sealAndDrain({ quietWindowMs: 1, timeoutMs: 0 });
  assert.equal(sealed.activeRemoteRequestCount, 3);
  assert.equal(sealed.activeRemoteRequests.length, 3);
  assert.equal(sealed.undrainedRequests.length, 3);
  assert.equal(sealed.undrainedRequestCount, 3);
  assert.equal(sealed.drainTimeoutCount, 1);
  assert.deepEqual(networkFidelityFailures(sealed, ["article.example"], roleEvidence), [],
    "three unrelated active analytics requests do not invalidate a complete article");
  const late = recorder.reserveRemoteRequest("article.example", { requestType: "fetch", isMainNavigation: false,
    urlText: "https://article.example/analytics-late?private=late-token" });
  assert.equal(late.allowed, false, "the sealed network boundary still denies the late request");
  recorder.recordBlocked("article.example", "fetch", late.reason, false);
  const observed = recorder.snapshot();
  assert.equal(observed.lateRequestCount, 1);
  assert.equal(observed.lateRequests.length, 1);
  assert.deepEqual(networkFidelityFailures(observed, ["article.example"], roleEvidence), [],
    "same-host late analytics use exact resource identity, not the old host-only failure path");
  for (const token of ["analytics-", "pending-token", "late-token"]) {
    assert.equal(JSON.stringify(observed).includes(token), false);
  }
  pending.forEach(finishReservation);
  assert.equal(recorder.snapshot().activeRemoteRequests.length, 0);
  assert.equal(recorder.snapshot().undrainedRequests.length, 3, "deadline evidence survives eventual completion");

  const dependencies = createStylesheetDependencyRecorder();
  dependencies.recordRequest({ frameId: "main", type: "Font", request: { url: "https://cdn.example/article.woff2" },
    initiator: { type: "parser", url: "https://article.example/article.css" } }, "main");
  const cssRoleEvidence = { urlSha256s: [networkResourceUrlSha256("https://article.example/article.css")] };
  for (const [resource, required] of [
    [{ requestType: "image", urlText: requiredImage }, true],
    [{ requestType: "font", urlText: "https://cdn.example/article.woff2" }, true],
    [{ requestType: "document", urlText: "https://article.example/deal/7", isMainNavigation: true }, true],
    [{ requestType: "image", urlText: "https://cdn.example/final.webp", redirectEvidence: {
      ancestorUrlSha256s: [networkResourceUrlSha256(requiredImage)], status: "complete",
    } }, true],
    [{ requestType: "image", urlText: "https://cdn.example/ad.webp" }, false],
  ]) {
    const scoped = createNetworkPolicyEvidenceRecorder();
    const reservation = scoped.reserveRemoteRequest(new URL(resource.urlText).hostname, resource);
    const atSeal = await scoped.sealAndDrain({ quietWindowMs: 1, timeoutMs: 0 });
    const roles = { urlSha256s: [...roleEvidence.urlSha256s, ...cssRoleEvidence.urlSha256s] };
    const failures = networkFidelityFailures({ ...atSeal, stylesheetDependencies: dependencies.snapshot() }, [], roles);
    assert.equal(failures.includes("network evidence sealed with active remote requests"), required);
    assert.equal(failures.includes("remote requests did not drain inside the fail-closed deadline"), required);
    finishReservation(reservation);
    scoped.reserveRemoteRequest(new URL(resource.urlText).hostname, resource);
    assert.equal(networkFidelityFailures({ ...scoped.snapshot(), stylesheetDependencies: dependencies.snapshot() }, [], roles)
      .includes("remote requests appeared after the network evidence seal"), required);
  }
  const bounded = createNetworkPolicyEvidenceRecorder({ maximumRemoteRequests: 1 });
  await bounded.sealAndDrain({ quietWindowMs: 0, timeoutMs: 0 });
  bounded.reserveRemoteRequest("ads.example", { urlText: "https://ads.example/one" });
  bounded.reserveRemoteRequest("ads.example", { urlText: "https://ads.example/two" });
  assert.equal(bounded.snapshot().lateRequests.length, 1);
  assert.equal(bounded.snapshot().lifecycleEvidenceOverflowCount, 1);
  assert.ok(networkFidelityFailures(bounded.snapshot(), [], roleEvidence)
    .includes("request lifecycle evidence exceeded its bounded request count"));
}

async function testFailedNavigationRetainsNetworkEvidenceWithoutRetry() {
  const networkPolicy = { sealed: true, activeRemoteRequestCount: 0, pinnedTransport: {
    rejectedHosts: [{ hostname: "article.example", reasons: ["connect-failed"], count: 1 }],
  } };
  let seals = 0;
  const session = { sealNetworkPolicyEvidence: async () => { seals += 1; return networkPolicy; } };
  const result = { static: null, failures: ["article navigation/access error"] };
  assert.equal(await retainUnobservedSessionNetworkPolicy(session, result, "static"), networkPolicy);
  assert.equal(result.static.networkPolicy, networkPolicy);
  await retainUnobservedSessionNetworkPolicy(session, result, "static");
  assert.equal(seals, 1, "network evidence is captured once without performing any navigation/retry");
  const failedCapture = { userscript: null, failures: [] };
  await retainUnobservedSessionNetworkPolicy({ sealNetworkPolicyEvidence: async () => {
    throw new Error("net::ERR_FAILED at https://article.example/private-path?token=secret-query");
  } }, failedCapture, "userscript");
  assert.equal(failedCapture.userscript.networkPolicyCaptureFailure.category, "network");
  assert.equal(failedCapture.failures.length, 1, "capture failures are explicit, not silently discarded");
  assert.equal(JSON.stringify(failedCapture).includes("private-path"), false);
  assert.equal(JSON.stringify(failedCapture).includes("secret-query"), false);
}

async function testLifecycleIdentityCardinalityFailsClosed() {
  const optional = { hostname: "ads.example", requestType: "fetch", isMainNavigation: false,
    urlSha256: networkResourceUrlSha256("https://ads.example/analytics") };
  for (const [counter, entries, failure] of [
    ["activeRemoteRequestCount", "activeRemoteRequests", "network evidence sealed with active remote requests"],
    ["lateRequestCount", "lateRequests", "remote requests appeared after the network evidence seal"],
  ]) {
    for (const captured of [[], [optional], [optional, optional, optional], undefined]) {
      assert.ok(networkFidelityFailures({ [counter]: 2, [entries]: captured }).includes(failure),
        "missing, short, or contradictory identity lists cannot prove lifecycle activity optional");
    }
    assert.deepEqual(networkFidelityFailures({ [counter]: 1, [entries]: [optional] }), [],
      "complete optional identities continue to pass");
  }
  for (const [count, entries] of [[1, []], [2, [optional]], [undefined, []], [undefined, [optional]], [0, [optional]]]) {
    assert.ok(networkFidelityFailures({ drainTimeoutCount: 1, undrainedRequestCount: count, undrainedRequests: entries })
      .includes("remote requests did not drain inside the fail-closed deadline"),
    "the deadline must preserve both unfinished count and matching identities");
  }
  const quietOnly = createNetworkPolicyEvidenceRecorder();
  const evidence = await quietOnly.sealAndDrain({ quietWindowMs: 1_000, timeoutMs: 0 });
  assert.equal(evidence.drainTimeoutCount, 1);
  assert.equal(evidence.undrainedRequestCount, 0);
  assert.deepEqual(evidence.undrainedRequests, []);
  assert.deepEqual(networkFidelityFailures(evidence), [],
    "a quiet-window-only timeout has affirmative zero-unfinished evidence, not missing identities");
}

function testSpecialIpRanges() {
  const rejectedAddresses = [
    "not-an-ip",
    "0.0.0.1",
    "10.0.0.1",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.1.1",
    "172.16.0.1",
    "192.0.0.1",
    "192.0.2.1",
    "192.88.99.1",
    "192.168.0.1",
    "198.18.0.1",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "240.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
    "::ffff:127.0.0.1",
    "::ffff:7f00:1",
    "0:0:0:0:0:ffff:7f00:1",
    "0:0:0:0:0:ffff:c0a8:101",
    "0:0:0:0:0:0:c0a8:101",
    "64:ff9b::1",
    "64:ff9b:1::1",
    "100::1",
    "2001::1",
    "2001:db8::1",
    "2002::1",
    "fc00::1",
    "fe80::1",
    "fec0::1",
    "ff00::1",
  ];
  const acceptedAddresses = [
    "1.1.1.1",
    "8.8.8.8",
    "93.184.216.34",
    "2606:4700:4700::1111",
    "2001:4860:4860::8888",
  ];

  for (const address of rejectedAddresses) {
    assert.equal(isPrivateOrSpecialIp(address), true, `${address} must fail closed`);
  }
  for (const address of acceptedAddresses) {
    assert.equal(isPrivateOrSpecialIp(address), false, `${address} should be public`);
  }
}

function testConnectAuthorityParser() {
  assert.deepEqual(parseConnectAuthority("example.com:443"), {
    hostname: "example.com",
    port: 443,
  });
  assert.deepEqual(parseConnectAuthority("EXAMPLE.COM.:443"), {
    hostname: "example.com",
    port: 443,
  });
  assert.deepEqual(parseConnectAuthority("xn--bcher-kva.example:443"), {
    hostname: "xn--bcher-kva.example",
    port: 443,
  });

  for (const authority of [
    "example.com",
    "example.com:0",
    "example.com:65536",
    "example.com:443/path",
    "user@example.com:443",
    "127.0.0.1:443",
    "[::1]:443",
    "localhost:443",
    "service.localhost:443",
    "service.local:443",
    "service.internal:443",
    "metadata.google.internal:443",
  ]) {
    assert.equal(parseConnectAuthority(authority), null, `${authority} must be rejected`);
  }
}

function testHeadStylesheetTraversalBounds() {
  const collect = (length, elapsedStep = 0) => {
    let inspections = 0;
    let clock = 0;
    const headNodes = Array.from({ length }, (_, index) => ({
      href: `https://example.com/article-${index}.css`,
      matches() {
        inspections += 1;
        return index === length - 1;
      },
      nextElementSibling: null,
    }));
    for (let index = 0; index < headNodes.length - 1; index += 1) {
      headNodes[index].nextElementSibling = headNodes[index + 1];
    }
    const evidence = vm.runInNewContext(`(${collectRetainedRoleResourceEvidence.toString()})([])`, {
      document: { head: { firstElementChild: headNodes[0] ?? null }, baseURI: "https://example.com/deal/7" },
      performance: { now: () => { const value = clock; clock += elapsedStep; return value; } },
      URL,
    });
    return { evidence, inspections };
  };

  for (const length of [0, 100, 2048]) {
    const { evidence, inspections } = collect(length);
    assert.equal(inspections, length);
    assert.equal(evidence.headNodeCount, length);
    assert.equal(evidence.nodeOverflowCount, 0, "exactly completing the head budget is not overflow");
    assert.equal(evidence.elapsedTimeOverflowCount, 0);
    assert.equal(evidence.urlCount, length === 0 ? 0 : 1);
    assert.deepEqual(networkFidelityFailures({}, [], evidence), [], "ordinary metadata does not fail an article");
  }
  const overNodes = collect(4096);
  assert.equal(overNodes.inspections, 2048, "non-link children still consume the head traversal budget");
  assert.equal(overNodes.evidence.headNodeCount, 2048);
  assert.equal(overNodes.evidence.nodeOverflowCount, 1);
  assert.equal(overNodes.evidence.urlCount, 0, "a stylesheet past the inspected bound must not be claimed as inspected");
  assert.ok(networkFidelityFailures({}, [], overNodes.evidence)
    .includes("semantic role resource traversal exceeded its node budget"));

  const overTime = collect(1000, 20);
  assert.ok(overTime.inspections > 0 && overTime.inspections < 1000);
  assert.equal(overTime.evidence.nodeOverflowCount, 0);
  assert.equal(overTime.evidence.elapsedTimeOverflowCount, 1);
  assert.ok(networkFidelityFailures({}, [], overTime.evidence)
    .includes("semantic role resource traversal exceeded its time budget"));
}

function testRecoveryPaintClassification() {
  for (const [label, attributes, active] of [
    ["recovery-only", { "data-hotdeal-focus-status": "recovery-preflight-not-ready" }, false],
    ["recovery-with-lock", { "data-hotdeal-focus-status": "recovery-preflight-not-ready", "data-hotdeal-focus-lock": "1" }, true],
    ["recovery-with-protocol", { "data-hotdeal-focus-status": "recovery-preflight-not-ready", "data-hotdeal-focus-protocol": "2" }, true],
    ["locked-status", { "data-hotdeal-focus-status": "locked-preflight" }, true],
  ]) {
    const frames = [];
    const root = {
      getAttribute: (name) => attributes[name] ?? null,
      hasAttribute: (name) => Object.hasOwn(attributes, name),
      classList: { contains: () => false },
    };
    const visibleElement = {
      hasAttribute: () => false,
      getClientRects: () => [{ width: 100, height: 20 }],
    };
    const context = {
      window: {
        requestAnimationFrame: (callback) => frames.push(callback),
        getComputedStyle: () => ({ display: "block", visibility: "visible", opacity: "1" }),
      },
      document: { documentElement: root, body: { querySelectorAll: () => [visibleElement] } },
    };
    vm.runInNewContext(FIRST_PAINT_PROBE_SOURCE, context);
    frames.shift()();
    const probe = context.window.__HOTDEAL_FOCUS_PAINT_PROBE__;
    assert.equal(probe.samples[0].readerGateActive, active, label);
    assert.equal(probe.samples[0].status, attributes["data-hotdeal-focus-status"], label);
    assert.equal(probe.flashFrameCount, 1, `${label}: actual publisher visibility is still recorded`);
    assert.equal(probe.unsafeGateFrameCount, active ? 1 : 0, label);
    assert.equal(probe.publisherVisibleFrameCount, active ? 0 : 1, label);
  }
}

async function main() {
  testRecoveryPaintClassification();
  testNetworkPolicyTable();
  testRemoteHostBudgetBoundary();
  testRemoteRequestBudgetBoundary();
  testConcurrentReservations();
  testOptionalFailuresStayObservedWhileArticleResourcesRemainRequired();
  testRedirectedArticleResourceFailuresRemainRequired();
  testRedirectAncestryBoundsAndIncompleteEvidence();
  await testStylesheetDependenciesPreserveImportedCssAndFonts();
  testInlineStylesheetDependenciesUseActualDocumentUrl();
  testRetainedComputedUrlPropertiesExcludeUnrelatedImages();
  testRetainedUrlBudgetCountsUniqueNormalizedResources();
  testPublicDnsAnswerCardinalityAndPrivacy();
  testArticleLeaseBudgetsOnlyScopedCookies();
  await testArticleNavigationPrimingIsScopedAndPublic();
  await testSealDrainAndLateRequest();
  await testSealDrainTimeoutFailsClosed();
  await testOptionalLifecycleActivityStaysObservedWithoutFailingArticle();
  await testFailedNavigationRetainsNetworkEvidenceWithoutRetry();
  await testLifecycleIdentityCardinalityFailsClosed();
  testSpecialIpRanges();
  testConnectAuthorityParser();
  testHeadStylesheetTraversalBounds();
  process.stdout.write("PASS network fidelity pure-helper regression tests\n");
}

await main();
