import assert from "node:assert/strict";

import {
  createNetworkPolicyEvidenceRecorder,
  isPrivateOrSpecialIp,
  networkFidelityFailures,
  networkRequestDecision,
  parseConnectAuthority,
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

function testAllowedResourceFailuresAreTerminalFidelityEvidence() {
  const recorder = createNetworkPolicyEvidenceRecorder();
  recorder.recordAllowedRequestFailure(
    "ads.example",
    "script",
    "net::ERR_CONNECTION_RESET",
    false,
  );
  recorder.recordAllowedResponseFailure("api.example", "fetch", 503, false);

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
  const failures = networkFidelityFailures(evidence);
  assert.ok(failures.includes("an allowed remote request failed before a complete response"));
  assert.ok(failures.includes("an allowed remote response returned HTTP 4xx or 5xx"));
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

async function main() {
  testNetworkPolicyTable();
  testRemoteHostBudgetBoundary();
  testRemoteRequestBudgetBoundary();
  testConcurrentReservations();
  testAllowedResourceFailuresAreTerminalFidelityEvidence();
  await testSealDrainAndLateRequest();
  await testSealDrainTimeoutFailsClosed();
  testSpecialIpRanges();
  testConnectAuthorityParser();
  process.stdout.write("PASS network fidelity pure-helper regression tests\n");
}

await main();
