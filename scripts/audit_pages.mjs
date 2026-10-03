#!/usr/bin/env node

/**
 * Live DOM contract auditor for AdGuard Hotdeal Focus.
 *
 * The auditor injects the deterministic userscript at document-start and
 * proves its standalone nonce-bound runtime gate. Static selector projection
 * remains an offline contract oracle; it is not an installed runtime layer.
 *
 * Drift produces evidence and, only when every independent proof gate agrees,
 * one isolated promotion envelope. Repository mutation remains a CI concern.
 */

import { createHash } from "node:crypto";
import { lookup } from "node:dns/promises";
import { promises as fs } from "node:fs";
import { createServer } from "node:http";
import { BlockList, createConnection, isIP } from "node:net";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { publicBundleSha256 } from "./pages_release_contract.mjs";
import { PREAUTHORIZED_ADGUARD_CONTROL_SOURCE } from "./preauthorized_adguard_control.mjs";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(SCRIPT_DIR, "..");
const DEFAULT_CONFIG_PATH = path.join(PROJECT_ROOT, "config", "sites.json");
const DEFAULT_EVIDENCE_PATH = path.join(PROJECT_ROOT, "outputs", "evidence");
const DEFAULT_USERSCRIPT_PATH = path.join(PROJECT_ROOT, "hotdeal-focus.user.js");
const DEFAULT_REGRESSION_FIXTURES_PATH = path.join(
  PROJECT_ROOT,
  "tests",
  "fixtures",
  "dom-regressions.json",
);
const DEFAULT_BEHAVIOR_BASELINE_PATH = path.join(
  PROJECT_ROOT,
  "tests",
  "fixtures",
  "behavior-baseline.json",
);
const DEFAULT_TIMEOUT_MS = 30_000;
const FIXTURE_TIMEOUT_MS = 8_000;
const ALGUMON_ORIGIN = "https://www.algumon.com";
const ALGUMON_RUNTIME_REFERRER = `${ALGUMON_ORIGIN}/`;
const ALGUMON_HOSTNAMES = new Set(["algumon.com", "www.algumon.com"]);
const ALGUMON_GLOBAL_DISCOVERY_URL = `${ALGUMON_ORIGIN}/n/deal`;
// A live audit deliberately reads only the first three exact relay links for a
// source. Three is the minimum evidence cardinality for a promotable profile;
// scanning the rest of a feed would add load without strengthening that proof.
const ALGUMON_SITE_LINK_SCAN_LIMIT = 3;
const ALGUMON_PROOF_REPRESENTATIVES_PER_ROUTE_PROFILE = 3;
const ALGUMON_RELAY_RESPONSE_MAX_BYTES = 4_096;
const ALGUMON_FRESH_RELAY_MAX_AGE_MS = 5 * 60 * 1_000;
const ALGUMON_FRESH_RELAY_FUTURE_SKEW_MS = 30 * 1_000;
const ARTICLE_ACCESS_LEASE_TTL_MS = 60 * 1_000;
const ARTICLE_ACCESS_LEASE_MAX_COOKIES = 64;
const ARTICLE_ACCESS_LEASE_MAX_COOKIE_BYTES = 64 * 1_024;
const DESTINATION_CHALLENGE_SETTLE_MAX_MS = 12_000;
const NETWORK_POLICY_MAX_REMOTE_HOSTS = 128;
const NETWORK_POLICY_MAX_REMOTE_REQUESTS = 4_096;
const NETWORK_POLICY_MAX_REDIRECT_ANCESTORS = 32;
// Dedicated noise origins observed in cloud audit 37075520049, with the Google
// ad origins also identified by the existing AdGuard delivery policy. General
// Google origins and publisher paths named "analytics" are not evidence of noise.
const OBSERVED_DEDICATED_NOISE_HOSTS = new Set([
  "analytics.google.com", "sync.adkernel.com",
  "pagead2.googlesyndication.com", "securepubads.g.doubleclick.net",
]);
const PINNED_PROXY_MAX_CONNECT_REQUESTS = 1_024;
const PINNED_PROXY_MAX_ACTIVE_TUNNELS = 256;
const PINNED_PROXY_MAX_TRANSFER_BYTES = 512 * 1024 * 1024;
const PINNED_PROXY_CONNECT_TIMEOUT_MS = 15_000;
const PINNED_PROXY_ADDRESS_CONNECT_TIMEOUT_MS = 3_000;
const PINNED_PROXY_MAX_CONNECT_ATTEMPT_EVIDENCE = 128;
const PINNED_PROXY_SAFE_CONNECT_ERROR_CODES = new Set([
  "ETIMEDOUT", "ECONNREFUSED", "ECONNRESET", "ECONNABORTED", "EHOSTUNREACH",
  "ENETUNREACH", "EADDRNOTAVAIL", "EACCES", "EPERM", "EPIPE",
]);
const PINNED_PROXY_DNS_TIMEOUT_MS = 5_000;
const PINNED_PROXY_MAX_DNS_ADDRESSES = 128;
const PINNED_PROXY_MAX_EVIDENCE_HOSTS = 128;
const EXACT_CHALLENGE_RESOURCE_HOSTS_BY_SITE = Object.freeze({
  arcalive: Object.freeze(["challenges.cloudflare.com"]),
});
const ARTICLE_IDENTITY_DOMAINS = Object.freeze({
  clien: "clien.net",
  ppomppu: "ppomppu.co.kr",
  ruliweb: "ruliweb.com",
  quasarzone: "quasarzone.com",
  eomisae: "eomisae.co.kr",
  zod: "zod.kr",
  arcalive: "arca.live",
});
// Exact mobile redirects observed in cloud audit 37079206298. Chromium can
// establish their CONNECT tunnels before Playwright receives a redirect route.
const OBSERVED_MOBILE_ARTICLE_REDIRECT_HOSTS = Object.freeze({
  clien: Object.freeze({ from: "www.clien.net", to: "m.clien.net" }),
  ruliweb: Object.freeze({ from: "bbs.ruliweb.com", to: "m.ruliweb.com" }),
});
const ORACLE_EXECUTION_WORLD = "chromium-isolated-v1";
const SCREENSHOT_MAX_BYTES = 2 * 1024 * 1024;
const SCREENSHOT_MAX_COUNT = 256;
let screenshotCount = 0;
const ALGUMON_SOURCE_CONTRACTS = Object.freeze([
  Object.freeze({ siteId: "clien", label: "클리앙", iconSlug: "clien" }),
  Object.freeze({ siteId: "ppomppu", label: "뽐뿌", iconSlug: "ppomppu" }),
  Object.freeze({ siteId: "ruliweb", label: "루리웹", iconSlug: "ruliweb" }),
  Object.freeze({ siteId: "quasarzone", label: "퀘이사존", iconSlug: "quasarzone" }),
  Object.freeze({ siteId: "eomisae", label: "어미새", iconSlug: "eomisae" }),
  Object.freeze({ siteId: "zod", label: "zod", iconSlug: "zod" }),
  Object.freeze({ siteId: "arcalive", label: "아카라이브", iconSlug: "arcalive" }),
]);
const ALGUMON_SOURCE_BY_SITE_ID = new Map(
  ALGUMON_SOURCE_CONTRACTS.map((source) => [source.siteId, source]),
);
const ALGUMON_SOURCE_BY_LABEL = new Map(
  ALGUMON_SOURCE_CONTRACTS.map((source) => [source.label, source]),
);
const ALGUMON_SOURCE_BY_ICON_SLUG = new Map(
  ALGUMON_SOURCE_CONTRACTS.map((source) => [source.iconSlug, source]),
);
const REQUIRED_SITE_IDS = Object.freeze([
  "clien",
  "ppomppu",
  "ruliweb",
  "quasarzone",
  "eomisae",
  "zod",
  "arcalive",
]);
const REQUIRED_USERSCRIPT_MATCHES = Object.freeze([
  "https://*.clien.net/*",
  "https://*.ppomppu.co.kr/*",
  "https://*.ruliweb.com/*",
  "https://*.quasarzone.com/*",
  "https://*.eomisae.co.kr/*",
  "https://*.zod.kr/*",
  "https://*.arca.live/*",
]);
const REQUIRED_USERSCRIPT_GRANTS = Object.freeze([
  "GM_addElement",
  "window.onurlchange",
]);
// One global source inventory, one filtered source page per configured site,
// and three signed relay documents per site. This bounds explicit acquisitions,
// not the normal browser's resources or same-origin automatic document changes;
// those have separate observed counters and the existing network/time limits.
const DEFAULT_ALGUMON_REQUEST_START_BUDGET =
  1 + REQUIRED_SITE_IDS.length * (1 + ALGUMON_SITE_LINK_SCAN_LIMIT);
const REQUIRED_ROLE_NAMES = Object.freeze(["title", "body", "comments"]);
const READER_GATE_PROTOCOL_VERSION = 2;
const PREAUTHORIZED_ADGUARD_CONTROL_SCHEMA_VERSION = 3;
const READER_GATE_INSTALL_URL =
  "https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js";
const FIRST_PAINT_PROBE_SCHEMA_VERSION = 2;
const ARTICLE_ACCESS_LEASE_SCHEMA_VERSION = 1;
const DEVICE_PROFILES = Object.freeze({
  desktop: {
    descriptorName: "Desktop Chrome",
    expectedMobile: false,
  },
  mobile: {
    descriptorName: "Pixel 7",
    expectedMobile: true,
  },
});
let RUNTIME_DEVICE_PROFILES = null;
export const FIRST_PAINT_PROBE_SOURCE = String.raw`
(() => {
  "use strict";
  const probe = {
    schemaVersion: ${FIRST_PAINT_PROBE_SCHEMA_VERSION},
    sampleCount: 0,
    flashFrameCount: 0,
    publisherVisibleFrameCount: 0,
    unsafeGateFrameCount: 0,
    lockedFrameCount: 0,
    firstContentFrame: null,
    firstReadyFrame: null,
    samples: [],
  };
  Object.defineProperty(window, "__HOTDEAL_FOCUS_PAINT_PROBE__", {
    value: probe,
    configurable: false,
    enumerable: false,
    writable: false,
  });
  const isVisible = (element) => {
    const style = window.getComputedStyle(element);
    return style.display !== "none" && style.visibility !== "hidden" &&
      Number(style.opacity) !== 0 &&
      [...element.getClientRects()].some((rect) => rect.width > 0 && rect.height > 0);
  };
  const sample = () => {
    const root = document.documentElement;
    const body = document.body;
    const state = root?.getAttribute("data-hotdeal-focus-state") ?? "unset";
    const status = root?.getAttribute("data-hotdeal-focus-status") ?? "";
    const ready = root?.classList.contains("hdf-v2-ready") === true &&
      root?.getAttribute("data-hotdeal-focus-ready") === "1" &&
      root?.getAttribute("data-hotdeal-focus-protocol") === "2" &&
      state === "ready" &&
      root?.getAttribute("data-hotdeal-focus-status") === "ready" &&
      root?.classList.contains("hdf-v2-lock") === false &&
      !root?.hasAttribute("data-hotdeal-focus-lock");
    const rootStyle = root ? window.getComputedStyle(root) : null;
    const readerGateActive = root?.classList.contains("hdf-v2-lock") === true ||
      root?.classList.contains("hdf-v2-ready") === true ||
      root?.hasAttribute("data-hotdeal-focus-lock") === true ||
      root?.hasAttribute("data-hotdeal-focus-ready") === true ||
      root?.hasAttribute("data-hotdeal-focus-protocol") === true ||
      root?.hasAttribute("data-hotdeal-focus-state") === true ||
      // Recovery reports readable publisher content, not an active allow-set.
      // Any remaining lock/protocol/state evidence above still counts as active.
      (status.length > 0 && !status.startsWith("recovery-"));
    const paintLockIntact = !ready &&
      root?.classList.contains("hdf-v2-lock") === true &&
      root?.getAttribute("data-hotdeal-focus-lock") === "1" &&
      rootStyle?.transitionProperty === "none" &&
      rootStyle?.animationName === "none" &&
      rootStyle?.visibility === "hidden" &&
      rootStyle?.contentVisibility === "hidden" &&
      Number(rootStyle?.opacity) === 0 &&
      rootStyle?.clipPath === "inset(50%)" &&
      rootStyle?.pointerEvents === "none" &&
      root?.style.getPropertyValue("opacity") === "0" &&
      root?.style.getPropertyPriority("opacity") === "important" &&
      root?.style.getPropertyValue("clip-path") === "inset(50%)" &&
      root?.style.getPropertyPriority("clip-path") === "important" &&
      root?.style.getPropertyValue("visibility") === "hidden" &&
      root?.style.getPropertyPriority("visibility") === "important" &&
      root?.style.getPropertyValue("content-visibility") === "hidden" &&
      root?.style.getPropertyPriority("content-visibility") === "important";
    const bodyElementCount = body?.querySelectorAll("*").length ?? 0;
    const visibleUnmarkedCount = paintLockIntact
      ? 0
      : body
      ? [...body.querySelectorAll("*")].filter((element) =>
          isVisible(element) && !element.hasAttribute("data-hotdeal-focus-keep"),
        ).length
      : 0;
    const frame = probe.sampleCount;
    if (bodyElementCount > 0 && probe.firstContentFrame === null) probe.firstContentFrame = frame;
    if (ready && probe.firstReadyFrame === null) probe.firstReadyFrame = frame;
    if (!ready && visibleUnmarkedCount > 0) probe.flashFrameCount += 1;
    if (!ready && !readerGateActive && visibleUnmarkedCount > 0) {
      probe.publisherVisibleFrameCount += 1;
    }
    if (!ready && readerGateActive && !paintLockIntact && visibleUnmarkedCount > 0) {
      probe.unsafeGateFrameCount += 1;
    }
    if (paintLockIntact) probe.lockedFrameCount += 1;
    if (probe.samples.length < 180) {
      probe.samples.push({
        frame,
        state,
        status,
        ready,
        readerGateActive,
        paintLockIntact,
        bodyElementCount,
        visibleUnmarkedCount,
      });
    }
    probe.sampleCount += 1;
    if ((!ready || probe.sampleCount < 3) && probe.sampleCount < 180) {
      window.requestAnimationFrame(sample);
    }
  };
  window.requestAnimationFrame(sample);
})();
`;

function userscriptAuditInitSource(userscriptContent) {
  const targetDomains = Object.values(ARTICLE_IDENTITY_DOMAINS);
  return `(() => {
  "use strict";
  const hostname = location.hostname.toLowerCase();
  const targetDomains = ${JSON.stringify(targetDomains)};
  if (!targetDomains.some((domain) =>
    hostname === domain || hostname.endsWith("." + domain))) return;
  ${FIRST_PAINT_PROBE_SOURCE}
  ${PREAUTHORIZED_ADGUARD_CONTROL_SOURCE}
  ${userscriptContent}
})();`;
}

function parseArguments(argv) {
  const options = {
    configPath: DEFAULT_CONFIG_PATH,
    evidencePath: DEFAULT_EVIDENCE_PATH,
    userscriptPath: DEFAULT_USERSCRIPT_PATH,
    timeoutMs: DEFAULT_TIMEOUT_MS,
    discoverAlgumon: false,
    requireAlgumonDiscovery: false,
    integrityOnly: false,
    fixtureOnly: false,
    tamperFixtureOnly: false,
    relayFixtureOnly: false,
    relayFixtureIds: new Set(),
    edgeFixtureIds: new Set(),
    runtimeOnly: false,
    synthesizeCandidates: false,
    promotionDraftPath: null,
    draftManifestPath: null,
    promotionScopePath: null,
    baselineReportPath: null,
    capturedAlgumonReportPath: null,
    noAlgumonNetwork: false,
    algumonRequestBudget: DEFAULT_ALGUMON_REQUEST_START_BUDGET,
    headed: false,
    siteIds: new Set(),
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const nextValue = () => {
      index += 1;
      if (index >= argv.length || argv[index].startsWith("--")) {
        throw new Error(`${argument} requires a value`);
      }
      return argv[index];
    };

    switch (argument) {
      case "--config":
        options.configPath = path.resolve(nextValue());
        break;
      case "--evidence-dir":
        options.evidencePath = path.resolve(nextValue());
        break;
      case "--userscript":
        options.userscriptPath = path.resolve(nextValue());
        break;
      case "--timeout-ms": {
        const timeoutMs = Number(nextValue());
        if (!Number.isInteger(timeoutMs) || timeoutMs < 1_000) {
          throw new Error("--timeout-ms must be an integer of at least 1000");
        }
        options.timeoutMs = timeoutMs;
        break;
      }
      case "--site":
        options.siteIds.add(nextValue().toLowerCase());
        break;
      case "--discover-algumon":
        options.discoverAlgumon = true;
        break;
      case "--no-discover-algumon":
        options.discoverAlgumon = false;
        break;
      case "--require-algumon-discovery":
        options.requireAlgumonDiscovery = true;
        options.discoverAlgumon = true;
        break;
      case "--integrity-only":
        options.integrityOnly = true;
        break;
      case "--fixture-only":
        options.fixtureOnly = true;
        options.discoverAlgumon = false;
        break;
      case "--tamper-fixture-only":
        options.fixtureOnly = true;
        options.tamperFixtureOnly = true;
        options.discoverAlgumon = false;
        break;
      case "--edge-fixture":
        options.edgeFixtureIds.add(nextValue());
        options.fixtureOnly = true;
        options.discoverAlgumon = false;
        break;
      case "--relay-fixture-only":
        options.relayFixtureOnly = true;
        options.fixtureOnly = true;
        options.discoverAlgumon = false;
        break;
      case "--relay-fixture":
        options.relayFixtureIds.add(nextValue());
        options.relayFixtureOnly = true;
        options.fixtureOnly = true;
        options.discoverAlgumon = false;
        break;
      case "--runtime-only":
        options.runtimeOnly = true;
        break;
      case "--synthesize-candidates":
        options.synthesizeCandidates = true;
        break;
      case "--promotion-draft":
        options.promotionDraftPath = path.resolve(nextValue());
        options.synthesizeCandidates = true;
        break;
      case "--draft-manifest":
        options.draftManifestPath = path.resolve(nextValue());
        break;
      case "--promotion-scope":
        options.promotionScopePath = path.resolve(nextValue());
        break;
      case "--baseline-report":
        options.baselineReportPath = path.resolve(nextValue());
        break;
      case "--captured-algumon-report":
      case "--algumon-source-snapshot":
        options.capturedAlgumonReportPath = path.resolve(nextValue());
        options.discoverAlgumon = false;
        options.noAlgumonNetwork = true;
        break;
      case "--no-algumon-network":
        options.discoverAlgumon = false;
        options.noAlgumonNetwork = true;
        break;
      case "--algumon-request-budget": {
        const maximumStarts = Number(nextValue());
        if (
          !Number.isInteger(maximumStarts) ||
          maximumStarts < 1 ||
          maximumStarts > DEFAULT_ALGUMON_REQUEST_START_BUDGET
        ) {
          throw new Error(
            `--algumon-request-budget must be an integer from 1 to ` +
            `${DEFAULT_ALGUMON_REQUEST_START_BUDGET}`,
          );
        }
        options.algumonRequestBudget = maximumStarts;
        break;
      }
      case "--headed":
        options.headed = true;
        break;
      case "--help":
        printUsage();
        process.exit(0);
        break;
      default:
        throw new Error(`unknown argument: ${argument}`);
    }
  }
  if (options.capturedAlgumonReportPath || options.noAlgumonNetwork) {
    options.discoverAlgumon = false;
    options.noAlgumonNetwork = true;
  }
  if (
    options.requireAlgumonDiscovery &&
    !options.fixtureOnly &&
    !options.discoverAlgumon &&
    !options.capturedAlgumonReportPath
  ) {
    throw new Error(
      "--require-algumon-discovery needs live discovery or --algumon-source-snapshot",
    );
  }
  return options;
}

function printUsage() {
  process.stdout.write(`Usage: node scripts/audit_pages.mjs [options]\n\n`);
  process.stdout.write(`  --config PATH                    Config file (default: config/sites.json)\n`);
  process.stdout.write(`  --evidence-dir PATH              Evidence root (default: outputs/evidence)\n`);
  process.stdout.write(`  --userscript PATH                Userscript to inject at document-start\n`);
  process.stdout.write(`  --site ID                        Audit one site; repeat to select several\n`);
  process.stdout.write(`  --[no-]discover-algumon          Toggle latest-link discovery\n`);
  process.stdout.write(`  --require-algumon-discovery      Fail unless every selected site/device resolves\n`);
  process.stdout.write(`  --integrity-only                 Verify artifacts without launching a browser\n`);
  process.stdout.write(`  --fixture-only                   Run synthetic June/July behavior regressions only\n`);
  process.stdout.write(`  --tamper-fixture-only            Run the bounded terminal style-tamper regression only\n`);
  process.stdout.write(`  --edge-fixture ID                Run one edge fixture; repeat to select several\n`);
  process.stdout.write(`  --relay-fixture-only             Run only signed Algumon relay fixtures\n`);
  process.stdout.write(`  --relay-fixture ID               Run one relay fixture; repeat to select several\n`);
  process.stdout.write(`  --runtime-only                   Run only the standalone userscript proof\n`);
  process.stdout.write(`  --synthesize-candidates          Emit a proven atomic overlay when all proof gates pass\n`);
  process.stdout.write(`  --promotion-draft PATH           Finalize one isolated draft after candidate live proof\n`);
  process.stdout.write(`  --draft-manifest PATH            Draft bundle manifest used for byte-identity proof\n`);
  process.stdout.write(`  --promotion-scope PATH           Proven candidate for profile-scoped pre-push audit\n`);
  process.stdout.write(`  --baseline-report PATH           Frozen full audit used for non-regression scope\n`);
  process.stdout.write(`  --algumon-source-snapshot PATH   Reuse sealed relay evidence; never revisit Algumon\n`);
  process.stdout.write(`  --captured-algumon-report PATH   Compatibility alias for --algumon-source-snapshot\n`);
  process.stdout.write(`  --no-algumon-network             Audit registered articles without Algumon discovery\n`);
  process.stdout.write(`  --algumon-request-budget N       Tighten the live Algumon-start cap (1-${DEFAULT_ALGUMON_REQUEST_START_BUDGET})\n`);
  process.stdout.write(`  --timeout-ms N                   Per-page timeout\n`);
  process.stdout.write(`  --headed                         Show Chromium\n`);
}

class AlgumonRequestBudgetExceeded extends Error {
  constructor(maximumStarts, attemptedKind) {
    super(
      `Algumon request-start budget exhausted before ${attemptedKind} ` +
      `(${maximumStarts} starts maximum)`,
    );
    this.name = "AlgumonRequestBudgetExceeded";
    this.maximumStarts = maximumStarts;
    this.attemptedKind = attemptedKind;
  }
}

function createLowTrafficAlgumonProbePlan(siteCount) {
  if (!Number.isInteger(siteCount) || siteCount < 1) {
    throw new Error("Algumon probe plan requires at least one selected site");
  }
  const globalInventoryNavigations = 1;
  const siteDiscoveryNavigations = siteCount;
  const signedRelayFetches = siteCount * ALGUMON_SITE_LINK_SCAN_LIMIT;
  return Object.freeze({
    globalInventoryNavigations,
    siteDiscoveryNavigations,
    signedRelayFetches,
    justInTimeRelayAcquisitions: 0,
    justInTimeSignedRelayFetches: 0,
    totalRequestStarts:
      globalInventoryNavigations + siteDiscoveryNavigations + signedRelayFetches,
  });
}

function createAlgumonRequestStartBudget(
  maximumStarts = DEFAULT_ALGUMON_REQUEST_START_BUDGET,
) {
  if (
    !Number.isInteger(maximumStarts) ||
    maximumStarts < 1 ||
    maximumStarts > DEFAULT_ALGUMON_REQUEST_START_BUDGET
  ) {
    throw new Error(
      `Algumon request-start budget must be an integer from 1 to ` +
      `${DEFAULT_ALGUMON_REQUEST_START_BUDGET}`,
    );
  }
  const starts = [];
  return Object.freeze({
    reserve(kind, urlLike) {
      let url;
      try {
        url = new URL(urlLike);
      } catch {
        throw new Error(`Algumon request start has an invalid URL: ${String(urlLike)}`);
      }
      if (
        url.protocol !== "https:" ||
        !ALGUMON_HOSTNAMES.has(url.hostname.toLocaleLowerCase())
      ) {
        throw new Error(`Algumon request start escaped the exact source origin: ${url.href}`);
      }
      if (starts.length >= maximumStarts) {
        throw new AlgumonRequestBudgetExceeded(maximumStarts, kind);
      }
      const start = Object.freeze({ ordinal: starts.length + 1, kind: String(kind) });
      starts.push(start);
      return start;
    },
    snapshot() {
      return Object.freeze({
        maximumStarts,
        startedCount: starts.length,
        remainingStarts: maximumStarts - starts.length,
        starts: Object.freeze(starts.slice()),
      });
    },
  });
}

function reserveAlgumonProbeStart(requestBudget, transitionBudget, kind, url) {
  if (!requestBudget || typeof requestBudget.reserve !== "function") {
    throw new Error("Algumon request-start budget is required before a live source request");
  }
  if (
    kind === "just-in-time-site-discovery" ||
    kind === "just-in-time-signed-relay-fetch"
  ) {
    throw new AlgumonRequestBudgetExceeded(0, kind);
  }
  const start = requestBudget.reserve(kind, url);
  if (!transitionBudget) return start;
  const actual = transitionBudget.actual;
  actual.requestStarts = start.ordinal;
  if (kind === "global-inventory") actual.globalInventoryNavigations += 1;
  if (kind === "site-discovery") actual.siteDiscoveryNavigations += 1;
  if (kind === "signed-relay-fetch") actual.signedRelayFetches += 1;
  if (kind === "just-in-time-site-discovery") actual.justInTimeRelayAcquisitions += 1;
  if (kind === "just-in-time-signed-relay-fetch") {
    actual.justInTimeSignedRelayFetches += 1;
    actual.signedRelayFetches += 1;
  }
  return start;
}

function createAlgumonSourceBrowserBudget(requestedUrl) {
  const requested = new URL(canonicalHttpsUrl(requestedUrl, "Algumon source URL"));
  if (!ALGUMON_HOSTNAMES.has(requested.hostname) || requested.pathname !== "/n/deal") {
    throw new Error("Algumon source browser requires an exact feed URL");
  }
  let requestStarts = 0;
  let navigationStarts = 0;
  let blockedStarts = 0;
  const violations = new Set();
  const requestDecisions = new WeakMap();
  return {
    observeRequest(request) {
      if (!requestDecisions.has(request)) {
        requestDecisions.set(request, this.observe(request.url(), isTopLevelNavigationRequest(request)));
      }
      return requestDecisions.get(request);
    },
    observe(urlText, isMainNavigation) {
      const parsed = new URL(urlText);
      if (["about:", "data:", "blob:"].includes(parsed.protocol) && !isMainNavigation) {
        return { allowed: true, reason: "local-browser-scheme" };
      }
      requestStarts += 1;
      if (isMainNavigation) navigationStarts += 1;
      const reason = requestStarts > NETWORK_POLICY_MAX_REMOTE_REQUESTS
        ? "source-browser-request-budget-exceeded"
        : isMainNavigation && (parsed.origin !== requested.origin || parsed.username || parsed.password)
          ? "source-browser-navigation-origin-denied"
          : isMainNavigation && navigationStarts === 1 && parsed.href !== requested.href
            ? "source-browser-initial-feed-mismatch"
            : navigationStarts > NETWORK_POLICY_MAX_REDIRECT_ANCESTORS
              ? "source-browser-navigation-budget-exceeded"
              : null;
      if (reason) {
        blockedStarts += 1;
        violations.add(reason);
      }
      return { allowed: reason === null, reason: reason ?? "bounded-source-browser-request" };
    },
    snapshot() {
      return {
        maximumRequestStarts: NETWORK_POLICY_MAX_REMOTE_REQUESTS,
        maximumNavigationStarts: NETWORK_POLICY_MAX_REDIRECT_ANCESTORS,
        requestStarts,
        navigationStarts,
        subresourceStarts: requestStarts - navigationStarts,
        blockedStarts,
        violations: [...violations].sort(),
      };
    },
  };
}

async function readJson(filePath) {
  const raw = await fs.readFile(filePath, "utf8");
  return JSON.parse(raw);
}

function assertConfiguredResourceDomains(value, location) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new Error(`${location} must be an array`);
  }
  const domainPattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/u;
  const domains = value.map((domain, index) => {
    if (
      typeof domain !== "string" ||
      domain !== domain.trim() ||
      domain !== domain.toLocaleLowerCase() ||
      !domainPattern.test(domain)
    ) {
      throw new Error(
        `${location}[${index}] must be a lowercase hostname without scheme, port, path or wildcard`,
      );
    }
    return domain;
  });
  if (new Set(domains).size !== domains.length) {
    throw new Error(`${location} contains duplicate values`);
  }
  return domains;
}

function assertAuditConfig(config) {
  if (!config || config.schema_version !== 1 || !Array.isArray(config.sites)) {
    throw new Error("config/sites.json must use schema_version 1 and contain sites[]");
  }
  const siteIds = new Set();
  for (const site of config.sites) {
    if (!site?.id || siteIds.has(site.id) || !Array.isArray(site.layouts)) {
      throw new Error(`invalid or duplicate site entry: ${site?.id ?? "<missing>"}`);
    }
    siteIds.add(site.id);
    assertConfiguredResourceDomains(
      site.algumon_resource_domains,
      `${site.id}.algumon_resource_domains`,
    );
    for (const layout of site.layouts) {
      const location = `${site.id}/${layout?.id ?? "<missing>"}`;
      assertConfiguredResourceDomains(layout?.resource_domains, `${location}.resource_domains`);
      for (const field of [
        "sample_urls",
        "ancestor_markers",
        "preserve_deep",
        "preserve_shallow",
      ]) {
        if (!Array.isArray(layout?.[field])) {
          throw new Error(`${location}.${field} must be an array`);
        }
      }
      if (!layout.domain || pathsForLayout(layout).length === 0 || layout.sample_urls.length === 0) {
        throw new Error(`${location} requires domain, path/paths, and sample_urls`);
      }
      if (
        !Array.isArray(layout.applicable_profiles) ||
        layout.applicable_profiles.length === 0 ||
        new Set(layout.applicable_profiles).size !== layout.applicable_profiles.length ||
        layout.applicable_profiles.some((profile) => !(profile in DEVICE_PROFILES))
      ) {
        throw new Error(`${location}.applicable_profiles is invalid`);
      }
      if (layout.ancestor_markers.length === 0) {
        throw new Error(`${location}.ancestor_markers must not be empty`);
      }
      const preserved = new Set([
        ...layout.preserve_deep,
        ...layout.preserve_shallow,
      ]);
      const requiredRoles = requiredRolesForLayout(layout);
      for (const role of requiredRoles) {
        const selectors = layout.required_groups?.[role];
        if (!Array.isArray(selectors) || selectors.length === 0) {
          throw new Error(`${location}.required_groups.${role} must be a non-empty array`);
        }
        for (const selector of selectors) {
          if (!preserved.has(selector)) {
            throw new Error(`${location}.${role} selector is not preserved: ${selector}`);
          }
        }
      }
      const commentContract = layout.comment_contract;
      if (commentContract) {
        if (
          canonicalJson(Object.keys(commentContract).sort()) !==
            canonicalJson(["allow_empty", "controls", "ignored", "items", "mount"]) ||
          !Array.isArray(commentContract.mount) ||
          commentContract.mount.length === 0 ||
          !Array.isArray(commentContract.items) ||
          !Array.isArray(commentContract.controls) ||
          !Array.isArray(commentContract.ignored) ||
          typeof commentContract.allow_empty !== "boolean"
        ) {
          throw new Error(`${location}.comment_contract is invalid`);
        }
      }
      buildProjectedHideSelector(layout);
    }
  }
  const actualSiteIds = [...siteIds].sort();
  const requiredSiteIds = [...REQUIRED_SITE_IDS].sort();
  if (canonicalJson(actualSiteIds) !== canonicalJson(requiredSiteIds)) {
    throw new Error(
      "config/sites.json site IDs must equal the exact Algumon seven-source contract",
    );
  }
  return config;
}

function pathsForLayout(layout) {
  if (Array.isArray(layout.paths) && layout.paths.length > 0) return layout.paths;
  return typeof layout.path === "string" && layout.path ? [layout.path] : [];
}

function requiredRolesForLayout(layout) {
  const roles = Array.isArray(layout.required_roles)
    ? [...layout.required_roles]
    : [...REQUIRED_ROLE_NAMES];
  for (const requiredRole of REQUIRED_ROLE_NAMES) {
    if (!roles.includes(requiredRole)) roles.push(requiredRole);
  }
  const allowedRoles = new Set(["title", "product", "body", "comments"]);
  const invalid = roles.filter((role) => !allowedRoles.has(role));
  if (invalid.length > 0) throw new Error(`invalid required_roles: ${invalid.join(", ")}`);
  return [...new Set(roles)];
}

function projectionPolicyFingerprint(value) {
  const source = JSON.stringify(value);
  let hash = 2166136261;
  for (let index = 0; index < source.length; index += 1) {
    hash ^= source.charCodeAt(index);
    hash = Math.imul(hash, 16777619) >>> 0;
  }
  return `projection-policy-v1-${hash.toString(16).padStart(8, "0")}`;
}

function commentControlSelectorDigest(selectors) {
  return projectionPolicyFingerprint({
    kind: "comment-control-selectors",
    selectors: [...new Set(selectors)].sort(),
  }).replace("projection-policy-v1-", "comment-control-selectors-v1-");
}

function commentControlSelectorDigestsForUrl(layout, urlText) {
  const contracts = [layout, ...(layout.variants ?? [])];
  let parsed;
  try {
    parsed = new URL(urlText);
  } catch {
    return [];
  }
  const pathAndQuery = parsed.pathname + parsed.search;
  return [...new Set(
    contracts
      .filter((contract) => pathsForLayout(contract).some(
        (configuredPath) => wildcardPathMatches(pathAndQuery, configuredPath),
      ))
      .map((contract) => commentControlSelectorDigest(
        contract.comment_contract?.controls ?? [],
      )),
  )].sort();
}

function selectedSites(config, selectedIds) {
  if (selectedIds.size === 0) {
    return config.sites;
  }
  const available = new Set(config.sites.map((site) => site.id));
  const unknown = [...selectedIds].filter((siteId) => !available.has(siteId));
  if (unknown.length > 0) {
    throw new Error(`unknown --site values: ${unknown.join(", ")}`);
  }
  return config.sites.filter((site) => selectedIds.has(site.id));
}

function buildPromotionRetestScope(config, ready, baselineReport) {
  const candidate = ready?.candidate;
  if (
    ready?.status !== "proven" ||
    !candidate?.siteId ||
    !candidate?.layoutId ||
    !candidate?.variantId ||
    !Array.isArray(candidate.proofProfiles) ||
    candidate.proofProfiles.length === 0 ||
    baselineReport?.integrity?.passed !== true ||
    ready.baseConfigSha256 !== baselineReport.integrity?.config?.sha256
  ) {
    throw new Error("promotion scope does not match one proven frozen audit base");
  }
  const site = config.sites.find((item) => item.id === candidate.siteId);
  const layout = site?.layouts.find((item) => item.id === candidate.layoutId);
  const variant = layout?.variants?.find((item) => item.id === candidate.variantId);
  if (!site || !layout || !variant) {
    throw new Error("promoted candidate is absent from the materialized config");
  }
  const candidateProfiles = new Set(candidate.proofProfiles);
  if (
    [...candidateProfiles].some(
      (profile) =>
        !(profile in DEVICE_PROFILES) ||
        !profilesForLayout(site, layout).includes(profile),
    )
  ) {
    throw new Error("candidate promotion profiles are invalid for its layout");
  }
  const groupedResults = new Map();
  for (const result of baselineReport.results ?? []) {
    if (result.siteId !== candidate.siteId) continue;
    const key = `${result.layoutId}\u0000${result.profile}`;
    const group = groupedResults.get(key) ?? [];
    group.push(result);
    groupedResults.set(key, group);
  }
  const tuples = new Map();
  for (const candidateLayout of site.layouts) {
    for (const profile of profilesForLayout(site, candidateLayout)) {
      const key = `${candidateLayout.id}\u0000${profile}`;
      const results = groupedResults.get(key) ?? [];
      if (results.length === 0) {
        throw new Error(`frozen audit omitted ${candidateLayout.id}/${profile}`);
      }
      const isCandidate =
        candidateLayout.id === candidate.layoutId &&
        candidateProfiles.has(profile);
      tuples.set(key, {
        layoutId: candidateLayout.id,
        profile,
        reason: isCandidate
          ? "candidate"
          : results.every((result) => result.passed === true)
            ? "currently-passing"
            : "already-failed",
      });
    }
  }
  return {
    siteId: candidate.siteId,
    candidateLayoutId: candidate.layoutId,
    candidateVariantId: candidate.variantId,
    candidateProfiles: [...candidateProfiles].sort(),
    tuples: [...tuples.values()].sort((left, right) =>
      left.layoutId.localeCompare(right.layoutId) ||
      left.profile.localeCompare(right.profile),
    ),
  };
}

function sitesForPromotionRetest(config, scope) {
  const sourceSite = config.sites.find((site) => site.id === scope.siteId);
  const profilesByLayout = new Map();
  for (const tuple of scope.tuples) {
    const profiles = profilesByLayout.get(tuple.layoutId) ?? new Set();
    profiles.add(tuple.profile);
    profilesByLayout.set(tuple.layoutId, profiles);
  }
  const layouts = sourceSite.layouts
    .filter((layout) => profilesByLayout.has(layout.id))
    .map((layout) => ({
      ...layout,
      applicable_profiles: [...profilesByLayout.get(layout.id)].sort(),
    }));
  if (layouts.length !== profilesByLayout.size) {
    throw new Error("promotion retest scope references an unknown layout");
  }
  return [{ ...sourceSite, layouts }];
}

function buildProjectedHideSelector(layout) {
  const markers = [...layout.ancestor_markers].sort().join(", ");
  let selector = `body *:not(:has(:is(${markers})))`;
  for (const preserved of [...layout.preserve_deep].sort()) {
    selector += `:not(${preserved}):not(${preserved} *)`;
  }
  for (const preserved of [...layout.preserve_shallow].sort()) {
    selector += `:not(${preserved})`;
  }
  return selector;
}

function parsedCosmeticRule(domains, pathPattern, operator, payload) {
  if (operator !== "#$#" && operator !== "#$?#") {
    return {
      domains,
      selector: payload,
      declarations: null,
      cssText: null,
      malformed: false,
      path: pathPattern,
      operator,
    };
  }
  const declarationStart = payload.lastIndexOf(" {");
  const hasClosingBrace = payload.endsWith("}");
  if (declarationStart <= 0 || !hasClosingBrace) {
    return {
      domains,
      selector: payload,
      declarations: null,
      cssText: payload,
      malformed: true,
      path: pathPattern,
      operator,
    };
  }
  return {
    domains,
    selector: payload.slice(0, declarationStart).trim(),
    declarations: payload.slice(declarationStart + 2, -1).trim(),
    cssText: payload,
    malformed: false,
    path: pathPattern,
    operator,
  };
}

function parseAdguardCosmeticRules(filterText) {
  const rules = [];
  for (const rawLine of filterText.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("!")) continue;
    const officialMatch = line.match(
      /^\[\$domain=([^,\]]+),path=([^\]]+)\](#\$\?#|#\?#|#\$#|##)(.+)$/u,
    );
    if (officialMatch) {
      const [, domainValue, configuredPath, operator, selector] = officialMatch;
      const domains = domainValue
        .split("|")
        .map((domain) => domain.trim())
        .filter((domain) => domain && !domain.startsWith("~"));
      if (domains.length > 0 && selector && configuredPath) {
        rules.push(parsedCosmeticRule(domains, configuredPath, operator, selector));
      }
      continue;
    }
    const domainOnlyMatch = line.match(
      /^\[\$domain=([^,\]]+)\](#\$\?#|#\?#|#\$#|##)(.+)$/u,
    );
    if (domainOnlyMatch) {
      const [, domainValue, operator, selector] = domainOnlyMatch;
      const domains = domainValue
        .split("|")
        .map((domain) => domain.trim())
        .filter((domain) => domain && !domain.startsWith("~"));
      if (domains.length > 0 && selector) {
        rules.push(parsedCosmeticRule(domains, null, operator, selector));
      }
      continue;
    }
    const operator = line.includes("#$?#")
      ? "#$?#"
      : line.includes("#?#")
        ? "#?#"
        : line.includes("#$#")
          ? "#$#"
          : line.includes("##")
            ? "##"
            : null;
    if (!operator) continue;
    const operatorIndex = line.indexOf(operator);
    const pathIndex = line.lastIndexOf("$path=");
    if (operatorIndex <= 0 || pathIndex <= operatorIndex + operator.length) continue;
    const domains = line
      .slice(0, operatorIndex)
      .split(",")
      .map((domain) => domain.trim())
      .filter((domain) => domain && !domain.startsWith("~"));
    const selector = line.slice(operatorIndex + operator.length, pathIndex);
    const configuredPath = line.slice(pathIndex + "$path=".length);
    if (domains.length > 0 && selector && configuredPath) {
      rules.push(parsedCosmeticRule(domains, configuredPath, operator, selector));
    }
  }
  return rules;
}

function hostnameMatches(hostname, domain) {
  const normalizedHostname = hostname.toLowerCase();
  const normalizedDomain = domain.toLowerCase();
  return (
    normalizedHostname === normalizedDomain ||
    normalizedHostname.endsWith(`.${normalizedDomain}`)
  );
}

function exactChallengeResourceHostsForSite(siteId) {
  return [...(EXACT_CHALLENGE_RESOURCE_HOSTS_BY_SITE[siteId] ?? [])];
}

function networkRequestDecision(
  urlText,
  isMainNavigation,
  allowedNavigationDomains = [],
  allowedResourceDomains = allowedNavigationDomains,
  exactResourceHosts = [],
  allowPublicHttpsSubresources = false,
  noAlgumonNetwork = false,
) {
  let parsed;
  try {
    parsed = new URL(urlText);
  } catch {
    return { allowed: false, reason: "invalid-url", hostname: null };
  }
  if (["about:", "blob:", "data:"].includes(parsed.protocol)) {
    if (isMainNavigation && parsed.href !== "about:blank") {
      return {
        allowed: false,
        reason: "local-top-level-navigation-denied",
        hostname: null,
      };
    }
    return { allowed: true, reason: "local-browser-scheme", hostname: null };
  }
  const hostname = normalizedHostname(parsed.hostname);
  if (noAlgumonNetwork && hostnameMatches(hostname, "algumon.com")) {
    return { allowed: false, reason: "algumon-network-disabled", hostname };
  }
  const secureTransport =
    parsed.protocol === "https:" ||
    (!isMainNavigation && parsed.protocol === "wss:");
  if (!secureTransport) {
    return { allowed: false, reason: "https-required", hostname };
  }
  if (parsed.username || parsed.password || parsed.port) {
    return { allowed: false, reason: "credentialed-or-non-default-authority", hostname };
  }
  if (forbiddenInfrastructureHostname(hostname)) {
    return { allowed: false, reason: "forbidden-infrastructure", hostname };
  }
  const navigationAllowed = allowedNavigationDomains.some((domain) =>
    hostnameMatches(hostname, domain),
  );
  const firstPartyResourceAllowed = allowedResourceDomains.some((domain) =>
    hostnameMatches(hostname, domain),
  );
  const exactChallengeResourceAllowed = exactResourceHosts.some(
    (exactHostname) => hostname === normalizedHostname(exactHostname),
  );
  if (isMainNavigation && !navigationAllowed) {
    return { allowed: false, reason: "top-level-navigation-denied", hostname };
  }
  if (isMainNavigation) {
    return { allowed: true, reason: "declared-navigation-domain", hostname };
  }
  if (!firstPartyResourceAllowed && !exactChallengeResourceAllowed) {
    return allowPublicHttpsSubresources
      ? { allowed: true, reason: "bounded-public-https-subresource", hostname }
      : { allowed: false, reason: "resource-host-denied", hostname };
  }
  return {
    allowed: true,
    reason: exactChallengeResourceAllowed && !firstPartyResourceAllowed
      ? "exact-challenge-subresource"
      : "declared-resource-domain",
    hostname,
  };
}

function isTopLevelNavigationRequest(request) {
  if (!request.isNavigationRequest()) return false;
  try {
    return request.frame().parentFrame() === null;
  } catch {
    return true;
  }
}

function createNetworkPolicyEvidenceRecorder({
  allowPublicHttpsSubresources = false,
  maximumRemoteHosts = NETWORK_POLICY_MAX_REMOTE_HOSTS,
  maximumRemoteRequests = NETWORK_POLICY_MAX_REMOTE_REQUESTS,
} = {}) {
  if (!Number.isInteger(maximumRemoteHosts) || maximumRemoteHosts < 1) {
    throw new Error("maximumRemoteHosts must be a positive integer");
  }
  if (!Number.isInteger(maximumRemoteRequests) || maximumRemoteRequests < 1) {
    throw new Error("maximumRemoteRequests must be a positive integer");
  }
  const blockedByHost = new Map();
  const exactChallengeByHost = new Map();
  const allowedPublicByHost = new Map();
  const undeclaredPublicByHost = new Map();
  const failedAllowedRequestByHost = new Map();
  const failedAllowedResponseByHost = new Map();
  const failedAllowedRequests = [];
  const failedAllowedResponses = [];
  const activeRemoteRequests = new Map();
  const lateRequests = [];
  let undrainedRequests = [];
  let undrainedRequestCount = 0;
  let requestSequence = 0;
  let lifecycleEvidenceOverflowCount = 0;
  let failedResourceEvidenceOverflowCount = 0;
  const navigationViolationByAuthority = new Map();
  const navigationViolationKeys = new Set();
  const attemptedRemoteHosts = new Set();
  let attemptedRemoteRequestCount = 0;
  let remoteHostBudgetOverflowCount = 0;
  let remoteRequestBudgetOverflowCount = 0;
  let blockedHostOverflowCount = 0;
  let activeRemoteRequestCount = 0;
  let lateRequestCount = 0;
  let drainTimeoutCount = 0;
  let sealed = false;
  let lastRemoteEventAt = Date.now();
  const record = (collection, hostname, requestType, reason, isMainNavigation) => {
    const normalized = normalizedHostname(hostname);
    let entry = collection.get(normalized);
    if (!entry) {
      if (collection.size >= maximumRemoteHosts) {
        blockedHostOverflowCount += 1;
        return;
      }
      entry = {
        hostname: normalized.slice(0, 253),
        count: 0,
        mainNavigationCount: 0,
        requestTypes: new Set(),
        reasons: new Set(),
      };
      collection.set(normalized, entry);
    }
    entry.count += 1;
    if (isMainNavigation) entry.mainNavigationCount += 1;
    entry.requestTypes.add(String(requestType ?? "unknown").slice(0, 32));
    entry.reasons.add(String(reason ?? "unknown").slice(0, 64));
  };
  const serialize = (collection) => [...collection.values()]
    .map((entry) => ({
      hostname: entry.hostname,
      count: entry.count,
      mainNavigationCount: entry.mainNavigationCount,
      requestTypes: [...entry.requestTypes].sort(),
      reasons: [...entry.reasons].sort(),
    }))
    .sort((left, right) =>
      left.hostname < right.hostname ? -1 : left.hostname > right.hostname ? 1 : 0,
    );
  const recordFailedResource = (collection, hostname, requestType, reason, isMainNavigation, urlText, redirectEvidence) => {
    if (collection.length >= maximumRemoteRequests) {
      failedResourceEvidenceOverflowCount += 1;
      return;
    }
    collection.push({
      hostname: normalizedHostname(hostname).slice(0, 253),
      requestType: String(requestType ?? "unknown").slice(0, 32),
      reason: String(reason ?? "unknown").slice(0, 64),
      isMainNavigation: isMainNavigation === true,
      // URLs may carry signed queries or path tokens. Persist only their digest.
      urlSha256: networkResourceUrlSha256(urlText),
      ...(redirectEvidence ? {
        redirectAncestorUrlSha256s: [...redirectEvidence.ancestorUrlSha256s],
        redirectAncestryStatus: redirectEvidence.status,
      } : {}),
    });
  };
  return {
    reserveRemoteRequest(hostname, resource = {}) {
      lastRemoteEventAt = Date.now();
      const entry = {
        hostname: normalizedHostname(hostname).slice(0, 253),
        requestType: String(resource.requestType ?? "unknown").slice(0, 32),
        isMainNavigation: resource.isMainNavigation === true,
        urlSha256: networkResourceUrlSha256(resource.urlText),
        ...(resource.redirectEvidence ? {
          redirectAncestorUrlSha256s: [...resource.redirectEvidence.ancestorUrlSha256s],
          redirectAncestryStatus: resource.redirectEvidence.status,
        } : {}),
      };
      if (sealed) {
        lateRequestCount += 1;
        if (lateRequests.length < maximumRemoteRequests) lateRequests.push(entry);
        else lifecycleEvidenceOverflowCount += 1;
        return {
          allowed: false,
          reason: "network-evidence-sealed",
          finish() {},
        };
      }
      activeRemoteRequestCount += 1;
      const sequence = ++requestSequence;
      if (activeRemoteRequests.size < maximumRemoteRequests) activeRemoteRequests.set(sequence, entry);
      else lifecycleEvidenceOverflowCount += 1;
      let finished = false;
      const finish = () => {
        if (finished) return;
        finished = true;
        activeRemoteRequestCount -= 1;
        activeRemoteRequests.delete(sequence);
        lastRemoteEventAt = Date.now();
      };
      attemptedRemoteRequestCount += 1;
      if (attemptedRemoteRequestCount > maximumRemoteRequests) {
        remoteRequestBudgetOverflowCount += 1;
        return { allowed: false, reason: "remote-request-budget-exceeded", finish };
      }
      const normalized = normalizedHostname(hostname);
      if (normalized && !attemptedRemoteHosts.has(normalized)) {
        if (attemptedRemoteHosts.size >= maximumRemoteHosts) {
          remoteHostBudgetOverflowCount += 1;
          return { allowed: false, reason: "remote-host-budget-exceeded", finish };
        }
        attemptedRemoteHosts.add(normalized);
      }
      return { allowed: true, reason: "within-remote-network-budget", finish };
    },
    recordBlocked(hostname, requestType, reason, isMainNavigation) {
      record(blockedByHost, hostname, requestType, reason, isMainNavigation);
    },
    recordAllowedPublic(hostname, requestType, reason, isMainNavigation) {
      record(allowedPublicByHost, hostname, requestType, reason, isMainNavigation);
      if (reason === "bounded-public-https-subresource") {
        record(undeclaredPublicByHost, hostname, requestType, reason, isMainNavigation);
      }
    },
    recordAllowedRequestFailure(hostname, requestType, reason, isMainNavigation, urlText, redirectEvidence) {
      record(failedAllowedRequestByHost, hostname, requestType, reason, isMainNavigation);
      recordFailedResource(failedAllowedRequests, hostname, requestType, reason, isMainNavigation, urlText, redirectEvidence);
    },
    recordAllowedResponseFailure(hostname, requestType, status, isMainNavigation, urlText, redirectEvidence) {
      record(
        failedAllowedResponseByHost,
        hostname,
        requestType,
        `http-${Number.isInteger(status) ? status : "invalid"}`,
        isMainNavigation,
      );
      recordFailedResource(failedAllowedResponses, hostname, requestType,
        `http-${Number.isInteger(status) ? status : "invalid"}`, isMainNavigation, urlText, redirectEvidence);
    },
    recordExactChallenge(hostname, requestType, reason, isMainNavigation) {
      record(exactChallengeByHost, hostname, requestType, reason, isMainNavigation);
    },
    recordNavigationViolation(protocol, hostname, reason) {
      const safeProtocol = String(protocol ?? "unknown")
        .toLowerCase()
        .replace(/[^a-z0-9+.-]/gu, "")
        .slice(0, 24);
      const safeHostname = normalizedHostname(hostname) || `[${safeProtocol || "unknown"}]`;
      const key = `${safeProtocol}|${safeHostname}|${String(reason ?? "unknown")}`;
      if (navigationViolationKeys.has(key)) return;
      navigationViolationKeys.add(key);
      record(
        navigationViolationByAuthority,
        safeHostname,
        "document",
        reason,
        true,
      );
    },
    async sealAndDrain({
      quietWindowMs = 250,
      timeoutMs = 3_000,
      onSeal = () => {},
    } = {}) {
      const deadline = Date.now() + timeoutMs;
      while (
        activeRemoteRequestCount > 0 ||
        Date.now() - lastRemoteEventAt < quietWindowMs
      ) {
        if (Date.now() >= deadline) {
          drainTimeoutCount += 1;
          undrainedRequestCount = activeRemoteRequestCount;
          undrainedRequests = structuredClone([...activeRemoteRequests.values()]);
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, Math.min(50, quietWindowMs)));
      }
      sealed = true;
      onSeal();
      await new Promise((resolve) => setTimeout(resolve, Math.min(100, quietWindowMs)));
      return this.snapshot();
    },
    snapshot() {
      const blockedHosts = serialize(blockedByHost);
      return {
        policyVersion: 2,
        mode: allowPublicHttpsSubresources
          ? "bounded-public-https-fidelity"
          : "declared-only",
        limits: {
          maximumRemoteHosts,
          maximumRemoteRequests,
        },
        attemptedRemoteHostCount: attemptedRemoteHosts.size,
        attemptedRemoteRequestCount,
        remoteHostBudgetOverflowCount,
        remoteRequestBudgetOverflowCount,
        activeRemoteRequestCount,
        lateRequestCount,
        drainTimeoutCount,
        activeRemoteRequests: structuredClone([...activeRemoteRequests.values()]),
        lateRequests: structuredClone(lateRequests),
        undrainedRequests: structuredClone(undrainedRequests),
        undrainedRequestCount,
        lifecycleEvidenceOverflowCount,
        sealed,
        allowedPublicHosts: serialize(allowedPublicByHost),
        undeclaredPublicHosts: serialize(undeclaredPublicByHost),
        failedAllowedRequestHosts: serialize(failedAllowedRequestByHost),
        failedAllowedResponseHosts: serialize(failedAllowedResponseByHost),
        failedAllowedRequests: structuredClone(failedAllowedRequests),
        failedAllowedResponses: structuredClone(failedAllowedResponses),
        failedResourceEvidenceOverflowCount,
        navigationViolations: serialize(navigationViolationByAuthority),
        blockedHosts,
        blockedHostCount: blockedHosts.length,
        blockedRequestCount: blockedHosts.reduce((sum, entry) => sum + entry.count, 0),
        blockedHostOverflowCount,
        exactChallengeHosts: serialize(exactChallengeByHost),
      };
    },
  };
}

function networkResourceUrlSha256(urlText) {
  try {
    const url = new URL(urlText);
    url.hash = "";
    return sha256(url.href);
  } catch {
    return null;
  }
}

function networkRequestRedirectEvidence(request) {
  const ancestorUrlSha256s = [];
  const seen = new Set([request]);
  let current = request;
  try {
    while (true) {
      const ancestor = current.redirectedFrom();
      if (!ancestor) return { ancestorUrlSha256s, status: "complete" };
      if (seen.has(ancestor)) return { ancestorUrlSha256s, status: "cycle" };
      if (ancestorUrlSha256s.length >= NETWORK_POLICY_MAX_REDIRECT_ANCESTORS) {
        return { ancestorUrlSha256s, status: "overflow" };
      }
      seen.add(ancestor);
      const digest = networkResourceUrlSha256(ancestor.url());
      if (!digest) return { ancestorUrlSha256s, status: "invalid-url" };
      ancestorUrlSha256s.push(digest);
      current = ancestor;
    }
  } catch {
    return { ancestorUrlSha256s, status: "unavailable" };
  }
}

function createStylesheetDependencyRecorder({ maximumDependencies = NETWORK_POLICY_MAX_REMOTE_REQUESTS } = {}) {
  if (!Number.isInteger(maximumDependencies) || maximumDependencies < 1) {
    throw new Error("maximumDependencies must be a positive integer");
  }
  const dependencies = new Map();
  let dependencyOverflowCount = 0;
  let invalidDependencyCount = 0;
  const recordDependency = (parentUrl, childUrl, kind) => {
    const parentUrlSha256 = networkResourceUrlSha256(parentUrl);
    const childUrlSha256 = networkResourceUrlSha256(childUrl);
    if (!parentUrlSha256 || !childUrlSha256) {
      invalidDependencyCount += 1;
      return;
    }
    if (parentUrlSha256 === childUrlSha256) return;
    const key = `${parentUrlSha256}:${childUrlSha256}`;
    if (dependencies.has(key)) return;
    if (dependencies.size >= maximumDependencies) {
      dependencyOverflowCount += 1;
      return;
    }
    dependencies.set(key, { parentUrlSha256, childUrlSha256, kind });
  };
  return {
    recordRequest(event, mainFrameId) {
      if (event.frameId !== mainFrameId || !["Stylesheet", "Font"].includes(event.type)) return;
      // CDP observes parser dependencies even when CSSOM access to an imported
      // cross-origin stylesheet is forbidden. Do not infer a dependency merely
      // from sharing a host, or promote unrelated script/XHR/font requests.
      if (event.initiator?.url) {
        recordDependency(event.initiator.url, event.request?.url, event.type.toLowerCase());
      }
      if (event.redirectResponse?.url) {
        recordDependency(event.redirectResponse.url, event.request?.url, "redirect");
      }
    },
    snapshot() {
      return {
        dependencies: [...dependencies.values()].map((entry) => ({ ...entry })),
        dependencyOverflowCount,
        invalidDependencyCount,
      };
    },
  };
}

async function observeStylesheetDependencies(context, page, recorder) {
  const session = await context.newCDPSession(page);
  let mainFrameId;
  const onFrameNavigated = ({ frame }) => {
    if (!frame.parentId) mainFrameId = frame.id;
  };
  const onRequest = (event) => recorder.recordRequest(event, mainFrameId);
  try {
    await session.send("Page.enable");
    const frameTree = await session.send("Page.getFrameTree");
    mainFrameId = frameTree.frameTree.frame.id;
    session.on("Page.frameNavigated", onFrameNavigated);
    session.on("Network.requestWillBeSent", onRequest);
    await session.send("Network.enable");
  } catch (error) {
    session.off("Page.frameNavigated", onFrameNavigated);
    session.off("Network.requestWillBeSent", onRequest);
    await session.detach().catch(() => {});
    throw error;
  }
  return async () => {
    session.off("Page.frameNavigated", onFrameNavigated);
    session.off("Network.requestWillBeSent", onRequest);
    await session.detach().catch(() => {});
  };
}

async function primeDeclaredArticleNavigation(
  session, targetUrl, navigationDomains, { siteId, profileName } = {},
) {
  const decision = networkRequestDecision(targetUrl, true, navigationDomains, navigationDomains);
  if (!decision.allowed || !decision.hostname) {
    throw new Error(`article navigation priming refused: ${decision.reason}`);
  }
  const hostnames = new Set([decision.hostname]);
  const mobileRedirect = profileName === "mobile"
    ? OBSERVED_MOBILE_ARTICLE_REDIRECT_HOSTS[siteId]
    : null;
  if (mobileRedirect?.from === decision.hostname) {
    const mobileUrl = new URL(targetUrl);
    mobileUrl.hostname = mobileRedirect.to;
    const mobileDecision = networkRequestDecision(
      mobileUrl.href, true, navigationDomains, navigationDomains,
    );
    if (!mobileDecision.allowed || mobileDecision.hostname !== mobileRedirect.to) {
      throw new Error(`article navigation priming refused: ${mobileDecision.reason}`);
    }
    hostnames.add(mobileDecision.hostname);
  }
  // Preapprove only the initial host and this site's observed mobile redirect,
  // with the same public DNS/IP pinning. Redirect URL/navigation guards remain.
  for (const hostname of hostnames) {
    const addresses = await session.approvePublicHost(hostname);
    if (!Array.isArray(addresses) || addresses.length === 0 || addresses.some(isPrivateOrSpecialIp)) {
      throw new Error("article navigation priming found no verified public DNS addresses");
    }
  }
}

function networkFidelityFailures(
  networkPolicyEvidence,
  declaredResourceDomains = [],
  roleReferencedResourceEvidence = [],
) {
  const failures = [];
  const roleResourceEvidence = Array.isArray(roleReferencedResourceEvidence)
    ? {
        hosts: roleReferencedResourceEvidence,
        selectorErrorCount: 0,
        rootOverflowCount: 0,
        nodeOverflowCount: 0,
        urlOverflowCount: 0,
        hostOverflowCount: 0,
        elapsedTimeOverflowCount: 0,
        unsafeReferences: [],
        unsafeReferenceOverflowCount: 0,
      }
    : roleReferencedResourceEvidence ?? { hosts: [] };
  const pinnedTransport = networkPolicyEvidence?.pinnedTransport ?? null;
  const requiredResourceDigests = new Set(roleResourceEvidence.urlSha256s ?? []);
  const stylesheetDependencies = networkPolicyEvidence?.stylesheetDependencies;
  const dependencyChildren = new Map();
  for (const entry of stylesheetDependencies?.dependencies ?? []) {
    if (!dependencyChildren.has(entry.parentUrlSha256)) dependencyChildren.set(entry.parentUrlSha256, []);
    dependencyChildren.get(entry.parentUrlSha256).push(entry.childUrlSha256);
  }
  const requiredQueue = [...requiredResourceDigests];
  for (let index = 0; index < requiredQueue.length; index += 1) {
    for (const digest of dependencyChildren.get(requiredQueue[index]) ?? []) {
      if (requiredResourceDigests.has(digest)) continue;
      requiredResourceDigests.add(digest);
      requiredQueue.push(digest);
    }
  }
  const referencedHosts = new Set((roleResourceEvidence.hosts ?? []).map(normalizedHostname));
  const isRequiredHost = (hostname) =>
    declaredResourceDomains.some((domain) => hostnameMatches(hostname, domain)) ||
    referencedHosts.has(normalizedHostname(hostname));
  const isRequiredRequest = (entry) => entry.isMainNavigation === true ||
    (entry.urlSha256 && requiredResourceDigests.has(entry.urlSha256)) ||
    (entry.redirectAncestorUrlSha256s ?? []).some((digest) => requiredResourceDigests.has(digest));
  const hasIndependentNoiseEvidence = (entry) =>
    /^[a-f0-9]{64}$/u.test(entry.urlSha256 ?? "") &&
    OBSERVED_DEDICATED_NOISE_HOSTS.has(normalizedHostname(entry.hostname)) &&
    entry.redirectAncestryStatus === "complete" &&
    Array.isArray(entry.redirectAncestorUrlSha256s) && entry.redirectAncestorUrlSha256s.length === 0;
  const isDataRequestType = (type) => type === "fetch" || type === "xhr";
  // An exhaustive retained subtree can prove that a presentation-only request
  // is unrelated to the article. Embedded documents remain conservative: their
  // inner resources are not enumerated by the top-level DOM collector.
  const completeFrameFreePresentationEvidence = roleResourceEvidence.rootCount > 0 &&
    roleResourceEvidence.nodeCount > 0 && roleResourceEvidence.retainedFrameCount === 0 &&
    Array.isArray(roleResourceEvidence.urlSha256s) &&
    roleResourceEvidence.urlSha256s.every((digest) => /^[a-f0-9]{64}$/u.test(digest)) &&
    ["selectorErrorCount", "rootOverflowCount", "nodeOverflowCount", "urlOverflowCount",
      "hostOverflowCount", "elapsedTimeOverflowCount", "stylesheetRuleOverflowCount",
      "stylesheetRuleErrorCount", "unsafeReferenceOverflowCount"].every((key) => roleResourceEvidence[key] === 0) &&
    Array.isArray(roleResourceEvidence.unsafeReferences) && roleResourceEvidence.unsafeReferences.length === 0;
  const isUnreferencedPresentationRequest = (entry) => completeFrameFreePresentationEvidence &&
    ["image", "media"].includes(entry.requestType) && entry.isMainNavigation === false &&
    /^[a-f0-9]{64}$/u.test(entry.urlSha256 ?? "") && entry.redirectAncestryStatus === "complete" &&
    Array.isArray(entry.redirectAncestorUrlSha256s) && !isRequiredRequest(entry);
  const hasRequiredFailure = (requestKey, hostKey) => {
    const requests = networkPolicyEvidence?.[requestKey];
    if (Array.isArray(requests)) {
      return requests.some((entry) => isRequiredRequest(entry) ||
        (isDataRequestType(entry.requestType) && !hasIndependentNoiseEvidence(entry)) ||
        // Older callers without exact URL evidence keep the conservative host check.
        (!entry.urlSha256 && isRequiredHost(entry.hostname)));
    }
    return (networkPolicyEvidence?.[hostKey] ?? []).some((entry) =>
      entry.mainNavigationCount > 0 || isRequiredHost(entry.hostname) ||
      (entry.requestTypes ?? []).some(isDataRequestType));
  };
  const lifecycleContainsRequiredRequest = (key, expectedCount) => {
    const entries = networkPolicyEvidence?.[key];
    // Legacy/missing identities cannot prove an unfinished request optional.
    return !Number.isSafeInteger(expectedCount) || expectedCount < 0 ||
      !Array.isArray(entries) || entries.length !== expectedCount || entries.some((entry) => !entry.urlSha256 ||
      (entry.redirectAncestryStatus && entry.redirectAncestryStatus !== "complete") ||
      isRequiredRequest(entry) || (!hasIndependentNoiseEvidence(entry) && !isUnreferencedPresentationRequest(entry)));
  };
  if (
    networkPolicyEvidence?.mode === "bounded-public-https-fidelity" &&
    pinnedTransport?.mode !== "route-approved-numeric-ip-connect"
  ) {
    failures.push("bounded public fidelity mode has no pinned numeric-IP transport proof");
  }
  if (
    networkPolicyEvidence?.mode === "bounded-public-https-fidelity" &&
    networkPolicyEvidence?.sealed !== true
  ) {
    failures.push("bounded public fidelity evidence was not sealed after a quiet drain");
  }
  if ((networkPolicyEvidence?.activeRemoteRequestCount ?? 0) > 0 &&
    lifecycleContainsRequiredRequest("activeRemoteRequests", networkPolicyEvidence.activeRemoteRequestCount)) {
    failures.push("network evidence sealed with active remote requests");
  }
  if ((networkPolicyEvidence?.lateRequestCount ?? 0) > 0 &&
    lifecycleContainsRequiredRequest("lateRequests", networkPolicyEvidence.lateRequestCount)) {
    failures.push("remote requests appeared after the network evidence seal");
  }
  if ((networkPolicyEvidence?.drainTimeoutCount ?? 0) > 0 &&
    lifecycleContainsRequiredRequest("undrainedRequests", networkPolicyEvidence.undrainedRequestCount)) {
    failures.push("remote requests did not drain inside the fail-closed deadline");
  }
  if ((networkPolicyEvidence?.navigationViolations ?? []).length > 0) {
    failures.push("a main frame reached a non-approved or local document URL");
  }
  if (hasRequiredFailure("failedAllowedRequests", "failedAllowedRequestHosts")) {
    failures.push("an allowed remote request failed before a complete response");
  }
  if (hasRequiredFailure("failedAllowedResponses", "failedAllowedResponseHosts")) {
    failures.push("an allowed remote response returned HTTP 4xx or 5xx");
  }
  if ((networkPolicyEvidence?.failedResourceEvidenceOverflowCount ?? 0) > 0) {
    failures.push("failed resource evidence exceeded its bounded request count");
  }
  if ((networkPolicyEvidence?.lifecycleEvidenceOverflowCount ?? 0) > 0) {
    failures.push("request lifecycle evidence exceeded its bounded request count");
  }
  if ((stylesheetDependencies?.dependencyOverflowCount ?? 0) > 0 ||
    (stylesheetDependencies?.invalidDependencyCount ?? 0) > 0) {
    failures.push("stylesheet dependency evidence was invalid or exceeded its bounded dependency count");
  }
  if ([...(networkPolicyEvidence?.failedAllowedRequests ?? []),
    ...(networkPolicyEvidence?.failedAllowedResponses ?? [])].some((entry) =>
    entry.redirectAncestryStatus && entry.redirectAncestryStatus !== "complete")) {
    failures.push("failed resource redirect ancestry was incomplete or cyclic");
  }
  if ((networkPolicyEvidence?.remoteHostBudgetOverflowCount ?? 0) > 0) {
    failures.push("remote resource host cardinality exceeded its fail-closed budget");
  }
  if ((networkPolicyEvidence?.remoteRequestBudgetOverflowCount ?? 0) > 0) {
    failures.push("remote request count exceeded its fail-closed budget");
  }
  if ((networkPolicyEvidence?.blockedHostOverflowCount ?? 0) > 0) {
    failures.push("blocked resource host evidence exceeded its bounded host cardinality");
  }
  if ((pinnedTransport?.connectRequestBudgetOverflowCount ?? 0) > 0) {
    failures.push("pinned transport CONNECT count exceeded its fail-closed budget");
  }
  if ((pinnedTransport?.activeTunnelBudgetOverflowCount ?? 0) > 0) {
    failures.push("pinned transport active tunnel count exceeded its fail-closed budget");
  }
  if ((pinnedTransport?.transferByteBudgetOverflowCount ?? 0) > 0) {
    failures.push("pinned transport transfer bytes exceeded its fail-closed budget");
  }
  if ((pinnedTransport?.dnsAddressOverflowCount ?? 0) > 0) {
    failures.push("DNS answer cardinality exceeded its fail-closed budget");
  }
  if ((pinnedTransport?.dnsTimeoutCount ?? 0) > 0) {
    failures.push("public-host DNS resolution exceeded its fail-closed deadline");
  }
  if ((pinnedTransport?.evidenceHostOverflowCount ?? 0) > 0) {
    failures.push("pinned transport evidence exceeded its bounded host cardinality");
  }
  if ((pinnedTransport?.transportErrorCount ?? 0) > 0) {
    failures.push("pinned transport emitted an internal server error");
  }
  if (
    networkPolicyEvidence?.mode === "bounded-public-https-fidelity" &&
    pinnedTransport?.sealed !== true
  ) {
    failures.push("pinned numeric-IP transport was not sealed with network evidence");
  }
  const lateConnectCount = pinnedTransport?.lateConnectCount ?? 0;
  const rejectedBeforeUpstreamCount = pinnedTransport?.lateConnectRejectedBeforeUpstreamCount;
  if (lateConnectCount !== 0 || (rejectedBeforeUpstreamCount ?? 0) !== 0) {
    const allLateConnectsRejectedBeforeUpstream =
      pinnedTransport?.mode === "route-approved-numeric-ip-connect" &&
      pinnedTransport?.sealed === true &&
      Number.isSafeInteger(lateConnectCount) && lateConnectCount > 0 &&
      Number.isSafeInteger(pinnedTransport?.connectRequestCount) &&
      pinnedTransport.connectRequestCount >= lateConnectCount &&
      pinnedTransport.connectRequestCount <= PINNED_PROXY_MAX_CONNECT_REQUESTS &&
      Number.isSafeInteger(rejectedBeforeUpstreamCount) &&
      rejectedBeforeUpstreamCount === lateConnectCount;
    // A locally refused CONNECT never became an upstream request. Its explicit
    // rejection proof does not excuse any late HTTP/API or required resource.
    if (!allLateConnectsRejectedBeforeUpstream) {
      failures.push("CONNECT attempts appeared after the pinned transport seal without complete upstream-rejection proof");
    }
  }
  if ((roleResourceEvidence.selectorErrorCount ?? 0) > 0) {
    failures.push("exact semantic role resource selector evaluation failed");
  }
  if ((roleResourceEvidence.rootOverflowCount ?? 0) > 0) {
    failures.push("semantic role resource traversal exceeded its root budget");
  }
  if ((roleResourceEvidence.nodeOverflowCount ?? 0) > 0) {
    failures.push("semantic role resource traversal exceeded its node budget");
  }
  if ((roleResourceEvidence.stylesheetRuleOverflowCount ?? 0) > 0 ||
    (roleResourceEvidence.stylesheetRuleErrorCount ?? 0) > 0) {
    failures.push("inline stylesheet font evidence was unreadable or exceeded its bounded rule count");
  }
  if ((roleResourceEvidence.urlOverflowCount ?? 0) > 0) {
    failures.push("semantic role resource traversal exceeded its URL budget");
  }
  if ((roleResourceEvidence.hostOverflowCount ?? 0) > 0) {
    failures.push("semantic role resource traversal exceeded its host budget");
  }
  if ((roleResourceEvidence.elapsedTimeOverflowCount ?? 0) > 0) {
    failures.push("semantic role resource traversal exceeded its time budget");
  }
  if ((roleResourceEvidence.unsafeReferenceOverflowCount ?? 0) > 0) {
    failures.push("unsafe semantic role resource evidence exceeded its host budget");
  }
  if ((roleResourceEvidence.unsafeReferences ?? []).length > 0) {
    failures.push("semantic role resources contain insecure or non-default authorities");
  }
  const requiredBlockedHosts = (networkPolicyEvidence?.blockedHosts ?? []).filter(
    (entry) => isRequiredHost(entry.hostname) &&
      (!Array.isArray(networkPolicyEvidence?.lateRequests) ||
        (entry.reasons ?? []).some((reason) => reason !== "network-evidence-sealed")),
  );
  if (requiredBlockedHosts.length > 0) {
    failures.push(
      `${requiredBlockedHosts.length} required resource hosts were blocked by the audit network policy`,
    );
  }
  const connectedHosts = new Set(
    (pinnedTransport?.connectedHosts ?? []).map((entry) => normalizedHostname(entry.hostname)),
  );
  const requiredRejectedTransportHosts = (pinnedTransport?.rejectedHosts ?? []).filter(
    (entry) => isRequiredHost(entry.hostname) && !connectedHosts.has(normalizedHostname(entry.hostname)),
  );
  if (requiredRejectedTransportHosts.length > 0) {
    failures.push(
      `${requiredRejectedTransportHosts.length} required resource hosts failed pinned transport`,
    );
  }
  const unpinnedMainNavigationHosts = (networkPolicyEvidence?.allowedPublicHosts ?? []).filter(
    (entry) => entry.mainNavigationCount > 0 && !connectedHosts.has(normalizedHostname(entry.hostname)),
  );
  if (unpinnedMainNavigationHosts.length > 0) {
    failures.push("main-document transport did not prove a pinned numeric-IP tunnel");
  }
  return failures;
}

function normalizedHostname(hostname) {
  return String(hostname ?? "")
    .toLowerCase()
    .replace(/^\[|\]$/gu, "")
    .replace(/\.$/u, "");
}

const NON_PUBLIC_IPV4_BLOCKLIST = new BlockList();
const NON_PUBLIC_IPV6_BLOCKLIST = new BlockList();
for (const [network, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
]) {
  NON_PUBLIC_IPV4_BLOCKLIST.addSubnet(network, prefix, "ipv4");
}
for (const [network, prefix] of [
  ["::", 128],
  ["::1", 128],
  ["::", 96],
  ["::ffff:0:0", 96],
  ["64:ff9b::", 96],
  ["64:ff9b:1::", 48],
  ["100::", 64],
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["fc00::", 7],
  ["fe80::", 10],
  ["fec0::", 10],
  ["ff00::", 8],
]) {
  NON_PUBLIC_IPV6_BLOCKLIST.addSubnet(network, prefix, "ipv6");
}

function ipv4MappedAddress(address) {
  const normalized = normalizedHostname(address);
  const dotted = normalized.match(/^::(?:ffff:)?(\d+\.\d+\.\d+\.\d+)$/u)?.[1];
  if (dotted) return dotted;
  const hexadecimal = normalized.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/u);
  if (!hexadecimal) return null;
  const high = Number.parseInt(hexadecimal[1], 16);
  const low = Number.parseInt(hexadecimal[2], 16);
  return `${high >>> 8}.${high & 255}.${low >>> 8}.${low & 255}`;
}

function isPrivateOrSpecialIp(address) {
  const normalized = normalizedHostname(address);
  const family = isIP(normalized);
  if (family === 0) return true;
  const mapped = family === 6 ? ipv4MappedAddress(normalized) : null;
  if (mapped) return NON_PUBLIC_IPV4_BLOCKLIST.check(mapped, "ipv4");
  return family === 4
    ? NON_PUBLIC_IPV4_BLOCKLIST.check(normalized, "ipv4")
    : NON_PUBLIC_IPV6_BLOCKLIST.check(normalized, "ipv6");
}

function forbiddenInfrastructureHostname(hostname) {
  const normalized = normalizedHostname(hostname);
  return (
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    normalized.endsWith(".local") ||
    normalized.endsWith(".internal") ||
    normalized === "metadata.google.internal" ||
    isIP(normalized) !== 0
  );
}

function parseConnectAuthority(authority) {
  const match = String(authority ?? "").match(/^([^\s:@/?#\[\]]+):(\d{1,5})$/u);
  if (!match) return null;
  const hostname = normalizedHostname(match[1]);
  const port = Number(match[2]);
  if (
    !hostname ||
    hostname.length > 253 ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65_535 ||
    isIP(hostname) !== 0 ||
    forbiddenInfrastructureHostname(hostname)
  ) {
    return null;
  }
  return { hostname, port };
}

function validatePublicDnsAnswers(records, maximumAddresses = PINNED_PROXY_MAX_DNS_ADDRESSES) {
  if (!Array.isArray(records)) {
    return { addresses: [], answerCount: 0, uniqueAddressCount: 0, reason: "dns-invalid-answer" };
  }
  const addresses = [...new Set(records.map((record) => normalizedHostname(record?.address)))].sort();
  const evidence = { answerCount: records.length, uniqueAddressCount: addresses.length };
  if (addresses.length > maximumAddresses) {
    return { ...evidence, addresses: [], reason: "dns-answer-budget-exceeded" };
  }
  if (addresses.length === 0) {
    return { ...evidence, addresses: [], reason: "dns-empty-answer" };
  }
  if (addresses.some(isPrivateOrSpecialIp)) {
    return { ...evidence, addresses: [], reason: "dns-not-public" };
  }
  return { ...evidence, addresses, reason: "public-addresses-validated" };
}

function connectPinnedPublicAddress(
  address, timeoutMs, observeSocket = () => {}, createSocket = createConnection,
) {
  return new Promise((resolve, reject) => {
    const upstream = createSocket({ host: address, port: 443, family: isIP(address) });
    let settled = false;
    const cleanup = (awaitClose = false) => {
      upstream.setTimeout(0);
      upstream.removeListener("timeout", onTimeout);
      upstream.removeListener("connect", onConnect);
      if (!awaitClose) {
        upstream.removeListener("error", fail);
        upstream.removeListener("close", onClose);
      }
    };
    const fail = (error) => {
      if (settled) return;
      settled = true;
      // Keep the failure listener until close so a queued socket error cannot
      // become unhandled while a timed-out/cancelled socket is being destroyed.
      cleanup(true);
      upstream.destroy();
      reject(error);
    };
    const onTimeout = () => fail(Object.assign(new Error("pinned CONNECT timed out"), { code: "ETIMEDOUT" }));
    const onClose = () => {
      fail(Object.assign(new Error("pinned CONNECT closed before connection"), { code: "ECONNABORTED" }));
      upstream.removeListener("error", fail);
    };
    const onConnect = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(upstream);
    };
    upstream.setTimeout(timeoutMs, onTimeout);
    upstream.on("error", fail);
    upstream.once("close", onClose);
    upstream.once("connect", onConnect);
    try { observeSocket(upstream); } catch (error) { fail(error); }
  });
}

async function connectApprovedPublicAddresses(
  addresses,
  connectToAddress,
  { now = Date.now, isClientClosed = () => false,
    observePendingSocket = () => {}, observeAttempt = () => {} } = {},
) {
  const deadline = now() + PINNED_PROXY_CONNECT_TIMEOUT_MS;
  for (const [index, address] of addresses.entries()) {
    if (isClientClosed()) break;
    const remainingMs = deadline - now();
    if (remainingMs <= 0) break;
    let pendingSocket = null;
    const startedAt = now();
    let outcome = "failed";
    let errorCode = null;
    try {
      const upstream = await connectToAddress(
        address,
        index < addresses.length - 1
          ? Math.min(remainingMs, PINNED_PROXY_ADDRESS_CONNECT_TIMEOUT_MS)
          : remainingMs,
        (socket) => { pendingSocket = socket; observePendingSocket(socket); },
      );
      if (isClientClosed() || now() >= deadline) {
        outcome = isClientClosed() ? "cancelled" : "deadline-exceeded";
        errorCode = outcome === "deadline-exceeded" ? "ETIMEDOUT" : null;
        upstream.destroy();
        return null;
      }
      outcome = "connected";
      return upstream;
    } catch (error) {
      outcome = isClientClosed() ? "cancelled" : "failed";
      errorCode = PINNED_PROXY_SAFE_CONNECT_ERROR_CODES.has(error?.code) ? error.code : "UNKNOWN";
      pendingSocket?.destroy();
    } finally {
      observePendingSocket(null);
      observeAttempt({ family: isIP(address), outcome, errorCode,
        elapsedMs: Math.max(0, Math.min(PINNED_PROXY_CONNECT_TIMEOUT_MS, Math.round(now() - startedAt))) });
    }
  }
  return null;
}

async function createPinnedPublicHttpsProxy() {
  const approvedAddressesByHost = new Map();
  const resolutionCache = new Map();
  const connectedByHost = new Map();
  const rejectedByHost = new Map();
  const dnsAnswersByHost = new Map();
  const connectionAttempts = [];
  let omittedConnectionAttemptCount = 0;
  const sockets = new Set();
  let connectRequestCount = 0;
  let activeTunnelCount = 0;
  let connectRequestBudgetOverflowCount = 0;
  let activeTunnelBudgetOverflowCount = 0;
  let transferByteCount = 0;
  let transferByteBudgetOverflowCount = 0;
  let dnsAddressOverflowCount = 0;
  let dnsTimeoutCount = 0;
  let evidenceHostOverflowCount = 0;
  let transportErrorCount = 0;
  let lateConnectCount = 0;
  let lateConnectRejectedBeforeUpstreamCount = 0;
  let sealed = false;
  let closePromise = null;

  const record = (collection, hostname, reason) => {
    const normalized = normalizedHostname(hostname);
    let entry = collection.get(normalized);
    if (!entry) {
      if (collection.size >= PINNED_PROXY_MAX_EVIDENCE_HOSTS) {
        evidenceHostOverflowCount += 1;
        return;
      }
      entry = { hostname: normalized.slice(0, 253), count: 0, reasons: new Set() };
      collection.set(normalized, entry);
    }
    entry.count += 1;
    entry.reasons.add(String(reason ?? "unknown").slice(0, 64));
  };
  const serialize = (collection) => [...collection.values()]
    .map((entry) => ({
      hostname: entry.hostname,
      count: entry.count,
      reasons: [...entry.reasons].sort(),
    }))
    .sort((left, right) =>
      left.hostname < right.hostname ? -1 : left.hostname > right.hostname ? 1 : 0,
    );
  const resolvePublicAddresses = async (hostname) => {
    const normalized = normalizedHostname(hostname);
    if (forbiddenInfrastructureHostname(normalized)) return [];
    const now = Date.now();
    const cached = resolutionCache.get(normalized);
    if (cached && cached.expiresAt > now) return cached.promise;
    const promise = (async () => {
      try {
        let timeoutId;
        const records = await Promise.race([
          lookup(normalized, { all: true, verbatim: true }),
          new Promise((_, reject) => {
            timeoutId = setTimeout(() => {
              dnsTimeoutCount += 1;
              reject(new Error("public-host DNS resolution timed out"));
            }, PINNED_PROXY_DNS_TIMEOUT_MS);
          }),
        ]).finally(() => clearTimeout(timeoutId));
        const answer = validatePublicDnsAnswers(records);
        dnsAnswersByHost.set(normalized, {
          hostname: normalized,
          answerCount: answer.answerCount,
          uniqueAddressCount: answer.uniqueAddressCount,
          maximumAddresses: PINNED_PROXY_MAX_DNS_ADDRESSES,
          reason: answer.reason,
        });
        if (answer.reason === "dns-answer-budget-exceeded") {
          dnsAddressOverflowCount += 1;
        }
        if (answer.addresses.length === 0) {
          record(rejectedByHost, normalized, answer.reason);
        }
        return answer.addresses;
      } catch {
        dnsAnswersByHost.set(normalized, {
          hostname: normalized,
          answerCount: null,
          uniqueAddressCount: null,
          maximumAddresses: PINNED_PROXY_MAX_DNS_ADDRESSES,
          reason: "dns-resolution-failed",
        });
        return [];
      }
    })();
    resolutionCache.set(normalized, { expiresAt: now + 300_000, promise });
    return promise;
  };
  const approvePublicHost = async (hostname) => {
    const normalized = normalizedHostname(hostname);
    const addresses = await resolvePublicAddresses(normalized);
    if (addresses.length < 1) return [];
    if (
      !approvedAddressesByHost.has(normalized) &&
      approvedAddressesByHost.size >= NETWORK_POLICY_MAX_REMOTE_HOSTS
    ) {
      evidenceHostOverflowCount += 1;
      return [];
    }
    approvedAddressesByHost.set(normalized, addresses);
    return addresses;
  };
  const rejectConnect = (clientSocket, status, hostname, reason) => {
    record(rejectedByHost, hostname, reason);
    if (!clientSocket.destroyed) {
      clientSocket.end(
        `HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`,
      );
    }
  };
  const server = createServer((_request, response) => {
    response.writeHead(405, { Connection: "close", "Content-Length": "0" });
    response.end();
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  server.on("connect", (request, clientSocket, head) => {
    connectRequestCount += 1;
    const authority = parseConnectAuthority(request.url);
    const evidenceHostname = authority?.hostname ?? "invalid-connect-authority";
    if (sealed) {
      lateConnectCount += 1;
      rejectConnect(clientSocket, "403 Forbidden", evidenceHostname, "transport-sealed");
      // This branch returns before approval lookup, upstream creation, or head
      // forwarding. Record only rejections that completed this exact branch.
      lateConnectRejectedBeforeUpstreamCount += 1;
      return;
    }
    if (connectRequestCount > PINNED_PROXY_MAX_CONNECT_REQUESTS) {
      connectRequestBudgetOverflowCount += 1;
      rejectConnect(clientSocket, "429 Too Many Requests", evidenceHostname, "connect-budget");
      return;
    }
    if (activeTunnelCount >= PINNED_PROXY_MAX_ACTIVE_TUNNELS) {
      activeTunnelBudgetOverflowCount += 1;
      rejectConnect(clientSocket, "429 Too Many Requests", evidenceHostname, "active-budget");
      return;
    }
    if (!authority || authority.port !== 443) {
      rejectConnect(clientSocket, "403 Forbidden", evidenceHostname, "authority-denied");
      return;
    }
    const approvedAddresses = approvedAddressesByHost.get(authority.hostname);
    if (!approvedAddresses?.length) {
      rejectConnect(clientSocket, "403 Forbidden", authority.hostname, "unapproved-host");
      return;
    }
    activeTunnelCount += 1;
    let tunnelReleased = false;
    let clientClosed = false;
    let pendingUpstream = null;
    const releaseTunnel = () => {
      if (tunnelReleased) return;
      tunnelReleased = true;
      activeTunnelCount -= 1;
    };
    clientSocket.once("close", () => {
      clientClosed = true;
      pendingUpstream?.destroy();
      releaseTunnel();
    });
    void (async () => {
      const upstream = await connectApprovedPublicAddresses(approvedAddresses, connectPinnedPublicAddress, {
        isClientClosed: () => clientClosed,
        observePendingSocket: (socket) => { pendingUpstream = socket; },
        observeAttempt: (attempt) => {
          if (connectionAttempts.length >= PINNED_PROXY_MAX_CONNECT_ATTEMPT_EVIDENCE) {
            omittedConnectionAttemptCount += 1;
          } else {
            connectionAttempts.push({ hostname: authority.hostname, ...attempt });
          }
        },
      });
      pendingUpstream = null;
      if (!upstream || clientClosed) {
        upstream?.destroy();
        releaseTunnel();
        if (!clientClosed) {
          rejectConnect(clientSocket, "502 Bad Gateway", authority.hostname, "connect-failed");
        }
        return;
      }
      sockets.add(upstream);
      upstream.once("close", () => sockets.delete(upstream));
      record(connectedByHost, authority.hostname, "pinned-public-ip");
      const accountTransfer = (chunk) => {
        transferByteCount += chunk.length;
        if (
          transferByteCount > PINNED_PROXY_MAX_TRANSFER_BYTES &&
          transferByteBudgetOverflowCount === 0
        ) {
          transferByteBudgetOverflowCount += 1;
          clientSocket.destroy();
          upstream.destroy();
        }
      };
      clientSocket.on("data", accountTransfer);
      upstream.on("data", accountTransfer);
      clientSocket.once("error", () => upstream.destroy());
      upstream.once("error", () => clientSocket.destroy());
      clientSocket.once("close", () => upstream.destroy());
      upstream.once("close", () => clientSocket.destroy());
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head?.length) {
        accountTransfer(head);
        if (!upstream.destroyed) upstream.write(head);
      }
      clientSocket.pipe(upstream);
      upstream.pipe(clientSocket);
    })().catch(() => {
      releaseTunnel();
      rejectConnect(clientSocket, "502 Bad Gateway", authority.hostname, "proxy-error");
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  server.on("error", () => {
    transportErrorCount += 1;
    for (const socket of sockets) socket.destroy();
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("pinned public HTTPS proxy did not bind to a TCP port");
  }
  return {
    serverUrl: `http://127.0.0.1:${address.port}`,
    approvePublicHost,
    rejectionReasonForHost(hostname) {
      const reason = dnsAnswersByHost.get(normalizedHostname(hostname))?.reason;
      return reason && reason !== "public-addresses-validated" ? reason : "public-host-not-approved";
    },
    seal() {
      sealed = true;
    },
    snapshot() {
      return {
        policyVersion: 1,
        mode: "route-approved-numeric-ip-connect",
        approvedHostCount: approvedAddressesByHost.size,
        connectRequestCount,
        activeTunnelCount,
        connectRequestBudgetOverflowCount,
        activeTunnelBudgetOverflowCount,
        transferByteCount,
        transferByteBudgetOverflowCount,
        connectionAttempts: connectionAttempts.map((attempt) => ({ ...attempt })),
        omittedConnectionAttemptCount,
        dnsAddressOverflowCount,
        dnsAnswerEvidence: [...dnsAnswersByHost.values()].sort((left, right) =>
          left.hostname < right.hostname ? -1 : left.hostname > right.hostname ? 1 : 0),
        dnsTimeoutCount,
        evidenceHostOverflowCount,
        transportErrorCount,
        lateConnectCount,
        lateConnectRejectedBeforeUpstreamCount,
        sealed,
        connectedHosts: serialize(connectedByHost),
        rejectedHosts: serialize(rejectedByHost),
      };
    },
    async close() {
      if (!closePromise) {
        closePromise = (async () => {
          for (const socket of sockets) socket.destroy();
          await new Promise((resolve) => server.close(resolve));
        })();
      }
      return closePromise;
    },
  };
}

function wildcardPathMatches(pathAndQuery, configuredPath) {
  const anchored = configuredPath.startsWith("|");
  const separatorTerminated = configuredPath.endsWith("^");
  const rawPattern = configuredPath
    .slice(anchored ? 1 : 0, separatorTerminated ? -1 : undefined);
  const escaped = rawPattern
    .replace(/[|\\{}()[\]^$+?.]/g, "\\$&")
    .replaceAll("*", "[^/?&=]+");
  const start = anchored ? "^" : "";
  const terminalWildcard = rawPattern.endsWith("*");
  const wildcardIsQueryToken = rawPattern.lastIndexOf("?") > rawPattern.lastIndexOf("/");
  const end = !separatorTerminated
    ? ""
    : terminalWildcard
      ? wildcardIsQueryToken ? "(?:&|$)" : "(?:\\?|$)"
      : "(?:$|[^a-zA-Z0-9_.%-])";
  return new RegExp(`${start}${escaped}${end}`).test(pathAndQuery);
}

function approvedPathsForLayout(layout, excludedVariantId = null) {
  return [...new Set([
    ...pathsForLayout(layout),
    ...(Array.isArray(layout.variants)
      ? layout.variants
          .filter((variant) => variant.id !== excludedVariantId)
          .flatMap((variant) => pathsForLayout(variant))
      : []),
  ])].sort();
}

function matchingApprovedPaths(urlText, layout, excludedVariantId = null) {
  try {
    const parsed = new URL(urlText);
    const pathAndQuery = parsed.pathname + parsed.search;
    if (
      parsed.protocol !== "https:" ||
      !hostnameMatches(parsed.hostname, layout.domain)
    ) {
      return [];
    }
    return approvedPathsForLayout(layout, excludedVariantId).filter(
      (configuredPath) => wildcardPathMatches(pathAndQuery, configuredPath),
    );
  } catch {
    return [];
  }
}

function urlMatchesLayout(urlText, layout) {
  return matchingApprovedPaths(urlText, layout).length > 0;
}

function runtimeExpectationForTarget(target) {
  const derived = target?.source === "sample" && !target.algumon
    ? target.readerRouteRegistered === true ? "registered-positive" : "direct-negative"
    : target?.source === "algumon-latest" && target.algumon
      ? "relay-positive"
      : null;
  if (
    derived &&
    (target.runtimeExpectation === undefined || target.runtimeExpectation === derived)
  ) {
    return derived;
  }
  throw new Error("audit target has no explicit direct-negative, registered-positive or relay-positive expectation");
}

function candidateGenerationAllowed(
  runtimeExpectation,
  sourceClassification,
  networkFidelityFailureCount = 0,
) {
  return Boolean(
    ["registered-positive", "relay-positive"].includes(runtimeExpectation) &&
      sourceClassification?.kind === "article-response" &&
      sourceClassification?.candidateEligible === true &&
      networkFidelityFailureCount === 0,
  );
}

function isPromotionArticleResult(result) {
  return (result?.source === "sample" && result.runtimeExpectation === "registered-positive") ||
    result?.source === "algumon-latest";
}

function classifyProfileLandingRoute(
  site,
  profileName,
  finalUrl,
  promotionCandidate = null,
) {
  const applicableLayouts = site.layouts.filter((layout) =>
    profilesForLayout(site, layout).includes(profileName),
  );
  const configuredMatches = applicableLayouts.flatMap((layout) =>
    matchingApprovedPaths(finalUrl, layout).map((configuredPath) => ({
      layout,
      configuredPath,
    })),
  );
  const baselineMatches = applicableLayouts.flatMap((layout) => {
    const excludedVariantId =
      promotionCandidate?.siteId === site.id &&
      promotionCandidate?.layoutId === layout.id
        ? promotionCandidate.variantId
        : null;
    return matchingApprovedPaths(finalUrl, layout, excludedVariantId).map(
      (configuredPath) => ({ layout, configuredPath }),
    );
  });
  const sameDomainLayouts = applicableLayouts.filter((layout) => {
    try {
      return hostnameMatches(new URL(finalUrl).hostname, layout.domain);
    } catch {
      return false;
    }
  });
  const configuredLayoutIds = new Set(
    configuredMatches.map(({ layout }) => layout.id),
  );
  const associatedLayout = configuredLayoutIds.size === 1
    ? configuredMatches[0].layout
    : configuredMatches.length === 0 && sameDomainLayouts.length === 1
      ? sameDomainLayouts[0]
      : null;
  const classification = configuredMatches.length === 1
    ? "configured-exact"
    : configuredMatches.length > 1
      ? "configured-ambiguous"
      : associatedLayout
        ? "same-domain-candidate"
        : "outside-or-ambiguous-domain";
  return {
    layoutId: associatedLayout?.id ?? null,
    classification,
    configuredPathMatchCount: configuredMatches.length,
    configuredPathMatches: configuredMatches.map(({ layout, configuredPath }) => ({
      layoutId: layout.id,
      configuredPath,
    })),
    baselineApprovedPathMatchCount: baselineMatches.length,
    baselineApprovedPathMatches: baselineMatches.map(({ layout, configuredPath }) => ({
      layoutId: layout.id,
      configuredPath,
    })),
    approvedRouteMatched: baselineMatches.length === 1,
    matchedApprovedPath:
      baselineMatches.length === 1 ? baselineMatches[0].configuredPath : null,
  };
}

function profilesForLayout(site, layout) {
  if (
    Array.isArray(layout.applicable_profiles) &&
    layout.applicable_profiles.length > 0
  ) {
    return layout.applicable_profiles.filter((profile) => profile in DEVICE_PROFILES);
  }
  if (Array.isArray(layout.devices) && layout.devices.length > 0) {
    return layout.devices.filter((device) => device in DEVICE_PROFILES);
  }
  const layoutId = layout.id.toLowerCase();
  const hasMobileSibling = site.layouts.some((candidate) =>
    /mobile|mweb/.test(candidate.id.toLowerCase()),
  );
  if (/mobile|mweb/.test(layoutId)) {
    return ["mobile"];
  }
  if (hasMobileSibling && /pc|desktop|www/.test(layoutId)) {
    return ["desktop"];
  }
  return ["desktop", "mobile"];
}

function resourceDomainsForLayout(site, layout, includeAlgumon = false) {
  return [
    layout.domain,
    ...(Array.isArray(layout.resource_domains) ? layout.resource_domains : []),
    ...(includeAlgumon ? ["algumon.com"] : []),
    ...(includeAlgumon && Array.isArray(site.algumon_resource_domains)
      ? site.algumon_resource_domains
      : []),
  ];
}

function resourceDomainsForSite(site, includeAlgumon = false) {
  return [...new Set(site.layouts.flatMap((layout) =>
    resourceDomainsForLayout(site, layout, includeAlgumon),
  ))];
}

function sha256(content) {
  return createHash("sha256").update(content).digest("hex");
}

async function evaluateInIsolatedWorld(page, evaluator, argument = undefined) {
  const session = await page.context().newCDPSession(page);
  try {
    await session.send("Page.enable");
    const { frameTree } = await session.send("Page.getFrameTree");
    const frameId = frameTree?.frame?.id;
    if (!frameId) throw new Error("isolated oracle could not resolve the main frame");
    const { executionContextId } = await session.send("Page.createIsolatedWorld", {
      frameId,
      worldName: ORACLE_EXECUTION_WORLD,
      grantUniveralAccess: false,
    });
    const response = await session.send("Runtime.callFunctionOn", {
      functionDeclaration: `function(value) { return (${evaluator.toString()})(value); }`,
      executionContextId,
      arguments: [{ value: argument }],
      returnByValue: true,
      awaitPromise: true,
      silent: false,
    });
    if (response.exceptionDetails) {
      const detail = response.exceptionDetails.exception?.description ||
        response.exceptionDetails.text ||
        "unknown isolated oracle exception";
      throw new Error(detail);
    }
    if (!response.result || response.result.type === "undefined") {
      throw new Error("isolated oracle returned no verdict");
    }
    return response.result.value;
  } finally {
    await session.detach().catch(() => {});
  }
}

async function captureBoundedScreenshot(page, outputPath) {
  if (screenshotCount >= SCREENSHOT_MAX_COUNT) {
    throw new Error(`screenshot count exceeds ${SCREENSHOT_MAX_COUNT}`);
  }
  screenshotCount += 1;
  const bytes = await page.screenshot({
    path: outputPath,
    fullPage: false,
    animations: "disabled",
    caret: "hide",
    timeout: 10_000,
  });
  if (bytes.byteLength > SCREENSHOT_MAX_BYTES) {
    await fs.unlink(outputPath).catch(() => {});
    throw new Error(
      `bounded screenshot exceeds ${SCREENSHOT_MAX_BYTES} bytes`,
    );
  }
  return Object.freeze({
    byteLength: bytes.byteLength,
    viewportBounded: true,
  });
}

function canonicalText(content) {
  return content
    .replace(/^\uFEFF+/u, "")
    .replace(/\r\n/gu, "\n")
    .replace(/\r/gu, "\n")
    .replace(/\n+$/u, "");
}

function canonicalTextSha256(content) {
  return sha256(Buffer.from(canonicalText(content), "utf8"));
}

function canonicalJson(value, propertyName = null) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key], key)}`)
      .join(",")}}`;
  }
  if (
    typeof value === "number" &&
    Number.isInteger(value) &&
    ["titleConsistency", "countConsistency", "selectorStability"].includes(
      propertyName,
    )
  ) {
    return `${value}.0`;
  }
  return JSON.stringify(value);
}

async function readArtifact(relativePath, baseDirectory = PROJECT_ROOT) {
  const absolutePath = path.join(baseDirectory, relativePath);
  try {
    const content = await fs.readFile(absolutePath);
    return {
      path: relativePath.replaceAll(path.sep, "/"),
      absolutePath,
      bytes: content.length,
      sha256: sha256(content),
      content: content.toString("utf8"),
    };
  } catch (error) {
    if (error?.code === "ENOENT") {
      return {
        path: relativePath.replaceAll(path.sep, "/"),
        absolutePath,
        missing: true,
      };
    }
    throw error;
  }
}

async function buildIntegrityManifest(
  config,
  evidencePath,
  {
    bundleRoot = PROJECT_ROOT,
    draftManifest = null,
  } = {},
) {
  const artifactPaths = [
    "filter-static.txt",
    "hotdeal-focus.user.js",
    "package.json",
    "package-lock.json",
    "state/approved-variants.json",
    "state/release-high-water.json",
    "config/sites.json",
    "tests/fixtures/dom-regressions.json",
    "tests/fixtures/behavior-baseline.json",
    "release-manifest.json",
  ];
  const artifacts = await Promise.all(artifactPaths.map((artifactPath) =>
    artifactPath.startsWith("tests/fixtures/")
      ? readArtifact(artifactPath)
      : readArtifact(artifactPath, bundleRoot)));
  const byPath = new Map(artifacts.map((artifact) => [artifact.path, artifact]));
  const staticFilter = byPath.get("filter-static.txt");
  const userscript = byPath.get("hotdeal-focus.user.js");
  const configArtifact = byPath.get("config/sites.json");
  const approvedStateArtifact = byPath.get("state/approved-variants.json");
  const highWaterArtifact = byPath.get("state/release-high-water.json");
  const releaseManifestArtifact = byPath.get("release-manifest.json");
  const behaviorBaselineArtifact = byPath.get("tests/fixtures/behavior-baseline.json");
  const exactObjectKeys = (value, expectedKeys) =>
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    canonicalJson(Object.keys(value).sort()) === canonicalJson([...expectedKeys].sort());
  const artifactEntryFor = (artifact) => artifact?.missing
    ? null
    : { sha256: artifact.sha256, bytes: artifact.bytes };

  let releaseManifest = null;
  if (!releaseManifestArtifact?.missing) {
    try {
      releaseManifest = JSON.parse(releaseManifestArtifact.content);
    } catch {
      releaseManifest = null;
    }
  }
  let approvedState = null;
  if (!approvedStateArtifact?.missing) {
    try {
      approvedState = JSON.parse(approvedStateArtifact.content);
    } catch {
      approvedState = null;
    }
  }
  let releaseHighWater = null;
  if (!highWaterArtifact?.missing) {
    try {
      releaseHighWater = JSON.parse(highWaterArtifact.content);
    } catch {
      releaseHighWater = null;
    }
  }

  const isDraftBundle = draftManifest !== null;
  const expectedDraftArtifactPaths = [
    "config/sites.json",
    "filter-static.txt",
    "hotdeal-focus.user.js",
    "package-lock.json",
    "package.json",
  ];
  const draftArtifactEntries = Object.fromEntries(
    expectedDraftArtifactPaths.map((artifactPath) => [
      artifactPath,
      artifactEntryFor(byPath.get(artifactPath)),
    ]),
  );
  const draftArtifactSetSha256 = sha256(
    Buffer.from(canonicalJson(draftArtifactEntries), "utf8"),
  );
  const draftManifestContract =
    isDraftBundle &&
    exactObjectKeys(draftManifest, [
      "schemaVersion",
      "status",
      "releaseVersion",
      "protocolVersion",
      "baseConfigSha256",
      "candidateSha256",
      "discoveryEvidenceSha256",
      "proofProfiles",
      "artifactSetSha256",
      "artifacts",
    ]) &&
    draftManifest.schemaVersion === 1 &&
    draftManifest.status === "draft-non-promotable" &&
    draftManifest.protocolVersion === READER_GATE_PROTOCOL_VERSION &&
    typeof draftManifest.releaseVersion === "string" &&
    canonicalJson(Object.keys(draftManifest.artifacts ?? {}).sort()) ===
      canonicalJson(expectedDraftArtifactPaths) &&
    canonicalJson(draftManifest.artifacts) === canonicalJson(draftArtifactEntries) &&
    draftManifest.artifactSetSha256 === draftArtifactSetSha256;

  const actualSiteIds = config.sites.map((site) => site.id).sort();
  const actualLayoutCount = config.sites.reduce(
    (count, site) => count + site.layouts.length,
    0,
  );
  const actualVariantCount = config.sites.reduce(
    (siteCount, site) => siteCount + site.layouts.reduce(
      (layoutCount, layout) => layoutCount + (layout.variants ?? []).length,
      0,
    ),
    0,
  );
  const actualContractCount = actualLayoutCount + actualVariantCount;
  const missingSiteIds = REQUIRED_SITE_IDS.filter(
    (siteId) => !actualSiteIds.includes(siteId),
  );
  const unexpectedSiteIds = actualSiteIds.filter(
    (siteId) => !REQUIRED_SITE_IDS.includes(siteId),
  );
  const staticRules = staticFilter?.missing
    ? []
    : parseAdguardCosmeticRules(staticFilter.content);
  const layouts = config.sites.flatMap((site) =>
    site.layouts.flatMap((layout) => [
      layout,
      ...(layout.variants ?? []).map((variant) => ({
        ...variant,
        domain: layout.domain,
        id: `${layout.id}--${variant.id}`,
      })),
    ].flatMap((contract) => pathsForLayout(contract).map((configuredPath) => ({
      siteId: site.id,
      layoutId: contract.id,
      domain: contract.domain,
      path: configuredPath,
      desktop: profilesForLayout(site, contract).includes("desktop"),
      mobile: profilesForLayout(site, contract).includes("mobile"),
      staticCovered: staticRules.some(
        (rule) =>
          rule.domains.includes(contract.domain) &&
          rule.path === configuredPath &&
          rule.operator === "#?#",
      ),
    })))),
  );

  const userscriptVersion = userscript?.content?.match(
    /^\/\/\s*@version\s+([^\s]+)\s*$/mu,
  )?.[1];
  const userscriptContractCovered =
    !userscript?.missing &&
    /^\/\/\s*@grant\s+GM_addElement\s*$/mu.test(userscript.content) &&
    /^\/\/\s*@grant\s+window\.onurlchange\s*$/mu.test(userscript.content) &&
    !/^\/\/\s*@grant\s+GM_(?:getValue|setValue|deleteValue)\s*$/mu.test(
      userscript.content,
    ) &&
    !/^\/\/\s*@match\s+https:\/\/www\.algumon\.com\/\*\s*$/mu.test(
      userscript.content,
    ) &&
    (userscript.content.match(/^\/\/\s*@grant\s+/gmu) ?? []).length === 2 &&
    (userscript.content.match(/^\/\/\s*@match\s+/gmu) ?? []).length === 7 &&
    userscript.content.includes('const PROTOCOL_VERSION = "2"') &&
    userscript.content.includes('GM_addElement(parent, "style", {') &&
    userscript.content.includes("function proveStandaloneCascadeRelease") &&
    userscript.content.includes("runtime.verifyUnlockedCascadeRelease()") &&
    userscript.content.includes('subscribe("urlchange", revalidateSafely)') &&
    userscript.content.includes('subscribe("hashchange", revalidateSafely)') &&
    userscript.content.includes('"data-hotdeal-focus-runtime-style": "2"') &&
    !/proveExtendedCssRelease|extended-css-release-proof|engineStylePresence/u.test(
      userscript.content,
    );

  let behaviorBaseline = null;
  try {
    behaviorBaseline = JSON.parse(behaviorBaselineArtifact?.content ?? "null");
  } catch {
    behaviorBaseline = null;
  }
  const approvedVariants =
    approvedState?.schemaVersion === 1 && Array.isArray(approvedState.variants)
      ? approvedState.variants
      : [];
  const expectedReleaseCoverage = {
    siteCount: config.sites.length,
    layoutCount: actualLayoutCount,
    layoutFamilyCount: actualLayoutCount,
    contractCount: actualContractCount,
    routeCount: layouts.length,
    sites: [...config.sites]
      .sort((left, right) => left.id.localeCompare(right.id))
      .map((site) => ({
        id: site.id,
        layouts: [...site.layouts]
          .sort((left, right) => left.id.localeCompare(right.id))
          .map((layout) => ({
            id: layout.id,
            domain: layout.domain,
            paths: [...pathsForLayout(layout)].sort(),
            applicableProfiles: [...profilesForLayout(site, layout)].sort(),
            requiredRoles: [...layout.required_roles].sort(),
            variants: [...(layout.variants ?? [])]
              .sort((left, right) => left.id.localeCompare(right.id))
              .map((variant) => ({
                id: variant.id,
                paths: [...pathsForLayout(variant)].sort(),
                applicableProfiles: [...profilesForLayout(site, variant)].sort(),
                proofProfiles: [...(variant.proof_profiles ?? [])].sort(),
                requiredRoles: [...variant.required_roles].sort(),
              })),
          })),
      })),
    approvedVariantCount: approvedVariants.length,
  };
  const latestApprovedVariant = approvedVariants.reduce(
    (latest, variant) =>
      !latest || compareSemanticVersions(variant.releaseVersion, latest.releaseVersion) > 0
        ? variant
        : latest,
    null,
  );
  const expectedPromotion = latestApprovedVariant
    ? {
        candidateSha256: latestApprovedVariant.candidateSha256,
        evidenceSha256: latestApprovedVariant.evidenceSha256,
        draftArtifactSetSha256: latestApprovedVariant.draftArtifactSetSha256,
      }
    : null;
  const requiredSourcePaths = [
    "filter-static.txt",
    "config/sites.json",
    "package.json",
    "package-lock.json",
    "tests/fixtures/dom-regressions.json",
    "tests/fixtures/behavior-baseline.json",
    "state/release-high-water.json",
    ...(approvedStateArtifact?.missing ? [] : ["state/approved-variants.json"]),
  ].sort();
  const sourceIntegrityContract = !isDraftBundle &&
    exactObjectKeys(releaseManifest?.sourceIntegrity, requiredSourcePaths) &&
    requiredSourcePaths.every((artifactPath) => {
      const artifact = byPath.get(artifactPath);
      const entry = releaseManifest.sourceIntegrity[artifactPath];
      if (artifactPath === "state/release-high-water.json") {
        if (
          artifact?.missing ||
          !exactObjectKeys(entry, ["sha256", "bytes", "mode", "recordCount"]) ||
          entry.mode !== "append-only-prefix-v1" ||
          !Number.isSafeInteger(entry.recordCount) ||
          entry.recordCount < 0 ||
          !releaseHighWater ||
          !exactObjectKeys(releaseHighWater, ["bundleFormat", "records", "schemaVersion"]) ||
          releaseHighWater.bundleFormat !== "hdf-public-bundle-v1" ||
          releaseHighWater.schemaVersion !== 1 ||
          !Array.isArray(releaseHighWater.records) ||
          entry.recordCount !== releaseHighWater.records.length - 1
        ) return false;
        const prefixBytes = Buffer.from(canonicalJson({
          bundleFormat: releaseHighWater.bundleFormat,
          records: releaseHighWater.records.slice(0, entry.recordCount),
          schemaVersion: releaseHighWater.schemaVersion,
        }), "utf8");
        return entry.bytes === prefixBytes.length && entry.sha256 === sha256(prefixBytes);
      }
      return !artifact?.missing &&
        exactObjectKeys(entry, ["sha256", "bytes"]) &&
        entry.sha256 === artifact.sha256 &&
        entry.bytes === artifact.bytes;
    });
  const publicArtifact = releaseManifest?.artifacts?.["hotdeal-focus.user.js"];
  const highWaterCurrent = releaseHighWater?.records?.at?.(-1);
  const highWaterCurrentContract = !isDraftBundle &&
    exactObjectKeys(highWaterCurrent, [
      "bundleSha256", "manifest", "releaseVersion", "userscript",
    ]) &&
    exactObjectKeys(highWaterCurrent?.manifest, ["bytes", "sha256"]) &&
    exactObjectKeys(highWaterCurrent?.userscript, [
      "bytes", "canonicalTextSha256", "sha256",
    ]) &&
    highWaterCurrent.releaseVersion === releaseManifest?.releaseVersion &&
    highWaterCurrent.manifest.bytes === releaseManifestArtifact?.bytes &&
    highWaterCurrent.manifest.sha256 === releaseManifestArtifact?.sha256 &&
    highWaterCurrent.userscript.bytes === userscript?.bytes &&
    highWaterCurrent.userscript.sha256 === userscript?.sha256 &&
    highWaterCurrent.userscript.canonicalTextSha256 === canonicalTextSha256(
      userscript?.content ?? "",
    ) &&
    highWaterCurrent.bundleSha256 === publicBundleSha256(
      Buffer.from(releaseManifestArtifact?.content ?? "", "utf8"),
      Buffer.from(userscript?.content ?? "", "utf8"),
    );
  const releaseManifestContract = !isDraftBundle &&
    exactObjectKeys(releaseManifest, [
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
    ]) &&
    releaseManifest.schemaVersion === 2 &&
    releaseManifest.status === "release-ready" &&
    releaseManifest.protocolVersion === READER_GATE_PROTOCOL_VERSION &&
    releaseManifest.installUrl === READER_GATE_INSTALL_URL &&
    releaseManifest.releaseVersion === userscriptVersion &&
    releaseManifest.generatorVersion === releaseManifest.releaseVersion &&
    releaseManifest.rollback_of === config.metadata.rollback_of &&
    releaseManifest.configSha256 === configArtifact?.sha256 &&
    canonicalJson(releaseManifest.coverage) === canonicalJson(expectedReleaseCoverage) &&
    canonicalJson(releaseManifest.promotion) === canonicalJson(expectedPromotion) &&
    exactObjectKeys(releaseManifest.artifacts, ["hotdeal-focus.user.js"]) &&
    exactObjectKeys(publicArtifact, [
      "sha256",
      "bytes",
      "version",
      "canonicalTextSha256",
    ]) &&
    publicArtifact.sha256 === userscript?.sha256 &&
    publicArtifact.bytes === userscript?.bytes &&
    publicArtifact.version === userscriptVersion &&
    publicArtifact.canonicalTextSha256 === canonicalTextSha256(userscript.content) &&
    highWaterCurrentContract &&
    sourceIntegrityContract;

  const checks = {
    requiredSevenSites:
      missingSiteIds.length === 0 &&
      unexpectedSiteIds.length === 0 &&
      actualSiteIds.length === REQUIRED_SITE_IDS.length,
    everySiteHasLayout: config.sites.every((site) => site.layouts.length > 0),
    everyLayoutHasDesktopOrMobile: layouts.every(
      (layout) => layout.desktop || layout.mobile,
    ),
    everyLayoutInStaticFilter: layouts.every((layout) => layout.staticCovered),
    userscriptContract: userscriptContractCovered,
    draftManifestContract: !isDraftBundle || draftManifestContract,
    releaseManifestContract: isDraftBundle || releaseManifestContract,
    publicArtifactSetUserscriptOnly:
      isDraftBundle || exactObjectKeys(releaseManifest?.artifacts, ["hotdeal-focus.user.js"]),
    userscriptCanonicalTextHashMatchesRelease:
      isDraftBundle || publicArtifact?.canonicalTextSha256 ===
        canonicalTextSha256(userscript?.content ?? ""),
    sourceHashesMatchRelease: isDraftBundle ? draftManifestContract : sourceIntegrityContract,
    configHashMatchesRelease:
      isDraftBundle
        ? draftManifest?.artifacts?.["config/sites.json"]?.sha256 === configArtifact?.sha256
        : releaseManifest?.configSha256 === configArtifact?.sha256,
    releaseCoverageMatchesConfig:
      isDraftBundle || canonicalJson(releaseManifest?.coverage) ===
        canonicalJson(expectedReleaseCoverage),
    protocolMajorStable:
      (isDraftBundle ? draftManifest?.protocolVersion : releaseManifest?.protocolVersion) ===
        READER_GATE_PROTOCOL_VERSION &&
      behaviorBaseline?.protocol_major === READER_GATE_PROTOCOL_VERSION,
    userscriptVersionMatchesRelease:
      typeof userscriptVersion === "string" &&
      userscriptVersion === (isDraftBundle
        ? draftManifest?.releaseVersion
        : releaseManifest?.releaseVersion),
    installUrlContract: isDraftBundle || releaseManifest?.installUrl === READER_GATE_INSTALL_URL,
  };
  const manifest = {
    schemaVersion: 2,
    generatedAt: new Date().toISOString(),
    config: {
      path: path.relative(PROJECT_ROOT, DEFAULT_CONFIG_PATH).replaceAll(path.sep, "/"),
      sha256: configArtifact?.sha256 ?? sha256(JSON.stringify(config)),
      siteCount: config.sites.length,
      layoutCount: actualLayoutCount,
      layoutFamilyCount: actualLayoutCount,
      contractCount: actualContractCount,
      routeCount: layouts.length,
      requiredSiteIds: REQUIRED_SITE_IDS,
      actualSiteIds,
      missingSiteIds,
      unexpectedSiteIds,
    },
    artifacts: artifacts.map(
      ({ content: _content, absolutePath: _absolutePath, ...item }) => item,
    ),
    releaseManifest: releaseManifest
      ? {
          sha256: releaseManifestArtifact.sha256,
          schemaVersion: releaseManifest.schemaVersion,
          protocolVersion: releaseManifest.protocolVersion,
          generatorVersion: releaseManifest.generatorVersion,
          installUrl: releaseManifest.installUrl,
        }
      : null,
    coverage: layouts,
    checks,
    passed: Object.values(checks).every(Boolean),
  };

  await fs.mkdir(evidencePath, { recursive: true });
  await fs.writeFile(
    path.join(evidencePath, "integrity-manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
    "utf8",
  );
  return manifest;
}

async function importPlaywright() {
  try {
    return await import("playwright");
  } catch (error) {
    throw new Error(
      "Playwright is required for live DOM audits. Install the approved devDependency before running audit:dom.",
      { cause: error },
    );
  }
}

function resolveRuntimeDeviceProfiles(devices) {
  const profiles = {};
  for (const [profileName, contract] of Object.entries(DEVICE_PROFILES)) {
    const descriptor = devices?.[contract.descriptorName];
    const chromeVersion = String(descriptor?.userAgent ?? "").match(
      /\bChrome\/(\d+\.\d+\.\d+\.\d+)\b/u,
    )?.[1];
    if (
      !descriptor ||
      descriptor.defaultBrowserType !== "chromium" ||
      descriptor.isMobile !== contract.expectedMobile ||
      !chromeVersion ||
      !descriptor.viewport ||
      !descriptor.screen ||
      !Number.isFinite(descriptor.deviceScaleFactor)
    ) {
      throw new Error(
        `Playwright device descriptor is incomplete or incompatible: ${contract.descriptorName}`,
      );
    }
    profiles[profileName] = Object.freeze({
      descriptorName: contract.descriptorName,
      userAgent: descriptor.userAgent,
      viewport: Object.freeze({ ...descriptor.viewport }),
      screen: Object.freeze({ ...descriptor.screen }),
      deviceScaleFactor: descriptor.deviceScaleFactor,
      isMobile: descriptor.isMobile,
      hasTouch: descriptor.hasTouch,
      chromeVersion,
    });
  }
  return Object.freeze(profiles);
}

function assertBrowserMatchesDeviceProfiles(browserVersion, profiles) {
  if (!/^\d+\.\d+\.\d+\.\d+$/u.test(browserVersion)) {
    throw new Error(`Chromium reported an invalid browser version: ${browserVersion}`);
  }
  for (const [profileName, profile] of Object.entries(profiles)) {
    if (profile.chromeVersion !== browserVersion) {
      throw new Error(
        `${profileName} UA ${profile.chromeVersion} does not match Chromium ${browserVersion}`,
      );
    }
  }
}

function contextOptions(profileName) {
  const profile = RUNTIME_DEVICE_PROFILES?.[profileName];
  if (!profile) {
    throw new Error(`runtime device profile is not initialized: ${profileName}`);
  }
  return {
    viewport: profile.viewport,
    screen: profile.screen,
    userAgent: profile.userAgent,
    deviceScaleFactor: profile.deviceScaleFactor,
    isMobile: profile.isMobile,
    hasTouch: profile.hasTouch,
    locale: "ko-KR",
    timezoneId: "Asia/Seoul",
    colorScheme: "light",
    reducedMotion: "reduce",
  };
}

async function settlePage(page, timeoutMs) {
  await page.waitForLoadState("domcontentloaded", { timeout: timeoutMs });
  await page.waitForLoadState("networkidle", { timeout: Math.min(timeoutMs, 8_000) }).catch(() => {});
  const scrollSettlement = await page.evaluate(async ({ maxSteps, deadlineMs }) => {
    const delay = (milliseconds) =>
      new Promise((resolve) => window.setTimeout(resolve, milliseconds));
    const startedAt = performance.now();
    let position = 0;
    let stepCount = 0;
    while (
      position < document.documentElement.scrollHeight &&
      stepCount < maxSteps &&
      performance.now() - startedAt < deadlineMs
    ) {
      const step = Math.max(
        600,
        Math.floor(window.innerHeight * 0.8),
        Math.ceil(document.documentElement.scrollHeight / maxSteps),
      );
      window.scrollTo(0, position);
      await delay(40);
      position += step;
      stepCount += 1;
    }
    const completed = position >= document.documentElement.scrollHeight;
    window.scrollTo(0, 0);
    return {
      completed,
      stepCount,
      finalScrollHeight: document.documentElement.scrollHeight,
    };
  }, {
    maxSteps: 128,
    deadlineMs: Math.min(timeoutMs, 7_000),
  });
  if (scrollSettlement.completed !== true) {
    throw new Error(
      "source-or-infrastructure-failure: bounded scroll settlement exceeded its step or time budget",
    );
  }
  await page.waitForTimeout(250);
  await page.addStyleTag({
    content:
      "*,*::before,*::after{animation-duration:0s!important;transition-duration:0s!important;scroll-behavior:auto!important}",
  });
}

function comparableDocumentUrl(urlText) {
  try {
    const parsed = new URL(urlText);
    parsed.hash = "";
    return parsed.href;
  } catch {
    return null;
  }
}

function mainDocumentResponseUrlMatches(responseUrl, finalUrl) {
  const comparableResponse = comparableDocumentUrl(responseUrl);
  const comparableFinal = comparableDocumentUrl(finalUrl);
  if (!comparableResponse || !comparableFinal) return false;
  if (comparableResponse === comparableFinal) return true;
  const response = new URL(comparableResponse);
  const final = new URL(comparableFinal);
  // The observed mobile redirect returns this marker, then the same article
  // removes it without another document response. Do not normalize other
  // queries or accept the broader desktop/mobile article-identity aliases.
  if (
    response.origin !== "https://m.ruliweb.com" || final.origin !== response.origin ||
    !/^\/(?:market|news)\/board\/1020\/read\/\d{1,24}\/?$/u.test(response.pathname) ||
    final.pathname !== response.pathname ||
    !siteArticleIdentity(response.href, "ruliweb") ||
    siteArticleIdentity(response.href, "ruliweb") !== siteArticleIdentity(final.href, "ruliweb") ||
    response.searchParams.getAll("_rd").length !== 1 || final.searchParams.has("_rd")
  ) return false;
  const queryParts = response.search.slice(1).split("&");
  if (queryParts.filter((part) => part === "_rd=1").length !== 1) return false;
  response.search = queryParts.filter((part) => part !== "_rd=1").join("&");
  return response.href === final.href;
}

function selectFinalMainDocumentResponse(responseChain, finalUrl) {
  const matchingResponses = (responseChain ?? []).filter(
    (response) => mainDocumentResponseUrlMatches(response.url, finalUrl),
  );
  return matchingResponses.at(-1) ?? null;
}

function observeMainDocumentResponses(page) {
  const responseChain = [];
  const onResponse = (response) => {
    const request = response.request();
    let isMainDocument = false;
    try {
      isMainDocument =
        request.isNavigationRequest() &&
        request.resourceType() === "document" &&
        request.frame() === page.mainFrame();
    } catch {}
    if (!isMainDocument) return;
    responseChain.push({
      sequence: responseChain.length,
      url: response.url(),
      status: response.status(),
      contentType: response.headers()["content-type"] ?? "",
    });
  };
  page.on("response", onResponse);
  return {
    responseChain,
    stop() {
      page.off("response", onResponse);
    },
  };
}

function navigationEvidenceFromObserver(observer, finalUrl, fallbackResponse = null) {
  const responseChain = observer.responseChain.map((response) => ({ ...response }));
  const selected =
    selectFinalMainDocumentResponse(responseChain, finalUrl) ??
    (fallbackResponse
      ? {
          sequence: responseChain.length,
          url: fallbackResponse.url(),
          status: fallbackResponse.status(),
          contentType: fallbackResponse.headers()["content-type"] ?? "",
        }
      : null);
  return {
    finalUrl,
    status: selected?.status ?? null,
    contentType: selected?.contentType ?? "",
    mainDocumentResponse: selected,
    mainDocumentResponseChain: responseChain,
  };
}

async function navigate(page, targetUrl, timeoutMs, externalResponseObserver = null) {
  let response = null;
  const responseObserver = externalResponseObserver ?? observeMainDocumentResponses(page);
  const navigationProof = seededNavigationProof(targetUrl);
  try {
    try {
      response = await page.goto(targetUrl, {
        waitUntil: "domcontentloaded",
        timeout: timeoutMs,
        ...(navigationProof ? { referer: ALGUMON_GLOBAL_DISCOVERY_URL } : {}),
      });
    } catch (error) {
      if (page.url() === "about:blank") {
        throw error;
      }
    }
    await settlePage(page, timeoutMs);
    return navigationEvidenceFromObserver(responseObserver, page.url(), response);
  } finally {
    if (!externalResponseObserver) responseObserver.stop();
  }
}

function siteArticleIdentity(urlText, siteId) {
  let parsed;
  try {
    parsed = new URL(urlText);
  } catch {
    return null;
  }
  const domain = ARTICLE_IDENTITY_DOMAINS[siteId];
  if (
    !domain ||
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.port ||
    parsed.hash ||
    !hostnameMatches(parsed.hostname, domain)
  ) {
    return null;
  }
  const numeric = (value) => /^\d{1,24}$/u.test(String(value ?? ""))
    ? String(value)
    : null;
  const token = (value) => /^[a-z0-9_-]{1,48}$/iu.test(String(value ?? ""))
    ? String(value).toLocaleLowerCase()
    : null;
  const uniqueQueryValue = (name) => {
    const values = parsed.searchParams.getAll(name);
    return values.length === 1 ? values[0] : null;
  };
  let route = null;
  let board = null;
  let articleId = null;
  let match = null;
  if (siteId === "clien") {
    match = parsed.pathname.match(/^\/service\/board\/([a-z0-9_-]+)\/(\d{1,24})\/?$/iu);
    route = match ? "service-board" : null;
    board = token(match?.[1]);
    articleId = numeric(match?.[2]);
  } else if (siteId === "ppomppu") {
    const idValues = parsed.searchParams.getAll("id");
    const numberValues = parsed.searchParams.getAll("no");
    if (idValues.length !== 1 || numberValues.length !== 1) return null;
    route = ["/zboard/view.php", "/new/bbs_view.php"].includes(parsed.pathname)
      ? "board-view"
      : null;
    board = token(uniqueQueryValue("id"));
    articleId = numeric(uniqueQueryValue("no"));
  } else if (siteId === "ruliweb") {
    match = parsed.pathname.match(
      /^\/(market|news)\/board\/(\d{1,24})\/read\/(\d{1,24})\/?$/u,
    );
    route = match ? `${match[1]}-board-read` : null;
    board = numeric(match?.[2]);
    articleId = numeric(match?.[3]);
  } else if (siteId === "quasarzone") {
    match = parsed.pathname.match(/^\/bbs\/([a-z0-9_-]+)\/views\/(\d{1,24})\/?$/iu);
    route = match ? "bbs-views" : null;
    board = token(match?.[1]);
    articleId = numeric(match?.[2]);
  } else if (siteId === "eomisae") {
    match = parsed.pathname.match(/^\/(rt|os|fs)\/(\d{1,24})\/?$/u);
    const documentValues = parsed.searchParams.getAll("document_srl");
    const midValues = parsed.searchParams.getAll("mid");
    if (documentValues.length > 1 || midValues.length > 1) return null;
    if (match) {
      const pathArticleId = numeric(match[2]);
      const queryDocumentId = documentValues.length === 1
        ? numeric(documentValues[0])
        : null;
      if (
        (documentValues.length === 1 && queryDocumentId !== pathArticleId) ||
        (midValues.length === 1 && !["rt", "os", "fs"].includes(token(midValues[0])))
      ) {
        return null;
      }
      route = "document";
      board = "document";
      articleId = pathArticleId;
    } else if (parsed.pathname === "/index.php") {
      if (
        documentValues.length !== 1 ||
        (midValues.length === 1 && !["rt", "os", "fs"].includes(token(midValues[0])))
      ) {
        return null;
      }
      route = "document";
      board = "document";
      articleId = numeric(uniqueQueryValue("document_srl"));
    }
  } else if (siteId === "zod") {
    match = parsed.pathname.match(/^\/deal\/(\d{1,24})\/?$/u);
    route = match ? "deal" : null;
    board = "deal";
    articleId = numeric(match?.[1]);
  } else if (siteId === "arcalive") {
    match = parsed.pathname.match(/^\/b\/([a-z0-9_-]+)\/(\d{1,24})\/?$/iu);
    route = match ? "board-article" : null;
    board = token(match?.[1]);
    articleId = numeric(match?.[2]);
  }
  return route && board && articleId
    ? `${siteId}:${domain}:${route}:${board}:${articleId}`
    : null;
}

function canonicalArticleIdentity(urlText, siteId = null) {
  let parsed;
  try {
    parsed = new URL(urlText);
  } catch {
    throw new Error("article identity requires a valid URL");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.port ||
    parsed.hash
  ) {
    throw new Error("article identity requires an uncredentialed default-port HTTPS URL");
  }
  const semanticIdentity = siteId ? siteArticleIdentity(parsed.href, siteId) : null;
  if (siteId && !semanticIdentity) {
    throw new Error("article identity does not match one canonical site article route");
  }
  parsed.hostname = normalizedHostname(parsed.hostname);
  const sortedQuery = [...parsed.searchParams.entries()].sort(
    ([leftKey, leftValue], [rightKey, rightValue]) =>
      leftKey.localeCompare(rightKey) || leftValue.localeCompare(rightValue),
  );
  parsed.search = "";
  for (const [key, value] of sortedQuery) parsed.searchParams.append(key, value);
  const canonicalUrl = parsed.href;
  return {
    sha256: sha256(canonicalUrl),
    routeFamily: routeFamily(canonicalUrl),
    articleTokenSha256: semanticIdentity ? sha256(semanticIdentity) : null,
  };
}

function articleIdentitiesLogicallyEquivalent(requestedIdentity, resolvedIdentity) {
  return Boolean(
    requestedIdentity?.sha256 === resolvedIdentity?.sha256 ||
      (requestedIdentity?.articleTokenSha256 &&
        requestedIdentity.articleTokenSha256 === resolvedIdentity?.articleTokenSha256),
  );
}

async function destinationDocumentSnapshot(page) {
  return evaluateInIsolatedWorld(page, () => ({
    title: String(document.title ?? "").slice(0, 512),
    bodyText: String(document.body?.textContent ?? "").slice(0, 8_192),
    challengeSelectors: [
      "main.captcha-wrapper",
      "#challenge-running",
      "#challenge-form",
      ".cf-challenge-running",
      "[id^='cf-chl']",
      "iframe[src^='https://challenges.cloudflare.com/']",
    ].filter((selector) => {
      try {
        return document.querySelector(selector) !== null;
      } catch {
        return false;
      }
    }),
  }));
}

function fidelitySelectorsForLayout(layout) {
  return [...new Set([
    layout.page_root,
    layout.pageRoot,
    ...(layout.ancestor_markers ?? []),
    ...(layout.preserve_deep ?? []),
    ...(layout.preserve_shallow ?? []),
    ...Object.values(layout.required_groups ?? {}).flat(),
    ...(layout.comment_contract?.mount ?? []),
    ...(layout.comment_contract?.items ?? []),
    ...(layout.comment_contract?.controls ?? []),
  ].filter((selector) => typeof selector === "string" && selector.length > 0))];
}

function collectRetainedRoleResourceEvidence(roleSelectors) {
    const maximumRoots = 32;
    const maximumNodes = 2_048;
    // Normal comment trees exceed the head/CSS inspection budget. Keep their
    // independent traversal bound without increasing time, URL, or host caps.
    const maximumRetainedNodes = 16_384;
    const maximumUrls = 4_096;
    const maximumHosts = 128;
    const maximumElapsedMs = 2_000;
    const startedAt = performance.now();
    const roots = new Set();
    let selectorErrorCount = 0;
    let rootOverflowCount = 0;
    let elapsedTimeOverflowCount = 0;
    for (const selector of roleSelectors) {
      try {
        // The semantic oracle and runtime gate have already proved exact role
        // cardinality.  Re-query only the first exact root here so an adversarial
        // selector match cannot force querySelectorAll() to materialize an
        // unbounded NodeList before our traversal budgets apply.
        const element = document.querySelector(selector);
        if (element && !roots.has(element) && roots.size >= maximumRoots) {
          rootOverflowCount += 1;
        } else if (element) {
          roots.add(element);
        }
      } catch {
        selectorErrorCount += 1;
      }
      if (performance.now() - startedAt > maximumElapsedMs) {
        elapsedTimeOverflowCount += 1;
        break;
      }
    }
    const nodes = new Set();
    let nodeOverflowCount = 0;
    const queue = [...roots];
    const queued = new Set(queue);
    let queueIndex = 0;
    const enqueue = (element) => {
      if (!(element instanceof Element) || nodes.has(element) || queued.has(element)) return true;
      if (nodes.size + queue.length - queueIndex >= maximumRetainedNodes) {
        nodeOverflowCount += 1;
        return false;
      }
      queued.add(element);
      queue.push(element);
      return true;
    };
    while (queueIndex < queue.length) {
      const element = queue[queueIndex++];
      queued.delete(element);
      if (!(element instanceof Element) || nodes.has(element)) continue;
      if (nodes.size >= maximumRetainedNodes) {
        nodeOverflowCount += 1;
        continue;
      }
      nodes.add(element);
      for (const child of element.children) {
        if (!enqueue(child)) break;
      }
      if (element.shadowRoot) {
        for (const child of element.shadowRoot.children) {
          if (!enqueue(child)) break;
        }
      }
      if (performance.now() - startedAt > maximumElapsedMs) {
        elapsedTimeOverflowCount += 1;
        break;
      }
    }
    const rawUrls = [];
    const appendedUrls = new Set();
    let urlOverflowCount = 0;
    const append = (value) => {
      if (typeof value !== "string" || !value.trim()) return;
      let canonicalUrl;
      try {
        const url = new URL(value.trim(), document.baseURI);
        url.hash = "";
        canonicalUrl = url.href;
      } catch { return; }
      if (appendedUrls.has(canonicalUrl)) return;
      if (rawUrls.length >= maximumUrls) {
        urlOverflowCount += 1;
        return;
      }
      appendedUrls.add(canonicalUrl);
      rawUrls.push(canonicalUrl);
    };
    // Inline <style> imports and font faces use the document as their CDP
    // initiator. The actual document URL, not a <base>-controlled baseURI,
    // roots those dependencies; the caller persists only URL digests.
    append(document.URL);
    const appendSrcset = (value) => {
      if (typeof value !== "string") return;
      let index = 0;
      while (index < value.length) {
        while (index < value.length && /[\s,]/u.test(value[index])) index += 1;
        if (index >= value.length) break;
        const start = index;
        while (index < value.length && !/\s/u.test(value[index])) index += 1;
        let candidate = value.slice(start, index).replace(/,+$/u, "");
        append(candidate);
        let parenthesisDepth = 0;
        while (index < value.length) {
          const character = value[index];
          if (character === "(") parenthesisDepth += 1;
          if (character === ")" && parenthesisDepth > 0) parenthesisDepth -= 1;
          index += 1;
          if (character === "," && parenthesisDepth === 0) break;
        }
      }
    };
    const cssUnescape = (value) => value.replace(
      /\\(?:([0-9a-f]{1,6})(?:\r\n|[\n\r\f\t ])?|([^\n\r\f0-9a-f]))/giu,
      (_match, hexadecimal, escapedCharacter) => {
        if (hexadecimal) {
          const codePoint = Number.parseInt(hexadecimal, 16);
          return codePoint === 0 || codePoint > 0x10ffff
            ? "\uFFFD"
            : String.fromCodePoint(codePoint);
        }
        return escapedCharacter ?? "";
      },
    );
    const appendCssUrls = (cssText) => {
      const text = String(cssText ?? "");
      let index = 0;
      while (index < text.length) {
        const match = /url\s*\(/giu.exec(text.slice(index));
        if (!match) break;
        index += match.index + match[0].length;
        while (index < text.length && /\s/u.test(text[index])) index += 1;
        const quote = text[index] === "\"" || text[index] === "'" ? text[index++] : null;
        let value = "";
        let escaped = false;
        while (index < text.length) {
          const character = text[index++];
          if (escaped) {
            value += `\\${character}`;
            escaped = false;
            continue;
          }
          if (character === "\\") {
            escaped = true;
            continue;
          }
          if ((quote && character === quote) || (!quote && character === ")")) break;
          value += character;
        }
        if (quote) {
          while (index < text.length && /\s/u.test(text[index])) index += 1;
          if (text[index] === ")") index += 1;
        }
        append(cssUnescape(value.trim()));
      }
    };
    const inlineSheets = new Set();
    let stylesheetRuleCount = 0;
    let stylesheetRuleOverflowCount = 0;
    let stylesheetRuleErrorCount = 0;
    const appendInlineFontSources = (element) => {
      const sheet = element.sheet;
      if (!sheet || sheet.href || inlineSheets.has(sheet)) return;
      inlineSheets.add(sheet);
      try {
        const stack = [{ rules: sheet.cssRules, index: 0 }];
        while (stack.length > 0) {
          const frame = stack.at(-1);
          if (frame.index >= frame.rules.length) { stack.pop(); continue; }
          if (stylesheetRuleCount >= maximumNodes) { stylesheetRuleOverflowCount += 1; break; }
          if (performance.now() - startedAt > maximumElapsedMs) { elapsedTimeOverflowCount += 1; break; }
          const rule = frame.rules[frame.index++];
          stylesheetRuleCount += 1;
          if (rule.type === 5) appendCssUrls(rule.style.getPropertyValue("src"));
          // Imported cross-origin sheets are tracked by CDP instead of reading
          // their protected CSSOM. Grouped inline font faces remain inspectable.
          if (rule.type !== 3 && rule.cssRules) stack.push({ rules: rule.cssRules, index: 0 });
        }
      } catch {
        stylesheetRuleErrorCount += 1;
      }
    };
    // Only resolved URL-bearing properties of retained nodes/pseudo-elements
    // count. Enumerating declarations would also promote unused custom-property
    // URLs, while treating every document-initiated image as required would
    // incorrectly include unrelated ads.
    const retainedComputedUrlProperties = [
      "backgroundImage", "listStyleImage", "content", "maskImage", "webkitMaskImage",
      "borderImageSource", "maskBorderSource", "webkitMaskBoxImageSource", "cursor",
      "shapeOutside", "filter", "backdropFilter", "webkitBackdropFilter", "clipPath",
      "offsetPath", "fill", "stroke", "markerStart", "markerMid", "markerEnd", "webkitBoxReflect",
    ];
    let retainedFrameCount = 0;
    for (const element of nodes) {
      const tagName = element.localName;
      if (["iframe", "object", "embed"].includes(tagName)) retainedFrameCount += 1;
      if (tagName === "style") appendInlineFontSources(element);
      if (["img", "video", "audio"].includes(tagName)) {
        append(element.currentSrc);
      }
      if (
        [
          "audio", "embed", "iframe", "img", "input", "script", "source", "track", "video",
        ].includes(tagName)
      ) {
        append(element.getAttribute("src"));
        append(element.getAttribute("data-src"));
      }
      if (["img", "source"].includes(tagName)) {
        appendSrcset(element.getAttribute("srcset"));
        appendSrcset(element.getAttribute("data-srcset"));
      }
      if (tagName === "video") append(element.getAttribute("poster"));
      if (tagName === "object") append(element.getAttribute("data"));
      if (["image", "use"].includes(tagName) && element.namespaceURI?.includes("svg")) {
        append(element.getAttribute("href"));
        append(element.getAttribute("xlink:href"));
      }
      appendCssUrls(element.style.backgroundImage);
      appendCssUrls(element.style.listStyleImage);
      appendCssUrls(element.style.content);
      for (const pseudo of [null, "::before", "::after"]) {
        try {
          const style = window.getComputedStyle(element, pseudo);
          for (const property of retainedComputedUrlProperties) appendCssUrls(style[property]);
        } catch {}
      }
      if (performance.now() - startedAt > maximumElapsedMs) {
        elapsedTimeOverflowCount += 1;
        break;
      }
    }
    // Document stylesheets affect the retained article even when linked in head.
    // Count every inspected child, including non-links. A live head collection
    // must not bypass traversal/time bounds merely by producing few URLs.
    let headNodeCount = 0;
    let headElement = document.head?.firstElementChild ?? null;
    while (headElement) {
      if (headNodeCount >= maximumNodes) {
        nodeOverflowCount += 1;
        break;
      }
      if (performance.now() - startedAt > maximumElapsedMs) {
        elapsedTimeOverflowCount += 1;
        break;
      }
      const element = headElement;
      headNodeCount += 1;
      if (element.matches("link[rel~='stylesheet'][href]")) append(element.href);
      if (element.localName === "style") appendInlineFontSources(element);
      headElement = element.nextElementSibling;
    }
    const hosts = new Set();
    const urls = new Set();
    const unsafeReferencesByAuthority = new Map();
    let hostOverflowCount = 0;
    let unsafeReferenceOverflowCount = 0;
    const recordUnsafeReference = (url, reason) => {
      const hostname = url.hostname.toLowerCase();
      const key = `${url.protocol}|${hostname}|${reason}`;
      let entry = unsafeReferencesByAuthority.get(key);
      if (!entry) {
        if (unsafeReferencesByAuthority.size >= maximumHosts) {
          unsafeReferenceOverflowCount += 1;
          return;
        }
        entry = {
          protocol: url.protocol,
          hostname,
          reason,
          count: 0,
        };
        unsafeReferencesByAuthority.set(key, entry);
      }
      entry.count += 1;
    };
    for (const value of rawUrls) {
      try {
        const url = new URL(value, document.baseURI);
        if (["http:", "https:", "ws:", "wss:"].includes(url.protocol)) {
          url.hash = "";
          urls.add(url.href);
          const hostname = url.hostname.toLowerCase();
          if (!hosts.has(hostname) && hosts.size >= maximumHosts) {
            hostOverflowCount += 1;
          } else {
            hosts.add(hostname);
          }
          if (!["https:", "wss:"].includes(url.protocol)) {
            recordUnsafeReference(url, "secure-transport-required");
          } else if (url.username || url.password) {
            recordUnsafeReference(url, "credentialed-authority");
          } else if (url.port) {
            recordUnsafeReference(url, "non-default-port");
          } else if (/^\[|\]$/u.test(url.hostname) || /^\d+(?:\.\d+){3}$/u.test(url.hostname)) {
            recordUnsafeReference(url, "literal-ip-authority");
          }
        }
      } catch {}
    }
    return {
      hosts: [...hosts].sort(),
      urls: [...urls],
      rootCount: roots.size,
      nodeCount: nodes.size,
      retainedFrameCount,
      headNodeCount,
      stylesheetRuleCount,
      stylesheetRuleOverflowCount,
      stylesheetRuleErrorCount,
      urlCount: rawUrls.length,
      selectorErrorCount,
      rootOverflowCount,
      nodeOverflowCount,
      urlOverflowCount,
      hostOverflowCount,
      elapsedTimeOverflowCount,
      unsafeReferences: [...unsafeReferencesByAuthority.values()].sort((left, right) => {
        const leftKey = `${left.protocol}|${left.hostname}|${left.reason}`;
        const rightKey = `${right.protocol}|${right.hostname}|${right.reason}`;
        return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
      }),
      unsafeReferenceOverflowCount,
    };
}

async function roleReferencedResourceHosts(page, selectors) {
  const evidence = await evaluateInIsolatedWorld(page, collectRetainedRoleResourceEvidence, selectors);
  const { urls, ...safeEvidence } = evidence;
  return {
    ...safeEvidence,
    urlSha256s: [...new Set((urls ?? []).map(networkResourceUrlSha256).filter(Boolean))].sort(),
  };
}

function classifyDestinationResponse(responseEvidence) {
  const finalUrl = String(responseEvidence?.finalUrl ?? "");
  const selectedChainResponse = selectFinalMainDocumentResponse(
    responseEvidence?.mainDocumentResponseChain ?? [],
    finalUrl,
  );
  const suppliedFinalResponse = responseEvidence?.mainDocumentResponse;
  const finalResponse =
    selectedChainResponse ??
    (mainDocumentResponseUrlMatches(suppliedFinalResponse?.url, finalUrl)
      ? suppliedFinalResponse
      : null);
  const status = Number.isInteger(finalResponse?.status)
    ? finalResponse.status
    : Number.isInteger(responseEvidence?.status)
      ? responseEvidence.status
      : null;
  const contentType = String(
    finalResponse?.contentType ?? responseEvidence?.contentType ?? "",
  );
  const normalizedTitle = normalizeAlgumonSourceLabel(responseEvidence?.title ?? "");
  const normalizedBody = normalizeAlgumonSourceLabel(responseEvidence?.bodyText ?? "");
  const challengeSelectors = Array.isArray(responseEvidence?.challengeSelectors)
    ? responseEvidence.challengeSelectors.filter((value) => typeof value === "string")
    : [];
  const challengePattern =
    /(?:\bE002\b|access denied|request blocked|too many requests|attention required|just a moment|checking your browser|performing security verification|verify you are human|captcha|cloudflare ray id|접근.{0,8}차단|보안.{0,8}(?:검사|확인)|자동.{0,8}요청)/iu;
  const challengeText =
    challengePattern.test(normalizedTitle) ||
    (/cloudflare ray id/iu.test(normalizedBody) && challengePattern.test(normalizedBody)) ||
    (normalizedBody.length < 4_096 && challengePattern.test(normalizedBody));
  const htmlResponse = /^(?:text\/html|application\/xhtml\+xml)(?:\s*;|$)/iu.test(
    contentType,
  );
  const finalDocumentUrlMatches = Boolean(
    finalResponse && mainDocumentResponseUrlMatches(finalResponse.url, finalUrl),
  );
  const blockedStatus = status === 401 || status === 403 || status === 429 || status === 503;
  const sourceFailure =
    status === null ||
    status < 200 ||
    status >= 300 ||
    !htmlResponse ||
    !finalDocumentUrlMatches ||
    blockedStatus ||
    challengeSelectors.length > 0 ||
    challengeText;
  const evidence = {
    kind: sourceFailure ? "source-or-infrastructure-failure" : "article-response",
    subkind: sourceFailure
      ? blockedStatus || challengeSelectors.length > 0 || challengeText
        ? "waf-or-challenge"
        : status === null || !finalDocumentUrlMatches
          ? "missing-final-main-document-response"
          : !htmlResponse
            ? "non-html-response"
            : "http-status"
      : "accepted-final-main-document",
    candidateEligible: !sourceFailure,
    status,
    contentType: contentType.slice(0, 160),
    finalDocumentUrlMatches,
    challengeSelectorCount: challengeSelectors.length,
    challengeText,
    titleSha256: sha256(String(responseEvidence?.title ?? "")),
    bodyTextSha256: sha256(String(responseEvidence?.bodyText ?? "")),
  };
  return evidence;
}

function validateArticleAccessCookies(cookies, allowedCookieDomains, nowMs = Date.now()) {
  if (!Array.isArray(cookies)) {
    throw new Error("article access lease contains an invalid cookie collection");
  }
  const normalizedAllowedDomains = new Set(
    allowedCookieDomains.map((domain) => normalizedHostname(domain)),
  );
  const accepted = [];
  for (const cookie of cookies) {
    if (!cookie || typeof cookie !== "object" || Array.isArray(cookie)) {
      throw new Error("article access lease contains an invalid cookie record");
    }
    const domain = normalizedHostname(String(cookie.domain ?? "").replace(/^\./u, ""));
    const domainAllowed = [...normalizedAllowedDomains].some((allowedDomain) =>
      hostnameMatches(domain, allowedDomain),
    );
    // Third-party advertising cookies never enter the lease or its size budget.
    if (!domainAllowed) continue;
    const validShape =
      typeof cookie.name === "string" &&
      cookie.name.length >= 1 &&
      cookie.name.length <= 256 &&
      !/[\u0000-\u001f\u007f;]/u.test(cookie.name) &&
      typeof cookie.value === "string" &&
      cookie.value.length <= 4_096 &&
      !/[\u0000\r\n]/u.test(cookie.value) &&
      typeof cookie.path === "string" &&
      cookie.path.startsWith("/") &&
      cookie.path.length <= 1_024 &&
      typeof cookie.secure === "boolean" &&
      typeof cookie.httpOnly === "boolean" &&
      ["Strict", "Lax", "None"].includes(cookie.sameSite) &&
      Number.isFinite(cookie.expires);
    if (!validShape) {
      throw new Error("article access lease contains an invalid cookie record");
    }
    const unexpired = cookie.expires === -1 || cookie.expires * 1_000 > nowMs;
    if (cookie.secure !== true || !unexpired) continue;
    accepted.push({
      name: cookie.name,
      value: cookie.value,
      domain: cookie.domain,
      path: cookie.path,
      expires: cookie.expires,
      httpOnly: cookie.httpOnly,
      secure: cookie.secure,
      sameSite: cookie.sameSite,
    });
    if (accepted.length > ARTICLE_ACCESS_LEASE_MAX_COOKIES) {
      throw new Error("article access lease cookie count exceeded its bound");
    }
    if (Buffer.byteLength(JSON.stringify(accepted), "utf8") > ARTICLE_ACCESS_LEASE_MAX_COOKIE_BYTES) {
      throw new Error("article access lease cookie bytes exceeded their bound");
    }
  }
  return accepted;
}

function createArticleAccessLease(cookies, binding, allowedCookieDomains, nowMs = Date.now()) {
  const normalizedBinding = {
    siteId: String(binding?.siteId ?? ""),
    profileName: String(binding?.profileName ?? ""),
    requestedArticleIdentitySha256: String(
      binding?.requestedArticleIdentitySha256 ?? "",
    ),
    resolvedArticleIdentitySha256: String(binding?.resolvedArticleIdentitySha256 ?? ""),
    resolvedRouteFamily: String(binding?.resolvedRouteFamily ?? ""),
  };
  if (
    !/^[a-z0-9][a-z0-9_-]{0,79}$/u.test(normalizedBinding.siteId) ||
    !/^(?:desktop|mobile)$/u.test(normalizedBinding.profileName) ||
    !/^[0-9a-f]{64}$/u.test(normalizedBinding.requestedArticleIdentitySha256) ||
    !/^[0-9a-f]{64}$/u.test(normalizedBinding.resolvedArticleIdentitySha256) ||
    normalizedBinding.resolvedRouteFamily.length < 1
  ) {
    throw new Error("article access lease binding is invalid");
  }
  const acceptedCookies = validateArticleAccessCookies(
    cookies,
    allowedCookieDomains,
    nowMs,
  );
  const expiresAtMs = nowMs + ARTICLE_ACCESS_LEASE_TTL_MS;
  const bindingSha256 = sha256(canonicalJson(normalizedBinding));
  return {
    schemaVersion: ARTICLE_ACCESS_LEASE_SCHEMA_VERSION,
    issuedAtMs: nowMs,
    expiresAtMs,
    consumed: false,
    binding: normalizedBinding,
    bindingSha256,
    storageState: { cookies: acceptedCookies, origins: [] },
    evidence: {
      schemaVersion: ARTICLE_ACCESS_LEASE_SCHEMA_VERSION,
      kind: "validated-cookies-only-one-use",
      issuedAt: new Date(nowMs).toISOString(),
      expiresAt: new Date(expiresAtMs).toISOString(),
      ttlMs: ARTICLE_ACCESS_LEASE_TTL_MS,
      cookieCount: acceptedCookies.length,
      originsCount: 0,
      bindingSha256,
    },
  };
}

async function acquireArticleAccessLease(
  context,
  site,
  profileName,
  requestedUrl,
  resolvedUrl,
  nowMs = Date.now(),
) {
  const requestedIdentity = canonicalArticleIdentity(requestedUrl, site.id);
  const resolvedIdentity = canonicalArticleIdentity(resolvedUrl, site.id);
  if (!articleIdentitiesLogicallyEquivalent(requestedIdentity, resolvedIdentity)) {
    throw new Error("article access lease refused a different requested/resolved article identity");
  }
  const allowedCookieDomains = [
    ...new Set([
      ...site.layouts.map((layout) => layout.domain),
      new URL(resolvedUrl).hostname,
    ]),
  ];
  return createArticleAccessLease(
    await context.cookies(),
    {
      siteId: site.id,
      profileName,
      requestedArticleIdentitySha256: requestedIdentity.sha256,
      resolvedArticleIdentitySha256: resolvedIdentity.sha256,
      resolvedRouteFamily: resolvedIdentity.routeFamily,
    },
    allowedCookieDomains,
    nowMs,
  );
}

function consumeArticleAccessLease(lease, expectedBinding, nowMs = Date.now()) {
  if (
    !lease ||
    lease.schemaVersion !== ARTICLE_ACCESS_LEASE_SCHEMA_VERSION ||
    lease.consumed !== false ||
    !Number.isSafeInteger(lease.issuedAtMs) ||
    !Number.isSafeInteger(lease.expiresAtMs) ||
    nowMs < lease.issuedAtMs ||
    nowMs > lease.expiresAtMs
  ) {
    throw new Error("article access lease is stale, invalid, or already consumed");
  }
  const normalizedExpectedBinding = {
    siteId: String(expectedBinding?.siteId ?? ""),
    profileName: String(expectedBinding?.profileName ?? ""),
    requestedArticleIdentitySha256: String(
      expectedBinding?.requestedArticleIdentitySha256 ?? "",
    ),
    resolvedArticleIdentitySha256: String(
      expectedBinding?.resolvedArticleIdentitySha256 ?? "",
    ),
    resolvedRouteFamily: String(expectedBinding?.resolvedRouteFamily ?? ""),
  };
  if (
    sha256(canonicalJson(normalizedExpectedBinding)) !== lease.bindingSha256 ||
    canonicalJson(normalizedExpectedBinding) !== canonicalJson(lease.binding)
  ) {
    throw new Error("article access lease binding mismatch");
  }
  const storageState = structuredClone(lease.storageState);
  lease.consumed = true;
  lease.storageState = null;
  return storageState;
}

function staticRuntimeConsistencyFailures(
  staticEvidence,
  runtimeNavigation,
  runtimeGate,
  runtimeLayoutId,
) {
  const failures = [];
  if (!staticEvidence || staticEvidence.provenanceOnly === true) return failures;
  const runtimeIdentity = canonicalArticleIdentity(
    runtimeNavigation.finalUrl,
    staticEvidence.siteId,
  );
  if (
    staticEvidence.resolvedArticleIdentitySha256 !== runtimeIdentity.sha256 ||
    staticEvidence.resolvedRouteFamily !== runtimeIdentity.routeFamily
  ) {
    failures.push("static/runtime route and canonical article identity diverged");
  }
  if (staticEvidence.layoutId !== runtimeLayoutId) {
    failures.push("static/runtime layout identity diverged");
  }
  if (Array.isArray(staticEvidence.projectionAliases)) {
    const runtimeAliases = [...(runtimeGate?.diagnostics?.layoutAliases ?? [])].sort();
    const staticAliases = [...staticEvidence.projectionAliases].sort();
    if (
      runtimeGate?.diagnostics?.semanticProjectionCount !==
        staticEvidence.semanticProjectionCount ||
      canonicalJson(runtimeAliases) !== canonicalJson(staticAliases)
    ) {
      failures.push("static/runtime semantic projection identity diverged");
    }
  }
  return failures;
}

async function navigateThroughAlgumon(page, target, timeoutMs, expectedDomain = null) {
  if (!target.algumon) return navigate(page, target.url, timeoutMs);
  if (!target.algumon.verifiedResolution) {
    throw new Error(
      "relay-contract-failure: source-click fallback is disabled; use a sealed signed relay",
    );
  }
  const signedUrl = exactSignedAlgumonDealUrl(
    target.algumon.redirectUrl,
    target.algumon.dealId,
  );
  const useTimeAcquisition = target.source === "algumon-latest"
    ? recordedSignedRelayAcquisitionEvidence(
        target.algumon.redirectUrl,
        target.algumon.dealId,
        target.relayAcquisition,
      )
    : null;
  const resolution = target.algumon.verifiedResolution;
  if (
    !signedUrl ||
    (target.source === "algumon-latest" &&
      (!target.relayAcquisition ||
        useTimeAcquisition?.signedUrl !== target.relayAcquisition.signedUrl)) ||
    resolution.relayFetchUrl !== signedUrl.href ||
    resolution.resolvedDestination !== target.url ||
    !/^[0-9a-f]{64}$/u.test(resolution.responseSha256 ?? "") ||
    resolution.responseStatus !== 200
  ) {
    throw new Error("verified Algumon relay evidence is internally inconsistent");
  }
  const destination = new URL(target.url);
  const expectedTargetDomain = expectedDomain || destination.hostname;
  if (!hostnameMatches(destination.hostname, expectedTargetDomain)) {
    throw new Error(`verified Algumon relay ended outside ${expectedTargetDomain}`);
  }
  const navigation = await navigate(
    page,
    seededNavigationUrl(
      target.url,
      target.algumon.siteId,
      target.algumon.title,
      target.algumon.dealId,
      target.algumon.redirectUrl,
    ),
    timeoutMs,
  );
  return {
    ...navigation,
    viaAlgumon: true,
    provenanceMode: "sealed-single-fetch-signed-relay",
    relayFetchUrl: resolution.relayFetchUrl,
    resolvedDestination: resolution.resolvedDestination,
    popupNavigation: [],
    relayResponseSha256: resolution.responseSha256,
  };
}

function safeFileStem(parts) {
  return parts
    .join("-")
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/gu, "-")
    .replace(/^-+|-+$/gu, "")
    .slice(0, 150);
}

async function selectorCandidates(page) {
  return evaluateInIsolatedWorld(page, () => {
    const visible = (element) => {
      const style = window.getComputedStyle(element);
      return (
        style.display !== "none" &&
        style.visibility !== "hidden" &&
        Number(style.opacity) !== 0 &&
        [...element.getClientRects()].some((rect) => rect.width > 0 && rect.height > 0)
      );
    };
    const escapeCss = (value) => {
      if (window.CSS?.escape) return window.CSS.escape(value);
      return String(value).replace(/[^a-zA-Z0-9_-]/g, "\\$&");
    };
    const structuralSelector = (element) => {
      if (element.id && !/\d{5,}/u.test(element.id)) {
        return `#${escapeCss(element.id)}`;
      }
      const stableClasses = [...element.classList]
        .filter((name) => !/\d{5,}|^css-|^sc-/u.test(name))
        .slice(0, 3)
        .map((name) => `.${escapeCss(name)}`)
        .join("");
      return `${element.tagName.toLowerCase()}${stableClasses}`;
    };
    const landmarks = [
      "h1",
      "h2",
      "h3",
      "article",
      "main",
      "[class*='title' i]",
      "[class*='subject' i]",
      "[class*='content' i]",
      "[class*='article' i]",
      "[class*='comment' i]",
      "[class*='reply' i]",
      "[id*='comment' i]",
      "[id*='reply' i]",
    ].join(",");
    return [...document.querySelectorAll(landmarks)]
      .filter(visible)
      .slice(0, 120)
      .map((element) => {
        const rect = element.getBoundingClientRect();
        return {
          selector: structuralSelector(element),
          tag: element.tagName.toLowerCase(),
          textLength: (element.textContent ?? "").trim().length,
          descendantCount: element.querySelectorAll("*").length,
          box: {
            width: Math.round(rect.width),
            height: Math.round(rect.height),
          },
        };
      });
  });
}

function targetAlgumonSeed(siteId, target) {
  const redirectUrl = target.algumon
    ? exactSignedAlgumonDealUrl(target.algumon.redirectUrl)
    : null;
  const redirectPath = redirectUrl?.pathname ?? "";
  const dealId = redirectPath.match(/^\/l\/d\/(\d{1,24})(?:\/|$)/u)?.[1] ?? "0";
  return target.algumon && redirectUrl
    ? {
        v: 1,
        siteType: siteId,
        dealId,
        title: target.algumon.title,
        commentCount: target.algumon.commentCount,
        ts: Date.now(),
        relayV: redirectUrl.searchParams.get("v"),
        relayT: redirectUrl.searchParams.get("t"),
      }
    : null;
}

function seededNavigationUrl(url, siteType, title, dealId, signedRelayUrl = null) {
  const now = Date.now();
  const signedRelay = signedRelayUrl
    ? exactSignedAlgumonDealUrl(signedRelayUrl, dealId)
    : null;
  const relayT = signedRelay?.searchParams.get("t") ?? String(now);
  const relayV = signedRelay?.searchParams.get("v") ?? createHash("sha256")
    .update(`${siteType}:${dealId}:${relayT}`)
    .digest("hex")
    .slice(0, 32);
  const navigationNonce = `hdf-${createHash("sha256")
    .update(`navigation:${siteType}:${dealId}:${now}`)
    .digest("hex")
    .slice(0, 28)}`;
  const seed = {
    v: 1,
    siteType,
    dealId: String(dealId),
    title,
    commentCount: null,
    ts: now,
    relayV,
    relayT,
    navigationNonce,
    destinationUrl: new URL(url).href,
  };
  const encoded = Buffer.from(JSON.stringify(seed), "utf8").toString("base64url");
  const parsed = new URL(url);
  parsed.hash = `hdf-audit-seed=${encoded}`;
  return parsed.href;
}

function seededNavigationProof(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  const encoded = new URLSearchParams(parsed.hash.replace(/^#/u, "")).get("hdf-audit-seed");
  if (!encoded || !/^[A-Za-z0-9_-]+$/u.test(encoded)) return null;
  try {
    const seed = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    return /^hdf-[0-9a-z]{28}$/u.test(String(seed?.navigationNonce ?? ""))
      ? { encoded, navigationNonce: seed.navigationNonce, seed }
      : null;
  } catch {
    return null;
  }
}

async function semanticOracle(
  page,
  userscriptContent,
  siteId,
  layoutId,
  requiredRoles,
  target,
) {
  const seed = targetAlgumonSeed(siteId, target);
  const verdict = await evaluateInIsolatedWorld(
    page,
    ({ sourceBytes, expectedSiteId, expectedLayoutId, rolesRequired, oracleSeed, registeredSample }) => {
      const originalModule = Object.getOwnPropertyDescriptor(globalThis, "module");
      if (originalModule && originalModule.configurable !== true) {
        throw new Error("page has a non-configurable global module");
      }
      const moduleRecord = { exports: {} };
      Object.defineProperty(globalThis, "module", {
        value: moduleRecord,
        configurable: true,
        enumerable: false,
        writable: false,
      });
      let api;
      try {
        (0, eval)(sourceBytes);
        api = moduleRecord.exports;
      } finally {
        delete globalThis.module;
        if (originalModule) {
          Object.defineProperty(globalThis, "module", originalModule);
        }
      }
      if (
        !api ||
        typeof api.discoverSemanticContract !== "function" ||
        typeof api.lowestCommonAncestor !== "function"
      ) {
        throw new Error("verified userscript did not export the semantic oracle");
      }
      const siteContract = api.SITE_CONTRACTS.find(
        (contract) => contract.id === expectedSiteId,
      );
      const oracleLayout = siteContract?.layouts.find(
        (layout) => layout.id === expectedLayoutId,
      );
      if (!oracleLayout) {
        throw new Error(
          "verified userscript has no oracle layout for " +
            expectedSiteId +
            "/" +
            expectedLayoutId,
        );
      }
      // Preserve an exact approved contract. A changed registered tuple alone
      // proceeds to the independent native-article discovery below.
      if (registeredSample) {
        const hostname = location.hostname.toLocaleLowerCase();
        const siteMatches = hostname === siteContract.domain ||
          hostname.endsWith(`.${siteContract.domain}`);
        const registeredRoute = api.readerEntryAuthority(location.href, "") ===
          "registered-hotdeal-route";
        const pathAndQuery = `${location.pathname}${location.search}`;
        const matchingLayouts = siteMatches && registeredRoute ? siteContract.layouts.filter((layout) =>
          (layout.paths ?? [layout.path]).some((pattern) =>
            api.pathPatternMatches(pathAndQuery, pattern))) : [];
        const projection = api.resolveProjectionClasses(document, matchingLayouts, null);
        const projectionClass = projection.projectionClasses.length === 1
          ? projection.projectionClasses[0] : [];
        const expectedLayoutApproved = projectionClass.some((item) =>
          item.layoutId === expectedLayoutId);
        const resolution = projectionClass[0] ?? null;
        const resolvedLayout = matchingLayouts.find((layout) =>
          layout.id === resolution?.layoutId);
        const exactSelector = (element, preferred = []) => {
          if (!element) return null;
          const candidates = [...preferred];
          if (element.id) candidates.push(`#${CSS.escape(element.id)}`);
          const tag = element.tagName.toLocaleLowerCase();
          if (element.classList.length) {
            candidates.push(tag + [...element.classList].map((name) => `.${CSS.escape(name)}`).join(""));
          }
          candidates.push(tag);
          for (const selector of candidates) {
            try {
              const matches = document.querySelectorAll(selector);
              if (matches.length === 1 && matches[0] === element) return selector;
            } catch {}
          }
          // This locator only records an already approved node. It is never a
          // learned selector or a promotion proposal.
          const segments = [];
          for (let current = element; current && current !== document.documentElement;
            current = current.parentElement) {
            const index = [...current.parentElement.children].indexOf(current) + 1;
            segments.unshift(`${current.tagName.toLocaleLowerCase()}:nth-child(${index})`);
          }
          const selector = `html > ${segments.join(" > ")}`;
          return document.querySelector(selector) === element ? selector : null;
        };
        const roleNames = ["title", "body", "comments"].concat(
          resolution?.roles.product ? ["product"] : [],
        );
        const roles = Object.fromEntries(roleNames.map((role) => [role,
          exactSelector(resolution?.roles[role], resolvedLayout?.hints?.[role] ?? []),
        ]));
        const cardinality = Object.fromEntries(Object.entries(roles).map(([role, selector]) =>
          [role, selector ? document.querySelectorAll(selector).length : 0]));
        const commentItems = resolution?.roles.commentItems ?? [];
        const dormantItems = resolution?.roles.commentDormantItems ?? [];
        const commentMount = resolution?.roles.comments;
        const pageRoot = resolution?.commonRoot;
        const containment = Boolean(pageRoot) && roleNames.every((role) => {
          const node = resolution.roles[role];
          return node && (node === pageRoot || pageRoot.contains(node));
        });
        const itemRoots = [...new Set([...commentItems, ...dormantItems])];
        const itemContainment = Boolean(commentMount) && itemRoots.every((node) =>
          node !== commentMount && commentMount.contains(node));
        const exact = siteMatches && registeredRoute && projection.projectionClasses.length === 1 &&
          expectedLayoutApproved && resolution?.ok === true && containment && itemContainment &&
          rolesRequired.every((role) => Boolean(roles[role])) &&
          Object.values(cardinality).every((count) => count === 1);
        // A different approved sibling or ambiguous approved projections are
        // profile/contract failures, not evidence of a previously unknown DOM.
        if (exact || projection.projectionClasses.length > 0 || !siteMatches || !registeredRoute) return {
          ok: exact,
          verificationMode: "registered-sample",
          candidateEligible: false,
          reason: exact ? "exact-approved-registered-projection" :
            projectionClass.length && !expectedLayoutApproved ? "expected-layout-not-approved" :
            projection.resolutions.find((item) => !item.ok)?.reason ?? "no-unique-approved-projection",
          pageRoot: exactSelector(pageRoot, [resolvedLayout?.pageRoot].filter(Boolean)),
          pageRootCount: pageRoot ? 1 : 0,
          roles,
          cardinality,
          metrics: resolution?.roleDiagnostics ?? {},
          commentItems: resolution?.commentItemSelectors ?? [],
          commentControls: resolution?.commentControlSelectors ?? [],
          commentIgnored: resolution?.commentIgnoredSelectors ?? [],
          commentItemCount: commentItems.length,
          dormantCommentItemCount: dormantItems.length,
          ignoredCommentCount: resolution?.roles.commentIgnored.length ?? 0,
          titleNormalized: api.normalizeText(resolution?.resolvedTitle ?? ""),
          containment,
          approvedProjection: {
            count: projection.projectionClasses.length,
            aliases: projectionClass.map((item) => item.layoutId).sort(),
            loadedCommentItemsExact: exact && itemRoots.length === commentItems.length &&
              dormantItems.every((item) => commentItems.includes(item)),
            commentItemContainment: itemContainment,
            commentControlsClassified: resolution?.ok === true,
          },
          policyProposal: null,
          productOrder: resolution?.projectionPolicy.productOrder ?? null,
          oracleSource: "verified-userscript-export",
        };
      }
      const resolution = api.discoverSemanticContract(
        document,
        [oracleLayout],
        oracleSeed,
      );
      const cssEscape = (value) =>
        window.CSS?.escape
          ? window.CSS.escape(value)
          : String(value).replace(/[^a-zA-Z0-9_-]/gu, "\\$&");
      const stableClassNames = (element) =>
        [...element.classList].filter(
          (name) =>
            /^[a-zA-Z_-][a-zA-Z0-9_-]{1,63}$/u.test(name) &&
            !/\d{4,}|^(?:css|sc|jsx)-|active|selected|open|closed|hover|focus/iu.test(name),
        );
      const uniqueInDocument = (selector, element) => {
        try {
          const matches = document.querySelectorAll(selector);
          return matches.length === 1 && matches[0] === element;
        } catch {
          return false;
        }
      };
      const shallowSelector = (element) => {
        const tag = element.tagName.toLocaleLowerCase();
        if (element.id && !/\d{4,}|^[0-9]/u.test(element.id)) {
          const selector = "#" + cssEscape(element.id);
          if (uniqueInDocument(selector, element)) return selector;
        }
        const classes = stableClassNames(element);
        for (let count = Math.min(2, classes.length); count >= 1; count -= 1) {
          const selector =
            tag +
            classes
              .slice(0, count)
              .map((name) => "." + cssEscape(name))
              .join("");
          if (uniqueInDocument(selector, element)) return selector;
        }
        return uniqueInDocument(tag, element) ? tag : null;
      };
      const stableSelector = (element) => {
        const tag = element.tagName.toLocaleLowerCase();
        if (element.id && !/\d{4,}|^[0-9]/u.test(element.id)) {
          const selector = "#" + cssEscape(element.id);
          if (uniqueInDocument(selector, element)) return selector;
        }
        for (const attribute of ["itemprop", "role"]) {
          const value = element.getAttribute(attribute);
          if (value && /^[a-zA-Z0-9 _:-]{1,48}$/u.test(value)) {
            const selector =
              tag + "[" + attribute + "=\"" + cssEscape(value) + "\"]";
            if (uniqueInDocument(selector, element)) return selector;
          }
        }
        const classes = stableClassNames(element);
        for (let count = Math.min(3, classes.length); count >= 1; count -= 1) {
          const selector =
            tag +
            classes
              .slice(0, count)
              .map((name) => "." + cssEscape(name))
              .join("");
          if (uniqueInDocument(selector, element)) return selector;
        }
        if (uniqueInDocument(tag, element)) return tag;
        for (
          let ancestor = element.parentElement, depth = 0;
          ancestor && ancestor !== document.body && depth < 4;
          ancestor = ancestor.parentElement, depth += 1
        ) {
          const prefix = shallowSelector(ancestor);
          if (!prefix) continue;
          const suffix =
            tag +
            classes
              .slice(0, 2)
              .map((name) => "." + cssEscape(name))
              .join("");
          const combined = prefix + " " + suffix;
          if (uniqueInDocument(combined, element)) return combined;
        }
        return null;
      };
      const relativeItemSelector = (element) => {
        const tag = element.tagName.toLocaleLowerCase();
        const itemprop = element.getAttribute("itemprop");
        if (itemprop && /^[a-zA-Z0-9 _:-]{1,48}$/u.test(itemprop)) {
          return tag + "[itemprop=\"" + cssEscape(itemprop) + "\"]";
        }
        const classes = stableClassNames(element);
        if (classes.length > 0) {
          return (
            tag +
            classes
              .slice(0, 2)
              .map((name) => "." + cssEscape(name))
              .join("")
          );
        }
        return tag;
      };
      const proposedProductCardinality = resolution.policyProposal?.product?.cardinality;
      const observedRoles = ["title", "body", "comments"].concat(
        proposedProductCardinality === "required" ? ["product"] : [],
      );
      const roleNodes = Object.fromEntries(
        observedRoles.map((role) => [role, resolution.roles?.[role]?.node ?? null]),
      );
      const nodes = observedRoles.map((role) => roleNodes[role]).filter(Boolean);
      const pageRoot =
        nodes.length === observedRoles.length
          ? api.lowestCommonAncestor(nodes)
          : null;
      const pageRootSelector = resolution.policyProposal?.pageRoot ?? null;
      const roleSelectors = Object.fromEntries(
        observedRoles.map((role) => [
          role,
          role === "product"
            ? resolution.policyProposal?.product?.selectors?.[0] ?? null
            : roleNodes[role] ? stableSelector(roleNodes[role]) : null,
        ]),
      );
      const cardinality = Object.fromEntries(
        Object.entries(roleSelectors).map(([role, selector]) => {
          let count = 0;
          try {
            count = selector ? document.querySelectorAll(selector).length : 0;
          } catch {}
          return [role, count];
        }),
      );
      let pageRootCount = 0;
      try {
        pageRootCount = pageRootSelector
          ? document.querySelectorAll(pageRootSelector).length
          : 0;
      } catch {}
      const commentMount = roleNodes.comments;
      const commentIgnored = [
        ...new Set(resolution.policyProposal?.commentIgnored ?? []),
      ].sort();
      const ignoredCommentNodes = [];
      if (commentMount) {
        for (const selector of commentIgnored) {
          try {
            for (const element of commentMount.querySelectorAll(selector)) {
              if (!ignoredCommentNodes.includes(element)) {
                ignoredCommentNodes.push(element);
              }
            }
          } catch {}
        }
      }
      const insideIgnoredCommentSubtree = (element) =>
        ignoredCommentNodes.some(
          (ignored) => ignored === element || ignored.contains(element),
        );
      const itemGroups = new Map();
      if (commentMount) {
        for (const selector of oracleLayout.hints?.commentItems ?? []) {
          try {
            const matchedCount = [...commentMount.querySelectorAll(selector)]
              .filter((element) => !insideIgnoredCommentSubtree(element)).length;
            if (matchedCount > 0) {
              itemGroups.set(selector, {
                selector,
                count: matchedCount,
                depth: -1,
                hinted: true,
              });
            }
          } catch {}
        }
      }
      if (commentMount) {
        const queue = [...commentMount.children].map((element) => ({
          element,
          depth: 0,
        }));
        while (queue.length > 0) {
          const current = queue.shift();
          if (insideIgnoredCommentSubtree(current.element)) continue;
          if (current.depth < 2) {
            for (const child of current.element.children) {
              queue.push({ element: child, depth: current.depth + 1 });
            }
          }
          const selector = relativeItemSelector(current.element);
          let matchedCount = 0;
          try {
            matchedCount = [...commentMount.querySelectorAll(selector)]
              .filter((element) => !insideIgnoredCommentSubtree(element)).length;
          } catch {}
          if (matchedCount > 0) {
            const previous = itemGroups.get(selector);
            if (!previous || matchedCount > previous.count) {
              itemGroups.set(selector, {
                selector,
                count: matchedCount,
                depth: current.depth,
                hinted: previous?.hinted === true,
              });
            }
          }
        }
      }
      const seedCount = Number.isInteger(oracleSeed?.commentCount)
        ? oracleSeed.commentCount
        : null;
      const rankedItemGroups = [...itemGroups.values()].sort((left, right) => {
        const leftDistance =
          seedCount === null ? -left.count : Math.abs(left.count - seedCount);
        const rightDistance =
          seedCount === null ? -right.count : Math.abs(right.count - seedCount);
        return (
          leftDistance - rightDistance ||
          right.count - left.count ||
          Number(right.hinted === true) - Number(left.hinted === true) ||
          left.depth - right.depth ||
          left.selector.localeCompare(right.selector)
        );
      });
      const selectedItems = rankedItemGroups[0] ?? {
        selector: "[itemprop='comment']",
        count: 0,
      };
      const rawSelectedItemNodes = commentMount
        ? [...commentMount.querySelectorAll(selectedItems.selector)]
        : [];
      const selectedItemNodes = rawSelectedItemNodes.filter(
        (element) => !insideIgnoredCommentSubtree(element),
      );
      const hintedCommentControls = [];
      if (commentMount) {
        for (const selector of oracleLayout.hints?.commentControls ?? []) {
          try {
            hintedCommentControls.push(...commentMount.querySelectorAll(selector));
          } catch {}
        }
      }
      const hintedCommentControlSet = new Set(hintedCommentControls);
      const rawCommentControlNodes = commentMount
        ? [...new Set([
            ...hintedCommentControls,
            ...commentMount.querySelectorAll(
            "button, a[href], input, select, textarea, [role='button'], " +
              "[class*='more' i], [class*='reply' i], [class*='pagination' i]",
            ),
          ])]
            .filter((element) =>
              hintedCommentControlSet.has(element) ||
              /more|reply|pagination|page|comment|더보기|답글|댓글|페이지/iu.test(
                [
                  element.id,
                  element.className,
                  element.getAttribute("role"),
                  element.getAttribute("aria-label"),
                  element.textContent,
                ].join(" "),
              ),
            )
        : [];
      const commentControlNodes = rawCommentControlNodes.filter(
        (element) => !insideIgnoredCommentSubtree(element),
      );
      const commentControls = commentControlNodes
            .map(relativeItemSelector)
            .filter((selector, index, selectors) => selectors.indexOf(selector) === index)
            .sort()
            .slice(0, 12);
      const classifiedCommentRoots = [
        ...selectedItemNodes,
        ...commentControlNodes,
        ...ignoredCommentNodes,
      ];
      const exactItemControlOverlapCount = rawSelectedItemNodes.filter(
        (item) => rawCommentControlNodes.includes(item),
      ).length;
      const ignoredClassificationOverlapCount = [
        ...rawSelectedItemNodes,
        ...rawCommentControlNodes,
      ].filter((classified) =>
        ignoredCommentNodes.some(
          (ignored) =>
            ignored === classified ||
            ignored.contains(classified) ||
            classified.contains(ignored),
        ),
      ).length;
      const classificationOverlapCount =
        exactItemControlOverlapCount + ignoredClassificationOverlapCount;
      const hasUnclassifiedCommentContent = commentMount
        ? [...commentMount.childNodes].some(function inspect(node) {
            if (node.nodeType === Node.TEXT_NODE) {
              return Boolean(api.normalizeText(node.data));
            }
            if (
              node.nodeType !== Node.ELEMENT_NODE ||
              node.matches("script, style, template, noscript")
            ) {
              return false;
            }
            if (
              classifiedCommentRoots.some(
                (root) => root === node || root.contains(node),
              )
            ) {
              return false;
            }
            const containsClassifiedRoot = classifiedCommentRoots.some(
              (root) => node.contains(root),
            );
            if ([...node.childNodes].some(inspect)) {
              return true;
            }
            if (containsClassifiedRoot) return false;
            return node.matches(
              "img, picture, video, iframe, table, button, input, " +
                "textarea, select, [contenteditable='true']",
            );
          })
        : true;
      const metrics = Object.fromEntries(
        observedRoles.map((role) => {
          const evidence = resolution.roles?.[role];
          return [
            role,
            {
              count: evidence?.count ?? 0,
              score: evidence?.score ?? 0,
              signalCount: evidence?.signalCount ?? 0,
              margin: evidence?.margin ?? 0,
            },
          ];
        }),
      );
      const containment =
        Boolean(pageRoot) &&
        nodes.length === observedRoles.length &&
        nodes.every(
          (node) => node === pageRoot || pageRoot.contains(node),
        );
      const nativeTitleEvidence = registeredSample && roleNodes.title
        ? api.titleEvidence(document, null, roleNodes.title.textContent)
        : null;
      return {
        verificationMode: registeredSample ? "native-article-discovery" : "relay-discovery",
        ok:
          resolution.ok === true &&
          pageRoot !== document.documentElement &&
          pageRoot !== document.body &&
          resolution.policyProposal?.complete === true &&
          resolution.policyProposal?.pageRootEvidence ===
            "all-role-lowest-common-ancestor" &&
          pageRootSelector !== null &&
          pageRootCount === 1 &&
          document.querySelector(pageRootSelector) === pageRoot &&
          containment &&
          Object.values(roleSelectors).every(Boolean) &&
          Object.values(cardinality).every((count) => count === 1),
        reason: resolution.reason,
        projectionTupleCount: resolution.projectionTupleCount,
        pageRoot: pageRootSelector,
        pageRootCount,
        roles: roleSelectors,
        cardinality,
        metrics,
        commentItems: [selectedItems.selector],
        commentControls,
        commentIgnored,
        commentItemCount: selectedItemNodes.length,
        ignoredCommentCount: ignoredCommentNodes.length,
        classificationOverlapCount,
        unclassifiedCommentContentCount: hasUnclassifiedCommentContent ? 1 : 0,
        emptyStateSelector:
          selectedItemNodes.length === 0 && !hasUnclassifiedCommentContent
            ? roleSelectors.comments
            : null,
        emptyStateCount:
          selectedItemNodes.length === 0 && !hasUnclassifiedCommentContent ? 1 : 0,
        titleNormalized: roleNodes.title
          ? api.normalizeText(roleNodes.title.textContent)
          : "",
        containment,
        seedTitleSimilarity:
          nativeTitleEvidence?.score ?? resolution.seedConsistency?.titleSimilarity ?? 0,
        seedTitleConsistencyOk:
          nativeTitleEvidence ? nativeTitleEvidence.ok === true
            : resolution.seedConsistency?.titleConsistencyOk === true,
        seedTitleConsistencyMode: registeredSample
          ? String(nativeTitleEvidence?.mode ?? "missing")
            .replace(/^algumon(?:-referrer)?/u, "native-article")
          : resolution.seedConsistency?.titleMode ?? "missing",
        seedTitleMetadataSourceCount:
          nativeTitleEvidence?.metadata.sourceCount ?? resolution.seedConsistency?.metadataSourceCount ?? 0,
        seedTitleMetadataSourceKinds:
          nativeTitleEvidence?.metadata.sourceKinds ?? resolution.seedConsistency?.metadataSourceKinds ?? [],
        productOrder: resolution.productOrder ?? null,
        existingPolicy: resolution.existingPolicy ?? null,
        policyProposal: resolution.policyProposal ?? null,
        oracleSource: "verified-userscript-export",
      };
    },
    {
      sourceBytes: userscriptContent,
      expectedSiteId: siteId,
      expectedLayoutId: layoutId,
      rolesRequired: requiredRoles,
      oracleSeed: seed,
      registeredSample: target.source === "sample",
    },
  );
  return { ...verdict, oracleExecutionWorld: ORACLE_EXECUTION_WORLD };
}
async function countExistingApprovedLayoutMatches(
  page,
  layout,
  userscriptContent,
  seed,
  explicitLayouts = null,
) {
  const verdict = await evaluateInIsolatedWorld(
    page,
    ({ expectedSiteId, expectedDomain, sourceBytes, oracleSeed, projectionLayouts }) => {
      const originalModule = Object.getOwnPropertyDescriptor(globalThis, "module");
      if (originalModule && originalModule.configurable !== true) {
        throw new Error("page has a non-configurable global module");
      }
      const moduleRecord = { exports: {} };
      Object.defineProperty(globalThis, "module", {
        value: moduleRecord,
        configurable: true,
        enumerable: false,
        writable: false,
      });
      let api;
      try {
        (0, eval)(sourceBytes);
        api = moduleRecord.exports;
      } finally {
        delete globalThis.module;
        if (originalModule) Object.defineProperty(globalThis, "module", originalModule);
      }
      if (typeof api?.resolveProjectionClasses !== "function") {
        throw new Error("verified userscript has no projection-class resolver");
      }
      const site = api.SITE_CONTRACTS.find((contract) => {
        const hostname = location.hostname.toLocaleLowerCase();
        return (!expectedSiteId || contract.id === expectedSiteId) &&
          contract.domain === expectedDomain &&
          (hostname === contract.domain || hostname.endsWith(`.${contract.domain}`));
      });
      const pathAndQuery = `${location.pathname}${location.search}`;
      const layouts = (site ? projectionLayouts ?? site.layouts : []).filter((candidate) =>
        (candidate.paths ?? [candidate.path]).some((configuredPath) =>
          api.pathPatternMatches(pathAndQuery, configuredPath)));
      const projectionSeed = oracleSeed && site && oracleSeed.siteType === site.id
        ? Object.freeze({
          siteType: oracleSeed.siteType,
          title: oracleSeed.title,
          commentCount: oracleSeed.commentCount ?? null,
        })
        : null;
      const projection = api.resolveProjectionClasses(
        document,
        layouts,
        projectionSeed,
      );
      return {
        semanticProjectionCount: projection.projectionClasses.length,
        classes: projection.projectionClasses.map((projectionClass) => {
          const aliases = projectionClass.map((resolution) => resolution.layoutId).sort();
          return { canonicalId: aliases[0], aliases };
        }).sort((left, right) => left.canonicalId.localeCompare(right.canonicalId)),
      };
    },
    {
      expectedSiteId: seed?.siteType ?? null,
      expectedDomain: layout.domain,
      sourceBytes: userscriptContent,
      oracleSeed: seed,
      projectionLayouts: explicitLayouts,
    },
  );
  return { ...verdict, oracleExecutionWorld: ORACLE_EXECUTION_WORLD };
}

function projectionCardinalityEvidence(structuralOk, semanticProjectionCount) {
  if (
    !Number.isInteger(semanticProjectionCount) ||
    semanticProjectionCount < 0
  ) {
    throw new Error("semantic projection count must be a non-negative integer");
  }
  return {
    semanticProjectionCount,
    coMatchCount: Math.max(0, semanticProjectionCount - 1),
    exactApprovedCount:
      structuralOk === true && semanticProjectionCount === 1 ? 1 : 0,
  };
}

function commentLowerBoundConsistency(observedCount, lowerBound) {
  if (
    !Number.isInteger(observedCount) ||
    observedCount < 0 ||
    !Number.isInteger(lowerBound) ||
    lowerBound < 0
  ) {
    return null;
  }
  return observedCount >= lowerBound ? 1 : 0;
}

function committedProjectionEvidence(approvedProjection) {
  const count = approvedProjection?.semanticProjectionCount;
  if (!Number.isInteger(count) || count < 0) {
    throw new Error("committed projection count must be a non-negative integer");
  }
  return {
    count,
    exactCount: count === 1 ? 1 : 0,
    coMatchCount: Math.max(0, count - 1),
    aliases: (approvedProjection.classes ?? []).map(
      (projectionClass) => projectionClass.aliases,
    ),
    oracleExecutionWorld: approvedProjection.oracleExecutionWorld,
  };
}

function candidateOracleLayout(layout, oracle, targetUrl) {
  const parsed = new URL(targetUrl);
  const proposal = oracle.policyProposal;
  const productCardinality = proposal?.product?.cardinality;
  if (
    proposal?.complete !== true ||
    !["required", "zero"].includes(productCardinality)
  ) {
    throw new Error("candidate oracle requires one complete independent policy proposal");
  }
  const roleProjection = {
    title: { mode: "metadata-shallow" },
    body: {
      mode: "atomic-boundary",
      ignored: [...proposal.bodyIgnored],
    },
    product: productCardinality === "required"
      ? {
          mode: "atomic-boundary",
          cardinality: "required",
          order: proposal.product.order,
          selectors: [...proposal.product.selectors],
          ignored: [...proposal.productIgnored],
        }
      : {
          mode: "absent",
          cardinality: "zero",
          selectors: [],
          ignored: [],
        },
    comments: { mode: "classified-children" },
  };
  const requiredRoles = ["title", "body", "comments"].concat(
    productCardinality === "required" ? ["product"] : [],
  );
  return {
    id: `${layout.id}--candidate-oracle`,
    paths: [`|${parsed.pathname}${parsed.search}^`],
    pageRoot: proposal.pageRoot,
    requiredRoles,
    allowEmptyComments: true,
    roleProjection,
    hints: {
      ...Object.fromEntries(
        Object.entries(oracle.roles ?? {}).map(([role, selector]) => [role, [selector]]),
      ),
      commentItems: [...(oracle.commentItems ?? [])],
      commentControls: [...(oracle.commentControls ?? [])],
      commentIgnored: [...proposal.commentIgnored],
    },
  };
}

async function candidateOracleProjectionEvidence(
  page,
  layout,
  oracle,
  userscriptContent,
  seed,
  targetUrl,
) {
  if (oracle?.structuralOk !== true && oracle?.ok !== true) {
    return {
      semanticProjectionCount: 0,
      exactCandidateCount: 0,
      coMatchCount: 0,
      aliases: [],
    };
  }
  const candidateLayout = candidateOracleLayout(layout, oracle, targetUrl);
  const projection = await countExistingApprovedLayoutMatches(
    page,
    layout,
    userscriptContent,
    seed,
    [candidateLayout],
  );
  const candidateId = candidateLayout.id;
  const exactCandidateCount = projection.classes.filter((projectionClass) =>
    projectionClass.aliases.includes(candidateId)).length;
  return {
    semanticProjectionCount: projection.semanticProjectionCount,
    exactCandidateCount,
    coMatchCount: Math.max(0, projection.semanticProjectionCount - 1),
    aliases: projection.classes.map((projectionClass) => projectionClass.aliases),
    oracleExecutionWorld: projection.oracleExecutionWorld,
  };
}

function staticProjectionContract(layout, approvedMatchId) {
  if (approvedMatchId === layout.id) return layout;
  const prefix = `${layout.id}--`;
  const variantId = approvedMatchId?.startsWith(prefix)
    ? approvedMatchId.slice(prefix.length)
    : null;
  const variant = layout.variants?.find((item) => item.id === variantId);
  if (!variant) return layout;
  const shallow = [...new Set([
    ...(variant.required_groups?.title ?? []),
    ...(variant.required_groups?.comments ?? []),
  ])].sort();
  const deepRoleNames = ["body"];
  if (variant.required_roles?.includes("product")) deepRoleNames.push("product");
  const deep = [...new Set([
    ...deepRoleNames.flatMap((role) => variant.required_groups?.[role] ?? []),
    ...(variant.role_projection?.product?.selectors ?? []),
    ...(variant.comment_contract?.items ?? []),
    ...(variant.comment_contract?.controls ?? []),
  ])].sort();
  return {
    ...variant,
    domain: layout.domain,
    ancestor_markers: [...new Set([...shallow, ...deep])].sort(),
    preserve_deep: deep,
    preserve_shallow: shallow,
  };
}

async function auditCandidateOverlay(
  page,
  layout,
  candidate,
  target,
  userscriptContent,
) {
  const approvedProjection = await countExistingApprovedLayoutMatches(
    page,
    layout,
    userscriptContent,
    targetAlgumonSeed(candidate.siteId, target),
  );
  const candidateApprovedId = `${candidate.layoutId}--${candidate.variantId}`;
  const contract = await evaluateInIsolatedWorld(
    page,
    ({ payload, algumon, sourceBytes }) => {
      const originalModule = Object.getOwnPropertyDescriptor(globalThis, "module");
      if (originalModule && originalModule.configurable !== true) {
        throw new Error("page has a non-configurable global module");
      }
      const moduleRecord = { exports: {} };
      Object.defineProperty(globalThis, "module", {
        value: moduleRecord,
        configurable: true,
        enumerable: false,
        writable: false,
      });
      let api;
      try {
        (0, eval)(sourceBytes);
        api = moduleRecord.exports;
      } finally {
        delete globalThis.module;
        if (originalModule) Object.defineProperty(globalThis, "module", originalModule);
      }
      if (typeof api?.titleEvidence !== "function") {
        throw new Error("verified userscript did not export titleEvidence");
      }
      const unique = (root, selectors) => {
        const nodes = new Set();
        for (const selector of selectors ?? []) {
          try {
            root.querySelectorAll(selector).forEach((element) => nodes.add(element));
          } catch {
            return [];
          }
        }
        return [...nodes];
      };
      let pageRoots = [];
      try {
        pageRoots = [...document.querySelectorAll(payload.pageRoot)];
      } catch {
        pageRoots = [];
      }
      const pageRoot = pageRoots.length === 1 ? pageRoots[0] : null;
      const roleNodes = Object.fromEntries(payload.requiredRoles.map((role) => [
        role,
        pageRoot ? unique(pageRoot, payload.roles[role]) : [],
      ]));
      const roleEvidence = Object.fromEntries(payload.requiredRoles.map((role) => {
        const nodes = roleNodes[role];
        return [
          role,
          {
            selector: payload.roles[role].join(", "),
            count: nodes.length,
            containedInPageRoot:
              Boolean(pageRoot) &&
              nodes.length === 1 &&
              (nodes[0] === pageRoot || pageRoot.contains(nodes[0])),
          },
        ];
      }));
      const titleNodes = pageRoot ? unique(pageRoot, payload.roles.title) : [];
      const commentMounts = pageRoot ? unique(pageRoot, payload.roles.comments) : [];
      const commentIgnored = commentMounts.length === 1
        ? unique(commentMounts[0], payload.commentIgnored ?? [])
        : [];
      const insideIgnoredCommentSubtree = (element) =>
        commentIgnored.some(
          (ignored) => ignored === element || ignored.contains(element),
        );
      const rawCommentItems = commentMounts.length === 1
        ? unique(commentMounts[0], payload.commentItems)
        : [];
      const commentItems = rawCommentItems.filter(
        (element) => !insideIgnoredCommentSubtree(element),
      );
      const rawCommentControls = commentMounts.length === 1
        ? unique(commentMounts[0], payload.commentControls)
        : [];
      const commentControls = rawCommentControls.filter(
        (element) => !insideIgnoredCommentSubtree(element),
      );
      const commentMount = commentMounts.length === 1 ? commentMounts[0] : null;
      const classifiedCommentRoots = [
        ...commentItems,
        ...commentControls,
        ...commentIgnored,
      ];
      const exactItemControlOverlapCount = rawCommentItems.filter(
        (item) => rawCommentControls.includes(item),
      ).length;
      const ignoredClassificationOverlapCount = [
        ...rawCommentItems,
        ...rawCommentControls,
      ].filter((classified) =>
        commentIgnored.some(
          (ignored) =>
            ignored === classified ||
            ignored.contains(classified) ||
            classified.contains(ignored),
        ),
      ).length;
      const classificationOverlapCount =
        exactItemControlOverlapCount + ignoredClassificationOverlapCount;
      const hasUnclassifiedCommentContent = commentMount
        ? [...commentMount.childNodes].some(function inspect(node) {
            if (node.nodeType === Node.TEXT_NODE) {
              return Boolean(api.normalizeText(node.data));
            }
            if (
              node.nodeType !== Node.ELEMENT_NODE ||
              node.matches("script, style, template, noscript")
            ) {
              return false;
            }
            if (
              classifiedCommentRoots.some(
                (root) => root === node || root.contains(node),
              )
            ) {
              return false;
            }
            const containsClassifiedRoot = classifiedCommentRoots.some(
              (root) => node.contains(root),
            );
            if ([...node.childNodes].some(inspect)) {
              return true;
            }
            if (containsClassifiedRoot) return false;
            return node.matches(
              "img, picture, video, iframe, table, button, input, " +
                "textarea, select, [contenteditable='true']",
            );
          })
        : true;
      const titleResult = titleNodes.length === 1
        ? api.titleEvidence(document, algumon?.title, titleNodes[0].textContent)
        : {
            ok: false,
            score: 0,
            mode: "missing",
            metadata: { sourceCount: 0, sourceKinds: [] },
          };
      const commentComparable =
        Number.isInteger(algumon?.commentCount) && commentMounts.length === 1;
      const countConsistency = commentComparable
        ? commentLowerBoundConsistency(commentItems.length, algumon.commentCount)
        : null;
      const visible = (element) => {
        const style = getComputedStyle(element);
        return style.display !== "none" && style.visibility !== "hidden" &&
          Number(style.opacity) !== 0 &&
          [...element.getClientRects()].some((rect) => rect.width > 0 && rect.height > 0);
      };
      const bodyNode = roleNodes.body?.length === 1 ? roleNodes.body[0] : null;
      const productNodes = pageRoot
        ? unique(pageRoot, payload.roleProjection.product.selectors)
        : [];
      const productNode = productNodes.length === 1 ? productNodes[0] : null;
      const bodyIgnored = bodyNode
        ? unique(bodyNode, payload.roleProjection.body.ignored)
        : [];
      const productIgnored = productNode
        ? unique(productNode, payload.roleProjection.product.ignored)
        : [];
      const ignoredContentOverlapCount = [...bodyIgnored, ...productIgnored]
        .filter((root, index, roots) => roots.some((other, otherIndex) =>
          index !== otherIndex &&
          (root === other || root.contains(other) || other.contains(root)))).length;
      const productCardinality = payload.roleProjection.product.cardinality;
      const productCardinalityOk =
        (productCardinality === "zero" && productNodes.length === 0) ||
        (productCardinality === "required" && productNodes.length === 1) ||
        (productCardinality === "optional" && productNodes.length <= 1);
      const observedProductOrder = productNode && bodyNode
        ? bodyNode.compareDocumentPosition(productNode) & Node.DOCUMENT_POSITION_FOLLOWING
          ? "after-body"
          : productNode.compareDocumentPosition(bodyNode) & Node.DOCUMENT_POSITION_FOLLOWING
            ? "before-body"
            : null
        : null;
      const productOrderOk = !productNode ||
        observedProductOrder === payload.roleProjection.product.order;
      return {
        pageRootCount: pageRoots.length,
        roles: roleEvidence,
        titleConsistency: Number(titleResult.score.toFixed(3)),
        titleConsistencyOk: titleResult.ok === true,
        titleConsistencyMode: algumon?.title ? titleResult.mode
          : String(titleResult.mode).replace(/^algumon(?:-referrer)?/u, "native-article"),
        titleMetadataSourceCount: titleResult.metadata.sourceCount,
        titleMetadataSourceKinds: titleResult.metadata.sourceKinds,
        titleConsistent: titleResult.ok === true,
        commentItemCount: commentItems.length,
        ignoredSelectors: [...(payload.commentIgnored ?? [])].sort(),
        ignoredCount: commentIgnored.length,
        classificationOverlapCount,
        visibleIgnoredCount: commentIgnored.filter(visible).length,
        unclassifiedCommentContentCount:
          hasUnclassifiedCommentContent ? 1 : 0,
        emptyStateSelector:
          commentItems.length === 0 && !hasUnclassifiedCommentContent
            ? payload.roles.comments[0]
            : null,
        emptyStateCount:
          commentItems.length === 0 && !hasUnclassifiedCommentContent ? 1 : 0,
        countComparable: commentComparable,
        countConsistency:
          commentComparable ? Number(countConsistency.toFixed(3)) : null,
        countConsistent:
          !commentComparable || countConsistency === 1,
        roleProjection: payload.roleProjection,
        productCount: productNodes.length,
        productCardinalityOk,
        productOrder: observedProductOrder,
        productOrderOk,
        contentIgnoredCount: bodyIgnored.length + productIgnored.length,
        contentIgnoredVisibleCount: [...bodyIgnored, ...productIgnored].filter(visible).length,
        ignoredContentOverlapCount,
      };
    },
    {
      payload: candidate,
      algumon: target.algumon ?? null,
      sourceBytes: userscriptContent,
    },
  );
  const candidateProjection = approvedProjection.classes.find((projectionClass) =>
    projectionClass.aliases.includes(candidateApprovedId));
  return {
    ...contract,
    oracleExecutionWorld: ORACLE_EXECUTION_WORLD,
    pageRootSelector: candidate.pageRoot,
    itemSelector: candidate.commentItems[0],
    candidateApprovedId,
    candidateMatchCount: candidateProjection ? 1 : 0,
    approvedVariantCount: approvedProjection.semanticProjectionCount,
    semanticProjectionCount: approvedProjection.semanticProjectionCount,
    projectionAliases: approvedProjection.classes.map((projectionClass) =>
      projectionClass.aliases),
    coMatchCount: Math.max(0, approvedProjection.semanticProjectionCount - 1),
    otherApprovedMatchCount:
      approvedProjection.classes.filter((projectionClass) =>
        !projectionClass.aliases.includes(candidateApprovedId)).length,
  };
}

function candidateOverlayFailures(
  overlay,
  requiredRoles,
  candidateProofRequired = true,
) {
  const failures = [];
  if (overlay.approvedVariantCount !== 1) {
    failures.push(`total approved match count is ${overlay.approvedVariantCount}`);
  }
  if (overlay.oracleExecutionWorld !== ORACLE_EXECUTION_WORLD) {
    failures.push("candidate overlay was not measured in the Chromium isolated world");
  }
  if (overlay.coMatchCount !== 0) {
    failures.push(`candidate co-match count is ${overlay.coMatchCount}`);
  }
  if (overlay.candidateMatchCount === 0 && !candidateProofRequired) {
    return failures;
  }
  if (overlay.candidateMatchCount !== 1) {
    failures.push(`candidate approved match count is ${overlay.candidateMatchCount}`);
  }
  if (overlay.pageRootCount !== 1) {
    failures.push(`candidate page-root count is ${overlay.pageRootCount}`);
  }
  for (const role of requiredRoles) {
    const evidence = overlay.roles?.[role];
    if (evidence?.count !== 1 || evidence?.containedInPageRoot !== true) {
      failures.push(`candidate ${role} is not one contained node`);
    }
  }
  if (overlay.titleConsistent !== true) {
    failures.push("candidate title is inconsistent with Algumon");
  }
  if (overlay.countComparable === true && overlay.countConsistent !== true) {
    failures.push("candidate comment count is inconsistent with Algumon");
  }
  if (overlay.unclassifiedCommentContentCount !== 0) {
    failures.push("candidate comments contain unclassified content");
  }
  if (overlay.classificationOverlapCount !== 0) {
    failures.push("candidate comment classifications overlap");
  }
  if (overlay.visibleIgnoredCount !== 0) {
    failures.push("candidate ignored comment UI remained visible");
  }
  if (overlay.productCardinalityOk !== true) {
    failures.push("candidate product cardinality violates RoleProjection");
  }
  if (overlay.productOrderOk !== true) {
    failures.push("candidate product order violates RoleProjection");
  }
  if (overlay.contentIgnoredVisibleCount !== 0) {
    failures.push("candidate ignored body/product UI remained visible");
  }
  if (overlay.ignoredContentOverlapCount !== 0) {
    failures.push("candidate body/product ignored roots overlap");
  }
  if (
    overlay.commentItemCount === 0 &&
    (overlay.emptyStateSelector === null || overlay.emptyStateCount !== 1)
  ) {
    failures.push("candidate empty comments lack exact empty-state evidence");
  }
  return failures;
}

function semanticOracleEvidence(oracle, target) {
  if (oracle.verificationMode === "registered-sample") {
    const exact = target.source === "sample" && oracle.ok === true &&
      oracle.containment === true && oracle.approvedProjection?.count === 1 &&
      oracle.approvedProjection.loadedCommentItemsExact === true &&
      oracle.approvedProjection.commentItemContainment === true &&
      oracle.approvedProjection.commentControlsClassified === true;
    return {
      ...oracle,
      ok: exact,
      structuralOk: exact,
      titleNormalized: undefined,
      titleSha256: oracle.titleNormalized ? sha256(oracle.titleNormalized) : null,
      commentStructure: {
        mountSelector: oracle.roles.comments,
        mountCount: oracle.cardinality.comments,
        itemSelector: oracle.commentItems.join(", "),
        itemCount: oracle.commentItemCount,
        dormantItemCount: oracle.dormantCommentItemCount,
        ignoredSelectors: oracle.commentIgnored,
        ignoredCount: oracle.ignoredCommentCount,
        evidenceSource: "exact-approved-loaded-dom-items",
      },
      // No aggregator claim is invented for direct sample URLs. These records
      // prove the installed contract, not a candidate eligible for promotion.
      algumon: null,
      candidateEligible: false,
    };
  }
  const algumonTitle = target.algumon?.title ?? "";
  const nativeArticle = target.source === "sample" &&
    target.readerRouteRegistered === true && oracle.verificationMode === "native-article-discovery";
  const algumonCommentCount = target.algumon?.commentCount ?? null;
  const titleSimilarity = Number(oracle.seedTitleSimilarity ?? 0);
  const titleComparable = Boolean(oracle.titleNormalized && algumonTitle);
  const commentComparable =
    Number.isInteger(oracle.commentItemCount) && Number.isInteger(algumonCommentCount);
  const commentTolerance = commentComparable ? 0 : null;
  const titleConsistency = titleComparable || nativeArticle
    ? Number(titleSimilarity.toFixed(3))
    : 0;
  const countConsistency = commentComparable
    ? commentLowerBoundConsistency(oracle.commentItemCount, algumonCommentCount)
    : null;
  const titleConsistent = oracle.seedTitleConsistencyOk === true;
  const commentConsistent =
    !commentComparable || countConsistency === 1;
  const commentStructure = {
    mountSelector: oracle.roles.comments,
    mountCount: oracle.cardinality.comments,
    itemSelector: oracle.commentItems[0],
    itemCount: oracle.commentItemCount,
    ignoredSelectors: oracle.commentIgnored,
    ignoredCount: oracle.ignoredCommentCount,
    classificationOverlapCount: oracle.classificationOverlapCount,
    unclassifiedContentCount: oracle.unclassifiedCommentContentCount,
    emptyStateSelector: oracle.emptyStateSelector,
    emptyStateCount: oracle.emptyStateCount,
  };
  const exactCommentStructure =
    commentStructure.mountCount === 1 &&
    typeof commentStructure.itemSelector === "string" &&
    commentStructure.itemSelector.length > 0 &&
    Number.isInteger(commentStructure.itemCount) &&
    commentStructure.itemCount >= 0 &&
    Array.isArray(commentStructure.ignoredSelectors) &&
    Number.isInteger(commentStructure.ignoredCount) &&
    commentStructure.ignoredCount >= 0 &&
    commentStructure.classificationOverlapCount === 0 &&
    commentStructure.unclassifiedContentCount === 0 &&
    (commentStructure.itemCount > 0
      ? commentStructure.emptyStateSelector === null &&
        commentStructure.emptyStateCount === 0
      : commentStructure.emptyStateSelector === commentStructure.mountSelector &&
        commentStructure.emptyStateCount === 1);
  return {
    ok:
      oracle.ok === true &&
      oracle.containment === true &&
      (target.source === "algumon-latest" || nativeArticle) &&
      titleConsistent &&
      commentConsistent &&
      exactCommentStructure,
    structuralOk: oracle.ok === true,
    verificationMode: oracle.verificationMode,
    reason: oracle.reason,
    projectionTupleCount: oracle.projectionTupleCount,
    oracleSource: oracle.oracleSource,
    oracleExecutionWorld: oracle.oracleExecutionWorld,
    pageRoot: oracle.pageRoot,
    pageRootCount: oracle.pageRootCount,
    roles: oracle.roles,
    cardinality: oracle.cardinality,
    metrics: oracle.metrics,
    commentItems: oracle.commentItems,
    commentControls: oracle.commentControls,
    commentIgnored: oracle.commentIgnored,
    commentItemCount: oracle.commentItemCount,
    commentStructure,
    productOrder: oracle.productOrder ?? null,
    existingPolicy: oracle.existingPolicy ?? null,
    policyProposal: oracle.policyProposal ?? null,
    containment: oracle.containment,
    titleSha256: oracle.titleNormalized ? sha256(oracle.titleNormalized) : null,
    algumon: {
      redirectPath: target.algumon
        ? new URL(target.algumon.redirectUrl).pathname
        : null,
      titleSha256: algumonTitle ? sha256(algumonTitle) : null,
      titleComparable,
      titleConsistency,
      titleConsistencyOk: titleConsistent,
      titleConsistencyMode: oracle.seedTitleConsistencyMode ?? "missing",
      titleMetadataSourceCount: oracle.seedTitleMetadataSourceCount ?? 0,
      titleMetadataSourceKinds: oracle.seedTitleMetadataSourceKinds ?? [],
      titleConsistent,
      commentComparable,
      commentCount: algumonCommentCount,
      commentCountRelation: commentComparable ? "algumon-lower-bound" : null,
      commentTolerance,
      countConsistency,
      commentConsistent,
    },
  };
}

function semanticOracleContractFailures(evidence) {
  const failures = [];
  if (evidence?.oracleSource !== "verified-userscript-export") {
    failures.push("semantic oracle source is not the verified userscript export");
  }
  if (evidence?.oracleExecutionWorld !== ORACLE_EXECUTION_WORLD) {
    failures.push("semantic oracle did not run in the isolated execution world");
  }
  if (evidence?.structuralOk !== true) {
    failures.push("semantic oracle could not prove one complete projection tuple");
  }
  if (evidence?.verificationMode === "registered-sample") {
    if (evidence.ok !== true || evidence.candidateEligible !== false ||
      evidence.policyProposal !== null || evidence.approvedProjection?.count !== 1 ||
      evidence.approvedProjection?.loadedCommentItemsExact !== true ||
      evidence.approvedProjection?.commentItemContainment !== true ||
      evidence.approvedProjection?.commentControlsClassified !== true) {
      failures.push("registered sample lacks one exact approved article/comment projection");
    }
    return failures;
  }
  if (!independentPolicyProposalIsComplete(evidence)) {
    failures.push("semantic oracle policy proposal is incomplete or not independently bounded");
  }
  if (evidence?.ok !== true) {
    failures.push("semantic oracle title/comment completeness contract failed");
  }
  return failures;
}

async function auditStaticProjection(page, layout) {
  const hideSelector = buildProjectedHideSelector(layout);
  const verdict = await evaluateInIsolatedWorld(
    page,
    ({ contract, projectedHideSelector }) => {
      const visible = (element) => {
        const style = window.getComputedStyle(element);
        return (
          style.display !== "none" &&
          style.visibility !== "hidden" &&
          Number(style.opacity) !== 0 &&
          [...element.getClientRects()].some((rect) => rect.width > 0 && rect.height > 0)
        );
      };
      const matchesAny = (element, selectors) =>
        selectors.some((selector) => element.matches(selector));
      const insideAny = (element, selectors) =>
        selectors.some((selector) =>
          element.matches(selector) || Boolean(element.closest(selector)),
        );
      const statsFor = (selectors) => {
        const nodes = new Set();
        for (const selector of selectors) {
          for (const element of document.querySelectorAll(selector)) nodes.add(element);
        }
        return {
          count: nodes.size,
          visibleCount: [...nodes].filter(visible).length,
        };
      };
      const pseudoTextLength = (element) => ["::before", "::after"]
        .map((pseudo) => window.getComputedStyle(element, pseudo).content)
        .filter((content) => content && content !== "none" && content !== "normal" && content !== '""')
        .join("").length;

      let hiddenNodes;
      try {
        hiddenNodes = [...document.querySelectorAll(projectedHideSelector)];
      } catch (error) {
        return { selectorError: String(error) };
      }
      const preservedNodes = new Set();
      for (const selector of contract.preserveDeep) {
        for (const element of document.querySelectorAll(selector)) {
          preservedNodes.add(element);
          for (const descendant of element.querySelectorAll("*")) preservedNodes.add(descendant);
        }
      }
      for (const selector of contract.preserveShallow) {
        for (const element of document.querySelectorAll(selector)) preservedNodes.add(element);
      }
      const conflicts = hiddenNodes.filter((element) => preservedNodes.has(element));
      for (const element of hiddenNodes) {
        element.setAttribute("data-hotdeal-audit-static-hidden", "1");
      }
      const style = document.createElement("style");
      style.id = "hotdeal-audit-static-projection";
      style.textContent =
        "[data-hotdeal-audit-static-hidden='1']{display:none!important}";
      document.documentElement.append(style);

      const groupStats = Object.fromEntries(
        Object.entries(contract.requiredGroups).map(([role, selectors]) => [
          role,
          statsFor(selectors),
        ]),
      );
      const markerStats = statsFor(contract.ancestorMarkers);
      const preserveStats = {
        deep: statsFor(contract.preserveDeep),
        shallow: statsFor(contract.preserveShallow),
      };
      const commentContractStats = contract.commentContract
        ? {
            mount: statsFor(contract.commentContract.mount),
            items: statsFor(contract.commentContract.items),
            allowEmpty: contract.commentContract.allow_empty,
          }
        : null;
      const directTextLeaks = [];
      for (const element of [document.body, ...document.body.querySelectorAll("*")]) {
        if (!visible(element)) continue;
        const isAllowedContent =
          insideAny(element, contract.preserveDeep) ||
          matchesAny(element, contract.preserveShallow);
        if (isAllowedContent) continue;
        const textLength = [...element.childNodes]
          .filter((node) => node.nodeType === Node.TEXT_NODE)
          .map((node) => (node.textContent ?? "").replace(/\s+/gu, " ").trim())
          .filter(Boolean)
          .join(" ").length + pseudoTextLength(element);
        if (textLength > 0) {
          directTextLeaks.push({
            tag: element.tagName.toLowerCase(),
            id: element.id || null,
            classes: [...element.classList].slice(0, 4),
            textLength,
          });
        }
      }
      return {
        hideSelector: projectedHideSelector,
        hiddenCount: hiddenNodes.length,
        conflictCount: conflicts.length,
        markerStats,
        preserveStats,
        commentContractStats,
        groupStats,
        directTextLeaks: directTextLeaks.slice(0, 50),
        directVisibleTextLeakCount: directTextLeaks.length,
      };
    },
    {
      contract: {
        ancestorMarkers: layout.ancestor_markers,
        preserveDeep: layout.preserve_deep,
        preserveShallow: layout.preserve_shallow,
        requiredGroups: layout.required_groups,
        commentContract: layout.comment_contract ?? null,
      },
      projectedHideSelector: hideSelector,
    },
  );
  return { ...verdict, oracleExecutionWorld: ORACLE_EXECUTION_WORLD };
}

function staticProjectionFailures(projection) {
  const failures = [];
  if (projection.selectorError) failures.push(`invalid projected selector: ${projection.selectorError}`);
  if (!projection.selectorError && projection.markerStats.count === 0) {
    failures.push("no ancestor marker exists");
  }
  if (projection.conflictCount > 0) {
    failures.push(`${projection.conflictCount} preserved nodes are hidden by static projection`);
  }
  for (const [role, stats] of Object.entries(projection.groupStats ?? {})) {
    if (!stats || stats.count === 0) failures.push(`${role} group is absent`);
    else if (stats.visibleCount === 0) failures.push(`${role} group is not visible after projection`);
  }
  if (projection.commentContractStats) {
    if (projection.commentContractStats.mount.count === 0) {
      failures.push("comment mount is absent");
    }
    if (
      !projection.commentContractStats.allowEmpty &&
      projection.commentContractStats.items.count === 0
    ) {
      failures.push("comment items are required but absent");
    }
  }
  if (projection.directVisibleTextLeakCount > 0) {
    failures.push(
      `${projection.directVisibleTextLeakCount} direct visible text leaks remain outside preserved content`,
    );
  }
  return failures;
}

function validateDiagnostics(diagnostics, requiredRoles) {
  const failures = [];
  if (!diagnostics || typeof diagnostics !== "object" || Array.isArray(diagnostics)) {
    return ["window.__HOTDEAL_FOCUS_DIAGNOSTICS__ is missing or invalid"];
  }
  const allowedTopKeys = new Set([
    "protocolVersion",
    "state",
    "targetReason",
    "roles",
    "layoutAliases",
    "semanticProjectionCount",
    "standaloneCascadeProof",
    "commentControlProjection",
    "visibleLeakCount",
    "reconciliationFailure",
  ]);
  const unexpectedTopKeys = Object.keys(diagnostics).filter((key) => !allowedTopKeys.has(key));
  if (unexpectedTopKeys.length > 0) {
    failures.push(`diagnostics contains non-contract keys: ${unexpectedTopKeys.join(", ")}`);
  }
  const reconciliation = diagnostics.reconciliationFailure;
  if (reconciliation !== undefined && reconciliation !== null && (
    typeof reconciliation !== "object" || Array.isArray(reconciliation) ||
    canonicalJson(Object.keys(reconciliation).sort()) !== canonicalJson(["reason", "role"]) ||
    !["body", "product"].includes(reconciliation.role) ||
    !["role-root", "descendant-bound", "configured-overlap", "autonomous-bound",
      "unsafe-projection", "marker-record"].includes(reconciliation.reason)
  )) {
    failures.push("diagnostics.reconciliationFailure is not an exact bounded role failure");
  }
  if (diagnostics.protocolVersion !== READER_GATE_PROTOCOL_VERSION) {
    failures.push(
      `diagnostics.protocolVersion must equal reader gate protocol ${READER_GATE_PROTOCOL_VERSION}`,
    );
  }
  if (diagnostics.state !== "ready") failures.push(`diagnostics.state is ${diagnostics.state ?? "missing"}`);
  if (
    typeof diagnostics.targetReason !== "string" ||
    !/^[a-zA-Z0-9:_-]{1,80}$/u.test(diagnostics.targetReason)
  ) {
    failures.push("diagnostics.targetReason must be a non-sensitive token");
  }
  if (!Number.isInteger(diagnostics.visibleLeakCount) || diagnostics.visibleLeakCount !== 0) {
    failures.push(`diagnostics.visibleLeakCount is ${diagnostics.visibleLeakCount ?? "missing"}`);
  }
  const standaloneProof = diagnostics.standaloneCascadeProof;
  if (
    !standaloneProof ||
    typeof standaloneProof !== "object" ||
    Array.isArray(standaloneProof) ||
    canonicalJson(Object.keys(standaloneProof).sort()) !== canonicalJson([
      "authority",
      "frameCount",
      "nonceBound",
      "unownedHidden",
    ].sort()) ||
    standaloneProof.authority !== "userscript-runtime-style" ||
    standaloneProof.frameCount !== 2 ||
    standaloneProof.nonceBound !== true ||
    standaloneProof.unownedHidden !== true
  ) {
    failures.push("diagnostics.standaloneCascadeProof is not the exact two-frame proof");
  }
  if (
    !Number.isInteger(diagnostics.semanticProjectionCount) ||
    diagnostics.semanticProjectionCount !== 1
  ) {
    failures.push(
      `diagnostics.semanticProjectionCount is ${diagnostics.semanticProjectionCount ?? "missing"}`,
    );
  }
  if (
    !Array.isArray(diagnostics.layoutAliases) ||
    diagnostics.layoutAliases.length < 1 ||
    new Set(diagnostics.layoutAliases).size !== diagnostics.layoutAliases.length ||
    diagnostics.layoutAliases.some(
      (alias) => typeof alias !== "string" || !/^[a-z0-9][a-z0-9-]{0,79}$/u.test(alias),
    )
  ) {
    failures.push("diagnostics.layoutAliases must be non-empty, unique safe layout ids");
  }
  if (!diagnostics.roles || typeof diagnostics.roles !== "object" || Array.isArray(diagnostics.roles)) {
    failures.push("diagnostics.roles is missing or invalid");
    return failures;
  }
  const allowedRoleKeys = new Set(["title", "product", "body", "comments"]);
  for (const roleName of Object.keys(diagnostics.roles)) {
    if (!allowedRoleKeys.has(roleName)) failures.push(`unexpected diagnostics role: ${roleName}`);
  }
  const allowedMetricKeys = new Set(["count", "score", "signalCount", "margin"]);
  for (const roleName of requiredRoles) {
    const role = diagnostics.roles[roleName];
    if (!role || typeof role !== "object" || Array.isArray(role)) {
      failures.push(`diagnostics role is missing: ${roleName}`);
      continue;
    }
    const unexpectedMetricKeys = Object.keys(role).filter((key) => !allowedMetricKeys.has(key));
    if (unexpectedMetricKeys.length > 0) {
      failures.push(`${roleName} diagnostics contains non-contract keys: ${unexpectedMetricKeys.join(", ")}`);
    }
    for (const metric of allowedMetricKeys) {
      if (typeof role[metric] !== "number" || !Number.isFinite(role[metric])) {
        failures.push(`${roleName}.${metric} must be a finite number`);
      }
    }
    if (!(role.count >= 1)) failures.push(`${roleName}.count must be at least 1`);
    if (!(role.score > 0)) failures.push(`${roleName}.score must be positive`);
    if (!(role.signalCount >= 1)) failures.push(`${roleName}.signalCount must be at least 1`);
    if (!(role.margin >= 0)) failures.push(`${roleName}.margin must not be negative`);
  }
  return failures;
}

async function auditUserscriptGate(
  page,
  requiredRoles,
  timeoutMs,
  runtimeExpectation = "relay-positive",
  allowedCommentControlSelectorDigests = [],
) {
  await page
    .waitForFunction(
      ({ expectation, protocolVersion, preauthorizedControlSchemaVersion }) => {
        const html = document.documentElement;
        const state = html.getAttribute("data-hotdeal-focus-state");
        const status = html.getAttribute("data-hotdeal-focus-status");
        const paintProbe = window.__HOTDEAL_FOCUS_PAINT_PROBE__;
        const sampled = Number.isInteger(paintProbe?.sampleCount) &&
          paintProbe.sampleCount >= 1;
        const terminal = state === "blocked" &&
          String(status ?? "").startsWith("terminal-");
        if (terminal) return sampled;
        // Direct navigations deliberately remain on the publisher page while
        // semantic provenance preflight is unlocked. One document-start sample
        // is enough to audit that inactive state; waiting for a terminal lock
        // would turn the normal publisher-visible path into a timeout.
        if (expectation === "direct-negative") return sampled;
        const diagnostics = window.__HOTDEAL_FOCUS_DIAGNOSTICS__;
        const preauthorized = window.__HOTDEAL_FOCUS_PREAUTHORIZED_CONTROL__;
        return sampled &&
          paintProbe.firstReadyFrame !== null &&
          html.classList.contains("hdf-v2-ready") &&
          html.getAttribute("data-hotdeal-focus-ready") === "1" &&
          html.getAttribute("data-hotdeal-focus-protocol") === String(protocolVersion) &&
          state === "ready" &&
          status === "ready" &&
          !html.classList.contains("hdf-v2-lock") &&
          !html.hasAttribute("data-hotdeal-focus-lock") &&
          diagnostics?.state === "ready" &&
          diagnostics?.semanticProjectionCount === 1 &&
          Array.isArray(diagnostics?.layoutAliases) &&
          diagnostics.layoutAliases.length >= 1 &&
          diagnostics?.standaloneCascadeProof?.authority === "userscript-runtime-style" &&
          diagnostics?.standaloneCascadeProof?.frameCount === 2 &&
          diagnostics?.standaloneCascadeProof?.nonceBound === true &&
          diagnostics?.standaloneCascadeProof?.unownedHidden === true &&
          preauthorized?.kind === "preauthorized-userscript-style-control" &&
          preauthorized?.schemaVersion === preauthorizedControlSchemaVersion &&
          preauthorized?.gmAddElementCalls === 1 &&
          document.querySelectorAll(
            'style[data-hotdeal-focus-runtime-style="2"]',
          ).length === 1;
      },
      {
        expectation: runtimeExpectation,
        protocolVersion: READER_GATE_PROTOCOL_VERSION,
        preauthorizedControlSchemaVersion:
          PREAUTHORIZED_ADGUARD_CONTROL_SCHEMA_VERSION,
      },
      { timeout: timeoutMs },
    )
    .catch(() => {});

  return page.evaluate(({ rolesToRequire, allowedControlSelectorDigests }) => {
    const visible = (element) => {
      const style = window.getComputedStyle(element);
      return (
        style.display !== "none" &&
        style.visibility !== "hidden" &&
        Number(style.opacity) !== 0 &&
        [...element.getClientRects()].some((rect) => rect.width > 0 && rect.height > 0)
      );
    };
    const exactlyOwned = (element) =>
      element.classList.contains("hdf-v2-keep") &&
      element.hasAttribute("data-hotdeal-focus-keep");
    const hasVisibleOwnedDescendant = (element) =>
      [...element.querySelectorAll(".hdf-v2-keep[data-hotdeal-focus-keep]")]
        .some(visible);
    const logicallyVisible = (element) =>
      visible(element) || hasVisibleOwnedDescendant(element);
    const html = document.documentElement;
    const pseudoTextLength = (element) => ["::before", "::after"]
      .map((pseudo) => window.getComputedStyle(element, pseudo).content)
      .filter((content) => content && content !== "none" && content !== "normal" && content !== '""')
      .join("").length;
    const state = html.getAttribute("data-hotdeal-focus-state");
    const status = html.getAttribute("data-hotdeal-focus-status");
    const ready =
      html.classList.contains("hdf-v2-ready") &&
      html.getAttribute("data-hotdeal-focus-ready") === "1" &&
      html.getAttribute("data-hotdeal-focus-protocol") === "2" &&
      state === "ready" &&
      status === "ready" &&
      !html.classList.contains("hdf-v2-lock") &&
      !html.hasAttribute("data-hotdeal-focus-lock");
    const rootStyle = window.getComputedStyle(html);
    const globalPaintLockIntact =
      !ready &&
      html.classList.contains("hdf-v2-lock") &&
      html.getAttribute("data-hotdeal-focus-lock") === "1" &&
      rootStyle.transitionProperty === "none" &&
      rootStyle.animationName === "none" &&
      rootStyle.visibility === "hidden" &&
      rootStyle.contentVisibility === "hidden" &&
      Number(rootStyle.opacity) === 0 &&
      rootStyle.clipPath === "inset(50%)" &&
      rootStyle.pointerEvents === "none" &&
      html.style.getPropertyValue("opacity") === "0" &&
      html.style.getPropertyPriority("opacity") === "important" &&
      html.style.getPropertyValue("clip-path") === "inset(50%)" &&
      html.style.getPropertyPriority("clip-path") === "important" &&
      html.style.getPropertyValue("visibility") === "hidden" &&
      html.style.getPropertyPriority("visibility") === "important" &&
      html.style.getPropertyValue("content-visibility") === "hidden" &&
      html.style.getPropertyPriority("content-visibility") === "important";
    const visibleWithoutKeep = [...document.body.querySelectorAll("*")]
      .filter(visible)
      .filter((element) => !exactlyOwned(element))
      .map((element) => ({
        tag: element.tagName.toLowerCase(),
        id: element.id || null,
        classes: [...element.classList].slice(0, 4),
      }));
    const roleStats = Object.fromEntries(
      rolesToRequire.map((role) => {
        const nodes = [
          ...document.querySelectorAll(
            `.hdf-v2-role-${role}[data-hotdeal-focus-role="${role}"]`,
          ),
        ];
        return [
          role,
          {
            count: nodes.length,
            selfVisibleCount: nodes.filter(visible).length,
            visibleOwnedDescendantCount: nodes.filter(hasVisibleOwnedDescendant).length,
            visibleCount: nodes.filter(logicallyVisible).length,
            allKept: nodes.every(exactlyOwned),
          },
        ];
      }),
    );
    const summarizeProjectedRole = (role) => {
      const nodes = [
        ...document.querySelectorAll(
          `.hdf-v2-role-${role}[data-hotdeal-focus-role="${role}"]`,
        ),
      ];
      const visibleCount = nodes.filter(visible).length;
      const commentMounts = role === "comment-item" ? [...document.querySelectorAll(
        '.hdf-v2-role-comments[data-hotdeal-focus-role="comments"]',
      )] : [];
      const approvedDormantCount = nodes.filter((element) =>
        !visible(element) && exactlyOwned(element) &&
        element.classList.contains("hdf-v2-role-comment-dormant") &&
        commentMounts.some((mount) => exactlyOwned(mount) && mount.contains(element) &&
          Boolean(mount.getAttribute("data-hotdeal-focus-keep")) &&
          element.getAttribute("data-hotdeal-focus-keep") ===
            mount.getAttribute("data-hotdeal-focus-keep")),
      ).length;
      return {
        count: nodes.length,
        visibleCount,
        ...(role === "comment-item" ? { approvedDormantCount } : {}),
        allKept: nodes.every(exactlyOwned),
      };
    };
    const commentItemStats = summarizeProjectedRole("comment-item");
    const commentControlStats = summarizeProjectedRole("comment-control");
    const directTextLeaks = [];
    const keptNodes = [
      ...document.body.querySelectorAll(".hdf-v2-keep[data-hotdeal-focus-keep]"),
    ];
    for (const element of [document.body, ...keptNodes]) {
      if (!visible(element)) continue;
      const insideRole = Boolean(element.closest("[data-hotdeal-focus-role]"));
      if (insideRole) continue;
      const textLength = [...element.childNodes]
        .filter((node) => node.nodeType === Node.TEXT_NODE)
        .map((node) => (node.textContent ?? "").replace(/\s+/gu, " ").trim())
        .filter(Boolean)
        .join(" ").length + pseudoTextLength(element);
      if (textLength > 0) {
        directTextLeaks.push({
          tag: element.tagName.toLowerCase(),
          id: element.id || null,
          classes: [...element.classList].slice(0, 4),
          textLength,
        });
      }
    }
    let diagnostics = null;
    try {
      diagnostics = JSON.parse(JSON.stringify(window.__HOTDEAL_FOCUS_DIAGNOSTICS__));
    } catch {
      diagnostics = null;
    }
    let paintProbe = null;
    try {
      paintProbe = JSON.parse(JSON.stringify(window.__HOTDEAL_FOCUS_PAINT_PROBE__));
    } catch {
      paintProbe = null;
    }
    const preauthorized = window.__HOTDEAL_FOCUS_PREAUTHORIZED_CONTROL__;
    const testOnlyAdguardControl = preauthorized
      ? {
          kind: preauthorized.kind,
          schemaVersion: preauthorized.schemaVersion,
          gmAddElementCalls: preauthorized.gmAddElementCalls,
        }
      : null;
    const runtimeStyleCount = document.querySelectorAll(
      'style[data-hotdeal-focus-runtime-style="2"]',
    ).length;
    const publisherProtocolAttributes = [
      "data-hotdeal-focus-lock",
      "data-hotdeal-focus-ready",
      "data-hotdeal-focus-protocol",
      "data-hotdeal-focus-state",
      "data-hotdeal-focus-status",
      "data-hotdeal-focus-measure",
    ];
    const publisherProtocolCleared = publisherProtocolAttributes.every(
      (attribute) => !html.hasAttribute(attribute),
    ) && !html.classList.contains("hdf-v2-lock") &&
      !html.classList.contains("hdf-v2-ready");
    const hotdealMarkerCount = [html, ...document.querySelectorAll("*")].filter((element) =>
      [...element.attributes].some((attribute) =>
        attribute.name.startsWith("data-hotdeal-focus-")) ||
      [...element.classList].some((className) => className.startsWith("hdf-v2-")),
    ).length;
    const rootInlineLockCleared = [
      ["opacity", "0"],
      ["visibility", "hidden"],
      ["content-visibility", "hidden"],
      ["clip-path", "inset(50%)"],
      ["pointer-events", "none"],
    ].every(([property, value]) =>
      html.style.getPropertyValue(property) !== value ||
      html.style.getPropertyPriority(property) !== "important",
    );
    const publisherRootVisible =
      rootStyle.display !== "none" &&
      rootStyle.visibility !== "hidden" &&
      rootStyle.contentVisibility !== "hidden" &&
      Number(rootStyle.opacity) !== 0;
    const publisherVisibleContentCount = [...document.body.querySelectorAll("*")]
      .filter(visible).length;
    const activeGateSamples = (paintProbe?.samples ?? []).filter(
      (sample) => sample.readerGateActive === true || sample.paintLockIntact === true,
    );
    const unsafeGateFrameCount = Number(paintProbe?.unsafeGateFrameCount ?? 1);
    const diagnosticsInactiveOrAbsent =
      diagnostics === null || diagnostics?.state === "inactive";
    const inactivePublisherSafety = {
      applicable: !ready,
      publisherProtocolCleared,
      hotdealMarkerCount,
      rootInlineLockCleared,
      publisherRootVisible,
      publisherVisibleContentCount,
      runtimeStyleCount,
      activeGateFrameCount: activeGateSamples.length,
      unsafeGateFrameCount,
      diagnosticsInactiveOrAbsent,
      passed:
        !ready &&
        publisherProtocolCleared &&
        hotdealMarkerCount === 0 &&
        rootInlineLockCleared &&
        publisherRootVisible &&
        publisherVisibleContentCount > 0 &&
        runtimeStyleCount === 0 &&
        activeGateSamples.length === 0 &&
        unsafeGateFrameCount === 0 &&
        diagnosticsInactiveOrAbsent &&
        paintProbe?.firstReadyFrame === null,
    };
    const standaloneRuntimeCoverage = {
      applicable: ready,
      runtimeStyleCount,
      visibleUnownedCount: visibleWithoutKeep.length,
      standaloneCascadeProof: diagnostics?.standaloneCascadeProof ?? null,
      passed:
        ready &&
        runtimeStyleCount === 1 &&
        visibleWithoutKeep.length === 0 &&
        diagnostics?.standaloneCascadeProof?.authority === "userscript-runtime-style" &&
        diagnostics?.standaloneCascadeProof?.frameCount === 2 &&
        diagnostics?.standaloneCascadeProof?.nonceBound === true &&
        diagnostics?.standaloneCascadeProof?.unownedHidden === true,
    };
    return {
      ready,
      state,
      status,
      globalPaintLockIntact,
      inactivePublisherSafety,
      // Compatibility name retained for existing report consumers. It now
      // describes an intentionally inactive, publisher-visible page rather
      // than a blank terminal lock.
      blockedStateSafety: inactivePublisherSafety,
      standaloneRuntimeCoverage,
      diagnostics,
      paintProbe,
      testOnlyAdguardControl,
      runtimeStyleCount,
      publisherProtocolCleared,
      hotdealMarkerCount,
      rootInlineLockCleared,
      publisherRootVisible,
      publisherVisibleContentCount,
      roleStats,
      commentItemStats,
      commentControlStats,
      commentControlProjection: diagnostics?.commentControlProjection ?? null,
      allowedCommentControlSelectorDigests: allowedControlSelectorDigests,
      visibleWithoutKeep: visibleWithoutKeep.slice(0, 50),
      visibleWithoutKeepCount: visibleWithoutKeep.length,
      directTextLeaks: directTextLeaks.slice(0, 50),
      directVisibleTextLeakCount: directTextLeaks.length,
    };
  }, {
    rolesToRequire: requiredRoles,
    allowedControlSelectorDigests: allowedCommentControlSelectorDigests,
  });
}

function commentControlProjectionFailures(gate) {
  const failures = [];
  const projection = gate?.commentControlProjection;
  const stats = gate?.commentControlStats;
  const allowedDigests = gate?.allowedCommentControlSelectorDigests;
  const exactKeys = [
    "selectors",
    "count",
    "initiallyVisibleCount",
    "initiallyDormantCount",
    "initialShapeFingerprint",
    "selectorDigest",
    "projectionEpoch",
    "currentCount",
    "currentVisibleCount",
    "currentShapeFingerprint",
    "currentDormantApprovedCount",
    "currentProjectionValid",
  ];
  if (!projection || typeof projection !== "object" || Array.isArray(projection)) {
    return ["comment-control projection diagnostics are missing or invalid"];
  }
  if (
    canonicalJson(Object.keys(projection).sort()) !== canonicalJson(exactKeys.sort())
  ) {
    failures.push("comment-control projection diagnostics do not have the exact schema");
  }
  const selectorsAreStringArray =
    Array.isArray(projection.selectors) &&
    projection.selectors.every((selector) => typeof selector === "string");
  if (!selectorsAreStringArray) {
    failures.push("comment-control selectors must be an array of strings");
  } else {
    if (new Set(projection.selectors).size !== projection.selectors.length) {
      failures.push("comment-control selectors contain duplicate values");
    }
    if (
      canonicalJson(projection.selectors) !==
      canonicalJson([...projection.selectors].sort())
    ) {
      failures.push("comment-control selectors are not canonical sorted");
    }
    if (
      commentControlSelectorDigest(projection.selectors) !== projection.selectorDigest
    ) {
      failures.push("comment-control selector digest does not match its selectors");
    }
  }
  for (const field of [
    "count",
    "initiallyVisibleCount",
    "initiallyDormantCount",
    "projectionEpoch",
    "currentCount",
    "currentVisibleCount",
    "currentDormantApprovedCount",
  ]) {
    if (!Number.isInteger(projection[field]) || projection[field] < 0) {
      failures.push(`comment-control ${field} must be a non-negative integer`);
    }
  }
  if (
    Number.isInteger(projection.initiallyVisibleCount) &&
    Number.isInteger(projection.initiallyDormantCount) &&
    Number.isInteger(projection.count) &&
    projection.initiallyVisibleCount + projection.initiallyDormantCount !==
      projection.count
  ) {
    failures.push("comment-control initial visible and dormant counts do not equal total");
  }
  if (
    Number.isInteger(projection.currentVisibleCount) &&
    Number.isInteger(projection.currentDormantApprovedCount) &&
    Number.isInteger(projection.currentCount) &&
    projection.currentVisibleCount + projection.currentDormantApprovedCount !==
      projection.currentCount
  ) {
    failures.push("comment-control current visible and dormant counts do not equal total");
  }
  if (
    typeof projection.initialShapeFingerprint !== "string" ||
    !/^comment-control-shape-v1-[0-9a-f]{8}$/u.test(projection.initialShapeFingerprint)
  ) {
    failures.push("comment-control initial shape fingerprint is invalid");
  }
  if (
    typeof projection.currentShapeFingerprint !== "string" ||
    !/^comment-control-shape-v1-[0-9a-f]{8}$/u.test(projection.currentShapeFingerprint)
  ) {
    failures.push("comment-control current shape fingerprint is invalid");
  }
  if (
    !Array.isArray(allowedDigests) ||
    allowedDigests.length < 1 ||
    new Set(allowedDigests).size !== allowedDigests.length ||
    !allowedDigests.includes(projection.selectorDigest)
  ) {
    failures.push("comment-control selector digest is not owned by the exact route contract");
  }
  if (projection.currentProjectionValid !== true) {
    failures.push("comment-control current projection is not exact and approved");
  }
  if (!stats || typeof stats !== "object" || Array.isArray(stats)) {
    failures.push("comment-control DOM statistics are missing");
    return failures;
  }
  if (stats.count !== projection.currentCount) {
    failures.push("comment-control diagnostics count differs from the current DOM");
  }
  if (stats.visibleCount !== projection.currentVisibleCount) {
    failures.push("comment-control DOM visible count differs from projection diagnostics");
  }
  if (stats.allKept !== true) {
    failures.push("comment control lacks keep marker");
  }
  if (
    Number.isInteger(projection.count) &&
    Number.isInteger(projection.initiallyDormantCount) &&
    projection.initiallyDormantCount > projection.count
  ) {
    failures.push("initial dormant comment-control count exceeds the initial total");
  }
  if (projection.projectionEpoch === 0) {
    if (projection.currentCount !== projection.count) {
      failures.push("comment-control count changed without a projection epoch");
    }
    if (projection.currentShapeFingerprint !== projection.initialShapeFingerprint) {
      failures.push("comment-control shape changed without a projection epoch");
    }
    if (projection.currentDormantApprovedCount !== projection.initiallyDormantCount) {
      failures.push("comment-control dormant state changed without a projection epoch");
    }
  }
  return failures;
}

function commentItemProjectionFailures(gate) {
  const stats = gate?.commentItemStats;
  const dormantCount = stats?.approvedDormantCount ?? 0;
  if (!stats || [stats.count, stats.visibleCount, dormantCount].some((count) =>
    !Number.isSafeInteger(count) || count < 0)) {
    return ["comment item projection counts are missing or invalid"];
  }
  const failures = [];
  if (stats.allKept !== true) failures.push("comment item lacks keep marker");
  if (stats.visibleCount + dormantCount !== stats.count) {
    failures.push("comment items are neither visible nor runtime-approved dormant");
  }
  return failures;
}

function userscriptGateFailures(gate, requiredRoles) {
  const failures = [];
  if (!gate.ready) failures.push(`userscript gate is not ready (state=${gate.state ?? "missing"})`);
  if (gate.diagnostics?.protocolVersion !== READER_GATE_PROTOCOL_VERSION) {
    failures.push("userscript diagnostics are not exact reader-gate protocol 2");
  }
  if (
    gate.testOnlyAdguardControl?.kind !== "preauthorized-userscript-style-control" ||
    gate.testOnlyAdguardControl?.schemaVersion !== PREAUTHORIZED_ADGUARD_CONTROL_SCHEMA_VERSION ||
    gate.testOnlyAdguardControl?.gmAddElementCalls !== 1
  ) {
    failures.push("userscript-manager style control did not provide exactly one GM style");
  }
  if (
    gate.diagnostics?.standaloneCascadeProof?.authority !== "userscript-runtime-style" ||
    gate.diagnostics?.standaloneCascadeProof?.frameCount !== 2 ||
    gate.diagnostics?.standaloneCascadeProof?.nonceBound !== true ||
    gate.diagnostics?.standaloneCascadeProof?.unownedHidden !== true
  ) {
    failures.push("userscript did not prove its standalone two-frame cascade authority");
  }
  if (gate.runtimeStyleCount !== 1) {
    failures.push(`runtime stylesheet cardinality is ${gate.runtimeStyleCount ?? "missing"}`);
  }
  if (gate.standaloneRuntimeCoverage?.passed !== true) {
    failures.push("standalone userscript runtime projection coverage is not exact");
  }
  if (!gate.paintProbe || gate.paintProbe.sampleCount < 1) {
    failures.push("document-start first-paint probe is missing");
  } else {
    if (gate.paintProbe.unsafeGateFrameCount !== 0) {
      failures.push(
        `${gate.paintProbe.unsafeGateFrameCount} active reader-gate frames exposed unmarked content`,
      );
    }
    if (gate.paintProbe.firstReadyFrame === null) {
      failures.push("first-paint probe never observed the ready state");
    }
  }
  if (gate.visibleWithoutKeepCount > 0) {
    failures.push(`${gate.visibleWithoutKeepCount} visible nodes lack the keep marker`);
  }
  if (gate.directVisibleTextLeakCount > 0) {
    failures.push(`${gate.directVisibleTextLeakCount} direct visible text leaks remain outside roles`);
  }
  for (const role of requiredRoles) {
    const stats = gate.roleStats?.[role];
    if (!stats || stats.count === 0) failures.push(`${role} role root is absent`);
    else if (!stats.allKept) failures.push(`${role} role root lacks keep marker`);
    else if (role !== "comments" && stats.visibleCount === 0) {
      failures.push(`${role} role has no visible keep-owned projection`);
    } else if (
      role === "comments" &&
      (gate.commentItemStats?.count ?? 0) > (gate.commentItemStats?.approvedDormantCount ?? 0) &&
      stats.visibleCount === 0
    ) {
      failures.push("comments role has no visible keep-owned projection");
    }
  }
  failures.push(...commentItemProjectionFailures(gate));
  failures.push(...commentControlProjectionFailures(gate));
  failures.push(...validateDiagnostics(gate.diagnostics, requiredRoles));
  return failures;
}

function blockedUserscriptGateFailures(gate) {
  const failures = [];
  if (gate.ready) failures.push("direct navigation unexpectedly became reader-ready");
  const inactiveSafety = gate.inactivePublisherSafety ?? gate.blockedStateSafety;
  if (inactiveSafety?.passed !== true) {
    failures.push("direct navigation did not preserve an inactive publisher-visible page");
  }
  if (inactiveSafety?.diagnosticsInactiveOrAbsent !== true) {
    failures.push("direct navigation left non-inactive userscript diagnostics");
  }
  if (!gate.paintProbe || gate.paintProbe.sampleCount < 1) {
    failures.push("document-start first-paint probe is missing");
  } else {
    if (gate.paintProbe.unsafeGateFrameCount !== 0) {
      failures.push(
        `${gate.paintProbe.unsafeGateFrameCount} inactive direct-navigation frames activated an unsafe reader gate`,
      );
    }
    if (gate.paintProbe.firstReadyFrame !== null) {
      failures.push("direct navigation emitted a ready frame");
    }
    const activeGateSamples = (gate.paintProbe.samples ?? []).filter(
      (sample) => sample.readerGateActive === true || sample.paintLockIntact === true,
    );
    if (activeGateSamples.length > 0) {
      failures.push("direct navigation installed reader-gate state before provenance approval");
    }
  }
  if (gate.runtimeStyleCount !== 0) {
    failures.push("direct navigation left a runtime stylesheet installed");
  }
  if (gate.hotdealMarkerCount !== 0 || gate.publisherProtocolCleared !== true) {
    failures.push("direct navigation left userscript protocol markers on the publisher page");
  }
  return failures;
}

async function createPageContext(
  browser,
  profileName,
  userscriptContent = null,
  allowedNavigationDomains = [],
  allowedResourceDomains = allowedNavigationDomains,
  contextPolicy = {},
) {
  const storageState = contextPolicy.storageState ?? null;
  const navigationDomains = new Set(allowedNavigationDomains.map((domain) => domain.toLowerCase()));
  const resourceDomains = new Set(allowedResourceDomains.map((domain) => domain.toLowerCase()));
  const exactResourceHosts = new Set(
    (contextPolicy.exactResourceHosts ?? []).map((hostname) => normalizedHostname(hostname)),
  );
  const allowPublicHttpsSubresources = contextPolicy.allowPublicHttpsSubresources === true;
  const noAlgumonNetwork = contextPolicy.noAlgumonNetwork === true;
  const sourceBrowserBudget = contextPolicy.algumonSourceUrl
    ? createAlgumonSourceBrowserBudget(contextPolicy.algumonSourceUrl)
    : null;
  const networkEvidenceRecorder = createNetworkPolicyEvidenceRecorder({
    allowPublicHttpsSubresources,
  });
  const stylesheetDependencyRecorder = createStylesheetDependencyRecorder();
  let stopStylesheetObservation = null;
  const pinnedTransport = await createPinnedPublicHttpsProxy();
  const approvePublicHost = (hostname) => {
    // Redirect CONNECTs may bypass Playwright routing. Never approve this host
    // in a no-Algumon context, including through navigation priming.
    if (noAlgumonNetwork && hostnameMatches(normalizedHostname(hostname), "algumon.com")) {
      return Promise.resolve([]);
    }
    return pinnedTransport.approvePublicHost(hostname);
  };
  let context;
  try {
    context = await browser.newContext({
      ...contextOptions(profileName),
      serviceWorkers: "block",
      proxy: { server: pinnedTransport.serverUrl },
      ...(storageState ? { storageState } : {}),
    });
  } catch (error) {
    await pinnedTransport.close();
    throw error;
  }
  const nativeContextClose = context.close.bind(context);
  let contextClosePromise = null;
  Object.defineProperty(context, "close", {
    configurable: true,
    value: (...arguments_) => {
      if (!contextClosePromise) {
        contextClosePromise = (async () => {
          try {
            await stopStylesheetObservation?.();
            return await nativeContextClose(...arguments_);
          } finally {
            await pinnedTransport.close();
          }
        })();
      }
      return contextClosePromise;
    },
  });
  context.once("close", () => {
    void pinnedTransport.close();
  });
  const inFlightReservations = new WeakMap();
  const finishInFlightReservation = (request) => {
    const lifecycle = inFlightReservations.get(request);
    if (!lifecycle) return;
    inFlightReservations.delete(request);
    lifecycle.reservation.finish();
  };
  const failInFlightReservation = (request) => {
    const lifecycle = inFlightReservations.get(request);
    if (!lifecycle) return;
    const failureText = String(request.failure()?.errorText ?? "network-request-failed")
      .replace(/[^\w .:+-]/gu, "")
      .slice(0, 64) || "network-request-failed";
    networkEvidenceRecorder.recordAllowedRequestFailure(
      lifecycle.hostname,
      lifecycle.requestType,
      failureText,
      lifecycle.isMainNavigation,
      request.url(),
      networkRequestRedirectEvidence(request),
    );
    finishInFlightReservation(request);
  };
  context.on("requestfinished", finishInFlightReservation);
  context.on("requestfailed", failInFlightReservation);
  const observeSourceRequest = (request) => {
    return sourceBrowserBudget?.observeRequest(request) ?? null;
  };
  if (sourceBrowserBudget) context.on("request", (request) => {
    // Request events include HTTP redirects even when Playwright does not route
    // their follow-up requests. Count them too, and terminate a looping/escaped
    // source context instead of silently publishing an incomplete request total.
    if (!observeSourceRequest(request).allowed) void context.close().catch(() => {});
  });
  context.on("response", (response) => {
    const request = response.request();
    const lifecycle = inFlightReservations.get(request);
    if (!lifecycle || response.status() < 400) return;
    networkEvidenceRecorder.recordAllowedResponseFailure(
      lifecycle.hostname,
      lifecycle.requestType,
      response.status(),
      lifecycle.isMainNavigation,
      request.url(),
      networkRequestRedirectEvidence(request),
    );
  });
  await context.route("**/*", async (route) => {
    const request = route.request();
    let parsed;
    try {
      parsed = new URL(request.url());
    } catch {
      await route.abort("blockedbyclient");
      return;
    }
    const isMainNavigation = isTopLevelNavigationRequest(request);
    const sourceDecision = observeSourceRequest(request);
    if (sourceDecision && !sourceDecision.allowed) {
      networkEvidenceRecorder.recordBlocked(
        parsed.hostname,
        request.resourceType(),
        sourceDecision.reason,
        isMainNavigation,
      );
      await route.abort("blockedbyclient").catch(() => {});
      return;
    }
    const decision = networkRequestDecision(
      parsed.href,
      isMainNavigation,
      [...navigationDomains],
      [...resourceDomains],
      [...exactResourceHosts],
      allowPublicHttpsSubresources,
      noAlgumonNetwork,
    );
    if (decision.reason === "local-browser-scheme") {
      await route.continue();
      return;
    }
    const reservation = networkEvidenceRecorder.reserveRemoteRequest(parsed.hostname, {
      requestType: request.resourceType(), isMainNavigation, urlText: request.url(),
      redirectEvidence: networkRequestRedirectEvidence(request),
    });
    let handedToNetworkLifecycle = false;
    try {
      if (!reservation.allowed) {
        networkEvidenceRecorder.recordBlocked(
          parsed.hostname,
          request.resourceType(),
          reservation.reason,
          isMainNavigation,
        );
        await route.abort("blockedbyclient");
        return;
      }
      const approvedAddresses = decision.allowed
        ? await approvePublicHost(parsed.hostname)
        : [];
      if (!decision.allowed || approvedAddresses.length < 1) {
        networkEvidenceRecorder.recordBlocked(
          parsed.hostname,
          request.resourceType(),
          decision.allowed ? pinnedTransport.rejectionReasonForHost(parsed.hostname) : decision.reason,
          isMainNavigation,
        );
        await route.abort("blockedbyclient");
        return;
      }
      if (decision.reason === "exact-challenge-subresource") {
        networkEvidenceRecorder.recordExactChallenge(
          parsed.hostname,
          request.resourceType(),
          decision.reason,
          isMainNavigation,
        );
      }
      networkEvidenceRecorder.recordAllowedPublic(
        parsed.hostname,
        request.resourceType(),
        decision.reason,
        isMainNavigation,
      );
      inFlightReservations.set(request, {
        reservation,
        hostname: parsed.hostname,
        requestType: request.resourceType(),
        isMainNavigation,
      });
      handedToNetworkLifecycle = true;
      try {
        await route.continue();
      } catch (error) {
        inFlightReservations.delete(request);
        handedToNetworkLifecycle = false;
        throw error;
      }
    } finally {
      if (!handedToNetworkLifecycle) reservation.finish();
    }
  });
  await context.routeWebSocket("**/*", async (webSocketRoute) => {
    let parsed;
    try {
      parsed = new URL(webSocketRoute.url());
    } catch {
      await webSocketRoute.close({ code: 1008, reason: "invalid-url" });
      return;
    }
    const sourceDecision = sourceBrowserBudget?.observe(parsed.href, false);
    if (sourceDecision && !sourceDecision.allowed) {
      networkEvidenceRecorder.recordBlocked(
        parsed.hostname,
        "websocket",
        sourceDecision.reason,
        false,
      );
      await webSocketRoute.close({ code: 1008, reason: "network-policy" });
      return;
    }
    const decision = networkRequestDecision(
      parsed.href,
      false,
      [...navigationDomains],
      [...resourceDomains],
      [...exactResourceHosts],
      allowPublicHttpsSubresources,
      noAlgumonNetwork,
    );
    const reservation = networkEvidenceRecorder.reserveRemoteRequest(parsed.hostname, {
      requestType: "websocket", isMainNavigation: false, urlText: webSocketRoute.url(),
    });
    try {
      if (!reservation.allowed || !decision.allowed) {
        const reason = reservation.allowed ? decision.reason : reservation.reason;
        networkEvidenceRecorder.recordBlocked(
          parsed.hostname,
          "websocket",
          reason,
          false,
        );
        await webSocketRoute.close({ code: 1008, reason: "network-policy" });
        return;
      }
      const approvedAddresses = await approvePublicHost(parsed.hostname);
      if (approvedAddresses.length < 1) {
        networkEvidenceRecorder.recordBlocked(
          parsed.hostname,
          "websocket",
          pinnedTransport.rejectionReasonForHost(parsed.hostname),
          false,
        );
        await webSocketRoute.close({ code: 1008, reason: "network-policy" });
        return;
      }
      if (decision.reason === "exact-challenge-subresource") {
        networkEvidenceRecorder.recordExactChallenge(
          parsed.hostname,
          "websocket",
          decision.reason,
          false,
        );
      }
      networkEvidenceRecorder.recordAllowedPublic(
        parsed.hostname,
        "websocket",
        decision.reason,
        false,
      );
      webSocketRoute.connectToServer();
    } catch {
      networkEvidenceRecorder.recordBlocked(
        parsed.hostname,
        "websocket",
        "websocket-connect-failed",
        false,
      );
      await webSocketRoute.close({ code: 1011, reason: "connect-failed" }).catch(() => {});
    } finally {
      reservation.finish();
    }
  });
  if (userscriptContent !== null) {
    await context.addInitScript({
      content: userscriptAuditInitSource(userscriptContent),
    });
  }
  const validateMainDocumentUrl = (urlText) => {
    const decision = networkRequestDecision(
      urlText,
      true,
      [...navigationDomains],
      [...resourceDomains],
      [...exactResourceHosts],
      allowPublicHttpsSubresources,
      noAlgumonNetwork,
    );
    if (decision.allowed) return;
    let parsed = null;
    try {
      parsed = new URL(urlText);
    } catch {}
    networkEvidenceRecorder.recordNavigationViolation(
      parsed?.protocol,
      parsed?.hostname,
      decision.reason,
    );
  };
  const validateAllMainDocumentUrls = () => {
    for (const observedPage of context.pages()) {
      validateMainDocumentUrl(observedPage.mainFrame().url());
    }
  };
  const navigationGuardedPages = new WeakSet();
  const attachNavigationGuard = (observedPage) => {
    if (navigationGuardedPages.has(observedPage)) return;
    navigationGuardedPages.add(observedPage);
    observedPage.on("framenavigated", (frame) => {
      if (frame.parentFrame() !== null) return;
      validateMainDocumentUrl(frame.url());
    });
  };
  context.on("page", attachNavigationGuard);
  let page;
  try {
    page = await context.newPage();
    stopStylesheetObservation = await observeStylesheetDependencies(context, page, stylesheetDependencyRecorder);
  } catch (error) {
    await context.close();
    throw error;
  }
  attachNavigationGuard(page);
  return {
    context,
    page,
    approvePublicHost,
    sourceBrowserBudgetSnapshot: () => sourceBrowserBudget?.snapshot() ?? null,
    sealNetworkPolicyEvidence: async () => {
      validateAllMainDocumentUrls();
      await networkEvidenceRecorder.sealAndDrain({
        onSeal: () => pinnedTransport.seal(),
      });
      validateAllMainDocumentUrls();
      await context.close();
      return {
        ...networkEvidenceRecorder.snapshot(),
        ...(sourceBrowserBudget ? { sourceBrowser: sourceBrowserBudget.snapshot() } : {}),
        stylesheetDependencies: stylesheetDependencyRecorder.snapshot(),
        pinnedTransport: pinnedTransport.snapshot(),
      };
    },
  };
}

async function retainUnobservedSessionNetworkPolicy(session, result, stage) {
  if (result[stage]?.networkPolicy) return result[stage].networkPolicy;
  result[stage] ??= {};
  try {
    const evidence = await session.sealNetworkPolicyEvidence();
    result[stage].networkPolicy = evidence;
    return evidence;
  } catch (error) {
    const evidence = algumonNavigationErrorEvidence(error);
    result[stage].networkPolicyCaptureFailure = evidence;
    result.failures.push(`${stage} network evidence capture failed: ${evidence.category} (${evidence.errorSha256})`);
    return null;
  }
}

async function auditOneTarget({
  browser,
  site,
  layout,
  profileName,
  target,
  userscriptContent,
  promotionCandidate,
  runtimeOnly,
  noAlgumonNetwork = false,
  runDirectory,
  timeoutMs,
}) {
  const runtimeExpectation = runtimeExpectationForTarget(target);
  const auditedTarget = target;
  let auditedLayout = layout;
  const stem = safeFileStem([
    site.id,
    layout.id,
    profileName,
    auditedTarget.source,
    sha256(auditedTarget.url).slice(0, 10),
  ]);
  const result = {
    siteId: site.id,
    layoutId: layout.id,
    profile: profileName,
    source: auditedTarget.source,
    runtimeExpectation,
    candidateGenerationAllowed: false,
    requestedUrl: auditedTarget.url,
    relayDestinationUrl: auditedTarget.algumon?.verifiedResolution?.resolvedDestination ?? null,
    relayAcquisition: auditedTarget.relayAcquisition ?? null,
    algumonSeed: auditedTarget.algumon
      ? {
          discoveryUrl: auditedTarget.algumon.discoveryUrl ?? null,
          redirectUrl: auditedTarget.algumon.redirectUrl,
          dealId: auditedTarget.algumon.dealId,
          siteId: auditedTarget.algumon.siteId,
          title: auditedTarget.algumon.title ?? "",
          commentCount: auditedTarget.algumon.commentCount ?? null,
          verifiedResolution: auditedTarget.algumon.verifiedResolution,
        }
      : null,
    routeFamily: auditedTarget.routeFamily ?? null,
    configuredPathMatchCount: auditedTarget.configuredPathMatchCount ?? null,
    approvedRouteMatched: auditedTarget.approvedRouteMatched !== false,
    matchedApprovedPath: auditedTarget.matchedApprovedPath ?? null,
    routeObservation: auditedTarget.routeObservation ?? null,
    profileLanding: null,
    committedProjection: null,
    static: null,
    userscript: null,
    failures: [],
  };
  let candidates = [];

  const navigationDomains = [...new Set(site.layouts.map((candidate) => candidate.domain))];
  const exactChallengeResourceHosts = exactChallengeResourceHostsForSite(site.id);
  let accessLease = null;
  let staticConsistency = null;
  let candidateExtractionAllowed = false;
  let storageState = null;
  if (runtimeExpectation === "direct-negative") {
    result.static = {
      provenanceOnly: true,
      skipped:
        "direct-negative provenance-only; bootstrap, lease, and static semantic audit omitted",
    };
    storageState = { cookies: [], origins: [] };
  } else {
    const staticSession = await createPageContext(
      browser,
      profileName,
      null,
      navigationDomains,
      resourceDomainsForSite(site),
      {
        exactResourceHosts: exactChallengeResourceHosts,
        allowPublicHttpsSubresources: true,
        noAlgumonNetwork,
      },
    );
    try {
    const responseObserver = observeMainDocumentResponses(staticSession.page);
    let navigation;
    let sourceSnapshot;
    let sourceClassification;
    try {
      await primeDeclaredArticleNavigation(staticSession, auditedTarget.url, navigationDomains, {
        siteId: site.id, profileName,
      });
      navigation = await navigate(
        staticSession.page,
        auditedTarget.url,
        timeoutMs,
        responseObserver,
      );
      sourceSnapshot = await destinationDocumentSnapshot(staticSession.page);
      sourceClassification = classifyDestinationResponse({
        ...navigation,
        ...sourceSnapshot,
      });
      const challengeObserved = sourceClassification.subkind === "waf-or-challenge";
      const challengeDeadline =
        Date.now() + Math.min(timeoutMs, DESTINATION_CHALLENGE_SETTLE_MAX_MS);
      while (
        runtimeExpectation !== "direct-negative" &&
        sourceClassification.subkind === "waf-or-challenge" &&
        Date.now() < challengeDeadline
      ) {
        await staticSession.page.waitForTimeout(250);
        navigation = navigationEvidenceFromObserver(
          responseObserver,
          staticSession.page.url(),
        );
        sourceSnapshot = await destinationDocumentSnapshot(staticSession.page);
        sourceClassification = classifyDestinationResponse({
          ...navigation,
          ...sourceSnapshot,
        });
      }
      if (challengeObserved && sourceClassification.kind === "article-response") {
        await settlePage(staticSession.page, timeoutMs);
        navigation = navigationEvidenceFromObserver(
          responseObserver,
          staticSession.page.url(),
        );
        sourceSnapshot = await destinationDocumentSnapshot(staticSession.page);
        sourceClassification = classifyDestinationResponse({
          ...navigation,
          ...sourceSnapshot,
        });
      }
    } finally {
      responseObserver.stop();
    }
    result.static = {
      navigation,
      sourceClassification,
      networkPolicy: null,
      provenanceOnly: false,
    };
    result.sourceClassification = sourceClassification;
    if (
      runtimeExpectation !== "direct-negative" &&
      sourceClassification.kind !== "article-response"
    ) {
      result.failures.push(
        `source-or-infrastructure-failure: ${sourceClassification.subkind}`,
      );
      await captureBoundedScreenshot(
        staticSession.page,
        path.join(runDirectory, `${stem}-source-failure.png`),
      ).catch(() => {});
      result.capturedAt = new Date().toISOString().replace(/\.\d{3}Z$/u, "Z");
      result.passed = false;
      return { result, candidates: [] };
    }
    candidateExtractionAllowed = candidateGenerationAllowed(
      runtimeExpectation,
      sourceClassification,
    );
    const landing = classifyProfileLandingRoute(
      site,
      profileName,
      navigation.finalUrl,
      promotionCandidate,
    );
    const landedLayout = site.layouts.find(
      (candidate) => candidate.id === landing.layoutId,
    ) ?? null;
    if (landedLayout) auditedLayout = landedLayout;
    result.layoutId = auditedLayout.id;
    result.requestedUrl = navigation.finalUrl;
    result.routeFamily = routeFamily(navigation.finalUrl);
    result.configuredPathMatchCount = landing.configuredPathMatchCount;
    result.approvedRouteMatched = landing.approvedRouteMatched;
    result.matchedApprovedPath = landing.matchedApprovedPath;
    result.profileLanding = {
      evidenceKind: "profile-user-agent-final-landing",
      finalUrl: navigation.finalUrl,
      ...landing,
    };
    if (result.routeObservation) {
      result.routeObservation = {
        ...result.routeObservation,
        finalResolvedUrl: navigation.finalUrl,
        resolvedDestination: auditedTarget.url,
        algumonEntryUrl:
          auditedTarget.algumon?.redirectUrl ?? result.routeObservation.algumonEntryUrl,
        relayFetchUrl:
          auditedTarget.algumon?.verifiedResolution?.relayFetchUrl ??
          result.routeObservation.relayFetchUrl,
        relayResolutionSha256: auditedTarget.algumon?.verifiedResolution
          ? sha256(canonicalJson(auditedTarget.algumon.verifiedResolution))
          : result.routeObservation.relayResolutionSha256,
        provenanceSha256: sha256(
          canonicalJson({
            algumonDealId: auditedTarget.algumon?.dealId ?? null,
            algumonEntryUrl: auditedTarget.algumon?.redirectUrl ?? null,
            finalResolvedUrl: navigation.finalUrl,
            profile: profileName,
          }),
        ),
      };
    }
    let staticRoleResourceEvidence = {
      hosts: [],
      rootCount: 0,
      nodeCount: 0,
      urlCount: 0,
      selectorErrorCount: 0,
      nodeOverflowCount: 0,
      urlOverflowCount: 0,
      hostOverflowCount: 0,
      skipped: "runtime-only exact role resources are verified after userscript projection",
    };
    if (runtimeOnly) {
      result.static.skipped =
        "runtime-only candidate verification; source and access lease still verified";
    } else {
      if (landing.configuredPathMatchCount !== 1 || !landedLayout) {
        result.failures.push(
          `static path gate mismatch: ${new URL(navigation.finalUrl).hostname}${new URL(navigation.finalUrl).pathname}`,
        );
      }
      try {
        await captureBoundedScreenshot(
          staticSession.page,
          path.join(runDirectory, `${stem}-static-before.png`),
        );
        const approvedProjection = await countExistingApprovedLayoutMatches(
          staticSession.page,
          auditedLayout,
          userscriptContent,
          targetAlgumonSeed(site.id, auditedTarget),
        );
        result.committedProjection = committedProjectionEvidence(approvedProjection);
        const oracle = await semanticOracle(
          staticSession.page,
          userscriptContent,
          site.id,
          auditedLayout.id,
          requiredRolesForLayout(auditedLayout),
          auditedTarget,
        );
        result.semanticOracle = semanticOracleEvidence(oracle, auditedTarget);
        staticRoleResourceEvidence = await roleReferencedResourceHosts(
          staticSession.page,
          Object.values(result.semanticOracle.roles ?? {}).filter(Boolean),
        );
        const candidateProjection = result.semanticOracle.verificationMode === "registered-sample"
          ? {
            semanticProjectionCount: 0,
            exactCandidateCount: 0,
            coMatchCount: 0,
            aliases: [],
            skipped: "registered sample is not independent candidate evidence",
          }
          : await candidateOracleProjectionEvidence(
            staticSession.page,
            auditedLayout,
            result.semanticOracle,
            userscriptContent,
            targetAlgumonSeed(site.id, auditedTarget),
            navigation.finalUrl,
          );
        const cardinality = projectionCardinalityEvidence(
          result.semanticOracle.structuralOk,
          approvedProjection.semanticProjectionCount,
        );
        result.semanticOracle.semanticProjectionCount = cardinality.semanticProjectionCount;
        result.semanticOracle.coMatchCount = cardinality.coMatchCount;
        result.semanticOracle.coMatchIds = approvedProjection.classes.flatMap(
          (projectionClass) => projectionClass.aliases,
        );
        result.semanticOracle.projectionAliases = approvedProjection.classes.map(
          (projectionClass) => projectionClass.aliases,
        );
        result.semanticOracle.exactApprovedCount = cardinality.exactApprovedCount;
        result.semanticOracle.candidateProjection = candidateProjection;
        result.failures.push(
          ...semanticOracleContractFailures(result.semanticOracle).map(
            (item) => `semantic: ${item}`,
          ),
        );
        const preProjectionCandidates = await selectorCandidates(staticSession.page);
        const approvedMatchId = approvedProjection.semanticProjectionCount === 1
          ? approvedProjection.classes[0].canonicalId
          : auditedLayout.id;
        const projectionLayout = staticProjectionContract(auditedLayout, approvedMatchId);
        const projection = await auditStaticProjection(staticSession.page, projectionLayout);
        result.static.projectionContractId = approvedMatchId;
        await staticSession.page.waitForTimeout(100);
        await captureBoundedScreenshot(
          staticSession.page,
          path.join(runDirectory, `${stem}-static-projected.png`),
        );
        result.static.projection = projection;
        result.static.projectionPurpose = "legacy-filter-diagnostic-only";
        result.static.projectionFailures = staticProjectionFailures(projection);
        if (result.failures.length > 0) candidates = preProjectionCandidates;
        staticConsistency = {
          siteId: site.id,
          layoutId: auditedLayout.id,
          resolvedArticleIdentitySha256:
            canonicalArticleIdentity(navigation.finalUrl, site.id).sha256,
          resolvedRouteFamily: canonicalArticleIdentity(navigation.finalUrl, site.id).routeFamily,
          semanticProjectionCount: result.committedProjection.count,
          projectionAliases: result.committedProjection.aliases.flat(),
        };
      } catch (error) {
        result.failures.push(`static audit error: ${error?.stack ?? String(error)}`);
        if (candidateExtractionAllowed) {
          candidates = await selectorCandidates(staticSession.page).catch(() => []);
        }
        await captureBoundedScreenshot(
          staticSession.page,
          path.join(runDirectory, `${stem}-static-error.png`),
        ).catch(() => {});
      }
    }
    if (!staticConsistency && runtimeExpectation !== "direct-negative") {
      const identity = canonicalArticleIdentity(navigation.finalUrl, site.id);
      staticConsistency = {
        siteId: site.id,
        layoutId: auditedLayout.id,
        resolvedArticleIdentitySha256: identity.sha256,
        resolvedRouteFamily: identity.routeFamily,
        semanticProjectionCount: null,
        projectionAliases: null,
      };
    }
    accessLease = await acquireArticleAccessLease(
      staticSession.context,
      site,
      profileName,
      auditedTarget.url,
      navigation.finalUrl,
    );
    result.articleAccessLease = accessLease.evidence;
    const staticNetworkPolicy = await staticSession.sealNetworkPolicyEvidence();
    staticNetworkPolicy.roleReferencedResourceEvidence = staticRoleResourceEvidence;
    staticNetworkPolicy.roleReferencedResourceHosts = staticRoleResourceEvidence.hosts;
    result.static.networkPolicy = staticNetworkPolicy;
    const staticNetworkFailures = networkFidelityFailures(
      staticNetworkPolicy,
      resourceDomainsForSite(site),
      staticRoleResourceEvidence,
    );
    if (staticNetworkFailures.length > 0) {
      candidateExtractionAllowed = false;
      candidates = [];
      result.failures.push(
        ...staticNetworkFailures.map((failure) => `network-fidelity: ${failure}`),
      );
      await captureBoundedScreenshot(
        staticSession.page,
        path.join(runDirectory, `${stem}-network-fidelity-failure.png`),
      ).catch(() => {});
      result.capturedAt = new Date().toISOString().replace(/\.\d{3}Z$/u, "Z");
      result.passed = false;
      return { result, candidates: [] };
    }
    } catch (error) {
      const evidence = algumonNavigationErrorEvidence(error);
      result.articleAccessFailure = evidence;
      result.failures.push(`article navigation/access error: ${evidence.category} (${evidence.errorSha256})`);
      await captureBoundedScreenshot(
        staticSession.page,
        path.join(runDirectory, `${stem}-access-error.png`),
      ).catch(() => {});
    } finally {
      await retainUnobservedSessionNetworkPolicy(staticSession, result, "static");
      await staticSession.context.close();
    }

    if (!accessLease) {
      result.capturedAt = new Date().toISOString().replace(/\.\d{3}Z$/u, "Z");
      result.passed = false;
      return { result, candidates: [] };
    }
    storageState = consumeArticleAccessLease(accessLease, accessLease.binding);
  }
  const userscriptSession = await createPageContext(
    browser,
    profileName,
    userscriptContent,
    navigationDomains,
    resourceDomainsForSite(site),
    {
      exactResourceHosts: exactChallengeResourceHosts,
      storageState,
      allowPublicHttpsSubresources: true,
      noAlgumonNetwork,
    },
  );
  const consoleErrors = [];
  const capturePageErrors = (observedPage) => {
    observedPage.on("console", (message) => {
      if (message.type() === "error") consoleErrors.push(message.text().slice(0, 500));
    });
    observedPage.on("pageerror", (error) => {
      consoleErrors.push(String(error).slice(0, 500));
    });
  };
  userscriptSession.context.on("page", capturePageErrors);
  capturePageErrors(userscriptSession.page);
  let auditedPage = userscriptSession.page;
  let runtimeCandidateExtractionAllowed = false;
  try {
    await primeDeclaredArticleNavigation(userscriptSession, auditedTarget.url, navigationDomains, {
      siteId: site.id, profileName,
    });
    const navigation = await navigateThroughAlgumon(
      userscriptSession.page,
      auditedTarget,
      timeoutMs,
      auditedLayout.domain,
    );
    auditedPage = navigation.page ?? userscriptSession.page;
    const { page: _destinationPage, ...navigationEvidence } = navigation;
    result.userscript = {
      expectation: runtimeExpectation,
      navigation: navigationEvidence,
      networkPolicy: null,
    };
    const runtimeSnapshot = await destinationDocumentSnapshot(auditedPage);
    const runtimeSourceClassification = classifyDestinationResponse({
      ...navigationEvidence,
      ...runtimeSnapshot,
    });
    result.userscript.sourceClassification = runtimeSourceClassification;
    if (
      runtimeExpectation !== "direct-negative" &&
      runtimeSourceClassification.kind !== "article-response"
    ) {
      candidateExtractionAllowed = false;
      candidates = [];
      result.failures.push(
        `userscript source-or-infrastructure-failure: ${runtimeSourceClassification.subkind}`,
      );
      await captureBoundedScreenshot(
        auditedPage,
        path.join(runDirectory, `${stem}-userscript-source-failure.png`),
      ).catch(() => {});
      throw Object.assign(new Error("runtime destination response was not an article"), {
        sourceClassified: true,
      });
    }
    runtimeCandidateExtractionAllowed = candidateGenerationAllowed(
      runtimeExpectation,
      runtimeSourceClassification,
      0,
    );
    const runtimeLanding = classifyProfileLandingRoute(
      site,
      profileName,
      navigation.finalUrl,
      promotionCandidate,
    );
    const runtimeLayout = site.layouts.find(
      (candidate) => candidate.id === runtimeLanding.layoutId,
    ) ?? null;
    if (
      runtimeExpectation !== "direct-negative" &&
      runtimeLayout &&
      runtimeLayout.id !== auditedLayout.id
    ) {
      result.failures.push(
        `profile landing layout changed between static and userscript audit (${auditedLayout.id} -> ${runtimeLayout.id})`,
      );
      auditedLayout = runtimeLayout;
    }
    result.layoutId = auditedLayout.id;
    result.requestedUrl = navigation.finalUrl;
    result.routeFamily = routeFamily(navigation.finalUrl);
    result.configuredPathMatchCount = runtimeLanding.configuredPathMatchCount;
    result.approvedRouteMatched = runtimeLanding.approvedRouteMatched;
    result.matchedApprovedPath = runtimeLanding.matchedApprovedPath;
    result.profileLanding = {
      evidenceKind: "profile-user-agent-final-landing",
      finalUrl: navigation.finalUrl,
      ...runtimeLanding,
    };
    if (result.routeObservation) {
      result.routeObservation = {
        ...result.routeObservation,
        finalResolvedUrl: navigation.finalUrl,
        resolvedDestination: auditedTarget.url,
        algumonEntryUrl:
          auditedTarget.algumon?.redirectUrl ?? result.routeObservation.algumonEntryUrl,
        relayFetchUrl:
          auditedTarget.algumon?.verifiedResolution?.relayFetchUrl ??
          result.routeObservation.relayFetchUrl,
        relayResolutionSha256: auditedTarget.algumon?.verifiedResolution
          ? sha256(canonicalJson(auditedTarget.algumon.verifiedResolution))
          : result.routeObservation.relayResolutionSha256,
        provenanceSha256: sha256(
          canonicalJson({
            algumonDealId: auditedTarget.algumon?.dealId ?? null,
            algumonEntryUrl: auditedTarget.algumon?.redirectUrl ?? null,
            finalResolvedUrl: navigation.finalUrl,
            profile: profileName,
          }),
        ),
      };
    }
    if (
      runtimeExpectation !== "direct-negative" &&
      (runtimeLanding.configuredPathMatchCount !== 1 || !runtimeLayout)
    ) {
      result.failures.push(
        `userscript path gate mismatch: ${new URL(navigation.finalUrl).hostname}${new URL(navigation.finalUrl).pathname}`,
      );
    }
    const requiredRoles = requiredRolesForLayout(auditedLayout);
    const gate = await auditUserscriptGate(
      auditedPage,
      requiredRoles,
      timeoutMs,
      runtimeExpectation,
      commentControlSelectorDigestsForUrl(auditedLayout, navigation.finalUrl),
    );
    await auditedPage.waitForTimeout(100);
    await captureBoundedScreenshot(
      auditedPage,
      path.join(runDirectory, `${stem}-userscript-gated.png`),
    );
    result.userscript.gate = gate;
    if (runtimeExpectation !== "direct-negative") {
      result.failures.push(
        ...staticRuntimeConsistencyFailures(
          staticConsistency,
          navigation,
          gate,
          runtimeLayout?.id ?? auditedLayout.id,
        ).map((item) => `consistency: ${item}`),
      );
    }
    if (
      promotionCandidate &&
      promotionCandidate.siteId === site.id &&
      promotionCandidate.layoutId === auditedLayout.id &&
      ["registered-positive", "relay-positive"].includes(runtimeExpectation)
    ) {
      result.candidateOverlay = await auditCandidateOverlay(
        auditedPage,
        auditedLayout,
        promotionCandidate,
        auditedTarget,
        userscriptContent,
      );
      result.failures.push(
        ...candidateOverlayFailures(
          result.candidateOverlay,
          requiredRoles,
          promotionCandidate.proofProfiles.includes(profileName),
        ).map((item) => `candidate: ${item}`),
      );
    }
    result.userscript.consoleErrors = consoleErrors;
    const runtimeFailures = runtimeExpectation === "direct-negative"
      ? blockedUserscriptGateFailures(gate)
      : userscriptGateFailures(gate, requiredRoles);
    result.failures.push(...runtimeFailures.map((item) => `userscript: ${item}`));
    if (
      ["registered-positive", "relay-positive"].includes(runtimeExpectation) &&
      runtimeCandidateExtractionAllowed &&
      result.failures.length > 0 &&
      candidates.length === 0
    ) {
      candidates = await selectorCandidates(auditedPage);
    }
    const runtimeRoleResourceEvidence = runtimeExpectation !== "direct-negative"
      ? await roleReferencedResourceHosts(
          auditedPage,
          [
            "[data-hotdeal-focus-role='title']",
            "[data-hotdeal-focus-role='body']",
            "[data-hotdeal-focus-role='product']",
            "[data-hotdeal-focus-role='comments']",
          ],
        )
      : {
          hosts: [],
          rootCount: 0,
          nodeCount: 0,
          urlCount: 0,
          selectorErrorCount: 0,
          nodeOverflowCount: 0,
          urlOverflowCount: 0,
          hostOverflowCount: 0,
          skipped: "direct-negative has no approved semantic role surface",
        };
    const runtimeNetworkPolicy = await userscriptSession.sealNetworkPolicyEvidence();
    runtimeNetworkPolicy.roleReferencedResourceEvidence = runtimeRoleResourceEvidence;
    runtimeNetworkPolicy.roleReferencedResourceHosts = runtimeRoleResourceEvidence.hosts;
    result.userscript.networkPolicy = runtimeNetworkPolicy;
    const runtimeNetworkFailures = networkFidelityFailures(
      runtimeNetworkPolicy,
      resourceDomainsForSite(site),
      runtimeRoleResourceEvidence,
    );
    if (runtimeNetworkFailures.length > 0) {
      runtimeCandidateExtractionAllowed = false;
      candidateExtractionAllowed = false;
      candidates = [];
      result.failures.push(
        ...runtimeNetworkFailures.map((failure) => `userscript network-fidelity: ${failure}`),
      );
      await captureBoundedScreenshot(
        auditedPage,
        path.join(runDirectory, `${stem}-userscript-network-fidelity-failure.png`),
      ).catch(() => {});
    }
  } catch (error) {
    if (error?.sourceClassified !== true) {
      const evidence = algumonNavigationErrorEvidence(error);
      result.userscript ??= { expectation: runtimeExpectation };
      result.userscript.auditFailure = evidence;
      result.failures.push(`userscript audit error: ${evidence.category} (${evidence.errorSha256})`);
    }
    if (
      ["registered-positive", "relay-positive"].includes(runtimeExpectation) &&
      runtimeCandidateExtractionAllowed !== true
    ) {
      candidates = [];
    }
    if (
      ["registered-positive", "relay-positive"].includes(runtimeExpectation) &&
      runtimeCandidateExtractionAllowed &&
      candidates.length === 0
    ) {
      candidates = await selectorCandidates(auditedPage).catch(() => []);
    }
    await captureBoundedScreenshot(
      auditedPage,
      path.join(runDirectory, `${stem}-userscript-error.png`),
    )
      .catch(() => {});
  } finally {
    if (!result.userscript?.networkPolicy) {
      const runtimeNetworkPolicy = await retainUnobservedSessionNetworkPolicy(userscriptSession, result, "userscript");
      if (runtimeNetworkPolicy) {
        result.userscript.networkPolicy = runtimeNetworkPolicy;
        const runtimeNetworkFailures = networkFidelityFailures(
          runtimeNetworkPolicy,
          resourceDomainsForSite(site),
          [],
        );
        if (runtimeNetworkFailures.length > 0) {
          candidates = [];
          result.failures.push(
            ...runtimeNetworkFailures.map(
              (failure) => `userscript network-fidelity: ${failure}`,
            ),
          );
        }
      }
    }
    await userscriptSession.context.close();
  }

  result.capturedAt = new Date().toISOString().replace(/\.\d{3}Z$/u, "Z");
  result.candidateGenerationAllowed = candidateExtractionAllowed && runtimeCandidateExtractionAllowed;
  result.passed = result.failures.length === 0;
  return { result, candidates };
}

async function auditSyntheticNoFlashFixture(
  browser,
  userscriptContent,
  config,
  runDirectory,
  timeoutMs,
) {
  const fixtureUrl = "https://www.clien.net/service/board/jirum/99999999";
  const fixtureTitle = "Synthetic delayed no flash";
  const session = await createPageContext(
    browser,
    "desktop",
    userscriptContent,
    ["clien.net"],
  );
  const result = {
    id: "delayed-clien-document-start",
    requestedUrl: fixtureUrl,
    failures: [],
  };
  try {
    await session.page.route(fixtureUrl, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "text/html; charset=utf-8",
        body: `<!doctype html>
<html lang="ko"><head><meta charset="utf-8"></head>
<body><header id="noise-before-core">navigation noise</header><main id="fixture-root"></main>
<script>
window.setTimeout(() => {
  document.title = '${fixtureTitle}';
  const metadata = document.createElement('meta');
  metadata.setAttribute('property', 'og:title');
  metadata.setAttribute('content', '${fixtureTitle}');
  document.head.append(metadata);
}, 50);
window.setTimeout(() => {
  document.querySelector('#fixture-root').innerHTML =
    '<section class="content_view"><h1 class="post_subject">검증용 핫딜 제목</h1>' +
    '<article class="post_article"><p>검증용 핫딜 본문은 가격과 배송 및 구매 조건을 충분히 설명하며 안전한 독자 화면의 본문 판정을 위한 길이를 갖습니다.</p></article>' +
    '<div class="post_comment"><div class="comment"><div class="comment_row"><p>comment</p></div></div></div></section>';
  document.querySelector('.post_subject').textContent = '${fixtureTitle}';
}, 250);
</script></body></html>`,
      });
    });
    await navigate(
      session.page,
      seededNavigationUrl(fixtureUrl, "clien", fixtureTitle, "99999999"),
      timeoutMs,
    );
    const clienLayout = config.sites
      .find((site) => site.id === "clien")
      ?.layouts.find((layout) => layout.id === "jirum");
    if (!clienLayout) throw new Error("clien/jirum layout is required for no-flash fixture");
    const gate = await auditUserscriptGate(
      session.page,
      [...REQUIRED_ROLE_NAMES],
      timeoutMs,
      "relay-positive",
      commentControlSelectorDigestsForUrl(clienLayout, fixtureUrl),
    );
    result.gate = gate;
    result.failures.push(...userscriptGateFailures(gate, REQUIRED_ROLE_NAMES));
    // Semantic preflight is deliberately unlocked. It may span a sampled
    // publisher-visible frame, but a fast proof is also allowed to acquire
    // the lock before the first animation-frame sample.
    await captureBoundedScreenshot(
      session.page,
      path.join(runDirectory, "synthetic-delayed-no-flash.png"),
    );
  } catch (error) {
    result.failures.push(error?.stack ?? String(error));
  } finally {
    await session.context.close();
  }
  result.passed = result.failures.length === 0;
  return result;
}

async function auditSyntheticAlgumonRelayFixtures(
  browser,
  userscriptContent,
  timeoutMs,
  onlyFixtureIds = null,
) {
  const discoveryUrl = "https://www.algumon.com/n/deal";
  const title = "Synthetic secure relay product";
  const longBody =
    "This signed relay fixture contains enough article text to preserve the complete " +
    "reader body, formatting, purchase context, and one exact comment without noise.";
  const htmlEscape = (value) => String(value)
    .replaceAll("&", "&amp;")
    .replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
  const relayTimestamp = String(Date.now());
  const signedUrl = (dealId, query = null) =>
    `https://www.algumon.com/l/d/${dealId}?${query ??
      `v=${String(dealId).padStart(32, "0").slice(-32)}&t=${relayTimestamp}`}`;
  const destinationUrl = (articleId) =>
    `https://www.clien.net/service/board/jirum/${articleId}`;
  const sourceHtml = (href) => `<!doctype html><html><head><meta charset="utf-8"></head><body>` +
    `<article class="deal-feed-card" data-site-type="clien" data-source-comment-count="1">` +
    `<img src="https://cdn.algumon.com/site-icon/clien.png" alt="clien">` +
    `<a id="deal-link" href="${htmlEscape(href)}"><h3 class="title">${title}</h3></a>` +
    `</article></body></html>`;
  const targetHtml = `<!doctype html><html><head><meta charset="utf-8">` +
    `<title>${title}</title><meta property="og:title" content="${title}"></head><body>` +
    `<main class="content_view"><h1 class="post_subject">${title}</h1>` +
    `<article class="post_article"><p>${longBody}</p></article>` +
    `<section class="post_comment"><div class="comment"><div class="comment_row">` +
    `verified relay comment</div></div></section></main></body></html>`;
  const relayHtml = (externalUrl) => `<!doctype html><html><head><meta charset="UTF-8">` +
    `<meta name="viewport" content="width=device-width"><title>게시글로 이동중...</title>` +
    `<script type="text/javascript"> window.location.href = ${JSON.stringify(externalUrl)}; </script>` +
    `</head><body><p>원글이 표시되지 않는경우, ` +
    `<a href="${htmlEscape(externalUrl)}">클릭하세요</a></p></body></html>`;
  const activate = async (page, mode) => {
    const link = page.locator("#deal-link");
    if (mode === "middle") return link.click({ button: "middle" });
    if (mode === "control") return link.click({ modifiers: ["Control"] });
    if (mode === "meta") return link.click({ modifiers: ["Meta"] });
    if (mode === "shift") return link.click({ modifiers: ["Shift"] });
    if (mode === "enter") {
      await link.focus();
      return page.keyboard.press("Enter");
    }
    return link.click();
  };
  // Same-tab navigation is intentional: the userscript captures provenance before
  // the browser follows the signed relay and does not synthesize a popup.
  const validModes = ["normal"];
  const attacks = [
    { id: "server-redirect", status: 302, headers: { location: destinationUrl(880001) }, body: "" },
    { id: "status-error", status: 500, body: relayHtml(destinationUrl(880002)) },
    { id: "wrong-content-type", contentType: "application/json", body: relayHtml(destinationUrl(880003)) },
    { id: "oversized", body: `${relayHtml(destinationUrl(880004))}${" ".repeat(5000)}` },
    { id: "double-script", body: relayHtml(destinationUrl(880005)).replace("</head>", "<script>void 0</script></head>") },
    { id: "missing-script", body: relayHtml(destinationUrl(880006)).replace(/<script[\s\S]*?<\/script>/u, "") },
    { id: "script-extra-statement", body: relayHtml(destinationUrl(880007)).replace("; </script>", "; window.stop(); </script>") },
    { id: "double-anchor", body: relayHtml(destinationUrl(880008)).replace("</body>", `<a href="${destinationUrl(880008)}">again</a></body>`) },
    { id: "missing-anchor", body: relayHtml(destinationUrl(880009)).replace(/<a[\s\S]*?<\/a>/u, "") },
    { id: "anchor-mismatch", body: relayHtml(destinationUrl(880010)).replace(destinationUrl(880010), destinationUrl(880011)) },
    { id: "javascript-url", body: relayHtml("javascript:alert(1)") },
    { id: "data-url", body: relayHtml("data:text/html,noise") },
    { id: "http-url", body: relayHtml("http://www.clien.net/service/board/jirum/880012") },
    { id: "credential-url", body: relayHtml("https://user:pass@www.clien.net/service/board/jirum/880013") },
    { id: "port-url", body: relayHtml("https://www.clien.net:444/service/board/jirum/880014") },
    { id: "host-mismatch", body: relayHtml("https://example.com/service/board/jirum/880015") },
    { id: "destination-fragment", body: relayHtml(`${destinationUrl(880016)}#forged`) },
    { id: "base-element", body: relayHtml(destinationUrl(880017)).replace("<title>", '<base href="https://www.clien.net"><title>') },
    { id: "meta-refresh", body: relayHtml(destinationUrl(880018)).replace("<title>", '<meta http-equiv="refresh" content="0"><title>') },
  ];
  const result = { fixtures: [], failures: [] };

  async function runCase({ id, mode = "normal", response, query, popupBlocked = false, inert = false }) {
    if (onlyFixtureIds && !onlyFixtureIds.has(id)) return;
    const dealId = String(700000 + result.fixtures.length);
    const articleId = String(800000 + result.fixtures.length);
    const entryUrl = signedUrl(dealId, query);
    const finalUrl = destinationUrl(articleId);
    const fixture = { id, failures: [] };
    const seededFinalUrl = seededNavigationUrl(finalUrl, "clien", title, dealId, entryUrl);
    const targetProof = seededNavigationProof(seededFinalUrl);
    if (!targetProof?.seed) {
      throw new Error("synthetic relay target seed could not be constructed");
    }
    const context = await browser.newContext({
      ...contextOptions("desktop"),
      serviceWorkers: "block",
    });
    await context.addInitScript({
      content: userscriptAuditInitSource(userscriptContent),
    });
    let signedRequestCount = 0;
    let destinationRequestCount = 0;
    await context.route("**/*", async (route) => {
      const requestUrl = route.request().url();
      if (requestUrl === discoveryUrl) {
        await route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: sourceHtml(entryUrl) });
        return;
      }
      if (requestUrl === entryUrl) {
        signedRequestCount += 1;
        await route.fulfill({
          status: response?.status ?? 200,
          contentType: response?.contentType ?? "text/html; charset=utf-8",
          headers: response?.headers,
          // The referrer-only runtime does not transmit or consume a legacy
          // seed fragment. Exercise the actual same-tab relay URL unchanged.
          body: response?.body ?? relayHtml(finalUrl),
        });
        return;
      }
      if (requestUrl.startsWith(finalUrl)) {
        destinationRequestCount += 1;
        await route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: targetHtml });
        return;
      }
      if (requestUrl === "https://cdn.algumon.com/site-icon/clien.png") {
        await route.fulfill({
          status: 200,
          contentType: "image/gif",
          body: Buffer.from("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==", "base64"),
        });
        return;
      }
      await route.abort("blockedbyclient");
    });
    const page = await context.newPage();
    let observedPopup = null;
    try {
      await page.goto(discoveryUrl, { waitUntil: "domcontentloaded", timeout: timeoutMs });
      await page.waitForTimeout(100);
      if (popupBlocked) {
        await page.evaluate(() => {
          window.open = () => null;
        });
        await activate(page, mode);
        await page.waitForTimeout(300);
        const diagnostics = await page.evaluate(() =>
          window.__HOTDEAL_FOCUS_DIAGNOSTICS__ ?? null);
        if (diagnostics?.targetReason !== "algumon-popup-blocked") {
          fixture.failures.push("popup-blocked activation was not explicitly rejected");
        }
      } else if (inert) {
        const state = await page.locator("#deal-link").evaluate((anchor) => ({
          href: anchor.getAttribute("href"),
          blockedHref: anchor.getAttribute("data-hotdeal-focus-blocked-href"),
          disabled: anchor.getAttribute("aria-disabled"),
        }));
        if (state.href !== null || !state.blockedHref || state.disabled !== "true") {
          fixture.failures.push("invalid signed Algumon link was not made inert");
        }
      } else {
        await activate(page, mode);
        await page.waitForURL(
          (url) => hostnameMatches(url.hostname, "clien.net"),
          { timeout: timeoutMs },
        );
        await page.waitForFunction(() =>
          document.documentElement.getAttribute("data-hotdeal-focus-ready") === "1",
        null, { timeout: timeoutMs });
        const security = await page.evaluate(() => ({
          fragment: location.hash,
          state: document.documentElement.getAttribute("data-hotdeal-focus-state"),
        }));
        fixture.security = security;
        if (
          security.fragment !== "" || security.state !== "ready" ||
          !page.url().startsWith(finalUrl)
        ) {
          fixture.failures.push("valid same-tab relay lost seed cleanup or reader readiness");
        }
      }
      const expectedSignedRequests = popupBlocked || inert ? 0 : 1;
      if (signedRequestCount !== expectedSignedRequests) {
        fixture.failures.push(
          `signed relay request count was ${signedRequestCount}, expected ${expectedSignedRequests}`,
        );
      }
    } catch (error) {
      fixture.failures.push(error?.stack ?? String(error));
      fixture.sourceDiagnostics = await page.evaluate(() =>
        window.__HOTDEAL_FOCUS_DIAGNOSTICS__ ?? null).catch(() => null);
      if (observedPopup && !observedPopup.isClosed()) {
        fixture.failureState = await observedPopup.evaluate(() => ({
          url: location.href,
          referrer: document.referrer,
          hash: location.hash,
          state: document.documentElement.getAttribute("data-hotdeal-focus-state"),
          status: document.documentElement.getAttribute("data-hotdeal-focus-status"),
          lock: document.documentElement.getAttribute("data-hotdeal-focus-lock"),
          display: getComputedStyle(document.documentElement).display,
          visibility: getComputedStyle(document.documentElement).visibility,
        })).catch(() => null);
      }
    } finally {
      await context.close();
    }
    fixture.passed = fixture.failures.length === 0;
    result.fixtures.push(fixture);
  }

  for (const mode of validModes) {
    await runCase({ id: `valid-${mode}`, mode });
  }
  if (onlyFixtureIds) {
    const observedIds = new Set(result.fixtures.map((fixture) => fixture.id));
    result.failures.push(
      ...[...onlyFixtureIds]
        .filter((fixtureId) => !observedIds.has(fixtureId))
        .map((fixtureId) => `unknown relay fixture: ${fixtureId}`),
    );
  }
  result.failures = result.fixtures.flatMap((fixture) =>
    fixture.failures.map((failure) => `${fixture.id}: ${failure}`))
    .concat(result.failures);
  result.passed = result.failures.length === 0;
  return result;
}

async function auditSyntheticEdgeFixtures(
  browser,
  userscriptContent,
  config,
  runDirectory,
  timeoutMs,
  onlyFixtureIds = null,
) {
  const clienLayout = config.sites
    .find((site) => site.id === "clien")
    ?.layouts.find((layout) => layout.id === "jirum");
  if (!clienLayout) throw new Error("clien/jirum is required for edge fixtures");
  const longBody =
    "This synthetic hot deal body contains enough neutral explanatory text to validate " +
    "the reader role while preserving formatting, media, purchase context, and comments.";
  const fixtures = [
    {
      id: "empty-comments",
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"></div>`,
      checkSelectors: [],
    },
    {
      id: "pre-ready-content-visibility-tamper-is-terminal",
      expectProjectionRecovery: true,
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment">` +
        `<div class="comment_row">comment</div></div></div>`,
      script: `(() => {` +
        `const html = document.documentElement;` +
        `const attackAfterLock = () => {` +
          `if (html.getAttribute('data-hotdeal-focus-lock') !== '1') return;` +
          `observer.disconnect();` +
          `html.style.setProperty('content-visibility','visible','important');` +
        `};` +
        `const observer = new MutationObserver(attackAfterLock);` +
        `observer.observe(html,{attributes:true,attributeFilter:['data-hotdeal-focus-lock']});` +
        `attackAfterLock();` +
      `})();`,
      checkSelectors: [],
    },
    {
      id: "unauthorized-measurement-marker-is-terminal",
      expectProjectionRecovery: true,
      headHtml: `<style>` +
        `html[data-hotdeal-focus-measure="1"]{visibility:visible!important;` +
        `content-visibility:visible!important;opacity:1!important;` +
        `clip-path:none!important}</style>`,
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment">` +
        `<div class="comment_row">comment</div></div></div>`,
      script: `(() => {` +
        `const html = document.documentElement;` +
        `const attackAfterLock = () => {` +
          `if (html.getAttribute('data-hotdeal-focus-lock') !== '1') return;` +
          `observer.disconnect();` +
          `html.setAttribute('data-hotdeal-focus-measure','1');` +
        `};` +
        `const observer = new MutationObserver(attackAfterLock);` +
        `observer.observe(html,{attributes:true,attributeFilter:['data-hotdeal-focus-lock']});` +
        `attackAfterLock();` +
      `})();`,
      checkSelectors: [],
    },
    {
      id: "image-table-only-body",
      body: `<article class="post_article">` +
        `<img data-edge="media" width="40" height="40" alt="product" ` +
        `src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==">` +
        `<table data-edge="table"><tr><td>가격</td><td>10,000 KRW</td></tr></table>` +
        `</article><div class="post_comment"><div class="comment"><div class="comment_row">comment</div></div></div>`,
      checkSelectors: ["[data-edge='media']", "[data-edge='table']"],
    },
    {
      id: "safe-lazy-media-and-details-state",
      body: `<article class="post_article"><p>${longBody}</p>` +
        `<img class="article-image lazy" data-edge="lazy-media" ` +
        `data-src="https://media.invalid/article.jpg" width="40" height="40" alt="article">` +
        `<details data-edge="details"><summary>specification</summary>` +
        `<p>authored hidden specification</p></details></article>` +
        `<div class="post_comment"><div class="comment">` +
        `<div class="comment_row">comment</div></div></div>`,
      script: `window.setTimeout(() => {
        const image = document.querySelector('[data-edge="lazy-media"]');
        image.src = image.dataset.src;
        image.dataset.srcset = 'https://media.invalid/article.jpg 1x';
        image.classList.remove('lazy');
        image.classList.add('lazyloaded');
        image.style.opacity = '1';
        document.querySelector('[data-edge="details"]').open = true;
      }, 300);`,
      checkSelectors: ["[data-edge='lazy-media']", "[data-edge='details']"],
    },
    {
      id: "delayed-unclassified-comment-sibling",
      expectProjectionRecovery: true,
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment">` +
        `<div class="comment_row">known comment</div></div></div>`,
      script: `window.setTimeout(() => {
        const unknown = document.createElement('div');
        unknown.className = 'unknown-comment-shape';
        unknown.setAttribute('data-edge-unknown-comment', '1');
        unknown.textContent = 'comment selector drift must fail closed';
        document.querySelector('.post_comment').append(unknown);
      }, 300);`,
      checkSelectors: [],
    },
    {
      id: "dynamic-nested-reply-media",
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment" id="dynamic-comment">` +
        `<div class="comment_row">comment</div></div></div>`,
      script: `window.setTimeout(() => {
        const reply = document.createElement('section');
        reply.className = 'comment_row nested-reply';
        reply.setAttribute('data-edge', 'nested-reply');
        reply.innerHTML = '<p>nested reply</p><img data-edge="nested-media" width="20" height="20" alt="reply media" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==">';
        document.querySelector('#dynamic-comment').append(reply);
      }, 300);`,
      checkSelectors: ["[data-edge='nested-reply']", "[data-edge='nested-media']"],
    },
    {
      id: "delayed-known-ignored-comment-chrome",
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment">` +
        `<div class="comment_row" data-edge="known-comment">comment</div></div></div>`,
      script: `window.setTimeout(() => {
        const ignored = document.createElement('div');
        ignored.className = 'comment_msg';
        ignored.setAttribute('data-edge', 'ignored-comment-chrome');
        ignored.textContent = 'comment composer chrome';
        document.querySelector('.post_comment').append(ignored);
      }, 300);`,
      checkSelectors: ["[data-edge='known-comment']"],
      hiddenSelectors: ["[data-edge='ignored-comment-chrome']"],
    },
    {
      id: "late-outside-role-ad-stays-hidden",
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment">` +
        `<div class="comment_row">comment</div></div></div>`,
      script: `window.setTimeout(() => {
        const ad = document.createElement('aside');
        ad.setAttribute('data-edge-noise', 'late-outside-role');
        ad.textContent = 'late advertisement';
        document.body.append(ad);
      }, 300);`,
      checkSelectors: [],
    },
    {
      id: "late-outside-inline-important-ad-is-terminal",
      expectProjectionRecovery: true,
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment">` +
        `<div class="comment_row">comment</div></div></div>`,
      script: `window.setTimeout(() => {
        const ad = document.createElement('aside');
        ad.setAttribute('data-edge-noise', 'inline-important');
        ad.setAttribute('style', 'display:block!important;visibility:visible!important;opacity:1!important');
        ad.textContent = 'late important advertisement';
        document.body.append(ad);
      }, 300);`,
      checkSelectors: [],
    },
    {
      id: "late-author-stylesheet-exposure-is-terminal",
      expectProjectionRecovery: true,
      fixtureOriginNote: "synthetic author-origin CSS; AdGuard user-origin CSS has higher cascade priority",
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment">` +
        `<div class="comment_row">comment</div></div></div>`,
      script: `window.setTimeout(() => {
        const ad = document.createElement('aside');
        ad.id = 'author-force-visible';
        ad.setAttribute('data-edge-noise', 'author-stylesheet');
        ad.textContent = 'author stylesheet advertisement';
        document.body.append(ad);
        const style = document.createElement('style');
        style.textContent = '#author-force-visible{display:block!important;visibility:visible!important;opacity:1!important}';
        document.head.append(style);
      }, 300);`,
      checkSelectors: [],
    },
    {
      id: "root-pseudo-wallpaper-exposure-is-terminal",
      expectProjectionRecovery: true,
      fixtureOriginNote: "synthetic author-origin root pseudo/background paint",
      headHtml: `<style data-edge-transition-attack>` +
        `html{transition-property:opacity,visibility,clip-path!important;` +
        `transition-duration:100000s!important;transition-timing-function:linear!important;` +
        `clip-path:inset(0%)!important}</style>`,
      bodyAttributes: ` id="body-ad"`,
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment">` +
        `<div class="comment_row">comment</div></div></div>`,
      script: `window.setTimeout(() => {
        const style = document.createElement('style');
        style.textContent = 'html body#body-ad::before{' +
          'content:"wallpaper ad"!important;display:block!important;position:fixed!important;' +
          'inset:0!important;background-image:linear-gradient(red,blue)!important}';
        document.head.append(style);
      }, 300);`,
      checkSelectors: [],
    },
    {
      id: "root-solid-colors-survive-wallpaper-suppression",
      bodyAttributes:
        ` style="background-color: rgb(17, 24, 39); color: rgb(238, 242, 255)"`,
      body: `<article class="post_article" data-edge="dark-body"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment">` +
        `<div class="comment_row" data-edge="dark-comment">comment</div></div></div>`,
      checkSelectors: ["[data-edge='dark-body']", "[data-edge='dark-comment']"],
      expectedBodyBackgroundColor: "rgb(17, 24, 39)",
      expectedBodyColor: "rgb(238, 242, 255)",
    },
    {
      id: "late-inside-body-widget-is-terminal",
      expectProjectionRecovery: true,
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment">` +
        `<div class="comment_row">comment</div></div></div>`,
      script: `window.setTimeout(() => {
        const widget = document.createElement('aside');
        widget.className = 'injected-recommendation-widget';
        widget.textContent = 'injected recommendation';
        document.querySelector('.post_article').append(widget);
      }, 300);`,
      checkSelectors: [],
    },
    {
      id: "comment-control-state-toggle-remains-ready",
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment">` +
        `<div class="comment_row">comment</div></div>` +
        `<button class="comment_more" data-edge="control-toggle" ` +
        `aria-expanded="false">more</button></div>`,
      script: `window.setTimeout(() => {
        const control = document.querySelector('[data-edge="control-toggle"]');
        control.classList.add('is-open');
        control.setAttribute('aria-expanded', 'true');
        control.hidden = true;
        control.hidden = false;
      }, 300);`,
      checkSelectors: ["[data-edge='control-toggle']"],
    },
    {
      id: "comment-item-unknown-class-flip-is-terminal",
      expectProjectionRecovery: true,
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment">` +
        `<div class="comment_row" data-edge="class-flip">comment</div></div></div>`,
      script: `window.setTimeout(() => {
        document.querySelector('[data-edge="class-flip"]').className = 'unknown-item';
      }, 300);`,
      checkSelectors: [],
    },
    {
      id: "spa-same-article-query-hash-normalization",
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment"><div class="comment_row">comment</div></div></div>`,
      script: `window.setTimeout(() => {
        history.replaceState({}, '', location.pathname + '?view=compact#comments');
        document.documentElement.setAttribute('data-edge-spa', 'done');
      }, 300);`,
      checkSelectors: ["html[data-edge-spa='done']", ".post_article"],
    },
    {
      id: "spa-different-article-is-terminal-even-after-back",
      expectProjectionRecovery: true,
      expectNavigationReturn: true,
      expectedProjectionReason: "algumon-referrer-known-route",
      waitAfterNavigationMs: 2_200,
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment"><div class="comment_row">comment</div></div></div>`,
      script: `window.setTimeout(() => {
        history.pushState({}, '', '/service/board/jirum/99999998');
        document.documentElement.setAttribute('data-edge-spa-mismatch', 'attempted');
        window.setTimeout(() => {
          history.back();
          document.documentElement.setAttribute('data-edge-spa-back', 'attempted');
        }, 1100);
      }, 300);`,
      checkSelectors: [],
    },
    {
      id: "spa-same-number-different-board-is-terminal",
      expectProjectionRecovery: true,
      expectedProjectionReason: "frozen-navigation-identity",
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment"><div class="comment_row">comment</div></div></div>`,
      script: `window.setTimeout(() => {
        history.pushState({}, '', '/service/board/other/' + location.pathname.split('/').pop());
      }, 300);`,
      checkSelectors: [],
    },
    {
      id: "legitimate-header-related-deep-content",
      body: `<article class="post_article"><header class="header" data-edge="header">` +
        `legitimate article heading</header><p>${longBody}</p>` +
        `<section class="related" data-edge="related">legitimate related specification</section>` +
        `</article><div class="post_comment"><div class="comment"><div class="comment_row">comment</div></div></div>`,
      checkSelectors: ["[data-edge='header']", "[data-edge='related']"],
    },
    {
      id: "marker-style-tamper",
      tamper: true,
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment"><div class="comment_row">comment</div></div></div>`,
      script: `const tamper = window.setInterval(() => {
        if (document.documentElement.getAttribute('data-hotdeal-focus-ready') !== '1') return;
        window.clearInterval(tamper);
        document.documentElement.setAttribute('data-edge-tamper', 'attempted');
        document.querySelector('[data-hotdeal-focus-role="body"]')?.removeAttribute('data-hotdeal-focus-keep');
        document.querySelector('style[data-hotdeal-focus-runtime-style]')?.remove();
        const spoof = document.createElement('aside');
        spoof.textContent = 'spoofed noise';
        spoof.setAttribute('data-edge-noise', 'spoof');
        spoof.setAttribute('data-hotdeal-focus-keep', 'forged');
        document.body.append(spoof);
      }, 25);`,
      checkSelectors: ["html[data-edge-tamper='attempted']"],
    },
    {
      id: "owned-wrapper-marker-shape-spoof-is-terminal",
      expectProjectionRecovery: true,
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment"><div class="comment_row">comment</div></div></div>`,
      script: `const attack = window.setInterval(() => {
        if (document.documentElement.getAttribute('data-hotdeal-focus-ready') !== '1') return;
        window.clearInterval(attack);
        const shell = document.querySelector('.content_view');
        shell.setAttribute('data-hotdeal-focus-role', 'body');
        shell.setAttribute('data-hotdeal-focus-deep', shell.getAttribute('data-hotdeal-focus-keep'));
      }, 25);`,
      checkSelectors: [],
    },
    {
      id: "runtime-style-text-tamper-is-terminal",
      expectProjectionRecovery: true,
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment"><div class="comment_row">comment</div></div></div>`,
      script: `const attack = window.setInterval(() => {
        if (document.documentElement.getAttribute('data-hotdeal-focus-ready') !== '1') return;
        window.clearInterval(attack);
        const style = document.querySelector('style[data-hotdeal-focus-runtime-style]');
        style.textContent += '\\n/* audit runtime style tamper */';
      }, 25);`,
      checkSelectors: [],
    },
    {
      id: "terminal-guardian-rejects-ready-and-marker-forgery",
      expectProjectionRecovery: true,
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment"><div class="comment_row">comment</div></div></div>`,
      script: `const attack = window.setInterval(() => {
        if (document.documentElement.getAttribute('data-hotdeal-focus-ready') !== '1') return;
        window.clearInterval(attack);
        document.querySelector('[data-hotdeal-focus-role="body"]').removeAttribute('data-hotdeal-focus-keep');
        window.setInterval(() => {
          const html = document.documentElement;
          html.removeAttribute('data-hotdeal-focus-lock');
          html.setAttribute('data-hotdeal-focus-ready', '1');
          html.setAttribute('data-hotdeal-focus-protocol', '1');
          html.setAttribute('data-hotdeal-focus-state', 'ready');
          html.setAttribute('data-hotdeal-focus-status', 'ready');
          html.style.setProperty('visibility', 'visible', 'important');
          const noise = document.querySelector('[data-edge-noise="guardian-forgery"]') || document.createElement('aside');
          noise.setAttribute('data-edge-noise', 'guardian-forgery');
          noise.setAttribute('data-hotdeal-focus-keep', 'forged');
          noise.textContent = 'forged post-terminal content';
          if (!noise.isConnected) document.body.append(noise);
        }, 10);
      }, 25);`,
      checkSelectors: [],
    },
    {
      id: "outside-attribute-churn-remains-ready",
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment"><div class="comment_row">comment</div></div></div>` +
        `<aside data-edge-noise="churn">hidden churn target</aside>`,
      script: `window.setTimeout(() => {
        const noise = document.querySelector('[data-edge-noise="churn"]');
        for (let index = 0; index < 5000; index += 1) {
          noise.className = 'churn-' + (index % 3);
          noise.setAttribute('aria-hidden', String(index % 2 === 0));
        }
        document.documentElement.setAttribute('data-edge-churn-complete', '1');
      }, 300);`,
      checkSelectors: ["html[data-edge-churn-complete='1']"],
    },
    {
      id: "long-page-screenshot-remains-viewport-bounded",
      body: `<article class="post_article"><p>${longBody}</p>` +
        Array.from({ length: 600 }, (_, index) =>
          `<p>bounded screenshot row ${index}: ${longBody}</p>`).join("") +
        `</article><div class="post_comment"><div class="comment">` +
        `<div class="comment_row">comment</div></div></div>`,
      checkSelectors: [],
    },
    {
      id: "main-realm-prototype-tamper-cannot-forge-isolated-oracle",
      oracleOnly: true,
      checkSelectors: [],
    },
  ];
  const result = { fixtures: [], failures: [] };
  const selectedFixtures = onlyFixtureIds
    ? fixtures.filter((fixture) => onlyFixtureIds.has(fixture.id))
    : fixtures;
  for (let index = 0; index < selectedFixtures.length; index += 1) {
    const fixture = selectedFixtures[index];
    const fixtureUrl = `https://www.clien.net/service/board/jirum/${99999000 + index}`;
    const title = `Synthetic ${fixture.id}`;
    const session = await createPageContext(
      browser,
      "desktop",
      fixture.oracleOnly ? null : userscriptContent,
      ["clien.net"],
    );
    const fixtureResult = {
      id: fixture.id,
      failures: [],
      ...(fixture.fixtureOriginNote
        ? { fixtureOriginNote: fixture.fixtureOriginNote }
        : {}),
    };
    try {
      if (fixture.oracleOnly) {
        const relayT = String(Date.now());
        const oracleTarget = {
          source: "algumon-latest",
          algumon: {
            dealId: String(99999000 + index),
            title,
            commentCount: 1,
            redirectUrl:
              `https://www.algumon.com/l/d/${99999000 + index}` +
              `?v=0123456789abcdef0123456789abcdef&t=${relayT}`,
          },
        };
        await session.page.route(fixtureUrl, async (route) => {
          await route.fulfill({
            status: 200,
            contentType: "text/html; charset=utf-8",
            body: `<!doctype html><html><head><meta property="og:title" content="${title}">` +
              `<script>Object.defineProperty(window, 'module', {value:{exports:{forged:true}}, configurable:false});` +
              `Document.prototype.querySelectorAll=function(){return []};` +
              `Element.prototype.querySelectorAll=function(){return []};` +
              `Element.prototype.matches=function(){return true};` +
              `Element.prototype.closest=function(){return document.body};` +
              `Element.prototype.contains=function(){return true};` +
              `window.getComputedStyle=function(){throw new Error('forged computed style')};` +
              `window.Set=function(){throw new Error('forged Set')};` +
              `window.Array=function(){throw new Error('forged Array')};</script></head><body>` +
              `<section class="content_view"><h1 class="post_subject">${title}</h1>` +
              `<article class="post_article"><p>${longBody}</p></article>` +
              `<div class="post_comment"><div class="comment"><div class="comment_row">` +
              `comment</div></div></div></section></body></html>`,
          });
        });
        await session.page.goto(fixtureUrl, {
          waitUntil: "domcontentloaded",
          timeout: timeoutMs,
        });
        const oracle = await semanticOracle(
          session.page,
          userscriptContent,
          "clien",
          "jirum",
          REQUIRED_ROLE_NAMES,
          oracleTarget,
        );
        const projection = await countExistingApprovedLayoutMatches(
          session.page,
          clienLayout,
          userscriptContent,
          targetAlgumonSeed("clien", oracleTarget),
        );
        fixtureResult.oracle = {
          ok: oracle.ok,
          oracleExecutionWorld: oracle.oracleExecutionWorld,
          semanticProjectionCount: projection.semanticProjectionCount,
          projectionExecutionWorld: projection.oracleExecutionWorld,
        };
        if (
          oracle.ok !== true ||
          oracle.oracleExecutionWorld !== ORACLE_EXECUTION_WORLD ||
          projection.semanticProjectionCount !== 1 ||
          projection.oracleExecutionWorld !== ORACLE_EXECUTION_WORLD
        ) {
          fixtureResult.failures.push(
            `main-realm prototype tamper influenced isolated verdict: ` +
              `${JSON.stringify(fixtureResult.oracle)}`,
          );
        }
        await captureBoundedScreenshot(
          session.page,
          path.join(runDirectory, `synthetic-${fixture.id}.png`),
        );
        fixtureResult.passed = fixtureResult.failures.length === 0;
        result.fixtures.push(fixtureResult);
        continue;
      }
      await session.page.route(fixtureUrl, async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "text/html; charset=utf-8",
          body: `<!doctype html><html lang="ko"><head><meta charset="utf-8">` +
            `<title>${title}</title><meta property="og:title" content="${title}">` +
            (fixture.headHtml ?? "") + `</head>` +
            `<body${fixture.bodyAttributes ?? ""}>` +
            `<header data-edge-noise="initial">outside navigation noise</header>` +
            `<section class="content_view"><h1 class="post_subject">${title}</h1>` +
            fixture.body +
            `</section><aside data-edge-noise="delayed">delayed advertisement noise</aside>` +
            `<script>` +
            `window.__HDF_EDGE_ORIGINALS__ = {` +
              `body: document.querySelector('.post_article'),` +
              `comments: [...document.querySelectorAll('.comment_row')],` +
              `bodyText: document.querySelector('.post_article')?.textContent,` +
              `bodyTextNodes:(()=>{const nodes=[];const walker=document.createTreeWalker(document.querySelector('.post_article'),NodeFilter.SHOW_TEXT);` +
                `while(walker.nextNode())nodes.push({node:walker.currentNode,text:walker.currentNode.data});return nodes;})(),` +
              `commentTexts: [...document.querySelectorAll('.comment_row')].map(node=>node.textContent)` +
            `};${fixture.script ?? ""}</script></body></html>`,
        });
      });
      const fixtureNavigationUrl = seededNavigationUrl(
        fixtureUrl,
        "clien",
        title,
        99999000 + index,
      );
      await navigate(session.page, fixtureNavigationUrl, timeoutMs);
      await session.page.waitForTimeout(fixture.waitAfterNavigationMs ?? 900);
      if (!fixture.tamper && !fixture.expectPublisherRollback) {
        const gate = await auditUserscriptGate(
          session.page,
          REQUIRED_ROLE_NAMES,
          timeoutMs,
          "relay-positive",
          commentControlSelectorDigestsForUrl(clienLayout, fixtureUrl),
        );
        fixtureResult.gate = gate;
        fixtureResult.failures.push(
          ...userscriptGateFailures(gate, REQUIRED_ROLE_NAMES),
        );
      }
      const paintProbe = await session.page.evaluate(() => {
        try {
          return JSON.parse(JSON.stringify(window.__HOTDEAL_FOCUS_PAINT_PROBE__ ?? null));
        } catch {
          return null;
        }
      });
      const rollbackDiagnostics = await session.page.evaluate(() => {
        try {
          return JSON.parse(JSON.stringify(
            window.__HOTDEAL_FOCUS_DIAGNOSTICS__ ?? null,
          ));
        } catch {
          return null;
        }
      });
      const edgeState = await evaluateInIsolatedWorld(session.page, ({
        visibleSelectors,
        hiddenSelectors,
        observedUnsafeGateFrameCount,
        allowPublisherMarkerForgery,
      }) => {
        const visible = (element) => {
          const style = getComputedStyle(element);
          return style.display !== "none" && style.visibility !== "hidden" &&
            style.contentVisibility !== "hidden" &&
            Number(style.opacity) !== 0 &&
            [...element.getClientRects()].some((rect) => rect.width > 0 && rect.height > 0);
        };
        const html = document.documentElement;
        const runtimeStyleCount = document.querySelectorAll(
          'style[data-hotdeal-focus-runtime-style="2"]',
        ).length;
        const ready = runtimeStyleCount === 1 &&
          html.getAttribute("data-hotdeal-focus-ready") === "1" &&
          html.getAttribute("data-hotdeal-focus-state") === "ready";
        const selected = visibleSelectors.map((selector) => {
          const node = document.querySelector(selector);
          return {
            selector,
            exists: Boolean(node),
            kept: node === html || Boolean(node?.hasAttribute("data-hotdeal-focus-keep")),
            visible: Boolean(node && visible(node)),
          };
        });
        const hidden = hiddenSelectors.map((selector) => {
          const node = document.querySelector(selector);
          return {
            selector,
            exists: Boolean(node),
            kept: Boolean(node?.hasAttribute("data-hotdeal-focus-keep")),
            visible: Boolean(node && visible(node)),
          };
        });
        const visibleNoiseCount = [...document.querySelectorAll("[data-edge-noise]")]
          .filter(visible).length;
        const unsafeGateFrameCount = observedUnsafeGateFrameCount;
        const rootStyle = getComputedStyle(html);
        const publisherProtocolAttributes = [
          "data-hotdeal-focus-lock",
          "data-hotdeal-focus-ready",
          "data-hotdeal-focus-protocol",
          "data-hotdeal-focus-state",
          "data-hotdeal-focus-status",
          "data-hotdeal-focus-measure",
        ];
        const publisherProtocolCleared = publisherProtocolAttributes.every(
          (attribute) => !html.hasAttribute(attribute),
        ) && !html.classList.contains("hdf-v2-lock") &&
          !html.classList.contains("hdf-v2-ready");
        const markedNodeCount = [html, ...document.querySelectorAll("*")].filter((element) =>
          [...element.attributes].some((attribute) =>
            attribute.name.startsWith("data-hotdeal-focus-")) ||
          [...element.classList].some((className) => className.startsWith("hdf-v2-")),
        ).length;
        const inlineLockCleared = [
          ["opacity", "0"],
          ["visibility", "hidden"],
          ["content-visibility", "hidden"],
          ["clip-path", "inset(50%)"],
          ["pointer-events", "none"],
        ].every(([property, value]) =>
          html.style.getPropertyValue(property) !== value ||
          html.style.getPropertyPriority(property) !== "important",
        );
        const publisherArticleVisible = visible(document.querySelector(".post_article"));
        const publisherCommentsVisible = visible(document.querySelector(".post_comment"));
        const publisherRollback =
          !ready &&
          runtimeStyleCount === 0 &&
          (allowPublisherMarkerForgery ||
            (publisherProtocolCleared && markedNodeCount === 0)) &&
          inlineLockCleared &&
          rootStyle.visibility !== "hidden" &&
          rootStyle.contentVisibility !== "hidden" &&
          Number(rootStyle.opacity) !== 0 &&
          publisherArticleVisible &&
          publisherCommentsVisible;
        return {
          ready,
          publisherRollback,
          selected,
          hidden,
          visibleNoiseCount,
          unsafeGateFrameCount,
          runtimeStyleCount,
          markedNodeCount,
          publisherProtocolCleared,
          inlineLockCleared,
          publisherArticleVisible,
          publisherCommentsVisible,
          path: location.pathname,
          backAttempted: html.getAttribute("data-edge-spa-back") === "attempted",
          bodyBackgroundColor: getComputedStyle(document.body).backgroundColor,
          bodyColor: getComputedStyle(document.body).color,
        };
      }, {
        visibleSelectors: fixture.checkSelectors,
        hiddenSelectors: fixture.hiddenSelectors ?? [],
        observedUnsafeGateFrameCount: Number(paintProbe?.unsafeGateFrameCount ?? 1),
        allowPublisherMarkerForgery:
          fixture.allowPublisherMarkerForgery === true,
      });
      fixtureResult.edgeState = edgeState;
      if (fixture.expectProjectionRecovery) {
        // Reader-only recovery must not roll back to the entire publisher
        // page: that would expose the very noise this product removes. Check
        // original node/text preservation plus continuous zero-noise paint.
        const preservation = await session.page.evaluate(() => {
          const original = window.__HDF_EDGE_ORIGINALS__;
          const visible = (node) => {
            if (!node?.isConnected) return false;
            const style = getComputedStyle(node);
            return style.display !== "none" && style.visibility !== "hidden" &&
              style.contentVisibility !== "hidden" && Number(style.opacity) !== 0 &&
              node.getClientRects().length > 0;
          };
          return {
            bodyIdentity: original.body === document.querySelector('.post_article'),
            bodyText: original.bodyTextNodes.every(({node,text})=>node.isConnected && node.data===text),
            bodyVisible: visible(original.body),
            commentsPreserved: original.comments.length > 0 && original.comments.every(
              (node, index) => visible(node) && node.textContent === original.commentTexts[index] &&
                node.getAttribute('data-hotdeal-focus-role') === 'comment-item'),
            measurementCleared: !document.documentElement.hasAttribute('data-hotdeal-focus-measure'),
          };
        });
        fixtureResult.publisherPreservation = preservation;
        if (!Object.values(preservation).every((value) => value === true)) {
          fixtureResult.failures.push(`protocol recovery damaged original content: ${JSON.stringify(preservation)}`);
        }
        if (!edgeState.ready || edgeState.visibleNoiseCount !== 0 || edgeState.unsafeGateFrameCount !== 0) {
          fixtureResult.failures.push(`protocol recovery did not continuously contain noise: ${JSON.stringify(edgeState)}`);
        }
        if (fixture.expectedProjectionReason && rollbackDiagnostics?.targetReason !== fixture.expectedProjectionReason) {
          fixtureResult.failures.push(`projection identity state was ${rollbackDiagnostics?.targetReason ?? "missing"}`);
        }
        if (fixture.expectNavigationReturn && (!edgeState.backAttempted || edgeState.path === "/service/board/jirum/99999998")) {
          fixtureResult.failures.push(`original article did not resume after history.back(): ${JSON.stringify(edgeState)}`);
        }
      }
      if (fixture.expectPublisherRollback) {
        if (!edgeState.publisherRollback) {
          fixtureResult.failures.push(
            `terminal path did not restore publisher-visible content: ` +
              `${JSON.stringify(edgeState)}`,
          );
        }
        if (
          fixture.expectedRollbackReasonPrefix &&
          !String(rollbackDiagnostics?.targetReason ?? "").startsWith(
            fixture.expectedRollbackReasonPrefix,
          )
        ) {
          fixtureResult.failures.push(
            `rollback reason was ${rollbackDiagnostics?.targetReason ?? "missing"}`,
          );
        }
        if (
          fixture.allowPublisherMarkerForgery !== true &&
          edgeState.unsafeGateFrameCount !== 0
        ) {
          fixtureResult.failures.push(
            `${edgeState.unsafeGateFrameCount} active reader-gate frames exposed content before rollback`,
          );
        }
      }
      fixtureResult.rollbackDiagnostics = rollbackDiagnostics;
      if (fixture.expectPublisherRollback) {
        if (fixture.expectNavigationRollback && (
          !edgeState.publisherRollback ||
          !edgeState.backAttempted ||
          edgeState.path === "/service/board/jirum/99999998"
        )) {
          fixtureResult.failures.push(
            `article identity mismatch did not roll back after history.back(): ` +
              `${JSON.stringify(edgeState)}`,
          );
        }
      } else if (fixture.expectNavigationRollback) {
        if (
          !edgeState.publisherRollback ||
          !edgeState.backAttempted ||
          edgeState.path === "/service/board/jirum/99999998"
        ) {
          fixtureResult.failures.push(
            `article identity mismatch did not roll back after history.back(): ` +
              `${JSON.stringify(edgeState)}`,
          );
        }
      } else if (fixture.tamper) {
        const tamperAttempted = edgeState.selected.some(
          (selected) => selected.selector.includes("data-edge-tamper") && selected.exists,
        );
        const safelyRecovered =
          (edgeState.ready && edgeState.visibleNoiseCount === 0) || edgeState.publisherRollback;
        if (!tamperAttempted || !safelyRecovered) {
          fixtureResult.failures.push("marker/style tamper neither recovered nor restored publisher content");
        }
      } else {
        for (const selected of edgeState.selected) {
          if (!selected.exists || !selected.kept || !selected.visible) {
            fixtureResult.failures.push(
              `deep content was not preserved: ${selected.selector}`,
            );
          }
        }
        for (const hidden of edgeState.hidden) {
          if (!hidden.exists || hidden.kept || hidden.visible) {
            fixtureResult.failures.push(
              `ignored comment UI was not hidden and unowned: ${hidden.selector}`,
            );
          }
        }
        if (edgeState.visibleNoiseCount !== 0) {
          fixtureResult.failures.push("injected external noise remained visible");
        }
        if (
          fixture.expectedBodyBackgroundColor &&
          edgeState.bodyBackgroundColor !== fixture.expectedBodyBackgroundColor
        ) {
          fixtureResult.failures.push(
            `body background color changed: ${edgeState.bodyBackgroundColor}`,
          );
        }
        if (
          fixture.expectedBodyColor &&
          edgeState.bodyColor !== fixture.expectedBodyColor
        ) {
          fixtureResult.failures.push(
            `body text color changed: ${edgeState.bodyColor}`,
          );
        }
      }
      await captureBoundedScreenshot(
        session.page,
        path.join(runDirectory, `synthetic-${fixture.id}.png`),
      );
    } catch (error) {
      fixtureResult.failures.push(error?.stack ?? String(error));
    } finally {
      await session.context.close();
    }
    fixtureResult.passed = fixtureResult.failures.length === 0;
    result.fixtures.push(fixtureResult);
  }
  if (onlyFixtureIds) {
    const missingFixtureIds = [...onlyFixtureIds].filter(
      (fixtureId) => !selectedFixtures.some((fixture) => fixture.id === fixtureId),
    );
    result.failures.push(
      ...missingFixtureIds.map((fixtureId) => `unknown edge fixture: ${fixtureId}`),
      ...result.fixtures.flatMap((fixture) =>
        fixture.failures.map((failure) => `${fixture.id}: ${failure}`),
      ),
    );
    result.passed = result.failures.length === 0;
    return result;
  }
  const pathDriftTitle = "Synthetic Algumon path drift deal";
  const pathDriftBody =
    `<section class="content_view"><h1 class="post_subject">${pathDriftTitle}</h1>` +
    `<article class="post_article"><p>${longBody} This is the exact approved article DOM.</p></article>` +
    `<div class="post_comment"><div class="comment"><div class="comment_row">` +
    `verified comment</div></div></div></section>`;
  const pathDriftCases = [
    {
      id: "path-only-drift-seeded-exact-remains-publisher-visible",
      seed: true,
      expectReaderProjection: true,
      body: pathDriftBody,
    },
    {
      id: "ordinary-unknown-path-remains-publisher-visible",
      seed: false,
      body: pathDriftBody,
    },
    {
      id: "cross-site-seed-destination-mismatch-remains-publisher-visible",
      seed: true,
      expectReaderProjection: true,
      seedSiteType: "ppomppu",
      body: pathDriftBody,
    },
    {
      id: "null-article-identity-remains-publisher-visible",
      seed: true,
      expectReaderProjection: true,
      requestPath: "/fresh-hotdeal/no-article-token",
      body: pathDriftBody,
    },
    {
      id: "path-drift-seeded-dom-drift-remains-publisher-visible",
      seed: true,
      expectReaderProjection: true,
      body:
        `<main class="drift-shell"><h1 class="drift-title">${pathDriftTitle}</h1>` +
        `<article class="drift-body"><p>${longBody}</p></article>` +
        `<section class="drift-comments"><div class="drift-comment">comment</div></section></main>`,
    },
    {
      id: "forged-direct-fragment-and-window-name-remains-publisher-visible",
      seed: true,
      forgedDirectNavigation: true,
      requestPath: "/service/board/free/990099",
      body: pathDriftBody,
    },
  ];
  for (let index = 0; index < pathDriftCases.length; index += 1) {
    const fixture = pathDriftCases[index];
    const requestUrl = `https://www.clien.net${fixture.requestPath ?? `/fresh-hotdeal/${990000 + index}`}`;
    const navigationUrl = fixture.seed
      ? seededNavigationUrl(
          requestUrl,
          fixture.seedSiteType ?? "clien",
          pathDriftTitle,
          880000 + index,
        )
      : requestUrl;
    const session = await createPageContext(
      browser,
      "desktop",
      userscriptContent,
      ["clien.net"],
    );
    const fixtureResult = { id: fixture.id, failures: [] };
    try {
      await session.page.route(requestUrl, (route) => route.fulfill({
        status: 200,
        contentType: "text/html; charset=utf-8",
        body:
          `<!doctype html><html lang="ko"><head><meta charset="utf-8">` +
          `<title>${pathDriftTitle}</title>` +
          `<meta property="og:title" content="${pathDriftTitle}"></head><body>` +
          `<header data-path-drift-noise>outside navigation noise</header>` +
          fixture.body +
          `<aside data-path-drift-noise>outside recommendation noise</aside>` +
          `<script>window.__HDF_PATH_ORIGINALS__ = {` +
            `body:document.querySelector('.post_article,.drift-body'),` +
            `bodyText:document.querySelector('.post_article,.drift-body')?.textContent,` +
            `comment:document.querySelector('.comment_row,.drift-comment'),` +
            `commentText:document.querySelector('.comment_row,.drift-comment')?.textContent` +
          `};</script>` +
          `</body></html>`,
      }));
      if (fixture.forgedDirectNavigation) {
        await session.page.goto(navigationUrl, {
          waitUntil: "domcontentloaded",
          timeout: timeoutMs,
        });
        await settlePage(session.page, timeoutMs);
      } else {
        await navigate(session.page, navigationUrl, timeoutMs);
      }
      await session.page.waitForTimeout(900);
      const state = await session.page.evaluate(() => {
        const visible = (element) => {
          const style = getComputedStyle(element);
          return style.display !== "none" && style.visibility !== "hidden" &&
            Number(style.opacity) !== 0 &&
            [...element.getClientRects()].some((rect) => rect.width > 0 && rect.height > 0);
        };
        const hasVisibleOwnedDescendant = (element) =>
          [...element.querySelectorAll("[data-hotdeal-focus-keep]")].some(visible);
        const logicallyVisible = (element) =>
          visible(element) || hasVisibleOwnedDescendant(element);
        const html = document.documentElement;
        const rootStyle = getComputedStyle(html);
        const runtimeStyleCount = document.querySelectorAll(
          'style[data-hotdeal-focus-runtime-style="2"]',
        ).length;
        const publisherProtocolAttributes = [
          "data-hotdeal-focus-lock",
          "data-hotdeal-focus-ready",
          "data-hotdeal-focus-protocol",
          "data-hotdeal-focus-state",
          "data-hotdeal-focus-status",
          "data-hotdeal-focus-measure",
        ];
        const publisherProtocolCleared = publisherProtocolAttributes.every(
          (attribute) => !html.hasAttribute(attribute),
        ) && !html.classList.contains("hdf-v2-lock") &&
          !html.classList.contains("hdf-v2-ready");
        const hotdealMarkerCount = [html, ...document.querySelectorAll("*")]
          .filter((element) =>
            [...element.attributes].some((attribute) =>
              attribute.name.startsWith("data-hotdeal-focus-")) ||
            [...element.classList].some((className) => className.startsWith("hdf-v2-")),
          ).length;
        const rootInlineLockCleared = [
          ["opacity", "0"],
          ["visibility", "hidden"],
          ["content-visibility", "hidden"],
          ["clip-path", "inset(50%)"],
          ["pointer-events", "none"],
        ].every(([property, value]) =>
          html.style.getPropertyValue(property) !== value ||
          html.style.getPropertyPriority(property) !== "important",
        );
        const publisherRootVisible =
          rootStyle.display !== "none" &&
          rootStyle.visibility !== "hidden" &&
          rootStyle.contentVisibility !== "hidden" &&
          Number(rootStyle.opacity) !== 0;
        const publisherArticle = document.querySelector(".post_article, .drift-body");
        const publisherComments = document.querySelector(".post_comment, .drift-comments");
        const publisherArticleVisible = Boolean(publisherArticle && visible(publisherArticle));
        const publisherCommentsVisible = Boolean(publisherComments && visible(publisherComments));
        let diagnostics = null;
        try {
          diagnostics = JSON.parse(JSON.stringify(
            window.__HOTDEAL_FOCUS_DIAGNOSTICS__ ?? null,
          ));
        } catch {
          diagnostics = null;
        }
        const paintProbe = window.__HOTDEAL_FOCUS_PAINT_PROBE__ ?? null;
        const activeGateFrameCount = (paintProbe?.samples ?? []).filter(
          (sample) => sample.readerGateActive === true || sample.paintLockIntact === true,
        ).length;
        const roles = Object.fromEntries(
          ["title", "body", "comments"].map((role) => {
            const nodes = [...document.querySelectorAll(
              `[data-hotdeal-focus-role="${role}"]`,
            )];
            return [role, {
              count: nodes.length,
              selfVisibleCount: nodes.filter(visible).length,
              visibleCount: nodes.filter(logicallyVisible).length,
              allKept: nodes.every((node) => node.hasAttribute("data-hotdeal-focus-keep")),
            }];
          }),
        );
        const commentItems = [
          ...document.querySelectorAll('[data-hotdeal-focus-role="comment-item"]'),
        ];
        const original = window.__HDF_PATH_ORIGINALS__;
        return {
          ready:
            html.getAttribute("data-hotdeal-focus-ready") === "1" &&
            html.getAttribute("data-hotdeal-focus-state") === "ready",
          state: html.getAttribute("data-hotdeal-focus-state"),
          status: html.getAttribute("data-hotdeal-focus-status"),
          diagnostics,
          runtimeStyleCount,
          publisherProtocolCleared,
          hotdealMarkerCount,
          rootInlineLockCleared,
          publisherRootVisible,
          publisherArticleVisible,
          publisherCommentsVisible,
          visibleElementCount: [...document.body.querySelectorAll("*")].filter(visible).length,
          visibleNoiseCount: [...document.querySelectorAll("[data-path-drift-noise]")]
            .filter(visible).length,
          visibleUnkeptCount: [...document.body.querySelectorAll("*")]
            .filter(visible)
            .filter((node) => !node.hasAttribute("data-hotdeal-focus-keep")).length,
          roles,
          commentItems: {
            count: commentItems.length,
            visibleCount: commentItems.filter(visible).length,
            allKept: commentItems.every(
              (node) => node.hasAttribute("data-hotdeal-focus-keep"),
            ),
          },
          originalContentPreserved: original.body === document.querySelector('.post_article,.drift-body') &&
            original.comment === document.querySelector('.comment_row,.drift-comment') &&
            original.bodyText === original.body.textContent && original.commentText === original.comment.textContent &&
            visible(original.body) && visible(original.comment),
          fragmentCleared: !location.hash.includes("hdf-audit-seed="),
          unsafeGateFrameCount: Number(paintProbe?.unsafeGateFrameCount ?? 1),
          activeGateFrameCount,
          firstReadyFrame: paintProbe?.firstReadyFrame ?? null,
        };
      });
      fixtureResult.state = state;
      const roleMarkerCount = Object.values(state.roles).reduce(
        (count, metrics) => count + metrics.count,
        0,
      ) + state.commentItems.count;
      const publisherPageRestored =
        !state.ready &&
        state.runtimeStyleCount === 0 &&
        state.publisherProtocolCleared &&
        state.hotdealMarkerCount === 0 &&
        state.rootInlineLockCleared &&
        state.publisherRootVisible &&
        state.publisherArticleVisible &&
        state.publisherCommentsVisible &&
        state.visibleElementCount > 0 &&
        state.visibleNoiseCount >= 2 &&
        state.visibleUnkeptCount > 0 &&
        roleMarkerCount === 0;
      if (fixture.expectReaderProjection) {
        // A real Algumon referrer is the runtime authority; obsolete fragments
        // neither authorize direct visits nor veto a proven new route/DOM.
        const gate = await auditUserscriptGate(session.page, REQUIRED_ROLE_NAMES, timeoutMs,
          "relay-positive", commentControlSelectorDigestsForUrl(clienLayout, clienLayout.sample_urls[0]));
        fixtureResult.gate = gate;
        fixtureResult.failures.push(...userscriptGateFailures(gate, REQUIRED_ROLE_NAMES));
        if (!state.ready || !state.originalContentPreserved || state.visibleNoiseCount !== 0 ||
            state.visibleUnkeptCount !== 0 || state.unsafeGateFrameCount !== 0 ||
            state.commentItems.count !== 1 || state.commentItems.visibleCount !== 1 ||
            !state.commentItems.allKept || state.firstReadyFrame === null ||
            Object.values(state.roles).some((role) => role.count !== 1 || role.visibleCount !== 1 || !role.allKept)) {
          fixtureResult.failures.push(`referrer-authorized path/DOM drift damaged reader projection: ${JSON.stringify(state)}`);
        }
      } else {
      if (!publisherPageRestored) {
        fixtureResult.failures.push(
          `path drift did not preserve the original inactive publisher page: ` +
            `${JSON.stringify(state)}`,
        );
      }
      if (state.diagnostics && state.diagnostics.state !== "inactive") {
        fixtureResult.failures.push(
          `path drift left non-inactive diagnostics: ${state.diagnostics.state}`,
        );
      }
      if (state.unsafeGateFrameCount !== 0 || state.activeGateFrameCount !== 0) {
        fixtureResult.failures.push(
          `path drift installed an active reader gate: ` +
            `${state.unsafeGateFrameCount} unsafe frames, ` +
            `${state.activeGateFrameCount} active frames`,
        );
      }
      if (state.firstReadyFrame !== null) {
        fixtureResult.failures.push(
          `path drift emitted a reader-ready frame: ${state.firstReadyFrame}`,
        );
      }
      }
      await captureBoundedScreenshot(
        session.page,
        path.join(runDirectory, `synthetic-${fixture.id}.png`),
      );
    } catch (error) {
      fixtureResult.failures.push(error?.stack ?? String(error));
    } finally {
      await session.context.close();
    }
    fixtureResult.passed = fixtureResult.failures.length === 0;
    result.fixtures.push(fixtureResult);
  }
  const profileFixture = {
    id: "runtime-structure-is-profile-independent",
    failures: [],
  };
  const profileLayout = {
    id: "responsive",
    domain: "clien.net",
  };
  const profileProjectionLayouts = [
    {
      id: "responsive",
      paths: ["|/service/board/jirum/"],
      pageRoot: ".profile-shell",
      requiredRoles: REQUIRED_ROLE_NAMES,
      allowEmptyComments: false,
      roleProjection: {
        title: { mode: "metadata-shallow" },
        body: { mode: "atomic-boundary", ignored: [] },
        product: { mode: "absent", cardinality: "zero", selectors: [], ignored: [] },
        comments: { mode: "classified-children" },
      },
      hints: {
        title: [".old-title"],
        body: [".old-body"],
        comments: [".old-comments"],
        commentItems: [".old-comment"],
        commentControls: [],
        commentIgnored: [],
      },
    },
    {
      id: "responsive--mobile-new",
      paths: ["|/service/board/jirum/"],
      pageRoot: ".profile-shell",
      requiredRoles: REQUIRED_ROLE_NAMES,
      allowEmptyComments: false,
      roleProjection: {
        title: { mode: "metadata-shallow" },
        body: { mode: "atomic-boundary", ignored: [] },
        product: { mode: "absent", cardinality: "zero", selectors: [], ignored: [] },
        comments: { mode: "classified-children" },
      },
      hints: {
        title: [".new-title"],
        body: [".new-body"],
        comments: [".new-comments"],
        commentItems: [".new-comment"],
        commentControls: [],
        commentIgnored: [],
      },
    },
  ];
  const profileCases = [
    {
      profile: "desktop",
      expected: ["responsive"],
      title: "Synthetic old article",
      body: `<main class="profile-shell"><h1 class="old-title">Synthetic old article</h1>` +
        `<article class="old-body">old body</article>` +
        `<section class="old-comments"><div class="old-comment">old comments</div></section></main>`,
    },
    {
      profile: "mobile",
      expected: ["responsive--mobile-new"],
      title: "Synthetic new article",
      body: `<main class="profile-shell"><h1 class="new-title">Synthetic new article</h1>` +
        `<article class="new-body">new body</article>` +
        `<section class="new-comments"><div class="new-comment">new comments</div></section></main>`,
    },
    {
      profile: "desktop",
      expected: ["responsive--mobile-new"],
      title: "Synthetic new article",
      body: `<main class="profile-shell"><h1 class="new-title">Synthetic new article</h1>` +
        `<article class="new-body">new body</article>` +
        `<section class="new-comments"><div class="new-comment">new comments</div></section></main>`,
    },
    {
      profile: "mobile",
      expected: ["responsive"],
      title: "Synthetic old article",
      body: `<main class="profile-shell"><h1 class="old-title">Synthetic old article</h1>` +
        `<article class="old-body">old body</article>` +
        `<section class="old-comments"><div class="old-comment">old comments</div></section></main>`,
    },
  ];
  for (let index = 0; index < profileCases.length; index += 1) {
    const profileCase = profileCases[index];
    const fixtureUrl = `https://www.clien.net/service/board/jirum/${99998000 + index}`;
    const session = await createPageContext(
      browser,
      profileCase.profile,
      null,
      ["clien.net"],
    );
    try {
      await session.page.route(fixtureUrl, (route) => route.fulfill({
        status: 200,
        contentType: "text/html; charset=utf-8",
        body: `<!doctype html><html><head>` +
          `<meta property="og:title" content="${profileCase.title}"></head>` +
          `<body>${profileCase.body}</body></html>`,
      }));
      const profileTitle = profileCase.title;
      await navigate(
        session.page,
        seededNavigationUrl(fixtureUrl, "clien", profileTitle, 99998000 + index),
        timeoutMs,
      );
      const projection = await countExistingApprovedLayoutMatches(
        session.page,
        profileLayout,
        userscriptContent,
        {
          v: 1,
          siteType: "clien",
          dealId: String(99998000 + index),
          title: profileCase.title,
          commentCount: null,
          ts: Date.now(),
          relayV: "00000000000000000000000000000000",
          relayT: String(Date.now()),
        },
        profileProjectionLayouts,
      );
      const matches = projection.classes.flatMap((projectionClass) =>
        projectionClass.aliases);
      if (canonicalJson(matches) !== canonicalJson(profileCase.expected)) {
        profileFixture.failures.push(
          `${profileCase.profile} matched ${matches.join(",") || "nothing"}`,
        );
      }
    } catch (error) {
      profileFixture.failures.push(error?.stack ?? String(error));
    } finally {
      await session.context.close();
    }
  }
  profileFixture.passed = profileFixture.failures.length === 0;
  result.fixtures.push(profileFixture);

  const crossBaseFixture = {
    id: "cross-base-projection-overlap-is-site-wide",
    failures: [],
  };
  const crossBaseTitle = "Synthetic cross base article";
  const crossBaseUrl = "https://www.clien.net/service/board/jirum/99997999";
  const crossBaseLayouts = ["a", "b"].map((suffix) => ({
    id: `cross-base-${suffix}`,
    paths: ["|/service/board/jirum/"],
    pageRoot: `.cross-${suffix}-shell`,
    requiredRoles: REQUIRED_ROLE_NAMES,
    allowEmptyComments: false,
    roleProjection: {
      title: { mode: "metadata-shallow" },
      body: { mode: "atomic-boundary", ignored: [] },
      product: { mode: "absent", cardinality: "zero", selectors: [], ignored: [] },
      comments: { mode: "classified-children" },
    },
    hints: {
      title: [`.cross-${suffix}-title`],
      body: [`.cross-${suffix}-body`],
      comments: [`.cross-${suffix}-comments`],
      commentItems: [`.cross-${suffix}-comment`],
      commentControls: [],
      commentIgnored: [],
    },
  }));
  const crossBaseSession = await createPageContext(
    browser,
    "desktop",
    null,
    ["clien.net"],
  );
  try {
    await crossBaseSession.page.route(crossBaseUrl, (route) => route.fulfill({
      status: 200,
      contentType: "text/html; charset=utf-8",
      body: `<!doctype html><html><head><meta property="og:title" ` +
        `content="${crossBaseTitle}"></head><body>` +
        ["a", "b"].map((suffix) =>
          `<main class="cross-${suffix}-shell">` +
          `<h1 class="cross-${suffix}-title">${crossBaseTitle}</h1>` +
          `<article class="cross-${suffix}-body">body ${suffix}</article>` +
          `<section class="cross-${suffix}-comments">` +
          `<div class="cross-${suffix}-comment">comment ${suffix}</div>` +
          `</section></main>`).join("") +
        `</body></html>`,
    }));
    await navigate(crossBaseSession.page, crossBaseUrl, timeoutMs);
    const projection = await countExistingApprovedLayoutMatches(
      crossBaseSession.page,
      profileLayout,
      userscriptContent,
      {
        v: 1,
        siteType: "clien",
        dealId: "99997999",
        title: crossBaseTitle,
        commentCount: null,
        ts: Date.now(),
        relayV: "00000000000000000000000000000000",
        relayT: String(Date.now()),
      },
      crossBaseLayouts,
    );
    const evidence = projectionCardinalityEvidence(
      true,
      projection.semanticProjectionCount,
    );
    crossBaseFixture.evidence = evidence;
    if (
      evidence.semanticProjectionCount !== 2 ||
      evidence.coMatchCount !== 1 ||
      evidence.exactApprovedCount !== 0
    ) {
      crossBaseFixture.failures.push(
        `cross-base projections produced ${JSON.stringify(evidence)}`,
      );
    }
  } catch (error) {
    crossBaseFixture.failures.push(error?.stack ?? String(error));
  } finally {
    await crossBaseSession.context.close();
  }
  crossBaseFixture.passed = crossBaseFixture.failures.length === 0;
  result.fixtures.push(crossBaseFixture);

  const productMutationFixture = {
    id: "late-inside-product-widget-is-terminal",
    failures: [],
  };
  const productMutationUrl =
    "https://www.ppomppu.co.kr/zboard/view.php?id=ppomppu&no=99997998";
  const productMutationTitle = "Synthetic product boundary article";
  const productMutationSession = await createPageContext(
    browser,
    "desktop",
    userscriptContent,
    ["ppomppu.co.kr"],
  );
  try {
    await productMutationSession.page.route(productMutationUrl, (route) => route.fulfill({
      status: 200,
      contentType: "text/html; charset=utf-8",
      body: `<!doctype html><html><head><meta property="og:title" ` +
        `content="${productMutationTitle}"></head><body>` +
        `<main class="wrapper"><section id="topTitle">` +
        `<h1>${productMutationTitle}</h1>` +
        `<dl class="topTitle-link"><dt>Product price</dt>` +
        `<dd>USD 10 <a href="https://shop.invalid/product">buy</a></dd></dl>` +
        `</section><article class="board-contents"><p>${longBody}</p></article>` +
        `<div id="comment_list_area"><div id="iC_1" class="comment_wrapper">` +
        `comment</div></div></main><script>` +
        `window.__HDF_PRODUCT_ORIGINALS__={product:document.querySelector('.topTitle-link'),` +
        `body:document.querySelector('.board-contents'),comment:document.querySelector('.comment_wrapper'),` +
        `bodyText:document.querySelector('.board-contents').textContent,` +
        `commentText:document.querySelector('.comment_wrapper').textContent,` +
        `purchaseText:document.querySelector('.topTitle-link dd').textContent,` +
        `purchaseHref:document.querySelector('.topTitle-link a').href};` +
        `window.setTimeout(() => {` +
        `const widget = document.createElement('aside');` +
        `widget.setAttribute('data-product-mutation-noise','1');` +
        `widget.textContent = 'injected product recommendation';` +
        `document.querySelector('.topTitle-link').append(widget);` +
        `}, 300);</script></body></html>`,
    }));
    await navigate(
      productMutationSession.page,
      seededNavigationUrl(
        productMutationUrl,
        "ppomppu",
        productMutationTitle,
        99997998,
      ),
      timeoutMs,
    );
    await productMutationSession.page.waitForTimeout(900);
    const state = await productMutationSession.page.evaluate(() => {
      const visible = (element) => {
        if (!element) return false;
        const style = getComputedStyle(element);
        return style.display !== "none" && style.visibility !== "hidden" &&
          style.contentVisibility !== "hidden" && Number(style.opacity) !== 0 &&
          [...element.getClientRects()].some((rect) => rect.width > 0 && rect.height > 0);
      };
      const html = document.documentElement;
      const rootStyle = getComputedStyle(html);
      const runtimeStyleCount = document.querySelectorAll(
        'style[data-hotdeal-focus-runtime-style="2"]',
      ).length;
      const publisherProtocolAttributes = [
        "data-hotdeal-focus-lock",
        "data-hotdeal-focus-ready",
        "data-hotdeal-focus-protocol",
        "data-hotdeal-focus-state",
        "data-hotdeal-focus-status",
        "data-hotdeal-focus-measure",
      ];
      const publisherProtocolCleared = publisherProtocolAttributes.every(
        (attribute) => !html.hasAttribute(attribute),
      ) && !html.classList.contains("hdf-v2-lock") &&
        !html.classList.contains("hdf-v2-ready");
      const hotdealMarkerCount = [html, ...document.querySelectorAll("*")].filter(
        (element) =>
          [...element.attributes].some((attribute) =>
            attribute.name.startsWith("data-hotdeal-focus-")) ||
          [...element.classList].some((className) => className.startsWith("hdf-v2-")),
      ).length;
      const rootInlineLockCleared = [
        ["opacity", "0"],
        ["visibility", "hidden"],
        ["content-visibility", "hidden"],
        ["clip-path", "inset(50%)"],
        ["pointer-events", "none"],
      ].every(([property, value]) =>
        html.style.getPropertyValue(property) !== value ||
        html.style.getPropertyPriority(property) !== "important",
      );
      let diagnostics = null;
      try {
        diagnostics = JSON.parse(JSON.stringify(
          window.__HOTDEAL_FOCUS_DIAGNOSTICS__ ?? null,
        ));
      } catch {
        diagnostics = null;
      }
      const paintProbe = window.__HOTDEAL_FOCUS_PAINT_PROBE__ ?? null;
      return {
        ready: html.getAttribute("data-hotdeal-focus-ready") === "1",
        state: html.getAttribute("data-hotdeal-focus-state"),
        status: html.getAttribute("data-hotdeal-focus-status"),
        diagnostics,
        runtimeStyleCount,
        publisherProtocolCleared,
        hotdealMarkerCount,
        rootInlineLockCleared,
        publisherRootVisible:
          rootStyle.display !== "none" && rootStyle.visibility !== "hidden" &&
          rootStyle.contentVisibility !== "hidden" && Number(rootStyle.opacity) !== 0,
        productVisible: visible(document.querySelector(".topTitle-link")),
        articleVisible: visible(document.querySelector(".board-contents")),
        commentsVisible: visible(document.querySelector(".comment_wrapper")),
        originalContentPreserved: (() => {
          const original = window.__HDF_PRODUCT_ORIGINALS__;
          return original.product === document.querySelector('.topTitle-link') &&
            original.body === document.querySelector('.board-contents') &&
            original.comment === document.querySelector('.comment_wrapper') &&
            original.bodyText === original.body.textContent && original.commentText === original.comment.textContent &&
            original.purchaseText === document.querySelector('.topTitle-link dd').textContent &&
            original.purchaseHref === document.querySelector('.topTitle-link a').href;
        })(),
        noiseHiddenAndUnowned: (() => {
          const noise = document.querySelector('[data-product-mutation-noise]');
          return Boolean(noise) && !visible(noise) && !noise.hasAttribute('data-hotdeal-focus-keep');
        })(),
        unsafeGateFrameCount: Number(paintProbe?.unsafeGateFrameCount ?? 1),
      };
    });
    productMutationFixture.state = state;
    if (
      !state.ready ||
      state.diagnostics?.state !== "ready" ||
      state.diagnostics?.standaloneCascadeProof?.frameCount !== 2 ||
      state.diagnostics?.visibleLeakCount !== 0 ||
      state.runtimeStyleCount !== 1 ||
      !state.originalContentPreserved || !state.noiseHiddenAndUnowned ||
      !state.rootInlineLockCleared ||
      !state.publisherRootVisible ||
      !state.productVisible ||
      !state.articleVisible ||
      !state.commentsVisible ||
      state.unsafeGateFrameCount !== 0
    ) {
      productMutationFixture.failures.push(
        `product injection damaged the reader projection or exposed noise: ${JSON.stringify(state)}`,
      );
    }
  } catch (error) {
    productMutationFixture.failures.push(error?.stack ?? String(error));
  } finally {
    await productMutationSession.context.close();
  }
  productMutationFixture.passed = productMutationFixture.failures.length === 0;
  result.fixtures.push(productMutationFixture);
  result.failures.push(
    ...result.fixtures.flatMap((fixture) =>
      fixture.failures.map((failure) => `${fixture.id}: ${failure}`),
    ),
  );
  result.passed = result.failures.length === 0;
  return result;
}

function fixtureCoverageFailures(fixtures, config) {
  const failures = [];
  for (const site of config.sites) {
    for (const layout of site.layouts) {
      const applicableProfiles = Array.isArray(layout.applicable_profiles)
        ? layout.applicable_profiles
        : [];
      const layoutFixtures = fixtures.filter(
        (fixture) => fixture.site_id === site.id && fixture.layout_id === layout.id,
      );
      for (const fixture of layoutFixtures) {
        const profileName = fixture.profile ?? "desktop";
        if (!applicableProfiles.includes(profileName)) {
          failures.push(
            `${site.id}/${layout.id}/${profileName}: fixture profile is not applicable`,
          );
        }
      }
      for (const profileName of applicableProfiles) {
        const vintages = new Set(
          layoutFixtures
            .filter((fixture) => (fixture.profile ?? "desktop") === profileName)
            .map((fixture) => fixture.vintage),
        );
        for (const vintage of ["june", "july"]) {
          if (!vintages.has(vintage)) {
            failures.push(
              `${site.id}/${layout.id}/${profileName}: ` +
                `missing ${vintage} regression fixture`,
            );
          }
        }
      }
    }
  }
  return failures;
}

async function runRegressionFixtures(
  browser,
  userscriptContent,
  config,
  runDirectory,
  timeoutMs,
) {
  const fixtureDocument = await readJson(DEFAULT_REGRESSION_FIXTURES_PATH);
  const baselineDocument = await readJson(DEFAULT_BEHAVIOR_BASELINE_PATH);
  if (fixtureDocument.schema_version !== 1 || !Array.isArray(fixtureDocument.fixtures)) {
    throw new Error("tests/fixtures/dom-regressions.json is invalid");
  }
  if (baselineDocument.schema_version !== 1 || !baselineDocument.fixtures) {
    throw new Error("tests/fixtures/behavior-baseline.json is invalid");
  }
  const result = {
    baselineReleaseVersion: baselineDocument.release_version,
    baselineProtocolMajor: baselineDocument.protocol_major,
    coverageFailures: fixtureCoverageFailures(fixtureDocument.fixtures, config),
    fixtures: [],
    failures: [],
  };
  result.failures.push(...result.coverageFailures);
  const siteById = new Map(config.sites.map((site) => [site.id, site]));

  for (const fixture of fixtureDocument.fixtures) {
    const site = siteById.get(fixture.site_id);
    const layout = site?.layouts.find((candidate) => candidate.id === fixture.layout_id);
    const baseline = baselineDocument.fixtures[fixture.id];
    const fixtureResult = {
      id: fixture.id,
      siteId: fixture.site_id,
      layoutId: fixture.layout_id,
      vintage: fixture.vintage,
      profile: fixture.profile ?? "desktop",
      failures: [],
    };
    if (!site || !layout) {
      fixtureResult.failures.push("fixture does not map to config site/layout");
      result.fixtures.push(fixtureResult);
      continue;
    }
    if (!baseline || !Array.isArray(baseline.allowed_node_ids)) {
      fixtureResult.failures.push("released behavior baseline is missing");
      result.fixtures.push(fixtureResult);
      continue;
    }
    if (!urlMatchesLayout(fixture.url, layout)) {
      fixtureResult.failures.push("fixture URL does not match the configured path gate");
      result.fixtures.push(fixtureResult);
      continue;
    }
    const profileName = fixture.profile ?? "desktop";
    if (!layout.applicable_profiles.includes(profileName)) {
      fixtureResult.failures.push(
        `fixture profile ${profileName} is not applicable to ${site.id}/${layout.id}`,
      );
      result.fixtures.push(fixtureResult);
      continue;
    }
    const session = await createPageContext(
      browser,
      profileName,
      userscriptContent,
      [layout.domain],
    );
    try {
      await session.page.route(fixture.url, async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "text/html; charset=utf-8",
          body: `<!doctype html><html lang="ko"><head><meta charset="utf-8">` +
            `<title>DOM regression fixture</title>` +
            `<meta property="og:title" content="DOM regression fixture"></head><body>` +
            `<header data-fixture-node-id="noise-header">noise header</header>` +
            fixture.body_html +
            `<aside data-fixture-node-id="noise-sidebar">noise sidebar</aside>` +
            `<footer data-fixture-node-id="noise-footer">noise footer</footer>` +
            `</body></html>`,
        });
      });
      await navigate(
        session.page,
        seededNavigationUrl(
          fixture.url,
          fixture.site_id,
          "DOM regression fixture",
          `97${String(result.fixtures.length + 1).padStart(6, "0")}`,
        ),
        timeoutMs,
      );
      const requiredRoles = requiredRolesForLayout(layout);
      const gate = await auditUserscriptGate(
        session.page,
        requiredRoles,
        timeoutMs,
        "relay-positive",
        commentControlSelectorDigestsForUrl(layout, fixture.url),
      );
      fixtureResult.gate = gate;
      fixtureResult.failures.push(...userscriptGateFailures(gate, requiredRoles));
      const visibleNodeIds = await session.page.evaluate(() => {
        const visible = (element) => {
          const style = window.getComputedStyle(element);
          return (
            style.display !== "none" &&
            style.visibility !== "hidden" &&
            Number(style.opacity) !== 0 &&
            [...element.getClientRects()].some((rect) => rect.width > 0 && rect.height > 0)
          );
        };
        const logicallyProjected = (element) =>
          element.hasAttribute("data-hotdeal-focus-keep") &&
          (
            visible(element) ||
            [...element.querySelectorAll("[data-hotdeal-focus-keep]")].some(visible)
          );
        return [...document.querySelectorAll("[data-fixture-node-id]")]
          .filter(logicallyProjected)
          .map((element) => element.getAttribute("data-fixture-node-id"))
          .sort();
      });
      const allowedNodeIds = [...baseline.allowed_node_ids].sort();
      const newlyExposedNodeIds = visibleNodeIds.filter(
        (nodeId) => !allowedNodeIds.includes(nodeId),
      );
      const missingAllowedNodeIds = allowedNodeIds.filter(
        (nodeId) => !visibleNodeIds.includes(nodeId),
      );
      fixtureResult.behaviorDiff = {
        allowedNodeIds,
        visibleNodeIds,
        newlyExposedNodeIds,
        missingAllowedNodeIds,
      };
      if (newlyExposedNodeIds.length > 0) {
        fixtureResult.failures.push(
          `newly exposed fixture nodes: ${newlyExposedNodeIds.join(", ")}`,
        );
      }
      if (missingAllowedNodeIds.length > 0) {
        fixtureResult.failures.push(
          `previously allowed fixture nodes disappeared: ${missingAllowedNodeIds.join(", ")}`,
        );
      }
      await captureBoundedScreenshot(
        session.page,
        path.join(runDirectory, `${safeFileStem([fixture.id])}.png`),
      );
    } catch (error) {
      fixtureResult.failures.push(error?.stack ?? String(error));
    } finally {
      await session.context.close();
    }
    fixtureResult.passed = fixtureResult.failures.length === 0;
    result.fixtures.push(fixtureResult);
  }
  result.failures.push(
    ...result.fixtures.flatMap((fixture) =>
      fixture.failures.map((failure) => `${fixture.id}: ${failure}`),
    ),
  );
  result.passed = result.failures.length === 0;
  return result;
}

function normalizeAlgumonSourceLabel(value) {
  return String(value ?? "").normalize("NFKC").replace(/\s+/gu, " ").trim();
}

function exactSignedAlgumonDealUrl(urlLike, expectedDealId = null) {
  let url;
  try {
    url = new URL(urlLike);
  } catch {
    return null;
  }
  const dealMatch = url.pathname.match(/^\/(l|n)\/d\/(\d{1,24})$/u);
  const queryKeys = [...url.searchParams.keys()];
  const currentRelay = dealMatch?.[1] === "n";
  const expectedQueryKeys = currentRelay ? ["v", "t", "enc"] : ["v", "t"];
  const encryptedDestination = url.searchParams.get("enc") || "";
  if (
    url.protocol !== "https:" ||
    url.hostname !== "www.algumon.com" ||
    url.username ||
    url.password ||
    url.port ||
    url.hash ||
    !dealMatch ||
    (expectedDealId && dealMatch[2] !== String(expectedDealId)) ||
    queryKeys.length !== expectedQueryKeys.length ||
    queryKeys.some((key, index) => key !== expectedQueryKeys[index]) ||
    url.searchParams.getAll("v").length !== 1 ||
    url.searchParams.getAll("t").length !== 1 ||
    !/^[0-9a-f]{32}$/u.test(url.searchParams.get("v") || "") ||
    !/^\d{13}$/u.test(url.searchParams.get("t") || "") ||
    (currentRelay && (
      url.searchParams.getAll("enc").length !== 1 ||
      encryptedDestination.length > 4_096 ||
      !/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(encryptedDestination)
    ))
  ) {
    return null;
  }
  return url;
}

function signedRelayAcquisitionEvidence(urlLike, expectedDealId, acquiredAtMs = Date.now()) {
  const signedUrl = exactSignedAlgumonDealUrl(urlLike, expectedDealId);
  if (!signedUrl) {
    throw new Error("relay-contract-failure: fresh acquisition was not one exact signed deal URL");
  }
  const issuedAtMs = Number(signedUrl.searchParams.get("t"));
  const ageMs = acquiredAtMs - issuedAtMs;
  if (
    !Number.isSafeInteger(acquiredAtMs) ||
    !Number.isSafeInteger(issuedAtMs) ||
    ageMs > ALGUMON_FRESH_RELAY_MAX_AGE_MS ||
    ageMs < -ALGUMON_FRESH_RELAY_FUTURE_SKEW_MS
  ) {
    throw new Error("relay-contract-failure: just-in-time signed relay is not fresh");
  }
  return {
    signedUrl: signedUrl.href,
    acquiredAt: new Date(acquiredAtMs).toISOString(),
    issuedAt: new Date(issuedAtMs).toISOString(),
    ageMs,
  };
}

function recordedSignedRelayAcquisitionEvidence(
  urlLike,
  expectedDealId,
  recordedAcquisition,
) {
  if (
    !recordedAcquisition ||
    typeof recordedAcquisition !== "object" ||
    typeof recordedAcquisition.acquiredAt !== "string"
  ) {
    throw new Error("relay-contract-failure: signed relay has no recorded acquisition evidence");
  }
  const acquiredAtMs = Date.parse(recordedAcquisition.acquiredAt);
  if (
    !Number.isSafeInteger(acquiredAtMs) ||
    new Date(acquiredAtMs).toISOString() !== recordedAcquisition.acquiredAt
  ) {
    throw new Error("relay-contract-failure: recorded relay acquisition time is not canonical");
  }
  const expected = signedRelayAcquisitionEvidence(urlLike, expectedDealId, acquiredAtMs);
  if (
    recordedAcquisition.signedUrl !== expected.signedUrl ||
    recordedAcquisition.acquiredAt !== expected.acquiredAt ||
    recordedAcquisition.issuedAt !== expected.issuedAt ||
    recordedAcquisition.ageMs !== expected.ageMs
  ) {
    throw new Error("relay-contract-failure: recorded relay acquisition is internally inconsistent");
  }
  return expected;
}

function algumonNavigationErrorEvidence(error) {
  if (error === null || error === undefined) return null;
  const categories = ["timeout", "network", "navigation-failed"];
  if (categories.includes(error?.category) && typeof error?.errorSha256 === "string" &&
    /^[a-f0-9]{64}$/u.test(error.errorSha256)) {
    return { category: error.category, errorSha256: error.errorSha256 };
  }
  const message = String(error?.message ?? error);
  return {
    category: /\b(?:timeout|timed out)\b/iu.test(message)
      ? "timeout"
      : /\bnet::ERR_[A-Z_]+\b/u.test(message) ? "network" : "navigation-failed",
    errorSha256: sha256(message),
  };
}

function classifyAlgumonSourceResponse(responseEvidence) {
  const status = responseEvidence?.status;
  const body = normalizeAlgumonSourceLabel(
    `${responseEvidence?.title ?? ""}\n${responseEvidence?.bodyText ?? ""}`,
  );
  let exactUrl = false;
  const describeUrl = (value) => {
    try {
      const url = new URL(value);
      const queryKeys = [...url.searchParams.keys()];
      const publicQueryKeys = new Set(["sites", "page", "sort", "order", "q", "query"]);
      return {
        protocol: url.protocol,
        hostname: url.hostname,
        pathKind: url.pathname === "/n/deal" ? "deal-feed" : url.pathname === "/" ? "root" : "other",
        pathSha256: sha256(url.pathname),
        pathDepth: url.pathname.split("/").filter(Boolean).length,
        trailingSlash: url.pathname.endsWith("/"),
        queryKeys: [...new Set(queryKeys.filter((key) => publicQueryKeys.has(key)))],
        otherQueryKeyCount: queryKeys.filter((key) => !publicQueryKeys.has(key)).length,
        hasFragment: Boolean(url.hash),
        urlSha256: sha256(url.href),
      };
    } catch {
      return null;
    }
  };
  try {
    exactUrl =
      new URL(responseEvidence?.finalUrl).href ===
      new URL(responseEvidence?.requestedUrl).href;
  } catch {}
  const blockPage =
    /(?:\bE002\b|접근이 차단되었|접근 차단됨|access denied|request blocked|too many requests|attention required|captcha)/iu.test(
      body,
    );
  const htmlResponse = /^text\/html(?:\s*;|$)/iu.test(
    responseEvidence?.contentType ?? "",
  );
  if (
    status !== 200 ||
    status === 403 ||
    status === 429 ||
    !exactUrl ||
    !htmlResponse ||
    blockPage
  ) {
    return {
      kind: "source-or-infrastructure-failure",
      status: Number.isInteger(status) ? status : null,
      exactUrl,
      htmlResponse,
      blockPage,
      requested: describeUrl(responseEvidence?.requestedUrl),
      final: describeUrl(responseEvidence?.finalUrl),
      response: describeUrl(responseEvidence?.responseUrl),
      navigationError: algumonNavigationErrorEvidence(responseEvidence?.navigationError),
    };
  }
  return null;
}

function classifyAlgumonCardSnapshot(card, expectedSiteId = null) {
  const failures = [];
  const dealId = String(card?.cardDomId ?? "").match(/^deal-(\d{1,24})$/u)?.[1] ?? null;
  const hrefs = [...new Set((card?.hrefs ?? []).map(String))];
  const signedUrl = hrefs.length === 1
    ? exactSignedAlgumonDealUrl(hrefs[0], dealId)
    : null;
  if (!dealId) failures.push("card-id");
  if (hrefs.length !== 1 || !signedUrl) failures.push("signed-relay-url");

  const iconSlugs = [];
  let invalidIcon = false;
  for (const iconUrlText of card?.iconUrls ?? []) {
    try {
      const iconUrl = new URL(iconUrlText);
      const match = iconUrl.pathname.match(/^\/site-icon\/([a-z0-9_-]+)\.png$/u);
      if (
        iconUrl.protocol !== "https:" ||
        iconUrl.hostname !== "cdn.algumon.com" ||
        iconUrl.username ||
        iconUrl.password ||
        iconUrl.port ||
        iconUrl.hash ||
        !match
      ) {
        invalidIcon = true;
      } else {
        iconSlugs.push(match[1]);
      }
    } catch {
      invalidIcon = true;
    }
  }
  const uniqueIconSlugs = [...new Set(iconSlugs)];
  if (
    invalidIcon ||
    uniqueIconSlugs.length !== 1 ||
    !ALGUMON_SOURCE_BY_ICON_SLUG.has(uniqueIconSlugs[0])
  ) {
    failures.push("site-icon");
  }

  const sourceLabels = [
    ...new Set(
      (card?.sourceLabels ?? [])
        .map(normalizeAlgumonSourceLabel)
        .filter(Boolean),
    ),
  ];
  if (sourceLabels.length !== 1 || !ALGUMON_SOURCE_BY_LABEL.has(sourceLabels[0])) {
    failures.push("source-label");
  }
  const dataSiteTypes = [
    ...new Set(
      (card?.dataSiteTypes ?? [])
        .map((value) => String(value ?? "").toLocaleLowerCase().trim())
        .filter(Boolean),
    ),
  ];
  if (
    dataSiteTypes.length > 1 ||
    (dataSiteTypes.length === 1 && !ALGUMON_SOURCE_BY_SITE_ID.has(dataSiteTypes[0]))
  ) {
    failures.push("data-site-type");
  }

  const identities = [
    ALGUMON_SOURCE_BY_ICON_SLUG.get(uniqueIconSlugs[0])?.siteId,
    ALGUMON_SOURCE_BY_LABEL.get(sourceLabels[0])?.siteId,
    dataSiteTypes[0],
  ].filter(Boolean);
  const siteIds = [...new Set(identities)];
  if (siteIds.length !== 1) failures.push("contradictory-source-identity");
  const siteId = siteIds.length === 1 ? siteIds[0] : null;
  if (expectedSiteId && siteId !== expectedSiteId) failures.push("unexpected-source-identity");

  const title = normalizeAlgumonSourceLabel(card?.title).slice(0, 240);
  if (!title) failures.push("title");
  const commentCount = Number.isSafeInteger(card?.commentCount) && card.commentCount >= 0
    ? card.commentCount
    : null;
  return {
    failures,
    dealId,
    href: signedUrl?.href ?? null,
    title,
    siteId,
    commentCount,
  };
}

function classifyAlgumonInventorySnapshot(snapshot, expectedSiteId = null) {
  const sourceFailure = classifyAlgumonSourceResponse(snapshot?.response);
  if (sourceFailure) {
    return {
      status: sourceFailure.kind,
      failures: [sourceFailure.kind],
      sourceFailure,
      links: [],
      observedSiteTypes: [],
    };
  }
  const failures = [];
  let observedLabels = [];
  let sourcePickerPresent = false;
  if (!expectedSiteId) {
    const expectedLabels = new Set(ALGUMON_SOURCE_CONTRACTS.map((source) => source.label));
    const dropdowns = (snapshot?.dropdowns ?? []).map((labels) =>
      labels.map(normalizeAlgumonSourceLabel).filter(Boolean),
    );
    sourcePickerPresent = dropdowns.length > 0;
    const candidates = dropdowns.filter((labels) =>
      labels.some((label) => expectedLabels.has(label)),
    );
    if (sourcePickerPresent && candidates.length !== 1) {
      failures.push("source-dropdown-cardinality");
    } else if (candidates.length === 1) {
      observedLabels = candidates[0];
      const expectedSorted = [...expectedLabels].sort();
      const observedSorted = [...observedLabels].sort();
      if (
        observedLabels.length !== expectedSorted.length ||
        new Set(observedLabels).size !== observedLabels.length ||
        canonicalJson(observedSorted) !== canonicalJson(expectedSorted)
      ) {
        failures.push("source-dropdown-inventory");
      }
    }
  }

  const classifiedCards = (snapshot?.cards ?? []).map((card) =>
    classifyAlgumonCardSnapshot(card, expectedSiteId),
  );
  if (classifiedCards.length === 0) failures.push("deal-card-inventory-empty");
  for (const [index, card] of classifiedCards.entries()) {
    failures.push(...card.failures.map((failure) => `card-${index}:${failure}`));
  }
  const validCards = classifiedCards.filter((card) => card.failures.length === 0);
  const dealIds = validCards.map((card) => card.dealId);
  const hrefs = validCards.map((card) => card.href);
  if (new Set(dealIds).size !== dealIds.length) failures.push("duplicate-deal-id");
  if (new Set(hrefs).size !== hrefs.length) failures.push("duplicate-signed-relay-url");

  const observedSiteTypes = [...new Set(validCards.map((card) => card.siteId))].sort();
  return {
    status: failures.length === 0 ? "ok" : "inventory-contract-failure",
    failures,
    observedLabels,
    sourceInventoryMode: expectedSiteId
      ? "filtered-feed-source-identity"
      : sourcePickerPresent ? "source-picker" : "source-picker-unavailable",
    observedSiteTypes,
    cardCount: classifiedCards.length,
    links: failures.length === 0
      ? validCards.slice(0, ALGUMON_SITE_LINK_SCAN_LIMIT).map((card) => ({
          href: card.href,
          dealId: card.dealId,
          title: card.title,
          siteType: card.siteId,
          commentCount: card.commentCount,
        }))
      : [],
  };
}

async function navigateAlgumonSourceSession(session, requestedUrl, timeoutMs) {
  // Chromium may open CONNECT before its routed request reaches the handler.
  // Use the existing public-DNS pinning before the initial source navigation.
  await primeDeclaredArticleNavigation(session, requestedUrl, ["algumon.com"]);
  return navigateAlgumonSourcePage(session.page, requestedUrl, timeoutMs);
}

async function navigateAlgumonSourcePage(page, requestedUrl, timeoutMs) {
  const responseObserver = observeMainDocumentResponses(page);
  let response;
  try {
    try {
      response = await page.goto(requestedUrl, {
        waitUntil: "domcontentloaded",
        timeout: timeoutMs,
      });
    } catch (error) {
      return {
        requestedUrl,
        finalUrl: page.url(),
        status: null,
        responseUrl: null,
        contentType: "",
        title: await page.title().catch(() => ""),
        bodyText: await page.locator("body").innerText({ timeout: 250 }).catch(() => ""),
        navigationError: algumonNavigationErrorEvidence(error),
      };
    }
    const deadline = Date.now() + Math.min(timeoutMs, DESTINATION_CHALLENGE_SETTLE_MAX_MS);
    let evidence;
    do {
      await page.waitForTimeout(Math.min(250, Math.max(0, deadline - Date.now())));
      const finalUrl = page.url();
      const navigation = navigationEvidenceFromObserver(responseObserver, finalUrl, response);
      evidence = {
        requestedUrl,
        finalUrl,
        status: navigation.status,
        responseUrl: navigation.mainDocumentResponse?.url ?? null,
        contentType: navigation.contentType,
        title: await page.title().catch(() => ""),
        bodyText: (await page.locator("body").innerText({
          timeout: Math.max(1, Math.min(250, deadline - Date.now())),
        }).catch(() => "")).slice(0, 4_096),
      };
      const sameOrigin = new URL(finalUrl).origin === new URL(requestedUrl).origin;
      if (!sameOrigin) break;
      if (classifyAlgumonSourceResponse(evidence) === null &&
          await page.locator(".deal-feed-card[id^='deal-']").count().catch(() => 0) > 0) break;
      // Let the publisher's own JS finish; no clicking, reload, or extra goto.
    } while (Date.now() < deadline);
    return evidence;
  } catch (error) {
    return {
      requestedUrl,
      finalUrl: page.url(),
      status: null,
      responseUrl: null,
      contentType: "",
      title: await page.title().catch(() => ""),
      bodyText: await page.locator("body").innerText({ timeout: 250 }).catch(() => ""),
      navigationError: algumonNavigationErrorEvidence(error),
    };
  } finally {
    responseObserver.stop();
  }
}

async function snapshotAlgumonInventoryPage(page, response) {
  const dom = await page.evaluate(() => {
    const cleanText = (value) => String(value ?? "").normalize("NFKC")
      .replace(/\s+/gu, " ").trim();
    const dropdowns = [...document.querySelectorAll("ul.dropdown-content")].map((list) =>
      [...list.querySelectorAll("li")].flatMap((item) => {
        if (!item.querySelector('input[type="checkbox"]')) return [];
        const labels = [...item.querySelectorAll("button")]
          .map((button) => cleanText(button.textContent))
          .filter(Boolean);
        return labels.length === 1 ? labels : [];
      }),
    );
    for (const fieldset of document.querySelectorAll(
      'dialog[aria-label="필터"] fieldset, [role="dialog"][aria-label="필터"] fieldset',
    )) {
      if (cleanText(fieldset.querySelector("legend")?.textContent) !== "사이트") continue;
      dropdowns.push([...fieldset.querySelectorAll('input[type="checkbox"][value]')]
        .filter((input) => input.getAttribute("value"))
        .map((input) => cleanText(input.closest("label")?.textContent)));
    }
    const cards = [...document.querySelectorAll(".deal-feed-card[id^='deal-']")].map((card) => {
      const relayAnchors = [...card.querySelectorAll('a[href*="/l/d/"], a[href*="/n/d/"]')];
      const iconImages = [...card.querySelectorAll('img[src*="/site-icon/"]')];
      const explicitCount = card.getAttribute("data-source-comment-count") ||
        card.getAttribute("data-origin-comment-count") ||
        card.querySelector("[data-source-comment-count]")?.getAttribute("data-source-comment-count") ||
        card.querySelector("[data-origin-comment-count]")?.getAttribute("data-origin-comment-count") ||
        "";
      const parsedCount = Number.parseInt(String(explicitCount).replace(/[^0-9]/gu, ""), 10);
      return {
        cardDomId: card.id,
        hrefs: relayAnchors.map((anchor) => anchor.href),
        title: cleanText(
          card.querySelector('h3 a[href*="/l/d/"], h3 a[href*="/n/d/"]')?.textContent ||
            card.querySelector("h3")?.textContent ||
            "",
        ),
        iconUrls: iconImages.map((image) => image.src),
        sourceLabels: iconImages.map((image) => cleanText(
          image.closest(".badge")?.textContent || image.closest("span")?.textContent,
        )),
        dataSiteTypes: [
          card.getAttribute("data-site-type"),
          card.getAttribute("data-site"),
          card.querySelector("[data-site-type]")?.getAttribute("data-site-type"),
          card.querySelector("[data-site]")?.getAttribute("data-site"),
        ].filter(Boolean),
        commentCount:
          Number.isSafeInteger(parsedCount) && parsedCount >= 0 && parsedCount <= 100_000
            ? parsedCount
            : null,
      };
    });
    return { dropdowns, cards };
  });
  return { response, ...dom };
}

async function captureAlgumonSourceFailure(page, runDirectory) {
  if (!runDirectory) return null;
  const filename = "algumon-global-source-failure.png";
  try {
    const screenshot = await captureBoundedScreenshot(page, path.join(runDirectory, filename));
    return { filename, ...screenshot };
  } catch (error) {
    return { filename: null, error: algumonNavigationErrorEvidence(error) };
  }
}

async function finishAlgumonSourceBrowser(session, result, transitionBudget) {
  let networkPolicy;
  try {
    networkPolicy = await session.sealNetworkPolicyEvidence();
  } catch (error) {
    networkPolicy = {
      sourceBrowser: session.sourceBrowserBudgetSnapshot(),
      sealError: algumonNavigationErrorEvidence(error),
    };
  }
  result.networkPolicy = networkPolicy;
  const observed = networkPolicy.sourceBrowser;
  const actual = transitionBudget.actual;
  actual.sourceBrowserRequestStarts = (actual.sourceBrowserRequestStarts ?? 0) + observed.requestStarts;
  actual.sourceBrowserNavigationStarts = (actual.sourceBrowserNavigationStarts ?? 0) + observed.navigationStarts;
  actual.sourceBrowserSubresourceStarts = (actual.sourceBrowserSubresourceStarts ?? 0) + observed.subresourceStarts;
  actual.sourceBrowserBlockedStarts = (actual.sourceBrowserBlockedStarts ?? 0) + observed.blockedStarts;
  const budgetFailures = [...observed.violations];
  if (networkPolicy.sealError) budgetFailures.push("source-browser-network-seal-failed");
  if (networkPolicy.remoteHostBudgetOverflowCount || networkPolicy.remoteRequestBudgetOverflowCount) {
    budgetFailures.push("source-browser-network-budget-exceeded");
  }
  if (networkPolicy.navigationViolations?.length > 0) budgetFailures.push("source-browser-navigation-violation");
  if (budgetFailures.length > 0) {
    result.status = "source-or-infrastructure-failure";
    result.failures = [...new Set([...(result.failures ?? []), ...budgetFailures])];
    result.links = [];
  }
  return result;
}

async function collectAlgumonGlobalInventory(
  browser,
  timeoutMs,
  requestBudget,
  transitionBudget,
  runDirectory = null,
) {
  const session = await createPageContext(
    browser,
    "desktop",
    null,
    ["algumon.com"],
    ["algumon.com"],
    {
      allowPublicHttpsSubresources: true,
      algumonSourceUrl: ALGUMON_GLOBAL_DISCOVERY_URL,
    },
  );
  const { context, page } = session;
  try {
    reserveAlgumonProbeStart(
      requestBudget,
      transitionBudget,
      "global-inventory",
      ALGUMON_GLOBAL_DISCOVERY_URL,
    );
    const response = await navigateAlgumonSourceSession(
      session,
      ALGUMON_GLOBAL_DISCOVERY_URL,
      timeoutMs,
    );
    const result = classifyAlgumonInventorySnapshot(
      await snapshotAlgumonInventoryPage(page, response),
    );
    return await finishAlgumonSourceBrowser(session, {
      discoveryUrl: ALGUMON_GLOBAL_DISCOVERY_URL,
      ...result,
      ...(result.status !== "ok" ? { sourceScreenshot: await captureAlgumonSourceFailure(page, runDirectory) } : {}),
    }, transitionBudget);
  } catch (error) {
    return await finishAlgumonSourceBrowser(session, {
      discoveryUrl: ALGUMON_GLOBAL_DISCOVERY_URL,
      status: "source-or-infrastructure-failure",
      failures: ["global source navigation or inventory inspection failed"],
      navigationError: algumonNavigationErrorEvidence(error),
      sourceScreenshot: await captureAlgumonSourceFailure(page, runDirectory),
      links: [],
      observedSiteTypes: [],
    }, transitionBudget);
  } finally {
    await context.close();
  }
}

async function collectAlgumonRedirectLinks(
  browser,
  site,
  timeoutMs,
  requestBudget,
  transitionBudget,
  requestKind = "site-discovery",
  relayContext = null,
) {
  const source = site.algumon_source ?? site.id.toUpperCase();
  const discoveryUrl = `${ALGUMON_ORIGIN}/n/deal?sites=${encodeURIComponent(source)}`;
  const session = await createPageContext(
    browser,
    "desktop",
    null,
    ["algumon.com"],
    [
      "algumon.com",
      ...(Array.isArray(site.algumon_resource_domains)
        ? site.algumon_resource_domains
        : []),
    ],
    {
      allowPublicHttpsSubresources: true,
      algumonSourceUrl: discoveryUrl,
    },
  );
  const { context, page } = session;
  try {
    reserveAlgumonProbeStart(
      requestBudget,
      transitionBudget,
      requestKind,
      discoveryUrl,
    );
    const response = await navigateAlgumonSourceSession(session, discoveryUrl, timeoutMs);
    const result = classifyAlgumonInventorySnapshot(
      await snapshotAlgumonInventoryPage(page, response),
      site.id,
    );
    if (result.status === "ok" && relayContext) {
      await transferAlgumonRelaySession(context, relayContext);
    }
    return await finishAlgumonSourceBrowser(session, {
      discoveryUrl,
      ...result,
      siteTypeFailures: result.failures
        .filter((failure) => failure.includes("source-identity"))
        .map((failure) => ({ status: failure })),
    }, transitionBudget);
  } catch (error) {
    return await finishAlgumonSourceBrowser(session, {
      discoveryUrl,
      status: "source-or-infrastructure-failure",
      failures: ["source navigation or inventory inspection failed"],
      navigationError: algumonNavigationErrorEvidence(error),
      links: [],
      observedSiteTypes: [],
      siteTypeFailures: [],
    }, transitionBudget);
  } finally {
    await context.close();
  }
}

async function transferAlgumonRelaySession(sourceContext, relayContext) {
  const cookies = await sourceContext.cookies([
    `${ALGUMON_ORIGIN}/n/d/1`,
    `${ALGUMON_ORIGIN}/l/d/1`,
  ]);
  if (cookies.some((cookie) =>
    !ALGUMON_HOSTNAMES.has(String(cookie.domain).replace(/^\./u, "")),
  )) {
    throw new Error("relay-contract-failure: discovery cookies escaped the exact Algumon origin");
  }
  // The private resolver context is not a user browser session. Keep only this
  // source acquisition's cookies, in memory, without adding them to evidence.
  await relayContext.clearCookies();
  await relayContext.addCookies(cookies);
}

async function parseSignedRelayDestination(page, source, expectedDomain) {
  return evaluateInIsolatedWorld(
    page,
    ({ html, domain }) => {
      const parsed = new DOMParser().parseFromString(html, "text/html");
      if (
        !parsed ||
        parsed.querySelector("parsererror") ||
        parsed.querySelector("base, meta[http-equiv='refresh' i]")
      ) {
        return null;
      }
      const scripts = [...parsed.querySelectorAll("script")];
      const anchors = [...(parsed.body?.querySelectorAll("a[href]") ?? [])];
      if (scripts.length !== 1 || anchors.length !== 1) return null;
      const scriptMatch = String(scripts[0].textContent || "").match(
        /^\s*window\.location\.href\s*=\s*("(?:\\.|[^"\\])*")\s*;\s*$/u,
      );
      if (!scriptMatch) return null;
      let scriptedUrl;
      try {
        scriptedUrl = JSON.parse(scriptMatch[1]);
      } catch {
        return null;
      }
      const exactDestination = (urlLike) => {
        let url;
        try {
          url = new URL(urlLike);
        } catch {
          return null;
        }
        const hostname = url.hostname.toLocaleLowerCase();
        const expected = domain.toLocaleLowerCase();
        if (
          url.protocol !== "https:" ||
          url.username ||
          url.password ||
          url.port ||
          url.hash ||
          !(hostname === expected || hostname.endsWith(`.${expected}`))
        ) {
          return null;
        }
        return url.href;
      };
      const scriptDestination = exactDestination(scriptedUrl);
      const anchorDestination = exactDestination(anchors[0].getAttribute("href"));
      return scriptDestination && scriptDestination === anchorDestination
        ? scriptDestination
        : null;
    },
    { html: source, domain: expectedDomain },
  );
}

function createAlgumonRelayResolver(
  context,
  parserPage,
  timeoutMs,
  transitionBudget,
  requestBudget,
  requestKind = "signed-relay-fetch",
) {
  const responseCache = new Map();
  return async function resolveAlgumonRedirect(site, redirectUrl) {
    const signedUrl = exactSignedAlgumonDealUrl(redirectUrl);
    if (!signedUrl) {
      throw new Error("relay-contract-failure: unsigned or malformed Algumon URL");
    }
    let responsePromise = responseCache.get(signedUrl.href);
    if (!responsePromise) {
      reserveAlgumonProbeStart(
        requestBudget,
        transitionBudget,
        requestKind,
        signedUrl.href,
      );
      responsePromise = context.request.get(signedUrl.href, {
        failOnStatusCode: false,
        maxRedirects: 0,
        maxRetries: 0,
        timeout: timeoutMs,
        headers: {
          "cache-control": "no-store",
          pragma: "no-cache",
          referer: `${ALGUMON_ORIGIN}/n/deal?sites=${encodeURIComponent(
            site.algumon_source ?? site.id.toUpperCase(),
          )}`,
        },
      }).then(async (response) => {
        const bytes = await response.body();
        return {
          requestedUrl: signedUrl.href,
          finalUrl: response.url(),
          status: response.status(),
          contentType: response.headers()["content-type"] ?? "",
          title: "",
          bodyText: bytes.toString("utf8").slice(0, 4_096),
          bytes,
        };
      });
      responseCache.set(signedUrl.href, responsePromise);
    }
    const response = await responsePromise;
    const sourceFailure = classifyAlgumonSourceResponse(response);
    if (sourceFailure) {
      const error = new Error("source-or-infrastructure-failure: signed relay response rejected");
      error.failureKind = "source-or-infrastructure-failure";
      error.evidence = sourceFailure;
      throw error;
    }
    if (response.bytes.byteLength > ALGUMON_RELAY_RESPONSE_MAX_BYTES) {
      throw new Error("relay-contract-failure: response exceeds 4096 bytes");
    }
    const expectedDomains = [...new Set(site.layouts.map((layout) => layout.domain))];
    const destinations = [];
    for (const domain of expectedDomains) {
      const destination = await parseSignedRelayDestination(
        parserPage,
        response.bytes.toString("utf8"),
        domain,
      );
      if (destination) destinations.push(destination);
    }
    if (new Set(destinations).size !== 1) {
      throw new Error("relay-contract-failure: destination is missing, ambiguous, or outside the site");
    }
    const resolvedDestination = destinations[0];
    return {
      relayFetchUrl: signedUrl.href,
      resolvedDestination,
      responseStatus: response.status,
      responseSha256: sha256(response.bytes),
    };
  };
}

async function refreshLatestTargetRelayProof(
  _browser,
  _site,
  _profileName,
  _target,
  _timeoutMs,
  _transitionBudget,
  _requestBudget,
) {
  // Retained as a named terminal guard for legacy audit-contract consumers.
  // Live audits must use a freshly scheduled source snapshot instead of
  // independently revisiting Algumon for every destination/profile.
  throw new Error(
    "relay-contract-failure: automatic just-in-time Algumon refresh is disabled",
  );
}

function routeFamily(urlText) {
  try {
    const parsed = new URL(urlText);
    const pathSegments = parsed.pathname.split("/");
    const lastPathToken = pathSegments.findLastIndex((segment) => segment.length > 0);
    const normalizedPath = pathSegments
      .map((segment, index) => {
        if (index === lastPathToken) return ":article-token";
        if (
          /^\d{3,}$/u.test(segment) ||
          /^[0-9a-f]{8,}(?:-[0-9a-f]{4,})+$/iu.test(segment) ||
          /^[0-9a-f]{16,}$/iu.test(segment)
        ) {
          return ":article-token";
        }
        return segment;
      })
      .join("/");
    const normalizedQuery = [...parsed.searchParams.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key]) => `${key}=:article-token`)
      .join("&");
    return `${parsed.hostname}${normalizedPath}${normalizedQuery ? `?${normalizedQuery}` : ""}`;
  } catch {
    return "invalid-url";
  }
}

function deriveCanonicalPathPattern(finalUrls) {
  const tokenized = finalUrls.map((urlText) => {
    const parsed = new URL(urlText);
    const pathAndQuery = parsed.pathname + parsed.search;
    return pathAndQuery.split(/([/?&=])/gu);
  });
  if (tokenized.length < 3) return null;
  const reference = tokenized[0];
  if (
    tokenized.some((tokens) => tokens.length !== reference.length)
  ) {
    return null;
  }
  const delimiter = /^[/?&=]$/u;
  const output = [];
  let varyingTokenCount = 0;
  for (let index = 0; index < reference.length; index += 1) {
    const column = tokenized.map((tokens) => tokens[index]);
    const delimiterFlags = column.map((token) => delimiter.test(token));
    if (delimiterFlags.some(Boolean)) {
      if (!delimiterFlags.every(Boolean) || new Set(column).size !== 1) return null;
      output.push(column[0]);
      continue;
    }
    if (new Set(column).size === 1) {
      output.push(column[0]);
      continue;
    }
    if (
      column.some((token) => token.length === 0) ||
      new Set(column).size !== tokenized.length
    ) {
      return null;
    }
    if (index + 1 < reference.length && reference[index + 1] === "=") {
      return null;
    }
    output.push("*");
    varyingTokenCount += 1;
  }
  if (varyingTokenCount !== 1) return null;
  const pattern = `|${output.join("")}^`;
  const fixedLiteralPrefix = pattern.slice(0, pattern.indexOf("*"));
  if (
    pattern === "|/^" ||
    pattern === "|/*^" ||
    pattern.includes("**") ||
    pattern.length < 9 ||
    (pattern.match(/\//gu)?.length ?? 0) < 2 ||
    !/[A-Za-z]{2,}/u.test(fixedLiteralPrefix)
  ) {
    return null;
  }
  return pattern;
}

function routeEvidenceForResults(results) {
  const newRouteResults = results.filter(
    (result) => result.approvedRouteMatched === false && result.routeObservation,
  );
  if (newRouteResults.length === 0) return [];
  const samples = [];
  const seenDealIds = new Set();
  const seenFinalUrls = new Set();
  for (const result of newRouteResults.sort((left, right) =>
    left.requestedUrl.localeCompare(right.requestedUrl),
  )) {
    const sample = result.routeObservation;
    if (
      seenDealIds.has(sample.algumonDealId) ||
      seenFinalUrls.has(sample.finalResolvedUrl)
    ) {
      continue;
    }
    seenDealIds.add(sample.algumonDealId);
    seenFinalUrls.add(sample.finalResolvedUrl);
    samples.push(sample);
  }
  const selected = samples
    .slice(0, 3)
    .sort((left, right) =>
      left.algumonDealId.localeCompare(right.algumonDealId) ||
      left.finalResolvedUrl.localeCompare(right.finalResolvedUrl),
    );
  const canonicalPathPattern = deriveCanonicalPathPattern(
    selected.map((sample) => sample.finalResolvedUrl),
  );
  if (selected.length < 3 || !canonicalPathPattern) return null;
  return [{ canonicalPathPattern, samples: selected }];
}

async function discoverLatestTargets(
  browser,
  sites,
  timeoutMs,
  promotionCandidate = null,
  requestBudget,
  runDirectory = null,
) {
  if (!requestBudget || typeof requestBudget.snapshot !== "function") {
    throw new Error("live Algumon discovery requires one request-start budget");
  }
  const targets = [];
  const records = [];
  const probePlan = createLowTrafficAlgumonProbePlan(sites.length);
  const transitionBudget = {
    policy: {
      requestStartsCount: "explicit-source-and-relay-acquisitions",
      sourceBrowserRequestsCount: "observed-request-events-including-redirects-and-blocked-attempts",
      sourceBrowserRequestsPerAcquisition: NETWORK_POLICY_MAX_REMOTE_REQUESTS,
      sourceBrowserNavigationsPerAcquisition: NETWORK_POLICY_MAX_REDIRECT_ANCESTORS,
      globalInventoryNavigations: 1,
      siteDiscoveryNavigationsPerSite: 1,
      signedRelayFetchesPerSite: ALGUMON_SITE_LINK_SCAN_LIMIT,
      // Legacy report keys stay stable, but automatic JIT work has a hard zero
      // maximum below and the terminal guard rejects it before a request starts.
      justInTimeRelayAcquisitionsPerTarget: 1,
      justInTimeSignedRelayFetchesPerTarget: 1,
      proofUrlsPerRouteProfile: ALGUMON_PROOF_REPRESENTATIVES_PER_ROUTE_PROFILE,
    },
    maximum: {
      globalInventoryNavigations: probePlan.globalInventoryNavigations,
      siteDiscoveryNavigations: probePlan.siteDiscoveryNavigations,
      signedRelayFetches: probePlan.signedRelayFetches,
      justInTimeRelayAcquisitions: 0,
      justInTimeSignedRelayFetches: 0,
      requestStarts: probePlan.totalRequestStarts,
    },
    actual: {
      globalInventoryNavigations: 0,
      siteDiscoveryNavigations: 0,
      signedRelayFetches: 0,
      justInTimeRelayAcquisitions: 0,
      justInTimeSignedRelayFetches: 0,
      requestStarts: 0,
      routeProfileProofTargets: 0,
      destinationAuditNavigationStartsMaximum: 0,
      plannedAcquisitionAndDestinationNavigationsMaximum: 0,
      sourceBrowserRequestStarts: 0,
      sourceBrowserNavigationStarts: 0,
      sourceBrowserSubresourceStarts: 0,
      sourceBrowserBlockedStarts: 0,
    },
  };
  const inventory = await collectAlgumonGlobalInventory(
    browser,
    timeoutMs,
    requestBudget,
    transitionBudget,
    runDirectory,
  );
  if (inventory.status !== "ok") {
    for (const site of sites) {
      records.push({
        siteId: site.id,
        status: "skipped-after-global-inventory-failure",
        discoveryUrl: null,
        linkCount: 0,
        observedSiteTypes: [],
        siteTypeFailures: [],
        profiles: {},
      });
    }
    const requestStarts = requestBudget.snapshot();
    transitionBudget.actual.algumonRequestStarts = requestStarts.startedCount;
    transitionBudget.actual.plannedAcquisitionAndDestinationNavigationsMaximum = requestStarts.startedCount;
    return { targets: [], records, inventory, transitionBudget };
  }

  const relaySession = await createPageContext(
    browser,
    "desktop",
    null,
    ["algumon.com"],
    ["algumon.com"],
  );
  const resolveAlgumonRedirect = createAlgumonRelayResolver(
    relaySession.context,
    relaySession.page,
    timeoutMs,
    transitionBudget,
    requestBudget,
  );
  let terminalSourceFailure = false;
  try {
    // APIRequestContext does not pass through page routing. Prime only the exact
    // relay host through the same public-address pinning used by browser requests.
    await relaySession.approvePublicHost(new URL(ALGUMON_ORIGIN).hostname);
    for (const site of sites) {
      const record = {
        siteId: site.id,
        status: "pending",
        discoveryUrl: null,
        linkCount: 0,
        observedSiteTypes: [],
        siteTypeFailures: [],
        resolutionFailures: [],
        profiles: {},
      };
      if (terminalSourceFailure) {
        record.status = "skipped-after-source-or-infrastructure-failure";
        records.push(record);
        continue;
      }
      try {
        const discovery = await collectAlgumonRedirectLinks(
          browser,
          site,
          timeoutMs,
          requestBudget,
          transitionBudget,
          "site-discovery",
          relaySession.context,
        );
        record.discoveryUrl = discovery.discoveryUrl;
        record.status = discovery.status;
        record.linkCount = discovery.links.length;
        record.observedSiteTypes = discovery.observedSiteTypes;
        record.siteTypeFailures = discovery.siteTypeFailures;
        record.inventoryFailures = discovery.failures;
        record.networkPolicy = discovery.networkPolicy;
        if (discovery.status !== "ok") {
          if (discovery.status === "source-or-infrastructure-failure") {
            terminalSourceFailure = true;
            targets.length = 0;
          }
          records.push(record);
          continue;
        }

        const resolved = [];
        for (const redirect of discovery.links) {
          try {
            const resolution = await resolveAlgumonRedirect(site, redirect.href);
            resolved.push({ redirect, resolution });
          } catch (error) {
            const failureKind = error?.failureKind ??
              (String(error?.message ?? error).startsWith("relay-contract-failure")
                ? "relay-contract-failure"
                : "source-or-infrastructure-failure");
            record.resolutionFailures.push({
              redirectUrlSha256: sha256(redirect.href),
              failureKind,
              message: error?.message ?? String(error),
            });
            record.status = failureKind;
            if (failureKind === "source-or-infrastructure-failure") {
              terminalSourceFailure = true;
              targets.length = 0;
              break;
            }
          }
        }
        const finalDestinations = resolved.map(({ resolution }) => resolution.resolvedDestination);
        if (new Set(finalDestinations).size !== finalDestinations.length) {
          record.status = "inventory-contract-failure";
          record.resolutionFailures.push({ failureKind: "duplicate-resolved-destination" });
          resolved.length = 0;
        }
        if (record.resolutionFailures.length === 0) record.status = "ok";

        const desiredProfiles = new Set(
          site.layouts.flatMap((layout) => profilesForLayout(site, layout)),
        );
        for (const profileName of desiredProfiles) {
          const attempts = [];
          const clusterTargets = new Map();
          for (const { redirect, resolution } of resolved) {
            const finalUrl = resolution.resolvedDestination;
            const landing = classifyProfileLandingRoute(
              site,
              profileName,
              finalUrl,
              promotionCandidate,
            );
            const layout = site.layouts.find(
              (candidate) => candidate.id === landing.layoutId,
            ) ?? null;
            const family = routeFamily(finalUrl);
            attempts.push({
              evidenceKind: "relay-destination-inventory",
              redirectPath: new URL(redirect.href).pathname,
              finalHost: new URL(finalUrl).hostname,
              finalPath: new URL(finalUrl).pathname,
              routeFamily: family,
              matchedLayoutId: layout?.id ?? null,
              routeClassification: landing.classification,
              configuredPathMatchCount: landing.configuredPathMatchCount,
              approvedRouteMatched: landing.approvedRouteMatched,
              matchedApprovedPath: landing.matchedApprovedPath,
              approvedPathMatchCount: landing.baselineApprovedPathMatchCount,
              relayResolutionSha256: sha256(canonicalJson(resolution)),
              titleSha256: redirect.title ? sha256(redirect.title) : null,
              commentCount: redirect.commentCount,
            });
            if (!layout) continue;
            const clusterKey = `${layout.id}\u0000${family}`;
            const representatives = clusterTargets.get(clusterKey) ?? [];
            if (
              representatives.length >=
              ALGUMON_PROOF_REPRESENTATIVES_PER_ROUTE_PROFILE
            ) {
              continue;
            }
            const routeObservation = {
              algumonDealId: redirect.dealId,
              algumonEntryUrl: redirect.href,
              finalResolvedUrl: finalUrl,
              relayFetchUrl: resolution.relayFetchUrl,
              resolvedDestination: resolution.resolvedDestination,
              popupNavigation: [],
              relayResolutionSha256: sha256(canonicalJson(resolution)),
              provenanceSha256: sha256(
                canonicalJson({
                  algumonDealId: redirect.dealId,
                  algumonEntryUrl: redirect.href,
                  finalResolvedUrl: finalUrl,
                }),
              ),
            };
            representatives.push({
              layout,
              finalUrl,
              redirect,
              resolution,
              routeFamily: family,
              configuredPathMatchCount: landing.configuredPathMatchCount,
              approvedRouteMatched: landing.approvedRouteMatched,
              matchedApprovedPath: landing.matchedApprovedPath,
              approvedPathMatchCount: landing.baselineApprovedPathMatchCount,
              routeObservation,
            });
            clusterTargets.set(clusterKey, representatives);
          }
          const unmatchedAttempts = attempts.filter(
            (attempt) =>
              !attempt.matchedLayoutId ||
              attempt.configuredPathMatchCount !== 1,
          );
          record.profiles[profileName] = {
            matched: false,
            allObservedRoutesCovered: null,
            coverageState: "pending-profile-user-agent-final-landings",
            clusterCount: 0,
            matchedClusters: [],
            unmatchedClusters: [],
            attempts: [],
            relayInventory: {
              candidateClusterCount: new Set(
                attempts.map((attempt) => attempt.routeFamily),
              ).size,
              candidateMatchedClusters: [...clusterTargets.keys()].sort(),
              candidateUnmatchedClusters: [
              ...new Set(unmatchedAttempts.map((attempt) => attempt.routeFamily)),
              ].sort(),
              attempts,
            },
          };
          for (const representatives of clusterTargets.values()) {
            for (const match of representatives) {
              const relayAcquisition = signedRelayAcquisitionEvidence(
                match.redirect.href,
                match.redirect.dealId,
              );
              targets.push({
                site,
                layout: match.layout,
                profileName,
                target: {
                  source: "algumon-latest",
                  runtimeExpectation: "relay-positive",
                  url: match.finalUrl,
                   routeFamily: match.routeFamily,
                  configuredPathMatchCount: match.configuredPathMatchCount,
                  approvedRouteMatched: match.approvedRouteMatched,
                  matchedApprovedPath: match.matchedApprovedPath,
                  routeObservation: match.routeObservation,
                  relayAcquisition,
                  algumon: {
                    discoveryUrl: discovery.discoveryUrl,
                    redirectUrl: match.redirect.href,
                    dealId: match.redirect.dealId,
                    siteId: site.id,
                    title: match.redirect.title,
                    commentCount: match.redirect.commentCount,
                    verifiedResolution: match.resolution,
                  },
                },
              });
            }
          }
        }
      } catch (error) {
        record.status = "source-or-infrastructure-failure";
        record.error = error?.stack ?? String(error);
        terminalSourceFailure = true;
        targets.length = 0;
      }
      records.push(record);
    }
  } finally {
    await relaySession.context.close();
  }
  transitionBudget.actual.routeProfileProofTargets = targets.length;
  const proofGroupCounts = new Map();
  for (const target of targets) {
    const key = [
      target.site.id,
      target.layout.id,
      target.profileName,
      target.target.routeFamily,
    ].join("/");
    proofGroupCounts.set(key, (proofGroupCounts.get(key) ?? 0) + 1);
  }
  transitionBudget.actual.routeProfileProofGroups = Object.fromEntries(
    [...proofGroupCounts.entries()].sort(([left], [right]) => left.localeCompare(right)),
  );
  transitionBudget.maximum.routeProfileProofTargets =
    proofGroupCounts.size * ALGUMON_PROOF_REPRESENTATIVES_PER_ROUTE_PROFILE;
  transitionBudget.actual.destinationAuditNavigationStartsMaximum = targets.length * 2;
  const requestStarts = requestBudget.snapshot();
  if (requestStarts.startedCount > transitionBudget.maximum.requestStarts) {
    throw new Error("Algumon request-start budget was exceeded after discovery");
  }
  transitionBudget.actual.algumonRequestStarts = requestStarts.startedCount;
  transitionBudget.actual.plannedAcquisitionAndDestinationNavigationsMaximum =
    requestStarts.startedCount + transitionBudget.actual.destinationAuditNavigationStartsMaximum;
  return { targets, records, inventory, transitionBudget };
}

function sampleTargets(sites) {
  const targets = [];
  for (const site of sites) {
    for (const layout of site.layouts) {
      for (const profileName of profilesForLayout(site, layout)) {
        for (const sampleUrl of layout.sample_urls) {
          targets.push({
            site,
            layout,
            profileName,
            target: {
              source: "sample",
              runtimeExpectation: "registered-positive",
              readerRouteRegistered: true,
              url: sampleUrl,
            },
          });
        }
      }
    }
  }
  return targets;
}

function resultHasZeroLeak(result) {
  const gate = result.userscript?.gate;
  if (!gate) return false;
  if (gate.ready !== true) {
    return Boolean(
      gate.inactivePublisherSafety?.passed === true,
    );
  }
  const commentItemsProjected = commentItemProjectionFailures(gate).length === 0;
  const commentControlsProjected = Boolean(
    commentControlProjectionFailures(gate).length === 0,
  );
  return Boolean(
    gate.standaloneRuntimeCoverage?.passed === true &&
    gate.visibleWithoutKeepCount === 0 &&
    gate.directVisibleTextLeakCount === 0 &&
    gate.paintProbe?.unsafeGateFrameCount === 0 &&
    commentItemsProjected &&
    commentControlsProjected,
  );
}

function resultIsSafelyReadableOrPublisherVisible(result) {
  const gate = result.userscript?.gate;
  if (!resultHasZeroLeak(result)) return false;
  const staticOnlyFailure = (result.failures ?? []).every((failure) =>
    failure.startsWith("static"),
  );
  const safelyReadable = gate.ready === true && staticOnlyFailure;
  const publisherVisible =
    gate.ready === false && gate.inactivePublisherSafety?.passed === true;
  return safelyReadable || publisherVisible;
}

function promotionRetestFailures(report, scope) {
  const failures = [];
  for (const profile of scope.candidateProfiles) {
    const distinctCandidateProofs = new Set(
      report.results
        .filter(
          (result) =>
            result.siteId === scope.siteId &&
            result.layoutId === scope.candidateLayoutId &&
            result.profile === profile &&
            isPromotionArticleResult(result) &&
            result.passed === true,
        )
        .map((result) => result.requestedUrl),
    );
    if (distinctCandidateProofs.size < 3) {
      failures.push(
        `promotion-retest ${scope.candidateLayoutId}/${profile}: ` +
          `${distinctCandidateProofs.size}/3 distinct article proofs passed`,
      );
    }
  }
  for (const tuple of scope.tuples.filter(
    (candidate) => candidate.reason === "currently-passing",
  )) {
    const results = report.results.filter(
      (result) =>
        result.siteId === scope.siteId &&
        result.layoutId === tuple.layoutId &&
        result.profile === tuple.profile,
    );
    if (results.length === 0 || results.some((result) => result.passed !== true)) {
      failures.push(
        `promotion-retest regressed ${tuple.layoutId}/${tuple.profile}`,
      );
    }
  }
  for (const tuple of scope.tuples.filter(
    (candidate) => candidate.reason === "already-failed",
  )) {
    const results = report.results.filter(
      (result) =>
        result.siteId === scope.siteId &&
        result.layoutId === tuple.layoutId &&
        result.profile === tuple.profile,
    );
    if (
      results.length === 0 ||
      results.some((result) => !resultIsSafelyReadableOrPublisherVisible(result))
    ) {
      failures.push(
        `promotion-retest failed sibling is not zero-leak: ` +
          `${tuple.layoutId}/${tuple.profile}`,
      );
    }
  }
  return failures;
}

function discoveryFailuresRequiredForPromotion(failures, scope) {
  if (!scope) return failures;
  const exclusivelyFailedProfiles = new Set(
    [...new Set(scope.tuples.map((tuple) => tuple.profile))].filter((profile) =>
      scope.tuples
        .filter((tuple) => tuple.profile === profile)
        .every((tuple) => tuple.reason === "already-failed"),
    ),
  );
  return failures.filter((failure) =>
    ![...exclusivelyFailedProfiles].some((profile) =>
      failure.startsWith(`${scope.siteId}/${profile}:`),
    ),
  );
}

function finalizeProfileLandingCoverage(discoveryRecords, results) {
  for (const record of discoveryRecords) {
    for (const [profileName, profile] of Object.entries(record.profiles ?? {})) {
      const profileResults = results.filter(
        (result) =>
          result.siteId === record.siteId &&
          result.profile === profileName &&
          result.source === "algumon-latest",
      );
      const attempts = profileResults.map((result) => {
        let finalHost = null;
        let finalPath = null;
        try {
          const finalUrl = new URL(result.profileLanding?.finalUrl ?? result.requestedUrl);
          finalHost = finalUrl.hostname;
          finalPath = finalUrl.pathname;
        } catch {}
        return {
          evidenceKind: "profile-user-agent-final-landing",
          finalHost,
          finalPath,
          routeFamily: result.routeFamily,
          matchedLayoutId: result.profileLanding?.layoutId ?? null,
          routeClassification: result.profileLanding?.classification ?? null,
          configuredPathMatchCount:
            result.profileLanding?.configuredPathMatchCount ?? null,
          approvedRouteMatched: result.approvedRouteMatched === true,
          matchedApprovedPath: result.matchedApprovedPath ?? null,
          baselineApprovedPathMatchCount:
            result.profileLanding?.baselineApprovedPathMatchCount ?? null,
          relayAcquisitionAgeMs: result.relayAcquisition?.ageMs ?? null,
          relayProofRefreshed: Boolean(result.relayAcquisition),
          algumonDealId: result.routeObservation?.algumonDealId ?? null,
        };
      });
      const unmatchedAttempts = attempts.filter(
        (attempt) =>
          !attempt.matchedLayoutId ||
          attempt.configuredPathMatchCount !== 1,
      );
      const matchedClusters = new Set(
        attempts
          .filter((attempt) => !unmatchedAttempts.includes(attempt))
          .map((attempt) => `${attempt.matchedLayoutId}\u0000${attempt.routeFamily}`),
      );
      profile.matched = attempts.length > 0 && matchedClusters.size > 0;
      profile.allObservedRoutesCovered =
        attempts.length > 0 && unmatchedAttempts.length === 0;
      profile.coverageState = "profile-user-agent-final-landings";
      profile.clusterCount = new Set(
        attempts.map((attempt) => attempt.routeFamily),
      ).size;
      profile.matchedClusters = [...matchedClusters].sort();
      profile.unmatchedClusters = [
        ...new Set(unmatchedAttempts.map((attempt) => attempt.routeFamily)),
      ].sort();
      profile.attempts = attempts;
    }
  }
}

function discoveryFailures(
  sites,
  discoveryRecords,
  inventory = null,
  transitionBudget = null,
  results = [],
) {
  const recordsBySite = new Map(discoveryRecords.map((record) => [record.siteId, record]));
  const failures = [];
  if (inventory?.status !== "ok") {
    failures.push(
      `Algumon global inventory failed closed: ${inventory?.status ?? "missing"}`,
    );
  } else {
    const expectedLabels = ALGUMON_SOURCE_CONTRACTS.map((source) => source.label).sort();
    const observedLabels = [...(inventory.observedLabels ?? [])].sort();
    // All configured sites require their own validated filtered feed even if
    // the responsive source picker is not present in the completed document.
    const pickerUnavailable = inventory.sourceInventoryMode === "source-picker-unavailable" &&
      observedLabels.length === 0;
    if (!pickerUnavailable && canonicalJson(observedLabels) !== canonicalJson(expectedLabels)) {
      failures.push("Algumon global dropdown differs from the exact seven-source contract");
    }
  }
  if (transitionBudget) {
    const { actual, maximum, policy } = transitionBudget;
    if (actual.globalInventoryNavigations !== 1) {
      failures.push("Algumon global inventory navigation budget was not exactly one");
    }
    if (actual.siteDiscoveryNavigations > maximum.siteDiscoveryNavigations) {
      failures.push("Algumon site discovery navigation budget was exceeded");
    }
    if (actual.signedRelayFetches > maximum.signedRelayFetches) {
      failures.push("Algumon signed relay fetch budget was exceeded");
    }
    if (actual.requestStarts > maximum.requestStarts) {
      failures.push("Algumon total request-start budget was exceeded");
    }
    if (
      actual.justInTimeRelayAcquisitions > maximum.justInTimeRelayAcquisitions ||
      actual.justInTimeSignedRelayFetches > maximum.justInTimeSignedRelayFetches
    ) {
      failures.push("Algumon just-in-time relay proof budget was exceeded");
    }
    if (
      Object.values(actual.routeProfileProofGroups ?? {}).some(
        (count) => count > policy.proofUrlsPerRouteProfile,
      )
    ) {
      failures.push("Algumon route/profile proof cap was exceeded");
    }
  }
  for (const site of sites) {
    const record = recordsBySite.get(site.id);
    if (!record || record.status !== "ok") {
      failures.push(
        `${site.id}: Algumon discovery failed closed (${record?.status ?? "missing"})`,
      );
    }
    if (
      record &&
      (record.linkCount < 1 || record.linkCount > ALGUMON_SITE_LINK_SCAN_LIMIT)
    ) {
      failures.push(
        `${site.id}: Algumon yielded an invalid bounded link count (${record.linkCount})`,
      );
    }
    if (
      !record ||
      canonicalJson(record.observedSiteTypes ?? []) !== canonicalJson([site.id]) ||
      (record.siteTypeFailures ?? []).length > 0 ||
      (record.resolutionFailures ?? []).length > 0
    ) {
      failures.push(
        `${site.id}: Algumon siteType evidence is missing, unknown, ambiguous, or mismatched`,
      );
    }
    const desiredProfiles = new Set(
      site.layouts.flatMap((layout) => profilesForLayout(site, layout)),
    );
    for (const profileName of desiredProfiles) {
      const profile = record?.profiles?.[profileName];
      if (!profile?.matched) {
        failures.push(`${site.id}/${profileName}: Algumon latest redirect did not match a path gate`);
      }
      if (
        profile?.allObservedRoutesCovered !== true ||
        (profile?.unmatchedClusters ?? []).length > 0 ||
        (profile?.attempts ?? []).some(
          (attempt) =>
            attempt.evidenceKind !== "profile-user-agent-final-landing" ||
            !attempt.matchedLayoutId ||
            attempt.configuredPathMatchCount !== 1,
        )
      ) {
        failures.push(
          `${site.id}/${profileName}: profile-UA final landing coverage has unmatched or non-exact configured paths`,
        );
      }
    }
  }
  const latestResults = results.filter((result) => result.source === "algumon-latest");
  if (
    latestResults.some(
      (result) =>
        result.runtimeExpectation !== "relay-positive" ||
        !result.relayAcquisition ||
        result.profileLanding?.evidenceKind !== "profile-user-agent-final-landing",
    )
  ) {
    failures.push("Algumon latest audit lacks sealed signed relay or profile landing evidence");
  }
  return failures;
}

function deduplicateTargets(targets) {
  const seen = new Set();
  return targets.filter(({ site, layout, profileName, target }) => {
    const key = `${site.id}\u0000${layout.id}\u0000${profileName}\u0000${target.source}\u0000${target.url}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function canonicalHttpsUrl(urlLike, label) {
  let url;
  try {
    url = new URL(urlLike);
  } catch {
    throw new Error(`${label} is not a URL`);
  }
  if (url.protocol !== "https:" || url.username || url.password) {
    throw new Error(`${label} is not one canonical HTTPS URL`);
  }
  return url.href;
}

function capturedAlgumonTargetsFromReport(capturedReport, candidate, sites) {
  if (!capturedReport || !Array.isArray(capturedReport.results)) {
    throw new Error("Algumon source snapshot has no audit results");
  }
  if (
    !candidate?.siteId ||
    !candidate?.layoutId ||
    !Array.isArray(candidate?.proofProfiles) ||
    !Array.isArray(candidate?.sampleUrls)
  ) {
    throw new Error("Algumon source snapshot requires one sealed promotion candidate");
  }
  const site = sites.find((item) => item.id === candidate.siteId);
  const layout = site?.layouts.find((item) => item.id === candidate.layoutId);
  if (!site || !layout) {
    throw new Error("sealed candidate is outside the selected Algumon source snapshot scope");
  }
  const profiles = [...new Set(candidate.proofProfiles)];
  if (
    profiles.length !== candidate.proofProfiles.length ||
    profiles.length === 0 ||
    profiles.some(
      (profile) =>
        !(profile in DEVICE_PROFILES) || !profilesForLayout(site, layout).includes(profile),
    )
  ) {
    throw new Error("sealed candidate has invalid proof profiles");
  }
  const sampleUrls = candidate.sampleUrls.map((url) =>
    canonicalHttpsUrl(url, "sealed candidate sample URL"));
  if (
    sampleUrls.length !== ALGUMON_PROOF_REPRESENTATIVES_PER_ROUTE_PROFILE ||
    new Set(sampleUrls).size !== sampleUrls.length
  ) {
    throw new Error(
      `sealed candidate requires exactly ${ALGUMON_PROOF_REPRESENTATIVES_PER_ROUTE_PROFILE} distinct URLs`,
    );
  }

  const targets = [];
  for (const profileName of profiles) {
    for (const requestedUrl of sampleUrls) {
      const matchingResults = capturedReport.results.filter((result) => {
        try {
          return (
            result?.siteId === site.id &&
            result?.layoutId === layout.id &&
            result?.profile === profileName &&
            result?.source === "algumon-latest" &&
            canonicalHttpsUrl(result?.requestedUrl, "snapshot result URL") === requestedUrl
          );
        } catch {
          return false;
        }
      });
      if (matchingResults.length !== 1) {
        throw new Error(
          `sealed source snapshot is missing one exact ${layout.id}/${profileName} relay proof`,
        );
      }
      const result = matchingResults[0];
      if (result.passed !== true || result.runtimeExpectation !== "relay-positive") {
        throw new Error("sealed source snapshot contains a non-passing relay proof");
      }
      const seed = result.algumonSeed;
      if (
        !seed ||
        seed.siteId !== site.id ||
        typeof seed.dealId !== "string" ||
        !seed.verifiedResolution
      ) {
        throw new Error("sealed source snapshot lacks an exact signed relay seed");
      }
      const acquisition = recordedSignedRelayAcquisitionEvidence(
        seed.redirectUrl,
        seed.dealId,
        result.relayAcquisition,
      );
      const resolution = seed.verifiedResolution;
      const relayDestinationUrl = canonicalHttpsUrl(
        resolution.resolvedDestination,
        "snapshot relay destination",
      );
      if (
        resolution.relayFetchUrl !== acquisition.signedUrl ||
        result.relayDestinationUrl === null ||
          canonicalHttpsUrl(result.relayDestinationUrl, "snapshot relay destination") !==
            relayDestinationUrl ||
        resolution.responseStatus !== 200 ||
        !/^[0-9a-f]{64}$/u.test(resolution.responseSha256 ?? "")
      ) {
        throw new Error("sealed source snapshot relay resolution is internally inconsistent");
      }
      const landing = classifyProfileLandingRoute(
        site,
        profileName,
        requestedUrl,
        candidate,
      );
      if (landing.layoutId !== layout.id || landing.configuredPathMatchCount !== 1) {
        throw new Error("sealed source snapshot destination no longer matches one candidate layout");
      }
      const routeObservation = result.routeObservation;
      if (
        !routeObservation ||
        routeObservation.algumonDealId !== seed.dealId ||
        canonicalHttpsUrl(routeObservation.algumonEntryUrl, "snapshot relay entry") !==
          acquisition.signedUrl ||
        canonicalHttpsUrl(routeObservation.finalResolvedUrl, "snapshot final destination") !==
          requestedUrl ||
        canonicalHttpsUrl(routeObservation.resolvedDestination, "snapshot relay destination") !==
          relayDestinationUrl
      ) {
        throw new Error("sealed source snapshot route observation is internally inconsistent");
      }
      targets.push({
        site,
        layout,
        profileName,
        target: {
          source: "algumon-latest",
          runtimeExpectation: "relay-positive",
          url: relayDestinationUrl,
          routeFamily: routeFamily(requestedUrl),
          configuredPathMatchCount: landing.configuredPathMatchCount,
          approvedRouteMatched: landing.approvedRouteMatched,
          matchedApprovedPath: landing.matchedApprovedPath,
          routeObservation: {
            ...routeObservation,
            algumonDealId: seed.dealId,
            algumonEntryUrl: acquisition.signedUrl,
            finalResolvedUrl: requestedUrl,
            relayFetchUrl: acquisition.signedUrl,
            resolvedDestination: relayDestinationUrl,
          },
          relayAcquisition: { ...result.relayAcquisition },
          algumon: {
            discoveryUrl: seed.discoveryUrl ?? null,
            redirectUrl: acquisition.signedUrl,
            dealId: seed.dealId,
            siteId: seed.siteId,
            title: typeof seed.title === "string" ? seed.title : "",
            commentCount: seed.commentCount ?? null,
            verifiedResolution: { ...resolution },
          },
        },
      });
    }
  }
  return {
    mode: "captured-sealed-relay",
    sourceRunId: typeof capturedReport.runId === "string" ? capturedReport.runId : null,
    targetCount: targets.length,
    targets,
  };
}

function semanticVersionTuple(version) {
  const match = typeof version === "string"
    ? version.match(/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u)
    : null;
  if (!match) throw new Error(`invalid semantic version: ${version}`);
  return match.slice(1).map((part) => BigInt(part));
}

function compareSemanticVersions(left, right) {
  const leftParts = semanticVersionTuple(left);
  const rightParts = semanticVersionTuple(right);
  for (let index = 0; index < 3; index += 1) {
    if (leftParts[index] !== rightParts[index]) {
      return leftParts[index] < rightParts[index] ? -1 : 1;
    }
  }
  return 0;
}

function incrementStablePatchVersion(version) {
  const [major, minor, patchVersion] = semanticVersionTuple(version);
  return `${major}.${minor}.${patchVersion + 1n}`;
}

async function nextPromotionVersion(config) {
  const versions = [config.metadata.version];
  try {
    const state = await readJson(
      path.join(PROJECT_ROOT, "state", "approved-variants.json"),
    );
    for (const variant of state.variants ?? []) {
      if (typeof variant.releaseVersion === "string") {
        versions.push(variant.releaseVersion);
      }
    }
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const latest = versions.sort(compareSemanticVersions).at(-1);
  return incrementStablePatchVersion(latest);
}

function promotionShape(result) {
  const oracle = result.semanticOracle;
  const proposal = oracle.policyProposal;
  return {
    pageRoot: proposal.pageRoot,
    roles: Object.fromEntries(
      ["title", "body", "comments"].map((role) => [role, [oracle.roles[role]]]),
    ),
    commentItems: [...oracle.commentItems].sort(),
    commentControls: [...(oracle.commentControls ?? [])].sort(),
    commentIgnored: [...proposal.commentIgnored].sort(),
    bodyIgnored: [...proposal.bodyIgnored].sort(),
  };
}

function productObservation(result) {
  const oracle = result.semanticOracle;
  const product = oracle.policyProposal.product;
  return {
    cardinality: product.cardinality,
    selector: product.cardinality === "required" ? product.selectors[0] : null,
    count: product.cardinality === "required" ? oracle.cardinality.product : 0,
    order: product.order,
  };
}

function discoveryObservation(result, roleProjection, requiredRoles) {
  const oracle = result.semanticOracle;
  return {
    url: result.requestedUrl,
    profile: result.profile,
    capturedAt: result.capturedAt,
    pageRoot: { selector: oracle.pageRoot, count: oracle.pageRootCount },
    roles: Object.fromEntries(
      requiredRoles.map((role) => [
        role,
        {
          selector: oracle.roles[role],
          count: oracle.cardinality[role],
          containedInPageRoot: oracle.containment === true,
        },
      ]),
    ),
    roleProjection,
    productObservation: productObservation(result),
    algumon: {
      titleConsistency: oracle.algumon.titleConsistency,
      titleConsistencyOk: oracle.algumon.titleConsistencyOk,
      titleConsistencyMode: oracle.algumon.titleConsistencyMode,
      titleMetadataSourceCount: oracle.algumon.titleMetadataSourceCount,
      titleMetadataSourceKinds: oracle.algumon.titleMetadataSourceKinds,
      countComparable: oracle.algumon.commentComparable,
      countConsistency: oracle.algumon.countConsistency,
    },
    commentStructure: oracle.commentStructure,
    selectorStability: 1,
    oracleExecutionWorld: oracle.oracleExecutionWorld,
  };
}

function promotionRouteGroup(result) {
  if (result.approvedRouteMatched === false) {
    return result.routeObservation && result.routeFamily
      ? `additive:${result.routeFamily}`
      : null;
  }
  return typeof result.matchedApprovedPath === "string" &&
    result.matchedApprovedPath.length > 0
    ? `approved:${result.matchedApprovedPath}`
    : null;
}

function independentPolicyProposalIsComplete(oracle) {
  const proposal = oracle?.policyProposal;
  const product = proposal?.product;
  const promotionGate = proposal?.promotionGate;
  const exactUniqueStrings = (values) =>
    Array.isArray(values) &&
    new Set(values).size === values.length &&
    values.every((value) => typeof value === "string" && value.length > 0);
  if (
    !proposal ||
    proposal.schemaVersion !== 1 ||
    proposal.source !== "independent-projection-tuple" ||
    proposal.complete !== true ||
    ![
      "all-role-lowest-common-ancestor",
      "nearest-unique-stable-all-role-ancestor",
    ].includes(proposal.pageRootEvidence) ||
    typeof proposal.pageRoot !== "string" ||
    proposal.pageRoot !== oracle.pageRoot ||
    !product ||
    !["required", "zero"].includes(product.cardinality) ||
    !exactUniqueStrings(proposal.bodyIgnored) ||
    !exactUniqueStrings(proposal.productIgnored) ||
    !exactUniqueStrings(proposal.commentIgnored) ||
    proposal.safety?.strictDescendantsOnly !== true ||
    proposal.safety?.strongStructuralNoiseOnly !== true ||
    proposal.safety?.meaningfulTextPriceAndPurchaseLinksExcluded !== true ||
    typeof proposal.shapeFingerprint !== "string" ||
    !/^projection-policy-v1-[0-9a-f]{8}$/u.test(proposal.shapeFingerprint) ||
    promotionGate?.promotable !== false ||
    promotionGate?.requiredDistinctUrlsPerProfile !== 3 ||
    promotionGate?.requiredProfilesSource !== "auditor-layout-contract" ||
    promotionGate?.requiredMatchingShapeFingerprint !== true
  ) {
    return false;
  }
  if (product.cardinality === "required") {
    return (
      ["before-body", "after-body"].includes(product.order) &&
      exactUniqueStrings(product.selectors) &&
      product.selectors.length === 1 &&
      oracle.roles?.product === product.selectors[0] &&
      oracle.cardinality?.product === 1 &&
      oracle.productOrder === product.order
    );
  }
  return (
    product.order === null &&
    Array.isArray(product.selectors) &&
    product.selectors.length === 0 &&
    proposal.productIgnored.length === 0 &&
    !("product" in (oracle.roles ?? {})) &&
    !("product" in (oracle.cardinality ?? {})) &&
    oracle.productOrder === null
  );
}

function qualifiedDiscoveryResult(result) {
  const oracle = result.semanticOracle;
  return (
    isPromotionArticleResult(result) &&
    result.candidateGenerationAllowed !== false &&
    typeof result.capturedAt === "string" &&
    oracle?.ok === true &&
    oracle.oracleSource === "verified-userscript-export" &&
    oracle.oracleExecutionWorld === ORACLE_EXECUTION_WORLD &&
    oracle.exactApprovedCount === 0 &&
    oracle.semanticProjectionCount === 0 &&
    oracle.coMatchCount === 0 &&
    oracle.candidateProjection?.semanticProjectionCount === 1 &&
    oracle.candidateProjection?.exactCandidateCount === 1 &&
    oracle.candidateProjection?.coMatchCount === 0 &&
    oracle.candidateProjection?.oracleExecutionWorld === ORACLE_EXECUTION_WORLD &&
    independentPolicyProposalIsComplete(oracle) &&
    (result.approvedRouteMatched === false || result.passed === false) &&
    oracle.algumon?.titleConsistencyOk === true &&
    (oracle.algumon?.commentComparable === false
      ? oracle.algumon.countConsistency === null
      : oracle.algumon?.countConsistency === 1) &&
    oracle.commentStructure?.mountSelector === oracle.roles?.comments &&
    oracle.commentStructure?.mountCount === 1 &&
    oracle.commentStructure?.classificationOverlapCount === 0 &&
    oracle.commentStructure?.unclassifiedContentCount === 0 &&
    promotionRouteGroup(result) !== null
  );
}

function exactEmptyCommentStructure(structure) {
  return (
    structure?.itemCount === 0 &&
    structure?.classificationOverlapCount === 0 &&
    structure?.unclassifiedContentCount === 0 &&
    structure?.emptyStateSelector === structure?.mountSelector &&
    structure?.emptyStateCount === 1
  );
}

function selectCommentProofResults(results) {
  const distinct = [...new Map(
    results
      .slice()
      .sort((left, right) => left.requestedUrl.localeCompare(right.requestedUrl))
      .map((result) => [result.requestedUrl, result]),
  ).values()];
  const comparable = distinct.filter(
    (result) =>
      result.semanticOracle?.algumon?.commentComparable === true &&
      result.semanticOracle.algumon.countConsistency === 1,
  );
  if (comparable.length >= 3) return comparable.slice(0, 3);
  const structural = distinct.filter(
    (result) => result.semanticOracle?.algumon?.commentComparable === false,
  );
  const nonempty = structural.filter(
    (result) => result.semanticOracle.commentStructure?.itemCount > 0,
  );
  if (nonempty.length >= 2 && structural.length >= 3) {
    const chosen = nonempty.slice(0, 2);
    const chosenUrls = new Set(chosen.map((result) => result.requestedUrl));
    chosen.push(
      structural.find((result) => !chosenUrls.has(result.requestedUrl)),
    );
    return chosen;
  }
  const exactEmpty = structural.filter((result) =>
    exactEmptyCommentStructure(result.semanticOracle?.commentStructure),
  );
  return exactEmpty.length >= 3 ? exactEmpty.slice(0, 3) : [];
}

function threeResultsHaveStrongCommentProof(results) {
  if (results.length !== 3) return false;
  if (!results.every((result) => {
    const algumon = result.semanticOracle?.algumon;
    return algumon?.commentComparable === false
      ? algumon.countConsistency === null
      : algumon?.commentComparable === true && algumon.countConsistency === 1;
  })) {
    return false;
  }
  if (results.every(
    (result) => result.semanticOracle.algumon.commentComparable === true,
  )) {
    return true;
  }
  const nonemptyCount = results.filter(
    (result) => result.semanticOracle?.commentStructure?.itemCount > 0,
  ).length;
  return nonemptyCount >= 2 || results.every(
    (result) => exactEmptyCommentStructure(result.semanticOracle?.commentStructure),
  );
}

function selectPromotionProofResults(results, productCardinality) {
  const distinct = [...new Map(
    results
      .slice()
      .sort((left, right) => left.requestedUrl.localeCompare(right.requestedUrl))
      .map((result) => [result.requestedUrl, result]),
  ).values()];
  for (let first = 0; first < distinct.length - 2; first += 1) {
    for (let second = first + 1; second < distinct.length - 1; second += 1) {
      for (let third = second + 1; third < distinct.length; third += 1) {
        const selected = [distinct[first], distinct[second], distinct[third]];
        if (!threeResultsHaveStrongCommentProof(selected)) continue;
        if (productCardinality === "optional") {
          const cardinalities = new Set(selected.map(
            (result) => result.semanticOracle.policyProposal.product.cardinality,
          ));
          if (!cardinalities.has("required") || !cardinalities.has("zero")) continue;
        }
        return selected;
      }
    }
  }
  return [];
}

function observationsHaveStrongCommentProof(observations, profiles) {
  return profiles.every((profile) => {
    const profileObservations = observations.filter(
      (observation) => observation.profile === profile,
    );
    if (profileObservations.length < 3) return false;
    const shapeKeys = new Set(
      profileObservations.map((observation) =>
        canonicalJson({
          mountSelector: observation.commentStructure?.mountSelector,
          itemSelector: observation.commentStructure?.itemSelector,
          ignoredSelectors: observation.commentStructure?.ignoredSelectors,
        }),
      ),
    );
    if (shapeKeys.size !== 1) return false;
    if (
      profileObservations.every(
        (observation) =>
          observation.algumon?.countComparable === true &&
          observation.algumon.countConsistency === 1,
      )
    ) {
      return true;
    }
    if (
      !profileObservations.every((observation) =>
        observation.algumon?.countComparable === false
          ? observation.algumon.countConsistency === null
          : observation.algumon?.countComparable === true &&
            observation.algumon.countConsistency === 1,
      )
    ) {
      return false;
    }
    const nonemptyCount = profileObservations.filter(
      (observation) => observation.commentStructure?.itemCount > 0,
    ).length;
    return (
      nonemptyCount >= 2 ||
      profileObservations.every((observation) =>
        exactEmptyCommentStructure(observation.commentStructure),
      )
    );
  });
}

function observationsHaveProductProof(observations, roleProjection, profiles) {
  const productPolicy = roleProjection?.product;
  if (
    !productPolicy ||
    !["required", "optional", "zero"].includes(productPolicy.cardinality) ||
    !profiles.every(
      (profile) => observations.filter((observation) => observation.profile === profile).length >= 3,
    )
  ) {
    return false;
  }
  const valid = observations.every((observation) => {
    const product = observation.productObservation;
    if (!product || !["required", "zero"].includes(product.cardinality)) return false;
    if (product.cardinality === "zero") {
      return product.selector === null && product.count === 0 && product.order === null;
    }
    return (
      product.count === 1 &&
      typeof product.selector === "string" &&
      productPolicy.selectors.includes(product.selector) &&
      product.order === productPolicy.order
    );
  });
  if (!valid) return false;
  const observed = new Set(
    observations.map((observation) => observation.productObservation.cardinality),
  );
  if (productPolicy.cardinality === "zero") {
    return observed.size === 1 && observed.has("zero");
  }
  if (productPolicy.cardinality === "required") {
    return observed.size === 1 && observed.has("required");
  }
  return observed.size === 2 && observed.has("required") && observed.has("zero");
}

function selectStableDiscoveryGroups(report, config) {
  const groups = new Map();
  for (const result of report.results.filter(qualifiedDiscoveryResult)) {
    const shape = promotionShape(result);
    const routeGroup = promotionRouteGroup(result);
    const key = canonicalJson({
      siteId: result.siteId,
      layoutId: result.layoutId,
      routeGroup,
      shape,
    });
    const group = groups.get(key) ?? {
      siteId: result.siteId,
      layoutId: result.layoutId,
      shape,
      routeGroup,
      approvedPath:
        result.approvedRouteMatched === true
          ? result.matchedApprovedPath
          : null,
      results: [],
    };
    group.results.push(result);
    groups.set(key, group);
  }
  return [...groups.values()]
    .sort((left, right) =>
      canonicalJson([
        left.siteId,
        left.layoutId,
        left.routeGroup,
        left.shape,
      ]).localeCompare(canonicalJson([
        right.siteId,
        right.layoutId,
        right.routeGroup,
        right.shape,
      ])),
    )
    .filter((group) => {
      const site = config.sites.find((candidate) => candidate.id === group.siteId);
      const layout = site?.layouts.find((candidate) => candidate.id === group.layoutId);
      if (!site || !layout) return false;
      const presentProductShapes = [...new Map(
        group.results
          .filter(
            (result) => result.semanticOracle.policyProposal.product.cardinality === "required",
          )
          .map((result) => {
            const proposal = result.semanticOracle.policyProposal;
            const shape = {
              order: proposal.product.order,
              selectors: [...proposal.product.selectors].sort(),
              ignored: [...proposal.productIgnored].sort(),
            };
            return [canonicalJson(shape), shape];
          }),
      ).values()];
      if (presentProductShapes.length > 1) return false;
      const observedCardinalities = new Set(group.results.map(
        (result) => result.semanticOracle.policyProposal.product.cardinality,
      ));
      if (
        [...observedCardinalities].some(
          (cardinality) => !["required", "zero"].includes(cardinality),
        ) ||
        (observedCardinalities.has("required") && presentProductShapes.length !== 1)
      ) {
        return false;
      }
      const productCardinality = observedCardinalities.size === 2
        ? "optional"
        : observedCardinalities.has("required") ? "required" : "zero";
      const presentProduct = presentProductShapes[0] ?? null;
      group.roleProjection = {
        title: { mode: "metadata-shallow" },
        body: {
          mode: "atomic-boundary",
          ignored: [...group.shape.bodyIgnored],
        },
        product: productCardinality === "zero"
          ? {
              mode: "absent",
              cardinality: "zero",
              selectors: [],
              ignored: [],
            }
          : {
              mode: "atomic-boundary",
              cardinality: productCardinality,
              order: presentProduct.order,
              selectors: [...presentProduct.selectors],
              ignored: [...presentProduct.ignored],
            },
        comments: { mode: "classified-children" },
      };
      group.requiredRoles = ["title", "body", "comments"].concat(
        productCardinality === "required" ? ["product"] : [],
      ).sort();
      if (productCardinality === "required") {
        group.shape.roles.product = [...presentProduct.selectors];
      }
      const applicableProfiles = profilesForLayout(site, layout);
      group.proofProfiles = applicableProfiles.filter(
        (profile) =>
          selectPromotionProofResults(
            group.results.filter((result) => result.profile === profile),
            "unconstrained",
          ).length === 3,
      );
      if (canonicalJson(group.proofProfiles) !== canonicalJson(applicableProfiles)) {
        return false;
      }
      group.selectedResults = group.proofProfiles.flatMap((profile) =>
        selectPromotionProofResults(
          group.results.filter((result) => result.profile === profile),
          "unconstrained",
        ));
      if (productCardinality === "optional") {
        const selectedCardinalities = new Set(group.selectedResults.map(
          (result) => result.semanticOracle.policyProposal.product.cardinality,
        ));
        if (selectedCardinalities.size !== 2) {
          for (const profile of group.proofProfiles) {
            const mixed = selectPromotionProofResults(
              group.results.filter((result) => result.profile === profile),
              "optional",
            );
            if (mixed.length !== 3) continue;
            group.selectedResults = [
              ...group.selectedResults.filter((result) => result.profile !== profile),
              ...mixed,
            ];
            break;
          }
        }
        const finalCardinalities = new Set(group.selectedResults.map(
          (result) => result.semanticOracle.policyProposal.product.cardinality,
        ));
        if (finalCardinalities.size !== 2) return false;
      }
      group.fingerprint = sha256(canonicalJson({
        siteId: group.siteId,
        layoutId: group.layoutId,
        routeGroup: group.routeGroup,
        shape: group.shape,
        roleProjection: group.roleProjection,
      })).slice(0, 24);
      return (
        group.proofProfiles.length > 0 &&
        group.selectedResults.length === group.proofProfiles.length * 3
      );
    });
}

function selectStableDiscoveryGroup(report, config) {
  return selectStableDiscoveryGroups(report, config)[0] ?? null;
}

function promotionVariantId(group, promotedPaths) {
  const stableIdentity = {
    siteId: group.siteId,
    layoutId: group.layoutId,
    paths: [...promotedPaths].sort(),
    pageRoot: group.shape.pageRoot,
    roles: group.shape.roles,
    roleProjection: group.roleProjection,
    commentItems: group.shape.commentItems,
    commentControls: group.shape.commentControls,
    commentIgnored: group.shape.commentIgnored,
  };
  return `auto-${sha256(canonicalJson(stableIdentity)).slice(0, 24)}`;
}

async function synthesizePromotionDraftForGroup(
  report,
  config,
  baseConfigBytes,
  group,
  releaseVersion,
) {
  const site = config.sites.find((candidate) => candidate.id === group.siteId);
  const layout = site.layouts.find((candidate) => candidate.id === group.layoutId);
  const selectedResults = [...group.selectedResults];
  const observations = selectedResults.map((result) =>
    discoveryObservation(result, group.roleProjection, group.requiredRoles));
  observations.sort((left, right) =>
    left.profile.localeCompare(right.profile) || left.url.localeCompare(right.url),
  );
  const requiredRoles = [...group.requiredRoles];
  const routeEvidence = routeEvidenceForResults(selectedResults);
  if (routeEvidence === null) {
    return {
      status: "rejected",
      fingerprint: group.fingerprint,
      reason: "new route does not have one strict numeric-run mask and three Algumon proofs",
    };
  }
  const promotedPaths = routeEvidence.length > 0
    ? routeEvidence.map((evidence) => evidence.canonicalPathPattern).sort()
    : group.approvedPath
      ? [group.approvedPath]
      : [];
  if (promotedPaths.length === 0) {
    return {
      status: "rejected",
      fingerprint: group.fingerprint,
      reason: "promotion group does not own one exact proven route",
    };
  }
  const payload = {
    siteId: group.siteId,
    layoutId: group.layoutId,
    variantId: promotionVariantId(group, promotedPaths),
    pageRoot: group.shape.pageRoot,
    paths: promotedPaths,
    sampleUrls: [...new Set(observations.map((observation) => observation.url))].sort(),
    requiredRoles,
    roles: Object.fromEntries(
      requiredRoles.map((role) => [role, [...group.shape.roles[role]].sort()]),
    ),
    roleProjection: group.roleProjection,
    commentItems: group.shape.commentItems,
    commentControls: group.shape.commentControls,
    commentIgnored: group.shape.commentIgnored,
    allowEmptyComments: true,
    proofProfiles: [...group.proofProfiles].sort(),
  };
  const candidateSha256 = sha256(canonicalJson(payload));
  const evidenceSha256 = sha256(
    canonicalJson({ observations, routeEvidence }),
  );
  return {
    status: "draft",
    envelope: {
      schemaVersion: 1,
      status: "draft",
      protocolVersion: report.integrity.releaseManifest.protocolVersion,
      baseConfigSha256: sha256(baseConfigBytes),
      releaseVersion,
      discovery: {
        candidateSha256,
        evidenceSha256,
        observations,
        routeEvidence,
      },
      candidate: payload,
    },
    fingerprint: group.fingerprint,
  };
}

async function synthesizePromotionDraft(report, config, baseConfigBytes) {
  if (
    report.integrity.passed !== true ||
    report.syntheticFixture?.passed !== true ||
    report.regressionFixtures?.passed !== true ||
    report.edgeFixtures?.passed !== true
  ) {
    return {
      status: "rejected",
      reason: "integrity or executable fixture gate failed",
      candidates: [],
    };
  }
  const groups = selectStableDiscoveryGroups(report, config);
  if (groups.length === 0) {
    return {
      status: "rejected",
      reason: "no selector-identical group has three distinct URLs per proof profile",
      candidates: [],
    };
  }
  const releaseVersion = await nextPromotionVersion(config);
  const attempts = [];
  for (const group of groups) {
    attempts.push(
      await synthesizePromotionDraftForGroup(
        report,
        config,
        baseConfigBytes,
        group,
        releaseVersion,
      ),
    );
  }
  const drafts = attempts.filter((attempt) => attempt.status === "draft");
  if (drafts.length === 0) {
    return {
      status: "rejected",
      reason: "all stable candidate fingerprints failed isolated synthesis",
      candidates: attempts,
    };
  }
  return {
    status: "draft",
    envelope: drafts[0].envelope,
    drafts,
    candidates: attempts.map((attempt) => ({
      fingerprint: attempt.fingerprint,
      status: attempt.status,
      reason: attempt.reason ?? null,
      variantId: attempt.envelope?.candidate?.variantId ?? null,
    })),
  };
}

function measuredVisibleLeakCount(gate) {
  return Math.max(
    Number(gate?.diagnostics?.visibleLeakCount ?? 1),
    Number(gate?.visibleWithoutKeepCount ?? 1),
    Number(gate?.directVisibleTextLeakCount ?? 1),
    Number(gate?.standaloneRuntimeCoverage?.visibleUnownedCount ?? gate?.uncoveredUnmarkedCount ?? 1),
    Number(gate?.paintProbe?.unsafeGateFrameCount ?? 1),
  );
}

function provenObservation(result, fixturePassed, baselineNoNewExposure) {
  const overlay = result.candidateOverlay;
  const gate = result.userscript.gate;
  return {
    url: result.requestedUrl,
    profile: result.profile,
    capturedAt: result.capturedAt,
    pageRoot: {
      selector: overlay.pageRootSelector,
      count: overlay.pageRootCount,
    },
    roles: overlay.roles,
    roleProjection: overlay.roleProjection,
    productObservation: {
      cardinality: overlay.productCount === 1 ? "required" : "zero",
      selector: overlay.productCount === 1
        ? overlay.roleProjection.product.selectors[0]
        : null,
      count: overlay.productCount,
      order: overlay.productCount === 1
        ? overlay.productOrder
        : null,
    },
    algumon: {
      titleConsistency: overlay.titleConsistency,
      titleConsistencyOk: overlay.titleConsistencyOk,
      titleConsistencyMode: overlay.titleConsistencyMode,
      titleMetadataSourceCount: overlay.titleMetadataSourceCount,
      titleMetadataSourceKinds: overlay.titleMetadataSourceKinds,
      countComparable: overlay.countComparable,
      countConsistency: overlay.countConsistency,
    },
    commentStructure: {
      mountSelector: overlay.roles.comments.selector,
      mountCount: overlay.roles.comments.count,
      itemSelector: overlay.itemSelector,
      itemCount: overlay.commentItemCount,
      ignoredSelectors: overlay.ignoredSelectors,
      ignoredCount: overlay.ignoredCount,
      classificationOverlapCount: overlay.classificationOverlapCount,
      unclassifiedContentCount: overlay.unclassifiedCommentContentCount,
      emptyStateSelector: overlay.emptyStateSelector,
      emptyStateCount: overlay.emptyStateCount,
    },
    selectorStability: 1,
    oracleExecutionWorld: overlay.oracleExecutionWorld,
    livePassed: result.passed === true,
    fixturePassed,
    visibleLeakCount: measuredVisibleLeakCount(gate),
    baselineNoNewExposure,
    approvedVariantCount: overlay.approvedVariantCount,
    coMatchCount: overlay.coMatchCount,
  };
}

function synthesizePromotionProof(report, config, draftEnvelope, draftManifest) {
  const candidate = draftEnvelope.candidate;
  const expectedProfiles = candidate.proofProfiles ?? [];
  const fixturePassed =
    report.syntheticFixture?.passed === true &&
    report.regressionFixtures?.passed === true &&
    report.edgeFixtures?.passed === true;
  const baselineNoNewExposure = report.regressionFixtures?.passed === true;
  const proofResults = report.results
    .filter(
      (result) =>
        result.siteId === candidate.siteId &&
        result.layoutId === candidate.layoutId &&
        isPromotionArticleResult(result) &&
        candidate.sampleUrls.includes(result.requestedUrl) &&
        expectedProfiles.includes(result.profile) &&
        result.candidateOverlay,
    );
  const observations = proofResults
    .map((result) => provenObservation(result, fixturePassed, baselineNoNewExposure))
    .sort((left, right) =>
      left.profile.localeCompare(right.profile) || left.url.localeCompare(right.url),
    );
  const site = config.sites.find((item) => item.id === candidate.siteId);
  const layout = site?.layouts.find((item) => item.id === candidate.layoutId);
  const routeEvidence = routeEvidenceForResults(proofResults);
  const previouslyApprovedPaths = layout
    ? new Set(approvedPathsForLayout(layout, candidate.variantId))
    : new Set();
  const expectedNewPaths = candidate.paths.filter(
    (configuredPath) => !previouslyApprovedPaths.has(configuredPath),
  );
  const observationsPass =
    report.integrity.passed === true &&
    fixturePassed &&
    expectedProfiles.length > 0 &&
    routeEvidence !== null &&
    canonicalJson(
      (routeEvidence ?? []).map((evidence) => evidence.canonicalPathPattern).sort(),
    ) === canonicalJson([...expectedNewPaths].sort()) &&
    expectedProfiles.every(
      (profile) =>
        new Set(
          observations
            .filter((observation) => observation.profile === profile)
            .map((observation) => observation.url),
        ).size >= 3,
    ) &&
    observationsHaveStrongCommentProof(observations, expectedProfiles) &&
    observationsHaveProductProof(
      observations,
      candidate.roleProjection,
      expectedProfiles,
    ) &&
    observations.every(
      (observation) =>
        observation.livePassed === true &&
        observation.oracleExecutionWorld === ORACLE_EXECUTION_WORLD &&
        observation.fixturePassed === true &&
        observation.visibleLeakCount === 0 &&
        observation.baselineNoNewExposure === true &&
        observation.approvedVariantCount === 1 &&
        observation.coMatchCount === 0 &&
        observation.algumon.titleConsistencyOk === true &&
        (observation.algumon.countComparable === false
          ? observation.algumon.countConsistency === null
          : observation.algumon.countConsistency === 1) &&
        observation.commentStructure.mountCount === 1 &&
        observation.commentStructure.classificationOverlapCount === 0 &&
        observation.commentStructure.unclassifiedContentCount === 0 &&
        Object.values(observation.roles).every(
          (role) => role.count === 1 && role.containedInPageRoot === true,
        ),
    ) &&
    /^[0-9a-f]{64}$/u.test(draftManifest.artifactSetSha256 ?? "");
  if (!observationsPass) {
    return {
      status: "rejected",
      reason: "candidate live, fixture, leak, co-match, or profile evidence gate failed",
      observationCount: observations.length,
    };
  }
  const evidenceSha256 = sha256(
    canonicalJson({ observations, routeEvidence }),
  );
  return {
    status: "proven",
    envelope: {
      schemaVersion: 1,
      status: "proven",
      protocolVersion: draftEnvelope.protocolVersion,
      baseConfigSha256: draftEnvelope.baseConfigSha256,
      releaseVersion: draftEnvelope.releaseVersion,
      proof: {
        candidateSha256: draftEnvelope.discovery.candidateSha256,
        evidenceSha256,
        draftArtifactSetSha256: draftManifest.artifactSetSha256,
        observations,
        routeEvidence,
      },
      candidate,
    },
  };
}

async function main() {
  const startedAt = new Date();
  const options = parseArguments(process.argv.slice(2));
  const configBytes = await fs.readFile(options.configPath);
  const config = assertAuditConfig(JSON.parse(configBytes.toString("utf8")));
  const promotionDraft = options.promotionDraftPath
    ? await readJson(options.promotionDraftPath)
    : null;
  const draftManifest = options.draftManifestPath
    ? await readJson(options.draftManifestPath)
    : null;
  if (promotionDraft && !draftManifest) {
    throw new Error("--promotion-draft requires --draft-manifest");
  }
  if (Boolean(options.promotionScopePath) !== Boolean(options.baselineReportPath)) {
    throw new Error("--promotion-scope and --baseline-report must be used together");
  }
  if (options.promotionScopePath && options.siteIds.size > 0) {
    throw new Error("--promotion-scope cannot be combined with --site");
  }
  const promotionScopeArtifact = options.promotionScopePath
    ? await readJson(options.promotionScopePath)
    : null;
  const baselineReport = options.baselineReportPath
    ? await readJson(options.baselineReportPath)
    : null;
  const promotionScope = promotionScopeArtifact
    ? buildPromotionRetestScope(
        config,
        promotionScopeArtifact,
        baselineReport,
      )
    : null;
  const sites = promotionScope
    ? sitesForPromotionRetest(config, promotionScope)
    : selectedSites(config, options.siteIds);
  const integrity = await buildIntegrityManifest(config, options.evidencePath, {
    bundleRoot: path.dirname(options.userscriptPath),
    draftManifest,
  });
  if (options.integrityOnly) {
    process.stdout.write(
      `${integrity.passed ? "PASS" : "FAIL"} integrity: ` +
        `${integrity.config.siteCount} sites, ${integrity.config.layoutCount} layouts\n`,
    );
    return integrity.passed ? 0 : 1;
  }

  const capturedAlgumonReport = options.capturedAlgumonReportPath && !options.fixtureOnly
    ? await readJson(options.capturedAlgumonReportPath)
    : null;
  const capturedCandidate = promotionDraft?.candidate ?? promotionScopeArtifact?.candidate ?? null;
  const capturedDiscovery = capturedAlgumonReport
    ? capturedAlgumonTargetsFromReport(capturedAlgumonReport, capturedCandidate, sites)
    : null;
  const algumonRequestBudget = createAlgumonRequestStartBudget(
    options.algumonRequestBudget,
  );

  const userscriptContent = await fs.readFile(options.userscriptPath, "utf8");
  const { chromium, devices } = await importPlaywright();
  RUNTIME_DEVICE_PROFILES = resolveRuntimeDeviceProfiles(devices);
  const runId = startedAt.toISOString().replace(/[:.]/gu, "-");
  const runDirectory = path.join(options.evidencePath, runId);
  await fs.mkdir(runDirectory, { recursive: true });
  const report = {
    schemaVersion: 1,
    runId,
    startedAt: startedAt.toISOString(),
    completedAt: null,
    configSha256: sha256(JSON.stringify(config)),
    userscriptSha256: sha256(userscriptContent),
    profiles: RUNTIME_DEVICE_PROFILES,
    browser: null,
    integrity,
    discovery: capturedDiscovery
      ? {
          enabled: false,
          required: options.requireAlgumonDiscovery,
          mode: capturedDiscovery.mode,
          sourceRunId: capturedDiscovery.sourceRunId,
          targetCount: capturedDiscovery.targetCount,
          failures: [],
        }
      : { enabled: options.discoverAlgumon, required: options.requireAlgumonDiscovery },
    algumonRequestBudget: algumonRequestBudget.snapshot(),
    promotionRetestScope: promotionScope,
    results: [],
    failures: [],
    summary: null,
  };
  const liveSites = sites;
  const candidateReport = {
    schemaVersion: 1,
    generatedAt: null,
    note:
      "Drafts are non-promotable. Only a separate byte-identical candidate live proof can emit promotion-ready.json.",
    failures: [],
  };
  const browser = await chromium.launch({
    headless: !options.headed,
    args: [
      "--disable-blink-features=AutomationControlled",
      "--disable-background-networking",
      "--disable-quic",
      "--dns-prefetch-disable",
      "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
      "--host-resolver-rules=" +
        "MAP localhost ~NOTFOUND, " +
        "MAP *.localhost ~NOTFOUND, " +
        "MAP metadata.google.internal ~NOTFOUND, " +
        "MAP *.internal ~NOTFOUND",
    ],
  });
  assertBrowserMatchesDeviceProfiles(browser.version(), RUNTIME_DEVICE_PROFILES);
  report.browser = {
    engine: "chromium",
    version: browser.version(),
    headed: options.headed,
    profileSource: "playwright-pinned-device-descriptors",
  };
  try {
    const fixtureTimeoutMs = Math.min(options.timeoutMs, FIXTURE_TIMEOUT_MS);
    const edgeFixtureOnly = options.tamperFixtureOnly || options.edgeFixtureIds.size > 0;
    report.syntheticFixture = edgeFixtureOnly || options.relayFixtureOnly
      ? { passed: true, skipped: "selected-fixture-only" }
      : await auditSyntheticNoFlashFixture(
          browser,
          userscriptContent,
          config,
          runDirectory,
          fixtureTimeoutMs,
        );
    if (!report.syntheticFixture.passed) {
      report.failures.push(
        ...report.syntheticFixture.failures.map(
          (failure) => `synthetic-no-flash: ${failure}`,
        ),
      );
    }
    report.relayFixtures = edgeFixtureOnly
      ? { passed: true, fixtures: [], skipped: "edge-fixture-only" }
      : await auditSyntheticAlgumonRelayFixtures(
          browser,
          userscriptContent,
          fixtureTimeoutMs,
          options.relayFixtureIds.size > 0 ? options.relayFixtureIds : null,
        );
    if (!report.relayFixtures.passed) {
      report.failures.push(
        ...report.relayFixtures.failures.map(
          (failure) => `algumon-relay: ${failure}`,
        ),
      );
    }
    report.regressionFixtures = edgeFixtureOnly || options.relayFixtureOnly
      ? { passed: true, fixtures: [], skipped: "selected-fixture-only" }
      : await runRegressionFixtures(
          browser,
          userscriptContent,
          config,
          runDirectory,
          fixtureTimeoutMs,
        );
    if (!report.regressionFixtures.passed) {
      report.failures.push(
        ...report.regressionFixtures.failures.map(
          (failure) => `behavior-regression: ${failure}`,
        ),
      );
    }
    report.edgeFixtures = options.relayFixtureOnly
      ? { passed: true, fixtures: [], skipped: "relay-fixture-only" }
      : await auditSyntheticEdgeFixtures(
          browser,
          userscriptContent,
          config,
          runDirectory,
          fixtureTimeoutMs,
          options.tamperFixtureOnly
            ? new Set(["marker-style-tamper"])
            : options.edgeFixtureIds.size > 0
              ? options.edgeFixtureIds
              : null,
        );
    if (!report.edgeFixtures.passed) {
      report.failures.push(
        ...report.edgeFixtures.failures.map(
          (failure) => `synthetic-edge: ${failure}`,
        ),
      );
    }
    const auditBaselineSamples = !options.fixtureOnly &&
      (!capturedDiscovery || promotionScope !== null);
    let targets = auditBaselineSamples ? sampleTargets(liveSites) : [];
    let discovery = null;
    if (capturedDiscovery) {
      targets = targets.concat(capturedDiscovery.targets);
    } else if (!options.fixtureOnly && options.discoverAlgumon) {
      discovery = await discoverLatestTargets(
        browser,
        liveSites,
        options.timeoutMs,
        promotionDraft?.candidate ?? null,
        algumonRequestBudget,
        runDirectory,
      );
      report.discovery.inventory = discovery.inventory;
      report.discovery.records = discovery.records;
      report.discovery.transitionBudget = discovery.transitionBudget;
      targets = targets.concat(discovery.targets);
    }
    targets = deduplicateTargets(targets);
    for (const targetContract of targets) {
      process.stdout.write(
        `AUDIT ${targetContract.site.id}/${targetContract.layout.id} ` +
          `${targetContract.profileName} ${targetContract.target.source}\n`,
      );
      const { result, candidates } = await auditOneTarget({
        browser,
        ...targetContract,
        userscriptContent,
        promotionCandidate: promotionDraft?.candidate ?? null,
        runtimeOnly: options.runtimeOnly,
        noAlgumonNetwork: options.noAlgumonNetwork,
        runDirectory,
        timeoutMs: options.timeoutMs,
      });
      report.results.push(result);
      if (!result.passed) {
        candidateReport.failures.push({
          siteId: result.siteId,
          layoutId: result.layoutId,
          profile: result.profile,
          source: result.source,
          reasons: result.failures,
          candidates,
        });
      }
    }
    if (discovery) {
      const transitionActual = discovery.transitionBudget.actual;
      transitionActual.plannedAcquisitionAndDestinationNavigationsMaximum =
        transitionActual.algumonRequestStarts +
        transitionActual.destinationAuditNavigationStartsMaximum;
      finalizeProfileLandingCoverage(discovery.records, report.results);
      const failures = discoveryFailures(
        liveSites,
        discovery.records,
        discovery.inventory,
        discovery.transitionBudget,
        report.results,
      );
      report.discovery.failures = failures;
      if (options.requireAlgumonDiscovery) {
        report.failures.push(
          ...discoveryFailuresRequiredForPromotion(failures, promotionScope),
        );
      }
    }
  } finally {
    report.algumonRequestBudget = algumonRequestBudget.snapshot();
    await browser.close();
  }

  report.completedAt = new Date().toISOString();
  const promotionReasons = new Map(
    (promotionScope?.tuples ?? []).map((tuple) => [
      `${promotionScope.siteId}\u0000${tuple.layoutId}\u0000${tuple.profile}`,
      tuple.reason,
    ]),
  );
  report.failures.push(
    ...report.results.flatMap((result) => {
      const reason = promotionReasons.get(
        `${result.siteId}\u0000${result.layoutId}\u0000${result.profile}`,
      );
      if (reason === "already-failed") return [];
      return result.failures.map(
        (failure) => `${result.siteId}/${result.layoutId}/${result.profile}: ${failure}`,
      );
    }),
  );
  if (promotionScope) {
    report.failures.push(...promotionRetestFailures(report, promotionScope));
  }
  report.summary = {
    targetCount: report.results.length,
    passedCount: report.results.filter((result) => result.passed).length,
    failedCount: report.results.filter((result) => !result.passed).length,
    directNegativeCount: report.results.filter(
      (result) => result.runtimeExpectation === "direct-negative",
    ).length,
    directNegativePassedCount: report.results.filter(
      (result) =>
        result.runtimeExpectation === "direct-negative" && result.passed === true,
    ).length,
    registeredPositiveCount: report.results.filter(
      (result) => result.runtimeExpectation === "registered-positive",
    ).length,
    registeredPositivePassedCount: report.results.filter(
      (result) => result.runtimeExpectation === "registered-positive" && result.passed === true,
    ).length,
    relayPositiveCount: report.results.filter(
      (result) => result.runtimeExpectation === "relay-positive",
    ).length,
    relayPositivePassedCount: report.results.filter(
      (result) =>
        result.runtimeExpectation === "relay-positive" && result.passed === true,
    ).length,
    inactivePublisherSafetyPassedCount: report.results.filter(
      (result) =>
        result.runtimeExpectation === "direct-negative" &&
        result.userscript?.gate?.inactivePublisherSafety?.passed === true,
    ).length,
    standaloneRuntimeCoveragePassedCount: report.results.filter(
      (result) =>
        result.runtimeExpectation !== "direct-negative" &&
        result.userscript?.gate?.standaloneRuntimeCoverage?.passed === true,
    ).length,
    failureCount: report.failures.length,
    syntheticNoFlashPassed: report.syntheticFixture?.passed === true,
    regressionFixtureCount: report.regressionFixtures?.fixtures?.length ?? 0,
    regressionFixturesPassed: report.regressionFixtures?.passed === true,
    edgeFixtureCount: report.edgeFixtures?.fixtures?.length ?? 0,
    edgeFixturesPassed: report.edgeFixtures?.passed === true,
    passed: integrity.passed && report.failures.length === 0,
  };
  let promotion = { status: "disabled" };
  if (options.synthesizeCandidates) {
    promotion = promotionDraft
      ? synthesizePromotionProof(report, config, promotionDraft, draftManifest)
      : await synthesizePromotionDraft(report, config, configBytes);
  }
  report.promotion = {
    status: promotion.status,
    reason: promotion.reason ?? null,
    candidates: promotion.candidates ?? [],
  };
  candidateReport.generatedAt = report.completedAt;
  const writes = [
    fs.writeFile(
      path.join(runDirectory, "audit-report.json"),
      `${JSON.stringify(report, null, 2)}\n`,
      "utf8",
    ),
    fs.writeFile(
      path.join(runDirectory, "selector-candidates.json"),
      `${JSON.stringify(candidateReport, null, 2)}\n`,
      "utf8",
    ),
    fs.writeFile(
      path.join(options.evidencePath, "latest-run.json"),
      `${JSON.stringify(
        {
          runId,
          report: `${runId}/audit-report.json`,
          passed: report.summary.passed,
          completedAt: report.completedAt,
        },
        null,
        2,
      )}\n`,
      "utf8",
    ),
    fs.writeFile(
      path.join(runDirectory, "promotion-proof.json"),
      `${JSON.stringify(
        {
          schemaVersion: 1,
          status: promotion.status,
          reason: promotion.reason ?? null,
          observationCount:
            promotion.envelope?.discovery?.observations?.length ??
            promotion.envelope?.proof?.observations?.length ??
            promotion.observationCount ??
            0,
          candidates: promotion.candidates ?? [],
        },
        null,
        2,
      )}\n`,
      "utf8",
    ),
  ];
  if (promotion.status === "draft") {
    const promotionDraftDirectory = path.join(runDirectory, "promotion-drafts");
    await fs.mkdir(promotionDraftDirectory, { recursive: true });
    for (const draft of promotion.drafts ?? []) {
      writes.push(
        fs.writeFile(
          path.join(promotionDraftDirectory, `${draft.fingerprint}.json`),
          `${JSON.stringify(draft.envelope, null, 2)}\n`,
          "utf8",
        ),
      );
    }
    writes.push(
      fs.writeFile(
        path.join(runDirectory, "promotion-candidates.json"),
        `${JSON.stringify(
          {
            schemaVersion: 1,
            candidates: promotion.candidates ?? [],
          },
          null,
          2,
        )}\n`,
        "utf8",
      ),
    );
    writes.push(
      fs.writeFile(
        path.join(runDirectory, "promotion-draft.json"),
        `${JSON.stringify(promotion.envelope, null, 2)}\n`,
        "utf8",
      ),
    );
  }
  if (promotion.status === "proven") {
    writes.push(
      fs.writeFile(
        path.join(runDirectory, "promotion-ready.json"),
        `${JSON.stringify(promotion.envelope, null, 2)}\n`,
        "utf8",
      ),
    );
  }
  await Promise.all(writes);
  process.stdout.write(
    `${report.summary.passed ? "PASS" : "FAIL"} DOM audit: ` +
      `${report.summary.passedCount}/${report.summary.targetCount} targets passed\n`,
  );
  return report.summary.passed ? 0 : 1;
}

export {
  AlgumonRequestBudgetExceeded,
  DEFAULT_ALGUMON_REQUEST_START_BUDGET,
  acquireArticleAccessLease,
  approvedPathsForLayout,
  articleIdentitiesLogicallyEquivalent,
  assertAuditConfig,
  auditCandidateOverlay,
  auditUserscriptGate,
  blockedUserscriptGateFailures,
  buildProjectedHideSelector,
  candidateGenerationAllowed,
  candidateOracleProjectionEvidence,
  candidateOverlayFailures,
  canonicalArticleIdentity,
  capturedAlgumonTargetsFromReport,
  classifyAlgumonInventorySnapshot,
  classifyAlgumonSourceResponse,
  captureAlgumonSourceFailure,
  classifyDestinationResponse,
  classifyProfileLandingRoute,
  collectRetainedRoleResourceEvidence,
  connectApprovedPublicAddresses,
  connectPinnedPublicAddress,
  commentControlProjectionFailures,
  commentItemProjectionFailures,
  commentControlSelectorDigest,
  commentControlSelectorDigestsForUrl,
  commentLowerBoundConsistency,
  committedProjectionEvidence,
  compareSemanticVersions,
  consumeArticleAccessLease,
  countExistingApprovedLayoutMatches,
  createArticleAccessLease,
  createAlgumonRequestStartBudget,
  createAlgumonSourceBrowserBudget,
  createLowTrafficAlgumonProbePlan,
  createNetworkPolicyEvidenceRecorder,
  createPageContext,
  createStylesheetDependencyRecorder,
  createPinnedPublicHttpsProxy,
  exactSignedAlgumonDealUrl,
  fixtureCoverageFailures,
  finishAlgumonSourceBrowser,
  finalizeProfileLandingCoverage,
  matchingApprovedPaths,
  navigateAlgumonSourcePage,
  navigateAlgumonSourceSession,
  networkFidelityFailures,
  networkResourceUrlSha256,
  networkRequestDecision,
  networkRequestRedirectEvidence,
  observeStylesheetDependencies,
  isPrivateOrSpecialIp,
  isTopLevelNavigationRequest,
  incrementStablePatchVersion,
  parseConnectAuthority,
  primeDeclaredArticleNavigation,
  retainUnobservedSessionNetworkPolicy,
  projectionCardinalityEvidence,
  promotionVariantId,
  promotionRetestFailures,
  recordedSignedRelayAcquisitionEvidence,
  runtimeExpectationForTarget,
  resultHasZeroLeak,
  semanticOracle,
  semanticOracleEvidence,
  semanticOracleContractFailures,
  selectFinalMainDocumentResponse,
  selectStableDiscoveryGroup,
  selectStableDiscoveryGroups,
  semanticVersionTuple,
  settlePage,
  signedRelayAcquisitionEvidence,
  siteArticleIdentity,
  staticRuntimeConsistencyFailures,
  synthesizePromotionDraftForGroup,
  synthesizePromotionProof,
  transferAlgumonRelaySession,
  userscriptGateFailures,
  validateDiagnostics,
  validatePublicDnsAnswers,
};

if (path.resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  try {
    process.exitCode = await main();
  } catch (error) {
    process.stderr.write(`${error?.stack ?? String(error)}\n`);
    process.exitCode = 2;
  }
}
