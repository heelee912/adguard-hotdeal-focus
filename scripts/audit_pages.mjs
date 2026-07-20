#!/usr/bin/env node

/**
 * Live DOM contract auditor for AdGuard Hotdeal Focus.
 *
 * The auditor has two independent gates:
 *   1. project the static ExtendedCSS selector from config/sites.json;
 *   2. inject the deterministic userscript at document-start and project the
 *      marker-only AdGuard gate.
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
const ALGUMON_HOSTNAMES = new Set(["algumon.com", "www.algumon.com"]);
const ALGUMON_GLOBAL_DISCOVERY_URL = `${ALGUMON_ORIGIN}/n/deal`;
const ALGUMON_SITE_LINK_SCAN_LIMIT = 12;
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
const PINNED_PROXY_MAX_CONNECT_REQUESTS = 1_024;
const PINNED_PROXY_MAX_ACTIVE_TUNNELS = 256;
const PINNED_PROXY_MAX_TRANSFER_BYTES = 512 * 1024 * 1024;
const PINNED_PROXY_CONNECT_TIMEOUT_MS = 15_000;
const PINNED_PROXY_DNS_TIMEOUT_MS = 5_000;
const PINNED_PROXY_MAX_DNS_ADDRESSES = 16;
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
const REQUIRED_ROLE_NAMES = Object.freeze(["title", "body", "comments"]);
const READER_GATE_PROTOCOL_VERSION = 2;
const READER_GATE_ARTIFACT_VERSION = "2.0.2";
const READER_GATE_READY_SELECTOR =
  'html.hdf-v2-ready[data-hotdeal-focus-ready="1"]' +
  '[data-hotdeal-focus-protocol="2"]' +
  '[data-hotdeal-focus-state="ready"]' +
  '[data-hotdeal-focus-status="ready"]';
const READER_GATE_PROJECTION_HIDE_SELECTOR =
  `${READER_GATE_READY_SELECTOR} body *:not(` +
  ".hdf-v2-keep[data-hotdeal-focus-keep])";
const IMPORTANT_DISPLAY_NONE_DECLARATION =
  /(?:^|;)\s*display\s*:\s*none\s*!important\s*(?:;|$)/iu;
const READER_GATE_SUBSCRIPTION_URL =
  "https://github.com/heelee912/adguard-hotdeal-focus/releases/download/" +
  "gate-v2.0.2/filter.txt";
const FIRST_PAINT_PROBE_SCHEMA_VERSION = 1;
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
const FIRST_PAINT_PROBE_SOURCE = String.raw`
(() => {
  "use strict";
  const probe = {
    schemaVersion: ${FIRST_PAINT_PROBE_SCHEMA_VERSION},
    sampleCount: 0,
    flashFrameCount: 0,
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
    const ready = root?.classList.contains("hdf-v2-ready") === true &&
      root?.getAttribute("data-hotdeal-focus-ready") === "1" &&
      root?.getAttribute("data-hotdeal-focus-protocol") === "2" &&
      state === "ready" &&
      root?.getAttribute("data-hotdeal-focus-status") === "ready" &&
      root?.classList.contains("hdf-v2-lock") === false &&
      !root?.hasAttribute("data-hotdeal-focus-lock");
    const rootStyle = root ? window.getComputedStyle(root) : null;
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
    if (probe.samples.length < 180) {
      probe.samples.push({
        frame,
        state,
        ready,
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
  return `${FIRST_PAINT_PROBE_SOURCE}\n` +
    `${PREAUTHORIZED_ADGUARD_CONTROL_SOURCE}\n${userscriptContent}`;
}

function parseArguments(argv) {
  const options = {
    configPath: DEFAULT_CONFIG_PATH,
    evidencePath: DEFAULT_EVIDENCE_PATH,
    userscriptPath: DEFAULT_USERSCRIPT_PATH,
    markerFilterPath: path.join(PROJECT_ROOT, "filter.txt"),
    timeoutMs: DEFAULT_TIMEOUT_MS,
    discoverAlgumon: true,
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
      case "--marker-filter":
        options.markerFilterPath = path.resolve(nextValue());
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
  return options;
}

function printUsage() {
  process.stdout.write(`Usage: node scripts/audit_pages.mjs [options]\n\n`);
  process.stdout.write(`  --config PATH                    Config file (default: config/sites.json)\n`);
  process.stdout.write(`  --evidence-dir PATH              Evidence root (default: outputs/evidence)\n`);
  process.stdout.write(`  --userscript PATH                Userscript to inject at document-start\n`);
  process.stdout.write(`  --marker-filter PATH             Marker-only filter projected in the browser\n`);
  process.stdout.write(`  --site ID                        Audit one site; repeat to select several\n`);
  process.stdout.write(`  --[no-]discover-algumon          Toggle latest-link discovery\n`);
  process.stdout.write(`  --require-algumon-discovery      Fail unless every selected site/device resolves\n`);
  process.stdout.write(`  --integrity-only                 Verify artifacts without launching a browser\n`);
  process.stdout.write(`  --fixture-only                   Run synthetic June/July behavior regressions only\n`);
  process.stdout.write(`  --tamper-fixture-only            Run the bounded terminal style-tamper regression only\n`);
  process.stdout.write(`  --edge-fixture ID                Run one edge fixture; repeat to select several\n`);
  process.stdout.write(`  --relay-fixture-only             Run only signed Algumon relay fixtures\n`);
  process.stdout.write(`  --relay-fixture ID               Run one relay fixture; repeat to select several\n`);
  process.stdout.write(`  --runtime-only                   Skip legacy static projection (candidate proof only)\n`);
  process.stdout.write(`  --synthesize-candidates          Emit a proven atomic overlay when all proof gates pass\n`);
  process.stdout.write(`  --promotion-draft PATH           Finalize one isolated draft after candidate live proof\n`);
  process.stdout.write(`  --draft-manifest PATH            Draft bundle manifest used for byte-identity proof\n`);
  process.stdout.write(`  --promotion-scope PATH           Proven candidate for profile-scoped pre-push audit\n`);
  process.stdout.write(`  --baseline-report PATH           Frozen full audit used for non-regression scope\n`);
  process.stdout.write(`  --timeout-ms N                   Per-page timeout\n`);
  process.stdout.write(`  --headed                         Show Chromium\n`);
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

function isReaderGateProjectionHideRule(rule) {
  return (
    rule.malformed === false &&
    rule.selector === READER_GATE_PROJECTION_HIDE_SELECTOR &&
    IMPORTANT_DISPLAY_NONE_DECLARATION.test(rule.declarations ?? "")
  );
}

function markerSelectorsForUrl(filterText, layout, urlText) {
  const parsed = new URL(urlText);
  const pathAndQuery = parsed.pathname + parsed.search;
  return [
    ...new Set(
      parseAdguardCosmeticRules(filterText)
        .filter(
          (rule) =>
            rule.domains.some((domain) => hostnameMatches(parsed.hostname, domain)) &&
            hostnameMatches(parsed.hostname, layout.domain) &&
            (rule.path === null || wildcardPathMatches(pathAndQuery, rule.path)) &&
            rule.operator === "#$?#" &&
            isReaderGateProjectionHideRule(rule),
        )
        .map((rule) => rule.selector),
    ),
  ];
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
  return {
    reserveRemoteRequest(hostname) {
      lastRemoteEventAt = Date.now();
      if (sealed) {
        lateRequestCount += 1;
        return {
          allowed: false,
          reason: "network-evidence-sealed",
          finish() {},
        };
      }
      activeRemoteRequestCount += 1;
      let finished = false;
      const finish = () => {
        if (finished) return;
        finished = true;
        activeRemoteRequestCount -= 1;
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
    recordAllowedRequestFailure(hostname, requestType, reason, isMainNavigation) {
      record(failedAllowedRequestByHost, hostname, requestType, reason, isMainNavigation);
    },
    recordAllowedResponseFailure(hostname, requestType, status, isMainNavigation) {
      record(
        failedAllowedResponseByHost,
        hostname,
        requestType,
        `http-${Number.isInteger(status) ? status : "invalid"}`,
        isMainNavigation,
      );
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
        sealed,
        allowedPublicHosts: serialize(allowedPublicByHost),
        undeclaredPublicHosts: serialize(undeclaredPublicByHost),
        failedAllowedRequestHosts: serialize(failedAllowedRequestByHost),
        failedAllowedResponseHosts: serialize(failedAllowedResponseByHost),
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
  if ((networkPolicyEvidence?.activeRemoteRequestCount ?? 0) > 0) {
    failures.push("network evidence sealed with active remote requests");
  }
  if ((networkPolicyEvidence?.lateRequestCount ?? 0) > 0) {
    failures.push("remote requests appeared after the network evidence seal");
  }
  if ((networkPolicyEvidence?.drainTimeoutCount ?? 0) > 0) {
    failures.push("remote requests did not drain inside the fail-closed deadline");
  }
  if ((networkPolicyEvidence?.navigationViolations ?? []).length > 0) {
    failures.push("a main frame reached a non-approved or local document URL");
  }
  if ((networkPolicyEvidence?.failedAllowedRequestHosts ?? []).length > 0) {
    failures.push("an allowed remote request failed before a complete response");
  }
  if ((networkPolicyEvidence?.failedAllowedResponseHosts ?? []).length > 0) {
    failures.push("an allowed remote response returned HTTP 4xx or 5xx");
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
  if ((pinnedTransport?.lateConnectCount ?? 0) > 0) {
    failures.push("CONNECT attempts appeared after the pinned transport seal");
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
  const referencedHosts = new Set((roleResourceEvidence.hosts ?? []).map(normalizedHostname));
  const isRequiredHost = (hostname) =>
    declaredResourceDomains.some((domain) => hostnameMatches(hostname, domain)) ||
    referencedHosts.has(normalizedHostname(hostname));
  const requiredBlockedHosts = (networkPolicyEvidence?.blockedHosts ?? []).filter(
    (entry) => isRequiredHost(entry.hostname),
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

async function createPinnedPublicHttpsProxy() {
  const approvedAddressesByHost = new Map();
  const resolutionCache = new Map();
  const connectedByHost = new Map();
  const rejectedByHost = new Map();
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
        const addresses = [
          ...new Set(records.map(({ address }) => normalizedHostname(address))),
        ].sort();
        if (addresses.length > PINNED_PROXY_MAX_DNS_ADDRESSES) {
          dnsAddressOverflowCount += 1;
          return [];
        }
        if (
          addresses.length < 1 ||
          addresses.some((address) => isPrivateOrSpecialIp(address))
        ) {
          return [];
        }
        return addresses;
      } catch {
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
  const connectToAddress = (
    address,
    timeoutMs,
    observeSocket = () => {},
  ) => new Promise((resolve, reject) => {
    const upstream = createConnection({
      host: address,
      port: 443,
      family: isIP(address),
    });
    observeSocket(upstream);
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      upstream.destroy();
      reject(error);
    };
    upstream.setTimeout(
      timeoutMs,
      () => fail(new Error("pinned CONNECT timed out")),
    );
    upstream.once("error", fail);
    upstream.once("connect", () => {
      if (settled) return;
      settled = true;
      upstream.removeListener("error", fail);
      upstream.setTimeout(0);
      resolve(upstream);
    });
  });
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
      let upstream = null;
      const connectDeadline = Date.now() + PINNED_PROXY_CONNECT_TIMEOUT_MS;
      for (const address of approvedAddresses) {
        if (clientClosed) break;
        const remainingMs = connectDeadline - Date.now();
        if (remainingMs <= 0) break;
        try {
          pendingUpstream = await connectToAddress(
            address,
            remainingMs,
            (socket) => {
              pendingUpstream = socket;
            },
          );
          upstream = pendingUpstream;
          break;
        } catch {}
      }
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
        dnsAddressOverflowCount,
        dnsTimeoutCount,
        evidenceHostOverflowCount,
        transportErrorCount,
        lateConnectCount,
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
    ? "direct-negative"
    : target?.source === "algumon-latest" && target.algumon
      ? "relay-positive"
      : null;
  if (
    derived &&
    (target.runtimeExpectation === undefined || target.runtimeExpectation === derived)
  ) {
    return derived;
  }
  throw new Error("audit target has no explicit direct-negative or relay-positive expectation");
}

function candidateGenerationAllowed(
  runtimeExpectation,
  sourceClassification,
  networkFidelityFailureCount = 0,
) {
  return Boolean(
    runtimeExpectation === "relay-positive" &&
      sourceClassification?.kind === "article-response" &&
      sourceClassification?.candidateEligible === true &&
      networkFidelityFailureCount === 0,
  );
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

function installedFilterRulesSha256(content) {
  const rules = canonicalText(content)
    .split("\n")
    .filter((line) => line.trim() && !line.trimStart().startsWith("!"));
  return rules.length > 0
    ? canonicalTextSha256(rules.join("\n"))
    : null;
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
  const artifacts = await Promise.all([
    readArtifact("filter.txt", bundleRoot),
    readArtifact("filter-static.txt", bundleRoot),
    readArtifact("hotdeal-focus.user.js", bundleRoot),
    readArtifact("package.json", bundleRoot),
    readArtifact("package-lock.json", bundleRoot),
    readArtifact("state/approved-variants.json", bundleRoot),
    readArtifact("config/sites.json", bundleRoot),
    readArtifact("config/gate-artifacts.json", bundleRoot),
    readArtifact("tests/fixtures/dom-regressions.json"),
    readArtifact("tests/fixtures/behavior-baseline.json"),
    readArtifact("release-manifest.json", bundleRoot),
  ]);
  const byPath = new Map(artifacts.map((artifact) => [artifact.path, artifact]));
  const markerFilter = byPath.get("filter.txt");
  const staticFilter = byPath.get("filter-static.txt");
  const userscript = byPath.get("hotdeal-focus.user.js");
  const configArtifact = byPath.get("config/sites.json");
  const approvedStateArtifact = byPath.get("state/approved-variants.json");
  const gateArtifactLockArtifact = byPath.get("config/gate-artifacts.json");
  const releaseManifestArtifact = byPath.get("release-manifest.json");
  const behaviorBaselineArtifact = byPath.get(
    "tests/fixtures/behavior-baseline.json",
  );
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
  let gateArtifactLock = null;
  if (!gateArtifactLockArtifact?.missing) {
    try {
      gateArtifactLock = JSON.parse(gateArtifactLockArtifact.content);
    } catch {
      gateArtifactLock = null;
    }
  }
  const isDraftBundle = draftManifest !== null;
  const draftArtifactPaths = Object.keys(draftManifest?.artifacts ?? {}).sort();
  const expectedDraftArtifactPaths = [
    "config/sites.json",
    "filter-static.txt",
    "filter.txt",
    "hotdeal-focus.user.js",
    "package-lock.json",
    "package.json",
  ];
  const draftArtifactEntries = Object.fromEntries(
    artifacts
      .filter((artifact) => expectedDraftArtifactPaths.includes(artifact.path))
      .map((artifact) => [
        artifact.path,
        artifact.missing
          ? null
          : { sha256: artifact.sha256, bytes: artifact.bytes },
      ]),
  );
  const draftArtifactSetSha256 = sha256(
    Buffer.from(canonicalJson(draftArtifactEntries), "utf8"),
  );
  const draftManifestContract =
    isDraftBundle &&
    draftManifest?.schemaVersion === 1 &&
    draftManifest?.status === "draft-non-promotable" &&
    draftManifest?.protocolVersion === READER_GATE_PROTOCOL_VERSION &&
    typeof draftManifest?.releaseVersion === "string" &&
    canonicalJson(draftArtifactPaths) === canonicalJson(expectedDraftArtifactPaths) &&
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
    site.layouts.flatMap((layout) =>
      [
        layout,
        ...(layout.variants ?? []).map((variant) => ({
          ...variant,
          domain: layout.domain,
          id: `${layout.id}--${variant.id}`,
        })),
      ].flatMap((contract) => pathsForLayout(contract).map((configuredPath) => {
      const staticCovered = staticRules.some(
        (rule) =>
          rule.domains.includes(contract.domain) &&
          rule.path === configuredPath &&
          rule.operator === "#?#",
      );
      return {
        siteId: site.id,
        layoutId: contract.id,
        domain: contract.domain,
        path: configuredPath,
        desktop: profilesForLayout(site, contract).includes("desktop"),
        mobile: profilesForLayout(site, contract).includes("mobile"),
        staticCovered,
      };
    }))),
  );
  const markerRules = markerFilter?.missing
    ? []
    : parseAdguardCosmeticRules(markerFilter.content);
  const exactObjectKeys = (value, expectedKeys) =>
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    canonicalJson(Object.keys(value).sort()) === canonicalJson([...expectedKeys].sort());
  const gateLockEntry = gateArtifactLock?.artifact;
  const gateArtifactLockContract = isDraftBundle || (
    !markerFilter?.missing &&
    !gateArtifactLockArtifact?.missing &&
    exactObjectKeys(gateArtifactLock, [
      "schemaVersion",
      "protocolVersion",
      "gateArtifactVersion",
      "filterSubscriptionUrl",
      "artifact",
    ]) &&
    exactObjectKeys(gateLockEntry, [
      "path",
      "bytes",
      "sha256",
      "installedRulesSha256",
    ]) &&
    gateArtifactLock.schemaVersion === 1 &&
    gateArtifactLock.protocolVersion === READER_GATE_PROTOCOL_VERSION &&
    gateArtifactLock.gateArtifactVersion === READER_GATE_ARTIFACT_VERSION &&
    gateArtifactLock.filterSubscriptionUrl === READER_GATE_SUBSCRIPTION_URL &&
    gateLockEntry.path === "filter.txt" &&
    gateLockEntry.bytes === markerFilter.bytes &&
    gateLockEntry.sha256 === markerFilter.sha256 &&
    gateLockEntry.installedRulesSha256 ===
      installedFilterRulesSha256(markerFilter.content)
  );
  const markerDomains = [...new Set(layouts.map((layout) => layout.domain))];
  const paintSafeLayoutPreservingLockDeclarations = [
    "transition: none !important",
    "animation: none !important",
    "visibility: hidden !important",
    "content-visibility: hidden !important",
    "opacity: 0 !important",
    "clip-path: inset(50%) !important",
    "pointer-events: none !important",
    "caret-color: transparent !important",
  ];
  const domainGateRules = (domain) => markerRules.filter(
    (rule) =>
      rule.path === null &&
      rule.domains.length === 1 &&
      rule.domains[0] === domain,
  );
  const markerGateCovered = markerDomains.every((domain) =>
    (() => {
      const rules = domainGateRules(domain);
      const standard = rules.filter((rule) => rule.operator === "#$#");
      const extended = rules.filter((rule) => rule.operator === "#$?#");
      const everyRuleIsV2 = rules.every((rule) =>
        rule.malformed === false &&
        !/hdf-v1-|data-hotdeal-focus-protocol=["'](?!2["'])/u.test(rule.selector));
      const projectionInBothEngines = [standard, extended].every((engineRules) =>
        engineRules.some(isReaderGateProjectionHideRule));
      const requiredMarkerTokens = [
        "hdf-v2-keep",
        "hdf-v2-shell",
        "hdf-v2-deep",
        "hdf-v2-role-title",
        "hdf-v2-role-title-text",
        "hdf-v2-role-body",
        "hdf-v2-role-product",
        "hdf-v2-role-comment-item",
        "hdf-v2-role-comment-control",
      ];
      return rules.length === 13 && standard.length === 7 && extended.length === 6 &&
        everyRuleIsV2 && projectionInBothEngines &&
        requiredMarkerTokens.every((token) =>
          standard.some((rule) => rule.selector.includes(token)) &&
          extended.some((rule) => rule.selector.includes(token)));
    })(),
  );
  const prelockGateCovered = markerDomains.every((domain) =>
    (() => {
      const rules = domainGateRules(domain);
      const rootLockRules = ["#$#", "#$?#"].map((operator) =>
        rules.find((rule) =>
          rule.operator === operator &&
          rule.selector.includes(
            `html:not(${READER_GATE_READY_SELECTOR.slice(4)})`,
          ) &&
          rule.selector.includes("html.hdf-v2-lock") &&
          paintSafeLayoutPreservingLockDeclarations.every((declaration) =>
            rule.declarations?.includes(declaration)) &&
          !/display\s*:/u.test(
            rule.declarations ?? "",
          )),
      );
      const topLayerRule = rules.find((rule) =>
        rule.operator === "#$#" &&
        rule.selector.includes("dialog::backdrop") &&
        rule.selector.includes("[popover]::backdrop") &&
        rule.selector.includes(":fullscreen::backdrop") &&
        /display:\s*none\s*!important/u.test(rule.declarations ?? "") &&
        /visibility:\s*hidden\s*!important/u.test(rule.declarations ?? ""));
      return rootLockRules.every(Boolean) && Boolean(topLayerRule);
    })(),
  );
  const userscriptContractCovered =
    !userscript?.missing &&
    /^\/\/\s*@grant\s+GM_addElement\s*$/mu.test(userscript.content) &&
    (userscript.content.match(/^\/\/\s*@grant\s+/gmu) ?? []).length === 1 &&
    userscript.content.includes('const PROTOCOL_VERSION = "2"') &&
    userscript.content.includes('GM_addElement(parent, "style", {') &&
    userscript.content.includes('"data-hotdeal-focus-runtime-style": "2"') &&
    userscript.content.includes("hdf-v2-lock") &&
    userscript.content.includes("hdf-v2-ready") &&
    userscript.content.includes("data-hotdeal-focus-ready") &&
    userscript.content.includes("data-hotdeal-focus-keep") &&
    userscript.content.includes("__HOTDEAL_FOCUS_DIAGNOSTICS__");
  const releaseArtifactEntryFor = (artifactPath) => {
    const entries = releaseManifest?.artifacts;
    if (Array.isArray(entries)) {
      return entries.find((candidate) => candidate?.path === artifactPath) ?? null;
    }
    const entry = entries?.[artifactPath];
    return entry && typeof entry === "object" ? entry : null;
  };
  const releaseHashFor = (artifactPath) => {
    if (isDraftBundle) {
      return draftManifest?.artifacts?.[artifactPath]?.sha256 ?? null;
    }
    const entries = releaseManifest?.artifacts;
    if (Array.isArray(entries)) {
      const entry = entries.find((candidate) => candidate?.path === artifactPath);
      return entry?.sha256 ?? null;
    }
    const entry = entries?.[artifactPath];
    return typeof entry === "string" ? entry : entry?.sha256 ?? null;
  };
  const releaseGateEntry = releaseArtifactEntryFor("filter.txt");
  const gateArtifactLockMatchesRelease = isDraftBundle || (
    gateArtifactLockContract &&
    releaseManifest?.protocolVersion === gateArtifactLock.protocolVersion &&
    releaseManifest?.gateArtifactVersion === gateArtifactLock.gateArtifactVersion &&
    releaseManifest?.filterSubscriptionUrl === gateArtifactLock.filterSubscriptionUrl &&
    releaseGateEntry?.version === gateArtifactLock.gateArtifactVersion &&
    releaseGateEntry?.bytes === gateLockEntry.bytes &&
    releaseGateEntry?.sha256 === gateLockEntry.sha256 &&
    releaseGateEntry?.installedRulesSha256 === gateLockEntry.installedRulesSha256
  );
  const artifactHashesMatchRelease = [markerFilter, userscript].every(
    (artifact) =>
      !artifact?.missing && releaseHashFor(artifact.path) === artifact.sha256,
  );
  const installedRulesHashMatchesRelease = isDraftBundle ||
    (!markerFilter?.missing &&
      releaseArtifactEntryFor("filter.txt")?.installedRulesSha256 ===
        installedFilterRulesSha256(markerFilter.content));
  const userscriptCanonicalTextHashMatchesRelease = isDraftBundle ||
    (!userscript?.missing &&
      releaseArtifactEntryFor("hotdeal-focus.user.js")?.canonicalTextSha256 ===
        canonicalTextSha256(userscript.content));
  const releaseSourceHashFor = (artifactPath) => {
    const entry = releaseManifest?.sourceIntegrity?.[artifactPath];
    return typeof entry === "string" ? entry : entry?.sha256 ?? null;
  };
  const sourceIntegrityPaths = Object.keys(
    releaseManifest?.sourceIntegrity ?? {},
  );
  const sourceHashesMatchRelease = isDraftBundle
    ? draftManifestContract
    : sourceIntegrityPaths.length > 0 &&
      sourceIntegrityPaths.every((artifactPath) => {
        const artifact = byPath.get(artifactPath);
        return (
          artifact !== undefined &&
          !artifact.missing &&
          releaseSourceHashFor(artifactPath) === artifact.sha256
        );
      });
  const expectedConfigHash =
    (isDraftBundle
      ? draftManifest?.artifacts?.["config/sites.json"]?.sha256
      : releaseManifest?.configSha256 ??
        releaseManifest?.config_sha256 ??
        releaseManifest?.config?.sha256 ??
        releaseHashFor("config/sites.json"));
  const configHashMatchesRelease =
    !configArtifact?.missing && expectedConfigHash === configArtifact.sha256;
  const releaseProtocolVersion =
    (isDraftBundle
      ? draftManifest?.protocolVersion
      : releaseManifest?.protocolVersion ?? releaseManifest?.protocol_version);
  const markerProtocolVersions = new Set(
    markerRules.flatMap((rule) => {
      return [...rule.selector.matchAll(
        /data-hotdeal-focus-protocol=["']([^"']+)["']/gu,
      )].map((match) => match[1]);
    }),
  );
  const markerHeaderProtocolVersions = markerFilter?.missing
    ? []
    : [...markerFilter.content.matchAll(/^! Hotdeal-Focus-Protocol:\s*(\d+)\s*$/gmu)]
        .map((match) => Number(match[1]));
  let behaviorBaseline = null;
  try {
    behaviorBaseline = JSON.parse(behaviorBaselineArtifact?.content ?? "null");
  } catch {
    behaviorBaseline = null;
  }
  const protocolMajorStable =
    releaseProtocolVersion === READER_GATE_PROTOCOL_VERSION &&
    behaviorBaseline?.protocol_major === READER_GATE_PROTOCOL_VERSION;
  const userscriptVersion = userscript?.content?.match(
    /^\/\/\s*@version\s+([^\s]+)\s*$/mu,
  )?.[1];
  const releaseVersion =
    (isDraftBundle
      ? draftManifest?.releaseVersion
      : releaseManifest?.version ??
        releaseManifest?.releaseVersion ??
        releaseManifest?.release_version);
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
    approvedVariantCount:
      approvedState?.schemaVersion === 1 && Array.isArray(approvedState.variants)
        ? approvedState.variants.length
        : 0,
  };
  const releaseCoverageMatchesConfig = isDraftBundle ||
    canonicalJson(releaseManifest?.coverage ?? null) ===
      canonicalJson(expectedReleaseCoverage);
  const generatorVersion =
    releaseManifest?.generatorVersion ?? releaseManifest?.generator_version;
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
    markerGateContract: markerGateCovered,
    prelockGateContract: prelockGateCovered,
    gateArtifactLockContract,
    gateArtifactLockMatchesRelease,
    userscriptContract: userscriptContractCovered,
    releaseManifestContract:
      isDraftBundle
        ? draftManifestContract
        : Boolean(releaseManifest) &&
          releaseProtocolVersion === READER_GATE_PROTOCOL_VERSION &&
          typeof generatorVersion === "string" &&
          generatorVersion.length > 0 &&
          canonicalJson(Object.keys(releaseManifest.artifacts ?? {}).sort()) ===
            canonicalJson(["filter.txt", "hotdeal-focus.user.js"]),
    artifactHashesMatchRelease,
    installedRulesHashMatchesRelease,
    userscriptCanonicalTextHashMatchesRelease,
    sourceHashesMatchRelease,
    configHashMatchesRelease,
    releaseCoverageMatchesConfig,
    protocolMajorStable,
    markerProtocolMajorStable:
      markerProtocolVersions.size === 1 &&
      markerProtocolVersions.has(String(READER_GATE_PROTOCOL_VERSION)) &&
      markerHeaderProtocolVersions.length === 1 &&
      markerHeaderProtocolVersions[0] === READER_GATE_PROTOCOL_VERSION &&
      !markerFilter?.missing &&
      !markerFilter.content.includes("hdf-v1-") &&
      !/data-hotdeal-focus-protocol=["']1["']/u.test(markerFilter.content),
    userscriptVersionMatchesRelease:
      typeof userscriptVersion === "string" && userscriptVersion === releaseVersion,
    distinctStaticAndMarkerFilters:
      !markerFilter?.missing &&
      !staticFilter?.missing &&
      markerFilter.sha256 !== staticFilter.sha256,
  };
  const manifest = {
    schemaVersion: 1,
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
    artifacts: artifacts.map(({ content: _content, absolutePath: _absolutePath, ...item }) => item),
    releaseManifest: releaseManifest
      ? {
          sha256: releaseManifestArtifact.sha256,
          protocolVersion: releaseProtocolVersion,
          generatorVersion,
        }
      : null,
    gateArtifactLock: gateArtifactLock
      ? {
          sha256: gateArtifactLockArtifact.sha256,
          protocolVersion: gateArtifactLock.protocolVersion,
          gateArtifactVersion: gateArtifactLock.gateArtifactVersion,
          filterSubscriptionUrl: gateArtifactLock.filterSubscriptionUrl,
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

function selectFinalMainDocumentResponse(responseChain, finalUrl) {
  const comparableFinalUrl = comparableDocumentUrl(finalUrl);
  const matchingResponses = (responseChain ?? []).filter(
    (response) => comparableDocumentUrl(response.url) === comparableFinalUrl,
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
      if (navigationProof) {
        await page.goto("about:blank", {
          waitUntil: "commit",
          timeout: timeoutMs,
        });
        await page.evaluate((name) => {
          window.name = name;
        }, `hdf-provenance:${navigationProof.navigationNonce}`);
      }
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

async function roleReferencedResourceHosts(page, selectors) {
  return evaluateInIsolatedWorld(page, (roleSelectors) => {
    const maximumRoots = 32;
    const maximumNodes = 2_048;
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
      if (nodes.size + queue.length - queueIndex >= maximumNodes) {
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
      if (nodes.size >= maximumNodes) {
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
    let urlOverflowCount = 0;
    const append = (value) => {
      if (typeof value !== "string" || !value.trim()) return;
      if (rawUrls.length >= maximumUrls) {
        urlOverflowCount += 1;
        return;
      }
      rawUrls.push(value.trim());
    };
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
    for (const element of nodes) {
      const tagName = element.localName;
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
          appendCssUrls(style.backgroundImage);
          appendCssUrls(style.listStyleImage);
          appendCssUrls(style.content);
        } catch {}
      }
      if (performance.now() - startedAt > maximumElapsedMs) {
        elapsedTimeOverflowCount += 1;
        break;
      }
    }
    const hosts = new Set();
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
      rootCount: roots.size,
      nodeCount: nodes.size,
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
  }, selectors);
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
    (comparableDocumentUrl(suppliedFinalResponse?.url) === comparableDocumentUrl(finalUrl)
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
    finalResponse && comparableDocumentUrl(finalResponse.url) === comparableDocumentUrl(finalUrl),
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
  if (!Array.isArray(cookies) || cookies.length > ARTICLE_ACCESS_LEASE_MAX_COOKIES) {
    throw new Error("article access lease cookie count exceeded its bound");
  }
  if (Buffer.byteLength(JSON.stringify(cookies), "utf8") > ARTICLE_ACCESS_LEASE_MAX_COOKIE_BYTES) {
    throw new Error("article access lease cookie bytes exceeded their bound");
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
    if (!domainAllowed || cookie.secure !== true || !unexpired) continue;
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
  if (target.algumon.verifiedResolution) {
    const signedUrl = exactSignedAlgumonDealUrl(
      target.algumon.redirectUrl,
      target.algumon.dealId,
    );
    const useTimeAcquisition = target.source === "algumon-latest"
      ? signedRelayAcquisitionEvidence(
          target.algumon.redirectUrl,
          target.algumon.dealId,
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
      provenanceMode: "single-fetch-signed-relay",
      relayFetchUrl: resolution.relayFetchUrl,
      resolvedDestination: resolution.resolvedDestination,
      popupNavigation: [],
      relayResponseSha256: resolution.responseSha256,
    };
  }
  await navigate(page, target.algumon.discoveryUrl, timeoutMs);
  const expectedRedirect = new URL(target.algumon.redirectUrl);
  const redirectPath = expectedRedirect.pathname;
  const redirectLinks = page.locator('a[href*="/l/d/"]');
  const matchingIndexes = await redirectLinks.evaluateAll(
    (anchors, expectedHref) => anchors.flatMap((anchor, index) => {
      try {
        return new URL(anchor.href).href === expectedHref ? [index] : [];
      } catch {
        return [];
      }
    }),
    expectedRedirect.href,
  );
  if (matchingIndexes.length < 1) {
    throw new Error(
      `Algumon click proof found no ${redirectPath} link`,
    );
  }
  const anchor = redirectLinks.nth(matchingIndexes[0]);
  await anchor.scrollIntoViewIfNeeded();
  const clickedUrl = new URL(await anchor.getAttribute("href"), page.url());
  if (
    clickedUrl.href !== expectedRedirect.href ||
    clickedUrl.origin !== ALGUMON_ORIGIN ||
    clickedUrl.pathname !== redirectPath
  ) {
    throw new Error("Algumon click proof selected a non-exact redirect URL");
  }
  const context = page.context();
  let entryRequest = null;
  const navigationUrls = [];
  const observeRequest = (request) => {
    try {
      const requestUrl = new URL(request.url());
      if (
        !entryRequest &&
        hostnameMatches(requestUrl.hostname, "algumon.com") &&
        requestUrl.pathname === redirectPath
      ) {
        entryRequest = request;
      }
    } catch {}
  };
  context.on("request", observeRequest);
  const popupPromise = page.waitForEvent("popup", { timeout: timeoutMs });
  let popup;
  try {
    [popup] = await Promise.all([
      popupPromise,
      anchor.click({ timeout: timeoutMs }),
    ]);
    const playwrightOpener = await popup.opener();
    if (playwrightOpener !== page) {
      throw new Error("Algumon popup was not created by the audited source page");
    }
    popup.on("framenavigated", (frame) => {
      if (frame === popup.mainFrame()) navigationUrls.push(frame.url());
    });
    navigationUrls.push(popup.url());
    await popup.waitForURL(
      (url) =>
        url.protocol === "https:" &&
        !hostnameMatches(url.hostname, "algumon.com"),
      { timeout: timeoutMs },
    );
    await settlePage(popup, timeoutMs);
  } finally {
    context.off("request", observeRequest);
  }
  if (!entryRequest) {
    throw new Error("Algumon popup request chain did not begin at the clicked redirect");
  }
  const relayFetchUrl = entryRequest.url();
  if (relayFetchUrl !== clickedUrl.href || entryRequest.redirectedTo() !== null) {
    throw new Error("Algumon relay fetch was not the exact non-redirecting signed request");
  }
  const finalUrl = popup.url();
  const expectedTargetDomain = expectedDomain || new URL(target.url).hostname;
  if (!hostnameMatches(new URL(finalUrl).hostname, expectedTargetDomain)) {
    throw new Error(`Algumon popup ended outside ${expectedTargetDomain}`);
  }
  const popupSecurity = await popup.evaluate(() => ({
    openerIsNull: window.opener === null,
    referrer: document.referrer,
    nameCleared: window.name === "",
  }));
  if (
    popupSecurity.openerIsNull !== true ||
    popupSecurity.referrer !== `${ALGUMON_ORIGIN}/` ||
    popupSecurity.nameCleared !== true
  ) {
    throw new Error("Algumon popup opener/referrer/seed cleanup contract failed");
  }
  return {
    finalUrl,
    status: null,
    viaAlgumon: true,
    page: popup,
    openedNewContext: true,
    relayFetchUrl,
    resolvedDestination: finalUrl,
    popupNavigation: [...new Set(navigationUrls.filter(Boolean))],
    popupSecurity,
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
  parsed.hash = `hdf-seed=${encoded}`;
  return parsed.href;
}

function seededNavigationProof(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  const encoded = new URLSearchParams(parsed.hash.replace(/^#/u, "")).get("hdf-seed");
  if (!encoded || !/^[A-Za-z0-9_-]+$/u.test(encoded)) return null;
  try {
    const seed = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    return /^hdf-[0-9a-z]{28}$/u.test(String(seed?.navigationNonce ?? ""))
      ? { navigationNonce: seed.navigationNonce }
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
    ({ sourceBytes, expectedSiteId, expectedLayoutId, rolesRequired, oracleSeed }) => {
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
      return {
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
          resolution.seedConsistency?.titleSimilarity ?? 0,
        seedTitleConsistencyOk:
          resolution.seedConsistency?.titleConsistencyOk === true,
        seedTitleConsistencyMode:
          resolution.seedConsistency?.titleMode ?? "missing",
        seedTitleMetadataSourceCount:
          resolution.seedConsistency?.metadataSourceCount ?? 0,
        seedTitleMetadataSourceKinds:
          resolution.seedConsistency?.metadataSourceKinds ?? [],
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
    ({ expectedSiteId, sourceBytes, oracleSeed, projectionLayouts }) => {
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
        return contract.id === expectedSiteId &&
          (hostname === contract.domain || hostname.endsWith(`.${contract.domain}`));
      });
      const pathAndQuery = `${location.pathname}${location.search}`;
      const layouts = (projectionLayouts ?? site?.layouts ?? []).filter((candidate) =>
        (candidate.paths ?? [candidate.path]).some((configuredPath) =>
          api.pathPatternMatches(pathAndQuery, configuredPath)));
      const validatedSeed = api.validateSeed(oracleSeed, Date.now(), false);
      const projection = api.resolveProjectionClasses(
        document,
        layouts,
        validatedSeed?.siteType === site?.id ? validatedSeed : null,
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
    title: { mode: "seeded-shallow" },
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
        titleConsistencyMode: titleResult.mode,
        titleMetadataSourceCount: titleResult.metadata.sourceCount,
        titleMetadataSourceKinds: titleResult.metadata.sourceKinds,
        titleConsistent: Boolean(algumon?.title) && titleResult.ok === true,
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
  const algumonTitle = target.algumon?.title ?? "";
  const algumonCommentCount = target.algumon?.commentCount ?? null;
  const titleSimilarity = Number(oracle.seedTitleSimilarity ?? 0);
  const titleComparable = Boolean(oracle.titleNormalized && algumonTitle);
  const commentComparable =
    Number.isInteger(oracle.commentItemCount) && Number.isInteger(algumonCommentCount);
  const commentTolerance = commentComparable ? 0 : null;
  const titleConsistency = titleComparable
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
      target.source === "algumon-latest" &&
      titleConsistent &&
      commentConsistent &&
      exactCommentStructure,
    structuralOk: oracle.ok === true,
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
    "commentControlProjection",
    "visibleLeakCount",
  ]);
  const unexpectedTopKeys = Object.keys(diagnostics).filter((key) => !allowedTopKeys.has(key));
  if (unexpectedTopKeys.length > 0) {
    failures.push(`diagnostics contains non-contract keys: ${unexpectedTopKeys.join(", ")}`);
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
  markerSelectors,
  runtimeExpectation = "relay-positive",
  allowedCommentControlSelectorDigests = [],
) {
  await page
    .waitForFunction(
      ({ expectation, protocolVersion }) => {
        const html = document.documentElement;
        const state = html.getAttribute("data-hotdeal-focus-state");
        const status = html.getAttribute("data-hotdeal-focus-status");
        const paintProbe = window.__HOTDEAL_FOCUS_PAINT_PROBE__;
        const sampled = Number.isInteger(paintProbe?.sampleCount) &&
          paintProbe.sampleCount >= 1;
        const terminal = state === "blocked" &&
          String(status ?? "").startsWith("terminal-");
        if (terminal) return sampled;
        if (expectation === "direct-negative") return false;
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
          preauthorized?.kind === "preauthorized-nonce-control" &&
          preauthorized?.schemaVersion === protocolVersion &&
          preauthorized?.gmAddElementCalls === 1 &&
          preauthorized?.extendedCssCallbacks >= 2 &&
          document.querySelectorAll(
            'style[data-hotdeal-focus-runtime-style="2"]',
          ).length === 1;
      },
      {
        expectation: runtimeExpectation,
        protocolVersion: READER_GATE_PROTOCOL_VERSION,
      },
      { timeout: timeoutMs },
    )
    .catch(() => {});

  return page.evaluate(({ rolesToRequire, selectors, allowedControlSelectorDigests }) => {
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
    const markerMatchedNodes = new Set();
    const markerSelectorErrors = [];
    for (const selector of selectors) {
      try {
        for (const element of document.querySelectorAll(selector)) {
          markerMatchedNodes.add(element);
        }
      } catch (error) {
        markerSelectorErrors.push(String(error));
      }
    }
    const bodyElements = [...document.body.querySelectorAll("*")];
    const uncoveredUnmarkedNodes = bodyElements.filter(
      (element) =>
        !exactlyOwned(element) &&
        !markerMatchedNodes.has(element),
    );
    const coveredKeptNodes = bodyElements.filter(
      (element) =>
        exactlyOwned(element) &&
        markerMatchedNodes.has(element),
    );
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
      return {
        count: nodes.length,
        visibleCount: nodes.filter(visible).length,
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
          extendedCssCallbacks: preauthorized.extendedCssCallbacks,
        }
      : null;
    const runtimeStyleCount = document.querySelectorAll(
      'style[data-hotdeal-focus-runtime-style="2"]',
    ).length;
    const zeroFlash = paintProbe?.flashFrameCount === 0;
    const zeroVisibleContent = globalPaintLockIntact || (
      visibleWithoutKeep.length === 0 && directTextLeaks.length === 0
    );
    const blockedStateSafety = {
      applicable: !ready,
      terminal: state === "blocked" && String(status ?? "").startsWith("terminal-"),
      globalPaintLockIntact,
      zeroVisibleContent,
      zeroFlash,
      passed:
        !ready &&
        state === "blocked" &&
        String(status ?? "").startsWith("terminal-") &&
        globalPaintLockIntact &&
        zeroVisibleContent &&
        zeroFlash,
    };
    const readyMarkerCoverage = {
      applicable: ready,
      selectorCount: selectors.length,
      selectorErrorCount: markerSelectorErrors.length,
      uncoveredUnmarkedCount: uncoveredUnmarkedNodes.length,
      coveredKeptCount: coveredKeptNodes.length,
      passed:
        ready &&
        selectors.length > 0 &&
        markerSelectorErrors.length === 0 &&
        uncoveredUnmarkedNodes.length === 0 &&
        coveredKeptNodes.length === 0,
    };
    return {
      ready,
      state,
      status,
      globalPaintLockIntact,
      blockedStateSafety,
      readyMarkerCoverage,
      markerSelectorCount: selectors.length,
      markerSelectorErrors,
      uncoveredUnmarkedCount: uncoveredUnmarkedNodes.length,
      coveredKeptCount: coveredKeptNodes.length,
      diagnostics,
      paintProbe,
      testOnlyAdguardControl,
      runtimeStyleCount,
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
    selectors: markerSelectors,
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

function userscriptGateFailures(gate, requiredRoles) {
  const failures = [];
  if (!gate.ready) failures.push(`userscript gate is not ready (state=${gate.state ?? "missing"})`);
  if (gate.diagnostics?.protocolVersion !== READER_GATE_PROTOCOL_VERSION) {
    failures.push("userscript diagnostics are not exact reader-gate protocol 2");
  }
  if (
    gate.testOnlyAdguardControl?.kind !== "preauthorized-nonce-control" ||
    gate.testOnlyAdguardControl?.schemaVersion !== READER_GATE_PROTOCOL_VERSION ||
    gate.testOnlyAdguardControl?.gmAddElementCalls !== 1 ||
    !(gate.testOnlyAdguardControl?.extendedCssCallbacks >= 2)
  ) {
    failures.push("preauthorized AdGuard test control did not prove the two-frame fixture callback");
  }
  if (gate.runtimeStyleCount !== 1) {
    failures.push(`runtime stylesheet cardinality is ${gate.runtimeStyleCount ?? "missing"}`);
  }
  if (gate.markerSelectorCount < 1) failures.push("no manifest-matched marker filter selector applies");
  if (gate.markerSelectorErrors.length > 0) {
    failures.push(`marker filter selector errors: ${gate.markerSelectorErrors.join(" | ")}`);
  }
  if (gate.uncoveredUnmarkedCount > 0) {
    failures.push(`${gate.uncoveredUnmarkedCount} unmarked nodes escape the real marker filter`);
  }
  if (gate.coveredKeptCount > 0) {
    failures.push(`${gate.coveredKeptCount} kept nodes are hidden by the real marker filter`);
  }
  if (!gate.paintProbe || gate.paintProbe.sampleCount < 1) {
    failures.push("document-start first-paint probe is missing");
  } else {
    if (gate.paintProbe.flashFrameCount !== 0) {
      failures.push(`${gate.paintProbe.flashFrameCount} pre-ready frames exposed unmarked content`);
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
      (gate.commentItemStats?.count ?? 0) > 0 &&
      stats.visibleCount === 0
    ) {
      failures.push("comments role has no visible keep-owned projection");
    }
  }
  const commentItemStats = gate.commentItemStats;
  if (commentItemStats?.count > 0) {
    if (!commentItemStats.allKept) failures.push("comment item lacks keep marker");
    if (commentItemStats.visibleCount !== commentItemStats.count) {
      failures.push(
        `${commentItemStats.count - commentItemStats.visibleCount} comment items are not visible`,
      );
    }
  }
  failures.push(...commentControlProjectionFailures(gate));
  failures.push(...validateDiagnostics(gate.diagnostics, requiredRoles));
  return failures;
}

function blockedUserscriptGateFailures(gate) {
  const failures = [];
  if (gate.ready) failures.push("direct navigation unexpectedly became reader-ready");
  if (gate.state !== "blocked") {
    failures.push(`direct navigation did not remain blocked (state=${gate.state ?? "missing"})`);
  }
  if (gate.status !== "terminal-algumon-seed-required") {
    failures.push(
      `direct navigation did not terminate at the provenance gate (status=${gate.status ?? "missing"})`,
    );
  }
  if (gate.blockedStateSafety?.globalPaintLockIntact !== true) {
    failures.push("blocked-state global paint lock is not intact");
  }
  if (gate.blockedStateSafety?.zeroVisibleContent !== true) {
    failures.push("blocked-state content is visible");
  }
  if (!gate.paintProbe || gate.paintProbe.sampleCount < 1) {
    failures.push("document-start first-paint probe is missing");
  } else {
    if (gate.paintProbe.flashFrameCount !== 0) {
      failures.push(`${gate.paintProbe.flashFrameCount} blocked-state frames exposed content`);
    }
    if (gate.paintProbe.firstReadyFrame !== null) {
      failures.push("direct navigation emitted a ready frame");
    }
    const contentSamples = (gate.paintProbe.samples ?? []).filter(
      (sample) => sample.bodyElementCount > 0 && sample.ready !== true,
    );
    if (
      contentSamples.length < 1 ||
      contentSamples.some((sample) => sample.paintLockIntact !== true)
    ) {
      failures.push("blocked-state paint lock was not intact for every sampled content frame");
    }
  }
  if (gate.visibleWithoutKeepCount !== 0 || gate.directVisibleTextLeakCount !== 0) {
    failures.push("blocked-state visible content count is not zero");
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
  const networkEvidenceRecorder = createNetworkPolicyEvidenceRecorder({
    allowPublicHttpsSubresources,
  });
  const pinnedTransport = await createPinnedPublicHttpsProxy();
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
    );
    finishInFlightReservation(request);
  };
  context.on("requestfinished", finishInFlightReservation);
  context.on("requestfailed", failInFlightReservation);
  context.on("response", (response) => {
    const request = response.request();
    const lifecycle = inFlightReservations.get(request);
    if (!lifecycle || response.status() < 400) return;
    networkEvidenceRecorder.recordAllowedResponseFailure(
      lifecycle.hostname,
      lifecycle.requestType,
      response.status(),
      lifecycle.isMainNavigation,
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
    const decision = networkRequestDecision(
      parsed.href,
      isMainNavigation,
      [...navigationDomains],
      [...resourceDomains],
      [...exactResourceHosts],
      allowPublicHttpsSubresources,
    );
    if (decision.reason === "local-browser-scheme") {
      await route.continue();
      return;
    }
    const reservation = networkEvidenceRecorder.reserveRemoteRequest(parsed.hostname);
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
        ? await pinnedTransport.approvePublicHost(parsed.hostname)
        : [];
      if (!decision.allowed || approvedAddresses.length < 1) {
        networkEvidenceRecorder.recordBlocked(
          parsed.hostname,
          request.resourceType(),
          decision.allowed ? "dns-not-public" : decision.reason,
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
    const decision = networkRequestDecision(
      parsed.href,
      false,
      [...navigationDomains],
      [...resourceDomains],
      [...exactResourceHosts],
      allowPublicHttpsSubresources,
    );
    const reservation = networkEvidenceRecorder.reserveRemoteRequest(parsed.hostname);
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
      const approvedAddresses = await pinnedTransport.approvePublicHost(parsed.hostname);
      if (approvedAddresses.length < 1) {
        networkEvidenceRecorder.recordBlocked(
          parsed.hostname,
          "websocket",
          "dns-not-public",
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
  } catch (error) {
    await context.close();
    throw error;
  }
  attachNavigationGuard(page);
  return {
    context,
    page,
    sealNetworkPolicyEvidence: async () => {
      validateAllMainDocumentUrls();
      await networkEvidenceRecorder.sealAndDrain({
        onSeal: () => pinnedTransport.seal(),
      });
      validateAllMainDocumentUrls();
      await context.close();
      return {
        ...networkEvidenceRecorder.snapshot(),
        pinnedTransport: pinnedTransport.snapshot(),
      };
    },
  };
}

async function auditOneTarget({
  browser,
  site,
  layout,
  profileName,
  target,
  userscriptContent,
  markerFilterContent,
  promotionCandidate,
  runtimeOnly,
  runDirectory,
  timeoutMs,
  transitionBudget,
}) {
  const runtimeExpectation = runtimeExpectationForTarget(target);
  let auditedTarget = target;
  let auditedLayout = layout;
  let relayRefreshError = null;
  if (runtimeExpectation === "relay-positive") {
    try {
      if (!transitionBudget) {
        throw new Error("relay-contract-failure: transition budget is missing");
      }
      auditedTarget = await refreshLatestTargetRelayProof(
        browser,
        site,
        profileName,
        target,
        timeoutMs,
        transitionBudget,
      );
    } catch (error) {
      relayRefreshError = error;
    }
  }
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
    requestedUrl: auditedTarget.url,
    relayDestinationUrl: auditedTarget.algumon?.verifiedResolution?.resolvedDestination ?? null,
    relayAcquisition: auditedTarget.relayAcquisition ?? null,
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

  if (relayRefreshError) {
    result.failures.push(
      `relay-positive proof refresh error: ${relayRefreshError?.stack ?? String(relayRefreshError)}`,
    );
    result.capturedAt = new Date().toISOString().replace(/\.\d{3}Z$/u, "Z");
    result.passed = false;
    return { result, candidates };
  }

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
      },
    );
    try {
    const responseObserver = observeMainDocumentResponses(staticSession.page);
    let navigation;
    let sourceSnapshot;
    let sourceClassification;
    try {
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
        runtimeExpectation === "relay-positive" &&
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
      runtimeExpectation === "relay-positive" &&
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
        const candidateProjection = await candidateOracleProjectionEvidence(
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
        result.failures.push(
          ...staticProjectionFailures(projection).map((item) => `static: ${item}`),
        );
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
    if (!staticConsistency && runtimeExpectation === "relay-positive") {
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
      result.failures.push(`article access acquisition error: ${error?.stack ?? String(error)}`);
      await captureBoundedScreenshot(
        staticSession.page,
        path.join(runDirectory, `${stem}-access-error.png`),
      ).catch(() => {});
    } finally {
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
    [
      ...new Set([
        ...navigationDomains,
        ...(auditedTarget.algumon ? ["algumon.com"] : []),
      ]),
    ],
    resourceDomainsForSite(site, Boolean(auditedTarget.algumon)),
    {
      exactResourceHosts: exactChallengeResourceHosts,
      storageState,
      allowPublicHttpsSubresources: true,
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
      runtimeExpectation === "relay-positive" &&
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
      runtimeExpectation === "relay-positive" &&
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
      runtimeExpectation === "relay-positive" &&
      (runtimeLanding.configuredPathMatchCount !== 1 || !runtimeLayout)
    ) {
      result.failures.push(
        `userscript path gate mismatch: ${new URL(navigation.finalUrl).hostname}${new URL(navigation.finalUrl).pathname}`,
      );
    }
    const requiredRoles = requiredRolesForLayout(auditedLayout);
    const markerSelectors = markerSelectorsForUrl(
      markerFilterContent,
      auditedLayout,
      navigation.finalUrl,
    );
    const gate = await auditUserscriptGate(
      auditedPage,
      requiredRoles,
      timeoutMs,
      markerSelectors,
      runtimeExpectation,
      commentControlSelectorDigestsForUrl(auditedLayout, navigation.finalUrl),
    );
    await auditedPage.waitForTimeout(100);
    await captureBoundedScreenshot(
      auditedPage,
      path.join(runDirectory, `${stem}-userscript-gated.png`),
    );
    result.userscript.gate = gate;
    if (runtimeExpectation === "relay-positive") {
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
      auditedTarget.source === "algumon-latest"
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
      runtimeExpectation === "relay-positive" &&
      runtimeCandidateExtractionAllowed &&
      result.failures.length > 0 &&
      candidates.length === 0
    ) {
      candidates = await selectorCandidates(auditedPage);
    }
    const runtimeRoleResourceEvidence = runtimeExpectation === "relay-positive"
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
      resourceDomainsForSite(site, Boolean(auditedTarget.algumon)),
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
      result.failures.push(`userscript audit error: ${error?.stack ?? String(error)}`);
    }
    if (
      runtimeExpectation === "relay-positive" &&
      runtimeCandidateExtractionAllowed !== true
    ) {
      candidates = [];
    }
    if (
      runtimeExpectation === "relay-positive" &&
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
    if (result.userscript && !result.userscript.networkPolicy) {
      const runtimeNetworkPolicy = await userscriptSession
        .sealNetworkPolicyEvidence()
        .catch(() => null);
      if (runtimeNetworkPolicy) {
        result.userscript.networkPolicy = runtimeNetworkPolicy;
        const runtimeNetworkFailures = networkFidelityFailures(
          runtimeNetworkPolicy,
          resourceDomainsForSite(site, Boolean(auditedTarget.algumon)),
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
  result.passed = result.failures.length === 0;
  return { result, candidates };
}

async function auditSyntheticNoFlashFixture(
  browser,
  userscriptContent,
  markerFilterContent,
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
<html lang="ko"><head><meta charset="utf-8"><title>${fixtureTitle}</title>
<meta property="og:title" content="${fixtureTitle}"></head>
<body><header id="noise-before-core">navigation noise</header><main id="fixture-root"></main>
<script>
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
      markerSelectorsForUrl(markerFilterContent, clienLayout, fixtureUrl),
      "relay-positive",
      commentControlSelectorDigestsForUrl(clienLayout, fixtureUrl),
    );
    result.gate = gate;
    result.failures.push(...userscriptGateFailures(gate, REQUIRED_ROLE_NAMES));
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
  const validModes = ["normal", "middle", "control", "meta", "shift", "enter"];
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
        const popupPromise = page.waitForEvent("popup", { timeout: timeoutMs });
        const [popup] = await Promise.all([popupPromise, activate(page, mode)]);
        observedPopup = popup;
        if (response) {
          if (!popup.isClosed()) {
            await popup.waitForEvent("close", { timeout: timeoutMs }).catch(() => {});
          }
          if (!popup.isClosed()) {
            fixture.failures.push("rejected relay popup remained open");
          }
          if (destinationRequestCount !== 0) {
            fixture.failures.push("rejected relay reached a destination");
          }
        } else {
          await popup.waitForURL(
            (url) => hostnameMatches(url.hostname, "clien.net"),
            { timeout: timeoutMs },
          );
          await popup.waitForFunction(() =>
            document.documentElement.getAttribute("data-hotdeal-focus-ready") === "1",
          null, { timeout: timeoutMs });
          const security = await popup.evaluate(() => ({
            openerIsNull: window.opener === null,
            referrer: document.referrer,
            name: window.name,
            fragment: location.hash,
            state: document.documentElement.getAttribute("data-hotdeal-focus-state"),
          }));
          fixture.security = security;
          if (
            !security.openerIsNull || security.referrer !== `${ALGUMON_ORIGIN}/` ||
            security.name !== "" ||
            security.fragment !== "" || security.state !== "ready"
          ) {
            fixture.failures.push("valid relay lost popup security, seed cleanup, or reader readiness");
          }
          if ((await popup.opener()) !== page) {
            fixture.failures.push("valid relay popup was not attributed to the source page");
          }
        }
      }
      if (page.url() !== discoveryUrl) {
        fixture.failures.push("Algumon source page navigated during relay handling");
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
          name: window.name,
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
  for (const attack of attacks) {
    await runCase({ id: `reject-${attack.id}`, response: attack });
  }
  await runCase({
    id: "reject-changed-signature",
    query: "v=not-a-32-hex-signature&t=1760000000000",
    inert: true,
  });
  await runCase({
    id: "reject-extra-signature-key",
    query: "v=0123456789abcdef0123456789abcdef&t=1760000000000&x=1",
    inert: true,
  });
  await runCase({ id: "reject-popup-blocked", popupBlocked: true });
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
  markerFilterContent,
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
  const clienGateRules = parseAdguardCosmeticRules(markerFilterContent).filter(
    (rule) => rule.domains.some((domain) => hostnameMatches("www.clien.net", domain)),
  );
  const clienPaintGateCss = clienGateRules
    .filter((rule) => rule.operator === "#$#")
    .map((rule) => rule.cssText)
    .join("\n");
  const clienGateCss = clienGateRules
    .flatMap((rule) => {
      if (rule.operator === "#$#") return [rule.cssText];
      if (
        rule.operator === "#?#" &&
        rule.selector.includes("data-hotdeal-focus-keep")
      ) {
        return [rule.cssText];
      }
      return [];
    })
    .join("\n");
  if (!clienPaintGateCss || !clienGateCss) {
    throw new Error("edge fixtures require parsed Clien domain gate CSS");
  }
  const fixtures = [
    {
      id: "fixed-gate-descendant-and-top-layer-zero-paint",
      fixedGateOnly: true,
      includeMarkerGate: true,
      lockedPixelProbe: true,
      headHtml: `<style data-edge-lock-attack-style>` +
        `html,html body,html body *{transition-property:opacity,visibility,clip-path!important;` +
        `transition-duration:100000s!important;transition-timing-function:linear!important}` +
        `html body,html body *{visibility:visible!important;opacity:1!important;` +
        `pointer-events:auto!important;clip-path:none!important}` +
        `#locked-fixed{position:fixed!important;inset:0!important;background:red!important}` +
        `dialog{position:fixed!important;inset:0!important;width:100vw!important;` +
        `height:100vh!important;background:lime!important}` +
        `dialog::backdrop{background:blue!important;opacity:1!important}` +
        `[popover]{position:fixed!important;inset:0!important;background:magenta!important}` +
        `</style>`,
      body: `<aside id="locked-fixed">fixed advertisement</aside>` +
        `<dialog data-edge-lock-dialog>modal advertisement</dialog>` +
        `<div popover="manual" data-edge-lock-popover>popover advertisement</div>` +
        `<div data-edge-lock-shadow-host></div>`,
      script: `document.querySelector('[data-edge-lock-dialog]').showModal();` +
        `document.querySelector('[data-edge-lock-popover]')?.showPopover?.();` +
        `const shadowHost=document.querySelector('[data-edge-lock-shadow-host]');` +
        `const shadowRoot=shadowHost.attachShadow({mode:'closed'});` +
        `shadowRoot.innerHTML='<style>dialog{position:fixed!important;inset:0!important;` +
        `width:100vw!important;height:100vh!important;background:cyan!important;` +
        `visibility:visible!important;opacity:1!important;content-visibility:visible!important;` +
        `clip-path:none!important}dialog::backdrop{background:yellow!important;` +
        `opacity:1!important;visibility:visible!important}</style><dialog>shadow modal ad</dialog>';` +
        `shadowRoot.querySelector('dialog').showModal();` +
        `document.documentElement.setAttribute('data-edge-lock-attack-active','1');`,
      checkSelectors: [],
    },
    {
      id: "preseeded-ready-spoof-relocks-zero-paint-then-ready",
      includeMarkerGate: true,
      preseedProtocolReady: true,
      lockedPixelProbe: true,
      headHtml: `<style data-edge-lock-attack-style>` +
        `html,html body,html body *{transition-property:opacity,visibility,clip-path!important;` +
        `transition-duration:100000s!important;transition-timing-function:linear!important}` +
        `html body,html body *{visibility:visible!important;opacity:1!important;` +
        `pointer-events:auto!important;clip-path:none!important}` +
        `#locked-fixed{position:fixed!important;inset:0!important;background:red!important}` +
        `dialog{position:fixed!important;inset:0!important;width:100vw!important;` +
        `height:100vh!important;background:lime!important}` +
        `dialog::backdrop{background:blue!important;opacity:1!important}` +
        `[popover]{position:fixed!important;inset:0!important;background:magenta!important}` +
        `</style>`,
      body: `<aside id="locked-fixed">fixed advertisement</aside>` +
        `<dialog data-edge-lock-dialog>modal advertisement</dialog>` +
        `<div popover="manual" data-edge-lock-popover>popover advertisement</div>` +
        `<div data-edge-lock-shadow-host></div>` +
        `<div data-edge-delayed-approved style="display:none!important">` +
        `<article class="post_article" data-edge="post-lock-body"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment">` +
        `<div class="comment_row" data-edge="post-lock-comment">comment</div>` +
        `</div></div></div>`,
      script: `document.querySelector('[data-edge-lock-dialog]').showModal();` +
        `document.querySelector('[data-edge-lock-popover]')?.showPopover?.();` +
        `const shadowHost=document.querySelector('[data-edge-lock-shadow-host]');` +
        `const shadowRoot=shadowHost.attachShadow({mode:'closed'});` +
        `shadowRoot.innerHTML='<style>dialog{position:fixed!important;inset:0!important;` +
        `width:100vw!important;height:100vh!important;background:cyan!important;` +
        `visibility:visible!important;opacity:1!important;content-visibility:visible!important;` +
        `clip-path:none!important}dialog::backdrop{background:yellow!important;` +
        `opacity:1!important;visibility:visible!important}</style><dialog>shadow modal ad</dialog>';` +
        `shadowRoot.querySelector('dialog').showModal();` +
        `document.documentElement.setAttribute('data-edge-lock-attack-active','1');` +
        `window.setTimeout(() => {` +
        `document.querySelector('[data-edge-lock-dialog]')?.close();` +
        `document.querySelector('[data-edge-lock-dialog]')?.remove();` +
        `document.querySelector('[data-edge-lock-popover]')?.hidePopover?.();` +
        `document.querySelector('[data-edge-lock-popover]')?.remove();` +
        `shadowHost.remove();` +
        `document.querySelector('#locked-fixed')?.remove();` +
        `document.querySelector('[data-edge-lock-attack-style]')?.remove();` +
        `document.querySelector('[data-edge-delayed-approved]')?.removeAttribute('style');` +
        `document.documentElement.setAttribute('data-edge-lock-attack-released','1');` +
        `}, 800);`,
      checkSelectors: ["[data-edge='post-lock-body']", "[data-edge='post-lock-comment']"],
    },
    {
      id: "empty-comments",
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"></div>`,
      checkSelectors: [],
    },
    {
      id: "pre-ready-content-visibility-tamper-is-terminal",
      expectFailClosed: true,
      expectedStatusPrefix:
        "terminal-bootstrap-inline-lock-tamper-content-visibility",
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment">` +
        `<div class="comment_row">comment</div></div></div>`,
      script: `document.documentElement.style.setProperty(` +
        `'content-visibility','visible','important');`,
      checkSelectors: [],
    },
    {
      id: "unauthorized-measurement-marker-is-terminal",
      expectFailClosed: true,
      expectedStatusPrefix: "terminal-protocol-marker-tamper",
      headHtml: `<style>` +
        `html[data-hotdeal-focus-measure="1"]{visibility:visible!important;` +
        `content-visibility:visible!important;opacity:1!important;` +
        `clip-path:none!important}</style>`,
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment">` +
        `<div class="comment_row">comment</div></div></div>`,
      script: `document.documentElement.setAttribute(` +
        `'data-hotdeal-focus-measure','1');`,
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
      expectFailClosed: true,
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
      expectFailClosed: true,
      expectedStatusPrefix: "terminal-cascade-visible-leak",
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
      expectFailClosed: true,
      expectedStatusPrefix: "terminal-cascade-visible-leak",
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
      expectFailClosed: true,
      expectedStatusPrefix: "terminal-cascade-visible-leak",
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
      expectFailClosed: true,
      expectedStatusPrefix: "terminal-role-projection-atomic-addition",
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
      expectFailClosed: true,
      expectedStatusPrefix: "terminal-protocol-marker-tamper",
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
      expectNavigationTerminal: true,
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment"><div class="comment_row">comment</div></div></div>`,
      script: `window.setTimeout(() => {
        history.pushState({}, '', '/service/board/jirum/99999998');
        document.documentElement.setAttribute('data-edge-spa-mismatch', 'attempted');
        window.setTimeout(() => {
          history.back();
          document.documentElement.setAttribute('data-edge-spa-back', 'attempted');
        }, 150);
      }, 300);`,
      checkSelectors: [],
    },
    {
      id: "spa-same-number-different-board-is-terminal",
      expectFailClosed: true,
      expectedStatusPrefix: "terminal-navigation-identity",
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
      expectFailClosed: true,
      expectedStatusPrefix: "terminal-protocol-marker-tamper",
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
      id: "runtime-cssom-insert-rule-is-terminal",
      expectFailClosed: true,
      expectedStatusPrefix: "terminal-runtime-style-tamper",
      body: `<article class="post_article"><p>${longBody}</p></article>` +
        `<div class="post_comment"><div class="comment"><div class="comment_row">comment</div></div></div>`,
      script: `const attack = window.setInterval(() => {
        if (document.documentElement.getAttribute('data-hotdeal-focus-ready') !== '1') return;
        window.clearInterval(attack);
        const style = document.querySelector('style[data-hotdeal-focus-runtime-style]');
        style.sheet.insertRule('html{outline:0!important}', style.sheet.cssRules.length);
      }, 25);`,
      checkSelectors: [],
    },
    {
      id: "terminal-guardian-rejects-ready-and-marker-forgery",
      expectFailClosed: true,
      expectedStatusPrefix: "terminal-protocol-marker-tamper",
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
      fixture.oracleOnly || fixture.fixedGateOnly ? null : userscriptContent,
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
      const blankPaint = fixture.lockedPixelProbe
        ? await session.page.screenshot({ animations: "disabled" })
        : null;
      await session.page.route(fixtureUrl, async (route) => {
        const protocolSpoof = fixture.preseedProtocolReady
          ? ` data-hotdeal-focus-ready="1" data-hotdeal-focus-protocol="1" ` +
            `data-hotdeal-focus-state="ready" data-hotdeal-focus-status="ready"`
          : "";
        await route.fulfill({
          status: 200,
          contentType: "text/html; charset=utf-8",
          body: `<!doctype html><html lang="ko"${protocolSpoof}><head><meta charset="utf-8">` +
            `<title>${title}</title><meta property="og:title" content="${title}">` +
            (fixture.headHtml ?? "") +
            (fixture.includeMarkerGate
              ? `<style data-edge-marker-gate>${clienPaintGateCss}</style>`
              : "") + `</head>` +
            `<body${fixture.bodyAttributes ?? ""}>` +
            `<header data-edge-noise="initial">outside navigation noise</header>` +
            `<section class="content_view"><h1 class="post_subject">${title}</h1>` +
            fixture.body +
            `</section><aside data-edge-noise="delayed">delayed advertisement noise</aside>` +
            `<script>${fixture.script ?? ""}</script></body></html>`,
        });
      });
      const fixtureNavigationUrl = fixture.fixedGateOnly
        ? fixtureUrl
        : seededNavigationUrl(fixtureUrl, "clien", title, 99999000 + index);
      if (fixture.lockedPixelProbe) {
        const navigationProof = seededNavigationProof(fixtureNavigationUrl);
        if (navigationProof) {
          await session.page.goto("about:blank", {
            waitUntil: "commit",
            timeout: timeoutMs,
          });
          await session.page.evaluate((name) => {
            window.name = name;
          }, `hdf-provenance:${navigationProof.navigationNonce}`);
        }
        await session.page.goto(fixtureNavigationUrl, {
          waitUntil: "domcontentloaded",
          timeout: timeoutMs,
          ...(navigationProof ? { referer: ALGUMON_GLOBAL_DISCOVERY_URL } : {}),
        });
      } else {
        await navigate(session.page, fixtureNavigationUrl, timeoutMs);
      }
      if (fixture.lockedPixelProbe) {
        await session.page.waitForFunction(
          () => document.documentElement.getAttribute("data-edge-lock-attack-active") === "1",
          null,
          { timeout: timeoutMs },
        );
        await session.page.waitForTimeout(50);
        const lockedPaint = await session.page.screenshot({ animations: "disabled" });
        const lockedState = await evaluateInIsolatedWorld(session.page, () => {
          const html = document.documentElement;
          const rootStyle = getComputedStyle(html);
          const dialog = document.querySelector("[data-edge-lock-dialog]");
          const dialogStyle = dialog ? getComputedStyle(dialog) : null;
          return {
            runtimeLock: html.getAttribute("data-hotdeal-focus-lock"),
            ready: html.getAttribute("data-hotdeal-focus-ready"),
            state: html.getAttribute("data-hotdeal-focus-state"),
            rootTransitionProperty: rootStyle.transitionProperty,
            rootAnimationName: rootStyle.animationName,
            rootContentVisibility: rootStyle.contentVisibility,
            rootVisibility: rootStyle.visibility,
            rootOpacity: rootStyle.opacity,
            rootPointerEvents: rootStyle.pointerEvents,
            rootClipPath: rootStyle.clipPath,
            dialogOpen: Boolean(dialog?.open),
            dialogDisplay: dialogStyle?.display ?? null,
            dialogTransitionProperty: dialogStyle?.transitionProperty ?? null,
            dialogAnimationName: dialogStyle?.animationName ?? null,
            dialogContentVisibility: dialogStyle?.contentVisibility ?? null,
            dialogVisibility: dialogStyle?.visibility ?? null,
            dialogOpacity: dialogStyle?.opacity ?? null,
            dialogPointerEvents: dialogStyle?.pointerEvents ?? null,
            dialogClipPath: dialogStyle?.clipPath ?? null,
          };
        });
        fixtureResult.lockedPaint = {
          blankPixelMatch: lockedPaint.equals(blankPaint),
          ...lockedState,
        };
        if (!fixtureResult.lockedPaint.blankPixelMatch) {
          fixtureResult.failures.push(
            `locked descendant or top-layer content painted: ` +
              `${JSON.stringify(fixtureResult.lockedPaint)}`,
          );
        }
        if (
          lockedState.rootTransitionProperty !== "none" ||
          lockedState.rootAnimationName !== "none" ||
          lockedState.rootVisibility !== "hidden" ||
          lockedState.rootContentVisibility !== "hidden" ||
          Number(lockedState.rootOpacity) !== 0 ||
          lockedState.rootClipPath !== "inset(50%)" ||
          lockedState.rootPointerEvents !== "none" ||
          lockedState.dialogOpen !== true ||
          lockedState.dialogDisplay !== "none" ||
          lockedState.dialogTransitionProperty !== "none" ||
          lockedState.dialogAnimationName !== "none" ||
          lockedState.dialogVisibility !== "hidden" ||
          Number(lockedState.dialogOpacity) !== 0 ||
          lockedState.dialogPointerEvents !== "none" ||
          (!fixture.fixedGateOnly && lockedState.runtimeLock !== "1")
        ) {
          fixtureResult.failures.push(
            `paint lock did not cover the root and top layer: ${JSON.stringify(lockedState)}`,
          );
        }
      }
      if (fixture.fixedGateOnly) {
        await captureBoundedScreenshot(
          session.page,
          path.join(runDirectory, `synthetic-${fixture.id}.png`),
        );
        fixtureResult.passed = fixtureResult.failures.length === 0;
        result.fixtures.push(fixtureResult);
        continue;
      }
      if (fixture.lockedPixelProbe) {
        await session.page.waitForFunction(
          () =>
            document.documentElement.getAttribute("data-edge-lock-attack-released") === "1" &&
            document.documentElement.getAttribute("data-hotdeal-focus-ready") === "1",
          null,
          { timeout: timeoutMs },
        );
        await session.page.waitForTimeout(100);
      } else {
        await session.page.waitForTimeout(900);
      }
      if (!fixture.tamper && !fixture.expectFailClosed && !fixture.expectNavigationTerminal) {
        const gate = await auditUserscriptGate(
          session.page,
          REQUIRED_ROLE_NAMES,
          timeoutMs,
          markerSelectorsForUrl(markerFilterContent, clienLayout, fixtureUrl),
          "relay-positive",
          commentControlSelectorDigestsForUrl(clienLayout, fixtureUrl),
        );
        fixtureResult.gate = gate;
        fixtureResult.failures.push(
          ...userscriptGateFailures(gate, REQUIRED_ROLE_NAMES),
        );
      }
      const paintFlashCount = await session.page.evaluate(() =>
        window.__HOTDEAL_FOCUS_PAINT_PROBE__?.flashFrameCount ?? 1);
      const edgeState = await evaluateInIsolatedWorld(session.page, ({
        visibleSelectors,
        hiddenSelectors,
        observedPaintFlashCount,
      }) => {
        const visible = (element) => {
          const style = getComputedStyle(element);
          return style.display !== "none" && style.visibility !== "hidden" &&
            Number(style.opacity) !== 0 &&
            [...element.getClientRects()].some((rect) => rect.width > 0 && rect.height > 0);
        };
        const html = document.documentElement;
        const ready = html.getAttribute("data-hotdeal-focus-ready") === "1" &&
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
        const paintFlashCount = observedPaintFlashCount;
        const rootStyle = getComputedStyle(html);
        const failClosed =
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
          html.style.getPropertyPriority("content-visibility") === "important" &&
          !html.hasAttribute("data-hotdeal-focus-measure") &&
          paintFlashCount === 0;
        return {
          ready,
          failClosed,
          selected,
          hidden,
          visibleNoiseCount,
          paintFlashCount,
          status: html.getAttribute("data-hotdeal-focus-status"),
          measurementMarker: html.getAttribute("data-hotdeal-focus-measure"),
          path: location.pathname,
          backAttempted: html.getAttribute("data-edge-spa-back") === "attempted",
          bodyBackgroundColor: getComputedStyle(document.body).backgroundColor,
          bodyColor: getComputedStyle(document.body).color,
        };
      }, {
        visibleSelectors: fixture.checkSelectors,
        hiddenSelectors: fixture.hiddenSelectors ?? [],
        observedPaintFlashCount: paintFlashCount,
      });
      fixtureResult.edgeState = edgeState;
      if (fixture.expectNavigationTerminal) {
        if (
          !edgeState.failClosed ||
          edgeState.status !== "terminal-navigation-identity" ||
          !edgeState.backAttempted ||
          edgeState.path === "/service/board/jirum/99999998"
        ) {
          fixtureResult.failures.push(
            `article identity mismatch was not terminal after history.back(): ` +
            `${JSON.stringify(edgeState)}`,
          );
        }
      } else if (fixture.expectFailClosed) {
        if (!edgeState.failClosed) {
          fixtureResult.failures.push("unclassified comment content did not fail closed");
        }
        if (
          fixture.expectedStatusPrefix &&
          !String(edgeState.status ?? "").startsWith(fixture.expectedStatusPrefix)
        ) {
          fixtureResult.failures.push(
            `terminal status was ${edgeState.status ?? "missing"}`,
          );
        }
      } else if (fixture.tamper) {
        const tamperAttempted = edgeState.selected.some(
          (selected) => selected.selector.includes("data-edge-tamper") && selected.exists,
        );
        const safelyRecovered =
          (edgeState.ready && edgeState.visibleNoiseCount === 0) || edgeState.failClosed;
        if (!tamperAttempted || !safelyRecovered) {
          fixtureResult.failures.push("marker/style tamper neither recovered nor failed closed");
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
      id: "path-only-drift-seeded-exact-remains-blank",
      seed: true,
      expectedState: "blocked",
      expectedStatus: "terminal-algumon-seed-required",
      body: pathDriftBody,
    },
    {
      id: "ordinary-unknown-path-remains-blank",
      seed: false,
      expectedState: "blocked",
      body: pathDriftBody,
    },
    {
      id: "cross-site-seed-destination-mismatch-is-terminal",
      seed: true,
      seedSiteType: "ppomppu",
      expectedState: "blocked",
      expectedStatus: "terminal-algumon-seed-required",
      body: pathDriftBody,
    },
    {
      id: "null-article-identity-is-terminal",
      seed: true,
      requestPath: "/fresh-hotdeal/no-article-token",
      expectedState: "blocked",
      expectedStatus: "terminal-algumon-seed-required",
      body: pathDriftBody,
    },
    {
      id: "path-drift-seeded-dom-drift-remains-blank",
      seed: true,
      expectedState: "blocked",
      body:
        `<main class="drift-shell"><h1 class="drift-title">${pathDriftTitle}</h1>` +
        `<article class="drift-body"><p>${longBody}</p></article>` +
        `<section class="drift-comments"><div class="drift-comment">comment</div></section></main>`,
    },
    {
      id: "forged-direct-fragment-and-window-name-is-terminal",
      seed: true,
      forgedDirectNavigation: true,
      requestPath: "/service/board/jirum/990099",
      expectedState: "blocked",
      expectedStatus: "terminal-algumon-seed-required",
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
      await session.context.addInitScript({
        content: `(() => {
          const css = ${JSON.stringify(clienGateCss)};
          const apply = () => {
            if (!document.documentElement) return false;
            const style = document.createElement("style");
            style.id = "hotdeal-audit-adguard-domain-gate";
            style.textContent = css;
            document.documentElement.append(style);
            return true;
          };
          if (!apply()) {
            const observer = new MutationObserver(() => {
              if (apply()) observer.disconnect();
            });
            observer.observe(document, { childList: true, subtree: true });
          }
        })();`,
      });
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
          `</body></html>`,
      }));
      if (fixture.forgedDirectNavigation) {
        const proof = seededNavigationProof(navigationUrl);
        await session.page.evaluate((name) => {
          window.name = name;
        }, `hdf-provenance:${proof.navigationNonce}`);
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
        return {
          ready:
            html.getAttribute("data-hotdeal-focus-ready") === "1" &&
            html.getAttribute("data-hotdeal-focus-state") === "ready",
          state: html.getAttribute("data-hotdeal-focus-state"),
          status: html.getAttribute("data-hotdeal-focus-status"),
          htmlVisibility: getComputedStyle(html).visibility,
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
          fragmentCleared: !location.hash.includes("hdf-seed="),
          paintFlashCount:
            window.__HOTDEAL_FOCUS_PAINT_PROBE__?.flashFrameCount ?? 1,
        };
      });
      fixtureResult.state = state;
      if (fixture.expectedState === "ready") {
        if (!state.ready || state.state !== "ready") {
          fixtureResult.failures.push(`seeded exact DOM did not become ready (${state.state})`);
        }
        for (const [role, metrics] of Object.entries(state.roles)) {
          if (metrics.count !== 1 || metrics.visibleCount !== 1 || !metrics.allKept) {
            fixtureResult.failures.push(`${role} was not preserved exactly once`);
          }
        }
        if (
          state.commentItems.count !== 1 ||
          state.commentItems.visibleCount !== 1 ||
          !state.commentItems.allKept
        ) {
          fixtureResult.failures.push("comment item was not preserved exactly once");
        }
        if (state.visibleNoiseCount !== 0 || state.visibleUnkeptCount !== 0) {
          fixtureResult.failures.push("seeded path probe exposed outside noise");
        }
      } else {
        if (state.ready || state.state !== fixture.expectedState) {
          fixtureResult.failures.push(
            `fail-closed path probe state was ${state.state ?? "missing"}`,
          );
        }
        if (state.htmlVisibility !== "hidden" || state.visibleElementCount !== 0) {
          fixtureResult.failures.push("unknown/drifted path was not completely blank");
        }
        if (fixture.expectedStatus && state.status !== fixture.expectedStatus) {
          fixtureResult.failures.push(
            `terminal path status was ${state.status ?? "missing"}`,
          );
        }
      }
      if (!state.fragmentCleared) {
        fixtureResult.failures.push("public Algumon seed fragment was not cleared");
      }
      if (state.paintFlashCount !== 0) {
        fixtureResult.failures.push(
          `path-drift gate exposed ${state.paintFlashCount} pre-ready frames`,
        );
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
        title: { mode: "seeded-shallow" },
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
        title: { mode: "seeded-shallow" },
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
      title: { mode: "seeded-shallow" },
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
        `comment</div></div></main><script>window.setTimeout(() => {` +
        `const widget = document.createElement('aside');` +
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
      const html = document.documentElement;
      return {
        ready: html.getAttribute("data-hotdeal-focus-ready") === "1",
        state: html.getAttribute("data-hotdeal-focus-state"),
        status: html.getAttribute("data-hotdeal-focus-status"),
        visibility: getComputedStyle(html).visibility,
        paintFlashCount: window.__HOTDEAL_FOCUS_PAINT_PROBE__?.flashFrameCount ?? 1,
      };
    });
    productMutationFixture.state = state;
    if (
      state.ready ||
      state.state !== "blocked" ||
      state.status !== "terminal-role-projection-atomic-addition" ||
      state.visibility !== "hidden" ||
      state.paintFlashCount !== 0
    ) {
      productMutationFixture.failures.push(
        `product injection did not terminally fail closed: ${JSON.stringify(state)}`,
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
      const vintages = new Set(
        fixtures
          .filter(
            (fixture) =>
              fixture.site_id === site.id && fixture.layout_id === layout.id,
          )
          .map((fixture) => fixture.vintage),
      );
      for (const vintage of ["june", "july"]) {
        if (!vintages.has(vintage)) {
          failures.push(`${site.id}/${layout.id}: missing ${vintage} regression fixture`);
        }
      }
    }
  }
  return failures;
}

async function runRegressionFixtures(
  browser,
  userscriptContent,
  markerFilterContent,
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
        markerSelectorsForUrl(markerFilterContent, layout, fixture.url),
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
  const dealMatch = url.pathname.match(/^\/l\/d\/(\d{1,24})$/u);
  const queryKeys = [...url.searchParams.keys()];
  if (
    url.protocol !== "https:" ||
    url.hostname !== "www.algumon.com" ||
    url.username ||
    url.password ||
    url.port ||
    url.hash ||
    !dealMatch ||
    (expectedDealId && dealMatch[1] !== String(expectedDealId)) ||
    queryKeys.length !== 2 ||
    queryKeys[0] !== "v" ||
    queryKeys[1] !== "t" ||
    url.searchParams.getAll("v").length !== 1 ||
    url.searchParams.getAll("t").length !== 1 ||
    !/^[0-9a-f]{32}$/u.test(url.searchParams.get("v") || "") ||
    !/^\d{13}$/u.test(url.searchParams.get("t") || "")
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

function classifyAlgumonSourceResponse(responseEvidence) {
  const status = responseEvidence?.status;
  const body = normalizeAlgumonSourceLabel(
    `${responseEvidence?.title ?? ""}\n${responseEvidence?.bodyText ?? ""}`,
  );
  let exactUrl = false;
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
  if (!expectedSiteId) {
    const expectedLabels = new Set(ALGUMON_SOURCE_CONTRACTS.map((source) => source.label));
    const dropdowns = (snapshot?.dropdowns ?? []).map((labels) =>
      labels.map(normalizeAlgumonSourceLabel).filter(Boolean),
    );
    const candidates = dropdowns.filter((labels) =>
      labels.some((label) => expectedLabels.has(label)),
    );
    if (candidates.length !== 1) {
      failures.push("source-dropdown-cardinality");
    } else {
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

async function navigateAlgumonSourcePage(page, requestedUrl, timeoutMs) {
  let response;
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
      contentType: "",
      title: await page.title().catch(() => ""),
      bodyText: await page.locator("body").innerText().catch(() => ""),
      navigationError: error?.message ?? String(error),
    };
  }
  await page.waitForTimeout(350);
  return {
    requestedUrl,
    finalUrl: page.url(),
    status: response?.status() ?? null,
    contentType: response?.headers()?.["content-type"] ?? "",
    title: await page.title().catch(() => ""),
    bodyText: (await page.locator("body").innerText().catch(() => "")).slice(0, 4_096),
  };
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
    const cards = [...document.querySelectorAll(".deal-feed-card[id^='deal-']")].map((card) => {
      const relayAnchors = [...card.querySelectorAll('a[href*="/l/d/"]')];
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
          card.querySelector('h3 a[href*="/l/d/"]')?.textContent ||
            card.querySelector("h3")?.textContent ||
            "",
        ),
        iconUrls: iconImages.map((image) => image.src),
        sourceLabels: iconImages.map((image) => cleanText(image.closest("span")?.textContent)),
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

async function collectAlgumonGlobalInventory(browser, timeoutMs) {
  const { context, page } = await createPageContext(
    browser,
    "desktop",
    null,
    ["algumon.com"],
    ["algumon.com"],
  );
  try {
    const response = await navigateAlgumonSourcePage(
      page,
      ALGUMON_GLOBAL_DISCOVERY_URL,
      timeoutMs,
    );
    const result = classifyAlgumonInventorySnapshot(
      await snapshotAlgumonInventoryPage(page, response),
    );
    return {
      discoveryUrl: ALGUMON_GLOBAL_DISCOVERY_URL,
      ...result,
    };
  } catch (error) {
    return {
      discoveryUrl: ALGUMON_GLOBAL_DISCOVERY_URL,
      status: "source-or-infrastructure-failure",
      failures: [error?.message ?? String(error)],
      links: [],
      observedSiteTypes: [],
    };
  } finally {
    await context.close();
  }
}

async function collectAlgumonRedirectLinks(browser, site, timeoutMs) {
  const source = site.algumon_source ?? site.id.toUpperCase();
  const discoveryUrl = `${ALGUMON_ORIGIN}/n/deal?sites=${encodeURIComponent(source)}`;
  const { context, page } = await createPageContext(
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
  );
  try {
    const response = await navigateAlgumonSourcePage(page, discoveryUrl, timeoutMs);
    const result = classifyAlgumonInventorySnapshot(
      await snapshotAlgumonInventoryPage(page, response),
      site.id,
    );
    return {
      discoveryUrl,
      ...result,
      siteTypeFailures: result.failures
        .filter((failure) => failure.includes("source-identity"))
        .map((failure) => ({ status: failure })),
    };
  } finally {
    await context.close();
  }
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

function createAlgumonRelayResolver(context, parserPage, timeoutMs, transitionBudget) {
  const responseCache = new Map();
  return async function resolveAlgumonRedirect(site, redirectUrl) {
    const signedUrl = exactSignedAlgumonDealUrl(redirectUrl);
    if (!signedUrl) {
      throw new Error("relay-contract-failure: unsigned or malformed Algumon URL");
    }
    let responsePromise = responseCache.get(signedUrl.href);
    if (!responsePromise) {
      transitionBudget.actual.signedRelayFetches += 1;
      responsePromise = context.request.get(signedUrl.href, {
        failOnStatusCode: false,
        maxRedirects: 0,
        timeout: timeoutMs,
        headers: { "cache-control": "no-store", pragma: "no-cache" },
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
  browser,
  site,
  profileName,
  target,
  timeoutMs,
  transitionBudget,
) {
  if (target?.source !== "algumon-latest" || !target.algumon?.dealId) {
    throw new Error("relay-contract-failure: only an Algumon latest target can be refreshed");
  }
  transitionBudget.actual.justInTimeRelayAcquisitions += 1;
  const discovery = await collectAlgumonRedirectLinks(browser, site, timeoutMs);
  if (discovery.status !== "ok") {
    const error = new Error(
      `source-or-infrastructure-failure: just-in-time Algumon acquisition failed (${discovery.status})`,
    );
    error.failureKind = "source-or-infrastructure-failure";
    throw error;
  }
  const exactCards = discovery.links.filter(
    (card) =>
      card.dealId === String(target.algumon.dealId) &&
      card.siteType === site.id,
  );
  if (exactCards.length !== 1) {
    throw new Error(
      "relay-contract-failure: just-in-time Algumon page did not contain one exact deal identity",
    );
  }
  const freshCard = exactCards[0];
  const acquisition = signedRelayAcquisitionEvidence(
    freshCard.href,
    target.algumon.dealId,
  );
  const relaySession = await createPageContext(
    browser,
    profileName,
    null,
    ["algumon.com"],
    ["algumon.com"],
  );
  try {
    transitionBudget.actual.justInTimeSignedRelayFetches += 1;
    const resolveAlgumonRedirect = createAlgumonRelayResolver(
      relaySession.context,
      relaySession.page,
      timeoutMs,
      transitionBudget,
    );
    const resolution = await resolveAlgumonRedirect(site, acquisition.signedUrl);
    if (resolution.relayFetchUrl !== acquisition.signedUrl) {
      throw new Error("relay-contract-failure: refreshed relay resolution changed the exact signed URL");
    }
    return {
      ...target,
      url: resolution.resolvedDestination,
      relayAcquisition: acquisition,
      algumon: {
        discoveryUrl: discovery.discoveryUrl,
        redirectUrl: acquisition.signedUrl,
        dealId: freshCard.dealId,
        siteId: site.id,
        title: freshCard.title,
        commentCount: freshCard.commentCount,
        verifiedResolution: resolution,
      },
    };
  } finally {
    await relaySession.context.close();
  }
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
) {
  const targets = [];
  const records = [];
  const transitionBudget = {
    policy: {
      globalInventoryNavigations: 1,
      siteDiscoveryNavigationsPerSite: 1,
      signedRelayFetchesPerSite: ALGUMON_SITE_LINK_SCAN_LIMIT,
      justInTimeRelayAcquisitionsPerTarget: 1,
      justInTimeSignedRelayFetchesPerTarget: 1,
      proofUrlsPerRouteProfile: ALGUMON_PROOF_REPRESENTATIVES_PER_ROUTE_PROFILE,
    },
    maximum: {
      globalInventoryNavigations: 1,
      siteDiscoveryNavigations: sites.length,
      signedRelayFetches: sites.length * ALGUMON_SITE_LINK_SCAN_LIMIT,
      justInTimeRelayAcquisitions: 0,
      justInTimeSignedRelayFetches: 0,
    },
    actual: {
      globalInventoryNavigations: 1,
      siteDiscoveryNavigations: 0,
      signedRelayFetches: 0,
      justInTimeRelayAcquisitions: 0,
      justInTimeSignedRelayFetches: 0,
      routeProfileProofTargets: 0,
      destinationAuditNavigationStartsMaximum: 0,
      totalNetworkStartsMaximum: 1,
    },
  };
  const inventory = await collectAlgumonGlobalInventory(browser, timeoutMs);
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
  );
  let terminalSourceFailure = false;
  try {
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
        transitionBudget.actual.siteDiscoveryNavigations += 1;
        const discovery = await collectAlgumonRedirectLinks(browser, site, timeoutMs);
        record.discoveryUrl = discovery.discoveryUrl;
        record.status = discovery.status;
        record.linkCount = discovery.links.length;
        record.observedSiteTypes = discovery.observedSiteTypes;
        record.siteTypeFailures = discovery.siteTypeFailures;
        record.inventoryFailures = discovery.failures;
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
  transitionBudget.maximum.justInTimeRelayAcquisitions = targets.length;
  transitionBudget.maximum.justInTimeSignedRelayFetches = targets.length;
  transitionBudget.maximum.signedRelayFetches += targets.length;
  transitionBudget.actual.destinationAuditNavigationStartsMaximum = targets.length * 2;
  transitionBudget.actual.totalNetworkStartsMaximum =
    transitionBudget.actual.globalInventoryNavigations +
    transitionBudget.actual.siteDiscoveryNavigations +
    transitionBudget.actual.signedRelayFetches +
    transitionBudget.actual.destinationAuditNavigationStartsMaximum;
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
              runtimeExpectation: "direct-negative",
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
      gate.state === "blocked" &&
      gate.blockedStateSafety?.passed === true &&
      gate.paintProbe?.flashFrameCount === 0,
    );
  }
  const commentItemsProjected = Boolean(
    gate?.commentItemStats &&
    gate.commentItemStats.allKept === true &&
    gate.commentItemStats.visibleCount === gate.commentItemStats.count,
  );
  const commentControlsProjected = Boolean(
    commentControlProjectionFailures(gate).length === 0,
  );
  return Boolean(
    gate.readyMarkerCoverage?.passed === true &&
    gate.uncoveredUnmarkedCount === 0 &&
    gate.visibleWithoutKeepCount === 0 &&
    gate.directVisibleTextLeakCount === 0 &&
    gate.coveredKeptCount === 0 &&
    gate.paintProbe?.flashFrameCount === 0 &&
    commentItemsProjected &&
    commentControlsProjected,
  );
}

function resultIsSafelyReadableOrClosed(result) {
  const gate = result.userscript?.gate;
  if (!resultHasZeroLeak(result)) return false;
  const staticOnlyFailure = (result.failures ?? []).every((failure) =>
    failure.startsWith("static"),
  );
  const safelyReadable = gate.ready === true && staticOnlyFailure;
  const safelyClosed = gate.ready === false && gate.state === "blocked";
  return safelyReadable || safelyClosed;
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
            result.source === "algumon-latest" &&
            result.passed === true,
        )
        .map((result) => result.requestedUrl),
    );
    if (distinctCandidateProofs.size < 3) {
      failures.push(
        `promotion-retest ${scope.candidateLayoutId}/${profile}: ` +
          `${distinctCandidateProofs.size}/3 distinct Algumon proofs passed`,
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
      results.some((result) => !resultIsSafelyReadableOrClosed(result))
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
    if (canonicalJson(observedLabels) !== canonicalJson(expectedLabels)) {
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
    failures.push("Algumon latest audit lacks just-in-time relay or profile landing evidence");
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

function semanticVersionTuple(version) {
  const match = String(version ?? "").match(/^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/u);
  if (!match) throw new Error(`invalid semantic version: ${version}`);
  return match.slice(1).map(Number);
}

function compareSemanticVersions(left, right) {
  const leftParts = semanticVersionTuple(left);
  const rightParts = semanticVersionTuple(right);
  for (let index = 0; index < 3; index += 1) {
    if (leftParts[index] !== rightParts[index]) {
      return leftParts[index] - rightParts[index];
    }
  }
  return 0;
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
  const [major, minor, patchVersion] = semanticVersionTuple(latest);
  return `${major}.${minor}.${patchVersion + 1}`;
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
    result.source === "algumon-latest" &&
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
        title: { mode: "seeded-shallow" },
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
      group.proofProfiles = profilesForLayout(site, layout).filter(
        (profile) =>
          selectPromotionProofResults(
            group.results.filter((result) => result.profile === profile),
            "unconstrained",
          ).length === 3,
      );
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
      return group.proofProfiles.length > 0 && group.selectedResults.length >= 3;
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
    Number(gate?.uncoveredUnmarkedCount ?? 1),
    Number(gate?.paintProbe?.flashFrameCount ?? 1),
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
        result.source === "algumon-latest" &&
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
  const promotionScope = options.promotionScopePath
    ? buildPromotionRetestScope(
        config,
        await readJson(options.promotionScopePath),
        await readJson(options.baselineReportPath),
      )
    : null;
  const sites = promotionScope
    ? sitesForPromotionRetest(config, promotionScope)
    : selectedSites(config, options.siteIds);
  const integrity = await buildIntegrityManifest(config, options.evidencePath, {
    bundleRoot: path.dirname(options.markerFilterPath),
    draftManifest,
  });
  if (options.integrityOnly) {
    process.stdout.write(
      `${integrity.passed ? "PASS" : "FAIL"} integrity: ` +
        `${integrity.config.siteCount} sites, ${integrity.config.layoutCount} layouts\n`,
    );
    return integrity.passed ? 0 : 1;
  }

  const userscriptContent = await fs.readFile(options.userscriptPath, "utf8");
  const markerFilterContent = await fs.readFile(options.markerFilterPath, "utf8");
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
    discovery: { enabled: options.discoverAlgumon, required: options.requireAlgumonDiscovery },
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
          markerFilterContent,
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
          markerFilterContent,
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
          markerFilterContent,
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
    let targets = options.fixtureOnly ? [] : sampleTargets(liveSites);
    let discovery = null;
    if (!options.fixtureOnly && options.discoverAlgumon) {
      discovery = await discoverLatestTargets(
        browser,
        liveSites,
        options.timeoutMs,
        promotionDraft?.candidate ?? null,
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
        markerFilterContent,
        promotionCandidate: promotionDraft?.candidate ?? null,
        runtimeOnly: options.runtimeOnly,
        runDirectory,
        timeoutMs: options.timeoutMs,
        transitionBudget: discovery?.transitionBudget ?? null,
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
      transitionActual.totalNetworkStartsMaximum =
        transitionActual.globalInventoryNavigations +
        transitionActual.siteDiscoveryNavigations +
        transitionActual.justInTimeRelayAcquisitions +
        transitionActual.signedRelayFetches +
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
    relayPositiveCount: report.results.filter(
      (result) => result.runtimeExpectation === "relay-positive",
    ).length,
    relayPositivePassedCount: report.results.filter(
      (result) =>
        result.runtimeExpectation === "relay-positive" && result.passed === true,
    ).length,
    blockedSafetyPassedCount: report.results.filter(
      (result) =>
        result.runtimeExpectation === "direct-negative" &&
        result.userscript?.gate?.blockedStateSafety?.passed === true,
    ).length,
    readyMarkerCoveragePassedCount: report.results.filter(
      (result) =>
        result.runtimeExpectation === "relay-positive" &&
        result.userscript?.gate?.readyMarkerCoverage?.passed === true,
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
  acquireArticleAccessLease,
  approvedPathsForLayout,
  articleIdentitiesLogicallyEquivalent,
  assertAuditConfig,
  blockedUserscriptGateFailures,
  buildProjectedHideSelector,
  candidateGenerationAllowed,
  canonicalArticleIdentity,
  classifyAlgumonInventorySnapshot,
  classifyAlgumonSourceResponse,
  classifyDestinationResponse,
  classifyProfileLandingRoute,
  commentControlProjectionFailures,
  commentControlSelectorDigest,
  commentControlSelectorDigestsForUrl,
  commentLowerBoundConsistency,
  committedProjectionEvidence,
  consumeArticleAccessLease,
  createArticleAccessLease,
  createNetworkPolicyEvidenceRecorder,
  createPinnedPublicHttpsProxy,
  exactSignedAlgumonDealUrl,
  finalizeProfileLandingCoverage,
  matchingApprovedPaths,
  networkFidelityFailures,
  networkRequestDecision,
  isPrivateOrSpecialIp,
  isTopLevelNavigationRequest,
  markerSelectorsForUrl,
  parseConnectAuthority,
  projectionCardinalityEvidence,
  promotionVariantId,
  runtimeExpectationForTarget,
  semanticOracleContractFailures,
  selectFinalMainDocumentResponse,
  selectStableDiscoveryGroup,
  selectStableDiscoveryGroups,
  settlePage,
  signedRelayAcquisitionEvidence,
  siteArticleIdentity,
  staticRuntimeConsistencyFailures,
};

if (path.resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  try {
    process.exitCode = await main();
  } catch (error) {
    process.stderr.write(`${error?.stack ?? String(error)}\n`);
    process.exitCode = 2;
  }
}
