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
import { isIP } from "node:net";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

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
const DEVICE_PROFILES = Object.freeze({
  desktop: {
    viewport: { width: 1440, height: 1200 },
    userAgent:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
      "AppleWebKit/537.36 (KHTML, like Gecko) " +
      "Chrome/136.0.0.0 Safari/537.36",
    isMobile: false,
    hasTouch: false,
  },
  mobile: {
    viewport: { width: 390, height: 844 },
    userAgent:
      "Mozilla/5.0 (Linux; Android 15; Pixel 8) " +
      "AppleWebKit/537.36 (KHTML, like Gecko) " +
      "Chrome/136.0.0.0 Mobile Safari/537.36",
    isMobile: true,
    hasTouch: true,
  },
});
const FIRST_PAINT_PROBE_SOURCE = String.raw`
(() => {
  "use strict";
  const probe = {
    protocolVersion: 1,
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
      Number(style.opacity) !== 0 && element.getClientRects().length > 0;
  };
  const sample = () => {
    const root = document.documentElement;
    const body = document.body;
    const state = root?.getAttribute("data-hotdeal-focus-state") ?? "unset";
    const ready = root?.getAttribute("data-hotdeal-focus-ready") === "1" && state === "ready";
    const rootStyle = root ? window.getComputedStyle(root) : null;
    const paintLockIntact = !ready &&
      root?.getAttribute("data-hotdeal-focus-lock") === "1" &&
      rootStyle?.transitionProperty === "none" &&
      rootStyle?.animationName === "none" &&
      rootStyle?.contentVisibility === "hidden" &&
      rootStyle?.visibility === "hidden" &&
      Number(rootStyle?.opacity) === 0 &&
      rootStyle?.pointerEvents === "none" &&
      rootStyle?.clipPath === "inset(50%)";
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
    for (const layout of site.layouts) {
      const location = `${site.id}/${layout?.id ?? "<missing>"}`;
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
  let selector = `body *:not(:has(${markers}))`;
  for (const preserved of [...layout.preserve_deep].sort()) {
    selector += `:not(${preserved}):not(${preserved} *)`;
  }
  for (const preserved of [...layout.preserve_shallow].sort()) {
    selector += `:not(${preserved})`;
  }
  return selector;
}

function parseAdguardCosmeticRules(filterText) {
  const rules = [];
  for (const rawLine of filterText.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("!")) continue;
    const officialMatch = line.match(
      /^\[\$domain=([^,\]]+),path=([^\]]+)\](#\?#|#\$#|##)(.+)$/u,
    );
    if (officialMatch) {
      const [, domainValue, configuredPath, operator, selector] = officialMatch;
      const domains = domainValue
        .split("|")
        .map((domain) => domain.trim())
        .filter((domain) => domain && !domain.startsWith("~"));
      if (domains.length > 0 && selector && configuredPath) {
        rules.push({ domains, selector, path: configuredPath, operator });
      }
      continue;
    }
    const domainOnlyMatch = line.match(
      /^\[\$domain=([^,\]]+)\](#\?#|#\$#|##)(.+)$/u,
    );
    if (domainOnlyMatch) {
      const [, domainValue, operator, selector] = domainOnlyMatch;
      const domains = domainValue
        .split("|")
        .map((domain) => domain.trim())
        .filter((domain) => domain && !domain.startsWith("~"));
      if (domains.length > 0 && selector) {
        rules.push({ domains, selector, path: null, operator });
      }
      continue;
    }
    const operator = line.includes("#?#")
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
      rules.push({ domains, selector, path: configuredPath, operator });
    }
  }
  return rules;
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
            rule.operator === "#?#" &&
            rule.selector.includes("data-hotdeal-focus-keep"),
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

function normalizedHostname(hostname) {
  return String(hostname ?? "")
    .toLocaleLowerCase()
    .replace(/^\[|\]$/gu, "")
    .replace(/\.$/u, "");
}

function isPrivateOrSpecialIp(address) {
  const normalized = normalizedHostname(address);
  if (normalized.includes(":")) {
    if (
      normalized === "::" ||
      normalized === "::1" ||
      normalized.startsWith("fe8") ||
      normalized.startsWith("fe9") ||
      normalized.startsWith("fea") ||
      normalized.startsWith("feb") ||
      normalized.startsWith("fc") ||
      normalized.startsWith("fd")
    ) {
      return true;
    }
    const mapped = normalized.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/u)?.[1];
    return mapped ? isPrivateOrSpecialIp(mapped) : false;
  }
  const octets = normalized.split(".").map(Number);
  if (
    octets.length !== 4 ||
    octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)
  ) {
    return true;
  }
  const [first, second] = octets;
  return (
    first === 0 ||
    first === 10 ||
    first === 127 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 0) ||
    (first === 192 && second === 168) ||
    (first === 198 && (second === 18 || second === 19)) ||
    first >= 224
  );
}

function forbiddenInfrastructureHostname(hostname) {
  const normalized = normalizedHostname(hostname);
  return (
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    normalized.endsWith(".local") ||
    normalized.endsWith(".internal") ||
    normalized === "metadata.google.internal" ||
    (isIP(normalized) !== 0 && isPrivateOrSpecialIp(normalized))
  );
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
    Number.isInteger(draftManifest?.protocolVersion) &&
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
  const markerDomains = [...new Set(layouts.map((layout) => layout.domain))];
  const markerGateCovered = markerDomains.every((domain) =>
    markerRules.some(
      (rule) =>
        rule.domains.some((ruleDomain) => ruleDomain === domain) &&
        rule.path === null &&
        rule.operator === "#?#" &&
        /\[data-hotdeal-focus-ready=(?:"1"|'1')\]/u.test(rule.selector) &&
        /\[data-hotdeal-focus-state=(?:"ready"|'ready')\]/u.test(rule.selector) &&
        /:not\(\[data-hotdeal-focus-keep\]\)/u.test(rule.selector),
    ),
  );
  const prelockGateCovered = markerDomains.every((domain) =>
    markerRules.some(
      (rule) =>
        rule.domains.some((ruleDomain) => ruleDomain === domain) &&
        rule.path === null &&
        rule.operator === "#$#" &&
        /^html:not\(/u.test(rule.selector) &&
        /data-hotdeal-focus-ready/u.test(rule.selector) &&
        /html\[data-hotdeal-focus-lock=(?:"1"|'1')\]/u.test(rule.selector) &&
        /dialog::backdrop/u.test(rule.selector) &&
        /\[popover\]::backdrop/u.test(rule.selector) &&
        /:fullscreen::backdrop/u.test(rule.selector) &&
        /transition\s*:\s*none\s*!important/u.test(rule.selector) &&
        /animation\s*:\s*none\s*!important/u.test(rule.selector) &&
        /content-visibility\s*:\s*hidden\s*!important/u.test(rule.selector) &&
        /visibility\s*:\s*hidden\s*!important/u.test(rule.selector) &&
        /opacity\s*:\s*0\s*!important/u.test(rule.selector) &&
        /pointer-events\s*:\s*none\s*!important/u.test(rule.selector) &&
        /clip-path\s*:\s*inset\(50%\)\s*!important/u.test(rule.selector),
    ),
  );
  const userscriptContractCovered =
    !userscript?.missing &&
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
      const match = rule.selector.match(/data-hotdeal-focus-protocol=["']([^"']+)["']/u);
      return match ? [match[1]] : [];
    }),
  );
  let behaviorBaseline = null;
  try {
    behaviorBaseline = JSON.parse(behaviorBaselineArtifact?.content ?? "null");
  } catch {
    behaviorBaseline = null;
  }
  const protocolMajorStable =
    Number.isInteger(releaseProtocolVersion) &&
    behaviorBaseline?.protocol_major === releaseProtocolVersion;
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
    requiredSevenSites: missingSiteIds.length === 0,
    everySiteHasLayout: config.sites.every((site) => site.layouts.length > 0),
    everyLayoutHasDesktopOrMobile: layouts.every(
      (layout) => layout.desktop || layout.mobile,
    ),
    everyLayoutInStaticFilter: layouts.every((layout) => layout.staticCovered),
    markerGateContract: markerGateCovered,
    prelockGateContract: prelockGateCovered,
    userscriptContract: userscriptContractCovered,
    releaseManifestContract:
      isDraftBundle
        ? draftManifestContract
        : Boolean(releaseManifest) &&
          Number.isInteger(releaseProtocolVersion) &&
          releaseProtocolVersion >= 1 &&
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
      markerProtocolVersions.has(String(releaseProtocolVersion)),
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
    },
    artifacts: artifacts.map(({ content: _content, absolutePath: _absolutePath, ...item }) => item),
    releaseManifest: releaseManifest
      ? {
          sha256: releaseManifestArtifact.sha256,
          protocolVersion: releaseProtocolVersion,
          generatorVersion,
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

function contextOptions(profileName) {
  const profile = DEVICE_PROFILES[profileName];
  return {
    viewport: profile.viewport,
    userAgent: profile.userAgent,
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
  await page.evaluate(async () => {
    const delay = (milliseconds) =>
      new Promise((resolve) => window.setTimeout(resolve, milliseconds));
    const step = Math.max(400, Math.floor(window.innerHeight * 0.8));
    for (let position = 0; position < document.documentElement.scrollHeight; position += step) {
      window.scrollTo(0, position);
      await delay(60);
    }
    window.scrollTo(0, 0);
  });
  await page.waitForTimeout(250);
  await page.addStyleTag({
    content:
      "*,*::before,*::after{animation-duration:0s!important;transition-duration:0s!important;scroll-behavior:auto!important}",
  });
}

async function navigate(page, targetUrl, timeoutMs) {
  let response = null;
  const navigationProof = seededNavigationProof(targetUrl);
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
  return {
    finalUrl: page.url(),
    status: response?.status() ?? null,
  };
}

async function navigateThroughAlgumon(page, target, timeoutMs, expectedDomain = null) {
  if (!target.algumon) return navigate(page, target.url, timeoutMs);
  if (target.algumon.verifiedResolution) {
    const signedUrl = exactSignedAlgumonDealUrl(
      target.algumon.redirectUrl,
      target.algumon.dealId,
    );
    const resolution = target.algumon.verifiedResolution;
    if (
      !signedUrl ||
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
        element.getClientRects().length > 0
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
      const roleNodes = Object.fromEntries(
        rolesRequired.map((role) => [role, resolution.roles?.[role]?.node ?? null]),
      );
      const nodes = rolesRequired.map((role) => roleNodes[role]).filter(Boolean);
      const pageRoot =
        nodes.length === rolesRequired.length
          ? api.lowestCommonAncestor(nodes)
          : null;
      const pageRootSelector = pageRoot ? stableSelector(pageRoot) : null;
      const roleSelectors = Object.fromEntries(
        rolesRequired.map((role) => [
          role,
          roleNodes[role] ? stableSelector(roleNodes[role]) : null,
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
        ...new Set(oracleLayout.hints?.commentIgnored ?? []),
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
        rolesRequired.map((role) => {
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
        nodes.length === rolesRequired.length &&
        nodes.every(
          (node) => node === pageRoot || pageRoot.contains(node),
        );
      return {
        ok:
          resolution.ok === true &&
          pageRoot !== document.documentElement &&
          pageRoot !== document.body &&
          pageRootSelector !== null &&
          pageRootCount === 1 &&
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

function candidateOracleLayout(layout, oracle, targetUrl) {
  const parsed = new URL(targetUrl);
  const roleProjection = structuredClone(layout.role_projection);
  if (
    ["required", "optional"].includes(roleProjection.product.cardinality) &&
    typeof oracle.roles?.product === "string"
  ) {
    roleProjection.product.selectors = [oracle.roles.product];
  }
  return {
    id: `${layout.id}--candidate-oracle`,
    paths: [`|${parsed.pathname}${parsed.search}^`],
    pageRoot: oracle.pageRoot,
    requiredRoles: requiredRolesForLayout(layout),
    allowEmptyComments: layout.comment_contract?.allow_empty === true,
    roleProjection,
    hints: {
      ...Object.fromEntries(
        Object.entries(oracle.roles ?? {}).map(([role, selector]) => [role, [selector]]),
      ),
      commentItems: [...(oracle.commentItems ?? [])],
      commentControls: [...(oracle.commentControls ?? [])],
      commentIgnored: [...(oracle.commentIgnored ?? [])],
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
        ? Math.max(
            0,
            1 -
              Math.abs(commentItems.length - algumon.commentCount) /
                Math.max(1, commentItems.length, algumon.commentCount),
          )
        : null;
      const visible = (element) => {
        const style = getComputedStyle(element);
        return style.display !== "none" && style.visibility !== "hidden" &&
          Number(style.opacity) !== 0 && element.getClientRects().length > 0;
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
          !commentComparable || countConsistency >= 0.95,
        roleProjection: payload.roleProjection,
        productCount: productNodes.length,
        productCardinalityOk,
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
  const commentTolerance = commentComparable
    ? Math.max(2, algumonCommentCount * 0.35)
    : null;
  const titleConsistency = titleComparable
    ? Number(titleSimilarity.toFixed(3))
    : 0;
  const countConsistency = commentComparable
    ? Number(
        Math.max(
          0,
          1 -
            Math.abs(oracle.commentItemCount - algumonCommentCount) /
              Math.max(1, oracle.commentItemCount, algumonCommentCount),
        ).toFixed(3),
      )
    : null;
  const titleConsistent = oracle.seedTitleConsistencyOk === true;
  const commentConsistent =
    !commentComparable || countConsistency >= 0.95;
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
      commentTolerance,
      countConsistency,
      commentConsistent,
    },
  };
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
          element.getClientRects().length > 0
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
    "visibleLeakCount",
  ]);
  const unexpectedTopKeys = Object.keys(diagnostics).filter((key) => !allowedTopKeys.has(key));
  if (unexpectedTopKeys.length > 0) {
    failures.push(`diagnostics contains non-contract keys: ${unexpectedTopKeys.join(", ")}`);
  }
  if (!Number.isInteger(diagnostics.protocolVersion) || diagnostics.protocolVersion < 1) {
    failures.push("diagnostics.protocolVersion must be a positive integer");
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

async function auditUserscriptGate(page, requiredRoles, timeoutMs, markerSelectors) {
  await page
    .waitForSelector(
      'html[data-hotdeal-focus-ready="1"][data-hotdeal-focus-state="ready"]',
      { state: "attached", timeout: timeoutMs },
    )
    .catch(() => {});

  return page.evaluate(({ rolesToRequire, selectors }) => {
    const visible = (element) => {
      const style = window.getComputedStyle(element);
      return (
        style.display !== "none" &&
        style.visibility !== "hidden" &&
        Number(style.opacity) !== 0 &&
        element.getClientRects().length > 0
      );
    };
    const hasVisibleOwnedDescendant = (element) =>
      [...element.querySelectorAll("[data-hotdeal-focus-keep]")].some(visible);
    const logicallyVisible = (element) =>
      visible(element) || hasVisibleOwnedDescendant(element);
    const html = document.documentElement;
    const pseudoTextLength = (element) => ["::before", "::after"]
      .map((pseudo) => window.getComputedStyle(element, pseudo).content)
      .filter((content) => content && content !== "none" && content !== "normal" && content !== '""')
      .join("").length;
    const state = html.getAttribute("data-hotdeal-focus-state");
    const ready =
      html.getAttribute("data-hotdeal-focus-ready") === "1" && state === "ready";
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
        !element.hasAttribute("data-hotdeal-focus-keep") &&
        !markerMatchedNodes.has(element),
    );
    const coveredKeptNodes = bodyElements.filter(
      (element) =>
        element.hasAttribute("data-hotdeal-focus-keep") &&
        markerMatchedNodes.has(element),
    );
    const style = document.createElement("style");
    style.id = "hotdeal-audit-marker-projection";
    style.textContent = `${selectors.join(",\n")}{display:none!important}`;
    html.append(style);

    const visibleWithoutKeep = [...document.body.querySelectorAll("*")]
      .filter(visible)
      .filter((element) => !element.hasAttribute("data-hotdeal-focus-keep"))
      .map((element) => ({
        tag: element.tagName.toLowerCase(),
        id: element.id || null,
        classes: [...element.classList].slice(0, 4),
      }));
    const roleStats = Object.fromEntries(
      rolesToRequire.map((role) => {
        const nodes = [
          ...document.querySelectorAll(`[data-hotdeal-focus-role="${role}"]`),
        ];
        return [
          role,
          {
            count: nodes.length,
            selfVisibleCount: nodes.filter(visible).length,
            visibleOwnedDescendantCount: nodes.filter(hasVisibleOwnedDescendant).length,
            visibleCount: nodes.filter(logicallyVisible).length,
            allKept: nodes.every((node) => node.hasAttribute("data-hotdeal-focus-keep")),
          },
        ];
      }),
    );
    const summarizeProjectedRole = (role) => {
      const nodes = [
        ...document.querySelectorAll(`[data-hotdeal-focus-role="${role}"]`),
      ];
      return {
        count: nodes.length,
        visibleCount: nodes.filter(visible).length,
        allKept: nodes.every((node) => node.hasAttribute("data-hotdeal-focus-keep")),
      };
    };
    const commentItemStats = summarizeProjectedRole("comment-item");
    const commentControlStats = summarizeProjectedRole("comment-control");
    const directTextLeaks = [];
    const keptNodes = [...document.body.querySelectorAll("[data-hotdeal-focus-keep]")];
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
    return {
      ready,
      state,
      status: html.getAttribute("data-hotdeal-focus-status"),
      markerSelectorCount: selectors.length,
      markerSelectorErrors,
      uncoveredUnmarkedCount: uncoveredUnmarkedNodes.length,
      coveredKeptCount: coveredKeptNodes.length,
      diagnostics,
      paintProbe,
      roleStats,
      commentItemStats,
      commentControlStats,
      visibleWithoutKeep: visibleWithoutKeep.slice(0, 50),
      visibleWithoutKeepCount: visibleWithoutKeep.length,
      directTextLeaks: directTextLeaks.slice(0, 50),
      directVisibleTextLeakCount: directTextLeaks.length,
    };
  }, { rolesToRequire: requiredRoles, selectors: markerSelectors });
}

function userscriptGateFailures(gate, requiredRoles) {
  const failures = [];
  if (!gate.ready) failures.push(`userscript gate is not ready (state=${gate.state ?? "missing"})`);
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
  const commentControlStats = gate.commentControlStats;
  if (commentControlStats?.count > 0) {
    if (!commentControlStats.allKept) failures.push("comment control lacks keep marker");
    if (commentControlStats.visibleCount !== commentControlStats.count) {
      failures.push(
        `${commentControlStats.count - commentControlStats.visibleCount} comment controls are not visible`,
      );
    }
  }
  failures.push(...validateDiagnostics(gate.diagnostics, requiredRoles));
  return failures;
}

async function createPageContext(
  browser,
  profileName,
  userscriptContent = null,
  allowedNavigationDomains = [],
  allowedResourceDomains = allowedNavigationDomains,
) {
  const context = await browser.newContext({
    ...contextOptions(profileName),
    bypassCSP: true,
    serviceWorkers: "block",
  });
  const navigationDomains = new Set(allowedNavigationDomains.map((domain) => domain.toLowerCase()));
  const resourceDomains = new Set(allowedResourceDomains.map((domain) => domain.toLowerCase()));
  const dnsCache = new Map();
  const resolvesOnlyToPublicAddresses = async (hostname) => {
    const normalized = normalizedHostname(hostname);
    if (forbiddenInfrastructureHostname(normalized)) return false;
    const cached = dnsCache.get(normalized);
    if (cached && Date.now() - cached.checkedAt < 300_000) return cached.allowed;
    let addresses;
    try {
      addresses = isIP(normalized)
        ? [{ address: normalized }]
        : await lookup(normalized, { all: true, verbatim: true });
    } catch {
      dnsCache.set(normalized, { allowed: false, checkedAt: Date.now() });
      return false;
    }
    const allowed =
      addresses.length > 0 &&
      addresses.every(({ address }) => !isPrivateOrSpecialIp(address));
    dnsCache.set(normalized, { allowed, checkedAt: Date.now() });
    return allowed;
  };
  await context.route("**/*", async (route) => {
    const request = route.request();
    let parsed;
    try {
      parsed = new URL(request.url());
    } catch {
      await route.abort("blockedbyclient");
      return;
    }
    if (["about:", "blob:", "data:"].includes(parsed.protocol)) {
      await route.continue();
      return;
    }
    if (parsed.protocol !== "https:") {
      await route.abort("blockedbyclient");
      return;
    }
    const allowedRequest = [...resourceDomains].some((domain) =>
      hostnameMatches(parsed.hostname, domain),
    );
    const isMainNavigation =
      request.isNavigationRequest() && request.frame().parentFrame() === null;
    const allowedNavigation = [...navigationDomains].some((domain) =>
      hostnameMatches(parsed.hostname, domain),
    );
    if (
      !allowedRequest ||
      (isMainNavigation && !allowedNavigation) ||
      forbiddenInfrastructureHostname(parsed.hostname) ||
      !(await resolvesOnlyToPublicAddresses(parsed.hostname))
    ) {
      await route.abort("blockedbyclient");
      return;
    }
    await route.continue();
  });
  if (userscriptContent !== null) {
    await context.addInitScript({
      content: `${FIRST_PAINT_PROBE_SOURCE}\n${userscriptContent}`,
    });
  }
  const page = await context.newPage();
  return { context, page };
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
}) {
  const stem = safeFileStem([
    site.id,
    layout.id,
    profileName,
    target.source,
    sha256(target.url).slice(0, 10),
  ]);
  const result = {
    siteId: site.id,
    layoutId: layout.id,
    profile: profileName,
    source: target.source,
    requestedUrl: target.url,
    routeFamily: target.routeFamily ?? null,
    approvedRouteMatched: target.approvedRouteMatched !== false,
    matchedApprovedPath: target.matchedApprovedPath ?? null,
    routeObservation: target.routeObservation ?? null,
    static: null,
    userscript: null,
    failures: [],
  };
  let candidates = [];

  if (!runtimeOnly) {
    const staticSession = await createPageContext(
      browser,
      profileName,
      null,
      [layout.domain],
      resourceDomainsForLayout(site, layout),
    );
    try {
      const navigation = await navigate(staticSession.page, target.url, timeoutMs);
      result.static = { navigation };
      if (!urlMatchesLayout(navigation.finalUrl, layout)) {
        result.failures.push(
          `static path gate mismatch: ${new URL(navigation.finalUrl).hostname}${new URL(navigation.finalUrl).pathname}`,
        );
      }
      await captureBoundedScreenshot(
        staticSession.page,
        path.join(runDirectory, `${stem}-static-before.png`),
      );
      const oracle = await semanticOracle(
        staticSession.page,
        userscriptContent,
        site.id,
        layout.id,
        requiredRolesForLayout(layout),
        target,
      );
      result.semanticOracle = semanticOracleEvidence(oracle, target);
      const approvedProjection = await countExistingApprovedLayoutMatches(
        staticSession.page,
        layout,
        userscriptContent,
        targetAlgumonSeed(site.id, target),
      );
      const candidateProjection = await candidateOracleProjectionEvidence(
        staticSession.page,
        layout,
        result.semanticOracle,
        userscriptContent,
        targetAlgumonSeed(site.id, target),
        navigation.finalUrl,
      );
      const cardinality = projectionCardinalityEvidence(
        result.semanticOracle.structuralOk,
        approvedProjection.semanticProjectionCount,
      );
      result.semanticOracle.semanticProjectionCount =
        cardinality.semanticProjectionCount;
      result.semanticOracle.coMatchCount = cardinality.coMatchCount;
      result.semanticOracle.coMatchIds = approvedProjection.classes.flatMap(
        (projectionClass) => projectionClass.aliases,
      );
      result.semanticOracle.projectionAliases = approvedProjection.classes.map(
        (projectionClass) => projectionClass.aliases,
      );
      result.semanticOracle.exactApprovedCount = cardinality.exactApprovedCount;
      result.semanticOracle.candidateProjection = candidateProjection;
      const preProjectionCandidates = await selectorCandidates(staticSession.page);
      const approvedMatchId = approvedProjection.semanticProjectionCount === 1
        ? approvedProjection.classes[0].canonicalId
        : layout.id;
      const projectionLayout = staticProjectionContract(layout, approvedMatchId);
      const projection = await auditStaticProjection(staticSession.page, projectionLayout);
      result.static.projectionContractId = approvedMatchId;
      await staticSession.page.waitForTimeout(100);
      await captureBoundedScreenshot(
        staticSession.page,
        path.join(runDirectory, `${stem}-static-projected.png`),
      );
      result.static.projection = projection;
      result.failures.push(...staticProjectionFailures(projection).map((item) => `static: ${item}`));
      if (result.failures.length > 0) candidates = preProjectionCandidates;
    } catch (error) {
      result.failures.push(`static audit error: ${error?.stack ?? String(error)}`);
      candidates = await selectorCandidates(staticSession.page).catch(() => []);
      await captureBoundedScreenshot(
        staticSession.page,
        path.join(runDirectory, `${stem}-static-error.png`),
      )
        .catch(() => {});
    } finally {
      await staticSession.context.close();
    }
  } else {
    result.static = { skipped: "runtime-only candidate verification" };
  }

  const userscriptSession = await createPageContext(
    browser,
    profileName,
    userscriptContent,
    target.algumon ? [layout.domain, "algumon.com"] : [layout.domain],
    resourceDomainsForLayout(site, layout, Boolean(target.algumon)),
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
  try {
    const navigation = await navigateThroughAlgumon(
      userscriptSession.page,
      target,
      timeoutMs,
      layout.domain,
    );
    auditedPage = navigation.page ?? userscriptSession.page;
    const { page: _destinationPage, ...navigationEvidence } = navigation;
    result.userscript = { navigation: navigationEvidence };
    if (!urlMatchesLayout(navigation.finalUrl, layout)) {
      result.failures.push(
        `userscript path gate mismatch: ${new URL(navigation.finalUrl).hostname}${new URL(navigation.finalUrl).pathname}`,
      );
    }
    const requiredRoles = requiredRolesForLayout(layout);
    const markerSelectors = markerSelectorsForUrl(
      markerFilterContent,
      layout,
      navigation.finalUrl,
    );
    const gate = await auditUserscriptGate(
      auditedPage,
      requiredRoles,
      timeoutMs,
      markerSelectors,
    );
    await auditedPage.waitForTimeout(100);
    await captureBoundedScreenshot(
      auditedPage,
      path.join(runDirectory, `${stem}-userscript-gated.png`),
    );
    result.userscript.gate = gate;
    if (
      promotionCandidate &&
      promotionCandidate.siteId === site.id &&
      promotionCandidate.layoutId === layout.id &&
      target.source === "algumon-latest"
    ) {
      result.candidateOverlay = await auditCandidateOverlay(
        auditedPage,
        layout,
        promotionCandidate,
        target,
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
    result.failures.push(...userscriptGateFailures(gate, requiredRoles).map((item) => `userscript: ${item}`));
    if (result.failures.length > 0 && candidates.length === 0) {
      candidates = await selectorCandidates(auditedPage);
    }
  } catch (error) {
    result.failures.push(`userscript audit error: ${error?.stack ?? String(error)}`);
    if (candidates.length === 0) {
      candidates = await selectorCandidates(auditedPage).catch(() => []);
    }
    await captureBoundedScreenshot(
      auditedPage,
      path.join(runDirectory, `${stem}-userscript-error.png`),
    )
      .catch(() => {});
  } finally {
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
      bypassCSP: true,
      serviceWorkers: "block",
    });
    await context.addInitScript({
      content: `${FIRST_PAINT_PROBE_SOURCE}\n${userscriptContent}`,
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
    .map((rule) => rule.selector)
    .join("\n");
  const clienGateCss = clienGateRules
    .flatMap((rule) => {
      if (rule.operator === "#$#") return [rule.selector];
      if (
        rule.operator === "#?#" &&
        rule.selector.includes("data-hotdeal-focus-keep")
      ) {
        return [`${rule.selector}{display:none!important}`];
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
      expectedStatusPrefix: "terminal-role-projection-attribute-mutation",
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
      expectedStatusPrefix: "terminal-role-projection-marker-mutation",
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
      expectedStatusPrefix: "terminal-role-projection-marker-mutation",
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
            (fixture.includeMarkerGate
              ? `<style data-edge-marker-gate>${clienPaintGateCss}</style>`
              : "") +
            (fixture.headHtml ?? "") + `</head>` +
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
            dialogTransitionProperty: dialogStyle?.transitionProperty ?? null,
            dialogAnimationName: dialogStyle?.animationName ?? null,
            dialogContentVisibility: dialogStyle?.contentVisibility ?? null,
            dialogVisibility: dialogStyle?.visibility ?? null,
            dialogOpacity: dialogStyle?.opacity ?? null,
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
          lockedState.rootContentVisibility !== "hidden" ||
          lockedState.rootVisibility !== "hidden" ||
          Number(lockedState.rootOpacity) !== 0 ||
          lockedState.rootPointerEvents !== "none" ||
          lockedState.rootClipPath !== "inset(50%)" ||
          lockedState.dialogOpen !== true ||
          lockedState.dialogTransitionProperty !== "none" ||
          lockedState.dialogAnimationName !== "none" ||
          lockedState.dialogContentVisibility !== "hidden" ||
          lockedState.dialogVisibility !== "hidden" ||
          Number(lockedState.dialogOpacity) !== 0 ||
          lockedState.dialogClipPath !== "inset(50%)" ||
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
            Number(style.opacity) !== 0 && element.getClientRects().length > 0;
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
        const failClosed =
          !ready &&
          html.getAttribute("data-hotdeal-focus-lock") === "1" &&
          getComputedStyle(html).visibility === "hidden" &&
          visibleNoiseCount === 0 &&
          paintFlashCount === 0;
        return {
          ready,
          failClosed,
          selected,
          hidden,
          visibleNoiseCount,
          paintFlashCount,
          status: html.getAttribute("data-hotdeal-focus-status"),
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
          edgeState.status !== fixture.expectedStatusPrefix
        ) {
          fixtureResult.failures.push(
            `terminal status was ${edgeState.status ?? "missing"}`,
          );
        }
      } else if (fixture.tamper) {
        const safelyRecovered =
          (edgeState.ready && edgeState.visibleNoiseCount === 0) || edgeState.failClosed;
        if (!safelyRecovered) {
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
      expectedStatus: "terminal-article-identity-required",
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
      expectedStatus: "terminal-article-identity-required",
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
            Number(style.opacity) !== 0 && element.getClientRects().length > 0;
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
            element.getClientRects().length > 0
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
      proofUrlsPerRouteProfile: ALGUMON_PROOF_REPRESENTATIVES_PER_ROUTE_PROFILE,
    },
    maximum: {
      globalInventoryNavigations: 1,
      siteDiscoveryNavigations: sites.length,
      signedRelayFetches: sites.length * ALGUMON_SITE_LINK_SCAN_LIMIT,
    },
    actual: {
      globalInventoryNavigations: 1,
      siteDiscoveryNavigations: 0,
      signedRelayFetches: 0,
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
            const applicableLayouts = site.layouts.filter((candidate) =>
              profilesForLayout(site, candidate).includes(profileName),
            );
            const approvedLayouts = applicableLayouts.filter((candidate) =>
              urlMatchesLayout(finalUrl, candidate),
            );
            const sameDomainLayouts = applicableLayouts.filter((candidate) => {
              try {
                return hostnameMatches(new URL(finalUrl).hostname, candidate.domain);
              } catch {
                return false;
              }
            });
            const layout = approvedLayouts.length === 1
              ? approvedLayouts[0]
              : sameDomainLayouts.length === 1
                ? sameDomainLayouts[0]
                : null;
            const excludedVariantId =
              promotionCandidate?.siteId === site.id &&
              promotionCandidate?.layoutId === layout?.id
                ? promotionCandidate.variantId
                : null;
            const approvedPathMatches = layout
              ? matchingApprovedPaths(finalUrl, layout, excludedVariantId)
              : [];
            const approvedRouteMatched = approvedPathMatches.length > 0;
            const matchedApprovedPath = approvedPathMatches.length === 1
              ? approvedPathMatches[0]
              : null;
            const family = routeFamily(finalUrl);
            attempts.push({
              redirectPath: new URL(redirect.href).pathname,
              finalHost: new URL(finalUrl).hostname,
              finalPath: new URL(finalUrl).pathname,
              routeFamily: family,
              matchedLayoutId: layout?.id ?? null,
              approvedRouteMatched,
              matchedApprovedPath,
              approvedPathMatchCount: approvedPathMatches.length,
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
              approvedRouteMatched,
              matchedApprovedPath,
              approvedPathMatchCount: approvedPathMatches.length,
              routeObservation,
            });
            clusterTargets.set(clusterKey, representatives);
          }
          const unmatchedAttempts = attempts.filter(
            (attempt) =>
              !attempt.matchedLayoutId ||
              attempt.approvedRouteMatched === false ||
              attempt.approvedPathMatchCount !== 1,
          );
          record.profiles[profileName] = {
            matched: clusterTargets.size > 0,
            allObservedRoutesCovered: unmatchedAttempts.length === 0,
            clusterCount: new Set(attempts.map((attempt) => attempt.routeFamily)).size,
            matchedClusters: [...clusterTargets.keys()].sort(),
            unmatchedClusters: [
              ...new Set(unmatchedAttempts.map((attempt) => attempt.routeFamily)),
            ].sort(),
            attempts,
          };
          for (const representatives of clusterTargets.values()) {
            for (const match of representatives) {
              targets.push({
                site,
                layout: match.layout,
                profileName,
                target: {
                  source: "algumon-latest",
                  url: match.finalUrl,
                  routeFamily: match.routeFamily,
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
            target: { source: "sample", url: sampleUrl },
          });
        }
      }
    }
  }
  return targets;
}

function resultHasZeroLeak(result) {
  const gate = result.userscript?.gate;
  const commentItemsProjected = Boolean(
    gate?.commentItemStats &&
    gate.commentItemStats.allKept === true &&
    gate.commentItemStats.visibleCount === gate.commentItemStats.count,
  );
  const commentControlsProjected = Boolean(
    gate?.commentControlStats &&
    gate.commentControlStats.allKept === true &&
    gate.commentControlStats.visibleCount === gate.commentControlStats.count,
  );
  return Boolean(
    gate &&
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

function discoveryFailures(
  sites,
  discoveryRecords,
  inventory = null,
  transitionBudget = null,
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
      if (!record?.profiles?.[profileName]?.matched) {
        failures.push(`${site.id}/${profileName}: Algumon latest redirect did not match a path gate`);
      }
    }
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
  return {
    pageRoot: oracle.pageRoot,
    roles: Object.fromEntries(
      Object.entries(oracle.roles).map(([role, selector]) => [role, [selector]]),
    ),
    commentItems: [...oracle.commentItems].sort(),
    commentControls: [...(oracle.commentControls ?? [])].sort(),
    commentIgnored: [...(oracle.commentIgnored ?? [])].sort(),
  };
}

function discoveryObservation(result, roleProjection) {
  const oracle = result.semanticOracle;
  return {
    url: result.requestedUrl,
    profile: result.profile,
    capturedAt: result.capturedAt,
    pageRoot: { selector: oracle.pageRoot, count: oracle.pageRootCount },
    roles: Object.fromEntries(
      Object.entries(oracle.roles).map(([role, selector]) => [
        role,
        {
          selector,
          count: oracle.cardinality[role],
          containedInPageRoot: oracle.containment === true,
        },
      ]),
    ),
    roleProjection,
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
    (result.approvedRouteMatched === false || result.passed === false) &&
    oracle.algumon?.titleConsistencyOk === true &&
    (oracle.algumon?.commentComparable === false
      ? oracle.algumon.countConsistency === null
      : oracle.algumon?.countConsistency >= 0.95) &&
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
      result.semanticOracle.algumon.countConsistency >= 0.95,
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
          observation.algumon.countConsistency >= 0.95,
      )
    ) {
      return true;
    }
    if (
      !profileObservations.every((observation) =>
        observation.algumon?.countComparable === false
          ? observation.algumon.countConsistency === null
          : observation.algumon?.countComparable === true &&
            observation.algumon.countConsistency >= 0.95,
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
      group.roleProjection = structuredClone(layout.role_projection);
      if (group.roleProjection.product.cardinality === "required") {
        group.roleProjection.product.selectors = [
          ...(group.shape.roles.product ?? []),
        ].sort();
      }
      group.proofProfiles = profilesForLayout(site, layout).filter(
        (profile) =>
          selectCommentProofResults(
            group.results.filter((result) => result.profile === profile),
          ).length === 3,
      );
      group.fingerprint = sha256(canonicalJson({
        siteId: group.siteId,
        layoutId: group.layoutId,
        routeGroup: group.routeGroup,
        shape: group.shape,
        roleProjection: group.roleProjection,
      })).slice(0, 24);
      return group.proofProfiles.length > 0;
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
  const selectedResults = [];
  for (const profile of group.proofProfiles) {
    selectedResults.push(
      ...selectCommentProofResults(
        group.results.filter((candidate) => candidate.profile === profile),
      ),
    );
  }
  const observations = selectedResults.map((result) =>
    discoveryObservation(result, group.roleProjection));
  observations.sort((left, right) =>
    left.profile.localeCompare(right.profile) || left.url.localeCompare(right.url),
  );
  const requiredRoles = [...requiredRolesForLayout(layout)].sort();
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
          : observation.algumon.countConsistency >= 0.95) &&
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
  const { chromium } = await importPlaywright();
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
    profiles: DEVICE_PROFILES,
    integrity,
    discovery: { enabled: options.discoverAlgumon, required: options.requireAlgumonDiscovery },
    promotionRetestScope: promotionScope,
    results: [],
    failures: [],
    summary: null,
  };
  const isGitHubHostedRunner =
    process.env.GITHUB_ACTIONS === "true" &&
    process.env.RUNNER_ENVIRONMENT === "github-hosted";
  const liveSites = sites.filter(
    (site) =>
      options.fixtureOnly || site.id !== "arcalive" || isGitHubHostedRunner,
  );
  if (!options.fixtureOnly && liveSites.length !== sites.length) {
    report.failures.push(
      "arcalive: live navigation is CI-only and was refused outside a GitHub-hosted runner",
    );
    report.safetySkips = ["arcalive"];
  }
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
      "--host-resolver-rules=" +
        "MAP localhost ~NOTFOUND, " +
        "MAP *.localhost ~NOTFOUND, " +
        "MAP metadata.google.internal ~NOTFOUND, " +
        "MAP *.internal ~NOTFOUND",
    ],
  });
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
    if (!options.fixtureOnly && options.discoverAlgumon) {
      const discovery = await discoverLatestTargets(
        browser,
        liveSites,
        options.timeoutMs,
        promotionDraft?.candidate ?? null,
      );
      report.discovery.inventory = discovery.inventory;
      report.discovery.records = discovery.records;
      report.discovery.transitionBudget = discovery.transitionBudget;
      targets = targets.concat(discovery.targets);
      const failures = discoveryFailures(
        liveSites,
        discovery.records,
        discovery.inventory,
        discovery.transitionBudget,
      );
      report.discovery.failures = failures;
      if (options.requireAlgumonDiscovery) {
        report.failures.push(
          ...discoveryFailuresRequiredForPromotion(failures, promotionScope),
        );
      }
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
  approvedPathsForLayout,
  classifyAlgumonInventorySnapshot,
  classifyAlgumonSourceResponse,
  exactSignedAlgumonDealUrl,
  matchingApprovedPaths,
  projectionCardinalityEvidence,
  promotionVariantId,
  selectStableDiscoveryGroup,
  selectStableDiscoveryGroups,
};

if (path.resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  try {
    process.exitCode = await main();
  } catch (error) {
    process.stderr.write(`${error?.stack ?? String(error)}\n`);
    process.exitCode = 2;
  }
}
