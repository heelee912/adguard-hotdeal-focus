#!/usr/bin/env node

import https from "node:https";
import { chromium } from "playwright";

const PROBE_URL =
  "https://testcases.agrd.dev/userscripts-csp/header-csp-default-src-none";
const EXPECTED_COMPUTED_VALUE = "hdf-gm-style-pass";
const EXPECTED_RAW_COMPUTED_VALUE = "hdf-raw-style-pass";
const PROBE_HOST = "testcases.agrd.dev";
const PROBE_PATH = "/userscripts-csp/header-csp-default-src-none";
const PROBE_SLUG = "header-csp-default-src-none";
const PROBE_TITLE =
  "Userscripts: Content security policy (CSP) tests - " + PROBE_SLUG;
const PROBE_USER_SCRIPT_NAME = "AdGuard Hotdeal Focus CSP Probe";
const EXPECTED_CONTENT_TYPE = "text/html;charset=UTF-8";
const EXPECTED_ORIGIN_CSP =
  "default-src 'none'; connect-src 'self'; script-src 'nonce-AGTEST'; " +
  "object-src 'none'; base-uri 'none'; frame-ancestors 'none';";
const LOCAL_ADGUARD_ORIGIN = "https://local.adguard.org";
const ORIGIN_TIMEOUT_MS = 10_000;
const NAVIGATION_TIMEOUT_MS = 45_000;
const MARKER_POLL_INTERVAL_MS = 250;
const MARKER_POLL_LIMIT = 60;
const BROWSER_PROBE_ATTEMPT_LIMIT = 6;
const BROWSER_PROBE_RETRY_DELAY_MS = 1_000;
const MAX_ORIGIN_BODY_BYTES = 128 * 1024;
const COMMAND = "adguard-csp-browser-probe";

const RESULT_KEYS = Object.freeze([
  "schema_version",
  "command",
  "ok",
  "origin_status_exact",
  "origin_content_type_exact",
  "origin_csp_exact",
  "origin_html_semantics_exact",
  "endpoint_exact",
  "response_status_ok",
  "response_content_type_exact",
  "page_identity_exact",
  "effective_csp_present",
  "effective_csp_directive_set_exact",
  "effective_csp_default_rewrite_exact",
  "effective_csp_connect_rewrite_exact",
  "effective_csp_script_rewrite_exact",
  "effective_csp_style_rewrite_exact",
  "effective_csp_restrictions_preserved",
  "adguard_content_script_request_exact",
  "adguard_user_script_request_exact",
  "probe_selected_exact",
  "probe_state_complete",
  "raw_style_element_present",
  "raw_style_applied",
  "raw_engine_attributes_absent",
  "gm_style_count_exact",
  "gm_style_applied",
  "engine_nonce_present",
  "engine_data_source_present",
  "userscript_marker_consistent",
  "computed_custom_property",
]);

const BOOLEAN_RESULT_KEYS = new Set(
  RESULT_KEYS.filter(
    (key) =>
      !["schema_version", "command", "ok", "computed_custom_property"].includes(
        key,
      ),
  ),
);

function writeResult(value, exitCode) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
  process.exitCode = exitCode;
}

function safeRootState(value) {
  if (["missing", "pending", "complete", "failed", "other"].includes(value)) {
    return value;
  }
  return "other";
}

function safeFailure(kind, observed = {}, rootState) {
  const result = {
    schema_version: 2,
    command: COMMAND,
    ok: false,
    failure_kind: kind,
  };
  for (const key of RESULT_KEYS) {
    if (BOOLEAN_RESULT_KEYS.has(key) && typeof observed[key] === "boolean") {
      result[key] = observed[key];
    }
  }
  if (rootState !== undefined) {
    result.root_state = safeRootState(rootState);
  }
  return result;
}

function originHtmlSemanticsExact(html) {
  const tests = [
    /<!doctype html>/iu,
    /<html\b[^>]*\blang=(?:"en"|'en')[^>]*>/iu,
    new RegExp(`<title>\\s*${escapeRegExp(PROBE_TITLE)}\\s*</title>`, "u"),
    new RegExp(
      `<h1\\b[^>]*>\\s*${escapeRegExp(PROBE_SLUG)}\\s*</h1>`,
      "u",
    ),
    /<pre\b[^>]*\bid=(?:"headers-output"|'headers-output')[^>]*>\s*<\/pre>/iu,
    /<script\b[^>]*\bnonce=(?:"AGTEST"|'AGTEST')[^>]*>/iu,
  ];
  return tests.every((pattern) => pattern.test(html));
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function singleHeaderValue(headers, name) {
  const value = headers[name];
  return typeof value === "string" ? value : "";
}

function nativeOriginGet() {
  return new Promise((resolve, reject) => {
    let settled = false;
    let deadline;
    const settle = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      callback(value);
    };
    const request = https.request(
      {
        protocol: "https:",
        hostname: PROBE_HOST,
        port: 443,
        method: "GET",
        path: PROBE_PATH,
        agent: false,
        headers: { Accept: "text/html" },
      },
      (response) => {
        const chunks = [];
        let byteCount = 0;
        response.on("data", (chunk) => {
          byteCount += chunk.length;
          if (byteCount > MAX_ORIGIN_BODY_BYTES) {
            response.destroy(new Error("origin-body-limit"));
            return;
          }
          chunks.push(chunk);
        });
        response.on("error", (error) => settle(reject, error));
        response.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf8");
          settle(resolve, {
            statusCode: response.statusCode ?? 0,
            contentType: singleHeaderValue(response.headers, "content-type"),
            csp: singleHeaderValue(
              response.headers,
              "content-security-policy",
            ),
            body,
          });
        });
      },
    );
    deadline = setTimeout(() => {
      request.destroy(new Error("origin-timeout"));
    }, ORIGIN_TIMEOUT_MS);
    request.on("error", (error) => settle(reject, error));
    request.end();
  });
}

function parseCsp(value) {
  const directives = new Map();
  if (typeof value !== "string" || value.length === 0) {
    return { valid: false, directives };
  }
  const entries = value
    .split(";")
    .map((entry) => entry.trim())
    .filter(Boolean);
  for (const entry of entries) {
    const tokens = entry.split(/\s+/u);
    const name = tokens.shift()?.toLowerCase() ?? "";
    if (!/^[a-z][a-z0-9-]*$/u.test(name) || directives.has(name)) {
      return { valid: false, directives: new Map() };
    }
    directives.set(name, tokens);
  }
  return { valid: directives.size > 0, directives };
}

function exactSet(values, expected) {
  if (!values || values.length !== expected.length) return false;
  const actualSet = new Set(values);
  const expectedSet = new Set(expected);
  return (
    actualSet.size === values.length &&
    expectedSet.size === expected.length &&
    expected.every((value) => actualSet.has(value))
  );
}

function effectiveCspProof(value) {
  const parsed = parseCsp(value);
  const expectedDirectives = [
    "base-uri",
    "connect-src",
    "default-src",
    "frame-ancestors",
    "object-src",
    "script-src",
    "style-src",
  ];
  const directiveSetExact =
    parsed.valid && exactSet([...parsed.directives.keys()], expectedDirectives);
  const scriptTokens = parsed.directives.get("script-src") ?? [];
  const opaqueEngineNonceCount = scriptTokens.filter(
    (token) =>
      token !== "'nonce-AGTEST'" && /^'nonce-[^'\s;]+'$/u.test(token),
  ).length;
  return {
    effective_csp_present: typeof value === "string" && value.length > 0,
    effective_csp_directive_set_exact: directiveSetExact,
    effective_csp_default_rewrite_exact: exactSet(
      parsed.directives.get("default-src"),
      ["local.adguard.org", "data:"],
    ),
    effective_csp_connect_rewrite_exact: exactSet(
      parsed.directives.get("connect-src"),
      [
        "'self'",
        "local.adguard.org",
        "ws://local.adguard.org",
        "wss://local.adguard.org",
      ],
    ),
    effective_csp_script_rewrite_exact:
      scriptTokens.length === 5 &&
      new Set(scriptTokens).size === 5 &&
      scriptTokens.includes("'nonce-AGTEST'") &&
      scriptTokens.includes("local.adguard.org") &&
      scriptTokens.includes("'unsafe-eval'") &&
      scriptTokens.includes("'unsafe-inline'") &&
      opaqueEngineNonceCount === 1,
    effective_csp_style_rewrite_exact: exactSet(
      parsed.directives.get("style-src"),
      ["local.adguard.org", "'unsafe-inline'"],
    ),
    effective_csp_restrictions_preserved:
      exactSet(parsed.directives.get("base-uri"), ["'none'"]) &&
      exactSet(parsed.directives.get("object-src"), ["'none'"]) &&
      exactSet(parsed.directives.get("frame-ancestors"), ["'none'"]),
  };
}

function exactQueryValue(url, name, expected) {
  const values = url.searchParams.getAll(name);
  return values.length === 1 && values[0] === expected;
}

function createAdguardRequestObservation() {
  const content = { count: 0, allExact: true };
  const user = { count: 0, allExact: true, probeSelected: true };
  const exactContentContext = (url) =>
    url.origin === LOCAL_ADGUARD_ORIGIN &&
    url.pathname === "/" &&
    url.hash === "" &&
    exactQueryValue(url, "dmn", PROBE_HOST) &&
    exactQueryValue(url, "url", PROBE_URL) &&
    exactQueryValue(url, "app", "chrome.exe");

  return {
    observe(rawUrl) {
      let url;
      try {
        url = new URL(rawUrl);
      } catch {
        return;
      }
      if (url.origin !== LOCAL_ADGUARD_ORIGIN) return;
      const types = url.searchParams.getAll("type");
      if (types.includes("content-script")) {
        content.count += 1;
        content.allExact &&=
          types.length === 1 &&
          types[0] === "content-script" &&
          exactContentContext(url);
      }
      if (types.includes("user-script")) {
        user.count += 1;
        const queryNames = [...url.searchParams.keys()];
        const timestamps = url.searchParams.getAll("ts");
        const selectedNames = url.searchParams.getAll("name");
        user.allExact &&=
          url.origin === LOCAL_ADGUARD_ORIGIN &&
          url.pathname === "/" &&
          url.hash === "" &&
          types.length === 1 &&
          types[0] === "user-script" &&
          exactSet([...new Set(queryNames)], ["ts", "name", "type"]) &&
          timestamps.length === 1 &&
          /^\d{13}$/u.test(timestamps[0]) &&
          selectedNames.length > 0 &&
          selectedNames.every((name) => name.length > 0) &&
          new Set(selectedNames).size === selectedNames.length;
        user.probeSelected &&=
          selectedNames.filter((name) => name === PROBE_USER_SCRIPT_NAME)
            .length === 1;
      }
    },
    proof() {
      return {
        adguard_content_script_request_exact:
          content.count === 1 && content.allExact,
        adguard_user_script_request_exact: user.count === 1 && user.allExact,
        probe_selected_exact:
          user.count === 1 && user.allExact && user.probeSelected,
      };
    },
  };
}

function pageIdentityAndDomProof(expected) {
  const root = document.documentElement;
  const rawState = root?.getAttribute("data-hdf-csp-probe-state");
  const state =
    rawState === null
      ? "missing"
      : ["complete", "failed"].includes(rawState)
        ? rawState
        : "other";
  const rawStyles = document.querySelectorAll(
    'style[data-hdf-csp-raw-control="1"]',
  );
  const gmStyles = document.querySelectorAll(
    'style[data-hdf-csp-probe-style="1"]',
  );
  const rawStyle = rawStyles.length === 1 ? rawStyles[0] : null;
  const gmStyle = gmStyles.length === 1 ? gmStyles[0] : null;
  const computed = root ? getComputedStyle(root) : null;
  const rawValue =
    computed?.getPropertyValue("--hdf-csp-raw-control").trim() ?? "";
  const gmValue =
    computed?.getPropertyValue("--hdf-csp-gm-control").trim() ?? "";
  const markerBoolean = (name) => {
    const value = root?.getAttribute(name);
    if (value === "1") return true;
    if (value === "0") return false;
    return null;
  };
  const rawStyleApplied = rawValue === expected.rawComputedValue;
  const rawEngineAttributesAbsent = Boolean(
    rawStyle &&
      !rawStyle.hasAttribute("nonce") &&
      !rawStyle.hasAttribute("data-source"),
  );
  const gmStyleApplied = gmValue === expected.gmComputedValue;
  const engineNoncePresent = Boolean(gmStyle?.hasAttribute("nonce"));
  const engineDataSourcePresent = Boolean(gmStyle?.hasAttribute("data-source"));
  const originScripts = [...document.scripts].filter(
    (script) => script.nonce === expected.originNonce,
  );
  const pageIdentityExact = Boolean(
    root?.lang === "en" &&
      document.title === expected.pageTitle &&
      document.querySelectorAll("h1.text-primary").length === 1 &&
      document.querySelector("h1.text-primary")?.textContent?.trim() ===
        expected.pageSlug &&
      document.querySelectorAll("pre#headers-output").length === 1 &&
      originScripts.length === 1 &&
      originScripts[0].textContent.includes("fetchAndDisplayHeaders"),
  );
  return {
    rootState: state,
    pageIdentityExact,
    probeStateComplete: state === "complete",
    rawStyleElementPresent: rawStyles.length === 1,
    rawStyleApplied,
    rawEngineAttributesAbsent,
    gmStyleCountExact: gmStyles.length === 1,
    gmStyleApplied,
    engineNoncePresent,
    engineDataSourcePresent,
    userscriptMarkerConsistent:
      markerBoolean("data-hdf-csp-probe-raw-applied") === rawStyleApplied &&
      markerBoolean(
        "data-hdf-csp-probe-raw-engine-attributes-absent",
      ) === rawEngineAttributesAbsent &&
      markerBoolean("data-hdf-csp-probe-gm-applied") === gmStyleApplied &&
      markerBoolean("data-hdf-csp-probe-engine-nonce-present") ===
        engineNoncePresent &&
      markerBoolean("data-hdf-csp-probe-engine-source-present") ===
        engineDataSourcePresent &&
      (root?.getAttribute("data-hdf-csp-probe-computed") ?? "") === gmValue,
    computedCustomProperty: gmValue,
  };
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function pollDomProof(page) {
  let observation = {
    rootState: "pending",
    pageIdentityExact: false,
    probeStateComplete: false,
    rawStyleElementPresent: false,
    rawStyleApplied: false,
    rawEngineAttributesAbsent: false,
    gmStyleCountExact: false,
    gmStyleApplied: false,
    engineNoncePresent: false,
    engineDataSourcePresent: false,
    userscriptMarkerConsistent: false,
    computedCustomProperty: "",
  };
  for (let index = 0; index < MARKER_POLL_LIMIT; index += 1) {
    observation = await page.evaluate(pageIdentityAndDomProof, {
      pageTitle: PROBE_TITLE,
      pageSlug: PROBE_SLUG,
      originNonce: "AGTEST",
      rawComputedValue: EXPECTED_RAW_COMPUTED_VALUE,
      gmComputedValue: EXPECTED_COMPUTED_VALUE,
    });
    if (["complete", "failed"].includes(observation.rootState)) break;
    if (index + 1 < MARKER_POLL_LIMIT) {
      await delay(MARKER_POLL_INTERVAL_MS);
    }
  }
  return observation;
}

function resultIsExact(result) {
  if (Object.keys(result).length !== RESULT_KEYS.length) return false;
  if (!RESULT_KEYS.every((key) => Object.hasOwn(result, key))) return false;
  return RESULT_KEYS.every((key) => {
    if (key === "schema_version") return result[key] === 2;
    if (key === "command") return result[key] === COMMAND;
    if (key === "ok") return true;
    if (key === "computed_custom_property") {
      return result[key] === EXPECTED_COMPUTED_VALUE;
    }
    return result[key] === true;
  });
}

function buildResult(observed, dom) {
  return {
    schema_version: 2,
    command: COMMAND,
    ok: false,
    origin_status_exact: observed.origin_status_exact,
    origin_content_type_exact: observed.origin_content_type_exact,
    origin_csp_exact: observed.origin_csp_exact,
    origin_html_semantics_exact: observed.origin_html_semantics_exact,
    endpoint_exact: observed.endpoint_exact,
    response_status_ok: observed.response_status_ok,
    response_content_type_exact: observed.response_content_type_exact,
    page_identity_exact: observed.page_identity_exact,
    effective_csp_present: observed.effective_csp_present,
    effective_csp_directive_set_exact:
      observed.effective_csp_directive_set_exact,
    effective_csp_default_rewrite_exact:
      observed.effective_csp_default_rewrite_exact,
    effective_csp_connect_rewrite_exact:
      observed.effective_csp_connect_rewrite_exact,
    effective_csp_script_rewrite_exact:
      observed.effective_csp_script_rewrite_exact,
    effective_csp_style_rewrite_exact:
      observed.effective_csp_style_rewrite_exact,
    effective_csp_restrictions_preserved:
      observed.effective_csp_restrictions_preserved,
    adguard_content_script_request_exact:
      observed.adguard_content_script_request_exact,
    adguard_user_script_request_exact:
      observed.adguard_user_script_request_exact,
    probe_selected_exact: observed.probe_selected_exact,
    probe_state_complete: observed.probe_state_complete,
    raw_style_element_present: observed.raw_style_element_present,
    raw_style_applied: observed.raw_style_applied,
    raw_engine_attributes_absent: observed.raw_engine_attributes_absent,
    gm_style_count_exact: observed.gm_style_count_exact,
    gm_style_applied: observed.gm_style_applied,
    engine_nonce_present: observed.engine_nonce_present,
    engine_data_source_present: observed.engine_data_source_present,
    userscript_marker_consistent: observed.userscript_marker_consistent,
    computed_custom_property: dom.computedCustomProperty,
  };
}

async function runBrowserAttempt(browser) {
  const attemptObserved = {};
  let rootState;
  const context = await browser.newContext({
    javaScriptEnabled: true,
    serviceWorkers: "block",
  });
  try {
    const page = await context.newPage();
    const adguardRequests = createAdguardRequestObservation();
    page.on("request", (request) => adguardRequests.observe(request.url()));

    let response;
    try {
      response = await page.goto(PROBE_URL, {
        waitUntil: "domcontentloaded",
        timeout: NAVIGATION_TIMEOUT_MS,
      });
    } catch {
      return {
        failureKind: "navigation-failed",
        observed: attemptObserved,
        rootState,
      };
    }
    if (!response) {
      return {
        failureKind: "navigation-response-missing",
        observed: attemptObserved,
        rootState,
      };
    }

    const headers = await response.allHeaders();
    const effectiveCsp = singleHeaderValue(headers, "content-security-policy");
    Object.assign(attemptObserved, {
      endpoint_exact:
        page.url() === PROBE_URL &&
        response.url() === PROBE_URL &&
        response.request().redirectedFrom() === null,
      response_status_ok: response.status() === 200,
      response_content_type_exact:
        singleHeaderValue(headers, "content-type") === EXPECTED_CONTENT_TYPE,
      ...effectiveCspProof(effectiveCsp),
    });

    const dom = await pollDomProof(page);
    rootState = dom.rootState;
    Object.assign(attemptObserved, {
      page_identity_exact: dom.pageIdentityExact,
      ...adguardRequests.proof(),
      probe_state_complete: dom.probeStateComplete,
      raw_style_element_present: dom.rawStyleElementPresent,
      raw_style_applied: dom.rawStyleApplied,
      raw_engine_attributes_absent: dom.rawEngineAttributesAbsent,
      gm_style_count_exact: dom.gmStyleCountExact,
      gm_style_applied: dom.gmStyleApplied,
      engine_nonce_present: dom.engineNoncePresent,
      engine_data_source_present: dom.engineDataSourcePresent,
      userscript_marker_consistent: dom.userscriptMarkerConsistent,
    });
    return {
      failureKind: "proof-failed",
      observed: attemptObserved,
      rootState,
      dom,
    };
  } catch {
    return {
      failureKind: "proof-error",
      observed: attemptObserved,
      rootState,
    };
  } finally {
    await context.close().catch(() => {});
  }
}

async function run() {
  if (process.argv.length !== 2) {
    writeResult(safeFailure("arguments-rejected"), 2);
    return;
  }

  const observed = {};
  let rootState;
  let browser;
  try {
    let origin;
    try {
      origin = await nativeOriginGet();
    } catch {
      writeResult(safeFailure("origin-request-failed", observed), 1);
      return;
    }
    Object.assign(observed, {
      origin_status_exact: origin.statusCode === 200,
      origin_content_type_exact: origin.contentType === EXPECTED_CONTENT_TYPE,
      origin_csp_exact: origin.csp === EXPECTED_ORIGIN_CSP,
      origin_html_semantics_exact: originHtmlSemanticsExact(origin.body),
    });
    if (Object.values(observed).some((value) => value !== true)) {
      writeResult(safeFailure("origin-contract-failed", observed), 1);
      return;
    }

    try {
      browser = await chromium.launch({
        channel: "chrome",
        headless: true,
        args: ["--disable-background-networking", "--no-first-run"],
      });
    } catch {
      writeResult(safeFailure("browser-launch-failed", observed), 1);
      return;
    }
    let lastFailureKind = "proof-failed";
    for (
      let attemptIndex = 0;
      attemptIndex < BROWSER_PROBE_ATTEMPT_LIMIT;
      attemptIndex += 1
    ) {
      const attempt = await runBrowserAttempt(browser);
      Object.assign(observed, attempt.observed);
      rootState = attempt.rootState;
      lastFailureKind = attempt.failureKind;
      if (attempt.dom) {
        const result = buildResult(observed, attempt.dom);
        result.ok = resultIsExact(result);
        if (result.ok) {
          writeResult(result, 0);
          return;
        }
      }
      if (attemptIndex + 1 < BROWSER_PROBE_ATTEMPT_LIMIT) {
        await delay(BROWSER_PROBE_RETRY_DELAY_MS);
      }
    }
    writeResult(safeFailure(lastFailureKind, observed, rootState), 1);
  } catch {
    writeResult(safeFailure("proof-error", observed, rootState), 1);
  } finally {
    if (browser) {
      await browser.close().catch(() => {});
    }
  }
}

await run();
