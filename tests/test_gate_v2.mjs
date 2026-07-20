import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";
import { markerSelectorsForUrl } from "../scripts/audit_pages.mjs";

const require = createRequire(import.meta.url);
const extendedCssPackage = require("@adguard/extended-css/package.json");
const extendedCssBundlePath = require.resolve("@adguard/extended-css");
const expectedExtendedCssVersion = "2.0.52";
const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(testDirectory, "..");
const gateBuilderPath = path.join(projectRoot, "scripts", "build_gate_filter.py");
const configPath = path.join(projectRoot, "config", "sites.json");
const pythonCommand = process.env.PYTHON || "python";
const standardMarker = "#$#";
const extendedMarker = "#$?#";
const rulesPerDomain = 13;
const standardRulesPerDomain = 7;
const extendedRulesPerDomain = 6;
const cspNonce = "hdf-engine-test";

assert.equal(
  extendedCssPackage.version,
  expectedExtendedCssVersion,
  "gate-v2 tests must use the ExtendedCSS version embedded by the product contract",
);

function renderGateFilter() {
  return execFileSync(
    pythonCommand,
    [gateBuilderPath, "--config", configPath, "--stdout"],
    { cwd: projectRoot, encoding: "utf8" },
  );
}

function rulePayload(rule, marker) {
  const markerIndex = rule.indexOf(marker);
  assert.notEqual(markerIndex, -1, `missing ${marker} marker: ${rule}`);
  return rule.slice(markerIndex + marker.length);
}

function selectorFromRule(rule, marker) {
  const payload = rulePayload(rule, marker);
  const declarationIndex = payload.lastIndexOf(" {");
  assert.ok(declarationIndex > 0, `missing declarations: ${rule}`);
  return payload.slice(0, declarationIndex);
}

function rulesForDomain(rules, domain, marker) {
  const prefix = `[$domain=${domain}]${marker}`;
  return rules.filter((rule) => rule.startsWith(prefix));
}

function waitForExtendedCss() {
  return new Promise((resolve) => setTimeout(resolve, 350));
}

const renderedGate = renderGateFilter();
assert.equal(
  renderedGate,
  renderGateFilter(),
  "gate-v2 rendering must be byte-deterministic",
);
assert.match(renderedGate, /^! Version: 2\.0\.2$/mu);
assert.match(renderedGate, /^! Hotdeal-Focus-Protocol: 2$/mu);
assert.match(renderedGate, /^! Generator-Version: 2\.0\.2$/mu);
assert.doesNotMatch(renderedGate, /(?:,path=|\$path=)/u);
assert.match(renderedGate, /\.hdf-v2-ready/u);
assert.match(renderedGate, /\.hdf-v2-lock/u);
assert.match(renderedGate, /\.hdf-v2-keep/u);
assert.match(renderedGate, /\.hdf-v2-shell/u);
assert.match(renderedGate, /\.hdf-v2-deep/u);
assert.match(renderedGate, /\.hdf-v2-role-comment-control/u);
assert.match(renderedGate, /dialog::backdrop/u);
assert.match(renderedGate, /\[popover\]::backdrop/u);
assert.match(renderedGate, /:fullscreen::backdrop/u);

const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
const configuredDomains = [...new Set(
  config.sites.flatMap((site) => site.layouts.map((layout) => layout.domain)),
)].sort();
const generatedRules = renderedGate
  .split(/\r?\n/u)
  .filter((line) => line.startsWith("[$domain="));

assert.equal(
  generatedRules.length,
  configuredDomains.length * rulesPerDomain,
  "every configured domain must receive the complete v2 gate",
);
assert.equal(
  new Set(generatedRules).size,
  generatedRules.length,
  "gate-v2 must not emit duplicate rules",
);

const exactProjectionHideSelector =
  'html.hdf-v2-ready[data-hotdeal-focus-ready="1"]' +
  '[data-hotdeal-focus-protocol="2"]' +
  '[data-hotdeal-focus-state="ready"]' +
  '[data-hotdeal-focus-status="ready"]' +
  ' body *:not(.hdf-v2-keep[data-hotdeal-focus-keep])';
for (const site of config.sites) {
  for (const layout of site.layouts) {
    const selectors = markerSelectorsForUrl(
      renderedGate,
      layout,
      layout.sample_urls[0],
    );
    assert.deepEqual(
      selectors,
      [exactProjectionHideSelector],
      `auditor must select only the exact projection-hide rule for ${layout.id}`,
    );
  }
}

for (const domain of configuredDomains) {
  assert.equal(
    rulesForDomain(generatedRules, domain, standardMarker).length,
    standardRulesPerDomain,
    `unexpected standard CSS rule count for ${domain}`,
  );
  assert.equal(
    rulesForDomain(generatedRules, domain, extendedMarker).length,
    extendedRulesPerDomain,
    `unexpected ExtendedCSS rule count for ${domain}`,
  );
}

const exercisedDomain = "ruliweb.com";
const standardRules = rulesForDomain(
  generatedRules,
  exercisedDomain,
  standardMarker,
);
const extendedRules = rulesForDomain(
  generatedRules,
  exercisedDomain,
  extendedMarker,
);
const standardStyleSheet = standardRules
  .map((rule) => rulePayload(rule, standardMarker))
  .join("\n");
const extendedStyleSheet = extendedRules
  .map((rule) => rulePayload(rule, extendedMarker))
  .join("\n");
const extendedSelectors = extendedRules.flatMap((rule) =>
  selectorFromRule(rule, extendedMarker).split(", "));
assert.equal(
  extendedSelectors.some((selector) =>
    /^html\.hdf-v2-ready(?:\[[^\]]+\]){4}$/u.test(selector)),
  false,
  "a ready ExtendedCSS rule must not keep html affected after root-lock release",
);

const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext();
  await context.addInitScript({ path: extendedCssBundlePath });
  const shadowLockPage = await context.newPage();
  await shadowLockPage.goto("about:blank");
  const blankShadowLockPaint = await shadowLockPage.screenshot({ animations: "disabled" });
  await shadowLockPage.setContent(`<!doctype html><html><head>
    <style>
      html, html body, html body * {
        transition-property: opacity, visibility, clip-path !important;
        transition-duration: 100000s !important;
      }
      html body, html body * {
        visibility: visible !important;
        opacity: 1 !important;
        clip-path: none !important;
      }
    </style>
    <style>${standardStyleSheet}</style>
    </head><body><div id="closed-shadow-host"></div><script>
      const shadowRoot = document.querySelector("#closed-shadow-host")
        .attachShadow({ mode: "closed" });
      shadowRoot.innerHTML = '<style>dialog{position:fixed!important;inset:0!important;' +
        'width:100vw!important;height:100vh!important;background:cyan!important;' +
        'visibility:visible!important;opacity:1!important;content-visibility:visible!important;' +
        'clip-path:none!important}dialog::backdrop{background:yellow!important;' +
        'opacity:1!important;visibility:visible!important}</style>' +
        '<dialog>closed shadow modal advertisement</dialog>';
      shadowRoot.querySelector("dialog").showModal();
    </script></body></html>`);
  await shadowLockPage.waitForTimeout(50);
  const closedShadowLockedState = await shadowLockPage.evaluate(() => {
    const style = getComputedStyle(document.documentElement);
    return {
      clipPath: style.clipPath,
      bodyWidth: document.body.getBoundingClientRect().width,
      visibility: style.visibility,
    };
  });
  const closedShadowLockedPaint = await shadowLockPage.screenshot({ animations: "disabled" });
  assert.equal(closedShadowLockedState.visibility, "hidden");
  assert.equal(closedShadowLockedState.clipPath, "inset(50%)");
  assert.ok(closedShadowLockedState.bodyWidth > 0, "paint lock must preserve layout geometry");
  assert.equal(
    closedShadowLockedPaint.equals(blankShadowLockPaint),
    true,
    "the pre-ready gate must suppress a closed-shadow top-layer modal without painting",
  );
  await shadowLockPage.close();

  const page = await context.newPage();
  const consoleErrors = [];
  page.on("console", (message) => {
    if (message.type() === "error") {
      consoleErrors.push(message.text());
    }
  });

  const strictCspDocument = `<!doctype html>
    <html class="hdf-v2-lock">
      <head>
        <meta http-equiv="Content-Security-Policy"
          content="default-src 'none'; script-src 'none'; style-src 'nonce-site-test' 'nonce-${cspNonce}'; style-src-elem 'nonce-site-test' 'nonce-${cspNonce}'; style-src-attr 'none'">
        <style nonce="site-test">
          html, body { margin: 0; min-height: 100%; }
          html::before, body::before, #shell::before {
            content: "publisher-noise";
            display: block;
            background-image: linear-gradient(red, blue);
          }
          html, body { background-image: linear-gradient(red, blue); }
          dialog::backdrop { display: block; background: rgb(0, 255, 0); }
        </style>
      </head>
      <body>
        <div id="csp-target">CSP probe</div>
        <main id="shell">
          <h1 id="title">Deal title</h1>
          <span id="title-text">Deal title text</span>
          <article id="body-role"><p id="body-child">Article body</p></article>
          <section id="product"><span id="product-child">Price</span></section>
          <section id="comments">
            <article id="comment-item"><p id="comment-child">Reply</p></article>
            <button id="comment-control">More replies</button>
          </section>
          <aside id="noise">Recommended post</aside>
        </main>
        <dialog id="modal">Promoted modal</dialog>
      </body>
    </html>`;
  await page.goto(`data:text/html,${encodeURIComponent(strictCspDocument)}`);

  const cspResult = await page.evaluate(
    ({ nonce, injectedStyleSheet }) => {
      const rawStyle = document.createElement("style");
      rawStyle.textContent = "#csp-target { color: rgb(255, 0, 0) !important; }";
      document.documentElement.appendChild(rawStyle);
      const rawSheetBlocked = rawStyle.sheet === null;
      const rawColor = getComputedStyle(document.querySelector("#csp-target")).color;

      const nonceStyle = document.createElement("style");
      nonceStyle.setAttribute("nonce", nonce);
      nonceStyle.setAttribute("data-hotdeal-focus-runtime-style", "2");
      nonceStyle.textContent = `${injectedStyleSheet}\n` +
        "#csp-target { color: rgb(0, 0, 255) !important; }";
      document.documentElement.appendChild(nonceStyle);
      return {
        nonceRuleCount: nonceStyle.sheet?.cssRules.length ?? 0,
        nonceStyleApplied:
          getComputedStyle(document.querySelector("#csp-target")).color ===
          "rgb(0, 0, 255)",
        rawColor,
        rawSheetBlocked,
      };
    },
    { nonce: cspNonce, injectedStyleSheet: standardStyleSheet },
  );
  assert.equal(cspResult.rawSheetBlocked, true, "strict CSP must reject a raw style tag");
  assert.notEqual(cspResult.rawColor, "rgb(255, 0, 0)");
  assert.equal(
    cspResult.nonceRuleCount,
    standardRulesPerDomain + 1,
    "the nonce-bound stylesheet must parse every standard gate rule",
  );
  assert.equal(
    cspResult.nonceStyleApplied,
    true,
    "the AdGuard/GM nonce model must survive strict CSP",
  );

  const validation = await page.evaluate(
    ({ selectors, styleSheet }) => {
      const ExtendedCssEngine = globalThis.ExtendedCss.ExtendedCss;
      const validations = selectors.map((selector) =>
        ExtendedCssEngine.validate(selector));
      const html = document.documentElement;
      const noise = document.querySelector("#noise");
      html.style.setProperty("--publisher-root", "retained");
      noise.style.setProperty("display", "block", "important");
      noise.style.setProperty("visibility", "visible", "important");
      noise.style.setProperty("opacity", "1", "important");
      noise.style.setProperty("pointer-events", "auto", "important");
      document.querySelector("#modal").style.setProperty(
        "display", "block", "important");
      const engine = new ExtendedCssEngine({ styleSheet });
      engine.apply();
      globalThis.__hdfGateV2ExtendedCss = engine;
      return validations;
    },
    {
      selectors: extendedRules.map((rule) =>
        selectorFromRule(rule, extendedMarker)),
      styleSheet: extendedStyleSheet,
    },
  );
  assert.deepEqual(
    validation.filter((result) => !result.ok),
    [],
    "all generated gate-v2 selectors must parse in ExtendedCSS 2.0.52",
  );

  await waitForExtendedCss();
  const lockedState = await page.evaluate(() => ({
    modalDisplay: getComputedStyle(document.querySelector("#modal")).display,
    rootInlineOpacity: document.documentElement.style.getPropertyValue("opacity"),
    rootInlineClipPath: document.documentElement.style.getPropertyValue("clip-path"),
    rootClipPath: getComputedStyle(document.documentElement).clipPath,
    rootInlineContentVisibility:
      document.documentElement.style.getPropertyValue("content-visibility"),
    rootContentVisibility: getComputedStyle(document.documentElement).contentVisibility,
    rootInlineVisibility: document.documentElement.style.getPropertyValue("visibility"),
    rootVisibility: getComputedStyle(document.documentElement).visibility,
    rootOpacity: getComputedStyle(document.documentElement).opacity,
    rootOpacityPriority:
      document.documentElement.style.getPropertyPriority("opacity"),
    shellRectWidth: document.querySelector("#shell").getBoundingClientRect().width,
    backdropDisplay: getComputedStyle(
      document.querySelector("#modal"),
      "::backdrop",
    ).display,
  }));
  assert.equal(lockedState.rootOpacity, "0");
  assert.equal(lockedState.rootClipPath, "inset(50%)");
  assert.equal(lockedState.rootInlineClipPath, "inset(50%)");
  assert.equal(lockedState.rootContentVisibility, "hidden");
  assert.equal(lockedState.rootInlineContentVisibility, "hidden");
  assert.equal(lockedState.rootVisibility, "hidden");
  assert.equal(lockedState.rootInlineVisibility, "hidden");
  assert.equal(lockedState.rootInlineOpacity, "0");
  assert.equal(lockedState.rootOpacityPriority, "important");
  assert.ok(
    lockedState.shellRectWidth > 0,
    "the clipped transparent root curtain must preserve publisher layout for measurement",
  );
  assert.equal(lockedState.modalDisplay, "none");
  assert.equal(lockedState.backdropDisplay, "none");

  await page.evaluate(() => {
    const owner = "hdf2-test-owner";
    const mark = (selector, classes, attributes) => {
      const element = document.querySelector(selector);
      element.classList.add("hdf-v2-keep", ...classes);
      element.setAttribute("data-hotdeal-focus-keep", owner);
      for (const [name, value] of Object.entries(attributes)) {
        element.setAttribute(name, value);
      }
    };

    mark("#shell", ["hdf-v2-shell"], {
      "data-hotdeal-focus-shell": owner,
    });
    mark("#title", ["hdf-v2-role-title"], {
      "data-hotdeal-focus-role": "title",
    });
    mark("#title-text", ["hdf-v2-role-title-text"], {
      "data-hotdeal-focus-role": "title-text",
    });
    mark("#body-role", ["hdf-v2-role-body", "hdf-v2-deep"], {
      "data-hotdeal-focus-role": "body",
      "data-hotdeal-focus-deep": owner,
    });
    mark("#body-child", ["hdf-v2-deep"], {
      "data-hotdeal-focus-deep": owner,
    });
    mark("#product", ["hdf-v2-role-product", "hdf-v2-deep"], {
      "data-hotdeal-focus-role": "product",
      "data-hotdeal-focus-deep": owner,
    });
    mark("#product-child", ["hdf-v2-deep"], {
      "data-hotdeal-focus-deep": owner,
    });
    mark("#comments", ["hdf-v2-shell"], {
      "data-hotdeal-focus-shell": owner,
    });
    mark("#comment-item", ["hdf-v2-role-comment-item", "hdf-v2-deep"], {
      "data-hotdeal-focus-role": "comment-item",
      "data-hotdeal-focus-deep": owner,
    });
    mark("#comment-child", ["hdf-v2-deep"], {
      "data-hotdeal-focus-deep": owner,
    });
    mark("#comment-control", ["hdf-v2-role-comment-control", "hdf-v2-deep"], {
      "data-hotdeal-focus-role": "comment-control",
      "data-hotdeal-focus-deep": owner,
    });

    const html = document.documentElement;
    html.setAttribute("data-hotdeal-focus-ready", "1");
    html.setAttribute("data-hotdeal-focus-protocol", "2");
    html.setAttribute("data-hotdeal-focus-state", "ready");
    html.setAttribute("data-hotdeal-focus-status", "ready");
  });
  await waitForExtendedCss();
  assert.equal(
    await page.locator("#noise").evaluate((element) => getComputedStyle(element).display),
    "block",
    "data attributes alone must not release or activate the class-triggered projection",
  );

  await page.evaluate(() => {
    document.documentElement.classList.add("hdf-v2-ready");
  });
  await waitForExtendedCss();
  const armedState = await page.evaluate(() => {
    const style = (selector) => getComputedStyle(document.querySelector(selector));
    const pseudo = (selector, name) =>
      getComputedStyle(document.querySelector(selector), name);
    return {
      bodyBackground: style("body").backgroundImage,
      bodyVisibility: style("#body-role").visibility,
      commentControlVisibility: style("#comment-control").visibility,
      commentVisibility: style("#comment-item").visibility,
      htmlBackground: style("html").backgroundImage,
      noiseDisplay: style("#noise").display,
      noiseDisplayPriority:
        document.querySelector("#noise").style.getPropertyPriority("display"),
      productVisibility: style("#product").visibility,
      rootOpacity: style("html").opacity,
      rootContentVisibility: style("html").contentVisibility,
      rootVisibility: style("html").visibility,
      rootPseudoContent: pseudo("html", "::before").content,
      shellPseudoContent: pseudo("#shell", "::before").content,
      shellVisibility: style("#shell").visibility,
      titleVisibility: style("#title").visibility,
    };
  });
  assert.equal(armedState.rootOpacity, "0", "lock must remain during projection arming");
  assert.equal(armedState.rootContentVisibility, "hidden");
  assert.equal(armedState.rootVisibility, "hidden");
  assert.equal(armedState.noiseDisplay, "none");
  assert.equal(armedState.noiseDisplayPriority, "important");
  assert.equal(armedState.shellVisibility, "hidden");
  assert.equal(armedState.titleVisibility, "visible");
  assert.equal(armedState.bodyVisibility, "visible");
  assert.equal(armedState.productVisibility, "visible");
  assert.equal(armedState.commentVisibility, "visible");
  assert.equal(armedState.commentControlVisibility, "visible");
  assert.equal(armedState.htmlBackground, "none");
  assert.equal(armedState.bodyBackground, "none");
  assert.equal(armedState.rootPseudoContent, "none");
  assert.equal(armedState.shellPseudoContent, "none");

  await page.evaluate(() => {
    document.documentElement.classList.remove("hdf-v2-lock");
  });
  await waitForExtendedCss();
  const releasedState = await page.evaluate(() => ({
    noiseDisplay: getComputedStyle(document.querySelector("#noise")).display,
    publisherRootProperty:
      document.documentElement.style.getPropertyValue("--publisher-root"),
      rootInlineOpacity: document.documentElement.style.getPropertyValue("opacity"),
      rootInlineClipPath: document.documentElement.style.getPropertyValue("clip-path"),
      rootClipPath: getComputedStyle(document.documentElement).clipPath,
      rootInlineContentVisibility:
        document.documentElement.style.getPropertyValue("content-visibility"),
      rootContentVisibility: getComputedStyle(document.documentElement).contentVisibility,
      rootInlineVisibility: document.documentElement.style.getPropertyValue("visibility"),
      rootVisibility: getComputedStyle(document.documentElement).visibility,
      rootOpacity: getComputedStyle(document.documentElement).opacity,
  }));
  assert.equal(releasedState.rootOpacity, "1");
  assert.equal(releasedState.rootClipPath, "none");
  assert.equal(releasedState.rootInlineClipPath, "");
  assert.equal(releasedState.rootContentVisibility, "visible");
  assert.equal(releasedState.rootInlineContentVisibility, "");
  assert.equal(releasedState.rootVisibility, "visible");
  assert.equal(releasedState.rootInlineVisibility, "");
  assert.equal(releasedState.rootInlineOpacity, "");
  assert.equal(releasedState.publisherRootProperty, "retained");
  assert.equal(releasedState.noiseDisplay, "none");

  await page.evaluate(async () => {
    const noise = document.querySelector("#noise");
    noise.style.setProperty("display", "block", "important");
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
  assert.equal(
    await page.locator("#noise").evaluate((element) => getComputedStyle(element).display),
    "none",
    "ExtendedCSS must recover a normal inline-important overwrite",
  );

  const exhaustedState = await page.evaluate(async () => {
    const noise = document.querySelector("#noise");
    for (let attempt = 0; attempt < 55; attempt += 1) {
      noise.style.setProperty("display", "block", "important");
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    const leakedDisplay = getComputedStyle(noise).display;
    if (leakedDisplay !== "none") {
      document.documentElement.classList.add("hdf-v2-lock");
    }
    return { leakedDisplay };
  });
  assert.equal(
    exhaustedState.leakedDisplay,
    "block",
    "ExtendedCSS 2.0.52 alone must expose its documented 50-callback protection limit",
  );
  await waitForExtendedCss();
  const terminalState = await page.evaluate(() => ({
    lockClass: document.documentElement.classList.contains("hdf-v2-lock"),
    rootInlineOpacity: document.documentElement.style.getPropertyValue("opacity"),
    rootOpacity: getComputedStyle(document.documentElement).opacity,
  }));
  assert.equal(terminalState.lockClass, true);
  assert.equal(terminalState.rootOpacity, "0");
  assert.equal(terminalState.rootInlineOpacity, "0");
  assert.ok(
    consoleErrors.some((message) =>
      message.includes("ExtendedCss: infinite loop protection for style")),
    "the test must prove why an independent userscript terminal sentinel is required",
  );

  await context.close();
} finally {
  await browser.close();
}

process.stdout.write(
  `gate-v2: ${configuredDomains.length} domains, ${generatedRules.length} deterministic rules; strict-CSP/class/inline-important/50-limit contracts passed\n`,
);
