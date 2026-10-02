import assert from "node:assert/strict";
import fs from "node:fs";
import { chromium } from "playwright";
import { PREAUTHORIZED_ADGUARD_CONTROL_SOURCE } from
  "../scripts/preauthorized_adguard_control.mjs";

const userscriptSource = fs.readFileSync(
  new URL("../hotdeal-focus.user.js", import.meta.url),
  "utf8",
);
const preauthorizedOracleStyleControlSource = String.raw`
(() => {
  "use strict";
  const control = {
    kind: "preauthorized-oracle-style-control",
    calls: 0,
  };
  globalThis.GM_addElement = (parent, tagName, attributes) => {
    if (
      tagName !== "style" ||
      attributes?.["data-hotdeal-focus-runtime-style"] !== "2" ||
      typeof attributes?.textContent !== "string"
    ) {
      throw new Error("unexpected oracle GM_addElement contract");
    }
    const style = document.createElement("style");
    style.textContent = attributes.textContent;
    style.setAttribute(
      "data-hotdeal-focus-runtime-style",
      attributes["data-hotdeal-focus-runtime-style"],
    );
    parent.appendChild(style);
    control.calls += 1;
    return style;
  };
  Object.defineProperty(globalThis, "__HDF_PREAUTHORIZED_ORACLE_STYLE_CONTROL__", {
    configurable: true,
    value: control,
  });
})();
`;
const title = "Amazing Deal Product 2026";
const longBody = `
  <p>This is a sufficiently detailed product description with useful
  specifications and purchasing context for the reader.</p>
  <p>A second paragraph preserves shipping details, variants, and a complete
  account of the hot deal without unrelated page chrome.</p>`;

function layout({
  product = "zero",
  productOrder = "before-body",
  productHints = [".purchase"],
  bodyHints = [".story-body"],
  commentHints = [".comments"],
  commentItems = [".comments > .comment-item"],
  commentControls = [],
  commentIgnored = [],
} = {}) {
  return {
    allowEmptyComments: true,
    requiredRoles: product === "required"
      ? ["title", "product", "body", "comments"]
      : ["title", "body", "comments"],
    roleProjection: {
      product: {
        cardinality: product,
        ...(product === "zero" ? {} : { order: productOrder }),
      },
    },
    hints: {
      title: [".title-wrap", ".deal-title"],
      product: productHints,
      body: bodyHints,
      comments: commentHints,
      commentItems,
      commentControls,
      commentIgnored,
    },
  };
}

function exactLayout({
  product = "zero",
  productOrder = "before-body",
  bodyHints = [".exact-body"],
  bodyIgnored = [],
  productIgnored = [],
  commentHints = [".exact-comments"],
  commentItems = [".exact-comments > .comment-item"],
  commentControls = [".exact-comments > .comment-control"],
  commentIgnored = [".exact-comments > .comment-ignored"],
} = {}) {
  return {
    id: "exact-fixture",
    pageRoot: "#page",
    allowEmptyComments: true,
    requiredRoles: product === "required"
      ? ["title", "product", "body", "comments"]
      : ["title", "body", "comments"],
    roleProjection: {
      title: { mode: "metadata-shallow" },
      body: { mode: "atomic-boundary", ignored: bodyIgnored },
      comments: { mode: "classified-children" },
      product: {
        cardinality: product,
        ...(product === "zero" ? {} : { order: productOrder }),
        selectors: [".exact-product"],
        ignored: productIgnored,
      },
    },
    hints: {
      title: [".exact-title"],
      product: [".exact-product"],
      body: bodyHints,
      comments: commentHints,
      commentItems,
      commentControls,
      commentIgnored,
    },
  };
}

function metadata() {
  return `<meta property="og:title" content="${title}">`;
}

function populatedComments() {
  return `<div class="comments" aria-label="Comments">
    <div class="comment-item">First complete comment</div>
    <div class="comment-item">Second complete comment</div>
  </div>`;
}

function exactPage({
  titleHtml = `<h1 class="exact-title">${title}</h1>`,
  bodyExtra = "",
  productHtml = "",
  commentsHtml = `<div class="comment-item">Visible comment</div>
    <button class="comment-control">Visible reply control</button>
    <div class="comment-ignored" style="display:none">Ignored template</div>`,
  mountStyle = "",
} = {}) {
  return `<main id="page">
    ${titleHtml}
    ${productHtml}
    <article class="exact-body">${longBody}${bodyExtra}</article>
    <section class="exact-comments" aria-label="Comments" style="${mountStyle}">
      ${commentsHtml}
    </section>
  </main>`;
}

function clienPage({
  titleHtml = `<div class="post_subject">${title}</div>`,
  bodyExtra = "",
  commentsHtml = `<div class="comment"><div class="comment_row" itemprop="comment">Visible comment</div></div>
    <div class="comment_nav">Visible comment control</div>`,
  publisherCss = "",
  unownedHtml = "",
  commentsTotalHtml = "",
  fixtureBodyHtml = null,
} = {}) {
  return `<!doctype html><html><head>${metadata()}<style>
    ${publisherCss}
  </style></head><body>${fixtureBodyHtml ?? `<div class="content_view">
    ${titleHtml}
    <article class="post_article">${longBody}${bodyExtra}</article>
    ${commentsTotalHtml}
    <section class="post_comment" aria-label="Comments">${commentsHtml}</section>
  </div>`}${unownedHtml}</body></html>`;
}

async function openClienGate(browser, options = {}) {
  const {
    controlSource = PREAUTHORIZED_ADGUARD_CONTROL_SOURCE,
    userSource = userscriptSource,
    beforeUserScriptSource = "",
    afterUserScriptSource = "",
    destinationUrl = "https://www.clien.net/service/board/jirum/123",
    ...pageOptions
  } = options;
  const context = await browser.newContext();
  const page = await context.newPage();
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.addInitScript(
    ({ controlSource, userSource, beforeUserScriptSource, afterUserScriptSource }) => {
      (0, eval)(controlSource);
      const legacyNavigationSeedCalls = [];
      Object.defineProperty(globalThis, "__HDF_LEGACY_GM_SEED_CALLS__", {
        configurable: false,
        enumerable: false,
        value: legacyNavigationSeedCalls,
        writable: false,
      });
      const rejectLegacyNavigationSeed = (name) => (...args) => {
        legacyNavigationSeedCalls.push({ name, argumentCount: args.length });
        throw new Error(`${name} must not be used for Algumon handoff`);
      };
      Object.defineProperties(globalThis, {
        GM_getValue: {
          configurable: false,
          value: rejectLegacyNavigationSeed("GM_getValue"),
        },
        GM_setValue: {
          configurable: false,
          value: rejectLegacyNavigationSeed("GM_setValue"),
        },
        GM_deleteValue: {
          configurable: false,
          value: rejectLegacyNavigationSeed("GM_deleteValue"),
        },
      });
      const paintProbe = { sampleCount: 0, visibleLeakFrames: 0 };
      Object.defineProperty(globalThis, "__HDF_STANDALONE_LEAK_PROBE__", {
        configurable: false,
        enumerable: false,
        writable: false,
        value: paintProbe,
      });
      const sampleLeaks = () => {
        const root = document.documentElement;
        const rootStyle = root ? getComputedStyle(root) : null;
        const rootPaintable = Boolean(rootStyle) &&
          rootStyle.display !== "none" &&
          rootStyle.visibility !== "hidden" &&
          Number(rootStyle.opacity) !== 0 &&
          rootStyle.contentVisibility !== "hidden";
        const visibleLeak = rootPaintable &&
          [...document.querySelectorAll("#unlock-leak, #unlock-dialog")].some((element) => {
            const style = getComputedStyle(element);
            return style.display !== "none" &&
              style.visibility !== "hidden" &&
              Number(style.opacity) !== 0 &&
              element.getClientRects().length > 0;
          });
        paintProbe.sampleCount += 1;
        if (visibleLeak) paintProbe.visibleLeakFrames += 1;
        requestAnimationFrame(sampleLeaks);
      };
      requestAnimationFrame(sampleLeaks);
      if (beforeUserScriptSource) (0, eval)(beforeUserScriptSource);
      (0, eval)(userSource);
      if (afterUserScriptSource) (0, eval)(afterUserScriptSource);
    },
    {
      controlSource,
      userSource,
      beforeUserScriptSource,
      afterUserScriptSource,
    },
  );
  await page.route(`${destinationUrl}*`, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "text/html; charset=utf-8",
      body: clienPage(pageOptions),
    });
  });
  await page.goto(destinationUrl, {
    referer: "https://www.algumon.com/",
    waitUntil: "domcontentloaded",
  });
  return { context, page, pageErrors };
}

async function gateState(page) {
  return page.evaluate(() => {
    const html = document.documentElement;
    const visible = (element) => {
      if (!element) return false;
      const style = getComputedStyle(element);
      return style.display !== "none" &&
        style.visibility !== "hidden" &&
        style.contentVisibility !== "hidden" &&
        Number(style.opacity) !== 0 &&
        [...element.getClientRects()].some((rect) => rect.width > 0 && rect.height > 0);
    };
    const inlineLockProperties = [
      "animation",
      "caret-color",
      "clip-path",
      "content-visibility",
      "opacity",
      "pointer-events",
      "transition",
      "visibility",
    ];
    const markedNodeCount = [html, ...document.querySelectorAll("*")].filter((element) =>
      [...element.attributes].some((attribute) =>
        attribute.name.startsWith("data-hotdeal-focus-")) ||
      [...element.classList].some((className) => className.startsWith("hdf-v2-")),
    ).length;
    return {
      diagnostics: globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__ || null,
      commentControlProjection:
        globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.commentControlProjection || null,
      lock: html.getAttribute("data-hotdeal-focus-lock"),
      ready: html.getAttribute("data-hotdeal-focus-ready"),
      protocol: html.getAttribute("data-hotdeal-focus-protocol"),
      measure: html.getAttribute("data-hotdeal-focus-measure"),
      state: html.getAttribute("data-hotdeal-focus-state"),
      status: html.getAttribute("data-hotdeal-focus-status"),
      inlineStyle: html.getAttribute("style"),
      inlineLockProperties: Object.fromEntries(inlineLockProperties.map((property) => [
        property,
        [
          html.style.getPropertyValue(property),
          html.style.getPropertyPriority(property),
        ],
      ])),
      markedNodeCount,
      runtimeStyleCount: document.querySelectorAll(
        'style[data-hotdeal-focus-runtime-style="2"]',
      ).length,
      publisherContentVisible: {
        article: visible(document.querySelector(".post_article")),
        comments: visible(document.querySelector(".post_comment")),
      },
      preauthorizedControl: globalThis.__HOTDEAL_FOCUS_PREAUTHORIZED_CONTROL__
        ? {
            kind: globalThis.__HOTDEAL_FOCUS_PREAUTHORIZED_CONTROL__.kind,
            schemaVersion:
              globalThis.__HOTDEAL_FOCUS_PREAUTHORIZED_CONTROL__.schemaVersion,
            gmAddElementCalls:
              globalThis.__HOTDEAL_FOCUS_PREAUTHORIZED_CONTROL__.gmAddElementCalls,
          }
        : null,
      releaseProbe: document.querySelector('[data-hdf-v2-release-probe]')
        ?.getAttribute("style") ?? null,
      leakPaintProbe: globalThis.__HDF_STANDALONE_LEAK_PROBE__
        ? { ...globalThis.__HDF_STANDALONE_LEAK_PROBE__ }
        : null,
      legacyGmSeedCalls: Array.from(globalThis.__HDF_LEGACY_GM_SEED_CALLS__ || []),
      visibility: getComputedStyle(html).visibility,
      contentVisibility: getComputedStyle(html).contentVisibility,
      opacity: getComputedStyle(html).opacity,
      clipPath: getComputedStyle(html).clipPath,
      pointerEvents: getComputedStyle(html).pointerEvents,
    };
  });
}

function withLockedActivationTimeout(source, timeoutMs) {
  const timeoutDeclaration = /const LOCKED_ACTIVATION_TIMEOUT_MS\s*=\s*[\d_]+\s*;/;
  assert.match(source, timeoutDeclaration);
  return source.replace(
    timeoutDeclaration,
    `const LOCKED_ACTIVATION_TIMEOUT_MS = ${timeoutMs};`,
  );
}

function withPreReleaseRuntimeStop(source) {
  const activation = "      activeRuntime.beginDiscovery();";
  assert.ok(source.includes(activation), "runtime activation hook is missing");
  return source.replace(
    activation,
    `${activation}
      const stopBeforeRelease = function stopBeforeRelease() {
        const root = document.documentElement;
        if (
          root?.getAttribute("data-hotdeal-focus-lock") === "1" &&
          root?.getAttribute("data-hotdeal-focus-ready") === "1"
        ) {
          activeRuntime.stop();
          return;
        }
        nativeTimeout(browserRoot, stopBeforeRelease, 0);
      };
      stopBeforeRelease();`,
  );
}

async function evaluate(page, html, oracleLayout, commentCount) {
  await page.setContent(`<!doctype html><html><head>${metadata()}</head><body>${html}</body></html>`);
  return page.evaluate(
    ({ source, suppliedLayout, seedTitle, seedCommentCount }) => {
      const originalModule = Object.getOwnPropertyDescriptor(globalThis, "module");
      const moduleRecord = { exports: {} };
      Object.defineProperty(globalThis, "module", {
        value: moduleRecord,
        configurable: true,
        writable: false,
      });
      try {
        (0, eval)(source);
      } finally {
        delete globalThis.module;
        if (originalModule) Object.defineProperty(globalThis, "module", originalModule);
      }
      const resolution = moduleRecord.exports.discoverSemanticContract(
        document,
        [suppliedLayout],
        { title: seedTitle, commentCount: seedCommentCount },
      );
      const identity = (node) => node?.id || node?.className || node?.tagName || null;
      return {
        ok: resolution.ok,
        reason: resolution.reason,
        projectionTupleCount: resolution.projectionTupleCount,
        roles: Object.fromEntries(
          Object.entries(resolution.roles || {}).map(([role, evidence]) => [
            role,
            identity(evidence.node),
          ]),
        ),
      };
    },
    {
      source: userscriptSource,
      suppliedLayout: oracleLayout,
      seedTitle: title,
      seedCommentCount: commentCount,
    },
  );
}

async function evaluatePolicyProposal(page, html, oracleLayout, commentCount) {
  await page.setContent(`<!doctype html><html><head>${metadata()}</head><body>${html}</body></html>`);
  return page.evaluate(
    ({ source, suppliedLayout, seedTitle, seedCommentCount }) => {
      const moduleRecord = { exports: {} };
      Object.defineProperty(globalThis, "module", {
        value: moduleRecord,
        configurable: true,
      });
      try {
        (0, eval)(source);
      } finally {
        delete globalThis.module;
      }
      const resolution = moduleRecord.exports.discoverSemanticContract(
        document,
        [suppliedLayout],
        { title: seedTitle, commentCount: seedCommentCount },
      );
      return {
        ok: resolution.ok,
        reason: resolution.reason,
        existingPolicy: resolution.existingPolicy || null,
        policyProposal: resolution.policyProposal || null,
      };
    },
    {
      source: userscriptSource,
      suppliedLayout: oracleLayout,
      seedTitle: title,
      seedCommentCount: commentCount,
    },
  );
}

async function evaluateExact(page, html, oracleLayout, commentCount) {
  await page.setContent(`<!doctype html><html><head>${metadata()}</head><body>${html}</body></html>`);
  return page.evaluate(
    ({ source, suppliedLayout, seedTitle, seedCommentCount }) => {
      const moduleRecord = { exports: {} };
      Object.defineProperty(globalThis, "module", {
        value: moduleRecord,
        configurable: true,
      });
      try {
        (0, eval)(source);
      } finally {
        delete globalThis.module;
      }
      const resolution = moduleRecord.exports.resolveDocument(
        document,
        [suppliedLayout],
        { title: seedTitle, commentCount: seedCommentCount },
      );
      return {
        ok: resolution.ok,
        role: resolution.role || null,
        reason: resolution.reason || null,
        commentMountIdentity:
          resolution.roles?.comments?.id ||
          resolution.roles?.comments?.className ||
          null,
        projectionPolicy: resolution.projectionPolicy || null,
        bodyIgnoredCount: resolution.roles?.bodyIgnored?.length || 0,
        productIgnoredCount: resolution.roles?.productIgnored?.length || 0,
        commentIgnoredCount: resolution.roles?.commentIgnored?.length || 0,
      };
    },
    {
      source: userscriptSource,
      suppliedLayout: oracleLayout,
      seedTitle: title,
      seedCommentCount: commentCount,
    },
  );
}

async function evaluateExactWithAttachedShadow(page, mode) {
  const html = exactPage({ bodyExtra: '<div class="shadow-host">Fallback article detail</div>' });
  await page.setContent(`<!doctype html><html><head>${metadata()}</head><body>${html}</body></html>`);
  return page.evaluate(
    ({ source, suppliedLayout, seedTitle, shadowMode }) => {
      const instrumentedSource = source.replace(
        /    discoverSemanticContract,\r?\n    start,/,
        "    discoverSemanticContract,\n    initializeShadowTracker,\n    start,",
      );
      if (instrumentedSource === source) {
        throw new Error("shadow tracker export instrumentation failed");
      }
      const moduleRecord = { exports: {} };
      Object.defineProperty(globalThis, "module", {
        value: moduleRecord,
        configurable: true,
      });
      try {
        (0, eval)(instrumentedSource);
      } finally {
        delete globalThis.module;
      }
      const tracker = moduleRecord.exports.initializeShadowTracker(window);
      if (!tracker?.installed) throw new Error("scoped shadow tracker was unavailable");
      try {
        document.querySelector(".shadow-host").attachShadow({ mode: shadowMode });
        const resolution = moduleRecord.exports.resolveDocument(
          document,
          [suppliedLayout],
          { title: seedTitle, commentCount: 1 },
        );
        return {
          ok: resolution.ok,
          role: resolution.role || null,
          reason: resolution.reason || null,
        };
      } finally {
        tracker.uninstall();
      }
    },
    {
      source: userscriptSource,
      suppliedLayout: exactLayout(),
      seedTitle: title,
      shadowMode: mode,
    },
  );
}

async function evaluateExactWithRegisteredLightDomCustomElement(page) {
  const html = exactPage({
    commentsHtml: `<div class="comment-item" itemprop="comment">
      Posted <el-tooltip content="28분 전">28분 전</el-tooltip>
    </div>`,
  });
  await page.setContent(`<!doctype html><html><head>${metadata()}</head><body>${html}</body></html>`);
  return page.evaluate(
    ({ source, suppliedLayout, seedTitle }) => {
      const moduleRecord = { exports: {} };
      Object.defineProperty(globalThis, "module", {
        value: moduleRecord,
        configurable: true,
      });
      try {
        (0, eval)(source);
      } finally {
        delete globalThis.module;
      }
      if (!customElements.get("el-tooltip")) {
        customElements.define("el-tooltip", class LightDomTooltip extends HTMLElement {});
      }
      const resolution = moduleRecord.exports.resolveDocument(
        document,
        [suppliedLayout],
        { title: seedTitle, commentCount: 1 },
      );
      return {
        ok: resolution.ok,
        role: resolution.role || null,
        reason: resolution.reason || null,
      };
    },
    {
      source: userscriptSource,
      suppliedLayout: exactLayout(),
      seedTitle: title,
    },
  );
}

async function exerciseProjectionEventSubscriptions(page) {
  await page.setContent(`<!doctype html><html><head>${metadata()}</head><body>${exactPage()}</body></html>`);
  return page.evaluate(
    ({ source, suppliedLayout, seedTitle }) => {
      const originalAdd = EventTarget.prototype.addEventListener;
      const originalRemove = EventTarget.prototype.removeEventListener;
      const trackedTypes = new Set(["beforetoggle", "toggle", "fullscreenchange"]);
      const added = [];
      const removed = [];
      EventTarget.prototype.addEventListener = function trackedAdd(type, listener, options) {
        if (trackedTypes.has(type)) added.push(type);
        return Reflect.apply(originalAdd, this, [type, listener, options]);
      };
      EventTarget.prototype.removeEventListener = function trackedRemove(type, listener, options) {
        if (trackedTypes.has(type)) removed.push(type);
        return Reflect.apply(originalRemove, this, [type, listener, options]);
      };
      try {
        const instrumentedSource = source.replace(
          /    discoverSemanticContract,\r?\n    start,/,
          "    discoverSemanticContract,\n    applyRoleMarkers,\n    installRuntimeGateStyle,\n    installIntegrityObserver,\n    start,",
        );
        if (instrumentedSource === source) throw new Error("private export instrumentation failed");
        const moduleRecord = { exports: {} };
        Object.defineProperty(globalThis, "module", {
          value: moduleRecord,
          configurable: true,
        });
        try {
          (0, eval)(instrumentedSource);
        } finally {
          delete globalThis.module;
        }
        const api = moduleRecord.exports;
        const resolution = api.resolveDocument(
          document,
          [suppliedLayout],
          { title: seedTitle, commentCount: 1 },
        );
        if (!resolution.ok) return { setup: resolution, added, removed };
        const nonce = "event-fixture-nonce";
        const state = api.applyRoleMarkers(
          document,
          resolution.roles,
          resolution.commonRoot,
          resolution.resolvedTitle,
          resolution.requiredRoles,
          resolution.commentItemSelectors,
          resolution.commentControlSelectors,
          resolution.commentIgnoredSelectors,
          resolution.projectionPolicy,
          nonce,
        );
        const style = api.installRuntimeGateStyle(document);
        style.textContent = api.gateStyleText(nonce);
        document.documentElement.classList.add("hdf-v2-ready");
        document.documentElement.setAttribute("data-hotdeal-focus-ready", "1");
        document.documentElement.setAttribute("data-hotdeal-focus-protocol", api.PROTOCOL_VERSION);
        document.documentElement.setAttribute("data-hotdeal-focus-state", "ready");
        const runtime = {
          terminallyBlocked: false,
          enterTerminal() { this.terminallyBlocked = true; },
          unsubscribeShadow: null,
          unsubscribeProjectionEvents: null,
        };
        api.installIntegrityObserver(window, runtime, state, style);
        const subscribed = added.slice();
        runtime.unsubscribeProjectionEvents();
        return { setup: { ok: true }, added: subscribed, removed: removed.slice() };
      } finally {
        EventTarget.prototype.addEventListener = originalAdd;
        EventTarget.prototype.removeEventListener = originalRemove;
      }
    },
    {
      source: `${preauthorizedOracleStyleControlSource}\n${userscriptSource}`,
      suppliedLayout: exactLayout(),
      seedTitle: title,
    },
  );
}

async function exerciseDynamicControl(page, hidden) {
  const html = `<main id="page">
    <h1 class="exact-title">${title}</h1>
    <article class="exact-body">${longBody}</article>
    <section class="exact-comments" aria-label="Comments">
      <div class="comment-item">Initial visible comment</div>
      <button class="comment-control">Initial visible control</button>
      <div class="comment-ignored" style="display:none">Ignored template</div>
    </section>
  </main>`;
  await page.setContent(`<!doctype html><html><head>${metadata()}</head><body>${html}</body></html>`);
  return page.evaluate(
    async ({ source, suppliedLayout, seedTitle, shouldHide }) => {
      const instrumentedSource = source.replace(
        /    discoverSemanticContract,\r?\n    start,/,
        "    discoverSemanticContract,\n    applyRoleMarkers,\n    installRuntimeGateStyle,\n    installIntegrityObserver,\n    start,",
      );
      if (instrumentedSource === source) throw new Error("private export instrumentation failed");
      const moduleRecord = { exports: {} };
      Object.defineProperty(globalThis, "module", {
        value: moduleRecord,
        configurable: true,
      });
      try {
        (0, eval)(instrumentedSource);
      } finally {
        delete globalThis.module;
      }
      const api = moduleRecord.exports;
      const resolution = api.resolveDocument(
        document,
        [suppliedLayout],
        { title: seedTitle, commentCount: 1 },
      );
      if (!resolution.ok) return { setup: resolution, terminalReason: null, role: null };
      const state = api.applyRoleMarkers(
        document,
        resolution.roles,
        resolution.commonRoot,
        resolution.resolvedTitle,
        resolution.requiredRoles,
        resolution.commentItemSelectors,
        resolution.commentControlSelectors,
        resolution.commentIgnoredSelectors,
        resolution.projectionPolicy,
        "fixture-nonce",
      );
      const runtime = {
        terminallyBlocked: false,
        terminalReason: null,
        authorizedReady: true,
        releasePhase: "released",
        relockForReprojection() { return false; },
        publishReadyProjectionDiagnostics() { return true; },
        enterTerminal(reason) {
          this.terminallyBlocked = true;
          this.terminalReason = reason;
        },
      };
      const gateStyle = api.installRuntimeGateStyle(document);
      gateStyle.textContent = api.gateStyleText("fixture-nonce");
      document.documentElement.removeAttribute("data-hotdeal-focus-lock");
      document.documentElement.classList.add("hdf-v2-ready");
      document.documentElement.setAttribute("data-hotdeal-focus-ready", "1");
      document.documentElement.setAttribute("data-hotdeal-focus-protocol", api.PROTOCOL_VERSION);
      document.documentElement.setAttribute("data-hotdeal-focus-state", "ready");
      document.documentElement.setAttribute("data-hotdeal-focus-status", "ready");
      api.installIntegrityObserver(window, runtime, state, gateStyle);
      const control = document.createElement("button");
      control.className = "comment-control";
      control.textContent = "Dynamically added reply control";
      if (shouldHide) control.style.visibility = "hidden";
      resolution.roles.comments.appendChild(control);
      await new Promise((resolve) => setTimeout(resolve, 0));
      return {
        setup: { ok: true },
        terminalReason: runtime.terminalReason,
        role: control.getAttribute("data-hotdeal-focus-role"),
        visibility: getComputedStyle(control).visibility,
        pointerEvents: getComputedStyle(control).pointerEvents,
      };
    },
    {
      source: `${preauthorizedOracleStyleControlSource}\n${userscriptSource}`,
      suppliedLayout: exactLayout(),
      seedTitle: title,
      shouldHide: hidden,
    },
  );
}

async function exerciseDynamicComment(page, {
  exactTotal = false,
  updateExactTotal = false,
  separateExactTotalUpdate = false,
  totalUpdateAfterItems = false,
  exerciseControls = false,
  removeInitial = false,
  nestedMount = false,
  mutateInitial = false,
} = {}) {
  const totalHtml = exactTotal
    ? '<p class="comment-total">Comments: 1</p>'
    : "";
  const html = `<main id="page">
    <h1 class="exact-title">${title}</h1>
    <article class="exact-body">${longBody}${exerciseControls ? `
      <a id="body-link" href="https://example.com/product">Product link</a>
      <img id="body-image" alt="Product image" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==">
      <details id="body-details" open><summary>Specifications</summary><p>Original specifications</p></details>` : ""}</article>
    ${totalHtml}
    <section class="exact-comments" aria-label="Comments">
      <div class="comment-item" id="initial-comment">Initial visible comment</div>
      <button class="comment-control">Initial visible control</button>
      <div class="comment-ignored" style="display:none">Ignored template</div>
      ${nestedMount ? '<div class="thread-mount"></div>' : ""}
    </section>
  </main>`;
  await page.setContent(`<!doctype html><html><head>${metadata()}</head><body>${html}</body></html>`);
  return page.evaluate(
    async ({
      source,
      suppliedLayout,
      seedTitle,
      shouldUpdateTotal,
      shouldSeparateTotalUpdate,
      shouldUpdateTotalAfterItems,
      shouldExerciseControls,
      shouldRemoveInitial,
      shouldUseNestedMount,
      shouldMutateInitial,
    }) => {
      const instrumentedSource = source.replace(
        /    discoverSemanticContract,\r?\n    start,/,
        "    discoverSemanticContract,\n    applyRoleMarkers,\n    installRuntimeGateStyle,\n    installIntegrityObserver,\n    start,",
      );
      if (instrumentedSource === source) throw new Error("private export instrumentation failed");
      const moduleRecord = { exports: {} };
      Object.defineProperty(globalThis, "module", {
        value: moduleRecord,
        configurable: true,
      });
      try {
        (0, eval)(instrumentedSource);
      } finally {
        delete globalThis.module;
      }
      const api = moduleRecord.exports;
      const resolution = api.resolveDocument(
        document,
        [suppliedLayout],
        { title: seedTitle, commentCount: 1 },
      );
      if (!resolution.ok) {
        return { setup: resolution, terminalAfterAddition: null };
      }
      const state = api.applyRoleMarkers(
        document,
        resolution.roles,
        resolution.commonRoot,
        resolution.resolvedTitle,
        resolution.requiredRoles,
        resolution.commentItemSelectors,
        resolution.commentControlSelectors,
        resolution.commentIgnoredSelectors,
        resolution.projectionPolicy,
        "dynamic-comment-fixture-nonce",
      );
      const runtime = {
        terminallyBlocked: false,
        terminalReason: null,
        authorizedReady: true,
        releasePhase: "released",
        relockForReprojection() { return false; },
        publishReadyProjectionDiagnostics() { return true; },
        enterTerminal(reason) {
          this.terminallyBlocked = true;
          this.terminalReason = reason;
        },
      };
      const gateStyle = api.installRuntimeGateStyle(document);
      gateStyle.textContent = api.gateStyleText("dynamic-comment-fixture-nonce");
      document.documentElement.removeAttribute("data-hotdeal-focus-lock");
      document.documentElement.classList.add("hdf-v2-ready");
      document.documentElement.setAttribute("data-hotdeal-focus-ready", "1");
      document.documentElement.setAttribute("data-hotdeal-focus-protocol", api.PROTOCOL_VERSION);
      document.documentElement.setAttribute("data-hotdeal-focus-state", "ready");
      document.documentElement.setAttribute("data-hotdeal-focus-status", "ready");
      api.installIntegrityObserver(window, runtime, state, gateStyle);

      const initial = document.querySelector("#initial-comment");
      const initialIdentity = initial;
      const originalBody = document.querySelector(".exact-body");
      const originalBodyText = originalBody.textContent;
      const originalControl = document.querySelector(".comment-control");
      const originalLink = document.querySelector("#body-link");
      const originalImage = document.querySelector("#body-image");
      const originalDetails = document.querySelector("#body-details");
      if (shouldExerciseControls) {
        originalControl.addEventListener("click", () => {
          const reply = document.createElement("div");
          reply.className = "comment-item";
          reply.id = "loaded-more-comment";
          reply.textContent = "Reply loaded by the original comment control";
          resolution.roles.comments.appendChild(reply);
        });
      }
      if (shouldMutateInitial) {
        initial.classList.add("publisher-loaded");
        initial.setAttribute("aria-label", "Loaded visible comment");
        initial.firstChild.data = "Updated visible comment";
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
      const added = document.createElement("section");
      added.className = "comment-item";
      added.innerHTML = '<p>New nested reply</p><img alt="reply media" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==">';
      if (shouldUpdateTotal && !shouldUpdateTotalAfterItems) {
        document.querySelector(".comment-total").textContent = "Comments: 2";
        if (shouldSeparateTotalUpdate) {
          await new Promise((resolve) => setTimeout(resolve, 0));
        }
      }
      const insertionRoot = shouldUseNestedMount
        ? resolution.roles.comments.querySelector(".thread-mount")
        : resolution.roles.comments;
      insertionRoot.appendChild(added);
      await new Promise((resolve) => setTimeout(resolve, 0));
      if (shouldUpdateTotal && shouldUpdateTotalAfterItems) {
        document.querySelector(".comment-total").textContent = "Comments: 2";
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
      if (shouldExerciseControls) {
        originalDetails.querySelector("summary").click();
        await new Promise((resolve) => setTimeout(resolve, 0));
        originalDetails.querySelector("summary").click();
        await new Promise((resolve) => setTimeout(resolve, 0));
        originalControl.click();
        await new Promise((resolve) => setTimeout(resolve, 0));
        const popular = document.createElement("aside");
        popular.className = "popular";
        popular.id = "unrelated-popular";
        popular.textContent = "Popular unrelated posts";
        document.querySelector("#page").appendChild(popular);
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
      const visible = (element) => Boolean(element) &&
        getComputedStyle(element).display !== "none" &&
        getComputedStyle(element).visibility !== "hidden" &&
        element.getClientRects().length > 0;
      const additionState = {
        terminalReason: runtime.terminalReason,
        role: added.getAttribute("data-hotdeal-focus-role"),
        addedKept: added.hasAttribute("data-hotdeal-focus-keep"),
        mediaKept: added.querySelector("img")?.hasAttribute("data-hotdeal-focus-keep") === true,
        initialPreserved: initial.isConnected && initial === document.querySelector("#initial-comment"),
        initialIdentityPreserved: initial === initialIdentity,
        initialText: initial.textContent,
        itemCount: document.querySelectorAll(".exact-comments .comment-item").length,
        nestedMountKept: insertionRoot.hasAttribute("data-hotdeal-focus-keep"),
        bodyIdentityPreserved: originalBody === document.querySelector(".exact-body"),
        bodyTextPreserved: originalBody.textContent === originalBodyText,
        bodyVisible: visible(originalBody),
        commentVisible: visible(initial),
        imagePreserved: !shouldExerciseControls || (
          originalImage === document.querySelector("#body-image") &&
          originalImage.naturalWidth > 0 && visible(originalImage)
        ),
        linkPreserved: !shouldExerciseControls || (
          originalLink === document.querySelector("#body-link") &&
          originalLink.href === "https://example.com/product" && visible(originalLink)
        ),
        detailsPreserved: !shouldExerciseControls || (
          originalDetails === document.querySelector("#body-details") &&
          originalDetails.open && visible(originalDetails.querySelector("p"))
        ),
        moreControlPreserved: !shouldExerciseControls || (
          originalControl === document.querySelector(".comment-control") &&
          visible(originalControl) && visible(document.querySelector("#loaded-more-comment")) &&
          document.querySelector("#loaded-more-comment").hasAttribute("data-hotdeal-focus-keep")
        ),
        popularHidden: !shouldExerciseControls || !visible(document.querySelector("#unrelated-popular")),
      };
      if (shouldRemoveInitial && !runtime.terminallyBlocked) {
        initial.remove();
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
      return {
        setup: { ok: true },
        ...additionState,
        terminalAfterRemoval: runtime.terminalReason,
      };
    },
    {
      source: `${preauthorizedOracleStyleControlSource}\n${userscriptSource}`,
      suppliedLayout: exactLayout({
        commentItems: nestedMount
          ? [".exact-comments .comment-item"]
          : [".exact-comments > .comment-item"],
      }),
      seedTitle: title,
      shouldUpdateTotal: updateExactTotal,
      shouldSeparateTotalUpdate: separateExactTotalUpdate,
      shouldUpdateTotalAfterItems: totalUpdateAfterItems,
      shouldExerciseControls: exerciseControls,
      shouldRemoveInitial: removeInitial,
      shouldUseNestedMount: nestedMount,
      shouldMutateInitial: mutateInitial,
    },
  );
}

async function exerciseExternalCommentImplementationRemoval(page) {
  await page.setContent(`<!doctype html><html><head>${metadata()}</head><body>
    <main id="page">
      <h1 class="exact-title">${title}</h1>
      <article class="exact-body">${longBody}</article>
      <section class="exact-comments" aria-label="Comments">
        <div class="comment-item" id="retained-comment">Retained visible comment</div>
      </section>
      <div id="external-comment-control-parent">
        <button class="external-comment-control">New comment</button>
        <iframe id="publisher-editor-bootstrap" class="cheditor-editarea"></iframe>
      </div>
    </main>
  </body></html>`);
  return page.evaluate(
    async ({ source, suppliedLayout, seedTitle }) => {
      const instrumentedSource = source.replace(
        /    discoverSemanticContract,\r?\n    start,/,
        "    discoverSemanticContract,\n    applyRoleMarkers,\n    installRuntimeGateStyle,\n    installIntegrityObserver,\n    start,",
      );
      if (instrumentedSource === source) {
        throw new Error("private export instrumentation failed");
      }
      const moduleRecord = { exports: {} };
      Object.defineProperty(globalThis, "module", {
        value: moduleRecord,
        configurable: true,
      });
      try {
        (0, eval)(instrumentedSource);
      } finally {
        delete globalThis.module;
      }
      const api = moduleRecord.exports;
      const resolution = api.resolveDocument(
        document,
        [suppliedLayout],
        { title: seedTitle, commentCount: 1 },
      );
      if (!resolution.ok) return { setup: resolution };
      const nonce = "external-comment-removal-fixture-nonce";
      const state = api.applyRoleMarkers(
        document,
        resolution.roles,
        resolution.commonRoot,
        resolution.resolvedTitle,
        resolution.requiredRoles,
        resolution.commentItemSelectors,
        resolution.commentControlSelectors,
        resolution.commentIgnoredSelectors,
        resolution.projectionPolicy,
        nonce,
      );
      const comment = document.querySelector("#retained-comment");
      const control = document.querySelector(".external-comment-control");
      const editor = document.querySelector("#publisher-editor-bootstrap");
      const commentIdentity = comment;
      const controlIdentity = control;
      const editorInitiallyOwned =
        editor.hasAttribute("data-hotdeal-focus-keep");
      const runtime = {
        terminallyBlocked: false,
        terminalReason: null,
        authorizedReady: true,
        releasePhase: "released",
        projectionPublishCount: 0,
        relockForReprojection() { return false; },
        publishReadyProjectionDiagnostics() {
          this.projectionPublishCount += 1;
          return true;
        },
        enterTerminal(reason) {
          this.terminallyBlocked = true;
          this.terminalReason = reason;
        },
      };
      const gateStyle = api.installRuntimeGateStyle(document);
      gateStyle.textContent = api.gateStyleText(nonce);
      document.documentElement.removeAttribute("data-hotdeal-focus-lock");
      document.documentElement.classList.add("hdf-v2-ready");
      document.documentElement.setAttribute("data-hotdeal-focus-ready", "1");
      document.documentElement.setAttribute(
        "data-hotdeal-focus-protocol",
        api.PROTOCOL_VERSION,
      );
      document.documentElement.setAttribute("data-hotdeal-focus-state", "ready");
      document.documentElement.setAttribute("data-hotdeal-focus-status", "ready");
      api.installIntegrityObserver(window, runtime, state, gateStyle);

      editor.remove();
      await new Promise((resolve) => setTimeout(resolve, 0));
      const visible = (element) => {
        const style = getComputedStyle(element);
        return style.display !== "none" &&
          style.visibility !== "hidden" &&
          element.getClientRects().length > 0;
      };
      return {
        setup: { ok: true },
        editorInitiallyOwned,
        editorRemoved: !document.querySelector("#publisher-editor-bootstrap"),
        terminalReason: runtime.terminalReason,
        projectionPublishCount: runtime.projectionPublishCount,
        projectionEpoch: state.projectionEpoch,
        commentIdentityPreserved:
          comment === commentIdentity && comment.isConnected,
        controlIdentityPreserved:
          control === controlIdentity && control.isConnected,
        commentVisible: visible(comment),
        controlVisible: visible(control),
        commentText: comment.textContent,
        controlText: control.textContent,
      };
    },
    {
      source: `${preauthorizedOracleStyleControlSource}\n${userscriptSource}`,
      suppliedLayout: exactLayout({
        commentControls: [
          "#external-comment-control-parent > .external-comment-control",
        ],
      }),
      seedTitle: title,
    },
  );
}

async function exerciseDynamicCommentControlReplacement(page, {
  injectPopularNoise = false,
} = {}) {
  await page.setContent(`<!doctype html><html><head>${metadata()}</head><body>
    <main id="page">
      <h1 class="exact-title">${title}</h1>
      <article class="exact-body">${longBody}</article>
      <section class="exact-comments" aria-label="Comments">
        <div class="comment-item" id="retained-dynamic-comment">
          Retained visible comment
        </div>
      </section>
      <div id="external-comment-control-parent">
        <div id="comment_paging_area">
          <div id="initial-page-control"><a href="#page-1">1</a></div>
        </div>
      </div>
    </main>
  </body></html>`);
  return page.evaluate(
    async ({ source, suppliedLayout, seedTitle, shouldInjectPopularNoise }) => {
      const instrumentedSource = source.replace(
        /    discoverSemanticContract,\r?\n    start,/,
        "    discoverSemanticContract,\n    applyRoleMarkers,\n" +
          "    verifyOwnedMarkerState,\n    verifyOwnedState,\n" +
          "    currentCommentControlProjection,\n" +
          "    projectionHasPublisherPaintRiskWithPublisherStyles,\n" +
          "    deriveCommentProjectionRoots,\n" +
          "    hasUnclassifiedCommentContent,\n" +
          "    commentProjectionHasRisk,\n" +
          "    installRuntimeGateStyle,\n    installIntegrityObserver,\n    start,",
      );
      if (instrumentedSource === source) {
        throw new Error("private export instrumentation failed");
      }
      const moduleRecord = { exports: {} };
      Object.defineProperty(globalThis, "module", {
        value: moduleRecord,
        configurable: true,
      });
      try {
        (0, eval)(instrumentedSource);
      } finally {
        delete globalThis.module;
      }
      const api = moduleRecord.exports;
      const resolution = api.resolveDocument(
        document,
        [suppliedLayout],
        { title: seedTitle, commentCount: 1 },
      );
      if (!resolution.ok) return { setup: resolution };
      const nonce = "dynamic-comment-control-replacement-nonce";
      const state = api.applyRoleMarkers(
        document,
        resolution.roles,
        resolution.commonRoot,
        resolution.resolvedTitle,
        resolution.requiredRoles,
        resolution.commentItemSelectors,
        resolution.commentControlSelectors,
        resolution.commentIgnoredSelectors,
        resolution.projectionPolicy,
        nonce,
      );
      const comment = document.querySelector("#retained-dynamic-comment");
      const control = document.querySelector("#comment_paging_area");
      const commentIdentity = comment;
      const controlIdentity = control;
      const runtime = {
        terminallyBlocked: false,
        terminalReason: null,
        authorizedReady: true,
        releasePhase: "released",
        projectionPublishCount: 0,
        relockForReprojection() { return false; },
        publishReadyProjectionDiagnostics() {
          this.projectionPublishCount += 1;
          return true;
        },
        enterTerminal(reason) {
          this.terminallyBlocked = true;
          this.terminalReason = reason;
        },
      };
      const gateStyle = api.installRuntimeGateStyle(document);
      gateStyle.textContent = api.gateStyleText(nonce);
      document.documentElement.removeAttribute("data-hotdeal-focus-lock");
      document.documentElement.classList.add("hdf-v2-ready");
      document.documentElement.setAttribute("data-hotdeal-focus-ready", "1");
      document.documentElement.setAttribute(
        "data-hotdeal-focus-protocol",
        api.PROTOCOL_VERSION,
      );
      document.documentElement.setAttribute("data-hotdeal-focus-state", "ready");
      document.documentElement.setAttribute("data-hotdeal-focus-status", "ready");
      api.installIntegrityObserver(window, runtime, state, gateStyle);

      control.innerHTML = shouldInjectPopularNoise
        ? '<div class="popular"><a href="/popular">인기글</a></div>'
        : `<link rel="stylesheet" href="data:text/css,">
           <div id="page_down"><div id="page"><table><tbody><tr>
             <td id="page_list"><a href="#page-2">2</a></td>
           </tr></tbody></table></div></div>`;
      await new Promise((resolve) => setTimeout(resolve, 0));
      const descendants = Array.from(control.querySelectorAll("*"));
      const currentProjection = api.deriveCommentProjectionRoots(
        state.roles.comments,
        state.commentControlScope,
        state.commentItemSelectors,
        state.commentControlSelectors,
        state.commentIgnoredSelectors,
        state.commentControlRoots,
      );
      const visible = (element) => {
        const style = getComputedStyle(element);
        return style.display !== "none" &&
          style.visibility !== "hidden" &&
          element.getClientRects().length > 0;
      };
      return {
        setup: { ok: true },
        terminalReason: runtime.terminalReason,
        projectionPublishCount: runtime.projectionPublishCount,
        projectionEpoch: state.projectionEpoch,
        commentIdentityPreserved:
          comment === commentIdentity && comment.isConnected,
        controlIdentityPreserved:
          control === controlIdentity && control.isConnected,
        commentText: comment.textContent.trim(),
        commentVisible: visible(comment),
        controlVisible: visible(control),
        descendantCount: descendants.length,
        allDescendantsOwned: descendants.every(
          (element) =>
            element.getAttribute("data-hotdeal-focus-keep") === nonce &&
            element.getAttribute("data-hotdeal-focus-deep") === "comment-control",
        ),
        popularVisible:
          Boolean(control.querySelector(".popular")) &&
          visible(control.querySelector(".popular")),
        markerStateValid: api.verifyOwnedMarkerState(document, state),
        ownedStateValid: api.verifyOwnedState(document, state),
        controlProjection: api.currentCommentControlProjection(state),
        projectionPaintRisk:
          api.projectionHasPublisherPaintRiskWithPublisherStyles(state),
        commentProjectionOk: currentProjection.ok,
        currentItemCount: currentProjection.ok
          ? currentProjection.commentItems.length
          : -1,
        currentControlCount: currentProjection.ok
          ? currentProjection.commentControls.length
          : -1,
        currentIgnoredCount: currentProjection.ok
          ? currentProjection.commentIgnored.length
          : -1,
        unclassifiedCommentContent: currentProjection.ok
          ? api.hasUnclassifiedCommentContent(
              state.roles.comments,
              currentProjection.commentItems.concat(
                currentProjection.commentControls,
                currentProjection.commentIgnored,
              ),
            )
          : true,
        directCommentRisk: currentProjection.ok
          ? api.commentProjectionHasRisk(
              state.roles.comments,
              currentProjection.commentItems,
              currentProjection.commentControls,
              currentProjection.commentIgnored,
              false,
              state.commentControlScope,
            )
          : true,
      };
    },
    {
      source: `${preauthorizedOracleStyleControlSource}\n${userscriptSource}`,
      suppliedLayout: exactLayout({
        commentControls: [
          "#external-comment-control-parent > #comment_paging_area",
        ],
      }),
      seedTitle: title,
      shouldInjectPopularNoise: injectPopularNoise,
    },
  );
}

async function exerciseMobileResponsiveProjection(page) {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.setContent(`<!doctype html><html><head></head><body>
    <div id="main" style="width:1389px;min-width:1389px;margin-right:-1014px">
      <div id="news" style="width:1159px;min-width:1159px;margin-right:230px">
        <div class="row" style="display:flex;width:1159px">
          <div class="subtop_center_w" style="width:1024px">
            <div id="board" style="width:1024px">
              <main id="board_read" style="display:inline-block;width:1024px">
                <h1 id="responsive-title"
                    style="display:inline;white-space:nowrap;width:426px">${title}</h1>
                <article id="responsive-body"
                    style="width:962px;margin-left:30px;margin-right:30px">
                  <div id="responsive-body-text">${longBody}</div>
                </article>
                <aside id="responsive-product"
                    style="width:400px;margin-left:15px;margin-right:15px">
                  Original product information
                </aside>
                <section id="responsive-comments" style="width:1024px"></section>
              </main>
            </div>
          </div>
        </div>
      </div>
    </div>
  </body></html>`);
  const result = await page.evaluate(
    ({ source, expectedTitle }) => {
      const moduleRecord = { exports: {} };
      Object.defineProperty(globalThis, "module", {
        configurable: true,
        value: moduleRecord,
      });
      try {
        (0, eval)(source);
      } finally {
        delete globalThis.module;
      }
      const api = moduleRecord.exports;
      const nonce = "responsive-fixture-nonce";
      const keep = "hdf-v2-keep";
      const shell = "hdf-v2-shell";
      const deep = "hdf-v2-deep";
      const markShell = (element) => {
        element.classList.add(keep, shell);
        element.setAttribute("data-hotdeal-focus-keep", nonce);
        element.setAttribute("data-hotdeal-focus-shell", nonce);
      };
      document.querySelectorAll("#main, #news, .row, .subtop_center_w, #board, #board_read")
        .forEach(markShell);
      const markRole = (selector, role, isDeep = false) => {
        const element = document.querySelector(selector);
        element.classList.add(keep, `hdf-v2-role-${role}`);
        element.setAttribute("data-hotdeal-focus-keep", nonce);
        element.setAttribute("data-hotdeal-focus-role", role);
        if (isDeep) {
          element.classList.add(deep);
          element.setAttribute("data-hotdeal-focus-deep", role);
        }
        return element;
      };
      const titleNode = markRole("#responsive-title", "title");
      const bodyNode = markRole("#responsive-body", "body", true);
      const bodyText = document.querySelector("#responsive-body-text");
      bodyText.classList.add(keep, deep);
      bodyText.setAttribute("data-hotdeal-focus-keep", nonce);
      bodyText.setAttribute("data-hotdeal-focus-deep", "body");
      const productNode = markRole("#responsive-product", "product", true);
      const commentsNode = markRole("#responsive-comments", "comments");
      markShell(commentsNode);
      document.documentElement.classList.add("hdf-v2-ready");
      document.documentElement.setAttribute("data-hotdeal-focus-ready", "1");
      document.documentElement.setAttribute("data-hotdeal-focus-protocol", api.PROTOCOL_VERSION);
      document.documentElement.setAttribute("data-hotdeal-focus-state", "ready");
      document.documentElement.setAttribute("data-hotdeal-focus-status", "ready");
      const style = document.createElement("style");
      style.textContent = api.gateStyleText(nonce);
      document.head.appendChild(style);
      const rect = (node) => {
        const value = node.getBoundingClientRect();
        return { left: value.left, right: value.right, width: value.width };
      };
      return {
        viewport: document.documentElement.clientWidth,
        scrollWidth: document.documentElement.scrollWidth,
        title: rect(titleNode),
        body: rect(bodyNode),
        product: rect(productNode),
        comments: rect(commentsNode),
        identitiesPreserved:
          titleNode === document.querySelector("#responsive-title") &&
          bodyNode === document.querySelector("#responsive-body") &&
          productNode === document.querySelector("#responsive-product") &&
          commentsNode === document.querySelector("#responsive-comments"),
        textPreserved: titleNode.textContent === expectedTitle &&
          productNode.textContent.trim() === "Original product information",
      };
    },
    { source: userscriptSource, expectedTitle: title },
  );
  await page.setViewportSize({ width: 1280, height: 720 });
  return result;
}

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();

  const responsiveProjection = await exerciseMobileResponsiveProjection(page);
  assert.equal(responsiveProjection.identitiesPreserved, true);
  assert.equal(responsiveProjection.textPreserved, true);
  assert.ok(
    responsiveProjection.scrollWidth <= responsiveProjection.viewport,
    JSON.stringify(responsiveProjection),
  );
  ["title", "body", "product", "comments"].forEach((role) => {
    assert.ok(responsiveProjection[role].left >= 0, JSON.stringify(responsiveProjection));
    assert.ok(
      responsiveProjection[role].right <= responsiveProjection.viewport,
      JSON.stringify(responsiveProjection),
    );
  });

  const nestedTitle = await evaluate(
    page,
    `<main><section class="deal">
      <div class="title-wrap" role="heading"><h1 class="deal-title">${title}</h1></div>
      <article class="story-body">${longBody}</article>
      ${populatedComments()}
    </section></main>`,
    layout(),
    2,
  );
  assert.deepEqual(nestedTitle, {
    ok: true,
    reason: "unique-complete-projection-tuple",
    projectionTupleCount: 1,
    roles: { title: "deal-title", body: "story-body", comments: "comments" },
  });

  const duplicateDeal = (suffix) => `<section class="deal deal-${suffix}">
    <h1 class="deal-title">${title}</h1>
    <article class="story-body">${longBody}</article>
    <div class="comments" aria-label="Comments" style="min-height:1px"></div>
  </section>`;
  const disconnectedDuplicates = await evaluate(
    page,
    `<main>${duplicateDeal("one")}${duplicateDeal("two")}</main>`,
    layout(),
    0,
  );
  assert.equal(disconnectedDuplicates.ok, false);
  assert.equal(disconnectedDuplicates.reason, "ambiguous-disconnected-projections");
  assert.equal(disconnectedDuplicates.projectionTupleCount, 2);

  const ambiguousBodies = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}</article>
      <article class="story-body">${longBody}</article>
      ${populatedComments()}
    </main>`,
    layout(),
    2,
  );
  assert.equal(ambiguousBodies.ok, false);
  assert.equal(ambiguousBodies.reason, "ambiguous-projection-tuples");
  assert.equal(ambiguousBodies.projectionTupleCount, 2);

  const minimalBody = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <article class="article-shell">
        <div class="story-body">${longBody}</div>
        ${populatedComments()}
      </article>
    </main>`,
    layout({ bodyHints: [".article-shell", ".story-body"] }),
    2,
  );
  assert.equal(minimalBody.ok, true);
  assert.equal(minimalBody.roles.body, "story-body");
  assert.equal(minimalBody.roles.comments, "comments");

  const withRequiredProduct = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <table class="purchase" itemprop="offers"><tbody><tr>
        <td>Price $99</td><td><a href="https://shop.example/buy">Buy product</a></td>
      </tr></tbody></table>
      <article class="story-body">${longBody}</article>
      ${populatedComments()}
    </main>`,
    layout({ product: "required" }),
    2,
  );
  assert.equal(withRequiredProduct.ok, true);
  assert.equal(withRequiredProduct.roles.product, "purchase");

  const ppomppuNestedSourceAndOpaqueCommentMount = await evaluate(
    page,
    `<main><h4 class="deal-title">${title}<sup><span class="reply-badge">2</span></sup>
      <div class="article-info">Writer<br>링크 :
        <a class="source-link" href="https://shop.example/deal">shop.example/deal</a>
      </div></h4>
      <article class="story-body">${longBody}</article>
      <section id="cmAr"><div id="comment-list">
        <div class="comment-row">First complete response</div>
        <div class="comment-row">Second complete response</div>
      </div></section></main>`,
    layout({
      product: "required",
      productHints: [".source-link"],
      commentHints: ["#cmAr"],
      commentItems: ["#comment-list > .comment-row"],
      commentControls: [],
    }),
    2,
  );
  assert.equal(ppomppuNestedSourceAndOpaqueCommentMount.ok, true);
  assert.equal(ppomppuNestedSourceAndOpaqueCommentMount.roles.product, "source-link");
  assert.equal(ppomppuNestedSourceAndOpaqueCommentMount.roles.comments, "cmAr");

  const pageRootScopedProductProposal = await evaluatePolicyProposal(
    page,
    `<main id="page"><h1 class="deal-title">${title}</h1>
      <div>링크 : <a class="noeffect" href="https://shop.example/deal">shop.example/deal</a></div>
      <article class="story-body">${longBody}</article>${populatedComments()}</main>
      <aside><a class="noeffect" href="https://unrelated.example/">Unrelated link</a></aside>`,
    layout({ product: "required", productHints: [".noeffect"] }),
    2,
  );
  assert.equal(pageRootScopedProductProposal.ok, true);
  assert.equal(pageRootScopedProductProposal.policyProposal.complete, true);
  assert.deepEqual(pageRootScopedProductProposal.policyProposal.product.selectors, [
    "#page .noeffect",
  ]);

  const pageRootScopedProductCollisionIsIncomplete = await evaluatePolicyProposal(
    page,
    `<main id="page"><h1 class="deal-title">${title}</h1>
      <div class="source-box">링크 : <a class="noeffect" href="https://shop.example/deal">shop.example/deal</a></div>
      <article class="story-body">${longBody}</article>${populatedComments()}
      <div class="source-box"><a class="noeffect" href="https://unrelated.example/">Unrelated link</a></div></main>`,
    layout({ product: "required", productHints: [".noeffect"] }),
    2,
  );
  assert.equal(pageRootScopedProductCollisionIsIncomplete.ok, true);
  assert.equal(pageRootScopedProductCollisionIsIncomplete.policyProposal.complete, false);
  assert.deepEqual(
    pageRootScopedProductCollisionIsIncomplete.policyProposal.product.selectors,
    [],
  );

  const ruliProductAfterBody = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}</article>
      <div class="purchase" itemprop="offers">Price 49,500원
        <a href="https://shop.example/buy">예약 구매</a></div>
      ${populatedComments()}
    </main>`,
    layout({ product: "required", productOrder: "after-body" }),
    2,
  );
  assert.equal(ruliProductAfterBody.ok, true);
  assert.equal(ruliProductAfterBody.roles.product, "purchase");

  const ruliProductBeforeBodyDrift = await evaluatePolicyProposal(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <div class="purchase" itemprop="offers">Price 49,500원
        <a href="https://shop.example/buy">예약 구매</a></div>
      <article class="story-body">${longBody}</article>
      ${populatedComments()}
    </main>`,
    layout({ product: "required", productOrder: "after-body" }),
    2,
  );
  assert.equal(ruliProductBeforeBodyDrift.ok, true);
  assert.equal(ruliProductBeforeBodyDrift.existingPolicy.compatible, false);
  assert.equal(ruliProductBeforeBodyDrift.policyProposal.product.cardinality, "required");
  assert.equal(ruliProductBeforeBodyDrift.policyProposal.product.order, "before-body");

  const ruliProductAfterCommentsRejected = await evaluatePolicyProposal(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}</article>
      ${populatedComments()}
      <div class="purchase" itemprop="offers">Price 49,500원
        <a href="https://shop.example/buy">예약 구매</a></div>
    </main>`,
    layout({ product: "required", productOrder: "after-body" }),
    2,
  );
  assert.equal(ruliProductAfterCommentsRejected.ok, true);
  assert.equal(ruliProductAfterCommentsRejected.existingPolicy.compatible, false);
  assert.equal(ruliProductAfterCommentsRejected.policyProposal.product.cardinality, "zero");

  const missingRequiredProduct = await evaluatePolicyProposal(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}</article>
      ${populatedComments()}
    </main>`,
    layout({ product: "required" }),
    2,
  );
  assert.equal(missingRequiredProduct.ok, true);
  assert.equal(missingRequiredProduct.existingPolicy.compatible, false);
  assert.equal(missingRequiredProduct.policyProposal.product.cardinality, "zero");
  assert.equal(missingRequiredProduct.policyProposal.product.order, null);

  const unexpectedProductFromZeroPolicy = await evaluatePolicyProposal(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <div class="purchase" itemprop="offers">Price $99
        <a href="https://shop.example/buy">Buy product</a></div>
      <article class="story-body">${longBody}</article>
      ${populatedComments()}
    </main>`,
    layout({ product: "zero" }),
    2,
  );
  assert.equal(unexpectedProductFromZeroPolicy.ok, true);
  assert.equal(unexpectedProductFromZeroPolicy.existingPolicy.compatible, false);
  assert.equal(unexpectedProductFromZeroPolicy.policyProposal.product.cardinality, "required");
  assert.equal(unexpectedProductFromZeroPolicy.policyProposal.product.order, "before-body");

  const zeroComments = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}</article>
      <section class="comment-shell"><div id="comments" aria-label="Comments" style="min-height:1px"></div></section>
    </main>`,
    layout({ commentHints: [".comment-shell", "#comments"] }),
    0,
  );
  assert.equal(zeroComments.ok, true);
  assert.equal(zeroComments.roles.comments, "comments");

  const staleZeroSeedAllowsObservedComments = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}</article>${populatedComments()}</main>`,
    layout(),
    0,
  );
  assert.equal(staleZeroSeedAllowsObservedComments.ok, true);

  const visibleZeroIsExactForStableEmptyComments = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}</article>
      <section class="comment-shell"><div>Comments | total 0</div>
        <div id="comments" aria-label="Comments" style="min-height:1px"></div>
      </section></main>`,
    layout({
      commentHints: ["#comments"],
      commentItems: ["#comments > .comment-item"],
    }),
    null,
  );
  assert.equal(visibleZeroIsExactForStableEmptyComments.ok, true);

  const visibleZeroRejectsObservedComment = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}</article>
      <section class="comment-shell"><div>Comments | total 0</div>
        <div id="comments" aria-label="Comments">
          <div class="comment-item">Contradicting visible comment</div>
        </div>
      </section></main>`,
    layout({
      commentHints: ["#comments"],
      commentItems: ["#comments > .comment-item"],
    }),
    null,
  );
  assert.equal(visibleZeroRejectsObservedComment.ok, false);
  assert.equal(visibleZeroRejectsObservedComment.reason, "no-complete-projection-tuple");

  const incompleteCommentMount = await evaluate(
    page,
    `<main><section class="deal"><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}</article>
      <div class="comments"><div class="comment-item" itemprop="comment">First</div></div>
      <div class="escaped-comment" itemprop="comment">Escaped second comment</div>
    </section></main>`,
    layout(),
    2,
  );
  assert.equal(incompleteCommentMount.ok, false);
  assert.equal(incompleteCommentMount.reason, "no-complete-projection-tuple");

  const noisyBody = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <article class="story-body">
        ${longBody}<aside class="sponsor-banner">Sponsored recommendation</aside>
      </article>
      ${populatedComments()}
    </main>`,
    layout(),
    2,
  );
  assert.equal(noisyBody.ok, true);

  const authoredMediaAndWords = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}
        <header class="header"><p>Authored introduction for this deal.</p></header>
        <section class="related"><p>Popular recommendations are words in the article, not page chrome.</p></section>
        <img class="banner" alt="Product dimensions" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==">
      </article>
      ${populatedComments()}
    </main>`,
    layout(),
    2,
  );
  assert.equal(authoredMediaAndWords.ok, true);

  for (const structuralTag of ["aside", "nav", "footer"]) {
    const structuralNoise = await evaluate(
      page,
      `<main><h1 class="deal-title">${title}</h1>
        <article class="story-body">${longBody}<${structuralTag}>Site chrome</${structuralTag}></article>
        ${populatedComments()}
      </main>`,
      layout(),
      2,
    );
    assert.equal(
      structuralNoise.ok,
      true,
      `bare ${structuralTag} must be isolated without rejecting the article`,
    );
  }

  const recommendationContainer = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}<div class="recommendation">Other deal</div></article>
      ${populatedComments()}
    </main>`,
    layout(),
    2,
  );
  assert.equal(recommendationContainer.ok, true);

  const noisyProduct = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <table class="purchase" itemprop="offers"><tbody><tr><td>Price $99</td></tr></tbody>
        <tfoot><tr><td><nav>Popular store links</nav></td></tr></tfoot>
      </table>
      <article class="story-body">${longBody}</article>
      ${populatedComments()}
    </main>`,
    layout({ product: "required" }),
    2,
  );
  assert.equal(noisyProduct.ok, true);

  const policyDriftHtml = `<main id="page">
    <h1 class="exact-title">${title}</h1>
    <article class="exact-body">${longBody}
      <aside class="ad-slot">Sponsored advertisement</aside>
    </article>
    <div class="exact-product" itemprop="offers">Price 49,500원
      <a href="https://shop.example/buy">예약 구매</a>
      <span class="affiliate-badge">Affiliate promotion</span>
    </div>
    <section class="exact-comments" aria-label="Comments">
      <div class="comment-item" itemprop="comment">Visible comment</div>
      <footer class="related-footer">Sponsored related content</footer>
    </section>
  </main>`;
  const resilientExactPolicy = await evaluateExact(
    page,
    policyDriftHtml,
    exactLayout({ product: "required", productOrder: "after-body" }),
    1,
  );
  assert.equal(resilientExactPolicy.ok, true, JSON.stringify(resilientExactPolicy));
  assert.equal(resilientExactPolicy.bodyIgnoredCount, 1);
  assert.equal(resilientExactPolicy.productIgnoredCount, 1);
  assert.equal(resilientExactPolicy.commentIgnoredCount, 1);

  const independentPolicyProposal = await evaluatePolicyProposal(
    page,
    policyDriftHtml,
    exactLayout({ product: "required", productOrder: "after-body" }),
    1,
  );
  assert.equal(independentPolicyProposal.ok, true);
  assert.equal(independentPolicyProposal.policyProposal.complete, true);
  assert.equal(independentPolicyProposal.policyProposal.pageRoot, "#page");
  assert.equal(
    independentPolicyProposal.policyProposal.pageRootEvidence,
    "all-role-lowest-common-ancestor",
  );
  assert.equal(independentPolicyProposal.policyProposal.product.cardinality, "required");
  assert.equal(independentPolicyProposal.policyProposal.product.order, "after-body");
  assert.deepEqual(independentPolicyProposal.policyProposal.product.selectors, [
    ".exact-product",
  ]);
  assert.deepEqual(independentPolicyProposal.policyProposal.bodyIgnored, [".ad-slot"]);
  assert.deepEqual(independentPolicyProposal.policyProposal.productIgnored, [
    ".affiliate-badge",
  ]);
  assert.deepEqual(independentPolicyProposal.policyProposal.commentIgnored, [
    ".related-footer",
  ]);
  assert.equal(
    independentPolicyProposal.policyProposal.promotionGate.requiredDistinctUrlsPerProfile,
    3,
  );
  assert.equal(
    independentPolicyProposal.policyProposal.promotionGate.requiredProfilesSource,
    "auditor-layout-contract",
  );
  assert.equal(independentPolicyProposal.policyProposal.promotionGate.promotable, false);
  assert.match(
    independentPolicyProposal.policyProposal.shapeFingerprint,
    /^projection-policy-v1-[0-9a-f]{8}$/,
  );

  const uniqueStableAncestorProposal = await evaluatePolicyProposal(
    page,
    `<div id="board_read"><section class="content_wrapper">
      <h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}</article>
      ${populatedComments()}
    </section></div><section class="content_wrapper"></section>`,
    layout(),
    2,
  );
  assert.equal(uniqueStableAncestorProposal.ok, true);
  assert.equal(uniqueStableAncestorProposal.policyProposal.complete, true);
  assert.equal(uniqueStableAncestorProposal.policyProposal.pageRoot, "#board_read");
  assert.equal(
    uniqueStableAncestorProposal.policyProposal.pageRootEvidence,
    "nearest-unique-stable-all-role-ancestor",
  );

  const unsafeIgnoredPurchase = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}
        <aside class="sponsor-banner"><a href="https://shop.example/buy">
          49,500원 상품 구매</a></aside>
      </article>
      ${populatedComments()}
    </main>`,
    layout(),
    2,
  );
  assert.equal(
    unsafeIgnoredPurchase.ok,
    true,
    "publisher sponsor surfaces remain noise even when they contain a purchase link",
  );

  const productLeafMedia = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <table class="purchase" itemprop="offers"><tbody><tr>
        <td>Price $99</td><td><a href="https://shop.example/buy">Buy product</a>
        <img class="banner" alt="Product image" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw=="></td>
      </tr></tbody></table>
      <article class="story-body">${longBody}</article>
      ${populatedComments()}
    </main>`,
    layout({ product: "required" }),
    2,
  );
  assert.equal(productLeafMedia.ok, true);

  const eomisaeLayout = layout({
    commentHints: ["#C_"],
    commentItems: ["#C_ > ._bd > ._comment[id^='comment_']"],
    commentControls: [
      "#C_ > #comment",
      "#C_ > ._bd .pagination",
      "#C_ > ._bd .more",
      "#C_ > ._bd .reply",
    ],
    commentIgnored: ["#C_ > ._hd._hdc", "#C_ > center", "#C_ > ._ft"],
  });
  const eomisaeCommentShell = (item = "") => `<section id="C_" aria-label="Comments">
    <header class="_hd _hdc">Comments</header>
    <div class="_bd">${item}<button class="reply">Reply</button><div class="pagination">1</div></div>
    <div id="comment">Write a comment</div><center>Guidance</center><div class="_ft">Footer note</div>
  </section>`;
  const realisticZero = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}</article>${eomisaeCommentShell()}
    </main>`,
    eomisaeLayout,
    0,
  );
  assert.equal(realisticZero.ok, true);
  assert.equal(realisticZero.roles.comments, "C_");

  const exactDomObservedZero = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}</article>${eomisaeCommentShell()}
    </main>`,
    eomisaeLayout,
    null,
  );
  assert.equal(exactDomObservedZero.ok, true);

  const staleZeroEomisaeSeedAllowsNewComment = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}</article>${eomisaeCommentShell(
        '<div class="_comment" id="comment_1">Unexpected comment</div>',
      )}
    </main>`,
    eomisaeLayout,
    0,
  );
  assert.equal(staleZeroEomisaeSeedAllowsNewComment.ok, true);

  const manyNeutralDivs = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      ${Array.from({ length: 1000 }, (_, index) => `<div class="decoration-${index}"></div>`).join("")}
      <article class="story-body">${longBody}</article>${populatedComments()}
    </main>`,
    layout(),
    2,
  );
  assert.equal(manyNeutralDivs.ok, true);

  const qualifiedBodyOverflow = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      ${Array.from({ length: 33 }, () => `<article class="bounded-body">${longBody}</article>`).join("")}
      ${populatedComments()}
    </main>`,
    layout({ bodyHints: [".bounded-body"] }),
    2,
  );
  assert.equal(qualifiedBodyOverflow.ok, false);
  assert.equal(qualifiedBodyOverflow.reason, "body-candidate-bound");

  const injectedHintOverflow = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      ${Array.from({ length: 5000 }, () => '<div class="injected-body"></div>').join("")}
      <article>${longBody}</article>${populatedComments()}
    </main>`,
    layout({ bodyHints: [".injected-body"] }),
    2,
  );
  assert.equal(injectedHintOverflow.ok, false);
  assert.equal(injectedHintOverflow.reason, "body-candidate-bound");

  const commentEvidenceOverflow = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}</article>
      <ul class="comments" aria-label="Comments">
        ${Array.from({ length: 4097 }, () => '<li class="evidence-item">Comment evidence</li>').join("")}
      </ul>
    </main>`,
    layout({ commentItems: [".comments > .evidence-item"] }),
    4097,
  );
  assert.equal(commentEvidenceOverflow.ok, false);
  assert.equal(commentEvidenceOverflow.reason, "comment-evidence-bound");

  const inferredCommentEvidenceOverflow = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}</article>
      <ol class="comments" aria-label="Comments">
        ${Array.from({ length: 4097 }, () => '<li class="generic-entry">Repeated entry</li>').join("")}
      </ol>
    </main>`,
    layout(),
    4097,
  );
  assert.equal(inferredCommentEvidenceOverflow.ok, false);
  assert.equal(inferredCommentEvidenceOverflow.reason, "comment-evidence-bound");

  const hundredSemanticComments = await evaluate(
    page,
    `<main><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}</article>
      <section class="comments" aria-label="Comments">
        ${Array.from({ length: 100 }, (_, index) =>
          `<div class="comment-item" itemprop="comment">Complete comment ${index + 1}</div>`
        ).join("")}
      </section>
    </main>`,
    layout(),
    100,
  );
  assert.equal(hundredSemanticComments.ok, true);
  assert.equal(hundredSemanticComments.roles.comments, "comments");

  const zodCommentItems = Array.from({ length: 13 }, (_, index) =>
    `<div class="comment-item" itemprop="comment">Comment ${index + 1}
      <el-tooltip>Posted date ${index + 1}</el-tooltip></div>`
  ).join("");
  const zodNestedCommentMount = Array.from({ length: 40 }).reduce(
    (nested, index) => `<div class="comment-layer-${index}">${nested}</div>`,
    `<section id="app-board-comment-list" aria-label="Comments">${zodCommentItems}</section>`,
  );
  const zodCandidateOverflowRegression = await evaluate(
    page,
    `<main id="page"><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}</article>
      ${zodNestedCommentMount}
    </main>`,
    layout({
      product: "required",
      commentHints: ["#app-board-comment-list"],
      commentItems: ["#app-board-comment-list > .comment-item"],
    }),
    13,
  );
  assert.equal(zodCandidateOverflowRegression.ok, true);
  assert.equal(zodCandidateOverflowRegression.roles.comments, "app-board-comment-list");

  const ruliBody = Array.from({ length: 12 }).reduce(
    (nested, index) => `<section class="article-copy-${index}">${nested}</section>`,
    `<article class="view_content autolink">${longBody}</article>`,
  );
  const ruliProduct = Array.from({ length: 6 }).reduce(
    (nested, index) => `<div class="offer-source-${index}">${nested}</div>`,
    `<div class="source_url box_line_with_shadow">
      <a href="https://store.example/deal">Open source deal</a></div>`,
  );
  const ruliCommentItems = Array.from({ length: 19 }, (_, index) =>
    `<tr class="comment_element" itemprop="comment"><td>Comment ${index + 1}</td></tr>`
  ).join("");
  const ruliComments = Array.from({ length: 20 }).reduce(
    (nested, index) => `<div class="comment-shell-${index}">${nested}</div>`,
    `<section class="comment_view normal" aria-label="Comments">
      <table class="comment_table"><tbody>${ruliCommentItems}</tbody></table>
    </section>`,
  );
  const ruliLiveLayout = layout({
    product: "optional",
    productOrder: "after-body",
    productHints: [".source_url.box_line_with_shadow"],
    bodyHints: [".view_content.autolink"],
    commentHints: [".comment_view.normal"],
    commentItems: [
      ".comment_view.normal > table.comment_table > tbody > tr.comment_element",
    ],
  });
  const ruliAmbiguityRegression = await evaluatePolicyProposal(
    page,
    `<main id="page"><h1 class="deal-title">${title}</h1>
      <table class="board_list_table"><tbody><tr><td>Price $99</td></tr></tbody></table>
      ${ruliBody}${ruliProduct}${ruliComments}
    </main>`,
    ruliLiveLayout,
    19,
  );
  assert.equal(ruliAmbiguityRegression.ok, true);
  assert.equal(ruliAmbiguityRegression.policyProposal.complete, true);
  assert.equal(ruliAmbiguityRegression.policyProposal.pageRoot, "#page");
  assert.equal(ruliAmbiguityRegression.policyProposal.product.cardinality, "required");
  assert.equal(ruliAmbiguityRegression.policyProposal.product.order, "after-body");
  assert.deepEqual(ruliAmbiguityRegression.policyProposal.product.selectors, [
    ".box_line_with_shadow.source_url",
  ]);

  const ruliNestedMountLayout = exactLayout({
    commentHints: [".comment_view.normal", "#cmt.comment_wrapper"],
    commentItems: [
      ".comment_view.normal > table.comment_table > tbody > tr.comment_element",
    ],
    commentControls: [],
    commentIgnored: [
      "#cmt.comment_wrapper > input",
      "#cmt.comment_wrapper > .comment_count_wrapper",
      "#cmt.comment_wrapper > .comment_disable",
      "#cmt.comment_wrapper > br",
    ],
  });
  const ruliNestedMount = await evaluateExact(
    page,
    `<main id="page">
      <h1 class="exact-title">${title}</h1>
      <article class="exact-body">${longBody}</article>
      <section id="cmt" class="comment_wrapper">
        <input type="hidden" value="publisher state">
        <div class="comment_count_wrapper">Comments 1</div>
        <section class="comment_view normal">
          <table class="comment_table"><tbody>
            <tr class="comment_element" itemprop="comment"><td>Complete comment</td></tr>
          </tbody></table>
        </section>
      </section>
    </main>`,
    ruliNestedMountLayout,
    1,
  );
  assert.equal(ruliNestedMount.ok, true, JSON.stringify(ruliNestedMount));
  assert.equal(ruliNestedMount.commentMountIdentity, "comment_view normal");

  const ruliEmptyOuterMount = await evaluateExact(
    page,
    `<main id="page">
      <h1 class="exact-title">${title}</h1>
      <article class="exact-body">${longBody}</article>
      <section id="cmt" class="comment_wrapper">
        <input id="c_mpc" type="hidden" value="publisher state">
        <input class="comment_profile_image_enabled" type="hidden" value="1">
        <div class="comment_count_wrapper">댓글 | 총 0 개</div>
        <br><br>
        <div class="comment_disable">로그인이 필요합니다.</div>
        <br><br>
        <script>globalThis.__ruliEmptyCommentFixture = true;</script>
      </section>
    </main>`,
    ruliNestedMountLayout,
    0,
  );
  assert.equal(ruliEmptyOuterMount.ok, true, JSON.stringify(ruliEmptyOuterMount));
  assert.equal(ruliEmptyOuterMount.commentMountIdentity, "cmt");
  assert.equal(ruliEmptyOuterMount.commentIgnoredCount, 8);

  const eomisaePopularWidget = `<ul class="widget-list">
    ${Array.from({ length: 14 }, (_, index) =>
      `<li><a href="/popular/${index + 1}">Popular post ${index + 1}</a></li>`
    ).join("")}
  </ul>`;
  const eomisaeDriftLayout = layout({
    commentHints: [".stale-comments"],
    commentItems: [".stale-comments > .comment-item"],
  });
  const eomisaeZeroCommentRegression = await evaluate(
    page,
    `<main id="page"><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}</article>
      <section id="C_" aria-label="Comments" style="min-height:1px"></section>
      ${eomisaePopularWidget}
    </main>`,
    eomisaeDriftLayout,
    null,
  );
  assert.equal(eomisaeZeroCommentRegression.ok, true);
  assert.equal(eomisaeZeroCommentRegression.roles.comments, "C_");

  const genericPopularListIsNotComments = await evaluate(
    page,
    `<main id="page"><h1 class="deal-title">${title}</h1>
      <article class="story-body">${longBody}</article>${eomisaePopularWidget}
    </main>`,
    eomisaeDriftLayout,
    null,
  );
  assert.equal(genericPopularListIsNotComments.ok, false);
  assert.equal(genericPopularListIsNotComments.reason, "no-complete-projection-tuple");

  const seedBackedShallowTitleLeaf = await evaluate(
    page,
    `<main><div class="deal-title"><span class="sold-out">Sold out</span>
      <span>${title}</span><a class="comment-reply" href="#comments">3</a></div>
      <article class="story-body">${longBody}</article>${populatedComments()}</main>`,
    layout(),
    2,
  );
  assert.equal(seedBackedShallowTitleLeaf.ok, true);
  assert.equal(seedBackedShallowTitleLeaf.roles.title, "SPAN");

  const exactBaseline = await evaluateExact(page, exactPage(), exactLayout(), 1);
  assert.equal(exactBaseline.ok, true);

  const shortAuthoredRelatedSpecification = await evaluateExact(
    page,
    exactPage({ bodyExtra: '<section class="related">legitimate related specification</section>' }),
    exactLayout(),
    1,
  );
  assert.equal(shortAuthoredRelatedSpecification.ok, true);
  assert.equal(shortAuthoredRelatedSpecification.bodyIgnoredCount, 0);

  const replySetRevealPreservesLoadedComments = await evaluateExact(
    page,
    exactPage({
      commentsHtml: `<div class="comment-item">Visible comment</div>
        <button class="comment-control" aria-expanded="false">View 2 replies</button>`,
    }),
    exactLayout(),
    1,
  );
  assert.equal(replySetRevealPreservesLoadedComments.ok, true, JSON.stringify(replySetRevealPreservesLoadedComments));

  const moreCommentsPreserveLoadedComments = await evaluateExact(
    page,
    exactPage({
      commentsHtml: `<div class="comment-item">Visible comment</div>
        <button class="comment-control">Load more comments</button>`,
    }),
    exactLayout(),
    1,
  );
  assert.equal(moreCommentsPreserveLoadedComments.ok, true, JSON.stringify(moreCommentsPreserveLoadedComments));

  const shallowTitleIgnoresUnprojectedChrome = await evaluateExact(
    page,
    exactPage({
      titleHtml: `<h4 class="exact-title">${title}
        <a class="js_share" href="/share">Share</a>
        <div id="top_recommend_area">
          <a href="/other"><img class="recommend-banner" alt="Recommended post"></a>
        </div>
      </h4>`,
    }),
    exactLayout(),
    1,
  );
  assert.equal(shallowTitleIgnoresUnprojectedChrome.ok, true);

  const projectedTitleLeafPaint = await evaluateExact(
    page,
    `<style>.subject-text::after { content: "Sponsored"; }</style>${exactPage({
      titleHtml: `<h4 class="exact-title"><span class="subject-text">${title}</span>
        <a class="js_share" href="/share">Share</a></h4>`,
    })}`,
    exactLayout(),
    1,
  );
  assert.equal(projectedTitleLeafPaint.ok, false);
  assert.equal(projectedTitleLeafPaint.reason, "publisher-paint");

  const hundredExactComments = await evaluateExact(
    page,
    exactPage({
      commentsHtml: Array.from({ length: 100 }, (_, index) =>
        `<div class="comment-item" itemprop="comment">Complete comment ${index + 1}</div>`
      ).join(""),
    }),
    exactLayout({ commentItems: [".exact-comments .comment-item"] }),
    100,
  );
  assert.equal(hundredExactComments.ok, true);

  const staleAlgumonCountIsOnlyALowerBound = await evaluateExact(
    page,
    exactPage({
      commentsHtml: Array.from({ length: 3 }, (_, index) =>
        `<div class="comment-item">Newer complete comment ${index + 1}</div>`
      ).join(""),
    }),
    exactLayout({ commentItems: [".exact-comments > .comment-item"] }),
    1,
  );
  assert.equal(staleAlgumonCountIsOnlyALowerBound.ok, true);
  assert.equal(
    staleAlgumonCountIsOnlyALowerBound.projectionPolicy.provenCommentCountSource,
    "exact-dom+algumon-lower-bound",
  );

  const lowerBoundStillRejectsMissingComments = await evaluateExact(
    page,
    exactPage({
      commentsHtml: Array.from({ length: 3 }, (_, index) =>
        `<div class="comment-item">Partial comment ${index + 1}</div>`
      ).join(""),
    }),
    exactLayout({ commentItems: [".exact-comments > .comment-item"] }),
    4,
  );
  assert.equal(lowerBoundStillRejectsMissingComments.ok, false);
  assert.equal(lowerBoundStillRejectsMissingComments.reason, "partial-comment-set");

  const approvedContinuationPreservesLoadedComments = await evaluateExact(
    page,
    exactPage({
      commentsHtml: `<div class="comment-item" itemprop="comment">Only loaded comment</div>
        <button class="comment-control comment-more">Load 99 more comments</button>`,
    }),
    exactLayout({ commentItems: [".exact-comments .comment-item"] }),
    100,
  );
  assert.equal(approvedContinuationPreservesLoadedComments.ok, true, JSON.stringify(approvedContinuationPreservesLoadedComments));
  assert.equal(approvedContinuationPreservesLoadedComments.projectionPolicy.provenCommentCount, 1);
  assert.equal(approvedContinuationPreservesLoadedComments.projectionPolicy.provenCommentCountSource, "exact-dom-paginated");

  const escapedExactEvidence = await evaluateExact(
    page,
    `${exactPage({
      commentsHtml: '<div class="comment-item" itemprop="comment">Old loaded comment</div>',
    })}<section class="escaped-v2-comments">
      ${Array.from({ length: 99 }, (_, index) =>
        `<div itemprop="comment">Escaped v2 comment ${index + 2}</div>`
      ).join("")}
    </section>`,
    exactLayout(),
    100,
  );
  assert.equal(escapedExactEvidence.ok, false);
  assert.equal(escapedExactEvidence.reason, "evidence-outside-items");

  const articleAncestorIsNotCommentEvidence = await evaluateExact(
    page,
    `<main id="page">
      <h1 class="exact-title">${title}</h1>
      <div id="D_">
        <article><div class="exact-body">${longBody}</div></article>
        <div class="article-meta">Comments 4</div>
        <div class="article-layout-row">Article row one</div>
        <div class="article-layout-row">Article row two</div>
      </div>
      <section class="exact-comments" aria-label="Comments">
        ${Array.from({ length: 4 }, (_, index) =>
          `<div class="comment-item" itemprop="comment">Real comment ${index + 1}</div>`
        ).join("")}
      </section>
    </main>`,
    exactLayout(),
    4,
  );
  assert.equal(articleAncestorIsNotCommentEvidence.ok, true);

  const boardSortSelectsAreNotCommentEvidence = await evaluateExact(
    page,
    `<main id="page">
      <h1 class="exact-title">${title}</h1>
      <article class="exact-body">${longBody}</article>
      <div class="btns-board">
        <select aria-label="정렬"><option>최근댓글순</option></select>
        <select aria-label="표시"><option>댓글갯수순</option></select>
      </div>
      <section class="exact-comments" aria-label="Comments" style="min-height:1px"></section>
    </main>`,
    exactLayout({ commentControls: [], commentIgnored: [] }),
    null,
  );
  assert.equal(
    boardSortSelectsAreNotCommentEvidence.ok,
    true,
    JSON.stringify(boardSortSelectsAreNotCommentEvidence),
  );

  const clienHyphenatedMobileCommentControl = await evaluateExact(
    page,
    exactPage({
      commentsHtml: `<div class="comment-item" itemprop="comment">Visible comment</div>
        <div class="comment-nav" data-role="comment-newest" id="comment_write">
          <button class="comment-more">새로운 댓글 확인하기</button>
        </div>`,
    }),
    exactLayout({
      commentControls: [
        ".exact-comments > .comment_nav",
        ".exact-comments > .comment-nav",
        ".exact-comments .comment_more",
        ".exact-comments .comment-more",
      ],
      commentIgnored: [],
    }),
    1,
  );
  assert.equal(
    clienHyphenatedMobileCommentControl.ok,
    true,
    JSON.stringify(clienHyphenatedMobileCommentControl),
  );

  const hiddenMount = await evaluateExact(
    page,
    exactPage({ mountStyle: "visibility:hidden" }),
    exactLayout(),
    1,
  );
  assert.equal(hiddenMount.ok, false);
  assert.equal(hiddenMount.role, "comments");

  const hiddenInitialItem = await evaluateExact(
    page,
    exactPage({
      commentsHtml: `<div class="comment-item" style="visibility:hidden">Hidden comment</div>
        <button class="comment-control">Visible reply control</button>
        <div class="comment-ignored" style="display:none">Ignored template</div>`,
    }),
    exactLayout(),
    1,
  );
  assert.equal(hiddenInitialItem.ok, false);
  assert.equal(hiddenInitialItem.reason, "classified-rendering");

  const dormantInitialControls = await evaluateExact(
    page,
    exactPage({
      commentsHtml: `<div class="comment-item">Visible comment</div>
        <button class="comment-control cmt-more-btn" style="display:none">Previous page</button>
        <button class="comment-control cmt-more-btn" style="display:none">Next page</button>
        <button class="comment-control cmt-more-btn" style="display:none">New comments</button>
        <div class="comment-ignored" style="display:none">Ignored template</div>`,
    }),
    exactLayout(),
    1,
  );
  assert.equal(dormantInitialControls.ok, true);

  const commentShellWithNoiseToken = await evaluateExact(
    page,
    exactPage({
      commentsHtml: `<div class="comment ad_banner">
          <div class="comment-item" itemprop="comment">Visible nested comment</div>
        </div>
        <button class="comment-control">Visible reply control</button>`,
    }),
    exactLayout({ commentItems: [".exact-comments .comment-item"] }),
    1,
  );
  assert.equal(commentShellWithNoiseToken.ok, true, JSON.stringify(commentShellWithNoiseToken));

  const fixedCommentShell = await evaluateExact(
    page,
    exactPage({
      commentsHtml: `<div class="comment ad_banner"
          style="position:fixed;left:0;top:0;width:100vw;height:100vh">
          <div class="comment-item" itemprop="comment">Overlayed comment</div>
        </div><button class="comment-control">Visible reply control</button>`,
    }),
    exactLayout({ commentItems: [".exact-comments .comment-item"] }),
    1,
  );
  assert.equal(fixedCommentShell.ok, false);
  assert.equal(fixedCommentShell.reason, "publisher-paint");

  const exactProvenEmpty = await evaluateExact(
    page,
    exactPage({
      commentsHtml: `<button class="comment-control">Visible reply control</button>
        <div class="comment-ignored" style="display:none">Ignored empty-state template</div>`,
    }),
    exactLayout(),
    0,
  );
  assert.equal(exactProvenEmpty.ok, true);

  const exactDomProvenEmpty = await evaluateExact(
    page,
    exactPage({
      commentsHtml: `<button class="comment-control">Visible reply control</button>
        <div class="comment-ignored" style="display:none">Ignored empty-state template</div>`,
    }),
    exactLayout(),
    null,
  );
  assert.equal(exactDomProvenEmpty.ok, true);

  const exactStaleZeroSeedAllowsNewComment = await evaluateExact(
    page,
    exactPage(),
    exactLayout(),
    0,
  );
  assert.equal(exactStaleZeroSeedAllowsNewComment.ok, true);
  assert.equal(
    exactStaleZeroSeedAllowsNewComment.projectionPolicy.provenCommentCountSource,
    "exact-dom+algumon-lower-bound",
  );

  const exactBareAside = await evaluateExact(
    page,
    exactPage({ bodyExtra: "<aside>Popular site chrome</aside>" }),
    exactLayout(),
    1,
  );
  assert.equal(exactBareAside.ok, true);
  assert.equal(exactBareAside.bodyIgnoredCount, 1);

  const exactRecommendation = await evaluateExact(
    page,
    exactPage({ bodyExtra: '<div class="recommendation">Other posts</div>' }),
    exactLayout(),
    1,
  );
  assert.equal(exactRecommendation.ok, true);
  assert.equal(exactRecommendation.bodyIgnoredCount, 1);

  const exactRuliProductAfterBody = await evaluateExact(
    page,
    `<main id="page">
      <h1 class="exact-title">${title}</h1>
      <article class="exact-body">${longBody}</article>
      <div class="exact-product">Price 49,500원
        <a href="https://shop.example/buy">예약 구매</a></div>
      <section class="exact-comments" aria-label="Comments">
        <div class="comment-item">Visible comment</div>
        <button class="comment-control">Visible reply control</button>
        <div class="comment-ignored" style="display:none">Ignored template</div>
      </section>
    </main>`,
    exactLayout({ product: "required", productOrder: "after-body" }),
    1,
  );
  assert.equal(exactRuliProductAfterBody.ok, true);

  const ruliNestedTableCommentItems = await evaluateExact(
    page,
    exactPage({
      commentsHtml: `<table class="comment_table"><tbody>
        <tr class="comment_element"><td>First complete comment</td></tr>
        <tr class="comment_element"><td>Second complete comment</td></tr>
      </tbody></table>`,
    }),
    exactLayout({
      commentItems: [
        ".exact-comments > table.comment_table > tbody > tr.comment_element",
      ],
      commentControls: [],
      commentIgnored: [],
    }),
    2,
  );
  assert.equal(ruliNestedTableCommentItems.ok, true, JSON.stringify(ruliNestedTableCommentItems));

  const schemaSubsetWithVisibleCommentTotal = await evaluateExact(
    page,
    `<main id="page">
      <h1 class="exact-title">${title}</h1>
      <article class="exact-body">${longBody}</article>
      <div class="comment-shell">
        <div class="comment-count">Comments | total 3</div>
        <section class="exact-comments" aria-label="Comments">
          <div class="comment-item">Visible comment one</div>
          <div class="comment-item">Visible comment two</div>
          <div class="comment-item">Visible comment three</div>
        </section>
      </div>
      <script type="application/ld+json">${JSON.stringify({
        "@type": "DiscussionForumPosting",
        headline: title,
        commentCount: 1,
      })}</script>
    </main>`,
    exactLayout({
      commentItems: [".exact-comments > .comment-item"],
      commentControls: [],
      commentIgnored: [],
    }),
    null,
  );
  assert.equal(schemaSubsetWithVisibleCommentTotal.ok, true);
  assert.equal(
    schemaSubsetWithVisibleCommentTotal.projectionPolicy.provenCommentCount,
    3,
  );
  assert.equal(
    schemaSubsetWithVisibleCommentTotal.projectionPolicy.provenCommentCountSource,
    "visible-comment-total",
  );

  const visibleCommentTotalRejectsPartialRows = await evaluateExact(
    page,
    `<main id="page">
      <h1 class="exact-title">${title}</h1>
      <article class="exact-body">${longBody}</article>
      <div class="comment-shell">
        <div class="comment-count">Comments | total 4</div>
        <section class="exact-comments" aria-label="Comments">
          <div class="comment-item">Visible comment one</div>
          <div class="comment-item">Visible comment two</div>
          <div class="comment-item">Visible comment three</div>
        </section>
      </div>
    </main>`,
    exactLayout({
      commentItems: [".exact-comments > .comment-item"],
      commentControls: [],
      commentIgnored: [],
    }),
    null,
  );
  assert.equal(visibleCommentTotalRejectsPartialRows.ok, false);
  assert.equal(visibleCommentTotalRejectsPartialRows.reason, "partial-comment-set");

  const exactRuliWrongProductOrder = await evaluateExact(
    page,
    exactPage({
      productHtml: `<div class="exact-product">Price 49,500원
        <a href="https://shop.example/buy">예약 구매</a></div>`,
    }),
    exactLayout({ product: "required", productOrder: "after-body" }),
    1,
  );
  assert.equal(exactRuliWrongProductOrder.ok, false);
  assert.equal(exactRuliWrongProductOrder.role, "product");
  assert.equal(exactRuliWrongProductOrder.reason, "approved-order");

  for (const [name, bodyExtra] of [
    ["affiliate anchor", '<a class="affiliate-ad" href="https://shop.example/deal">Partner deal</a>'],
    ["advertisement span", '<span id="advertisement">Promoted placement</span>'],
    ["related link container", '<div class="related"><a href="/other-post">Related post</a></div>'],
    ["related link itself", '<a class="related" href="/other-post">Related post</a>'],
    ["share link", '<a class="share" href="/share">Share</a>'],
    ["ranking button", '<button class="ranking">Ranking</button>'],
    ["social link", '<a class="social" href="/social">Social</a>'],
    ["breadcrumb span", '<span class="breadcrumb">Breadcrumb</span>'],
    ["camel related posts", '<div class="relatedPosts"><a href="/other">Related post</a></div>'],
    ["camel advertisement slot", '<div class="adSlot">Advertisement</div>'],
    ["camel recommended articles", '<div class="recommendedArticles"><a href="/other">Other article</a></div>'],
    ["data test advertisement", '<div data-testid="advertisement">Placement</div>'],
    ["data component related posts", '<div data-component="related-posts"><a href="/other">Other post</a></div>'],
    ["data role sponsored", '<a data-role="sponsored" href="/partner">Partner</a>'],
    ["sponsored relation", '<a rel="sponsored" href="/partner">Partner</a>'],
    ["ad network resource", '<a href="https://googleads.g.doubleclick.net/pagead/landing">Placement</a>'],
  ]) {
    const strongExactNoise = await evaluateExact(
      page,
      exactPage({ bodyExtra }),
      exactLayout(),
      1,
    );
    assert.equal(strongExactNoise.ok, true, `${name} must be isolated`);
    assert.ok(
      strongExactNoise.bodyIgnoredCount >= 1,
      `${name} must be excluded from the approved body projection`,
    );
  }

  const exactNoisyProduct = await evaluateExact(
    page,
    exactPage({
      productHtml: '<table class="exact-product"><tr><td>Price $99<nav>Stores</nav></td></tr></table>',
    }),
    exactLayout({ product: "required" }),
    1,
  );
  assert.equal(exactNoisyProduct.ok, true);
  assert.equal(exactNoisyProduct.productIgnoredCount, 1);

  const exactBenignMedia = await evaluateExact(
    page,
    exactPage({
      bodyExtra: `<header class="header"><p>Authored heading context</p></header>
        <section class="related"><p>The words popular recommendations belong to the article.</p></section>
        <img class="banner" alt="Product image" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==">`,
    }),
    exactLayout(),
    1,
  );
  assert.equal(exactBenignMedia.ok, true);

  const arcaOuterAtomicBoundary = await evaluateExact(
    page,
    `<main id="page">
      <h1 class="exact-title">${title}</h1>
      <article class="article-body">
        <div class="article-content"></div>
        ${longBody}
        <div class="ad">Publisher advertisement slot</div>
      </article>
      <section class="exact-comments" aria-label="Comments">
        <div class="comment-item">Visible comment</div>
        <button class="comment-control">Reply</button>
      </section>
    </main>`,
    exactLayout({
      bodyHints: [".article-body"],
      bodyIgnored: [".article-body > .ad"],
    }),
    1,
  );
  assert.equal(arcaOuterAtomicBoundary.ok, true);

  const arcaIgnoredMeaningfulBody = await evaluateExact(
    page,
    `<main id="page">
      <h1 class="exact-title">${title}</h1>
      <article class="article-body"><div class="ad">${longBody}
        <a href="https://shop.example/buy">Buy the authored product</a></div></article>
      <section class="exact-comments" aria-label="Comments">
        <div class="comment-item">Visible comment</div>
        <button class="comment-control">Reply</button>
      </section>
    </main>`,
    exactLayout({
      bodyHints: [".article-body"],
      bodyIgnored: [".article-body > .ad"],
    }),
    1,
  );
  assert.equal(arcaIgnoredMeaningfulBody.ok, false);
  assert.equal(arcaIgnoredMeaningfulBody.role, "body");
  assert.equal(arcaIgnoredMeaningfulBody.reason, "approved-structure");

  const arcaNestedUnapprovedAd = await evaluateExact(
    page,
    `<main id="page">
      <h1 class="exact-title">${title}</h1>
      <article class="article-body">${longBody}<div class="slot"><div class="ad">Ad</div></div></article>
      <section class="exact-comments" aria-label="Comments">
        <div class="comment-item">Visible comment</div>
        <button class="comment-control">Reply</button>
      </section>
    </main>`,
    exactLayout({
      bodyHints: [".article-body"],
      bodyIgnored: [".article-body > .ad"],
    }),
    1,
  );
  assert.equal(arcaNestedUnapprovedAd.ok, true);
  assert.equal(arcaNestedUnapprovedAd.bodyIgnoredCount, 1);

  const arcaDuplicateOuterBody = await evaluateExact(
    page,
    `<main id="page">
      <h1 class="exact-title">${title}</h1>
      <article class="article-body">${longBody}</article>
      <article class="article-body">${longBody}</article>
      <section class="exact-comments" aria-label="Comments">
        <div class="comment-item">Visible comment</div>
        <button class="comment-control">Reply</button>
      </section>
    </main>`,
    exactLayout({ bodyHints: [".article-body"] }),
    1,
  );
  assert.equal(arcaDuplicateOuterBody.ok, false);
  assert.equal(arcaDuplicateOuterBody.role, "body");
  assert.equal(arcaDuplicateOuterBody.reason, "approved-structure");

  const arcaNestedReplyItems = await evaluateExact(
    page,
    exactPage({
      commentsHtml: `<div class="title">댓글 [3]</div>
        <div class="alert alert-info">로그인 후 댓글을 작성할 수 있습니다.</div>
        <div class="list-area">
          <div class="comment-wrapper">
            <div class="comment-item" id="c_1">Top-level comment
              <div class="comment-wrapper">
                <div class="comment-item" id="c_2">Nested reply</div>
              </div>
            </div>
          </div>
          <div class="comment-wrapper"><div class="comment-item" id="c_3">Second comment</div></div>
          <div class="newcomment-alert fetch-comment" style="display:none">새 댓글 불러오기</div>
        </div>`,
    }),
    exactLayout({
      commentItems: [
        ".exact-comments .comment-wrapper > .comment-item[id^='c_']",
      ],
      commentControls: [
        ".exact-comments > .list-area > .newcomment-alert.fetch-comment",
      ],
      commentIgnored: [
        ".exact-comments > .title",
        ".exact-comments > .alert.alert-info",
      ],
    }),
    3,
  );
  assert.equal(arcaNestedReplyItems.ok, true, JSON.stringify(arcaNestedReplyItems));

  const arcaExactDomZeroComments = await evaluateExact(
    page,
    exactPage({
      commentsHtml: `<div class="title">댓글 [0]</div>
        <div class="alert alert-info">로그인 후 댓글을 작성할 수 있습니다.</div>
        <div class="list-area">
          <div class="newcomment-alert fetch-comment" style="display:none">새 댓글 불러오기</div>
        </div>`,
    }),
    exactLayout({
      commentItems: [
        ".exact-comments .comment-wrapper > .comment-item[id^='c_']",
      ],
      commentControls: [
        ".exact-comments > .list-area > .newcomment-alert.fetch-comment",
      ],
      commentIgnored: [
        ".exact-comments > .title",
        ".exact-comments > .alert.alert-info",
      ],
    }),
    null,
  );
  assert.equal(arcaExactDomZeroComments.ok, true, JSON.stringify(arcaExactDomZeroComments));

  const ppomppuAffiliateDecorationIgnored = await evaluateExact(
    page,
    exactPage({
      productHtml: `<a class="exact-product" href="https://shop.example/buy">
        <span>19,800원 구매하기</span>
        <span class="affiliate-img">Affiliate image decoration</span>
        <span class="affiliate-sign">Affiliate disclosure</span>
      </a>`,
    }),
    exactLayout({
      product: "required",
      productIgnored: [
        ".exact-product > .affiliate-img",
        ".exact-product > .affiliate-sign",
      ],
    }),
    1,
  );
  assert.equal(ppomppuAffiliateDecorationIgnored.ok, true);

  const ppomppuIgnoredOnlyMeaningfulProduct = await evaluateExact(
    page,
    exactPage({
      productHtml: `<div class="exact-product"><a class="affiliate-img"
        href="https://shop.example/buy">19,800원 구매하기</a></div>`,
    }),
    exactLayout({
      product: "required",
      productIgnored: [".exact-product > .affiliate-img"],
    }),
    1,
  );
  assert.equal(ppomppuIgnoredOnlyMeaningfulProduct.ok, false);
  assert.equal(ppomppuIgnoredOnlyMeaningfulProduct.role, "product");
  assert.equal(ppomppuIgnoredOnlyMeaningfulProduct.reason, "approved-structure");

  const ppomppuOverlappingProductIgnored = await evaluateExact(
    page,
    exactPage({
      productHtml: `<div class="exact-product">19,800원 구매하기
        <div class="affiliate-img"><span class="affiliate-sign">Disclosure</span></div>
      </div>`,
    }),
    exactLayout({
      product: "required",
      productIgnored: [
        ".exact-product > .affiliate-img",
        ".exact-product > .affiliate-img .affiliate-sign",
      ],
    }),
    1,
  );
  assert.equal(ppomppuOverlappingProductIgnored.ok, false);
  assert.equal(ppomppuOverlappingProductIgnored.role, "product");
  assert.equal(ppomppuOverlappingProductIgnored.reason, "ignored-overlap");

  const zodAuthoredAdsPathLink = await evaluateExact(
    page,
    exactPage({
      bodyExtra: `<p>결제 안내:
        <a href="https://ofw.adison.co/u/naverpay/ads/benefit">Naver Pay point</a>
      </p>`,
    }),
    exactLayout(),
    1,
  );
  assert.equal(zodAuthoredAdsPathLink.ok, true);

  const ppomppuAuthoredProductPreviewBackground = await evaluateExact(
    page,
    `<style>.scrap_img {
      display:inline-block; position:absolute; width:80px; height:80px;
      background-image:url("https://img.publichs.com/ECMCFO/share/product/example.jpg");
    }</style>${exactPage({
      bodyExtra: '<span class="scrap_img" aria-label="상품 미리보기"></span>',
    })}`,
    exactLayout(),
    1,
  );
  assert.equal(
    ppomppuAuthoredProductPreviewBackground.ok,
    true,
    JSON.stringify(ppomppuAuthoredProductPreviewBackground),
  );

  for (const mediaNoise of [
    '<img class="sponsor" alt="Placement" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==">',
    '<iframe class="promo" title="Placement" srcdoc="<p>placement</p>"></iframe>',
  ]) {
    const strongMedia = await evaluateExact(
      page,
      exactPage({ bodyExtra: mediaNoise }),
      exactLayout(),
      1,
    );
    assert.equal(strongMedia.ok, true);
    assert.equal(strongMedia.bodyIgnoredCount, 1);
  }

  const benignPublisherPaint = await evaluateExact(
    page,
    `<style>
      .exact-title::after { content: "님"; }
      .comment-item::before { content: "\\f075"; font-family: sans-serif; }
      .comment-item { background-image: linear-gradient(#fff, #eee); }
      .exact-body::after { content: ""; display: table; clear: both; }
    </style>${exactPage()}`,
    exactLayout(),
    1,
  );
  assert.equal(benignPublisherPaint.ok, true);

  const fixedAdvertisementPseudo = await evaluateExact(
    page,
    `<style>.exact-body::after {
      content: "Sponsored"; position: fixed; left: 0; top: 0;
      width: 100vw; height: 100vh;
    }</style>${exactPage()}`,
    exactLayout(),
    1,
  );
  assert.equal(fixedAdvertisementPseudo.ok, false);
  assert.equal(fixedAdvertisementPseudo.reason, "publisher-paint");

  for (const [name, rule] of [
    ["partner offer pseudo", '.exact-body::before { content: "Partner offer — click here"; }'],
    ["promoted deal pseudo", '.comment-item::after { content: "Read this promoted deal"; }'],
    ["promotional background", '.exact-body { background-image: url("https://example.com/promo.png"); }'],
  ]) {
    const paintNoise = await evaluateExact(
      page,
      `<style>${rule}</style>${exactPage()}`,
      exactLayout(),
      1,
    );
    assert.equal(paintNoise.ok, false, `${name} must fail exact projection`);
    assert.equal(paintNoise.reason, "publisher-paint");
  }

  const ordinaryOpenDetails = await evaluateExact(
    page,
    exactPage({
      bodyExtra: "<details open><summary>Specifications</summary><p>Expanded authored detail.</p></details>",
    }),
    exactLayout(),
    1,
  );
  assert.equal(ordinaryOpenDetails.ok, true);

  const activeDialog = await evaluateExact(
    page,
    exactPage({ bodyExtra: "<dialog open>Overlay content</dialog>" }),
    exactLayout(),
    1,
  );
  assert.equal(activeDialog.ok, false);
  assert.equal(activeDialog.reason, "publisher-paint");

  const fixedViewportOverlay = await evaluateExact(
    page,
    exactPage({
      bodyExtra: '<div style="position:fixed;left:0;top:0;width:100vw;height:100vh">Overlay</div>',
    }),
    exactLayout(),
    1,
  );
  assert.equal(fixedViewportOverlay.ok, false);
  assert.equal(fixedViewportOverlay.reason, "publisher-paint");

  const opacityHiddenAncestor = await evaluateExact(
    page,
    `<div style="opacity:0">${exactPage()}</div>`,
    exactLayout(),
    1,
  );
  assert.equal(opacityHiddenAncestor.ok, false);

  const contentHiddenAncestor = await evaluateExact(
    page,
    `<div style="content-visibility:hidden">${exactPage()}</div>`,
    exactLayout(),
    1,
  );
  assert.equal(contentHiddenAncestor.ok, false);

  const visibilityHiddenAncestor = await evaluateExact(
    page,
    `<div style="visibility:hidden">${exactPage()}</div>`,
    exactLayout(),
    1,
  );
  assert.equal(visibilityHiddenAncestor.ok, false);

  const zeroSizedMount = await evaluateExact(
    page,
    exactPage({ mountStyle: "width:0;height:0;overflow:hidden" }),
    exactLayout(),
    1,
  );
  assert.equal(zeroSizedMount.ok, false);
  assert.equal(zeroSizedMount.role, "comments");

  const stableZeroHeightEmptyMount = await evaluateExact(
    page,
    exactPage({
      commentsHtml: "",
      mountStyle: "width:900px;height:0;overflow:hidden;opacity:1",
    }),
    exactLayout({ commentControls: [], commentIgnored: [] }),
    null,
  );
  assert.equal(
    stableZeroHeightEmptyMount.ok,
    true,
    JSON.stringify(stableZeroHeightEmptyMount),
  );

  const contradictedZeroHeightMount = await evaluateExact(
    page,
    exactPage({
      commentsHtml: "",
      mountStyle: "width:900px;height:0;overflow:hidden;opacity:1",
    }),
    exactLayout({ commentControls: [], commentIgnored: [] }),
    1,
  );
  assert.equal(contradictedZeroHeightMount.ok, false);
  assert.equal(contradictedZeroHeightMount.reason, "partial-comment-set");

  const hiddenEmptyMountWithoutHistoricalCount = await evaluateExact(
    page,
    exactPage({ commentsHtml: "", mountStyle: "display:none" }),
    exactLayout({ commentControls: [], commentIgnored: [] }),
    null,
  );
  assert.equal(hiddenEmptyMountWithoutHistoricalCount.ok, false);
  assert.equal(hiddenEmptyMountWithoutHistoricalCount.role, "comments");

  const inspectableUnregisteredLightDomCustomElement = await evaluateExact(
    page,
    exactPage({ bodyExtra: "<deal-card>Unproven custom rendering boundary</deal-card>" }),
    exactLayout(),
    1,
  );
  assert.equal(
    inspectableUnregisteredLightDomCustomElement.ok,
    true,
    JSON.stringify(inspectableUnregisteredLightDomCustomElement),
  );

  const emptyUnprovenCustomElement = await evaluateExact(
    page,
    exactPage({ bodyExtra: "<deal-card></deal-card>" }),
    exactLayout(),
    1,
  );
  assert.equal(emptyUnprovenCustomElement.ok, false);
  assert.equal(emptyUnprovenCustomElement.reason, "shadow-boundary");

  const registeredLightDomTooltip = await evaluateExactWithRegisteredLightDomCustomElement(page);
  assert.equal(registeredLightDomTooltip.ok, true, JSON.stringify(registeredLightDomTooltip));

  const declarativeShadow = await evaluateExact(
    page,
    exactPage({
      bodyExtra: '<div class="dsd-host"><template shadowrootmode="open"><span>Hidden rendering</span></template></div>',
    }),
    exactLayout(),
    1,
  );
  assert.equal(declarativeShadow.ok, false);
  assert.equal(declarativeShadow.reason, "shadow-boundary");

  const openShadow = await evaluateExactWithAttachedShadow(page, "open");
  assert.equal(openShadow.ok, false);
  assert.equal(openShadow.reason, "shadow-boundary");

  const closedShadow = await evaluateExactWithAttachedShadow(page, "closed");
  assert.equal(closedShadow.ok, false);
  assert.equal(closedShadow.reason, "shadow-boundary");

  const visibleDynamicControl = await exerciseDynamicControl(page, false);
  assert.equal(visibleDynamicControl.setup.ok, true);
  assert.equal(visibleDynamicControl.terminalReason, null);
  assert.equal(
    visibleDynamicControl.role,
    "comment-control",
    JSON.stringify(visibleDynamicControl),
  );

  const hiddenDynamicControl = await exerciseDynamicControl(page, true);
  assert.equal(hiddenDynamicControl.setup.ok, true);
  assert.equal(hiddenDynamicControl.terminalReason, null);
  assert.equal(hiddenDynamicControl.role, "comment-control");
  assert.equal(hiddenDynamicControl.visibility, "hidden");
  assert.equal(hiddenDynamicControl.pointerEvents, "none");

  const lowerBoundDynamicComment = await exerciseDynamicComment(page);
  assert.equal(lowerBoundDynamicComment.setup.ok, true);
  assert.equal(lowerBoundDynamicComment.terminalReason, null);
  assert.equal(lowerBoundDynamicComment.role, "comment-item");
  assert.equal(lowerBoundDynamicComment.addedKept, true);
  assert.equal(lowerBoundDynamicComment.mediaKept, true);
  assert.equal(lowerBoundDynamicComment.initialPreserved, true);
  assert.equal(lowerBoundDynamicComment.itemCount, 2);

  const mutatedExistingComment = await exerciseDynamicComment(page, {
    mutateInitial: true,
  });
  assert.equal(mutatedExistingComment.setup.ok, true);
  assert.equal(mutatedExistingComment.terminalReason, null);
  assert.equal(mutatedExistingComment.initialIdentityPreserved, true);
  assert.equal(mutatedExistingComment.initialText, "Updated visible comment");
  assert.equal(mutatedExistingComment.itemCount, 2);

  const nestedMountDynamicComment = await exerciseDynamicComment(page, {
    nestedMount: true,
  });
  assert.equal(nestedMountDynamicComment.setup.ok, true);
  assert.equal(nestedMountDynamicComment.terminalReason, null);
  assert.equal(nestedMountDynamicComment.role, "comment-item");
  assert.equal(nestedMountDynamicComment.addedKept, true);
  assert.equal(nestedMountDynamicComment.nestedMountKept, true);

  const exactTotalDynamicComment = await exerciseDynamicComment(page, {
    exactTotal: true,
    updateExactTotal: true,
  });
  assert.equal(exactTotalDynamicComment.setup.ok, true);
  assert.equal(exactTotalDynamicComment.terminalReason, null);
  assert.equal(exactTotalDynamicComment.itemCount, 2);

  const nonAtomicExactTotalDynamicComment = await exerciseDynamicComment(page, {
    exactTotal: true,
    updateExactTotal: true,
    separateExactTotalUpdate: true,
  });
  assert.equal(nonAtomicExactTotalDynamicComment.setup.ok, true);
  assert.equal(
    nonAtomicExactTotalDynamicComment.terminalReason,
    null,
    JSON.stringify(nonAtomicExactTotalDynamicComment),
  );
  assert.equal(nonAtomicExactTotalDynamicComment.initialPreserved, true);
  assert.equal(nonAtomicExactTotalDynamicComment.addedKept, true);
  assert.equal(nonAtomicExactTotalDynamicComment.mediaKept, true);
  assert.equal(nonAtomicExactTotalDynamicComment.itemCount, 2);

  const staleExactTotalDynamicComment = await exerciseDynamicComment(page, {
    exactTotal: true,
  });
  assert.equal(staleExactTotalDynamicComment.setup.ok, true);
  assert.equal(
    staleExactTotalDynamicComment.terminalReason,
    null,
    JSON.stringify(staleExactTotalDynamicComment),
  );
  assert.equal(staleExactTotalDynamicComment.initialPreserved, true);
  assert.equal(staleExactTotalDynamicComment.addedKept, true);
  assert.equal(staleExactTotalDynamicComment.mediaKept, true);
  assert.equal(staleExactTotalDynamicComment.itemCount, 2);

  for (const totalUpdateAfterItems of [false, true]) {
    for (const width of [1280, 390]) {
      await page.setViewportSize({ width, height: 900 });
      const preservedAsyncComments = await exerciseDynamicComment(page, {
        exactTotal: true,
        updateExactTotal: true,
        separateExactTotalUpdate: true,
        totalUpdateAfterItems,
        exerciseControls: true,
      });
      assert.equal(preservedAsyncComments.setup.ok, true);
      assert.equal(preservedAsyncComments.terminalReason, null, JSON.stringify(preservedAsyncComments));
      for (const key of [
        "initialPreserved", "addedKept", "mediaKept", "bodyIdentityPreserved",
        "bodyTextPreserved", "bodyVisible", "commentVisible", "imagePreserved",
        "linkPreserved", "detailsPreserved", "moreControlPreserved", "popularHidden",
      ]) {
        assert.equal(preservedAsyncComments[key], true, `${key}: ${JSON.stringify(preservedAsyncComments)}`);
      }
      assert.equal(preservedAsyncComments.itemCount, 3);
    }
  }
  await page.setViewportSize({ width: 1280, height: 720 });

  const removedExistingComment = await exerciseDynamicComment(page, {
    removeInitial: true,
  });
  assert.equal(removedExistingComment.setup.ok, true);
  assert.equal(removedExistingComment.terminalReason, null);
  assert.equal(
    removedExistingComment.terminalAfterRemoval,
    "role-projection-comment-removal",
  );

  const externalImplementationRemoval =
    await exerciseExternalCommentImplementationRemoval(page);
  assert.equal(externalImplementationRemoval.setup.ok, true);
  assert.equal(externalImplementationRemoval.editorInitiallyOwned, false);
  assert.equal(externalImplementationRemoval.editorRemoved, true);
  assert.equal(externalImplementationRemoval.terminalReason, null);
  assert.equal(externalImplementationRemoval.projectionPublishCount, 1);
  assert.equal(externalImplementationRemoval.projectionEpoch, 1);
  assert.equal(externalImplementationRemoval.commentIdentityPreserved, true);
  assert.equal(externalImplementationRemoval.controlIdentityPreserved, true);
  assert.equal(externalImplementationRemoval.commentVisible, true);
  assert.equal(externalImplementationRemoval.controlVisible, true);
  assert.equal(
    externalImplementationRemoval.commentText,
    "Retained visible comment",
  );
  assert.equal(externalImplementationRemoval.controlText, "New comment");

  const dynamicCommentControlReplacement =
    await exerciseDynamicCommentControlReplacement(page);
  assert.equal(dynamicCommentControlReplacement.setup.ok, true);
  assert.equal(
    dynamicCommentControlReplacement.terminalReason,
    null,
    JSON.stringify(dynamicCommentControlReplacement),
  );
  assert.equal(dynamicCommentControlReplacement.projectionPublishCount, 1);
  assert.equal(dynamicCommentControlReplacement.projectionEpoch, 1);
  assert.equal(dynamicCommentControlReplacement.commentIdentityPreserved, true);
  assert.equal(dynamicCommentControlReplacement.controlIdentityPreserved, true);
  assert.equal(
    dynamicCommentControlReplacement.commentText,
    "Retained visible comment",
  );
  assert.equal(dynamicCommentControlReplacement.commentVisible, true);
  assert.equal(dynamicCommentControlReplacement.controlVisible, true);
  assert.equal(dynamicCommentControlReplacement.descendantCount, 8);
  assert.equal(dynamicCommentControlReplacement.allDescendantsOwned, true);
  assert.equal(dynamicCommentControlReplacement.popularVisible, false);

  const dynamicCommentControlNoise =
    await exerciseDynamicCommentControlReplacement(page, {
      injectPopularNoise: true,
    });
  assert.equal(dynamicCommentControlNoise.setup.ok, true);
  assert.equal(
    dynamicCommentControlNoise.terminalReason,
    "role-projection-comment-control-reconciliation",
    JSON.stringify(dynamicCommentControlNoise),
  );
  assert.equal(dynamicCommentControlNoise.commentIdentityPreserved, true);
  assert.equal(dynamicCommentControlNoise.controlIdentityPreserved, true);

  const eventSubscriptions = await exerciseProjectionEventSubscriptions(page);
  assert.equal(eventSubscriptions.setup.ok, true);
  assert.deepEqual(eventSubscriptions.added.sort(), [
    "beforetoggle",
    "fullscreenchange",
    "toggle",
  ]);
  assert.deepEqual(eventSubscriptions.removed.sort(), [
    "beforetoggle",
    "fullscreenchange",
    "toggle",
  ]);

  const forgedMeasurementGate = await openClienGate(browser, {
    unownedHtml: '<script>document.documentElement.setAttribute("data-hotdeal-focus-measure", "1");</script>',
  });
  try {
    await forgedMeasurementGate.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready" &&
        !document.documentElement.hasAttribute("data-hotdeal-focus-measure"),
      null, { timeout: 5000 },
    );
    const state = await gateState(forgedMeasurementGate.page);
    assert.equal(state.publisherContentVisible.article, true, JSON.stringify(state));
    assert.equal(state.diagnostics.standaloneCascadeProof?.frameCount, 2);
    assert.deepEqual(forgedMeasurementGate.pageErrors, []);
  } finally {
    await forgedMeasurementGate.context.close();
  }

  for (const width of [1280, 390]) {
    for (const mutationKind of ["publisher-class", "owned-shape", "runtime-style", "repeated-forgery"]) {
      const protocolRecoveryGate = await openClienGate(browser, {
        bodyExtra: '<a id="preserved-purchase" href="https://shop.example/item/123">Purchase item</a>',
        commentsHtml: `<div class="comment"><div id="protocol-original-comment" class="comment_row" itemprop="comment">Original comment</div></div>
          <button class="comment_nav">Load more comments</button>`,
        unownedHtml: '<aside id="protocol-noise" class="popular">Popular unrelated posts</aside>',
      });
      try {
        await protocolRecoveryGate.page.setViewportSize({ width, height: 900 });
        await protocolRecoveryGate.page.waitForFunction(
          () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
          null, { timeout: 5000 },
        );
        await protocolRecoveryGate.page.evaluate((mutationKind) => {
          const body = document.querySelector(".post_article");
          const comment = document.querySelector("#protocol-original-comment");
          window.__protocolOriginals = { body, comment, bodyText: body.textContent, commentText: comment.textContent };
          document.querySelector(".comment_nav").addEventListener("click", () => {
            const reply = document.createElement("div");
            reply.className = "comment_row";
            reply.textContent = "Reply after protocol recovery";
            document.querySelector(".comment").append(reply);
          });
          if (mutationKind === "publisher-class") {
            comment.className = "unknown-item publisher-highlight";
            comment.removeAttribute("itemprop");
          } else if (mutationKind === "owned-shape") {
            const wrapper = document.querySelector(".content_view");
            wrapper.setAttribute("data-hotdeal-focus-role", "body");
            wrapper.setAttribute("data-hotdeal-focus-deep", wrapper.getAttribute("data-hotdeal-focus-keep"));
          } else if (mutationKind === "runtime-style") {
            document.querySelector("style[data-hotdeal-focus-runtime-style]").textContent += "\n/* publisher rewrite */";
          } else {
            body.removeAttribute("data-hotdeal-focus-keep");
            const noise = document.querySelector("#protocol-noise");
            let attempts = 0;
            const timer = setInterval(() => {
              noise.setAttribute("data-hotdeal-focus-keep", body.getAttribute("data-hotdeal-focus-keep") || "forged");
              noise.classList.add("hdf-v2-keep");
              document.documentElement.setAttribute("data-hotdeal-focus-protocol", "1");
              document.documentElement.setAttribute("data-hotdeal-focus-measure", "1");
              if (++attempts === 12) clearInterval(timer);
            }, 10);
          }
        }, mutationKind);
        await protocolRecoveryGate.page.waitForTimeout(250);
        const recovered = await gateState(protocolRecoveryGate.page);
        assert.equal(recovered.diagnostics?.state, "ready", JSON.stringify({ width, mutationKind, recovered }));
        assert.equal(recovered.lock, null, JSON.stringify({ width, mutationKind, recovered }));
        assert.equal(recovered.diagnostics.standaloneCascadeProof?.frameCount, 2,
          JSON.stringify({ width, mutationKind, recovered }));
        await protocolRecoveryGate.page.getByRole("button", { name: "Load more comments" }).click();
        await protocolRecoveryGate.page.waitForFunction(
          () => document.querySelectorAll('[data-hotdeal-focus-role="comment-item"]').length === 2,
          null, { timeout: 5000 },
        );
        const preserved = await protocolRecoveryGate.page.evaluate(() => {
          const visible = (element) => {
            const style = getComputedStyle(element);
            return style.display !== "none" && style.visibility !== "hidden" &&
              Number(style.opacity) !== 0 && element.getClientRects().length > 0;
          };
          const originals = window.__protocolOriginals;
          return {
            bodyIdentity: originals.body === document.querySelector(".post_article"),
            commentIdentity: originals.comment === document.querySelector("#protocol-original-comment"),
            bodyText: originals.body.textContent === originals.bodyText,
            commentText: originals.comment.textContent === originals.commentText,
            bodyVisible: visible(originals.body),
            commentsVisible: [...document.querySelectorAll('[data-hotdeal-focus-role="comment-item"]')].every(visible),
            purchaseHref: document.querySelector("#preserved-purchase").href,
            noiseHidden: !visible(document.querySelector("#protocol-noise")),
            measureCleared: !document.documentElement.hasAttribute("data-hotdeal-focus-measure"),
            ready: globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state,
          };
        });
        assert.deepEqual(preserved, {
          bodyIdentity: true, commentIdentity: true, bodyText: true, commentText: true,
          bodyVisible: true, commentsVisible: true, purchaseHref: "https://shop.example/item/123",
          noiseHidden: true, measureCleared: true, ready: "ready",
        }, JSON.stringify({ width, mutationKind, preserved }));
        assert.deepEqual(protocolRecoveryGate.pageErrors, []);
      } finally {
        await protocolRecoveryGate.context.close();
      }
    }
  }

  for (const width of [1280, 390]) {
    const paginatedGate = await openClienGate(browser, {
      commentsTotalHtml: '<p class="comment-total">Comments: 5</p>',
      commentsHtml: `<div class="comment"><div class="comment_row" itemprop="comment">Original loaded comment</div></div>
        <button class="comment_more" id="load-publisher-replies">Load more comments</button>`,
      unownedHtml: '<aside class="popular" id="paginated-popular">Popular unrelated posts</aside>',
    });
    try {
      await paginatedGate.page.setViewportSize({ width, height: 900 });
      await paginatedGate.page.waitForFunction(
        () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
        null,
        { timeout: 5000 },
      );
      const initialState = await gateState(paginatedGate.page);
      assert.equal(initialState.publisherContentVisible.article, true, JSON.stringify(initialState));
      await paginatedGate.page.evaluate(() => {
        window.__paginatedBody = document.querySelector(".post_article");
        document.querySelector("#load-publisher-replies").addEventListener("click", () => {
          const reply = document.createElement("div");
          reply.className = "comment_row";
          reply.id = "publisher-loaded-reply";
          reply.setAttribute("itemprop", "comment");
          reply.textContent = "Original publisher loaded reply";
          document.querySelector(".post_comment > .comment").appendChild(reply);
        });
      });
      await paginatedGate.page.getByRole("button", { name: "Load more comments" }).click();
      await paginatedGate.page.waitForFunction(
        () => document.querySelector("#publisher-loaded-reply")?.hasAttribute("data-hotdeal-focus-keep"),
        null,
        { timeout: 5000 },
      );
      const preserved = await paginatedGate.page.evaluate(() => {
        const visible = (element) => getComputedStyle(element).display !== "none" &&
          getComputedStyle(element).visibility !== "hidden" && element.getClientRects().length > 0;
        return {
          bodyIdentityPreserved: window.__paginatedBody === document.querySelector(".post_article"),
          bodyVisible: visible(document.querySelector(".post_article")),
          initialCommentVisible: visible(document.querySelector(".comment_row")),
          loadedReplyVisible: visible(document.querySelector("#publisher-loaded-reply")),
          moreVisible: visible(document.querySelector("#load-publisher-replies")),
          popularHidden: !visible(document.querySelector("#paginated-popular")),
          state: window.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state,
        };
      });
      assert.equal(preserved.state, "ready", JSON.stringify(preserved));
      for (const key of ["bodyIdentityPreserved", "bodyVisible", "initialCommentVisible", "loadedReplyVisible", "moreVisible", "popularHidden"]) {
        assert.equal(preserved[key], true, `${key}: ${JSON.stringify(preserved)}`);
      }
      assert.deepEqual(paginatedGate.pageErrors, []);
    } finally {
      await paginatedGate.context.close();
    }
  }

  const ruliwebJuly = JSON.parse(fs.readFileSync(
    new URL("fixtures/dom-regressions.json", import.meta.url), "utf8",
  )).fixtures.find((fixture) => fixture.id === "ruliweb-hotdeal-july");
  for (const width of [1280, 390]) {
    const ruliwebGate = await openClienGate(browser, {
      destinationUrl: ruliwebJuly.url,
      fixtureBodyHtml: ruliwebJuly.body_html.replaceAll("DOM regression fixture", title),
      unownedHtml: '<aside class="popular" id="ruliweb-popular">Popular unrelated posts</aside>',
    });
    try {
      await ruliwebGate.page.setViewportSize({ width, height: 900 });
      await ruliwebGate.page.waitForFunction(
        () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready", null, { timeout: 5000 },
      );
      const state = await gateState(ruliwebGate.page);
      assert.equal(state.diagnostics.standaloneCascadeProof?.frameCount, 2, JSON.stringify(state));
      assert.equal(state.diagnostics.commentControlProjection?.currentProjectionValid, true);
      const preserved = await ruliwebGate.page.evaluate(() => {
        const visible = (element) => getComputedStyle(element).display !== "none" &&
          getComputedStyle(element).visibility !== "hidden" && element.getClientRects().length > 0;
        const comments = [...document.querySelectorAll(".comment_element")];
        return {
          titleVisible: visible(document.querySelector(".subject_inner_text")),
          bodyVisible: visible(document.querySelector(".view_content")),
          productVisible: visible(document.querySelector(".source_url")),
          originalLinkPreserved: document.querySelector(".source_url a").href === "https://shop.invalid/product",
          commentCount: comments.length,
          commentsVisible: comments.every(visible),
          originalCommentsPreserved: comments.map((item) => item.textContent).join("|") === "comment one|comment two|comment three",
          popularHidden: !visible(document.querySelector("#ruliweb-popular")),
        };
      });
      for (const key of ["titleVisible", "bodyVisible", "productVisible", "originalLinkPreserved", "commentsVisible", "originalCommentsPreserved", "popularHidden"]) {
        assert.equal(preserved[key], true, `${key}: ${JSON.stringify(preserved)}`);
      }
      assert.equal(preserved.commentCount, 3);
      assert.deepEqual(ruliwebGate.pageErrors, []);
    } finally {
      await ruliwebGate.context.close();
    }
  }

  const prelockedGate = await openClienGate(browser, {
    titleHtml: `<h4 class="post_subject">${title}
      <a class="js_share" href="/share">Share</a>
      <div id="top_recommend_area"><a href="/other">Recommended post</a></div>
    </h4>`,
  });
  try {
    try {
      await prelockedGate.page.waitForFunction(
        () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
        null,
        { timeout: 5000 },
      );
    } catch (error) {
      throw new Error(
        `${error.message}; gate=${JSON.stringify(await gateState(prelockedGate.page))}; ` +
          `pageErrors=${JSON.stringify(prelockedGate.pageErrors)}`,
        { cause: error },
      );
    }
    await prelockedGate.page.evaluate(() => {
      const hiddenRecommendation = document.querySelector("#top_recommend_area");
      const link = document.createElement("a");
      link.href = "/new-recommendation";
      link.textContent = "Updated recommendation";
      hiddenRecommendation.appendChild(link);
    });
    await prelockedGate.page.waitForTimeout(50);
    const state = await gateState(prelockedGate.page);
    assert.equal(state.diagnostics.state, "ready");
    assert.deepEqual(state.diagnostics.standaloneCascadeProof, {
      authority: "userscript-runtime-style",
      frameCount: 2,
      nonceBound: true,
      unownedHidden: true,
    });
    assert.deepEqual(state.preauthorizedControl, {
      kind: "preauthorized-userscript-style-control",
      schemaVersion: 3,
      gmAddElementCalls: 1,
    });
    assert.equal(state.releaseProbe, null);
    assert.equal(state.lock, null);
    assert.equal(state.ready, "1");
    assert.equal(state.state, "ready");
    assert.equal(state.visibility, "visible");
    assert.equal(state.opacity, "1");
    assert.equal(state.commentControlProjection.count, 1);
    assert.equal(state.commentControlProjection.initiallyVisibleCount, 1);
    assert.equal(state.commentControlProjection.initiallyDormantCount, 0);
    assert.equal(state.commentControlProjection.currentCount, 1);
    assert.equal(state.commentControlProjection.currentVisibleCount, 1);
    assert.equal(state.commentControlProjection.currentDormantApprovedCount, 0);
    assert.equal(state.commentControlProjection.projectionEpoch, 0);
    assert.equal(state.commentControlProjection.currentProjectionValid, true);
    assert.equal(
      state.commentControlProjection.currentShapeFingerprint,
      state.commentControlProjection.initialShapeFingerprint,
    );
    assert.match(
      state.commentControlProjection.selectorDigest,
      /^comment-control-selectors-v1-[0-9a-f]{8}$/,
    );
    assert.deepEqual(
      state.commentControlProjection.selectors,
      [
        ".post_comment .comment-more",
        ".post_comment .comment_more",
        ".post_comment .pagination",
        ".post_comment > .comment-nav",
        ".post_comment > .comment_nav",
        ".post_comment [data-role='reply-toggle']",
      ].sort(),
    );
  } finally {
    await prelockedGate.context.close();
  }

  const boundedOriginalTitlePrefixGate = await openClienGate(browser, {
    titleHtml: `<h4 class="post_subject">
      <span id="popular-title-badge">[\uC778\uAE30\uAE00]</span>
      <span id="original-title-prefix" class="subject_preface">[G\uB9C8\uCF13]</span>
      ${title}
      <a id="title-share" class="js_share" href="/share">Share</a>
      <div id="title-recommendations"><a href="/other">Recommended post</a></div>
    </h4>
    <script>
      globalThis.__HDF_ORIGINAL_TITLE_PREFIX__ =
        document.querySelector("#original-title-prefix");
      globalThis.__HDF_ORIGINAL_TITLE_PREFIX_TEXT__ =
        globalThis.__HDF_ORIGINAL_TITLE_PREFIX__.textContent;
    </script>`,
  });
  try {
    await boundedOriginalTitlePrefixGate.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
      null,
      { timeout: 5000 },
    );
    const projection = await boundedOriginalTitlePrefixGate.page.evaluate(() => {
      const visible = (element) => {
        const style = getComputedStyle(element);
        return style.display !== "none" &&
          style.visibility !== "hidden" &&
          element.getClientRects().length > 0;
      };
      const prefix = document.querySelector("#original-title-prefix");
      const popular = document.querySelector("#popular-title-badge");
      const share = document.querySelector("#title-share");
      const recommendations = document.querySelector("#title-recommendations");
      return {
        prefixIdentityPreserved:
          prefix === globalThis.__HDF_ORIGINAL_TITLE_PREFIX__,
        prefixTextPreserved:
          prefix.textContent === globalThis.__HDF_ORIGINAL_TITLE_PREFIX_TEXT__,
        prefixVisible: visible(prefix),
        prefixOwned: prefix.hasAttribute("data-hotdeal-focus-keep"),
        prefixRole: prefix.getAttribute("data-hotdeal-focus-role"),
        titleInnerText: document.querySelector(".post_subject").innerText.trim(),
        noise: [popular, share, recommendations].map((element) => ({
          id: element.id,
          visible: visible(element),
          owned: element.hasAttribute("data-hotdeal-focus-keep"),
        })),
      };
    });
    assert.equal(projection.prefixIdentityPreserved, true);
    assert.equal(projection.prefixTextPreserved, true);
    assert.equal(projection.prefixVisible, true);
    assert.equal(projection.prefixOwned, true);
    assert.equal(projection.prefixRole, "title-text");
    assert.equal(projection.titleInnerText, `[G\uB9C8\uCF13] ${title}`);
    projection.noise.forEach((noise) => {
      assert.equal(noise.visible, false, JSON.stringify(noise));
      assert.equal(noise.owned, false, JSON.stringify(noise));
    });
    assert.deepEqual(boundedOriginalTitlePrefixGate.pageErrors, []);
  } finally {
    await boundedOriginalTitlePrefixGate.context.close();
  }

  const inlineImportantLeak = await openClienGate(browser, {
    unownedHtml: `<aside id="unlock-leak" style="display:block!important;
      visibility:visible!important;opacity:1!important;position:fixed!important;
      inset:0!important;z-index:2147483647!important">Unowned inline leak</aside>`,
  });
  try {
    await inlineImportantLeak.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
      null,
      { timeout: 5000 },
    );
    await inlineImportantLeak.page.waitForTimeout(50);
    const state = await gateState(inlineImportantLeak.page);
    const leak = await inlineImportantLeak.page.evaluate(() => {
      const element = document.querySelector("#unlock-leak");
      const style = getComputedStyle(element);
      return {
        owned: element.hasAttribute("data-hotdeal-focus-keep"),
        visible: style.display !== "none" &&
          style.visibility !== "hidden" &&
          Number(style.opacity) !== 0 &&
          element.getClientRects().length > 0,
      };
    });
    assert.equal(state.ready, "1");
    assert.equal(state.diagnostics?.visibleLeakCount, 0);
    assert.deepEqual(leak, { owned: false, visible: false });
    assert.ok(state.leakPaintProbe.sampleCount >= 1);
    assert.equal(state.leakPaintProbe.visibleLeakFrames, 0);
  } finally {
    await inlineImportantLeak.context.close();
  }

  const topLayerLeak = await openClienGate(browser, {
    unownedHtml: `<dialog id="unlock-dialog" open style="display:block!important;
      visibility:visible!important;opacity:1!important;position:fixed!important;
      inset:0!important;z-index:2147483647!important">Unowned top-layer leak</dialog>`,
  });
  try {
    await topLayerLeak.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
      null,
      { timeout: 5000 },
    );
    await topLayerLeak.page.waitForTimeout(50);
    const state = await gateState(topLayerLeak.page);
    const leak = await topLayerLeak.page.evaluate(() => {
      const element = document.querySelector("#unlock-dialog");
      const style = getComputedStyle(element);
      return {
        open: element.hasAttribute("open"),
        owned: element.hasAttribute("data-hotdeal-focus-keep"),
        visible: style.display !== "none" &&
          style.visibility !== "hidden" &&
          Number(style.opacity) !== 0 &&
          element.getClientRects().length > 0,
      };
    });
    assert.equal(state.ready, "1");
    assert.equal(state.diagnostics?.visibleLeakCount, 0);
    assert.deepEqual(leak, { open: false, owned: false, visible: false });
    assert.ok(state.leakPaintProbe.sampleCount >= 1);
    assert.equal(state.leakPaintProbe.visibleLeakFrames, 0);
  } finally {
    await topLayerLeak.context.close();
  }

  const unavailableSecureNonce = await openClienGate(browser, {
    beforeUserScriptSource: String.raw`
      Object.defineProperty(globalThis.crypto, "getRandomValues", {
        configurable: true,
        writable: true,
        value() {
          throw new TypeError("Illegal invocation: synthetic crypto failure");
        },
      });
    `,
  });
  try {
    await unavailableSecureNonce.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "locked" &&
        globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.targetReason ===
          "contained-secure-nonce",
      null,
      { timeout: 5000 },
    );
    const state = await gateState(unavailableSecureNonce.page);
    assert.equal(state.lock, "1");
    assert.equal(state.ready, null);
    assert.equal(state.publisherContentVisible.article, false);
    assert.equal(state.publisherContentVisible.comments, false);
    assert.deepEqual(unavailableSecureNonce.pageErrors, []);
  } finally {
    await unavailableSecureNonce.context.close();
  }

  const releaseProofComputedStyleFailure = await openClienGate(browser, {
    beforeUserScriptSource: String.raw`
      (() => {
        const nativeGetComputedStyle = globalThis.getComputedStyle.bind(globalThis);
        Object.defineProperty(globalThis, "getComputedStyle", {
          configurable: true,
          writable: true,
          value(element, pseudoElement) {
            if (element?.hasAttribute?.("data-hdf-v2-release-probe")) {
              throw new Error("synthetic release-proof computed-style failure");
            }
            return nativeGetComputedStyle(element, pseudoElement);
          },
        });
      })();
    `,
  });
  try {
    await releaseProofComputedStyleFailure.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready" &&
        globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.targetReason
          ?.startsWith("frozen-"),
      null,
      { timeout: 5000 },
    );
    const state = await gateState(releaseProofComputedStyleFailure.page);
    const commentVisible = await releaseProofComputedStyleFailure.page.evaluate(() => {
      const item = document.querySelector(".comment_row");
      const style = getComputedStyle(item);
      return style.display !== "none" && style.visibility !== "hidden" &&
        item.getClientRects().length > 0;
    });
    assert.equal(state.ready, "1");
    assert.equal(state.publisherContentVisible.article, true);
    assert.equal(commentVisible, true);
    assert.deepEqual(releaseProofComputedStyleFailure.pageErrors, []);
  } finally {
    await releaseProofComputedStyleFailure.context.close();
  }

  const stalledReleaseProof = await openClienGate(browser, {
    userSource: withLockedActivationTimeout(userscriptSource, 75),
    beforeUserScriptSource: String.raw`
      Object.defineProperty(globalThis, "requestAnimationFrame", {
        configurable: true,
        writable: true,
        value: () => 1,
      });
    `,
  });
  try {
    await stalledReleaseProof.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready" &&
        globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.targetReason
          ?.includes("timeout"),
      null,
      { timeout: 2000, polling: 25 },
    );
    const state = await gateState(stalledReleaseProof.page);
    const commentVisible = await stalledReleaseProof.page.evaluate(() => {
      const item = document.querySelector(".comment_row");
      const style = getComputedStyle(item);
      return style.display !== "none" && style.visibility !== "hidden" &&
        item.getClientRects().length > 0;
    });
    assert.equal(state.publisherContentVisible.article, true);
    assert.equal(commentVisible, true);
    assert.equal(state.preauthorizedControl?.gmAddElementCalls, 1);
    assert.deepEqual(stalledReleaseProof.pageErrors, []);
  } finally {
    await stalledReleaseProof.context.close();
  }

  const stoppedBeforeRelease = await openClienGate(browser, {
    userSource: withPreReleaseRuntimeStop(userscriptSource),
  });
  try {
    await stoppedBeforeRelease.page.waitForFunction(
      () =>
        globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready" &&
        globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.targetReason ===
          "frozen-runtime-stop-before-release",
      null,
      { timeout: 5000, polling: 25 },
    );
    const stoppedBeforeReleaseState = await gateState(stoppedBeforeRelease.page);
    assert.equal(stoppedBeforeReleaseState.lock, null);
    assert.equal(stoppedBeforeReleaseState.ready, "1");
    assert.equal(
      stoppedBeforeReleaseState.publisherContentVisible.article,
      true,
      JSON.stringify(stoppedBeforeReleaseState),
    );
    const stoppedBeforeReleaseCommentVisible =
      await stoppedBeforeRelease.page.evaluate(() => {
        const item = document.querySelector(".comment_row");
        const style = getComputedStyle(item);
        return style.display !== "none" &&
          style.visibility !== "hidden" &&
          item.getClientRects().length > 0;
      });
    assert.equal(
      stoppedBeforeReleaseCommentVisible,
      true,
      JSON.stringify(stoppedBeforeReleaseState),
    );
    assert.deepEqual(stoppedBeforeRelease.pageErrors, []);
  } finally {
    await stoppedBeforeRelease.context.close();
  }

  const independentSemanticGate = await openClienGate(browser, {
    titleHtml: `<h1 id="semantic-title" itemprop="headline">${title}</h1>`,
    bodyExtra: `<section id="semantic-popular" aria-label="Popular posts">
      <a href="/popular/1">Popular post 1</a>
      <a href="/popular/2">Popular post 2</a>
    </section>`,
  });
  try {
    await independentSemanticGate.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
      null,
      { timeout: 5000 },
    );
    const state = await gateState(independentSemanticGate.page);
    const projection = await independentSemanticGate.page.evaluate(() => {
      const visible = (element) => {
        const style = getComputedStyle(element);
        return style.display !== "none" &&
          style.visibility !== "hidden" &&
          element.getClientRects().length > 0;
      };
      const noise = document.querySelector("#semantic-popular");
      return {
        titleVisible: visible(document.querySelector("#semantic-title")),
        articleVisible: visible(document.querySelector(".post_article")),
        commentVisible: visible(document.querySelector(".comment_row")),
        noiseVisible: visible(noise),
        noiseOwned: noise.hasAttribute("data-hotdeal-focus-keep"),
      };
    });
    assert.equal(state.diagnostics?.targetReason, "algumon-referrer-known-route");
    assert.equal(state.diagnostics?.semanticProjectionCount, 1);
    assert.equal(state.diagnostics?.visibleLeakCount, 0);
    assert.equal(projection.titleVisible, true);
    assert.equal(projection.articleVisible, true);
    assert.equal(projection.commentVisible, true);
    assert.equal(projection.noiseVisible, false);
    assert.equal(projection.noiseOwned, false);
    assert.deepEqual(independentSemanticGate.pageErrors, []);
  } finally {
    await independentSemanticGate.context.close();
  }

  const independentRouteGate = await openClienGate(browser, {
    destinationUrl: "https://www.clien.net/service/board/newhot/987654",
  });
  try {
    await independentRouteGate.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
      null,
      { timeout: 5000 },
    );
    const state = await gateState(independentRouteGate.page);
    const content = await independentRouteGate.page.evaluate(() => {
      const visible = (element) => {
        const style = getComputedStyle(element);
        return style.display !== "none" &&
          style.visibility !== "hidden" &&
          element.getClientRects().length > 0;
      };
      return {
        article: visible(document.querySelector(".post_article")),
        comment: visible(document.querySelector(".comment_row")),
      };
    });
    assert.equal(
      state.diagnostics?.targetReason,
      "algumon-referrer-independent-route",
      JSON.stringify(state),
    );
    assert.equal(state.diagnostics?.visibleLeakCount, 0);
    assert.equal(content.article, true);
    assert.equal(content.comment, true);
    assert.deepEqual(independentRouteGate.pageErrors, []);
  } finally {
    await independentRouteGate.context.close();
  }

  const singletonDriftOracle = await evaluate(page,
    `<main class="drift-shell"><h1 class="drift-title">${title}</h1>
      <article class="drift-body">${longBody}</article>
      <section class="drift-comments"><div class="drift-comment">Original drift comment</div>
        <button id="drift-more">Load more comments</button></section></main>`,
    layout(), null);
  assert.equal(singletonDriftOracle.ok, true, JSON.stringify(singletonDriftOracle));
  assert.equal(singletonDriftOracle.roles.comments, "drift-comments");
  for (const [malformedComments, requiredCommentCount] of [
    ['<div class="drift-comment">Original comment</div><div>Unclassified sibling content</div>', null],
    ['<div class="drift-comment"><form><input placeholder="Write a comment"></form></div>', 1],
    ['<p>Unlabelled paragraph</p>', null],
  ]) {
    const incompleteSingleton = await evaluate(page,
      `<main><h1>${title}</h1><article>${longBody}</article>
        <section class="drift-comments">${malformedComments}</section></main>`, layout(), requiredCommentCount);
    assert.equal(incompleteSingleton.ok, false, JSON.stringify({ malformedComments, incompleteSingleton }));
  }

  for (const width of [1280, 390]) {
    const simultaneousDriftGate = await openClienGate(browser, {
      destinationUrl: "https://www.clien.net/fresh-hotdeal/990004",
      fixtureBodyHtml: `<main class="drift-shell"><h1 class="drift-title">${title}</h1>
        <article class="drift-body"><p>${longBody}</p>
          <a href="https://shop.example/item/drift" id="drift-purchase">Purchase</a></article>
        <section class="drift-comments"><div class="drift-comment">Original drift comment</div>
          <button id="drift-more">Load more comments</button></section></main>`,
      unownedHtml: '<aside id="drift-popular" class="popular">Popular unrelated articles</aside>',
    });
    try {
      await simultaneousDriftGate.page.setViewportSize({ width, height: 900 });
      await simultaneousDriftGate.page.waitForFunction(
        () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
        null, { timeout: 5000 },
      );
      await simultaneousDriftGate.page.evaluate(() => {
        const body = document.querySelector(".drift-body");
        const comment = document.querySelector(".drift-comment");
        window.__driftOriginals = { body, comment, bodyText: body.textContent, commentText: comment.textContent };
        document.querySelector("#drift-more").addEventListener("click", () => {
          const reply = document.createElement("div");
          reply.className = "drift-comment";
          reply.textContent = "Reply after combined path and DOM drift";
          document.querySelector(".drift-comments").append(reply);
        });
      });
      await simultaneousDriftGate.page.getByRole("button", { name: "Load more comments" }).click();
      await simultaneousDriftGate.page.waitForFunction(
        () => document.querySelectorAll('.drift-comment[data-hotdeal-focus-role="comment-item"]').length === 2,
        null, { timeout: 5000 },
      );
      const driftState = await simultaneousDriftGate.page.evaluate(() => {
        const visible = (node) => {
          const style = getComputedStyle(node);
          return style.display !== "none" && style.visibility !== "hidden" &&
            Number(style.opacity) !== 0 && node.getClientRects().length > 0;
        };
        const original = window.__driftOriginals;
        return {
          bodyIdentity: original.body === document.querySelector(".drift-body"),
          commentIdentity: original.comment === document.querySelector(".drift-comment"),
          bodyText: original.bodyText === original.body.textContent,
          commentText: original.commentText === original.comment.textContent,
          bodyVisible: visible(original.body),
          commentsVisible: [...document.querySelectorAll(".drift-comment")].every(visible),
          controlVisible: visible(document.querySelector("#drift-more")),
          purchaseHref: document.querySelector("#drift-purchase").href,
          popularHidden: !visible(document.querySelector("#drift-popular")),
          ready: globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state,
          proofFrames: globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.standaloneCascadeProof?.frameCount,
          leaks: globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.visibleLeakCount,
        };
      });
      assert.deepEqual(driftState, {
        bodyIdentity: true, commentIdentity: true, bodyText: true, commentText: true,
        bodyVisible: true, commentsVisible: true, controlVisible: true,
        purchaseHref: "https://shop.example/item/drift", popularHidden: true,
        ready: "ready", proofFrames: 2, leaks: 0,
      }, JSON.stringify({ width, driftState }));
      assert.deepEqual(simultaneousDriftGate.pageErrors, []);
    } finally {
      await simultaneousDriftGate.context.close();
    }
  }

  for (const width of [1280, 390]) {
    const continuedObserverGate = await openClienGate(browser, {
      commentsHtml: `<div class="comment"><div class="comment_row">Original comment</div></div>
        <button class="comment_nav">Load more comments</button>`,
    });
    try {
      await continuedObserverGate.page.setViewportSize({ width, height: 900 });
      await continuedObserverGate.page.waitForFunction(
        () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
        null, { timeout: 5000 },
      );
      await continuedObserverGate.page.evaluate(() => {
        const body = document.querySelector(".post_article");
        const comment = document.querySelector(".comment_row");
        window.__continuingOriginals = { body, comment, bodyText: body.textContent, commentText: comment.textContent };
        document.querySelector(".comment_nav").addEventListener("click", () => {
          const reply = document.createElement("div");
          reply.className = "comment_row";
          reply.id = "reply-after-unclassified-panel";
          reply.textContent = "Reply after unclassified panel";
          document.querySelector(".comment").append(reply);
        });
        const panel = document.createElement("div");
        panel.id = "unclassified-panel";
        panel.textContent = "Unclassified unrelated extra content";
        document.querySelector(".post_comment").append(panel);
      });
      await continuedObserverGate.page.waitForTimeout(100);
      await continuedObserverGate.page.evaluate(() => {
        const titleText = document.querySelector(".post_subject").firstChild;
        titleText.data = titleText.data;
      });
      await continuedObserverGate.page.waitForTimeout(100);
      await continuedObserverGate.page.evaluate(() => {
        window.__originalReaderUrl = location.href;
        history.pushState({}, "", "/service/board/jirum/99999998");
      });
      await continuedObserverGate.page.waitForFunction(
        () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.targetReason === "frozen-navigation-identity",
        null, { timeout: 5000 },
      );
      await continuedObserverGate.page.evaluate(() => {
        const noise = document.querySelector("#unclassified-panel");
        noise.setAttribute("data-hotdeal-focus-keep", document.querySelector(".post_article").getAttribute("data-hotdeal-focus-keep"));
      });
      await continuedObserverGate.page.waitForTimeout(100);
      assert.equal(await continuedObserverGate.page.evaluate(() => {
        const node = document.querySelector("#unclassified-panel");
        const style = getComputedStyle(node);
        return style.display !== "none" && style.visibility !== "hidden" && node.getClientRects().length > 0;
      }), false);
      await continuedObserverGate.page.evaluate(() => history.replaceState({}, "", window.__originalReaderUrl));
      await continuedObserverGate.page.waitForFunction(
        () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.targetReason === "algumon-referrer-known-route",
        null, { timeout: 5000 },
      );
      await continuedObserverGate.page.getByRole("button", { name: "Load more comments" }).click();
      await continuedObserverGate.page.waitForFunction(
        () => document.querySelector('#reply-after-unclassified-panel')
          ?.getAttribute('data-hotdeal-focus-role') === 'comment-item',
        null, { timeout: 5000 },
      );
      await continuedObserverGate.page.evaluate(() => {
        const panel = document.querySelector("#unclassified-panel");
        const body = document.querySelector(".post_article");
        panel.setAttribute("data-hotdeal-focus-keep", body.getAttribute("data-hotdeal-focus-keep"));
        document.querySelector("style[data-hotdeal-focus-runtime-style]").textContent += "\n/* later publisher rewrite */";
      });
      await continuedObserverGate.page.waitForTimeout(100);
      const continuingState = await continuedObserverGate.page.evaluate(() => {
        const visible = (node) => {
          const style = getComputedStyle(node);
          return style.display !== "none" && style.visibility !== "hidden" &&
            Number(style.opacity) !== 0 && node.getClientRects().length > 0;
        };
        const original = window.__continuingOriginals;
        return {
          bodyIdentity: original.body === document.querySelector(".post_article"),
          commentIdentity: original.comment === document.querySelector(".comment_row"),
          bodyText: original.bodyText === original.body.textContent,
          commentText: original.commentText === original.comment.textContent,
          bodyVisible: visible(original.body),
          commentsVisible: [...document.querySelectorAll(".comment_row")].every(visible),
          panelHidden: !visible(document.querySelector("#unclassified-panel")),
          ready: globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state,
          proofFrames: globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.standaloneCascadeProof?.frameCount,
          leaks: globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.visibleLeakCount,
        };
      });
      assert.deepEqual(continuingState, {
        bodyIdentity: true, commentIdentity: true, bodyText: true, commentText: true,
        bodyVisible: true, commentsVisible: true, panelHidden: true,
        ready: "ready", proofFrames: 2, leaks: 0,
      }, JSON.stringify({ width, continuingState }));
      assert.deepEqual(continuedObserverGate.pageErrors, []);
    } finally {
      await continuedObserverGate.context.close();
    }
  }

  const initialAutonomousNoiseGate = await openClienGate(browser, {
    bodyExtra: `<section id="initial-popular" aria-label="인기글">
        <h2>인기글</h2><a href="/popular/1">인기 게시물 1</a>
        <a href="/popular/2">인기 게시물 2</a>
      </section>
      <section id="initial-recommended" aria-label="Recommended posts">
        <h2>Recommended posts</h2><a href="/recommended/1">Other post</a>
        <a href="/recommended/2">Another post</a>
      </section>`,
    commentsHtml: `<div class="comment"><div class="comment_row" itemprop="comment">
        Visible comment
      </div></div>
      <div class="comment_nav">Visible comment control</div>
      <aside id="initial-related-comments" aria-label="関連投稿">
        <a href="/related/1">関連記事 1</a><a href="/related/2">関連記事 2</a>
      </aside>`,
  });
  try {
    await initialAutonomousNoiseGate.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
      null,
      { timeout: 5000 },
    );
    const state = await gateState(initialAutonomousNoiseGate.page);
    const projection = await initialAutonomousNoiseGate.page.evaluate(() => {
      const visible = (element) => {
        const style = getComputedStyle(element);
        return style.display !== "none" &&
          style.visibility !== "hidden" &&
          element.getClientRects().length > 0;
      };
      const noise = [
        "#initial-popular",
        "#initial-recommended",
        "#initial-related-comments",
      ].map((selector) => {
        const element = document.querySelector(selector);
        return {
          selector,
          visible: visible(element),
          owned: element.hasAttribute("data-hotdeal-focus-keep"),
        };
      });
      return {
        noise,
        title: document.querySelector(".post_subject").textContent.trim(),
        articleVisible: visible(document.querySelector(".post_article")),
        commentVisible: visible(document.querySelector(".comment_row")),
      };
    });
    assert.equal(
      state.diagnostics?.targetReason,
      "algumon-referrer-known-route",
      JSON.stringify(state),
    );
    assert.equal(state.diagnostics?.visibleLeakCount, 0);
    assert.equal(projection.title, title);
    assert.equal(projection.articleVisible, true);
    assert.equal(projection.commentVisible, true);
    projection.noise.forEach((noise) => {
      assert.equal(noise.visible, false, JSON.stringify(noise));
      assert.equal(noise.owned, false, JSON.stringify(noise));
    });
    assert.deepEqual(initialAutonomousNoiseGate.pageErrors, []);
  } finally {
    await initialAutonomousNoiseGate.context.close();
  }

  const lateAutonomousNoiseGate = await openClienGate(browser, {
    bodyExtra: '<p id="stable-body-sentinel">Stable authored body sentinel</p>',
  });
  try {
    await lateAutonomousNoiseGate.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
      null,
      { timeout: 5000 },
    );
    await lateAutonomousNoiseGate.page.evaluate(() => {
      globalThis.__HDF_RUNTIME_SENTINELS__ = {
        title: document.querySelector(".post_subject"),
        body: document.querySelector("#stable-body-sentinel"),
        comment: document.querySelector(".comment_row"),
        titleText: document.querySelector(".post_subject").textContent,
        bodyText: document.querySelector("#stable-body-sentinel").textContent,
        commentText: document.querySelector(".comment_row").textContent,
      };
      const article = document.querySelector(".post_article");
      [
        ["late-popular-ko", "인기글", "인기 게시물"],
        ["late-recommended-en", "Recommended posts", "Recommended post"],
        ["late-related-ja", "関連投稿", "関連記事"],
        ["late-popular-zh", "热门文章", "热门内容"],
      ].forEach(([id, label, text]) => {
        const section = document.createElement("section");
        section.id = id;
        section.setAttribute("aria-label", label);
        section.innerHTML = `<h2>${label}</h2><a href="/popular/1">${text} 1</a>` +
          `<a href="/popular/2">${text} 2</a>`;
        article.appendChild(section);
      });
      const lateBody = document.createElement("p");
      lateBody.id = "late-body-sentinel";
      lateBody.textContent = "Late legitimate authored body content";
      article.appendChild(lateBody);

      const commentNoise = document.createElement("aside");
      commentNoise.id = "late-comment-popular";
      commentNoise.setAttribute("aria-label", "추천글");
      commentNoise.innerHTML =
        '<a href="/recommended/1">추천 게시물 1</a><a href="/recommended/2">추천 게시물 2</a>';
      document.querySelector(".post_comment").appendChild(commentNoise);

      const comment = document.createElement("div");
      comment.id = "late-comment";
      comment.className = "comment_row";
      comment.setAttribute("itemprop", "comment");
      comment.textContent = "Late legitimate comment";
      document.querySelector(".post_comment > .comment").appendChild(comment);
    });
    await lateAutonomousNoiseGate.page.waitForFunction(
      () =>
        document.querySelector("#late-comment")
          ?.hasAttribute("data-hotdeal-focus-keep") &&
        document.querySelector("#late-body-sentinel")
          ?.hasAttribute("data-hotdeal-focus-keep") &&
        !document.querySelector("#late-popular-ko")
          ?.hasAttribute("data-hotdeal-focus-keep") &&
        !document.querySelector("#late-comment-popular")
          ?.hasAttribute("data-hotdeal-focus-keep"),
      null,
      { timeout: 5000 },
    );
    const state = await gateState(lateAutonomousNoiseGate.page);
    const projection = await lateAutonomousNoiseGate.page.evaluate(() => {
      const visible = (element) => {
        const style = getComputedStyle(element);
        return style.display !== "none" &&
          style.visibility !== "hidden" &&
          element.getClientRects().length > 0;
      };
      const sentinels = globalThis.__HDF_RUNTIME_SENTINELS__;
      const noise = [
        "#late-popular-ko",
        "#late-recommended-en",
        "#late-related-ja",
        "#late-popular-zh",
        "#late-comment-popular",
      ].map((selector) => {
        const element = document.querySelector(selector);
        return {
          selector,
          visible: visible(element),
          owned: element.hasAttribute("data-hotdeal-focus-keep"),
        };
      });
      return {
        noise,
        identitiesPreserved:
          sentinels.title === document.querySelector(".post_subject") &&
          sentinels.body === document.querySelector("#stable-body-sentinel") &&
          sentinels.comment === document.querySelector(".comment_row"),
        textsPreserved:
          sentinels.titleText === document.querySelector(".post_subject").textContent &&
          sentinels.bodyText === document.querySelector("#stable-body-sentinel").textContent &&
          sentinels.commentText === document.querySelector(".comment_row").textContent,
        lateBodyVisible: visible(document.querySelector("#late-body-sentinel")),
        lateCommentVisible: visible(document.querySelector("#late-comment")),
      };
    });
    assert.equal(state.diagnostics?.state, "ready", JSON.stringify(state));
    assert.equal(
      state.diagnostics?.targetReason,
      "algumon-referrer-known-route",
      JSON.stringify(state),
    );
    assert.equal(state.diagnostics?.visibleLeakCount, 0);
    assert.equal(projection.identitiesPreserved, true);
    assert.equal(projection.textsPreserved, true);
    assert.equal(projection.lateBodyVisible, true);
    assert.equal(projection.lateCommentVisible, true);
    projection.noise.forEach((noise) => {
      assert.equal(noise.visible, false, JSON.stringify(noise));
      assert.equal(noise.owned, false, JSON.stringify(noise));
    });
    assert.deepEqual(lateAutonomousNoiseGate.pageErrors, []);
  } finally {
    await lateAutonomousNoiseGate.context.close();
  }

  const dormantPublisherControl = await openClienGate(browser, {
    commentsHtml: `<div class="comment"><div class="comment_row" itemprop="comment">Visible comment</div></div>
      <div class="comment_nav" style="display:none">Dormant publisher control</div>`,
  });
  try {
    await dormantPublisherControl.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
      null,
      { timeout: 5000 },
    );
    const dormantInitialState = await gateState(dormantPublisherControl.page);
    assert.equal(dormantInitialState.commentControlProjection.count, 1);
    assert.equal(dormantInitialState.commentControlProjection.initiallyVisibleCount, 0);
    assert.equal(dormantInitialState.commentControlProjection.initiallyDormantCount, 1);
    assert.equal(dormantInitialState.commentControlProjection.currentVisibleCount, 0);
    assert.equal(dormantInitialState.commentControlProjection.currentDormantApprovedCount, 1);
    const dormantInitialFingerprint =
      dormantInitialState.commentControlProjection.initialShapeFingerprint;
    await dormantPublisherControl.page.evaluate(() => {
      document.querySelector(".comment_nav").style.display = "block";
    });
    await dormantPublisherControl.page.waitForTimeout(100);
    const state = await gateState(dormantPublisherControl.page);
    assert.equal(state.diagnostics?.state, "ready");
    assert.equal(state.ready, "1");
    assert.equal(state.commentControlProjection.projectionEpoch, 1, JSON.stringify(state));
    assert.equal(state.commentControlProjection.currentVisibleCount, 1);
    assert.equal(state.commentControlProjection.currentDormantApprovedCount, 0);
    assert.equal(
      state.commentControlProjection.currentShapeFingerprint,
      dormantInitialFingerprint,
    );
  } finally {
    await dormantPublisherControl.context.close();
  }

  const publisherControlBecomesDormant = await openClienGate(browser);
  try {
    await publisherControlBecomesDormant.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
      null,
      { timeout: 5000 },
    );
    const beforeDormant = await gateState(publisherControlBecomesDormant.page);
    assert.equal(beforeDormant.commentControlProjection.currentVisibleCount, 1);
    await publisherControlBecomesDormant.page.evaluate(() => {
      document.querySelector(".comment_nav").style.display = "none";
    });
    await publisherControlBecomesDormant.page.waitForTimeout(200);
    const afterDormant = await gateState(publisherControlBecomesDormant.page);
    assert.equal(afterDormant.diagnostics?.state, "ready", JSON.stringify(afterDormant));
    assert.equal(afterDormant.commentControlProjection.currentVisibleCount, 0);
    assert.equal(afterDormant.commentControlProjection.currentDormantApprovedCount, 1);
    assert.equal(afterDormant.commentControlProjection.currentProjectionValid, true);
  } finally {
    await publisherControlBecomesDormant.context.close();
  }

  const inertCommentCleanupGate = await openClienGate(browser, {
    commentsHtml: `
      <div class="comment"><div class="comment_row" itemprop="comment">Visible comment</div></div>
      <div class="comment_nav">Visible comment control</div>
      <script id="publisher-comment-bootstrap">globalThis.__publisherCommentBootstrap = true;</script>
    `,
  });
  try {
    await inertCommentCleanupGate.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
      null,
      { timeout: 5000 },
    );
    await inertCommentCleanupGate.page.evaluate(() => {
      const mount = document.querySelector(".post_comment");
      const whitespace = Array.from(mount.childNodes).find(
        (node) => node.nodeType === Node.TEXT_NODE && !node.data.trim(),
      );
      if (!whitespace) throw new Error("whitespace fixture node missing");
      whitespace.remove();
      document.querySelector("#publisher-comment-bootstrap").remove();
    });
    await inertCommentCleanupGate.page.waitForTimeout(100);
    const inertCleanupState = await gateState(inertCommentCleanupGate.page);
    assert.equal(
      inertCleanupState.diagnostics?.state,
      "ready",
      JSON.stringify(inertCleanupState),
    );
    assert.equal(inertCleanupState.ready, "1");
    const survivingCommentVisible = await inertCommentCleanupGate.page.evaluate(() => {
      const item = document.querySelector(".comment_row");
      const style = getComputedStyle(item);
      return style.display !== "none" && style.visibility !== "hidden" &&
        item.getClientRects().length > 0;
    });
    assert.equal(survivingCommentVisible, true);
  } finally {
    await inertCommentCleanupGate.context.close();
  }

  const dynamicControlProjectionGate = await openClienGate(browser);
  try {
    await dynamicControlProjectionGate.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
      null,
      { timeout: 5000 },
    );
    const initialState = await gateState(dynamicControlProjectionGate.page);
    const initialProof = initialState.commentControlProjection;
    await dynamicControlProjectionGate.page.evaluate(() => {
      const control = document.createElement("button");
      control.className = "comment_more";
      control.textContent = "Load more replies";
      document.querySelector(".post_comment").appendChild(control);
    });
    await dynamicControlProjectionGate.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__
        ?.commentControlProjection?.projectionEpoch === 1,
    );
    const addedState = await gateState(dynamicControlProjectionGate.page);
    assert.equal(addedState.commentControlProjection.currentCount, 2);
    assert.equal(addedState.commentControlProjection.currentProjectionValid, true);
    assert.notEqual(
      addedState.commentControlProjection.currentShapeFingerprint,
      initialProof.initialShapeFingerprint,
    );
    assert.equal(
      addedState.commentControlProjection.selectorDigest,
      initialProof.selectorDigest,
    );
    await dynamicControlProjectionGate.page.evaluate(() => {
      document.querySelector(".comment_more").remove();
    });
    await dynamicControlProjectionGate.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__
        ?.commentControlProjection?.projectionEpoch === 2,
    );
    const removedState = await gateState(dynamicControlProjectionGate.page);
    assert.equal(removedState.commentControlProjection.currentCount, 1);
    assert.equal(removedState.commentControlProjection.currentProjectionValid, true);
    assert.equal(
      removedState.commentControlProjection.currentShapeFingerprint,
      initialProof.initialShapeFingerprint,
    );
    assert.equal(removedState.commentControlProjection.count, initialProof.count);
  } finally {
    await dynamicControlProjectionGate.context.close();
  }

  const sponsoredDormantControl = await openClienGate(browser, {
    commentsHtml: `<div class="comment"><div class="comment_row" itemprop="comment">Visible comment</div></div>
      <div class="comment_nav sponsor" style="display:none">Sponsored control</div>`,
  });
  try {
    await sponsoredDormantControl.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
      null,
      { timeout: 5000 },
    );
    await sponsoredDormantControl.page.evaluate(() => {
      document.querySelector(".comment_nav").style.display = "block";
    });
    await sponsoredDormantControl.page.waitForTimeout(100);
    const state = await gateState(sponsoredDormantControl.page);
    const sponsoredControlState = await sponsoredDormantControl.page.evaluate(() => {
      const control = document.querySelector(".comment_nav");
      const style = getComputedStyle(control);
      return {
        visible: style.display !== "none" &&
          style.visibility !== "hidden" &&
          control.getClientRects().length > 0,
        owned: control.hasAttribute("data-hotdeal-focus-keep"),
      };
    });
    assert.equal(state.diagnostics?.state, "ready", JSON.stringify(state));
    assert.equal(sponsoredControlState.visible, false, JSON.stringify(sponsoredControlState));
    assert.equal(sponsoredControlState.owned, false, JSON.stringify(sponsoredControlState));
  } finally {
    await sponsoredDormantControl.context.close();
  }

  const cssMutationGate = await openClienGate(browser);
  try {
    await cssMutationGate.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
      null,
      { timeout: 5000 },
    );
    await cssMutationGate.page.evaluate(() => {
      const runtimeStyle = document.querySelector(
        'style[data-hotdeal-focus-runtime-style="2"]',
      );
      Object.defineProperty(runtimeStyle, "remove", {
        configurable: true,
        value() {
          throw new Error("synthetic runtime-style removal failure");
        },
      });
      const style = document.createElement("style");
      style.textContent = `.post_article::after {
        content: "Sponsored"; position: fixed; left: 0; top: 0;
        width: 100vw; height: 100vh;
      }`;
      document.head.appendChild(style);
    });
    await cssMutationGate.page.waitForFunction(
      () => ![...document.querySelectorAll("style")].some((style) =>
        style.textContent.includes('content: "Sponsored"')),
      null,
      { timeout: 5000 },
    );
    const state = await gateState(cssMutationGate.page);
    const cssContainment = await cssMutationGate.page.evaluate(() => {
      const article = document.querySelector(".post_article");
      return {
        pseudoContent: getComputedStyle(article, "::after").content,
        commentVisible: (() => {
          const item = document.querySelector(".comment_row");
          const style = getComputedStyle(item);
          return style.display !== "none" &&
            style.visibility !== "hidden" &&
            item.getClientRects().length > 0;
        })(),
      };
    });
    assert.equal(state.diagnostics?.state, "ready", JSON.stringify(state));
    assert.equal(state.publisherContentVisible.article, true);
    assert.ok(["none", "normal", '""'].includes(cssContainment.pseudoContent));
    assert.equal(cssContainment.commentVisible, true);
    assert.deepEqual(cssMutationGate.pageErrors, []);
  } finally {
    await cssMutationGate.context.close();
  }

  const shadowMutationGate = await openClienGate(browser, {
    bodyExtra: '<div id="runtime-shadow-host">Fallback authored detail</div>',
  });
  try {
    await shadowMutationGate.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
      null,
      { timeout: 5000 },
    );
    await shadowMutationGate.page.evaluate(() => {
      document.querySelector("#runtime-shadow-host").attachShadow({ mode: "closed" });
    });
    await shadowMutationGate.page.waitForFunction(
      () => !document.querySelector("#runtime-shadow-host")
        ?.hasAttribute("data-hotdeal-focus-keep"),
      null,
      { timeout: 5000 },
    );
    const state = await gateState(shadowMutationGate.page);
    const shadowHostState = await shadowMutationGate.page.evaluate(() => {
      const host = document.querySelector("#runtime-shadow-host");
      const style = getComputedStyle(host);
      return {
        visible: style.display !== "none" &&
          style.visibility !== "hidden" &&
          host.getClientRects().length > 0,
        owned: host.hasAttribute("data-hotdeal-focus-keep"),
      };
    });
    assert.equal(state.diagnostics?.state, "ready", JSON.stringify(state));
    assert.equal(state.publisherContentVisible.article, true);
    assert.equal(shadowHostState.visible, false);
    assert.equal(shadowHostState.owned, false);
  } finally {
    await shadowMutationGate.context.close();
  }

  const popoverMutationGate = await openClienGate(browser, {
    bodyExtra: '<div id="runtime-popover" popover>Projected popup</div>',
  });
  try {
    await popoverMutationGate.page.waitForFunction(
      () => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready",
      null,
      { timeout: 5000 },
    );
    await popoverMutationGate.page.evaluate(() => {
      document.querySelector("#runtime-popover").showPopover();
    });
    await popoverMutationGate.page.waitForTimeout(100);
    const state = await gateState(popoverMutationGate.page);
    const popoverState = await popoverMutationGate.page.evaluate(() => {
      const popover = document.querySelector("#runtime-popover");
      const style = getComputedStyle(popover);
      return {
        open: popover.matches(":popover-open"),
        visible: style.display !== "none" &&
          style.visibility !== "hidden" &&
          popover.getClientRects().length > 0,
        owned: popover.hasAttribute("data-hotdeal-focus-keep"),
      };
    });
    assert.equal(state.diagnostics?.state, "ready", JSON.stringify(state));
    assert.equal(state.publisherContentVisible.article, true);
    assert.equal(popoverState.open, false);
    assert.equal(popoverState.visible, false);
    assert.equal(popoverState.owned, false);
  } finally {
    await popoverMutationGate.context.close();
  }
} finally {
  await browser.close();
}

process.stdout.write("ProjectionTuple semantic/runtime oracle fixtures passed\n");
