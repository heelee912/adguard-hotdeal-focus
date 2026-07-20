import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";
import { chromium } from "playwright";

const require = createRequire(import.meta.url);
const extendedCssPackage = require("@adguard/extended-css/package.json");
const extendedCssBundlePath = require.resolve("@adguard/extended-css");
const expectedExtendedCssVersion = "2.0.52";
const filterPath = new URL("../filter-static.txt", import.meta.url);
const configPath = new URL("../config/sites.json", import.meta.url);
const extendedCssDelimiter = "#?#";
const eomisaeRulePrefix =
  "[$domain=eomisae.co.kr,path=|/fs/]#?#";

assert.equal(
  extendedCssPackage.version,
  expectedExtendedCssVersion,
  "the product-semantic oracle must stay pinned to AdGuard's embedded ExtendedCSS floor",
);

const cosmeticRules = fs
  .readFileSync(filterPath, "utf8")
  .split(/\r?\n/u)
  .filter((line) => line.includes(extendedCssDelimiter));
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
const configuredRouteKeys = new Set();
for (const site of config.sites) {
  for (const layout of site.layouts) {
    for (const contract of [layout, ...(layout.variants ?? [])]) {
      const domain = contract.domain ?? layout.domain;
      const paths = contract.paths ?? [contract.path];
      for (const path of paths) {
        configuredRouteKeys.add(JSON.stringify([domain, path]));
      }
    }
  }
}
assert.equal(
  cosmeticRules.length,
  configuredRouteKeys.size,
  "filter-static.txt must contain exactly one rule per unique base/variant route contract",
);

const selectors = cosmeticRules.map((rule) => {
  const delimiterIndex = rule.indexOf(extendedCssDelimiter);
  const selector = rule.slice(delimiterIndex + extendedCssDelimiter.length);
  assert.ok(selector, `generated rule has no selector: ${rule}`);
  return selector;
});

const eomisaeRule = cosmeticRules.find((rule) => rule.startsWith(eomisaeRulePrefix));
assert.ok(eomisaeRule, "the Eomisae /fs/ generated rule is missing");
const eomisaeSelector = eomisaeRule.slice(eomisaeRulePrefix.length);

let unwrappedMarkerCount = 0;
const oldRelativeSelector = eomisaeSelector.replace(
  /:has\(:is\(([^()]*)\)\)/gu,
  (_match, marker) => {
    unwrappedMarkerCount += 1;
    return `:has(${marker})`;
  },
);
assert.ok(
  unwrappedMarkerCount > 0,
  "the Eomisae rule must contain document-scoped :has(:is()) markers",
);
assert.notEqual(oldRelativeSelector, eomisaeSelector);

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  await page.setContent(`<!doctype html><html><body>
    <main id="page">
      <section id="D_">
        <div class="_hd" id="title-shell"><h2 id="title">Deal title</h2></div>
        <div class="et_vars" id="product"><span id="product-child">Price</span></div>
        <article id="ARTICLE">
          <div class="rhymix_content" id="article-body">
            <p id="article-child">Article body</p>
          </div>
        </article>
      </section>
      <section id="C_">
        <div id="comment"><span id="comment-heading-child">Comments</span></div>
        <div class="_bd" id="comment-board">
          <div class="_comment" id="comment_1">
            <span id="comment-child">Complete reply</span>
          </div>
          <nav class="pagination" id="pagination"><a id="page-link">2</a></nav>
          <button class="more" id="more">More</button>
        </div>
      </section>
      <aside id="noise">Recommended post</aside>
    </main>
  </body></html>`);
  await page.addScriptTag({ path: extendedCssBundlePath });

  const result = await page.evaluate(
    ({ generatedSelectors, newSelector, oldSelector }) => {
      const ExtendedCssEngine = globalThis.ExtendedCss.ExtendedCss;
      const elementNames = (elements) =>
        Array.from(elements, (element) => element.id || element.tagName);
      const validations = generatedSelectors.map((selector) =>
        ExtendedCssEngine.validate(selector));
      return {
        validations,
        extendedNew: elementNames(ExtendedCssEngine.query(newSelector)),
        extendedOld: elementNames(ExtendedCssEngine.query(oldSelector)),
        nativeNew: elementNames(document.querySelectorAll(newSelector)),
        nativeOld: elementNames(document.querySelectorAll(oldSelector)),
      };
    },
    {
      generatedSelectors: selectors,
      newSelector: eomisaeSelector,
      oldSelector: oldRelativeSelector,
    },
  );

  const invalidSelectors = result.validations.flatMap((validation, index) =>
    validation.ok
      ? []
      : [{ index, error: validation.error, selector: selectors[index] }]);
  assert.deepEqual(
    invalidSelectors,
    [],
    "every generated selector must parse in AdGuard ExtendedCSS 2.0.52",
  );
  assert.deepEqual(
    result.extendedNew,
    ["noise"],
    "the generated rule must preserve document-scoped article/comment ancestors",
  );
  assert.deepEqual(
    result.extendedOld,
    ["D_", "title-shell", "ARTICLE", "comment-board", "noise"],
    "the historical selector must exactly reproduce ancestor over-hide and content loss",
  );
  assert.deepEqual(
    result.nativeNew,
    result.extendedNew,
    "native qSA and ExtendedCSS must independently agree on the fixed projection",
  );
  assert.deepEqual(
    result.nativeOld,
    result.extendedOld,
    "native qSA and ExtendedCSS must independently reproduce the historical bug",
  );
} finally {
  await browser.close();
}

await import("./test_gate_v2.mjs");

process.stdout.write(
  `ExtendedCSS ${expectedExtendedCssVersion}: ${selectors.length}/${selectors.length} selectors valid; Eomisae old/new/native oracle passed\n`,
);
