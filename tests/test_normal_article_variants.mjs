import assert from "node:assert/strict";
import fs from "node:fs";
import { chromium } from "playwright";
import { PREAUTHORIZED_ADGUARD_CONTROL_SOURCE } from "../scripts/preauthorized_adguard_control.mjs";
import {
  FIRST_PAINT_PROBE_SOURCE, auditUserscriptGate, commentControlSelectorDigestsForUrl,
  resultHasZeroLeak, userscriptGateFailures,
  semanticOracle, semanticOracleEvidence, semanticOracleContractFailures,
} from "../scripts/audit_pages.mjs";

// Ordinary variations of the observed Arca article template are not evidence of
// an invalid article. No request in this suite reaches a real site.
const source = fs.readFileSync(new URL("../hotdeal-focus.user.js", import.meta.url), "utf8");
const imageSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="240" height="160"><rect width="240" height="160" fill="#2467ab"/></svg>';
const image = "data:image/svg+xml," + encodeURIComponent(imageSvg);
const escapeHtml = value => String(value).replace(/[&<>"']/g, character => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[character]));
const cases = [
  { name: "one-character-title", title: "쌀" },
  { name: "two-character-title", title: "우유" },
  { name: "three-character-title", title: "컵라면" },
  { name: "one-word-english-title", title: "DOOM" },
  { name: "emoji-title", title: "🎁" },
  { name: "zero-price-image-body", title: "무료 게임", price: "0원" },
  { name: "free-price-image-body", title: "무료 배포", price: "무료" },
  { name: "sponsored-purchase-link", title: "제휴 구매 링크 상품", purchaseRel: "sponsored nofollow" },
  { name: "promotional-product-image-filename", title: "행사 안내 이미지 상품", imageUrl: "https://ac-o.arca.live/assets/promo-affiliate-ad-sale-product.png" },
  { name: "one-character-body", title: "짧은 본문 상품", body: "text", text: "쌀" },
  { name: "single-character-comments", title: "한 글자 댓글 상품", comments: ["ㅇ", "ㅋ"] },
  { name: "emoji-comments", title: "이모티콘 댓글 상품", comments: ["👍", "😂"] },
  { name: "image-only-comment", title: "이미지 댓글 상품", comments: [{ image: true }] },
  { name: "metadata-absent", title: "메타 정보 없는 상품", metadata: "absent" },
  { name: "split-short-title-without-metadata", title: "우유", titleParts: ["우", "유"], metadata: "absent" },
  { name: "split-one-word-title", title: "듀얼센스", titleParts: ["듀얼", "센스"] },
  { name: "twitter-metadata-stale", title: "수정된 상품 제목", metadata: "twitter-stale" },
  { name: "all-title-metadata-stale", title: "현재 보이는 상품 제목", metadata: "all-stale" },
  { name: "paginated-comment-total", title: "댓글 페이지 상품", comments: ["좋습니다", "감사합니다"], count: 31 },
  { name: "zero-loaded-comments-stale-total", title: "댓글 없는 상품", count: 0, metadataCommentCount: 9 },
  { name: "hidden-responsive-page-copy", title: "반응형 페이지 상품", hiddenCopy: "article.board-article" },
  { name: "hidden-responsive-wrapper-copy", title: "반응형 래퍼 상품", hiddenCopy: ".article-wrapper" },
  { name: "hidden-responsive-role-copies", title: "반응형 제목 본문 상품", hiddenCopy: ".article-head > .title, .article-body" },
  { name: "native-collapsed-reply", title: "접힌 댓글 상품", comments: ["보이는 댓글", { text: "원래 접혀 있던 답글", hidden: true }], foldedReply: true },
];

function fixture(article) {
  const comments = article.comments || [];
  const count = article.count ?? comments.length;
  const titleMarkup = article.titleParts
    ? article.titleParts.map((part, index) => `<span id="original-title-part-${index}">${escapeHtml(part)}</span>`).join("")
    : escapeHtml(article.title);
  const metadata = article.metadata === "absent" ? "" : `
    <meta property="og:title" content="${escapeHtml(article.metadata === "all-stale" ? "수정 전 상품 제목" : article.title)} - 핫딜 채널">
    <meta property="og:type" content="website">
    ${article.metadata === "twitter-stale" || article.metadata === "all-stale"
      ? '<meta name="twitter:title" content="수정 전 상품 제목 - 핫딜 채널">' : ""}
    ${article.metadataCommentCount === undefined ? "" : `<script type="application/ld+json">${JSON.stringify({
      "@context": "https://schema.org", "@type": "DiscussionForumPosting",
      headline: article.title, commentCount: article.metadataCommentCount,
    })}</script>`}`;
  const body = article.body === "text"
    ? `<p id="original-body-content">${escapeHtml(article.text)}</p>`
    : `<p><img id="original-body-content" src="${article.imageUrl || image}" width="240" height="160"></p>`;
  const commentHtml = comments.map((comment, index) => `
    <div class="comment-wrapper"${comment.hidden ? ' id="folded-replies" hidden' : ""}><div class="comment-item" id="c_${index + 1}">
      <div class="content">${comment.image
        ? `<img id="original-comment-image-${index}" class="emoticon" src="${image}" width="80" height="54" alt="">`
        : escapeHtml(comment.text ?? comment)}</div>
    </div></div>`).join("");
  const pagination = count > comments.length && comments.length > 0
    ? '<nav class="pagination"><a href="?p=2#comment">다음 댓글</a></nav>' : "";
  const responsiveCopy = article.hiddenCopy ? `<script>
    for (const original of Array.from(document.querySelectorAll(${JSON.stringify(article.hiddenCopy)}))) {
      const copy = original.cloneNode(true);
      copy.style.display = "none";
      copy.dataset.fixtureHiddenCopy = "1";
      copy.removeAttribute("id");
      for (const child of copy.querySelectorAll("[id]")) child.removeAttribute("id");
      original.after(copy);
    }
  </script>` : "";
  return `<!doctype html><html><head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(article.title)} - 핫딜 채널</title>${metadata}
    <style>.d-none { display:none !important; } img { max-width:100%; height:auto; }</style>
    </head><body><div class="root-container"><article class="board-article">
    <div class="article-view"><div class="article-wrapper">
      <div class="article-head"><div class="title" id="original-title"><span class="badge category-badge">기타</span><span class="title"><img src="${image}" width="18" height="18" alt="">&nbsp;</span> ${titleMarkup}</div></div>
      <div class="article-body" id="original-body">
        <table class="table align-middle article-options" id="original-product"><tbody>
          <tr><td>링크</td><td><a id="original-purchase" href="https://shop.example/product/1"${article.purchaseRel ? ` rel="${escapeHtml(article.purchaseRel)}"` : ""}>https://shop.example/product/1</a></td></tr>
          <tr><td>쇼핑몰</td><td>공식 스토어</td></tr>
          <tr><td>상품명</td><td>${escapeHtml(article.title)}</td></tr>
          <tr><td>가격</td><td>${escapeHtml(article.price ?? "1,000원")}</td></tr>
          <tr><td>배송비</td><td>무료</td></tr>
        </tbody></table>
        <div class="fr-view article-content">${body}</div>
      </div>
      <div class="article-comment position-relative" id="comment">
        <div class="title">댓글 <span class="title-comment-count">[${count}]</span></div>
        <div class="list-area">${commentHtml}<a class="newcomment-alert w-100 d-none fetch-comment" href="#comment"><span class="text">새로운 댓글이 달렸습니다!</span></a></div>
        ${pagination}<button class="reply-toggle" id="original-control" type="button"${article.foldedReply ? ' aria-controls="folded-replies" aria-expanded="false" data-reveal-target="folded-replies"' : ""}>${article.foldedReply ? "답글 펼치기" : "댓글 작성"}</button>
        <div class="alert alert-info">로그인 하신 후 댓글을 다실 수 있습니다.</div>
      </div>
      <aside class="popular" id="publisher-popular"><a href="/b/best/1">인기글 추천글</a></aside>
      <div class="sidebar" id="publisher-sidebar">다른 게시판 인기글</div>
      <ins class="adsbygoogle" id="publisher-ad">광고</ins>
    </div></div></article></div>${responsiveCopy}</body></html>`;
}

const browser = await chromium.launch({ headless: true });
let completed = 0;
try {
  const discoveryPage = await browser.newPage();
  try {
    for (const [reference, visible, expected] of [
      ["쌀", "[쿠팡] 쌀", true],
      ["[쿠팡] 쌀", "쌀", true],
      ["DOOM", "[Steam] DOOM", true],
      ["[Steam] DOOM", "DOOM", true],
      ["DOOM", "[스팀] DOOM", true],
      ["[PS5] DOOM", "[PC] DOOM", false],
      ["[PC] DOOM", "[XBOX] DOOM", false],
      ["[빨강] 컵", "[파랑] 컵", false],
      ["쌀", "찹쌀", false],
      ["쌀", "쌀국수", false],
      ["DOOM", "DOOM Eternal", false],
      ["[쿠팡] 쌀", "[쿠팡] 우유", false],
      ["[Steam] DOOM", "[Steam] DOOM Eternal", false],
    ]) {
      await discoveryPage.setContent(`<!doctype html><html><head>
        <meta property="og:title" content="${escapeHtml(visible)}"></head><body>
        <main><h1 class="new-title">${escapeHtml(visible)}</h1>
        <article class="new-body"><p>This is the original product description with useful specifications,
        delivery conditions and purchasing information for the current hot deal.</p>
        <p>Another complete paragraph provides enough original article context for independent discovery.</p></article>
        <section class="comments" aria-label="Comments">
          <div itemprop="comment">Original first comment.</div>
          <div itemprop="comment">Original second comment.</div>
        </section></main></body></html>`);
      const verdict = await discoveryPage.evaluate(({ source, reference }) => {
        const module = { exports: {} };
        new Function("module", source)(module);
        const api = module.exports;
        const result = api.discoverSemanticContract(document, [{
          allowEmptyComments: true,
          requiredRoles: ["title", "body", "comments"],
          roleProjection: { product: { cardinality: "zero" } },
          hints: { title: [".old-title"], body: [".old-body"], comments: [".old-comments"],
            commentItems: ["[itemprop='comment']"], commentControls: [], commentIgnored: [] },
        }], { title: reference, commentCount: 2 });
        return {
          ok: result.ok, reason: result.reason,
          seedConsistency: result.seedConsistency,
          policyComplete: result.policyProposal?.complete,
          comparison: api.titleConsistency(reference, document.querySelector("h1").textContent),
        };
      }, { source, reference });
      assert.equal(verdict.ok, expected, `${reference} -> ${visible}: ${JSON.stringify(verdict)}`);
      assert.equal(verdict.comparison.ok, expected, `${reference} -> ${visible}: bounded exact core`);
      if (expected) {
        assert.equal(verdict.seedConsistency.titleConsistencyOk, true);
        assert.equal(verdict.policyComplete, true);
      }
    }
  } finally { await discoveryPage.close(); }
  // These are ordinary registered articles, not new-layout promotion inputs.
  // Exercise the cloud auditor against the same untouched DOM before the
  // userscript runs, including h4/span titles and nested div/span comments.
  const regressions = JSON.parse(fs.readFileSync(
    new URL("fixtures/dom-regressions.json", import.meta.url), "utf8",
  )).fixtures;
  const contracts = JSON.parse(fs.readFileSync(
    new URL("../config/sites.json", import.meta.url), "utf8",
  )).sites;
  for (const id of ["clien-jirum-july", "ppomppu-mobile-july", "ruliweb-hotdeal-july", "eomisae-hotdeal-july",
    "quasarzone-market-july", "quasarzone-market-mobile-july"]) {
    const sample = regressions.find(item => item.id === id);
    const layout = contracts.find(site => site.id === sample.site_id).layouts
      .find(item => item.id === sample.layout_id);
    const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
    try {
      const page = await context.newPage();
      await page.route("**/*", route => route.fulfill({ status: 200,
        contentType: "text/html; charset=utf-8",
        body: `<!doctype html><html><head></head><body>${sample.body_html}</body></html>`,
      }));
      await page.goto(sample.url);
      const originalCommentCount = await page.evaluate(({ layout }) => {
        const title = document.querySelector('[data-fixture-node-id="title"]');
        const direct = [...title.childNodes].find(node => node.nodeType === Node.TEXT_NODE);
        direct.data = "쌀";
        const items = [...new Set(layout.comment_contract.items.flatMap(selector =>
          [...document.querySelectorAll(selector)]))];
        for (const item of items) {
          for (let index = 0; index < 12; index += 1) {
            const wrapper = document.createElement("div");
            const text = document.createElement("span");
            text.textContent = "원래 댓글 내용";
            wrapper.append(text);
            item.append(wrapper);
          }
        }
        return items.length;
      }, { layout });
      const before = await page.locator("body").innerHTML();
      const target = { source: "sample", url: sample.url };
      const oracle = await semanticOracle(page, source, sample.site_id, sample.layout_id,
        layout.required_roles, target);
      const evidence = semanticOracleEvidence(oracle, target);
      assert.deepEqual(semanticOracleContractFailures(evidence), [], JSON.stringify({ id, evidence }));
      assert.equal(evidence.verificationMode, "registered-sample");
      assert.equal(evidence.commentItemCount, originalCommentCount, `${id}: nested wrappers are not comments`);
      assert.equal(evidence.candidateEligible, false);
      assert.equal(evidence.policyProposal, null);
      assert.equal(evidence.algumon, null);
      assert.equal(await page.locator("body").innerHTML(), before, `${id}: source DOM must stay untouched`);
      if (sample.site_id === "quasarzone") {
        const siblingId = sample.layout_id === "market" ? "market-mobile" : "market";
        const siblingOracle = await semanticOracle(page, source, sample.site_id, siblingId,
          layout.required_roles, target);
        const siblingEvidence = semanticOracleEvidence(siblingOracle, target);
        assert.deepEqual(siblingOracle.approvedProjection.aliases, [sample.layout_id],
          `${id}: only the actual sibling layout resolves this original DOM`);
        assert.equal(siblingOracle.reason, "expected-layout-not-approved");
        assert.ok(semanticOracleContractFailures(siblingEvidence).length > 0,
          `${id}: a successful same-route sibling cannot hide failure of the audited layout`);
      }
      const invalidPromotionEvidence = semanticOracleEvidence(oracle, { ...target, source: "algumon-latest" });
      assert.ok(semanticOracleContractFailures(invalidPromotionEvidence).length > 0,
        "registered proof must not be relabeled as independent discovery evidence");
      await page.locator('[data-fixture-node-id="body"]').evaluate(element => element.remove());
      const missingBody = semanticOracleEvidence(await semanticOracle(page, source,
        sample.site_id, sample.layout_id, layout.required_roles, target), target);
      assert.ok(semanticOracleContractFailures(missingBody).length > 0,
        `${id}: a genuinely missing original body must still fail`);
      await page.goto(new URL("/not-a-hotdeal", sample.url).href);
      const wrongRoute = semanticOracleEvidence(await semanticOracle(page, source,
        sample.site_id, sample.layout_id, layout.required_roles, target), target);
      assert.ok(semanticOracleContractFailures(wrongRoute).length > 0,
        `${id}: matching markup outside a registered article route must still fail`);
      await page.goto("https://unrelated.invalid/not-a-hotdeal");
      const foreign = semanticOracleEvidence(await semanticOracle(page, source,
        sample.site_id, sample.layout_id, layout.required_roles, target), target);
      assert.ok(semanticOracleContractFailures(foreign).length > 0,
        `${id}: matching markup on another host cannot become an approved article`);
    } finally { await context.close(); }
  }
  // One browser and one context at a time keep the regression cheap in RAM.
  for (const width of [1280, 390]) {
    for (const article of cases) {
      const context = await browser.newContext({ viewport: { width, height: 844 } });
      try {
        const page = await context.newPage();
        const requests = [];
        await page.route("**/*", route => {
          requests.push(route.request().url());
          if (route.request().url() === article.imageUrl) {
            return route.fulfill({ status: 200, contentType: "image/svg+xml", body: imageSvg });
          }
          return route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: fixture(article) });
        });
        const target = { source: "sample", url: "https://arca.live/b/hotdeal/184784422" };
        const runtimeLayout = contracts.find(site => site.id === "arcalive")
          .layouts.find(layout => layout.id === "hotdeal");
        await page.goto(target.url);
        const oracle = semanticOracleEvidence(await semanticOracle(page, source,
          "arcalive", "hotdeal", runtimeLayout.required_roles, target), target);
        assert.deepEqual(semanticOracleContractFailures(oracle), [],
          `${article.name}/${width}: ${JSON.stringify(oracle)}`);
        assert.equal(oracle.commentItemCount, (article.comments ?? []).length,
          `${article.name}/${width}: use loaded items, not aggregate counters or child wrappers`);
        assert.equal(oracle.dormantCommentItemCount,
          (article.comments ?? []).filter(comment => comment.hidden).length,
          `${article.name}/${width}: native folded replies are loaded items, not missing comments`);
        await page.addInitScript(({ source, control, paintProbeSource }) => {
          (0, eval)(paintProbeSource);
          globalThis.originalArticleNodes = new Map();
          globalThis.originalControlClicks = 0;
          const captureOriginals = () => {
            for (const node of document.querySelectorAll('[id^="original-"], .comment-item[id^="c_"]')) {
              if (globalThis.originalArticleNodes.has(node.id)) continue;
              globalThis.originalArticleNodes.set(node.id, node);
              if (node.id === "original-control") {
                node.addEventListener("click", () => {
                  globalThis.originalControlClicks += 1;
                  const target = document.getElementById(node.dataset.revealTarget || "");
                  if (target) {
                    target.hidden = !target.hidden;
                    node.setAttribute("aria-expanded", String(!target.hidden));
                  }
                });
              }
            }
          };
          const originalsObserver = new MutationObserver(captureOriginals);
          originalsObserver.observe(document, { childList: true, subtree: true });
          document.addEventListener("DOMContentLoaded", () => {
            captureOriginals();
            originalsObserver.disconnect();
          }, { once: true });
          (0, eval)(control);
          (0, eval)(source);
        }, { source, control: PREAUTHORIZED_ADGUARD_CONTROL_SOURCE, paintProbeSource: FIRST_PAINT_PROBE_SOURCE });
        await page.goto("https://arca.live/b/hotdeal/184784422");
        await page.waitForFunction(() =>
          document.documentElement.getAttribute("data-hotdeal-focus-status") === "ready" &&
          !document.documentElement.hasAttribute("data-hotdeal-focus-lock"),
        null, { timeout: 5000 }).catch(async error => {
          throw new Error(`${article.name}/${width}: ${error.message}; ${JSON.stringify(await page.evaluate(() => ({
            status: document.documentElement.getAttribute("data-hotdeal-focus-status"),
            diagnostics: globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__,
          })))}`);
        });
        // Let the release paint and its observer checkpoint both settle.
        await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
        const assertActualAudit = async expectedDormantCount => {
          const gate = await auditUserscriptGate(page, runtimeLayout.required_roles, 5000,
            "registered-positive", commentControlSelectorDigestsForUrl(runtimeLayout, target.url));
          assert.deepEqual(userscriptGateFailures(gate, runtimeLayout.required_roles), [],
            `${article.name}/${width}: ${JSON.stringify(gate)}`);
          assert.equal(gate.commentItemStats.approvedDormantCount, expectedDormantCount);
          assert.equal(resultHasZeroLeak({ userscript: { gate } }), true);
          return gate;
        };
        const gate = await assertActualAudit((article.comments ?? []).filter(comment => comment.hidden).length);
        if (article.foldedReply) {
          const unprovenHidden = { ...gate, commentItemStats: {
            ...gate.commentItemStats, approvedDormantCount: 0,
          } };
          assert.ok(userscriptGateFailures(unprovenHidden, runtimeLayout.required_roles)
            .some(failure => failure.includes("runtime-approved dormant")));
          assert.equal(resultHasZeroLeak({ userscript: { gate: unprovenHidden } }), false);
        }
        const observed = await page.evaluate(() => {
          const visible = node => Boolean(node) && getComputedStyle(node).display !== "none" &&
            getComputedStyle(node).visibility === "visible" && node.getBoundingClientRect().height > 0;
          const originalNodes = Array.from(globalThis.originalArticleNodes, ([id, node]) => ({
            id, same: document.getElementById(id) === node, visible: visible(node),
          }));
          return {
            status: document.documentElement.getAttribute("data-hotdeal-focus-status"),
            locked: document.documentElement.hasAttribute("data-hotdeal-focus-lock"),
            originalNodes,
            commentCount: document.querySelectorAll(".comment-item[id^='c_']").length,
            noiseVisible: ["publisher-popular", "publisher-sidebar", "publisher-ad"]
              .filter(id => visible(document.getElementById(id))),
            purchaseHref: document.getElementById("original-purchase")?.getAttribute("href"),
            purchaseRel: document.getElementById("original-purchase")?.getAttribute("rel"),
            commentsPaginationVisible: document.querySelector(".article-comment .pagination")
              ? visible(document.querySelector(".article-comment .pagination")) : null,
            hiddenCopiesVisible: Array.from(document.querySelectorAll("[data-fixture-hidden-copy]")).some(visible),
          };
        });
        const label = `${article.name}/${width}: ${JSON.stringify(observed)}`;
        assert.equal(observed.status, "ready", label);
        assert.equal(observed.locked, false, label);
        assert.ok(observed.originalNodes.length >= 6, label);
        const hiddenOriginalIds = (article.comments || []).flatMap((comment, index) =>
          comment.hidden ? [`c_${index + 1}`, `original-comment-image-${index}`] : []);
        assert.ok(observed.originalNodes.every(node => node.same &&
          node.visible === !hiddenOriginalIds.includes(node.id)), label);
        assert.equal(observed.hiddenCopiesVisible, false, label);
        assert.equal(observed.commentCount, (article.comments || []).length, label);
        assert.deepEqual(observed.noiseVisible, [], label);
        assert.equal(observed.purchaseHref, "https://shop.example/product/1", label);
        assert.equal(observed.purchaseRel, article.purchaseRel || null, label);
        if ((article.count ?? 0) > (article.comments || []).length && article.comments?.length) {
          assert.equal(observed.commentsPaginationVisible, true, label);
        }
        await page.getByRole("button", { name: article.foldedReply ? "답글 펼치기" : "댓글 작성", exact: true }).click();
        assert.equal(await page.evaluate(() => globalThis.originalControlClicks), 1, label);
        if (article.foldedReply) {
          await page.waitForFunction(() =>
            document.documentElement.getAttribute("data-hotdeal-focus-status") === "ready" &&
            !document.documentElement.hasAttribute("data-hotdeal-focus-lock") &&
            document.getElementById("c_2").getBoundingClientRect().height > 0,
          null, { timeout: 5000 });
          assert.equal(await page.evaluate(() =>
            document.getElementById("c_2") === globalThis.originalArticleNodes.get("c_2") &&
            document.getElementById("original-control").getAttribute("aria-expanded") === "true"), true, label);
          await assertActualAudit(0);
          await page.getByRole("button", { name: "답글 펼치기", exact: true }).click();
          await page.waitForFunction(() =>
            document.documentElement.getAttribute("data-hotdeal-focus-status") === "ready" &&
            !document.documentElement.hasAttribute("data-hotdeal-focus-lock") &&
            document.getElementById("c_2").getBoundingClientRect().height === 0,
          null, { timeout: 5000 });
          assert.equal(await page.evaluate(() => globalThis.originalControlClicks), 2, label);
          await assertActualAudit(1);
        }
        const fixtureRequests = [target.url, ...(article.imageUrl ? [article.imageUrl] : [])];
        assert.deepEqual(requests, [...fixtureRequests, ...fixtureRequests]);
        completed += 1;
      } finally {
        await context.close();
      }
    }
  }
  console.log(`Short-title discovery: 13 allowed-prefix/negative cases passed. Registered sample oracle: six site layouts, same-route sibling rejection, and ${completed} desktop/mobile normal variants passed before runtime; original article, purchase link, comments and controls preserved while ads and sidebars stay hidden.`);
} finally {
  await browser.close();
}
