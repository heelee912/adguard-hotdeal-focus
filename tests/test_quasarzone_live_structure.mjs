import assert from "node:assert/strict";
import fs from "node:fs";
import { chromium } from "playwright";
import { PREAUTHORIZED_ADGUARD_CONTROL_SOURCE } from "../scripts/preauthorized_adguard_control.mjs";

// Minimal regression preserving the publisher structure observed through the
// actual Algumon -> QuasarZone entry on 2026-10-02. No live network requests.
const source = fs.readFileSync(new URL("../hotdeal-focus.user.js", import.meta.url), "utf8");
const title = "[스팀] 이스케이프 프롬 덕코프 30% 할인";
const body = "많이들 알고 계시는 덕코프 25에서 5% 더해서 30% 할인으로 돌아왔습니다. 저도 많이는 하지 않았는데 재밌게 엔딩 봤었네요 ㅎ 한국어평가 압긍이니 대부분 재밌으실 것 같습니다.";
const destination = "https://store.steampowered.com/app/3167020/Escape_from_Duckov/";
const image = 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><rect width="100" height="100" fill="blue"/></svg>');
const html = `<!doctype html><html><head>
<meta property="og:title" content="${title}">
<meta property="og:type" content="article">
<script type="application/ld+json">${JSON.stringify({
  "@context": "https://schema.org", "@graph": [
    { "@type": "DiscussionForumPosting", headline: title, text: body, commentCount: 2 },
    { "@type": "Product", name: title, offers: { "@type": "Offer", price: "11550", priceCurrency: "KRW", url: destination } },
  ],
})}</script></head><body><main class="left-con-wrap" id="con-body">
<h1 class="v2-view-head__title"><span class="label">진행중</span> ${title}</h1>
<table class="market-info-view-table"><tbody>
<tr><th>링크 <img alt="info" src="${image}"><div class="tooltip active">구매링크는 제휴 링크로 전환될 수 있습니다.</div><div class="common-tooltip active">제휴 링크 안내</div></th><td><a href="javascript:goToLink('${Buffer.from(destination).toString("base64")}');">${destination}</a></td></tr>
<tr><th>판매처</th><td>스팀</td></tr><tr><th>가격</th><td>￦ 11,550 (KRW)</td></tr>
<tr><th>배송/직배</th><td>무료</td></tr></tbody></table>
<div class="view-content"><div class="note-editor"><div id="new_contents"><p>${body}</p><p></p><p><img src="${image}" alt="상품 사진"></p></div></div></div>
<div class="reply-wrap v2-cmt-wrap"><p class="reply-tit">댓글: <span id="comm_cnt">2</span>개</p>
<div class="reply-list" id="ajax-reply-list"><ul class="common-reply-list">
<li id="comment1990135"><div class="listNode v2-cmt"><div class="contentArea v2-cmt__main"><div class="nickWrap">삣삐삣삐</div><div class="note-editor content-view-ok" id="saveComment_1990135">덕코프 재밌죠 ㅋㅋ</div></div></div></li>
<li id="comment1990146"><div class="listNode v2-cmt"><div class="contentArea v2-cmt__main"><div class="nickWrap">Emot</div><div class="note-editor content-view-ok" id="saveComment_1990146"><p>FPS는 아니고 탑뷰입니다. (FPS 모딩이 있긴함)</p><p>난이도는 높게 하면 상당히 하드코어합니다.</p></div></div></div></li>
</ul></div></div><aside>인기글 추천글 광고</aside></main></body></html>`;

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  await page.setContent(html);
  const result = await page.evaluate(({ source }) => {
    const module = { exports: {} };
    new Function("module", source)(module);
    const api = module.exports;
    const contract = api.SITE_CONTRACTS.find(site => site.id === "quasarzone");
    const exact = api.resolveDocument(document, contract.layouts, null);
    const semantic = api.discoverSemanticContract(document, contract.layouts, null);
    return {
      exact: { ok: exact.ok, reason: exact.reason, error: exact.error },
      semantic: { ok: semantic.ok, reason: semantic.reason, error: semantic.error,
        rejected: semantic.rejected, tuple: semantic.tuple },
    };
  }, { source });
  assert.equal(result.exact.ok, true, JSON.stringify(result));
  await page.close();
  for (const { width, drift, handler = "native" } of [{ width: 1280, drift: false }, { width: 1280, drift: true }, { width: 390, drift: true }, { width: 1280, drift: true, handler: "mismatch" }, { width: 390, drift: true, handler: "arbitrary" }]) {
    const context = await browser.newContext({ viewport: { width, height: 844 } });
    try {
      const runtimePage = await context.newPage();
      let fixture = drift ? html.replace('class="left-con-wrap" id="con-body"', 'class="info-body" id="publisher-root"') : html;
      const nativeHref = `javascript:goToLink('${Buffer.from(destination).toString("base64")}');`;
      const purchaseHref = handler === "mismatch"
        ? `javascript:goToLink('${Buffer.from('https://example.com/unrelated').toString("base64")}');`
        : handler === "arbitrary" ? "javascript:unrelatedPublisherFunction()" : nativeHref;
      fixture = fixture.replace(nativeHref, purchaseHref);
      await runtimePage.route("**/*", route => route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: fixture }));
      await runtimePage.addInitScript(({ source, control }) => {
        (0, eval)(control);
        (0, eval)(source);
      }, { source, control: PREAUTHORIZED_ADGUARD_CONTROL_SOURCE });
      await runtimePage.goto("https://quasarzone.com/bbs/qb_saleinfo/views/1990129", { referer: "https://www.algumon.com/" });
      await runtimePage.waitForFunction(() => document.documentElement.getAttribute("data-hotdeal-focus-status") === "ready", null, {timeout:5000});
      const state = await runtimePage.evaluate(() => {
        const visible = e => getComputedStyle(e).visibility === "visible" && getComputedStyle(e).display !== "none" && !!e.getClientRects().length;
        return {
          body: visible(document.querySelector("#new_contents")),
          items: [...document.querySelectorAll("li[id^='comment']")].map(e => ({visible:visible(e),text:e.innerText})),
          noise: visible(document.querySelector("aside")),
          purchaseHref: document.querySelector(".market-info-view-table a").getAttribute("href"),
          purchaseVisible: visible(document.querySelector(".market-info-view-table a")),
          tooltipVisible: [...document.querySelectorAll(".market-info-view-table th .tooltip, .market-info-view-table th .common-tooltip, .market-info-view-table th img[alt='info']")].some(visible),
          proofFrames: globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.standaloneGate?.cascadeProofFrames,
        };
      });
      assert.equal(state.body, true);
      assert.equal(state.items.length, 2);
      assert.equal(state.items.every(item => item.visible), true);
      assert.match(state.items[0].text, /덕코프 재밌죠/);
      assert.match(state.items[1].text, /FPS는 아니고 탑뷰/);
      assert.equal(state.noise, false);
      assert.equal(state.purchaseHref, purchaseHref);
      assert.equal(state.purchaseVisible, handler === "native", `Only a matching native purchase handler must be visible at ${width}px (drift=${drift}, handler=${handler})`);
      assert.equal(state.tooltipVisible, false);
    } finally { await context.close(); }
  }
  console.log("Actual QuasarZone title/comment-wrapper regression passed at 1280px and 390px");
} finally {
  await browser.close();
}
