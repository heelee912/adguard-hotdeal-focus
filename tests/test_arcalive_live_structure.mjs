import assert from "node:assert/strict";
import fs from "node:fs";
import { chromium } from "playwright";
import { PREAUTHORIZED_ADGUARD_CONTROL_SOURCE } from "../scripts/preauthorized_adguard_control.mjs";

// Reconstruct the image wrapper and nested decorative title observed in actual
// Chrome on 2026-10-03. Arca reuses .title for a textless popularity icon.
// Every request is fulfilled locally; this test sends no traffic to Arca.
const source = fs.readFileSync(new URL("../hotdeal-focus.user.js", import.meta.url), "utf8");
const title = "파워에이드 900ml 12입 (10,640원/무료)";
const image = "data:image/svg+xml," + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" width="320" height="480"><rect width="320" height="480" fill="blue"/></svg>',
);
const html = `<!doctype html><html><head>
<meta property="og:title" content="${title} - 핫딜 채널">
<meta property="og:type" content="website">
<style>.d-none { display:none !important; }</style></head><body>
<div class="root-container"><article class="containe-fluid board-article">
<div class="article-view"><div class="article-wrapper">
<div class="article-head"><div class="title"><span class="badge category-badge">식품</span><span class="title"><img src="${image}" width="18" height="18" class="button-svg-margin" alt="">&nbsp;</span> ${title}</div></div>
<div class="article-body"><table class="table align-middle article-options"><tbody>
<tr><td>링크</td><td><a href="https://shop.example/product/1">https://shop.example/product/1</a></td></tr>
<tr><td>쇼핑몰</td><td>롯데온</td></tr><tr><td>상품명</td><td>파워에이드 900ml 12입</td></tr>
<tr><td>가격</td><td>10,640원</td></tr><tr><td>배송비</td><td>무료</td></tr></tbody></table>
<div class="fr-view article-content"><p><img id="original-image" src="${image}" width="320" height="480" loading="lazy"></p><p><img id="original-emoticon" class="arca-emoticon" data-store-id="50022" src="${image}" width="100" height="100" loading="lazy"></p></div></div>
<div class="article-comment position-relative" id="comment"><div class="title">댓글 <span class="title-comment-count">[0]</span></div>
<div class="list-area"><a class="newcomment-alert w-100 d-none fetch-comment" href="#comment"><span class="text">새로운 댓글이 달렸습니다!</span></a></div>
<div class="alert alert-info">로그인 하신 후 댓글을 다실 수 있습니다.</div></div>
<aside class="popular" id="publisher-popular">인기글 추천글 광고</aside>
</div></div></article></div></body></html>`;

// These two live URLs share the same Arca template. A one-word product title
// must not lose reader mode merely because it has fewer distinctive tokens.
const articleCases = [
  { id: "177371604", title, category: "식품", product: "파워에이드 900ml 12입", price: "10,640원" },
  { id: "184784422", title: "듀얼센스 (64,000원/무료)", category: "전자제품", product: "듀얼센스", price: "64,000원" },
  { id: "184750098", title: "장송의 프리렌 전15권 세트 등 (72,100원/무료)", category: "도서", product: "장송의 프리렌 전15권 세트 등", price: "72,100원" },
];

const browser = await chromium.launch({ headless: true });
try {
  for (const width of [1280, 390]) {
    for (const article of articleCases) {
    for (const timing of ["released", "armed", "frozen"]) {
      const context = await browser.newContext({ viewport: { width, height: 844 } });
      try {
        const page = await context.newPage();
        await page.route("**/*", route => route.fulfill({
          status: 200, contentType: "text/html; charset=utf-8", body: html
            .replaceAll(title, article.title)
            .replaceAll("파워에이드 900ml 12입", article.product)
            .replaceAll("10,640원", article.price)
            .replace("category-badge\">식품", `category-badge">${article.category}`),
        }));
        await page.addInitScript(({ source, control, timing }) => {
          (0, eval)(control);
          globalThis.wrapOriginalImage = () => {
            const img = document.querySelector("#original-image");
            if (!img || document.querySelector("#publisher-image-link")) return;
            globalThis.originalBodyImage = img;
            const link = document.createElement("a");
            link.id = "publisher-image-link";
            link.href = "https://ac-o.arca.live/original.png";
            link.target = "_blank";
            img.replaceWith(link);
            link.append(img);
            const emoticon = document.querySelector("#original-emoticon");
            globalThis.originalEmoticon = emoticon;
            const emoticonLink = document.createElement("a");
            emoticonLink.id = "publisher-emoticon-link";
            emoticonLink.href = "/e/50022";
            emoticon.replaceWith(emoticonLink);
            emoticonLink.append(emoticon);
          };
          if (timing === "frozen") {
            // A bounded cascade proof failure used to leave the script ready
            // but stop its content observer. Arca's later original-image and
            // emoticon wrappers then hid already accepted media indefinitely.
            const nativeStyle = globalThis.getComputedStyle.bind(globalThis);
            globalThis.getComputedStyle = (element, pseudo) => {
              if (element?.hasAttribute?.("data-hdf-v2-release-probe")) {
                throw new Error("Synthetic unavailable release probe style");
              }
              return nativeStyle(element, pseudo);
            };
          }
          if (timing === "armed") {
            const wrappingObserver = new MutationObserver(() => {
              const root = document.documentElement;
              if (root?.getAttribute("data-hotdeal-focus-ready") !== "1") return;
              wrappingObserver.disconnect();
              globalThis.wrapOriginalImage();
            });
            wrappingObserver.observe(document, { subtree: true, attributes: true });
          }
          (0, eval)(source);
        }, { source, control: PREAUTHORIZED_ADGUARD_CONTROL_SOURCE, timing });
        await page.goto(`https://arca.live/b/hotdeal/${article.id}`);
        await page.waitForFunction(
          () => document.documentElement.getAttribute("data-hotdeal-focus-ready") === "1",
          null, { timeout: 5000 },
        ).catch(async error => {
          throw new Error(`${article.id}/${width}/${timing}: ${error.message}; ${JSON.stringify(await page.evaluate(() => ({status:document.documentElement.getAttribute("data-hotdeal-focus-status"),diagnostics:globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__})))}`);
        });
        if (timing === "frozen") {
          await page.waitForFunction(() => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__
            ?.targetReason?.startsWith("frozen-"), null, { timeout: 5000 });
        }
        if (timing === "released" || timing === "frozen") {
          await page.waitForFunction(() => !document.documentElement.hasAttribute("data-hotdeal-focus-lock"));
          await page.evaluate(() => globalThis.wrapOriginalImage());
        }
        await page.waitForFunction(() => {
          const img = document.querySelector("#original-image");
          return !document.documentElement.hasAttribute("data-hotdeal-focus-lock") &&
            img?.getBoundingClientRect().height > 0;
        }, null, { timeout: 5000 }).catch(() => {});
        const observed = await page.evaluate(() => {
          const img = document.querySelector("#original-image");
          const link = document.querySelector("#publisher-image-link");
          const emoticon = document.querySelector("#original-emoticon");
          const emoticonLink = document.querySelector("#publisher-emoticon-link");
          const visible = node => Boolean(node) && getComputedStyle(node).display !== "none" &&
            getComputedStyle(node).visibility === "visible" && node.getBoundingClientRect().height > 0;
          return {
            imageIdentity: img === globalThis.originalBodyImage,
            imageVisible: visible(img),
            wrapperOwned: link?.hasAttribute("data-hotdeal-focus-keep") === true,
            wrapperVisible: visible(link),
            emoticonIdentity: emoticon === globalThis.originalEmoticon,
            emoticonVisible: visible(emoticon),
            emoticonWrapperOwned: emoticonLink?.hasAttribute("data-hotdeal-focus-keep") === true,
            emoticonWrapperVisible: visible(emoticonLink),
            popularVisible: visible(document.querySelector("#publisher-popular")),
            decorativeTitleVisible: visible(document.querySelector(".article-head .title .title")),
            locked: document.documentElement.hasAttribute("data-hotdeal-focus-lock"),
            diagnostics: globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__,
          };
        });
        assert.equal(observed.imageVisible, true, JSON.stringify({ article: article.id, width, timing, observed }));
        assert.equal(observed.imageIdentity, true);
        assert.equal(observed.wrapperOwned, true);
        assert.equal(observed.wrapperVisible, true);
        assert.equal(observed.emoticonIdentity, true);
        assert.equal(observed.emoticonVisible, true);
        assert.equal(observed.emoticonWrapperOwned, true);
        assert.equal(observed.emoticonWrapperVisible, true);
        assert.equal(observed.popularVisible, false);
        assert.equal(observed.decorativeTitleVisible, false);
        assert.equal(observed.locked, false);
      } finally {
        await context.close();
      }
    }
    }
  }
  console.log("Arca short/long live titles and image/emoticon wrappers passed before/after release and after frozen proof at 1280px and 390px");
} finally {
  await browser.close();
}
