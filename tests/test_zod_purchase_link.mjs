import assert from 'node:assert/strict';
import fs from 'node:fs';
import { chromium } from 'playwright';
import { PREAUTHORIZED_ADGUARD_CONTROL_SOURCE } from '../scripts/preauthorized_adguard_control.mjs';

const source = fs.readFileSync(new URL('../hotdeal-focus.user.js', import.meta.url), 'utf8');
const title = '[지마켓] 사무용 키보드 (79,900원 / 무료)';
const purchaseHref = 'https://zod.kr/go/fyI14m30';
const image = 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><rect width="100" height="100" fill="blue"/></svg>');
const html = `<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta property="og:title" content="${title} - 특가"><meta property="og:type" content="article"><link rel="canonical" href="https://zod.kr/deal/99000001"></head><body><main class="app-clearfix"><article><header class="app-board-article-head"><h1>${title}</h1></header><div class="app-board-container app-article-container"><table class="app-board-extra-value"><tbody><tr data-extravar-key="deal-mall"><th>쇼핑몰</th><td>지마켓</td></tr><tr data-extravar-key="deal-link"><th>상품 링크<i class="iconoir-info-circle"></i></th><td><a class="zod-link--affiliated" href="${purchaseHref}" target="_blank" rel="nofollow">https://store.ohou.se/goods/4220928...</a></td></tr><tr data-extravar-key="deal-product_title"><th>제품명</th><td>사무용 키보드</td></tr><tr data-extravar-key="deal-price"><th>가격</th><td>79,900원</td></tr><tr data-extravar-key="deal-parcel"><th>배송비</th><td>무료</td></tr></tbody></table><div class="app-article-content app-clearfix"><div class="rhymix_content xe_content"><p><img src="${image}" alt="상품 사진"></p><p>풀배열 가스켓 유무선 기계식키보드 화이트 컬러입니다.</p><p>예약구매이고 발송 예정입니다.</p><p>키캡이랑 디자인 이뻐서 사무용으로 사볼만 한 것 같습니다.</p></div></div></div></article><div class="app-card app-board-comment app-board-section"><div class="app-comment-header"><div class="app-comment-header__title">댓글</div><div class="app-comment-header__count">총 <span class="app-comment-header__number">0</span> 개</div></div><ul id="app-board-comment-list" class="app-board-comment-list"></ul><div class="app-comment-denied">댓글 쓰기 권한이 없습니다.</div></div><aside>인기글 추천글 광고</aside></main></body></html>`;
const browser = await chromium.launch({headless:true});
try {
  for (const {width,drift,purchase=true} of [{width:1280,drift:false},{width:1280,drift:true},{width:390,drift:true},{width:1280,drift:true,purchase:false}]) {
    const context = await browser.newContext({viewport:{width,height:844},isMobile:width===390});
    try {
      const page = await context.newPage();
      const imageCompleteHtml = html.replace('<p>풀배열',`<p><img src="${image}" alt="상품 사진 2"></p><p>&nbsp;</p><p>풀배열`);
      const projectedHtml = drift ? imageCompleteHtml.replace('<main class="app-clearfix">','<section class="publisher-root">').replace('</main>','</section>') : imageCompleteHtml;
      const fixture = purchase ? projectedHtml : projectedHtml.replace(purchaseHref,'https://zod.kr/deal/99000002');
      await page.route('**/*',route=>route.fulfill({status:200,contentType:'text/html; charset=utf-8',body:fixture}));
      await page.addInitScript(({source,control})=>{(0,eval)(control);(0,eval)(source);},{source,control:PREAUTHORIZED_ADGUARD_CONTROL_SOURCE});
      await page.goto('https://zod.kr/deal/99000001');
      await page.waitForFunction(()=>document.documentElement.getAttribute('data-hotdeal-focus-state')==='ready'&&!document.documentElement.hasAttribute('data-hotdeal-focus-lock'),null,{timeout:5000});
      assert.equal(await page.locator('[data-hotdeal-focus-role="product"]').count(),purchase?1:0,`Native purchase relays, not ordinary article navigation, must be projected at ${width}px`);
      assert.equal(await page.locator('table a').getAttribute('href'),purchase?purchaseHref:'https://zod.kr/deal/99000002');
      assert.equal(await page.locator('table a').isVisible(),purchase);
      assert.equal(await page.locator('[data-hotdeal-focus-role="body"] img').first().isVisible(),true);
      assert.equal(await page.locator('aside').isVisible(),false);
    } finally { await context.close(); }
  }
} finally { await browser.close(); }
console.log('Zod native same-origin product redirect remains visible at desktop/mobile widths');
