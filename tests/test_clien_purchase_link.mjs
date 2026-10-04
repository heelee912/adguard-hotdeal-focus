import assert from 'node:assert/strict';
import fs from 'node:fs';
import { chromium } from 'playwright';
import { PREAUTHORIZED_ADGUARD_CONTROL_SOURCE } from '../scripts/preauthorized_adguard_control.mjs';

const source = fs.readFileSync(new URL('../hotdeal-focus.user.js', import.meta.url), 'utf8');
const fixture = JSON.parse(fs.readFileSync(new URL('./fixtures/dom-regressions.json', import.meta.url), 'utf8'))
  .fixtures.find(item => item.id === 'clien-jirum-july');
const purchaseHref = 'https://shop.example/rateplan_view.do?plan=5g&agentCode=original#purchase';
const browser = await chromium.launch({ headless: true });
try {
  for (const mobile of [false, true]) {
    for (const variant of ['native-link', 'sponsored-native-link', 'no-native-link']) {
      const context = await browser.newContext({
        viewport: { width: mobile ? 390 : 1280, height: 844 }, isMobile: mobile,
      });
      try {
        const page = await context.newPage();
        const attached = variant === 'no-native-link' ? '' : `<div class="attached_link top${mobile ? ' inline_link' : ''}" id="original-product">${mobile ? '<div class="link_list">' : ''}
          <span class="attached_subject">구매링크</span>
          <a id="original-purchase" href="${purchaseHref.replace('&', '&amp;')}" target="_blank"${variant === 'sponsored-native-link' ? ' rel="sponsored nofollow"' : ''}>Original purchase destination</a>
        ${mobile ? '</div>' : ''}</div>`;
        // The native purchase field is a sibling of article, not a descendant
        // of .post_article. A link-only body fixture misses this publisher UI.
        // PC places the field inside .post_content; mobile places it directly
        // under .post_view. A narrow viewport alone does not model the mobile DOM.
        const noise = '<aside id="publisher-noise" class="popular-posts"><a href="https://ads.example/">광고 추천글</a></aside>';
        const body = fixture.body_html.replace(/(<article class="post_article"[\s\S]*?<\/article>)/,
          mobile ? `<div class="post_view">${attached}$1${noise}</div>`
            : `<div class="post_view"><div class="post_content">${attached}$1${noise}</div></div>`);
        await page.route('**/*', route => route.fulfill({ status: 200,
          contentType: 'text/html; charset=utf-8',
          body: `<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><meta property="og:title" content="DOM regression fixture"></head><body>${body}</body></html>`,
        }));
        await page.addInitScript(({ source, control }) => { (0, eval)(control); (0, eval)(source); },
          { source, control: PREAUTHORIZED_ADGUARD_CONTROL_SOURCE });
        await page.goto(`https://${mobile ? 'm' : 'www'}.clien.net/service/board/jirum/19272856`);
        await page.waitForFunction(() => document.documentElement.getAttribute('data-hotdeal-focus-state') === 'ready' && !document.documentElement.hasAttribute('data-hotdeal-focus-lock'), null, { timeout: 5000 });
        assert.match(await page.locator('.post_article').innerText(), /Second content paragraph/);
        assert.ok((await page.locator('[data-hotdeal-focus-role="title"]').innerText()).trim());
        assert.equal(await page.locator('[data-hotdeal-focus-role="comment-item"]').count(), 3);
        assert.equal(await page.locator('#publisher-noise').isVisible(), false);
        if (variant !== 'no-native-link') {
          assert.equal(await page.locator('#original-product').getAttribute('data-hotdeal-focus-role'), 'product');
          assert.equal(await page.locator('#original-purchase').isVisible(), true);
          assert.equal(await page.locator('#original-purchase').getAttribute('href'), purchaseHref);
          assert.equal(await page.locator('#original-purchase').getAttribute('target'), '_blank');
          assert.equal(await page.locator('#original-purchase').getAttribute('rel'), variant === 'sponsored-native-link' ? 'sponsored nofollow' : null);
        } else {
          assert.equal(await page.locator('[data-hotdeal-focus-role="product"]').count(), 0);
        }
      } finally { await context.close(); }
    }
  }
} finally { await browser.close(); }
console.log('Clien desktop/mobile native sibling purchase links, original attributes, optional absence, body/comments and noise isolation passed');
