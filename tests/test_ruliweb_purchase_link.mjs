import assert from 'node:assert/strict';
import fs from 'node:fs';
import { chromium } from 'playwright';
import { PREAUTHORIZED_ADGUARD_CONTROL_SOURCE } from '../scripts/preauthorized_adguard_control.mjs';

const source = fs.readFileSync(new URL('../hotdeal-focus.user.js', import.meta.url), 'utf8');
const fixtures = JSON.parse(fs.readFileSync(new URL('./fixtures/dom-regressions.json', import.meta.url), 'utf8'));
const fixture = fixtures.fixtures.find(item => item.id === 'ruliweb-hotdeal-july');
const browser = await chromium.launch({ headless: true });
try {
  for (const mobile of [false, true]) {
    const context = await browser.newContext({ viewport: { width: mobile ? 390 : 1280, height: 844 }, isMobile: mobile });
    try {
      const page = await context.newPage();
      const body = fixture.body_html.replace('source_url box_line_with_shadow', 'source_url')
        .replace('</article>', '<aside class="popular-posts">인기글 추천글 광고</aside></article>');
      await page.route('**/*', route => route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: `<!doctype html><html><head><meta property="og:title" content="DOM regression fixture"></head><body>${body}</body></html>` }));
      await page.addInitScript(({ source, control }) => { (0, eval)(control); (0, eval)(source); }, { source, control: PREAUTHORIZED_ADGUARD_CONTROL_SOURCE });
      await page.goto(fixture.url.replace('bbs.ruliweb.com', mobile ? 'm.ruliweb.com' : 'bbs.ruliweb.com'));
      await page.waitForFunction(() => globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === 'ready' && !document.documentElement.hasAttribute('data-hotdeal-focus-lock'), null, { timeout: 5000 });
      assert.equal(await page.locator('.source_url').getAttribute('data-hotdeal-focus-role'), 'product');
      assert.equal(await page.locator('.source_url a').getAttribute('href'), 'https://shop.invalid/product');
      assert.equal(await page.locator('.source_url a').isVisible(), true);
      assert.match(await page.locator('.view_content').innerText(), /Second content paragraph/);
      assert.equal(await page.locator('[data-hotdeal-focus-role="comment-item"]').count(), 3);
      assert.equal(await page.evaluate(() => getComputedStyle(document.querySelector('.popular-posts')).visibility), 'hidden');
    } finally { await context.close(); }
  }
} finally { await browser.close(); }
console.log('Ruliweb desktop/mobile original purchase link preservation passed');
