import assert from 'node:assert/strict';
import fs from 'node:fs';
import { chromium } from 'playwright';
import { PREAUTHORIZED_ADGUARD_CONTROL_SOURCE } from '../scripts/preauthorized_adguard_control.mjs';

const source = fs.readFileSync(new URL('../hotdeal-focus.user.js', import.meta.url), 'utf8');
const commentText = '구매 전에 확인할 내용입니다. 배송 조건과 실제 사용 후기를 댓글에서 편하게 확인할 수 있어야 합니다.';
const row = (id, child = false) => `<tr id="${id}" class="comment_element normal${child ? ' child' : ''}">
  <td class="user"><div class="user_inner_wrapper"><div class="user_info_wrapper"><span class="nick">원래 작성자</span></div></div></td>
  <td class="comment"><div class="text_wrapper"><span class="text">${commentText}</span></div>
    <div class="comment_reply" style="display:none"><label>답글<textarea></textarea></label><button type="button">등록</button></div></td>
  <td class="parent_control_box_wrapper"><div class="control_box r_col"><span class="time">2026.10.03 06:30</span>
    <button class="like" type="button">추천 1</button><button class="dislike" type="button">비추천</button>
    <button class="btn_reply" type="button">답글</button><button class="report" type="button">신고</button></div></td>
</tr>`;
const html = `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<meta property="og:title" content="루리웹 정상 핫딜 댓글"><style>
body { margin:8px; font:16px/1.5 sans-serif; }
#board_read { width:1100px; }
.comment_table { width:100%; table-layout:fixed; border-collapse:collapse; }
.comment_table td { vertical-align:top; }
.comment_table td.user { width:165px; }
.user_inner_wrapper, .user_info_wrapper { width:165px; }
.comment_table td.comment { padding:12px 15px; }
.text_wrapper { width:100%; word-break:break-all; }
.text { white-space:pre-wrap; }
.parent_control_box_wrapper { width:125px; }
.control_box.r_col { float:right; width:125px; position:relative; padding-top:24px; }
.control_box .time { position:absolute; top:0; right:0; font-size:12px; white-space:nowrap; }
.comment_element.child td.user { padding-left:20px; }
.comment_reply textarea { width:100%; box-sizing:border-box; }
</style></head><body><article id="board_read">
<h1 class="subject_inner_text">루리웹 정상 핫딜 댓글</h1>
<div class="view_content"><p>구매에 필요한 원본 상품 설명입니다.</p><p>배송과 결제 조건도 그대로 유지합니다.</p></div>
<div class="source_url"><a href="https://shop.example/item/123">원래 구매 링크</a></div>
<div id="cmt" class="comment_wrapper"><div class="comment_view normal"><table class="comment_table"><tbody>
${row('original-comment')}${row('original-reply', true)}
<tr class="comment_element normal child"><td class="user">광고</td><td class="comment" colspan="2"><div class="nbp_container"><a href="https://ads.example/">광고</a></div></td></tr>
</tbody></table></div></div><aside class="popular-posts">인기글 추천글</aside>
</article><script>
window.originalRows = Array.from(document.querySelectorAll('#original-comment,#original-reply'));
window.originalTexts = window.originalRows.map(row => row.querySelector('.text'));
document.querySelectorAll('.btn_reply').forEach(button => button.addEventListener('click', () => {
  const composer = button.closest('tr').querySelector('.comment_reply');
  composer.style.display = composer.style.display === 'none' ? 'block' : 'none';
}));
document.querySelectorAll('.like').forEach(button => button.addEventListener('click', () => {
  button.dataset.clicked = 'true';
}));
</script></body></html>`;

const browser = await chromium.launch({ headless: true });
try {
  for (const width of [1280, 390]) {
    const context = await browser.newContext({ viewport: { width, height: 844 } });
    try {
      const page = await context.newPage();
      await page.route('**/*', route => route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: html }));
      await page.addInitScript(({ source, control }) => { (0, eval)(control); (0, eval)(source); },
        { source, control: PREAUTHORIZED_ADGUARD_CONTROL_SOURCE });
      await page.goto('https://bbs.ruliweb.com/news/board/1020/read/107751');
      await page.waitForFunction(() => document.documentElement.getAttribute('data-hotdeal-focus-state') === 'ready' &&
        !document.documentElement.hasAttribute('data-hotdeal-focus-lock'), null, { timeout: 5000 });
      const observed = await page.evaluate(() => ({
        rows: window.originalRows.map((row, index) => {
          const text = row.querySelector('.text');
          const rect = element => { const box = element.getBoundingClientRect(); return { x:box.x, y:box.y, width:box.width, height:box.height, bottom:box.bottom }; };
          return {
            rowIdentity: row === document.getElementById(row.id), textIdentity: text === window.originalTexts[index],
            rowDisplay: getComputedStyle(row).display, user:rect(row.querySelector('.user')),
            comment:rect(row.querySelector('.comment')), text:rect(text), controls:rect(row.querySelector('.parent_control_box_wrapper')),
            composerHidden:getComputedStyle(row.querySelector('.comment_reply')).display === 'none',
          };
        }),
        horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
        adHidden: document.querySelector('.nbp_container').getClientRects().length === 0,
        sidebarHidden: document.querySelector('.popular-posts').getClientRects().length === 0,
      }));
      for (const item of observed.rows) {
        assert.equal(item.rowIdentity, true);
        assert.equal(item.textIdentity, true);
        assert.equal(item.composerHidden, true);
        if (width === 390) {
          assert.ok(item.comment.width >= 300, JSON.stringify({ width, observed }));
          assert.ok(item.text.width >= 280, JSON.stringify({ width, observed }));
          assert.ok(item.comment.y >= item.user.bottom - 1, JSON.stringify({ width, observed }));
          assert.ok(item.controls.y >= item.comment.bottom - 1, JSON.stringify({ width, observed }));
          assert.ok(item.text.height < 150, JSON.stringify({ width, observed }));
        } else {
          assert.equal(item.rowDisplay, 'table-row');
          assert.ok(item.user.width >= 165 && item.user.width <= 190, JSON.stringify(item));
          assert.ok(Math.abs(item.user.y - item.comment.y) < 2);
          assert.ok(item.comment.width >= 600);
        }
      }
      assert.equal(observed.horizontalOverflow, false, JSON.stringify({ width, observed }));
      assert.equal(observed.adHidden, true);
      assert.equal(observed.sidebarHidden, true);
      await page.locator('#original-comment .btn_reply').click();
      await page.waitForFunction(() => getComputedStyle(document.querySelector('#original-comment .comment_reply')).display !== 'none');
      assert.equal(await page.locator('#original-reply .comment_reply').isVisible(), false);
      await page.locator('#original-comment .like').click();
      assert.equal(await page.locator('#original-comment .like').getAttribute('data-clicked'), 'true');
      await page.locator('#original-comment .btn_reply').click();
      await page.waitForFunction(() => getComputedStyle(document.querySelector('#original-comment .comment_reply')).display === 'none');
      assert.equal(await page.locator('html').getAttribute('data-hotdeal-focus-state'), 'ready');
    } finally { await context.close(); }
  }
  console.log('Ruliweb original comment/reply columns remain native on desktop and stack readably at 390px; native reply/like handlers and hidden forms preserved.');
} finally { await browser.close(); }
