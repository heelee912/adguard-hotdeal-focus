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

// Observed mobile article 38542: these six repeated boxes are native controls,
// not six comments. The empty desktop template does not contain this toolbar.
const emptyCommentHtml = `<!doctype html><html><head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta property="og:title" content="루리웹 정상 빈 댓글">
</head><body><article id="board_read">
<h1 class="subject_inner_text">루리웹 정상 빈 댓글</h1>
<div class="view_content"><p>댓글이 없어도 원래 상품 설명은 그대로 보여야 합니다.</p></div>
<div class="comment_container"><div id="cmt" class="comment_wrapper theme_default">
  <input id="c_mpc" class="c_mpc" type="hidden" value="0">
  <input class="comment_profile_image_enabled" type="hidden" value="1">
  <div class="comment_count_wrapper row"></div><br>
  <div class="comment_btn_wrapper flex flex_wrap text_center padding_h_10" data-nosnippet>
    <div class="box_line flex_item_1 comment_count"><span class="comment_title">댓글</span>
      <span class="num_txt"><strong class="reply_count">0</strong></span></div>
    <div class="box_line flex_item_1"><button class="best_toggle" aria-label="c-best"
      onclick="window.originalBestClicks=(window.originalBestClicks||0)+1">
      <span class="icon_best">BEST</span><span class="best_toggle_text_on">ON</span>
      <span class="best_toggle_text_off screen_out">OFF</span></button></div>
    <div class="box_line flex_item_1"><button class="btn_comment_video">
      <i class="icon-youtube-play"></i><span class="btn_comment_video_text">ON</span></button></div>
    <div class="box_line flex_item_1"><button class="btn_comment_img" data-active="0">
      <i class="icon-picture"></i>ON</button></div>
    <div class="box_line flex_item_1"><a class="btn_comment_go" href="#comment_input"><i class="icon-pencil"></i></a></div>
    <div class="box_line flex_item_1"><button class="btn_comment_refresh"><i class="icon-refresh"></i></button></div>
  </div><div class="comment_disable text_center">로그인이 필요합니다.</div>
</div></div><aside class="popular-posts">인기글 추천글</aside></article></body></html>`;

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
  for (const width of [1280, 390]) {
    const context = await browser.newContext({ viewport: { width, height: 844 } });
    try {
      const page = await context.newPage();
      await page.route('**/*', route => route.fulfill({ status: 200,
        contentType: 'text/html; charset=utf-8', body: emptyCommentHtml }));
      await page.addInitScript(({ source, control }) => { (0, eval)(control); (0, eval)(source); },
        { source, control: PREAUTHORIZED_ADGUARD_CONTROL_SOURCE });
      await page.goto('https://m.ruliweb.com/news/board/1020/read/38542');
      await page.waitForFunction(() => document.documentElement.getAttribute('data-hotdeal-focus-state') === 'ready' &&
        !document.documentElement.hasAttribute('data-hotdeal-focus-lock'), null, { timeout: 5000 });
      assert.equal(await page.locator('.subject_inner_text').isVisible(), true);
      assert.equal(await page.locator('.view_content').isVisible(), true);
      assert.equal(await page.locator('[data-hotdeal-focus-role="comment-item"]').count(), 0);
      assert.equal(await page.locator('.comment_btn_wrapper').isVisible(), true);
      assert.equal(await page.locator('.popular-posts').isVisible(), false);
      await page.locator('.best_toggle').click();
      assert.equal(await page.evaluate(() => window.originalBestClicks), 1);
      const evidence = await page.evaluate(source => {
        const moduleRecord = { exports: {} };
        new Function('module', source)(moduleRecord);
        const api = moduleRecord.exports;
        const current = api.SITE_CONTRACTS.find(site => site.id === 'ruliweb').layouts
          .find(layout => layout.id === 'hotdeal');
        const previous = structuredClone(current);
        previous.hints.commentControls = previous.hints.commentControls
          .filter(selector => !selector.includes('.comment_btn_wrapper'));
        const before = api.resolveDocument(document, [previous], null);
        const missingItems = [];
        for (const explicit of [true, false]) {
          // One schema-marked item is explicit evidence; unmarked native
          // evidence requires repeated siblings, not an arbitrary singleton.
          const comments = Array.from({ length: explicit ? 1 : 2 }, (_unused, index) => {
            const comment = document.createElement('div');
            comment.className = 'comment-item';
            if (explicit) comment.setAttribute('itemprop', 'comment');
            comment.textContent = `분류에서 빠졌지만 삭제하면 안 되는 실제 댓글 ${index + 1}입니다.`;
            document.getElementById('cmt').append(comment);
            return comment;
          });
          const result = api.resolveDocument(document, [current], null);
          missingItems.push({ ok: result.ok, role: result.role, reason: result.reason });
          comments.forEach(comment => comment.remove());
        }
        return { before: { ok: before.ok, role: before.role, reason: before.reason }, missingItems };
      }, source);
      assert.deepEqual(evidence.before,
        { ok: false, role: 'comments', reason: 'evidence-outside-items' });
      assert.ok(evidence.missingItems.every(result => !result.ok &&
        result.role === 'comments' && result.reason === 'evidence-outside-items'), JSON.stringify(evidence));
    } finally { await context.close(); }
  }
  console.log('Ruliweb native comment/reply layout and handlers preserved; observed six-box empty-comment controls work on desktop/mobile while unclassified actual comments remain rejected.');
} finally { await browser.close(); }
