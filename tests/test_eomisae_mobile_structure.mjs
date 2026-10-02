import assert from 'node:assert/strict';
import fs from 'node:fs';
import { chromium } from 'playwright';
import { PREAUTHORIZED_ADGUARD_CONTROL_SOURCE } from '../scripts/preauthorized_adguard_control.mjs';
const source = fs.readFileSync(new URL('../hotdeal-focus.user.js', import.meta.url), 'utf8');
const title = '[아빠새] 모바일 상품 정보';
const html = `<!doctype html><html><head><meta property="og:title" content="${title} - 패션정보 - 어미새"><meta property="og:type" content="article"></head><body><main id="bd"><div id="D_"><div class="_hd"><h2>국내 ${title}</h2></div><table class="et_vars"><tbody><tr><th>링크</th><td><a href="https://shop.invalid/product">https://shop.invalid/product</a></td></tr></tbody></table><article><div class="document_99000001_123 rhymix_content xe_content"><p><a href="https://shop.invalid/product">https://shop.invalid/product</a></p><p>상품 정보와 구매 링크를 그대로 보존하는 모바일 본문입니다.</p></div></article></div><div id="C_"><div class="_hd" id="comment"><span>댓글 <b>1</b></span></div><div class="_bd cf clear"><div id="comment_99000002" data-press-trigger="99000002" style="cursor:pointer;touch-action:pan-y;user-select:none" class="_comment p_rt cf re clear"><div class="content"><div class="user">작성자</div><div class="comment_99000002_123 rhymix_content xe_content">가격 괜찮은 상품들이 종종 보입니다.</div><a class="re_comment" href="/index.php?document_srl=99000001&act=dispBoardReplyComment&comment_srl=99000002">답글</a></div></div><div class="cmt-overlay-background" data-cmt-overlay="99000002" style="display:none"><div class="cmt-option"><div class="container"><a class="favorite" href="#">추천</a><a class="re_comment" href="/index.php?document_srl=99000001&act=dispBoardReplyComment&comment_srl=99000002">답글</a><a href="#" class="quit">닫기</a></div></div></div></div><div class="_hd _hdc"></div><center>게시판 공지와 광고</center><div class="_ft">댓글 쓰기 권한이 없습니다.</div></div><aside>인기글 추천글</aside></main></body></html>`;
const fixtureHtml = html.replace('<th>링크</th>', '<th>링크<i class="fas fa-question-circle tooltip"><span class="tooltiptext" style="visibility:hidden;position:absolute">어미새 커뮤니티 내 게시된 구매 링크는 제휴 링크로 전환되며, 이를 통해 어미새는 제휴사로부터 일정 비율의 커미션을 지급 받습니다.</span></i></th>').replace('style="display:none"', 'style="display:table;visibility:hidden;opacity:0;position:fixed;width:390px;height:176px;z-index:400888"');
const browser = await chromium.launch({headless:true});
try {
 const page = await browser.newPage({viewport:{width:390,height:844}});
 await page.setContent(fixtureHtml);
 const resolution = await page.evaluate(source => {
  const module={exports:{}};new Function('module',source)(module);
  const api=module.exports;const contract=api.SITE_CONTRACTS.find(s=>s.id==='eomisae');
  const exact=api.resolveDocument(document,contract.layouts,null);
  return {ok:exact.ok,role:exact.role,reason:exact.reason,error:exact.error};
 },source);
 assert.equal(resolution.ok,true,JSON.stringify(resolution));
 await page.close();
 const context=await browser.newContext({viewport:{width:390,height:844},isMobile:true});
 try {
  const page=await context.newPage();
  const nativeInitialization = `<script>document.addEventListener('DOMContentLoaded',()=>{document.documentElement.dataset.initialProjectionRaced=String(!!document.querySelector('#D_ [data-hotdeal-focus-keep]'));const container=document.querySelector('#comment_99000002 .content');const nativeWrapper=document.createElement('section');nativeWrapper.className='native-comment-wrapper';container.parentElement.append(nativeWrapper);nativeWrapper.append(container);});</script>`;
  await page.route('**/*',r=>r.fulfill({status:200,contentType:'text/html; charset=utf-8',body:fixtureHtml.replace('</body>',nativeInitialization+'</body>')}));
  await page.addInitScript(({source,control})=>{(0,eval)(control);(0,eval)(source);},{source,control:PREAUTHORIZED_ADGUARD_CONTROL_SOURCE});
  await page.goto('https://eomisae.co.kr/os/99000001');
  await page.waitForFunction(()=>globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state==='ready'&&!document.documentElement.hasAttribute('data-hotdeal-focus-lock'),null,{timeout:5000});
  assert.equal(await page.locator('html').getAttribute('data-initial-projection-raced'),'false');
  assert.equal(await page.evaluate(()=>{const e=document.querySelector('.tooltip'),s=getComputedStyle(e);return !!e.getClientRects().length&&s.display!=='none'&&s.visibility==='visible';}),false);
  assert.equal(await page.locator('.et_vars a').getAttribute('href'),'https://shop.invalid/product');
  assert.match(await page.locator('article').innerText(),/모바일 본문/);
  assert.match(await page.locator('#comment_99000002').innerText(),/가격 괜찮은/);
  assert.equal(await page.evaluate(()=>getComputedStyle(document.querySelector('aside')).visibility),'hidden');
  await page.evaluate(() => {
   const paragraph=document.querySelector('#D_ article p');
   const existingLink=paragraph.querySelector('a');
   const wrapper=document.createElement('span');
   wrapper.className='publisher-native-wrapper';
   wrapper.append(existingLink);
   paragraph.append(wrapper);
  });
  await page.waitForTimeout(100);
  assert.equal(await page.evaluate(()=>globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state),'ready',await page.evaluate(()=>JSON.stringify(globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__)));
  assert.match(await page.locator('#D_ article').innerText(),/모바일 본문/);
  await page.evaluate(() => {
   const clone=document.querySelector('#D_ article p a').cloneNode(true);
   const widget=document.createElement('aside');widget.id='publisher-clone-widget';
   widget.append(clone);document.body.append(widget);
  });
  await page.waitForTimeout(100);
  assert.equal(await page.evaluate(()=>globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state),'ready');
  assert.equal(await page.locator('#publisher-clone-widget [data-hotdeal-focus-keep]').count(),0);
  assert.equal(await page.evaluate(()=>getComputedStyle(document.querySelector('#publisher-clone-widget')).visibility),'hidden');
 } finally {await context.close();}
} finally {await browser.close();}
console.log('Eomisae mobile comment context menu and original body regression passed');
