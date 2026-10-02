import assert from 'node:assert/strict';
import fs from 'node:fs';
import { chromium } from 'playwright';
import { PREAUTHORIZED_ADGUARD_CONTROL_SOURCE } from '../scripts/preauthorized_adguard_control.mjs';

const source = fs.readFileSync(new URL('../hotdeal-focus.user.js', import.meta.url), 'utf8');
const title = '정상 핫딜 상품 제목';
const body = '원본 본문과 구매 설명은 구조를 확인하지 못해도 없어지면 안 됩니다. '.repeat(8);
const html = `<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1">
<meta property="og:title" content="${title}"><meta property="og:type" content="article">
<script type="application/ld+json">${JSON.stringify({'@context':'https://schema.org','@type':'DiscussionForumPosting',headline:title,text:body,commentCount:1})}</script>
</head><body><main class="content_view"><h1 class="post_subject">${title}</h1>
<article class="post_article"><p>${body}</p><a href="https://example.com/product">원본 구매 링크</a></article>
<section class="post_comment"><div class="comment"><div class="comment_row">원본 댓글입니다.</div></div><nav class="comment_nav"><button type="button">댓글 더 보기</button></nav></section>
<aside>인기글 추천글 광고</aside></main></body></html>`;
const browser = await chromium.launch({headless:true});
try {
  for (const width of [1280,390]) {
    for (const failure of ['ambiguous-article','nonce','style-api']) {
      const context = await browser.newContext({viewport:{width,height:844}});
      try {
        const page = await context.newPage();
        const fixture = failure === 'ambiguous-article'
          ? html.replace('</body>', `<div id="ambiguous-clone">${html.match(/<main[\s\S]*<\/main>/)[0]}</div></body>`)
          : html;
        await page.route('**/*', route => route.fulfill({status:200,contentType:'text/html; charset=utf-8',body:fixture}));
        await page.addInitScript(({source,control,failure}) => {
          if (failure !== 'style-api') (0,eval)(control);
          if (failure === 'nonce') Object.defineProperty(crypto,'getRandomValues',{configurable:true,value(){throw new Error('test nonce failure');}});
          if (failure === 'style-api') globalThis.GM_addElement = () => {throw new Error('test style API failure');};
          document.addEventListener('DOMContentLoaded', () => {
            globalThis.originalArticle = document.querySelector('.post_article');
            globalThis.originalComment = document.querySelector('.comment_row');
            globalThis.commentClicks = 0;
            document.querySelector('.comment_nav button').addEventListener('click', () => {globalThis.commentClicks += 1;});
          }, {once:true});
          (0,eval)(source);
        }, {source,control:PREAUTHORIZED_ADGUARD_CONTROL_SOURCE,failure});
        await page.goto('https://www.clien.net/service/board/jirum/19230509', {referer:'https://www.algumon.com/'});
        await page.waitForFunction(() => !document.documentElement.hasAttribute('data-hotdeal-focus-lock') &&
          ['recovery','inactive'].includes(globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state), null, {timeout:5000}).catch(async error => {
            throw new Error(`${width}/${failure}: ${error.message}; ${JSON.stringify(await page.evaluate(() => ({diagnostics:globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__,html:document.documentElement.outerHTML.slice(0,600)})))}`);
          });
        const result = await page.evaluate(() => {
          const visible = element => getComputedStyle(element).display !== 'none' && getComputedStyle(element).visibility === 'visible' && element.getClientRects().length > 0;
          return {
            article:visible(originalArticle), comment:visible(originalComment),
            articleIdentity:document.querySelector('.post_article') === originalArticle,
            commentIdentity:document.querySelector('.comment_row') === originalComment,
            noise:visible(document.querySelector('aside')),
            controls:visible(document.querySelector('.comment_nav')),
            uiCount:document.querySelectorAll('[aria-label="핫딜 읽기 도구"]').length,
            rootOpacity:getComputedStyle(document.documentElement).opacity,
          };
        });
        assert.deepEqual(result, {article:true,comment:true,articleIdentity:true,commentIdentity:true,noise:false,controls:true,uiCount:0,rootOpacity:'1'}, `${width}/${failure}: ${JSON.stringify(result)}`);
        await page.getByRole('button',{name:'댓글 더 보기'}).first().click();
        assert.equal(await page.evaluate(() => commentClicks), 1);
        if (failure === 'ambiguous-article') {
          await page.evaluate(() => document.querySelector('#ambiguous-clone').remove());
          await page.waitForFunction(() => document.documentElement.getAttribute('data-hotdeal-focus-status') === 'ready' && !document.documentElement.hasAttribute('data-hotdeal-focus-lock'), null, {timeout:5000});
          assert.equal(await page.evaluate(() => document.querySelector('.post_article') === originalArticle && document.querySelector('.comment_row') === originalComment), true);
        }
      } finally { await context.close(); }
    }
  }
  console.log('Content recovery: ambiguous article, nonce and style API failures preserve original article/comments and hide static noise at 1280/390px; valid DOM resumes the reader.');
} finally { await browser.close(); }
