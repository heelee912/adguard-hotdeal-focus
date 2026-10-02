import assert from "node:assert/strict";
import fs from "node:fs";
import { chromium } from "playwright";
import { PREAUTHORIZED_ADGUARD_CONTROL_SOURCE } from "../scripts/preauthorized_adguard_control.mjs";

const source = fs.readFileSync(new URL("../hotdeal-focus.user.js", import.meta.url), "utf8");
const module = { exports: {} };
new Function("module", source)(module);
const api = module.exports;
const mobileUrl = "https://m.ppomppu.co.kr/new/bbs_view.php?id=ppomppu&no=737713&extref=1";
// The real publisher redirect replaces Algumon's referrer with this origin.
assert.equal(typeof api.readerEntryAuthority, "function");
assert.equal(api.readerEntryAuthority(mobileUrl, "https://www.ppomppu.co.kr/"), "registered-hotdeal-route");
assert.equal(api.readerEntryAuthority(mobileUrl, "https://www.algumon.com/"), "algumon-referrer");
for (const [url, referrer] of [
  [mobileUrl, ""],
  [mobileUrl, "https://example.com/"],
  [mobileUrl, "https://www.ppomppu.co.kr.evil.invalid/"],
  [mobileUrl, "https://www.ppomppu.co.kr@evil.invalid/"],
  [mobileUrl, "http://www.ppomppu.co.kr/"],
  [mobileUrl, "https://www.ppomppu.co.kr:8443/"],
  [mobileUrl.replace("&extref=1", ""), "https://www.ppomppu.co.kr/"],
  [mobileUrl + "&extref=1", "https://www.ppomppu.co.kr/"],
  [mobileUrl.replace("m.ppomppu", "www.ppomppu"), "https://www.ppomppu.co.kr/"],
  [mobileUrl, "https://www.ppomppu.co.kr/zboard/view.php?id=ppomppu&no=999"],
]) assert.equal(api.readerEntryAuthority(url, referrer), "registered-hotdeal-route", `${url} <- ${referrer}`);
for (const [url, referrer] of [
  [mobileUrl + "&no=1", ""],
  [mobileUrl.replace("id=ppomppu", "id=freeboard"), ""],
  [mobileUrl.replace("/new/bbs_view.php", "/new/bbs_list.php"), ""],
  [mobileUrl.replace("https:", "http:"), ""],
  [mobileUrl.replace("m.ppomppu.co.kr", "m.ppomppu.co.kr.evil.invalid"), ""],
  [mobileUrl.replace("m.ppomppu.co.kr", "m.ppomppu.co.kr:8443"), ""],
  ["https://m.clien.net/service/board/free/19272662", "https://www.algumon.com.evil.invalid/"],
]) assert.equal(api.readerEntryAuthority(url, referrer), null, `${url} <- ${referrer}`);
assert.equal(api.readerEntryAuthority("https://m.clien.net/service/board/jirum/19272662", ""), "registered-hotdeal-route");

const fixtures = JSON.parse(fs.readFileSync(new URL("fixtures/dom-regressions.json", import.meta.url), "utf8"));
const fixture = fixtures.fixtures.find(item => item.id === "ppomppu-mobile-july");
assert.ok(fixture);
const html = `<!doctype html><html><head><meta property="og:title" content="DOM regression fixture"><meta property="og:type" content="article"></head><body>${fixture.body_html}<aside id="noise">인기글 추천글 광고</aside></body></html>`;
const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true });
  try {
    const page = await context.newPage();
    await page.route("**/*", route => route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: html }));
    await page.addInitScript(({ source, control }) => { (0, eval)(control); (0, eval)(source); }, { source, control: PREAUTHORIZED_ADGUARD_CONTROL_SOURCE });
    await page.goto(mobileUrl, { referer: "https://www.ppomppu.co.kr/" });
    // Public ready markers arm the two-frame cascade proof. They do not prove
    // the actual paint lock was released, so assert the completed release.
    await page.waitForFunction(() =>
      globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready" &&
      !document.documentElement.hasAttribute("data-hotdeal-focus-lock"),
    null, { timeout: 5000 });
    const state = await page.evaluate(() => {
      const visible = e => !!e && !!e.getClientRects().length && getComputedStyle(e).visibility === "visible" && getComputedStyle(e).display !== "none";
      return {
        body: visible(document.querySelector("#KH_Content")),
        text: document.querySelector("#KH_Content").innerText,
        bodyNodes: [...document.querySelectorAll("#KH_Content *")].map(e => ({ tag: e.tagName, visible: visible(e), text: e.textContent, cls: e.className })),
        diagnostics: globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__,
        comments: [...document.querySelectorAll(".sect-cmt")].map(e => ({ visible: visible(e), text: e.innerText })),
        purchase: document.querySelector("a.noeffect").getAttribute("href"),
        reply: visible(document.querySelector(".cmt-reply-btn")),
        noise: visible(document.querySelector("#noise")),
        reason: globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.targetReason,
      };
    });
    assert.equal(state.body, true);
    assert.match(state.text, /Second content paragraph/, JSON.stringify(state));
    assert.equal(state.comments.length, 2);
    assert.equal(state.comments.every(item => item.visible), true);
    assert.match(state.comments[1].text, /nested reply/);
    assert.equal(state.purchase, "https://shop.invalid/product");
    assert.equal(state.reply, true);
    assert.equal(state.noise, false);
    assert.match(state.reason, /^registered-hotdeal-route-/);
    // Match the current publisher's real comment structure and asynchronous
    // load-more insertion; content and member identifiers are synthetic.
    await page.evaluate(() => {
      const mount = document.querySelector("#cmList");
      for (let index = 0; index < 55; index += 1) {
        const id = 9000 + index;
        const anchor = document.createElement("a");
        anchor.id = String(id);
        anchor.style.display = "block";
        const item = document.createElement("div");
        item.className = "sect0 sect-cmt";
        item.dataset.cno = String(id);
        item.dataset.depth = String(index === 2 ? 1 : 0);
        item.innerHTML = `<h6 class="com_name"><span class="com_name_writer"><a href="#none">작성자 ${index}</a></span></h6><div class="quiz_wrap"></div><div id="mod_ctx_${id}" style="display:none" class="mobile-modify-form-container"></div><div id="ctx_${id}" class="comment_memo my-gallery mid-text-area"><table class="content"><tbody><tr><td><p>동적으로 받은 원래 댓글 ${index}입니다.</p></td></tr></tbody></table></div><div class="cin_02 over_hide"><time>2026-10-02 16:21</time><span class="com_c"><a href="javascript:reComment(${id});">덧글</a></span><span class="add_dot"><ol class="dot_box"><li><a href="javascript:;" class="copyCmtUrlButton" data-cno="${id}">댓글주소복사</a></li></ol></span></div><div id="form_${id}"></div><div id="cC_${id}"></div><div id="recomment_${id}" class="recomment" data-depth="0"></div>`;
        mount.append(anchor, item);
      }
    });
    try {
      await page.waitForFunction(() => document.querySelectorAll('#cmList > .sect-cmt[data-hotdeal-focus-role="comment-item"]').length === 57, null, { timeout: 5000 });
    } catch (error) {
      console.error(await page.evaluate(() => JSON.stringify(globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__)));
      throw error;
    }
    const asyncState = await page.evaluate(() => ({
      text: document.querySelector("#cmList").innerText,
      diagnostics: globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__,
      visibleNoise: !!document.querySelector("#noise").getClientRects().length && getComputedStyle(document.querySelector("#noise")).visibility === "visible",
    }));
    assert.match(asyncState.text, /동적으로 받은 원래 댓글 54입니다/, JSON.stringify(asyncState));
    assert.equal(asyncState.diagnostics.state, "ready", JSON.stringify(asyncState));
    assert.equal(asyncState.visibleNoise, false);
    await page.close();
    const directPage = await context.newPage();
    await directPage.route("**/*", route => route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: html }));
    await directPage.addInitScript(({ source, control }) => { (0, eval)(control); (0, eval)(source); }, { source, control: PREAUTHORIZED_ADGUARD_CONTROL_SOURCE });
    await directPage.goto(mobileUrl);
    await directPage.waitForFunction(() =>
      globalThis.__HOTDEAL_FOCUS_DIAGNOSTICS__?.state === "ready" &&
      !document.documentElement.hasAttribute("data-hotdeal-focus-lock"),
    null, { timeout: 5000 });
    assert.equal(await directPage.evaluate(() => document.referrer), "");
    assert.match(await directPage.locator("#KH_Content").innerText(), /Second content paragraph/);
    assert.equal(await directPage.evaluate(() => getComputedStyle(document.querySelector("#noise")).visibility), "hidden");
  } finally { await context.close(); }
} finally { await browser.close(); }
console.log("Ppomppu official mobile handoff: scope, body, purchase, nested comments and noise regression passed");
