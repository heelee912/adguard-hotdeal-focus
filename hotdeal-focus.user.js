// ==UserScript==
// @name         AdGuard Hotdeal Focus Reader Gate
// @namespace    https://github.com/heelee912/adguard-hotdeal-focus
// @version      0.6.75
// @description  Fail-closed semantic reader gate for Algumon hot-deal destinations.
// @match        https://*.clien.net/*
// @match        https://*.ppomppu.co.kr/*
// @match        https://*.ruliweb.com/*
// @match        https://*.quasarzone.com/*
// @match        https://*.eomisae.co.kr/*
// @match        https://*.zod.kr/*
// @match        https://*.arca.live/*
// @run-at       document-start
// @grant        GM_addElement
// @grant        window.onurlchange
// @noframes
// @downloadURL  https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
// @updateURL    https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js
// ==/UserScript==

(function hotdealFocusUmd(root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module && module.exports) {
    module.exports = api;
    return;
  }
  try {
    Object.defineProperty(root, "__HOTDEAL_FOCUS_AUDIT__", {
      value: Object.freeze({ discoverSemanticContract: api.discoverSemanticContract }),
      configurable: true,
      enumerable: false,
      writable: false,
    });
  } catch (_error) {
    // Audit exposure is optional; a hostile page-global must not prevent the
    // independently sandboxed reader gate from starting.
  }
  api.start(root);
})(typeof globalThis === "object" ? globalThis : this, function hotdealFocusFactory() {
  "use strict";

  const PROTOCOL_VERSION = "2";
  const GENERATOR_VERSION = "0.6.73";
  const RELEASE_URLS = Object.freeze({
    download: "https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js",
    update: "https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js",
  });
  const ATTR = Object.freeze({
    lock: "data-hotdeal-focus-lock",
    ready: "data-hotdeal-focus-ready",
    keep: "data-hotdeal-focus-keep",
    protocol: "data-hotdeal-focus-protocol",
    shell: "data-hotdeal-focus-shell",
    deep: "data-hotdeal-focus-deep",
    role: "data-hotdeal-focus-role",
    state: "data-hotdeal-focus-state",
    status: "data-hotdeal-focus-status",
    measure: "data-hotdeal-focus-measure",
  });
  const CLASS = Object.freeze({
    lock: "hdf-v2-lock",
    ready: "hdf-v2-ready",
    keep: "hdf-v2-keep",
    shell: "hdf-v2-shell",
    deep: "hdf-v2-deep",
    rolePrefix: "hdf-v2-role-",
  });
  const HDF_ATTRIBUTE_PREFIX = "data-hotdeal-focus-";
  const HDF_CLASS_PREFIX = "hdf-v2-";
  const HDF_CLASS_PATTERN = /^hdf-v\d+-/u;
  const COMMENT_CONTROL_STATE_ATTRIBUTES = new Set([
    "class",
    "hidden",
    "aria-expanded",
    "aria-pressed",
    "aria-selected",
    "aria-hidden",
    "style",
  ]);
  const BOOTSTRAP_INLINE_LOCK = Object.freeze({
    animation: "none",
    caretColor: "transparent",
    clipPath: "inset(50%)",
    contentVisibility: "hidden",
    opacity: "0",
    pointerEvents: "none",
    transition: "none",
    visibility: "hidden",
  });
  const BOOTSTRAP_PUBLISHER_INLINE = new WeakMap();
  const MEASUREMENT_HTML_RESTORES = new WeakMap();
  let measurementStyleSheetMutationDepth = 0;
  const CASCADE_PROOF_FRAMES = 2;
  const ALGUMON_HANDOFF_SETTLE_TIMEOUT_MS = 5_000;
  const ALGUMON_HANDOFF_POLL_INTERVAL_MS = 100;
  const SEMANTIC_PREFLIGHT_TIMEOUT_MS = 15_000;
  const LOCKED_ACTIVATION_TIMEOUT_MS = 5_000;
  const RUNTIME_GLOBAL = typeof globalThis === "object" ? globalThis : null;
  const NATIVE = Object.freeze({
    MutationObserver: RUNTIME_GLOBAL?.MutationObserver ?? null,
    getComputedStyle: typeof RUNTIME_GLOBAL?.getComputedStyle === "function"
      ? RUNTIME_GLOBAL.getComputedStyle.bind(RUNTIME_GLOBAL)
      : null,
    requestAnimationFrame: typeof RUNTIME_GLOBAL?.requestAnimationFrame === "function"
      ? RUNTIME_GLOBAL.requestAnimationFrame.bind(RUNTIME_GLOBAL)
      : null,
    cancelAnimationFrame: typeof RUNTIME_GLOBAL?.cancelAnimationFrame === "function"
      ? RUNTIME_GLOBAL.cancelAnimationFrame.bind(RUNTIME_GLOBAL)
      : null,
    queueMicrotask: typeof RUNTIME_GLOBAL?.queueMicrotask === "function"
      ? RUNTIME_GLOBAL.queueMicrotask.bind(RUNTIME_GLOBAL)
      : null,
    setTimeout: typeof RUNTIME_GLOBAL?.setTimeout === "function"
      ? RUNTIME_GLOBAL.setTimeout.bind(RUNTIME_GLOBAL)
      : null,
    clearTimeout: typeof RUNTIME_GLOBAL?.clearTimeout === "function"
      ? RUNTIME_GLOBAL.clearTimeout.bind(RUNTIME_GLOBAL)
      : null,
    cryptoGetRandomValues: typeof RUNTIME_GLOBAL?.crypto?.getRandomValues === "function"
      ? RUNTIME_GLOBAL.crypto.getRandomValues.bind(RUNTIME_GLOBAL.crypto)
      : null,
    addEventListener: RUNTIME_GLOBAL?.EventTarget?.prototype?.addEventListener ?? null,
    removeEventListener: RUNTIME_GLOBAL?.EventTarget?.prototype?.removeEventListener ?? null,
    defineProperty: Object.defineProperty,
    reflectApply: Reflect.apply,
    locationReplace: RUNTIME_GLOBAL?.Location?.prototype?.replace ?? null,
    anchorClick: RUNTIME_GLOBAL?.HTMLAnchorElement?.prototype?.click ?? null,
  });
  const SHADOW_TRACKERS = new WeakMap();

  function initializeShadowTracker(browserRoot) {
    if (!browserRoot) return null;
    const existing = SHADOW_TRACKERS.get(browserRoot);
    if (existing?.installed === true) return existing;
    const prototype = browserRoot.Element?.prototype;
    const nativeAttachShadow = prototype?.attachShadow;
    if (!prototype || typeof nativeAttachShadow !== "function") return null;
    const descriptor = Object.getOwnPropertyDescriptor(prototype, "attachShadow");
    if (!descriptor || descriptor.configurable !== true || descriptor.writable !== true) {
      return null;
    }
    const hosts = new WeakSet();
    const listeners = new Set();
    const trackedAttachShadow = function hotdealFocusTrackedAttachShadow() {
      const host = this;
      const shadowRoot = NATIVE.reflectApply(nativeAttachShadow, host, arguments);
      hosts.add(host);
      listeners.forEach(function notifyShadowAttachment(listener) {
        try {
          listener(host);
        } catch (_error) {
          // A failing observer cannot change attachShadow semantics.
        }
      });
      return shadowRoot;
    };
    try {
      NATIVE.defineProperty(prototype, "attachShadow", {
        configurable: descriptor.configurable,
        enumerable: descriptor?.enumerable === true,
        writable: descriptor.writable,
        value: trackedAttachShadow,
      });
      const tracker = Object.freeze({
        hosts,
        listeners,
        installed: prototype.attachShadow === trackedAttachShadow,
        wrapper: trackedAttachShadow,
        uninstall: function uninstallShadowTracker() {
          if (prototype.attachShadow !== trackedAttachShadow) return false;
          try {
            NATIVE.defineProperty(prototype, "attachShadow", descriptor);
            SHADOW_TRACKERS.delete(browserRoot);
            return prototype.attachShadow === nativeAttachShadow;
          } catch (_error) {
            return false;
          }
        },
      });
      if (!tracker.installed) return null;
      SHADOW_TRACKERS.set(browserRoot, tracker);
      return tracker;
    } catch (_error) {
      return null;
    }
  }

  function createNativeMutationObserver(browserRoot, callback) {
    const Constructor = browserRoot === RUNTIME_GLOBAL
      ? NATIVE.MutationObserver
      : browserRoot?.MutationObserver;
    if (typeof Constructor !== "function") {
      throw new Error("MutationObserver is unavailable");
    }
    return new Constructor(callback);
  }

  function nativeComputedStyle(browserRoot, element, pseudoElement) {
    const getter = browserRoot === RUNTIME_GLOBAL
      ? NATIVE.getComputedStyle
      : typeof browserRoot?.getComputedStyle === "function"
        ? browserRoot.getComputedStyle.bind(browserRoot)
        : null;
    return getter ? getter(element, pseudoElement) : null;
  }

  function nativeAnimationFrame(browserRoot, callback) {
    const request = browserRoot === RUNTIME_GLOBAL
      ? NATIVE.requestAnimationFrame
      : browserRoot?.requestAnimationFrame?.bind(browserRoot);
    if (typeof request !== "function") throw new Error("requestAnimationFrame is unavailable");
    return request(callback);
  }

  function nativeCancelAnimationFrame(browserRoot, frameId) {
    const cancel = browserRoot === RUNTIME_GLOBAL
      ? NATIVE.cancelAnimationFrame
      : browserRoot?.cancelAnimationFrame?.bind(browserRoot);
    if (typeof cancel === "function") cancel(frameId);
  }

  function nativeTimeout(browserRoot, callback, delayMs) {
    const schedule = browserRoot === RUNTIME_GLOBAL
      ? NATIVE.setTimeout
      : browserRoot?.setTimeout?.bind(browserRoot);
    if (typeof schedule !== "function") throw new Error("setTimeout is unavailable");
    return schedule(callback, delayMs);
  }

  function nativeClearTimeout(browserRoot, timeoutId) {
    const cancel = browserRoot === RUNTIME_GLOBAL
      ? NATIVE.clearTimeout
      : browserRoot?.clearTimeout?.bind(browserRoot);
    if (typeof cancel === "function" && timeoutId) cancel(timeoutId);
  }
  const MAX_PROJECTION_CANDIDATE_EVALUATIONS = 800;
  const MAX_PROJECTION_ROLE_CANDIDATES = 32;
  const MAX_PROJECTION_TUPLES = 4096;
  const MAX_COMMENT_EVIDENCE = 4096;
  const MAX_SEMANTIC_DESCENDANTS = 8192;
  const MAX_PROJECTION_METADATA_ATTRIBUTES = 64;
  const PROJECTION_TUPLE_MARGIN = 0.75;
  const MAX_JSON_LD_BYTES = 262144;
  const MIN_BODY_TEXT_LENGTH = 80;
  const NOISE_TOKEN_PATTERN = /(?:^|[-_\s])(ad(?:s|vert|vertise|vertisement)?|banner|sponsor|promo|affiliate|recommend(?:ed|ation)?|related|popular|ranking|share|social|nav(?:igation)?|sidebar|footer|header|toolbar|breadcrumb|광고|広告|廣告|广告)(?:$|[-_\s])/i;
  const STRUCTURAL_NOISE_TOKEN_PATTERN = /(?:^|[-_\s])(ad(?:s|vert|vertise|vertisement)?|banner|sponsor|promo|affiliate|recommend(?:ed|ation)?|popular|ranking|share|social|nav(?:igation)?|sidebar|footer|toolbar|breadcrumb|광고|広告|廣告|广告)(?:$|[-_\s])/i;
  const MEDIA_NOISE_TOKEN_PATTERN = /(?:^|[-_\s])(ad(?:s|vert|vertise|vertisement)?|sponsor|promo|affiliate|recommend(?:ed|ation)?|popular|ranking|share|social|sidebar|광고|広告|廣告|广告)(?:$|[-_\s])/i;
  const STRONG_NOISE_TOKEN_PATTERN = /(?:^|[-_\s])(ad(?:s|vert|vertise|vertisement)?|sponsor(?:ed)?|promot(?:e|ed|ion|ional)?|promo|affiliate|recommend(?:ed|ation)?|popular|ranking|share|social|sidebar|toolbar|breadcrumb|광고|広告|廣告|广告)(?:$|[-_\s])/i;
  const BACKGROUND_RESOURCE_NOISE_TOKEN_PATTERN = /(?:^|[-_\s])(ad(?:s|vert|vertise|vertisement)?|sponsor(?:ed)?|promot(?:e|ed|ion|ional)?|promo|affiliate|광고|広告|廣告|广告)(?:$|[-_\s])/i;
  const PSEUDO_NOISE_TOKEN_PATTERN = /(?:^|\s)(?:partner\s+offer|click\s+here|read\s+this|promot(?:e|ed|ion|ional)?|sponsor(?:ed)?|affiliate|advertisement|recommend(?:ed)?\s+(?:deal|post)|popular\s+(?:deal|post))(?:$|\s)/i;
  const RELATED_NOISE_TOKEN_PATTERN = /(?:^|[-_\s])related(?:$|[-_\s])/i;
  const AUTONOMOUS_NOISE_METADATA_PATTERN = /(?:^|[-_\s])(?:best|trend(?:ing)?|most[-_\s]?viewed|hot[-_\s]?(?:post|deal|list)|인기(?:글|게시물|핫딜)?|추천(?:글|게시물|핫딜)?|관련(?:글|게시물|핫딜)?|베스트(?:글|게시물|핫딜)?|실시간[-_\s]?인기|人気(?:記事|投稿)?|おすすめ|関連記事|ランキング|热门(?:文章|帖子)?|推荐(?:文章|帖子)?|相关文章|排行)(?:$|[-_\s])/iu;
  const AUTONOMOUS_NOISE_LABEL_PATTERN = /^(?:(?:(?:실시간|오늘의|주간|월간)\s*)?인기\s*(?:글|게시물|핫딜|상품|콘텐츠)?|추천\s*(?:글|게시물|핫딜|상품|콘텐츠)|관련\s*(?:글|게시물|핫딜|상품|콘텐츠)|베스트\s*(?:글|게시물|핫딜)?|많이\s*본\s*(?:글|게시물)|popular(?:\s+(?:posts?|deals?|articles?|content))?|recommended?(?:\s+(?:posts?|deals?|articles?|content))?|related(?:\s+(?:posts?|deals?|articles?|content))?|trending(?:\s+(?:posts?|deals?|articles?|content))?|best(?:\s+(?:posts?|deals?|articles?|content))?|most\s+(?:viewed|read)(?:\s+(?:posts?|articles?))?|人気(?:記事|投稿|ランキング)?|おすすめ(?:記事|投稿)?|関連記事|ランキング|热门(?:文章|帖子|内容)?|推荐(?:文章|帖子|内容)?|相关文章|排行)(?:\s*(?:더\s*보기|모두\s*보기|전체\s*보기|view\s*all|more|もっと見る|查看更多))?$/iu;
  const AUTONOMOUS_NOISE_RESOURCE_PATTERN = /(?:^|[/_.?&#=-])(?:popular|recommend(?:ed|ation|ations)?|related|ranking|trending|most[-_]?viewed|best[-_]?(?:post|deal|list)?)(?:$|[/_.?&#=-])/iu;
  const AD_NETWORK_RESOURCE_PATTERN = /(?:doubleclick\.net|googlesyndication\.com|googleadservices\.com|adservice\.google\.|amazon-adsystem\.com|taboola\.com|outbrain\.com|criteo\.(?:com|net)|adnxs\.com|adform\.net|adroll\.com|adsrvr\.org|dable\.io|adfit\.co\.kr|mobon\.net)(?:[/:?]|$)/i;
  const STRUCTURAL_NOISE_ELEMENTS = "aside, nav, footer, [role='navigation'], [role='complementary'], [role='banner']";
  const STRUCTURAL_CONTAINER_ELEMENTS = "div, section, header, ul, ol, menu, form, dialog, table";
  const LEAF_MEDIA_ELEMENTS = "img, picture, video, audio, source, track, iframe, canvas, svg";
  const COMMENT_TOKEN_PATTERN = /(?:댓글|답글|코멘트|comment|comments|reply|replies|コメント|返信|评论|回复)/i;
  const COMMENT_CONTINUATION_PATTERN = /(?:\b(?:pagination|page|load(?:ing)?|next|prev|previous)\b|\bmore\s+(?:comments?|repl(?:y|ies))\b|\b(?:comments?|repl(?:y|ies))\s+more\b|(?:\uB313\uAE00|\uB2F5\uAE00|\uCF54\uBA58\uD2B8)\s*(?:\uB354\s*\uBCF4\uAE30|\uBD88\uB7EC\uC624\uAE30|\uCD94\uAC00)|\uB354\s*\uBCF4\uAE30|\uBD88\uB7EC\uC624\uAE30|\u30DA\u30FC\u30B8|\u3082\u3063\u3068(?:\u8868\u793A|\u8AAD\u3080)?|\u66F4(?:\u591A)?(?:\u8BC4\u8BBA|\u56DE\u590D)?)/iu;
  const COMMENT_STRUCTURAL_CONTINUATION_PATTERN = /(?:pagination|page|load(?:ing)?|next|prev|previous)/iu;
  const COMMENT_REPLY_TOKEN_PATTERN = /(?:reply|repl(?:y|ies)|\uB2F5\uAE00|\u8FD4\u4FE1|\u56DE\u590D)/iu;
  const COMMENT_REPLY_REVEAL_PATTERN = /(?:view|show|open|more|load|expand|\uBCF4\uAE30|\uD3BC\uCE58|\uD45C\uC2DC|\u66F4\u591A|\u67E5\u770B|\u5C55\u5F00)/iu;
  const COMMENT_REPLY_COUNT_PATTERN = /(?:\d+\s*(?:reply|repl(?:y|ies)|\uB2F5\uAE00|\u8FD4\u4FE1|\u56DE\u590D|\uAC1C|\u4EF6|\u6761)|(?:reply|repl(?:y|ies)|\uB2F5\uAE00|\u8FD4\u4FE1|\u56DE\u590D)\s*\d+)/iu;
  const PRODUCT_TOKEN_PATTERN = /(?:가격|상품|구매|쿠폰|배송|price|product|buy|coupon|shipping|価格|商品|購入|优惠|价格|购买)/i;
  const PRODUCT_SOURCE_IDENTITY_PATTERN = /(?:^|\s)(?:source\s+url|purchase|offer|deal\s+link|buy\s+link|shop\s+link|product\s+link)(?:$|\s)/i;
  const BODY_METADATA_TOKEN_PATTERN = /(?:^|\s)(?:author|byline|writer|profile|avatar|nickname|member\s+info|post\s+meta|article\s+meta)(?:$|\s)/i;
  const CURRENCY_PATTERN = /(?:₩|원|\$|€|£|¥|USD|KRW|JPY|CNY|円|元)/i;
  const TITLE_METADATA_PATTERN = /(?:author|user|writer|date|time|view|count|info|meta|button|badge|share|report|작성|조회|날짜)/i;
  const UNTRUSTED_SIGNALS = Object.freeze(
    new Set(["selector-hint", "seed-title-match", "seed-count-match"])
  );
  const ROLE_POLICIES = Object.freeze({
    title: Object.freeze({ threshold: 6.0, margin: 0.75, minIndependentSignals: 2 }),
    body: Object.freeze({ threshold: 6.0, margin: 0.75, minIndependentSignals: 2 }),
    comments: Object.freeze({ threshold: 5.0, margin: 0.5, minIndependentSignals: 2 }),
    product: Object.freeze({ threshold: 4.5, margin: 0.5, minIndependentSignals: 2 }),
  });

  const SITE_CONTRACTS = deepFreeze(
    /* HOTDEAL_FOCUS_CONTRACTS_START */
    [
      {
        "id": "clien",
        "domain": "clien.net",
        "layouts": [
          {
            "id": "jirum",
            "path": "|/service/board/jirum/",
            "applicableProfiles": ["desktop", "mobile"],
            "pageRoot": ".content_view",
            "allowEmptyComments": true,
            "requiredRoles": ["title", "body", "comments"],
            "roleProjection": {"title":{"mode":"metadata-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"absent","cardinality":"zero","selectors":[],"ignored":[]},"comments":{"mode":"classified-children"}},
            "hints": {
              "title": [".post_subject"],
              "body": [".post_article"],
              "comments": [".post_comment"],
              "commentItems": [".post_comment > .comment .comment_row"],
              "commentControls": [".post_comment > .comment_nav", ".post_comment > .comment-nav", ".post_comment .comment_more", ".post_comment .comment-more", ".post_comment .pagination", ".post_comment [data-role='reply-toggle']"],
              "commentIgnored": [".post_comment > .comment_head", ".post_comment > .comment_msg", ".post_comment > .comment-msg", ".post_comment > #comment_write_div", ".post_comment > .fr-overlay"]
            }
          }
        ]
      },
      {
        "id": "ppomppu",
        "domain": "ppomppu.co.kr",
        "layouts": [
          {
            "id": "pc",
            "path": "|/zboard/view.php?id=ppomppu^",
            "applicableProfiles": ["desktop"],
            "pageRoot": ".wrapper",
            "allowEmptyComments": true,
            "requiredRoles": ["title", "product", "body", "comments"],
            "roleProjection": {"title":{"mode":"metadata-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"required","order":"before-body","selectors":[".topTitle-link"],"ignored":[".topTitle-link > .affiliate-img",".topTitle-link > .affiliate-sign"]},"comments":{"mode":"classified-children"}},
            "hints": {
              "title": ["#topTitle > h1"],
              "product": [".topTitle-link"],
              "body": [".board-contents"],
              "comments": ["#comment_list_area"],
              "commentItems": ["#comment_list_area > .comment_wrapper[id^='iC_']"],
              "commentControls": ["#comment_list_area .comment_more", "#comment_list_area .pagination", "#quote > .cmt-more-btn-pc", "#quote > #comment_total_btn_area", "#quote > #comment_paging_area"],
              "commentIgnored": []
            }
          },
          {
            "id": "mobile",
            "path": "|/new/bbs_view.php?id=ppomppu^",
            "applicableProfiles": ["mobile"],
            "pageRoot": ".bbs.view",
            "allowEmptyComments": true,
            "requiredRoles": ["title", "product", "body", "comments"],
            "roleProjection": {"title":{"mode":"metadata-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"required","order":"before-body","selectors":[".bbs.view > h4 .info a.noeffect"],"ignored":[]},"comments":{"mode":"classified-children"}},
            "hints": {
              "title": [".bbs.view > h4"],
              "product": [".bbs.view > h4 .info a.noeffect"],
              "body": ["#KH_Content"],
              "comments": ["#cmAr"],
              "commentItems": ["#cmList > .sect-cmt[data-cno]"],
              "commentControls": ["#cmList > a[id]", "#cmAr > .cmt-more-btn", "#cmAr .cmt-reply-btn"],
              "commentIgnored": ["#cmAr > #hot-comment-preview"]
            }
          }
        ]
      },
      {
        "id": "ruliweb",
        "domain": "ruliweb.com",
        "layouts": [
          {
            "id": "hotdeal",
            "paths": ["|/market/board/1020/read/", "|/news/board/1020/read/"],
            "applicableProfiles": ["desktop", "mobile"],
            "pageRoot": "#board_read",
            "allowEmptyComments": true,
            "requiredRoles": ["title", "body", "comments"],
            "roleProjection": {"title":{"mode":"metadata-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"optional","order":"after-body","selectors":[".source_url"],"ignored":[]},"comments":{"mode":"classified-children"}},
            "hints": {
              "title": [".subject_inner_text"],
              "product": [".source_url"],
              "body": [".view_content"],
              "comments": [".comment_view.normal", "#cmt.comment_wrapper"],
              "commentItems": [".comment_view.normal > table.comment_table > tbody > tr.comment_element:not(:has(> td.comment > .nbp_container))"],
              "commentControls": [".comment_view.normal .comment_more", ".comment_view.normal .pagination", ".comment_view.normal .btn_reply"],
              "commentIgnored": ["#cmt.comment_wrapper > input", "#cmt.comment_wrapper > .comment_count_wrapper", "#cmt.comment_wrapper > .comment_disable", "#cmt.comment_wrapper > br", ".comment_view.normal > table.comment_table > tbody > tr.comment_element:has(> td.comment > .nbp_container)"]
            }
          }
        ]
      },
      {
        "id": "quasarzone",
        "domain": "quasarzone.com",
        "layouts": [
          {
            "id": "market",
            "path": "|/bbs/qb_*/views/",
            "applicableProfiles": ["desktop"],
            "pageRoot": ".left-con-wrap",
            "allowEmptyComments": true,
            "requiredRoles": ["title", "product", "body", "comments"],
            "roleProjection": {"title":{"mode":"metadata-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"required","order":"before-body","selectors":[".market-info-view-table"],"ignored":[".market-info-view-table th .tooltip",".market-info-view-table th .common-tooltip",".market-info-view-table th img[alt='info']"]},"comments":{"mode":"classified-children"}},
            "hints": {
              "title": ["h1.title", "h1.v2-view-head__title"],
              "product": [".market-info-view-table"],
              "body": [".view-content > .note-editor"],
              "comments": ["#ajax-reply-list"],
              "commentItems": ["#ajax-reply-list > li[id^='comment']", "#ajax-reply-list > ul.common-reply-list > li[id^='comment']"],
              "commentControls": ["#ajax-reply-list .more-btn", "#ajax-reply-list .pagination", "#ajax-reply-list .reply-toggle"],
              "commentIgnored": ["#ajax-reply-list > .best-comment-wrap"]
            }
          },
          {
            "id": "market-mobile",
            "path": "|/bbs/qb_*/views/",
            "applicableProfiles": ["mobile"],
            "pageRoot": "#con-body",
            "allowEmptyComments": true,
            "requiredRoles": ["title", "product", "body", "comments"],
            "roleProjection": {"title":{"mode":"metadata-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"required","order":"before-body","selectors":[".market-info-view-table"],"ignored":[".market-info-view-table th .tooltip",".market-info-view-table th .common-tooltip",".market-info-view-table th img[alt='info']"]},"comments":{"mode":"classified-children"}},
            "hints": {
              "title": [".content.market-info-view-wrap .view-style01 .tit .ment > h1", "h1.v2-view-head__title"],
              "product": [".market-info-view-table"],
              "body": [".view-content > .note-editor"],
              "comments": ["#ajax-reply-list"],
              "commentItems": ["#ajax-reply-list > .commnet-main[id^='comment']", "#ajax-reply-list > ul.common-reply-list > li[id^='comment']"],
              "commentControls": ["#ajax-reply-list .more-btn", "#ajax-reply-list .pagination", "#ajax-reply-list .reply-toggle"],
              "commentIgnored": ["#ajax-reply-list > .best-comment-wrap"]
            }
          }
        ]
      },
      {
        "id": "eomisae",
        "domain": "eomisae.co.kr",
        "layouts": [
          {
            "id": "hotdeal",
            "paths": ["|/rt/", "|/os/", "|/fs/", "|/index.php?document_srl="],
            "applicableProfiles": ["desktop", "mobile"],
            "pageRoot": "#bd",
            "allowEmptyComments": true,
            "requiredRoles": ["title", "product", "body", "comments"],
            "roleProjection": {"title":{"mode":"metadata-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"required","order":"before-body","selectors":["#D_ .et_vars"],"ignored":["#D_ .et_vars > caption","#D_ .et_vars .tooltip"]},"comments":{"mode":"classified-children"}},
            "hints": {
              "title": ["#D_ ._hd h2"],
              "product": ["#D_ .et_vars"],
              "body": ["#D_ article > .rhymix_content"],
              "comments": ["#C_"],
              "commentItems": ["#C_ > ._bd > ._comment[id^='comment_']"],
              "commentControls": ["#C_ > #comment", "#C_ > ._bd > .cmt-overlay-background[data-cmt-overlay]", "#C_ > ._bd .pagination", "#C_ > ._bd .more", "#C_ > ._bd .reply"],
              "commentIgnored": ["#C_ > ._hd._hdc", "#C_ > center", "#C_ > ._ft"]
            }
          }
        ]
      },
      {
        "id": "zod",
        "domain": "zod.kr",
        "layouts": [
          {
            "id": "deal",
            "path": "|/deal/",
            "applicableProfiles": ["desktop", "mobile"],
            "pageRoot": "main",
            "allowEmptyComments": true,
            "requiredRoles": ["title", "product", "body", "comments"],
            "roleProjection": {"title":{"mode":"metadata-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"required","order":"before-body","selectors":[".app-article-container > .app-board-extra-value"],"ignored":[]},"comments":{"mode":"classified-children"}},
            "hints": {
              "title": [".app-board-article-head h1"],
              "product": [".app-article-container > .app-board-extra-value"],
              "body": [".app-article-container > .app-article-content"],
              "comments": ["#app-board-comment-list"],
              "commentItems": ["#app-board-comment-list > li[id^='comment_'].app-comment-item"],
              "commentControls": ["#app-board-comment-list .pagination", "#app-board-comment-list .more", "#app-board-comment-list .reply-toggle"],
              "commentIgnored": []
            }
          }
        ]
      },
      {
        "id": "arcalive",
        "domain": "arca.live",
        "layouts": [
          {
            "id": "hotdeal",
            "path": "|/b/hotdeal/",
            "applicableProfiles": ["desktop", "mobile"],
            "pageRoot": "article.board-article",
            "allowEmptyComments": true,
            "requiredRoles": ["title", "body", "comments"],
            "roleProjection": {"title":{"mode":"metadata-shallow"},"body":{"mode":"atomic-boundary","ignored":[".article-body > .ad"]},"product":{"mode":"absent","cardinality":"zero","selectors":[],"ignored":[]},"comments":{"mode":"classified-children"}},
            "hints": {
              "title": [".article-head h1", ".article-head h2", ".article-head .title"],
              "body": [".article-body"],
              "comments": [".article-comment"],
              "commentItems": [".article-comment .comment-wrapper > .comment-item[id^='c_']"],
              "commentControls": [".article-comment > .list-area > .newcomment-alert.fetch-comment", ".article-comment .pagination", ".article-comment .more", ".article-comment .reply-toggle"],
              "commentIgnored": [".article-comment > .title", ".article-comment > .alert.alert-info"]
            }
          }
        ]
      }
    ]
    /* HOTDEAL_FOCUS_CONTRACTS_END */
  );

  function deepFreeze(value) {
    if (!value || typeof value !== "object" || Object.isFrozen(value)) {
      return value;
    }
    Object.freeze(value);
    Object.keys(value).forEach(function freezeChild(key) {
      deepFreeze(value[key]);
    });
    return value;
  }

  function normalizeText(value) {
    return String(value || "")
      .normalize("NFKC")
      .toLocaleLowerCase()
      .replace(/[\u0000-\u001f\u007f]/g, " ")
      .replace(/[\[\]【】()（）<>《》|｜·•:：;,，.!！?？'"“”‘’/_\\-]+/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  }

  function truncateText(value, maximumLength) {
    return normalizeText(value).slice(0, maximumLength);
  }

  function truncateRawTitle(value, maximumLength) {
    return String(value || "")
      .normalize("NFKC")
      .replace(/(?:&#42;|&#x2a;|&ast;)/giu, "*")
      .replace(/[\u0000-\u001f\u007f]/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, maximumLength);
  }

  function textBigrams(value) {
    const compact = normalizeText(value).replace(/\s+/g, "");
    const grams = [];
    for (let index = 0; index < compact.length - 1; index += 1) {
      grams.push(compact.slice(index, index + 2));
    }
    return grams;
  }

  function textSimilarity(leftValue, rightValue) {
    const left = normalizeText(leftValue);
    const right = normalizeText(rightValue);
    if (!left || !right) {
      return 0;
    }
    if (left === right) {
      return 1;
    }
    const shorter = left.length <= right.length ? left : right;
    const longer = left.length > right.length ? left : right;
    const containment = longer.includes(shorter)
      ? Math.min(1, shorter.length / Math.max(12, longer.length))
      : 0;

    const leftTokens = new Set(left.split(" ").filter(Boolean));
    const rightTokens = new Set(right.split(" ").filter(Boolean));
    const tokenIntersection = Array.from(leftTokens).filter(function sharedToken(token) {
      return rightTokens.has(token);
    }).length;
    const tokenUnion = new Set(Array.from(leftTokens).concat(Array.from(rightTokens))).size;
    const tokenScore = tokenUnion ? tokenIntersection / tokenUnion : 0;

    const leftBigrams = textBigrams(left);
    const rightBigrams = textBigrams(right);
    const rightCounts = new Map();
    rightBigrams.forEach(function countBigram(gram) {
      rightCounts.set(gram, (rightCounts.get(gram) || 0) + 1);
    });
    let sharedBigrams = 0;
    leftBigrams.forEach(function consumeBigram(gram) {
      const remaining = rightCounts.get(gram) || 0;
      if (remaining > 0) {
        sharedBigrams += 1;
        rightCounts.set(gram, remaining - 1);
      }
    });
    const bigramScore = leftBigrams.length + rightBigrams.length
      ? (2 * sharedBigrams) / (leftBigrams.length + rightBigrams.length)
      : 0;
    return Math.max(containment, tokenScore, bigramScore);
  }

  const TITLE_NOISE_TOKENS = Object.freeze(new Set([
    "핫딜", "특가", "할인", "쿠폰", "무료", "무배", "무료배송", "배송", "배송비", "일시",
    "상품", "구매", "공식", "단독", "기타", "hotdeal", "deal", "sale", "coupon",
    "free", "shipping", "official",
  ]));
  const TITLE_SITE_SUFFIX_PATTERN = /\s*(?:[-–—|｜:：]\s*)?(?:클리앙|뽐뿌(?::뽐뿌게시판)?|루리웹|퀘이사존|어미새|zod|아카라이브|arca\s*live|패션정보|기타정보|핫딜\s*채널|특가)(?:\s*핫딜)?\s*$/iu;
  const TITLE_COMMERCE_SUFFIX_PATTERN = /(?:\d[\d,.]*\s*(?:원|krw|usd|jpy|cny|엔|달러|발)|무배|무료\s*배송|배송비|쿠폰|shipping)/iu;

  function stripBoundedTitleAffixes(value) {
    let text = String(value || "").normalize("NFKC").trim();
    const statusPrefix = text.match(/^(이벤트정보|진행중|인기|국내|식품)\s+/u);
    if (statusPrefix) {
      text = text.slice(statusPrefix[0].length).trim();
      if (statusPrefix[1] === "이벤트정보") {
        text = text.replace(/\s+\d{1,4}\s*$/u, "").trim();
      }
    }
    text = text.replace(
      /\s+\d{1,3}\s*[~～-]\s*\d{1,3}\s*%\s*할인\s*[\[【(（]\d{1,2}\/\d{1,2}\s*[~～-]\s*\d{1,2}[\]】)）]\s*$/u,
      "",
    );
    for (let count = 0; count < 3; count += 1) {
      const withoutSuffix = text.replace(TITLE_SITE_SUFFIX_PATTERN, "").trim();
      if (withoutSuffix === text) break;
      text = withoutSuffix;
    }
    text = text
      .replace(/^카톡선물하기지마켓\s+/u, "")
      .replace(/^네이버페이\s+(?=\S+\s+\S+\s+\S+)/u, "")
      .replace(/^네이버\s+(?=\S+\s+\S+\s+\S+)/u, "");
    for (let count = 0; count < 2; count += 1) {
      const prefix = text.match(/^\s*[\[【(（]([^\[【(（\]】)）]{1,24})[\]】)）]\s*/u);
      if (!prefix || /\d/u.test(prefix[1])) {
        break;
      }
      text = text.slice(prefix[0].length).trim();
    }
    for (let count = 0; count < 2; count += 1) {
      const suffix = text.match(/\s*[\[【(（]([^\[【(（\]】)）]{1,80})[\]】)）]\s*$/u);
      if (!suffix || !TITLE_COMMERCE_SUFFIX_PATTERN.test(suffix[1])) {
        break;
      }
      text = text.slice(0, suffix.index).trim();
    }
    text = text
      .replace(
        /\s+\d+(?:\.\d+)?\s*발(?:\s*[\[【(（][^\]】)）]{1,60}[\]】)）])?(?:\s*(?:무배|무료\s*배송))?\s*$/iu,
        "",
      )
      .replace(/\s+\d+(?:\.\d+)?\s*발(?:\s*\.{2,})?\s*$/iu, "")
      .replace(TITLE_SITE_SUFFIX_PATTERN, "")
      .replace(/\.{2,}\s*$/u, "")
      .trim();
    return text;
  }

  function canonicalizeAsciiModelSeparators(value) {
    return String(value || "").replace(
      /(?:(?<=[A-Za-z])[-_.\/](?=[A-Za-z0-9])|(?<=[A-Za-z0-9])[-_.\/](?=[A-Za-z]))/g,
      "",
    );
  }

  function punctuationInvariantTitleMatch(leftValue, rightValue) {
    const skeleton = function titleGlyphSkeleton(value) {
      return String(value || "")
        .normalize("NFKC")
        .toLocaleLowerCase()
        .replace(/[^\p{L}\p{N}]+/gu, "");
    };
    const left = skeleton(leftValue);
    const right = skeleton(rightValue);
    return left.length >= 8 && left === right;
  }

  function titleWordTokens(value) {
    return Array.from(new Set(
      normalizeText(canonicalizeAsciiModelSeparators(stripBoundedTitleAffixes(value)))
        .match(/[\p{L}\p{N}]+/gu) || []
    ));
  }

  function protectedTitleTokens(value) {
    const stripped = canonicalizeAsciiModelSeparators(stripBoundedTitleAffixes(value));
    const tokens = [];
    const mixedOrNumeric = stripped.match(
      /(?:[A-Za-z]+[-_.]?\d+(?:[-_.]\d+)*[A-Za-z0-9-]*|\d+(?:[.,]\d+)*(?:[A-Za-z가-힣ぁ-んァ-ヶ一-龠]+)?)/gu,
    ) || [];
    mixedOrNumeric.forEach(function addProtectedToken(token) {
      tokens.push(token.toLocaleLowerCase().replace(/,(?=\d)/g, ""));
    });
    const uppercaseModels = stripped.match(/(?:^|\s)([A-Z]{1,4})(?=\s|$)/g) || [];
    uppercaseModels.forEach(function addUppercaseModel(token) {
      tokens.push(token.trim().toLocaleLowerCase());
    });
    const asciiComponents = stripped.match(/[A-Za-z]{2,}/g) || [];
    asciiComponents.forEach(function addAsciiComponent(token) {
      tokens.push(token.toLocaleLowerCase());
    });
    return Array.from(new Set(tokens)).sort();
  }

  function isCjkToken(token) {
    return /[가-힣ぁ-んァ-ヶ一-龠]/u.test(token);
  }

  function distinctiveTitleTokens(value) {
    const protectedTokens = new Set(protectedTitleTokens(value));
    return titleWordTokens(value).filter(function distinctive(token) {
      if (TITLE_NOISE_TOKENS.has(token)) {
        return false;
      }
      return protectedTokens.has(token) ||
        (isCjkToken(token) ? token.length >= 2 : token.length >= 3);
    });
  }

  function titleTokenMatchScore(referenceToken, candidateToken) {
    if (referenceToken === candidateToken) {
      return 1;
    }
    if (/\d/u.test(referenceToken) || /\d/u.test(candidateToken)) {
      return 0;
    }
    if (!isCjkToken(referenceToken) || !isCjkToken(candidateToken)) {
      return 0;
    }
    const minimumLength = 2;
    const shorterLength = Math.min(referenceToken.length, candidateToken.length);
    const longerLength = Math.max(referenceToken.length, candidateToken.length);
    if (
      shorterLength >= minimumLength &&
      (referenceToken.startsWith(candidateToken) || candidateToken.startsWith(referenceToken)) &&
      shorterLength / longerLength >= 0.67
    ) {
      return shorterLength / longerLength;
    }
    return 0;
  }

  function titleCoreEquivalence(referenceValue, candidateValue) {
    const referenceCore = normalizeText(stripBoundedTitleAffixes(referenceValue));
    const candidateCore = normalizeText(stripBoundedTitleAffixes(candidateValue));
    if (!referenceCore || !candidateCore) {
      return Object.freeze({ ok: false, score: 0, mode: "missing" });
    }
    const referenceProtected = protectedTitleTokens(referenceValue);
    const candidateProtected = protectedTitleTokens(candidateValue);
    const protectedAgreement = referenceProtected.every(function hasProtectedToken(token) {
        return candidateProtected.includes(token);
      });
    const referenceTokens = distinctiveTitleTokens(referenceValue);
    const candidateTokens = distinctiveTitleTokens(candidateValue);
    const availableCandidateIndexes = new Set(candidateTokens.map(function indexToken(_token, index) {
      return index;
    }));
    let matchedWeight = 0;
    let matchedCount = 0;
    referenceTokens.forEach(function matchReferenceToken(referenceToken) {
      let bestIndex = -1;
      let bestScore = 0;
      availableCandidateIndexes.forEach(function compareCandidate(index) {
        const score = titleTokenMatchScore(referenceToken, candidateTokens[index]);
        if (score > bestScore) {
          bestScore = score;
          bestIndex = index;
        }
      });
      if (bestIndex >= 0) {
        availableCandidateIndexes.delete(bestIndex);
        matchedCount += 1;
        matchedWeight += Math.min(8, Math.max(2, referenceToken.length)) * bestScore;
      }
    });
    const referenceWeight = referenceTokens.reduce(
      (total, token) => total + Math.min(8, Math.max(2, token.length)),
      0,
    );
    const candidateWeight = candidateTokens.reduce(
      (total, token) => total + Math.min(8, Math.max(2, token.length)),
      0,
    );
    const recall = referenceWeight ? matchedWeight / referenceWeight : 0;
    const precision = candidateWeight ? matchedWeight / candidateWeight : 0;
    const compactLength = referenceCore.replace(/\s+/g, "").length;
    const boundedExpansion =
      candidateCore.replace(/\s+/g, "").length <= compactLength * 2 + 40;
    const ok =
      protectedAgreement &&
      referenceTokens.length >= 2 &&
      matchedCount >= 2 &&
      recall >= 0.8 &&
      precision >= 0.7 &&
      compactLength >= 6 &&
      boundedExpansion;
    const diagnosticScore = Math.min(0.999, Math.max(0, recall * 0.8 + precision * 0.2));
    return Object.freeze({
      ok,
      score: ok ? 1 : Number(diagnosticScore.toFixed(3)),
      mode: ok
        ? referenceCore === candidateCore ? "exact-core" : "distinctive-core"
        : protectedAgreement ? "insufficient-core" : "protected-token-mismatch",
      matchedDistinctiveTokenCount: matchedCount,
      referenceDistinctiveTokenCount: referenceTokens.length,
      protectedTokenAgreement: protectedAgreement,
    });
  }

  const TITLE_PUBLISHER_PREFIX_TOKENS = Object.freeze(new Set([
    "선착순", "겜우리", "공식몰", "판매처", "우리동네gs", "ssg", "g마켓", "옥션", "쿠팡", "네이버",
  ]));
  const TITLE_COMMERCE_EXTRA_TOKENS = Object.freeze(new Set([
    "가격", "특가", "할인", "쿠폰", "적립", "최대", "무료", "무료배송", "배송", "무배",
    "카드", "비씨", "bc", "한정", "선착순", "픽업", "세트", "묶음", "팩", "개", "개입",
    "g", "kg", "ml", "l", "gb", "tb", "box", "pack",
  ]));

  function boundaryTitleTokens(value) {
    return normalizeText(canonicalizeAsciiModelSeparators(stripBoundedTitleAffixes(value)))
      .replace(/([\p{L}])(?=\p{N})/gu, "$1 ")
      .replace(/([\p{N}])(?=\p{L})/gu, "$1 ")
      .match(/[\p{L}\p{N}]+/gu) || [];
  }

  function distinctiveBoundaryTitleTokens(value) {
    return boundaryTitleTokens(value).filter(function distinctiveBoundaryToken(token) {
      if (TITLE_NOISE_TOKENS.has(token)) return false;
      if (/^\d+(?:[.,]\d+)*$/u.test(token)) return true;
      return isCjkToken(token) ? token.length >= 2 : token.length >= 2;
    });
  }

  function numericTitleTokens(value) {
    return (stripBoundedTitleAffixes(value).match(/\d+(?:[.,]\d+)*/gu) || [])
      .map(function normalizedNumber(token) { return token.replace(/,/g, ""); });
  }

  function multisetContainsAll(candidateTokens, referenceTokens) {
    const counts = new Map();
    candidateTokens.forEach(function countCandidate(token) {
      counts.set(token, (counts.get(token) || 0) + 1);
    });
    return referenceTokens.every(function consumeReference(token) {
      const remaining = counts.get(token) || 0;
      if (!remaining) return false;
      counts.set(token, remaining - 1);
      return true;
    });
  }

  function mixedAsciiTitleModels(value) {
    return (canonicalizeAsciiModelSeparators(stripBoundedTitleAffixes(value))
      .match(/[A-Za-z]+\d+[A-Za-z0-9-]*/g) || [])
      .map(function normalizedModel(token) {
        return token.toLocaleLowerCase().replace(/-/g, "");
      });
  }

  function hasBoundedModelExpansion(referenceValue, candidateValue) {
    const referenceModels = mixedAsciiTitleModels(referenceValue);
    if (!referenceModels.length) return false;
    const candidateModels = mixedAsciiTitleModels(candidateValue);
    return referenceModels.every(function preservedModel(referenceModel) {
      return candidateModels.some(function exactOrPublisherComposite(candidateModel) {
        if (candidateModel === referenceModel) return true;
        const remainder = candidateModel.slice(referenceModel.length);
        return candidateModel.startsWith(referenceModel) &&
          /^[a-z][a-z0-9]{0,5}$/u.test(remainder);
      });
    });
  }

  function boundedPublisherModelReorder(referenceValue, matchedIndexes) {
    if (matchedIndexes.length < 3 || mixedAsciiTitleModels(referenceValue).length === 0) {
      return false;
    }
    const prefixIndexes = matchedIndexes.slice(0, 3);
    const sortedPrefixIndexes = prefixIndexes.slice().sort(function numericOrder(left, right) {
      return left - right;
    });
    const prefixIsCompact = sortedPrefixIndexes[2] - sortedPrefixIndexes[0] === 2 &&
      new Set(prefixIndexes).size === 3;
    const suffixIndexes = matchedIndexes.slice(3);
    const suffixIsOrderedAfterPrefix = suffixIndexes.every(function orderedSuffix(index, offset) {
      return index > sortedPrefixIndexes[2] &&
        (offset === 0 || index > suffixIndexes[offset - 1]);
    });
    let inversionCount = 0;
    for (let left = 0; left < prefixIndexes.length; left += 1) {
      for (let right = left + 1; right < prefixIndexes.length; right += 1) {
        if (prefixIndexes[left] > prefixIndexes[right]) inversionCount += 1;
      }
    }
    return prefixIsCompact && suffixIsOrderedAfterPrefix && inversionCount > 0 && inversionCount <= 2;
  }

  function publisherTitleExpansion(referenceValue, candidateValue) {
    const referenceCore = normalizeText(stripBoundedTitleAffixes(referenceValue));
    const candidateCore = normalizeText(stripBoundedTitleAffixes(candidateValue));
    const referenceTokens = distinctiveBoundaryTitleTokens(referenceValue);
    const candidateTokens = distinctiveBoundaryTitleTokens(candidateValue);
    if (
      !referenceCore ||
      !candidateCore ||
      referenceCore.replace(/\s+/g, "").length < 6 ||
      referenceTokens.length < 2 ||
      candidateCore.replace(/\s+/g, "").length >
        referenceCore.replace(/\s+/g, "").length * 2 + 48 ||
      candidateTokens.length > referenceTokens.length + 8 ||
      !multisetContainsAll(
        numericTitleTokens(candidateValue),
        numericTitleTokens(referenceValue),
      )
    ) {
      return Object.freeze({
        ok: false,
        score: 0,
        mode: "publisher-expansion-bounds",
        matchedDistinctiveTokenCount: 0,
        referenceDistinctiveTokenCount: referenceTokens.length,
        protectedTokenAgreement: false,
      });
    }
    const availableCandidateIndexes = new Set(
      candidateTokens.map(function candidateIndex(_token, index) { return index; }),
    );
    const matchedIndexes = [];
    let previousIndex = -1;
    let matchedWeight = 0;
    for (const referenceToken of referenceTokens) {
      let bestIndex = -1;
      let bestScore = 0;
      availableCandidateIndexes.forEach(function orderedCandidate(index) {
        if (index <= previousIndex) return;
        const score = titleTokenMatchScore(referenceToken, candidateTokens[index]);
        if (score > bestScore) {
          bestScore = score;
          bestIndex = index;
        }
      });
      if (bestIndex < 0) break;
      availableCandidateIndexes.delete(bestIndex);
      matchedIndexes.push(bestIndex);
      previousIndex = bestIndex;
      matchedWeight += Math.min(8, Math.max(2, referenceToken.length)) * bestScore;
    }
    const unorderedAvailableIndexes = new Set(
      candidateTokens.map(function unorderedCandidateIndex(_token, index) { return index; }),
    );
    const unorderedMatchedIndexes = [];
    let unorderedMatchedWeight = 0;
    for (const referenceToken of referenceTokens) {
      let bestIndex = -1;
      let bestScore = 0;
      unorderedAvailableIndexes.forEach(function unorderedCandidate(index) {
        const score = titleTokenMatchScore(referenceToken, candidateTokens[index]);
        if (score > bestScore) {
          bestScore = score;
          bestIndex = index;
        }
      });
      if (bestIndex < 0) break;
      unorderedAvailableIndexes.delete(bestIndex);
      unorderedMatchedIndexes.push(bestIndex);
      unorderedMatchedWeight += Math.min(8, Math.max(2, referenceToken.length)) * bestScore;
    }
    const publisherModelReordered =
      unorderedMatchedIndexes.length === referenceTokens.length &&
      boundedPublisherModelReorder(referenceValue, unorderedMatchedIndexes);
    const effectiveMatchedIndexes = publisherModelReordered
      ? unorderedMatchedIndexes
      : matchedIndexes;
    const effectiveMatchedWeight = publisherModelReordered
      ? unorderedMatchedWeight
      : matchedWeight;
    const referenceWeight = referenceTokens.reduce(
      (total, token) => total + Math.min(8, Math.max(2, token.length)),
      0,
    );
    const recall = referenceWeight ? effectiveMatchedWeight / referenceWeight : 0;
    const firstMatch = effectiveMatchedIndexes.length
      ? Math.min(...effectiveMatchedIndexes)
      : -1;
    const lastMatch = effectiveMatchedIndexes.length
      ? Math.max(...effectiveMatchedIndexes)
      : -1;
    const unmatched = candidateTokens.map(function indexedToken(token, index) {
      return { token, index };
    }).filter(function unmatchedToken(item) {
      return !effectiveMatchedIndexes.includes(item.index);
    });
    const leadingExtras = unmatched.filter(function leading(item) {
      return item.index < firstMatch;
    });
    const internalExtras = unmatched.filter(function internal(item) {
      return item.index > firstMatch && item.index < lastMatch;
    });
    const trailingExtras = unmatched.filter(function trailing(item) {
      return item.index > lastMatch;
    });
    const leadingApproved = leadingExtras.length <= 1 && leadingExtras.every(
      function approvedPublisherPrefix(item) {
        return TITLE_PUBLISHER_PREFIX_TOKENS.has(item.token);
      },
    );
    const modelExpanded = hasBoundedModelExpansion(referenceValue, candidateValue);
    const internalApproved = internalExtras.length === 0 || (
      internalExtras.length <= 2 &&
      internalExtras.every(function boundedInternalExtra(item) {
        return TITLE_COMMERCE_EXTRA_TOKENS.has(item.token) || (
          modelExpanded && (/^\d{1,3}$/u.test(item.token) || /^[a-z]{1,4}$/u.test(item.token))
        );
      })
    );
    const trailingApproved = trailingExtras.every(function approvedCommerceExtra(item) {
      return /^\d+(?:[.,]\d+)*$/u.test(item.token) ||
        TITLE_COMMERCE_EXTRA_TOKENS.has(item.token);
    });
    const protectedAgreement = numericTitleTokens(referenceValue).length === 0 ||
      multisetContainsAll(
        numericTitleTokens(candidateValue),
        numericTitleTokens(referenceValue),
      );
    const ok =
      protectedAgreement &&
      effectiveMatchedIndexes.length === referenceTokens.length &&
      recall >= 0.9 &&
      leadingApproved &&
      internalApproved &&
      trailingApproved;
    return Object.freeze({
      ok,
      score: ok ? 1 : Number(Math.min(0.999, Math.max(0, recall)).toFixed(3)),
      mode: ok ? "bounded-publisher-expansion" : "publisher-expansion-mismatch",
      matchedDistinctiveTokenCount: effectiveMatchedIndexes.length,
      referenceDistinctiveTokenCount: referenceTokens.length,
      protectedTokenAgreement: protectedAgreement,
    });
  }

  function titleConsistency(sourceValue, destinationValue) {
    const core = titleCoreEquivalence(sourceValue, destinationValue);
    if (core.ok) return core;
    const expansion = publisherTitleExpansion(sourceValue, destinationValue);
    return expansion.ok ? expansion : core;
  }

  function singleLongTitleTokenEquivalence(referenceValue, candidateValue) {
    const referenceTokens = distinctiveTitleTokens(referenceValue);
    const candidateTokens = distinctiveTitleTokens(candidateValue);
    const referenceProtected = protectedTitleTokens(referenceValue);
    const candidateProtected = protectedTitleTokens(candidateValue);
    const protectedAgreement = referenceProtected.every(function hasProtectedToken(token) {
        return candidateProtected.includes(token);
      });
    const candidateWithoutStatus = String(candidateValue || "")
      .normalize("NFKC")
      .trim()
      .replace(/^(?:이벤트정보|진행중|인기|국내|식품)\s+/u, "");
    const boundedContext = /^\s*[\[【(（][^\[【(（\]】)）]{2,24}[\]】)）]\s*/u.test(
      candidateWithoutStatus,
    );
    const candidateWords = titleWordTokens(candidateValue);
    const onlyBoundedNoiseExtras = candidateWords.every(function boundedWord(token) {
      return token === referenceTokens[0] || TITLE_NOISE_TOKENS.has(token);
    });
    const ok =
      protectedAgreement &&
      boundedContext &&
      onlyBoundedNoiseExtras &&
      referenceTokens.length === 1 &&
      candidateTokens.length === 1 &&
      referenceTokens[0] === candidateTokens[0] &&
      referenceTokens[0].length >= 7;
    return Object.freeze({
      ok,
      score: ok ? 1 : 0,
      mode: ok ? "single-long-token" : "insufficient-single-token",
      matchedDistinctiveTokenCount: ok ? 1 : 0,
      referenceDistinctiveTokenCount: referenceTokens.length,
      protectedTokenAgreement: protectedAgreement,
    });
  }

  function escapePattern(value) {
    return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function pathPatternMatches(pathAndQuery, configuredPath) {
    const configured = String(configuredPath || "");
    if (!configured.startsWith("|/")) {
      return false;
    }
    const requiresSeparator = configured.endsWith("^");
    const body = configured.slice(1, requiresSeparator ? -1 : undefined);
    const pattern = escapePattern(body).replace(/\\\*/g, "[^/?&=]+");
    const terminalWildcard = body.endsWith("*");
    const wildcardIsQueryToken = body.lastIndexOf("?") > body.lastIndexOf("/");
    const boundary = !requiresSeparator
      ? ""
      : terminalWildcard
        ? wildcardIsQueryToken ? "(?:&|$)" : "(?:\\?|$)"
        : "(?:[^A-Za-z0-9_.%\\-]|$)";
    return new RegExp(`^${pattern}${boundary}`).test(String(pathAndQuery || ""));
  }

  function contractPaths(layout) {
    return Array.isArray(layout.paths) ? layout.paths.slice() : [layout.path];
  }

  function hostnameMatches(hostname, domain) {
    const normalizedHostname = String(hostname || "").toLocaleLowerCase();
    return normalizedHostname === domain || normalizedHostname.endsWith(`.${domain}`);
  }

  function findSiteContract(hostname) {
    return SITE_CONTRACTS.find(function matchContract(contract) {
      return hostnameMatches(hostname, contract.domain);
    }) || null;
  }

  function matchingLayouts(contract, pathAndQuery) {
    return contract.layouts.filter(function matchLayout(layout) {
      return contractPaths(layout).some(function matchPath(path) {
        return pathPatternMatches(pathAndQuery, path);
      });
    });
  }

  function uniqueQueryValue(url, name) {
    const values = url.searchParams.getAll(name);
    return values.length === 1 ? values[0] : null;
  }

  function articleIdentity(locationLike, siteId) {
    let url;
    try {
      url = new URL(typeof locationLike === "string" ? locationLike : locationLike.href);
    } catch (_error) {
      return null;
    }
    const contract = SITE_CONTRACTS.find(function identityContract(candidate) {
      return candidate.id === siteId && hostnameMatches(url.hostname, candidate.domain);
    });
    const pathAndQuery = `${url.pathname}${url.search}`;
    if (
      !contract ||
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.port ||
      matchingLayouts(contract, pathAndQuery).length === 0
    ) {
      return null;
    }
    const numeric = (value) => /^\d{1,24}$/.test(String(value || ""))
      ? String(value)
      : null;
    const token = (value) => /^[a-z0-9_-]{1,48}$/i.test(String(value || ""))
      ? String(value).toLocaleLowerCase()
      : null;
    let route = null;
    let board = null;
    let articleId = null;
    let match = null;
    if (siteId === "clien") {
      match = url.pathname.match(/^\/service\/board\/([a-z0-9_-]+)\/(\d{1,24})\/?$/iu);
      route = match ? "service-board" : null;
      board = token(match?.[1]);
      articleId = numeric(match?.[2]);
    } else if (siteId === "ppomppu") {
      route = url.pathname === "/zboard/view.php"
        ? "board-view"
        : url.pathname === "/new/bbs_view.php"
          ? "board-view"
          : null;
      board = token(uniqueQueryValue(url, "id"));
      articleId = numeric(uniqueQueryValue(url, "no"));
    } else if (siteId === "ruliweb") {
      match = url.pathname.match(
        /^\/(market|news)\/board\/(\d{1,24})\/read\/(\d{1,24})\/?$/u,
      );
      route = match ? `${match[1]}-board-read` : null;
      board = numeric(match?.[2]);
      articleId = numeric(match?.[3]);
    } else if (siteId === "quasarzone") {
      match = url.pathname.match(/^\/bbs\/([a-z0-9_-]+)\/views\/(\d{1,24})\/?$/iu);
      route = match ? "bbs-views" : null;
      board = token(match?.[1]);
      articleId = numeric(match?.[2]);
    } else if (siteId === "eomisae") {
      match = url.pathname.match(/^\/(rt|os|fs)\/(\d{1,24})\/?$/u);
      if (match) {
        const pathArticleId = numeric(match[2]);
        const documentValues = url.searchParams.getAll("document_srl");
        const midValues = url.searchParams.getAll("mid");
        const queryDocumentId = documentValues.length === 1
          ? numeric(documentValues[0])
          : null;
        if (
          documentValues.length > 1 ||
          (documentValues.length === 1 && queryDocumentId !== pathArticleId) ||
          midValues.length > 1 ||
          (midValues.length === 1 && !["rt", "os", "fs"].includes(token(midValues[0])))
        ) {
          return null;
        }
        route = "document";
        board = "document";
        articleId = pathArticleId;
      } else if (url.pathname === "/index.php") {
        const midValues = url.searchParams.getAll("mid");
        if (
          midValues.length > 1 ||
          (midValues.length === 1 && !["rt", "os", "fs"].includes(token(midValues[0])))
        ) {
          return null;
        }
        route = "document";
        board = "document";
        articleId = numeric(uniqueQueryValue(url, "document_srl"));
      }
    } else if (siteId === "zod") {
      match = url.pathname.match(/^\/deal\/(\d{1,24})\/?$/u);
      route = match ? "deal" : null;
      board = "deal";
      articleId = numeric(match?.[1]);
    } else if (siteId === "arcalive") {
      match = url.pathname.match(/^\/b\/([a-z0-9_-]+)\/(\d{1,24})\/?$/iu);
      route = match ? "board-article" : null;
      board = token(match?.[1]);
      articleId = numeric(match?.[2]);
    }
    return route && board && articleId
      ? `${siteId}:${contract.domain}:${route}:${board}:${articleId}`
      : null;
  }

  function referrerScopedArticleIdentity(locationLike, siteId) {
    const approvedIdentity = articleIdentity(locationLike, siteId);
    if (approvedIdentity) return approvedIdentity;
    let url;
    try {
      url = new URL(
        typeof locationLike === "string" ? locationLike : locationLike.href,
      );
    } catch (_error) {
      return null;
    }
    const contract = SITE_CONTRACTS.find(function scopedIdentityContract(candidate) {
      return candidate.id === siteId &&
        hostnameMatches(url.hostname, candidate.domain);
    });
    if (
      !contract ||
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.port ||
      !url.pathname ||
      url.pathname === "/"
    ) {
      return null;
    }
    const stableQuery = new URLSearchParams(url.search);
    Array.from(stableQuery.keys()).forEach(function removeTrackingParameter(name) {
      if (/^(?:utm_.+|fbclid|gclid|dclid|msclkid|ref|source)$/iu.test(name)) {
        stableQuery.delete(name);
      }
    });
    stableQuery.sort();
    const query = stableQuery.toString();
    return `${siteId}:referrer-url:${url.pathname}${query ? `?${query}` : ""}`;
  }

  function sameArticleNavigation(sourceLocation, destinationLocation, siteId) {
    const sourceIdentity = articleIdentity(sourceLocation, siteId);
    const destinationIdentity = articleIdentity(destinationLocation, siteId);
    return Boolean(sourceIdentity) && sourceIdentity === destinationIdentity;
  }

  function isAlgumonReferrer(referrer) {
    try {
      const url = new URL(referrer);
      return url.protocol === "https:" &&
        url.hostname.toLocaleLowerCase() === "www.algumon.com" &&
        !url.username && !url.password && !url.port;
    } catch (_error) {
      return false;
    }
  }

  function canonicalAlgumonReferrerOrigin(urlLike) {
    try {
      const url = new URL(urlLike);
      return isAlgumonReferrer(url.href) ? `${url.origin}/` : null;
    } catch (_error) {
      return null;
    }
  }

  function readerEntryAuthority(locationLike, referrer) {
    if (canonicalAlgumonReferrerOrigin(referrer)) return "algumon-referrer";
    try {
      const target = new URL(typeof locationLike === "string" ? locationLike : locationLike.href);
      const contract = findSiteContract(target.hostname);
      // Mobile publisher redirects may replace or remove document.referrer.
      // The registered hot-deal route and article identity are sufficient to
      // start discovery; the full semantic/body/comment proof still controls
      // release. Unknown routes retain the exact Algumon-origin requirement.
      return contract && articleIdentity(target.href, contract.id)
        ? "registered-hotdeal-route"
        : null;
    } catch (_error) {
      return null;
    }
  }

  function utf8ByteLength(value) {
    return unescape(encodeURIComponent(String(value))).length;
  }

  function normalizeCommentCount(value) {
    const number = Number.parseInt(String(value || "").replace(/[^0-9]/g, ""), 10);
    return Number.isSafeInteger(number) && number >= 0 && number <= 100000 ? number : null;
  }

  function createRunNonce(browserRoot) {
    const getRandomValues = browserRoot === RUNTIME_GLOBAL
      ? NATIVE.cryptoGetRandomValues
      : browserRoot?.crypto?.getRandomValues?.bind(browserRoot.crypto);
    if (typeof getRandomValues !== "function") return null;
    const words = new Uint32Array(4);
    try {
      getRandomValues(words);
      return `hdf-${Array.from(words).map(function encodeWord(word) {
        return word.toString(36).padStart(7, "0");
      }).join("")}`;
    } catch (_error) {
      return null;
    }
  }

  function addSignal(evaluation, signal, points) {
    evaluation.signals.add(signal);
    evaluation.score += points;
  }

  function independentSignalCount(signals) {
    return Array.from(signals).filter(function trustedSignal(signal) {
      return !UNTRUSTED_SIGNALS.has(signal);
    }).length;
  }

  function documentOrder(leftNode, rightNode) {
    if (leftNode === rightNode) {
      return 0;
    }
    const position = leftNode.compareDocumentPosition(rightNode);
    return position & 4 ? -1 : 1;
  }

  function decideCandidate(evaluations, policy) {
    const qualified = evaluations.filter(function meetsSignalContract(evaluation) {
      return !evaluation.disqualified &&
        evaluation.score >= policy.threshold &&
        independentSignalCount(evaluation.signals) >= policy.minIndependentSignals;
    });
    qualified.sort(function rankCandidates(left, right) {
      if (right.score !== left.score) {
        return right.score - left.score;
      }
      return documentOrder(left.node, right.node);
    });
    if (!qualified.length) {
      return Object.freeze({ ok: false, reason: "threshold-or-signals", ranked: qualified });
    }
    if (qualified.length > 1 && qualified[0].score - qualified[1].score < policy.margin) {
      return Object.freeze({ ok: false, reason: "insufficient-margin", ranked: qualified });
    }
    return Object.freeze({ ok: true, winner: qualified[0], ranked: qualified });
  }

  function qualifiedCandidates(evaluations, policy) {
    const ranked = evaluations.filter(function meetsSignalContract(evaluation) {
      return !evaluation.disqualified &&
        evaluation.score >= policy.threshold &&
        independentSignalCount(evaluation.signals) >= policy.minIndependentSignals;
    });
    ranked.sort(function rankCandidates(left, right) {
      if (right.score !== left.score) {
        return right.score - left.score;
      }
      return documentOrder(left.node, right.node);
    });
    return ranked;
  }

  function preferUniqueQualifiedHintCandidate(decision, hintSelectors, approve) {
    if (!decision.ranked?.length || !hintSelectors?.length) return decision;
    const hinted = decision.ranked.filter(function qualifiedHintCandidate(evaluation) {
      return elementMatchesAny(evaluation.node, hintSelectors);
    });
    if (hinted.length !== 1 || (approve && !approve(hinted[0]))) return decision;
    return Object.freeze({
      ...decision,
      ok: true,
      reason: "unique-qualified-hint-anchor",
      winner: hinted[0],
      ranked: Object.freeze([hinted[0]]),
      hintAnchored: true,
    });
  }

  function decisionDiagnostics(decision, candidateCount, policy) {
    const runnerUp = decision.ranked && decision.ranked[1];
    const margin = decision.ok && runnerUp
      ? decision.winner.score - runnerUp.score
      : policy.margin;
    return Object.freeze({
      count: candidateCount,
      score: decision.ok ? Number(decision.winner.score.toFixed(3)) : 0,
      signalCount: decision.ok ? independentSignalCount(decision.winner.signals) : 0,
      margin: Number(margin.toFixed(3)),
    });
  }

  function queryAllSafe(rootNode, selectors) {
    const nodes = [];
    selectors.forEach(function querySelector(selector) {
      try {
        rootNode.querySelectorAll(selector).forEach(function addNode(node) {
          nodes.push(node);
        });
      } catch (_error) {
        // Invalid runtime hints are ignored; release-time validation rejects them.
      }
    });
    return nodes;
  }

  function collectBoundedCandidateElements(
    rootNode,
    broadSelector,
    hintSelectors,
    broadPredicate,
  ) {
    const elements = [];
    const seen = new Set();
    let overflow = false;
    function collect(selector, predicate) {
      if (!selector || overflow) return;
      let matches;
      try {
        matches = rootNode.querySelectorAll(selector);
      } catch (_error) {
        return;
      }
      for (const element of matches) {
        if (seen.has(element)) continue;
        if (predicate && !predicate(element)) continue;
        if (elements.length >= MAX_PROJECTION_CANDIDATE_EVALUATIONS) {
          overflow = true;
          return;
        }
        seen.add(element);
        elements.push(element);
      }
    }
    (hintSelectors || []).forEach(function collectHint(selector) {
      collect(selector, null);
    });
    collect(broadSelector, broadPredicate);
    elements.sort(documentOrder);
    return Object.freeze({
      ok: !overflow,
      elements: Object.freeze(elements),
      count: elements.length + Number(overflow),
    });
  }

  function decideBoundedCandidates(collection, evaluate, policy) {
    if (!collection.ok) {
      return Object.freeze({
        ok: false,
        reason: "candidate-bound",
        candidateOverflow: true,
        candidateCount: collection.count,
        ranked: Object.freeze([]),
      });
    }
    const decision = decideCandidate(collection.elements.map(evaluate), policy);
    return Object.freeze({
      ...decision,
      candidateOverflow: false,
      candidateCount: collection.count,
    });
  }

  function uniqueElements(elements) {
    const seen = new Set();
    return elements.filter(function unseen(element) {
      if (!element || element.nodeType !== 1 || seen.has(element)) {
        return false;
      }
      seen.add(element);
      return true;
    });
  }

  function isRendered(element) {
    if (!element || !element.isConnected) return false;
    const view = element.ownerDocument.defaultView;
    const documentElement = element.ownerDocument.documentElement;
    const measurementActive = documentElement?.getAttribute(ATTR.measure) === "1";
    for (let current = element; current; current = current.parentElement) {
      if (current.hidden || current.getAttribute("aria-hidden") === "true") return false;
      const style = view ? nativeComputedStyle(view, current) : null;
      if (!style) return false;
      const measurementOpacity = current === documentElement &&
        current.getAttribute(ATTR.measure) === "1";
      if (
        style.display === "none" ||
        (current === element && /^(?:hidden|collapse)$/.test(style.visibility)) ||
        (!measurementOpacity && Number(style.opacity || 1) === 0) ||
        (style.contentVisibility === "hidden" &&
          !(measurementActive && current === documentElement))
      ) {
        return false;
      }
    }
    if (typeof element.getClientRects !== "function") return false;
    const hasPositiveRect = Array.from(element.getClientRects()).some(function positiveRect(rect) {
      return rect.width > 0 && rect.height > 0;
    });
    if (!hasPositiveRect) {
      return false;
    }
    return true;
  }

  function isStableZeroAreaCommentMount(element) {
    if (!element || !element.isConnected || typeof element.getClientRects !== "function") {
      return false;
    }
    const view = element.ownerDocument.defaultView;
    const documentElement = element.ownerDocument.documentElement;
    const measurementActive = documentElement?.getAttribute(ATTR.measure) === "1";
    const gateOwnedShell = element.classList.contains(CLASS.keep) &&
      element.hasAttribute(ATTR.keep) &&
      element.classList.contains(CLASS.shell) &&
      element.hasAttribute(ATTR.shell) &&
      element.classList.contains(roleClass("comments")) &&
      element.getAttribute(ATTR.role) === "comments";
    for (let current = element; current; current = current.parentElement) {
      if (current.hidden || current.getAttribute("aria-hidden") === "true") return false;
      const style = view ? nativeComputedStyle(view, current) : null;
      const measurementOpacity = current === documentElement &&
        current.getAttribute(ATTR.measure) === "1";
      if (
        !style ||
        style.display === "none" ||
        (current === element && (!gateOwnedShell || measurementActive) &&
          /^(?:hidden|collapse)$/u.test(style.visibility)) ||
        (!measurementOpacity && Number(style.opacity || 1) === 0) ||
        (style.contentVisibility === "hidden" &&
          !(measurementActive && current === documentElement))
      ) {
        return false;
      }
    }
    return Array.from(element.getClientRects()).some(function stableEmptyRect(rect) {
      return rect.width > 0 && rect.height === 0;
    });
  }

  function withPublisherVisibilityMeasurement(document, inspect, measurementConflict) {
    const html = document.documentElement;
    const gateActive = html && (
      html.getAttribute(ATTR.lock) === "1" ||
      html.getAttribute(ATTR.ready) === "1"
    );
    if (!gateActive) {
      return inspect();
    }
    if (html.hasAttribute(ATTR.measure)) {
      return measurementConflict();
    }
    const gateStyles = document.querySelectorAll(
      `style[data-hotdeal-focus-runtime-style="${PROTOCOL_VERSION}"]`
    );
    const bootstrapOnlyLock = gateStyles.length === 0 &&
      html.getAttribute(ATTR.lock) === "1" &&
      BOOTSTRAP_PUBLISHER_INLINE.has(html);
    if (
      (!bootstrapOnlyLock && gateStyles.length !== 1) ||
      (gateStyles.length === 1 && (
        !gateStyles[0].sheet ||
        gateStyles[0].sheet.disabled
      ))
    ) {
      return measurementConflict();
    }
    const gateSheet = gateStyles[0]?.sheet || null;
    const previousTransition = html.style.getPropertyValue("transition");
    const previousTransitionPriority = html.style.getPropertyPriority("transition");
    const previousAnimation = html.style.getPropertyValue("animation");
    const previousAnimationPriority = html.style.getPropertyPriority("animation");
    const previousOpacity = html.style.getPropertyValue("opacity");
    const previousOpacityPriority = html.style.getPropertyPriority("opacity");
    const previousVisibility = html.style.getPropertyValue("visibility");
    const previousVisibilityPriority = html.style.getPropertyPriority("visibility");
    const publisherVisibility = BOOTSTRAP_PUBLISHER_INLINE.get(html)?.visibility ||
      Object.freeze({
        property: "visibility",
        value: previousVisibility,
        priority: previousVisibilityPriority,
      });
    const previousContentVisibility = html.style.getPropertyValue("content-visibility");
    const previousContentVisibilityPriority = html.style.getPropertyPriority("content-visibility");
    const previousClipPath = html.style.getPropertyValue("clip-path");
    const previousClipPathPriority = html.style.getPropertyPriority("clip-path");
    const measurementRestore = Object.freeze({
      properties: Object.freeze([
        inlinePropertySnapshot(html, "transition"),
        inlinePropertySnapshot(html, "animation"),
        inlinePropertySnapshot(html, "opacity"),
        inlinePropertySnapshot(html, "visibility"),
        inlinePropertySnapshot(html, "content-visibility"),
        inlinePropertySnapshot(html, "clip-path"),
      ]),
    });
    const previouslyDisabled = gateSheet?.disabled || false;
    html.style.setProperty("transition", "none", "important");
    html.style.setProperty("animation", "none", "important");
    html.style.setProperty("opacity", "0", "important");
    html.style.setProperty("visibility", "hidden", "important");
    html.style.setProperty("content-visibility", "hidden", "important");
    html.style.setProperty("clip-path", "inset(50%)", "important");
    html.setAttribute(ATTR.measure, "1");
    try {
      if (gateSheet) {
        measurementStyleSheetMutationDepth += 1;
        try {
          gateSheet.disabled = true;
        } finally {
          measurementStyleSheetMutationDepth -= 1;
        }
      }
      const view = document.defaultView;
      const rootStyle = view ? nativeComputedStyle(view, html) : null;
      if (
        !rootStyle ||
        rootStyle.display === "none" ||
        rootStyle.transitionDuration !== "0s" ||
        rootStyle.animationName !== "none" ||
        rootStyle.visibility !== "hidden" ||
        rootStyle.contentVisibility !== "hidden" ||
        rootStyle.clipPath !== "inset(50%)" ||
        Number(rootStyle.opacity || 1) !== 0
      ) {
        return measurementConflict();
      }
      applyInlinePropertySnapshot(html, publisherVisibility);
      let publisherRootStyle = view ? nativeComputedStyle(view, html) : null;
      const bootstrapEngineLockActive = BOOTSTRAP_PUBLISHER_INLINE.has(html) &&
        html.classList.contains(CLASS.lock) &&
        html.getAttribute(ATTR.lock) === "1";
      const publisherInlineVisibilityHidden = /^(?:hidden|collapse)$/u.test(
        String(publisherVisibility.value || "").trim().toLocaleLowerCase(),
      );
      if (
        publisherRootStyle?.visibility !== "visible" &&
        bootstrapEngineLockActive &&
        !publisherInlineVisibilityHidden
      ) {
        html.style.setProperty("visibility", "visible", "important");
        publisherRootStyle = view ? nativeComputedStyle(view, html) : null;
      }
      if (!publisherRootStyle || publisherRootStyle.visibility !== "visible") {
        return measurementConflict();
      }
      return inspect();
    } finally {
      html.style.setProperty("visibility", "hidden", "important");
      if (gateSheet) {
        measurementStyleSheetMutationDepth += 1;
        try {
          gateSheet.disabled = previouslyDisabled;
        } finally {
          measurementStyleSheetMutationDepth -= 1;
        }
      }
      html.removeAttribute(ATTR.measure);
      if (previousOpacity) {
        html.style.setProperty("opacity", previousOpacity, previousOpacityPriority);
      } else {
        html.style.removeProperty("opacity");
      }
      if (previousVisibility) {
        html.style.setProperty("visibility", previousVisibility, previousVisibilityPriority);
      } else {
        html.style.removeProperty("visibility");
      }
      if (previousContentVisibility) {
        html.style.setProperty(
          "content-visibility",
          previousContentVisibility,
          previousContentVisibilityPriority,
        );
      } else {
        html.style.removeProperty("content-visibility");
      }
      if (previousClipPath) {
        html.style.setProperty("clip-path", previousClipPath, previousClipPathPriority);
      } else {
        html.style.removeProperty("clip-path");
      }
      if (previousAnimation) {
        html.style.setProperty("animation", previousAnimation, previousAnimationPriority);
      } else {
        html.style.removeProperty("animation");
      }
      if (previousTransition) {
        html.style.setProperty("transition", previousTransition, previousTransitionPriority);
      } else {
        html.style.removeProperty("transition");
      }
      MEASUREMENT_HTML_RESTORES.set(html, measurementRestore);
    }
  }

  function normalizeProjectionTokenText(value) {
    return normalizeText(
      String(value || "")
        .replace(/([a-z\d])([A-Z])/g, "$1 $2")
        .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
        .replace(/[^\p{L}\p{N}]+/gu, " ")
    );
  }

  function semanticTokenText(element) {
    return normalizeProjectionTokenText(
      [
        element.id,
        element.className && typeof element.className === "string" ? element.className : "",
        element.getAttribute("role"),
        element.getAttribute("itemprop"),
        element.getAttribute("itemtype"),
        element.getAttribute("aria-label"),
      ].join(" ")
    );
  }

  function projectionNoiseMetadataText(element) {
    const metadataValues = Array.from(element.attributes || [])
      .filter(function projectionMetadata(attribute) {
        const name = attribute.name.toLocaleLowerCase();
        return name.startsWith("aria-") || name.startsWith("data-") ||
          name === "title" || name === "name";
      })
      .flatMap(function metadataValue(attribute) {
        return [attribute.name, attribute.value];
      });
    return normalizeProjectionTokenText([
      element.id,
      element.className && typeof element.className === "string" ? element.className : "",
      element.getAttribute("role"),
      element.getAttribute("itemprop"),
    ].concat(metadataValues).join(" "));
  }

  function projectionResourceText(element) {
    return ["href", "src", "srcset", "data-src", "data-srcset", "poster"]
      .map(function resourceValue(attribute) {
        return element.getAttribute(attribute) || "";
      })
      .join(" ");
  }

  function isStrongProjectionNoiseNode(element) {
    if ((element.attributes?.length || 0) > MAX_PROJECTION_METADATA_ATTRIBUTES) return true;
    const metadata = projectionNoiseMetadataText(element);
    if (STRONG_NOISE_TOKEN_PATTERN.test(metadata)) return true;
    const relation = (element.getAttribute("rel") || "").split(/\s+/);
    if (relation.some(function sponsored(token) {
      return token.toLocaleLowerCase() === "sponsored";
    })) {
      return true;
    }
    const resources = projectionResourceText(element);
    if (
      AD_NETWORK_RESOURCE_PATTERN.test(resources) ||
      (
        element.matches(LEAF_MEDIA_ELEMENTS) &&
        STRONG_NOISE_TOKEN_PATTERN.test(normalizeProjectionTokenText(resources))
      )
    ) return true;
    if (RELATED_NOISE_TOKEN_PATTERN.test(metadata)) {
      const interactiveSelector =
        "a[href], button, [role='link'], [role='button'], [role='menuitem']";
      return element.matches(interactiveSelector) ||
        Boolean(element.querySelector(interactiveSelector));
    }
    return false;
  }

  function collectJsonLd(document) {
    const result = {
      headlines: [],
      articleHeadlines: [],
      commentCount: null,
      hasCommentSchema: false,
    };
    function visit(value) {
      if (!value || typeof value !== "object") {
        return;
      }
      if (Array.isArray(value)) {
        value.forEach(visit);
        return;
      }
      const typeValues = Array.isArray(value["@type"]) ? value["@type"] : [value["@type"]];
      if (typeValues.some(function isComment(type) { return /comment/i.test(String(type || "")); })) {
        result.hasCommentSchema = true;
      }
      if (typeof value.headline === "string") {
        const headline = truncateRawTitle(value.headline, 300);
        if (headline) {
          result.headlines.push(headline);
          if (typeValues.some(function isArticle(type) {
            return /^(?:article|newsarticle|blogposting|discussionforumposting)$/iu.test(
              String(type || "").split(/[\/#]/u).pop() || "",
            );
          })) {
            result.articleHeadlines.push(headline);
          }
        }
      }
      const count = normalizeCommentCount(value.commentCount);
      if (count !== null) {
        result.commentCount = count;
      }
      Object.keys(value).forEach(function visitChild(key) {
        if (key !== "headline" && key !== "commentCount") {
          visit(value[key]);
        }
      });
    }
    document.querySelectorAll('script[type="application/ld+json"]').forEach(function parseScript(script) {
      const source = script.textContent || "";
      if (!source || utf8ByteLength(source) > MAX_JSON_LD_BYTES) {
        return;
      }
      try {
        visit(JSON.parse(source));
      } catch (_error) {
        // Malformed publisher metadata is not evidence.
      }
    });
    result.headlines = Array.from(new Set(result.headlines));
    result.articleHeadlines = Array.from(new Set(result.articleHeadlines));
    return result;
  }

  function collectArticleTitleMetadata(document, jsonLdValue) {
    const jsonLd = jsonLdValue || collectJsonLd(document);
    const sources = [];
    function addElements(kind, selector, attribute) {
      const values = [];
      document.querySelectorAll(selector).forEach(function collectValue(element) {
        const value = truncateRawTitle(
          attribute ? element.getAttribute(attribute) : element.textContent,
          300,
        );
        if (value) values.push(value);
      });
      sources.push({ kind, values });
    }
    addElements("og", 'meta[property="og:title"]', "content");
    addElements(
      "twitter",
      'meta[name="twitter:title"], meta[property="twitter:title"]',
      "content",
    );
    sources.push({ kind: "schema-article", values: jsonLd.articleHeadlines || [] });
    const normalizedSources = [];
    let conflictingKind = null;
    sources.forEach(function normalizeSource(source) {
      const valuesByCore = new Map();
      source.values.forEach(function addUniqueValue(value) {
        const core = normalizeText(stripBoundedTitleAffixes(value));
        if (core && !valuesByCore.has(core)) {
          valuesByCore.set(core, value);
        }
      });
      if (valuesByCore.size > 1) {
        conflictingKind = conflictingKind || source.kind;
      }
      valuesByCore.forEach(function addSourceValue(value, core) {
        normalizedSources.push({ kind: source.kind, core, value });
      });
    });
    return Object.freeze({
      ok: normalizedSources.length > 0 && conflictingKind === null,
      reason: conflictingKind
        ? `conflicting-${conflictingKind}`
        : normalizedSources.length ? "consistent-cardinality" : "missing",
      sources: Object.freeze(normalizedSources.map(function freezeSource(source) {
        return Object.freeze(source);
      })),
    });
  }

  function stripBoundedTrailingCommerceValue(value) {
    const source = String(value || "").normalize("NFKC").trim();
    const stripped = source.replace(
      /\s*(?:\(\s*)?\d[\d,.]*(?:\s*(?:원|krw|usd|jpy|cny|엔|달러))?(?:\s*[\/+]\s*\d[\d,.]*(?:\s*(?:원|krw|usd|jpy|cny|엔|달러))?)*(?:\s*\))?\s*$/iu,
      "",
    ).trim();
    return Object.freeze({
      text: stripped,
      removed: Boolean(stripped && stripped !== source),
    });
  }

  function boundedMetadataCommerceFormattingMatch(visibleTitle, metadataTitle) {
    const visibleCore = stripBoundedTrailingCommerceValue(visibleTitle);
    const metadataCore = stripBoundedTrailingCommerceValue(metadataTitle);
    if (!visibleCore.removed || !metadataCore.removed) return false;
    const forward = titleConsistency(visibleCore.text, metadataCore.text);
    const reverse = titleConsistency(metadataCore.text, visibleCore.text);
    return forward.ok || reverse.ok;
  }

  function titleEvidence(document, algumonTitle, visibleTitle, jsonLdValue) {
    const hasAlgumonTitle = Boolean(truncateRawTitle(algumonTitle, 300));
    const algumonCore = hasAlgumonTitle
      ? titleConsistency(algumonTitle, visibleTitle)
      : Object.freeze({ ok: true, score: 1, mode: "not-required" });
    const algumonSingle = hasAlgumonTitle
      ? singleLongTitleTokenEquivalence(algumonTitle, visibleTitle)
      : algumonCore;
    const algumon = algumonCore.ok ? algumonCore : algumonSingle.ok ? algumonSingle : algumonCore;
    const metadata = collectArticleTitleMetadata(document, jsonLdValue);
    const metadataComparisons = metadata.sources.map(function compareMetadata(source) {
      const visibleToMetadata = titleCoreEquivalence(visibleTitle, source.value);
      const metadataToVisible = titleCoreEquivalence(source.value, visibleTitle);
      const visibleSingle = singleLongTitleTokenEquivalence(visibleTitle, source.value);
      const metadataSingle = singleLongTitleTokenEquivalence(source.value, visibleTitle);
      const punctuationInvariant = punctuationInvariantTitleMatch(
        visibleTitle,
        source.value,
      );
      const coreOk = (visibleToMetadata.ok && metadataToVisible.ok) ||
        punctuationInvariant;
      const singleOk = visibleSingle.ok && metadataSingle.ok;
      const matchedCoreRatio = visibleToMetadata.referenceDistinctiveTokenCount
        ? visibleToMetadata.matchedDistinctiveTokenCount /
          visibleToMetadata.referenceDistinctiveTokenCount
        : 0;
      const conflictsWithVisibleArticle =
        !punctuationInvariant && (
          visibleToMetadata.protectedTokenAgreement !== true ||
          matchedCoreRatio < 0.5
        );
      return Object.freeze({
        kind: source.kind,
        ok: coreOk || singleOk,
        conflictsWithVisibleArticle,
        punctuationInvariant,
        boundedCommerceFormatting: boundedMetadataCommerceFormattingMatch(
          visibleTitle,
          source.value,
        ),
        score: coreOk || singleOk
          ? 1
          : Number(Math.min(visibleToMetadata.score, metadataToVisible.score).toFixed(3)),
        mode: punctuationInvariant
          ? "punctuation-invariant-consensus"
          : singleOk
            ? "single-long-token-consensus"
            : `${visibleToMetadata.mode}/${metadataToVisible.mode}`,
      });
    });
    const exactSchemaArticleMatch = metadataComparisons.some(
      function exactSchemaComparison(comparison) {
        return comparison.kind === "schema-article" && comparison.ok;
      },
    );
    const effectiveMetadataConflict = function effectiveMetadataConflict(comparison) {
      return comparison.conflictsWithVisibleArticle && !(
        exactSchemaArticleMatch &&
        (comparison.kind === "og" || comparison.kind === "twitter") &&
        comparison.boundedCommerceFormatting
      );
    };
    const authoritativeMatches = metadataComparisons.filter(
      function authoritativeComparison(comparison) {
        return (
          comparison.kind === "og" || comparison.kind === "schema-article"
        ) && comparison.ok;
      },
    );
    const metadataOk = metadata.ok &&
      authoritativeMatches.length > 0 &&
      !metadataComparisons.some(effectiveMetadataConflict);
    const ok = (!hasAlgumonTitle || algumon.ok) && metadataOk;
    return Object.freeze({
      ok,
      score: ok
        ? 1
        : Number(Math.min(
            algumon.score,
            metadataComparisons.length
              ? Math.min(...metadataComparisons.map(function comparisonScore(item) {
                  return item.score;
                }))
              : 0,
          ).toFixed(3)),
      mode: ok
        ? hasAlgumonTitle
          ? `algumon-${algumon.mode}+metadata-consensus`
          : "algumon-referrer+metadata-consensus"
        : hasAlgumonTitle && !algumon.ok
          ? `algumon-${algumon.mode}`
          : `metadata-${
              metadataComparisons.some(effectiveMetadataConflict)
                ? "article-conflict"
                : metadata.reason
            }`,
      algumon,
      metadata: Object.freeze({
        ok: metadataOk,
        reason: metadataOk
          ? "authoritative-quorum"
          : metadataComparisons.some(effectiveMetadataConflict)
            ? "article-conflict"
            : metadata.reason,
        authoritativeMatchCount: authoritativeMatches.length,
        sourceCount: metadataComparisons.length,
        sourceKinds: Object.freeze(metadataComparisons.map(function sourceKind(item) {
          return item.kind;
        }).sort()),
        comparisons: Object.freeze(metadataComparisons),
      }),
    });
  }

  function collectTitleSources(document, seed, jsonLd) {
    const sources = [];
    function add(kind, value, trusted) {
      const text = truncateText(value, 300);
      if (text) {
        sources.push({ kind, text, trusted });
      }
    }
    document.querySelectorAll('meta[property="og:title"]').forEach(function addOgTitle(element) {
      add("metadata-og", element.getAttribute("content"), true);
    });
    document.querySelectorAll(
      'meta[name="twitter:title"], meta[property="twitter:title"]',
    ).forEach(function addTwitterTitle(element) {
      add("metadata-twitter", element.getAttribute("content"), true);
    });
    jsonLd.articleHeadlines.forEach(function addHeadline(headline) {
      add("metadata-jsonld", headline, true);
    });
    if (seed) {
      add("seed-title-match", seed.title, false);
    }
    return sources;
  }

  function approvedVisibleTitle(document, seedTitle, titleNode, jsonLd) {
    const directText = truncateRawTitle(
      Array.from(titleNode.childNodes)
        .filter(function directTitleText(node) { return node.nodeType === 3; })
        .map(function directTitleValue(node) { return node.data; })
        .join(" "),
      320
    );
    const wholeText = truncateRawTitle(titleNode.textContent, 320);
    const leafTexts = Array.from(
      titleNode.querySelectorAll("span, strong, b, em, a, div")
    )
      .filter(function terminalTitleLeaf(element) {
        return !element.querySelector("span, strong, b, em, a, div");
      })
      .map(function terminalTitleText(element) {
        return truncateRawTitle(element.textContent, 320);
      });
    const candidates = [directText, wholeText].concat(leafTexts)
      .filter(function plausibleTitleText(value) { return value.length >= 4; })
      .filter(function uniqueTitleText(value, index, values) {
        return values.indexOf(value) === index;
      });
    const approved = candidates.map(function compareVisibleTitle(text) {
      return { text, evidence: titleEvidence(document, seedTitle, text, jsonLd) };
    }).filter(function approvedTitle(candidate) {
      return candidate.evidence.ok === true;
    });
    if (!approved.length) {
      return Object.freeze({ ok: false, text: wholeText, evidence: titleEvidence(
        document,
        seedTitle,
        wholeText,
        jsonLd,
      ) });
    }
    const selected = approved[0];
    return Object.freeze({ ok: true, text: selected.text, evidence: selected.evidence });
  }

  function collectSeedBackedShallowTitleElements(document, roots, seed, jsonLd) {
    if (!seed) {
      return Object.freeze({ ok: true, elements: Object.freeze([]) });
    }
    const inspected = new Set();
    const approved = [];
    let overflow = false;
    for (const root of roots) {
      if (overflow) break;
      if (
        isRendered(root) &&
        approvedVisibleTitle(document, seed.title, root, jsonLd).ok === true
      ) {
        approved.push(root);
      }
      const stack = Array.from(root.children).map(function shallowChild(node) {
        return { node, depth: 1 };
      });
      while (stack.length) {
        const current = stack.shift();
        if (inspected.has(current.node)) continue;
        inspected.add(current.node);
        if (inspected.size > MAX_PROJECTION_CANDIDATE_EVALUATIONS) {
          overflow = true;
          break;
        }
        const tagName = current.node.tagName.toLocaleLowerCase();
        if (
          /^(?:span|strong|b|em|a|div|p|small)$/u.test(tagName) &&
          isRendered(current.node)
        ) {
          const text = truncateRawTitle(current.node.textContent, 320);
          if (
            text.length >= 4 &&
            text.length <= 300 &&
            titleEvidence(document, seed.title, text, jsonLd).ok === true
          ) {
            approved.push(current.node);
          }
        }
        if (current.depth >= 3) continue;
        Array.from(current.node.children).forEach(function enqueueGrandchild(child) {
          stack.push({ node: child, depth: current.depth + 1 });
        });
      }
    }
    return Object.freeze({
      ok: !overflow,
      elements: Object.freeze(uniqueElements(approved)),
    });
  }

  function roleHints(layouts, role) {
    const hints = [];
    layouts.forEach(function collectLayoutHints(layout) {
      const roleSelectors = (layout.hints && layout.hints[role]) || [];
      roleSelectors.forEach(function collectHint(selector) {
        if (!hints.includes(selector)) {
          hints.push(selector);
        }
      });
    });
    return hints;
  }

  function elementMatchesAny(element, selectors) {
    return selectors.some(function matchesSelector(selector) {
      try {
        return element.matches(selector);
      } catch (_error) {
        return false;
      }
    });
  }

  function isStructuralNoiseNode(element) {
    if (isStrongProjectionNoiseNode(element)) {
      if (
        RELATED_NOISE_TOKEN_PATTERN.test(projectionNoiseMetadataText(element)) &&
        containsSubstantialArticleContent(element) &&
        !isAutonomousProjectionNoiseRoot(element)
      ) {
        return false;
      }
      return true;
    }
    if (element.matches(LEAF_MEDIA_ELEMENTS)) {
      const tagName = element.tagName.toLocaleLowerCase();
      const resourceTokens = ["src", "srcset", "data-src", "data-srcset", "poster", "href"]
        .map(function mediaResource(attribute) { return element.getAttribute(attribute) || ""; })
        .join(" ")
        .replace(/[^a-z0-9가-힣ぁ-んァ-ン一-龥_-]+/gi, " ");
      const mediaTokens = `${semanticTokenText(element)} ${resourceTokens}`;
      if (MEDIA_NOISE_TOKEN_PATTERN.test(mediaTokens)) return true;
      if (tagName !== "img" && NOISE_TOKEN_PATTERN.test(mediaTokens)) return true;
      return false;
    }
    if (element.matches(STRUCTURAL_NOISE_ELEMENTS)) {
      return !containsSubstantialArticleContent(element);
    }
    if (!element.matches(STRUCTURAL_CONTAINER_ELEMENTS)) {
      return false;
    }
    const tokenText = semanticTokenText(element);
    if (!NOISE_TOKEN_PATTERN.test(tokenText)) {
      return false;
    }
    if (STRUCTURAL_NOISE_TOKEN_PATTERN.test(tokenText)) {
      return true;
    }
    const navigationLinks = element.querySelectorAll(
      "a[href], button, [role='link'], [role='menuitem']"
    ).length;
    return navigationLinks >= 2 || element.matches("ul, ol, menu, form, [role='menu'], [role='list']");
  }

  function canonicalAutonomousNoiseLabel(value) {
    return normalizeText(value)
      .replace(/^[\s#·•|:：\-–—]+|[\s#·•|:：\-–—]+$/gu, "")
      .replace(/\s*[\[(（]\s*\d{1,4}\s*[\])）]\s*$/u, "")
      .trim();
  }

  function directAutonomousNoiseLabel(element) {
    const samples = [
      element.getAttribute("aria-label"),
      element.getAttribute("title"),
      element.getAttribute("data-title"),
      Array.from(element.childNodes)
        .filter(function directLabelText(node) { return node.nodeType === 3; })
        .map(function directLabelValue(node) { return node.data; })
        .join(" "),
    ];
    Array.from(element.children).slice(0, 8).forEach(function directHeading(child) {
      if (child.matches("h1, h2, h3, h4, h5, h6, legend, [role='heading']")) {
        samples.push(child.textContent);
        return;
      }
      if (child.matches("header")) {
        const heading = child.querySelector("h1, h2, h3, h4, h5, h6, [role='heading']");
        if (heading) samples.push(heading.textContent);
      }
    });
    return samples.some(function exactNoiseLabel(sample) {
      const label = canonicalAutonomousNoiseLabel(sample || "");
      return label.length > 0 &&
        label.length <= 80 &&
        AUTONOMOUS_NOISE_LABEL_PATTERN.test(label);
    });
  }

  function autonomousNoiseResourceLinkCount(element) {
    const links = (element.matches("a[href]") ? [element] : [])
      .concat(Array.from(element.querySelectorAll("a[href]")).slice(0, 256));
    return links.filter(function recognizedNoiseEndpoint(link) {
      const href = link.getAttribute("href") || "";
      try {
        const url = new URL(href, element.ownerDocument.location.href);
        return AUTONOMOUS_NOISE_RESOURCE_PATTERN.test(
          `${url.pathname}${url.search}${url.hash}`,
        );
      } catch (_error) {
        return AUTONOMOUS_NOISE_RESOURCE_PATTERN.test(href);
      }
    }).length;
  }

  function containsSubstantialArticleContent(element) {
    const prose = Array.from(
      element.querySelectorAll("p, blockquote, pre, code"),
    ).slice(0, 64).reduce(function proseLength(total, node) {
      return total + normalizeText(node.textContent).length;
    }, 0);
    return prose >= 48 ||
      Boolean(element.querySelector(
        "article, main, [itemprop='articleBody'], table, video, audio",
      ));
  }

  function isAutonomousProjectionNoiseRoot(element) {
    const metadata = projectionNoiseMetadataText(element);
    const resources = projectionResourceText(element);
    const relation = (element.getAttribute("rel") || "")
      .split(/\s+/)
      .map(function canonicalRelation(token) { return token.toLocaleLowerCase(); });
    if (
      AD_NETWORK_RESOURCE_PATTERN.test(resources) ||
      relation.includes("sponsored")
    ) {
      return true;
    }
    const strongMetadataSignal =
      STRONG_NOISE_TOKEN_PATTERN.test(metadata) ||
      RELATED_NOISE_TOKEN_PATTERN.test(metadata);
    if (
      strongMetadataSignal &&
      (
        !RELATED_NOISE_TOKEN_PATTERN.test(metadata) ||
        (!containsSubstantialArticleContent(element) && directAutonomousNoiseLabel(element))
      )
    ) {
      return true;
    }
    if (
      element.matches(STRUCTURAL_NOISE_ELEMENTS) &&
      !containsSubstantialArticleContent(element)
    ) {
      return true;
    }
    const structuralSurface = element.matches(
      `${STRUCTURAL_CONTAINER_ELEMENTS}, ${STRUCTURAL_NOISE_ELEMENTS}, ` +
      `${LEAF_MEDIA_ELEMENTS}, [role='list'], [role='menu']`,
    );
    if (!structuralSurface) return false;
    const directLabel = directAutonomousNoiseLabel(element);
    const metadataSignal =
      strongMetadataSignal ||
      AUTONOMOUS_NOISE_METADATA_PATTERN.test(metadata);
    const boundedNavigationCandidate =
      metadataSignal ||
      directLabel ||
      element.matches(
        `${STRUCTURAL_NOISE_ELEMENTS}, ul, ol, menu, [role='list'], [role='menu'], ` +
        `${LEAF_MEDIA_ELEMENTS}`,
      );
    if (!boundedNavigationCandidate) return false;
    const interactiveCount = (
      element.matches("a[href], button, [role='link'], [role='button'], [role='menuitem']")
        ? 1
        : 0
    ) + element.querySelectorAll(
      "a[href], button, [role='link'], [role='button'], [role='menuitem']",
    ).length;
    const rowCount = element.querySelectorAll(
      ":scope > li, :scope > tr, :scope > article, :scope > [role='listitem']",
    ).length;
    const resourceLinkCount = autonomousNoiseResourceLinkCount(element);
    const ancillarySignal = element.matches(STRUCTURAL_NOISE_ELEMENTS) &&
      interactiveCount > 0;
    const navigationShapeSignal =
      interactiveCount >= 2 ||
      rowCount >= 2 ||
      ((directLabel || metadataSignal || ancillarySignal || resourceLinkCount > 0) &&
        interactiveCount >= 1);
    const mediaNoiseSignal = element.matches(LEAF_MEDIA_ELEMENTS) &&
      (
        MEDIA_NOISE_TOKEN_PATTERN.test(metadata) ||
        MEDIA_NOISE_TOKEN_PATTERN.test(normalizeProjectionTokenText(resources))
      );
    const signalCount = Number(metadataSignal) +
      Number(directLabel) +
      Number(resourceLinkCount > 0) +
      Number(ancillarySignal) +
      Number(navigationShapeSignal) +
      Number(mediaNoiseSignal);
    if (signalCount < 2) return false;
    if (
      containsSubstantialArticleContent(element) &&
      !metadataSignal &&
      !resourceLinkCount
    ) {
      return false;
    }
    return true;
  }

  function containsSemanticNoise(element, noiseCache, excludedRoots) {
    const exclusions = excludedRoots || [];
    const effectiveCache = exclusions.length ? null : noiseCache;
    if (effectiveCache?.has(element)) return effectiveCache.get(element);
    const stack = [element];
    const inspectedElements = [];
    let inspected = 0;
    while (stack.length) {
      const current = stack.pop();
      if (current !== element && insideAnyRoot(current, exclusions)) continue;
      if (effectiveCache?.has(current)) {
        if (effectiveCache.get(current)) {
          effectiveCache.set(element, true);
          return true;
        }
        continue;
      }
      inspectedElements.push(current);
      inspected += 1;
      if (
        inspected > MAX_SEMANTIC_DESCENDANTS ||
        isStructuralNoiseNode(current)
      ) {
        if (effectiveCache) effectiveCache.set(element, true);
        return true;
      }
      if (inspected + stack.length + current.children.length > MAX_SEMANTIC_DESCENDANTS) {
        if (effectiveCache) effectiveCache.set(element, true);
        return true;
      }
      for (let index = current.children.length - 1; index >= 0; index -= 1) {
        stack.push(current.children[index]);
      }
    }
    if (effectiveCache) {
      inspectedElements.forEach(function cacheCleanSubtree(current) {
        effectiveCache.set(current, false);
      });
    }
    return false;
  }

  function containsMeaningfulIgnoredContent(element) {
    const text = normalizeText(element.textContent);
    if (
      element.matches("a[href], button, input, select, textarea, form, table, video, audio, iframe") ||
      element.querySelector("a[href], button, input, select, textarea, form, table, video, audio, iframe")
    ) {
      return true;
    }
    if (/\d[\d,.]*\s*(?:원|krw|usd|jpy|cny|엔|달러|%|개|팩|세트|kg|g|gb|tb|ml|l)(?=\s|$|[)\]】])/iu.test(text)) {
      return true;
    }
    if (text && (!NOISE_TOKEN_PATTERN.test(text) || text.length > 80)) {
      return true;
    }
    return [element].concat(Array.from(element.querySelectorAll("img, picture, source")))
      .some(function meaningfulIgnoredMedia(media) {
        const alt = normalizeText(media.getAttribute?.("alt") || "");
        return alt && !NOISE_TOKEN_PATTERN.test(alt);
      });
  }

  function discoverAutonomousIgnoredRoots(root, protectedRoots) {
    const protectedSet = protectedRoots || [];
    const candidates = Array.from(root.querySelectorAll("*"));
    if (candidates.length > MAX_SEMANTIC_DESCENDANTS) {
      return Object.freeze({ ok: false, roots: Object.freeze([]), count: candidates.length });
    }
    const roots = [];
    candidates.forEach(function safeStrongNoise(candidate) {
      if (
        roots.some(function insideSelected(selected) { return selected.contains(candidate); }) ||
        protectedSet.some(function overlapsProtected(protectedRoot) {
          return nodesOverlap(candidate, protectedRoot);
        }) ||
        !isAutonomousProjectionNoiseRoot(candidate)
      ) {
        return;
      }
      roots.push(candidate);
    });
    return Object.freeze({ ok: true, roots: Object.freeze(roots), count: roots.length });
  }

  function isInspectableLightDomCustomElement(element) {
    const tagName = element.tagName.toLocaleLowerCase();
    if (!tagName.includes("-")) return false;
    return Array.from(element.childNodes).some(function inspectableLightDom(node) {
      return node.nodeType === 1 || (node.nodeType === 3 && normalizeText(node.textContent));
    });
  }

  function containsUnprovenShadowBoundary(root, excludedRoots) {
    const view = root.ownerDocument.defaultView;
    const prototype = view?.Element?.prototype;
    const shadowTracker = view ? SHADOW_TRACKERS.get(view) : null;
    if (
      shadowTracker &&
      prototype &&
      typeof prototype.attachShadow === "function" &&
      prototype.attachShadow !== shadowTracker.wrapper
    ) {
      return true;
    }
    const stack = [root];
    let inspected = 0;
    while (stack.length) {
      const current = stack.pop();
      if (current !== root && insideAnyRoot(current, excludedRoots || [])) continue;
      inspected += 1;
      if (inspected > MAX_SEMANTIC_DESCENDANTS) return true;
      const tagName = current.tagName.toLocaleLowerCase();
      if (
        current.shadowRoot ||
        shadowTracker?.hosts.has(current) ||
        (tagName.includes("-") && !isInspectableLightDomCustomElement(current)) ||
        current.hasAttribute("is") ||
        current.matches("template[shadowrootmode], template[shadowroot]")
      ) {
        return true;
      }
      if (inspected + stack.length + current.children.length > MAX_SEMANTIC_DESCENDANTS) {
        return true;
      }
      for (let index = current.children.length - 1; index >= 0; index -= 1) {
        stack.push(current.children[index]);
      }
    }
    return false;
  }

  function meaningfulPseudoContent(content) {
    const value = String(content || "").trim();
    if (!value || value === "none" || value === "normal" || value === '""' || value === "''") {
      return false;
    }
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'")))
    ) {
      return normalizeText(value.slice(1, -1)).length > 0;
    }
    return true;
  }

  function publisherElementCanPaint(element, boundary) {
    const view = element.ownerDocument.defaultView;
    for (let current = element; current; current = current.parentElement) {
      if (current.hidden || current.getAttribute("aria-hidden") === "true") return false;
      const style = view ? nativeComputedStyle(view, current) : null;
      if (
        !style ||
        style.display === "none" ||
        Number(style.opacity || 1) === 0 ||
        style.contentVisibility === "hidden"
      ) {
        return false;
      }
      if (current === boundary) return true;
    }
    return false;
  }

  function activePopover(element) {
    try {
      return element.hasAttribute("popover") && element.matches(":popover-open");
    } catch (_error) {
      return false;
    }
  }

  function viewportOverlayRect(rect, view) {
    const viewportWidth = Number(view.innerWidth || view.document.documentElement.clientWidth || 0);
    const viewportHeight = Number(view.innerHeight || view.document.documentElement.clientHeight || 0);
    if (!viewportWidth || !viewportHeight || !rect) return true;
    const visibleWidth = Math.max(
      0,
      Math.min(rect.right, viewportWidth) - Math.max(rect.left, 0),
    );
    const visibleHeight = Math.max(
      0,
      Math.min(rect.bottom, viewportHeight) - Math.max(rect.top, 0),
    );
    if (!visibleWidth || !visibleHeight) return false;
    const widthRatio = visibleWidth / viewportWidth;
    const heightRatio = visibleHeight / viewportHeight;
    const areaRatio = (visibleWidth * visibleHeight) / (viewportWidth * viewportHeight);
    return areaRatio >= 0.08 ||
      (widthRatio >= 0.5 && visibleHeight >= 48) ||
      (heightRatio >= 0.5 && visibleWidth >= 48);
  }

  function positionedViewportOverlay(element, style, view) {
    if (!/^(?:fixed|sticky)$/.test(style.position)) return false;
    const hostRect = element.getBoundingClientRect();
    if (viewportOverlayRect(hostRect, view)) return true;
    const width = Number.parseFloat(style.width);
    const height = Number.parseFloat(style.height);
    const left = Number.parseFloat(style.left);
    const top = Number.parseFloat(style.top);
    if (!Number.isFinite(width) || !Number.isFinite(height)) return false;
    const projectedRect = {
      left: Number.isFinite(left) ? left : hostRect.left,
      top: Number.isFinite(top) ? top : hostRect.top,
      right: (Number.isFinite(left) ? left : hostRect.left) + width,
      bottom: (Number.isFinite(top) ? top : hostRect.top) + height,
    };
    return viewportOverlayRect(projectedRect, view);
  }

  function pseudoPaintIsStrongNoise(style) {
    const contentText = normalizeProjectionTokenText(style.content || "");
    const backgroundText = normalizeProjectionTokenText(style.backgroundImage || "");
    return STRONG_NOISE_TOKEN_PATTERN.test(contentText) ||
      PSEUDO_NOISE_TOKEN_PATTERN.test(contentText) ||
      BACKGROUND_RESOURCE_NOISE_TOKEN_PATTERN.test(backgroundText) ||
      AD_NETWORK_RESOURCE_PATTERN.test(style.backgroundImage || "");
  }

  function containsPublisherPaintRisk(root, excludedRoots) {
    const document = root.ownerDocument;
    const view = document.defaultView;
    const fullscreenElement = document.fullscreenElement;
    if (fullscreenElement && (root === fullscreenElement || root.contains(fullscreenElement))) {
      return true;
    }
    const stack = [root];
    let inspected = 0;
    while (stack.length) {
      const current = stack.pop();
      if (current !== root && insideAnyRoot(current, excludedRoots || [])) continue;
      inspected += 1;
      if (inspected > MAX_SEMANTIC_DESCENDANTS) return true;
      if (isStrongProjectionNoiseNode(current)) return true;
      const style = view ? nativeComputedStyle(view, current) : null;
      if (!style) return true;
      const canPaint = publisherElementCanPaint(current, root);
      if (canPaint) {
        if (
          pseudoPaintIsStrongNoise(style) ||
          positionedViewportOverlay(current, style, view) ||
          (current.matches("dialog[open]") || activePopover(current))
        ) {
          return true;
        }
        for (const pseudo of ["::before", "::after"]) {
          const pseudoStyle = nativeComputedStyle(view, current, pseudo);
          if (!pseudoStyle) return true;
          if (
            pseudoStyle.display !== "none" &&
            Number(pseudoStyle.opacity || 1) !== 0 &&
            pseudoStyle.contentVisibility !== "hidden" &&
            (
              pseudoPaintIsStrongNoise(pseudoStyle) ||
              (
                (pseudoStyle.backgroundImage !== "none" ||
                  meaningfulPseudoContent(pseudoStyle.content)) &&
                positionedViewportOverlay(current, pseudoStyle, view)
              )
            )
          ) {
            return true;
          }
        }
      }
      if (inspected + stack.length + current.children.length > MAX_SEMANTIC_DESCENDANTS) {
        return true;
      }
      for (let index = current.children.length - 1; index >= 0; index -= 1) {
        stack.push(current.children[index]);
      }
    }
    return false;
  }

  function commentProjectionShells(
    commentMount,
    commentItems,
    commentControls,
    commentControlScope,
  ) {
    const shells = new Set([commentMount]);
    commentItems.forEach(function collectItemShellChain(surface) {
      for (
        let current = surface.parentElement;
        current && commentMount.contains(current);
        current = current.parentElement
      ) {
        shells.add(current);
        if (current === commentMount) break;
      }
    });
    commentControls.forEach(function collectControlShellChain(surface) {
      const boundary = commentMount.contains(surface) ? commentMount : commentControlScope;
      for (
        // Dormant native comment menus cannot paint. Inspect their ancestor
        // shells here; visible controls are still fully paint-checked below.
        let current = isRendered(surface) ? surface : surface.parentElement;
        current && boundary && boundary.contains(current);
        current = current.parentElement
      ) {
        shells.add(current);
        if (current === boundary) break;
      }
    });
    return Array.from(shells);
  }

  function commentShellHasLayoutRisk(shell) {
    if (containsUnprovenShadowBoundary(shell, Array.from(shell.children))) return true;
    const document = shell.ownerDocument;
    const view = document.defaultView;
    const style = view ? nativeComputedStyle(view, shell) : null;
    if (!style) return true;
    const fullscreenElement = document.fullscreenElement;
    return Boolean(
      (fullscreenElement && (shell === fullscreenElement || shell.contains(fullscreenElement))) ||
      shell.matches("dialog[open]") ||
      activePopover(shell) ||
      positionedViewportOverlay(shell, style, view)
    );
  }

  function commentProjectionHasRisk(
    commentMount,
    commentItems,
    commentControls,
    commentIgnored,
    allowStableZeroAreaMount,
    commentControlScope,
  ) {
    const visibleItems = commentItems.filter(isRendered);
    const visibleControls = commentControls.filter(isRendered);
    if (
      !isRendered(commentMount) &&
      visibleItems.length === 0 &&
      visibleControls.length === 0 &&
      !(allowStableZeroAreaMount && isStableZeroAreaCommentMount(commentMount))
    ) return true;
    if (commentItems.some(function unsafeCommentItem(item) {
      return !isRendered(item) ||
        containsUnprovenShadowBoundary(item, []) ||
        containsPublisherPaintRisk(item, []);
    })) {
      return true;
    }
    if (visibleControls.some(function unsafeVisibleControl(control) {
      return containsUnprovenShadowBoundary(control, []) ||
        containsPublisherPaintRisk(control, []);
    })) {
      return true;
    }
    const shellSurfaces = commentProjectionShells(
      commentMount,
      commentItems,
      commentControls,
      commentControlScope || commentMount,
    ).filter(function shellOutsideIgnored(shell) {
      return !insideAnyRoot(shell, commentIgnored || []);
    });
    return shellSurfaces.some(commentShellHasLayoutRisk);
  }

  function evaluateTitleCandidate(
    element,
    sources,
    hintSelectors,
    document,
    seed,
    jsonLd,
    seedBackedShallow,
  ) {
    const evaluation = { node: element, score: 0, signals: new Set(), disqualified: false };
    const visibleTitle = seed
      ? approvedVisibleTitle(document, seed.title, element, jsonLd)
      : null;
    const text = truncateText(
      visibleTitle?.ok ? visibleTitle.text : element.textContent,
      320,
    );
    if (
      !isRendered(element) ||
      text.length < 4 ||
      text.length > 300
    ) {
      evaluation.disqualified = true;
      return evaluation;
    }
    evaluation.resolvedTitle = visibleTitle?.ok ? visibleTitle.text : element.textContent;
    if (
      shallowTitleSurfaceHasRisk(
        element,
        evaluation.resolvedTitle,
        containsUnprovenShadowBoundary,
      ) ||
      shallowTitleSurfaceHasRisk(
        element,
        evaluation.resolvedTitle,
        containsPublisherPaintRisk,
      )
    ) {
      evaluation.disqualified = true;
      return evaluation;
    }
    evaluation.titleEvidence = seed ? visibleTitle.evidence : null;
    if (seed && !evaluation.titleEvidence.ok) {
      evaluation.disqualified = true;
      return evaluation;
    }
    const tagName = element.tagName.toLocaleLowerCase();
    const role = element.getAttribute("role");
    if (/^h[1-3]$/.test(tagName) || role === "heading" || element.hasAttribute("itemprop")) {
      addSignal(evaluation, "visible-heading", tagName === "h1" ? 2.5 : 2.0);
    }
    let bestMetadataSimilarity = 0;
    let bestSeedSimilarity = 0;
    sources.forEach(function compareSource(source) {
      const similarity = textSimilarity(text, source.text);
      if (source.trusted) {
        bestMetadataSimilarity = Math.max(bestMetadataSimilarity, similarity);
      } else {
        bestSeedSimilarity = Math.max(bestSeedSimilarity, similarity);
      }
    });
    if (bestMetadataSimilarity >= 0.54) {
      addSignal(evaluation, "metadata-title-match", 2.2 + bestMetadataSimilarity * 1.8);
    }
    if (bestSeedSimilarity >= 0.54) {
      addSignal(evaluation, "seed-title-match", 0.75 + bestSeedSimilarity * 0.5);
    }
    if (elementMatchesAny(element, hintSelectors)) {
      addSignal(evaluation, "selector-hint", 1.25);
    }
    if (seedBackedShallow) {
      addSignal(evaluation, "seed-metadata-shallow-title", 2.25);
    }
    if (COMMENT_TOKEN_PATTERN.test(semanticTokenText(element))) {
      evaluation.score -= 4;
    }
    return evaluation;
  }

  function titleCandidateEvaluations(document, layouts, seed, jsonLd) {
    const hints = roleHints(layouts, "title");
    const collection = collectBoundedCandidateElements(
      document,
      "h1, h2, h3, [role='heading'], [itemprop='headline'], [class*='title'], [class*='subject']",
      hints,
      null,
    );
    if (!collection.ok) {
      return Object.freeze({
        ok: false,
        count: collection.count,
        evaluations: Object.freeze([]),
      });
    }
    const shallow = collectSeedBackedShallowTitleElements(
      document,
      collection.elements,
      seed,
      jsonLd,
    );
    if (!shallow.ok) {
      return Object.freeze({
        ok: false,
        count: collection.count + shallow.elements.length + 1,
        evaluations: Object.freeze([]),
      });
    }
    const candidates = uniqueElements(collection.elements.concat(shallow.elements));
    if (candidates.length > MAX_PROJECTION_CANDIDATE_EVALUATIONS) {
      return Object.freeze({
        ok: false,
        count: candidates.length,
        evaluations: Object.freeze([]),
      });
    }
    candidates.sort(documentOrder);
    const shallowSet = new WeakSet(shallow.elements);
    const sources = collectTitleSources(document, seed, jsonLd);
    return Object.freeze({
      ok: true,
      count: candidates.length,
      evaluations: Object.freeze(candidates.map(function scoreCandidate(candidate) {
        return evaluateTitleCandidate(
          candidate,
          sources,
          hints,
          document,
          seed,
          jsonLd,
          shallowSet.has(candidate),
        );
      })),
    });
  }

  function selectTitle(document, layouts, seed, jsonLd) {
    const result = titleCandidateEvaluations(document, layouts, seed, jsonLd);
    if (!result.ok) {
      return Object.freeze({
        ok: false,
        reason: "candidate-bound",
        candidateOverflow: true,
        candidateCount: result.count,
        ranked: Object.freeze([]),
      });
    }
    const evaluations = result.evaluations;
    if (seed) {
      const evidenceApproved = evaluations.filter(function hasExactTitleEvidence(evaluation) {
        return !evaluation.disqualified && evaluation.titleEvidence?.ok === true;
      });
      const decision = decideCandidate(evidenceApproved, ROLE_POLICIES.title);
      return Object.freeze({
        ...decision,
        candidateOverflow: false,
        candidateCount: result.count,
      });
    }
    const decision = decideCandidate(evaluations, ROLE_POLICIES.title);
    return Object.freeze({
      ...decision,
      candidateOverflow: false,
      candidateCount: result.count,
    });
  }

  function followsNode(element, earlierNode) {
    if (!element || !earlierNode || element === earlierNode || element.contains(earlierNode)) {
      return false;
    }
    return Boolean(earlierNode.compareDocumentPosition(element) & 4);
  }

  function outboundLinkCount(element) {
    const hostname = element.ownerDocument.location.hostname;
    const anchors = (element.matches("a[href]") ? [element] : []).concat(
      Array.from(element.querySelectorAll("a[href]")),
    );
    return anchors.filter(function externalAnchor(anchor) {
      try {
        const url = new URL(anchor.href, element.ownerDocument.location.href);
        return /^https?:$/.test(url.protocol) && url.hostname && url.hostname !== hostname;
      } catch (_error) {
        return false;
      }
    }).length;
  }

  function productPurchaseLinkCount(element) {
    const document = element.ownerDocument;
    const outbound = outboundLinkCount(element);
    const anchors = (element.matches("a[href]") ? [element] : []).concat(
      Array.from(element.querySelectorAll("a[href]")),
    );
    const nativeRedirects = anchors.filter(function labeledNativePurchaseRedirect(anchor) {
      try {
        const row = anchor.closest("tr, dd, [itemprop='offers']");
        const label = normalizeText(row?.querySelector("th, dt, label")?.textContent || "");
        const purchaseLabel = /^(?:상품\s*링크|구매\s*링크|구매처|판매처|링크|product\s*link|purchase\s*link|buy)(?:\s|$)/iu.test(label);
        // QuasarZone keeps its purchase destination in a native encoded handler.
        // Recognize that exact form without invoking it or replacing the href.
        const nativeHandler = /^(?:javascript:)\s*goToLink\(\s*(['"])([A-Za-z0-9+/]+={0,2})\1\s*\)\s*;?\s*$/iu.exec(anchor.getAttribute("href") || "");
        if (document.location.hostname === "quasarzone.com" && nativeHandler && purchaseLabel) {
          const decoded = new URL(atob(nativeHandler[2]));
          const displayed = new URL(String(anchor.textContent || "").trim());
          return /^https?:$/.test(decoded.protocol) && decoded.hostname !== document.location.hostname &&
            decoded.href === displayed.href;
        }
        const target = new URL(anchor.href, document.location.href);
        if (!/^https?:$/.test(target.protocol) ||
            target.hostname !== document.location.hostname ||
            !/^\/(?:go|out|redirect|buy|purchase)(?:\/|$)/iu.test(target.pathname)) return false;
        return purchaseLabel ||
          /^https?:\/\/[^\s]+/iu.test(String(anchor.textContent || "").trim());
      } catch (_error) {
        return false;
      }
    });
    return outbound + nativeRedirects.length;
  }

  function bodyFeatures(element, titleNode, noiseCache) {
    const textLength = normalizeText(element.textContent).length;
    const paragraphCount = element.querySelectorAll("p, blockquote, pre, li").length;
    const mediaCount = element.querySelectorAll("img, picture, video, iframe").length;
    const tableCount = element.querySelectorAll("table").length;
    const anchorCount = element.querySelectorAll("a[href]").length;
    const externalLinks = outboundLinkCount(element);
    const tokenText = semanticTokenText(element);
    const semantic = element.matches(
      "article, main, [role='main'], [itemprop='articleBody'], [itemtype*='Article']"
    );
    const metadataSurface = BODY_METADATA_TOKEN_PATTERN.test(tokenText);
    const afterTitle = followsNode(element, titleNode);
    const hasRichContent = paragraphCount >= 2 || mediaCount >= 1 || tableCount >= 1;
    const hasTextBlock = textLength >= MIN_BODY_TEXT_LENGTH;
    const externalDensity = anchorCount ? externalLinks / anchorCount : 0;
    const negativeContainers = element.querySelectorAll(
      "nav, aside, footer, header, [role='navigation'], [itemtype*='Comment']"
    ).length;
    const autonomousIgnored = discoverAutonomousIgnoredRoots(element, []);
    const autonomousIgnoredRoots = autonomousIgnored.ok
      ? Array.from(autonomousIgnored.roots)
      : [];
    const hasNoise = !autonomousIgnored.ok ||
      containsSemanticNoise(element, noiseCache, autonomousIgnoredRoots);
    const hasShadowBoundary = containsUnprovenShadowBoundary(
      element,
      autonomousIgnoredRoots,
    );
    const hasPublisherPaint = containsPublisherPaintRisk(
      element,
      autonomousIgnoredRoots,
    );
    return {
      textLength,
      paragraphCount,
      mediaCount,
      tableCount,
      externalLinks,
      externalDensity,
      semantic,
      metadataSurface,
      afterTitle,
      hasRichContent,
      hasTextBlock,
      negativeContainers,
      hasNoise,
      hasShadowBoundary,
      hasPublisherPaint,
      autonomousIgnored,
      tokenText,
    };
  }

  function scoreBodyFeatures(features) {
    let score = 0;
    const signals = [];
    if (features.semantic) {
      score += 2.5;
      signals.push("article-semantic");
    }
    if (features.afterTitle) {
      score += 2;
      signals.push("after-title");
    }
    if (features.hasTextBlock) {
      score += Math.min(3, 1.5 + features.textLength / 1200);
      signals.push("body-text");
    }
    if (features.hasRichContent) {
      score += Math.min(2.5, 1 + features.paragraphCount * 0.15 + features.mediaCount * 0.35 + features.tableCount * 0.5);
      signals.push("body-richness");
    }
    if (features.externalLinks > 0 && features.externalDensity <= 0.8) {
      score += 0.75;
      signals.push("outbound-content-link");
    }
    score -= Math.min(6, features.negativeContainers * 1.5);
    if (COMMENT_TOKEN_PATTERN.test(features.tokenText)) {
      score -= 4;
    }
    if (NOISE_TOKEN_PATTERN.test(features.tokenText)) {
      score -= 6;
    }
    if (features.metadataSurface) {
      score -= 6;
    }
    return { score, signals };
  }

  function evaluateBodyCandidate(element, titleNode, hintSelectors, noiseCache) {
    const evaluation = { node: element, score: 0, signals: new Set(), disqualified: false };
    if (!isRendered(element) || element.contains(titleNode)) {
      evaluation.disqualified = true;
      return evaluation;
    }
    const features = bodyFeatures(element, titleNode, noiseCache);
    evaluation.features = features;
    if (features.hasNoise || features.hasShadowBoundary || features.hasPublisherPaint) {
      evaluation.disqualified = true;
      return evaluation;
    }
    const scored = scoreBodyFeatures(features);
    evaluation.score = scored.score;
    scored.signals.forEach(function recordSignal(signal) { evaluation.signals.add(signal); });
    if (elementMatchesAny(element, hintSelectors)) {
      addSignal(evaluation, "selector-hint", 1.5);
    }
    return evaluation;
  }

  function selectBody(document, layouts, titleNode) {
    const hints = roleHints(layouts, "body");
    const noiseCache = new WeakMap();
    const collection = collectBoundedCandidateElements(
      document,
      "article, main, [role='main'], [itemprop='articleBody'], [itemtype*='Article'], section, div",
      hints,
      function plausibleBody(element) {
        if (element.matches("article, main, [role='main'], [itemprop='articleBody'], [itemtype*='Article']")) {
          return true;
        }
        return normalizeText(element.textContent).length >= MIN_BODY_TEXT_LENGTH;
      },
    );
    const decision = decideBoundedCandidates(
      collection,
      function scoreCandidate(candidate) {
        return evaluateBodyCandidate(candidate, titleNode, hints, noiseCache);
      },
      ROLE_POLICIES.body
    );
    return preferUniqueQualifiedHintCandidate(decision, hints);
  }

  function childFingerprint(child) {
    const classTokens = typeof child.className === "string"
      ? child.className.split(/\s+/).filter(Boolean).slice(0, 3).sort().join(".")
      : "";
    return [
      child.tagName.toLocaleLowerCase(),
      classTokens,
      child.getAttribute("role") || "",
      child.getAttribute("itemprop") || "",
    ].join("|");
  }

  function repeatedSiblingCount(element, excludedRoots) {
    const counts = new Map();
    Array.from(element.children).forEach(function countChild(child) {
      if ((excludedRoots || []).some(function excludedCommentChild(root) {
        return root === child || root.contains(child);
      })) {
        return;
      }
      const fingerprint = childFingerprint(child);
      counts.set(fingerprint, (counts.get(fingerprint) || 0) + 1);
    });
    const repeatedCount = Math.max(0, ...Array.from(counts.values()));
    return repeatedCount >= 2 ? repeatedCount : 0;
  }

  function commentClassificationRoots(element, controlHints, ignoredHints) {
    return uniqueElements(queryAllSafe(element, controlHints.concat(ignoredHints))).filter(
      function containedClassificationRoot(root) {
        return root !== element && element.contains(root);
      }
    );
  }

  function commentFeatures(
    element,
    bodyNode,
    jsonLd,
    seed,
    itemHints,
    controlHints,
    ignoredHints,
  ) {
    const tokenText = semanticTokenText(element);
    const shortText = truncateText(element.textContent, 1000);
    const schemaCount = element.querySelectorAll(
      "[itemtype*='schema.org/Comment'], [itemprop='comment']"
    ).length;
    const role = element.getAttribute("role") || "";
    const listSemantic = /^(?:feed|list|tree)$/.test(role) || /^(?:ol|ul)$/.test(element.tagName.toLocaleLowerCase());
    const excludedRoots = commentClassificationRoots(element, controlHints, ignoredHints);
    const repeatedCount = repeatedSiblingCount(element, excludedRoots);
    const hintedItems = uniqueElements(queryAllSafe(element, itemHints)).filter(
      function unexcludedHintedItem(item) {
        return !insideAnyRoot(item, excludedRoots);
      }
    ).length;
    const singletonItems = singletonSemanticCommentEvidence(element);
    const apparentItemCount = Math.max(schemaCount, repeatedCount, hintedItems, singletonItems.length);
    const labelMatch = COMMENT_TOKEN_PATTERN.test(`${tokenText} ${shortText.slice(0, 200)}`);
    const semantic = schemaCount > 0 || /comment|reply/i.test(tokenText);
    const anchorCount = element.querySelectorAll("a[href]").length;
    const navigationalList = listSemantic &&
      anchorCount >= 4 &&
      repeatedCount >= 4 &&
      schemaCount === 0 &&
      hintedItems === 0 &&
      !labelMatch;
    const afterBody = followsNode(element, bodyNode);
    const seedCountMatches = seed && seed.commentCount !== null && apparentItemCount > 0
      ? Math.abs(apparentItemCount - seed.commentCount) <= Math.max(2, seed.commentCount * 0.35)
      : false;
    const schemaCountMatches = jsonLd.commentCount !== null && apparentItemCount > 0
      ? Math.abs(apparentItemCount - jsonLd.commentCount) <= Math.max(2, jsonLd.commentCount * 0.35)
      : false;
    return {
      schemaCount,
      listSemantic,
      repeatedCount,
      apparentItemCount,
      labelMatch,
      semantic,
      navigationalList,
      afterBody,
      seedCountMatches,
      schemaCountMatches,
      tokenText,
    };
  }

  function scoreCommentFeatures(features) {
    let score = 0;
    const signals = [];
    if (features.semantic) {
      score += 2.25;
      signals.push("comment-semantic");
    }
    if (features.labelMatch) {
      score += 1.75;
      signals.push("comment-label");
    }
    if (features.afterBody) {
      score += 1.5;
      signals.push("after-body");
    }
    if (features.repeatedCount >= 2) {
      score += Math.min(2.5, 1 + features.repeatedCount * 0.2);
      signals.push("repeated-fingerprint");
    }
    if (features.schemaCount > 0) {
      score += 1.5;
      signals.push("schema-comment");
    }
    if (features.schemaCountMatches) {
      score += 1;
      signals.push("metadata-count-match");
    }
    if (features.seedCountMatches) {
      score += 0.5;
      signals.push("seed-count-match");
    }
    if (NOISE_TOKEN_PATTERN.test(features.tokenText) && !COMMENT_TOKEN_PATTERN.test(features.tokenText)) {
      score -= 6;
    }
    return { score, signals };
  }

  function evaluateCommentCandidate(
    element,
    bodyNode,
    jsonLd,
    seed,
    hints,
    itemHints,
    controlHints,
    ignoredHints,
    allowStableEmptyMount,
    explicitEvidenceElements,
  ) {
    const evaluation = { node: element, score: 0, signals: new Set(), disqualified: false };
    if (!element.isConnected || element === bodyNode || bodyNode.contains(element)) {
      evaluation.disqualified = true;
      return evaluation;
    }
    const itemRoots = uniqueElements(queryAllSafe(element, itemHints));
    const controlRoots = uniqueElements(queryAllSafe(element, controlHints));
    const ignoredRoots = uniqueElements(queryAllSafe(element, ignoredHints));
    if (commentProjectionHasRisk(
      element,
      itemRoots,
      controlRoots,
      ignoredRoots,
      allowStableEmptyMount,
    )) {
      evaluation.disqualified = true;
      return evaluation;
    }
    const features = commentFeatures(
      element,
      bodyNode,
      jsonLd,
      seed,
      itemHints,
      controlHints,
      ignoredHints,
    );
    evaluation.features = features;
    if (features.navigationalList) {
      evaluation.disqualified = true;
      return evaluation;
    }
    const scored = scoreCommentFeatures(features);
    evaluation.score = scored.score;
    scored.signals.forEach(function recordSignal(signal) { evaluation.signals.add(signal); });
    const stableEmptyStructure = allowStableEmptyMount &&
      features.apparentItemCount === 0 &&
      features.afterBody &&
      (features.labelMatch || features.semantic || elementMatchesAny(element, hints)) &&
      (isRendered(element) || isStableZeroAreaCommentMount(element));
    if (stableEmptyStructure) {
      addSignal(evaluation, "stable-empty-comment-mount", 0.5);
    }
    const explicitEvidence = Array.from(explicitEvidenceElements || []);
    if (
      explicitEvidence.length > 0 &&
      explicitEvidence.every(function containedExplicitCommentEvidence(item) {
        return element === item || element.contains(item);
      })
    ) {
      addSignal(evaluation, "complete-explicit-comment-evidence", 3.25);
    }
    if (elementMatchesAny(element, hints)) {
      addSignal(evaluation, "selector-hint", 1.5);
    }
    return evaluation;
  }

  function restrictCommentDecisionToExplicitEvidence(decision, explicitEvidenceElements) {
    const evidence = Array.from(explicitEvidenceElements || []);
    if (!evidence.length || !decision.ranked?.length) return decision;
    const complete = decision.ranked.filter(function completeCommentCandidate(evaluation) {
      return evidence.every(function explicitEvidenceInsideCandidate(element) {
        return evaluation.node === element || evaluation.node.contains(element);
      });
    });
    if (!complete.length) {
      return Object.freeze({
        ...decision,
        ok: false,
        reason: "explicit-comment-evidence-uncontained",
        winner: undefined,
        ranked: Object.freeze([]),
      });
    }
    const runnerUp = complete[1];
    const completeHasMargin = !runnerUp || complete[0].score - runnerUp.score >= ROLE_POLICIES.comments.margin;
    return Object.freeze({
      ...decision,
      ok: completeHasMargin,
      reason: completeHasMargin ? "complete-explicit-comment-evidence" : "insufficient-margin",
      winner: completeHasMargin ? complete[0] : undefined,
      ranked: Object.freeze(complete),
    });
  }

  function selectComments(document, layouts, bodyNode, jsonLd, seed, explicitEvidenceElements) {
    const hints = roleHints(layouts, "comments");
    const itemHints = roleHints(layouts, "commentItems");
    const controlHints = roleHints(layouts, "commentControls");
    const ignoredHints = roleHints(layouts, "commentIgnored");
    const allowStableEmptyMount = layouts.every(function approvedEmptyLayout(layout) {
      return layout.allowEmptyComments === true;
    });
    const collection = collectBoundedCandidateElements(
      document,
      "[role='feed'], [role='list'], section, div, ol, ul",
      hints,
      function plausibleComments(element) {
        if (
          element.matches("[itemtype*='schema.org/Comment'], [itemprop='comment']") ||
          elementMatchesAny(element, itemHints) ||
          elementMatchesAny(element, controlHints) ||
          elementMatchesAny(element, ignoredHints) ||
          (element.parentElement && !elementMatchesAny(element, hints) &&
            hasSingularSemanticCommentIdentity(element) &&
            COMMENT_TOKEN_PATTERN.test(semanticTokenText(element.parentElement)))
        ) {
          return false;
        }
        const tokens = semanticTokenText(element);
        const excludedRoots = commentClassificationRoots(element, controlHints, ignoredHints);
        return COMMENT_TOKEN_PATTERN.test(`${tokens} ${truncateText(element.textContent, 180)}`) ||
          repeatedSiblingCount(element, excludedRoots) >= 2 ||
          element.matches("[role='feed'], [role='list']");
      },
    );
    const decision = restrictCommentDecisionToExplicitEvidence(decideBoundedCandidates(
      collection,
      function scoreCandidate(candidate) {
        return evaluateCommentCandidate(
          candidate,
          bodyNode,
          jsonLd,
          seed,
          hints,
          itemHints,
          controlHints,
          ignoredHints,
          allowStableEmptyMount,
          explicitEvidenceElements,
        );
      },
      ROLE_POLICIES.comments
    ), explicitEvidenceElements);
    return preferUniqueQualifiedHintCandidate(
      decision,
      hints,
      function exhaustivelyAnchoredCommentMount(evaluation) {
        const evidence = Array.from(explicitEvidenceElements || []);
        if (evidence.length) {
          return evidence.every(function evidenceInsideHintAnchor(element) {
            return evaluation.node === element || evaluation.node.contains(element);
          });
        }
        return stableEmptyCommentMount(evaluation, layouts);
      },
    );
  }

  function productFeatures(element, titleNode, bodyNode, noiseCache) {
    const text = truncateText(element.textContent, 1200);
    const tokenText = semanticTokenText(element);
    const semantic = element.matches(
      "[itemprop='offers'], [itemprop='price'], [itemtype*='Offer']"
    );
    // A native purchase relay can stay on the publisher origin; its original
    // href must remain intact instead of being mistaken for site navigation.
    const outboundLinks = productPurchaseLinkCount(element);
    const hasPrice = CURRENCY_PATTERN.test(text);
    const hasProductLabel = PRODUCT_TOKEN_PATTERN.test(`${tokenText} ${text}`);
    let previousContext = "";
    let sibling = element.previousSibling;
    for (let inspected = 0; sibling && inspected < 3; inspected += 1) {
      if (sibling.nodeType === 1 && sibling.matches("br, hr")) break;
      previousContext = `${String(sibling.textContent || "")} ${previousContext}`;
      sibling = sibling.previousSibling;
    }
    const boundedSourceContext = normalizeText(previousContext).slice(-48);
    const hasSourceIdentity = PRODUCT_SOURCE_IDENTITY_PATTERN.test(tokenText) ||
      /(?:^|\s)(?:링크|출처|구매처|판매처|구매\s*링크|상품\s*링크)(?:$|\s)/iu.test(boundedSourceContext);
    const commentOverlap = COMMENT_TOKEN_PATTERN.test(tokenText) || element.matches(
      "[itemtype*='schema.org/Comment'], [itemprop='comment']"
    ) || Boolean(element.querySelector(
      "[itemtype*='schema.org/Comment'], [itemprop='comment']"
    ));
    const hasPurchaseEvidence = semantic || (
      outboundLinks > 0 && (hasPrice || hasProductLabel || hasSourceIdentity)
    );
    const afterTitle = followsNode(element, titleNode);
    const beforeOrSeparateFromBody = !bodyNode.contains(element) &&
      (followsNode(bodyNode, element) || !element.contains(bodyNode));
    const autonomousIgnored = discoverAutonomousIgnoredRoots(element, []);
    const autonomousIgnoredRoots = autonomousIgnored.ok
      ? Array.from(autonomousIgnored.roots)
      : [];
    const hasNoise = !autonomousIgnored.ok ||
      containsSemanticNoise(element, noiseCache, autonomousIgnoredRoots);
    const hasShadowBoundary = containsUnprovenShadowBoundary(
      element,
      autonomousIgnoredRoots,
    );
    const hasPublisherPaint = containsPublisherPaintRisk(
      element,
      autonomousIgnoredRoots,
    );
    return {
      semantic,
      outboundLinks,
      hasPrice,
      hasProductLabel,
      hasSourceIdentity,
      commentOverlap,
      hasPurchaseEvidence,
      afterTitle,
      beforeOrSeparateFromBody,
      hasNoise,
      hasShadowBoundary,
      hasPublisherPaint,
      autonomousIgnored,
    };
  }

  function evaluateProductCandidate(element, titleNode, bodyNode, hints, noiseCache) {
    const evaluation = { node: element, score: 0, signals: new Set(), disqualified: false };
    if (!isRendered(element) || element.contains(titleNode) || element.contains(bodyNode)) {
      evaluation.disqualified = true;
      return evaluation;
    }
    const features = productFeatures(element, titleNode, bodyNode, noiseCache);
    evaluation.features = features;
    if (
      features.hasNoise ||
      features.hasShadowBoundary ||
      features.hasPublisherPaint ||
      features.commentOverlap ||
      !features.hasPurchaseEvidence
    ) {
      evaluation.disqualified = true;
      return evaluation;
    }
    if (features.semantic) addSignal(evaluation, "product-semantic", 2);
    if (features.hasSourceIdentity) addSignal(evaluation, "purchase-source-structure", 2);
    if (features.outboundLinks > 0) addSignal(evaluation, "purchase-link", Math.min(2, 1 + features.outboundLinks * 0.25));
    if (features.hasPrice) addSignal(evaluation, "price-text", 1.75);
    if (features.hasProductLabel) addSignal(evaluation, "product-label", 1.25);
    if (features.afterTitle && features.beforeOrSeparateFromBody) addSignal(evaluation, "article-position", 1.25);
    if (elementMatchesAny(element, hints)) addSignal(evaluation, "selector-hint", 1.5);
    return evaluation;
  }

  function selectProduct(document, layouts, titleNode, bodyNode) {
    const hints = roleHints(layouts, "product");
    const noiseCache = new WeakMap();
    const collection = collectBoundedCandidateElements(
      document,
      "[itemprop='offers'], [itemprop='price'], [itemtype*='Offer'], table, dl, section, div",
      hints,
      function plausibleProduct(element) {
        const text = truncateText(element.textContent, 500);
        const tokenText = semanticTokenText(element);
        return CURRENCY_PATTERN.test(text) ||
          PRODUCT_TOKEN_PATTERN.test(`${tokenText} ${text}`) ||
          PRODUCT_SOURCE_IDENTITY_PATTERN.test(tokenText);
      },
    );
    const decision = decideBoundedCandidates(
      collection,
      function scoreCandidate(candidate) {
        return evaluateProductCandidate(candidate, titleNode, bodyNode, hints, noiseCache);
      },
      ROLE_POLICIES.product
    );
    return preferUniqueQualifiedHintCandidate(decision, hints);
  }

  function titleProofFingerprint(evaluation) {
    if (!evaluation || evaluation.titleEvidence?.ok !== true) {
      return null;
    }
    return JSON.stringify({
      title: normalizeText(stripBoundedTitleAffixes(evaluation.resolvedTitle)),
      mode: evaluation.titleEvidence.mode,
      score: evaluation.titleEvidence.score,
      metadataSourceCount: evaluation.titleEvidence.metadata?.sourceCount || 0,
      authoritativeMatchCount:
        evaluation.titleEvidence.metadata?.authoritativeMatchCount || 0,
      metadataKinds: Array.from(
        evaluation.titleEvidence.metadata?.sourceKinds || []
      ).slice().sort(),
    });
  }

  function elementDepth(element) {
    let depth = 0;
    for (let current = element; current?.parentElement; current = current.parentElement) {
      depth += 1;
    }
    return depth;
  }

  function titleSemanticPriority(element) {
    const tagName = element.tagName.toLocaleLowerCase();
    if (/^h[1-3]$/.test(tagName)) return 4;
    if (element.getAttribute("role") === "heading") return 3;
    if (element.hasAttribute("itemprop")) return 2;
    return 1;
  }

  function collapseProvenTitleWrappers(evaluations) {
    const parents = evaluations.map(function ownIndex(_evaluation, index) { return index; });
    function find(index) {
      let current = index;
      while (parents[current] !== current) {
        parents[current] = parents[parents[current]];
        current = parents[current];
      }
      return current;
    }
    function unite(leftIndex, rightIndex) {
      const leftRoot = find(leftIndex);
      const rightRoot = find(rightIndex);
      if (leftRoot !== rightRoot) parents[rightRoot] = leftRoot;
    }
    evaluations.forEach(function compareLeft(left, leftIndex) {
      const leftProof = titleProofFingerprint(left);
      if (!leftProof) return;
      evaluations.slice(leftIndex + 1).forEach(function compareRight(right, offset) {
        const rightIndex = leftIndex + offset + 1;
        const wrapperPair = left.node.contains(right.node) || right.node.contains(left.node);
        if (wrapperPair && leftProof === titleProofFingerprint(right)) {
          unite(leftIndex, rightIndex);
        }
      });
    });
    const groups = new Map();
    evaluations.forEach(function collectGroup(evaluation, index) {
      const root = find(index);
      if (!groups.has(root)) groups.set(root, []);
      groups.get(root).push(evaluation);
    });
    const collapsed = Array.from(groups.values()).map(function canonicalTitle(group) {
      const members = group.slice().sort(function compareCanonical(left, right) {
        const priorityDifference = titleSemanticPriority(right.node) - titleSemanticPriority(left.node);
        if (priorityDifference) return priorityDifference;
        const depthDifference = elementDepth(right.node) - elementDepth(left.node);
        if (depthDifference) return depthDifference;
        if (right.score !== left.score) return right.score - left.score;
        return documentOrder(left.node, right.node);
      });
      const representative = members[0];
      return Object.freeze({
        ...representative,
        members: Object.freeze(group.map(function titleMember(item) { return item.node; })),
        proofFingerprint: titleProofFingerprint(representative),
      });
    });
    collapsed.sort(function rankCollapsedTitles(left, right) {
      if (right.score !== left.score) return right.score - left.score;
      return documentOrder(left.node, right.node);
    });
    return collapsed;
  }

  function boundedRolePool(evaluations, policy) {
    const ranked = qualifiedCandidates(evaluations, policy);
    return Object.freeze({
      ok: ranked.length <= MAX_PROJECTION_ROLE_CANDIDATES,
      ranked: Object.freeze(ranked),
    });
  }

  function boundedDecisionPool(decision) {
    const ranked = Array.from(decision.ranked || []);
    const rawOverflow = decision.candidateOverflow === true;
    const roleOverflow = ranked.length > MAX_PROJECTION_ROLE_CANDIDATES;
    const overflow = rawOverflow || roleOverflow;
    return Object.freeze({
      ok: !overflow,
      overflow,
      count: rawOverflow ? decision.candidateCount : ranked.length,
      ranked: Object.freeze(overflow ? [] : ranked),
    });
  }

  function semanticProductCardinality(layouts) {
    if (layouts.some(function requiredProduct(layout) {
      return layout.requiredRoles?.includes("product") ||
        layout.roleProjection?.product?.cardinality === "required";
    })) {
      return "required";
    }
    if (layouts.some(function optionalProduct(layout) {
      return layout.roleProjection?.product?.cardinality === "optional";
    })) {
      return "optional";
    }
    return "zero";
  }

  function semanticProductOrder(layouts, productCardinality) {
    if (productCardinality === "zero") return null;
    const orders = new Set(
      layouts
        .filter(function projectedProduct(layout) {
          return layout.roleProjection?.product?.cardinality !== "zero";
        })
        .map(function configuredProductOrder(layout) {
          return layout.roleProjection?.product?.order;
        })
        .filter(function approvedProductOrder(order) {
          return order === "before-body" || order === "after-body";
        }),
    );
    return orders.size === 1 ? Array.from(orders)[0] : null;
  }

  function nodesOverlap(left, right) {
    return left === right || left.contains(right) || right.contains(left);
  }

  function collectBoundedCommentEvidence(rootNode, selectors) {
    const elements = [];
    const seen = new Set();
    for (const selector of selectors) {
      let matches;
      try {
        matches = rootNode.querySelectorAll(selector);
      } catch (_error) {
        continue;
      }
      for (const element of matches) {
        if (seen.has(element)) continue;
        if (elements.length >= MAX_COMMENT_EVIDENCE) {
          return Object.freeze({
            ok: false,
            reason: "comment-evidence-bound",
            count: elements.length + 1,
            elements: Object.freeze([]),
          });
        }
        seen.add(element);
        elements.push(element);
      }
    }
    return Object.freeze({
      ok: true,
      count: elements.length,
      elements: Object.freeze(elements),
    });
  }

  function explicitCommentEvidence(document, layouts) {
    return collectBoundedCommentEvidence(
      document,
      ["[itemtype*='schema.org/Comment'], [itemprop='comment']"].concat(
        roleHints(layouts, "commentItems")
      ),
    );
  }

  function stableEmptyCommentMount(evaluation, layouts) {
    const semanticIdentity = COMMENT_TOKEN_PATTERN.test([
      evaluation.features?.tokenText || semanticTokenText(evaluation.node),
      evaluation.node.getAttribute("aria-label") || "",
    ].join(" "));
    const classifiedRoots = commentClassificationRoots(
      evaluation.node, roleHints(layouts, "commentControls"), roleHints(layouts, "commentIgnored"),
    ).concat(Array.from(evaluation.node.children).filter(isFormOnlyCommentEvidenceSurface));
    return evaluation.features?.apparentItemCount === 0 &&
      !hasUnclassifiedCommentContent(evaluation.node, classifiedRoots) &&
      (isRendered(evaluation.node) || isStableZeroAreaCommentMount(evaluation.node)) &&
      (elementMatchesAny(evaluation.node, roleHints(layouts, "comments")) || semanticIdentity);
  }

  const COMMENT_FORM_CONTROL_SELECTOR = "form, fieldset, label, input, select, option, textarea";

  function isFormOnlyCommentEvidenceSurface(element) {
    if (element.matches(COMMENT_FORM_CONTROL_SELECTOR)) return true;
    if (!element.querySelector(COMMENT_FORM_CONTROL_SELECTOR)) return false;
    return Array.from(element.childNodes).every(function formOnlyChild(node) {
      if (node.nodeType === 3) return !normalizeText(node.textContent);
      return node.nodeType === 1 && isFormOnlyCommentEvidenceSurface(node);
    });
  }

  function singletonSemanticCommentEvidence(mount) {
    if (!COMMENT_TOKEN_PATTERN.test(semanticTokenText(mount))) return [];
    const items = Array.from(mount.children).filter(function explicitSingularItem(item) {
      return hasSingularSemanticCommentIdentity(item) &&
        isRendered(item) && normalizeText(item.textContent).length > 0 &&
        parseVisibleCommentTotal(item.textContent) === null &&
        !isFormOnlyCommentEvidenceSurface(item) &&
        !isCommentContinuationControl(item) &&
        !isAutonomousProjectionNoiseRoot(item) &&
        !containsSemanticNoise(item, new WeakMap(), []) &&
        !containsUnprovenShadowBoundary(item, []) &&
        !containsPublisherPaintRisk(item, []);
    });
    if (items.length !== 1) return [];
    const controls = Array.from(mount.querySelectorAll("button, a[href], [role='button']"))
      .filter(function independentContinuation(control) {
        return !items[0].contains(control) && isCommentContinuationControl(control) &&
          !isAutonomousProjectionNoiseRoot(control);
      });
    const ignored = Array.from(mount.children).filter(function explicitNoise(child) {
      return child !== items[0] && isAutonomousProjectionNoiseRoot(child);
    });
    // Singular item identity, a comment-labelled mount, and exhaustive child
    // coverage are all required. A lone unlabelled paragraph is not a comment.
    return hasUnclassifiedCommentContent(mount, items.concat(controls, ignored)) ? [] : items;
  }

  function hasSingularSemanticCommentIdentity(element) {
    return /(?:^|[\s_-])(?:comment|reply)(?:$|[\s_-](?:item|row|entry)(?:$|[\s_-]))/iu
      .test(semanticTokenText(element));
  }

  function inferredRepeatedCommentEvidence(evaluation, layouts, evidenceCache) {
    if (evidenceCache.has(evaluation.node)) {
      return evidenceCache.get(evaluation.node);
    }
    const singletonItems = singletonSemanticCommentEvidence(evaluation.node);
    if (singletonItems.length) {
      const result = Object.freeze({ ok: true, count: 1, elements: Object.freeze(singletonItems) });
      evidenceCache.set(evaluation.node, result);
      return result;
    }
    if (
      evaluation.features?.apparentItemCount < 2 ||
      (!evaluation.features.semantic && !evaluation.features.labelMatch)
    ) {
      const emptyResult = Object.freeze({
        ok: true,
        count: 0,
        elements: Object.freeze([]),
      });
      evidenceCache.set(evaluation.node, emptyResult);
      return emptyResult;
    }
    const evidence = [];
    const seen = new Set();
    const excludedRoots = commentClassificationRoots(
      evaluation.node,
      roleHints(layouts, "commentControls"),
      roleHints(layouts, "commentIgnored"),
    );
    const queue = [{ node: evaluation.node, depth: 0 }];
    const inspectedNodes = new Set([evaluation.node]);
    let queueIndex = 0;
    function evidenceOverflow(count) {
      const overflowResult = Object.freeze({
        ok: false,
        reason: "comment-evidence-bound",
        count,
        elements: Object.freeze([]),
      });
      evidenceCache.set(evaluation.node, overflowResult);
      return overflowResult;
    }
    while (queueIndex < queue.length) {
      const current = queue[queueIndex];
      queueIndex += 1;
      const groups = new Map();
      for (const child of current.node.children) {
        if (
          insideAnyRoot(child, excludedRoots) ||
          isFormOnlyCommentEvidenceSurface(child)
        ) continue;
        if (!inspectedNodes.has(child)) {
          if (inspectedNodes.size >= MAX_SEMANTIC_DESCENDANTS) {
            return evidenceOverflow(inspectedNodes.size + 1);
          }
          inspectedNodes.add(child);
        }
        const fingerprint = childFingerprint(child);
        if (!groups.has(fingerprint)) groups.set(fingerprint, []);
        groups.get(fingerprint).push(child);
      }
      const repeatedGroups = Array.from(groups.values()).filter(function repeated(group) {
        return group.length >= 2;
      });
      if (repeatedGroups.length) {
        const largestCount = Math.max(...repeatedGroups.map(function groupSize(group) {
          return group.length;
        }));
        const dominantGroups = repeatedGroups.filter(function dominantGroup(group) {
          return group.length === largestCount;
        });
        for (const group of dominantGroups) {
          for (const element of group) {
            if (!isRendered(element)) continue;
            if (seen.has(element)) continue;
            if (evidence.length >= MAX_COMMENT_EVIDENCE) {
              return evidenceOverflow(evidence.length + 1);
            }
            seen.add(element);
            evidence.push(element);
          }
        }
      }
      if (current.depth < 2) {
        for (const child of current.node.children) {
          if (
            insideAnyRoot(child, excludedRoots) ||
            isFormOnlyCommentEvidenceSurface(child)
          ) continue;
          queue.push({ node: child, depth: current.depth + 1 });
        }
      }
    }
    const result = Object.freeze({
      ok: true,
      count: evidence.length,
      elements: Object.freeze(evidence),
    });
    evidenceCache.set(evaluation.node, result);
    return result;
  }

  function precomputeCommentEvidence(
    commentPool,
    explicitEvidence,
    layouts,
    evidenceCache,
  ) {
    if (!explicitEvidence.ok) return explicitEvidence;
    if (explicitEvidence.elements.length) return explicitEvidence;
    const elements = [];
    const seen = new Set();
    function appendEvidence(element) {
      if (seen.has(element)) return true;
      if (elements.length >= MAX_COMMENT_EVIDENCE) return false;
      seen.add(element);
      elements.push(element);
      return true;
    }
    for (const element of explicitEvidence.elements) {
      if (!appendEvidence(element)) {
        return Object.freeze({
          ok: false,
          reason: "comment-evidence-bound",
          count: elements.length + 1,
          elements: Object.freeze([]),
        });
      }
    }
    for (const candidate of commentPool) {
      const inferred = inferredRepeatedCommentEvidence(candidate, layouts, evidenceCache);
      if (!inferred.ok) return inferred;
      for (const element of inferred.elements) {
        if (!appendEvidence(element)) {
          return Object.freeze({
            ok: false,
            reason: "comment-evidence-bound",
            count: elements.length + 1,
            elements: Object.freeze([]),
          });
        }
      }
    }
    return Object.freeze({
      ok: true,
      count: elements.length,
      elements: Object.freeze(elements),
    });
  }

  function precomputeSemanticCommentEvidence(
    commentPool,
    explicitEvidence,
    layouts,
    evidenceCache,
  ) {
    if (!explicitEvidence.ok) return explicitEvidence;
    const evidenceByCandidate = new Map();
    if (explicitEvidence.elements.length) {
      commentPool.forEach(function bindExplicitEvidence(candidate) {
        evidenceByCandidate.set(candidate, explicitEvidence.elements);
      });
      return Object.freeze({
        ok: true,
        count: explicitEvidence.elements.length,
        explicit: true,
        evidenceByCandidate,
      });
    }
    let largestEvidenceCount = 0;
    for (const candidate of commentPool) {
      const inferred = inferredRepeatedCommentEvidence(candidate, layouts, evidenceCache);
      if (!inferred.ok) return inferred;
      largestEvidenceCount = Math.max(largestEvidenceCount, inferred.count);
      evidenceByCandidate.set(candidate, inferred.elements);
    }
    return Object.freeze({
      ok: true,
      count: largestEvidenceCount,
      explicit: false,
      evidenceByCandidate,
    });
  }

  function independentArticleListRoots(document, layout, bodyNode) {
    const contract = findSiteContract(document.location?.hostname || "");
    const currentIdentity = contract && articleIdentity(document.location, contract.id);
    if (!currentIdentity) return [];
    const mounts = queryAllSafe(document, layout.hints.comments || []);
    const roots = [];
    for (const table of document.querySelectorAll(
      "table, ul, ol, [role='list'], [role='feed'], [class*='list'], [class*='lst'], [id*='list'], [id*='lst']",
    )) {
      const tokens = semanticTokenText(table);
      if (!/(?:^|\s)(?:list|lst|board|articles|posts)(?:\s|$)/iu.test(tokens) ||
          COMMENT_TOKEN_PATTERN.test(tokens) ||
          nodesOverlap(table, bodyNode) || mounts.some(mount => nodesOverlap(table, mount))) continue;
      const identities = new Set();
      for (const link of table.querySelectorAll("a[href]")) {
        try {
          const target = new URL(link.getAttribute("href"), document.baseURI);
          if (findSiteContract(target.hostname)?.id !== contract.id) continue;
          const identity = articleIdentity(target, contract.id);
          if (identity && identity !== currentIdentity) identities.add(identity);
        } catch (_error) {}
        if (identities.size >= 2) break;
      }
      if (identities.size < 2) continue;
      let root = table;
      while (root.parentElement && !nodesOverlap(root.parentElement, bodyNode) &&
          !mounts.some(mount => nodesOverlap(root.parentElement, mount))) {
        root = root.parentElement;
      }
      roots.push(root);
    }
    return uniqueElements(roots);
  }

  function collectExactDocumentCommentEvidence(document, layout, bodyNode, seed, jsonLd) {
    const layouts = [layout];
    const explicitEvidence = explicitCommentEvidence(document, layouts);
    if (!explicitEvidence.ok) return explicitEvidence;
    const mountHints = roleHints(layouts, "comments");
    const itemHints = roleHints(layouts, "commentItems");
    const controlHints = roleHints(layouts, "commentControls");
    const ignoredHints = roleHints(layouts, "commentIgnored");
    // Other article lists may advertise their own comment counts. They are
    // not evidence that the current article has missing comments.
    const articleLists = independentArticleListRoots(document, layout, bodyNode);
    const collection = collectBoundedCandidateElements(
      document,
      "[role='feed'], [role='list'], section, div, ol, ul",
      mountHints,
      function plausibleEvidenceMount(element) {
        if (
          element === bodyNode ||
          insideAnyRoot(element, articleLists) ||
          element.contains(bodyNode) ||
          bodyNode.contains(element) ||
          !followsNode(element, bodyNode) ||
          element.matches("[itemtype*='schema.org/Comment'], [itemprop='comment']") ||
         elementMatchesAny(element, itemHints) ||
          elementMatchesAny(element, controlHints) ||
          elementMatchesAny(element, ignoredHints) ||
          isFormOnlyCommentEvidenceSurface(element) ||
          (element.parentElement && !elementMatchesAny(element, mountHints) &&
            hasSingularSemanticCommentIdentity(element) &&
            COMMENT_TOKEN_PATTERN.test(semanticTokenText(element.parentElement)))
        ) {
          return false;
        }
        const configuredMounts = queryAllSafe(element, mountHints);
        if (
          configuredMounts.length > 0 &&
          queryAllSafe(element, itemHints).length === 0 &&
          queryAllSafe(element, controlHints).length > 0
        ) {
          return false;
        }
        const excludedRoots = commentClassificationRoots(element, controlHints, ignoredHints);
        return COMMENT_TOKEN_PATTERN.test(
          `${semanticTokenText(element)} ${truncateText(element.textContent, 180)}`
        ) || repeatedSiblingCount(element, excludedRoots) >= 2 ||
          element.matches("[role='feed'], [role='list']");
      },
    );
    if (!collection.ok) {
      return Object.freeze({
        ok: false,
        reason: "comments-candidate-bound",
        count: collection.count,
        elements: Object.freeze([]),
      });
    }
    const evaluations = collection.elements.map(function exactEvidenceCandidate(element) {
      return {
        node: element,
        features: commentFeatures(
          element,
          bodyNode,
          jsonLd,
          seed,
          itemHints,
          controlHints,
          ignoredHints,
        ),
      };
    });
    return precomputeCommentEvidence(
      evaluations,
      explicitEvidence,
      layouts,
      new WeakMap(),
    );
  }

  function parseVisibleCommentTotal(value) {
    const text = String(value || "").normalize("NFKC").replace(/\s+/gu, " ").trim();
    if (!text || text.length > 96) return null;
    const patterns = [
      /^(?:댓글|덧글|코멘트)\s*(?:[|｜:：·•-]\s*)?(?:총\s*)?(\d{1,7})\s*(?:개|건)?$/iu,
      /^총\s*(\d{1,7})\s*(?:개|건|개의)?\s*(?:댓글|덧글|코멘트)$/iu,
      /^(?:comments|replies)\s*(?:[|:·•-]\s*)?(?:total\s*)?(\d{1,7})$/iu,
      /^コメント\s*(?:[|｜:：·•-]\s*)?(?:全\s*)?(\d{1,7})\s*件?$/iu,
    ];
    for (const pattern of patterns) {
      const match = text.match(pattern);
      if (match) return Number.parseInt(match[1], 10);
    }
    return null;
  }

  function isCommentContinuationControl(control) {
    if (!control || !isRendered(control)) {
      return false;
    }
    const visibleText = normalizeProjectionTokenText([
      control.getAttribute("aria-label"),
      control.getAttribute("title"),
      control.textContent,
    ].join(" "));
    const semanticText = normalizeProjectionTokenText([
      semanticTokenText(control),
      projectionNoiseMetadataText(control),
    ].join(" "));
    if (
      COMMENT_CONTINUATION_PATTERN.test(visibleText) ||
      COMMENT_STRUCTURAL_CONTINUATION_PATTERN.test(semanticText)
    ) {
      return true;
    }
    // A bare Reply button commonly opens a composer and does not prove that
    // existing replies are hidden. Treat it as a continuation only when it
    // explicitly reveals a reply set, names a reply count, or exposes state.
    return COMMENT_REPLY_TOKEN_PATTERN.test(visibleText) && (
      COMMENT_REPLY_REVEAL_PATTERN.test(visibleText) ||
      COMMENT_REPLY_COUNT_PATTERN.test(visibleText) ||
      control.hasAttribute("aria-expanded") ||
      control.hasAttribute("aria-controls")
    );
  }

  function hasVisibleCommentContinuationControl(commentControls) {
    return commentControls.some(isCommentContinuationControl);
  }

  function visibleCommentTotalEvidence(commentMount, boundaryRoot, excludedRoots) {
    if (!commentMount || !boundaryRoot || (
      commentMount !== boundaryRoot && !boundaryRoot.contains(commentMount)
    )) {
      return Object.freeze({ ok: false, count: null, source: "invalid-boundary" });
    }
    const excluded = excludedRoots || [];
    let shell = commentMount;
    for (let depth = 0; shell && depth <= 6; depth += 1) {
      const values = new Map();
      const candidates = [shell].concat(Array.from(shell.querySelectorAll("*")));
      for (const candidate of candidates) {
        if (!isRendered(candidate) || insideAnyRoot(candidate, excluded)) continue;
        const count = parseVisibleCommentTotal(candidate.textContent);
        if (count === null) continue;
        if (!values.has(count)) values.set(count, []);
        values.get(count).push(candidate);
      }
      if (values.size > 1) {
        return Object.freeze({
          ok: false,
          count: null,
          source: "conflicting-visible-comment-totals",
          elements: Object.freeze([]),
        });
      }
      if (values.size === 1) {
        const entry = Array.from(values.entries())[0];
        return Object.freeze({
          ok: true,
          count: entry[0],
          source: "visible-comment-total",
          elements: Object.freeze(entry[1]),
        });
      }
      if (shell === boundaryRoot) break;
      shell = shell.parentElement;
      if (!shell || (shell !== boundaryRoot && !boundaryRoot.contains(shell))) break;
    }
    return Object.freeze({
      ok: true,
      count: null,
      source: null,
      elements: Object.freeze([]),
    });
  }

  function commentsAreExhaustive(
    tuple,
    layouts,
    seed,
    jsonLd,
    commentPool,
    commentEvidence,
  ) {
    const comments = tuple.comments.node;
    const evidenceInsideRoot = commentEvidence;
    const seedCount = Number.isInteger(seed?.commentCount) ? seed.commentCount : null;
    const metadataCount = Number.isInteger(jsonLd.commentCount) ? jsonLd.commentCount : null;
    const apparentItemCount = tuple.comments.features?.apparentItemCount || 0;
    const observedItemCount = evidenceInsideRoot.length || apparentItemCount;
    const visibleTotal = visibleCommentTotalEvidence(
      comments,
      tuple.root,
      evidenceInsideRoot,
    );
    if (
      !visibleTotal.ok ||
      (visibleTotal.count !== null && observedItemCount !== visibleTotal.count) ||
      (seedCount !== null && observedItemCount < seedCount) ||
      (metadataCount !== null && observedItemCount < metadataCount)
    ) {
      return false;
    }
    const emptyAllowed = layouts.every(function allowsEmpty(layout) {
      return layout.allowEmptyComments === true;
    });
    const exactDomObservedEmpty = visibleTotal.count === null &&
      evidenceInsideRoot.length === 0 &&
      apparentItemCount === 0 &&
      emptyAllowed &&
      stableEmptyCommentMount(tuple.comments, layouts);
    if (visibleTotal.count === 0 || exactDomObservedEmpty) {
      if (
        evidenceInsideRoot.length > 0 ||
        apparentItemCount > 0 ||
        !emptyAllowed ||
        !stableEmptyCommentMount(tuple.comments, layouts)
      ) {
        return false;
      }
    } else if (evidenceInsideRoot.length) {
      if (
        evidenceInsideRoot.includes(comments) ||
        evidenceInsideRoot.some(function hiddenCommentEvidence(element) {
          return !isRendered(element);
        }) ||
        evidenceInsideRoot.some(function evidenceEscapesMount(element) {
          return (tuple.root !== element && !tuple.root.contains(element)) ||
            (comments !== element && !comments.contains(element));
        })
      ) {
        return false;
      }
    } else {
      return false;
    }
    const containingCompetitors = commentPool.filter(function narrowerCompleteMount(candidate) {
      if (candidate === tuple.comments || !comments.contains(candidate.node)) return false;
      if (evidenceInsideRoot.length) {
        return evidenceInsideRoot.every(function containedEvidence(element) {
          return candidate.node === element || candidate.node.contains(element);
        });
      }
      return stableEmptyCommentMount(candidate, layouts);
    });
    return containingCompetitors.length === 0;
  }

  function validateProjectionTuple(
    tuple,
    document,
    layouts,
    seed,
    jsonLd,
    titlePool,
    commentPool,
    commentEvidence,
  ) {
    const titleNode = tuple.title.node;
    const bodyNode = tuple.body.node;
    const commentsNode = tuple.comments.node;
    const productNode = tuple.product?.node || null;
    const roleNodes = [titleNode, bodyNode, commentsNode].concat(productNode ? [productNode] : []);
    if (
      roleNodes.some(function unavailable(node) {
        const stableEmptyComments = node === commentsNode &&
          stableEmptyCommentMount(tuple.comments, layouts);
        return !node?.isConnected || (!isRendered(node) && !stableEmptyComments) ||
          node === document.documentElement || node === document.body;
      }) ||
      new Set(roleNodes).size !== roleNodes.length ||
      nodesOverlap(titleNode, bodyNode) ||
      nodesOverlap(titleNode, commentsNode) ||
      nodesOverlap(bodyNode, commentsNode) ||
      !followsNode(bodyNode, titleNode) ||
      !followsNode(commentsNode, bodyNode) ||
      tuple.body.features?.hasNoise === true ||
      tuple.product?.features?.hasNoise === true
    ) {
      return null;
    }
    if (productNode) {
      const nestedInTitle = titleNode.contains(productNode);
      const orderedAroundBody = nestedInTitle || (
        followsNode(productNode, titleNode) && (
          followsNode(bodyNode, productNode) || followsNode(productNode, bodyNode)
        )
      );
      if (
        nodesOverlap(productNode, bodyNode) ||
        nodesOverlap(productNode, commentsNode) ||
        productNode.contains(titleNode) ||
        !orderedAroundBody ||
        !followsNode(commentsNode, productNode)
      ) {
        return null;
      }
    }
    const root = lowestCommonAncestor(roleNodes);
    if (!root || root === document.documentElement || root === document.body || !isRendered(root)) {
      return null;
    }
    const competingTitle = titlePool.some(function disconnectedTitleInsideRoot(candidate) {
      if (candidate === tuple.title) return false;
      return candidate.members.some(function memberInsideRoot(member) {
        return root === member || root.contains(member);
      });
    });
    if (competingTitle) return null;
    const completeTuple = { ...tuple, root };
    if (!commentsAreExhaustive(
      completeTuple,
      layouts,
      seed,
      jsonLd,
      commentPool,
      commentEvidence,
    )) {
      return null;
    }
    return Object.freeze({
      root,
      productOrder: productNode
        ? followsNode(productNode, bodyNode) ? "after-body" : "before-body"
        : null,
    });
  }

  function projectionTupleScore(tuple) {
    return tuple.title.score + tuple.body.score + tuple.comments.score +
      (tuple.product ? tuple.product.score : 0);
  }

  function auditEvaluation(evaluation, pool) {
    const alternativeScores = pool.filter(function otherCandidate(candidate) {
      return candidate !== evaluation;
    }).map(function candidateScore(candidate) { return candidate.score; });
    const nextScore = alternativeScores.length ? Math.max(...alternativeScores) : evaluation.score;
    return Object.freeze({
      node: evaluation.node,
      count: pool.length,
      score: Number(evaluation.score.toFixed(3)),
      signalCount: independentSignalCount(evaluation.signals),
      margin: Number(Math.max(0, evaluation.score - nextScore).toFixed(3)),
    });
  }

  const PROPOSAL_UNSTABLE_SELECTOR_TOKEN_PATTERN = /^(?:active|current|selected|open|closed|show|shown|hide|hidden|loading|loaded|desktop|mobile|tablet|hover|focus|js|is-|has-)/iu;

  function proposalStableToken(value) {
    const token = String(value || "");
    return /^[A-Za-z_][A-Za-z0-9_-]{0,63}$/u.test(token) &&
      !PROPOSAL_UNSTABLE_SELECTOR_TOKEN_PATTERN.test(token) &&
      !/(?:^|[-_])\d{5,}(?:$|[-_])/u.test(token) &&
      !/^[a-f0-9]{12,}$/iu.test(token) &&
      !token.startsWith("data-hotdeal-focus");
  }

  function proposalSelectorCandidates(element) {
    const tag = element.tagName.toLocaleLowerCase();
    const candidates = [];
    if (proposalStableToken(element.id)) candidates.push(`#${element.id}`);
    const classes = Array.from(element.classList || [])
      .filter(proposalStableToken)
      .sort()
      .slice(0, 4);
    for (let size = Math.min(3, classes.length); size >= 1; size -= 1) {
      const choose = function chooseClass(start, selected) {
        if (selected.length === size) {
          const suffix = selected.map(function classSelector(token) { return `.${token}`; }).join("");
          candidates.push(suffix, `${tag}${suffix}`);
          return;
        }
        for (let index = start; index < classes.length; index += 1) {
          choose(index + 1, selected.concat(classes[index]));
        }
      };
      choose(0, []);
    }
    ["itemprop", "role"].forEach(function stableSemanticAttribute(name) {
      const value = element.getAttribute(name);
      if (value && /^[A-Za-z0-9_ -]{1,48}$/u.test(value)) {
        const escaped = value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
        candidates.push(`${tag}[${name}="${escaped}"]`);
      }
    });
    candidates.push(tag);
    return Array.from(new Set(candidates));
  }

  function stableExactProposalSelector(document, element) {
    for (const selector of proposalSelectorCandidates(element)) {
      try {
        const matches = document.querySelectorAll(selector);
        if (matches.length === 1 && matches[0] === element) return selector;
      } catch (_error) {
        // Only syntactically exact, document-unique selectors are proposed.
      }
    }
    return null;
  }

  function stableScopedProposalSelector(document, pageRootProposal, element) {
    const direct = stableExactProposalSelector(document, element);
    if (direct) return direct;
    const root = pageRootProposal?.node || null;
    const rootSelector = pageRootProposal?.selector || null;
    if (!root || !rootSelector || root === element || !root.contains(element)) return null;
    for (const localSelector of proposalSelectorCandidates(element)) {
      try {
        const localMatches = root.querySelectorAll(localSelector);
        if (localMatches.length !== 1 || localMatches[0] !== element) continue;
        const scopedSelector = `${rootSelector} ${localSelector}`;
        const documentMatches = document.querySelectorAll(scopedSelector);
        if (documentMatches.length === 1 && documentMatches[0] === element) {
          return scopedSelector;
        }
      } catch (_error) {
        // Both the local and composed selector must be exact in the captured document.
      }
    }
    const localSelectors = proposalSelectorCandidates(element).slice(0, 16);
    let ancestor = element.parentElement;
    let combinations = 0;
    for (
      let depth = 0;
      ancestor && ancestor !== root && depth < 4;
      depth += 1, ancestor = ancestor.parentElement
    ) {
      const ancestorTag = ancestor.tagName.toLocaleLowerCase();
      const ancestorSelectors = proposalSelectorCandidates(ancestor)
        .filter(function stableAncestorToken(selector) {
          return selector !== ancestorTag;
        })
        .slice(0, 16);
      for (const ancestorSelector of ancestorSelectors) {
        for (const localSelector of localSelectors) {
          const scopedCandidates = [
            `${ancestorSelector} ${localSelector}`,
            `${rootSelector} ${ancestorSelector} ${localSelector}`,
          ];
          for (const scopedSelector of scopedCandidates) {
            combinations += 1;
            if (combinations > 256) return null;
            try {
              const matches = document.querySelectorAll(scopedSelector);
              if (matches.length === 1 && matches[0] === element) {
                return scopedSelector;
              }
            } catch (_error) {
              // Every compound is re-proven document-global before promotion.
            }
          }
        }
      }
    }
    return null;
  }

  function stableProposalPageRoot(document, roleRoot, roleNodes) {
    for (
      let candidate = roleRoot;
      candidate && candidate !== document.body && candidate !== document.documentElement;
      candidate = candidate.parentElement
    ) {
      if (
        !isRendered(candidate) ||
        !roleNodes.every(function roleInsideCandidate(roleNode) {
          return candidate === roleNode || candidate.contains(roleNode);
        })
      ) {
        continue;
      }
      const selector = stableExactProposalSelector(document, candidate);
      if (!selector) continue;
      return Object.freeze({
        selector,
        node: candidate,
        evidence: candidate === roleRoot
          ? "all-role-lowest-common-ancestor"
          : "nearest-unique-stable-all-role-ancestor",
      });
    }
    return Object.freeze({ selector: null, node: null, evidence: null });
  }

  function ignoredSelectorProposal(document, roots) {
    const selectors = [];
    let unstableCount = 0;
    Array.from(roots || []).forEach(function exactIgnoredRoot(root) {
      const selector = stableExactProposalSelector(document, root);
      if (!selector) {
        unstableCount += 1;
      } else if (!selectors.includes(selector)) {
        selectors.push(selector);
      }
    });
    return Object.freeze({
      selectors: Object.freeze(selectors.sort()),
      unstableCount,
    });
  }

  function proposalShapeFingerprint(value) {
    const source = JSON.stringify(value);
    let hash = 2166136261;
    for (let index = 0; index < source.length; index += 1) {
      hash ^= source.charCodeAt(index);
      hash = Math.imul(hash, 16777619) >>> 0;
    }
    return `projection-policy-v1-${hash.toString(16).padStart(8, "0")}`;
  }

  function buildPolicyProposal(document, winner) {
    const productNode = winner.product?.node || null;
    const roleNodes = [winner.title.node, winner.body.node, winner.comments.node]
      .concat(productNode ? [productNode] : []);
    const pageRootProposal = stableProposalPageRoot(document, winner.root, roleNodes);
    const pageRoot = pageRootProposal.selector;
    const productSelector = productNode
      ? stableScopedProposalSelector(document, pageRootProposal, productNode)
      : null;
    const bodyIgnored = ignoredSelectorProposal(
      document,
      winner.body.features?.autonomousIgnored?.roots || [],
    );
    const productIgnored = ignoredSelectorProposal(
      document,
      winner.product?.features?.autonomousIgnored?.roots || [],
    );
    const commentIgnoredDiscovery = discoverAutonomousIgnoredRoots(
      winner.comments.node,
      winner.commentEvidence || [],
    );
    const commentIgnored = ignoredSelectorProposal(
      document,
      commentIgnoredDiscovery.ok ? commentIgnoredDiscovery.roots : [],
    );
    const productOrder = productNode
      ? followsNode(productNode, winner.body.node) ? "after-body" : "before-body"
      : null;
    const product = Object.freeze({
      cardinality: productNode ? "required" : "zero",
      order: productOrder,
      selectors: Object.freeze(productSelector ? [productSelector] : []),
    });
    const shape = {
      pageRoot,
      product,
      bodyIgnored: bodyIgnored.selectors,
      productIgnored: productIgnored.selectors,
      commentIgnored: commentIgnored.selectors,
      roleShapes: {
        title: childFingerprint(winner.title.node),
        body: childFingerprint(winner.body.node),
        product: productNode ? childFingerprint(productNode) : null,
        comments: childFingerprint(winner.comments.node),
      },
    };
    const complete = Boolean(pageRoot) &&
      (!productNode || Boolean(productSelector)) &&
      bodyIgnored.unstableCount === 0 &&
      productIgnored.unstableCount === 0 &&
      commentIgnored.unstableCount === 0 &&
      commentIgnoredDiscovery.ok;
    return Object.freeze({
      schemaVersion: 1,
      source: "independent-projection-tuple",
      complete,
      pageRoot,
      pageRootEvidence: pageRootProposal.evidence,
      product,
      bodyIgnored: bodyIgnored.selectors,
      productIgnored: productIgnored.selectors,
      commentIgnored: commentIgnored.selectors,
      safety: Object.freeze({
        strictDescendantsOnly: true,
        strongStructuralNoiseOnly: true,
        meaningfulTextPriceAndPurchaseLinksExcluded: true,
      }),
      shapeFingerprint: proposalShapeFingerprint(shape),
      promotionGate: Object.freeze({
        promotable: false,
        requiredDistinctUrlsPerProfile: 3,
        requiredProfilesSource: "auditor-layout-contract",
        requiredMatchingShapeFingerprint: true,
      }),
    });
  }

  function failedSemanticContract(reason, projectionTupleCount, candidateCounts) {
    const roles = {};
    Object.entries(candidateCounts || {}).forEach(function failedRole(entry) {
      roles[entry[0]] = Object.freeze({
        node: null,
        count: entry[1],
        score: 0,
        signalCount: 0,
        margin: 0,
      });
    });
    return Object.freeze({
      ok: false,
      reason,
      projectionTupleCount,
      roles: Object.freeze(roles),
      seedConsistency: null,
    });
  }

  function discoverSemanticContract(document, layouts, seed) {
    const jsonLd = collectJsonLd(document);
    const titleEvaluationResult = titleCandidateEvaluations(document, layouts, seed, jsonLd);
    if (!titleEvaluationResult.ok) {
      return failedSemanticContract("title-candidate-bound", 0, {
        title: titleEvaluationResult.count,
      });
    }
    const titleEvaluations = titleEvaluationResult.evaluations;
    const evidenceApproved = seed
      ? titleEvaluations.filter(function provenTitle(evaluation) {
          return evaluation.titleEvidence?.ok === true;
        })
      : titleEvaluations;
    const boundedTitles = boundedRolePool(evidenceApproved, ROLE_POLICIES.title);
    if (!boundedTitles.ok) {
      return failedSemanticContract("title-candidate-bound", 0, {
        title: boundedTitles.ranked.length,
      });
    }
    const titlePool = collapseProvenTitleWrappers(boundedTitles.ranked);
    if (!titlePool.length) {
      return failedSemanticContract("title-evidence", 0, { title: 0 });
    }
    const configuredProductCardinality = semanticProductCardinality(layouts);
    const configuredProductOrder = semanticProductOrder(
      layouts,
      configuredProductCardinality,
    );
    const explicitEvidence = explicitCommentEvidence(document, layouts);
    if (!explicitEvidence.ok) {
      return failedSemanticContract(explicitEvidence.reason, 0, {
        title: titlePool.length,
        comments: explicitEvidence.count,
      });
    }
    const inferredCommentEvidenceCache = new WeakMap();
    const tuples = [];
    let combinationsEvaluated = 0;
    let overflowReason = null;
    let largestBodyPool = 0;
    let largestCommentPool = 0;
    let largestProductPool = 0;

    titlePool.forEach(function enumerateTitle(title) {
      if (overflowReason) return;
      const bodyPoolResult = boundedDecisionPool(selectBody(document, layouts, title.node));
      largestBodyPool = Math.max(largestBodyPool, bodyPoolResult.count);
      if (!bodyPoolResult.ok) {
        overflowReason = "body-candidate-bound";
        return;
      }
      bodyPoolResult.ranked.forEach(function enumerateBody(body) {
        if (overflowReason) return;
        const commentPoolResult = boundedDecisionPool(
          selectComments(document, layouts, body.node, jsonLd, seed, explicitEvidence.elements)
        );
        largestCommentPool = Math.max(largestCommentPool, commentPoolResult.count);
        if (!commentPoolResult.ok) {
          overflowReason = "comments-candidate-bound";
          return;
        }
        const commentEvidenceResult = precomputeSemanticCommentEvidence(
          commentPoolResult.ranked,
          explicitEvidence,
          layouts,
          inferredCommentEvidenceCache,
        );
        if (!commentEvidenceResult.ok) {
          overflowReason = commentEvidenceResult.reason;
          largestCommentPool = Math.max(largestCommentPool, commentEvidenceResult.count);
          return;
        }
        const productPoolResult = boundedDecisionPool(
          selectProduct(document, layouts, title.node, body.node)
        );
        largestProductPool = Math.max(largestProductPool, productPoolResult.count);
        if (!productPoolResult.ok) {
          overflowReason = "product-candidate-bound";
          return;
        }
        const productPool = productPoolResult.ranked;
        const productChoices = [null].concat(productPool);
        commentPoolResult.ranked.forEach(function enumerateComments(comments) {
          if (overflowReason) return;
          const tupleCommentEvidence = commentEvidenceResult.evidenceByCandidate.get(comments) || [];
          productChoices.forEach(function enumerateProduct(product) {
            if (overflowReason) return;
            combinationsEvaluated += 1;
            if (combinationsEvaluated > MAX_PROJECTION_TUPLES) {
              overflowReason = "projection-tuple-bound";
              return;
            }
            const tuple = {
              title,
              body,
              comments,
              product,
              commentEvidence: tupleCommentEvidence,
              pools: {
                title: titlePool,
                body: bodyPoolResult.ranked,
                comments: commentPoolResult.ranked,
                product: productPool,
              },
            };
            const validation = validateProjectionTuple(
              tuple,
              document,
              layouts,
              seed,
              jsonLd,
              titlePool,
              commentPoolResult.ranked,
              tupleCommentEvidence,
            );
            if (validation) {
              tuples.push(Object.freeze({
                ...tuple,
                root: validation.root,
                productOrder: validation.productOrder,
                score: projectionTupleScore(tuple),
              }));
            }
          });
        });
      });
    });
    const candidateCounts = {
      title: titlePool.length,
      body: largestBodyPool,
      comments: largestCommentPool,
    };
    candidateCounts.product = largestProductPool;
    if (overflowReason) {
      return failedSemanticContract(overflowReason, 0, candidateCounts);
    }
    if (!tuples.length) {
      return failedSemanticContract("no-complete-projection-tuple", 0, candidateCounts);
    }
    const distinctRoots = new Set(tuples.map(function projectionRoot(tuple) { return tuple.root; }));
    if (distinctRoots.size > 1) {
      return failedSemanticContract(
        "ambiguous-disconnected-projections",
        tuples.length,
        candidateCounts,
      );
    }
    tuples.sort(function rankProjectionTuples(left, right) {
      if (right.score !== left.score) return right.score - left.score;
      const roleOrder = ["title", "body", "comments", "product"];
      for (const role of roleOrder) {
        if (!left[role] || !right[role]) continue;
        const order = documentOrder(left[role].node, right[role].node);
        if (order) return order;
      }
      return 0;
    });
    const winner = tuples[0];
    const runnerUp = tuples[1];
    if (runnerUp && winner.score - runnerUp.score < PROJECTION_TUPLE_MARGIN) {
      return failedSemanticContract(
        "ambiguous-projection-tuples",
        tuples.length,
        candidateCounts,
      );
    }
    const roles = {
      title: auditEvaluation(winner.title, winner.pools.title),
      body: auditEvaluation(winner.body, winner.pools.body),
      comments: auditEvaluation(winner.comments, winner.pools.comments),
    };
    if (winner.product) {
      roles.product = auditEvaluation(winner.product, winner.pools.product);
    }
    const resolvedTitleEvidence = seed
      ? winner.title.titleEvidence ||
        titleEvidence(document, seed.title, winner.title.node.textContent, jsonLd)
      : null;
    const seedConsistency = seed
      ? Object.freeze({
          titleSimilarity: resolvedTitleEvidence.score,
          titleConsistencyOk: resolvedTitleEvidence.ok,
          titleMode: resolvedTitleEvidence.mode,
          metadataSourceCount: resolvedTitleEvidence.metadata.sourceCount,
          metadataSourceKinds: resolvedTitleEvidence.metadata.sourceKinds,
          commentCountComparable: seed.commentCount !== null,
          commentCount: seed.commentCount,
        })
      : null;
    const observedProductCardinality = winner.product ? "required" : "zero";
    const existingProductPolicyCompatible =
      (configuredProductCardinality === "optional" ||
        configuredProductCardinality === observedProductCardinality) &&
      (!winner.product || configuredProductOrder === winner.productOrder);
    const policyProposal = buildPolicyProposal(document, winner);
    return Object.freeze({
      ok: true,
      reason: "unique-complete-projection-tuple",
      projectionTupleCount: tuples.length,
      tupleScore: Number(winner.score.toFixed(3)),
      tupleMargin: Number((runnerUp ? winner.score - runnerUp.score : winner.score).toFixed(3)),
      roles: Object.freeze(roles),
      seedConsistency,
      productOrder: winner.productOrder,
      existingPolicy: Object.freeze({
        compatible: existingProductPolicyCompatible,
        productCardinality: configuredProductCardinality,
        productOrder: configuredProductOrder,
      }),
      runtimeProjection: Object.freeze({
        commonRoot: winner.root,
        title: winner.title.node,
        body: winner.body.node,
        comments: winner.comments.node,
        product: winner.product?.node || null,
        commentItems: Object.freeze(winner.commentEvidence.slice()),
        bodyAutonomousIgnored: Object.freeze(
          Array.from(winner.body.features?.autonomousIgnored?.roots || []),
        ),
        productAutonomousIgnored: Object.freeze(
          Array.from(winner.product?.features?.autonomousIgnored?.roots || []),
        ),
        resolvedTitle: winner.title.resolvedTitle ||
          normalizeText(winner.title.node.textContent),
        productOrder: winner.productOrder,
      }),
      policyProposal,
    });
  }

  function lowestCommonAncestor(nodes) {
    if (!nodes.length || nodes.some(function missing(node) { return !node; })) {
      return null;
    }
    let candidate = nodes[0];
    while (candidate) {
      if (nodes.every(function isContained(node) { return candidate === node || candidate.contains(node); })) {
        return candidate;
      }
      candidate = candidate.parentElement;
    }
    return null;
  }

  function validateRoleRelationship(
    document,
    roles,
    requiredRoles,
    approvedPageRoot,
    allowStableZeroAreaComments,
  ) {
    const roleNodes = requiredRoles.map(function requiredNode(role) { return roles[role]; });
    if (roleNodes.some(function missingNode(node) { return !node || !node.isConnected; })) {
      return null;
    }
    if (new Set(roleNodes).size !== roleNodes.length) {
      return null;
    }
    if (!normalizeText(roles.title.textContent) || !isRendered(roles.title)) {
      return null;
    }
    const bodyHasContent = normalizeText(roles.body.textContent).length > 0 ||
      roles.body.querySelector("img, picture, video, iframe, table, a[href]");
    if (!bodyHasContent || !isRendered(roles.body)) {
      return null;
    }
    if (
      !isRendered(roles.comments) &&
      !(allowStableZeroAreaComments && isStableZeroAreaCommentMount(roles.comments))
    ) {
      return null;
    }
    if (roles.body.contains(roles.comments) || roles.comments.contains(roles.body)) {
      return null;
    }
    if (
      !approvedPageRoot ||
      approvedPageRoot === document.documentElement ||
      approvedPageRoot === document.body ||
      !roleNodes.every(function insideApprovedRoot(node) {
        return approvedPageRoot === node || approvedPageRoot.contains(node);
      })
    ) {
      return null;
    }
    const naturalCommonRoot = lowestCommonAncestor(roleNodes);
    if (!naturalCommonRoot || !approvedPageRoot.contains(naturalCommonRoot)) {
      return null;
    }
    return approvedPageRoot;
  }

  function insideAnyRoot(element, roots) {
    return roots.some(function insideRoot(root) {
      return root === element || root.contains(element);
    });
  }

  function insideCommentProjection(state, element) {
    if (!state || !element) return false;
    const insideTrackedControl = Array.from(state.commentControlRoots).some(
      function matchingTrackedControl(control) {
        return control === element || control.contains(element);
      },
    );
    const insideExternalControlParent = Array.from(
      state.commentControlMutationRoots || [],
    ).some(function matchingExternalControlParent(parent) {
      return parent === element || parent.contains(element);
    });
    return state.roles.comments === element ||
      state.roles.comments.contains(element) ||
      insideTrackedControl || insideExternalControlParent;
  }

  function roleClass(role) {
    return `${CLASS.rolePrefix}${role}`;
  }

  function hdfClasses(element) {
    return Array.from(element.classList || [])
      .filter(function ownedClass(className) { return HDF_CLASS_PATTERN.test(className); })
      .sort();
  }

  function projectionHdfClasses(element) {
    return hdfClasses(element).filter(function notRootGateClass(className) {
      return element === element.ownerDocument?.documentElement
        ? className !== CLASS.lock && className !== CLASS.ready
        : true;
    });
  }

  function removeHdfClasses(element) {
    const classes = hdfClasses(element);
    if (classes.length > 0) element.classList.remove(...classes);
  }

  function removeKnownProjectionMarkers(element) {
    [ATTR.keep, ATTR.shell, ATTR.deep, ATTR.role].forEach(function removeAttribute(attribute) {
      element.removeAttribute(attribute);
    });
    [CLASS.keep, CLASS.shell, CLASS.deep].forEach(function removeClass(className) {
      element.classList.remove(className);
    });
    hdfClasses(element)
      .filter(function roleMarker(className) { return className.startsWith(CLASS.rolePrefix); })
      .forEach(function removeRoleClass(className) { element.classList.remove(className); });
  }

  function stripOwnedAttributes(element, preservedOwnedElements) {
    if (!element || element.nodeType !== 1) {
      return;
    }
    [element].concat(Array.from(element.querySelectorAll("*"))).forEach(
      function removeAllReservedPublisherMarkers(candidate) {
        if (preservedOwnedElements?.has(candidate)) return;
        Array.from(candidate.attributes || []).forEach(function removeReserved(attribute) {
          if (attribute.name.startsWith(HDF_ATTRIBUTE_PREFIX)) {
            candidate.removeAttribute(attribute.name);
          }
        });
        removeHdfClasses(candidate);
      }
    );
  }

  function markOwned(element, ownedElements, nonce) {
    element.setAttribute(ATTR.keep, nonce);
    element.classList.add(CLASS.keep);
    ownedElements.add(element);
  }

  function markDeepSubtree(rootNode, role, ownedElements, nonce, ignoredRoots) {
    const excludedRoots = ignoredRoots || [];
    const stack = [rootNode];
    while (stack.length) {
      const element = stack.pop();
      if (element !== rootNode && insideAnyRoot(element, excludedRoots)) {
        stripOwnedAttributes(element);
        continue;
      }
      markOwned(element, ownedElements, nonce);
      element.setAttribute(ATTR.deep, role);
      element.classList.add(CLASS.deep);
      if (element === rootNode) {
        element.setAttribute(ATTR.role, role);
        element.classList.add(roleClass(role));
      }
      Array.from(element.children).reverse().forEach(function queueChild(child) {
        stack.push(child);
      });
    }
  }

  function markAncestorChain(element, ownedElements, nonce, shellElements) {
    let ancestor = element;
    while (ancestor) {
      markOwned(ancestor, ownedElements, nonce);
      if (!ancestor.hasAttribute(ATTR.deep)) {
        ancestor.setAttribute(ATTR.shell, nonce);
        ancestor.classList.add(CLASS.shell);
        shellElements.add(ancestor);
      }
      ancestor = ancestor.parentElement;
    }
  }

  function hasDirectText(element) {
    return Array.from(element.childNodes).some(function nonEmptyText(node) {
      return node.nodeType === 3 && Boolean(normalizeText(node.data));
    });
  }

  function projectedTitleLeaves(titleNode, resolvedTitle) {
    const resolvedCore = normalizeText(stripBoundedTitleAffixes(resolvedTitle));
    return Array.from(titleNode.querySelectorAll("span, strong, b, em, a, div"))
      .filter(function titleTextLeaf(element) {
        if (TITLE_METADATA_PATTERN.test(semanticTokenText(element))) {
          return false;
        }
        const text = normalizeText(element.textContent);
        if (
          !text ||
          Array.from(element.children).some(function nestedTitleText(child) {
            return normalizeText(child.textContent) &&
              !TITLE_METADATA_PATTERN.test(semanticTokenText(child));
          })
        ) {
          return false;
        }
        if (textSimilarity(text, resolvedTitle) >= 0.54) {
          return true;
        }
        if (
          !resolvedCore ||
          element.parentElement !== titleNode ||
          !element.matches("span, strong, b, em") ||
          element.children.length !== 0 ||
          isStrongProjectionNoiseNode(element) ||
          AUTONOMOUS_NOISE_LABEL_PATTERN.test(
            canonicalAutonomousNoiseLabel(element.textContent),
          ) ||
          STRONG_NOISE_TOKEN_PATTERN.test(
            normalizeProjectionTokenText(element.textContent),
          )
        ) {
          return false;
        }
        const rawText = truncateRawTitle(element.textContent, 80);
        const prefixCore = normalizeText(
          stripBoundedTitleAffixes(`${rawText} ${resolvedTitle}`),
        );
        const suffixCore = normalizeText(
          stripBoundedTitleAffixes(`${resolvedTitle} ${rawText}`),
        );
        return prefixCore === resolvedCore || suffixCore === resolvedCore;
      });
  }

  function shallowTitleSurfaceHasRisk(titleNode, resolvedTitle, inspect) {
    return [titleNode].concat(projectedTitleLeaves(titleNode, resolvedTitle))
      .some(function unsafeProjectedTitleElement(element) {
        return !isRendered(element) ||
          inspect(element, Array.from(element.children));
      });
  }

  function markShallowTitle(titleNode, resolvedTitle, ownedElements, nonce, shellElements) {
    markAncestorChain(titleNode, ownedElements, nonce, shellElements);
    titleNode.setAttribute(ATTR.role, "title");
    titleNode.classList.add(roleClass("title"));
    const leafCandidates = projectedTitleLeaves(titleNode, resolvedTitle);
    leafCandidates.forEach(function markOriginalTitleLeaf(leaf) {
      markOwned(leaf, ownedElements, nonce);
      leaf.setAttribute(ATTR.role, "title-text");
      leaf.classList.add(roleClass("title-text"));
      markAncestorChain(leaf, ownedElements, nonce, shellElements);
    });
    return hasDirectText(titleNode) || Array.from(titleNode.children).some(function ownedChild(child) {
      return ownedElements.has(child) && normalizeText(child.textContent);
    });
  }

  function clearProtocolState(document) {
    document.querySelectorAll(
      `[${ATTR.keep}], [${ATTR.shell}], [${ATTR.deep}], [${ATTR.role}], ` +
      `.${CLASS.keep}, .${CLASS.shell}, .${CLASS.deep}, [class*="${CLASS.rolePrefix}"]`
    ).forEach(function clearOneMarkedElement(element) {
      removeKnownProjectionMarkers(element);
    });
    const html = document.documentElement;
    if (html.hasAttribute(ATTR.ready)) html.removeAttribute(ATTR.ready);
    if (html.hasAttribute(ATTR.protocol)) html.removeAttribute(ATTR.protocol);
    if (html.classList.contains(CLASS.ready)) html.classList.remove(CLASS.ready);
  }

  function removePublisherHdfMarkers(document) {
    const root = document.documentElement;
    if (!root) return false;
    [root].concat(Array.from(root.querySelectorAll("*"))).forEach(
      function removeReservedPublisherMarkers(element) {
        Array.from(element.attributes || []).forEach(function removeReservedAttribute(attribute) {
          if (attribute.name.startsWith(HDF_ATTRIBUTE_PREFIX)) {
            element.removeAttribute(attribute.name);
          }
        });
        removeHdfClasses(element);
      }
    );
    return true;
  }

  function inlinePropertySnapshot(element, property) {
    return Object.freeze({
      property,
      value: element.style.getPropertyValue(property),
      priority: element.style.getPropertyPriority(property),
    });
  }

  function applyInlinePropertySnapshot(element, snapshot) {
    if (snapshot.value) {
      element.style.setProperty(snapshot.property, snapshot.value, snapshot.priority);
    } else {
      element.style.removeProperty(snapshot.property);
    }
  }

  function claimBootstrapLock(document, removePublisherMarkers = true) {
    const html = document.documentElement;
    if (!html) return null;
    const declarations = Object.freeze([
      ["animation", BOOTSTRAP_INLINE_LOCK.animation],
      ["caret-color", BOOTSTRAP_INLINE_LOCK.caretColor],
      ["clip-path", BOOTSTRAP_INLINE_LOCK.clipPath],
      ["content-visibility", BOOTSTRAP_INLINE_LOCK.contentVisibility],
      ["opacity", BOOTSTRAP_INLINE_LOCK.opacity],
      ["pointer-events", BOOTSTRAP_INLINE_LOCK.pointerEvents],
      ["transition", BOOTSTRAP_INLINE_LOCK.transition],
      ["visibility", BOOTSTRAP_INLINE_LOCK.visibility],
    ]);
    let previous = [];
    let claimedDeclarations = [];
    let restored = false;
    const restorePublisherDeclarations = function restorePublisherDeclarations() {
      if (restored) return true;
      let restoredAll = true;
      previous.forEach(function restoreDeclaration(snapshot) {
        try {
          applyInlinePropertySnapshot(html, snapshot);
        } catch (_error) {
          restoredAll = false;
        }
      });
      BOOTSTRAP_PUBLISHER_INLINE.delete(html);
      restored = true;
      return restoredAll;
    };
    const abandonLock = function abandonLock() {
      restorePublisherDeclarations();
      try { html.removeAttribute(ATTR.lock); } catch (_error) {}
      try { html.removeAttribute(ATTR.state); } catch (_error) {}
      try { html.classList.remove(CLASS.lock); } catch (_error) {}
      return null;
    };
    try {
      if (removePublisherMarkers && !removePublisherHdfMarkers(document)) {
        return null;
      }
      previous = Object.freeze(
        declarations.map(function captureDeclaration([property]) {
          return inlinePropertySnapshot(html, property);
        })
      );
      BOOTSTRAP_PUBLISHER_INLINE.set(
        html,
        Object.freeze(Object.fromEntries(previous.map(function indexSnapshot(snapshot) {
          return [snapshot.property, snapshot];
        }))),
      );
      declarations.forEach(function applyGeometryPreservingLock([property, value]) {
        html.style.setProperty(property, value, "important");
      });
      claimedDeclarations = Object.freeze(
        declarations.map(function captureClaimedDeclaration([property]) {
          return Object.freeze([
            property,
            html.style.getPropertyValue(property),
            html.style.getPropertyPriority(property),
          ]);
        })
      );
      if (claimedDeclarations.some(function failedInlineClaim([, value, priority]) {
        return !value || priority !== "important";
      })) {
        return abandonLock();
      }
      html.classList.add(CLASS.lock);
      html.setAttribute(ATTR.lock, "1");
      html.setAttribute(ATTR.state, "locked");
    } catch (_error) {
      return abandonLock();
    }
    return Object.freeze({
      intact() {
        return !restored &&
          html.classList.contains(CLASS.lock) &&
          html.getAttribute(ATTR.lock) === "1" &&
          claimedDeclarations.every(function exactInlineLock([property, value, priority]) {
            return html.style.getPropertyValue(property) === value &&
              html.style.getPropertyPriority(property) === priority;
          });
      },
      isRestored() {
        return restored;
      },
      mismatchProperty() {
        if (restored) return "restored";
        const mismatch = claimedDeclarations.find(
          function mismatchedInlineLock([property, value, priority]) {
          return html.style.getPropertyValue(property) !== value ||
              html.style.getPropertyPriority(property) !== priority;
          }
        );
        return mismatch ? mismatch[0] : "none";
      },
      restoreInline() {
        if (restored || !this.intact()) return false;
        return restorePublisherDeclarations();
      },
      restorePublisherInline() {
        return restorePublisherDeclarations();
      },
      repairInline() {
        if (restored) return false;
        claimedDeclarations.forEach(function repairClaimedProperty([property, value, priority]) {
          if (html.style.getPropertyValue(property) !== value ||
              html.style.getPropertyPriority(property) !== priority) {
            html.style.setProperty(property, value, priority);
          }
        });
        return this.intact();
      },
    });
  }

  function restorePublisherPage(document, styleElement, bootstrapLock) {
    if (!document?.documentElement) return false;
    const html = document.documentElement;
    let restored = true;
    try {
      if (styleElement?.isConnected) {
        try {
          styleElement.remove();
        } catch (_error) {
          try {
            styleElement.parentNode?.removeChild(styleElement);
          } catch (_fallbackError) {
            restored = false;
          }
        }
      }
    } finally {
      try {
        clearProtocolState(document);
      } catch (_error) {
        restored = false;
      } finally {
        try {
          bootstrapLock?.restorePublisherInline?.();
        } catch (_error) {
          restored = false;
        } finally {
          [ATTR.lock, ATTR.ready, ATTR.protocol, ATTR.state, ATTR.status, ATTR.measure]
            .forEach(function removeRootProtocolAttribute(attribute) {
              try {
                html.removeAttribute(attribute);
              } catch (_error) {
                restored = false;
              }
            });
          try {
            html.classList.remove(CLASS.lock, CLASS.ready);
          } catch (_error) {
            restored = false;
          }
        }
      }
    }
    return restored && !html.classList.contains(CLASS.lock) &&
      !html.hasAttribute(ATTR.lock) && !html.classList.contains(CLASS.ready) &&
      !html.hasAttribute(ATTR.ready) && !styleElement?.isConnected;
  }

  function orderedCommentControls(state) {
    return uniqueElements(queryAllSafe(
      state.commentControlScope,
      state.commentControlSelectors,
    )).filter(function trackedCommentControl(control) {
      return state.commentControlRoots.has(control);
    }).sort(documentOrder);
  }

  function commentControlSelectorDigest(selectors) {
    return proposalShapeFingerprint({
      kind: "comment-control-selectors",
      selectors: Array.from(new Set(selectors)).sort(),
    }).replace("projection-policy-v1-", "comment-control-selectors-v1-");
  }

  function commentControlShape(state, controls) {
    return controls.map(function controlShape(control) {
      let depth = 0;
      let ancestor = control.parentElement;
      while (ancestor && ancestor !== state.roles.comments && depth <= 16) {
        depth += 1;
        ancestor = ancestor.parentElement;
      }
      return Object.freeze({
        tag: control.tagName.toLocaleLowerCase(),
        depth: ancestor === state.roles.comments ? depth + 1 : -1,
        selectorIndexes: Object.freeze(
          state.commentControlSelectors.map(function matchingSelector(selector, index) {
            return elementMatchesAny(control, [selector]) ? index : -1;
          }).filter(function matchedSelector(index) { return index >= 0; }),
        ),
        parentShape: control.parentElement
          ? childFingerprint(control.parentElement)
          : null,
      });
    });
  }

  function commentControlShapeFingerprint(state, controls) {
    return proposalShapeFingerprint({
      kind: "comment-control-shape",
      controls: commentControlShape(state, controls),
    }).replace("projection-policy-v1-", "comment-control-shape-v1-");
  }

  function approvedDormantCommentControl(control, state) {
    return control.isConnected &&
      state.commentControlScope.contains(control) &&
      state.commentControlRoots.has(control) &&
      state.ownedElements.has(control) &&
      control.getAttribute(ATTR.role) === "comment-control" &&
      elementMatchesAny(control, state.commentControlSelectors) &&
      !containsUnprovenShadowBoundary(control, []);
  }

  function currentCommentControlProjection(state) {
    const controls = orderedCommentControls(state);
    const bounded = controls.length <= MAX_COMMENT_EVIDENCE;
    const dormant = bounded
      ? controls.filter(function currentlyDormant(control) { return !isRendered(control); })
      : [];
    const currentProjectionValid = bounded && controls.every(function exactCurrentControl(control) {
      return state.commentControlRoots.has(control) &&
        state.ownedElements.has(control) &&
        control.getAttribute(ATTR.role) === "comment-control" &&
        elementMatchesAny(control, state.commentControlSelectors);
    }) && dormant.every(function approvedDormant(control) {
      return approvedDormantCommentControl(control, state);
    });
    return Object.freeze({
      selectors: state.canonicalCommentControlSelectors,
      count: state.initialCommentControlCount,
      initiallyVisibleCount:
        state.initialCommentControlCount - state.initiallyDormantCommentControlCount,
      initiallyDormantCount: state.initiallyDormantCommentControlCount,
      initialShapeFingerprint: state.initialCommentControlShapeFingerprint,
      selectorDigest: state.commentControlSelectorDigest,
      projectionEpoch: state.projectionEpoch,
      currentCount: controls.length,
      currentVisibleCount: controls.length - dormant.length,
      currentShapeFingerprint: bounded
        ? commentControlShapeFingerprint(state, controls)
        : "comment-control-shape-v1-overflow",
      currentDormantApprovedCount: dormant.filter(function approvedDormant(control) {
        return approvedDormantCommentControl(control, state);
      }).length,
      currentProjectionValid,
    });
  }

  function applyRoleMarkers(
    document,
    roles,
    commonRoot,
    resolvedTitle,
    requiredRoles,
    commentItemSelectors,
    commentControlSelectors,
    commentIgnoredSelectors,
    projectionPolicy,
    nonce
  ) {
    clearProtocolState(document);
    const ownedElements = new WeakSet();
    const shellElements = new Set();
    const titleMarked = markShallowTitle(
      roles.title,
      resolvedTitle,
      ownedElements,
      nonce,
      shellElements
    );
    ["product", "body"].forEach(function markRole(role) {
      if (!roles[role]) {
        return;
      }
      const ignoredRoots = role === "body" ? roles.bodyIgnored : roles.productIgnored;
      markDeepSubtree(roles[role], role, ownedElements, nonce, ignoredRoots);
      markAncestorChain(roles[role], ownedElements, nonce, shellElements);
    });
    markOwned(roles.comments, ownedElements, nonce);
    roles.comments.setAttribute(ATTR.role, "comments");
    roles.comments.classList.add(roleClass("comments"));
    roles.comments.setAttribute(ATTR.shell, nonce);
    roles.comments.classList.add(CLASS.shell);
    shellElements.add(roles.comments);
    markAncestorChain(roles.comments, ownedElements, nonce, shellElements);
    roles.commentItems.forEach(function markInitialCommentItem(item) {
      markDeepSubtree(item, "comment-item", ownedElements, nonce);
      markAncestorChain(item, ownedElements, nonce, shellElements);
    });
    roles.commentControls.forEach(function markInitialCommentControl(control) {
      markDeepSubtree(control, "comment-control", ownedElements, nonce);
      markAncestorChain(control, ownedElements, nonce, shellElements);
    });
    markAncestorChain(commonRoot, ownedElements, nonce, shellElements);
    const state = {
      ownedElements,
      ownedElementSet: new Set(document.querySelectorAll(`[${ATTR.keep}="${nonce}"]`)),
      expectedMarkerShapes: new Map(),
      shellElements,
      nonce,
      roles,
      commonRoot,
      requiredRoles,
      commentItemSelectors: commentItemSelectors.slice(),
      commentControlSelectors: commentControlSelectors.slice(),
      commentIgnoredSelectors: commentIgnoredSelectors.slice(),
      commentItemRoots: new Set(roles.commentItems),
      commentControlRoots: new Set(roles.commentControls),
      commentControlScope: roles.commentControlScope || roles.comments,
      commentControlMutationRoots: new Set(
        roles.commentControls
          .filter(function externalCommentControl(control) {
            return !roles.comments.contains(control);
          })
          .map(function externalControlParent(control) { return control.parentElement; })
          .filter(function validExternalControlParent(parent) {
            return parent && (roles.commentControlScope || roles.comments).contains(parent);
          }),
      ),
      toggleableCommentControls: new Set(roles.commentDormantControls || []),
      commentIgnoredRoots: new Set(roles.commentIgnored),
      commentConfiguredIgnoredRoots: new Set(roles.commentConfiguredIgnored || []),
      commentAutonomousIgnoredRoots: new Set(roles.commentAutonomousIgnored || []),
      commentSafetyIgnoredRoots: new Set(),
      commentCountBoundary: roles.commentCountBoundary || commonRoot,
      commentTotalEvidenceRoots: new Set(roles.commentTotalEvidence || []),
      acceptedCommentCount: roles.commentItems.length,
      requiresVisibleExactCommentTotal:
        projectionPolicy.provenCommentCountSource === "visible-comment-total",
      bodyIgnoredRoots: new Set(roles.bodyIgnored),
      bodyConfiguredIgnoredRoots: new Set(roles.bodyConfiguredIgnored || []),
      bodyAutonomousIgnoredRoots: new Set(roles.bodyAutonomousIgnored || []),
      bodySafetyIgnoredRoots: new Set(),
      productIgnoredRoots: new Set(roles.productIgnored),
      productConfiguredIgnoredRoots: new Set(roles.productConfiguredIgnored || []),
      productAutonomousIgnoredRoots: new Set(roles.productAutonomousIgnored || []),
      productSafetyIgnoredRoots: new Set(),
      projectionPolicy,
      titleMarked,
      resolvedTitle,
      projectionEpoch: 0,
    };
    const initialControls = orderedCommentControls(state);
    state.initialCommentControlCount = initialControls.length;
    state.initiallyDormantCommentControlCount = state.toggleableCommentControls.size;
    state.commentControlSelectorDigest = commentControlSelectorDigest(
      state.commentControlSelectors,
    );
    state.canonicalCommentControlSelectors = Object.freeze(
      Array.from(new Set(state.commentControlSelectors)).sort(),
    );
    state.initialCommentControlShapeFingerprint = commentControlShapeFingerprint(
      state,
      initialControls,
    );
    state.ownedElementSet.forEach(function rememberExactMarkerShape(element) {
      state.expectedMarkerShapes.set(element, Object.freeze({
        keep: element.getAttribute(ATTR.keep),
        shell: element.getAttribute(ATTR.shell),
        deep: element.getAttribute(ATTR.deep),
        role: element.getAttribute(ATTR.role),
        classes: Object.freeze(projectionHdfClasses(element)),
      }));
    });
    return state;
  }

  function markerShapeMatches(element, expected) {
    return Boolean(expected) &&
      element.getAttribute(ATTR.keep) === expected.keep &&
      element.getAttribute(ATTR.shell) === expected.shell &&
      element.getAttribute(ATTR.deep) === expected.deep &&
      element.getAttribute(ATTR.role) === expected.role &&
      JSON.stringify(projectionHdfClasses(element)) === JSON.stringify(expected.classes);
  }

  function rememberAuthorizedMarkerTree(root, state) {
    if (!root || root.nodeType !== 1) {
      return;
    }
    const markerClosure = [root].concat(Array.from(root.querySelectorAll(`[${ATTR.keep}]`)));
    for (let ancestor = root.parentElement; ancestor; ancestor = ancestor.parentElement) {
      markerClosure.push(ancestor);
    }
    uniqueElements(markerClosure).forEach(
      function rememberAuthorized(element) {
        if (
          !state.ownedElements.has(element) ||
          element.getAttribute(ATTR.keep) !== state.nonce
        ) {
          return;
        }
        state.ownedElementSet.add(element);
        state.expectedMarkerShapes.set(element, Object.freeze({
          keep: element.getAttribute(ATTR.keep),
          shell: element.getAttribute(ATTR.shell),
          deep: element.getAttribute(ATTR.deep),
          role: element.getAttribute(ATTR.role),
          classes: Object.freeze(projectionHdfClasses(element)),
        }));
      }
    );
  }

  function commitAuthorizedCommentCountIncrease(state, addedItemCount) {
    if (!Number.isInteger(addedItemCount) || addedItemCount < 0) return false;
    const currentItems = uniqueElements(queryAllSafe(
      state.roles.comments,
      state.commentItemSelectors,
    ));
    const expectedCount = state.acceptedCommentCount + addedItemCount;
    if (
      currentItems.length !== expectedCount ||
      currentItems.length < state.projectionPolicy.provenCommentCount
    ) {
      return false;
    }
    if (state.requiresVisibleExactCommentTotal) {
      const values = new Set();
      for (const evidence of state.commentTotalEvidenceRoots) {
        if (
          !evidence.isConnected ||
          (state.commentCountBoundary !== evidence &&
            !state.commentCountBoundary.contains(evidence))
        ) {
          continue;
        }
        const count = parseVisibleCommentTotal(evidence.textContent);
        if (count !== null) values.add(count);
      }
      // A publisher may update its total before or after adding a reply,
      // or leave a cached total unchanged. After the initial projection,
      // only the exact, individually classified DOM item set is authoritative.
      // A lagging counter must not stop the observer or hide later replies.
      state.publisherCommentCount = values.size === 1
        ? values.values().next().value
        : null;
    }
    state.acceptedCommentCount = currentItems.length;
    return true;
  }

  function verifyOwnedState(document, state) {
    return withPublisherVisibilityMeasurement(
      document,
      function verifyMeasuredOwnedState() {
        return verifyOwnedStateWithPublisherStyles(document, state);
      },
      function rejectUnsafeOwnershipMeasurement() { return false; },
    );
  }

  function verifyOwnedMarkerState(document, state) {
    if (!state?.titleMarked || !state.commonRoot?.isConnected) return false;
    if (!state.ownedElements.has(state.commonRoot)) return false;
    if (!state.ownedElementSet.size) return false;
    if (!state.requiredRoles.every(function requiredRoleIsOwned(role) {
      const element = state.roles[role];
      return element?.isConnected && state.ownedElements.has(element) &&
        element.getAttribute(ATTR.role) === role;
    })) {
      return false;
    }
    const markedElements = document.querySelectorAll(
      `[${ATTR.keep}], [${ATTR.shell}], [${ATTR.deep}], [${ATTR.role}], ` +
      `.${CLASS.keep}, .${CLASS.shell}, .${CLASS.deep}, [class*="${CLASS.rolePrefix}"]`
    );
    if (markedElements.length !== state.ownedElementSet.size) return false;
    return Array.from(markedElements).every(function exactOwnedMarker(element) {
      return state.ownedElementSet.has(element) && state.ownedElements.has(element) &&
        element.getAttribute(ATTR.keep) === state.nonce &&
        markerShapeMatches(element, state.expectedMarkerShapes.get(element));
    }) && Array.from(state.ownedElementSet).every(function intactOwnedMarker(element) {
      return element.isConnected && state.ownedElements.has(element) &&
        element.getAttribute(ATTR.keep) === state.nonce &&
        markerShapeMatches(element, state.expectedMarkerShapes.get(element));
    });
  }

  function projectionHasPublisherPaintRiskWithPublisherStyles(state) {
    const projectionInvariantFails = function projectionInvariantFails(role, excludedRoots) {
      const root = state.roles[role];
      return Boolean(root) && (
        !isRendered(root) ||
        containsUnprovenShadowBoundary(root, Array.from(excludedRoots || [])) ||
        containsPublisherPaintRisk(root, Array.from(excludedRoots || []))
      );
    };
    return shallowTitleSurfaceHasRisk(
      state.roles.title,
      state.resolvedTitle,
      containsUnprovenShadowBoundary,
    ) || shallowTitleSurfaceHasRisk(
      state.roles.title,
      state.resolvedTitle,
      containsPublisherPaintRisk,
    ) || projectionInvariantFails("body", state.bodyIgnoredRoots) ||
      projectionInvariantFails("product", state.productIgnoredRoots) ||
      commentProjectionHasRisk(
        state.roles.comments,
        Array.from(state.commentItemRoots),
        Array.from(state.commentControlRoots),
        Array.from(state.commentIgnoredRoots),
        state.projectionPolicy.allowEmptyComments === true &&
          state.projectionPolicy.provenCommentCount === 0,
        state.commentControlScope,
      );
  }

  function projectionHasPublisherPaintRisk(document, state) {
    return withPublisherVisibilityMeasurement(
      document,
      function verifyMeasuredPublisherPaintRisk() {
        return projectionHasPublisherPaintRiskWithPublisherStyles(state);
      },
      function rejectUnsafePublisherPaintMeasurement() { return true; },
    );
  }

  function verifyOwnedStateWithPublisherStyles(document, state) {
    if (
      !state.titleMarked ||
      !state.commonRoot.isConnected ||
      !state.ownedElements.has(state.commonRoot)
    ) {
      return false;
    }
    for (const role of state.requiredRoles) {
      const node = state.roles[role];
      if (!node || !node.isConnected || !state.ownedElements.has(node)) {
        return false;
      }
      if (node.getAttribute(ATTR.role) !== role) {
        return false;
      }
    }
    const titleText = hasDirectText(state.roles.title) ||
      Array.from(state.roles.title.children).some(function validTitleChild(child) {
        return state.ownedElements.has(child) && normalizeText(child.textContent);
      });
    if (!titleText) {
      return false;
    }
    if (!hasApprovedContentOutside(
      state.roles.body,
      Array.from(state.bodyIgnoredRoots),
    )) {
      return false;
    }
    const noiseCache = new WeakMap();
    if (
      containsSemanticNoise(
        state.roles.body,
        noiseCache,
        Array.from(state.bodyIgnoredRoots),
      ) ||
      (state.roles.product && (
        !hasApprovedContentOutside(
          state.roles.product,
          Array.from(state.productIgnoredRoots),
        ) ||
        containsSemanticNoise(
          state.roles.product,
          noiseCache,
          Array.from(state.productIgnoredRoots),
        )
      )) ||
      (!isRendered(state.roles.comments) &&
        !Array.from(state.commentItemRoots).some(isRendered) &&
        !Array.from(state.commentControlRoots).some(isRendered) && !(
          state.projectionPolicy.allowEmptyComments === true &&
          state.projectionPolicy.provenCommentCount === 0 &&
          isStableZeroAreaCommentMount(state.roles.comments)
        ))
    ) {
      return false;
    }
    if (projectionHasPublisherPaintRiskWithPublisherStyles(state)) {
      return false;
    }
    const sameRootSet = function sameRootSet(current, expectedSet) {
      return current.length === expectedSet.size &&
        current.every(function expectedRoot(root) { return expectedSet.has(root); });
    };
    const currentBodyConfiguredIgnored = ignoredRootsWithin(
      state.roles.body,
      state.projectionPolicy.bodyIgnoredSelectors,
    );
    const currentProductConfiguredIgnored = state.roles.product
      ? ignoredRootsWithin(
          state.roles.product,
          state.projectionPolicy.productIgnoredSelectors,
        )
      : [];
    const currentBodySafetyIgnored = Array.from(state.bodySafetyIgnoredRoots)
      .filter(function connectedBodySafetyRoot(root) {
        return root?.isConnected &&
          root !== state.roles.body &&
          state.roles.body.contains(root);
      });
    const currentProductSafetyIgnored = state.roles.product
      ? Array.from(state.productSafetyIgnoredRoots)
          .filter(function connectedProductSafetyRoot(root) {
            return root?.isConnected &&
              root !== state.roles.product &&
              state.roles.product.contains(root);
          })
      : [];
    const currentBodyAutonomousDiscovery = discoverAutonomousIgnoredRoots(
      state.roles.body,
      currentBodyConfiguredIgnored.concat(currentBodySafetyIgnored),
    );
    const currentProductAutonomousDiscovery = state.roles.product
      ? discoverAutonomousIgnoredRoots(
          state.roles.product,
          currentProductConfiguredIgnored.concat(currentProductSafetyIgnored),
        )
      : Object.freeze({ ok: true, roots: Object.freeze([]), count: 0 });
    const currentBodyAutonomous = currentBodyAutonomousDiscovery.ok
      ? Array.from(currentBodyAutonomousDiscovery.roots)
      : [];
    const currentProductAutonomous = currentProductAutonomousDiscovery.ok
      ? Array.from(currentProductAutonomousDiscovery.roots)
      : [];
    if (
      !currentBodyAutonomousDiscovery.ok ||
      !currentProductAutonomousDiscovery.ok ||
      !sameRootSet(
        currentBodyConfiguredIgnored,
        state.bodyConfiguredIgnoredRoots,
      ) ||
      !sameRootSet(
        currentProductConfiguredIgnored,
        state.productConfiguredIgnoredRoots,
      ) ||
      !sameRootSet(currentBodySafetyIgnored, state.bodySafetyIgnoredRoots) ||
      !sameRootSet(currentProductSafetyIgnored, state.productSafetyIgnoredRoots) ||
      !sameRootSet(currentBodyAutonomous, state.bodyAutonomousIgnoredRoots) ||
      !sameRootSet(
        currentProductAutonomous,
        state.productAutonomousIgnoredRoots,
      ) ||
      !sameRootSet(
        currentBodyConfiguredIgnored.concat(
          currentBodySafetyIgnored,
          currentBodyAutonomous,
        ),
        state.bodyIgnoredRoots,
      ) ||
      !sameRootSet(
        currentProductConfiguredIgnored.concat(
          currentProductSafetyIgnored,
          currentProductAutonomous,
        ),
        state.productIgnoredRoots,
      )
    ) {
      return false;
    }
    const currentProducts = uniqueElements(queryAllSafe(
      state.commonRoot,
      state.projectionPolicy.productSelectors,
    ));
    if (
      (state.projectionPolicy.productCardinality === "zero" && currentProducts.length !== 0) ||
      (state.projectionPolicy.productCardinality === "required" &&
        (currentProducts.length !== 1 || currentProducts[0] !== state.roles.product)) ||
      (state.projectionPolicy.productCardinality === "optional" &&
        (currentProducts.length > 1 || (currentProducts[0] || null) !== state.roles.product))
    ) {
      return false;
    }
    if (state.roles.product) {
      const productNestedInTitle = state.roles.title.contains(state.roles.product);
      const productOrderValid = state.projectionPolicy.productOrder === "before-body"
        ? productNestedInTitle || (
            followsNode(state.roles.product, state.roles.title) &&
            followsNode(state.roles.body, state.roles.product)
          )
        : state.projectionPolicy.productOrder === "after-body"
          ? !productNestedInTitle && followsNode(state.roles.product, state.roles.body)
          : false;
      if (!productOrderValid || !followsNode(state.roles.comments, state.roles.product)) {
        return false;
      }
    }
    const atomicRoleIntact = function atomicRoleIntact(role, ignoredRoots) {
      const root = state.roles[role];
      if (!root) {
        return true;
      }
      return [root].concat(Array.from(root.querySelectorAll("*"))).every(
        function projectedExactly(element) {
          const ignored = insideAnyRoot(element, Array.from(ignoredRoots));
          return ignored
            ? !state.ownedElements.has(element) && !element.hasAttribute(ATTR.keep)
            : state.ownedElements.has(element) &&
                element.getAttribute(ATTR.keep) === state.nonce &&
                element.getAttribute(ATTR.deep) === role;
        },
      );
    };
    if (
      !atomicRoleIntact("body", state.bodyIgnoredRoots) ||
      !atomicRoleIntact("product", state.productIgnoredRoots)
    ) {
      return false;
    }
    const currentCommentProjection = deriveCommentProjectionRoots(
      state.roles.comments,
      state.commentControlScope,
      state.commentItemSelectors,
      state.commentControlSelectors,
      state.commentIgnoredSelectors,
      state.commentControlRoots,
      state.commentItemRoots,
    );
    if (!currentCommentProjection.ok) return false;
    const {
      commentItems: currentCommentItems,
      commentControls: currentCommentControls,
      commentConfiguredIgnored: currentCommentConfiguredIgnored,
      commentAutonomousIgnored: currentCommentAutonomousIgnored,
      commentIgnored: derivedCurrentCommentIgnored,
    } = currentCommentProjection;
    const currentCommentIgnored = uniqueElements(derivedCurrentCommentIgnored.concat(
      Array.from(state.commentSafetyIgnoredRoots).filter(function ignoredRootStillInMount(root) {
        return root.isConnected && state.roles.comments.contains(root);
      }),
    ));
    if (
      !Number.isInteger(state.acceptedCommentCount) ||
      currentCommentItems.length !== state.acceptedCommentCount ||
      currentCommentItems.length < state.projectionPolicy.provenCommentCount
    ) {
      return false;
    }
    if (
      !sameRootSet(currentCommentItems, state.commentItemRoots) ||
      !sameRootSet(currentCommentControls, state.commentControlRoots) ||
      !sameRootSet(
        currentCommentConfiguredIgnored,
        state.commentConfiguredIgnoredRoots,
      ) ||
      !sameRootSet(
        currentCommentAutonomousIgnored,
        state.commentAutonomousIgnoredRoots,
      ) ||
      !sameRootSet(currentCommentIgnored, state.commentIgnoredRoots)
    ) {
      return false;
    }
    const ignoredOverlap = currentCommentIgnored.some(function overlapsIgnored(ignored) {
      return currentCommentItems.concat(currentCommentControls).some(
        function overlapsVisible(visible) {
          return ignored === visible || ignored.contains(visible) || visible.contains(ignored);
        }
      );
    });
    if (
      ignoredOverlap ||
      hasUnclassifiedCommentContent(
        state.roles.comments,
        currentCommentItems.concat(currentCommentControls, currentCommentIgnored)
      ) ||
      currentCommentItems.some(function unownedItem(item) {
        return !isRendered(item) ||
          !state.ownedElements.has(item) ||
          item.getAttribute(ATTR.role) !== "comment-item";
      }) ||
      currentCommentControls.some(function unownedControl(control) {
        return (!isRendered(control) && !approvedDormantCommentControl(control, state)) ||
          !state.ownedElements.has(control) ||
          control.getAttribute(ATTR.role) !== "comment-control";
      }) ||
      currentCommentIgnored.some(function visibleIgnored(ignored) {
        return state.ownedElements.has(ignored) || ignored.hasAttribute(ATTR.keep);
      })
    ) {
      return false;
    }
    const markedElements = document.querySelectorAll(
      `[${ATTR.keep}], [${ATTR.shell}], [${ATTR.deep}], [${ATTR.role}], ` +
      `.${CLASS.keep}, .${CLASS.shell}, .${CLASS.deep}, [class*="${CLASS.rolePrefix}"]`
    );
    const noSpoofedMarker = Array.from(markedElements).every(function exactRunShape(element) {
      return state.ownedElements.has(element) &&
        markerShapeMatches(element, state.expectedMarkerShapes.get(element));
    });
    if (!noSpoofedMarker) {
      return false;
    }
    return Array.from(state.ownedElementSet).every(function intactOwnedElement(element) {
      return element.isConnected &&
        state.ownedElements.has(element) &&
        element.getAttribute(ATTR.keep) === state.nonce &&
        markerShapeMatches(element, state.expectedMarkerShapes.get(element));
    });
  }

  function paintLockSelectors(rootSelectors) {
    return rootSelectors.flatMap(function coverRootAndTopLayer(rootSelector) {
      return [
        rootSelector,
        `${rootSelector} dialog`,
        `${rootSelector} dialog::backdrop`,
        `${rootSelector} [popover]`,
        `${rootSelector} [popover]::backdrop`,
        `${rootSelector} :fullscreen`,
        `${rootSelector} :fullscreen::backdrop`,
      ];
    }).join(", ");
  }

  function gateStyleText(nonce) {
    const lockedRoots = [`html.${CLASS.lock}`, `html[${ATTR.lock}="1"]`];
    const lockRule = `${paintLockSelectors(lockedRoots)} { ` +
      `transition: none !important; animation: none !important; ` +
      `visibility: hidden !important; content-visibility: hidden !important; ` +
      `opacity: 0 !important; ` +
      `clip-path: inset(50%) !important; ` +
      `pointer-events: none !important; ` +
      `caret-color: transparent !important; }`;
    if (!nonce) {
      return lockRule;
    }
    const readyRoot = `html.${CLASS.ready}[${ATTR.ready}="1"]` +
      `[${ATTR.protocol}="${PROTOCOL_VERSION}"][${ATTR.state}="ready"]` +
      `[${ATTR.status}="ready"]`;
    const owned = `.${CLASS.keep}[${ATTR.keep}="${nonce}"]`;
    const shell = `.${CLASS.shell}[${ATTR.shell}="${nonce}"]`;
    const releaseProbe = `[data-hdf-v2-release-probe="${nonce}"]`;
    return [
      lockRule,
      `${readyRoot} { visibility: visible !important; }`,
      `${readyRoot}, ${readyRoot} body { background-image: none !important; box-shadow: none !important; }`,
      `${readyRoot}::before, ${readyRoot}::after,` +
        `${readyRoot} body::before, ${readyRoot} body::after { ` +
        `content: none !important; display: none !important; background: none !important; }`,
      `${readyRoot} body *:not(${owned}) { display: none !important; }`,
      `${readyRoot} ${releaseProbe} { ` +
        `--hdf-v2-cascade-proof: ${nonce} !important; ` +
        `display: none !important; visibility: hidden !important; ` +
        `opacity: 0 !important; pointer-events: none !important; }`,
      `${readyRoot} ${owned}${shell} { visibility: hidden !important; }`,
      `${readyRoot} ${owned}.${CLASS.deep}[${ATTR.deep}],`,
      `${readyRoot} ${owned}.${roleClass("title")}[${ATTR.role}="title"],`,
      `${readyRoot} ${owned}.${roleClass("title-text")}[${ATTR.role}="title-text"],`,
      `${readyRoot} ${owned}.${roleClass("body")}[${ATTR.role}="body"],`,
      `${readyRoot} ${owned}.${roleClass("product")}[${ATTR.role}="product"],`,
      `${readyRoot} ${owned}.${roleClass("comment-item")}` +
        `[${ATTR.role}="comment-item"],`,
      `${readyRoot} ${owned}.${roleClass("comment-control")}` +
        `[${ATTR.role}="comment-control"] { visibility: visible !important; }`,
      `${readyRoot} ${owned}${shell}::before,`,
      `${readyRoot} ${owned}${shell}::after { content: none !important; display: none !important; }`,
      `@media (max-width: 720px) {`,
      `${readyRoot}, ${readyRoot} body { ` +
        `box-sizing: border-box !important; width: 100% !important; ` +
        `min-width: 0 !important; max-width: 100% !important; ` +
        `margin-left: 0 !important; margin-right: 0 !important; }`,
      `${readyRoot} body ${owned}${shell} { ` +
        `box-sizing: border-box !important; width: 100% !important; ` +
        `min-width: 0 !important; max-width: 100% !important; ` +
        `margin-left: 0 !important; margin-right: 0 !important; }`,
      `${readyRoot} body ${owned}.${CLASS.deep}[${ATTR.deep}],` +
        `${readyRoot} body ${owned}.${roleClass("title")}[${ATTR.role}="title"],` +
        `${readyRoot} body ${owned}.${roleClass("body")}[${ATTR.role}="body"],` +
        `${readyRoot} body ${owned}.${roleClass("product")}[${ATTR.role}="product"],` +
        `${readyRoot} body ${owned}.${roleClass("comments")}[${ATTR.role}="comments"] { ` +
        `box-sizing: border-box !important; min-width: 0 !important; ` +
        `max-width: 100% !important; margin-left: 0 !important; ` +
        `margin-right: 0 !important; }`,
      `${readyRoot} body ${owned}.${roleClass("title")}[${ATTR.role}="title"] { ` +
        `display: block !important; width: 100% !important; ` +
        `white-space: normal !important; overflow-wrap: anywhere !important; }`,
      `${readyRoot} body ${owned}.${roleClass("body")}[${ATTR.role}="body"],` +
        `${readyRoot} body ${owned}.${roleClass("product")}[${ATTR.role}="product"],` +
        `${readyRoot} body ${owned}.${roleClass("comments")}[${ATTR.role}="comments"] { ` +
        `width: 100% !important; }`,
      `${readyRoot} body ${owned}.${CLASS.deep}[${ATTR.deep}] img,` +
        `${readyRoot} body ${owned}.${CLASS.deep}[${ATTR.deep}] picture,` +
        `${readyRoot} body ${owned}.${CLASS.deep}[${ATTR.deep}] video,` +
        `${readyRoot} body ${owned}.${CLASS.deep}[${ATTR.deep}] iframe { ` +
        `max-width: 100% !important; height: auto !important; }`,
      `}`,
    ].join("\n");
  }

  function installRuntimeGateStyle(document) {
    const parent = document.head || document.documentElement;
    const textContent = gateStyleText(null);
    if (!parent || typeof GM_addElement !== "function") {
      throw new Error("GM_addElement is unavailable");
    }
    const style = GM_addElement(parent, "style", {
      textContent,
      "data-hotdeal-focus-runtime-style": "2",
    });
    if (
      !style ||
      style.nodeType !== 1 ||
      style.localName !== "style" ||
      !style.isConnected ||
      style.getAttribute("data-hotdeal-focus-runtime-style") !== PROTOCOL_VERSION ||
      style.textContent !== textContent
    ) {
      throw new Error("GM_addElement returned an invalid runtime style");
    }
    return style;
  }

  function publisherVisualRecoveryStyleText() {
    return [
      "html { transition: none !important; animation: none !important; " +
        "visibility: visible !important; content-visibility: visible !important; " +
        "opacity: 1 !important; clip-path: none !important; pointer-events: auto !important; }",
      "html::before, html::after, body::before, body::after { " +
        "content: none !important; display: none !important; background: none !important; " +
        "background-image: none !important; box-shadow: none !important; " +
        "pointer-events: none !important; }",
    ].join("\n");
  }

  function installPublisherVisualRecoveryStyle(document) {
    const parent = document?.head || document?.documentElement;
    const textContent = publisherVisualRecoveryStyleText();
    if (!parent || typeof GM_addElement !== "function") return null;
    try {
      const style = GM_addElement(parent, "style", { textContent });
      return style?.nodeType === 1 && style.localName === "style" &&
        style.isConnected && style.textContent === textContent
        ? style
        : null;
    } catch (_error) {
      return null;
    }
  }

  function writeRuntimeGateStyle(styleElement, nonce, runtime) {
    const expectedText = gateStyleText(nonce);
    styleElement.textContent = expectedText;
    runtime.expectedStyleText = expectedText;
  }

  function runtimeGateStyleFailure(styleElement, runtime) {
    if (!styleElement) return "missing";
    if (!styleElement.isConnected) return "disconnected";
    if (
      styleElement.getAttribute("data-hotdeal-focus-runtime-style") !== PROTOCOL_VERSION
    ) return "marker";
    if (styleElement.textContent !== runtime.expectedStyleText) return "text";
    return null;
  }

  function runtimeGateStyleIntact(styleElement, runtime) {
    return runtimeGateStyleFailure(styleElement, runtime) === null;
  }

  function publishDiagnostics(browserRoot, details) {
    const safeDetails = Object.freeze({
      protocolVersion: Number(PROTOCOL_VERSION),
      state: details.state,
      targetReason: details.targetReason || "none",
      roles: Object.freeze(details.roles || {}),
      layoutAliases: Object.freeze((details.layoutAliases || []).slice()),
      semanticProjectionCount: Number(details.semanticProjectionCount || 0),
      standaloneCascadeProof: details.standaloneCascadeProof
        ? Object.freeze({ ...details.standaloneCascadeProof })
        : null,
      commentControlProjection: details.commentControlProjection
        ? Object.freeze({ ...details.commentControlProjection })
        : null,
      visibleLeakCount: Number(details.visibleLeakCount || 0),
      reconciliationFailure: details.reconciliationFailure
        ? Object.freeze({ ...details.reconciliationFailure })
        : null,
    });
    try {
      NATIVE.defineProperty(browserRoot, "__HOTDEAL_FOCUS_DIAGNOSTICS__", {
        value: safeDetails,
        configurable: true,
        enumerable: false,
        writable: false,
      });
    } catch (_error) {
      // Diagnostics never participate in reader authorization or rollback.
    }
  }

  function currentVisibleProjectionLeakCount(document, state) {
    const elements = Array.from(document.body?.querySelectorAll("*") || []);
    if (elements.length > MAX_SEMANTIC_DESCENDANTS) {
      return elements.length;
    }
    let count = 0;
    const countedNoiseRoots = [];
    elements.forEach(function countVisibleLeak(element) {
      if (
        countedNoiseRoots.some(function nestedNoise(root) {
          return root.contains(element);
        })
      ) {
        return;
      }
      const owned = state?.ownedElements?.has(element) === true;
      // Role roots have already passed role-specific content, resource and
      // paint checks. Publisher presentation classes on an exact purchase or
      // article root must not reclassify that verified role as page chrome.
      // Unowned elements and noise nested inside a role remain checked.
      const verifiedRoleRoot = owned && ["title", "body", "product", "comments"]
        .some(function exactVerifiedRole(role) { return state.roles[role] === element; });
      const autonomousNoise = !verifiedRoleRoot && isAutonomousProjectionNoiseRoot(element);
      if (autonomousNoise) countedNoiseRoots.push(element);
      if (
        isRendered(element) &&
        (!owned || autonomousNoise)
      ) {
        count += 1;
      }
    });
    return count;
  }

  function structuralRoleDiagnostics(signalCount) {
    return Object.freeze({ count: 1, score: 1, signalCount, margin: 1 });
  }

  function hasApprovedContent(element) {
    return normalizeText(element.textContent).length > 0 ||
      Boolean(element.querySelector("img, picture, video, iframe, table, a[href]"));
  }

  function hasApprovedContentOutside(element, excludedRoots) {
    const exclusions = excludedRoots || [];
    const stack = Array.from(element.childNodes);
    let inspected = 0;
    while (stack.length) {
      const node = stack.pop();
      inspected += 1;
      if (inspected > MAX_SEMANTIC_DESCENDANTS) return false;
      if (node.nodeType === 3 && normalizeText(node.data)) return true;
      if (node.nodeType !== 1 || insideAnyRoot(node, exclusions)) continue;
      if (node.matches("img, picture, video, iframe, table, a[href]")) return true;
      for (let index = node.childNodes.length - 1; index >= 0; index -= 1) {
        stack.push(node.childNodes[index]);
      }
    }
    return false;
  }

  function hasUnclassifiedCommentContent(commentMount, classifiedRoots) {
    const classified = classifiedRoots.slice();
    function inspect(node) {
      if (node.nodeType === 3) {
        return Boolean(normalizeText(node.data));
      }
      if (node.nodeType !== 1 || node.matches("script, style, template, noscript")) {
        return false;
      }
      if (classified.some(function insideClassified(root) {
        return root === node || root.contains(node);
      })) {
        return false;
      }
      const containsClassifiedRoot = classified.some(function wrapsClassified(root) {
        return node.contains(root);
      });
      if (Array.from(node.childNodes).some(inspect)) {
        return true;
      }
      if (containsClassifiedRoot) {
        return false;
      }
      return node.matches(
        "img, picture, video, iframe, table, button, input, textarea, select, [contenteditable='true']"
      );
    }
    return Array.from(commentMount.childNodes).some(inspect);
  }

  function ignoredRootsWithin(boundary, selectors) {
    return uniqueElements(queryAllSafe(boundary, selectors || []))
      .filter(function strictDescendant(root) {
        return root !== boundary && boundary.contains(root);
      });
  }

  function rootsOverlap(roots) {
    return roots.some(function overlaps(root, index) {
      return roots.some(function overlapsOther(other, otherIndex) {
        return index !== otherIndex &&
          (root === other || root.contains(other) || other.contains(root));
      });
    });
  }

  function deriveCommentProjectionFromItems(
    commentMount,
    pageRoot,
    suppliedCommentItems,
    controlHints,
    ignoredHints,
    trustedControlRoots
  ) {
    const commentItems = uniqueElements(Array.from(suppliedCommentItems || []));
    const rawCommentControls = uniqueElements(queryAllSafe(pageRoot, controlHints));
    const commentConfiguredIgnored = uniqueElements(
      queryAllSafe(commentMount, ignoredHints),
    );
    const autonomousNoiseControls = rawCommentControls.filter(
      function autonomousNoiseControl(control) {
        if (trustedControlRoots?.has(control)) return false;
        return !commentItems.some(function overlapsCommentItem(item) {
          return nodesOverlap(control, item);
        }) && isAutonomousProjectionNoiseRoot(control);
      },
    );
    const commentControls = rawCommentControls.filter(
      function approvedCommentControl(control) {
        return !autonomousNoiseControls.includes(control);
      },
    );
    const protectedCommentRoots = commentItems
      .concat(commentControls, commentConfiguredIgnored);
    const autonomousDiscovery = discoverAutonomousIgnoredRoots(
      commentMount,
      protectedCommentRoots,
    );
    if (!autonomousDiscovery.ok) {
      return Object.freeze({
        ok: false,
        reason: "ignored-bound",
      });
    }
    const commentAutonomousIgnored = uniqueElements(
      autonomousNoiseControls.filter(function noiseInsideCommentMount(control) {
        return commentMount.contains(control);
      }).concat(Array.from(autonomousDiscovery.roots)),
    );
    return Object.freeze({
      ok: true,
      commentItems: Object.freeze(commentItems),
      commentControls: Object.freeze(commentControls),
      commentConfiguredIgnored: Object.freeze(commentConfiguredIgnored),
      commentAutonomousIgnored: Object.freeze(commentAutonomousIgnored),
      commentIgnored: Object.freeze(uniqueElements(
        commentConfiguredIgnored.concat(commentAutonomousIgnored),
      )),
    });
  }

  function deriveCommentProjectionRoots(
    commentMount,
    pageRoot,
    itemHints,
    controlHints,
    ignoredHints,
    trustedControlRoots,
    trustedItemRoots
  ) {
    return deriveCommentProjectionFromItems(
      commentMount,
      pageRoot,
      uniqueElements(queryAllSafe(commentMount, itemHints).concat(
        Array.from(trustedItemRoots || []).filter(function acceptedItemStillInMount(item) {
          return item.isConnected && commentMount.contains(item);
        }),
      )),
      controlHints,
      ignoredHints,
      trustedControlRoots,
    );
  }

  function resolveApprovedLayout(document, layout, seed) {
    return withPublisherVisibilityMeasurement(
      document,
      function resolveMeasuredLayout() {
        return resolveApprovedLayoutWithPublisherStyles(document, layout, seed);
      },
      function rejectUnsafeLayoutMeasurement() {
        return { ok: false, role: "measurement", reason: "unsafe-state" };
      },
    );
  }

  function resolveApprovedLayoutWithPublisherStyles(document, layout, seed) {
    const pageRoots = uniqueElements(queryAllSafe(document, [layout.pageRoot]));
    if (pageRoots.length !== 1) {
      return { ok: false, role: "page-root", reason: "cardinality" };
    }
    const pageRoot = pageRoots[0];
    const titleCandidates = uniqueElements(queryAllSafe(pageRoot, layout.hints.title || []));
    if (titleCandidates.length !== 1 || !isRendered(titleCandidates[0]) || !normalizeText(titleCandidates[0].textContent)) {
      return { ok: false, role: "title", reason: "approved-structure" };
    }
    const titleNode = titleCandidates[0];
    const visibleTitle = approvedVisibleTitle(document, seed?.title || null, titleNode);
    const seedTitleEvidence = visibleTitle.evidence;
    if (seed && !seedTitleEvidence.algumon.ok) {
      return { ok: false, role: "seed", reason: "title-mismatch" };
    }
    if (!visibleTitle.ok || !seedTitleEvidence.metadata.ok) {
      return { ok: false, role: "title", reason: "metadata-mismatch" };
    }
    if (shallowTitleSurfaceHasRisk(
      titleNode,
      visibleTitle.text,
      containsUnprovenShadowBoundary,
    )) {
      return { ok: false, role: "title", reason: "shadow-boundary" };
    }
    if (shallowTitleSurfaceHasRisk(
      titleNode,
      visibleTitle.text,
      containsPublisherPaintRisk,
    )) {
      return { ok: false, role: "title", reason: "publisher-paint" };
    }

    const bodyCandidates = uniqueElements(queryAllSafe(pageRoot, layout.hints.body || []));
    if (bodyCandidates.length !== 1 || !isRendered(bodyCandidates[0])) {
      return { ok: false, role: "body", reason: "approved-structure" };
    }
    const bodyNode = bodyCandidates[0];
    const roleProjection = layout.roleProjection;
    const configuredProductCardinality = roleProjection?.product?.cardinality;
    const configuredProductOrder = roleProjection?.product?.order;
    if (
      roleProjection?.title?.mode !== "metadata-shallow" ||
      roleProjection?.body?.mode !== "atomic-boundary" ||
      roleProjection?.comments?.mode !== "classified-children" ||
      !["zero", "required", "optional"].includes(
        configuredProductCardinality,
      ) ||
      (configuredProductCardinality === "zero" && configuredProductOrder !== undefined) ||
      (configuredProductCardinality !== "zero" &&
        !["before-body", "after-body"].includes(configuredProductOrder))
    ) {
      return { ok: false, role: "projection", reason: "policy" };
    }
    const bodyConfiguredIgnored = ignoredRootsWithin(
      bodyNode,
      roleProjection.body.ignored,
    );
    if (rootsOverlap(bodyConfiguredIgnored)) {
      return { ok: false, role: "body", reason: "ignored-overlap" };
    }
    const bodyAutonomousIgnoredDiscovery = discoverAutonomousIgnoredRoots(
      bodyNode,
      bodyConfiguredIgnored,
    );
    if (!bodyAutonomousIgnoredDiscovery.ok) {
      return { ok: false, role: "body", reason: "ignored-bound" };
    }
    const bodyAutonomousIgnored = Array.from(bodyAutonomousIgnoredDiscovery.roots);
    const bodyIgnored = bodyConfiguredIgnored.concat(bodyAutonomousIgnored);
    if (!hasApprovedContentOutside(bodyNode, bodyIgnored)) {
      return { ok: false, role: "body", reason: "approved-structure" };
    }
    const structuralNoiseCache = new WeakMap();
    if (containsSemanticNoise(bodyNode, structuralNoiseCache, bodyIgnored)) {
      return { ok: false, role: "body", reason: "structural-noise" };
    }
    if (containsUnprovenShadowBoundary(bodyNode, bodyIgnored)) {
      return { ok: false, role: "body", reason: "shadow-boundary" };
    }
    if (containsPublisherPaintRisk(bodyNode, bodyIgnored)) {
      return { ok: false, role: "body", reason: "publisher-paint" };
    }
    const productCardinality = configuredProductCardinality;
    const productOrder = configuredProductOrder || null;
    const productCandidates = uniqueElements(queryAllSafe(
      pageRoot,
      roleProjection.product.selectors || [],
    ));
    if (
      (productCardinality === "zero" && productCandidates.length !== 0) ||
      (productCardinality === "required" && productCandidates.length !== 1) ||
      (productCardinality === "optional" && productCandidates.length > 1)
    ) {
      return { ok: false, role: "product", reason: "cardinality" };
    }
    const productNode = productCandidates[0] || null;
    const productConfiguredIgnored = productNode
      ? ignoredRootsWithin(productNode, roleProjection.product.ignored)
      : [];
    if (rootsOverlap(productConfiguredIgnored)) {
      return { ok: false, role: "product", reason: "ignored-overlap" };
    }
    const productAutonomousIgnoredDiscovery = productNode
      ? discoverAutonomousIgnoredRoots(productNode, productConfiguredIgnored)
      : Object.freeze({ ok: true, roots: Object.freeze([]), count: 0 });
    if (!productAutonomousIgnoredDiscovery.ok) {
      return { ok: false, role: "product", reason: "ignored-bound" };
    }
    const productAutonomousIgnored = Array.from(
      productAutonomousIgnoredDiscovery.roots,
    );
    const productIgnored = productConfiguredIgnored.concat(productAutonomousIgnored);
    if (productNode && (
      !isRendered(productNode) ||
      !hasApprovedContentOutside(productNode, productIgnored) ||
      containsSemanticNoise(productNode, structuralNoiseCache, productIgnored) ||
      productNode === bodyNode ||
      productNode.contains(bodyNode) ||
      bodyNode.contains(productNode)
    )) {
      return { ok: false, role: "product", reason: "approved-structure" };
    }
    const productNestedInTitle = Boolean(productNode && titleNode.contains(productNode));
    if (productNode && (
      !(productNestedInTitle || followsNode(productNode, titleNode)) ||
      (productOrder === "before-body" &&
        !(productNestedInTitle || followsNode(bodyNode, productNode))) ||
      (productOrder === "after-body" &&
        (productNestedInTitle || !followsNode(productNode, bodyNode)))
    )) {
      return { ok: false, role: "product", reason: "approved-order" };
    }
    if (productNode && containsUnprovenShadowBoundary(productNode, productIgnored)) {
      return { ok: false, role: "product", reason: "shadow-boundary" };
    }
    if (productNode && containsPublisherPaintRisk(productNode, productIgnored)) {
      return { ok: false, role: "product", reason: "publisher-paint" };
    }

    const commentHints = layout.hints.comments || [];
    const itemHints = layout.hints.commentItems || [];
    const controlHints = layout.hints.commentControls || [];
    const ignoredHints = layout.hints.commentIgnored || [];
    const commentCandidates = uniqueElements(queryAllSafe(pageRoot, commentHints));
    const nestedCommentCandidates = commentCandidates.filter(
      function uniqueInnermostCommentMount(candidate) {
        return commentCandidates.every(function candidateContainsSelected(other) {
          return other === candidate || other.contains(candidate);
        });
      },
    );
    if (nestedCommentCandidates.length !== 1) {
      return { ok: false, role: "comments", reason: "mount-cardinality" };
    }
    const commentMount = nestedCommentCandidates[0];
    const allowStableZeroAreaMount = layout.allowEmptyComments === true;
    if (
      (!isRendered(commentMount) &&
        !(allowStableZeroAreaMount && isStableZeroAreaCommentMount(commentMount))) ||
      !followsNode(commentMount, bodyNode)
    ) {
      return { ok: false, role: "comments", reason: "mount-order" };
    }
    if (productNode && !followsNode(commentMount, productNode)) {
      return { ok: false, role: "product", reason: "approved-order" };
    }
    const derivedCommentProjection = deriveCommentProjectionRoots(
      commentMount,
      pageRoot,
      itemHints,
      controlHints,
      ignoredHints,
    );
    if (!derivedCommentProjection.ok) {
      return {
        ok: false,
        role: "comments",
        reason: derivedCommentProjection.reason,
      };
    }
    const {
      commentItems,
      commentControls,
      commentConfiguredIgnored,
      commentAutonomousIgnored,
      commentIgnored,
    } = derivedCommentProjection;
    const commentDormantControls = commentControls.filter(
      function dormantInitialControl(control) { return !isRendered(control); }
    );
    if (commentItems.some(function hiddenInitialItem(item) { return !isRendered(item); })) {
      return { ok: false, role: "comments", reason: "classified-rendering" };
    }
    const classificationOverlap = commentIgnored.some(function overlapsIgnored(ignored) {
      return commentItems.concat(commentControls).some(function overlapsVisible(visible) {
        return ignored === visible || ignored.contains(visible) || visible.contains(ignored);
      });
    });
    if (classificationOverlap) {
      return { ok: false, role: "comments", reason: "classification-overlap" };
    }
    if (commentProjectionHasRisk(
      commentMount,
      commentItems,
      commentControls,
      commentIgnored,
      allowStableZeroAreaMount,
      pageRoot,
    )) {
      return { ok: false, role: "comments", reason: "publisher-paint" };
    }
    const classifiedCommentRoots = commentItems.concat(commentControls, commentIgnored);
    const commentJsonLd = collectJsonLd(document);
    const seedCommentCount = Number.isInteger(seed?.commentCount) ? seed.commentCount : null;
    const metadataCommentCount = Number.isInteger(commentJsonLd.commentCount)
      ? commentJsonLd.commentCount
      : null;
    let provenCommentCount = null;
    let provenCommentCountSource = null;
    const documentCommentEvidence = collectExactDocumentCommentEvidence(
      document,
      layout,
      bodyNode,
      seed,
      commentJsonLd,
    );
    if (!documentCommentEvidence.ok) {
      return {
        ok: false,
        role: "comments",
        reason: documentCommentEvidence.reason,
      };
    }
    const invalidCommentEvidence = documentCommentEvidence.elements.some(
      function evidenceOutsideExactItems(evidence) {
        if (insideAnyRoot(evidence, commentIgnored)) return true;
        if (commentMount !== evidence && !commentMount.contains(evidence)) return true;
        if (commentItems.some(function evidenceBelongsToItem(item) {
          return item === evidence || item.contains(evidence);
        })) {
          return false;
        }
        if (evidence === commentMount) return true;
        const exactItemsInsideEvidence = commentItems.filter(function itemInsideEvidence(item) {
          return evidence.contains(item);
        });
        if (!exactItemsInsideEvidence.length) return true;
        const classifiedInsideEvidence = classifiedCommentRoots.filter(
          function classificationInsideEvidence(root) {
            return evidence.contains(root);
          },
        );
        return hasUnclassifiedCommentContent(evidence, classifiedInsideEvidence);
      }
    );
    if (invalidCommentEvidence) {
      return { ok: false, role: "comments", reason: "evidence-outside-items" };
    }
    if (hasUnclassifiedCommentContent(commentMount, classifiedCommentRoots)) {
      return { ok: false, role: "comments", reason: "unclassified-comment-content" };
    }
    const visibleCommentTotal = visibleCommentTotalEvidence(
      commentMount,
      pageRoot,
      // A classified header/control can be the native authoritative total.
      // Exclude item text and noise, not the real "comments 0" header.
      commentItems.concat(commentIgnored),
    );
    if (!visibleCommentTotal.ok) {
      return { ok: false, role: "comments", reason: "count-evidence-conflict" };
    }
    const knownCommentTotal = visibleCommentTotal.count !== null ||
      seedCommentCount !== null || metadataCommentCount !== null;
    if (
      knownCommentTotal &&
      hasVisibleCommentContinuationControl(commentControls)
    ) {
      // Pagination and collapsed reply controls are part of the publisher's
      // comment UI, not a reason to hide an otherwise verified article.
      // Every currently loaded item and control was classified above; future
      // replies are classified by the integrity observer when they arrive.
      provenCommentCount = commentItems.length;
      provenCommentCountSource = "exact-dom-paginated";
    }
    if (provenCommentCount !== null) {
      // The total describes the whole thread, including unloaded pages.
    } else if (visibleCommentTotal.count !== null) {
      if (commentItems.length !== visibleCommentTotal.count) {
        return {
          ok: false,
          role: "comments",
          reason: commentItems.length < visibleCommentTotal.count
            ? "partial-comment-set"
            : "count-item-mismatch",
        };
      }
      if (
        (seedCommentCount !== null && seedCommentCount > visibleCommentTotal.count) ||
        (metadataCommentCount !== null && metadataCommentCount > visibleCommentTotal.count)
      ) {
        return { ok: false, role: "comments", reason: "count-evidence-conflict" };
      }
      provenCommentCount = visibleCommentTotal.count;
      provenCommentCountSource = visibleCommentTotal.source;
    } else if (commentItems.length > 0) {
      const lowerBounds = [seedCommentCount, metadataCommentCount].filter(
        function integerCommentLowerBound(value) { return value !== null; },
      );
      if (
        lowerBounds.length > 0 &&
        commentItems.length < Math.max(...lowerBounds)
      ) {
        return { ok: false, role: "comments", reason: "partial-comment-set" };
      }
      provenCommentCount = commentItems.length;
      provenCommentCountSource = seedCommentCount !== null && metadataCommentCount !== null
        ? "exact-dom+algumon+schema-lower-bound"
        : seedCommentCount !== null
          ? "exact-dom+algumon-lower-bound"
          : metadataCommentCount !== null
            ? "exact-dom+schema-lower-bound"
            : "exact-dom-observed";
    } else if (
      (seedCommentCount !== null && seedCommentCount > 0) ||
      (metadataCommentCount !== null && metadataCommentCount > 0)
    ) {
      return { ok: false, role: "comments", reason: "partial-comment-set" };
    }
    if (
      provenCommentCount === null &&
      commentItems.length === 0 &&
      documentCommentEvidence.elements.length === 0 &&
      layout.allowEmptyComments === true &&
      (isRendered(commentMount) || isStableZeroAreaCommentMount(commentMount))
    ) {
      provenCommentCount = 0;
      provenCommentCountSource = "exact-dom-zero";
    }
    if (commentItems.length === 0 && layout.allowEmptyComments !== true) {
      return { ok: false, role: "comments", reason: "empty-not-approved" };
    }
    if (commentItems.length === 0 && provenCommentCount !== 0) {
      return {
        ok: false,
        role: "comments",
        reason: provenCommentCount > 0 ? "seed-item-mismatch" : "empty-not-proven",
      };
    }
    if (commentItems.length > 0 && provenCommentCount === 0) {
      return { ok: false, role: "comments", reason: "seed-item-mismatch" };
    }
    if (provenCommentCount !== null && commentItems.length > provenCommentCount) {
      return { ok: false, role: "comments", reason: "count-item-mismatch" };
    }
    if (
      provenCommentCount !== null &&
      commentItems.length < provenCommentCount
    ) {
      return { ok: false, role: "comments", reason: "partial-comment-set" };
    }
    const requiredRoles = layout.requiredRoles.slice();
    const roles = {
      title: titleNode,
      body: bodyNode,
      comments: commentMount,
      commentItems,
      commentControls,
      commentDormantControls,
      commentIgnored,
      commentConfiguredIgnored,
      commentAutonomousIgnored,
      commentControlScope: pageRoot,
      commentCountBoundary: pageRoot,
      commentTotalEvidence: visibleCommentTotal.elements,
      bodyIgnored,
      bodyConfiguredIgnored,
      bodyAutonomousIgnored,
      productIgnored,
      productConfiguredIgnored,
      productAutonomousIgnored,
      product: productNode,
    };
    const roleDiagnostics = {
      title: structuralRoleDiagnostics(3),
      body: structuralRoleDiagnostics(4),
      comments: structuralRoleDiagnostics(commentItems.length ? 4 : 3),
    };
    if (productNode) {
      roleDiagnostics.product = structuralRoleDiagnostics(3);
    }
    const relationshipRoles = productNode && !requiredRoles.includes("product")
      ? requiredRoles.concat("product")
      : requiredRoles;
    const commonRoot = validateRoleRelationship(
      document,
      roles,
      relationshipRoles,
      pageRoot,
      layout.allowEmptyComments === true && provenCommentCount === 0,
    );
    if (!commonRoot) {
      return { ok: false, role: "relationship", reason: "approved-root" };
    }
    return {
      ok: true,
      layoutId: layout.id,
      roles,
      requiredRoles,
      commonRoot,
      commentItemSelectors: itemHints.slice(),
      commentControlSelectors: controlHints.slice(),
      commentIgnoredSelectors: ignoredHints.slice(),
      projectionPolicy: Object.freeze({
        allowEmptyComments: layout.allowEmptyComments === true,
        provenCommentCount,
        provenCommentCountSource,
        productCardinality,
        productOrder,
        productFallback: productNode ? "separate" : "body",
        productSelectors: roleProjection.product.selectors.slice(),
        bodyIgnoredSelectors: roleProjection.body.ignored.slice(),
        productIgnoredSelectors: roleProjection.product.ignored.slice(),
      }),
      seedConsistency: Object.freeze({
        titleSimilarity: seedTitleEvidence.score,
        titleConsistencyOk: seedTitleEvidence.ok,
        titleMode: seedTitleEvidence.mode,
        metadataSourceCount: seedTitleEvidence.metadata.sourceCount,
        metadataSourceKinds: seedTitleEvidence.metadata.sourceKinds,
      }),
      roleDiagnostics,
      resolvedTitle: visibleTitle.text,
    };
  }

  function resolveProjectionClasses(document, layouts, seed) {
    const resolutions = layouts.map(function resolveLayout(layout) {
      return resolveApprovedLayout(document, layout, seed);
    });
    const approved = resolutions.filter(function approvedResolution(resolution) {
      return resolution.ok;
    });
    const sameElementSet = function sameElementSet(left, right) {
      return left.length === right.length && left.every(function sameElement(element) {
        return right.includes(element);
      });
    };
    const sameProjection = function sameProjection(left, right) {
      const roleNames = [...new Set(left.requiredRoles.concat(right.requiredRoles))];
      return left.requiredRoles.length === right.requiredRoles.length &&
        roleNames.every(function sameRole(role) {
          return left.roles[role] === right.roles[role];
        }) &&
        left.roles.product === right.roles.product &&
        sameElementSet(left.roles.bodyIgnored, right.roles.bodyIgnored) &&
        sameElementSet(left.roles.productIgnored, right.roles.productIgnored) &&
        sameElementSet(left.roles.commentItems, right.roles.commentItems) &&
        sameElementSet(left.roles.commentControls, right.roles.commentControls) &&
        sameElementSet(
          left.roles.commentDormantControls,
          right.roles.commentDormantControls,
        ) &&
        sameElementSet(left.roles.commentIgnored, right.roles.commentIgnored) &&
        sameElementSet(
          left.roles.commentTotalEvidence,
          right.roles.commentTotalEvidence,
        ) &&
        left.roles.commentCountBoundary === right.roles.commentCountBoundary &&
        left.commonRoot === right.commonRoot &&
        left.projectionPolicy.productCardinality ===
          right.projectionPolicy.productCardinality &&
        left.projectionPolicy.productOrder ===
          right.projectionPolicy.productOrder &&
        left.projectionPolicy.productFallback ===
          right.projectionPolicy.productFallback &&
        left.projectionPolicy.allowEmptyComments ===
          right.projectionPolicy.allowEmptyComments &&
        left.projectionPolicy.provenCommentCount ===
          right.projectionPolicy.provenCommentCount &&
        left.projectionPolicy.provenCommentCountSource ===
          right.projectionPolicy.provenCommentCountSource;
    };
    const projectionClasses = [];
    approved.forEach(function classifyProjection(resolution) {
      const existing = projectionClasses.find(function equivalent(candidate) {
        return sameProjection(candidate[0], resolution);
      });
      if (existing) {
        existing.push(resolution);
      } else {
        projectionClasses.push([resolution]);
      }
    });
    return { resolutions, approved, projectionClasses };
  }

  function resolveDocument(document, layouts, seed) {
    const projection = resolveProjectionClasses(document, layouts, seed);
    if (projection.projectionClasses.length !== 1) {
      const firstFailure = projection.resolutions.find(
        function failedResolution(resolution) {
          return !resolution.ok;
        }
      );
      return {
        ok: false,
        role: projection.projectionClasses.length > 1
          ? "layout"
          : (firstFailure && firstFailure.role) || "layout",
        reason: projection.projectionClasses.length > 1
          ? "ambiguous-approved-layout"
          : (firstFailure && firstFailure.reason) || "no-approved-layout",
        semanticProjectionCount: projection.projectionClasses.length,
      };
    }
    const projectionAliases = projection.projectionClasses[0];
    return {
      ...projectionAliases[0],
      layoutAliases: projectionAliases.map(function aliasId(resolution) {
        return resolution.layoutId;
      }).sort(),
      semanticProjectionCount: 1,
    };
  }

  function exactObservedElementSelectors(scope, elements, configuredSelectors) {
    const expected = uniqueElements(Array.from(elements || []));
    if (!expected.length) return [];
    const sameExpectedSet = function sameExpectedSet(selector) {
      const matches = uniqueElements(queryAllSafe(scope, [selector]));
      return matches.length === expected.length &&
        matches.every(function expectedMatch(element) {
          return expected.includes(element);
        });
    };
    const groupCandidates = Array.from(new Set(
      Array.from(configuredSelectors || [])
        .concat(proposalSelectorCandidates(expected[0])),
    ));
    const groupSelector = groupCandidates.find(sameExpectedSet);
    if (groupSelector) return [groupSelector];
    const uniqueSelectors = expected.map(function uniqueObservedSelector(element) {
      return stableExactProposalSelector(scope.ownerDocument || scope, element);
    });
    if (
      uniqueSelectors.some(function unavailableSelector(selector) {
        return !selector;
      })
    ) {
      return null;
    }
    const selectors = Array.from(new Set(uniqueSelectors));
    const combined = uniqueElements(queryAllSafe(scope, selectors));
    return combined.length === expected.length &&
      combined.every(function exactObservedElement(element) {
        return expected.includes(element);
      })
      ? selectors
      : null;
  }

  function resolveIndependentSemanticDocument(document, layouts) {
    return withPublisherVisibilityMeasurement(
      document,
      function resolveMeasuredIndependentProjection() {
        const semantic = discoverSemanticContract(document, layouts, null);
        const projection = semantic.runtimeProjection;
        if (
          !semantic.ok ||
          semantic.projectionTupleCount < 1 ||
          !projection?.commonRoot ||
          semantic.policyProposal?.complete !== true
        ) {
          return {
            ok: false,
            role: "semantic",
            reason: semantic.reason || "incomplete-independent-projection",
          };
        }
        const bodyIgnoredSelectors = Array.from(new Set(
          layouts.flatMap(function configuredBodyIgnored(layout) {
            return layout.roleProjection?.body?.ignored || [];
          }),
        ));
        const productIgnoredSelectors = Array.from(new Set(
          layouts.flatMap(function configuredProductIgnored(layout) {
            return layout.roleProjection?.product?.ignored || [];
          }),
        ));
        const commentItemHints = roleHints(layouts, "commentItems");
        const configuredCommentControlHints = roleHints(layouts, "commentControls");
        const semanticContinuationControls = Array.from(
          projection.comments.querySelectorAll("button, a[href], [role='button']"),
        ).filter(function independentContinuation(control) {
          return !projection.commentItems.some(function insideItem(item) {
            return item === control || item.contains(control);
          }) && isCommentContinuationControl(control) &&
            !isAutonomousProjectionNoiseRoot(control) &&
            !containsSemanticNoise(control, new WeakMap(), []);
        });
        const observedControlSelectors = exactObservedElementSelectors(
          projection.commonRoot, semanticContinuationControls, configuredCommentControlHints,
        );
        if (semanticContinuationControls.length && !observedControlSelectors) {
          return { ok: false, role: "comments", reason: "independent-control-selector" };
        }
        const commentControlHints = Array.from(new Set(
          configuredCommentControlHints.concat(observedControlSelectors || []),
        ));
        const commentIgnoredHints = roleHints(layouts, "commentIgnored");
        const commentItemSelectors = exactObservedElementSelectors(
          projection.comments,
          projection.commentItems,
          commentItemHints,
        );
        if (
          projection.commentItems.length > 0 &&
          (!commentItemSelectors || !commentItemSelectors.length)
        ) {
          return {
            ok: false,
            role: "comments",
            reason: "independent-item-selector",
          };
        }
        const derivedComments = deriveCommentProjectionFromItems(
          projection.comments,
          projection.commonRoot,
          projection.commentItems,
          commentControlHints,
          commentIgnoredHints,
        );
        if (!derivedComments.ok) {
          return {
            ok: false,
            role: "comments",
            reason: derivedComments.reason,
          };
        }
        const {
          commentItems,
          commentControls,
          commentConfiguredIgnored,
          commentAutonomousIgnored,
          commentIgnored,
        } = derivedComments;
        const allowEmptyComments = layouts.every(function approvedEmptyComments(layout) {
          return layout.allowEmptyComments === true;
        });
        if (
          (!commentItems.length && !allowEmptyComments) ||
          commentItems.some(function hiddenIndependentComment(item) {
            return !isRendered(item);
          }) ||
          hasUnclassifiedCommentContent(
            projection.comments,
            commentItems.concat(commentControls, commentIgnored),
          ) ||
          commentProjectionHasRisk(
            projection.comments,
            commentItems,
            commentControls,
            commentIgnored,
            allowEmptyComments,
            projection.commonRoot,
          )
        ) {
          return {
            ok: false,
            role: "comments",
            reason: "independent-comment-projection",
          };
        }
        const visibleTotal = visibleCommentTotalEvidence(
          projection.comments,
          projection.commonRoot,
          commentItems.concat(commentIgnored),
        );
        if (
          !visibleTotal.ok ||
          (visibleTotal.count !== null && visibleTotal.count !== commentItems.length)
        ) {
          return {
            ok: false,
            role: "comments",
            reason: "independent-comment-count",
          };
        }

        const bodyConfiguredIgnored = ignoredRootsWithin(
          projection.body,
          bodyIgnoredSelectors,
        );
        if (rootsOverlap(bodyConfiguredIgnored)) {
          return { ok: false, role: "body", reason: "ignored-overlap" };
        }
        const bodyAutonomousDiscovery = discoverAutonomousIgnoredRoots(
          projection.body,
          bodyConfiguredIgnored,
        );
        if (!bodyAutonomousDiscovery.ok) {
          return { ok: false, role: "body", reason: "ignored-bound" };
        }
        const bodyAutonomousIgnored = Array.from(
          bodyAutonomousDiscovery.roots,
        );
        const bodyIgnored = uniqueElements(
          bodyConfiguredIgnored.concat(bodyAutonomousIgnored),
        );
        if (
          !hasApprovedContentOutside(projection.body, bodyIgnored) ||
          containsSemanticNoise(projection.body, new WeakMap(), bodyIgnored) ||
          containsUnprovenShadowBoundary(projection.body, bodyIgnored) ||
          containsPublisherPaintRisk(projection.body, bodyIgnored)
        ) {
          return {
            ok: false,
            role: "body",
            reason: "independent-body-projection",
          };
        }

        const productConfiguredIgnored = projection.product
          ? ignoredRootsWithin(projection.product, productIgnoredSelectors)
          : [];
        if (rootsOverlap(productConfiguredIgnored)) {
          return { ok: false, role: "product", reason: "ignored-overlap" };
        }
        const productAutonomousDiscovery = projection.product
          ? discoverAutonomousIgnoredRoots(
              projection.product,
              productConfiguredIgnored,
            )
          : Object.freeze({ ok: true, roots: Object.freeze([]) });
        if (!productAutonomousDiscovery.ok) {
          return { ok: false, role: "product", reason: "ignored-bound" };
        }
        const productAutonomousIgnored = Array.from(
          productAutonomousDiscovery.roots,
        );
        const productIgnored = uniqueElements(
          productConfiguredIgnored.concat(productAutonomousIgnored),
        );
        if (projection.product && (
          !hasApprovedContentOutside(projection.product, productIgnored) ||
          containsSemanticNoise(projection.product, new WeakMap(), productIgnored) ||
          containsUnprovenShadowBoundary(projection.product, productIgnored) ||
          containsPublisherPaintRisk(projection.product, productIgnored)
        )) {
          return {
            ok: false,
            role: "product",
            reason: "independent-product-projection",
          };
        }
        const productSelectors = projection.product
          ? exactObservedElementSelectors(
              projection.commonRoot,
              [projection.product],
              semantic.policyProposal.product?.selectors || [],
            )
          : [];
        if (projection.product && (!productSelectors || productSelectors.length !== 1)) {
          return {
            ok: false,
            role: "product",
            reason: "independent-product-selector",
          };
        }
        const requiredRoles = ["title", "body", "comments"]
          .concat(projection.product ? ["product"] : []);
        const roles = {
          title: projection.title,
          body: projection.body,
          comments: projection.comments,
          product: projection.product,
          commentItems,
          commentControls,
          commentDormantControls: commentControls.filter(
            function dormantIndependentControl(control) {
              return !isRendered(control);
            },
          ),
          commentIgnored,
          commentConfiguredIgnored,
          commentAutonomousIgnored,
          commentControlScope: projection.commonRoot,
          commentCountBoundary: projection.commonRoot,
          commentTotalEvidence: visibleTotal.elements || [],
          bodyIgnored,
          bodyConfiguredIgnored,
          bodyAutonomousIgnored,
          productIgnored,
          productConfiguredIgnored,
          productAutonomousIgnored,
        };
        const approvedRoot = validateRoleRelationship(
          document,
          roles,
          requiredRoles,
          projection.commonRoot,
          allowEmptyComments && commentItems.length === 0,
        );
        if (!approvedRoot) {
          return {
            ok: false,
            role: "relationship",
            reason: "independent-approved-root",
          };
        }
        const roleDiagnostics = Object.fromEntries(
          Object.entries(semantic.roles).map(function safeRoleDiagnostics(entry) {
            return [entry[0], Object.freeze({
              count: entry[1].count,
              score: entry[1].score,
              signalCount: entry[1].signalCount,
              margin: entry[1].margin,
            })];
          }),
        );
        return {
          ok: true,
          layoutId: "independent-semantic-v1",
          layoutAliases: layouts.map(function semanticLayoutAlias(layout) {
            return layout.id;
          }).sort(),
          semanticProjectionCount: 1,
          roles,
          requiredRoles,
          commonRoot: approvedRoot,
          commentItemSelectors: commentItemSelectors || [],
          commentControlSelectors: commentControlHints,
          commentIgnoredSelectors: commentIgnoredHints,
          projectionPolicy: Object.freeze({
            allowEmptyComments,
            provenCommentCount: commentItems.length,
            provenCommentCountSource: visibleTotal.count === null
              ? "independent-exhaustive-dom"
              : "visible-comment-total",
            productCardinality: projection.product ? "required" : "zero",
            productOrder: projection.product ? projection.productOrder : null,
            productFallback: projection.product ? "separate" : "body",
            productSelectors: productSelectors || [],
            bodyIgnoredSelectors,
            productIgnoredSelectors,
          }),
          seedConsistency: null,
          roleDiagnostics: Object.freeze(roleDiagnostics),
          resolvedTitle: projection.resolvedTitle,
          authority: "independent-semantic-tuple",
        };
      },
      function rejectUnsafeIndependentMeasurement() {
        return {
          ok: false,
          role: "measurement",
          reason: "unsafe-independent-measurement",
        };
      },
    );
  }

  function matchesIncludingRoot(rootNode, selectors) {
    const matches = [];
    if (rootNode.nodeType !== 1) {
      return matches;
    }
    if (elementMatchesAny(rootNode, selectors)) {
      matches.push(rootNode);
    }
    return uniqueElements(matches.concat(queryAllSafe(rootNode, selectors)));
  }

  function forgetRemovedTree(node, state) {
    if (node.nodeType !== 1) {
      return;
    }
    [node].concat(Array.from(node.querySelectorAll(`[${ATTR.keep}], .${CLASS.keep}`))).forEach(
      function forget(element) {
        state.ownedElementSet.delete(element);
        state.expectedMarkerShapes.delete(element);
        state.ownedElements.delete(element);
      }
    );
  }

  function installBootstrapGuard(browserRoot, runtime, styleElement) {
    const document = browserRoot.document;
    const html = document.documentElement;
    let terminallyBlocked = false;
    const reservedAttributes = function reservedAttributes(element) {
      return Array.from(element.attributes || [])
        .map(function attributeName(attribute) { return attribute.name; })
        .filter(function hdfAttribute(name) { return name.startsWith(HDF_ATTRIBUTE_PREFIX); })
        .sort();
    };
    const rootShapeIntact = function rootShapeIntact() {
      const phase = runtime.releasePhase;
      const lockClass = html.classList.contains(CLASS.lock);
      const lockAttribute = html.getAttribute(ATTR.lock) === "1";
      const readyClass = html.classList.contains(CLASS.ready);
      const readyAttribute = html.getAttribute(ATTR.ready) === "1";
      const protocol = html.getAttribute(ATTR.protocol);
      const state = html.getAttribute(ATTR.state);
      const status = html.getAttribute(ATTR.status);
      if (phase === "armed") {
        return lockClass && lockAttribute && readyClass && readyAttribute &&
          protocol === PROTOCOL_VERSION && state === "ready" && status === "ready";
      }
      if (phase === "released" || phase === "frozen") {
        return !lockClass && !html.hasAttribute(ATTR.lock) && readyClass && readyAttribute &&
          protocol === PROTOCOL_VERSION && state === "ready" && status === "ready";
      }
      const preReleaseStatusExact =
        (state === "locked" && /^locked-/u.test(status || "")) ||
        (state === "blocked" && /^blocked-/u.test(status || ""));
      return lockClass && lockAttribute && !readyClass && !html.hasAttribute(ATTR.ready) &&
        !html.hasAttribute(ATTR.protocol) && preReleaseStatusExact;
    };
    const elementShapeIntact = function elementShapeIntact(element) {
      if (!element || element.nodeType !== 1) return true;
      if (element === styleElement) {
        return reservedAttributes(element).every(function exactRuntimeAttribute(name) {
          return name === "data-hotdeal-focus-runtime-style";
        }) && hdfClasses(element).length === 0;
      }
      if (element === html) {
        if (!rootShapeIntact()) return false;
        const allowedRootAttributes = new Set([
          ATTR.lock,
          ATTR.ready,
          ATTR.protocol,
          ATTR.state,
          ATTR.status,
          ...(runtime.projectionState?.ownedElements.has(element)
            ? [ATTR.keep, ATTR.shell, ATTR.deep, ATTR.role]
            : []),
        ]);
        if (!reservedAttributes(element).every(function allowedRootAttribute(name) {
          return allowedRootAttributes.has(name);
        })) return false;
        if (runtime.projectionState?.ownedElements.has(element)) {
          return markerShapeMatches(
            element,
            runtime.projectionState.expectedMarkerShapes.get(element),
          );
        }
        return projectionHdfClasses(element).length === 0 &&
          ![ATTR.keep, ATTR.shell, ATTR.deep, ATTR.role].some(
            function hasProjectionAttribute(name) { return element.hasAttribute(name); }
          );
      }
      if (runtime.projectionState?.ownedElements.has(element)) {
        return markerShapeMatches(
          element,
          runtime.projectionState.expectedMarkerShapes.get(element),
        );
      }
      return reservedAttributes(element).length === 0 && hdfClasses(element).length === 0;
    };
    const treeShapeIntact = function treeShapeIntact(node) {
      if (!node || node.nodeType !== 1) return true;
      return [node].concat(Array.from(node.querySelectorAll("*"))).every(elementShapeIntact);
    };
    const repairVerifiedProtocol = function repairVerifiedProtocol(mutations) {
      const state = runtime.projectionState;
      if (
        (runtime.terminallyBlocked && runtime.releasePhase !== "frozen") || !runtime.authorizedReady ||
        !["armed", "released", "frozen"].includes(runtime.releasePhase) || !state ||
        runtime.activeNonce !== state.nonce
      ) return;
      // Restore only private presentation metadata from the accepted in-memory
      // projection. Never infer ownership from publisher-supplied attributes.
      const changedElements = new Set([html, styleElement]);
      for (const mutation of mutations) {
        const target = mutation.target?.nodeType === 1
          ? mutation.target : mutation.target?.parentElement;
        if (target) changedElements.add(target);
        for (const node of mutation.addedNodes || []) {
          if (node.nodeType !== 1) continue;
          changedElements.add(node);
          const descendants = node.querySelectorAll("*");
          if (descendants.length > MAX_SEMANTIC_DESCENDANTS) return;
          for (const descendant of descendants) changedElements.add(descendant);
        }
        if (changedElements.size > MAX_SEMANTIC_DESCENDANTS) return;
      }
      const setExactAttribute = function setExactAttribute(element, name, value) {
        if (value === null) {
          if (element.hasAttribute(name)) element.removeAttribute(name);
        } else if (element.getAttribute(name) !== value) {
          element.setAttribute(name, value);
        }
      };
      for (const element of changedElements) {
        if (!element.isConnected && element !== styleElement) continue;
        const expected = state.ownedElements.has(element)
          ? state.expectedMarkerShapes.get(element) : null;
        const allowed = new Set(expected ? [ATTR.keep, ATTR.shell, ATTR.deep, ATTR.role] : []);
        if (element === html) {
          [ATTR.ready, ATTR.protocol, ATTR.state, ATTR.status].forEach((name) => allowed.add(name));
          if (runtime.releasePhase === "armed") allowed.add(ATTR.lock);
        }
        if (element === styleElement) allowed.add("data-hotdeal-focus-runtime-style");
        for (const name of reservedAttributes(element)) {
          if (!allowed.has(name)) element.removeAttribute(name);
        }
        if (expected && !markerShapeMatches(element, expected)) {
          for (const key of ["keep", "shell", "deep", "role"]) {
            setExactAttribute(element, ATTR[key], expected[key]);
          }
          const expectedClasses = new Set(expected.classes);
          for (const name of projectionHdfClasses(element)) {
            if (!expectedClasses.has(name)) element.classList.remove(name);
          }
          for (const name of expected.classes) {
            if (!element.classList.contains(name)) element.classList.add(name);
          }
        } else if (!expected) {
          for (const name of projectionHdfClasses(element)) element.classList.remove(name);
        }
      }
      if (runtime.releasePhase === "armed") {
        setExactAttribute(html, ATTR.lock, "1");
        if (!html.classList.contains(CLASS.lock)) html.classList.add(CLASS.lock);
        runtime.bootstrapLock?.repairInline?.();
      } else if (html.classList.contains(CLASS.lock)) {
        html.classList.remove(CLASS.lock);
      }
      if (!html.classList.contains(CLASS.ready)) html.classList.add(CLASS.ready);
      setExactAttribute(html, ATTR.ready, "1");
      setExactAttribute(html, ATTR.protocol, PROTOCOL_VERSION);
      setExactAttribute(html, ATTR.state, "ready");
      setExactAttribute(html, ATTR.status, "ready");
      setExactAttribute(styleElement, "data-hotdeal-focus-runtime-style", PROTOCOL_VERSION);
      if (styleElement.textContent !== runtime.expectedStyleText) {
        styleElement.textContent = runtime.expectedStyleText;
      }
      if (!styleElement.isConnected) (document.head || html).appendChild(styleElement);
    };
    const guard = createNativeMutationObserver(browserRoot, function enforceBootstrapLock(mutations) {
      try {
        if (terminallyBlocked) {
          return;
        }
        repairVerifiedProtocol(mutations);
        const styleFailure = runtimeGateStyleFailure(styleElement, runtime);
        const styleIntact = styleFailure === null;
        const changedTreesIntact = mutations.every(function changedTreeIntact(mutation) {
          if (!elementShapeIntact(mutation.target)) return false;
          return Array.from(mutation.addedNodes || []).every(treeShapeIntact);
        });
        const rootIntact = rootShapeIntact();
        const bootstrapInlineIntact =
          ["released", "frozen"].includes(runtime.releasePhase) || runtime.bootstrapLock?.intact();
        if (!styleIntact || !rootIntact || !changedTreesIntact || !bootstrapInlineIntact) {
          terminallyBlocked = true;
          const reason = !styleIntact
            ? `runtime-style-tamper-bootstrap-${styleFailure || "unknown"}`
            : !rootIntact
              ? "protocol-root-tamper"
              : !changedTreesIntact
                ? "protocol-marker-tamper"
                : `bootstrap-inline-lock-tamper-${
                    runtime.bootstrapLock?.mismatchProperty?.() || "unknown"
                  }`;
          runtime.enterTerminal(reason);
        }
      } catch (_error) {
        terminallyBlocked = true;
        runtime.enterTerminal("bootstrap-guard-exception");
      }
    });
    guard.observe(document.documentElement, {
      subtree: true,
      childList: true,
      characterData: true,
      attributes: true,
    });
    runtime.bootstrapGuard = guard;
  }

  function installCascadeGuard(browserRoot, runtime, styleElement) {
    const document = browserRoot.document;
    const pendingElements = new Set();
    let fullScanRequired = true;
    const MAX_PENDING_ROOTS = 256;
    const MAX_BOUNDED_ELEMENTS = 20_000;
    const visible = function visiblyRendered(element) {
      const style = nativeComputedStyle(browserRoot, element);
      return Boolean(style) && style.display !== "none" && style.visibility !== "hidden" &&
        Number(style.opacity) !== 0 && element.getClientRects().length > 0;
    };
    const queueElement = function queueCascadeElement(element) {
      if (!element || element.nodeType !== 1 || element === styleElement) return;
      if (!["released", "frozen"].includes(runtime.releasePhase)) {
        pendingElements.clear();
        fullScanRequired = true;
        return;
      }
      pendingElements.add(element);
      if (pendingElements.size > MAX_PENDING_ROOTS) {
        runtime.enterTerminal("cascade-mutation-budget");
      }
    };
    const authorizedCommentControlStateMutation =
      function authorizedCommentControlStateMutation(mutation) {
        const state = runtime.projectionState;
        const target = mutation?.target;
        if (
          !state ||
          mutation?.type !== "attributes" ||
          !COMMENT_CONTROL_STATE_ATTRIBUTES.has(mutation.attributeName) ||
          target?.nodeType !== 1 ||
          !insideCommentProjection(state, target)
        ) {
          return false;
        }
        let candidate = target;
        while (candidate && state.commentControlScope.contains(candidate)) {
          if (
            state.commentControlRoots.has(candidate) &&
            elementMatchesAny(candidate, state.commentControlSelectors)
          ) {
            return true;
          }
          candidate = candidate.parentElement;
        }
        return false;
      };
    const authorizedProjectedMarkerClassMutation =
      function authorizedProjectedMarkerClassMutation(mutation) {
        const state = runtime.projectionState;
        const target = mutation?.target;
        return Boolean(
          state &&
          mutation?.type === "attributes" &&
          mutation.attributeName === "class" &&
          target?.nodeType === 1 &&
          state.ownedElements.has(target) &&
          markerShapeMatches(target, state.expectedMarkerShapes.get(target))
        );
      };
    const nodeIntroducesCascadeSurface = function nodeIntroducesCascadeSurface(node) {
      if (node?.nodeType !== 1) return false;
      return node.matches(
        "style, link[rel~='stylesheet' i], [style], dialog[open], [popover], iframe, object, embed",
      ) || Boolean(node.querySelector(
        "style, link[rel~='stylesheet' i], [style], dialog[open], [popover], iframe, object, embed",
      ));
    };
    const stylesheetIntroducesPublisherPaint = function stylesheetIntroducesPublisherPaint(node) {
      if (node?.nodeType !== 1 || node.tagName !== "STYLE") return false;
      const cssText = String(node.textContent || "").toLocaleLowerCase();
      if (!cssText) return false;
      const pseudoContent = /::?(?:before|after|backdrop)\s*\{[\s\S]{0,1024}?content\s*:/u;
      const viewportOverlay = /position\s*:\s*(?:fixed|sticky)\b/u.test(cssText) &&
        /(?:z-index|inset|(?:width|height)\s*:\s*100(?:vw|vh|%))/u.test(cssText);
      const noisePseudoContent =
        /content\s*:\s*["'][^"']*(?:advert|sponsor|promo|affiliate|recommend|related|popular|ranking|광고|추천|관련|인기)[^"']*["']/iu;
      return viewportOverlay || (pseudoContent.test(cssText) && noisePseudoContent.test(cssText));
    };
    const quarantinePublisherPaintStylesheet =
      function quarantinePublisherPaintStylesheet(node) {
        const style = node?.nodeType === 1
          ? (node.tagName === "STYLE" ? node : node.closest?.("style"))
          : node?.parentElement?.closest?.("style");
        if (
          !style ||
          style === styleElement ||
          !stylesheetIntroducesPublisherPaint(style)
        ) {
          return true;
        }
        try {
          style.remove();
        } catch (_error) {
          try {
            style.parentNode?.removeChild(style);
          } catch (_fallbackError) {
            // The disabled/media fallback below is independently authoritative.
          }
        }
        if (!style.isConnected) return true;
        try { style.disabled = true; } catch (_error) {}
        try {
          if (style.sheet) style.sheet.disabled = true;
        } catch (_error) {}
        try { style.media = "not all"; } catch (_error) {}
        return !style.isConnected || style.disabled === true || style.media === "not all";
    };
    const deferredAtomicProjectionMutation =
      function deferredAtomicProjectionMutation(mutation) {
        const state = runtime.projectionState;
        const mutationParent = mutation?.target?.nodeType === 1
          ? mutation.target
          : mutation?.target?.parentElement;
        const insideAtomicRole = Boolean(state && mutationParent) &&
          [state.roles.title, state.roles.body, state.roles.product]
            .filter(Boolean)
            .some(function parentIsInsideAtomicRole(roleRoot) {
              return roleRoot === mutationParent || roleRoot.contains(mutationParent);
            });
        if (!insideAtomicRole) return false;
        if (mutation.type === "characterData") return true;
        if (mutation.type !== "childList") return false;
        return [...mutation.addedNodes, ...mutation.removedNodes]
          .every(function atomicMutationAvoidsCascadeSurface(node) {
            return !nodeIntroducesCascadeSurface(node);
          });
      };
    const deferredCommentProjectionMutation =
      function deferredCommentProjectionMutation(mutation) {
        const state = runtime.projectionState;
        const mutationParent = mutation?.target?.nodeType === 1
          ? mutation.target
          : mutation?.target?.parentElement;
        if (!state || !mutationParent || !insideCommentProjection(state, mutationParent)) {
          return false;
        }
        if (mutation.type === "characterData") return true;
        if (mutation.type !== "childList") return false;
        return [...mutation.addedNodes, ...mutation.removedNodes]
          .every(function commentMutationAvoidsCascadeSurface(node) {
            return !nodeIntroducesCascadeSurface(node);
          });
      };
    const authorizedMeasurementMutation = function authorizedMeasurementMutation(mutation) {
      const html = document.documentElement;
      const restore = MEASUREMENT_HTML_RESTORES.get(html);
      if (
        !restore ||
        mutation?.type !== "attributes" ||
        mutation.target !== html
      ) {
        return false;
      }
      if (mutation.attributeName === ATTR.measure) {
        return !html.hasAttribute(ATTR.measure);
      }
      return mutation.attributeName === "style" &&
        restore.properties.every(function propertyWasRestored(snapshot) {
          return html.style.getPropertyValue(snapshot.property) === snapshot.value &&
            html.style.getPropertyPriority(snapshot.property) === snapshot.priority;
        });
    };
    const exposesUnowned = function exposesUnowned(elements) {
      return elements.some(function exposedOutsideProjection(element) {
        return element.getAttribute(ATTR.keep) !== runtime.activeNonce && visible(element);
      });
    };
    const exposesRootPaint = function exposesRootPaint() {
      return [document.documentElement, document.body].filter(Boolean).some(
        function rootPaintVisible(element) {
          const style = nativeComputedStyle(browserRoot, element);
          if (!style || style.backgroundImage !== "none") return true;
          return ["::before", "::after"].some(function pseudoPaintVisible(pseudo) {
            const pseudoStyle = nativeComputedStyle(browserRoot, element, pseudo);
            if (!pseudoStyle) return true;
            const content = String(pseudoStyle.content || "");
            return !["", "none", "normal", '\"\"'].includes(content) ||
              pseudoStyle.backgroundImage !== "none";
          });
        }
      );
    };
    const exposesTopLayer = function exposesTopLayer() {
      const candidates = Array.from(document.querySelectorAll("dialog[open], [popover]"))
        .filter(function activeTopLayer(element) {
          return element.matches("dialog[open]") || activePopover(element);
        });
      if (document.fullscreenElement) candidates.push(document.fullscreenElement);
      return uniqueElements(candidates).some(function visibleTopLayer(element) {
        if (visible(element)) return true;
        const backdrop = nativeComputedStyle(browserRoot, element, "::backdrop");
        return Boolean(backdrop) && backdrop.display !== "none" &&
          backdrop.visibility !== "hidden" && Number(backdrop.opacity) !== 0;
      });
    };
    const quarantineUnownedCascadeLeaks = function quarantineUnownedCascadeLeaks(
      elements,
    ) {
      const candidates = uniqueElements(
        (elements || []).concat(
          Array.from(document.querySelectorAll("dialog[open], [popover]")),
          document.fullscreenElement ? [document.fullscreenElement] : [],
        ),
      );
      candidates.forEach(function quarantineVisiblePublisherSurface(element) {
        if (
          element.getAttribute(ATTR.keep) === runtime.activeNonce ||
          !visible(element)
        ) {
          return;
        }
        try {
          if (element.matches("dialog[open]")) {
            if (typeof element.close === "function") element.close();
            if (element.hasAttribute("open")) element.removeAttribute("open");
          }
        } catch (_error) {
          try { element.removeAttribute("open"); } catch (_fallbackError) {}
        }
        try {
          if (activePopover(element) && typeof element.hidePopover === "function") {
            element.hidePopover();
          }
        } catch (_error) {
          // The inline quarantine below remains authoritative.
        }
        [
          ["display", "none"],
          ["visibility", "hidden"],
          ["content-visibility", "hidden"],
          ["opacity", "0"],
          ["pointer-events", "none"],
        ].forEach(function applyInlineQuarantine(entry) {
          element.style.setProperty(entry[0], entry[1], "important");
        });
      });
      return !exposesTopLayer() && !exposesUnowned(candidates);
    };
    const cascadeLeakRemains = function cascadeLeakRemains(elements) {
      if (exposesRootPaint()) return true;
      if (!exposesTopLayer() && !exposesUnowned(elements)) return false;
      return !quarantineUnownedCascadeLeaks(elements) ||
        exposesRootPaint() ||
        exposesTopLayer() ||
        exposesUnowned(elements);
    };
    const collectBoundedFullScan = function collectBoundedCascadeFullScan() {
      const candidates = Array.from(document.body.querySelectorAll("*"));
      if (candidates.length > MAX_BOUNDED_ELEMENTS) {
        runtime.enterTerminal("cascade-scan-budget");
        return null;
      }
      return candidates;
    };
    runtime.prepareCascadeRelease = function prepareCascadeRelease() {
      if (
        runtime.terminallyBlocked ||
        !document.body ||
        !runtimeGateStyleIntact(styleElement, runtime)
      ) {
        if (!runtime.terminallyBlocked) {
          runtime.enterTerminal(
            document.body ? "runtime-style-tamper-prepare" : "cascade-body-unavailable",
          );
        }
        return null;
      }
      const candidates = collectBoundedFullScan();
      if (!candidates) return null;
      pendingElements.clear();
      fullScanRequired = false;
      return candidates;
    };
    runtime.verifyCascadeRelease = function verifyCascadeRelease(candidates) {
      if (
        runtime.terminallyBlocked ||
        !runtime.authorizedReady ||
        !Array.isArray(candidates)
      ) {
        if (!runtime.terminallyBlocked) runtime.enterTerminal("cascade-release-state");
        return false;
      }
      let releaseCandidates = candidates;
      if (fullScanRequired) {
        releaseCandidates = collectBoundedFullScan();
        if (!releaseCandidates) return false;
      }
      pendingElements.clear();
      fullScanRequired = false;
      if (!runtimeGateStyleIntact(styleElement, runtime)) {
        runtime.enterTerminal("runtime-style-tamper-release");
        return false;
      }
      if (cascadeLeakRemains(releaseCandidates)) {
        runtime.enterTerminal("cascade-visible-leak");
        return false;
      }
      return true;
    };
    runtime.verifyUnlockedCascadeRelease = function verifyUnlockedCascadeRelease() {
      if (
        runtime.terminallyBlocked ||
        runtime.releasePhase !== "released" ||
        !runtime.authorizedReady ||
        !document.body
      ) {
        if (!runtime.terminallyBlocked) runtime.enterTerminal("cascade-unlock-state");
        return false;
      }
      const releaseCandidates = collectBoundedFullScan();
      if (!releaseCandidates) return false;
      pendingElements.clear();
      fullScanRequired = false;
      if (!runtimeGateStyleIntact(styleElement, runtime)) {
        runtime.enterTerminal("runtime-style-tamper-unlock");
        return false;
      }
      if (cascadeLeakRemains(releaseCandidates)) {
        runtime.enterTerminal("cascade-visible-leak");
        return false;
      }
      return true;
    };
    const verifyCascade = function verifyCascade() {
      if (runtime.terminallyBlocked && runtime.releasePhase !== "frozen") return false;
      if (!runtimeGateStyleIntact(styleElement, runtime)) {
        runtime.enterTerminal("runtime-style-tamper-sentinel");
        return false;
      }
      if (!["released", "frozen"].includes(runtime.releasePhase)) {
        // Before unlock, prepareCascadeRelease/verifyCascadeRelease own the
        // authoritative full snapshot. A competing per-frame full scan here
        // can starve the two-frame proof on publisher-heavy documents.
        return true;
      }
      if (!runtime.authorizedReady || !document.body) {
        pendingElements.clear();
        fullScanRequired = true;
        return true;
      }
      let candidates = [];
      if (fullScanRequired) {
        candidates = collectBoundedFullScan();
        if (!candidates) return false;
      } else {
        for (const root of pendingElements) {
          if (!root.isConnected || !document.body.contains(root)) continue;
          candidates.push(root, ...root.querySelectorAll("*"));
          if (candidates.length > MAX_BOUNDED_ELEMENTS) break;
        }
      }
      pendingElements.clear();
      fullScanRequired = false;
      if (candidates.length > MAX_BOUNDED_ELEMENTS) {
        runtime.enterTerminal("cascade-scan-budget");
        return false;
      }
      if (cascadeLeakRemains(candidates)) {
        runtime.enterTerminal("cascade-visible-leak");
        return false;
      }
      return true;
    };
    const observer = createNativeMutationObserver(browserRoot, function keepGateStyleLast(mutations) {
      try {
        const containsMeasurementMutation = mutations.some(authorizedMeasurementMutation);
        if (
          mutations.length > 0 &&
          mutations.every(function authorizedInternalMutation(mutation) {
            return authorizedProjectedMarkerClassMutation(mutation) ||
              authorizedCommentControlStateMutation(mutation) ||
              deferredAtomicProjectionMutation(mutation) ||
              deferredCommentProjectionMutation(mutation) ||
              authorizedMeasurementMutation(mutation);
          })
        ) {
          if (containsMeasurementMutation) {
            MEASUREMENT_HTML_RESTORES.delete(document.documentElement);
          }
          return;
        }
        let stylesheetChanged = false;
        const publisherPaintStylesheets = new Set();
        mutations.forEach(function recordCascadeMutation(mutation) {
          if (mutation.type === "attributes") {
            if (mutation.target === styleElement) return;
            if (mutation.target.tagName === "STYLE" || mutation.target.tagName === "LINK") {
              stylesheetChanged = true;
              fullScanRequired = true;
              if (stylesheetIntroducesPublisherPaint(mutation.target)) {
                publisherPaintStylesheets.add(mutation.target);
              }
            } else {
              queueElement(mutation.target);
            }
            return;
          }
          if (
            mutation.type === "characterData" &&
            mutation.target.parentElement?.closest("style")
          ) {
            stylesheetChanged = true;
            fullScanRequired = true;
            const style = mutation.target.parentElement?.closest("style");
            if (stylesheetIntroducesPublisherPaint(style)) {
              publisherPaintStylesheets.add(style);
            }
          }
          Array.from(mutation.addedNodes).forEach(function addedCascadeNode(node) {
            if (node === styleElement || node.nodeType !== 1) return;
            if (
              node.tagName === "STYLE" ||
              (node.tagName === "LINK" && /stylesheet/i.test(node.getAttribute("rel") || "")) ||
              node.querySelector("style, link[rel~='stylesheet' i]")
            ) {
              stylesheetChanged = true;
              fullScanRequired = true;
              if (stylesheetIntroducesPublisherPaint(node)) {
                publisherPaintStylesheets.add(node);
              }
              Array.from(node.querySelectorAll?.("style") || [])
                .filter(stylesheetIntroducesPublisherPaint)
                .forEach(function rememberPublisherPaintStyle(style) {
                  publisherPaintStylesheets.add(style);
                });
            }
            queueElement(node);
          });
        });
        if (stylesheetChanged) {
          if (
            Array.from(publisherPaintStylesheets).some(
              function quarantineFailed(style) {
                return !quarantinePublisherPaintStylesheet(style);
              },
            )
          ) {
            runtime.enterTerminal("projection-publisher-invariant-uncontained");
            return;
          }
          if (!runtimeGateStyleIntact(styleElement, runtime)) {
            runtime.enterTerminal("runtime-style-tamper-cascade-pre");
            return;
          }
          (document.head || document.documentElement).appendChild(styleElement);
          if (!runtimeGateStyleIntact(styleElement, runtime)) {
            runtime.enterTerminal("runtime-style-tamper-cascade-post");
          }
        }
      } catch (_error) {
        runtime.enterTerminal("cascade-observer-exception");
      }
    });
    observer.observe(document.documentElement, {
      subtree: true,
      childList: true,
      characterData: true,
      attributes: true,
      attributeFilter: [
        "href", "rel", "media", "disabled", "style", "class", "hidden", "open", "popover",
      ],
    });
    runtime.cascadeGuard = observer;
    runtime.discardCascadeRecords = function discardCascadeRecords() {
      observer.takeRecords();
      pendingElements.clear();
      fullScanRequired = false;
    };
    const sentinelFrame = function cascadeSentinelFrame() {
      try {
        verifyCascade();
        if (!runtime.terminallyBlocked || runtime.releasePhase === "frozen") {
          runtime.cascadeFrameId = nativeAnimationFrame(browserRoot, sentinelFrame);
        }
      } catch (_error) {
        runtime.enterTerminal("cascade-sentinel-exception");
      }
    };
    try {
      runtime.cascadeFrameId = nativeAnimationFrame(browserRoot, sentinelFrame);
    } catch (_error) {
      runtime.enterTerminal("cascade-sentinel-exception");
    }
  }

  function proveStandaloneCascadeRelease(
    browserRoot,
    runtime,
    styleElement,
    cascadeSnapshot,
    release
  ) {
    const document = browserRoot.document;
    runtime.releaseProofStage = "entered";
    if (!document.body) {
      runtime.releaseProofStage = "precondition-no-body";
      return false;
    }
    if (runtime.terminallyBlocked) {
      runtime.releaseProofStage = "precondition-terminal";
      return false;
    }
    if (runtime.releasePending) {
      runtime.releaseProofStage = "precondition-pending";
      return false;
    }
    runtime.releasePending = true;
    runtime.releaseProofStage = "pending";
    let probe = null;
    const discardProbe = function discardReleaseProbe() {
      if (probe?.isConnected) {
        try {
          probe.remove();
        } catch (_error) {
          try { probe.parentNode?.removeChild(probe); } catch (_fallbackError) {}
        }
      }
      if (runtime.releaseProbe === probe) runtime.releaseProbe = null;
      runtime.releasePending = false;
      runtime.releaseProofFrameId = 0;
    };
    const reject = function rejectReleaseProof(reason) {
      discardProbe();
      runtime.enterTerminal(reason);
    };
    try {
      probe = document.createElement("div");
      const proofNonce = runtime.activeNonce;
      if (!proofNonce) {
        reject("standalone-cascade-proof-nonce");
        return false;
      }
      probe.setAttribute("data-hdf-v2-release-probe", proofNonce);
      probe.textContent = "hotdeal-focus-release-probe";
      const armProbe = function armStandaloneCascadeProbe() {
        probe.style.setProperty("display", "block");
        probe.style.setProperty("visibility", "visible");
        probe.style.setProperty("opacity", "1");
        probe.style.setProperty("position", "fixed");
        probe.style.setProperty("inset", "0");
        probe.style.setProperty("z-index", "2147483647");
      };
      armProbe();
      document.body.appendChild(probe);
      runtime.releaseProbe = probe;
      runtime.releaseProofStage = "probe-appended";
      let provedFrames = 0;
      const sample = function sampleStandaloneCascade() {
        runtime.releaseProofFrameId = 0;
        runtime.releaseProofSampleCount += 1;
        runtime.releaseProofStage = "sample-started";
        try {
          if (runtime.terminallyBlocked) {
            discardProbe();
            return;
          }
          const computed = nativeComputedStyle(browserRoot, probe);
          const inlineStateIntact = probe.style.getPropertyValue("display") === "block" &&
            probe.style.getPropertyPriority("display") === "" &&
            probe.style.getPropertyValue("visibility") === "visible" &&
            probe.style.getPropertyPriority("visibility") === "" &&
            probe.style.getPropertyValue("opacity") === "1" &&
            probe.style.getPropertyPriority("opacity") === "";
          const nonceBoundRuleApplied = Boolean(computed) &&
            computed.getPropertyValue("--hdf-v2-cascade-proof").trim() === proofNonce;
          const hidden = Boolean(computed) &&
            computed.display === "none" &&
            computed.visibility === "hidden" &&
            Number(computed.opacity) === 0 &&
            probe.getClientRects().length === 0;
          if (
            !inlineStateIntact ||
            !nonceBoundRuleApplied ||
            !hidden ||
            !runtimeGateStyleIntact(styleElement, runtime)
          ) {
            reject("standalone-cascade-release-proof");
            return;
          }
          provedFrames += 1;
          runtime.releaseProofStage = "sample-proved";
          if (provedFrames < CASCADE_PROOF_FRAMES) {
            armProbe();
            runtime.releaseProofStage = "frame-rescheduled";
            runtime.releaseProofFrameId = nativeAnimationFrame(browserRoot, sample);
            return;
          }
          runtime.standaloneCascadeProof = Object.freeze({
            authority: "userscript-runtime-style",
            frameCount: provedFrames,
            nonceBound: true,
            unownedHidden: true,
          });
          discardProbe();
          runtime.releaseProofStage = "cascade-verifying";
          if (
            !runtimeGateStyleIntact(styleElement, runtime) ||
            !runtime.verifyCascadeRelease(cascadeSnapshot)
          ) {
            if (!runtime.terminallyBlocked) runtime.enterTerminal("cascade-release-proof");
            return;
          }
          runtime.releaseProofStage = "releasing";
          release();
        } catch (_error) {
          reject("standalone-cascade-release-exception");
        }
      };
      runtime.releaseProofStage = "frame-scheduled";
      runtime.releaseProofFrameId = nativeAnimationFrame(browserRoot, sample);
      return true;
    } catch (_error) {
      reject("standalone-cascade-release-exception");
      return false;
    }
  }

  function installIntegrityObserver(browserRoot, runtime, state, styleElement) {
    const document = browserRoot.document;
    const protocolAttributes = new Set([
      ATTR.keep,
      ATTR.deep,
      ATTR.shell,
      ATTR.role,
      ATTR.ready,
      ATTR.protocol,
      ATTR.lock,
      ATTR.state,
      ATTR.status,
    ]);
    const mediaAttributes = new Set([
      "src",
      "srcset",
      "sizes",
      "poster",
      "loading",
      "decoding",
      "width",
      "height",
      "data-src",
      "data-srcset",
      "class",
      "style",
    ]);
    const trackedRoots = function trackedRoots(rootSet) {
      return Array.from(rootSet);
    };
    const touchesCommentTotalEvidence = function touchesCommentTotalEvidence(node) {
      if (!node) return false;
      const element = node.nodeType === 1 ? node : node.parentElement;
      if (!element) return false;
      return trackedRoots(state.commentTotalEvidenceRoots).some(
        function insideExactCommentTotal(evidence) {
          return evidence === element || evidence.contains(element);
        }
      );
    };
    const containsCommentTotalEvidence = function containsCommentTotalEvidence(node) {
      if (!node || node.nodeType !== 1) return false;
      return trackedRoots(state.commentTotalEvidenceRoots).some(
        function containsExactCommentTotal(evidence) {
          return evidence === node || node.contains(evidence);
        }
      );
    };
    const mutationTouchesCommentTotalEvidence =
      function mutationTouchesCommentTotalEvidence(mutation) {
        return touchesCommentTotalEvidence(mutation.target) ||
          Array.from(mutation.addedNodes || []).some(function addedEvidence(node) {
            return touchesCommentTotalEvidence(node) || containsCommentTotalEvidence(node);
          }) ||
          Array.from(mutation.removedNodes || []).some(function removedEvidence(node) {
            return touchesCommentTotalEvidence(node) || containsCommentTotalEvidence(node);
          });
      };
    const insideOwnedTitleSurface = function insideOwnedTitleSurface(node) {
      const titleRoot = state.roles.title;
      return Boolean(node) &&
        (titleRoot === node || titleRoot.contains(node)) &&
        state.ownedElements.has(node);
    };
    const closestTrackedRoot = function closestTrackedRoot(element, rootSet) {
      let candidate = element;
      while (candidate && state.commentControlScope.contains(candidate)) {
        if (rootSet.has(candidate)) {
          return candidate;
        }
        candidate = candidate.parentElement;
      }
      return null;
    };
    const safeStyleStateChange = function safeStyleStateChange(element, oldValue) {
      const parseDeclarations = function parseDeclarations(value) {
        const declarations = new Map();
        String(value || "").split(";").forEach(function parseDeclaration(declaration) {
          const separator = declaration.indexOf(":");
          if (separator < 1) return;
          declarations.set(
            declaration.slice(0, separator).trim().toLocaleLowerCase(),
            declaration.slice(separator + 1).trim(),
          );
        });
        return declarations;
      };
      const before = parseDeclarations(oldValue);
      const after = parseDeclarations(element.getAttribute("style"));
      const changed = [...new Set([...before.keys(), ...after.keys()])]
        .filter(function changedProperty(property) {
          return before.get(property) !== after.get(property);
        });
      const allowed = new Set([
        "opacity",
        "visibility",
        "width",
        "height",
        "aspect-ratio",
      ]);
      return changed.length > 0 && changed.every(function safeProperty(property) {
        return allowed.has(property) &&
          !/url\s*\(|expression\s*\(|javascript:/iu.test(after.get(property) || "");
      });
    };
    const safeMediaAttribute = function safeMediaAttribute(
      element,
      attributeName,
      oldValue,
    ) {
      if (
        !mediaAttributes.has(attributeName) ||
        !element.matches("img, source, picture, video, audio, iframe")
      ) {
        return false;
      }
      const value = element.getAttribute(attributeName) || "";
      if (/^(?:src|srcset|poster|data-src|data-srcset)$/u.test(attributeName)) {
        return !/[\u0000-\u001f]|javascript:|data:text\/html/iu.test(value);
      }
      if (attributeName === "class") {
        const stateTokens = new Set([
          "lazy",
          "lazyload",
          "lazyloading",
          "lazyloaded",
          "loading",
          "loaded",
        ]);
        const stableTokens = function stableTokens(raw) {
          return String(raw || "").split(/\s+/).filter(Boolean)
            .filter(function notLazyState(token) { return !stateTokens.has(token); })
            .sort();
        };
        return JSON.stringify(stableTokens(oldValue)) ===
          JSON.stringify(stableTokens(value));
      }
      if (attributeName === "style") {
        return safeStyleStateChange(element, oldValue);
      }
      if (attributeName === "loading") {
        return value === "" || /^(?:lazy|eager)$/u.test(value);
      }
      if (attributeName === "decoding") {
        return value === "" || /^(?:async|sync|auto)$/u.test(value);
      }
      if (attributeName === "width" || attributeName === "height") {
        return value === "" || /^\d{1,6}$/u.test(value);
      }
      return value.length <= 512;
    };
    const exactProtocolAttribute = function exactProtocolAttribute(element, name) {
      if (!protocolAttributes.has(name)) {
        return false;
      }
      if (element === document.documentElement) {
        return !element.hasAttribute(ATTR.lock) &&
          !element.classList.contains(CLASS.lock) &&
          element.classList.contains(CLASS.ready) &&
          element.getAttribute(ATTR.ready) === "1" &&
          element.getAttribute(ATTR.protocol) === PROTOCOL_VERSION &&
          element.getAttribute(ATTR.state) === "ready" &&
          element.getAttribute(ATTR.status) === "ready";
      }
      if (!state.ownedElements.has(element)) {
        return hdfClasses(element).length === 0 &&
          !Array.from(element.attributes || []).some(function reservedMarker(attribute) {
            return attribute.name.startsWith(HDF_ATTRIBUTE_PREFIX);
          });
      }
      if (![ATTR.keep, ATTR.deep, ATTR.shell, ATTR.role].includes(name)) {
        return false;
      }
      return state.ownedElements.has(element) &&
        markerShapeMatches(element, state.expectedMarkerShapes.get(element));
    };
    const terminalBlock = function terminalBlock(reason) {
      observer.disconnect();
      runtime.enterTerminal(`role-projection-${reason}`);
    };
    const exactMeasurementMutation = function exactMeasurementMutation(mutation) {
      const html = document.documentElement;
      const restore = MEASUREMENT_HTML_RESTORES.get(html);
      if (!restore || mutation?.type !== "attributes" || mutation.target !== html) {
        return false;
      }
      if (mutation.attributeName === ATTR.measure) {
        return !html.hasAttribute(ATTR.measure);
      }
      return mutation.attributeName === "style" &&
        restore.properties.every(function propertyWasRestored(snapshot) {
          return html.style.getPropertyValue(snapshot.property) === snapshot.value &&
            html.style.getPropertyPriority(snapshot.property) === snapshot.priority;
        });
    };
    const consumeAuthorizedMarkerMutations = function consumeAuthorizedMarkerMutations(
      authorizedTargets,
    ) {
      return observer.takeRecords().every(function exactInternalMarkerMutation(mutation) {
        if (exactMeasurementMutation(mutation)) return true;
        if (
          mutation.type !== "attributes" ||
          (
            !authorizedTargets.has(mutation.target) &&
            !state.ownedElements.has(mutation.target)
          )
        ) {
          return false;
        }
        if (mutation.attributeName === "class") {
          return state.ownedElements.has(mutation.target)
            ? markerShapeMatches(
                mutation.target,
                state.expectedMarkerShapes.get(mutation.target),
              )
            : hdfClasses(mutation.target).length === 0 &&
                !Array.from(mutation.target.attributes || []).some(
                  function noReservedAttribute(attribute) {
                    return attribute.name.startsWith(HDF_ATTRIBUTE_PREFIX);
                  },
                );
        }
        return protocolAttributes.has(mutation.attributeName) &&
          (
            state.ownedElements.has(mutation.target)
              ? exactProtocolAttribute(mutation.target, mutation.attributeName)
              : !mutation.target.hasAttribute(mutation.attributeName) &&
                  hdfClasses(mutation.target).length === 0 &&
                  !Array.from(mutation.target.attributes || []).some(
                    function noReservedAttribute(attribute) {
                      return attribute.name.startsWith(HDF_ATTRIBUTE_PREFIX);
                    },
                  )
          );
      });
    };
    const classifyNewCommentRoot = function classifyNewCommentRoot(node) {
      const matchesItem = elementMatchesAny(node, state.commentItemSelectors);
      const matchesControl = elementMatchesAny(node, state.commentControlSelectors);
      const matchesConfiguredIgnored = elementMatchesAny(
        node,
        state.commentIgnoredSelectors,
      );
      if (matchesItem) {
        return Number(matchesControl) + Number(matchesConfiguredIgnored) === 0
          ? "item"
          : null;
      }
      if (isAutonomousProjectionNoiseRoot(node)) {
        return "autonomous-ignored";
      }
      if (Number(matchesControl) + Number(matchesConfiguredIgnored) !== 1) {
        return null;
      }
      return matchesControl ? "control" : "configured-ignored";
    };
    const explicitlyHiddenByPublisher = function explicitlyHiddenByPublisher(element) {
      const visibility = String(element.style?.getPropertyValue("visibility") || "")
        .trim().toLocaleLowerCase();
      const display = String(element.style?.getPropertyValue("display") || "")
        .trim().toLocaleLowerCase();
      const contentVisibility = String(
        element.style?.getPropertyValue("content-visibility") || "",
      ).trim().toLocaleLowerCase();
      const opacityValue = String(element.style?.getPropertyValue("opacity") || "").trim();
      const opacity = Number(opacityValue);
      return element.hidden || element.getAttribute("aria-hidden") === "true" ||
        display === "none" || /^(?:hidden|collapse)$/u.test(visibility) ||
        contentVisibility === "hidden" ||
        (opacityValue !== "" && Number.isFinite(opacity) && opacity === 0);
    };
    const replaceRootSet = function replaceRootSet(rootSet, roots) {
      rootSet.clear();
      roots.forEach(function rememberRoot(root) { rootSet.add(root); });
    };
    const forgetOwnedProjectionTree = function forgetOwnedProjectionTree(root) {
      if (!root || root.nodeType !== 1) return;
      [root].concat(Array.from(root.querySelectorAll("*"))).forEach(
        function forgetProjectedElement(element) {
          state.ownedElementSet.delete(element);
          state.expectedMarkerShapes.delete(element);
          state.ownedElements.delete(element);
          state.shellElements.delete(element);
        },
      );
    };
    const atomicRoleFields = function atomicRoleFields(role) {
      return role === "body"
        ? {
            ignoredRoots: state.bodyIgnoredRoots,
            configuredRoots: state.bodyConfiguredIgnoredRoots,
            autonomousRoots: state.bodyAutonomousIgnoredRoots,
            safetyRoots: state.bodySafetyIgnoredRoots,
            configuredSelectors: state.projectionPolicy.bodyIgnoredSelectors,
            roleConfigured: "bodyConfiguredIgnored",
            roleAutonomous: "bodyAutonomousIgnored",
            roleIgnored: "bodyIgnored",
          }
        : {
            ignoredRoots: state.productIgnoredRoots,
            configuredRoots: state.productConfiguredIgnoredRoots,
            autonomousRoots: state.productAutonomousIgnoredRoots,
            safetyRoots: state.productSafetyIgnoredRoots,
            configuredSelectors: state.projectionPolicy.productIgnoredSelectors,
            roleConfigured: "productConfiguredIgnored",
            roleAutonomous: "productAutonomousIgnored",
            roleIgnored: "productIgnored",
          };
    };
    const reconcileAtomicRole = function reconcileAtomicRole(role) {
      const rejectReconciliation = function rejectReconciliation(reason) {
        runtime.lastReconciliationFailure = Object.freeze({ role, reason });
        return false;
      };
      const roleRoot = state.roles[role];
      if (!roleRoot?.isConnected) return rejectReconciliation("role-root");
      const descendants = [roleRoot].concat(Array.from(roleRoot.querySelectorAll("*")));
      if (descendants.length > MAX_SEMANTIC_DESCENDANTS) {
        return rejectReconciliation("descendant-bound");
      }
      const fields = atomicRoleFields(role);
      const configured = ignoredRootsWithin(
        roleRoot,
        fields.configuredSelectors,
      );
      if (rootsOverlap(configured)) return rejectReconciliation("configured-overlap");
      const safety = trackedRoots(fields.safetyRoots)
        .filter(function connectedSafetyRoot(root) {
          return root?.isConnected && root !== roleRoot && roleRoot.contains(root);
        })
        .filter(function outermostSafetyRoot(root, _index, roots) {
          return !roots.some(function otherSafetyRoot(other) {
            return other !== root && other.contains(root);
          });
        });
      const autonomousDiscovery = discoverAutonomousIgnoredRoots(
        roleRoot,
        configured.concat(safety),
      );
      if (!autonomousDiscovery.ok) {
        return rejectReconciliation("autonomous-bound");
      }
      const autonomous = Array.from(autonomousDiscovery.roots);
      const ignored = uniqueElements(configured.concat(safety, autonomous));
      const safeProjection = withPublisherVisibilityMeasurement(
        document,
        function inspectReconciledAtomicRole() {
          return hasApprovedContentOutside(roleRoot, ignored) &&
            !containsSemanticNoise(roleRoot, new WeakMap(), ignored) &&
            !containsUnprovenShadowBoundary(roleRoot, ignored) &&
            !containsPublisherPaintRisk(roleRoot, ignored);
        },
        function rejectUnsafeAtomicMeasurement() { return false; },
      );
      if (!safeProjection) return rejectReconciliation("unsafe-projection");
      const authorizedTargets = new Set(descendants);
      for (
        let ancestor = roleRoot.parentElement;
        ancestor;
        ancestor = ancestor.parentElement
      ) {
        authorizedTargets.add(ancestor);
      }
      ignored.forEach(function demoteIgnoredRoot(ignoredRoot) {
        forgetOwnedProjectionTree(ignoredRoot);
        stripOwnedAttributes(ignoredRoot);
      });
      const promotionRoots = [];
      const stack = [roleRoot];
      while (stack.length) {
        const current = stack.pop();
        if (current !== roleRoot && insideAnyRoot(current, ignored)) continue;
        if (!state.ownedElements.has(current)) {
          promotionRoots.push(current);
          continue;
        }
        Array.from(current.children).reverse().forEach(
          function inspectUnownedChild(child) { stack.push(child); },
        );
      }
      promotionRoots.forEach(function promoteVerifiedContent(root) {
        const nestedIgnored = ignored.filter(function ignoredInsidePromotion(candidate) {
          return root === candidate || root.contains(candidate);
        });
        markDeepSubtree(
          root,
          role,
          state.ownedElements,
          state.nonce,
          nestedIgnored,
        );
        rememberAuthorizedMarkerTree(root, state);
      });
      replaceRootSet(fields.configuredRoots, configured);
      replaceRootSet(fields.autonomousRoots, autonomous);
      replaceRootSet(fields.safetyRoots, safety);
      replaceRootSet(fields.ignoredRoots, ignored);
      state.roles[fields.roleConfigured] = configured;
      state.roles[fields.roleAutonomous] = autonomous;
      state.roles[fields.roleIgnored] = ignored;
      if (!consumeAuthorizedMarkerMutations(authorizedTargets)) {
        return rejectReconciliation("marker-record");
      }
      runtime.lastReconciliationFailure = null;
      return true;
    };
    const quarantineAtomicProjectionRoot =
      function quarantineAtomicProjectionRoot(root) {
        if (!root || root.nodeType !== 1) return false;
        const role = ["body", "product"].find(function containingAtomicRole(name) {
          const roleRoot = state.roles[name];
          return roleRoot && roleRoot !== root && roleRoot.contains(root);
        });
        if (!role) return false;
        const fields = atomicRoleFields(role);
        fields.safetyRoots.add(root);
        if (!reconcileAtomicRole(role)) return false;
        state.projectionEpoch += 1;
        return runtime.publishReadyProjectionDiagnostics();
      };
    const removeTrackedCommentTree = function removeTrackedCommentTree(node) {
      if (node.nodeType !== 1) return null;
      const removedItems = trackedRoots(state.commentItemRoots).filter(
        function removedCommentItem(root) { return root === node || node.contains(root); }
      );
      if (removedItems.length > 0) return "item";
      const removedControls = trackedRoots(state.commentControlRoots).filter(
        function removedCommentControl(root) { return root === node || node.contains(root); }
      );
      const removedIgnored = trackedRoots(state.commentIgnoredRoots).filter(
        function removedIgnoredCommentRoot(root) { return root === node || node.contains(root); }
      );
      if (removedControls.length === 0 && removedIgnored.length === 0) return null;
      [
        state.commentControlRoots,
        state.commentIgnoredRoots,
        state.commentConfiguredIgnoredRoots,
        state.commentAutonomousIgnoredRoots,
        state.commentSafetyIgnoredRoots,
      ]
        .forEach(function removeContainedRoots(rootSet) {
          trackedRoots(rootSet).forEach(function removeContained(root) {
            if (root === node || node.contains(root)) rootSet.delete(root);
          });
        });
      if (node.nodeType === 1) {
        state.toggleableCommentControls.delete(node);
        Array.from(state.toggleableCommentControls).forEach(function forgetDormant(control) {
          if (node.contains(control)) state.toggleableCommentControls.delete(control);
        });
      }
      forgetRemovedTree(node, state);
      return "non-item";
    };
    const reconcileDynamicCommentControl =
      function reconcileDynamicCommentControl(control) {
        if (
          !control ||
          !control.isConnected ||
          !state.commentControlRoots.has(control) ||
          !state.commentControlScope.contains(control) ||
          !elementMatchesAny(control, state.commentControlSelectors)
        ) {
          return false;
        }
        const elements = [control, ...control.querySelectorAll("*")];
        if (elements.length > MAX_SEMANTIC_DESCENDANTS) return false;
        const overlapsAnotherProjectionRoot = [
          ...trackedRoots(state.commentItemRoots),
          ...trackedRoots(state.commentIgnoredRoots),
          ...trackedRoots(state.commentControlRoots).filter(
            function anotherControl(candidate) { return candidate !== control; },
          ),
        ].some(function nestedProjectionRoot(candidate) {
          return control.contains(candidate);
        });
        if (overlapsAnotherProjectionRoot) return false;
        elements
          .filter(function newlyIntroducedElement(element) {
            return !state.ownedElements.has(element) &&
              (!element.parentElement || state.ownedElements.has(element.parentElement));
          })
          .forEach(function clearPublisherMarkerSpoof(root) {
            stripOwnedAttributes(root);
          });
        const authorizedTargets = new Set(elements);
        for (
          let ancestor = control.parentElement;
          ancestor;
          ancestor = ancestor.parentElement
        ) {
          authorizedTargets.add(ancestor);
        }
        markDeepSubtree(
          control,
          "comment-control",
          state.ownedElements,
          state.nonce,
          [],
        );
        markAncestorChain(
          control,
          state.ownedElements,
          state.nonce,
          state.shellElements,
        );
        rememberAuthorizedMarkerTree(control, state);
        if (!consumeAuthorizedMarkerMutations(authorizedTargets)) return false;
        return withPublisherVisibilityMeasurement(
          document,
          function verifyReconciledCommentControl() {
            if (
              containsSemanticNoise(control, new WeakMap(), []) ||
              containsUnprovenShadowBoundary(control, [])
            ) {
              return false;
            }
            return isRendered(control)
              ? !containsPublisherPaintRisk(control, [])
              : approvedDormantCommentControl(control, state);
          },
          function rejectUnsafeCommentControlMeasurement() { return false; },
        );
      };
    const observer = createNativeMutationObserver(browserRoot, function sealProjection(mutations) {
      try {
        if (runtime.releasePhase !== "released" || !runtime.authorizedReady) {
          return;
        }
        if (runtime.terminallyBlocked) {
          return;
        }
        let failureReason = null;
        let projectionTouched = false;
        let commentProjectionChanged = false;
        let addedCommentItemCount = 0;
        let commentCountEvidenceChanged = false;
        const atomicRolesChanged = new Set();
        const dynamicCommentControlsChanged = new Set();
        for (const mutation of mutations) {
        if (failureReason) break;
        if (mutationTouchesCommentTotalEvidence(mutation)) {
          projectionTouched = true;
          commentCountEvidenceChanged = true;
        }
        if (mutation.type === "attributes") {
          const target = mutation.target;
          const name = mutation.attributeName;
          if (name === "class") {
            const exactClassShape = target === document.documentElement
              ? exactProtocolAttribute(target, ATTR.ready)
              : state.ownedElements.has(target)
                ? markerShapeMatches(target, state.expectedMarkerShapes.get(target))
                : hdfClasses(target).length === 0;
            if (!exactClassShape) {
              projectionTouched = true;
              failureReason = "marker-class-mutation";
              continue;
            }
            const publisherClasses = function publisherClasses(value) {
              return String(value || "").split(/\s+/).filter(Boolean)
                .filter(function nonProtocolClass(className) {
                  return !className.startsWith(HDF_CLASS_PREFIX);
                })
                .sort();
            };
            if (
              JSON.stringify(publisherClasses(mutation.oldValue)) ===
              JSON.stringify(publisherClasses(target.getAttribute("class")))
            ) {
              continue;
            }
          }
          if (protocolAttributes.has(name)) {
            projectionTouched = true;
            if (!exactProtocolAttribute(target, name)) {
              failureReason = "marker-mutation";
            }
            continue;
          }
          const inBody = state.roles.body.contains(target);
          const inProduct = Boolean(state.roles.product?.contains(target));
          const inTitle = insideOwnedTitleSurface(target);
          const inComments = insideCommentProjection(state, target);
          if (!inBody && !inProduct && !inTitle && !inComments) {
            continue;
          }
          projectionTouched = true;
          if (
            insideAnyRoot(target, trackedRoots(state.bodyIgnoredRoots)) ||
            insideAnyRoot(target, trackedRoots(state.productIgnoredRoots)) ||
            insideAnyRoot(target, trackedRoots(state.commentIgnoredRoots))
          ) {
            if (inBody) atomicRolesChanged.add("body");
            if (inProduct) atomicRolesChanged.add("product");
            continue;
          }
          if (inBody || inProduct) {
            if (inBody) atomicRolesChanged.add("body");
            if (inProduct) atomicRolesChanged.add("product");
            continue;
          }
          const controlRoot = closestTrackedRoot(target, state.commentControlRoots);
          if (
            controlRoot &&
            COMMENT_CONTROL_STATE_ATTRIBUTES.has(name) &&
            elementMatchesAny(controlRoot, state.commentControlSelectors)
          ) {
            if (!isRendered(controlRoot)) {
              state.toggleableCommentControls.add(controlRoot);
            } else if (containsPublisherPaintRisk(controlRoot, [])) {
              failureReason = "projection-mismatch";
            }
            if (!failureReason) {
              commentProjectionChanged = true;
            }
            continue;
          }
          if (
            (inBody || inProduct || inComments) &&
            safeMediaAttribute(target, name, mutation.oldValue)
          ) {
            continue;
          }
          if (
            (inBody || inProduct) &&
            target.matches("details") &&
            name === "open"
          ) {
            continue;
          }
          if (inTitle || inComments) {
            continue;
          }
          failureReason = "attribute-mutation";
          continue;
        }
        const mutationParent = mutation.target.nodeType === 1
          ? mutation.target
          : mutation.target.parentElement;
        const inBody = Boolean(mutationParent && state.roles.body.contains(mutationParent));
        const inProduct = Boolean(
          mutationParent && state.roles.product?.contains(mutationParent),
        );
        const inTitle = insideOwnedTitleSurface(mutationParent);
        const inComments = insideCommentProjection(state, mutationParent);
        const inIgnoredProjection = Boolean(mutationParent) && (
          insideAnyRoot(mutationParent, trackedRoots(state.bodyIgnoredRoots)) ||
          insideAnyRoot(mutationParent, trackedRoots(state.productIgnoredRoots)) ||
          insideAnyRoot(mutationParent, trackedRoots(state.commentIgnoredRoots))
        );
        if (mutation.type === "characterData") {
          if (inBody || inProduct) {
            projectionTouched = true;
            if (inBody) atomicRolesChanged.add("body");
            if (inProduct) atomicRolesChanged.add("product");
          } else if (!inIgnoredProjection && inComments) {
            projectionTouched = true;
          } else if (!inIgnoredProjection && inTitle) {
            projectionTouched = true;
            failureReason = "text-mutation";
          } else if (
            mutationParent === document.body &&
            normalizeText(mutation.target.data)
          ) {
            failureReason = "outside-body-text";
          }
          continue;
        }
        if (inIgnoredProjection) {
          if (inBody) atomicRolesChanged.add("body");
          if (inProduct) atomicRolesChanged.add("product");
          if (inBody || inProduct) projectionTouched = true;
          continue;
        }
        if (inBody || inProduct || inTitle || inComments) {
          projectionTouched = true;
        }
        const dynamicCommentControl = mutation.type === "childList"
          ? closestTrackedRoot(mutationParent, state.commentControlRoots)
          : null;
        if (dynamicCommentControl) {
          const nestedTrackedRootChanged = [
            ...mutation.removedNodes,
            ...mutation.addedNodes,
          ].some(function overlapsTrackedCommentRoot(node) {
            if (node.nodeType !== 1) return false;
            return trackedRoots(state.commentItemRoots).some(
              function overlapsItem(item) {
                return item === node || node.contains(item);
              },
            ) || trackedRoots(state.commentIgnoredRoots).some(
              function overlapsIgnored(ignored) {
                return ignored === node || node.contains(ignored);
              },
            ) || trackedRoots(state.commentControlRoots).some(
              function overlapsOtherControl(control) {
                return control !== dynamicCommentControl &&
                  (control === node || node.contains(control));
              },
            );
          });
          if (nestedTrackedRootChanged) {
            failureReason = "comment-control-root-mutation";
            continue;
          }
          for (const removed of mutation.removedNodes) {
            if (removed.nodeType === 1) forgetRemovedTree(removed, state);
          }
          for (const added of mutation.addedNodes) {
            if (added.nodeType === 1) stripOwnedAttributes(added);
          }
          commentProjectionChanged = true;
          dynamicCommentControlsChanged.add(dynamicCommentControl);
          continue;
        }
        for (const removed of mutation.removedNodes) {
          if (failureReason) break;
          const removesCore = removed.nodeType === 1 && (
            removed === state.commonRoot ||
            removed.contains(state.commonRoot) ||
            ["title", "body", "comments", "product"].some(function removedRole(role) {
              return state.roles[role] &&
                (removed === state.roles[role] || removed.contains(state.roles[role]));
            })
          );
          if (removesCore) {
            failureReason = "core-removal";
          } else if (inBody || inProduct) {
            // Mutation records also report publisher moves of the same object.
            // Retain identity only when it remains in its original atomic role.
            const movedWithinRole = removed.nodeType === 1 && removed.isConnected && (
              (inBody && state.roles.body.contains(removed)) ||
              (inProduct && state.roles.product.contains(removed))
            );
            if (removed.nodeType === 1 && !movedWithinRole) forgetRemovedTree(removed, state);
            if (inBody) atomicRolesChanged.add("body");
            if (inProduct) atomicRolesChanged.add("product");
          } else if (inTitle) {
            failureReason = "atomic-removal";
          } else if (inComments) {
            if (removed.nodeType === 3) {
              if (normalizeText(removed.data)) {
                failureReason = "comment-text-removal";
              }
            } else if (removed.nodeType === 8) {
              // Publisher comment nodes carry no reader-visible content.
            } else if (
              removed.nodeType === 1 &&
              removed.matches("script, style, template, noscript")
            ) {
              // Inert publisher implementation nodes are deliberately not
              // part of the visible comment projection.
            } else {
              const removalKind = removeTrackedCommentTree(removed);
              if (removalKind === "item") {
                failureReason = "comment-removal";
              } else if (removalKind === null) {
                const removedOwnedProjection = removed.nodeType === 1 && [
                  removed,
                  ...removed.querySelectorAll("*"),
                ].some(function removedOwnedElement(element) {
                  return state.ownedElements.has(element);
                });
                if (removedOwnedProjection) {
                  failureReason = "unclassified-comment-element-removal";
                } else {
                  forgetRemovedTree(removed, state);
                  commentProjectionChanged = true;
                }
              } else {
                commentProjectionChanged = true;
              }
            }
          } else if (removed.nodeType === 1) {
            forgetRemovedTree(removed, state);
          }
        }
        for (const added of mutation.addedNodes) {
          if (failureReason) break;
          if (added === styleElement) continue;
          if (inBody || inProduct) {
            const reservedMarkerSelector =
              `[${ATTR.keep}], [${ATTR.deep}], [${ATTR.shell}], [${ATTR.role}], ` +
              `.${CLASS.keep}, .${CLASS.shell}, .${CLASS.deep}, ` +
              `[class*="${CLASS.rolePrefix}"]`;
            if (
              added.nodeType === 1 &&
              [added, ...added.querySelectorAll(reservedMarkerSelector)].some(
                function unownedReservedMarker(element) {
                  return element.matches(reservedMarkerSelector) &&
                    !state.ownedElements.has(element);
                },
              )
            ) {
              failureReason = "inside-marker-spoof";
              break;
            }
            if (inBody) atomicRolesChanged.add("body");
            if (inProduct) atomicRolesChanged.add("product");
            continue;
          }
          if (inTitle) {
            failureReason = "atomic-addition";
            break;
          }
          if (!inComments) {
            if (added.nodeType === 1) {
              const reservedMarkerSelector =
                `[${ATTR.keep}], [${ATTR.deep}], [${ATTR.shell}], [${ATTR.role}], ` +
                `.${CLASS.keep}, .${CLASS.shell}, .${CLASS.deep}, ` +
                `[class*="${CLASS.rolePrefix}"]`;
              const markedElements = [added, ...added.querySelectorAll(reservedMarkerSelector)]
                .filter(function reservedMarker(element) { return element.matches(reservedMarkerSelector); });
              if (markedElements.some(function unownedMarker(element) {
                return !state.ownedElements.has(element);
              })) {
                // Publisher widgets may clone marked markup outside the
                // article. Remove copied authority before paint, without
                // blanking the intact original article and comments.
                const clearedTargets = new Set([added, ...added.querySelectorAll('*')]);
                stripOwnedAttributes(added, state.ownedElements);
                if (!consumeAuthorizedMarkerMutations(clearedTargets)) {
                  failureReason = "outside-marker-cleanup";
                }
                projectionTouched = true;
              } else if (markedElements.length) {
                projectionTouched = true;
              } else {
                stripOwnedAttributes(added);
              }
            }
            continue;
          }
          if (added.nodeType !== 1) {
            if (added.nodeType === 3 && normalizeText(added.data)) {
              failureReason = "unclassified-comment-text";
            }
            continue;
          }
          const classification = classifyNewCommentRoot(added);
          if (!classification) {
            const overlapsAcceptedRoot = [...state.commentItemRoots, ...state.commentControlRoots]
              .some(function containsAcceptedRoot(root) { return nodesOverlap(added, root); });
            if (overlapsAcceptedRoot || state.commentSafetyIgnoredRoots.size >= MAX_COMMENT_EVIDENCE) {
              failureReason = "unclassified-comment-addition";
              break;
            }
            // An unknown sibling has no authority to hide accepted comments or
            // stop their observer. Keep that exact unowned subtree outside the
            // projection while normal comment/control updates continue.
            stripOwnedAttributes(added);
            state.commentSafetyIgnoredRoots.add(added);
            state.commentIgnoredRoots.add(added);
            commentProjectionChanged = true;
            continue;
          }
          const publisherHiddenBeforeProjection = explicitlyHiddenByPublisher(added);
          stripOwnedAttributes(added);
          if (
            classification === "configured-ignored" ||
            classification === "autonomous-ignored"
          ) {
            state.commentIgnoredRoots.add(added);
            (
              classification === "configured-ignored"
                ? state.commentConfiguredIgnoredRoots
                : state.commentAutonomousIgnoredRoots
            ).add(added);
            commentProjectionChanged = true;
            continue;
          }
          const role = classification === "item" ? "comment-item" : "comment-control";
          const authorizedMarkerTargets = new Set([
            added,
            ...added.querySelectorAll("*"),
          ]);
          for (let ancestor = added.parentElement; ancestor; ancestor = ancestor.parentElement) {
            authorizedMarkerTargets.add(ancestor);
          }
          markDeepSubtree(added, role, state.ownedElements, state.nonce, []);
          markAncestorChain(added, state.ownedElements, state.nonce, state.shellElements);
          rememberAuthorizedMarkerTree(added, state);
          if (!consumeAuthorizedMarkerMutations(authorizedMarkerTargets)) {
            failureReason = "internal-marker-conflict";
            break;
          }
          if (classification === "item") {
            state.commentItemRoots.add(added);
            addedCommentItemCount += 1;
          } else {
            state.commentControlRoots.add(added);
            if (!isRendered(added)) state.toggleableCommentControls.add(added);
          }
          commentProjectionChanged = true;
          // Empty comment anchors and hidden load-more controls are valid
          // dormant controls, just as at initial resolution. Reject hidden
          // comment content, not the zero-area anchor preceding that content.
          const renderedAddition = isRendered(added);
          const dormantControl = classification === "control" &&
            !renderedAddition && approvedDormantCommentControl(added, state);
          const additionFailure = !dormantControl &&
            (publisherHiddenBeforeProjection || !renderedAddition)
            ? "hidden-comment-addition"
            : containsUnprovenShadowBoundary(added, [])
              ? "shadow-comment-addition"
              : renderedAddition && containsPublisherPaintRisk(added, [])
                ? "publisher-paint-comment-addition"
                : null;
          if (additionFailure) {
            failureReason = additionFailure;
            break;
          }
        }
      }
        if (!failureReason) {
          for (const control of dynamicCommentControlsChanged) {
            if (!reconcileDynamicCommentControl(control)) {
              failureReason = "comment-control-reconciliation";
              break;
            }
          }
        }
        if (!failureReason) {
          for (const role of atomicRolesChanged) {
            if (!reconcileAtomicRole(role)) {
              failureReason = `${role}-reconciliation`;
              break;
            }
          }
        }
        if (
          !failureReason &&
          (commentProjectionChanged || commentCountEvidenceChanged) &&
          !commitAuthorizedCommentCountIncrease(state, addedCommentItemCount)
        ) {
          failureReason = "comment-count";
        }
        if (!failureReason && projectionTouched) {
          if (
            !verifyOwnedMarkerState(document, state) ||
            !verifyOwnedState(document, state)
          ) {
            failureReason = "projection-mismatch";
          }
        }
        if (
          !failureReason &&
          (commentProjectionChanged || atomicRolesChanged.size > 0)
        ) {
          state.projectionEpoch += 1;
          if (!runtime.publishReadyProjectionDiagnostics()) {
            failureReason = "comment-control-projection";
          }
        }
        if (failureReason) {
          terminalBlock(failureReason);
        }
      } catch (_error) {
        terminalBlock("observer-exception");
      }
    });
    observer.observe(document.documentElement, {
      subtree: true,
      childList: true,
      characterData: true,
      attributes: true,
      attributeOldValue: true,
      attributeFilter: [
        ATTR.keep,
        ATTR.deep,
        ATTR.shell,
        ATTR.role,
        ATTR.ready,
        ATTR.protocol,
        ATTR.lock,
        ATTR.state,
        ATTR.status,
        "src",
        "srcset",
        "sizes",
        "poster",
        "loading",
        "decoding",
        "width",
        "height",
        "data-src",
        "data-srcset",
        "data-title",
        "data-component",
        "data-role",
        "data-testid",
        "id",
        "class",
        "role",
        "itemprop",
        "itemtype",
        "aria-label",
        "title",
        "name",
        "href",
        "rel",
        "style",
        "hidden",
        "aria-expanded",
        "aria-pressed",
        "aria-selected",
        "aria-hidden",
        "open",
      ],
    });
    if (runtime.shadowTracker) {
      const rejectProjectedShadow = function rejectProjectedShadow(host) {
        if (insideOwnedTitleSurface(host)) {
          terminalBlock("shadow-boundary");
          return;
        }
        const inAtomicProjection = ["body", "product"].some(
          function shadowInsideAtomicRole(role) {
            const root = state.roles[role];
            return root && (root === host || root.contains(host));
          }
        );
        if (inAtomicProjection) {
          if (!quarantineAtomicProjectionRoot(host)) {
            terminalBlock("shadow-boundary");
          }
          return;
        }
        if (
          state.roles.comments.contains(host) &&
          !verifyOwnedMarkerState(document, state)
        ) {
          terminalBlock("shadow-boundary");
        }
      };
      runtime.shadowTracker.listeners.add(rejectProjectedShadow);
      runtime.unsubscribeShadow = function unsubscribeShadowTracking() {
        runtime.shadowTracker?.listeners.delete(rejectProjectedShadow);
        runtime.unsubscribeShadow = null;
      };
    }
    if (typeof NATIVE.addEventListener === "function" && typeof NATIVE.removeEventListener === "function") {
      const subscriptions = [];
      const subscribe = function subscribe(target, type, listener) {
        NATIVE.reflectApply(NATIVE.addEventListener, target, [type, listener, true]);
        subscriptions.push([target, type, listener]);
      };
      const closeTopLayerSurface = function closeTopLayerSurface(target) {
        try {
          if (target?.matches?.("dialog[open]") && typeof target.close === "function") {
            target.close();
          }
        } catch (_error) {
          try { target?.removeAttribute?.("open"); } catch (_fallbackError) {}
        }
        try {
          if (activePopover(target) && typeof target.hidePopover === "function") {
            target.hidePopover();
          }
        } catch (_error) {
          // Projection demotion remains authoritative even if the page blocks the API.
        }
        return !activePopover(target) && !target?.matches?.("dialog[open]");
      };
      const containOpeningPopover = function containOpeningPopover(event) {
        const target = event.target;
        if (
          target?.matches?.("[popover], dialog") &&
          (event.newState === "open" || activePopover(target) || target.open === true)
        ) {
          try {
            if (event.cancelable) event.preventDefault();
          } catch (_error) {}
          closeTopLayerSurface(target);
          if (!quarantineAtomicProjectionRoot(target)) {
            const ownedCommentSurface =
              state.roles.comments.contains(target) &&
              state.ownedElements.has(target);
            if (ownedCommentSurface || activePopover(target) || target.open === true) {
              runtime.enterTerminal("role-projection-top-layer-activation");
            }
          }
        }
      };
      const containProjectedFullscreen = function containProjectedFullscreen() {
        const target = document.fullscreenElement;
        if (target) {
          try {
            const exit = document.exitFullscreen?.();
            if (exit && typeof exit.catch === "function") exit.catch(function ignoreExit() {});
          } catch (_error) {}
          if (!quarantineAtomicProjectionRoot(target)) {
            runtime.enterTerminal("role-projection-top-layer-activation");
          }
        }
      };
      subscribe(document, "beforetoggle", containOpeningPopover);
      subscribe(document, "toggle", containOpeningPopover);
      subscribe(document, "fullscreenchange", containProjectedFullscreen);
      runtime.unsubscribeProjectionEvents = function unsubscribeProjectionEvents() {
        subscriptions.forEach(function removeSubscription(subscription) {
          NATIVE.reflectApply(NATIVE.removeEventListener, subscription[0], [
            subscription[1],
            subscription[2],
            true,
          ]);
        });
        runtime.unsubscribeProjectionEvents = null;
      };
    }
    runtime.integrityObserver = observer;
  }

  function createReaderRuntime(
    browserRoot,
    contract,
    layouts,
    styleElement,
    bootstrapLock,
    targetReason,
    verifiedTargetProof,
    shadowTracker,
    onResolved
  ) {
    const document = browserRoot.document;
    const runtime = {
      discoveryObserver: null,
      integrityObserver: null,
      bootstrapGuard: null,
      cascadeGuard: null,
      cascadeFrameId: 0,
      unsubscribeShadow: null,
      unsubscribeProjectionEvents: null,
      projectionState: null,
      bootstrapLock,
      activeNonce: null,
      authorizedReady: false,
      releasePhase: "discovering",
      releasePending: false,
      releaseProofFrameId: 0,
      releaseProofSampleCount: 0,
      releaseProofStage: "not-entered",
      releaseProbe: null,
      lockedActivationTimeoutId: 0,
      expectedStyleText: styleElement.textContent,
      terminallyBlocked: false,
      rollbackComplete: false,
      beginDiscovery: null,
      stop: null,
      enterTerminal: null,
      discardCascadeRecords: null,
      prepareCascadeRelease: null,
      verifyCascadeRelease: null,
      verifyUnlockedCascadeRelease: null,
      readyDiagnostics: null,
      standaloneCascadeProof: null,
      lastReconciliationFailure: null,
      projectionArticleIdentity: referrerScopedArticleIdentity(browserRoot.location, contract.id),
      recoveringProjection: false,
      verifiedTargetProof,
      shadowTracker,
      publishReadyProjectionDiagnostics: null,
    };

    function armLockedActivationDeadline() {
      if (runtime.lockedActivationTimeoutId) {
        nativeClearTimeout(browserRoot, runtime.lockedActivationTimeoutId);
        runtime.lockedActivationTimeoutId = 0;
      }
      runtime.lockedActivationTimeoutId = nativeTimeout(
        browserRoot,
        function abandonStalledLockedActivation() {
          runtime.lockedActivationTimeoutId = 0;
          if (runtime.releasePhase !== "released" && !runtime.terminallyBlocked) {
            const probeState = runtime.releaseProbe?.isConnected
              ? "probe-connected"
              : "probe-absent";
            const pendingState = runtime.releasePending ? "pending" : "idle";
            runtime.enterTerminal(
              `locked-activation-timeout-${runtime.releasePhase}-` +
              `${runtime.releaseProofStage}-${pendingState}-${probeState}-` +
              `samples-${runtime.releaseProofSampleCount}`,
            );
          }
        },
        LOCKED_ACTIVATION_TIMEOUT_MS,
      );
    }

    runtime.publishReadyProjectionDiagnostics = function publishReadyProjectionDiagnostics() {
      if (
        !runtime.authorizedReady ||
        !runtime.projectionState ||
        !runtime.readyDiagnostics
      ) {
        return false;
      }
      try {
        const commentControlProjection = currentCommentControlProjection(
          runtime.projectionState,
        );
        if (!commentControlProjection?.currentProjectionValid) {
          runtime.enterTerminal("comment-control-projection");
          return false;
        }
        const visibleLeakCount = currentVisibleProjectionLeakCount(
          document,
          runtime.projectionState,
        );
        if (visibleLeakCount !== 0) {
          runtime.enterTerminal("visible-projection-leak");
          return false;
        }
        publishDiagnostics(browserRoot, {
          ...runtime.readyDiagnostics,
          standaloneCascadeProof: runtime.standaloneCascadeProof,
          commentControlProjection,
          visibleLeakCount,
        });
        return true;
      } catch (_error) {
        runtime.enterTerminal("comment-control-projection");
        return false;
      }
    };

    function resumeVerifiedProjection(reason, allowFrozen = false) {
      const state = runtime.projectionState;
      const resumingFrozen = allowFrozen && runtime.releasePhase === "frozen";
      if (
        runtime.recoveringProjection || (runtime.terminallyBlocked && !resumingFrozen) ||
        !String(reason || "").startsWith("role-projection-") ||
        (runtime.releasePhase !== "released" && !resumingFrozen) || !runtime.authorizedReady ||
        !runtime.standaloneCascadeProof || !state ||
        runtime.projectionArticleIdentity !== referrerScopedArticleIdentity(browserRoot.location, contract.id)
      ) return false;
      runtime.recoveringProjection = true;
      try {
        if (
          !verifyOwnedMarkerState(document, state) ||
          !runtimeGateStyleIntact(styleElement, runtime) ||
          !verifyOwnedState(document, state) ||
          currentVisibleProjectionLeakCount(document, state) !== 0
        ) return false;
        // The accepted nodes, content boundary and article identity remain
        // exact. Replace a disconnected/erroring observer, not the publisher
        // DOM, and retain the already-proven two-frame cascade authority.
        [runtime.discoveryObserver, runtime.integrityObserver, runtime.bootstrapGuard, runtime.cascadeGuard]
          .forEach(function disconnectStaleObserver(observer) { observer?.disconnect(); });
        if (runtime.cascadeFrameId) {
          nativeCancelAnimationFrame(browserRoot, runtime.cascadeFrameId);
          runtime.cascadeFrameId = 0;
        }
        runtime.unsubscribeShadow?.();
        runtime.unsubscribeProjectionEvents?.();
        runtime.terminallyBlocked = false;
        runtime.rollbackComplete = false;
        runtime.releasePhase = "released";
        runtime.discoveryObserver = null;
        installBootstrapGuard(browserRoot, runtime, styleElement);
        installCascadeGuard(browserRoot, runtime, styleElement);
        installIntegrityObserver(browserRoot, runtime, state, styleElement);
        return runtime.publishReadyProjectionDiagnostics();
      } catch (_error) {
        return false;
      } finally {
        runtime.recoveringProjection = false;
      }
    }

    runtime.resumeFrozenProjection = function resumeFrozenProjection() {
      return resumeVerifiedProjection("role-projection-frozen-retry", true);
    };

    function freezeVerifiedProjection(reason) {
      const resolution = runtime.verifiedTargetProof?.resolution;
      let state = runtime.projectionState;
      let nonce = runtime.activeNonce;
      try {
        if (!state) {
          if (!resolution?.ok) return false;
          nonce = createRunNonce(browserRoot);
          if (!nonce) return false;
          state = applyRoleMarkers(
            document,
            resolution.roles,
            resolution.commonRoot,
            resolution.resolvedTitle,
            resolution.requiredRoles,
            resolution.commentItemSelectors,
            resolution.commentControlSelectors,
            resolution.commentIgnoredSelectors,
            resolution.projectionPolicy,
            nonce,
          );
          runtime.activeNonce = nonce;
          runtime.projectionState = state;
          writeRuntimeGateStyle(styleElement, nonce, runtime);
        }
        if (
          !nonce ||
          !verifyOwnedMarkerState(document, state) ||
          !runtimeGateStyleIntact(styleElement, runtime)
        ) {
          return false;
        }
        runtime.bootstrapLock?.restorePublisherInline?.();
        const html = document.documentElement;
        html.setAttribute(ATTR.protocol, PROTOCOL_VERSION);
        html.setAttribute(ATTR.state, "ready");
        html.setAttribute(ATTR.status, "ready");
        html.setAttribute(ATTR.ready, "1");
        html.classList.add(CLASS.ready);
        html.removeAttribute(ATTR.lock);
        html.classList.remove(CLASS.lock);
        runtime.authorizedReady = true;
        runtime.releasePhase = "frozen";
        runtime.readyDiagnostics = runtime.readyDiagnostics || Object.freeze({
          state: "ready",
          targetReason,
          roles: resolution?.roleDiagnostics || {},
          layoutAliases: resolution?.layoutAliases || [],
          semanticProjectionCount: resolution?.semanticProjectionCount || 1,
        });
        publishDiagnostics(browserRoot, {
          ...runtime.readyDiagnostics,
          targetReason: `frozen-${reason || "terminal"}`,
          reconciliationFailure: runtime.lastReconciliationFailure,
          standaloneCascadeProof: runtime.standaloneCascadeProof,
          commentControlProjection: currentCommentControlProjection(state),
          visibleLeakCount: currentVisibleProjectionLeakCount(document, state),
        });
        return true;
      } catch (_error) {
        return false;
      }
    }

    runtime.enterTerminal = function enterTerminal(reason) {
      if (runtime.terminallyBlocked && runtime.rollbackComplete) return;
      if (resumeVerifiedProjection(reason)) return;
      const projectionFrozen = freezeVerifiedProjection(reason);
      runtime.terminallyBlocked = true;
      runtime.releasePending = false;
      if (!projectionFrozen) runtime.standaloneCascadeProof = null;
      if (!projectionFrozen) {
        runtime.authorizedReady = false;
        runtime.releasePhase = "terminal";
        runtime.activeNonce = null;
        runtime.projectionState = null;
        runtime.readyDiagnostics = null;
      }
      [
        runtime.discoveryObserver,
        runtime.integrityObserver,
        runtime.bootstrapGuard,
        runtime.cascadeGuard,
      ].forEach(
        function disconnectForTerminal(observer) {
          try {
            if (observer) observer.disconnect();
          } catch (_error) {
            // Recovery must continue even if a page wrapper rejects cleanup.
          }
        }
      );
      runtime.discoveryObserver = null;
      runtime.integrityObserver = null;
      runtime.bootstrapGuard = null;
      runtime.cascadeGuard = null;
      if (runtime.cascadeFrameId) {
        try { nativeCancelAnimationFrame(browserRoot, runtime.cascadeFrameId); } catch (_error) {}
        runtime.cascadeFrameId = 0;
      }
      if (runtime.releaseProofFrameId) {
        try { nativeCancelAnimationFrame(browserRoot, runtime.releaseProofFrameId); } catch (_error) {}
        runtime.releaseProofFrameId = 0;
      }
      if (runtime.releaseProbe?.isConnected) {
        try {
          runtime.releaseProbe.remove();
        } catch (_error) {
          try { runtime.releaseProbe.parentNode?.removeChild(runtime.releaseProbe); } catch (_fallbackError) {}
        }
      }
      runtime.releaseProbe = null;
      runtime.releasePending = false;
      if (runtime.lockedActivationTimeoutId) {
        try { nativeClearTimeout(browserRoot, runtime.lockedActivationTimeoutId); } catch (_error) {}
        runtime.lockedActivationTimeoutId = 0;
      }
      try { runtime.unsubscribeShadow?.(); } catch (_error) {}
      try { runtime.unsubscribeProjectionEvents?.(); } catch (_error) {}
      if (projectionFrozen) {
        runtime.rollbackComplete = true;
        // A different article is not adopted, but the accepted projection
        // still needs continuous marker/style/cascade containment. A return
        // to the exact original article can then resume its normal observer.
        installBootstrapGuard(browserRoot, runtime, styleElement);
        installCascadeGuard(browserRoot, runtime, styleElement);
        return;
      }
      try { runtime.shadowTracker?.uninstall?.(); } catch (_error) {}
      try {
        const html = document.documentElement;
        html.setAttribute(ATTR.lock, "1");
        html.setAttribute(ATTR.state, "locked");
        html.setAttribute(ATTR.status, `locked-${reason || "terminal"}`);
        html.removeAttribute(ATTR.ready);
        html.classList.remove(CLASS.ready);
        html.classList.add(CLASS.lock);
        runtime.expectedStyleText = gateStyleText(null);
        if (styleElement?.isConnected) {
          styleElement.textContent = runtime.expectedStyleText;
        }
      } catch (_error) {
        // The bootstrap inline lock remains the last fail-closed authority.
      } finally {
        runtime.rollbackComplete = true;
        try {
          publishDiagnostics(browserRoot, {
            state: "locked",
            targetReason: `contained-${reason || "terminal"}`,
          });
        } catch (_error) {
          // Diagnostics are optional; publisher content remains contained.
        }
      }
    };

    function attemptResolution() {
      if (runtime.releasePending || runtime.authorizedReady || runtime.terminallyBlocked) {
        return false;
      }
      if (!document.body) {
        runtime.enterTerminal("semantic-race-body-unavailable");
        return false;
      }
      // The semantic tuple was proven while the publisher page was visible.
      // Do not run the resolver a second time after the presentation lock: an
      // AdGuard-injected stylesheet may not expose CSSOM synchronously there,
      // and that race used to turn a valid handoff into a rollback.
      const candidateResolution = runtime.verifiedTargetProof;
      if (!candidateResolution?.ok || !candidateResolution.resolution?.ok) {
        runtime.enterTerminal("semantic-proof-unavailable");
        return false;
      }
      const resolution = candidateResolution.resolution;
      const nonce = createRunNonce(browserRoot);
      if (!nonce) {
        runtime.enterTerminal("secure-nonce");
        return false;
      }
      const state = applyRoleMarkers(
        document,
        resolution.roles,
        resolution.commonRoot,
        resolution.resolvedTitle,
        resolution.requiredRoles,
        resolution.commentItemSelectors,
        resolution.commentControlSelectors,
        resolution.commentIgnoredSelectors,
        resolution.projectionPolicy,
        nonce
      );
      runtime.activeNonce = nonce;
      runtime.projectionState = state;
      writeRuntimeGateStyle(styleElement, nonce, runtime);
      if (!verifyOwnedMarkerState(document, state)) {
        runtime.enterTerminal("ownership-verification");
        return false;
      }
      if (!runtimeGateStyleIntact(styleElement, runtime)) {
        runtime.enterTerminal("runtime-style");
        return false;
      }
      if (runtime.discoveryObserver) {
        runtime.discoveryObserver.disconnect();
        runtime.discoveryObserver = null;
      }
      const cascadeSnapshot = runtime.prepareCascadeRelease();
      if (!cascadeSnapshot) {
        return false;
      }
      runtime.authorizedReady = true;
      runtime.releasePhase = "armed";
      document.documentElement.setAttribute(ATTR.protocol, PROTOCOL_VERSION);
      document.documentElement.setAttribute(ATTR.state, "ready");
      document.documentElement.setAttribute(ATTR.status, "ready");
      document.documentElement.setAttribute(ATTR.ready, "1");
      document.documentElement.classList.add(CLASS.ready);
      runtime.readyDiagnostics = Object.freeze({
        state: "ready",
        targetReason,
        roles: resolution.roleDiagnostics,
        layoutAliases: resolution.layoutAliases,
        semanticProjectionCount: resolution.semanticProjectionCount,
      });
      // Synchronous ownership and full-DOM cascade verification can consume
      // most of the discovery deadline on publisher-heavy pages. Give the
      // already-armed two-frame release proof its own complete bounded window.
      armLockedActivationDeadline();
      return proveStandaloneCascadeRelease(
        browserRoot,
        runtime,
        styleElement,
        cascadeSnapshot,
        function releaseProvedProjection() {
          if (!runtime.bootstrapLock?.intact()) {
            runtime.enterTerminal(
              `bootstrap-inline-lock-tamper-${
                runtime.bootstrapLock?.mismatchProperty?.() || "unknown"
              }`,
            );
            return;
          }
          runtime.releasePhase = "released";
          if (!runtime.bootstrapLock?.restoreInline()) {
            runtime.enterTerminal(
              `bootstrap-inline-lock-tamper-${
                runtime.bootstrapLock?.mismatchProperty?.() || "unknown"
              }`,
            );
            return;
          }
          document.documentElement.removeAttribute(ATTR.lock);
          document.documentElement.classList.remove(CLASS.lock);
          if (!runtime.verifyUnlockedCascadeRelease()) return;
          installIntegrityObserver(browserRoot, runtime, state, styleElement);
          if (!runtime.publishReadyProjectionDiagnostics()) return;
          if (typeof onResolved === "function" &&
              onResolved(resolution) !== true) {
            runtime.enterTerminal("algumon-referrer-invalidated");
            return;
          }
          runtime.verifiedTargetProof = null;
          runtime.discardCascadeRecords?.();
          if (runtime.lockedActivationTimeoutId) {
            nativeClearTimeout(browserRoot, runtime.lockedActivationTimeoutId);
            runtime.lockedActivationTimeoutId = 0;
          }
        },
      );
    }

    runtime.beginDiscovery = function beginDiscovery() {
      if (runtime.releasePending || runtime.authorizedReady || runtime.terminallyBlocked) {
        return;
      }
      try {
        armLockedActivationDeadline();
        attemptResolution();
      } catch (_error) {
        runtime.enterTerminal("projection-activation-exception");
      }
    };
    runtime.stop = function stopRuntime() {
      if (runtime.releasePhase !== "released") {
        runtime.enterTerminal("runtime-stop-before-release");
        return;
      }
      [
        runtime.discoveryObserver,
        runtime.integrityObserver,
        runtime.bootstrapGuard,
        runtime.cascadeGuard,
      ].forEach(
        function disconnectObserver(observer) {
          if (observer) observer.disconnect();
        }
      );
      runtime.discoveryObserver = null;
      runtime.integrityObserver = null;
      runtime.bootstrapGuard = null;
      runtime.cascadeGuard = null;
      runtime.projectionState = null;
      if (runtime.cascadeFrameId) {
        nativeCancelAnimationFrame(browserRoot, runtime.cascadeFrameId);
        runtime.cascadeFrameId = 0;
      }
      if (runtime.releaseProofFrameId) {
        nativeCancelAnimationFrame(browserRoot, runtime.releaseProofFrameId);
        runtime.releaseProofFrameId = 0;
      }
      if (runtime.releaseProbe?.isConnected) {
        try {
          runtime.releaseProbe.remove();
        } catch (_error) {
          try { runtime.releaseProbe.parentNode?.removeChild(runtime.releaseProbe); } catch (_fallbackError) {}
        }
      }
      runtime.releaseProbe = null;
      runtime.releasePending = false;
      if (runtime.lockedActivationTimeoutId) {
        nativeClearTimeout(browserRoot, runtime.lockedActivationTimeoutId);
        runtime.lockedActivationTimeoutId = 0;
      }
      if (runtime.unsubscribeShadow) runtime.unsubscribeShadow();
      if (runtime.unsubscribeProjectionEvents) runtime.unsubscribeProjectionEvents();
      if (runtime.shadowTracker) runtime.shadowTracker.uninstall();
    };
    try {
      if (runtime.verifiedTargetProof?.resolution?.ok) runtime.bootstrapLock?.repairInline?.();
      installBootstrapGuard(browserRoot, runtime, styleElement);
      installCascadeGuard(browserRoot, runtime, styleElement);
    } catch (_error) {
      runtime.enterTerminal("runtime-setup-exception");
    }
    return runtime;
  }

  function lockWhenHtmlExists(document, callback) {
    if (document.documentElement) {
      const bootstrapLock = claimBootstrapLock(document);
      callback(document.documentElement, bootstrapLock);
      return;
    }
    const observer = createNativeMutationObserver(document.defaultView, function waitForHtml() {
      if (!document.documentElement) {
        return;
      }
      observer.disconnect();
      const bootstrapLock = claimBootstrapLock(document);
      callback(document.documentElement, bootstrapLock);
    });
    observer.observe(document, { childList: true, subtree: true });
  }

  function installNavigationRevalidation(browserRoot, revalidate) {
    if (!browserRoot) return null;
    let stopped = false;
    let pollTimeoutId = 0;
    let observedHref = String(browserRoot.location?.href || "");
    const subscriptions = [];
    const stop = function stopNavigationRevalidation() {
      if (stopped) return;
      stopped = true;
      if (pollTimeoutId) nativeClearTimeout(browserRoot, pollTimeoutId);
      pollTimeoutId = 0;
      subscriptions.forEach(function removeNavigationSubscription(subscription) {
        try {
          subscription[0].removeEventListener(
            subscription[1],
            subscription[2],
            true,
          );
        } catch (_error) {
          // Navigation cleanup must not leave a reader projection locked.
        }
      });
      subscriptions.length = 0;
    };
    const revalidateSafely = function revalidateSafely() {
      if (stopped) return;
      try {
        revalidate();
      } catch (_error) {
        stop();
      }
    };
    const scheduleUrlPoll = function scheduleUrlPoll() {
      if (stopped) return;
      const protocolState = browserRoot.document?.documentElement?.getAttribute(ATTR.state);
      if (protocolState !== "locked" && protocolState !== "ready") {
        stop();
        return;
      }
      const currentHref = String(browserRoot.location?.href || "");
      if (currentHref !== observedHref) {
        observedHref = currentHref;
        revalidateSafely();
      }
      try {
        pollTimeoutId = nativeTimeout(browserRoot, scheduleUrlPoll, 500);
      } catch (_error) {
        stop();
      }
    };
    const subscribe = function subscribeNavigation(type, listener) {
      if (typeof browserRoot.addEventListener !== "function") return false;
      try {
        browserRoot.addEventListener(type, listener, true);
        subscriptions.push([browserRoot, type, listener]);
        return true;
      } catch (_error) {
        return false;
      }
    };
    try {
      subscribe("urlchange", revalidateSafely);
      subscribe("hashchange", revalidateSafely);
      subscribe("popstate", revalidateSafely);
      subscribe("pageshow", function revalidateRestoredPage(event) {
        if (event.persisted === true) {
          revalidateSafely();
        }
      });
      scheduleUrlPoll();
      return Object.freeze({ stop });
    } catch (_error) {
      stop();
      return null;
    }
  }

  function waitForAlgumonReferrer(browserRoot, activate) {
    const document = browserRoot?.document;
    let pollTimeoutId = 0;
    let deadlineTimeoutId = 0;
    let stopped = false;
    const stop = function stopReferrerWait() {
      if (stopped) return;
      stopped = true;
      if (pollTimeoutId) nativeClearTimeout(browserRoot, pollTimeoutId);
      if (deadlineTimeoutId) nativeClearTimeout(browserRoot, deadlineTimeoutId);
      pollTimeoutId = 0;
      deadlineTimeoutId = 0;
    };
    const poll = function pollReferrer() {
      if (stopped) return;
      // At document-start Chromium can expose an empty referrer for the first
      // task even though the navigation did originate at Algumon. Wait inside
      // the existing bounded handoff window instead of permanently classifying
      // that target as unverified before the document metadata is ready.
      const referrer = String(document?.referrer || "");
      if (canonicalAlgumonReferrerOrigin(referrer)) {
        stop();
        activate();
        return;
      }
      if (referrer) {
        stop();
        return;
      }
      pollTimeoutId = nativeTimeout(
        browserRoot,
        poll,
        ALGUMON_HANDOFF_POLL_INTERVAL_MS,
      );
    };
    try {
      deadlineTimeoutId = nativeTimeout(
        browserRoot,
        stop,
        ALGUMON_HANDOFF_SETTLE_TIMEOUT_MS,
      );
      poll();
    } catch (_error) {
      stop();
      return null;
    }
    return Object.freeze({ stop });
  }

  function waitForVerifiedTargetSemanticProof(browserRoot, contract, activate) {
    const document = browserRoot.document;
    let observer = null;
    let timeoutId = 0;
    let attemptScheduled = false;
    let stopped = false;
    const stop = function stopSemanticPreflight() {
      if (stopped) return;
      stopped = true;
      if (observer) observer.disconnect();
      observer = null;
      if (timeoutId) nativeClearTimeout(browserRoot, timeoutId);
      timeoutId = 0;
      document.removeEventListener?.("DOMContentLoaded", scheduleAttempt);
    };
    const attempt = function attemptSemanticPreflight() {
      attemptScheduled = false;
      let observationPaused = false;
      try {
        if (stopped || !document.documentElement || !document.body) return false;
        // Never mark a partial parser tree. Publisher DOMContentLoaded
        // handlers must see their original markup, before our scheduled proof.
        if (document.readyState === "loading") return false;
        // Measuring publisher styles temporarily changes our root attributes
        // and inline lock. Do not feed those synchronous writes back into the
        // preflight observer when the article is not yet resolvable.
        if (observer) {
          observer.disconnect();
          observationPaused = true;
        }
        // Preflight runs outside the synchronous publisher measurement. A
        // page-supplied copy of our private measurement flag is not proof of
        // an active measurement and must not poison all later attempts.
        if (document.documentElement.hasAttribute(ATTR.measure)) {
          document.documentElement.removeAttribute(ATTR.measure);
        }
        const pathAndQuery = `${browserRoot.location.pathname}${browserRoot.location.search}`;
        const routeLayouts = matchingLayouts(contract, pathAndQuery);
        const layouts = routeLayouts.length ? routeLayouts : contract.layouts;
        const currentArticleIdentity = referrerScopedArticleIdentity(
          browserRoot.location,
          contract.id,
        );
        if (!currentArticleIdentity) {
          stop();
          return false;
        }
        const approvedResolution = resolveDocument(document, layouts, null);
        const resolution = approvedResolution.ok
          ? approvedResolution
          : resolveIndependentSemanticDocument(document, layouts);
        if (!resolution.ok) {
          const failure = approvedResolution.ok ? resolution : approvedResolution;
          const reason = `locked-preflight-${failure.role || "semantic"}-${failure.reason || "unresolved"}`;
          if (document.documentElement.getAttribute(ATTR.status) !== reason) {
            document.documentElement.setAttribute(ATTR.status, reason);
          }
          return false;
        }
        const entryAuthority = readerEntryAuthority(browserRoot.location, document.referrer);
        if (!entryAuthority) return false;
        const candidateResolution = Object.freeze({
          ok: true,
          authority: approvedResolution.ok
            ? `${entryAuthority}-approved-layout`
            : `${entryAuthority}-independent-semantic-tuple`,
          resolution,
        });
        stop();
        activate(candidateResolution);
        return true;
      } catch (_error) {
        // The presentation remains sealed; later DOM mutations may still
        // supply a complete exact or independently proven projection.
        return false;
      } finally {
        if (observationPaused && !stopped && observer) {
          observer.observe(document, {
            subtree: true,
            childList: true,
            characterData: true,
            attributes: true,
          });
        }
      }
    };
    const scheduleAttempt = function scheduleSemanticPreflight() {
      if (stopped || attemptScheduled) return;
      attemptScheduled = true;
      nativeTimeout(browserRoot, attempt, 0);
    };
    const retryUnresolvedSemanticPreflight =
      function retryUnresolvedSemanticPreflight() {
        timeoutId = 0;
        if (stopped) return;
        publishDiagnostics(browserRoot, {
          state: "locked",
          targetReason: "awaiting-complete-semantic-projection",
        });
        scheduleAttempt();
        timeoutId = nativeTimeout(
          browserRoot,
          retryUnresolvedSemanticPreflight,
          SEMANTIC_PREFLIGHT_TIMEOUT_MS,
        );
      };
    try {
      document.addEventListener?.("DOMContentLoaded", scheduleAttempt, { once: true });
      observer = createNativeMutationObserver(browserRoot, scheduleAttempt);
      observer.observe(document, {
        subtree: true,
        childList: true,
        characterData: true,
        attributes: true,
      });
      timeoutId = nativeTimeout(
        browserRoot,
        retryUnresolvedSemanticPreflight,
        SEMANTIC_PREFLIGHT_TIMEOUT_MS,
      );
      scheduleAttempt();
    } catch (_error) {
      stop();
    }
    return Object.freeze({ stop });
  }

  function start(browserRoot) {
    if (!browserRoot || !browserRoot.document || !browserRoot.location) {
      return { mode: "library" };
    }
    const contract = findSiteContract(browserRoot.location.hostname);
    if (!contract) {
      return { mode: "out-of-scope" };
    }
    const document = browserRoot.document;
    const beginVerifiedReaderGate = function beginVerifiedReaderGate() {
      if (!referrerScopedArticleIdentity(browserRoot.location, contract.id)) {
        publishDiagnostics(browserRoot, {
          state: "inactive",
          targetReason: "article-identity-required",
        });
        return false;
      }
      lockWhenHtmlExists(document, function configureTarget(html, initialBootstrapLock) {
      if (!initialBootstrapLock) {
        restorePublisherPage(document, null, initialBootstrapLock);
        return;
      }
      waitForVerifiedTargetSemanticProof(
        browserRoot,
        contract,
        function beginVerifiedTargetActivation(verifiedTargetProof) {
      function configureTargetWithReferrerProof(initialVerifiedProof) {
        let authorizedArticleIdentity = null;
        let pendingArticleIdentity = referrerScopedArticleIdentity(
          browserRoot.location,
          contract.id,
        );
        let activeRuntime = null;
        let activeStyle = null;
        let activeShadowTracker = null;
        let activeBootstrapLock = initialBootstrapLock;
        let verifiedProof = initialVerifiedProof;
        let initialActivation = true;
        let navigationTerminallyBlocked = false;
        let navigationTerminalReason = null;
        let navigationRevalidation = null;

      try {

      function terminalNavigationBlock(reason) {
        if (navigationTerminallyBlocked) {
          return false;
        }
        navigationTerminallyBlocked = true;
        navigationTerminalReason = reason || "blocked";
        authorizedArticleIdentity = null;
        pendingArticleIdentity = null;
        if (navigationRevalidation && !activeRuntime) {
          navigationRevalidation.stop();
          navigationRevalidation = null;
        }
        if (activeRuntime) {
          activeRuntime.enterTerminal(navigationTerminalReason);
          return true;
        }
        try { activeShadowTracker?.uninstall?.(); } catch (_error) {}
        activeShadowTracker = null;
        restorePublisherPage(document, activeStyle, activeBootstrapLock);
        publishDiagnostics(browserRoot, {
          state: "inactive",
          targetReason: navigationTerminalReason,
        });
        return true;
      }

      function activateCurrentLocation() {
        if (navigationTerminallyBlocked) {
          if (!activeRuntime?.resumeFrozenProjection?.()) return;
          navigationTerminallyBlocked = false;
          navigationTerminalReason = null;
          authorizedArticleIdentity = activeRuntime.projectionArticleIdentity;
        }
        if (activeRuntime && activeRuntime.terminallyBlocked) {
          return;
        }
        const isInitialActivation = initialActivation;
        const pathAndQuery = `${browserRoot.location.pathname}${browserRoot.location.search}`;
        const routeLayouts = matchingLayouts(contract, pathAndQuery);
        const layouts = routeLayouts.length ? routeLayouts : contract.layouts;
        const currentArticleIdentity = referrerScopedArticleIdentity(
          browserRoot.location,
          contract.id,
        );
        const expectedArticleIdentity =
          authorizedArticleIdentity || pendingArticleIdentity;
        if (!isInitialActivation) {
          if (
            !expectedArticleIdentity ||
            currentArticleIdentity !== expectedArticleIdentity
          ) {
            terminalNavigationBlock("navigation-identity");
          }
          return;
        }
        if (activeRuntime) {
          activeRuntime.stop();
          activeRuntime = null;
        }
        activeShadowTracker = null;
        if (activeStyle) {
          activeStyle.remove();
          activeStyle = null;
        }
        clearProtocolState(document);
        if (!isInitialActivation) {
          if (activeBootstrapLock && !activeBootstrapLock.isRestored()) {
            if (!activeBootstrapLock.restoreInline()) {
              terminalNavigationBlock("bootstrap-inline-lock-tamper");
              return;
            }
          }
          activeBootstrapLock = claimBootstrapLock(document);
          if (!activeBootstrapLock) {
            terminalNavigationBlock("bootstrap-lock-unavailable");
            return;
          }
        }

        if (verifiedProof?.ok !== true || !currentArticleIdentity) {
          initialActivation = false;
          terminalNavigationBlock(
            verifiedProof?.ok !== true
              ? "algumon-referrer-proof-required"
              : "article-identity-required"
          );
          return;
        }
        const evaluationLayouts = layouts;
        const entryAuthority = readerEntryAuthority(browserRoot.location, document.referrer);
        const targetReason = routeLayouts.length
          ? `${entryAuthority}-known-route`
          : `${entryAuthority}-independent-route`;
        initialActivation = false;
        try {
          activeStyle = installRuntimeGateStyle(document);
        } catch (_error) {
          activeStyle = null;
          terminalNavigationBlock("gm-runtime-style-unavailable");
          return;
        }
        activeShadowTracker = initializeShadowTracker(browserRoot);
        html.setAttribute(ATTR.status, `locked-${targetReason}`);
        publishDiagnostics(browserRoot, {
          state: "locked",
          targetReason,
        });
        activeRuntime = createReaderRuntime(
          browserRoot,
          contract,
          evaluationLayouts,
          activeStyle,
          activeBootstrapLock,
          targetReason,
          verifiedProof,
          activeShadowTracker,
          function authorizeResolvedArticle() {
            if (!readerEntryAuthority(browserRoot.location, document.referrer)) {
              return false;
            }
            authorizedArticleIdentity = currentArticleIdentity;
            pendingArticleIdentity = null;
            return true;
          }
        );
        activeRuntime.beginDiscovery();
        verifiedProof = null;
      }

      activateCurrentLocation();
      navigationRevalidation = installNavigationRevalidation(
        browserRoot,
        activateCurrentLocation,
      );
      if (!navigationRevalidation && !activeRuntime?.terminallyBlocked) {
        publishDiagnostics(browserRoot, {
          state: activeRuntime?.authorizedReady ? "ready" : "locked",
          targetReason: "navigation-poll-unavailable",
        });
      }
      } catch (_error) {
        if (activeRuntime) {
          activeRuntime.enterTerminal("activation-exception");
        } else {
          try { activeShadowTracker?.uninstall?.(); } catch (_cleanupError) {}
          activeShadowTracker = null;
          restorePublisherPage(document, activeStyle, activeBootstrapLock);
          publishDiagnostics(browserRoot, {
            state: "inactive",
            targetReason: "activation-exception",
          });
        }
      }
      }
      configureTargetWithReferrerProof(verifiedTargetProof);
        },
      );
    });
      return true;
    };
    const initialReferrer = String(document.referrer || "");
    if (readerEntryAuthority(browserRoot.location, initialReferrer)) {
      return {
        mode: beginVerifiedReaderGate()
          ? "reader-gate"
          : "reader-gate-inactive",
        site: contract.id,
      };
    }
    if (initialReferrer) {
      return {
        mode: "reader-gate-inactive",
        site: contract.id,
      };
    }
    const referrerWait = waitForAlgumonReferrer(browserRoot, beginVerifiedReaderGate);
    return {
      mode: referrerWait ? "reader-gate-awaiting-referrer" : "reader-gate-inactive",
      site: contract.id,
    };
  }

  return Object.freeze({
    PROTOCOL_VERSION,
    GENERATOR_VERSION,
    RELEASE_URLS,
    SITE_CONTRACTS,
    ROLE_POLICIES,
    normalizeText,
    textSimilarity,
    titleConsistency,
    titleEvidence,
    collectArticleTitleMetadata,
    pathPatternMatches,
    articleIdentity,
    readerEntryAuthority,
    sameArticleNavigation,
    waitForAlgumonReferrer,
    scoreBodyFeatures,
    scoreCommentFeatures,
    decideCandidate,
    lowestCommonAncestor,
    gateStyleText,
    resolveDocument,
    resolveProjectionClasses,
    discoverSemanticContract,
    start,
  });
});
