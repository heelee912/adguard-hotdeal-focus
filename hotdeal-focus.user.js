// ==UserScript==
// @name         AdGuard Hotdeal Focus Reader Gate
// @namespace    https://github.com/heelee912/adguard-hotdeal-focus
// @version      0.6.20
// @description  Fail-closed semantic reader gate for Algumon hot-deal destinations.
// @match        https://www.algumon.com/*
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
  Object.defineProperty(root, "__HOTDEAL_FOCUS_AUDIT__", {
    value: Object.freeze({ discoverSemanticContract: api.discoverSemanticContract }),
    configurable: false,
    enumerable: false,
    writable: false,
  });
  api.start(root);
})(typeof globalThis === "object" ? globalThis : this, function hotdealFocusFactory() {
  "use strict";

  const PROTOCOL_VERSION = "2";
  const GENERATOR_VERSION = "0.6.20";
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
    addEventListener: RUNTIME_GLOBAL?.EventTarget?.prototype?.addEventListener ?? null,
    removeEventListener: RUNTIME_GLOBAL?.EventTarget?.prototype?.removeEventListener ?? null,
    defineProperty: Object.defineProperty,
    reflectApply: Reflect.apply,
    history: RUNTIME_GLOBAL?.history ?? null,
    historyPushState: RUNTIME_GLOBAL?.history?.pushState ?? null,
    historyReplaceState: RUNTIME_GLOBAL?.history?.replaceState ?? null,
    locationReplace: RUNTIME_GLOBAL?.Location?.prototype?.replace ?? null,
    anchorClick: RUNTIME_GLOBAL?.HTMLAnchorElement?.prototype?.click ?? null,
    cssStyleSheetPrototype: RUNTIME_GLOBAL?.CSSStyleSheet?.prototype ?? null,
    cssStyleSheetMethods: Object.freeze(Object.fromEntries(
      ["insertRule", "deleteRule", "replace", "replaceSync"].map(function capture(methodName) {
        return [methodName, RUNTIME_GLOBAL?.CSSStyleSheet?.prototype?.[methodName] ?? null];
      })
    )),
  });
  const CSSOM_MUTATION_LISTENERS = new WeakMap();
  const ADOPTED_STYLE_SHEET_LISTENERS = new WeakMap();
  const STYLE_SHEET_STATE_LISTENERS = new WeakMap();
  const SHADOW_TRACKER_KEY = typeof Symbol === "function"
    ? Symbol.for("hotdeal-focus.shadow-tracker.v1")
    : "__HOTDEAL_FOCUS_SHADOW_TRACKER_V1__";

  function initializeShadowTracker(browserRoot) {
    if (!browserRoot) return null;
    const existing = browserRoot[SHADOW_TRACKER_KEY];
    if (existing?.installed === true) return existing;
    const prototype = browserRoot.Element?.prototype;
    const nativeAttachShadow = prototype?.attachShadow;
    if (!prototype || typeof nativeAttachShadow !== "function") return null;
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
      const descriptor = Object.getOwnPropertyDescriptor(prototype, "attachShadow");
      NATIVE.defineProperty(prototype, "attachShadow", {
        configurable: false,
        enumerable: descriptor?.enumerable === true,
        writable: false,
        value: trackedAttachShadow,
      });
      const tracker = Object.freeze({
        hosts,
        listeners,
        installed: prototype.attachShadow === trackedAttachShadow,
        wrapper: trackedAttachShadow,
      });
      NATIVE.defineProperty(browserRoot, SHADOW_TRACKER_KEY, {
        configurable: false,
        enumerable: false,
        writable: false,
        value: tracker,
      });
      return tracker.installed ? tracker : null;
    } catch (_error) {
      return null;
    }
  }

  const SHADOW_TRACKER = initializeShadowTracker(RUNTIME_GLOBAL);

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
            "roleProjection": {"title":{"mode":"seeded-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"absent","cardinality":"zero","selectors":[],"ignored":[]},"comments":{"mode":"classified-children"}},
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
            "roleProjection": {"title":{"mode":"seeded-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"required","order":"before-body","selectors":[".topTitle-link"],"ignored":[".topTitle-link > .affiliate-img",".topTitle-link > .affiliate-sign"]},"comments":{"mode":"classified-children"}},
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
            "roleProjection": {"title":{"mode":"seeded-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"required","order":"before-body","selectors":[".bbs.view > h4 .info a.noeffect"],"ignored":[]},"comments":{"mode":"classified-children"}},
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
            "roleProjection": {"title":{"mode":"seeded-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"optional","order":"after-body","selectors":[".source_url.box_line_with_shadow"],"ignored":[]},"comments":{"mode":"classified-children"}},
            "hints": {
              "title": [".subject_inner_text"],
              "product": [".source_url.box_line_with_shadow"],
              "body": [".view_content"],
              "comments": [".comment_view.normal"],
              "commentItems": [".comment_view.normal > table.comment_table > tbody > tr.comment_element"],
              "commentControls": [".comment_view.normal .comment_more", ".comment_view.normal .pagination", ".comment_view.normal .btn_reply"],
              "commentIgnored": []
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
            "roleProjection": {"title":{"mode":"seeded-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"required","order":"before-body","selectors":[".market-info-view-table"],"ignored":[]},"comments":{"mode":"classified-children"}},
            "hints": {
              "title": ["h1.title"],
              "product": [".market-info-view-table"],
              "body": [".view-content > .note-editor"],
              "comments": ["#ajax-reply-list"],
              "commentItems": ["#ajax-reply-list > li[id^='comment']"],
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
            "roleProjection": {"title":{"mode":"seeded-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"required","order":"before-body","selectors":[".market-info-view-table"],"ignored":[]},"comments":{"mode":"classified-children"}},
            "hints": {
              "title": [".content.market-info-view-wrap .view-style01 .tit .ment > h1"],
              "product": [".market-info-view-table"],
              "body": [".view-content > .note-editor"],
              "comments": ["#ajax-reply-list"],
              "commentItems": ["#ajax-reply-list > .commnet-main[id^='comment']"],
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
            "roleProjection": {"title":{"mode":"seeded-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"required","order":"before-body","selectors":["#D_ .et_vars"],"ignored":[]},"comments":{"mode":"classified-children"}},
            "hints": {
              "title": ["#D_ ._hd h2"],
              "product": ["#D_ .et_vars"],
              "body": ["#D_ article > .rhymix_content"],
              "comments": ["#C_"],
              "commentItems": ["#C_ > ._bd > ._comment[id^='comment_']"],
              "commentControls": ["#C_ > #comment", "#C_ > ._bd .pagination", "#C_ > ._bd .more", "#C_ > ._bd .reply"],
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
            "roleProjection": {"title":{"mode":"seeded-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"required","order":"before-body","selectors":[".app-article-container > .app-board-extra-value"],"ignored":[]},"comments":{"mode":"classified-children"}},
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
            "roleProjection": {"title":{"mode":"seeded-shallow"},"body":{"mode":"atomic-boundary","ignored":[".article-body > .ad"]},"product":{"mode":"absent","cardinality":"zero","selectors":[],"ignored":[]},"comments":{"mode":"classified-children"}},
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

  function sameArticleNavigation(sourceLocation, destinationLocation, siteId) {
    const sourceIdentity = articleIdentity(sourceLocation, siteId);
    const destinationIdentity = articleIdentity(destinationLocation, siteId);
    return Boolean(sourceIdentity) && sourceIdentity === destinationIdentity;
  }

  function isAlgumonHostname(hostname) {
    const normalizedHostname = String(hostname || "").toLocaleLowerCase();
    return normalizedHostname === "algumon.com" || normalizedHostname.endsWith(".algumon.com");
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

  function referrerProjectionSeed(browserRoot, siteType) {
    const document = browserRoot?.document;
    if (!document || !isAlgumonReferrer(document.referrer)) return null;
    const titleCandidates = [
      document.querySelector('meta[property="og:title"]')?.getAttribute("content"),
      document.querySelector('meta[name="twitter:title"]')?.getAttribute("content"),
      document.title,
    ];
    const title = titleCandidates.map(function normalizeCandidate(candidate) {
      return truncateRawTitle(candidate, 240);
    }).find(Boolean);
    return title
      ? Object.freeze({ siteType, title, commentCount: null })
      : null;
  }

  function utf8ByteLength(value) {
    return unescape(encodeURIComponent(String(value))).length;
  }

  function normalizeCommentCount(value) {
    const number = Number.parseInt(String(value || "").replace(/[^0-9]/g, ""), 10);
    return Number.isSafeInteger(number) && number >= 0 && number <= 100000 ? number : null;
  }

  function createRunNonce(browserRoot) {
    if (!browserRoot.crypto || typeof browserRoot.crypto.getRandomValues !== "function") {
      return null;
    }
    const words = new Uint32Array(4);
    browserRoot.crypto.getRandomValues(words);
    return `hdf-${Array.from(words).map(function encodeWord(word) {
      return word.toString(36).padStart(7, "0");
    }).join("")}`;
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
    if (
      gateStyles.length !== 1 ||
      !gateStyles[0].sheet ||
      gateStyles[0].sheet.disabled
    ) {
      return measurementConflict();
    }
    const gateSheet = gateStyles[0].sheet;
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
    const previouslyDisabled = gateSheet.disabled;
    html.style.setProperty("transition", "none", "important");
    html.style.setProperty("animation", "none", "important");
    html.style.setProperty("opacity", "0", "important");
    html.style.setProperty("visibility", "hidden", "important");
    html.style.setProperty("content-visibility", "hidden", "important");
    html.style.setProperty("clip-path", "inset(50%)", "important");
    html.setAttribute(ATTR.measure, "1");
    try {
      measurementStyleSheetMutationDepth += 1;
      try {
        gateSheet.disabled = true;
      } finally {
        measurementStyleSheetMutationDepth -= 1;
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
      measurementStyleSheetMutationDepth += 1;
      try {
        gateSheet.disabled = previouslyDisabled;
      } finally {
        measurementStyleSheetMutationDepth -= 1;
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
    const algumonCore = titleConsistency(algumonTitle, visibleTitle);
    const algumonSingle = singleLongTitleTokenEquivalence(algumonTitle, visibleTitle);
    const algumon = algumonCore.ok ? algumonCore : algumonSingle.ok ? algumonSingle : algumonCore;
    const metadata = collectArticleTitleMetadata(document, jsonLdValue);
    const metadataComparisons = metadata.sources.map(function compareMetadata(source) {
      const visibleToMetadata = titleCoreEquivalence(visibleTitle, source.value);
      const metadataToVisible = titleCoreEquivalence(source.value, visibleTitle);
      const visibleSingle = singleLongTitleTokenEquivalence(visibleTitle, source.value);
      const metadataSingle = singleLongTitleTokenEquivalence(source.value, visibleTitle);
      const coreOk = visibleToMetadata.ok && metadataToVisible.ok;
      const singleOk = visibleSingle.ok && metadataSingle.ok;
      const matchedCoreRatio = visibleToMetadata.referenceDistinctiveTokenCount
        ? visibleToMetadata.matchedDistinctiveTokenCount /
          visibleToMetadata.referenceDistinctiveTokenCount
        : 0;
      const conflictsWithVisibleArticle =
        visibleToMetadata.protectedTokenAgreement !== true ||
        matchedCoreRatio < 0.5;
      return Object.freeze({
        kind: source.kind,
        ok: coreOk || singleOk,
        conflictsWithVisibleArticle,
        boundedCommerceFormatting: boundedMetadataCommerceFormattingMatch(
          visibleTitle,
          source.value,
        ),
        score: coreOk || singleOk
          ? 1
          : Number(Math.min(visibleToMetadata.score, metadataToVisible.score).toFixed(3)),
        mode: singleOk
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
    const ok = algumon.ok && metadataOk;
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
        ? `algumon-${algumon.mode}+metadata-consensus`
        : !algumon.ok
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
    if (isStrongProjectionNoiseNode(element)) return true;
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
      return true;
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
        !isStructuralNoiseNode(candidate) ||
        containsMeaningfulIgnoredContent(candidate)
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
    if (
      prototype &&
      typeof prototype.attachShadow === "function" &&
      (!SHADOW_TRACKER || prototype.attachShadow !== SHADOW_TRACKER.wrapper)
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
        SHADOW_TRACKER?.hosts.has(current) ||
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

  function commentProjectionShells(commentMount, commentItems, commentControls) {
    const shells = new Set([commentMount]);
    commentItems.concat(commentControls).forEach(function collectShellChain(surface) {
      for (
        let current = surface.parentElement;
        current && commentMount.contains(current);
        current = current.parentElement
      ) {
        shells.add(current);
        if (current === commentMount) break;
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
    const apparentItemCount = Math.max(schemaCount, repeatedCount, hintedItems);
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
          elementMatchesAny(element, ignoredHints)
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
    const outboundLinks = outboundLinkCount(element);
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
    return evaluation.features?.apparentItemCount === 0 &&
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

  function inferredRepeatedCommentEvidence(evaluation, layouts, evidenceCache) {
    if (evidenceCache.has(evaluation.node)) {
      return evidenceCache.get(evaluation.node);
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

  function collectExactDocumentCommentEvidence(document, layout, bodyNode, seed, jsonLd) {
    const layouts = [layout];
    const explicitEvidence = explicitCommentEvidence(document, layouts);
    if (!explicitEvidence.ok) return explicitEvidence;
    const mountHints = roleHints(layouts, "comments");
    const itemHints = roleHints(layouts, "commentItems");
    const controlHints = roleHints(layouts, "commentControls");
    const ignoredHints = roleHints(layouts, "commentIgnored");
    const collection = collectBoundedCandidateElements(
      document,
      "[role='feed'], [role='list'], section, div, ol, ul",
      mountHints,
      function plausibleEvidenceMount(element) {
        if (
          element === bodyNode ||
          element.contains(bodyNode) ||
          bodyNode.contains(element) ||
          !followsNode(element, bodyNode) ||
          element.matches("[itemtype*='schema.org/Comment'], [itemprop='comment']") ||
         elementMatchesAny(element, itemHints) ||
         elementMatchesAny(element, controlHints) ||
          elementMatchesAny(element, ignoredHints) ||
          isFormOnlyCommentEvidenceSurface(element)
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

  function stripOwnedAttributes(element) {
    if (!element || element.nodeType !== 1) {
      return;
    }
    [element].concat(Array.from(element.querySelectorAll("*"))).forEach(
      function removeAllReservedPublisherMarkers(candidate) {
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
    return Array.from(titleNode.querySelectorAll("span, strong, b, em, a, div"))
      .filter(function titleTextLeaf(element) {
        if (TITLE_METADATA_PATTERN.test(semanticTokenText(element))) {
          return false;
        }
        const text = normalizeText(element.textContent);
        return text &&
          textSimilarity(text, resolvedTitle) >= 0.54 &&
          !Array.from(element.children).some(function nestedTitleText(child) {
            return normalizeText(child.textContent) &&
              !TITLE_METADATA_PATTERN.test(semanticTokenText(child));
          });
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
    if (!html || (removePublisherMarkers && !removePublisherHdfMarkers(document))) {
      return null;
    }
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
    const previous = Object.freeze(
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
    const claimedDeclarations = Object.freeze(
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
      return null;
    }
    html.classList.add(CLASS.lock);
    html.setAttribute(ATTR.lock, "1");
    html.setAttribute(ATTR.state, "locked");
    let restored = false;
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
        previous.forEach(function restoreDeclaration(snapshot) {
          applyInlinePropertySnapshot(html, snapshot);
        });
        BOOTSTRAP_PUBLISHER_INLINE.delete(html);
        restored = true;
        return true;
      },
    });
  }

  function orderedCommentControls(state) {
    return uniqueElements(queryAllSafe(
      state.roles.comments,
      state.commentControlSelectors,
    )).sort(documentOrder);
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
      state.roles.comments.contains(control) &&
      state.toggleableCommentControls.has(control) &&
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
      toggleableCommentControls: new Set(roles.commentDormantControls || []),
      commentIgnoredRoots: new Set(roles.commentIgnored),
      commentCountBoundary: roles.commentCountBoundary || commonRoot,
      commentTotalEvidenceRoots: new Set(roles.commentTotalEvidence || []),
      acceptedCommentCount: roles.commentItems.length,
      requiresVisibleExactCommentTotal:
        projectionPolicy.provenCommentCountSource === "visible-comment-total",
      bodyIgnoredRoots: new Set(roles.bodyIgnored),
      productIgnoredRoots: new Set(roles.productIgnored),
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
    [root].concat(Array.from(root.querySelectorAll(`[${ATTR.keep}]`))).forEach(
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
          return false;
        }
        const count = parseVisibleCommentTotal(evidence.textContent);
        if (count === null) return false;
        values.add(count);
      }
      if (values.size !== 1 || !values.has(currentItems.length)) return false;
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

  function projectionHasPublisherPaintRiskWithPublisherStyles(state) {
    const projectionInvariantFails = function projectionInvariantFails(role, excludedRoots) {
      const root = state.roles[role];
      return Boolean(root) && (
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
    const currentBodyIgnored = ignoredRootsWithin(
      state.roles.body,
      state.projectionPolicy.bodyIgnoredSelectors,
    );
    const currentProductIgnored = state.roles.product
      ? ignoredRootsWithin(
          state.roles.product,
          state.projectionPolicy.productIgnoredSelectors,
        )
      : [];
    if (
      !sameRootSet(currentBodyIgnored, state.bodyIgnoredRoots) ||
      !sameRootSet(currentProductIgnored, state.productIgnoredRoots)
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
    const currentCommentItems = uniqueElements(
      queryAllSafe(state.roles.comments, state.commentItemSelectors)
    );
    const currentCommentControls = uniqueElements(
      queryAllSafe(state.roles.comments, state.commentControlSelectors)
    );
    const currentCommentIgnored = uniqueElements(
      queryAllSafe(state.roles.comments, state.commentIgnoredSelectors)
    );
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
        return (!isRendered(control) && !state.toggleableCommentControls.has(control)) ||
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

  function canonicalRuntimeCssRules(styleElement) {
    try {
      if (!styleElement.sheet || styleElement.sheet.disabled) {
        return null;
      }
      return Array.from(styleElement.sheet.cssRules).map(function canonicalRule(rule) {
        return rule.cssText;
      }).join("\n");
    } catch (_error) {
      return null;
    }
  }

  function writeRuntimeGateStyle(styleElement, nonce, runtime) {
    const expectedText = gateStyleText(nonce);
    styleElement.textContent = expectedText;
    runtime.expectedStyleText = expectedText;
    runtime.expectedStyleRules = canonicalRuntimeCssRules(styleElement);
  }

  function runtimeGateStyleFailure(styleElement, runtime) {
    if (!styleElement) return "missing";
    if (!styleElement.isConnected) return "disconnected";
    if (
      styleElement.getAttribute("data-hotdeal-focus-runtime-style") !== PROTOCOL_VERSION
    ) return "marker";
    if (styleElement.textContent !== runtime.expectedStyleText) return "text";
    if (runtime.expectedStyleRules === null) return "expected-rules";
    if (canonicalRuntimeCssRules(styleElement) !== runtime.expectedStyleRules) return "rules";
    return null;
  }

  function runtimeGateStyleIntact(styleElement, runtime) {
    return runtimeGateStyleFailure(styleElement, runtime) === null;
  }

  function installPersistentTerminalGuardian(browserRoot, styleElement, status) {
    const document = browserRoot.document;
    const html = document.documentElement;
    let terminalStatus = String(status || "terminal-blocked").slice(0, 96);
    let expectedRules = null;
    let enforcing = false;
    const enforce = function enforceTerminalState() {
      if (enforcing) return;
      enforcing = true;
      try {
        const expectedText = gateStyleText(null);
        if (styleElement?.sheet?.disabled) {
          styleElement.sheet.disabled = false;
        }
        if (styleElement && (
          !styleElement.isConnected ||
          styleElement.textContent !== expectedText ||
          canonicalRuntimeCssRules(styleElement) !== expectedRules
        )) {
          styleElement.textContent = expectedText;
          (document.head || document.documentElement).appendChild(styleElement);
          expectedRules = canonicalRuntimeCssRules(styleElement);
        }
        if (!html.classList.contains(CLASS.lock)) html.classList.add(CLASS.lock);
        if (html.getAttribute(ATTR.lock) !== "1") html.setAttribute(ATTR.lock, "1");
        clearProtocolState(document);
        if (html.hasAttribute(ATTR.measure)) html.removeAttribute(ATTR.measure);
        if (html.classList.contains(CLASS.ready)) html.classList.remove(CLASS.ready);
        if (html.hasAttribute(ATTR.ready)) html.removeAttribute(ATTR.ready);
        if (html.hasAttribute(ATTR.protocol)) html.removeAttribute(ATTR.protocol);
        if (html.getAttribute(ATTR.state) !== "blocked") {
          html.setAttribute(ATTR.state, "blocked");
        }
        if (html.getAttribute(ATTR.status) !== terminalStatus) {
          html.setAttribute(ATTR.status, terminalStatus);
        }
        if (
          html.style.getPropertyValue("visibility") !== "hidden" ||
          html.style.getPropertyPriority("visibility") !== "important"
        ) {
          html.style.setProperty("visibility", "hidden", "important");
        }
        if (
          html.style.getPropertyValue("transition") !== "none" ||
          html.style.getPropertyPriority("transition") !== "important"
        ) {
          html.style.setProperty("transition", "none", "important");
        }
        if (
          html.style.getPropertyValue("animation") !== "none" ||
          html.style.getPropertyPriority("animation") !== "important"
        ) {
          html.style.setProperty("animation", "none", "important");
        }
        if (
          html.style.getPropertyValue("display") !== "none" ||
          html.style.getPropertyPriority("display") !== "important"
        ) {
          html.style.setProperty("display", "none", "important");
        }
        if (
          html.style.getPropertyValue("opacity") !== "0" ||
          html.style.getPropertyPriority("opacity") !== "important"
        ) {
          html.style.setProperty("opacity", "0", "important");
        }
        if (
          html.style.getPropertyValue("content-visibility") !== "hidden" ||
          html.style.getPropertyPriority("content-visibility") !== "important"
        ) {
          html.style.setProperty("content-visibility", "hidden", "important");
        }
        if (
          html.style.getPropertyValue("clip-path") !== "inset(50%)" ||
          html.style.getPropertyPriority("clip-path") !== "important"
        ) {
          html.style.setProperty("clip-path", "inset(50%)", "important");
        }
        if (
          html.style.getPropertyValue("pointer-events") !== "none" ||
          html.style.getPropertyPriority("pointer-events") !== "important"
        ) {
          html.style.setProperty("pointer-events", "none", "important");
        }
        if (
          html.style.getPropertyValue("caret-color") !== "transparent" ||
          html.style.getPropertyPriority("caret-color") !== "important"
        ) {
          html.style.setProperty("caret-color", "transparent", "important");
        }
      } finally {
        enforcing = false;
      }
    };
    enforce();
    const observer = createNativeMutationObserver(browserRoot, enforce);
    observer.observe(document.documentElement, {
      subtree: true,
      childList: true,
      characterData: true,
      attributes: true,
    });
    let frameId = 0;
    const frame = function terminalSentinelFrame() {
      enforce();
      frameId = nativeAnimationFrame(browserRoot, frame);
    };
    frameId = nativeAnimationFrame(browserRoot, frame);
    return Object.freeze({
      update(nextStatus) {
        terminalStatus = String(nextStatus || terminalStatus).slice(0, 96);
        enforce();
      },
      observer,
      frameId,
    });
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
      visibleLeakCount: 0,
    });
    NATIVE.defineProperty(browserRoot, "__HOTDEAL_FOCUS_DIAGNOSTICS__", {
      value: safeDetails,
      configurable: true,
      enumerable: false,
      writable: false,
    });
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
    if (!seed) {
      return { ok: false, role: "seed", reason: "required" };
    }
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
    const visibleTitle = approvedVisibleTitle(document, seed.title, titleNode);
    const seedTitleEvidence = visibleTitle.evidence;
    if (!seedTitleEvidence.algumon.ok) {
      return { ok: false, role: "seed", reason: "title-mismatch" };
    }
    if (!seedTitleEvidence.metadata.ok) {
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
      roleProjection?.title?.mode !== "seeded-shallow" ||
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
    const bodyIgnored = ignoredRootsWithin(
      bodyNode,
      roleProjection.body.ignored,
    );
    if (rootsOverlap(bodyIgnored)) {
      return { ok: false, role: "body", reason: "ignored-overlap" };
    }
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
    const productIgnored = productNode
      ? ignoredRootsWithin(productNode, roleProjection.product.ignored)
      : [];
    if (rootsOverlap(productIgnored)) {
      return { ok: false, role: "product", reason: "ignored-overlap" };
    }
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
    if (commentCandidates.length !== 1) {
      return { ok: false, role: "comments", reason: "mount-cardinality" };
    }
    const commentMount = commentCandidates[0];
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
    const commentItems = uniqueElements(queryAllSafe(commentMount, itemHints));
    const commentControls = uniqueElements(queryAllSafe(commentMount, controlHints));
    const commentIgnored = uniqueElements(queryAllSafe(commentMount, ignoredHints));
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
    )) {
      return { ok: false, role: "comments", reason: "publisher-paint" };
    }
    const classifiedCommentRoots = commentItems.concat(commentControls, commentIgnored);
    const commentJsonLd = collectJsonLd(document);
    const seedCommentCount = Number.isInteger(seed.commentCount) ? seed.commentCount : null;
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
      classifiedCommentRoots,
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
      return {
        ok: false,
        role: "comments",
        reason: "incomplete-comment-control",
      };
    }
    if (visibleCommentTotal.count !== null) {
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
      commentCountBoundary: pageRoot,
      commentTotalEvidence: visibleCommentTotal.elements,
      bodyIgnored,
      productIgnored,
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

  function resolveDocumentFromSeedCandidates(document, layouts, candidates) {
    const resolutions = candidates.map(function resolveCandidate(seed) {
      return Object.freeze({ seed, resolution: resolveDocument(document, layouts, seed) });
    });
    const approved = resolutions.filter(function approvedCandidate(candidate) {
      return candidate.resolution.ok;
    });
    if (approved.length === 1) {
      return Object.freeze({ ok: true, seed: approved[0].seed, resolution: approved[0].resolution });
    }
    if (approved.length > 1) {
      return Object.freeze({
        ok: false,
        reason: "ambiguous-seed-candidate",
        resolution: Object.freeze({ ok: false, role: "seed", reason: "ambiguous-candidate" }),
      });
    }
    return Object.freeze({
      ok: false,
      reason: "no-seed-candidate-match",
      resolution: resolutions[0]?.resolution ||
        Object.freeze({ ok: false, role: "seed", reason: "no-candidate" }),
    });
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
      if (phase === "released") {
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
    const guard = createNativeMutationObserver(browserRoot, function enforceBootstrapLock(mutations) {
      if (terminallyBlocked) {
        return;
      }
      const styleFailure = runtimeGateStyleFailure(styleElement, runtime);
      const styleIntact = styleFailure === null;
      const changedTreesIntact = mutations.every(function changedTreeIntact(mutation) {
        if (!elementShapeIntact(mutation.target)) return false;
        return Array.from(mutation.addedNodes || []).every(treeShapeIntact);
      });
      const rootIntact = rootShapeIntact();
      const bootstrapInlineIntact =
        runtime.releasePhase === "released" || runtime.bootstrapLock?.intact();
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
    });
    guard.observe(document.documentElement, {
      subtree: true,
      childList: true,
      characterData: true,
      attributes: true,
    });
    runtime.bootstrapGuard = guard;
  }

  function subscribeCssomMutations(browserRoot, listener) {
    const prototype = browserRoot === RUNTIME_GLOBAL
      ? NATIVE.cssStyleSheetPrototype
      : browserRoot.CSSStyleSheet?.prototype;
    if (!prototype) return function noopUnsubscribe() {};
    let record = CSSOM_MUTATION_LISTENERS.get(prototype);
    if (!record) {
      const listeners = new Set();
      record = { listeners };
      ["insertRule", "deleteRule", "replace", "replaceSync"].forEach(
        function sealCssomMutationMethod(methodName) {
          const nativeMethod = browserRoot === RUNTIME_GLOBAL
            ? NATIVE.cssStyleSheetMethods[methodName]
            : prototype[methodName];
          if (typeof nativeMethod !== "function") return;
          try {
            NATIVE.defineProperty(prototype, methodName, {
              configurable: false,
              enumerable: false,
              writable: false,
              value: function hotdealFocusObservedCssomMutation() {
                const sheet = this;
                const result = NATIVE.reflectApply(nativeMethod, sheet, arguments);
                listeners.forEach(function reportCssomMutation(callback) {
                  callback(sheet, methodName);
                });
                if (result && typeof result.then === "function") {
                  result.then(() => listeners.forEach(function reportResolved(callback) {
                    callback(sheet, methodName);
                  })).catch(function ignoreRejectedReplacement() {});
                }
                return result;
              },
            });
          } catch (_error) {
            // The nonce-bound runtime stylesheet still has a per-frame cssRules check.
          }
        }
      );
      CSSOM_MUTATION_LISTENERS.set(prototype, record);
    }
    record.listeners.add(listener);
    return function unsubscribeCssomMutations() {
      record.listeners.delete(listener);
    };
  }

  function subscribeAdoptedStyleSheetMutations(browserRoot, listener) {
    const prototypes = [
      browserRoot.Document?.prototype,
      browserRoot.ShadowRoot?.prototype,
    ].filter(function uniquePrototype(prototype, index, candidates) {
      return prototype && candidates.indexOf(prototype) === index;
    });
    const records = [];
    prototypes.forEach(function observeAdoptedStyleSheets(prototype) {
      let record = ADOPTED_STYLE_SHEET_LISTENERS.get(prototype);
      if (!record) {
        const descriptor = Object.getOwnPropertyDescriptor(prototype, "adoptedStyleSheets");
        if (
          !descriptor ||
          typeof descriptor.get !== "function" ||
          typeof descriptor.set !== "function"
        ) {
          return;
        }
        const listeners = new Set();
        try {
          NATIVE.defineProperty(prototype, "adoptedStyleSheets", {
            configurable: false,
            enumerable: descriptor.enumerable === true,
            get: descriptor.get,
            set: function hotdealFocusObservedAdoptedStyleSheets() {
              const result = NATIVE.reflectApply(descriptor.set, this, arguments);
              listeners.forEach(function reportAdoptedStyleSheetMutation(callback) {
                callback(this);
              });
              return result;
            },
          });
        } catch (_error) {
          return;
        }
        record = { listeners };
        ADOPTED_STYLE_SHEET_LISTENERS.set(prototype, record);
      }
      record.listeners.add(listener);
      records.push(record);
    });
    return function unsubscribeAdoptedStyleSheetMutations() {
      records.forEach(function removeAdoptedStyleSheetListener(record) {
        record.listeners.delete(listener);
      });
    };
  }

  function subscribeStyleSheetStateMutations(browserRoot, listener) {
    const prototype = browserRoot.StyleSheet?.prototype;
    const descriptor = prototype && Object.getOwnPropertyDescriptor(prototype, "disabled");
    if (!prototype || !descriptor || typeof descriptor.get !== "function" ||
        typeof descriptor.set !== "function") {
      return function noopUnsubscribe() {};
    }
    let record = STYLE_SHEET_STATE_LISTENERS.get(prototype);
    if (!record) {
      const listeners = new Set();
      try {
        NATIVE.defineProperty(prototype, "disabled", {
          configurable: false,
          enumerable: descriptor.enumerable === true,
          get: descriptor.get,
          set: function hotdealFocusObservedStyleSheetState() {
            const result = NATIVE.reflectApply(descriptor.set, this, arguments);
            listeners.forEach(function reportStyleSheetStateMutation(callback) {
              callback(this);
            });
            return result;
          },
        });
      } catch (_error) {
        return function noopUnsubscribe() {};
      }
      record = { listeners };
      STYLE_SHEET_STATE_LISTENERS.set(prototype, record);
    }
    record.listeners.add(listener);
    return function unsubscribeStyleSheetStateMutations() {
      record.listeners.delete(listener);
    };
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
      if (runtime.releasePhase !== "released") {
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
          !state.roles.comments.contains(target)
        ) {
          return false;
        }
        let candidate = target;
        while (candidate && state.roles.comments.contains(candidate)) {
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
        if (!state || !mutationParent || !state.roles.comments.contains(mutationParent)) {
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
      if (runtime.projectionState && projectionHasPublisherPaintRisk(document, runtime.projectionState)) {
        runtime.enterTerminal("projection-publisher-invariant");
        return false;
      }
      if (exposesRootPaint() || exposesTopLayer() || exposesUnowned(releaseCandidates)) {
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
      if (runtime.projectionState && projectionHasPublisherPaintRisk(document, runtime.projectionState)) {
        runtime.enterTerminal("projection-publisher-invariant");
        return false;
      }
      if (exposesRootPaint() || exposesTopLayer() || exposesUnowned(releaseCandidates)) {
        runtime.enterTerminal("cascade-visible-leak");
        return false;
      }
      return true;
    };
    const verifyCascade = function verifyCascade() {
      if (runtime.terminallyBlocked) return false;
      if (!runtimeGateStyleIntact(styleElement, runtime)) {
        runtime.enterTerminal("runtime-style-tamper-sentinel");
        return false;
      }
      if (!runtime.authorizedReady || !document.body) {
        pendingElements.clear();
        fullScanRequired = true;
        return true;
      }
      const projectionCascadeChanged = fullScanRequired || pendingElements.size > 0;
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
      if (
        projectionCascadeChanged &&
        runtime.projectionState &&
        projectionHasPublisherPaintRisk(document, runtime.projectionState)
      ) {
        runtime.enterTerminal("projection-publisher-invariant");
        return false;
      }
      if (exposesRootPaint() || exposesTopLayer() || exposesUnowned(candidates)) {
        runtime.enterTerminal("cascade-visible-leak");
        return false;
      }
      return true;
    };
    const observer = createNativeMutationObserver(browserRoot, function keepGateStyleLast(mutations) {
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
      mutations.forEach(function recordCascadeMutation(mutation) {
        if (mutation.type === "attributes") {
          if (mutation.target === styleElement) return;
          if (mutation.target.tagName === "STYLE" || mutation.target.tagName === "LINK") {
            stylesheetChanged = true;
            fullScanRequired = true;
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
          }
          queueElement(node);
        });
      });
      if (stylesheetChanged) {
        if (!runtimeGateStyleIntact(styleElement, runtime)) {
          runtime.enterTerminal("runtime-style-tamper-cascade-pre");
          return;
        }
        (document.head || document.documentElement).appendChild(styleElement);
        runtime.expectedStyleRules = canonicalRuntimeCssRules(styleElement);
        if (!runtimeGateStyleIntact(styleElement, runtime)) {
          runtime.enterTerminal("runtime-style-tamper-cascade-post");
        }
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
    runtime.unsubscribeCssom = subscribeCssomMutations(
      browserRoot,
      function cssomMutationObserved(sheet) {
        if (runtime.terminallyBlocked) return;
        if (sheet === styleElement.sheet) {
          runtime.enterTerminal("runtime-style-tamper-cssom");
          return;
        }
        fullScanRequired = true;
      },
    );
    runtime.unsubscribeAdoptedStyleSheets = subscribeAdoptedStyleSheetMutations(
      browserRoot,
      function adoptedStyleSheetsObserved() {
        if (runtime.terminallyBlocked) return;
        fullScanRequired = true;
      },
    );
    runtime.unsubscribeStyleSheetState = subscribeStyleSheetStateMutations(
      browserRoot,
      function styleSheetStateObserved(sheet) {
        if (runtime.terminallyBlocked) return;
        if (measurementStyleSheetMutationDepth > 0) {
          fullScanRequired = true;
          return;
        }
        if (sheet === styleElement.sheet) {
          if (document.documentElement.hasAttribute(ATTR.measure)) {
            fullScanRequired = true;
            return;
          }
          runtime.enterTerminal("runtime-style-tamper-sheet-state");
          return;
        }
        fullScanRequired = true;
      },
    );
    const sentinelFrame = function cascadeSentinelFrame() {
      verifyCascade();
      if (!runtime.terminallyBlocked) {
        runtime.cascadeFrameId = nativeAnimationFrame(browserRoot, sentinelFrame);
      }
    };
    runtime.cascadeFrameId = nativeAnimationFrame(browserRoot, sentinelFrame);
  }

  function proveStandaloneCascadeRelease(
    browserRoot,
    runtime,
    styleElement,
    cascadeSnapshot,
    release
  ) {
    const document = browserRoot.document;
    if (!document.body || runtime.terminallyBlocked || runtime.releasePending) return false;
    runtime.releasePending = true;
    const probe = document.createElement("div");
    const proofNonce = runtime.activeNonce;
    if (!proofNonce) {
      runtime.releasePending = false;
      runtime.enterTerminal("standalone-cascade-proof-nonce");
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
    const discardProbe = function discardReleaseProbe() {
      if (probe.isConnected) probe.remove();
      if (runtime.releaseProbe === probe) runtime.releaseProbe = null;
      runtime.releasePending = false;
      runtime.releaseProofFrameId = 0;
    };
    const reject = function rejectReleaseProof(reason) {
      discardProbe();
      runtime.enterTerminal(reason);
    };
    armProbe();
    document.body.appendChild(probe);
    runtime.releaseProbe = probe;
    let provedFrames = 0;
    const sample = function sampleStandaloneCascade() {
      runtime.releaseProofFrameId = 0;
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
      if (provedFrames < CASCADE_PROOF_FRAMES) {
        armProbe();
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
      if (
        !runtimeGateStyleIntact(styleElement, runtime) ||
        !runtime.verifyCascadeRelease(cascadeSnapshot)
      ) {
        if (!runtime.terminallyBlocked) runtime.enterTerminal("cascade-release-proof");
        return;
      }
      release();
    };
    runtime.releaseProofFrameId = nativeAnimationFrame(browserRoot, sample);
    return true;
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
      while (candidate && state.roles.comments.contains(candidate)) {
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
    const consumeAuthorizedMarkerMutations = function consumeAuthorizedMarkerMutations(
      authorizedTargets,
    ) {
      return observer.takeRecords().every(function exactInternalMarkerMutation(mutation) {
        if (
          mutation.type !== "attributes" ||
          !authorizedTargets.has(mutation.target)
        ) {
          return false;
        }
        if (mutation.attributeName === "class") {
          return state.ownedElements.has(mutation.target) &&
            markerShapeMatches(
              mutation.target,
              state.expectedMarkerShapes.get(mutation.target),
            );
        }
        return protocolAttributes.has(mutation.attributeName) &&
          exactProtocolAttribute(mutation.target, mutation.attributeName);
      });
    };
    const classifyNewCommentRoot = function classifyNewCommentRoot(node) {
      const matchesItem = elementMatchesAny(node, state.commentItemSelectors);
      const matchesControl = elementMatchesAny(node, state.commentControlSelectors);
      const matchesIgnored = elementMatchesAny(node, state.commentIgnoredSelectors);
      if (Number(matchesItem) + Number(matchesControl) + Number(matchesIgnored) !== 1) {
        return null;
      }
      return matchesItem ? "item" : matchesControl ? "control" : "ignored";
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
      [state.commentControlRoots, state.commentIgnoredRoots]
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
    const observer = createNativeMutationObserver(browserRoot, function sealProjection(mutations) {
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
          const inComments = state.roles.comments.contains(target);
          if (!inBody && !inProduct && !inTitle && !inComments) {
            continue;
          }
          projectionTouched = true;
          if (
            insideAnyRoot(target, trackedRoots(state.bodyIgnoredRoots)) ||
            insideAnyRoot(target, trackedRoots(state.productIgnoredRoots)) ||
            insideAnyRoot(target, trackedRoots(state.commentIgnoredRoots))
          ) {
            continue;
          }
          const controlRoot = inComments
            ? closestTrackedRoot(target, state.commentControlRoots)
            : null;
          if (
            controlRoot &&
            COMMENT_CONTROL_STATE_ATTRIBUTES.has(name) &&
            elementMatchesAny(controlRoot, state.commentControlSelectors)
          ) {
            commentProjectionChanged = true;
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
        const inComments = Boolean(
          mutationParent && state.roles.comments.contains(mutationParent),
        );
        const inIgnoredProjection = Boolean(mutationParent) && (
          insideAnyRoot(mutationParent, trackedRoots(state.bodyIgnoredRoots)) ||
          insideAnyRoot(mutationParent, trackedRoots(state.productIgnoredRoots)) ||
          insideAnyRoot(mutationParent, trackedRoots(state.commentIgnoredRoots))
        );
        if (mutation.type === "characterData") {
          if (!inIgnoredProjection && (inBody || inProduct || inTitle || inComments)) {
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
          continue;
        }
        if (inBody || inProduct || inTitle || inComments) {
          projectionTouched = true;
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
          } else if (inBody || inProduct || inTitle) {
            failureReason = "atomic-removal";
          } else if (inComments) {
            const removalKind = removeTrackedCommentTree(removed);
            if (removalKind === "item") {
              failureReason = "comment-removal";
            } else if (removalKind === null) {
              failureReason = "unclassified-comment-removal";
            } else {
              commentProjectionChanged = true;
            }
          } else if (removed.nodeType === 1) {
            forgetRemovedTree(removed, state);
          } else if (inComments && normalizeText(removed.data)) {
            failureReason = "comment-text-removal";
          }
        }
        for (const added of mutation.addedNodes) {
          if (failureReason) break;
          if (added === styleElement) continue;
          if (inBody || inProduct || inTitle) {
            failureReason = "atomic-addition";
            break;
          }
          if (!inComments) {
            if (added.nodeType === 1) {
              if (added.matches(
                `[${ATTR.keep}], [${ATTR.deep}], [${ATTR.shell}], [${ATTR.role}], ` +
                `.${CLASS.keep}, .${CLASS.shell}, .${CLASS.deep}, ` +
                `[class*="${CLASS.rolePrefix}"]`
              ) || added.querySelector(
                `[${ATTR.keep}], [${ATTR.deep}], [${ATTR.shell}], [${ATTR.role}], ` +
                `.${CLASS.keep}, .${CLASS.shell}, .${CLASS.deep}, ` +
                `[class*="${CLASS.rolePrefix}"]`
              )) {
                failureReason = "outside-marker-spoof";
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
            failureReason = "unclassified-comment-addition";
            break;
          }
          stripOwnedAttributes(added);
          if (classification === "ignored") {
            state.commentIgnoredRoots.add(added);
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
          }
          commentProjectionChanged = true;
          const additionFailure = withPublisherVisibilityMeasurement(
            document,
            function validateProjectedCommentAddition() {
              if (!isRendered(added)) return "hidden-comment-addition";
              if (containsUnprovenShadowBoundary(added, [])) {
                return "shadow-comment-addition";
              }
              if (containsPublisherPaintRisk(added, [])) {
                return "publisher-paint-comment-addition";
              }
              return null;
            },
            function rejectUnsafeCommentMeasurement() {
              return "comment-measurement";
            },
          );
          if (additionFailure) {
            failureReason = additionFailure;
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
        if (!verifyOwnedState(document, state)) {
          failureReason = "projection-mismatch";
        }
      }
      if (!failureReason && commentProjectionChanged) {
        state.projectionEpoch += 1;
        if (!runtime.publishReadyProjectionDiagnostics()) {
          failureReason = "comment-control-projection";
        }
      }
      if (failureReason) {
        terminalBlock(failureReason);
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
        "class",
        "style",
        "hidden",
        "aria-expanded",
        "aria-pressed",
        "aria-selected",
        "aria-hidden",
        "open",
      ],
    });
    if (SHADOW_TRACKER) {
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
          terminalBlock("shadow-boundary");
          return;
        }
        if (
          state.roles.comments.contains(host) &&
          !verifyOwnedState(document, state)
        ) {
          terminalBlock("shadow-boundary");
        }
      };
      SHADOW_TRACKER.listeners.add(rejectProjectedShadow);
      runtime.unsubscribeShadow = function unsubscribeShadowTracking() {
        SHADOW_TRACKER.listeners.delete(rejectProjectedShadow);
        runtime.unsubscribeShadow = null;
      };
    }
    if (typeof NATIVE.addEventListener === "function" && typeof NATIVE.removeEventListener === "function") {
      const subscriptions = [];
      const subscribe = function subscribe(target, type, listener) {
        NATIVE.reflectApply(NATIVE.addEventListener, target, [type, listener, true]);
        subscriptions.push([target, type, listener]);
      };
      const rejectOpeningPopover = function rejectOpeningPopover(event) {
        const target = event.target;
        if (
          target?.matches?.("[popover], dialog") &&
          (event.newState === "open" || activePopover(target) || target.open === true)
        ) {
          runtime.enterTerminal("role-projection-top-layer-activation");
        }
      };
      const rejectProjectedFullscreen = function rejectProjectedFullscreen() {
        if (document.fullscreenElement) {
          runtime.enterTerminal("role-projection-top-layer-activation");
        }
      };
      subscribe(document, "beforetoggle", rejectOpeningPopover);
      subscribe(document, "toggle", rejectOpeningPopover);
      subscribe(document, "fullscreenchange", rejectProjectedFullscreen);
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
    seedCandidates,
    styleElement,
    bootstrapLock,
    targetReason,
    onReady
  ) {
    const document = browserRoot.document;
    const runtime = {
      discoveryObserver: null,
      integrityObserver: null,
      bootstrapGuard: null,
      cascadeGuard: null,
      cascadeFrameId: 0,
      unsubscribeCssom: null,
      unsubscribeAdoptedStyleSheets: null,
      unsubscribeStyleSheetState: null,
      unsubscribeShadow: null,
      unsubscribeProjectionEvents: null,
      projectionState: null,
      terminalGuardian: null,
      bootstrapLock,
      activeNonce: null,
      authorizedReady: false,
      releasePhase: "discovering",
      releasePending: false,
      releaseProofFrameId: 0,
      releaseProbe: null,
      expectedStyleText: styleElement.textContent,
      expectedStyleRules: canonicalRuntimeCssRules(styleElement),
      terminallyBlocked: false,
      attemptScheduled: false,
      beginDiscovery: null,
      stop: null,
      enterTerminal: null,
      discardCascadeRecords: null,
      prepareCascadeRelease: null,
      verifyCascadeRelease: null,
      verifyUnlockedCascadeRelease: null,
      readyDiagnostics: null,
      standaloneCascadeProof: null,
      publishReadyProjectionDiagnostics: null,
    };

    runtime.publishReadyProjectionDiagnostics = function publishReadyProjectionDiagnostics() {
      if (
        !runtime.authorizedReady ||
        !runtime.projectionState ||
        !runtime.readyDiagnostics
      ) {
        return false;
      }
      const commentControlProjection = withPublisherVisibilityMeasurement(
        document,
        function measureCommentControlProjection() {
          return currentCommentControlProjection(runtime.projectionState);
        },
        function rejectCommentControlMeasurement() { return null; },
      );
      if (!commentControlProjection?.currentProjectionValid) {
        runtime.enterTerminal("comment-control-projection");
        return false;
      }
      publishDiagnostics(browserRoot, {
        ...runtime.readyDiagnostics,
        standaloneCascadeProof: runtime.standaloneCascadeProof,
        commentControlProjection,
      });
      return true;
    };

    runtime.enterTerminal = function enterTerminal(reason) {
      if (runtime.terminallyBlocked) return;
      const terminalStatus = `terminal-${reason || "blocked"}`.slice(0, 96);
      runtime.terminallyBlocked = true;
      runtime.authorizedReady = false;
      runtime.releasePhase = "terminal";
      runtime.releasePending = false;
      runtime.activeNonce = null;
      runtime.standaloneCascadeProof = null;
      runtime.projectionState = null;
      runtime.readyDiagnostics = null;
      [
        runtime.discoveryObserver,
        runtime.integrityObserver,
        runtime.bootstrapGuard,
        runtime.cascadeGuard,
      ].forEach(
        function disconnectForTerminal(observer) {
          if (observer) observer.disconnect();
        }
      );
      runtime.discoveryObserver = null;
      runtime.integrityObserver = null;
      runtime.bootstrapGuard = null;
      runtime.cascadeGuard = null;
      if (runtime.cascadeFrameId) {
        nativeCancelAnimationFrame(browserRoot, runtime.cascadeFrameId);
        runtime.cascadeFrameId = 0;
      }
      if (runtime.releaseProofFrameId) {
        nativeCancelAnimationFrame(browserRoot, runtime.releaseProofFrameId);
        runtime.releaseProofFrameId = 0;
      }
      if (runtime.releaseProbe?.isConnected) runtime.releaseProbe.remove();
      runtime.releaseProbe = null;
      runtime.releasePending = false;
      if (runtime.unsubscribeCssom) {
        runtime.unsubscribeCssom();
        runtime.unsubscribeCssom = null;
      }
      if (runtime.unsubscribeAdoptedStyleSheets) {
        runtime.unsubscribeAdoptedStyleSheets();
        runtime.unsubscribeAdoptedStyleSheets = null;
      }
      if (runtime.unsubscribeStyleSheetState) {
        runtime.unsubscribeStyleSheetState();
        runtime.unsubscribeStyleSheetState = null;
      }
      if (runtime.unsubscribeShadow) runtime.unsubscribeShadow();
      if (runtime.unsubscribeProjectionEvents) runtime.unsubscribeProjectionEvents();
      document.documentElement.classList.add(CLASS.lock);
      document.documentElement.setAttribute(ATTR.lock, "1");
      writeRuntimeGateStyle(styleElement, null, runtime);
      clearProtocolState(document);
      if (runtime.terminalGuardian) {
        runtime.terminalGuardian.update(terminalStatus);
      } else {
        runtime.terminalGuardian = installPersistentTerminalGuardian(
          browserRoot,
          styleElement,
          terminalStatus,
        );
      }
      publishDiagnostics(browserRoot, {
        state: "blocked",
        targetReason: reason || "terminal",
      });
    };

    function attemptResolution() {
      runtime.attemptScheduled = false;
      if (runtime.releasePending || runtime.authorizedReady || runtime.terminallyBlocked) {
        return false;
      }
      if (!document.body) {
        return false;
      }
        const candidateResolution = resolveDocumentFromSeedCandidates(
          document,
          layouts,
          seedCandidates,
        );
        if (candidateResolution.reason === "ambiguous-seed-candidate") {
          runtime.enterTerminal("ambiguous-algumon-seed");
          return false;
        }
        const resolution = candidateResolution.resolution;
      if (!resolution.ok) {
        document.documentElement.setAttribute(ATTR.state, "blocked");
        document.documentElement.setAttribute(
          ATTR.status,
          `blocked-${resolution.role}-${resolution.reason}`.slice(0, 96)
        );
        publishDiagnostics(browserRoot, {
          state: "blocked",
          targetReason,
          semanticProjectionCount: resolution.semanticProjectionCount || 0,
        });
        return false;
      }
      const nonce = createRunNonce(browserRoot);
      if (!nonce) {
        document.documentElement.setAttribute(ATTR.state, "blocked");
        document.documentElement.setAttribute(ATTR.status, "blocked-secure-nonce");
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
      if (!verifyOwnedState(document, state)) {
        runtime.activeNonce = null;
        runtime.projectionState = null;
        writeRuntimeGateStyle(styleElement, null, runtime);
        clearProtocolState(document);
        document.documentElement.setAttribute(ATTR.status, "blocked-ownership-verification");
        document.documentElement.setAttribute(ATTR.state, "blocked");
        publishDiagnostics(browserRoot, {
          state: "blocked",
          targetReason,
        });
        return false;
      }
      if (!runtimeGateStyleIntact(styleElement, runtime)) {
        clearProtocolState(document);
        runtime.activeNonce = null;
        runtime.projectionState = null;
        document.documentElement.setAttribute(ATTR.status, "blocked-runtime-style");
        document.documentElement.setAttribute(ATTR.state, "blocked");
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
      return proveStandaloneCascadeRelease(
        browserRoot,
        runtime,
        styleElement,
        cascadeSnapshot,
        function releaseProvedProjection() {
          if (!runtime.publishReadyProjectionDiagnostics()) return;
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
          runtime.discardCascadeRecords?.();
          if (typeof onReady === "function") onReady(resolution, candidateResolution.seed);
        },
      );
    }

    function scheduleAttempt() {
      if (runtime.attemptScheduled || runtime.releasePending ||
          runtime.authorizedReady || runtime.terminallyBlocked) {
        return;
      }
      runtime.attemptScheduled = true;
      const schedule = browserRoot === RUNTIME_GLOBAL
        ? NATIVE.setTimeout
        : browserRoot.setTimeout.bind(browserRoot);
      schedule(attemptResolution, 0);
    }

    runtime.beginDiscovery = function beginDiscovery() {
      if (runtime.discoveryObserver) {
        return;
      }
      runtime.discoveryObserver = createNativeMutationObserver(browserRoot, scheduleAttempt);
      runtime.discoveryObserver.observe(document, {
        subtree: true,
        childList: true,
        characterData: true,
        attributes: true,
      });
      scheduleAttempt();
    };
    runtime.stop = function stopRuntime() {
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
      if (runtime.releaseProbe?.isConnected) runtime.releaseProbe.remove();
      runtime.releaseProbe = null;
      runtime.releasePending = false;
      if (runtime.unsubscribeCssom) {
        runtime.unsubscribeCssom();
        runtime.unsubscribeCssom = null;
      }
      if (runtime.unsubscribeAdoptedStyleSheets) {
        runtime.unsubscribeAdoptedStyleSheets();
        runtime.unsubscribeAdoptedStyleSheets = null;
      }
      if (runtime.unsubscribeStyleSheetState) {
        runtime.unsubscribeStyleSheetState();
        runtime.unsubscribeStyleSheetState = null;
      }
      if (runtime.unsubscribeShadow) runtime.unsubscribeShadow();
      if (runtime.unsubscribeProjectionEvents) runtime.unsubscribeProjectionEvents();
    };
    installBootstrapGuard(browserRoot, runtime, styleElement);
    installCascadeGuard(browserRoot, runtime, styleElement);
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
    const history = browserRoot.history;
    ["pushState", "replaceState"].forEach(function wrapHistoryMethod(methodName) {
      const original = browserRoot === RUNTIME_GLOBAL
        ? methodName === "pushState"
          ? NATIVE.historyPushState
          : NATIVE.historyReplaceState
        : history[methodName];
      if (typeof original !== "function") {
        return;
      }
      const wrapper = function hotdealFocusHistoryWrapper() {
        const result = NATIVE.reflectApply(original, history, arguments);
        revalidate();
        return result;
      };
      try {
        NATIVE.defineProperty(history, methodName, {
          configurable: false,
          enumerable: false,
          writable: false,
          value: wrapper,
        });
      } catch (_error) {
        // The userscript-manager urlchange event remains the authoritative SPA trigger.
      }
    });
    const addEventListener = browserRoot === RUNTIME_GLOBAL
      ? NATIVE.addEventListener
      : browserRoot.EventTarget?.prototype?.addEventListener;
    if (typeof addEventListener !== "function") return false;
    NATIVE.reflectApply(addEventListener, browserRoot, ["urlchange", revalidate, true]);
    NATIVE.reflectApply(addEventListener, browserRoot, ["hashchange", revalidate, true]);
    NATIVE.reflectApply(addEventListener, browserRoot, ["popstate", revalidate, true]);
    NATIVE.reflectApply(addEventListener, browserRoot, ["pageshow", function revalidateRestoredPage(event) {
      if (event.persisted === true) {
        revalidate();
      }
    }, true]);
    return true;
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
    lockWhenHtmlExists(document, function configureTarget(html, initialBootstrapLock) {
      if (!initialBootstrapLock) {
        html.classList.add(CLASS.lock);
        html.setAttribute(ATTR.lock, "1");
        html.setAttribute(ATTR.state, "blocked");
        html.setAttribute(ATTR.status, "terminal-bootstrap-lock-unavailable");
        html.style.setProperty("display", "none", "important");
        return;
      }
      const referrerSeed = referrerProjectionSeed(browserRoot, contract.id);
      function configureTargetWithReferrer() {
      const canonicalSeeds = referrerSeed ? Object.freeze([referrerSeed]) : Object.freeze([]);
      const initialSeedCandidates = Object.freeze(canonicalSeeds.filter(function matchesTargetSite(seed) {
        return seed.siteType === contract.id;
      }));
      let authorizedSeed = null;
      let authorizedArticleIdentity = null;
      let pendingArticleIdentity =
        initialSeedCandidates.length > 0
          ? articleIdentity(browserRoot.location, contract.id)
          : null;
      let activeRuntime = null;
      let activeStyle = null;
      let activeBootstrapLock = initialBootstrapLock;
      let navigationTerminalGuardian = null;
      let initialActivation = true;
      let navigationTerminallyBlocked = false;
      let navigationTerminalReason = null;

      function terminalNavigationBlock(reason) {
        if (navigationTerminallyBlocked) {
          return false;
        }
        navigationTerminallyBlocked = true;
        navigationTerminalReason = reason || "blocked";
        authorizedSeed = null;
        authorizedArticleIdentity = null;
        pendingArticleIdentity = null;
        if (activeRuntime) {
          activeRuntime.enterTerminal(navigationTerminalReason);
          return true;
        }
        if (activeStyle) activeStyle.textContent = gateStyleText(null);
        html.classList.add(CLASS.lock);
        html.setAttribute(ATTR.lock, "1");
        clearProtocolState(document);
        html.classList.remove(CLASS.ready);
        html.removeAttribute(ATTR.ready);
        html.removeAttribute(ATTR.protocol);
        html.setAttribute(ATTR.state, "blocked");
        html.setAttribute(ATTR.status, `terminal-${navigationTerminalReason}`.slice(0, 96));
        if (navigationTerminalGuardian) {
          navigationTerminalGuardian.update(
            `terminal-${navigationTerminalReason}`.slice(0, 96),
          );
        } else {
          navigationTerminalGuardian = installPersistentTerminalGuardian(
            browserRoot,
            activeStyle,
            `terminal-${navigationTerminalReason}`.slice(0, 96),
          );
        }
        publishDiagnostics(browserRoot, {
          state: "blocked",
          targetReason: navigationTerminalReason,
        });
        return true;
      }

      function activateCurrentLocation() {
        if (navigationTerminallyBlocked) {
          return;
        }
        if (activeRuntime && activeRuntime.terminallyBlocked) {
          html.classList.add(CLASS.lock);
          html.setAttribute(ATTR.lock, "1");
          html.classList.remove(CLASS.ready);
          html.removeAttribute(ATTR.ready);
          html.removeAttribute(ATTR.protocol);
          html.setAttribute(ATTR.state, "blocked");
          html.setAttribute(ATTR.status, "terminal-tamper");
          return;
        }
        const isInitialActivation = initialActivation;
        const pathAndQuery = `${browserRoot.location.pathname}${browserRoot.location.search}`;
        const layouts = matchingLayouts(contract, pathAndQuery);
        const currentArticleIdentity = articleIdentity(
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

        const seedCandidates = isInitialActivation
          ? initialSeedCandidates
          : authorizedArticleIdentity &&
              currentArticleIdentity === authorizedArticleIdentity
            ? [authorizedSeed]
            : pendingArticleIdentity &&
                currentArticleIdentity === pendingArticleIdentity
              ? [authorizedSeed]
              : [];
        if (seedCandidates.length === 0 || !currentArticleIdentity) {
          initialActivation = false;
          terminalNavigationBlock(
            canonicalSeeds.length > 0 && initialSeedCandidates.length === 0
              ? "algumon-site-mismatch"
              : seedCandidates.length === 0
                ? "algumon-seed-required"
                : "article-identity-required"
          );
          return;
        }
        if (layouts.length === 0) {
          initialActivation = false;
          terminalNavigationBlock("route-unapproved");
          return;
        }
        const evaluationLayouts = layouts;
        const targetReason = "algumon-referrer-known-route";
        initialActivation = false;
        try {
          activeStyle = installRuntimeGateStyle(document);
        } catch (_error) {
          activeStyle = null;
          terminalNavigationBlock("gm-runtime-style-unavailable");
          return;
        }
        html.setAttribute(ATTR.status, `locked-${targetReason}`);
        publishDiagnostics(browserRoot, {
          state: "locked",
          targetReason,
        });
        activeRuntime = createReaderRuntime(
          browserRoot,
          contract,
          evaluationLayouts,
          seedCandidates,
          activeStyle,
          activeBootstrapLock,
          targetReason,
          function authorizeResolvedArticle(_resolution, resolvedSeed) {
            authorizedSeed = resolvedSeed;
            authorizedArticleIdentity = currentArticleIdentity;
            pendingArticleIdentity = null;
          }
        );
        activeRuntime.beginDiscovery();
      }

      activateCurrentLocation();
      if (!installNavigationRevalidation(browserRoot, activateCurrentLocation)) {
        terminalNavigationBlock("navigation-guard-unavailable");
      }
      }
      configureTargetWithReferrer();
    });
    return { mode: "reader-gate", site: contract.id };
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
    sameArticleNavigation,
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
