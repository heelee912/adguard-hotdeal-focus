// ==UserScript==
// @name         AdGuard Hotdeal Focus Reader Gate
// @namespace    https://github.com/heelee912/adguard-hotdeal-focus
// @version      0.3.6
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
// @grant        none
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

  const PROTOCOL_VERSION = "1";
  const GENERATOR_VERSION = "0.3.6";
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
  });
  const SEED_FRAGMENT_KEY = "hdf-seed";
  const SEED_VERSION = 1;
  const SEED_MAX_AGE_MS = 10 * 60 * 1000;
  const SEED_MAX_BYTES = 1024;
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
  const ALGUMON_SITE_ICON_TYPES = Object.freeze({
    clien: "clien",
    ppomppu: "ppomppu",
    ruliweb: "ruliweb",
    quasarzone: "quasarzone",
    eomisae: "eomisae",
    zod: "zod",
    arcalive: "arcalive",
  });
  const ALGUMON_DESTINATION_DOMAINS = Object.freeze({
    clien: "clien.net",
    ppomppu: "ppomppu.co.kr",
    ruliweb: "ruliweb.com",
    quasarzone: "quasarzone.com",
    eomisae: "eomisae.co.kr",
    zod: "zod.kr",
    arcalive: "arca.live",
  });
  const ALLOWED_ALGUMON_SITE_TYPES = Object.freeze(
    new Set(Object.values(ALGUMON_SITE_ICON_TYPES))
  );
  const MAX_CANDIDATES = 800;
  const MAX_JSON_LD_BYTES = 262144;
  const MIN_BODY_TEXT_LENGTH = 80;
  const NOISE_TOKEN_PATTERN = /(?:^|[-_\s])(ad(?:s|vert|vertise|vertisement)?|banner|sponsor|promo|affiliate|recommend(?:ed|ation)?|related|popular|ranking|share|social|nav(?:igation)?|sidebar|footer|header|toolbar|breadcrumb|광고|広告|廣告|广告)(?:$|[-_\s])/i;
  const COMMENT_TOKEN_PATTERN = /(?:댓글|답글|코멘트|comment|comments|reply|replies|コメント|返信|评论|回复)/i;
  const PRODUCT_TOKEN_PATTERN = /(?:가격|상품|구매|쿠폰|배송|price|product|buy|coupon|shipping|価格|商品|購入|优惠|价格|购买)/i;
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
              "commentControls": [".post_comment > .comment_nav", ".post_comment .comment_more", ".post_comment .pagination", ".post_comment [data-role='reply-toggle']"],
              "commentIgnored": [".post_comment > .comment_head", ".post_comment > .comment_msg", ".post_comment > #comment_write_div", ".post_comment > .fr-overlay"]
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
            "roleProjection": {"title":{"mode":"seeded-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"required","selectors":[".topTitle-link"],"ignored":[]},"comments":{"mode":"classified-children"}},
            "hints": {
              "title": ["#topTitle > h1"],
              "product": [".topTitle-link"],
              "body": [".board-contents"],
              "comments": ["#comment_list_area"],
              "commentItems": ["#comment_list_area > .comment_wrapper[id^='iC_']"],
              "commentControls": ["#comment_list_area .comment_more", "#comment_list_area .pagination"],
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
            "roleProjection": {"title":{"mode":"seeded-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"required","selectors":[".bbs.view > h4 .info a.noeffect"],"ignored":[]},"comments":{"mode":"classified-children"}},
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
            "roleProjection": {"title":{"mode":"seeded-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"optional","selectors":[".source_url.box_line_with_shadow"],"ignored":[]},"comments":{"mode":"classified-children"}},
            "hints": {
              "title": [".subject_inner_text"],
              "product": [".source_url.box_line_with_shadow"],
              "body": [".view_content"],
              "comments": [".comment_view.normal"],
              "commentItems": [".comment_view.normal > .comment_element"],
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
            "applicableProfiles": ["desktop", "mobile"],
            "pageRoot": ".common-view-wrap",
            "allowEmptyComments": true,
            "requiredRoles": ["title", "product", "body", "comments"],
            "roleProjection": {"title":{"mode":"seeded-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"required","selectors":[".market-info-view-table"],"ignored":[]},"comments":{"mode":"classified-children"}},
            "hints": {
              "title": [".market-info-view-wrap h1.title"],
              "product": [".market-info-view-table"],
              "body": [".view-content > .note-editor"],
              "comments": ["#ajax-reply-list"],
              "commentItems": ["#ajax-reply-list > li"],
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
            "roleProjection": {"title":{"mode":"seeded-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"required","selectors":["#D_ .et_vars"],"ignored":[]},"comments":{"mode":"classified-children"}},
            "hints": {
              "title": ["#D_ ._hd h2"],
              "product": ["#D_ .et_vars"],
              "body": ["#D_ article > .rhymix_content"],
              "comments": ["#C_ > ._bd"],
              "commentItems": ["#C_ > ._bd > ._comment[id^='comment_']"],
              "commentControls": ["#C_ > ._bd .pagination", "#C_ > ._bd .more", "#C_ > ._bd .reply"],
              "commentIgnored": []
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
            "roleProjection": {"title":{"mode":"seeded-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"atomic-boundary","cardinality":"required","selectors":[".app-article-container > .app-board-extra-value"],"ignored":[]},"comments":{"mode":"classified-children"}},
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
            "roleProjection": {"title":{"mode":"seeded-shallow"},"body":{"mode":"atomic-boundary","ignored":[]},"product":{"mode":"absent","cardinality":"zero","selectors":[],"ignored":[]},"comments":{"mode":"classified-children"}},
            "hints": {
              "title": [".article-head h1", ".article-head h2", ".article-head .title"],
              "body": [".article-body", ".article-content"],
              "comments": [".article-comment"],
              "commentItems": [".article-comment > .comment-item"],
              "commentControls": [".article-comment .pagination", ".article-comment .more", ".article-comment .reply-toggle"],
              "commentIgnored": []
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

  function titleWordTokens(value) {
    return Array.from(new Set(
      normalizeText(stripBoundedTitleAffixes(value))
        .match(/[\p{L}\p{N}]+/gu) || []
    ));
  }

  function protectedTitleTokens(value) {
    const stripped = stripBoundedTitleAffixes(value);
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

  function titleConsistency(sourceValue, destinationValue) {
    return titleCoreEquivalence(sourceValue, destinationValue);
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

  function articleIdentity(locationLike, siteId) {
    let url;
    try {
      url = new URL(locationLike.href);
    } catch (_error) {
      return null;
    }
    const contract = SITE_CONTRACTS.find(function identityContract(candidate) {
      return candidate.id === siteId && hostnameMatches(url.hostname, candidate.domain);
    });
    if (!contract) return null;
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
        ? "zboard-view"
        : url.pathname === "/new/bbs_view.php"
          ? "mobile-bbs-view"
          : null;
      board = token(url.searchParams.get("id"));
      articleId = numeric(url.searchParams.get("no"));
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
        route = "board-document";
        board = token(match[1]);
        articleId = numeric(match[2]);
      } else if (url.pathname === "/index.php") {
        route = "legacy-document";
        board = token(url.searchParams.get("mid")) || "index-unscoped";
        articleId = numeric(url.searchParams.get("document_srl"));
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

  function utf8ByteLength(value) {
    return unescape(encodeURIComponent(String(value))).length;
  }

  function normalizeSiteType(value) {
    return String(value || "")
      .toLocaleLowerCase()
      .replace(/[^a-z0-9_-]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 32);
  }

  function normalizeCommentCount(value) {
    const number = Number.parseInt(String(value || "").replace(/[^0-9]/g, ""), 10);
    return Number.isSafeInteger(number) && number >= 0 && number <= 100000 ? number : null;
  }

  function validateSeed(seed, now, requireNavigationProof) {
    if (!seed || typeof seed !== "object" || Array.isArray(seed)) {
      return null;
    }
    const allowedKeys = new Set([
      "v",
      "siteType",
      "dealId",
      "title",
      "commentCount",
      "ts",
      "relayV",
      "relayT",
      "navigationNonce",
      "destinationUrl",
    ]);
    if (Object.keys(seed).some(function unknownKey(key) { return !allowedKeys.has(key); })) {
      return null;
    }
    if (seed.v !== SEED_VERSION || !Number.isFinite(seed.ts)) {
      return null;
    }
    if (now - seed.ts < 0 || now - seed.ts > SEED_MAX_AGE_MS) {
      return null;
    }
    const dealId = String(seed.dealId || "");
    const title = truncateText(seed.title, 240);
    const siteType = normalizeSiteType(seed.siteType);
    const commentCount = seed.commentCount === null
      ? null
      : normalizeCommentCount(seed.commentCount);
    const relayV = String(seed.relayV || "");
    const relayT = String(seed.relayT || "");
    const navigationNonce = String(seed.navigationNonce || "");
    const destination = seed.destinationUrl
      ? exactDestinationUrl(seed.destinationUrl, siteType)
      : null;
    if (
      !/^\d{1,24}$/.test(dealId) ||
      !title ||
      !ALLOWED_ALGUMON_SITE_TYPES.has(siteType) ||
      !/^[0-9a-f]{32}$/.test(relayV) ||
      !/^\d{13}$/.test(relayT) ||
      Math.abs(now - Number(relayT)) > SEED_MAX_AGE_MS ||
      (navigationNonce && !/^hdf-[0-9a-z]{28}$/.test(navigationNonce)) ||
      (requireNavigationProof === true && (
        !/^hdf-[0-9a-z]{28}$/.test(navigationNonce) || !destination
      ))
    ) {
      return null;
    }
    return Object.freeze({
      v: SEED_VERSION,
      siteType,
      dealId,
      title,
      commentCount,
      ts: seed.ts,
      relayV,
      relayT,
      navigationNonce: navigationNonce || null,
      destinationUrl: destination?.href || null,
    });
  }

  function encodeSeedFragment(browserRoot, seed) {
    const serialized = JSON.stringify(seed);
    if (utf8ByteLength(serialized) > SEED_MAX_BYTES || typeof browserRoot.btoa !== "function") {
      return null;
    }
    try {
      const binary = unescape(encodeURIComponent(serialized));
      return browserRoot.btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
    } catch (_error) {
      return null;
    }
  }

  function decodeSeedFragment(browserRoot, encoded) {
    if (!/^[A-Za-z0-9_-]+$/.test(encoded) || typeof browserRoot.atob !== "function") {
      return null;
    }
    try {
      const padding = "=".repeat((4 - (encoded.length % 4)) % 4);
      const binary = browserRoot.atob(
        encoded.replace(/-/g, "+").replace(/_/g, "/") + padding
      );
      const serialized = decodeURIComponent(escape(binary));
      if (utf8ByteLength(serialized) > SEED_MAX_BYTES) {
        return null;
      }
      return validateSeed(JSON.parse(serialized), Date.now(), true);
    } catch (_error) {
      return null;
    }
  }

  function fragmentParts(hash) {
    return String(hash || "").replace(/^#/, "").split("&").filter(Boolean);
  }

  function writeSeedFragment(browserRoot, anchor, seed) {
    const encoded = encodeSeedFragment(browserRoot, seed);
    if (!encoded) {
      return false;
    }
    let url;
    try {
      url = new URL(anchor.href, anchor.ownerDocument.location.href);
    } catch (_error) {
      return false;
    }
    const retained = fragmentParts(url.hash).filter(function retainFragmentPart(part) {
      return !part.startsWith(`${SEED_FRAGMENT_KEY}=`);
    });
    retained.push(`${SEED_FRAGMENT_KEY}=${encoded}`);
    url.hash = retained.join("&");
    anchor.href = url.href;
    return true;
  }

  function readAndClearFragmentSeed(browserRoot) {
    const parts = fragmentParts(browserRoot.location.hash);
    let encoded = null;
    const retained = [];
    parts.forEach(function classifyFragmentPart(part) {
      if (encoded === null && part.startsWith(`${SEED_FRAGMENT_KEY}=`)) {
        encoded = part.slice(SEED_FRAGMENT_KEY.length + 1);
      } else if (!part.startsWith(`${SEED_FRAGMENT_KEY}=`)) {
        retained.push(part);
      }
    });
    if (encoded === null) {
      return null;
    }
    try {
      const remainingHash = retained.length ? `#${retained.join("&")}` : "";
      const cleanUrl = `${browserRoot.location.pathname}${browserRoot.location.search}${remainingHash}`;
      browserRoot.history.replaceState(
        browserRoot.history.state,
        browserRoot.document.title,
        cleanUrl
      );
    } catch (_error) {
      return null;
    }
    return decodeSeedFragment(browserRoot, encoded);
  }

  function readAndClearSeed(browserRoot) {
    const fragmentSeed = readAndClearFragmentSeed(browserRoot);
    let navigationName = "";
    try {
      navigationName = String(browserRoot.name || "");
      browserRoot.name = "";
    } catch (_error) {
      return null;
    }
    if (
      !fragmentSeed ||
      !isAlgumonReferrer(browserRoot.document.referrer) ||
      navigationName !== `hdf-provenance:${fragmentSeed.navigationNonce}` ||
      exactDestinationUrl(browserRoot.location.href, fragmentSeed.siteType)?.href !==
        fragmentSeed.destinationUrl
    ) {
      return null;
    }
    return fragmentSeed;
  }

  function exactSignedAlgumonDealUrl(urlLike, expectedDealId) {
    let url;
    try {
      url = new URL(urlLike);
    } catch (_error) {
      return null;
    }
    const dealMatch = url.pathname.match(/^\/l\/d\/(\d{1,24})$/u);
    const queryKeys = Array.from(url.searchParams.keys());
    if (
      url.protocol !== "https:" ||
      url.hostname.toLocaleLowerCase() !== "www.algumon.com" ||
      url.username ||
      url.password ||
      url.port ||
      url.hash ||
      !dealMatch ||
      (expectedDealId && dealMatch[1] !== String(expectedDealId)) ||
      queryKeys.length !== 2 ||
      queryKeys[0] !== "v" ||
      queryKeys[1] !== "t" ||
      url.searchParams.getAll("v").length !== 1 ||
      url.searchParams.getAll("t").length !== 1 ||
      !/^[0-9a-f]{32}$/u.test(url.searchParams.get("v") || "") ||
      !/^\d{13}$/u.test(url.searchParams.get("t") || "")
    ) {
      return null;
    }
    return url;
  }

  function exactDestinationUrl(urlLike, siteType) {
    let url;
    try {
      url = new URL(urlLike);
    } catch (_error) {
      return null;
    }
    const domain = ALGUMON_DESTINATION_DOMAINS[siteType];
    if (
      !domain ||
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.port ||
      url.hash ||
      !hostnameMatches(url.hostname, domain)
    ) {
      return null;
    }
    return url;
  }

  function exactAlgumonSiteType(card) {
    const rawDataType =
      card.getAttribute("data-site-type") ||
      card.getAttribute("data-site") ||
      card.querySelector("[data-site-type]")?.getAttribute("data-site-type") ||
      card.querySelector("[data-site]")?.getAttribute("data-site") ||
      "";
    const dataType = normalizeSiteType(rawDataType);
    const exactDataType = ALLOWED_ALGUMON_SITE_TYPES.has(dataType) ? dataType : null;
    if (rawDataType && !exactDataType) {
      return null;
    }
    const iconTypes = new Set();
    let invalidSiteIcon = false;
    card.querySelectorAll("img[src]").forEach(function inspectSiteIcon(image) {
      try {
        const iconUrl = new URL(image.src, card.ownerDocument.location.href);
        const match = iconUrl.pathname.match(/^\/site-icon\/([a-z0-9_-]+)\.png$/);
        if (!iconUrl.pathname.includes("/site-icon/")) {
          return;
        }
        if (
          iconUrl.protocol === "https:" &&
          iconUrl.hostname.toLocaleLowerCase() === "cdn.algumon.com" &&
          !iconUrl.username &&
          !iconUrl.password &&
          !iconUrl.port &&
          match &&
          ALGUMON_SITE_ICON_TYPES[match[1]]
        ) {
          iconTypes.add(ALGUMON_SITE_ICON_TYPES[match[1]]);
        } else {
          invalidSiteIcon = true;
        }
      } catch (_error) {
        if (String(image.getAttribute("src") || "").includes("/site-icon/")) {
          invalidSiteIcon = true;
        }
      }
    });
    if (invalidSiteIcon || iconTypes.size > 1) {
      return null;
    }
    const iconType = iconTypes.size === 1 ? [...iconTypes][0] : null;
    if (exactDataType && iconType && exactDataType !== iconType) {
      return null;
    }
    return exactDataType || iconType;
  }

  function extractAlgumonSeed(anchor) {
    let url;
    try {
      const rawHref = anchor.getAttribute("href") ||
        anchor.getAttribute("data-hotdeal-focus-blocked-href") || "";
      url = exactSignedAlgumonDealUrl(
        new URL(rawHref, anchor.ownerDocument.location.href).href,
      );
    } catch (_error) {
      return null;
    }
    if (!url) {
      return null;
    }
    const dealMatch = url.pathname.match(/^\/l\/d\/(\d{1,24})$/u);
    const card = anchor.closest(
      ".deal-feed-card, [data-site-type], [data-site], article, li, tr, .deal, .item, .card"
    ) || anchor;
    const titleNode = card.querySelector(
      "[data-title], h1, h2, h3, h4, .title, [class*='title']"
    );
    const title = truncateText(
      (titleNode && (titleNode.getAttribute("data-title") || titleNode.textContent)) ||
        anchor.getAttribute("data-title") ||
        anchor.textContent,
      240
    );
    if (!title) {
      return null;
    }
    const sourceCountNode = card.querySelector(
      "[data-source-comment-count], [data-origin-comment-count]"
    );
    const explicitCount =
      card.getAttribute("data-source-comment-count") ||
      card.getAttribute("data-origin-comment-count") ||
      (sourceCountNode && (
        sourceCountNode.getAttribute("data-source-comment-count") ||
        sourceCountNode.getAttribute("data-origin-comment-count")
      ));
    const siteType = exactAlgumonSiteType(card);
    if (!siteType) {
      return null;
    }
    return validateSeed(
      {
        v: SEED_VERSION,
        siteType,
        dealId: dealMatch[1],
        title,
        commentCount: normalizeCommentCount(explicitCount),
        ts: Date.now(),
        relayV: url.searchParams.get("v"),
        relayT: url.searchParams.get("t"),
      },
      Date.now(),
      false
    );
  }

  function installAlgumonSeedCapture(browserRoot) {
    const document = browserRoot.document;
    const BLOCKED_HREF_ATTR = "data-hotdeal-focus-blocked-href";
    const RELAY_RESPONSE_MAX_BYTES = 4096;
    const RELAY_CACHE_TTL_MS = 30 * 1000;
    const relayResolutionCache = new Map();
    function dealHref(anchor) {
      return anchor.getAttribute("href") || anchor.getAttribute(BLOCKED_HREF_ATTR) || "";
    }
    function isDealNavigation(anchor) {
      try {
        const dealUrl = new URL(dealHref(anchor), anchor.ownerDocument.location.href);
        return isAlgumonHostname(dealUrl.hostname) &&
          /^\/l\/d\/\d{1,24}(?:\/|$)/.test(dealUrl.pathname);
      } catch (_error) {
        return false;
      }
    }
    function isExactSignedDealNavigation(anchor) {
      try {
        return Boolean(exactSignedAlgumonDealUrl(
          new URL(dealHref(anchor), anchor.ownerDocument.location.href).href,
        ));
      } catch (_error) {
        return false;
      }
    }
    function enforceDealLinkIdentity() {
      document.querySelectorAll(`a[href*="/l/d/"], a[${BLOCKED_HREF_ATTR}]`).forEach(
        function classifyDealAnchor(anchor) {
          if (!isDealNavigation(anchor)) {
            return;
          }
          const blockedHref = anchor.getAttribute(BLOCKED_HREF_ATTR);
          if (isExactSignedDealNavigation(anchor) && extractAlgumonSeed(anchor)) {
            if (blockedHref && !anchor.hasAttribute("href")) {
              anchor.setAttribute("href", blockedHref);
            }
            anchor.removeAttribute(BLOCKED_HREF_ATTR);
            anchor.removeAttribute("aria-disabled");
            return;
          }
          const href = anchor.getAttribute("href") || blockedHref;
          if (href) {
            anchor.setAttribute(BLOCKED_HREF_ATTR, href);
          }
          anchor.removeAttribute("href");
          anchor.setAttribute("aria-disabled", "true");
        }
      );
    }
    let enforcementScheduled = false;
    function scheduleDealLinkEnforcement() {
      if (enforcementScheduled) return;
      enforcementScheduled = true;
      const queue = browserRoot === RUNTIME_GLOBAL
        ? NATIVE.queueMicrotask
        : browserRoot.queueMicrotask.bind(browserRoot);
      queue(function enforceAfterMutationBatch() {
        enforcementScheduled = false;
        enforceDealLinkIdentity();
      });
    }
    function createSecureRelayPopup() {
      let child = null;
      try {
        child = browserRoot.open("about:blank", "_blank");
        if (!child) {
          return null;
        }
        child.opener = null;
        const childDocument = child.document;
        const head = childDocument.head || childDocument.createElement("head");
        const body = childDocument.body || childDocument.createElement("body");
        if (!childDocument.head) {
          childDocument.documentElement.appendChild(head);
        }
        if (!childDocument.body) {
          childDocument.documentElement.appendChild(body);
        }
        const referrer = childDocument.createElement("meta");
        referrer.setAttribute("name", "referrer");
        referrer.setAttribute("content", "origin");
        head.appendChild(referrer);
        return child;
      } catch (_error) {
        try {
          if (child && !child.closed) child.close();
        } catch (_closeError) {
          // The originating Algumon page remains in place on relay failure.
        }
        return null;
      }
    }
    function parseSignedRelayDocument(source, siteType) {
      if (!source || utf8ByteLength(source) > RELAY_RESPONSE_MAX_BYTES) {
        return null;
      }
      const parsed = new browserRoot.DOMParser().parseFromString(source, "text/html");
      if (
        !parsed ||
        parsed.querySelector("parsererror") ||
        parsed.querySelector("base, meta[http-equiv='refresh' i]")
      ) {
        return null;
      }
      const scripts = Array.from(parsed.querySelectorAll("script"));
      const anchors = Array.from(parsed.body?.querySelectorAll("a[href]") || []);
      if (scripts.length !== 1 || anchors.length !== 1) {
        return null;
      }
      const scriptMatch = String(scripts[0].textContent || "").match(
        /^\s*window\.location\.href\s*=\s*("(?:\\.|[^"\\])*")\s*;\s*$/u,
      );
      if (!scriptMatch) {
        return null;
      }
      let scriptedUrl;
      try {
        scriptedUrl = JSON.parse(scriptMatch[1]);
      } catch (_error) {
        return null;
      }
      const scriptDestination = exactDestinationUrl(scriptedUrl, siteType);
      const anchorDestination = exactDestinationUrl(
        anchors[0].getAttribute("href"),
        siteType,
      );
      if (
        !scriptDestination ||
        !anchorDestination ||
        scriptDestination.href !== anchorDestination.href
      ) {
        return null;
      }
      return scriptDestination;
    }
    function resolveSignedAlgumonDestination(signedUrl, seed) {
      const cacheKey = signedUrl.href;
      const cached = relayResolutionCache.get(cacheKey);
      if (cached && cached.expiresAt > Date.now()) {
        return cached.promise;
      }
      const resolution = browserRoot.fetch(cacheKey, {
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer",
      }).then(async function verifySignedResponse(response) {
        if (
          response.status !== 200 ||
          response.redirected ||
          response.url !== cacheKey ||
          !/^text\/html(?:\s*;|$)/iu.test(response.headers.get("content-type") || "")
        ) {
          throw new Error("invalid signed relay response");
        }
        const source = await response.text();
        const destination = parseSignedRelayDocument(source, seed.siteType);
        if (!destination) {
          throw new Error("invalid signed relay document");
        }
        return destination;
      });
      relayResolutionCache.set(cacheKey, {
        expiresAt: Date.now() + RELAY_CACHE_TTL_MS,
        promise: resolution,
      });
      resolution.catch(function discardFailedRelay() {
        const current = relayResolutionCache.get(cacheKey);
        if (current?.promise === resolution) relayResolutionCache.delete(cacheKey);
      });
      return resolution;
    }
    function closeRelayPopup(child) {
      try {
        if (child && !child.closed) child.close();
      } catch (_error) {
        // A failed relay remains fail-closed even if the blank popup cannot be closed.
      }
    }
    function navigateResolvedRelay(child, destination, seed) {
      try {
        child.name = `hdf-provenance:${seed.navigationNonce}`;
        const relay = document.createElement("a");
        relay.href = destination.href;
        relay.target = child.name;
        relay.referrerPolicy = "origin";
        if (!writeSeedFragment(browserRoot, relay, seed)) {
          return false;
        }
        if (typeof NATIVE.anchorClick !== "function") return false;
        relay.hidden = true;
        document.documentElement.appendChild(relay);
        NATIVE.reflectApply(NATIVE.anchorClick, relay, []);
        relay.remove();
        return true;
      } catch (_error) {
        return false;
      }
    }
    function captureDealNavigation(event) {
      const isKeyboardActivation = event.type === "keydown" && event.key === "Enter";
      const isPrimaryActivation = event.type === "click" && event.button === 0;
      const isMiddleActivation = event.type === "auxclick" && event.button === 1;
      if (
        event.isTrusted !== true ||
        event.defaultPrevented ||
        (!isKeyboardActivation && !isPrimaryActivation && !isMiddleActivation)
      ) {
        return;
      }
      const element = event.target && event.target.nodeType === 1
        ? event.target
        : event.target && event.target.parentElement;
      const anchor = element && element.closest("a[href]");
      if (!anchor) {
        return;
      }
      if (!isDealNavigation(anchor)) {
        return;
      }
      const seed = extractAlgumonSeed(anchor);
      const signedUrl = seed
        ? exactSignedAlgumonDealUrl(
            new URL(dealHref(anchor), anchor.ownerDocument.location.href).href,
            seed.dealId,
          )
        : null;
      if (!seed || !signedUrl) {
        event.preventDefault();
        event.stopImmediatePropagation();
        publishDiagnostics(browserRoot, {
          state: "blocked",
          targetReason: "algumon-unapproved-site-type",
        });
        return;
      }
      const navigationNonce = createRunNonce(browserRoot);
      if (!/^hdf-[0-9a-z]{28}$/.test(String(navigationNonce || ""))) {
        event.preventDefault();
        event.stopImmediatePropagation();
        publishDiagnostics(browserRoot, {
          state: "blocked",
          targetReason: "algumon-navigation-proof-unavailable",
        });
        return;
      }
      event.preventDefault();
      event.stopImmediatePropagation();
      const child = createSecureRelayPopup();
      if (!child) {
        publishDiagnostics(browserRoot, {
          state: "blocked",
          targetReason: "algumon-popup-blocked",
        });
        return;
      }
      resolveSignedAlgumonDestination(signedUrl, seed)
        .then(function navigateVerifiedDestination(destination) {
          const navigationSeed = validateSeed(
            { ...seed, navigationNonce, destinationUrl: destination.href },
            Date.now(),
            true
          );
          if (!navigationSeed || !navigateResolvedRelay(child, destination, navigationSeed)) {
            closeRelayPopup(child);
            throw new Error("signed relay navigation failed");
          }
        })
        .catch(function rejectRelay() {
          closeRelayPopup(child);
          publishDiagnostics(browserRoot, {
            state: "blocked",
            targetReason: "algumon-relay-rejected",
          });
        });
    }
    document.addEventListener("click", captureDealNavigation, true);
    document.addEventListener("auxclick", captureDealNavigation, true);
    document.addEventListener("keydown", captureDealNavigation, true);
    const observer = createNativeMutationObserver(browserRoot, scheduleDealLinkEnforcement);
    observer.observe(document, {
      subtree: true,
      childList: true,
      attributes: true,
      attributeFilter: ["href", "src", "data-site", "data-site-type"],
    });
    scheduleDealLinkEnforcement();
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
    if (!element || !element.isConnected || element.hidden || element.getAttribute("aria-hidden") === "true") {
      return false;
    }
    const view = element.ownerDocument.defaultView;
    const style = view ? nativeComputedStyle(view, element) : null;
    if (style && (style.display === "none" || Number(style.opacity || 1) === 0 || style.contentVisibility === "hidden")) {
      return false;
    }
    if (typeof element.getClientRects === "function" && element.getClientRects().length === 0) {
      return false;
    }
    return true;
  }

  function semanticTokenText(element) {
    return normalizeText(
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

  function titleEvidence(document, algumonTitle, visibleTitle, jsonLdValue) {
    const algumonCore = titleCoreEquivalence(algumonTitle, visibleTitle);
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
        score: coreOk || singleOk
          ? 1
          : Number(Math.min(visibleToMetadata.score, metadataToVisible.score).toFixed(3)),
        mode: singleOk
          ? "single-long-token-consensus"
          : `${visibleToMetadata.mode}/${metadataToVisible.mode}`,
      });
    });
    const authoritativeMatches = metadataComparisons.filter(
      function authoritativeComparison(comparison) {
        return (
          comparison.kind === "og" || comparison.kind === "schema-article"
        ) && comparison.ok;
      },
    );
    const metadataOk = metadata.ok &&
      authoritativeMatches.length > 0 &&
      !metadataComparisons.some(function conflictsWithArticle(comparison) {
        return comparison.conflictsWithVisibleArticle;
      });
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
              metadataComparisons.some(function hasArticleConflict(comparison) {
                return comparison.conflictsWithVisibleArticle;
              })
                ? "article-conflict"
                : metadata.reason
            }`,
      algumon,
      metadata: Object.freeze({
        ok: metadataOk,
        reason: metadataOk
          ? "authoritative-quorum"
          : metadataComparisons.some(function hasArticleConflict(comparison) {
              return comparison.conflictsWithVisibleArticle;
            })
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

  function evaluateTitleCandidate(
    element,
    sources,
    hintSelectors,
    document,
    seed,
    jsonLd,
  ) {
    const evaluation = { node: element, score: 0, signals: new Set(), disqualified: false };
    const visibleTitle = seed
      ? approvedVisibleTitle(document, seed.title, element, jsonLd)
      : null;
    const text = truncateText(
      visibleTitle?.ok ? visibleTitle.text : element.textContent,
      320,
    );
    if (!isRendered(element) || text.length < 4 || text.length > 300) {
      evaluation.disqualified = true;
      return evaluation;
    }
    evaluation.resolvedTitle = visibleTitle?.ok ? visibleTitle.text : element.textContent;
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
    if (COMMENT_TOKEN_PATTERN.test(semanticTokenText(element))) {
      evaluation.score -= 4;
    }
    return evaluation;
  }

  function selectTitle(document, layouts, seed, jsonLd) {
    const hints = roleHints(layouts, "title");
    const candidates = uniqueElements(
      Array.from(
        document.querySelectorAll(
          "h1, h2, h3, [role='heading'], [itemprop='headline'], [class*='title'], [class*='subject']"
        )
      ).slice(0, MAX_CANDIDATES).concat(queryAllSafe(document, hints))
    );
    const sources = collectTitleSources(document, seed, jsonLd);
    const evaluations = candidates.map(function scoreCandidate(candidate) {
      return evaluateTitleCandidate(candidate, sources, hints, document, seed, jsonLd);
    });
    if (seed) {
      const evidenceApproved = evaluations.filter(function hasExactTitleEvidence(evaluation) {
        return !evaluation.disqualified && evaluation.titleEvidence?.ok === true;
      });
      if (evidenceApproved.length !== 1) {
        return Object.freeze({
          ok: false,
          reason: evidenceApproved.length > 1
            ? "ambiguous-title-evidence"
            : "title-evidence",
          ranked: evidenceApproved,
        });
      }
      return decideCandidate(evidenceApproved, ROLE_POLICIES.title);
    }
    return decideCandidate(evaluations, ROLE_POLICIES.title);
  }

  function followsNode(element, earlierNode) {
    if (!element || !earlierNode || element === earlierNode || element.contains(earlierNode)) {
      return false;
    }
    return Boolean(earlierNode.compareDocumentPosition(element) & 4);
  }

  function outboundLinkCount(element) {
    const hostname = element.ownerDocument.location.hostname;
    return Array.from(element.querySelectorAll("a[href]")).filter(function externalAnchor(anchor) {
      try {
        const url = new URL(anchor.href, element.ownerDocument.location.href);
        return /^https?:$/.test(url.protocol) && url.hostname && url.hostname !== hostname;
      } catch (_error) {
        return false;
      }
    }).length;
  }

  function bodyFeatures(element, titleNode) {
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
    const afterTitle = followsNode(element, titleNode);
    const hasRichContent = paragraphCount >= 2 || mediaCount >= 1 || tableCount >= 1;
    const hasTextBlock = textLength >= MIN_BODY_TEXT_LENGTH;
    const externalDensity = anchorCount ? externalLinks / anchorCount : 0;
    const negativeContainers = element.querySelectorAll(
      "nav, aside, footer, header, [role='navigation'], [itemtype*='Comment']"
    ).length;
    return {
      textLength,
      paragraphCount,
      mediaCount,
      tableCount,
      externalLinks,
      externalDensity,
      semantic,
      afterTitle,
      hasRichContent,
      hasTextBlock,
      negativeContainers,
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
    return { score, signals };
  }

  function evaluateBodyCandidate(element, titleNode, hintSelectors) {
    const evaluation = { node: element, score: 0, signals: new Set(), disqualified: false };
    if (!isRendered(element) || element.contains(titleNode)) {
      evaluation.disqualified = true;
      return evaluation;
    }
    const features = bodyFeatures(element, titleNode);
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
    const semanticCandidates = Array.from(
      document.querySelectorAll(
        "article, main, [role='main'], [itemprop='articleBody'], [itemtype*='Article'], section, div"
      )
    ).filter(function plausibleBody(element) {
      if (element.matches("article, main, [role='main'], [itemprop='articleBody'], [itemtype*='Article']")) {
        return true;
      }
      return normalizeText(element.textContent).length >= MIN_BODY_TEXT_LENGTH;
    }).slice(0, MAX_CANDIDATES);
    const candidates = uniqueElements(semanticCandidates.concat(queryAllSafe(document, hints)));
    return decideCandidate(
      candidates.map(function scoreCandidate(candidate) {
        return evaluateBodyCandidate(candidate, titleNode, hints);
      }),
      ROLE_POLICIES.body
    );
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

  function repeatedSiblingCount(element) {
    const counts = new Map();
    Array.from(element.children).forEach(function countChild(child) {
      const fingerprint = childFingerprint(child);
      counts.set(fingerprint, (counts.get(fingerprint) || 0) + 1);
    });
    return Math.max(0, ...Array.from(counts.values()));
  }

  function commentFeatures(element, bodyNode, jsonLd, seed, itemHints) {
    const tokenText = semanticTokenText(element);
    const shortText = truncateText(element.textContent, 1000);
    const schemaCount = element.querySelectorAll(
      "[itemtype*='schema.org/Comment'], [itemprop='comment']"
    ).length;
    const role = element.getAttribute("role") || "";
    const listSemantic = /^(?:feed|list|tree)$/.test(role) || /^(?:ol|ul)$/.test(element.tagName.toLocaleLowerCase());
    const repeatedCount = repeatedSiblingCount(element);
    const hintedItems = queryAllSafe(element, itemHints).length;
    const apparentItemCount = Math.max(schemaCount, repeatedCount, hintedItems);
    const labelMatch = COMMENT_TOKEN_PATTERN.test(`${tokenText} ${shortText.slice(0, 200)}`);
    const semantic = schemaCount > 0 || /comment|reply/i.test(tokenText) || listSemantic;
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

  function evaluateCommentCandidate(element, bodyNode, jsonLd, seed, hints, itemHints) {
    const evaluation = { node: element, score: 0, signals: new Set(), disqualified: false };
    if (!element.isConnected || element === bodyNode || bodyNode.contains(element)) {
      evaluation.disqualified = true;
      return evaluation;
    }
    const features = commentFeatures(element, bodyNode, jsonLd, seed, itemHints);
    const scored = scoreCommentFeatures(features);
    evaluation.score = scored.score;
    scored.signals.forEach(function recordSignal(signal) { evaluation.signals.add(signal); });
    if (elementMatchesAny(element, hints)) {
      addSignal(evaluation, "selector-hint", 1.5);
    }
    return evaluation;
  }

  function selectComments(document, layouts, bodyNode, jsonLd, seed) {
    const hints = roleHints(layouts, "comments");
    const itemHints = roleHints(layouts, "commentItems");
    const broadCandidates = Array.from(
      document.querySelectorAll(
        "[itemtype*='schema.org/Comment'], [itemprop='comment'], [role='feed'], [role='list'], section, div, ol, ul"
      )
    ).filter(function plausibleComments(element) {
      const tokens = semanticTokenText(element);
      return COMMENT_TOKEN_PATTERN.test(`${tokens} ${truncateText(element.textContent, 180)}`) ||
        repeatedSiblingCount(element) >= 2 ||
        element.matches("[itemtype*='schema.org/Comment'], [itemprop='comment'], [role='feed']");
    }).slice(0, MAX_CANDIDATES);
    const candidates = uniqueElements(broadCandidates.concat(queryAllSafe(document, hints)));
    return decideCandidate(
      candidates.map(function scoreCandidate(candidate) {
        return evaluateCommentCandidate(candidate, bodyNode, jsonLd, seed, hints, itemHints);
      }),
      ROLE_POLICIES.comments
    );
  }

  function productFeatures(element, titleNode, bodyNode) {
    const text = truncateText(element.textContent, 1200);
    const semantic = element.matches(
      "[itemprop='offers'], [itemprop='price'], [itemtype*='Offer'], table, dl"
    );
    const outboundLinks = outboundLinkCount(element);
    const hasPrice = CURRENCY_PATTERN.test(text);
    const hasProductLabel = PRODUCT_TOKEN_PATTERN.test(`${semanticTokenText(element)} ${text}`);
    const afterTitle = followsNode(element, titleNode);
    const beforeOrSeparateFromBody = !bodyNode.contains(element) &&
      (followsNode(bodyNode, element) || !element.contains(bodyNode));
    return { semantic, outboundLinks, hasPrice, hasProductLabel, afterTitle, beforeOrSeparateFromBody };
  }

  function evaluateProductCandidate(element, titleNode, bodyNode, hints) {
    const evaluation = { node: element, score: 0, signals: new Set(), disqualified: false };
    if (!isRendered(element) || element.contains(titleNode) || element.contains(bodyNode)) {
      evaluation.disqualified = true;
      return evaluation;
    }
    const features = productFeatures(element, titleNode, bodyNode);
    if (features.semantic) addSignal(evaluation, "product-semantic", 2);
    if (features.outboundLinks > 0) addSignal(evaluation, "purchase-link", Math.min(2, 1 + features.outboundLinks * 0.25));
    if (features.hasPrice) addSignal(evaluation, "price-text", 1.75);
    if (features.hasProductLabel) addSignal(evaluation, "product-label", 1.25);
    if (features.afterTitle && features.beforeOrSeparateFromBody) addSignal(evaluation, "article-position", 1.25);
    if (elementMatchesAny(element, hints)) addSignal(evaluation, "selector-hint", 1.5);
    return evaluation;
  }

  function selectProduct(document, layouts, titleNode, bodyNode) {
    const hints = roleHints(layouts, "product");
    const broad = Array.from(
      document.querySelectorAll(
        "[itemprop='offers'], [itemprop='price'], [itemtype*='Offer'], table, dl, section, div"
      )
    ).filter(function plausibleProduct(element) {
      const text = truncateText(element.textContent, 500);
      return CURRENCY_PATTERN.test(text) || PRODUCT_TOKEN_PATTERN.test(`${semanticTokenText(element)} ${text}`);
    }).slice(0, MAX_CANDIDATES);
    const candidates = uniqueElements(broad.concat(queryAllSafe(document, hints)));
    return decideCandidate(
      candidates.map(function scoreCandidate(candidate) {
        return evaluateProductCandidate(candidate, titleNode, bodyNode, hints);
      }),
      ROLE_POLICIES.product
    );
  }

  function auditDecision(decision) {
    const runnerUp = decision.ranked && decision.ranked[1];
    return Object.freeze({
      node: decision.ok ? decision.winner.node : null,
      count: decision.ranked ? decision.ranked.length : 0,
      score: decision.ok ? Number(decision.winner.score.toFixed(3)) : 0,
      signalCount: decision.ok ? independentSignalCount(decision.winner.signals) : 0,
      margin: decision.ok
        ? Number((runnerUp ? decision.winner.score - runnerUp.score : 0).toFixed(3))
        : 0,
    });
  }

  function discoverSemanticContract(document, layouts, seed) {
    const jsonLd = collectJsonLd(document);
    const titleDecision = selectTitle(document, layouts, seed, jsonLd);
    const title = auditDecision(titleDecision);
    if (!title.node) {
      return Object.freeze({ ok: false, roles: Object.freeze({ title }), seedConsistency: null });
    }
    const bodyDecision = selectBody(document, layouts, title.node);
    const body = auditDecision(bodyDecision);
    if (!body.node) {
      return Object.freeze({ ok: false, roles: Object.freeze({ title, body }), seedConsistency: null });
    }
    const commentsDecision = selectComments(document, layouts, body.node, jsonLd, seed);
    const comments = auditDecision(commentsDecision);
    const roles = { title, body, comments };
    const productRequired = layouts.some(function needsProduct(layout) {
      return layout.roleProjection?.product?.cardinality === "required";
    });
    const productOptional = layouts.some(function allowsProduct(layout) {
      return layout.roleProjection?.product?.cardinality === "optional";
    });
    if (productRequired || productOptional) {
      const product = auditDecision(selectProduct(document, layouts, title.node, body.node));
      if (productRequired || product.node) {
        roles.product = product;
      }
    }
    const resolvedTitleEvidence = seed
      ? titleDecision.winner?.titleEvidence ||
        titleEvidence(document, seed.title, title.node.textContent, jsonLd)
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
    return Object.freeze({
      ok: Object.entries(roles).every(function roleResolved(entry) {
        return entry[0] === "product" && productOptional
          ? true
          : Boolean(entry[1].node);
      }),
      roles: Object.freeze(roles),
      seedConsistency,
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

  function validateRoleRelationship(document, roles, requiredRoles, approvedPageRoot) {
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

  function stripOwnedAttributes(element) {
    if (!element || element.nodeType !== 1) {
      return;
    }
    [ATTR.keep, ATTR.shell, ATTR.deep, ATTR.role].forEach(function removeAttribute(attribute) {
      element.removeAttribute(attribute);
    });
    element.querySelectorAll(`[${ATTR.keep}], [${ATTR.shell}], [${ATTR.deep}], [${ATTR.role}]`).forEach(
      function removeDescendantAttributes(descendant) {
        [ATTR.keep, ATTR.shell, ATTR.deep, ATTR.role].forEach(function removeAttribute(attribute) {
          descendant.removeAttribute(attribute);
        });
      }
    );
  }

  function markOwned(element, ownedElements, nonce) {
    element.setAttribute(ATTR.keep, nonce);
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
      if (element === rootNode) {
        element.setAttribute(ATTR.role, role);
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

  function markShallowTitle(titleNode, resolvedTitle, ownedElements, nonce, shellElements) {
    markAncestorChain(titleNode, ownedElements, nonce, shellElements);
    titleNode.setAttribute(ATTR.role, "title");
    const leafCandidates = Array.from(titleNode.querySelectorAll("span, strong, b, em, a, div"))
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
    leafCandidates.forEach(function markOriginalTitleLeaf(leaf) {
      markOwned(leaf, ownedElements, nonce);
      leaf.setAttribute(ATTR.role, "title-text");
      markAncestorChain(leaf, ownedElements, nonce, shellElements);
    });
    return hasDirectText(titleNode) || Array.from(titleNode.children).some(function ownedChild(child) {
      return ownedElements.has(child) && normalizeText(child.textContent);
    });
  }

  function clearProtocolState(document) {
    document.querySelectorAll(
      `[${ATTR.keep}], [${ATTR.shell}], [${ATTR.deep}], [${ATTR.role}]`
    ).forEach(function clearOneMarkedElement(element) {
      [ATTR.keep, ATTR.shell, ATTR.deep, ATTR.role].forEach(function removeMarker(attribute) {
        if (element.hasAttribute(attribute)) element.removeAttribute(attribute);
      });
    });
    const html = document.documentElement;
    if (html.hasAttribute(ATTR.ready)) html.removeAttribute(ATTR.ready);
    if (html.hasAttribute(ATTR.protocol)) html.removeAttribute(ATTR.protocol);
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
    roles.comments.setAttribute(ATTR.shell, nonce);
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
      commentIgnoredRoots: new Set(roles.commentIgnored),
      bodyIgnoredRoots: new Set(roles.bodyIgnored),
      productIgnoredRoots: new Set(roles.productIgnored),
      projectionPolicy,
      titleMarked,
    };
    state.ownedElementSet.forEach(function rememberExactMarkerShape(element) {
      state.expectedMarkerShapes.set(element, Object.freeze({
        keep: element.getAttribute(ATTR.keep),
        shell: element.getAttribute(ATTR.shell),
        deep: element.getAttribute(ATTR.deep),
        role: element.getAttribute(ATTR.role),
      }));
    });
    return state;
  }

  function markerShapeMatches(element, expected) {
    return Boolean(expected) &&
      element.getAttribute(ATTR.keep) === expected.keep &&
      element.getAttribute(ATTR.shell) === expected.shell &&
      element.getAttribute(ATTR.deep) === expected.deep &&
      element.getAttribute(ATTR.role) === expected.role;
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
        }));
      }
    );
  }

  function verifyOwnedState(document, state) {
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
    if (
      normalizeText(state.roles.body.textContent).length === 0 &&
      !state.roles.body.querySelector("img, picture, video, iframe, table, a[href]")
    ) {
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
        return !state.ownedElements.has(item) || item.getAttribute(ATTR.role) !== "comment-item";
      }) ||
      currentCommentControls.some(function unownedControl(control) {
        return !state.ownedElements.has(control) || control.getAttribute(ATTR.role) !== "comment-control";
      }) ||
      currentCommentIgnored.some(function visibleIgnored(ignored) {
        return state.ownedElements.has(ignored) || ignored.hasAttribute(ATTR.keep);
      })
    ) {
      return false;
    }
    const markedElements = document.querySelectorAll(
      `[${ATTR.keep}], [${ATTR.shell}], [${ATTR.deep}], [${ATTR.role}]`
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

  function paintLockSelectors(rootSelector) {
    return [
      rootSelector,
      `${rootSelector} dialog`,
      `${rootSelector} dialog::backdrop`,
      `${rootSelector} [popover]`,
      `${rootSelector} [popover]::backdrop`,
      `${rootSelector} :fullscreen`,
      `${rootSelector} :fullscreen::backdrop`,
    ].join(", ");
  }

  function gateStyleText(nonce) {
    const lockedRoot = `html[${ATTR.lock}="1"]`;
    const lockRule = `${paintLockSelectors(lockedRoot)} { ` +
      `transition: none !important; animation: none !important; ` +
      `content-visibility: hidden !important; ` +
      `visibility: hidden !important; opacity: 0 !important; ` +
      `pointer-events: none !important; clip-path: inset(50%) !important; }`;
    if (!nonce) {
      return lockRule;
    }
    const readyRoot = `html[${ATTR.ready}="1"][${ATTR.protocol}="${PROTOCOL_VERSION}"][${ATTR.state}="ready"]`;
    const owned = `[${ATTR.keep}="${nonce}"]`;
    const shell = `[${ATTR.shell}="${nonce}"]`;
    return [
      lockRule,
      `${readyRoot} { visibility: visible !important; }`,
      `${readyRoot}, ${readyRoot} body { background-image: none !important; box-shadow: none !important; }`,
      `${readyRoot}::before, ${readyRoot}::after,` +
        `${readyRoot} body::before, ${readyRoot} body::after { ` +
        `content: none !important; display: none !important; background: none !important; }`,
      `${readyRoot} body *:not(${owned}) { display: none !important; }`,
      `${readyRoot} ${owned}${shell} { visibility: hidden !important; }`,
      `${readyRoot} ${owned}[${ATTR.deep}],`,
      `${readyRoot} ${owned}[${ATTR.role}="title"],`,
      `${readyRoot} ${owned}[${ATTR.role}="title-text"],`,
      `${readyRoot} ${owned}[${ATTR.role}="body"],`,
      `${readyRoot} ${owned}[${ATTR.role}="product"],`,
      `${readyRoot} ${owned}[${ATTR.role}="comment-item"] { visibility: visible !important; }`,
      `${readyRoot} ${owned}${shell}::before,`,
      `${readyRoot} ${owned}${shell}::after { content: none !important; display: none !important; }`,
    ].join("\n");
  }

  function installRuntimeGateStyle(document) {
    const style = document.createElement("style");
    style.setAttribute("data-hotdeal-focus-runtime-style", PROTOCOL_VERSION);
    style.textContent = gateStyleText(null);
    (document.head || document.documentElement).appendChild(style);
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

  function runtimeGateStyleIntact(styleElement, runtime) {
    return styleElement.isConnected &&
      styleElement.getAttribute("data-hotdeal-focus-runtime-style") === PROTOCOL_VERSION &&
      styleElement.textContent === runtime.expectedStyleText &&
      runtime.expectedStyleRules !== null &&
      canonicalRuntimeCssRules(styleElement) === runtime.expectedStyleRules;
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
        if (
          !styleElement.isConnected ||
          styleElement.textContent !== expectedText ||
          canonicalRuntimeCssRules(styleElement) !== expectedRules
        ) {
          styleElement.textContent = expectedText;
          (document.head || document.documentElement).appendChild(styleElement);
          expectedRules = canonicalRuntimeCssRules(styleElement);
        }
        clearProtocolState(document);
        if (html.getAttribute(ATTR.lock) !== "1") html.setAttribute(ATTR.lock, "1");
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
          html.style.getPropertyValue("display") !== "none" ||
          html.style.getPropertyPriority("display") !== "important"
        ) {
          html.style.setProperty("display", "none", "important");
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

    const bodyCandidates = uniqueElements(queryAllSafe(pageRoot, layout.hints.body || []));
    if (bodyCandidates.length !== 1 || !isRendered(bodyCandidates[0]) || !hasApprovedContent(bodyCandidates[0])) {
      return { ok: false, role: "body", reason: "approved-structure" };
    }
    const bodyNode = bodyCandidates[0];
    const roleProjection = layout.roleProjection;
    if (
      roleProjection?.title?.mode !== "seeded-shallow" ||
      roleProjection?.body?.mode !== "atomic-boundary" ||
      roleProjection?.comments?.mode !== "classified-children" ||
      !["zero", "required", "optional"].includes(
        roleProjection?.product?.cardinality,
      )
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
    const productCardinality = roleProjection.product.cardinality;
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
    if (productNode && (
      !isRendered(productNode) ||
      !hasApprovedContent(productNode) ||
      productNode === bodyNode ||
      productNode.contains(bodyNode) ||
      bodyNode.contains(productNode)
    )) {
      return { ok: false, role: "product", reason: "approved-structure" };
    }
    if (productNode && (
      !(titleNode.contains(productNode) || followsNode(productNode, titleNode)) ||
      !followsNode(bodyNode, productNode)
    )) {
      return { ok: false, role: "product", reason: "approved-order" };
    }
    const productIgnored = productNode
      ? ignoredRootsWithin(productNode, roleProjection.product.ignored)
      : [];
    if (rootsOverlap(productIgnored)) {
      return { ok: false, role: "product", reason: "ignored-overlap" };
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
    if (!followsNode(commentMount, bodyNode)) {
      return { ok: false, role: "comments", reason: "mount-order" };
    }
    const commentItems = uniqueElements(queryAllSafe(commentMount, itemHints));
    const commentControls = uniqueElements(queryAllSafe(commentMount, controlHints));
    const commentIgnored = uniqueElements(queryAllSafe(commentMount, ignoredHints));
    const classificationOverlap = commentIgnored.some(function overlapsIgnored(ignored) {
      return commentItems.concat(commentControls).some(function overlapsVisible(visible) {
        return ignored === visible || ignored.contains(visible) || visible.contains(ignored);
      });
    });
    if (classificationOverlap) {
      return { ok: false, role: "comments", reason: "classification-overlap" };
    }
    const classifiedCommentRoots = commentItems.concat(commentControls, commentIgnored);
    if (commentItems.length === 0 && layout.allowEmptyComments !== true) {
      return { ok: false, role: "comments", reason: "empty-not-approved" };
    }
    if (hasUnclassifiedCommentContent(commentMount, classifiedCommentRoots)) {
      return { ok: false, role: "comments", reason: "unclassified-comment-content" };
    }
    if (seed && seed.commentCount > 0 && commentItems.length === 0) {
      return { ok: false, role: "comments", reason: "seed-item-mismatch" };
    }
    const requiredRoles = layout.requiredRoles.slice();
    const roles = {
      title: titleNode,
      body: bodyNode,
      comments: commentMount,
      commentItems,
      commentControls,
      commentIgnored,
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
    const commonRoot = validateRoleRelationship(document, roles, relationshipRoles, pageRoot);
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
        productCardinality,
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
        sameElementSet(left.roles.commentIgnored, right.roles.commentIgnored) &&
        left.commonRoot === right.commonRoot &&
        left.projectionPolicy.productCardinality ===
          right.projectionPolicy.productCardinality &&
        left.projectionPolicy.productFallback ===
          right.projectionPolicy.productFallback &&
        left.projectionPolicy.allowEmptyComments ===
          right.projectionPolicy.allowEmptyComments;
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
    [node].concat(Array.from(node.querySelectorAll(`[${ATTR.keep}]`))).forEach(
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
    function setAttributeOnce(name, value) {
      if (html.getAttribute(name) !== value) {
        html.setAttribute(name, value);
      }
    }
    function removeAttributeOnce(name) {
      if (html.hasAttribute(name)) {
        html.removeAttribute(name);
      }
    }
    const guard = createNativeMutationObserver(browserRoot, function enforceBootstrapLock() {
      if (terminallyBlocked) {
        return;
      }
      const styleIntact = runtimeGateStyleIntact(styleElement, runtime);
      const ready = html.getAttribute(ATTR.ready) === "1";
      const protocolMatches = html.getAttribute(ATTR.protocol) === PROTOCOL_VERSION;
      const stateMatches = html.getAttribute(ATTR.state) === "ready";
      const readyShape = ready && protocolMatches && stateMatches &&
        html.getAttribute(ATTR.status) === "ready" &&
        !html.hasAttribute(ATTR.lock);
      if (
        !styleIntact ||
        (ready && !runtime.authorizedReady) ||
        (runtime.authorizedReady && !readyShape)
      ) {
        terminallyBlocked = true;
        runtime.enterTerminal(styleIntact ? "protocol-tamper" : "runtime-style-tamper");
        return;
      }
      if (!runtime.authorizedReady && html.getAttribute(ATTR.lock) !== "1") {
        html.setAttribute(ATTR.lock, "1");
      }
    });
    guard.observe(document.documentElement, {
      subtree: true,
      childList: true,
      characterData: true,
      attributes: true,
      attributeFilter: [ATTR.lock, ATTR.ready, ATTR.protocol, ATTR.state, ATTR.status],
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

  function installCascadeGuard(browserRoot, runtime, styleElement) {
    const document = browserRoot.document;
    const pendingElements = new Set();
    let fullScanRequired = false;
    const MAX_PENDING_ROOTS = 256;
    const MAX_BOUNDED_ELEMENTS = 20_000;
    const visible = function visiblyRendered(element) {
      const style = nativeComputedStyle(browserRoot, element);
      return style.display !== "none" && style.visibility !== "hidden" &&
        Number(style.opacity) !== 0 && element.getClientRects().length > 0;
    };
    const queueElement = function queueCascadeElement(element) {
      if (!element || element.nodeType !== 1 || element === styleElement) return;
      pendingElements.add(element);
      if (pendingElements.size > MAX_PENDING_ROOTS) {
        runtime.enterTerminal("cascade-mutation-budget");
      }
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
    const verifyCascade = function verifyCascade() {
      if (runtime.terminallyBlocked) return false;
      if (!runtimeGateStyleIntact(styleElement, runtime)) {
        runtime.enterTerminal("runtime-style-tamper");
        return false;
      }
      if (!runtime.authorizedReady || !document.body) {
        pendingElements.clear();
        fullScanRequired = false;
        return true;
      }
      let candidates = [];
      if (fullScanRequired) {
        candidates = Array.from(document.body.querySelectorAll("*"));
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
      if (exposesRootPaint() || exposesUnowned(candidates)) {
        runtime.enterTerminal("cascade-visible-leak");
        return false;
      }
      return true;
    };
    const observer = createNativeMutationObserver(browserRoot, function keepGateStyleLast(mutations) {
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
        (document.head || document.documentElement).appendChild(styleElement);
      }
    });
    observer.observe(document.documentElement, {
      subtree: true,
      childList: true,
      characterData: true,
      attributes: true,
      attributeFilter: ["href", "rel", "media", "disabled", "style", "class", "hidden"],
    });
    runtime.cascadeGuard = observer;
    runtime.unsubscribeCssom = subscribeCssomMutations(
      browserRoot,
      function cssomMutationObserved() {
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
    const controlStateAttributes = new Set([
      "class",
      "hidden",
      "aria-expanded",
      "aria-pressed",
      "aria-selected",
      "aria-hidden",
    ]);
    const trackedRoots = function trackedRoots(rootSet) {
      return Array.from(rootSet);
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
      const itemRoot = node.nodeType === 1 && state.commentItemRoots.has(node);
      const controlRoot = node.nodeType === 1 && state.commentControlRoots.has(node);
      const ignoredRoot = node.nodeType === 1 && state.commentIgnoredRoots.has(node);
      if (!itemRoot && !controlRoot && !ignoredRoot) {
        return false;
      }
      [state.commentItemRoots, state.commentControlRoots, state.commentIgnoredRoots]
        .forEach(function removeContainedRoots(rootSet) {
          trackedRoots(rootSet).forEach(function removeContained(root) {
            if (root === node || node.contains(root)) {
              rootSet.delete(root);
            }
          });
        });
      forgetRemovedTree(node, state);
      return true;
    };
    const observer = createNativeMutationObserver(browserRoot, function sealProjection(mutations) {
      let failureReason = null;
      let projectionTouched = false;
      for (const mutation of mutations) {
        if (failureReason) break;
        if (mutation.type === "attributes") {
          const target = mutation.target;
          const name = mutation.attributeName;
          if (protocolAttributes.has(name)) {
            projectionTouched = true;
            if (!exactProtocolAttribute(target, name)) {
              failureReason = "marker-mutation";
            }
            continue;
          }
          const inBody = state.roles.body.contains(target);
          const inProduct = Boolean(state.roles.product?.contains(target));
          const inTitle = state.roles.title.contains(target);
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
            controlStateAttributes.has(name) &&
            elementMatchesAny(controlRoot, state.commentControlSelectors)
          ) {
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
        const inTitle = Boolean(mutationParent && state.roles.title.contains(mutationParent));
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
          } else if (inComments && !removeTrackedCommentTree(removed)) {
            failureReason = "unclassified-comment-removal";
          } else if (removed.nodeType === 1) {
            forgetRemovedTree(removed, state);
          } else if (inComments && normalizeText(removed.data)) {
            failureReason = "comment-text-removal";
          }
        }
        for (const added of mutation.addedNodes) {
          if (failureReason) break;
          if (inBody || inProduct || inTitle) {
            failureReason = "atomic-addition";
            break;
          }
          if (!inComments) {
            if (added.nodeType === 1) {
              if (added.matches(`[${ATTR.keep}], [${ATTR.deep}], [${ATTR.shell}], [${ATTR.role}]`) ||
                  added.querySelector(`[${ATTR.keep}], [${ATTR.deep}], [${ATTR.shell}], [${ATTR.role}]`)) {
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
            continue;
          }
          const role = classification === "item" ? "comment-item" : "comment-control";
          markDeepSubtree(added, role, state.ownedElements, state.nonce, []);
          markAncestorChain(added, state.ownedElements, state.nonce, state.shellElements);
          rememberAuthorizedMarkerTree(added, state);
          if (classification === "item") {
            state.commentItemRoots.add(added);
          } else {
            state.commentControlRoots.add(added);
          }
        }
      }
      if (!failureReason && projectionTouched) {
        if (!verifyOwnedState(document, state)) {
          failureReason = "projection-mismatch";
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
    runtime.integrityObserver = observer;
  }

  function createReaderRuntime(
    browserRoot,
    contract,
    layouts,
    seed,
    styleElement,
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
      terminalGuardian: null,
      activeNonce: null,
      authorizedReady: false,
      expectedStyleText: styleElement.textContent,
      expectedStyleRules: canonicalRuntimeCssRules(styleElement),
      terminallyBlocked: false,
      attemptScheduled: false,
      beginDiscovery: null,
      stop: null,
      enterTerminal: null,
    };

    runtime.enterTerminal = function enterTerminal(reason) {
      if (runtime.terminallyBlocked) return;
      const terminalStatus = `terminal-${reason || "blocked"}`.slice(0, 96);
      runtime.terminallyBlocked = true;
      runtime.authorizedReady = false;
      runtime.activeNonce = null;
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
      if (runtime.unsubscribeCssom) {
        runtime.unsubscribeCssom();
        runtime.unsubscribeCssom = null;
      }
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
      if (!document.body) {
        return false;
      }
      const resolution = resolveDocument(document, layouts, seed);
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
      writeRuntimeGateStyle(styleElement, nonce, runtime);
      if (!verifyOwnedState(document, state)) {
        runtime.activeNonce = null;
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
        document.documentElement.setAttribute(ATTR.status, "blocked-runtime-style");
        document.documentElement.setAttribute(ATTR.state, "blocked");
        return false;
      }
      if (runtime.discoveryObserver) {
        runtime.discoveryObserver.disconnect();
        runtime.discoveryObserver = null;
      }
      runtime.authorizedReady = true;
      document.documentElement.setAttribute(ATTR.protocol, PROTOCOL_VERSION);
      document.documentElement.setAttribute(ATTR.state, "ready");
      document.documentElement.setAttribute(ATTR.status, "ready");
      document.documentElement.removeAttribute(ATTR.lock);
      document.documentElement.setAttribute(ATTR.ready, "1");
      publishDiagnostics(browserRoot, {
        state: "ready",
        targetReason,
        roles: resolution.roleDiagnostics,
        layoutAliases: resolution.layoutAliases,
        semanticProjectionCount: resolution.semanticProjectionCount,
      });
      installIntegrityObserver(browserRoot, runtime, state, styleElement);
      if (typeof onReady === "function") {
        onReady(resolution);
      }
      return true;
    }

    function scheduleAttempt() {
      if (runtime.attemptScheduled) {
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
      runtime.discoveryObserver.observe(document, { subtree: true, childList: true });
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
      if (runtime.cascadeFrameId) {
        nativeCancelAnimationFrame(browserRoot, runtime.cascadeFrameId);
        runtime.cascadeFrameId = 0;
      }
      if (runtime.unsubscribeCssom) {
        runtime.unsubscribeCssom();
        runtime.unsubscribeCssom = null;
      }
    };
    installBootstrapGuard(browserRoot, runtime, styleElement);
    installCascadeGuard(browserRoot, runtime, styleElement);
    return runtime;
  }

  function lockWhenHtmlExists(document, callback) {
    if (document.documentElement) {
      document.documentElement.setAttribute(ATTR.lock, "1");
      document.documentElement.setAttribute(ATTR.state, "locked");
      callback(document.documentElement);
      return;
    }
    const observer = createNativeMutationObserver(document.defaultView, function waitForHtml() {
      if (!document.documentElement) {
        return;
      }
      observer.disconnect();
      document.documentElement.setAttribute(ATTR.lock, "1");
      callback(document.documentElement);
    });
    observer.observe(document, { childList: true, subtree: true });
  }

  function installNavigationRevalidation(browserRoot, revalidate) {
    const history = browserRoot.history;
    let installed = true;
    ["pushState", "replaceState"].forEach(function wrapHistoryMethod(methodName) {
      const original = browserRoot === RUNTIME_GLOBAL
        ? methodName === "pushState"
          ? NATIVE.historyPushState
          : NATIVE.historyReplaceState
        : history[methodName];
      if (typeof original !== "function") {
        installed = false;
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
        installed = false;
      }
    });
    const addEventListener = browserRoot === RUNTIME_GLOBAL
      ? NATIVE.addEventListener
      : browserRoot.EventTarget?.prototype?.addEventListener;
    if (typeof addEventListener !== "function") return false;
    NATIVE.reflectApply(addEventListener, browserRoot, ["popstate", revalidate, true]);
    NATIVE.reflectApply(addEventListener, browserRoot, ["pageshow", function revalidateRestoredPage(event) {
      if (event.persisted === true) {
        revalidate();
      }
    }, true]);
    return installed;
  }

  function start(browserRoot) {
    if (!browserRoot || !browserRoot.document || !browserRoot.location) {
      return { mode: "library" };
    }
    if (isAlgumonHostname(browserRoot.location.hostname)) {
      installAlgumonSeedCapture(browserRoot);
      return { mode: "algumon-seed-capture" };
    }
    const contract = findSiteContract(browserRoot.location.hostname);
    if (!contract) {
      return { mode: "out-of-scope" };
    }
    const document = browserRoot.document;
    lockWhenHtmlExists(document, function configureTarget(html) {
      const initialSeed = readAndClearSeed(browserRoot);
      let authorizedSeed = initialSeed;
      let authorizedArticleIdentity = null;
      let pendingArticleIdentity =
        initialSeed && initialSeed.siteType === contract.id
          ? articleIdentity(browserRoot.location, contract.id)
          : null;
      let activeRuntime = null;
      let activeStyle = null;
      let navigationTerminalGuardian = null;
      let initialActivation = true;
      let navigationTerminallyBlocked = false;

      function terminalNavigationBlock(reason) {
        navigationTerminallyBlocked = true;
        authorizedSeed = null;
        authorizedArticleIdentity = null;
        pendingArticleIdentity = null;
        if (activeRuntime) {
          activeRuntime.enterTerminal(reason);
          return;
        }
        if (!activeStyle || !activeStyle.isConnected) {
          activeStyle = installRuntimeGateStyle(document);
        }
        activeStyle.textContent = gateStyleText(null);
        clearProtocolState(document);
        html.setAttribute(ATTR.lock, "1");
        html.removeAttribute(ATTR.ready);
        html.removeAttribute(ATTR.protocol);
        html.setAttribute(ATTR.state, "blocked");
        html.setAttribute(ATTR.status, `terminal-${reason}`.slice(0, 96));
        if (navigationTerminalGuardian) {
          navigationTerminalGuardian.update(`terminal-${reason}`.slice(0, 96));
        } else {
          navigationTerminalGuardian = installPersistentTerminalGuardian(
            browserRoot,
            activeStyle,
            `terminal-${reason}`.slice(0, 96),
          );
        }
        publishDiagnostics(browserRoot, {
          state: "blocked",
          targetReason: reason,
        });
      }

      function activateCurrentLocation() {
        if (navigationTerminallyBlocked) {
          terminalNavigationBlock("navigation-identity");
          return;
        }
        if (activeRuntime && activeRuntime.terminallyBlocked) {
          html.setAttribute(ATTR.lock, "1");
          html.removeAttribute(ATTR.ready);
          html.removeAttribute(ATTR.protocol);
          html.setAttribute(ATTR.state, "blocked");
          html.setAttribute(ATTR.status, "terminal-tamper");
          return;
        }
        html.setAttribute(ATTR.lock, "1");
        html.removeAttribute(ATTR.ready);
        html.removeAttribute(ATTR.protocol);
        html.setAttribute(ATTR.state, "locked");
        if (activeRuntime) {
          activeRuntime.stop();
          activeRuntime = null;
        }
        if (activeStyle) {
          activeStyle.remove();
          activeStyle = null;
        }
        clearProtocolState(document);

        const pathAndQuery = `${browserRoot.location.pathname}${browserRoot.location.search}`;
        const layouts = matchingLayouts(contract, pathAndQuery);
        const isInitialActivation = initialActivation;
        const currentArticleIdentity = articleIdentity(
          browserRoot.location,
          contract.id,
        );
        const expectedArticleIdentity =
          authorizedArticleIdentity || pendingArticleIdentity;
        if (!isInitialActivation && (
          !expectedArticleIdentity ||
          currentArticleIdentity !== expectedArticleIdentity
        )) {
          terminalNavigationBlock("navigation-identity");
          return;
        }
        const seed = isInitialActivation
          ? initialSeed
          : authorizedArticleIdentity &&
              currentArticleIdentity === authorizedArticleIdentity
            ? authorizedSeed
            : pendingArticleIdentity &&
                currentArticleIdentity === pendingArticleIdentity
              ? authorizedSeed
              : null;
        const seedMatchesSite = Boolean(seed) && seed.siteType === contract.id;
        if (!seedMatchesSite || !currentArticleIdentity) {
          initialActivation = false;
          terminalNavigationBlock(
            seed && seed.siteType !== contract.id
              ? "algumon-site-mismatch"
              : !seed
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
        const targetReason = "algumon-seed-known-route";
        initialActivation = false;
        activeStyle = installRuntimeGateStyle(document);
        html.setAttribute(ATTR.status, `locked-${targetReason}`);
        publishDiagnostics(browserRoot, {
          state: "locked",
          targetReason,
        });
        activeRuntime = createReaderRuntime(
          browserRoot,
          contract,
          evaluationLayouts,
          seed,
          activeStyle,
          targetReason,
          function authorizeResolvedArticle() {
            authorizedSeed = seed;
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
    validateSeed,
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
