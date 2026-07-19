// ==UserScript==
// @name         AdGuard Hotdeal Focus Reader Gate
// @namespace    https://example.com/adguard-hotdeal-focus-smoke
// @version      99.0.0
// @description  Non-installing fixture for the Windows CLI WhatIf smoke test.
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
// @downloadURL  https://example.com/adguard-hotdeal-focus-smoke.user.js
// @updateURL    https://example.com/adguard-hotdeal-focus-smoke.meta.js
// ==/UserScript==

(function smokeFixture() {
  "use strict";
  const protocolMarkers = [
    "data-hotdeal-focus-ready",
    "data-hotdeal-focus-keep",
    "data-hotdeal-focus-protocol",
  ];
  void protocolMarkers;
})();
