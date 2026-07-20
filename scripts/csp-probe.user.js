// ==UserScript==
// @name         AdGuard Hotdeal Focus CSP Probe
// @namespace    https://github.com/heelee912/adguard-hotdeal-focus/csp-probe
// @version      1.2.0
// @description  Fixed diagnostic for AdGuard GM_addElement on its official strict-CSP testcase.
// @match        https://testcases.agrd.dev/userscripts-csp/header-csp-default-src-none
// @run-at       document-start
// @grant        GM_addElement
// @noframes
// ==/UserScript==

(() => {
  "use strict";

  const EXPECTED_URL = "https://testcases.agrd.dev/userscripts-csp/header-csp-default-src-none";
  if (location.href !== EXPECTED_URL) {
    return;
  }

  const setBoolean = (root, name, value) => {
    root.setAttribute(name, value ? "1" : "0");
  };
  const fail = (root) => {
    setBoolean(root, "data-hdf-csp-probe-raw-applied", false);
    setBoolean(root, "data-hdf-csp-probe-raw-engine-attributes-absent", false);
    setBoolean(root, "data-hdf-csp-probe-gm-applied", false);
    setBoolean(root, "data-hdf-csp-probe-engine-nonce-present", false);
    setBoolean(root, "data-hdf-csp-probe-engine-source-present", false);
    root.setAttribute("data-hdf-csp-probe-computed", "");
    root.setAttribute("data-hdf-csp-probe-state", "failed");
  };
  const run = () => {
    const parent = document.documentElement;
    if (!parent) {
      return false;
    }
    try {
      const rawStyle = document.createElement("style");
      rawStyle.setAttribute("data-hdf-csp-raw-control", "1");
      rawStyle.textContent = "html{--hdf-csp-raw-control:hdf-raw-style-pass!important}";
      parent.appendChild(rawStyle);

      const textContent = "html{--hdf-csp-gm-control:hdf-gm-style-pass!important}";
      const gmStyle = GM_addElement(parent, "style", {
        textContent,
        "data-hdf-csp-probe-style": "1",
      });
      if (!gmStyle || gmStyle.nodeType !== 1 || gmStyle.localName !== "style") {
        throw new Error("gm-style-contract");
      }
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          try {
            const computed = getComputedStyle(parent);
            const rawValue = computed.getPropertyValue("--hdf-csp-raw-control").trim();
            const gmValue = computed.getPropertyValue("--hdf-csp-gm-control").trim();
            setBoolean(parent, "data-hdf-csp-probe-raw-applied", rawValue === "hdf-raw-style-pass");
            setBoolean(parent, "data-hdf-csp-probe-raw-engine-attributes-absent",
              !rawStyle.hasAttribute("nonce") && !rawStyle.hasAttribute("data-source"));
            setBoolean(parent, "data-hdf-csp-probe-gm-applied", gmValue === "hdf-gm-style-pass");
            setBoolean(parent, "data-hdf-csp-probe-engine-nonce-present", gmStyle.hasAttribute("nonce"));
            setBoolean(parent, "data-hdf-csp-probe-engine-source-present", gmStyle.hasAttribute("data-source"));
            parent.setAttribute("data-hdf-csp-probe-computed", gmValue);
            parent.setAttribute("data-hdf-csp-probe-state", "complete");
          } catch {
            fail(parent);
          }
        });
      });
    } catch {
      fail(parent);
    }
    return true;
  };

  if (!run()) {
    const observer = new MutationObserver(() => {
      if (run()) {
        observer.disconnect();
      }
    });
    observer.observe(document, { childList: true });
  }
})();
