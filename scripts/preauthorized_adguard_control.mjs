/**
 * Test/audit-only control for the AdGuard userscript contract.
 *
 * This is deliberately named a preauthorized control: it is not evidence that
 * AdGuard injected the style. The release CSP probe supplies that independent
 * product evidence. Browser fixtures use this source only to exercise the
 * userscript state machine without adding a production fallback.
 */
export const PREAUTHORIZED_ADGUARD_CONTROL_SOURCE = String.raw`
(() => {
  "use strict";
  const CONTROL_KIND = "preauthorized-nonce-control";
  const existing = globalThis.__HOTDEAL_FOCUS_PREAUTHORIZED_CONTROL__;
  if (existing?.kind === CONTROL_KIND &&
      globalThis.GM_addElement === existing.gmAddElement) return;
  if (typeof globalThis.GM_addElement !== "undefined") {
    throw new Error("preauthorized control refuses an existing GM_addElement");
  }
  const control = {
    schemaVersion: 2,
    kind: CONTROL_KIND,
    gmAddElementCalls: 0,
    extendedCssCallbacks: 0,
    gmAddElement: null,
  };
  const gmAddElement = (parent, tagName, attributes) => {
    const exactKeys = Object.keys(attributes ?? {}).sort();
    if (
      tagName !== "style" ||
      !parent?.appendChild ||
      exactKeys.length !== 2 ||
      exactKeys[0] !== "data-hotdeal-focus-runtime-style" ||
      exactKeys[1] !== "textContent" ||
      attributes["data-hotdeal-focus-runtime-style"] !== "2" ||
      typeof attributes.textContent !== "string"
    ) {
      throw new Error("unexpected GM_addElement contract");
    }
    const style = document.createElement("style");
    style.textContent = attributes.textContent;
    style.setAttribute(
      "data-hotdeal-focus-runtime-style",
      attributes["data-hotdeal-focus-runtime-style"],
    );
    style.setAttribute("nonce", CONTROL_KIND);
    style.setAttribute("data-source", CONTROL_KIND);
    parent.appendChild(style);
    control.gmAddElementCalls += 1;
    return style;
  };
  control.gmAddElement = gmAddElement;
  Object.defineProperty(globalThis, "GM_addElement", {
    configurable: false,
    enumerable: false,
    writable: false,
    value: gmAddElement,
  });
  Object.defineProperty(globalThis, "__HOTDEAL_FOCUS_PREAUTHORIZED_CONTROL__", {
    configurable: false,
    enumerable: false,
    writable: false,
    value: control,
  });

  const applyBoundedExtendedCssCallback = () => {
    const root = document.documentElement;
    if (
      !root?.classList.contains("hdf-v2-ready") ||
      root.getAttribute("data-hotdeal-focus-ready") !== "1" ||
      root.getAttribute("data-hotdeal-focus-protocol") !== "2" ||
      root.getAttribute("data-hotdeal-focus-state") !== "ready" ||
      root.getAttribute("data-hotdeal-focus-status") !== "ready"
    ) return;
    const probes = document.querySelectorAll(
      '[data-hdf-v2-release-probe="unowned-inline-important"]',
    );
    if (probes.length !== 1) return;
    const probe = probes[0];
    if (
      probe.style.getPropertyValue("display") !== "none" ||
      probe.style.getPropertyPriority("display") !== "important"
    ) {
      probe.style.setProperty("display", "none", "important");
      control.extendedCssCallbacks += 1;
    }
  };
  const observer = new MutationObserver(applyBoundedExtendedCssCallback);
  observer.observe(document, {
    subtree: true,
    childList: true,
    attributes: true,
    attributeFilter: ["class", "data-hotdeal-focus-ready", "style"],
  });
})();
`;

export async function installPreauthorizedAdguardControl(target) {
  await target.addInitScript({ content: PREAUTHORIZED_ADGUARD_CONTROL_SOURCE });
  if (typeof target.evaluate === "function") {
    await target.evaluate(
      (source) => (0, eval)(source),
      PREAUTHORIZED_ADGUARD_CONTROL_SOURCE,
    );
  }
}
