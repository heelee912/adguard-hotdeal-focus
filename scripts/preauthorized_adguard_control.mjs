/**
 * Test/audit-only control for the userscript-manager style API contract.
 *
 * Browser fixtures use this source only to provide the GM_addElement API that
 * an installed userscript receives. It does not inject filter CSS, mutate the
 * release probe, or participate in the reader-gate release decision.
 */
export const PREAUTHORIZED_ADGUARD_CONTROL_SOURCE = String.raw`
(() => {
  "use strict";
  const CONTROL_KIND = "preauthorized-userscript-style-control";
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
