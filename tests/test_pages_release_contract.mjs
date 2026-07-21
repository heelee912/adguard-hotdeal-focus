import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  canonicalJsonBytes,
  compareVersions,
  fetchBytes,
  highWaterDocument,
  LEGACY_V1_MIGRATION,
  preflight,
  readBundle,
  releaseHighWaterRecord,
  verifyHighWaterSource,
  verifyV2Bundle,
} from "../scripts/pages_release_contract.mjs";
import {
  compareSemanticVersions,
  incrementStablePatchVersion,
} from "../scripts/audit_pages.mjs";

const installUrl =
  "https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js";
const digest = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const encode = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
const emptyPrefixBytes = canonicalJsonBytes(highWaterDocument([]));

function userscript(version = "1.2.3") {
  return Buffer.from(`// ==UserScript==
// @name         AdGuard Hotdeal Focus Reader Gate
// @namespace    https://github.com/heelee912/adguard-hotdeal-focus
// @version      ${version}
// @downloadURL  ${installUrl}
// @updateURL    ${installUrl}
// @run-at       document-start
// @grant        GM_addElement
// @grant        window.onurlchange
// ==/UserScript==
(() => {})();
`, "utf8");
}

function manifestFor(source, version = "1.2.3") {
  const sourceEntry = { bytes: 1, sha256: "1".repeat(64) };
  return {
    artifacts: {
      "hotdeal-focus.user.js": {
        bytes: source.length,
        canonicalTextSha256: digest(Buffer.from(source.toString("utf8").trimEnd(), "utf8")),
        sha256: digest(source),
        version,
      },
    },
    configSha256: "1".repeat(64),
    coverage: {
      approvedVariantCount: 0,
      contractCount: 1,
      layoutCount: 1,
      layoutFamilyCount: 1,
      routeCount: 1,
      siteCount: 1,
      sites: [{
        id: "example",
        layouts: [{
          applicableProfiles: ["desktop", "mobile"],
          domain: "example.com",
          id: "article",
          paths: ["|/article/"],
          requiredRoles: ["body", "comments", "title"],
          variants: [],
        }],
      }],
    },
    generatorVersion: version,
    installUrl,
    promotion: null,
    protocolVersion: 2,
    releaseVersion: version,
    rollback_of: null,
    schemaVersion: 2,
    sourceIntegrity: {
      "config/sites.json": sourceEntry,
      "filter-static.txt": sourceEntry,
      "package-lock.json": sourceEntry,
      "package.json": sourceEntry,
      "state/release-high-water.json": {
        bytes: emptyPrefixBytes.length,
        mode: "append-only-prefix-v1",
        recordCount: 0,
        sha256: digest(emptyPrefixBytes),
      },
      "tests/fixtures/behavior-baseline.json": sourceEntry,
      "tests/fixtures/dom-regressions.json": sourceEntry,
    },
    status: "release-ready",
  };
}

function fixture() {
  const source = userscript();
  const manifest = manifestFor(source);
  const manifestBytes = encode(manifest);
  const proof = verifyV2Bundle(manifestBytes, source);
  const highWater = highWaterDocument([releaseHighWaterRecord(proof)]);
  return { source, manifest, manifestBytes, proof, highWater, highWaterBytes: encode(highWater) };
}

function writeBundle(root, manifestBytes, source) {
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, "release-manifest.json"), manifestBytes);
  fs.writeFileSync(path.join(root, "hotdeal-focus.user.js"), source);
}

const base = fixture();
assert.deepEqual(LEGACY_V1_MIGRATION, {
  releaseVersion: "0.5.5",
  bytes: 313912,
  sha256: "87ab45918f70ce536a6c23f0afa2290ce54e19e5ad8f4ef409f59c837338578c",
  canonicalTextSha256:
    "933e3ae50531bdcf2b5db52749ebfb633f5e4a196a1c62cdc4ba1d222dd0eb14",
});
assert.equal(base.proof.sha256, digest(base.source));
assert.equal(
  verifyHighWaterSource(base.highWaterBytes, base.proof).currentRecord.bundleSha256,
  base.proof.bundleSha256,
);
assert.equal(compareVersions("1.2.3", "1.2.3"), 0);
assert.equal(compareVersions("1.2.4", "1.2.3"), 1);
assert.equal(compareVersions("1.1.9", "1.2.0"), -1);
assert.equal(compareVersions("9007199254740993.0.0", "9007199254740992.0.0"), 1);
assert.equal(
  compareSemanticVersions("9007199254740993.0.0", "9007199254740992.0.0"),
  1,
);
assert.equal(
  incrementStablePatchVersion("1.2.9007199254740993"),
  "1.2.9007199254740994",
);

const extraRoot = structuredClone(base.manifest);
extraRoot.untrusted = true;
assert.throws(
  () => verifyV2Bundle(encode(extraRoot), base.source),
  /release manifest fields are not exact/,
);

const extraArtifact = structuredClone(base.manifest);
extraArtifact.artifacts["filter.txt"] = {
  bytes: 1,
  sha256: "0".repeat(64),
  canonicalTextSha256: "0".repeat(64),
  version: "1.2.3",
};
assert.throws(
  () => verifyV2Bundle(encode(extraArtifact), base.source),
  /public artifacts fields are not exact/,
);

const wrongName = Buffer.from(
  base.source.toString("utf8").replace(
    "AdGuard Hotdeal Focus Reader Gate",
    "Forged Reader Gate",
  ),
  "utf8",
);
assert.throws(
  () => verifyV2Bundle(encode(manifestFor(wrongName)), wrongName),
  /@name is not exactly/,
);

const forbiddenRequire = Buffer.from(
  base.source.toString("utf8").replace(
    "// @run-at       document-start\n",
    "// @run-at       document-start\n// @require      https://example.com/code.js\n",
  ),
  "utf8",
);
assert.throws(
  () => verifyV2Bundle(encode(manifestFor(forbiddenRequire)), forbiddenRequire),
  /@require is forbidden/,
);

const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hdf-pages-contract-"));
try {
  const publicRoot = path.join(temporaryRoot, "public");
  const highWaterPath = path.join(temporaryRoot, "release-high-water.json");
  const previousEmptyPath = path.join(temporaryRoot, "previous-high-water.json");
  writeBundle(publicRoot, base.manifestBytes, base.source);
  fs.writeFileSync(highWaterPath, base.highWaterBytes);
  fs.writeFileSync(previousEmptyPath, encode(highWaterDocument([])));

  assert.equal(
    verifyHighWaterSource(base.highWaterBytes, base.proof, encode(highWaterDocument([])))
      .currentRecord.bundleSha256,
    base.proof.bundleSha256,
  );

  const nestedRoot = path.join(temporaryRoot, "nested-public");
  writeBundle(nestedRoot, base.manifestBytes, base.source);
  fs.mkdirSync(path.join(nestedRoot, "nested"));
  fs.writeFileSync(path.join(nestedRoot, "nested", "extra.txt"), "forbidden");
  assert.throws(() => readBundle(nestedRoot), /public bundle file set is not exact/);

  const linkedEntryRoot = path.join(temporaryRoot, "linked-entry-public");
  writeBundle(linkedEntryRoot, base.manifestBytes, base.source);
  const linkedEntry = path.join(linkedEntryRoot, "hotdeal-focus.user.js");
  fs.rmSync(linkedEntry);
  try {
    fs.symlinkSync(path.join(publicRoot, "hotdeal-focus.user.js"), linkedEntry, "file");
    assert.throws(() => readBundle(linkedEntryRoot), /not a regular file/);
  } catch (error) {
    if (error?.code !== "EPERM") throw error;
  }

  const linkedRoot = path.join(temporaryRoot, "linked-public");
  try {
    fs.symlinkSync(publicRoot, linkedRoot, "dir");
    assert.throws(() => readBundle(linkedRoot), /one real directory/);
  } catch (error) {
    if (error?.code !== "EPERM") throw error;
  }

  const rewrittenPrevious = structuredClone(base.highWater);
  rewrittenPrevious.records[0].bundleSha256 = "f".repeat(64);
  assert.throws(
    () => verifyHighWaterSource(base.highWaterBytes, base.proof, encode(rewrittenPrevious)),
    /history was truncated or rewritten/,
  );

  const futureRecord = structuredClone(base.highWater.records[0]);
  futureRecord.releaseVersion = "1.2.4";
  const longerPrevious = highWaterDocument([base.highWater.records[0], futureRecord]);
  assert.throws(
    () => verifyHighWaterSource(base.highWaterBytes, base.proof, encode(longerPrevious)),
    /retain its prefix/,
  );

  const originalFetch = globalThis.fetch;
  try {
    await assert.rejects(
      preflight(publicRoot, installUrl.replace("hotdeal-focus.user.js", ""), highWaterPath),
      /previous high-water source is required/,
    );

    globalThis.fetch = async () => new Response(
      new ReadableStream({
        start(controller) {
          controller.enqueue(new Uint8Array(6));
          controller.close();
        },
      }),
      { status: 200 },
    );
    await assert.rejects(
      fetchBytes("https://heelee912.github.io/adguard-hotdeal-focus/test", {
        maxBytes: 5,
        timeoutMs: 100,
      }),
      /exceeds the byte limit/,
    );

    globalThis.fetch = async () => new Response(
      new ReadableStream({
        pull() {
          return new Promise(() => {});
        },
      }),
      { status: 200 },
    );
    await assert.rejects(
      fetchBytes("https://heelee912.github.io/adguard-hotdeal-focus/test", {
        timeoutMs: 10,
      }),
      /exceeded the 10ms deadline/,
    );

    globalThis.fetch = async () => new Response(null, { status: 404 });
    const missingResult = await preflight(publicRoot, installUrl.replace(
      "hotdeal-focus.user.js",
      "",
    ), highWaterPath, previousEmptyPath);
    assert.equal(missingResult.status, "durable-recovery");

    const staleHighWater = structuredClone(base.highWater);
    staleHighWater.records[0].bundleSha256 = "e".repeat(64);
    fs.writeFileSync(highWaterPath, encode(staleHighWater));
    await assert.rejects(
      preflight(
        publicRoot,
        installUrl.replace("hotdeal-focus.user.js", ""),
        highWaterPath,
        previousEmptyPath,
      ),
      /differs from the durable high-water current record/,
    );
    fs.writeFileSync(highWaterPath, base.highWaterBytes);

    const rewrittenPreviousPath = path.join(temporaryRoot, "rewritten-previous.json");
    fs.writeFileSync(rewrittenPreviousPath, encode(rewrittenPrevious));
    await assert.rejects(
      preflight(
        publicRoot,
        installUrl.replace("hotdeal-focus.user.js", ""),
        highWaterPath,
        rewrittenPreviousPath,
      ),
      /history was truncated or rewritten/,
    );

    const changedManifest = structuredClone(base.manifest);
    changedManifest.rollback_of = "1.2.2";
    const changedManifestBytes = encode(changedManifest);
    globalThis.fetch = async (url) => new Response(
      String(url).includes("release-manifest.json") ? changedManifestBytes : base.source,
      { status: 200 },
    );
    await assert.rejects(
      preflight(
        publicRoot,
        installUrl.replace("hotdeal-focus.user.js", ""),
        highWaterPath,
        previousEmptyPath,
      ),
      /violates durable monotonic versioning/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
} finally {
  fs.rmSync(temporaryRoot, { recursive: true, force: true });
}

process.stdout.write("pages release contract tests passed\n");
