#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const INSTALL_URL =
  "https://heelee912.github.io/adguard-hotdeal-focus/hotdeal-focus.user.js";
const USERSCRIPT_NAME_VALUE = "AdGuard Hotdeal Focus Reader Gate";
const USERSCRIPT_NAMESPACE = "https://github.com/heelee912/adguard-hotdeal-focus";
const MANIFEST_NAME = "release-manifest.json";
const USERSCRIPT_NAME = "hotdeal-focus.user.js";
const HIGH_WATER_NAME = "state/release-high-water.json";
const HIGH_WATER_SCHEMA_VERSION = 1;
const PUBLIC_BUNDLE_FORMAT = "hdf-public-bundle-v1";
const HIGH_WATER_PREFIX_MODE = "append-only-prefix-v1";
const MAX_REMOTE_BYTES = 8 * 1024 * 1024;
const REMOTE_TIMEOUT_MS = 20_000;
const STABLE_VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const SHA256 = /^[0-9a-f]{64}$/;
const REQUIRED_SOURCE_PATHS = Object.freeze([
  "config/sites.json",
  "filter-static.txt",
  "package-lock.json",
  "package.json",
  HIGH_WATER_NAME,
  "tests/fixtures/behavior-baseline.json",
  "tests/fixtures/dom-regressions.json",
]);
const OPTIONAL_APPROVED_STATE = "state/approved-variants.json";
const MANIFEST_KEYS = Object.freeze([
  "artifacts",
  "configSha256",
  "coverage",
  "generatorVersion",
  "installUrl",
  "promotion",
  "protocolVersion",
  "releaseVersion",
  "rollback_of",
  "schemaVersion",
  "sourceIntegrity",
  "status",
]);
const LEGACY_V1_MIGRATION_PREDECESSORS = Object.freeze([
  Object.freeze({
    // The exact manifest and script bytes currently served by Pages before v2.
    manifest: Object.freeze({
      bytes: 6138,
      sha256: "e18a342f6e3f79980129ca34510e423a2a87d99fe061a89f03c881af4b43a6c3",
    }),
    releaseVersion: "0.3.6",
    userscript: Object.freeze({
      bytes: 161161,
      sha256: "760c223c16108c421476d2832ab17060c81ca3dc034236986622d07c1532df5a",
      canonicalTextSha256:
        "991c1553ba27f7c8a0052f7af146443fd7fef20a983ca268bc756712d558af49",
    }),
  }),
  Object.freeze({
    // The exact manifest and script source predecessor recorded on the default branch.
    manifest: Object.freeze({
      bytes: 6529,
      sha256: "ca6d4d808e065febec81b48a3bfcc83c03c05187e82cf64b58bca638b95a160d",
    }),
    releaseVersion: "0.5.5",
    userscript: Object.freeze({
      bytes: 313912,
      sha256: "87ab45918f70ce536a6c23f0afa2290ce54e19e5ad8f4ef409f59c837338578c",
      canonicalTextSha256:
        "933e3ae50531bdcf2b5db52749ebfb633f5e4a196a1c62cdc4ba1d222dd0eb14",
    }),
  }),
]);

function fail(message) {
  throw new Error(message);
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function exactlyEqualBytes(left, right) {
  return Buffer.isBuffer(left) && Buffer.isBuffer(right) && left.equals(right);
}

function canonicalText(bytes) {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  return Buffer.from(
    text.replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n").replace(/\n+$/g, ""),
    "utf8",
  );
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map((item) => canonicalValue(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]),
    );
  }
  return value;
}

function canonicalJsonBytes(value) {
  return Buffer.from(JSON.stringify(canonicalValue(value)), "utf8");
}

function highWaterDocument(records) {
  return {
    bundleFormat: PUBLIC_BUNDLE_FORMAT,
    records,
    schemaVersion: HIGH_WATER_SCHEMA_VERSION,
  };
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    fail(`${label} fields are not exact: ${actual.join(",")}`);
  }
}

function exactJson(left, right) {
  return canonicalJsonBytes(left).equals(canonicalJsonBytes(right));
}

function safeInteger(value, label, { minimum = 0 } = {}) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    fail(`${label} must be a safe integer >= ${minimum}`);
  }
  return value;
}

function exactStringArray(value, label, { allowed = null, nonEmpty = false } = {}) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !item)) {
    fail(`${label} must be an array of non-empty strings`);
  }
  if (nonEmpty && value.length === 0) fail(`${label} must not be empty`);
  if (new Set(value).size !== value.length || JSON.stringify(value) !== JSON.stringify([...value].sort())) {
    fail(`${label} must be sorted and unique`);
  }
  if (allowed && value.some((item) => !allowed.has(item))) {
    fail(`${label} contains an unsupported value`);
  }
  return value;
}

function parseStableVersion(value, label) {
  const match = typeof value === "string" ? STABLE_VERSION.exec(value) : null;
  if (!match) fail(`${label} must be a stable x.y.z version`);
  return match.slice(1).map((part) => BigInt(part));
}

function compareVersions(left, right) {
  const a = parseStableVersion(left, "left release version");
  const b = parseStableVersion(right, "right release version");
  for (let index = 0; index < 3; index += 1) {
    if (a[index] !== b[index]) return a[index] < b[index] ? -1 : 1;
  }
  return 0;
}

function metadataValues(source, key) {
  return [...source.matchAll(new RegExp(`^//\\s+@${key}\\s+(.+?)\\s*$`, "gm"))]
    .map((match) => match[1]);
}

function verifyUserscriptMetadata(bytes, version) {
  const source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  for (const placeholder of [
    "__HOTDEAL_FOCUS_DOWNLOAD_URL__",
    "__HOTDEAL_FOCUS_UPDATE_URL__",
    "__HOTDEAL_FOCUS_OWNER__",
  ]) {
    if (source.includes(placeholder)) fail(`userscript contains unresolved ${placeholder}`);
  }
  const exact = (key, expected) => {
    const values = metadataValues(source, key);
    if (values.length !== 1 || values[0] !== expected) {
      fail(`userscript @${key} is not exactly ${expected}`);
    }
  };
  exact("name", USERSCRIPT_NAME_VALUE);
  exact("namespace", USERSCRIPT_NAMESPACE);
  exact("version", version);
  exact("downloadURL", INSTALL_URL);
  exact("updateURL", INSTALL_URL);
  exact("run-at", "document-start");
  const grants = metadataValues(source, "grant");
  if (JSON.stringify(grants) !== JSON.stringify(["GM_addElement", "window.onurlchange"])) {
    fail("userscript grants are not the exact standalone contract");
  }
  for (const forbidden of ["connect", "require", "resource"]) {
    if (metadataValues(source, forbidden).length !== 0) {
      fail(`userscript @${forbidden} is forbidden in the standalone release`);
    }
  }
}

function verifyCoverage(value) {
  exactKeys(value, [
    "approvedVariantCount",
    "contractCount",
    "layoutCount",
    "layoutFamilyCount",
    "routeCount",
    "siteCount",
    "sites",
  ], "coverage");
  for (const key of [
    "approvedVariantCount",
    "contractCount",
    "layoutCount",
    "layoutFamilyCount",
    "routeCount",
    "siteCount",
  ]) safeInteger(value[key], `coverage.${key}`);
  if (!Array.isArray(value.sites) || value.sites.length !== value.siteCount || value.siteCount < 1) {
    fail("coverage sites do not match siteCount");
  }
  const siteIds = [];
  let layouts = 0;
  let variants = 0;
  let routes = 0;
  for (const [siteIndex, site] of value.sites.entries()) {
    exactKeys(site, ["id", "layouts"], `coverage.sites[${siteIndex}]`);
    if (typeof site.id !== "string" || !site.id || !Array.isArray(site.layouts)) {
      fail(`coverage.sites[${siteIndex}] is malformed`);
    }
    siteIds.push(site.id);
    const layoutIds = [];
    for (const [layoutIndex, layout] of site.layouts.entries()) {
      const label = `coverage.sites[${siteIndex}].layouts[${layoutIndex}]`;
      exactKeys(layout, [
        "applicableProfiles",
        "domain",
        "id",
        "paths",
        "requiredRoles",
        "variants",
      ], label);
      if (typeof layout.id !== "string" || !layout.id || typeof layout.domain !== "string" || !layout.domain) {
        fail(`${label} identity is malformed`);
      }
      layoutIds.push(layout.id);
      exactStringArray(layout.paths, `${label}.paths`, { nonEmpty: true });
      exactStringArray(layout.applicableProfiles, `${label}.applicableProfiles`, {
        allowed: new Set(["desktop", "mobile"]),
        nonEmpty: true,
      });
      exactStringArray(layout.requiredRoles, `${label}.requiredRoles`, { nonEmpty: true });
      if (!Array.isArray(layout.variants)) fail(`${label}.variants must be an array`);
      routes += layout.paths.length;
      layouts += 1;
      const variantIds = [];
      for (const [variantIndex, variant] of layout.variants.entries()) {
        const variantLabel = `${label}.variants[${variantIndex}]`;
        exactKeys(variant, [
          "applicableProfiles",
          "id",
          "paths",
          "proofProfiles",
          "requiredRoles",
        ], variantLabel);
        if (typeof variant.id !== "string" || !variant.id) fail(`${variantLabel}.id is malformed`);
        variantIds.push(variant.id);
        exactStringArray(variant.paths, `${variantLabel}.paths`, { nonEmpty: true });
        exactStringArray(variant.applicableProfiles, `${variantLabel}.applicableProfiles`, {
          allowed: new Set(["desktop", "mobile"]),
          nonEmpty: true,
        });
        exactStringArray(variant.proofProfiles, `${variantLabel}.proofProfiles`, {
          allowed: new Set(["desktop", "mobile"]),
          nonEmpty: true,
        });
        exactStringArray(variant.requiredRoles, `${variantLabel}.requiredRoles`, { nonEmpty: true });
        routes += variant.paths.length;
        variants += 1;
      }
      if (JSON.stringify(variantIds) !== JSON.stringify([...variantIds].sort()) || new Set(variantIds).size !== variantIds.length) {
        fail(`${label}.variants must be sorted and unique`);
      }
    }
    if (JSON.stringify(layoutIds) !== JSON.stringify([...layoutIds].sort()) || new Set(layoutIds).size !== layoutIds.length) {
      fail(`coverage.sites[${siteIndex}].layouts must be sorted and unique`);
    }
  }
  if (JSON.stringify(siteIds) !== JSON.stringify([...siteIds].sort()) || new Set(siteIds).size !== siteIds.length) {
    fail("coverage sites must be sorted and unique");
  }
  if (
    value.layoutCount !== layouts ||
    value.layoutFamilyCount !== layouts ||
    value.approvedVariantCount !== variants ||
    value.contractCount !== layouts + variants ||
    value.routeCount !== routes
  ) fail("coverage aggregate counts are inconsistent");
}

function verifySourceIntegrity(manifest) {
  const hasApprovedState = manifest.coverage.approvedVariantCount > 0;
  const expectedPaths = [
    ...REQUIRED_SOURCE_PATHS,
    ...(hasApprovedState ? [OPTIONAL_APPROVED_STATE] : []),
  ];
  exactKeys(manifest.sourceIntegrity, expectedPaths, "sourceIntegrity");
  for (const sourcePath of expectedPaths) {
    const entry = manifest.sourceIntegrity[sourcePath];
    if (sourcePath === HIGH_WATER_NAME) {
      exactKeys(entry, ["bytes", "mode", "recordCount", "sha256"], "high-water prefix entry");
      safeInteger(entry.bytes, "high-water prefix bytes", { minimum: 1 });
      safeInteger(entry.recordCount, "high-water prefix recordCount");
      if (entry.mode !== HIGH_WATER_PREFIX_MODE || !SHA256.test(entry.sha256)) {
        fail("high-water prefix entry is malformed");
      }
      continue;
    }
    exactKeys(entry, ["bytes", "sha256"], `sourceIntegrity.${sourcePath}`);
    safeInteger(entry.bytes, `${sourcePath} bytes`, { minimum: 1 });
    if (!SHA256.test(entry.sha256)) fail(`${sourcePath} sha256 is malformed`);
  }
  if (manifest.configSha256 !== manifest.sourceIntegrity["config/sites.json"].sha256) {
    fail("configSha256 differs from config/sites.json source integrity");
  }
}

function decodeJson(bytes, label) {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    fail(`${label} is not strict UTF-8 JSON`);
  }
}

function verifyV2Bundle(manifestBytes, userscriptBytes) {
  const manifest = decodeJson(manifestBytes, "release manifest");
  exactKeys(manifest, MANIFEST_KEYS, "release manifest");
  if (manifest.schemaVersion !== 2 || manifest.status !== "release-ready") {
    fail("release manifest is not release-ready schema-v2");
  }
  if (manifest.protocolVersion !== 2 || manifest.installUrl !== INSTALL_URL) {
    fail("release manifest standalone install contract is not exact");
  }
  parseStableVersion(manifest.releaseVersion, "releaseVersion");
  if (manifest.generatorVersion !== manifest.releaseVersion) {
    fail("generatorVersion must equal releaseVersion");
  }
  if (manifest.rollback_of !== null) {
    parseStableVersion(manifest.rollback_of, "rollback_of");
    if (compareVersions(manifest.rollback_of, manifest.releaseVersion) >= 0) {
      fail("rollback_of must identify an older stable release");
    }
  }
  verifyCoverage(manifest.coverage);
  if (manifest.promotion === null) {
    if (manifest.coverage.approvedVariantCount !== 0) fail("promotion proof is missing");
  } else {
    exactKeys(manifest.promotion, [
      "candidateSha256",
      "draftArtifactSetSha256",
      "evidenceSha256",
    ], "promotion");
    if (Object.values(manifest.promotion).some((value) => !SHA256.test(value))) {
      fail("promotion hashes are malformed");
    }
    if (manifest.coverage.approvedVariantCount < 1) fail("promotion exists without an approved variant");
  }
  exactKeys(manifest.artifacts, [USERSCRIPT_NAME], "public artifacts");
  const artifact = manifest.artifacts[USERSCRIPT_NAME];
  exactKeys(
    artifact,
    ["bytes", "canonicalTextSha256", "sha256", "version"],
    "userscript artifact",
  );
  if (
    !Number.isSafeInteger(artifact.bytes) ||
    artifact.bytes < 1 ||
    !SHA256.test(artifact.sha256) ||
    !SHA256.test(artifact.canonicalTextSha256) ||
    artifact.version !== manifest.releaseVersion
  ) fail("userscript artifact metadata is malformed");
  verifySourceIntegrity(manifest);
  const actual = {
    bytes: userscriptBytes.length,
    sha256: sha256(userscriptBytes),
    canonicalTextSha256: sha256(canonicalText(userscriptBytes)),
  };
  for (const [field, value] of Object.entries(actual)) {
    if (artifact[field] !== value) fail(`userscript ${field} differs from manifest`);
  }
  verifyUserscriptMetadata(userscriptBytes, manifest.releaseVersion);
  const bundleSha256 = publicBundleSha256(manifestBytes, userscriptBytes);
  return {
    manifest,
    manifestBytes: manifestBytes.length,
    manifestSha256: sha256(manifestBytes),
    artifact,
    bundleSha256,
    ...actual,
  };
}

function publicBundleSha256(manifestBytes, userscriptBytes) {
  const hash = crypto.createHash("sha256");
  hash.update(Buffer.from(`${PUBLIC_BUNDLE_FORMAT}\0`, "ascii"));
  for (const [name, bytes] of [
    [MANIFEST_NAME, manifestBytes],
    [USERSCRIPT_NAME, userscriptBytes],
  ]) {
    const nameBytes = Buffer.from(name, "utf8");
    const nameLength = Buffer.alloc(4);
    nameLength.writeUInt32BE(nameBytes.length);
    const contentLength = Buffer.alloc(8);
    contentLength.writeBigUInt64BE(BigInt(bytes.length));
    hash.update(nameLength);
    hash.update(nameBytes);
    hash.update(contentLength);
    hash.update(bytes);
  }
  return hash.digest("hex");
}

function releaseHighWaterRecord(proof) {
  return {
    bundleSha256: proof.bundleSha256,
    manifest: {
      bytes: proof.manifestBytes,
      sha256: proof.manifestSha256,
    },
    releaseVersion: proof.manifest.releaseVersion,
    userscript: {
      bytes: proof.bytes,
      canonicalTextSha256: proof.canonicalTextSha256,
      sha256: proof.sha256,
    },
  };
}

function verifyHighWaterRecord(record, index) {
  const label = `release high-water record ${index}`;
  exactKeys(record, ["bundleSha256", "manifest", "releaseVersion", "userscript"], label);
  parseStableVersion(record.releaseVersion, `${label}.releaseVersion`);
  if (!SHA256.test(record.bundleSha256)) fail(`${label}.bundleSha256 is malformed`);
  exactKeys(record.manifest, ["bytes", "sha256"], `${label}.manifest`);
  safeInteger(record.manifest.bytes, `${label}.manifest.bytes`, { minimum: 1 });
  if (!SHA256.test(record.manifest.sha256)) fail(`${label}.manifest.sha256 is malformed`);
  exactKeys(
    record.userscript,
    ["bytes", "canonicalTextSha256", "sha256"],
    `${label}.userscript`,
  );
  safeInteger(record.userscript.bytes, `${label}.userscript.bytes`, { minimum: 1 });
  if (!SHA256.test(record.userscript.sha256) || !SHA256.test(record.userscript.canonicalTextSha256)) {
    fail(`${label}.userscript hashes are malformed`);
  }
}

function parseHighWater(bytes, { allowEmpty = false } = {}) {
  const value = decodeJson(bytes, "release high-water");
  exactKeys(value, ["bundleFormat", "records", "schemaVersion"], "release high-water");
  if (
    value.schemaVersion !== HIGH_WATER_SCHEMA_VERSION ||
    value.bundleFormat !== PUBLIC_BUNDLE_FORMAT ||
    !Array.isArray(value.records) ||
    (!allowEmpty && value.records.length === 0)
  ) fail("release high-water schema is not exact");
  value.records.forEach((record, index) => {
    verifyHighWaterRecord(record, index);
    if (index > 0 && compareVersions(record.releaseVersion, value.records[index - 1].releaseVersion) <= 0) {
      fail("release high-water versions must be strictly increasing");
    }
  });
  return value;
}

function verifyHighWaterSource(highWaterBytes, proof, previousHighWaterBytes = null) {
  const highWater = parseHighWater(highWaterBytes);
  const currentRecord = highWater.records.at(-1);
  const expectedRecord = releaseHighWaterRecord(proof);
  if (!exactJson(currentRecord, expectedRecord)) {
    fail("release bundle differs from the durable high-water current record");
  }
  const prefixEntry = proof.manifest.sourceIntegrity[HIGH_WATER_NAME];
  if (prefixEntry.recordCount !== highWater.records.length - 1) {
    fail("release manifest high-water prefix length is not the immediate predecessor");
  }
  const prefixBytes = canonicalJsonBytes(highWaterDocument(
    highWater.records.slice(0, prefixEntry.recordCount),
  ));
  if (prefixEntry.bytes !== prefixBytes.length || prefixEntry.sha256 !== sha256(prefixBytes)) {
    fail("release manifest high-water prefix digest is invalid");
  }
  if (previousHighWaterBytes !== null) {
    const previous = parseHighWater(previousHighWaterBytes, { allowEmpty: true });
    if (
      highWater.records.length < previous.records.length ||
      highWater.records.length > previous.records.length + 1
    ) fail("release high-water must retain its prefix and append at most one record");
    for (let index = 0; index < previous.records.length; index += 1) {
      if (!exactJson(previous.records[index], highWater.records[index])) {
        fail("release high-water history was truncated or rewritten");
      }
    }
  }
  return { highWater, currentRecord };
}

function matchExactLegacyMigrationPredecessor(candidate, manifestBytes, userscriptBytes) {
  if (
    manifestBytes.length !== candidate.manifest.bytes ||
    sha256(manifestBytes) !== candidate.manifest.sha256
  ) return null;
  const manifest = decodeJson(manifestBytes, "published legacy manifest");
  const entry = manifest?.artifacts?.[USERSCRIPT_NAME];
  if (
    manifest?.schemaVersion === 1 &&
    manifest?.status === "release-ready" &&
    manifest?.releaseVersion === candidate.releaseVersion &&
    entry &&
    entry.bytes === candidate.userscript.bytes &&
    entry.sha256 === candidate.userscript.sha256 &&
    entry.canonicalTextSha256 === candidate.userscript.canonicalTextSha256 &&
    userscriptBytes.length === candidate.userscript.bytes &&
    sha256(userscriptBytes) === candidate.userscript.sha256 &&
    sha256(canonicalText(userscriptBytes)) === candidate.userscript.canonicalTextSha256
  ) return { manifest, artifact: entry };
  return null;
}

function verifyLegacyV1Migration(manifestBytes, userscriptBytes) {
  const match = LEGACY_V1_MIGRATION_PREDECESSORS
    .map((candidate) => ({
      candidate,
      legacy: matchExactLegacyMigrationPredecessor(candidate, manifestBytes, userscriptBytes),
    }))
    .find(({ legacy }) => legacy !== null);
  if (!match) {
    fail("published schema-v1 release is not an exact migration predecessor");
  }
  return {
    manifest: match.legacy.manifest,
    artifact: match.legacy.artifact,
    bundleSha256: publicBundleSha256(manifestBytes, userscriptBytes),
    legacyMigration: true,
  };
}

function readBundle(root) {
  const rootStat = fs.lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    fail("public bundle root must be one real directory");
  }
  const entries = fs.readdirSync(root, { withFileTypes: true });
  const actual = entries.map((entry) => entry.name).sort();
  const expected = [MANIFEST_NAME, USERSCRIPT_NAME].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`public bundle file set is not exact: ${actual.join(",")}`);
  }
  for (const entry of entries) {
    const stat = fs.lstatSync(path.join(root, entry.name));
    if (!entry.isFile() || stat.isSymbolicLink() || !stat.isFile()) {
      fail(`public bundle entry is not a regular file: ${entry.name}`);
    }
  }
  const manifestBytes = fs.readFileSync(path.join(root, MANIFEST_NAME));
  const userscriptBytes = fs.readFileSync(path.join(root, USERSCRIPT_NAME));
  return { manifestBytes, userscriptBytes, proof: verifyV2Bundle(manifestBytes, userscriptBytes) };
}

async function fetchBytes(
  url,
  {
    allowNotFound = false,
    maxBytes = MAX_REMOTE_BYTES,
    timeoutMs = REMOTE_TIMEOUT_MS,
  } = {},
) {
  safeInteger(maxBytes, "remote byte limit", { minimum: 1 });
  safeInteger(timeoutMs, "remote timeout", { minimum: 1 });
  const controller = new AbortController();
  let deadlineExceeded = false;
  let rejectDeadline;
  const deadline = new Promise((_, reject) => {
    rejectDeadline = reject;
  });
  const timer = setTimeout(() => {
    deadlineExceeded = true;
    controller.abort();
    rejectDeadline(new Error(`GET ${url} exceeded the ${timeoutMs}ms deadline`));
  }, timeoutMs);
  const beforeDeadline = (operation) => Promise.race([operation, deadline]);
  let reader = null;
  try {
    const response = await beforeDeadline(fetch(url, {
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
      headers: { Accept: "application/octet-stream" },
    }));
    if (allowNotFound && response.status === 404) return null;
    if (!response.ok) fail(`GET ${url} returned ${response.status}`);
    const contentLength = response.headers.get("content-length");
    if (contentLength !== null) {
      if (!/^[0-9]+$/.test(contentLength)) fail(`GET ${url} has an invalid content-length`);
      if (BigInt(contentLength) > BigInt(maxBytes)) fail(`GET ${url} exceeds the byte limit`);
    }
    if (!response.body) fail(`GET ${url} returned no response body`);
    reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    while (true) {
      const { done, value } = await beforeDeadline(reader.read());
      if (done) break;
      if (!(value instanceof Uint8Array)) fail(`GET ${url} returned an invalid body chunk`);
      total += value.byteLength;
      if (total > maxBytes) {
        void reader.cancel("byte limit exceeded").catch(() => undefined);
        fail(`GET ${url} exceeds the byte limit`);
      }
      chunks.push(Buffer.from(value));
    }
    if (total < 1) fail(`GET ${url} returned an invalid byte count`);
    return Buffer.concat(chunks, total);
  } catch (error) {
    if (deadlineExceeded || error?.name === "AbortError") {
      if (reader) void reader.cancel("deadline exceeded").catch(() => undefined);
      fail(`GET ${url} exceeded the ${timeoutMs}ms deadline`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function remoteUrl(baseUrl, name, nonce) {
  const base = new URL(baseUrl);
  if (base.protocol !== "https:" || base.hostname !== "heelee912.github.io") {
    fail("Pages base URL is not the exact HTTPS origin");
  }
  const expectedPath = "/adguard-hotdeal-focus/";
  if (base.pathname !== expectedPath || base.search || base.hash) {
    fail("Pages base URL path is not exact");
  }
  const result = new URL(name, base);
  result.searchParams.set("hdf_attestation", nonce);
  return result.href;
}

async function publishedBundle(baseUrl, nonce, { allowMissing = false } = {}) {
  const manifestBytes = await fetchBytes(remoteUrl(baseUrl, MANIFEST_NAME, nonce), {
    allowNotFound: allowMissing,
  });
  if (manifestBytes === null) return null;
  const userscriptBytes = await fetchBytes(remoteUrl(baseUrl, USERSCRIPT_NAME, nonce));
  return { manifestBytes, userscriptBytes };
}

function readAndVerifyDurableBundle(root, highWaterSource, previousHighWaterSource = null) {
  const proposed = readBundle(root);
  const highWaterBytes = fs.readFileSync(highWaterSource);
  const previousBytes = previousHighWaterSource === null
    ? null
    : fs.readFileSync(previousHighWaterSource);
  const durable = verifyHighWaterSource(highWaterBytes, proposed.proof, previousBytes);
  return { proposed, durable };
}

async function preflight(root, baseUrl, highWaterSource, previousHighWaterSource = null) {
  if (typeof previousHighWaterSource !== "string" || !previousHighWaterSource) {
    fail("previous high-water source is required for preflight");
  }
  const { proposed, durable } = readAndVerifyDurableBundle(
    root,
    highWaterSource,
    previousHighWaterSource,
  );
  const live = await publishedBundle(baseUrl, `preflight-${Date.now()}`, {
    allowMissing: true,
  });
  if (live === null) {
    return {
      ok: true,
      status: "durable-recovery",
      proposedVersion: proposed.proof.manifest.releaseVersion,
      bundleSha256: durable.currentRecord.bundleSha256,
    };
  }
  let current;
  try {
    current = verifyV2Bundle(live.manifestBytes, live.userscriptBytes);
  } catch {
    current = verifyLegacyV1Migration(live.manifestBytes, live.userscriptBytes);
  }
  const comparison = compareVersions(
    proposed.proof.manifest.releaseVersion,
    current.manifest.releaseVersion,
  );
  const sameBundle =
    exactlyEqualBytes(proposed.manifestBytes, live.manifestBytes) &&
    exactlyEqualBytes(proposed.userscriptBytes, live.userscriptBytes);
  if ((sameBundle && comparison !== 0) || (!sameBundle && comparison <= 0)) {
    fail("proposed Pages bundle violates durable monotonic versioning");
  }
  return {
    ok: true,
    status: sameBundle ? "idempotent" : "upgrade",
    currentVersion: current.manifest.releaseVersion,
    proposedVersion: proposed.proof.manifest.releaseVersion,
    bundleSha256: proposed.proof.bundleSha256,
    legacyMigration: current.legacyMigration === true,
  };
}

async function attest(root, baseUrl, sourceSha, highWaterSource) {
  if (!/^[0-9a-f]{40}$/.test(sourceSha)) fail("source SHA must be a full SHA-1 commit id");
  const { proposed: expected } = readAndVerifyDurableBundle(root, highWaterSource);
  let last = "no response";
  for (let attempt = 1; attempt <= 12; attempt += 1) {
    try {
      const live = await publishedBundle(baseUrl, `${sourceSha}-${attempt}`);
      const liveProof = verifyV2Bundle(live.manifestBytes, live.userscriptBytes);
      if (
        live &&
        exactlyEqualBytes(live.manifestBytes, expected.manifestBytes) &&
        exactlyEqualBytes(live.userscriptBytes, expected.userscriptBytes)
      ) {
        if (liveProof.bundleSha256 !== expected.proof.bundleSha256) {
          fail("live Pages bundle digest differs after exact byte comparison");
        }
        return {
          ok: true,
          status: "published-and-byte-attested",
          sourceSha,
          attempts: attempt,
          releaseVersion: expected.proof.manifest.releaseVersion,
          userscriptSha256: expected.proof.sha256,
          bundleSha256: expected.proof.bundleSha256,
        };
      }
      last = "Pages still serves different bytes";
    } catch (error) {
      last = error instanceof Error ? error.message : String(error);
    }
    if (attempt < 12) await new Promise((resolve) => setTimeout(resolve, 5_000));
  }
  fail(`Pages byte attestation timed out: ${last}`);
}

function option(arguments_, name, { required = true } = {}) {
  const matches = arguments_.reduce((indexes, value, index) => {
    if (value === name) indexes.push(index);
    return indexes;
  }, []);
  if (matches.length > 1) fail(`duplicate ${name}`);
  if (matches.length === 0) {
    if (required) fail(`missing ${name}`);
    return null;
  }
  const index = matches[0];
  if (index + 1 >= arguments_.length || arguments_[index + 1].startsWith("--")) {
    fail(`missing ${name}`);
  }
  return arguments_[index + 1];
}

async function main(arguments_) {
  const [command] = arguments_;
  const root = path.resolve(option(arguments_, "--root"));
  const highWaterSource = path.resolve(option(arguments_, "--high-water-source"));
  const previousOption = option(arguments_, "--previous-high-water-source", { required: false });
  const previousHighWaterSource = previousOption === null ? null : path.resolve(previousOption);
  let result;
  if (command === "verify-bundle") {
    if (typeof previousHighWaterSource !== "string" || !previousHighWaterSource) {
      fail("previous high-water source is required for verify-bundle");
    }
    const { proposed, durable } = readAndVerifyDurableBundle(
      root,
      highWaterSource,
      previousHighWaterSource,
    );
    result = {
      ok: true,
      status: "verified",
      releaseVersion: proposed.proof.manifest.releaseVersion,
      userscriptSha256: proposed.proof.sha256,
      bundleSha256: durable.currentRecord.bundleSha256,
    };
  } else if (command === "preflight") {
    result = await preflight(
      root,
      option(arguments_, "--base-url"),
      highWaterSource,
      previousHighWaterSource,
    );
  } else if (command === "attest") {
    result = await attest(
      root,
      option(arguments_, "--base-url"),
      option(arguments_, "--source-sha"),
      highWaterSource,
    );
  } else {
    fail("command must be verify-bundle, preflight, or attest");
  }
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

export {
  canonicalJsonBytes,
  compareVersions,
  fetchBytes,
  highWaterDocument,
  LEGACY_V1_MIGRATION_PREDECESSORS,
  matchExactLegacyMigrationPredecessor,
  parseHighWater,
  preflight,
  publicBundleSha256,
  readBundle,
  releaseHighWaterRecord,
  verifyHighWaterSource,
  verifyV2Bundle,
  verifyUserscriptMetadata,
};

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))
) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
