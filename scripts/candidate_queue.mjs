#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const QUEUE_SCHEMA_VERSION = 2;
const RESULT_SCHEMA_VERSION = 2;
const PROMOTION_SCHEMA_VERSION = 2;
const MAX_MATRIX_CANDIDATES = 256;
const MATRIX_BATCH_SIZE = 8;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const BASE_SHA_PATTERN = /^[0-9a-f]{40,64}$/;
const FINGERPRINT_PATTERN = /^[0-9a-f]{24}$/;
const IDENTIFIER_PATTERN = /^[a-z0-9][a-z0-9_-]{0,127}$/;
const SYNTHETIC_MISSING_STATUS = "infrastructure-missing";
const RESULT_STATUSES = new Set([
  "proven",
  "infrastructure-failure",
  "build-timeout",
  "build-rejected",
  "proof-timeout",
  "live-proof-rejected",
  "proof-missing",
  "release-build-timeout",
  "release-build-rejected",
  "release-check-timeout",
  "release-check-rejected",
  "draft-release-mismatch",
]);
const RELEASE_REQUIRED_FILES = [
  "config/sites.json",
  "filter-static.txt",
  "hotdeal-focus.user.js",
  "package-lock.json",
  "package.json",
  "release-manifest.json",
  "state/approved-variants.json",
  "state/release-high-water.json",
];
const PROOF_REQUIRED_FILES = [
  "draft-manifest.json",
  "promotion-draft.json",
  "promotion-ready.json",
];

function fail(message) {
  throw new Error(message);
}

function parseArguments(argv) {
  const [command, ...tokens] = argv;
  if (!command) fail("a command is required");
  const values = new Map();
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (!token.startsWith("--")) fail(`unexpected argument: ${token}`);
    const key = token.slice(2);
    const value = tokens[index + 1];
    if (value === undefined || value.startsWith("--")) {
      fail(`missing value for --${key}`);
    }
    if (values.has(key)) fail(`duplicate argument: --${key}`);
    values.set(key, value);
    index += 1;
  }
  return { command, values };
}

function required(values, key) {
  const value = values.get(key);
  if (!value) fail(`--${key} is required`);
  return value;
}

function optionalInteger(values, key, defaultValue) {
  const raw = values.get(key);
  if (raw === undefined) return defaultValue;
  if (!/^[1-9][0-9]*$/.test(raw)) fail(`--${key} must be a positive integer`);
  return Number(raw);
}

function serializedJsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalValue(value[key])]),
    );
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function requireExactObjectKeys(value, expectedKeys, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    fail(`${label} keys are not exact`);
  }
}

function sha256Bytes(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function sha256File(filePath) {
  return sha256Bytes(fs.readFileSync(filePath));
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, serializedJsonBytes(value));
}

function writeText(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, value, "utf8");
}

function appendGithubOutput(filePath, entries) {
  if (!filePath) return;
  const body = Object.entries(entries)
    .map(([key, value]) => `${key}=${value}\n`)
    .join("");
  fs.appendFileSync(filePath, body, "utf8");
}

function normalizedRelative(filePath) {
  return filePath.split(path.sep).join("/");
}

function resolveInside(rootPath, relativePath) {
  if (typeof relativePath !== "string" || relativePath.length === 0) {
    fail("artifact path must be a non-empty string");
  }
  if (path.isAbsolute(relativePath)) fail(`absolute artifact path is forbidden: ${relativePath}`);
  const root = path.resolve(rootPath);
  const resolved = path.resolve(root, relativePath);
  const relation = path.relative(root, resolved);
  if (relation === "" || relation.startsWith("..") || path.isAbsolute(relation)) {
    fail(`artifact path escapes its root: ${relativePath}`);
  }
  return resolved;
}

function listFiles(rootPath) {
  const root = path.resolve(rootPath);
  if (!fs.existsSync(root)) return [];
  const files = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort(
      (left, right) => left.name.localeCompare(right.name),
    )) {
      const absolute = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) fail(`symbolic links are forbidden: ${absolute}`);
      if (entry.isDirectory()) {
        visit(absolute);
      } else if (entry.isFile()) {
        files.push(normalizedRelative(path.relative(root, absolute)));
      } else {
        fail(`unsupported filesystem entry: ${absolute}`);
      }
    }
  };
  visit(root);
  return files.sort();
}

function requireExactFiles(rootPath, expectedFiles) {
  const actual = listFiles(rootPath);
  const expected = [...expectedFiles].sort();
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    fail(
      `artifact file set mismatch; expected=${expected.join(",")} actual=${actual.join(",")}`,
    );
  }
}

function copyFile(source, destination) {
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
}

function skippedArtifactSummary(entries) {
  const canonicalEntries = entries
    .map(({ bytes, path: relative, reason }) => ({ bytes, path: relative, reason }))
    .sort((left, right) => left.path.localeCompare(right.path));
  return {
    count: canonicalEntries.length,
    pathsSha256: sha256Bytes(canonicalJson(canonicalEntries)),
    totalBytes: canonicalEntries.reduce((total, entry) => total + entry.bytes, 0),
  };
}

function renderBoundedManifest(manifestFactory, selectedBytes) {
  let manifestBytes = 0;
  for (let iteration = 0; iteration < 16; iteration += 1) {
    const manifest = manifestFactory({
      artifactTotalBytes: selectedBytes + manifestBytes,
      manifestBytes,
    });
    const bytes = serializedJsonBytes(manifest);
    if (bytes.length === manifestBytes) return { bytes, manifest };
    manifestBytes = bytes.length;
  }
  fail("bounded artifact manifest size did not converge");
}

function planBoundedArtifact(entries, maxFiles, maxBytes, manifestFactory) {
  const selected = [];
  const skipped = [];
  const payloadFileLimit = Math.max(0, maxFiles - 1);
  let selectedBytes = 0;
  for (const entry of entries) {
    if (selected.length >= payloadFileLimit || selectedBytes + entry.bytes > maxBytes) {
      skipped.push({ ...entry, reason: "cap" });
      continue;
    }
    selected.push(entry);
    selectedBytes += entry.bytes;
  }
  while (true) {
    const skippedSummary = skippedArtifactSummary(skipped);
    const rendered = renderBoundedManifest(
      ({ artifactTotalBytes, manifestBytes }) => manifestFactory({
        artifactFileCount: selected.length + 1,
        artifactTotalBytes,
        manifestBytes,
        selected,
        selectedBytes,
        skipped: skippedSummary,
      }),
      selectedBytes,
    );
    const artifactTotalBytes = selectedBytes + rendered.bytes.length;
    if (artifactTotalBytes <= maxBytes) {
      return {
        manifest: rendered.manifest,
        manifestBytes: rendered.bytes,
        selected,
      };
    }
    if (selected.length === 0) {
      fail(`--max-bytes is too small for the bounded artifact manifest: ${maxBytes}`);
    }
    const removed = selected.pop();
    selectedBytes -= removed.bytes;
    skipped.push({ ...removed, reason: "manifest-reserve" });
  }
}

function createDirectoryAtomically(targetPath, populate) {
  const target = path.resolve(targetPath);
  if (fs.existsSync(target)) fail(`output already exists: ${target}`);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const temporary = `${target}.tmp-${process.pid}-${crypto.randomBytes(6).toString("hex")}`;
  fs.mkdirSync(temporary, { recursive: false });
  try {
    populate(temporary);
    fs.renameSync(temporary, target);
  } catch (error) {
    if (fs.existsSync(temporary)) fs.rmSync(temporary, { recursive: true, force: true });
    throw error;
  }
}

function validateBaseSha(baseSha) {
  if (!BASE_SHA_PATTERN.test(baseSha)) fail(`invalid immutable base SHA: ${baseSha}`);
}

function validateFingerprint(fingerprint) {
  if (!FINGERPRINT_PATTERN.test(fingerprint)) {
    fail(`invalid candidate fingerprint: ${fingerprint}`);
  }
}

function validateIdentifier(identifier, location) {
  if (typeof identifier !== "string" || !IDENTIFIER_PATTERN.test(identifier)) {
    fail(`invalid ${location}: ${JSON.stringify(identifier)}`);
  }
}

function validateRunNumber(runNumber) {
  if (!/^[1-9][0-9]*$/.test(runNumber)) {
    fail(`invalid GitHub run number: ${JSON.stringify(runNumber)}`);
  }
  const parsed = BigInt(runNumber);
  if (parsed > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail(`GitHub run number exceeds the supported range: ${runNumber}`);
  }
  return parsed;
}

function candidateBatch(runNumber, candidateCount) {
  const parsedRunNumber = validateRunNumber(runNumber);
  const batchSize = Math.min(candidateCount, MATRIX_BATCH_SIZE);
  const batchStart = candidateCount === 0
    ? 0
    : Number(
      ((parsedRunNumber - 1n) * BigInt(MATRIX_BATCH_SIZE)) % BigInt(candidateCount),
    );
  const candidateIndexes = Array.from(
    { length: batchSize },
    (_unused, offset) => (batchStart + offset) % candidateCount,
  );
  return {
    runNumber,
    batchStart,
    batchSize,
    total: candidateCount,
    candidateIndexes,
  };
}

function queueSealPayload(queue, queueSha256) {
  return {
    auditReportSha256: queue.auditReport?.sha256 ?? null,
    baseSha: queue.baseSha,
    batch: queue.batch,
    orderedCandidates: queue.candidates.map((candidate) => ({
      draftSha256: candidate.draftSha256,
      fingerprint: candidate.fingerprint,
      index: candidate.index,
    })),
    queueSha256,
  };
}

function discoverAuditInputs(evidencePath) {
  const evidenceRoot = path.resolve(evidencePath);
  const latestPath = path.join(evidenceRoot, "latest-run.json");
  if (!fs.existsSync(latestPath)) {
    return { reportPath: null, orderedDrafts: [] };
  }
  const latest = readJson(latestPath);
  const reportPath = resolveInside(evidenceRoot, latest.report);
  if (!fs.statSync(reportPath).isFile()) fail("latest audit report is not a file");
  const runDirectory = path.dirname(reportPath);
  const candidatesPath = path.join(runDirectory, "promotion-candidates.json");
  const draftsDirectory = path.join(runDirectory, "promotion-drafts");
  const actualDraftNames = fs.existsSync(draftsDirectory)
    ? fs.readdirSync(draftsDirectory, { withFileTypes: true })
      .filter((entry) => entry.isFile() && entry.name.endsWith(".json"))
      .map((entry) => entry.name)
      .sort()
    : [];
  if (!fs.existsSync(candidatesPath)) {
    if (actualDraftNames.length > 0) {
      fail("candidate drafts exist without the ordered promotion-candidates manifest");
    }
    return { reportPath, orderedDrafts: [] };
  }
  const candidatesDocument = readJson(candidatesPath);
  if (candidatesDocument.schemaVersion !== 1 || !Array.isArray(candidatesDocument.candidates)) {
    fail("invalid promotion-candidates manifest");
  }
  const orderedDrafts = [];
  const seen = new Set();
  for (const candidate of candidatesDocument.candidates) {
    if (candidate?.status !== "draft") continue;
    const fingerprint = candidate.fingerprint;
    validateFingerprint(fingerprint);
    if (seen.has(fingerprint)) fail(`duplicate ordered fingerprint: ${fingerprint}`);
    seen.add(fingerprint);
    const draftPath = path.join(draftsDirectory, `${fingerprint}.json`);
    if (!fs.existsSync(draftPath) || !fs.statSync(draftPath).isFile()) {
      fail(`ordered candidate draft is missing: ${fingerprint}`);
    }
    const draft = readJson(draftPath);
    const siteId = draft.candidate?.siteId;
    const layoutId = draft.candidate?.layoutId;
    const variantId = draft.candidate?.variantId;
    validateIdentifier(siteId, `candidate site ID for ${fingerprint}`);
    validateIdentifier(layoutId, `candidate layout ID for ${fingerprint}`);
    validateIdentifier(variantId, `candidate variant ID for ${fingerprint}`);
    if (candidate.variantId !== null && candidate.variantId !== undefined &&
        candidate.variantId !== variantId) {
      fail(`ordered manifest variant does not match draft: ${fingerprint}`);
    }
    orderedDrafts.push({ draftPath, fingerprint, layoutId, siteId, variantId });
  }
  const expectedDraftNames = orderedDrafts.map(
    (candidate) => `${candidate.fingerprint}.json`,
  ).sort();
  if (canonicalJson(actualDraftNames) !== canonicalJson(expectedDraftNames)) {
    fail("promotion-drafts contains an unqueued or missing draft");
  }
  if (orderedDrafts.length > MAX_MATRIX_CANDIDATES) {
    fail(
      `candidate queue exceeds GitHub's ${MAX_MATRIX_CANDIDATES}-job matrix limit`,
    );
  }
  return { reportPath, orderedDrafts };
}

function createQueue(values) {
  const evidencePath = required(values, "evidence-dir");
  const outputPath = required(values, "output-dir");
  const baseSha = required(values, "base-sha").toLowerCase();
  const runNumber = required(values, "run-number");
  const githubOutput = values.get("github-output");
  validateBaseSha(baseSha);
  const discovered = discoverAuditInputs(evidencePath);
  let emittedQueue;
  let emittedQueueSha256;
  createDirectoryAtomically(outputPath, (temporary) => {
    let auditReport = null;
    if (discovered.reportPath !== null) {
      const destination = path.join(temporary, "base-audit-report.json");
      copyFile(discovered.reportPath, destination);
      auditReport = {
        file: "base-audit-report.json",
        sha256: sha256File(destination),
      };
    }
    const candidates = discovered.orderedDrafts.map((candidate, index) => {
      const draftFile = `drafts/${candidate.fingerprint}.json`;
      const destination = path.join(temporary, ...draftFile.split("/"));
      copyFile(candidate.draftPath, destination);
      return {
        draftFile,
        draftSha256: sha256File(destination),
        fingerprint: candidate.fingerprint,
        index,
        layoutId: candidate.layoutId,
        siteId: candidate.siteId,
        variantId: candidate.variantId,
      };
    });
    const batch = candidateBatch(runNumber, candidates.length);
    emittedQueue = {
      schemaVersion: QUEUE_SCHEMA_VERSION,
      auditReport,
      baseSha,
      batch,
      candidates,
    };
    const queuePath = path.join(temporary, "queue.json");
    writeJson(queuePath, emittedQueue);
    emittedQueueSha256 = sha256File(queuePath);
    const sealPayload = queueSealPayload(emittedQueue, emittedQueueSha256);
    const manifest = {
      schemaVersion: QUEUE_SCHEMA_VERSION,
      seal: {
        kind: "digest-bound",
        algorithm: "sha256",
        payloadSha256: sha256Bytes(canonicalJson(sealPayload)),
      },
      sealedQueueFile: "queue.json",
      sealedQueueSha256: emittedQueueSha256,
      ...sealPayload,
      candidateCount: candidates.length,
    };
    writeJson(path.join(temporary, "queue-manifest.json"), manifest);
  });
  const matrixCandidates = emittedQueue.batch.candidateIndexes.map(
    (index) => emittedQueue.candidates[index],
  );
  const matrix = {
    include: matrixCandidates.map(({ fingerprint, index }) => ({
      fingerprint,
      index,
    })),
  };
  appendGithubOutput(githubOutput, {
    candidate_batch_size: emittedQueue.batch.batchSize,
    candidate_batch_start: emittedQueue.batch.batchStart,
    candidate_count: emittedQueue.batch.batchSize,
    candidate_matrix: JSON.stringify(matrix),
    candidate_run_number: emittedQueue.batch.runNumber,
    candidate_total: emittedQueue.batch.total,
    queue_sha256: emittedQueueSha256,
  });
  process.stdout.write(
    `SEALED candidate queue: ${emittedQueue.candidates.length} total, ` +
      `${emittedQueue.batch.batchSize} in batch at ${emittedQueue.batch.batchStart}, ` +
      `${emittedQueueSha256}\n`,
  );
}

function verifyQueue(queueRoot, expectedBaseSha = null, expectedQueueSha256 = null) {
  const root = path.resolve(queueRoot);
  const queuePath = path.join(root, "queue.json");
  const manifestPath = path.join(root, "queue-manifest.json");
  const queue = readJson(queuePath);
  const manifest = readJson(manifestPath);
  requireExactObjectKeys(queue, [
    "auditReport",
    "baseSha",
    "batch",
    "candidates",
    "schemaVersion",
  ], "candidate queue");
  requireExactObjectKeys(manifest, [
    "auditReportSha256",
    "baseSha",
    "batch",
    "candidateCount",
    "orderedCandidates",
    "queueSha256",
    "schemaVersion",
    "seal",
    "sealedQueueFile",
    "sealedQueueSha256",
  ], "candidate queue manifest");
  requireExactObjectKeys(
    manifest.seal,
    ["algorithm", "kind", "payloadSha256"],
    "candidate queue seal",
  );
  if (queue.schemaVersion !== QUEUE_SCHEMA_VERSION ||
      manifest.schemaVersion !== QUEUE_SCHEMA_VERSION) {
    fail("unsupported candidate queue schema");
  }
  validateBaseSha(queue.baseSha);
  if (expectedBaseSha !== null && queue.baseSha !== expectedBaseSha.toLowerCase()) {
    fail("candidate queue base SHA does not match the checked-out commit");
  }
  if (!Array.isArray(queue.candidates) || queue.candidates.length > MAX_MATRIX_CANDIDATES) {
    fail("invalid candidate queue size");
  }
  const expectedBatch = candidateBatch(
    queue.batch?.runNumber,
    queue.candidates.length,
  );
  if (canonicalJson(queue.batch) !== canonicalJson(expectedBatch)) {
    fail("candidate queue batch binding is invalid");
  }
  const seen = new Set();
  const expectedFiles = ["queue-manifest.json", "queue.json"];
  for (const [index, candidate] of queue.candidates.entries()) {
    validateFingerprint(candidate.fingerprint);
    validateIdentifier(candidate.siteId, `queue candidate site ID at index ${index}`);
    validateIdentifier(candidate.layoutId, `queue candidate layout ID at index ${index}`);
    validateIdentifier(candidate.variantId, `queue candidate variant ID at index ${index}`);
    if (candidate.index !== index) fail("candidate queue indexes are not contiguous");
    if (seen.has(candidate.fingerprint)) fail("candidate queue contains a duplicate fingerprint");
    seen.add(candidate.fingerprint);
    if (!SHA256_PATTERN.test(candidate.draftSha256)) fail("invalid candidate draft digest");
    const expectedDraftFile = `drafts/${candidate.fingerprint}.json`;
    if (candidate.draftFile !== expectedDraftFile) fail("candidate draft path is not canonical");
    const draftPath = resolveInside(root, candidate.draftFile);
    if (sha256File(draftPath) !== candidate.draftSha256) {
      fail(`candidate draft digest mismatch: ${candidate.fingerprint}`);
    }
    const draft = readJson(draftPath);
    if (draft.candidate?.siteId !== candidate.siteId ||
        draft.candidate?.layoutId !== candidate.layoutId ||
        draft.candidate?.variantId !== candidate.variantId) {
      fail(`candidate identity does not match its draft: ${candidate.fingerprint}`);
    }
    expectedFiles.push(candidate.draftFile);
  }
  if (queue.auditReport === null) {
    if (queue.candidates.length !== 0) fail("non-empty queue has no frozen audit report");
  } else {
    if (queue.auditReport.file !== "base-audit-report.json" ||
        !SHA256_PATTERN.test(queue.auditReport.sha256)) {
      fail("invalid frozen audit report binding");
    }
    if (sha256File(path.join(root, queue.auditReport.file)) !== queue.auditReport.sha256) {
      fail("frozen audit report digest mismatch");
    }
    expectedFiles.push(queue.auditReport.file);
  }
  requireExactFiles(root, expectedFiles);
  const queueSha256 = sha256File(queuePath);
  if (expectedQueueSha256 !== null && queueSha256 !== expectedQueueSha256) {
    fail("candidate queue digest does not match the audit job output");
  }
  const sealPayload = queueSealPayload(queue, queueSha256);
  const expectedSeal = sha256Bytes(canonicalJson(sealPayload));
  if (manifest.sealedQueueFile !== "queue.json" ||
      manifest.sealedQueueSha256 !== queueSha256 ||
      manifest.queueSha256 !== queueSha256 ||
      manifest.baseSha !== queue.baseSha ||
      canonicalJson(manifest.batch) !== canonicalJson(queue.batch) ||
      manifest.auditReportSha256 !== (queue.auditReport?.sha256 ?? null) ||
      manifest.candidateCount !== queue.candidates.length ||
      canonicalJson(manifest.orderedCandidates) !==
        canonicalJson(sealPayload.orderedCandidates) ||
      manifest.seal?.kind !== "digest-bound" ||
      manifest.seal?.algorithm !== "sha256" ||
      manifest.seal?.payloadSha256 !== expectedSeal) {
    fail("candidate queue digest-bound seal mismatch");
  }
  return { manifest, queue, queueSha256 };
}

function prepareCandidate(values) {
  const queueRoot = required(values, "queue-root");
  const outputPath = required(values, "output-dir");
  const expectedBaseSha = required(values, "expected-base-sha").toLowerCase();
  const expectedQueueSha256 = required(values, "expected-queue-sha256");
  const fingerprint = required(values, "fingerprint");
  const expectedIndex = Number(required(values, "expected-index"));
  const githubOutput = values.get("github-output");
  if (!SHA256_PATTERN.test(expectedQueueSha256)) fail("invalid expected queue digest");
  const verified = verifyQueue(queueRoot, expectedBaseSha, expectedQueueSha256);
  const candidate = verified.queue.candidates.find(
    (entry) => entry.fingerprint === fingerprint,
  );
  if (!candidate || candidate.index !== expectedIndex) {
    fail("matrix tuple does not exist at the sealed queue index");
  }
  if (!verified.queue.batch.candidateIndexes.includes(candidate.index)) {
    fail("matrix tuple is outside the sealed circular batch");
  }
  createDirectoryAtomically(outputPath, (temporary) => {
    copyFile(
      resolveInside(queueRoot, candidate.draftFile),
      path.join(temporary, "promotion-draft.json"),
    );
    writeJson(path.join(temporary, "candidate-entry.json"), candidate);
    writeJson(path.join(temporary, "queue-binding.json"), {
      baseSha: verified.queue.baseSha,
      queueSha256: verified.queueSha256,
    });
  });
  appendGithubOutput(githubOutput, {
    draft_sha256: candidate.draftSha256,
    site_id: candidate.siteId,
  });
}

function collectEvidence(values) {
  const sourceRoot = path.resolve(required(values, "source-dir"));
  const outputPath = required(values, "output-dir");
  const maxFiles = optionalInteger(values, "max-files", 1024);
  const maxBytes = optionalInteger(values, "max-bytes", 32 * 1024 * 1024);
  const eligible = fs.existsSync(sourceRoot)
    ? listFiles(sourceRoot).filter((name) => /\.(?:json|sha256)$/i.test(name))
    : [];
  createDirectoryAtomically(outputPath, (temporary) => {
    const entries = eligible.map((relative) => {
      const source = resolveInside(sourceRoot, relative);
      return {
        bytes: fs.statSync(source).size,
        path: relative,
        sha256: sha256File(source),
        source,
      };
    });
    const planned = planBoundedArtifact(
      entries,
      maxFiles,
      maxBytes,
      ({
        artifactFileCount,
        artifactTotalBytes,
        manifestBytes,
        selected,
        selectedBytes,
        skipped,
      }) => ({
        schemaVersion: 1,
        allowedExtensions: [".json", ".sha256"],
        artifactFileCount,
        artifactTotalBytes,
        manifestBytes,
        maxBytes,
        maxFiles,
        selected: selected.map(({ bytes, path: relative, sha256 }) => ({
          bytes,
          path: relative,
          sha256,
        })),
        selectedBytes,
        skipped,
      }),
    );
    for (const entry of planned.selected) {
      const relative = entry.path;
      const source = entry.source;
      copyFile(source, path.join(temporary, ...relative.split("/")));
    }
    fs.writeFileSync(
      path.join(temporary, "evidence-manifest.json"),
      planned.manifestBytes,
    );
  });
}

function capScreenshots(values) {
  const sourceRoot = path.resolve(required(values, "source-dir"));
  const outputPath = required(values, "output-dir");
  const maxFiles = optionalInteger(values, "max-files", 8);
  const maxBytes = optionalInteger(values, "max-bytes", 8 * 1024 * 1024);
  const githubOutput = values.get("github-output");
  const eligible = fs.existsSync(sourceRoot)
    ? listFiles(sourceRoot).filter((name) => name.toLowerCase().endsWith(".png"))
    : [];
  let selectedCount = 0;
  let artifactTotalBytes = 0;
  createDirectoryAtomically(outputPath, (temporary) => {
    const entries = eligible.map((relative) => {
      const source = resolveInside(sourceRoot, relative);
      return {
        bytes: fs.statSync(source).size,
        path: relative,
        sha256: sha256File(source),
        source,
      };
    });
    const planned = planBoundedArtifact(
      entries,
      maxFiles,
      maxBytes,
      ({
        artifactFileCount,
        artifactTotalBytes: totalBytes,
        manifestBytes,
        selected,
        selectedBytes,
        skipped,
      }) => ({
        schemaVersion: 1,
        artifactFileCount,
        artifactTotalBytes: totalBytes,
        manifestBytes,
        maxBytes,
        maxFiles,
        selected: selected.map(({ bytes, path: relative, sha256 }) => ({
          bytes,
          path: relative,
          sha256,
        })),
        selectedBytes,
        skipped,
      }),
    );
    for (const entry of planned.selected) {
      const relative = entry.path;
      const source = entry.source;
      copyFile(source, path.join(temporary, ...relative.split("/")));
    }
    selectedCount = planned.selected.length;
    artifactTotalBytes = planned.manifest.artifactTotalBytes;
    fs.writeFileSync(
      path.join(temporary, "screenshot-manifest.json"),
      planned.manifestBytes,
    );
  });
  appendGithubOutput(githubOutput, {
    count: selectedCount,
    total_bytes: artifactTotalBytes,
  });
}

function resultSealPayload(result, files) {
  return {
    baseSha: result.baseSha,
    draftSha256: result.draftSha256,
    files,
    fingerprint: result.fingerprint,
    index: result.index,
    queueSha256: result.queueSha256,
    status: result.status,
  };
}

function verifyProvenPayload(resultRoot, candidate) {
  const releaseRoot = path.join(resultRoot, "release");
  requireExactFiles(releaseRoot, RELEASE_REQUIRED_FILES);
  for (const relative of PROOF_REQUIRED_FILES) {
    if (!fs.existsSync(path.join(resultRoot, "proof", relative))) {
      fail(`proven result is missing proof/${relative}`);
    }
  }
  for (const deferred of [
    "base-audit-report.json",
    "base-audit-report.sha256",
    "base-commit.txt",
  ]) {
    if (fs.existsSync(path.join(resultRoot, "proof", deferred))) {
      fail(`matrix result must not duplicate queue-owned proof/${deferred}`);
    }
  }
  const proofRoot = path.join(resultRoot, "proof");
  const releaseManifest = readJson(path.join(releaseRoot, "release-manifest.json"));
  if (canonicalJson(Object.keys(releaseManifest.artifacts ?? {}).sort()) !==
      canonicalJson(["hotdeal-focus.user.js"])) {
    fail("candidate release manifest public artifact set is not userscript-only");
  }
  if (sha256File(path.join(proofRoot, "promotion-draft.json")) !== candidate.draftSha256) {
    fail("proven result promotion draft does not match the sealed queue");
  }
  const draft = readJson(path.join(proofRoot, "promotion-draft.json"));
  const ready = readJson(path.join(proofRoot, "promotion-ready.json"));
  if (draft.candidate?.variantId !== candidate.variantId ||
      ready.candidate?.variantId !== candidate.variantId ||
      ready.baseConfigSha256 !== draft.baseConfigSha256) {
    fail("proven candidate identity changed between draft and ready proof");
  }
}

function sealResult(values) {
  const queueRoot = required(values, "queue-root");
  const resultRoot = path.resolve(required(values, "result-dir"));
  const expectedBaseSha = required(values, "expected-base-sha").toLowerCase();
  const expectedQueueSha256 = required(values, "expected-queue-sha256");
  const fingerprint = required(values, "fingerprint");
  const expectedIndex = Number(required(values, "expected-index"));
  const status = required(values, "status");
  const reason = values.get("reason") ?? null;
  if (!RESULT_STATUSES.has(status)) fail(`unsupported candidate result status: ${status}`);
  if (!SHA256_PATTERN.test(expectedQueueSha256)) fail("invalid expected queue digest");
  const verified = verifyQueue(queueRoot, expectedBaseSha, expectedQueueSha256);
  const candidate = verified.queue.candidates.find(
    (entry) => entry.fingerprint === fingerprint,
  );
  if (!candidate || candidate.index !== expectedIndex) {
    fail("candidate result does not match a sealed queue tuple");
  }
  if (!verified.queue.batch.candidateIndexes.includes(candidate.index)) {
    fail("candidate result is outside the sealed circular batch");
  }
  if (!fs.existsSync(resultRoot) || !fs.statSync(resultRoot).isDirectory()) {
    fail("candidate result directory does not exist");
  }
  if (fs.existsSync(path.join(resultRoot, "result.json")) ||
      fs.existsSync(path.join(resultRoot, "result-manifest.json"))) {
    fail("candidate result is already sealed");
  }
  if (status === "proven") {
    verifyProvenPayload(resultRoot, candidate);
  } else if (fs.existsSync(path.join(resultRoot, "release"))) {
    fail("a non-proven result must not carry release bytes");
  }
  const result = {
    schemaVersion: RESULT_SCHEMA_VERSION,
    baseSha: verified.queue.baseSha,
    draftSha256: candidate.draftSha256,
    fingerprint,
    index: candidate.index,
    queueSha256: verified.queueSha256,
    reason,
    status,
  };
  writeJson(path.join(resultRoot, "result.json"), result);
  const files = listFiles(resultRoot).map((relative) => {
    const absolute = resolveInside(resultRoot, relative);
    return {
      bytes: fs.statSync(absolute).size,
      path: relative,
      sha256: sha256File(absolute),
    };
  });
  const payload = resultSealPayload(result, files);
  writeJson(path.join(resultRoot, "result-manifest.json"), {
    schemaVersion: RESULT_SCHEMA_VERSION,
    ...payload,
    seal: {
      kind: "digest-bound",
      algorithm: "sha256",
      payloadSha256: sha256Bytes(canonicalJson(payload)),
    },
  });
}

function verifyResult(resultRoot, queueVerification, candidate) {
  const root = path.resolve(resultRoot);
  const result = readJson(path.join(root, "result.json"));
  const manifest = readJson(path.join(root, "result-manifest.json"));
  requireExactObjectKeys(result, [
    "baseSha",
    "draftSha256",
    "fingerprint",
    "index",
    "queueSha256",
    "reason",
    "schemaVersion",
    "status",
  ], "candidate result");
  requireExactObjectKeys(manifest, [
    "baseSha",
    "draftSha256",
    "files",
    "fingerprint",
    "index",
    "queueSha256",
    "schemaVersion",
    "seal",
    "status",
  ], "candidate result manifest");
  requireExactObjectKeys(
    manifest.seal,
    ["algorithm", "kind", "payloadSha256"],
    "candidate result seal",
  );
  if (result.schemaVersion !== RESULT_SCHEMA_VERSION ||
      manifest.schemaVersion !== RESULT_SCHEMA_VERSION ||
      !RESULT_STATUSES.has(result.status)) {
    fail(`invalid result envelope for ${candidate.fingerprint}`);
  }
  if (result.baseSha !== queueVerification.queue.baseSha ||
      result.queueSha256 !== queueVerification.queueSha256 ||
      result.fingerprint !== candidate.fingerprint ||
      result.index !== candidate.index ||
      result.draftSha256 !== candidate.draftSha256) {
    fail(`candidate result binding mismatch: ${candidate.fingerprint}`);
  }
  if (!Array.isArray(manifest.files)) fail("candidate result manifest has no file list");
  const expectedFiles = [
    "result-manifest.json",
    ...manifest.files.map((entry) => entry.path),
  ];
  requireExactFiles(root, expectedFiles);
  for (const entry of manifest.files) {
    if (!SHA256_PATTERN.test(entry.sha256) || !Number.isSafeInteger(entry.bytes) ||
        entry.bytes < 0) {
      fail("candidate result manifest contains invalid file metadata");
    }
    const absolute = resolveInside(root, entry.path);
    if (fs.statSync(absolute).size !== entry.bytes || sha256File(absolute) !== entry.sha256) {
      fail(`candidate result file digest mismatch: ${entry.path}`);
    }
  }
  const payload = resultSealPayload(result, manifest.files);
  if (manifest.baseSha !== payload.baseSha ||
      manifest.draftSha256 !== payload.draftSha256 ||
      manifest.fingerprint !== payload.fingerprint ||
      manifest.index !== payload.index ||
      manifest.queueSha256 !== payload.queueSha256 ||
      manifest.status !== payload.status ||
      manifest.seal?.kind !== "digest-bound" ||
      manifest.seal?.algorithm !== "sha256" ||
      manifest.seal?.payloadSha256 !== sha256Bytes(canonicalJson(payload))) {
    fail(`candidate result digest-bound seal mismatch: ${candidate.fingerprint}`);
  }
  if (result.status === "proven") {
    verifyProvenPayload(root, candidate);
  } else if (fs.existsSync(path.join(root, "release"))) {
    fail("a non-proven result carries release bytes");
  }
  return { manifest, result, root };
}

function promotionSealPayload(manifest) {
  return {
    baseSha: manifest.baseSha,
    files: manifest.files,
    queueSha256: manifest.queueSha256,
    selectedFingerprint: manifest.selectedFingerprint,
  };
}

function writePromotionManifest(promotionRoot, selection) {
  const files = listFiles(promotionRoot).map((relative) => {
    const absolute = resolveInside(promotionRoot, relative);
    return {
      bytes: fs.statSync(absolute).size,
      path: relative,
      sha256: sha256File(absolute),
    };
  });
  const payload = {
    baseSha: selection.baseSha,
    files,
    queueSha256: selection.queueSha256,
    selectedFingerprint: selection.selectedFingerprint,
  };
  writeJson(path.join(promotionRoot, "promotion-manifest.json"), {
    schemaVersion: PROMOTION_SCHEMA_VERSION,
    ...payload,
    seal: {
      kind: "digest-bound",
      algorithm: "sha256",
      payloadSha256: sha256Bytes(canonicalJson(payload)),
    },
  });
}

function aggregateResults(values) {
  const queueRoot = required(values, "queue-root");
  const resultsRoot = path.resolve(required(values, "results-root"));
  const outputPath = required(values, "output-dir");
  const summaryPath = required(values, "summary-file");
  const expectedBaseSha = required(values, "expected-base-sha").toLowerCase();
  const expectedQueueSha256 = required(values, "expected-queue-sha256");
  const artifactPrefix = required(values, "artifact-prefix");
  const githubOutput = values.get("github-output");
  if (!/^[A-Za-z0-9._-]+$/.test(artifactPrefix)) fail("invalid result artifact prefix");
  if (!SHA256_PATTERN.test(expectedQueueSha256)) fail("invalid expected queue digest");
  const queueVerification = verifyQueue(
    queueRoot,
    expectedBaseSha,
    expectedQueueSha256,
  );
  if (queueVerification.queue.candidates.length === 0) {
    fail("cannot aggregate an empty candidate queue");
  }
  if (!fs.existsSync(resultsRoot)) fs.mkdirSync(resultsRoot, { recursive: true });
  const actualEntries = fs.readdirSync(resultsRoot, { withFileTypes: true });
  for (const entry of actualEntries) {
    if (!entry.isDirectory() || entry.isSymbolicLink()) {
      fail(`unexpected result artifact entry: ${entry.name}`);
    }
  }
  const expectedNames = queueVerification.queue.batch.candidateIndexes.map(
    (index) =>
      `${artifactPrefix}${queueVerification.queue.candidates[index].fingerprint}`,
  ).sort();
  const actualNames = actualEntries.map((entry) => entry.name).sort();
  const expectedNameSet = new Set(expectedNames);
  const unexpectedNames = actualNames.filter((name) => !expectedNameSet.has(name));
  if (unexpectedNames.length > 0) {
    fail(
      `candidate result artifact set mismatch; unexpected=${unexpectedNames.join(",")}`,
    );
  }
  const actualNameSet = new Set(actualNames);
  const verifiedResults = queueVerification.queue.candidates.map((candidate) => {
    const artifactName = `${artifactPrefix}${candidate.fingerprint}`;
    if (actualNameSet.has(artifactName)) {
      return verifyResult(
        path.join(resultsRoot, artifactName),
        queueVerification,
        candidate,
      );
    }
    return {
      manifest: null,
      result: {
        schemaVersion: RESULT_SCHEMA_VERSION,
        baseSha: queueVerification.queue.baseSha,
        draftSha256: candidate.draftSha256,
        fingerprint: candidate.fingerprint,
        index: candidate.index,
        queueSha256: queueVerification.queueSha256,
        reason: "candidate result artifact was not uploaded",
        status: SYNTHETIC_MISSING_STATUS,
      },
      root: null,
      synthetic: true,
    };
  });
  const selectedIndex = verifiedResults.findIndex(
    (verified) => verified.result.status === "proven",
  );
  const summary = {
    schemaVersion: 1,
    baseSha: queueVerification.queue.baseSha,
    queueSha256: queueVerification.queueSha256,
    results: verifiedResults.map(({ result }) => ({
      draftSha256: result.draftSha256,
      fingerprint: result.fingerprint,
      index: result.index,
      reason: result.reason,
      status: result.status,
      synthetic: result.status === SYNTHETIC_MISSING_STATUS,
    })),
    selectedFingerprint:
      selectedIndex === -1 ? null : verifiedResults[selectedIndex].result.fingerprint,
  };
  writeJson(summaryPath, summary);
  if (selectedIndex === -1) {
    appendGithubOutput(githubOutput, { candidate_ready: "false" });
    process.stdout.write("No independently proven candidate was selected.\n");
    return;
  }
  const selected = verifiedResults[selectedIndex];
  const selection = {
    schemaVersion: 1,
    baseSha: queueVerification.queue.baseSha,
    draftSha256: selected.result.draftSha256,
    queueSha256: queueVerification.queueSha256,
    selectedFingerprint: selected.result.fingerprint,
    selectedIndex: selected.result.index,
  };
  createDirectoryAtomically(outputPath, (temporary) => {
    fs.cpSync(path.join(selected.root, "release"), path.join(temporary, "release"), {
      errorOnExist: true,
      recursive: true,
    });
    fs.cpSync(path.join(selected.root, "proof"), path.join(temporary, "proof"), {
      errorOnExist: true,
      recursive: true,
    });
    copyFile(
      path.join(queueRoot, "base-audit-report.json"),
      path.join(temporary, "proof", "base-audit-report.json"),
    );
    writeText(
      path.join(temporary, "proof", "base-commit.txt"),
      `${queueVerification.queue.baseSha}\n`,
    );
    writeText(
      path.join(temporary, "proof", "base-audit-report.sha256"),
      `${queueVerification.queue.auditReport.sha256}  base-audit-report.json\n`,
    );
    copyFile(
      path.join(selected.root, "result.json"),
      path.join(temporary, "proof", "candidate-result.json"),
    );
    copyFile(
      path.join(selected.root, "result-manifest.json"),
      path.join(temporary, "proof", "candidate-result-manifest.json"),
    );
    copyFile(
      path.join(queueRoot, "queue.json"),
      path.join(temporary, "proof", "candidate-queue.json"),
    );
    copyFile(
      path.join(queueRoot, "queue-manifest.json"),
      path.join(temporary, "proof", "candidate-queue-manifest.json"),
    );
    writeJson(path.join(temporary, "proof", "promotion-selection.json"), selection);
    writePromotionManifest(temporary, selection);
  });
  appendGithubOutput(githubOutput, {
    candidate_ready: "true",
    selected_fingerprint: selected.result.fingerprint,
  });
  process.stdout.write(
    `SELECTED canonical proven candidate ${selected.result.fingerprint}\n`,
  );
}

function verifyPromotion(values) {
  const root = path.resolve(required(values, "promotion-root"));
  const expectedBaseSha = required(values, "expected-base-sha").toLowerCase();
  const expectedQueueSha256 = required(values, "expected-queue-sha256");
  const manifestPath = path.join(root, "promotion-manifest.json");
  const manifest = readJson(manifestPath);
  requireExactObjectKeys(manifest, [
    "baseSha",
    "files",
    "queueSha256",
    "schemaVersion",
    "seal",
    "selectedFingerprint",
  ], "promotion manifest");
  requireExactObjectKeys(
    manifest.seal,
    ["algorithm", "kind", "payloadSha256"],
    "promotion seal",
  );
  if (!SHA256_PATTERN.test(expectedQueueSha256) ||
      manifest.schemaVersion !== PROMOTION_SCHEMA_VERSION ||
      manifest.baseSha !== expectedBaseSha ||
      !FINGERPRINT_PATTERN.test(manifest.selectedFingerprint) ||
      manifest.queueSha256 !== expectedQueueSha256 || !Array.isArray(manifest.files)) {
    fail("invalid promotion manifest binding");
  }
  requireExactFiles(root, [
    "promotion-manifest.json",
    ...manifest.files.map((entry) => entry.path),
  ]);
  for (const entry of manifest.files) {
    const absolute = resolveInside(root, entry.path);
    if (fs.statSync(absolute).size !== entry.bytes || sha256File(absolute) !== entry.sha256) {
      fail(`promotion artifact digest mismatch: ${entry.path}`);
    }
  }
  const payload = promotionSealPayload(manifest);
  if (manifest.seal?.kind !== "digest-bound" ||
      manifest.seal?.algorithm !== "sha256" ||
      manifest.seal?.payloadSha256 !== sha256Bytes(canonicalJson(payload))) {
    fail("promotion artifact digest-bound seal mismatch");
  }
  const selection = readJson(path.join(root, "proof", "promotion-selection.json"));
  const queue = readJson(path.join(root, "proof", "candidate-queue.json"));
  const queueManifest = readJson(
    path.join(root, "proof", "candidate-queue-manifest.json"),
  );
  const result = readJson(path.join(root, "proof", "candidate-result.json"));
  if (selection.baseSha !== expectedBaseSha ||
      selection.queueSha256 !== manifest.queueSha256 ||
      selection.selectedFingerprint !== manifest.selectedFingerprint ||
      queue.baseSha !== expectedBaseSha ||
      sha256File(path.join(root, "proof", "candidate-queue.json")) !==
        expectedQueueSha256 ||
      queueManifest.sealedQueueSha256 !== manifest.queueSha256 ||
      result.status !== "proven" ||
      result.fingerprint !== manifest.selectedFingerprint ||
      result.queueSha256 !== manifest.queueSha256) {
    fail("promotion provenance chain mismatch");
  }
  process.stdout.write(
    `VERIFIED promotion ${manifest.selectedFingerprint} from ${expectedBaseSha}\n`,
  );
}

function printUsage() {
  process.stdout.write(`Candidate queue workflow helper\n\n`);
  process.stdout.write(`Commands:\n`);
  process.stdout.write(`  create-queue       Freeze ordered drafts and their immutable audit base\n`);
  process.stdout.write(`  prepare-candidate  Verify and extract one sealed matrix tuple\n`);
  process.stdout.write(`  collect-evidence   Copy bounded JSON/hash evidence only\n`);
  process.stdout.write(`  cap-screenshots    Copy a deterministic bounded PNG subset\n`);
  process.stdout.write(`  seal-result        Bind one isolated proof result to the sealed queue\n`);
  process.stdout.write(`  aggregate-results  Verify the exact matrix result set and select one\n`);
  process.stdout.write(`  verify-promotion   Verify the selected promotion provenance and bytes\n`);
}

function main() {
  const { command, values } = parseArguments(process.argv.slice(2));
  switch (command) {
    case "create-queue":
      createQueue(values);
      break;
    case "prepare-candidate":
      prepareCandidate(values);
      break;
    case "collect-evidence":
      collectEvidence(values);
      break;
    case "cap-screenshots":
      capScreenshots(values);
      break;
    case "seal-result":
      sealResult(values);
      break;
    case "aggregate-results":
      aggregateResults(values);
      break;
    case "verify-promotion":
      verifyPromotion(values);
      break;
    case "help":
      printUsage();
      break;
    default:
      fail(`unknown command: ${command}`);
  }
}

try {
  main();
} catch (error) {
  process.stderr.write(`candidate-queue: ${error.message}\n`);
  process.exitCode = 1;
}

export {
  MAX_MATRIX_CANDIDATES,
  MATRIX_BATCH_SIZE,
  aggregateResults,
  canonicalJson,
  capScreenshots,
  createQueue,
  sealResult,
  verifyPromotion,
  verifyQueue,
};
