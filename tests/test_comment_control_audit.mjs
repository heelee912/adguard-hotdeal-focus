import assert from "node:assert/strict";

import {
  commentControlProjectionFailures,
  commentControlSelectorDigest,
  commentControlSelectorDigestsForUrl,
} from "../scripts/audit_pages.mjs";

const selectors = [".more-comments", ".reply-toggle"];
const selectorDigest = commentControlSelectorDigest(selectors);
const emptySelectorDigest = commentControlSelectorDigest([]);
const initialShape = "comment-control-shape-v1-0123abcd";

function gateWith(overrides = {}) {
  const projection = {
    selectors,
    count: 1,
    initiallyDormantCount: 0,
    initialShapeFingerprint: initialShape,
    selectorDigest,
    projectionEpoch: 0,
    currentCount: 1,
    currentShapeFingerprint: initialShape,
    currentDormantApprovedCount: 0,
    currentProjectionValid: true,
    ...(overrides.projection ?? {}),
  };
  projection.initiallyVisibleCount ??=
    projection.count - projection.initiallyDormantCount;
  projection.currentVisibleCount ??=
    projection.currentCount - projection.currentDormantApprovedCount;
  return {
    commentControlStats: {
      count: projection.currentCount,
      visibleCount: projection.currentCount - projection.currentDormantApprovedCount,
      allKept: true,
      ...(overrides.stats ?? {}),
    },
    commentControlProjection: projection,
    allowedCommentControlSelectorDigests: [selectorDigest],
    ...(overrides.gate ?? {}),
  };
}

assert.deepEqual(
  commentControlSelectorDigest([...selectors].reverse()),
  selectorDigest,
  "selector digest must be stable across configured order",
);

const layout = {
  paths: ["|/deal/"],
  comment_contract: { controls: selectors },
  variants: [
    {
      paths: ["|/new/*^"],
      comment_contract: { controls: ["button.load-next"] },
    },
  ],
};
assert.deepEqual(
  commentControlSelectorDigestsForUrl(layout, "https://example.test/deal/123"),
  [selectorDigest],
  "base route must bind the exact base comment-control contract",
);
assert.deepEqual(
  commentControlSelectorDigestsForUrl(layout, "https://example.test/new/123"),
  [commentControlSelectorDigest(["button.load-next"])],
  "variant route must bind the exact variant comment-control contract",
);
assert.deepEqual(
  commentControlSelectorDigestsForUrl(layout, "https://example.test/unknown/123"),
  [],
  "an unknown route must not inherit a comment-control selector digest",
);

assert.deepEqual(
  commentControlProjectionFailures(gateWith()),
  [],
  "one visible exact control must pass",
);
assert.deepEqual(
  commentControlProjectionFailures(gateWith({
    projection: {
      selectors: [],
      selectorDigest: emptySelectorDigest,
      count: 0,
      currentCount: 0,
    },
    gate: { allowedCommentControlSelectorDigests: [emptySelectorDigest] },
  })),
  [],
  "a canonical empty selector contract with its exact digest must pass",
);
assert.deepEqual(
  commentControlProjectionFailures(gateWith({
    projection: {
      initiallyDormantCount: 1,
      currentDormantApprovedCount: 1,
    },
  })),
  [],
  "one initially approved dormant control must pass without becoming visible",
);
assert.deepEqual(
  commentControlProjectionFailures(gateWith({
    projection: {
      initiallyDormantCount: 1,
      projectionEpoch: 1,
      currentDormantApprovedCount: 0,
    },
  })),
  [],
  "an approved dormant control activation must pass only with a new epoch",
);
assert.deepEqual(
  commentControlProjectionFailures(gateWith({
    projection: {
      projectionEpoch: 1,
      currentCount: 2,
      currentShapeFingerprint: "comment-control-shape-v1-fedcba98",
    },
  })),
  [],
  "an exact dynamic control addition must pass with updated evidence",
);

assert.ok(
  commentControlProjectionFailures(gateWith({
    stats: { visibleCount: 0 },
  })).some((failure) => failure.includes("visible count differs")),
  "an unapproved hidden control must fail",
);
assert.ok(
  commentControlProjectionFailures(gateWith({
    projection: { selectors: ".more-comments" },
  })).some((failure) => failure.includes("array of strings")),
  "a scalar selector projection must fail",
);
assert.ok(
  commentControlProjectionFailures(gateWith({
    projection: { selectors: [".more-comments", 7] },
  })).some((failure) => failure.includes("array of strings")),
  "a non-string selector projection member must fail",
);
assert.ok(
  commentControlProjectionFailures(gateWith({
    projection: { selectors: [".more-comments", ".more-comments"] },
  })).some((failure) => failure.includes("duplicate")),
  "a duplicate selector projection must fail",
);
assert.ok(
  commentControlProjectionFailures(gateWith({
    projection: { selectors: [...selectors].reverse() },
  })).some((failure) => failure.includes("canonical sorted")),
  "an unsorted selector projection must fail",
);
assert.ok(
  commentControlProjectionFailures(gateWith({
    projection: { selectors: [".different-control"] },
  })).some((failure) => failure.includes("does not match its selectors")),
  "a selector projection bound to another digest must fail",
);
assert.ok(
  commentControlProjectionFailures(gateWith({
    projection: { initiallyVisibleCount: 0 },
  })).some((failure) => failure.includes("initial visible and dormant counts")),
  "forged initial visibility arithmetic must fail",
);
assert.ok(
  commentControlProjectionFailures(gateWith({
    projection: { currentVisibleCount: 0 },
  })).some((failure) => failure.includes("current visible and dormant counts")),
  "forged current visibility arithmetic must fail",
);
assert.ok(
  commentControlProjectionFailures(gateWith({
    gate: { allowedCommentControlSelectorDigests: ["comment-control-selectors-v1-deadbeef"] },
  })).some((failure) => failure.includes("exact route contract")),
  "a selector digest from another route must fail",
);
assert.ok(
  commentControlProjectionFailures(gateWith({
    projection: {
      currentCount: 2,
      currentShapeFingerprint: "comment-control-shape-v1-fedcba98",
    },
  })).some((failure) => failure.includes("without a projection epoch")),
  "a zero-epoch structural change must fail",
);
assert.ok(
  commentControlProjectionFailures(gateWith({
    projection: { currentProjectionValid: false },
  })).some((failure) => failure.includes("not exact and approved")),
  "runtime rejection must remain terminal audit evidence",
);

process.stdout.write("comment-control projection audit: exact visible/dormant/dynamic contracts passed\n");
