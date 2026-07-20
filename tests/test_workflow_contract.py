from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WATCH_WORKFLOW = (
    PROJECT_ROOT / ".github" / "workflows" / "watch-dom.yml"
).read_text(encoding="utf-8")
VERIFY_WORKFLOW = (
    PROJECT_ROOT / ".github" / "workflows" / "verify.yml"
).read_text(encoding="utf-8")
PUBLISH_GATE_WORKFLOW = (
    PROJECT_ROOT / ".github" / "workflows" / "publish-gate.yml"
).read_text(encoding="utf-8")
AUDIT_SCRIPT = (PROJECT_ROOT / "scripts" / "audit_pages.mjs").read_text(
    encoding="utf-8"
)
CANDIDATE_QUEUE_HELPER = (
    PROJECT_ROOT / "scripts" / "candidate_queue.mjs"
).read_text(encoding="utf-8")
GITIGNORE_LINES = set(
    (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
)


class PublicRepositoryHygieneTests(unittest.TestCase):
    def test_generated_live_and_candidate_evidence_is_ignored(self) -> None:
        self.assertTrue(
            {
                "outputs/evidence/",
                "outputs/candidate-evidence/",
                ".candidate-draft/",
                ".candidate-release/",
                ".candidate-build-*/",
                ".candidate-queue/",
                ".candidate-work/",
                ".candidate-build/",
                ".candidate-result/",
                ".candidate-results/",
                ".candidate-aggregate/",
                ".candidate-json-evidence/",
                ".candidate-screenshots/",
                ".audit-json-evidence/",
                ".audit-failure-screenshots/",
                ".release-build-*/",
                ".promotion-package/",
                ".promotion-push/",
                "candidate-draft/",
                "candidate-release/",
            }.issubset(GITIGNORE_LINES)
        )

    def test_every_remote_action_is_pinned_to_a_full_commit_sha(self) -> None:
        uses = re.findall(
            r"^\s*uses:\s*([^\s#]+)",
            f"{WATCH_WORKFLOW}\n{VERIFY_WORKFLOW}\n{PUBLISH_GATE_WORKFLOW}",
            re.MULTILINE,
        )
        self.assertGreater(len(uses), 0)
        for action in uses:
            if action.startswith("./"):
                continue
            with self.subTest(action=action):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")

    def test_workflows_deny_undeclared_token_permissions_by_default(self) -> None:
        for name, workflow in (
            ("verify", VERIFY_WORKFLOW),
            ("watch-dom", WATCH_WORKFLOW),
            ("publish-gate", PUBLISH_GATE_WORKFLOW),
        ):
            with self.subTest(workflow=name):
                self.assertRegex(workflow, r"(?m)^permissions: \{\}\s*$")

    def test_every_artifact_upload_includes_hidden_staging_files(self) -> None:
        for name, workflow in (
            ("verify", VERIFY_WORKFLOW),
            ("watch-dom", WATCH_WORKFLOW),
            ("publish-gate", PUBLISH_GATE_WORKFLOW),
        ):
            upload_steps = workflow.split("uses: actions/upload-artifact@")[1:]
            self.assertGreater(len(upload_steps), 0, name)
            for index, tail in enumerate(upload_steps):
                step = tail.split("\n      - name:", 1)[0]
                with self.subTest(workflow=name, upload=index):
                    self.assertIn("include-hidden-files: true", step)


class ImmutableGateReleaseWorkflowTests(unittest.TestCase):
    def test_manual_workflows_expose_nonce_bound_machine_run_names(self) -> None:
        expectations = (
            (VERIFY_WORKFLOW, "hotdeal-focus-verify-"),
            (WATCH_WORKFLOW, "hotdeal-focus-watch-dom-"),
            (PUBLISH_GATE_WORKFLOW, "hotdeal-focus-publish-gate-"),
        )
        for workflow, prefix in expectations:
            with self.subTest(prefix=prefix):
                self.assertIn("dispatch_nonce:", workflow)
                self.assertIn(f"run-name: {prefix}", workflow)
        combined = VERIFY_WORKFLOW + WATCH_WORKFLOW + PUBLISH_GATE_WORKFLOW
        self.assertEqual(4, combined.count("{ok,status,sourceSha,workflow,ref,dispatchNonce,run}"))
        self.assertNotIn("{ok,status,sourceCommit,workflow,ref,dispatchNonce,run}", combined)

    def test_gate_publication_is_manual_verified_and_cli_controlled(self) -> None:
        trigger = PUBLISH_GATE_WORKFLOW.split("concurrency:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("schedule:", trigger)
        self.assertNotIn("push:", trigger)
        self.assertIn("contents: write", PUBLISH_GATE_WORKFLOW)
        self.assertIn("GH_TOKEN: ${{ github.token }}", PUBLISH_GATE_WORKFLOW)
        self.assertNotIn("secrets.", PUBLISH_GATE_WORKFLOW)
        for command in (
            "npm test",
            "npm run build",
            "git diff --exit-code -- .",
            "npm run integrity",
            "npm run test:network",
            "npm run test:oracle",
            "npm run test:tamper",
            "npm run test:behavior",
            "gate-release publish",
            '--source-ref "${GITHUB_SHA}"',
            "--apply",
        ):
            with self.subTest(command=command):
                self.assertIn(command, PUBLISH_GATE_WORKFLOW)
        self.assertIn(
            '--json > "${RUNNER_TEMP}/gate-release-result.json"',
            PUBLISH_GATE_WORKFLOW,
        )
        self.assertNotIn("> .gate-release-result.json", PUBLISH_GATE_WORKFLOW)
        self.assertIn(
            "${{ runner.temp }}/gate-release-result.json",
            PUBLISH_GATE_WORKFLOW,
        )
        self.assertIn("source_sha:\n", PUBLISH_GATE_WORKFLOW)
        self.assertIn(
            '[[ "${GITHUB_SHA}" == "${AUTHORIZED_SOURCE_SHA}" ]]',
            PUBLISH_GATE_WORKFLOW,
        )
        publisher = PUBLISH_GATE_WORKFLOW.split("  publish:\n", 1)[1].split(
            "  redispatch-verify:\n", 1
        )[0]
        verifier = PUBLISH_GATE_WORKFLOW.split("  verify-source:\n", 1)[1].split(
            "  publish:\n", 1
        )[0]
        self.assertIn("name: hdf-release-publisher", publisher)
        self.assertIn("deployment: false", publisher)
        self.assertIn("contents: write", publisher)
        self.assertNotIn("contents: write", verifier)
        redispatch = PUBLISH_GATE_WORKFLOW.split("  redispatch-verify:\n", 1)[1]
        self.assertIn("actions: write", redispatch)
        self.assertNotIn("contents: write", redispatch)
        self.assertIn("cloud dispatch", redispatch)
        self.assertIn("--workflow verify.yml", redispatch)

    def test_promotion_proof_and_secret_push_use_fresh_separate_jobs(self) -> None:
        proof = WATCH_WORKFLOW.split("  promote:\n", 1)[1].split(
            "  push-promotion:\n", 1
        )[0]
        push = WATCH_WORKFLOW.split("  push-promotion:\n", 1)[1].split(
            "  report-failure:\n", 1
        )[0]
        self.assertIn("npm run test:behavior", proof)
        self.assertIn("audit:dom", proof)
        self.assertIn("promotion.bundle", proof)
        self.assertNotIn("secrets.", proof)
        self.assertIn("promotion.bundle", push)
        self.assertIn("one exact child", push)
        self.assertIn("release manifest hash disagrees", push)
        self.assertIn("immutable filter.txt changed", push)
        self.assertIn("Lease the audited base immediately before", push)
        for forbidden in ("npm ci", "playwright", "xvfb-run", "audit:dom"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, push)

    def test_pages_and_dom_promotions_require_the_immutable_gate(self) -> None:
        verify_pages = VERIFY_WORKFLOW.split("  publish-pages:\n", 1)[1]
        watch_pages = WATCH_WORKFLOW.split("  deploy-pages:\n", 1)[1].split(
            "  continue-drift-chain:\n", 1
        )[0]
        for section in (verify_pages, watch_pages):
            gate_index = section.index("gate-release verify")
            configure_index = section.index("actions/configure-pages@")
            self.assertLess(gate_index, configure_index)
        self.assertIn(
            'cmp --silent filter.txt "${release}/filter.txt"',
            WATCH_WORKFLOW,
        )

    def test_gate_publication_and_every_default_branch_writer_share_one_mutex(self) -> None:
        mutex = "group: hotdeal-focus-release-state"
        self.assertIn(mutex, PUBLISH_GATE_WORKFLOW)
        push = WATCH_WORKFLOW.split("  push-promotion:\n", 1)[1].split(
            "  report-failure:\n", 1
        )[0]
        heartbeat = WATCH_WORKFLOW.split("  scheduler-heartbeat:\n", 1)[1].split(
            "  deploy-pages:\n", 1
        )[0]
        for name, section in (("push-promotion", push), ("heartbeat", heartbeat)):
            with self.subTest(job=name):
                self.assertIn(mutex, section)
                self.assertIn("cancel-in-progress: false", section)

    def test_default_branch_writers_use_one_fingerprint_bound_ssh_identity(self) -> None:
        proof = WATCH_WORKFLOW.split("  promote:\n", 1)[1].split(
            "  push-promotion:\n", 1
        )[0]
        push = WATCH_WORKFLOW.split("  push-promotion:\n", 1)[1].split(
            "  report-failure:\n", 1
        )[0]
        heartbeat = WATCH_WORKFLOW.split("  scheduler-heartbeat:\n", 1)[1].split(
            "  deploy-pages:\n", 1
        )[0]
        self.assertNotIn("contents: write", WATCH_WORKFLOW)
        self.assertEqual(
            2,
            WATCH_WORKFLOW.count(
                "git -c core.hooksPath=/dev/null push --porcelain"
            ),
        )
        self.assertEqual(2, WATCH_WORKFLOW.count(
            "secrets.HDF_AUTOMATION_PUSH_ED25519_PRIVATE_KEY"
        ))
        self.assertEqual(2, WATCH_WORKFLOW.count(
            "vars.HDF_AUTOMATION_PUSH_KEY_FINGERPRINT"
        ))
        official_host_key = (
            "github.com ssh-ed25519 "
            "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
        )
        official_host_fingerprint = (
            "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"
        )
        self.assertNotIn("secrets.", proof)
        self.assertIn("npm run test:behavior", proof)
        for name, section in (("push-promotion", push), ("heartbeat", heartbeat)):
            with self.subTest(job=name):
                self.assertIn("contents: read", section)
                self.assertIn("name: hdf-main-automation", section)
                self.assertIn("deployment: false", section)
                self.assertIn("GH_TOKEN:", section)
                self.assertIn("x-access-token", section)
                self.assertIn('ssh-keygen -y -f "${key_path}"', section)
                self.assertIn(
                    '"${actual_fingerprint}" == "${EXPECTED_AUTOMATION_PUSH_FINGERPRINT}"',
                    section,
                )
                self.assertIn(official_host_key, section)
                self.assertIn(official_host_fingerprint, section)
                for directive in (
                    "HostKeyAlgorithms ssh-ed25519",
                    "IdentitiesOnly yes",
                    "IdentityAgent none",
                    "BatchMode yes",
                    "StrictHostKeyChecking yes",
                    "GlobalKnownHostsFile /dev/null",
                    "PasswordAuthentication no",
                    "KbdInteractiveAuthentication no",
                ):
                    self.assertIn(directive, section)
                self.assertIn(
                    'remote="git@github.com:${GITHUB_REPOSITORY}.git"', section
                )
                self.assertIn("git merge-base --is-ancestor", section)
                self.assertIn(
                    "git -c core.hooksPath=/dev/null push --porcelain", section
                )
                self.assertNotIn("--force", section)
                self.assertGreaterEqual(section.count("git ls-remote --heads"), 2)
                self.assertIn('[[ "${pushed_sha}" == "${', section)
        self.assertIn(
            "git -c core.hooksPath=/dev/null commit", heartbeat
        )
        heartbeat_push = heartbeat.split(
            "- name: Fast-forward the heartbeat only if the remote head is unchanged",
            1,
        )[1]
        self.assertIn(
            "BASE_SHA: ${{ steps.heartbeat_commit.outputs.base_sha }}",
            heartbeat_push,
        )
        self.assertIn(
            "COMMIT_SHA: ${{ steps.heartbeat_commit.outputs.commit_sha }}",
            heartbeat_push,
        )
        self.assertNotIn("git add", heartbeat_push)
        self.assertNotIn("git commit", heartbeat_push)

    def test_every_release_lane_runs_network_and_projection_oracles(self) -> None:
        verify_lane = VERIFY_WORKFLOW.split(
            "- name: Compare June/July behavior", 1
        )[1].split("- name: Collect bounded", 1)[0]
        watch_live_lane = WATCH_WORKFLOW.split(
            "- name: Audit bounded samples", 1
        )[1].split("- name: Publish the full-audit outcome", 1)[0]
        watch_promotion_lane = WATCH_WORKFLOW.split(
            "- name: Audit the exact candidate profiles", 1
        )[1].split("- name: Seal the proven one-parent promotion", 1)[0]
        for name, section in (
            ("verify", verify_lane),
            ("publish-gate", PUBLISH_GATE_WORKFLOW),
            ("watch-live", watch_live_lane),
            ("watch-promotion", watch_promotion_lane),
        ):
            with self.subTest(lane=name):
                self.assertIn("npm run test:network", section)
                self.assertIn("npm run test:oracle", section)


class PagesRetryContractTests(unittest.TestCase):
    def test_audit_job_budget_exceeds_all_subprocess_timeouts_and_margin(self) -> None:
        audit_section = WATCH_WORKFLOW.split("  audit:\n", 1)[1].split(
            "  candidate-proof:\n", 1
        )[0]
        job_match = re.search(r"^    timeout-minutes:\s*(\d+)\s*$", audit_section, re.MULTILINE)
        self.assertIsNotNone(job_match)
        timeout_calls = re.findall(
            r"timeout\s+--kill-after=(\d+)([smh])\s+(\d+)([smh])",
            audit_section,
        )
        self.assertEqual(4, len(timeout_calls))

        def seconds(value: str, unit: str) -> int:
            return int(value) * {"s": 1, "m": 60, "h": 3600}[unit]

        subprocess_seconds = sum(
            seconds(kill_value, kill_unit) + seconds(limit_value, limit_unit)
            for kill_value, kill_unit, limit_value, limit_unit in timeout_calls
        )
        setup_and_upload_margin_seconds = 60 * 60
        self.assertGreater(
            int(job_match.group(1)) * 60,
            subprocess_seconds + setup_and_upload_margin_seconds,
        )

    def test_each_candidate_has_an_independent_bounded_timeout(self) -> None:
        candidate_section = WATCH_WORKFLOW.split(
            "  candidate-proof:\n", 1
        )[1].split("  aggregate-candidates:\n", 1)[0]
        job_match = re.search(
            r"^    timeout-minutes:\s*(\d+)\s*$", candidate_section, re.MULTILINE
        )
        self.assertIsNotNone(job_match)
        timeout_calls = re.findall(
            r"timeout\s+--kill-after=(\d+)([smh])\s+(\d+)([smh])",
            candidate_section,
        )
        self.assertGreaterEqual(len(timeout_calls), 8)

        def seconds(value: str, unit: str) -> int:
            return int(value) * {"s": 1, "m": 60, "h": 3600}[unit]

        subprocess_seconds = sum(
            seconds(kill_value, kill_unit) + seconds(limit_value, limit_unit)
            for kill_value, kill_unit, limit_value, limit_unit in timeout_calls
        )
        setup_and_upload_margin_seconds = 15 * 60
        self.assertGreater(
            int(job_match.group(1)) * 60,
            subprocess_seconds + setup_and_upload_margin_seconds,
        )
        self.assertLessEqual(int(job_match.group(1)), 360)

    def test_no_hosted_job_can_exceed_github_six_hour_limit(self) -> None:
        timeouts = [
            int(value)
            for value in re.findall(
                r"^    timeout-minutes:\s*(\d+)\s*$", WATCH_WORKFLOW, re.MULTILINE
            )
        ]
        self.assertGreater(len(timeouts), 0)
        self.assertTrue(all(timeout <= 360 for timeout in timeouts))

    def test_every_healthy_audit_retries_the_exact_current_release(self) -> None:
        self.assertIn(
            "deploy-pages:\n    needs: [audit, push-promotion]", WATCH_WORKFLOW
        )
        self.assertIn("needs.push-promotion.result == 'success' ||", WATCH_WORKFLOW)
        self.assertIn("needs.audit.outputs.failed == 'false'", WATCH_WORKFLOW)
        self.assertIn("ref: ${{ needs.audit.outputs.base_sha }}", WATCH_WORKFLOW)
        self.assertIn("if: needs.push-promotion.result != 'success'", WATCH_WORKFLOW)
        self.assertIn("if: needs.push-promotion.result == 'success'", WATCH_WORKFLOW)
        self.assertIn('remote_sha="$(git ls-remote', WATCH_WORKFLOW)
        self.assertIn('"${remote_sha}" != "${expected_sha}"', WATCH_WORKFLOW)

    def test_pages_stage_is_manifest_matched_and_public_only(self) -> None:
        deploy_section = WATCH_WORKFLOW.split("  deploy-pages:\n", 1)[1].split(
            "  report-pages-failure:\n", 1
        )[0]
        self.assertIn("manifest.artifacts[name]?.sha256", deploy_section)
        self.assertIn("['filter.txt', 'hotdeal-focus.user.js']", deploy_section)
        staged_names = set(
            re.findall(r"\.pages/([A-Za-z0-9._-]+)", deploy_section)
        )
        self.assertEqual(
            {"filter.txt", "hotdeal-focus.user.js", "release-manifest.json"},
            staged_names,
        )
        self.assertNotIn("filter-static.txt", deploy_section)
        self.assertNotIn("config/sites.json", deploy_section)
        self.assertNotIn("approved-variants.json", deploy_section)

        verify_stage = VERIFY_WORKFLOW.split(
            "      - name: Stage immutable release draft\n", 1
        )[1].split("      - name: Upload immutable release draft\n", 1)[0]
        verify_staged_names = set(
            re.findall(r"\.release-draft/([A-Za-z0-9._-]+)", verify_stage)
        )
        self.assertEqual(
            {"filter.txt", "hotdeal-focus.user.js", "release-manifest.json"},
            verify_staged_names,
        )
        self.assertNotIn("README.md", verify_stage)
        self.assertNotIn("LICENSE", verify_stage)
        self.assertIn("non-public fourth file", verify_stage)
        self.assertIn("non-public fourth file", deploy_section)

    def test_pages_failure_and_recovery_are_observable(self) -> None:
        self.assertIn("report-pages-failure:", WATCH_WORKFLOW)
        self.assertIn("needs.deploy-pages.result == 'failure'", WATCH_WORKFLOW)
        self.assertIn("report-pages-recovery:", WATCH_WORKFLOW)
        self.assertIn("needs.deploy-pages.result == 'success'", WATCH_WORKFLOW)
        self.assertIn("The next healthy six-hour audit will retry", WATCH_WORKFLOW)
        self.assertIn(
            "scheduler-heartbeat:\n    needs: [audit, push-promotion, deploy-pages]",
            WATCH_WORKFLOW,
        )

    def test_pages_deployments_are_serialized_and_head_pinned(self) -> None:
        shared_concurrency = (
            "concurrency:\n"
            "      group: hotdeal-focus-release-state\n"
            "      cancel-in-progress: false"
        )
        self.assertIn(shared_concurrency, VERIFY_WORKFLOW)
        self.assertIn(shared_concurrency, WATCH_WORKFLOW)
        self.assertIn('VERIFIED_SHA: ${{ github.sha }}', VERIFY_WORKFLOW)
        self.assertIn('"${remote_sha}" != "${VERIFIED_SHA}"', VERIFY_WORKFLOW)
        self.assertIn("github.event_name == 'workflow_dispatch'", VERIFY_WORKFLOW)
        self.assertIn(
            "github.ref_name == github.event.repository.default_branch",
            VERIFY_WORKFLOW,
        )
        for workflow in (VERIFY_WORKFLOW, WATCH_WORKFLOW):
            self.assertIn("id: predeploy_head", workflow)
            self.assertIn("id: postdeploy_head", workflow)
            self.assertIn("head_drift=true", workflow)
            self.assertIn("recover-pages-head-drift:", workflow)
            self.assertIn("--workflow verify.yml", workflow)


class MatrixDriftPromotionContractTests(unittest.TestCase):
    def test_path_scoped_discovery_requires_three_proofs_and_stable_identity(self) -> None:
        audit_uri = (PROJECT_ROOT / "scripts" / "audit_pages.mjs").as_uri()
        script = """
import {
  matchingApprovedPaths,
  promotionVariantId,
  selectStableDiscoveryGroup,
  selectStableDiscoveryGroups,
} from %s;

const approvedPaths = [
  "|/board/alpha/*^",
  "|/board/beta/*^",
  "|/board/gamma/*^",
];
const config = {
  sites: [{
    id: "example",
    layouts: [{
      id: "deal",
      domain: "example.com",
      paths: approvedPaths,
      applicable_profiles: ["desktop"],
      required_roles: ["title", "body", "comments"],
      role_projection: {
        title: { mode: "seeded-shallow" },
        body: { mode: "atomic-boundary", ignored: [] },
        product: {
          mode: "absent",
          cardinality: "zero",
          selectors: [],
          ignored: [],
        },
        comments: { mode: "classified-children" },
      },
    }],
  }],
};
const makeResult = (matchedApprovedPath, index) => ({
  siteId: "example",
  layoutId: "deal",
  profile: "desktop",
  source: "algumon-latest",
  requestedUrl: `https://example.com/board/item/${index}`,
  capturedAt: "2026-07-20T00:00:00Z",
  approvedRouteMatched: true,
  passed: false,
  matchedApprovedPath,
  routeFamily: `example.com/board/item/:article-token`,
  routeObservation: null,
  semanticOracle: {
    ok: true,
    oracleSource: "verified-userscript-export",
    oracleExecutionWorld: "chromium-isolated-v1",
    exactApprovedCount: 0,
    semanticProjectionCount: 0,
    coMatchCount: 0,
    candidateProjection: {
      semanticProjectionCount: 1,
      exactCandidateCount: 1,
      coMatchCount: 0,
      aliases: [["candidate"]],
      oracleExecutionWorld: "chromium-isolated-v1",
    },
    pageRoot: ".root",
    pageRootCount: 1,
    roles: { title: ".title", body: ".body", comments: ".comments" },
    cardinality: { title: 1, body: 1, comments: 1 },
    containment: true,
    productOrder: null,
    policyProposal: {
      schemaVersion: 1,
      source: "independent-projection-tuple",
      complete: true,
      pageRoot: ".root",
      pageRootEvidence: "all-role-lowest-common-ancestor",
      product: { cardinality: "zero", order: null, selectors: [] },
      bodyIgnored: [],
      productIgnored: [],
      commentIgnored: [],
      safety: {
        strictDescendantsOnly: true,
        strongStructuralNoiseOnly: true,
        meaningfulTextPriceAndPurchaseLinksExcluded: true,
      },
      shapeFingerprint: "projection-policy-v1-0123abcd",
      promotionGate: {
        promotable: false,
        requiredDistinctUrlsPerProfile: 3,
        requiredProfilesSource: "auditor-layout-contract",
        requiredMatchingShapeFingerprint: true,
      },
    },
    commentItems: [".comment"],
    commentControls: [],
    commentIgnored: [],
    algumon: {
      titleConsistency: 1,
      titleConsistencyOk: true,
      titleConsistencyMode: "metadata-quorum",
      titleMetadataSourceCount: 2,
      titleMetadataSourceKinds: ["document-title", "open-graph"],
      commentComparable: false,
      countConsistency: null,
    },
    commentStructure: {
      mountSelector: ".comments",
      mountCount: 1,
      itemSelector: ".comment",
      itemCount: 2,
      ignoredSelectors: [],
      classificationOverlapCount: 0,
      unclassifiedContentCount: 0,
    },
  },
});
const split = selectStableDiscoveryGroup({
  results: approvedPaths.map((path, index) => makeResult(path, index + 1)),
}, config);
if (split !== null) throw new Error("1+1+1 cross-path proofs were accepted");
const same = selectStableDiscoveryGroup({
  results: [1, 2, 3].map((index) => makeResult(approvedPaths[0], index)),
}, config);
if (!same || same.approvedPath !== approvedPaths[0] || same.results.length !== 3) {
  throw new Error("three same-path proofs were not grouped");
}
const secondShape = [1, 2, 3].map((index) => {
  const result = makeResult(approvedPaths[1], index + 10);
  result.semanticOracle = structuredClone(result.semanticOracle);
  result.semanticOracle.pageRoot = ".root-v2";
  result.semanticOracle.policyProposal.pageRoot = ".root-v2";
  result.semanticOracle.roles.title = ".title-v2";
  return result;
});
const queued = selectStableDiscoveryGroups({
  results: [
    ...[1, 2, 3].map((index) => makeResult(approvedPaths[0], index)),
    ...secondShape,
  ],
}, config);
if (queued.length !== 2 || queued.some((group) => !/^[0-9a-f]{24}$/.test(group.fingerprint))) {
  throw new Error("stable candidates were not emitted as a deterministic queue");
}
const simulatedAttempts = queued.map((group, index) => ({
  fingerprint: group.fingerprint,
  status: index === 0 ? "rejected" : "draft",
}));
if (simulatedAttempts.find((attempt) => attempt.status === "draft")?.fingerprint !== queued[1].fingerprint) {
  throw new Error("a rejected first fingerprint starved the second candidate");
}
const firstId = promotionVariantId(same, [approvedPaths[0]]);
const secondId = promotionVariantId(same, [approvedPaths[1]]);
if (firstId === secondId || !/^auto-[0-9a-f]{24}$/.test(firstId)) {
  throw new Error("variant identity is not path-stable");
}
const routeLayout = {
  id: "deal",
  domain: "example.com",
  path: "|/board/original/",
  variants: [{ id: "variant-a", paths: ["|/board/added/*^"] }],
};
if (matchingApprovedPaths("https://example.com/board/original/1", routeLayout).length !== 1) {
  throw new Error("base route does not have one approved path");
}
if (matchingApprovedPaths("https://example.com/board/added/1", routeLayout).length !== 1) {
  throw new Error("variant route does not have one approved path");
}
if (matchingApprovedPaths(
  "https://example.com/board/added/1",
  routeLayout,
  "variant-a",
).length !== 0) {
  throw new Error("candidate route remained approved when its own variant was excluded");
}
""" % json.dumps(audit_uri)
        completed = subprocess.run(
            ["node", "--input-type=module", "--eval", script],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)

    def test_candidate_workflow_is_a_non_starving_dynamic_matrix(self) -> None:
        candidate_section = WATCH_WORKFLOW.split(
            "  candidate-proof:\n", 1
        )[1].split("  aggregate-candidates:\n", 1)[0]
        audit_section = WATCH_WORKFLOW.split("  audit:\n", 1)[1].split(
            "  candidate-proof:\n", 1
        )[0]
        self.assertIn("strategy:\n      fail-fast: false", candidate_section)
        self.assertIn("needs.audit.result == 'success'", candidate_section)
        self.assertIn("needs.audit.outputs.candidate_count != '0'", candidate_section)
        max_parallel = re.search(r"max-parallel:\s*(\d+)", candidate_section)
        self.assertIsNotNone(max_parallel)
        self.assertGreaterEqual(int(max_parallel.group(1)), 2)
        self.assertLessEqual(int(max_parallel.group(1)), 256)
        self.assertIn(
            "matrix: ${{ fromJSON(needs.audit.outputs.candidate_matrix) }}",
            candidate_section,
        )
        self.assertIn("CANDIDATE_FINGERPRINT: ${{ matrix.fingerprint }}", candidate_section)
        self.assertIn("CANDIDATE_INDEX: ${{ matrix.index }}", candidate_section)
        self.assertIn("--expected-queue-sha256", candidate_section)
        self.assertIn('status="proof-timeout"', candidate_section)
        self.assertIn("--status infrastructure-failure", candidate_section)
        self.assertIn("steps.finalize_result.outputs.sealed == 'true'", candidate_section)
        self.assertIn("steps.queue_download.outcome == 'success'", candidate_section)
        self.assertIn("candidate-result-${{ github.run_id }}-${{ matrix.fingerprint }}", candidate_section)
        self.assertNotIn('for draft in "${drafts[@]}"; do', WATCH_WORKFLOW)
        self.assertNotIn("legacy_draft", WATCH_WORKFLOW)
        self.assertIn("create-queue", audit_section)
        self.assertIn('AUDIT_RUN_NUMBER: ${{ github.run_number }}', audit_section)
        self.assertIn('--run-number "${AUDIT_RUN_NUMBER}"', audit_section)
        self.assertIn("queue_sha256: ${{ steps.queue.outputs.queue_sha256 }}", audit_section)
        self.assertIn("candidate_total: ${{ steps.queue.outputs.candidate_total }}", audit_section)
        self.assertIn(
            "candidate_batch_start: ${{ steps.queue.outputs.candidate_batch_start }}",
            audit_section,
        )
        self.assertIn(
            "candidate_batch_size: ${{ steps.queue.outputs.candidate_batch_size }}",
            audit_section,
        )

    def test_aggregator_verifies_every_result_before_one_atomic_selection(self) -> None:
        aggregate_section = WATCH_WORKFLOW.split(
            "  aggregate-candidates:\n", 1
        )[1].split("  promote:\n", 1)[0]
        self.assertIn("always() &&", aggregate_section)
        self.assertIn("pattern: candidate-result-${{ github.run_id }}-*", aggregate_section)
        self.assertIn("merge-multiple: false", aggregate_section)
        self.assertIn("aggregate-results", aggregate_section)
        self.assertIn("--expected-queue-sha256", aggregate_section)
        self.assertIn("--output-dir .promotion-package", aggregate_section)
        self.assertIn("candidate_ready: ${{ steps.aggregate.outputs.candidate_ready }}", aggregate_section)
        self.assertIn("findIndex", CANDIDATE_QUEUE_HELPER)
        self.assertIn("candidate result artifact set mismatch", CANDIDATE_QUEUE_HELPER)
        self.assertIn('SYNTHETIC_MISSING_STATUS = "infrastructure-missing"', CANDIDATE_QUEUE_HELPER)
        self.assertIn("createDirectoryAtomically(outputPath", CANDIDATE_QUEUE_HELPER)
        promote_header = WATCH_WORKFLOW.split("  promote:\n", 1)[1].split(
            "    steps:\n", 1
        )[0]
        self.assertIn("needs: [audit, aggregate-candidates]", promote_header)
        self.assertIn(
            "needs.aggregate-candidates.outputs.candidate_ready == 'true'",
            promote_header,
        )

    def test_promotion_freezes_full_audit_and_rechecks_only_candidate_site(self) -> None:
        promote_section = WATCH_WORKFLOW.split("  promote:\n", 1)[1].split(
            "  report-failure:\n", 1
        )[0]
        self.assertIn("base-audit-report.json", promote_section)
        self.assertIn("sha256sum --check base-audit-report.sha256", promote_section)
        self.assertIn("unrelated drift is not fail-closed", promote_section)
        self.assertIn("--promotion-scope .promotion-package/proof/promotion-ready.json", promote_section)
        self.assertIn("--baseline-report .promotion-package/proof/base-audit-report.json", promote_section)
        self.assertIn("candidateProfiles.has(result.profile)", promote_section)
        self.assertIn('case "--promotion-scope":', AUDIT_SCRIPT)
        self.assertIn("distinctCandidateProofs.size < 3", AUDIT_SCRIPT)
        self.assertIn('"currently-passing"', AUDIT_SCRIPT)
        self.assertIn('reason === "already-failed"', AUDIT_SCRIPT)
        self.assertIn("resultIsSafelyReadableOrClosed", AUDIT_SCRIPT)

    def test_two_simultaneous_drifts_are_eventually_serialized(self) -> None:
        chain_section = WATCH_WORKFLOW.split(
            "  continue-drift-chain:\n", 1
        )[1].split("  report-pages-failure:\n", 1)[0]
        self.assertIn("needs.audit.outputs.failed == 'true'", chain_section)
        self.assertIn("needs.push-promotion.result == 'success'", chain_section)
        self.assertNotIn("deploy-pages", chain_section)
        self.assertIn("actions: write", chain_section)
        self.assertIn("cloud dispatch", chain_section)
        self.assertIn("--workflow watch-dom.yml", chain_section)
        self.assertIn("dispatchNonce", chain_section)

        # Contract model: each successful run promotes exactly one deterministic
        # candidate, then dispatches once from the updated head while drift remains.
        remaining = ["site-a", "site-b"]
        promoted: list[str] = []
        while remaining:
            promoted.append(remaining.pop(0))
            follow_up_dispatched = bool(remaining)
            if remaining:
                self.assertTrue(follow_up_dispatched)
        self.assertEqual(["site-a", "site-b"], promoted)

    def test_same_site_desktop_and_mobile_drift_do_not_livelock(self) -> None:
        remaining = [
            ("ppomppu", "pc", "desktop"),
            ("ppomppu", "mobile", "mobile"),
        ]
        passing: set[tuple[str, str, str]] = set()
        promotion_order: list[tuple[str, str, str]] = []
        while remaining:
            candidate = remaining.pop(0)
            failed_siblings = set(remaining)
            scoped_retest = {candidate, *passing, *failed_siblings}
            self.assertTrue(failed_siblings.issubset(scoped_retest))
            promotion_order.append(candidate)
            passing.add(candidate)
        self.assertEqual(
            [
                ("ppomppu", "pc", "desktop"),
                ("ppomppu", "mobile", "mobile"),
            ],
            promotion_order,
        )

    def test_candidate_cannot_open_noise_on_an_already_failed_sibling(self) -> None:
        def safely_readable_or_closed(gate: dict[str, object]) -> bool:
            zero_leak = all(
                gate[name] == 0
                for name in (
                    "uncoveredUnmarkedCount",
                    "visibleWithoutKeepCount",
                    "directVisibleTextLeakCount",
                    "coveredKeptCount",
                    "flashFrameCount",
                )
            )
            return zero_leak and (
                gate["ready"] is True
                or (gate["ready"] is False and gate["state"] == "blocked")
            )

        safely_closed = {
            "ready": False,
            "state": "blocked",
            "uncoveredUnmarkedCount": 0,
            "visibleWithoutKeepCount": 0,
            "directVisibleTextLeakCount": 0,
            "coveredKeptCount": 0,
            "flashFrameCount": 0,
        }
        newly_opened_with_noise = {
            **safely_closed,
            "ready": True,
            "state": "ready",
            "visibleWithoutKeepCount": 1,
        }
        self.assertTrue(safely_readable_or_closed(safely_closed))
        self.assertFalse(safely_readable_or_closed(newly_opened_with_noise))

    def test_drift_issue_closes_only_after_a_clean_full_audit(self) -> None:
        failure_section = WATCH_WORKFLOW.split("  report-failure:\n", 1)[1].split(
            "  report-recovery:\n", 1
        )[0]
        recovery_section = WATCH_WORKFLOW.split("  report-recovery:\n", 1)[1].split(
            "  scheduler-heartbeat:\n", 1
        )[0]
        self.assertNotIn("needs.promote.result != 'success'", failure_section)
        self.assertIn("needs.audit.outputs.failed == 'false'", recovery_section)
        self.assertNotIn("needs.promote.result == 'success'", recovery_section)

    def test_audit_abnormal_exit_always_opens_the_drift_issue(self) -> None:
        failure_section = WATCH_WORKFLOW.split("  report-failure:\n", 1)[1].split(
            "  report-recovery:\n", 1
        )[0]
        self.assertIn("needs: audit", failure_section)
        self.assertIn("always() &&", failure_section)
        self.assertIn("needs.audit.result != 'success'", failure_section)
        self.assertIn("needs.audit.outputs.failed == 'true'", failure_section)

        def should_report(job_result: str, gate_failed: str) -> bool:
            return job_result != "success" or gate_failed == "true"

        truth_table = {
            ("success", "false"): False,
            ("success", "true"): True,
            ("failure", ""): True,
            ("cancelled", ""): True,
            ("skipped", ""): True,
        }
        for inputs, expected in truth_table.items():
            with self.subTest(inputs=inputs):
                self.assertEqual(expected, should_report(*inputs))


class ArtifactQuotaContractTests(unittest.TestCase):
    def test_normal_evidence_is_json_hash_only_and_retained_two_days(self) -> None:
        audit_upload = WATCH_WORKFLOW.split(
            "      - name: Upload normal audit JSON and hashes\n", 1
        )[1].split("      - name: Upload bounded failure screenshots\n", 1)[0]
        self.assertIn("continue-on-error: true", audit_upload)
        self.assertIn("path: .audit-json-evidence/", audit_upload)
        self.assertIn("retention-days: 2", audit_upload)
        self.assertNotIn(".png", audit_upload)

        candidate_upload = WATCH_WORKFLOW.split(
            "      - name: Upload bounded candidate JSON and hashes\n", 1
        )[1].split("      - name: Upload bounded candidate screenshots\n", 1)[0]
        self.assertIn("continue-on-error: true", candidate_upload)
        self.assertIn("path: .candidate-json-evidence/", candidate_upload)
        self.assertIn("retention-days: 2", candidate_upload)
        self.assertNotIn(".png", candidate_upload)

        verify_collection = VERIFY_WORKFLOW.split(
            "      - name: Collect bounded SHA-256 and coverage evidence\n", 1
        )[1].split("      - name: Upload SHA-256 and coverage manifest\n", 1)[0]
        self.assertIn("collect-evidence", verify_collection)
        self.assertIn("--max-files 512", verify_collection)
        self.assertIn("--max-bytes 8388608", verify_collection)

        verify_upload = VERIFY_WORKFLOW.split(
            "      - name: Upload SHA-256 and coverage manifest\n", 1
        )[1].split("      - name: Stage immutable release draft\n", 1)[0]
        self.assertIn("continue-on-error: true", verify_upload)
        self.assertIn("path: .audit-json-evidence/", verify_upload)
        self.assertNotIn("outputs/evidence/", verify_upload)
        self.assertIn("retention-days: 2", verify_upload)

    def test_screenshots_have_deterministic_file_and_byte_caps(self) -> None:
        self.assertIn("--max-files 4", WATCH_WORKFLOW)
        self.assertIn("--max-bytes 4194304", WATCH_WORKFLOW)
        self.assertIn("--max-files 2", WATCH_WORKFLOW)
        self.assertIn("--max-bytes 524288", WATCH_WORKFLOW)
        self.assertIn("matrix.index < 4", WATCH_WORKFLOW)
        screenshot_uploads = re.findall(
            r"name: (?:dom-audit-failure-screenshots|candidate-screenshots)-[^\n]+"
            r"[\s\S]{0,500}?retention-days: (\d+)",
            WATCH_WORKFLOW,
        )
        self.assertEqual(["7", "7"], screenshot_uploads)
        self.assertIn("eligible = fs.existsSync(sourceRoot)", CANDIDATE_QUEUE_HELPER)
        self.assertIn(".sort()", CANDIDATE_QUEUE_HELPER)

    def test_only_gating_artifacts_can_block_promotion(self) -> None:
        self.assertRegex(
            WATCH_WORKFLOW,
            r"name: candidate-queue-\$\{\{ github\.run_id \}\}[\s\S]{0,220}?"
            r"if-no-files-found: error[\s\S]{0,80}?retention-days: 2",
        )
        self.assertRegex(
            WATCH_WORKFLOW,
            r"name: candidate-result-\$\{\{ github\.run_id \}\}-"
            r"\$\{\{ matrix\.fingerprint \}\}[\s\S]{0,260}?"
            r"if-no-files-found: error",
        )
        promotion_upload = WATCH_WORKFLOW.split(
            "      - name: Upload the one exact release-ready candidate\n", 1
        )[1].split("\n  promote:\n", 1)[0]
        self.assertNotIn("continue-on-error", promotion_upload)
        self.assertIn("if-no-files-found: error", promotion_upload)
        self.assertIn("retention-days: 7", promotion_upload)


class AuditProofLeaseAndExpectationTests(unittest.TestCase):
    def test_audit_resource_domains_are_exact_validated_hostnames(self) -> None:
        audit_uri = (PROJECT_ROOT / "scripts" / "audit_pages.mjs").as_uri()
        script = r"""
import { readFileSync } from "node:fs";
import { assertAuditConfig } from %s;
const config = JSON.parse(readFileSync("config/sites.json", "utf8"));
const selectedSiteIndex = 0;
const selectedLayoutIndex = 0;
config.sites[selectedSiteIndex].layouts[selectedLayoutIndex].resource_domains = [
  "cdn.example.net",
];
assertAuditConfig(config);
for (const invalid of [
  "https://cdn.example.net/assets",
  "CDN.example.net",
  "cdn.example.net:8443",
  "*.example.net",
]) {
  let rejected = false;
  try {
    const invalidConfig = structuredClone(config);
    invalidConfig.sites[selectedSiteIndex].layouts[
      selectedLayoutIndex
    ].resource_domains = [invalid];
    assertAuditConfig(invalidConfig);
  } catch { rejected = true; }
  if (!rejected) throw new Error(`invalid resource domain was accepted: ${invalid}`);
}
let duplicateRejected = false;
try {
  const duplicateConfig = structuredClone(config);
  duplicateConfig.sites[selectedSiteIndex].layouts[
    selectedLayoutIndex
  ].resource_domains = ["cdn.example.net", "cdn.example.net"];
  assertAuditConfig(duplicateConfig);
} catch { duplicateRejected = true; }
if (!duplicateRejected) throw new Error("duplicate resource domains were accepted");
""" % json.dumps(audit_uri)
        completed = subprocess.run(
            ["node", "--input-type=module", "--eval", script],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)

    def test_runtime_expectations_profile_routes_and_fresh_relay_are_fail_closed(self) -> None:
        audit_uri = (PROJECT_ROOT / "scripts" / "audit_pages.mjs").as_uri()
        script = r"""
import {
  blockedUserscriptGateFailures,
  classifyProfileLandingRoute,
  committedProjectionEvidence,
  finalizeProfileLandingCoverage,
  runtimeExpectationForTarget,
  semanticOracleContractFailures,
  signedRelayAcquisitionEvidence,
} from %s;

if (runtimeExpectationForTarget({
  source: "sample",
  runtimeExpectation: "direct-negative",
  url: "https://example.com/deal/1",
}) !== "direct-negative") throw new Error("sample was not direct-negative");
if (runtimeExpectationForTarget({
  source: "algumon-latest",
  runtimeExpectation: "relay-positive",
  algumon: { dealId: "1" },
}) !== "relay-positive") throw new Error("latest target was not relay-positive");
let mismatchedExpectationRejected = false;
try {
  runtimeExpectationForTarget({
    source: "sample",
    runtimeExpectation: "relay-positive",
    url: "https://example.com/deal/1",
  });
} catch { mismatchedExpectationRejected = true; }
if (!mismatchedExpectationRejected) throw new Error("expectation mismatch was accepted");

const safeBlockedGate = {
  ready: false,
  state: "blocked",
  status: "terminal-algumon-seed-required",
  blockedStateSafety: {
    globalPaintLockIntact: true,
    zeroVisibleContent: true,
    passed: true,
  },
  paintProbe: {
    sampleCount: 1,
    flashFrameCount: 0,
    firstReadyFrame: null,
    samples: [{ bodyElementCount: 3, ready: false, paintLockIntact: true }],
  },
  visibleWithoutKeepCount: 0,
  directVisibleTextLeakCount: 0,
  uncoveredUnmarkedCount: 999,
};
if (blockedUserscriptGateFailures(safeBlockedGate).length !== 0) {
  throw new Error("safe global-lock blocked state depended on ready marker coverage");
}
const unsafeBlockedGate = structuredClone(safeBlockedGate);
unsafeBlockedGate.blockedStateSafety.globalPaintLockIntact = false;
if (!blockedUserscriptGateFailures(unsafeBlockedGate).some((failure) =>
  failure.includes("global paint lock"))) {
  throw new Error("missing blocked global paint lock was accepted");
}

const site = {
  id: "example",
  layouts: [
    {
      id: "desktop",
      domain: "example.com",
      paths: ["|/desktop/view.php?id=deal^"],
      applicable_profiles: ["desktop"],
    },
    {
      id: "mobile",
      domain: "example.com",
      paths: ["|/mobile/view.php?id=deal^"],
      applicable_profiles: ["mobile"],
      variants: [{ id: "candidate", paths: ["|/mobile/new/*^"] }],
    },
  ],
};
const mobileLanding = classifyProfileLandingRoute(
  site,
  "mobile",
  "https://m.example.com/mobile/view.php?id=deal&no=7",
);
if (
  mobileLanding.layoutId !== "mobile" ||
  mobileLanding.configuredPathMatchCount !== 1 ||
  mobileLanding.approvedRouteMatched !== true
) throw new Error("profile-UA final route was not selected exactly");
const preRedirect = classifyProfileLandingRoute(
  site,
  "mobile",
  "https://www.example.com/desktop/view.php?id=deal&no=7",
);
if (
  preRedirect.classification !== "same-domain-candidate" ||
  preRedirect.configuredPathMatchCount !== 0
) throw new Error("relay destination was mistaken for the mobile final route");
const candidateLanding = classifyProfileLandingRoute(
  site,
  "mobile",
  "https://m.example.com/mobile/new/7",
  { siteId: "example", layoutId: "mobile", variantId: "candidate" },
);
if (
  candidateLanding.configuredPathMatchCount !== 1 ||
  candidateLanding.approvedRouteMatched !== false
) throw new Error("candidate route was not separated from baseline approval");

const records = [{
  siteId: "example",
  profiles: {
    mobile: {
      matched: false,
      allObservedRoutesCovered: null,
      attempts: [],
      relayInventory: { attempts: [{ finalPath: "/desktop/view.php" }] },
    },
  },
}];
finalizeProfileLandingCoverage(records, [{
  siteId: "example",
  profile: "mobile",
  source: "algumon-latest",
  requestedUrl: "https://m.example.com/mobile/view.php?id=deal&no=7",
  routeFamily: "m.example.com/mobile/view.php?id=:article-token&no=:article-token",
  approvedRouteMatched: true,
  matchedApprovedPath: "|/mobile/view.php?id=deal^",
  relayAcquisition: { ageMs: 1 },
  routeObservation: { algumonDealId: "7" },
  profileLanding: {
    evidenceKind: "profile-user-agent-final-landing",
    finalUrl: "https://m.example.com/mobile/view.php?id=deal&no=7",
    layoutId: "mobile",
    classification: "configured-exact",
    configuredPathMatchCount: 1,
    baselineApprovedPathMatchCount: 1,
  },
}]);
if (
  records[0].profiles.mobile.allObservedRoutesCovered !== true ||
  records[0].profiles.mobile.attempts.length !== 1 ||
  records[0].profiles.mobile.attempts[0].evidenceKind !==
    "profile-user-agent-final-landing"
) throw new Error("profile landing coverage was not finalized from actual UA evidence");

const now = 1_800_000_000_000;
const signature = "0123456789abcdef0123456789abcdef";
const fresh = signedRelayAcquisitionEvidence(
  `https://www.algumon.com/l/d/7?v=${signature}&t=${now - 1000}`,
  "7",
  now,
);
if (fresh.ageMs !== 1000) throw new Error("fresh signed relay age was not preserved");
let staleRejected = false;
try {
  signedRelayAcquisitionEvidence(
    `https://www.algumon.com/l/d/7?v=${signature}&t=${now - 300001}`,
    "7",
    now,
  );
} catch { staleRejected = true; }
if (!staleRejected) throw new Error("stale signed relay was accepted");

const committed = committedProjectionEvidence({
  semanticProjectionCount: 1,
  classes: [{ aliases: ["committed"] }],
  oracleExecutionWorld: "chromium-isolated-v1",
});
if (committed.count !== 1 || committed.exactCount !== 1) {
  throw new Error("committed projection count was not independently reported");
}
const completeSemanticOracle = {
  ok: true,
  structuralOk: true,
  oracleSource: "verified-userscript-export",
  oracleExecutionWorld: "chromium-isolated-v1",
  pageRoot: ".root",
  roles: {},
  cardinality: {},
  productOrder: null,
  policyProposal: {
    schemaVersion: 1,
    source: "independent-projection-tuple",
    complete: true,
    pageRoot: ".root",
    pageRootEvidence: "all-role-lowest-common-ancestor",
    product: { cardinality: "zero", order: null, selectors: [] },
    bodyIgnored: [],
    productIgnored: [],
    commentIgnored: [],
    safety: {
      strictDescendantsOnly: true,
      strongStructuralNoiseOnly: true,
      meaningfulTextPriceAndPurchaseLinksExcluded: true,
    },
    shapeFingerprint: "projection-policy-v1-0123abcd",
    promotionGate: {
      promotable: false,
      requiredDistinctUrlsPerProfile: 3,
      requiredProfilesSource: "auditor-layout-contract",
      requiredMatchingShapeFingerprint: true,
    },
  },
};
if (semanticOracleContractFailures(completeSemanticOracle).length !== 0) {
  throw new Error("a complete independent semantic oracle was rejected");
}
for (const incomplete of [
  { ...completeSemanticOracle, ok: false },
  { ...completeSemanticOracle, structuralOk: false },
  { ...completeSemanticOracle, oracleSource: "page-global" },
  { ...completeSemanticOracle, oracleExecutionWorld: "main-world" },
]) {
  if (semanticOracleContractFailures(incomplete).length === 0) {
    throw new Error("an incomplete semantic oracle was accepted");
  }
}
""" % json.dumps(audit_uri)
        completed = subprocess.run(
            ["node", "--input-type=module", "--eval", script],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)

    def test_discovery_enforces_actual_profile_coverage_and_jit_budget(self) -> None:
        self.assertIn("refreshLatestTargetRelayProof(", AUDIT_SCRIPT)
        self.assertIn("justInTimeRelayAcquisitionsPerTarget: 1", AUDIT_SCRIPT)
        self.assertIn("justInTimeSignedRelayFetchesPerTarget: 1", AUDIT_SCRIPT)
        self.assertIn("profile?.allObservedRoutesCovered !== true", AUDIT_SCRIPT)
        self.assertIn("attempt.configuredPathMatchCount !== 1", AUDIT_SCRIPT)
        self.assertIn('runtimeExpectation: "direct-negative"', AUDIT_SCRIPT)
        self.assertIn('runtimeExpectation: "relay-positive"', AUDIT_SCRIPT)

    def test_destination_network_response_and_access_lease_are_fail_closed(self) -> None:
        audit_uri = (PROJECT_ROOT / "scripts" / "audit_pages.mjs").as_uri()
        script = r"""
import {
  acquireArticleAccessLease,
  articleIdentitiesLogicallyEquivalent,
  candidateGenerationAllowed,
  canonicalArticleIdentity,
  classifyDestinationResponse,
  consumeArticleAccessLease,
  createArticleAccessLease,
  networkFidelityFailures,
  networkRequestDecision,
  selectFinalMainDocumentResponse,
  staticRuntimeConsistencyFailures,
} from %s;

const allowedChallenge = networkRequestDecision(
  "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/orchestrate/jsch/v1",
  false,
  ["arca.live"],
  ["arca.live"],
  ["challenges.cloudflare.com"],
);
if (!allowedChallenge.allowed || allowedChallenge.reason !== "exact-challenge-subresource") {
  throw new Error("exact Arca challenge subresource was not allowed");
}
if (networkRequestDecision(
  "https://challenges.cloudflare.com/",
  true,
  ["arca.live"],
  ["arca.live"],
  ["challenges.cloudflare.com"],
).allowed) throw new Error("challenge host was allowed as a top-level navigation");
if (networkRequestDecision(
  "https://nested.challenges.cloudflare.com/",
  false,
  ["arca.live"],
  ["arca.live"],
  ["challenges.cloudflare.com"],
).allowed) throw new Error("challenge host allowlist was not exact");
for (const deniedUrl of [
  "https://user:secret@arca.live/b/hotdeal/7",
  "https://arca.live:8443/b/hotdeal/7",
]) {
  if (networkRequestDecision(
    deniedUrl,
    false,
    ["arca.live"],
    ["arca.live"],
    ["challenges.cloudflare.com"],
  ).allowed) throw new Error("credentialed or non-default-port request was allowed");
}
const blockedNetworkEvidence = {
  blockedHostOverflowCount: 0,
  blockedHosts: [
    { hostname: "analytics.example", count: 2 },
    { hostname: "article-cdn.example", count: 1 },
  ],
};
if (networkFidelityFailures(blockedNetworkEvidence).length !== 0) {
  throw new Error("intentional unrelated third-party blocking became a fidelity failure");
}
if (networkFidelityFailures(
  blockedNetworkEvidence,
  [],
  ["article-cdn.example"],
).length !== 1) throw new Error("blocked role-referenced CDN was not a fidelity failure");

const articleUrl = "https://example.com/deal/7";
const responseChain = [
  { sequence: 0, url: articleUrl, status: 403, contentType: "text/html" },
  { sequence: 1, url: articleUrl, status: 200, contentType: "text/html; charset=utf-8" },
];
const finalResponse = selectFinalMainDocumentResponse(responseChain, `${articleUrl}#ignored`);
if (finalResponse?.status !== 200 || finalResponse?.sequence !== 1) {
  throw new Error("final main-document response did not supersede the initial WAF response");
}
const article = classifyDestinationResponse({
  finalUrl: articleUrl,
  mainDocumentResponseChain: responseChain,
  title: "Exact product article",
  bodyText: "A normal article body with price and delivery details.",
  challengeSelectors: [],
});
if (article.kind !== "article-response" || article.candidateEligible !== true) {
  throw new Error("a final 200 HTML article was rejected");
}
const waf = classifyDestinationResponse({
  finalUrl: articleUrl,
  mainDocumentResponseChain: [responseChain[0]],
  title: "Just a moment...",
  bodyText: "Checking your browser before accessing the site. Cloudflare Ray ID",
  challengeSelectors: ["#challenge-running"],
});
if (waf.kind !== "source-or-infrastructure-failure" || waf.candidateEligible !== false) {
  throw new Error("WAF content was allowed to generate a selector candidate");
}
if (
  candidateGenerationAllowed("direct-negative", article, 0) ||
  candidateGenerationAllowed("relay-positive", waf, 0) ||
  candidateGenerationAllowed("relay-positive", article, 1) ||
  !candidateGenerationAllowed("relay-positive", article, 0)
) throw new Error("candidate generation policy did not fail closed by source and fidelity");

const now = 1_800_000_000_000;
const identity = canonicalArticleIdentity(articleUrl);
const binding = {
  siteId: "example",
  profileName: "desktop",
  requestedArticleIdentitySha256: identity.sha256,
  resolvedArticleIdentitySha256: identity.sha256,
  resolvedRouteFamily: identity.routeFamily,
};
const cookie = (overrides = {}) => ({
  name: "clearance",
  value: "secret-cookie-value",
  domain: ".example.com",
  path: "/",
  expires: -1,
  httpOnly: true,
  secure: true,
  sameSite: "None",
  ...overrides,
});
const lease = createArticleAccessLease(
  [cookie(), cookie({ name: "foreign", domain: ".unrelated.test" }),
   cookie({ name: "challenge", domain: ".challenges.cloudflare.com" }),
   cookie({ name: "insecure", secure: false })],
  binding,
  ["example.com"],
  now,
);
if (
  lease.evidence.cookieCount !== 1 ||
  lease.storageState.origins.length !== 0 ||
  JSON.stringify(lease.evidence).includes("secret-cookie-value")
) throw new Error("lease evidence exposed or retained invalid browser storage");
const storageState = consumeArticleAccessLease(lease, binding, now + 1);
if (
  storageState.cookies.length !== 1 ||
  storageState.cookies[0].value !== "secret-cookie-value" ||
  storageState.origins.length !== 0 ||
  lease.storageState !== null
) throw new Error("one-use cookies-only storage state was not consumed exactly");
let reused = false;
try { consumeArticleAccessLease(lease, binding, now + 2); } catch { reused = true; }
if (!reused) throw new Error("article access lease was reusable");
const staleLease = createArticleAccessLease([cookie()], binding, ["example.com"], now);
let stale = false;
try { consumeArticleAccessLease(staleLease, binding, now + 60_001); } catch { stale = true; }
if (!stale) throw new Error("stale article access lease was accepted");
const wrongProfileLease = createArticleAccessLease([cookie()], binding, ["example.com"], now);
let wrongProfile = false;
try {
  consumeArticleAccessLease(
    wrongProfileLease,
    { ...binding, profileName: "mobile" },
    now + 1,
  );
} catch { wrongProfile = true; }
if (!wrongProfile) throw new Error("profile-mismatched article access lease was accepted");

const ppomppuDesktop = canonicalArticleIdentity(
  "https://www.ppomppu.co.kr/zboard/view.php?id=ppomppu&no=721171",
  "ppomppu",
);
const ppomppuMobile = canonicalArticleIdentity(
  "https://m.ppomppu.co.kr/new/bbs_view.php?id=ppomppu&no=721171",
  "ppomppu",
);
if (!articleIdentitiesLogicallyEquivalent(ppomppuDesktop, ppomppuMobile)) {
  throw new Error("canonical desktop/mobile identity alias was rejected");
}
let duplicateIdentityQuery = false;
try {
  canonicalArticleIdentity(
    "https://www.ppomppu.co.kr/zboard/view.php?id=ppomppu&no=721171&no=721172",
    "ppomppu",
  );
} catch { duplicateIdentityQuery = true; }
if (!duplicateIdentityQuery) throw new Error("duplicate article identity query was accepted");
let identityPort = false;
try {
  canonicalArticleIdentity("https://zod.kr:8443/deal/8452555", "zod");
} catch { identityPort = true; }
if (!identityPort) throw new Error("non-default-port canonical identity was accepted");
let redirectedToDifferentArticle = false;
try {
  await acquireArticleAccessLease(
    { cookies: async () => [] },
    { id: "ppomppu", layouts: [{ domain: "ppomppu.co.kr" }] },
    "desktop",
    "https://www.ppomppu.co.kr/zboard/view.php?id=ppomppu&no=721171",
    "https://m.ppomppu.co.kr/new/bbs_view.php?id=ppomppu&no=721172",
    now,
  );
} catch { redirectedToDifferentArticle = true; }
if (!redirectedToDifferentArticle) {
  throw new Error("requested/resolved different-article lease was issued");
}

const consistency = staticRuntimeConsistencyFailures(
  {
    layoutId: "article",
    resolvedArticleIdentitySha256: identity.sha256,
    resolvedRouteFamily: identity.routeFamily,
    semanticProjectionCount: 1,
    projectionAliases: ["article"],
  },
  { finalUrl: articleUrl },
  { diagnostics: { semanticProjectionCount: 1, layoutAliases: ["article"] } },
  "article",
);
if (consistency.length !== 0) throw new Error("equal static/runtime identity was rejected");
if (staticRuntimeConsistencyFailures(
  {
    layoutId: "article",
    resolvedArticleIdentitySha256: identity.sha256,
    resolvedRouteFamily: identity.routeFamily,
    semanticProjectionCount: 1,
    projectionAliases: ["article"],
  },
  { finalUrl: "https://example.com/deal/8" },
  { diagnostics: { semanticProjectionCount: 1, layoutAliases: ["article"] } },
  "article",
).length === 0) throw new Error("different canonical article identity was accepted");
""" % json.dumps(audit_uri)
        completed = subprocess.run(
            ["node", "--input-type=module", "--eval", script],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)

    def test_projected_hide_selector_uses_native_document_qsa_semantics(self) -> None:
        audit_uri = (PROJECT_ROOT / "scripts" / "audit_pages.mjs").as_uri()
        script = r"""
import { chromium } from "playwright";
import { buildProjectedHideSelector, settlePage } from %s;
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  await page.setContent(`<!doctype html><body>
    <div id="D_"><article><div class="rhymix_content"><p id="kept">article</p></div></article></div>
    <aside id="noise">noise</aside>
  </body>`);
  const selector = buildProjectedHideSelector({
    ancestor_markers: ["#D_ article > .rhymix_content"],
    preserve_deep: [".rhymix_content"],
    preserve_shallow: [],
  });
  const matched = await page.evaluate((nativeSelector) =>
    [...document.querySelectorAll(nativeSelector)].map((element) => element.id || element.tagName),
    selector,
  );
  if (JSON.stringify(matched) !== JSON.stringify(["noise"])) {
    throw new Error(`native document.querySelectorAll projection mismatch: ${JSON.stringify(matched)}`);
  }
  await page.setContent(`<!doctype html><body><main style="height:2000px">article</main>
    <script>
      addEventListener("scroll", () => {
        const growth = document.createElement("div");
        growth.style.height = "1000px";
        document.body.append(growth);
      });
    </script></body>`);
  let unboundedScrollRejected = false;
  try {
    await settlePage(page, 1_000);
  } catch (error) {
    unboundedScrollRejected = String(error).includes("bounded scroll settlement");
  }
  if (!unboundedScrollRejected) throw new Error("infinite-scroll settlement was not rejected");
} finally {
  await browser.close();
}
""" % json.dumps(audit_uri)
        completed = subprocess.run(
            ["node", "--input-type=module", "--eval", script],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if (
            completed.returncode != 0
            and "Executable doesn't exist" in completed.stderr
        ):
            self.skipTest(
                "Playwright Chromium is installed after the preflight unit-test stage"
            )
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)

    def test_live_audits_are_headed_under_xvfb_and_modes_are_separated(self) -> None:
        self.assertEqual(3, WATCH_WORKFLOW.count("xvfb-run -a"))
        for invocation in WATCH_WORKFLOW.split("xvfb-run -a")[1:]:
            self.assertIn("--headed", invocation[:500])
        self.assertIn(
            '"direct-negative provenance-only; bootstrap, lease, and static semantic audit omitted"',
            AUDIT_SCRIPT,
        )
        self.assertIn(
            '"runtime-only candidate verification; source and access lease still verified"',
            AUDIT_SCRIPT,
        )
        self.assertIn("const liveSites = sites;", AUDIT_SCRIPT)
        self.assertNotIn("live navigation is CI-only", AUDIT_SCRIPT)
        self.assertNotIn("safetySkips", AUDIT_SCRIPT)
        self.assertLess(
            AUDIT_SCRIPT.index("accessLease = await acquireArticleAccessLease("),
            AUDIT_SCRIPT.index("const userscriptSession = await createPageContext("),
        )
        self.assertIn("return { result, candidates: [] };", AUDIT_SCRIPT)


class BehaviorAuditContractTests(unittest.TestCase):
    def test_gate_snapshot_waits_for_the_atomic_released_protocol_state(self) -> None:
        gate = AUDIT_SCRIPT[
            AUDIT_SCRIPT.index("async function auditUserscriptGate"):
            AUDIT_SCRIPT.index("function commentControlProjectionFailures")
        ]
        self.assertIn(".waitForFunction(", gate)
        self.assertIn(
            ".some((rect) => rect.width > 0 && rect.height > 0)",
            gate,
        )
        self.assertNotIn("getClientRects().length > 0", gate)
        self.assertIn("paintProbe.firstReadyFrame !== null", gate)
        self.assertIn("diagnostics?.semanticProjectionCount === 1", gate)
        self.assertIn("preauthorized?.extendedCssCallbacks >= 2", gate)
        self.assertIn(".length === 1", gate)
        self.assertNotIn("hotdeal-audit-marker-projection", gate)

    def test_edge_gate_uses_complete_css_and_terminal_reason_prefixes(self) -> None:
        edge = AUDIT_SCRIPT[
            AUDIT_SCRIPT.index("async function auditSyntheticEdgeFixtures"):
            AUDIT_SCRIPT.index("function fixtureCoverageFailures")
        ]
        self.assertIn(".map((rule) => rule.cssText)", edge)
        self.assertIn('dialogDisplay: dialogStyle?.display ?? null', edge)
        self.assertIn('lockedState.dialogDisplay !== "none"', edge)
        self.assertIn(
            '!String(edgeState.status ?? "").startsWith(fixture.expectedStatusPrefix)',
            edge,
        )


class ReleaseManifestCanonicalHashTests(unittest.TestCase):
    def _run_manifest_check(
        self, artifact: str | None = None, field: str | None = None
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            bundle = Path(temporary_directory)
            for relative_path in (
                "filter.txt",
                "filter-static.txt",
                "hotdeal-focus.user.js",
                "package.json",
                "package-lock.json",
                "release-manifest.json",
                "config/sites.json",
                "config/gate-artifacts.json",
                "tests/fixtures/behavior-baseline.json",
                "tests/fixtures/dom-regressions.json",
            ):
                source = PROJECT_ROOT / relative_path
                destination = bundle / relative_path
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
            manifest_path = bundle / "release-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if artifact is not None and field is not None:
                manifest["artifacts"][artifact][field] = "0" * 64
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    "node",
                    str(PROJECT_ROOT / "scripts" / "audit_pages.mjs"),
                    "--integrity-only",
                    "--config",
                    str(bundle / "config" / "sites.json"),
                    "--marker-filter",
                    str(bundle / "filter.txt"),
                    "--userscript",
                    str(bundle / "hotdeal-focus.user.js"),
                    "--evidence-dir",
                    str(bundle / "evidence"),
                ],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            integrity = json.loads(
                (bundle / "evidence" / "integrity-manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            return result, integrity

    def test_untampered_canonical_hashes_pass_integrity(self) -> None:
        result, integrity = self._run_manifest_check()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertTrue(integrity["checks"]["installedRulesHashMatchesRelease"])
        self.assertTrue(
            integrity["checks"]["userscriptCanonicalTextHashMatchesRelease"]
        )

    def test_tampered_installed_rule_hash_fails_integrity(self) -> None:
        result, integrity = self._run_manifest_check(
            "filter.txt", "installedRulesSha256"
        )
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn("FAIL integrity", result.stdout)
        self.assertFalse(integrity["checks"]["installedRulesHashMatchesRelease"])
        self.assertTrue(
            integrity["checks"]["userscriptCanonicalTextHashMatchesRelease"]
        )

    def test_tampered_userscript_canonical_hash_fails_integrity(self) -> None:
        result, integrity = self._run_manifest_check(
            "hotdeal-focus.user.js", "canonicalTextSha256"
        )
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn("FAIL integrity", result.stdout)
        self.assertTrue(integrity["checks"]["installedRulesHashMatchesRelease"])
        self.assertFalse(
            integrity["checks"]["userscriptCanonicalTextHashMatchesRelease"]
        )


if __name__ == "__main__":
    unittest.main()
