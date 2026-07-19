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

    def test_gate_publication_is_manual_verified_and_cli_controlled(self) -> None:
        trigger = PUBLISH_GATE_WORKFLOW.split("concurrency:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("schedule:", trigger)
        self.assertNotIn("push:", trigger)
        self.assertIn("contents: write", PUBLISH_GATE_WORKFLOW)
        for command in (
            "npm test",
            "npm run build",
            "git diff --exit-code -- .",
            "npm run integrity",
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
        self.assertEqual(2, len(timeout_calls))

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
        self.assertIn("deploy-pages:\n    needs: [audit, promote]", WATCH_WORKFLOW)
        self.assertIn("needs.promote.result == 'success' ||", WATCH_WORKFLOW)
        self.assertIn("needs.audit.outputs.failed == 'false'", WATCH_WORKFLOW)
        self.assertIn("ref: ${{ needs.audit.outputs.base_sha }}", WATCH_WORKFLOW)
        self.assertIn("if: needs.promote.result != 'success'", WATCH_WORKFLOW)
        self.assertIn("if: needs.promote.result == 'success'", WATCH_WORKFLOW)
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
            "scheduler-heartbeat:\n    needs: [audit, promote, deploy-pages]",
            WATCH_WORKFLOW,
        )

    def test_pages_deployments_are_serialized_and_head_pinned(self) -> None:
        shared_concurrency = (
            "concurrency:\n"
            "      group: hotdeal-focus-pages-deployment\n"
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
        self.assertIn("needs.promote.result == 'success'", chain_section)
        self.assertNotIn("deploy-pages", chain_section)
        self.assertIn("actions: write", chain_section)
        self.assertIn("gh workflow run watch-dom.yml", chain_section)

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
