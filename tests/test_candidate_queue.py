from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
HELPER = PROJECT_ROOT / "scripts" / "candidate_queue.mjs"
BASE_SHA = "a" * 40
PREFIX = "candidate-result-99-"
RELEASE_REQUIRED_FILES = (
    "config/sites.json",
    "filter-static.txt",
    "hotdeal-focus.user.js",
    "package-lock.json",
    "package.json",
    "release-manifest.json",
    "state/approved-variants.json",
    "state/release-high-water.json",
)


class CandidateQueueWorkflowTests(unittest.TestCase):
    def _run(
        self,
        *arguments: object,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["node", str(HELPER), *(str(argument) for argument in arguments)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if check and result.returncode != 0:
            self.fail(result.stdout + result.stderr)
        return result

    @staticmethod
    def _write_json(file_path: Path, value: object) -> None:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def _write_evidence(
        self,
        root: Path,
        fingerprints: list[str],
    ) -> Path:
        evidence = root / "evidence"
        run = evidence / "run-1"
        self._write_json(run / "audit-report.json", {"summary": {"passed": False}})
        self._write_json(
            evidence / "latest-run.json",
            {"runId": "run-1", "report": "run-1/audit-report.json"},
        )
        candidates: list[dict[str, object]] = []
        for index, fingerprint in enumerate(fingerprints):
            variant_id = f"auto-{fingerprint}"
            draft = {
                "schemaVersion": 1,
                "baseConfigSha256": "b" * 64,
                "candidate": {
                    "siteId": f"site-{index}",
                    "layoutId": f"layout-{index}",
                    "variantId": variant_id,
                },
            }
            self._write_json(
                run / "promotion-drafts" / f"{fingerprint}.json",
                draft,
            )
            candidates.append(
                {
                    "fingerprint": fingerprint,
                    "status": "draft",
                    "reason": None,
                    "variantId": variant_id,
                }
            )
        self._write_json(
            run / "promotion-candidates.json",
            {"schemaVersion": 1, "candidates": candidates},
        )
        return evidence

    def _create_queue(
        self,
        root: Path,
        fingerprints: list[str],
        run_number: str = "1",
    ) -> tuple[Path, str]:
        evidence = self._write_evidence(root, fingerprints)
        queue = root / "queue"
        github_output = root / "github-output.txt"
        self._run(
            "create-queue",
            "--evidence-dir",
            evidence,
            "--base-sha",
            BASE_SHA,
            "--run-number",
            run_number,
            "--output-dir",
            queue,
            "--github-output",
            github_output,
        )
        queue_sha = hashlib.sha256((queue / "queue.json").read_bytes()).hexdigest()
        return queue, queue_sha

    def _write_result(
        self,
        root: Path,
        queue: Path,
        queue_sha: str,
        fingerprint: str,
        index: int,
        status: str,
    ) -> Path:
        result_root = root / "results" / f"{PREFIX}{fingerprint}"
        result_root.mkdir(parents=True)
        if status == "proven":
            for relative in RELEASE_REQUIRED_FILES:
                destination = result_root / "release" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                if relative == "release-manifest.json":
                    self._write_json(
                        destination,
                        {
                            "schemaVersion": 2,
                            "artifacts": {
                                "hotdeal-focus.user.js": {
                                    "sha256": "0" * 64,
                                }
                            },
                        },
                    )
                else:
                    destination.write_text(
                        f"release:{fingerprint}:{relative}\n",
                        encoding="utf-8",
                    )
            queue_document = json.loads((queue / "queue.json").read_text("utf-8"))
            candidate = queue_document["candidates"][index]
            draft_path = queue / candidate["draftFile"]
            draft = json.loads(draft_path.read_text("utf-8"))
            proof = result_root / "proof"
            proof.mkdir(parents=True)
            shutil.copy2(draft_path, proof / "promotion-draft.json")
            self._write_json(
                proof / "promotion-ready.json",
                {
                    "schemaVersion": 1,
                    "baseConfigSha256": draft["baseConfigSha256"],
                    "candidate": draft["candidate"],
                },
            )
            self._write_json(proof / "draft-manifest.json", {"schemaVersion": 1})
        self._run(
            "seal-result",
            "--queue-root",
            queue,
            "--expected-base-sha",
            BASE_SHA,
            "--expected-queue-sha256",
            queue_sha,
            "--fingerprint",
            fingerprint,
            "--expected-index",
            index,
            "--result-dir",
            result_root,
            "--status",
            status,
            "--reason",
            f"test-{status}",
        )
        return result_root

    def _aggregate(
        self,
        root: Path,
        queue: Path,
        queue_sha: str,
        *,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return self._run(
            "aggregate-results",
            "--queue-root",
            queue,
            "--results-root",
            root / "results",
            "--artifact-prefix",
            PREFIX,
            "--expected-base-sha",
            BASE_SHA,
            "--expected-queue-sha256",
            queue_sha,
            "--output-dir",
            root / "promotion",
            "--summary-file",
            root / "aggregate" / "summary.json",
            check=check,
        )

    def test_queue_preserves_audit_order_and_matrix_is_minimal(self) -> None:
        fingerprints = ["f" * 24, "0" * 24]
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            queue, queue_sha = self._create_queue(root, fingerprints)
            document = json.loads((queue / "queue.json").read_text("utf-8"))
            manifest = json.loads(
                (queue / "queue-manifest.json").read_text("utf-8")
            )
            self.assertEqual(fingerprints, [item["fingerprint"] for item in document["candidates"]])
            self.assertEqual([0, 1], [item["index"] for item in document["candidates"]])
            self.assertEqual(2, document["schemaVersion"])
            self.assertEqual(2, manifest["schemaVersion"])
            self.assertEqual(queue_sha, manifest["sealedQueueSha256"])
            self.assertEqual("queue.json", manifest["sealedQueueFile"])
            self.assertEqual(
                {
                    "kind": "digest-bound",
                    "algorithm": "sha256",
                    "payloadSha256": manifest["seal"]["payloadSha256"],
                },
                manifest["seal"],
            )
            self.assertNotIn("signature", manifest)
            self.assertNotIn("signedQueueFile", manifest)
            self.assertNotIn("signedQueueSha256", manifest)
            self.assertEqual(BASE_SHA, manifest["baseSha"])
            self.assertEqual(
                fingerprints,
                [item["fingerprint"] for item in manifest["orderedCandidates"]],
            )
            output_lines = dict(
                line.split("=", 1)
                for line in (root / "github-output.txt").read_text("utf-8").splitlines()
            )
            matrix = json.loads(output_lines["candidate_matrix"])
            self.assertEqual(
                [
                    {"fingerprint": fingerprints[0], "index": 0},
                    {"fingerprint": fingerprints[1], "index": 1},
                ],
                matrix["include"],
            )
            self.assertTrue(
                all(set(item) == {"fingerprint", "index"} for item in matrix["include"])
            )

            wrong_job_output = self._run(
                "prepare-candidate",
                "--queue-root",
                queue,
                "--expected-base-sha",
                BASE_SHA,
                "--expected-queue-sha256",
                "0" * 64,
                "--fingerprint",
                fingerprints[0],
                "--expected-index",
                0,
                "--output-dir",
                root / "work-wrong-job-output",
                check=False,
            )
            self.assertNotEqual(0, wrong_job_output.returncode)
            self.assertIn("audit job output", wrong_job_output.stderr)

            manifest_path = queue / "queue-manifest.json"
            original_manifest = manifest_path.read_bytes()
            tampered_manifest = json.loads(original_manifest.decode("utf-8"))
            tampered_manifest["seal"]["payloadSha256"] = "0" * 64
            self._write_json(manifest_path, tampered_manifest)
            seal_rejected = self._run(
                "prepare-candidate",
                "--queue-root",
                queue,
                "--expected-base-sha",
                BASE_SHA,
                "--expected-queue-sha256",
                queue_sha,
                "--fingerprint",
                fingerprints[0],
                "--expected-index",
                0,
                "--output-dir",
                root / "work-tampered-seal",
                check=False,
            )
            self.assertNotEqual(0, seal_rejected.returncode)
            self.assertIn("digest-bound seal mismatch", seal_rejected.stderr)
            manifest_path.write_bytes(original_manifest)

            legacy_manifest = json.loads(original_manifest.decode("utf-8"))
            legacy_manifest["signature"] = legacy_manifest.pop("seal")
            legacy_manifest["signedQueueFile"] = legacy_manifest.pop(
                "sealedQueueFile"
            )
            legacy_manifest["signedQueueSha256"] = legacy_manifest.pop(
                "sealedQueueSha256"
            )
            self._write_json(manifest_path, legacy_manifest)
            legacy_rejected = self._run(
                "prepare-candidate",
                "--queue-root",
                queue,
                "--expected-base-sha",
                BASE_SHA,
                "--expected-queue-sha256",
                queue_sha,
                "--fingerprint",
                fingerprints[0],
                "--expected-index",
                0,
                "--output-dir",
                root / "work-legacy-manifest",
                check=False,
            )
            self.assertNotEqual(0, legacy_rejected.returncode)
            self.assertIn("manifest keys are not exact", legacy_rejected.stderr)
            manifest_path.write_bytes(original_manifest)

            (queue / "drafts" / f"{fingerprints[0]}.json").write_text(
                "{}\n",
                encoding="utf-8",
            )
            rejected = self._run(
                "prepare-candidate",
                "--queue-root",
                queue,
                "--expected-base-sha",
                BASE_SHA,
                "--expected-queue-sha256",
                queue_sha,
                "--fingerprint",
                fingerprints[0],
                "--expected-index",
                0,
                "--output-dir",
                root / "work",
                check=False,
            )
            self.assertNotEqual(0, rejected.returncode)
            self.assertIn("digest mismatch", rejected.stderr)

    def test_legacy_single_draft_is_never_a_queue_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence = root / "evidence"
            run = evidence / "run-1"
            self._write_json(run / "audit-report.json", {"summary": {"passed": False}})
            self._write_json(
                evidence / "latest-run.json",
                {"runId": "run-1", "report": "run-1/audit-report.json"},
            )
            self._write_json(
                run / "promotion-draft.json",
                {"candidate": {"siteId": "legacy-only"}},
            )
            queue = root / "queue"
            self._run(
                "create-queue",
                "--evidence-dir",
                evidence,
                "--base-sha",
                BASE_SHA,
                "--run-number",
                "1",
                "--output-dir",
                queue,
            )
            document = json.loads((queue / "queue.json").read_text("utf-8"))
            self.assertEqual([], document["candidates"])
            self.assertFalse((queue / "promotion-draft.json").exists())

    def test_empty_audit_emits_a_guarded_empty_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            evidence = root / "evidence"
            evidence.mkdir()
            queue = root / "queue"
            github_output = root / "github-output.txt"
            self._run(
                "create-queue",
                "--evidence-dir",
                evidence,
                "--base-sha",
                BASE_SHA,
                "--run-number",
                "1",
                "--output-dir",
                queue,
                "--github-output",
                github_output,
            )
            output_lines = dict(
                line.split("=", 1)
                for line in github_output.read_text("utf-8").splitlines()
            )
            self.assertEqual("0", output_lines["candidate_count"])
            self.assertEqual({"include": []}, json.loads(output_lines["candidate_matrix"]))
            self.assertIsNone(
                json.loads((queue / "queue.json").read_text("utf-8"))["auditReport"]
            )

    def test_queue_refuses_more_than_github_matrix_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            fingerprints = [f"{index:024x}" for index in range(257)]
            evidence = self._write_evidence(root, fingerprints)
            result = self._run(
                "create-queue",
                "--evidence-dir",
                evidence,
                "--base-sha",
                BASE_SHA,
                "--run-number",
                "1",
                "--output-dir",
                root / "queue",
                check=False,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("256-job matrix limit", result.stderr)

    def test_circular_batches_cover_eighty_four_candidates_in_finite_runs(self) -> None:
        fingerprints = [f"{index:024x}" for index in range(84)]
        observed_indexes: set[int] = set()
        first_run_number = 100
        for offset in range(11):
            with tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                run_number = str(first_run_number + offset)
                queue, _queue_sha = self._create_queue(
                    root,
                    fingerprints,
                    run_number,
                )
                output_lines = dict(
                    line.split("=", 1)
                    for line in (root / "github-output.txt").read_text("utf-8").splitlines()
                )
                matrix = json.loads(output_lines["candidate_matrix"])
                indexes = [candidate["index"] for candidate in matrix["include"]]
                queue_document = json.loads((queue / "queue.json").read_text("utf-8"))
                queue_manifest = json.loads(
                    (queue / "queue-manifest.json").read_text("utf-8")
                )
                self.assertEqual(8, len(indexes))
                self.assertEqual(indexes, queue_document["batch"]["candidateIndexes"])
                self.assertEqual(queue_document["batch"], queue_manifest["batch"])
                self.assertEqual("8", output_lines["candidate_batch_size"])
                self.assertEqual("84", output_lines["candidate_total"])
                self.assertEqual(run_number, output_lines["candidate_run_number"])
                observed_indexes.update(indexes)

        self.assertEqual(set(range(84)), observed_indexes)

    def test_missing_or_malformed_run_number_fails_closed(self) -> None:
        fingerprint = "f" * 24
        invalid_run_numbers: tuple[str | None, ...] = (
            None,
            "0",
            "01",
            "tampered",
            str(2**53),
        )
        for run_number in invalid_run_numbers:
            with self.subTest(run_number=run_number):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = Path(temporary_directory)
                    evidence = self._write_evidence(root, [fingerprint])
                    arguments: list[object] = [
                        "create-queue",
                        "--evidence-dir",
                        evidence,
                        "--base-sha",
                        BASE_SHA,
                    ]
                    if run_number is not None:
                        arguments.extend(("--run-number", run_number))
                    arguments.extend(("--output-dir", root / "queue"))
                    result = self._run(*arguments, check=False)
                    self.assertNotEqual(0, result.returncode)
                    self.assertFalse((root / "queue").exists())

    def test_candidate_identity_cannot_inject_outputs_or_paths(self) -> None:
        fingerprint = "f" * 24
        for field, malicious in (
            ("siteId", "site\ninjected=true"),
            ("layoutId", "../../outside"),
        ):
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = Path(temporary_directory)
                    evidence = self._write_evidence(root, [fingerprint])
                    draft_path = (
                        evidence
                        / "run-1"
                        / "promotion-drafts"
                        / f"{fingerprint}.json"
                    )
                    draft = json.loads(draft_path.read_text("utf-8"))
                    draft["candidate"][field] = malicious
                    self._write_json(draft_path, draft)
                    github_output = root / "github-output.txt"
                    result = self._run(
                        "create-queue",
                        "--evidence-dir",
                        evidence,
                        "--base-sha",
                        BASE_SHA,
                        "--run-number",
                        "1",
                        "--output-dir",
                        root / "queue",
                        "--github-output",
                        github_output,
                        check=False,
                    )
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn("invalid candidate", result.stderr)
                    self.assertFalse(github_output.exists())

    def test_aggregation_truth_table_selects_first_proven_without_starvation(self) -> None:
        cases = (
            (("build-rejected", "proven"), 1),
            (("proof-timeout", "proven"), 1),
            (("infrastructure-failure", "proven"), 1),
            (("proven", "proven"), 0),
            (("build-rejected", "proof-timeout"), None),
        )
        for statuses, expected_index in cases:
            with self.subTest(statuses=statuses):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = Path(temporary_directory)
                    fingerprints = ["f" * 24, "0" * 24]
                    queue, queue_sha = self._create_queue(root, fingerprints)
                    for index, status in enumerate(statuses):
                        self._write_result(
                            root,
                            queue,
                            queue_sha,
                            fingerprints[index],
                            index,
                            status,
                        )
                    self._aggregate(root, queue, queue_sha)
                    summary = json.loads(
                        (root / "aggregate" / "summary.json").read_text("utf-8")
                    )
                    expected_fingerprint = (
                        None if expected_index is None else fingerprints[expected_index]
                    )
                    self.assertEqual(expected_fingerprint, summary["selectedFingerprint"])
                    if expected_index is None:
                        self.assertFalse((root / "promotion").exists())
                    else:
                        selected_result_root = (
                            root
                            / "results"
                            / f"{PREFIX}{expected_fingerprint}"
                        )
                        result_manifest = json.loads(
                            (selected_result_root / "result-manifest.json").read_text(
                                "utf-8"
                            )
                        )
                        self.assertEqual(2, result_manifest["schemaVersion"])
                        self.assertEqual("digest-bound", result_manifest["seal"]["kind"])
                        self.assertNotIn("signature", result_manifest)
                        self.assertFalse(
                            (selected_result_root / "release" / "filter.txt").exists()
                        )
                        selection = json.loads(
                            (
                                root
                                / "promotion"
                                / "proof"
                                / "promotion-selection.json"
                            ).read_text("utf-8")
                        )
                        self.assertEqual(expected_index, selection["selectedIndex"])
                        self.assertEqual(
                            expected_fingerprint,
                            selection["selectedFingerprint"],
                        )
                        promotion_manifest = json.loads(
                            (
                                root
                                / "promotion"
                                / "promotion-manifest.json"
                            ).read_text("utf-8")
                        )
                        self.assertEqual(2, promotion_manifest["schemaVersion"])
                        self.assertEqual(
                            "digest-bound", promotion_manifest["seal"]["kind"]
                        )
                        self.assertNotIn("signature", promotion_manifest)
                        self.assertFalse(
                            (root / "promotion" / "release" / "filter.txt").exists()
                        )
                        self._run(
                            "verify-promotion",
                            "--promotion-root",
                            root / "promotion",
                            "--expected-base-sha",
                            BASE_SHA,
                            "--expected-queue-sha256",
                            queue_sha,
                        )

    def test_missing_result_is_canonicalized_without_starving_later_proof(self) -> None:
        fingerprints = ["f" * 24, "0" * 24]
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            queue, queue_sha = self._create_queue(root, fingerprints)
            self._write_result(
                root,
                queue,
                queue_sha,
                fingerprints[1],
                1,
                "proven",
            )
            self._aggregate(root, queue, queue_sha)

            summary = json.loads(
                (root / "aggregate" / "summary.json").read_text("utf-8")
            )
            self.assertEqual(fingerprints[1], summary["selectedFingerprint"])
            self.assertEqual(
                ["infrastructure-missing", "proven"],
                [result["status"] for result in summary["results"]],
            )
            self.assertEqual(
                [True, False],
                [result["synthetic"] for result in summary["results"]],
            )
            queue_document = json.loads((queue / "queue.json").read_text("utf-8"))
            self.assertEqual(
                [candidate["draftSha256"] for candidate in queue_document["candidates"]],
                [result["draftSha256"] for result in summary["results"]],
            )
            self.assertEqual(
                fingerprints[1],
                json.loads(
                    (
                        root
                        / "promotion"
                        / "proof"
                        / "promotion-selection.json"
                    ).read_text("utf-8")
                )["selectedFingerprint"],
            )
            self._run(
                "verify-promotion",
                "--promotion-root",
                root / "promotion",
                "--expected-base-sha",
                BASE_SHA,
                "--expected-queue-sha256",
                queue_sha,
            )

    def test_all_missing_results_produce_no_promotion(self) -> None:
        fingerprints = ["f" * 24, "0" * 24]
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            queue, queue_sha = self._create_queue(root, fingerprints)
            self._aggregate(root, queue, queue_sha)

            summary = json.loads(
                (root / "aggregate" / "summary.json").read_text("utf-8")
            )
            self.assertIsNone(summary["selectedFingerprint"])
            self.assertEqual(
                ["infrastructure-missing", "infrastructure-missing"],
                [result["status"] for result in summary["results"]],
            )
            self.assertFalse((root / "promotion").exists())

    def test_extra_or_tampered_result_blocks_every_promotion(self) -> None:
        fingerprints = ["f" * 24, "0" * 24]
        for violation in ("extra", "tampered"):
            with self.subTest(violation=violation):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = Path(temporary_directory)
                    queue, queue_sha = self._create_queue(root, fingerprints)
                    self._write_result(
                        root,
                        queue,
                        queue_sha,
                        fingerprints[0],
                        0,
                        "proof-timeout",
                    )
                    self._write_result(
                        root,
                        queue,
                        queue_sha,
                        fingerprints[1],
                        1,
                        "proven",
                    )
                    if violation == "extra":
                        (root / "results" / f"{PREFIX}extra").mkdir()
                    if violation == "tampered":
                        result_path = (
                            root
                            / "results"
                            / f"{PREFIX}{fingerprints[0]}"
                            / "result.json"
                        )
                        result_path.write_text("{}\n", encoding="utf-8")
                    result = self._aggregate(
                        root,
                        queue,
                        queue_sha,
                        check=False,
                    )
                    self.assertNotEqual(0, result.returncode)
                    self.assertFalse((root / "promotion").exists())

    def test_screenshot_and_normal_evidence_caps_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source"
            (source / "nested").mkdir(parents=True)
            (source / "a.png").write_bytes(b"aaaa")
            (source / "b.png").write_bytes(b"bbbb")
            (source / "nested" / "c.png").write_bytes(b"cc")
            self._write_json(source / "report.json", {"ok": True})
            (source / "digest.sha256").write_text("0" * 64, encoding="utf-8")
            (source / "ignore.html").write_text("noise", encoding="utf-8")

            screenshots = root / "screenshots"
            self._run(
                "cap-screenshots",
                "--source-dir",
                source,
                "--output-dir",
                screenshots,
                "--max-files",
                3,
                "--max-bytes",
                2048,
            )
            manifest = json.loads(
                (screenshots / "screenshot-manifest.json").read_text("utf-8")
            )
            self.assertEqual(
                ["a.png", "b.png"],
                [item["path"] for item in manifest["selected"]],
            )
            screenshot_files = [file for file in screenshots.rglob("*") if file.is_file()]
            screenshot_bytes = sum(file.stat().st_size for file in screenshot_files)
            self.assertEqual(8, manifest["selectedBytes"])
            self.assertEqual(len(screenshot_files), manifest["artifactFileCount"])
            self.assertEqual(screenshot_bytes, manifest["artifactTotalBytes"])
            self.assertLessEqual(manifest["artifactFileCount"], manifest["maxFiles"])
            self.assertLessEqual(manifest["artifactTotalBytes"], manifest["maxBytes"])

            evidence = root / "json-evidence"
            self._run(
                "collect-evidence",
                "--source-dir",
                source,
                "--output-dir",
                evidence,
                "--max-files",
                3,
                "--max-bytes",
                4096,
            )
            copied = {
                file.relative_to(evidence).as_posix()
                for file in evidence.rglob("*")
                if file.is_file()
            }
            self.assertEqual(
                {"digest.sha256", "evidence-manifest.json", "report.json"},
                copied,
            )
            evidence_manifest = json.loads(
                (evidence / "evidence-manifest.json").read_text("utf-8")
            )
            evidence_bytes = sum(
                file.stat().st_size for file in evidence.rglob("*") if file.is_file()
            )
            self.assertEqual(len(copied), evidence_manifest["artifactFileCount"])
            self.assertEqual(evidence_bytes, evidence_manifest["artifactTotalBytes"])
            self.assertLessEqual(
                evidence_manifest["artifactFileCount"],
                evidence_manifest["maxFiles"],
            )
            self.assertLessEqual(
                evidence_manifest["artifactTotalBytes"],
                evidence_manifest["maxBytes"],
            )
            self.assertFalse(any(file.suffix == ".png" for file in evidence.rglob("*")))

            too_small = self._run(
                "collect-evidence",
                "--source-dir",
                source,
                "--output-dir",
                root / "too-small",
                "--max-files",
                1,
                "--max-bytes",
                1,
                check=False,
            )
            self.assertNotEqual(0, too_small.returncode)
            self.assertFalse((root / "too-small").exists())


if __name__ == "__main__":
    unittest.main()
