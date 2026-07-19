#!/usr/bin/env python3
"""Machine-oriented orchestration CLI for Hotdeal Focus.

The CLI deliberately exposes a small, typed command vocabulary.  Child processes
are always invoked with argument arrays and captured output, so callers receive one
JSON document on stdout and never have to scrape human-oriented command output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, Iterator, Mapping, Sequence


SCHEMA_VERSION = 1
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PAGES_MANIFEST = (
    "https://heelee912.github.io/adguard-hotdeal-focus/release-manifest.json"
)
GATE_LOCK_PROTOCOL_VERSION = 1
GATE_LOCK_ARTIFACT_VERSION = "1.0.0"
GATE_LOCK_SUBSCRIPTION_URL = (
    "https://github.com/heelee912/adguard-hotdeal-focus/releases/download/"
    "gate-v1.0.0/filter.txt"
)
GATE_LOCK_BYTES = 11707
GATE_LOCK_SHA256 = "9ef7301255056e8ca9fe2b1e91bd29f7f8edea5f312ab000f465638a8d4f065a"
GATE_LOCK_INSTALLED_RULES_SHA256 = (
    "561a2ba553589c67d7873b20a532bb446bae6f8bef011287c353bf26133cb9a7"
)
GATE_LOCK_RULE_COUNT = 14
GATE_RELEASE_TITLE = "Hotdeal Focus Gate v1 / 핫딜 포커스 게이트 v1"
GATE_RELEASE_NOTES = (
    "Stable protocol-v1 marker gate; semantic DOM updates are delivered by the "
    "userscript. / 프로토콜 v1 고정 게이트이며 DOM 의미 업데이트는 사용자 스크립트로 "
    "배포됩니다. / プロトコル v1 固定ゲート。DOM 更新はユーザースクリプトで配信します。"
    " / 协议 v1 固定门；DOM 更新由用户脚本发布。"
)
GATE_RELEASE_VIEW_FIELDS = (
    "databaseId,tagName,name,body,isDraft,isPrerelease,isImmutable,"
    "publishedAt,targetCommitish,assets"
)
GATE_RELEASE_EXISTENCE_QUERY = (
    "query GateReleaseByTag($owner:String!,$name:String!,$tag:String!){"
    "repository(owner:$owner,name:$name){release(tagName:$tag){databaseId}}}"
)
PUBLIC_ARTIFACT_NAMES = ("filter.txt", "hotdeal-focus.user.js")
WORKFLOW_FILES = ("verify.yml", "watch-dom.yml", "publish-gate.yml")
GITHUB_API_VERSION_HEADER = "X-GitHub-Api-Version: 2026-03-10"
GITHUB_JSON_ACCEPT_HEADER = "Accept: application/vnd.github+json"
GITHUB_ACTIONS_ALLOWED_POLICIES = frozenset({"all", "local_only", "selected"})
GITHUB_WORKFLOW_STATES = frozenset({
    "active", "disabled_manually", "disabled_inactivity", "disabled_fork",
})
WORKFLOW_RUN_TITLE_PREFIX = {
    "verify.yml": "hotdeal-focus-verify-",
    "watch-dom.yml": "hotdeal-focus-watch-dom-",
    "publish-gate.yml": "hotdeal-focus-publish-gate-",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
REPO_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}$"
)
RUN_ID_RE = re.compile(r"^[1-9][0-9]*$")
SEMANTIC_VERSION_RE = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$"
)
FILTER_HEADER_VERSION_RE = re.compile(rb"(?m)^! Version:\s+([^\s]+)\s*$")
USERSCRIPT_HEADER_VERSION_RE = re.compile(rb"(?m)^//\s*@version\s+([^\s]+)\s*$")
ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,240}$")
WINDOWS_UNSAFE_PATH_CHARACTER_RE = re.compile(r'[<>:"|?*\x00-\x1f]')
WINDOWS_RESERVED_NAMES = frozenset({
    "con", "prn", "aux", "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
    "com¹", "com²", "com³", "lpt¹", "lpt²", "lpt³",
})
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(token|secret|password|client[\s_-]*id|authorization|"
    r"api[\s_-]*key|ipc[\s_-]*key|access[\s_-]*key|private[\s_-]*key|key)\b"
    r"\s*(?::|=|\bis\b)\s*(?:bearer\s+)?"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
BEARER_CREDENTIAL_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
SENSITIVE_PUBLIC_KEYS = frozenset({
    "key", "apikey", "ipckey", "accesskey", "secretkey", "privatekey",
    "authorization", "authorizationheader", "credential", "credentials",
})
MAX_HTTPS_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_FILES = 10_000
MAX_EXTRACTED_ENTRIES = 10_000
HTTPS_TIMEOUT_SECONDS = 20
COMMAND_TIMEOUT_SECONDS = 900
LIVE_TIMEOUT_SECONDS = 19_800


EXIT_SUCCESS = 0
EXIT_USAGE = 2
EXIT_PREREQUISITE = 3
EXIT_VERIFICATION = 4
EXIT_INTEGRITY = 5
EXIT_TRANSIENT = 6
EXIT_MUTATION_ROLLED_BACK = 7
EXIT_ROLLBACK_INCOMPLETE = 8


class CliFailure(Exception):
    """A classified failure suitable for the stable process exit contract."""

    def __init__(
        self,
        message: str,
        exit_code: int,
        *,
        status: str,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.status = status
        self.details = dict(details or {})


class UsageFailure(CliFailure):
    def __init__(self, message: str) -> None:
        super().__init__(message, EXIT_USAGE, status="usage-error")


class PrerequisiteFailure(CliFailure):
    def __init__(self, message: str) -> None:
        super().__init__(message, EXIT_PREREQUISITE, status="prerequisite-failed")


class VerificationFailure(CliFailure):
    def __init__(self, message: str, *, details: Mapping[str, Any] | None = None) -> None:
        super().__init__(
            message, EXIT_VERIFICATION, status="verification-failed", details=details
        )


class IntegrityFailure(CliFailure):
    def __init__(self, message: str, *, details: Mapping[str, Any] | None = None) -> None:
        super().__init__(
            message, EXIT_INTEGRITY, status="integrity-conflict", details=details
        )


class TransientFailure(CliFailure):
    def __init__(self, message: str) -> None:
        super().__init__(message, EXIT_TRANSIENT, status="external-transient")


class MutationFailure(CliFailure):
    def __init__(
        self,
        message: str,
        *,
        rollback_complete: bool,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message,
            EXIT_MUTATION_ROLLED_BACK if rollback_complete else EXIT_ROLLBACK_INCOMPLETE,
            status=("mutation-failed-rollback-complete" if rollback_complete else
                    "rollback-incomplete"),
            details=details,
        )


class JsonArgumentParser(argparse.ArgumentParser):
    """Argparse variant that preserves the one-JSON-on-stdout contract."""

    def error(self, message: str) -> None:
        raise UsageFailure(message)

    def print_help(self, file: Any = None) -> None:
        del file
        raise UsageFailure("human help output is disabled; use the documented JSON command contract")


@dataclass
class ExtractionBudget:
    """Invocation-wide extraction budget shared by every downloaded artifact."""

    max_bytes: int = MAX_EXTRACTED_BYTES
    max_entries: int = MAX_EXTRACTED_ENTRIES
    reserved_bytes: int = 0
    reserved_entries: int = 0

    def reserve(self, *, byte_count: int) -> None:
        if byte_count < 0:
            raise IntegrityFailure("artifact entry declares a negative size")
        next_bytes = self.reserved_bytes + byte_count
        next_entries = self.reserved_entries + 1
        if next_bytes > self.max_bytes:
            raise IntegrityFailure("artifact extraction set exceeds the byte cap")
        if next_entries > self.max_entries:
            raise IntegrityFailure("artifact extraction set exceeds the entry cap")
        self.reserved_bytes = next_bytes
        self.reserved_entries = next_entries


@dataclass(frozen=True)
class ExecutionCapture:
    label: str
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.label,
            "exitCode": self.returncode,
            "stdoutSha256": sha256_bytes(self.stdout),
            "stderrSha256": sha256_bytes(self.stderr),
        }


def _log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_text_bytes(content: bytes) -> bytes:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise IntegrityFailure("release artifact is not strict UTF-8") from error
    canonical = text.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n")
    return canonical.rstrip("\n").encode("utf-8")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def installed_filter_rules_sha256(content: bytes) -> str:
    text = canonical_text_bytes(content).decode("utf-8")
    rules = [
        line
        for line in text.split("\n")
        if line.strip() and not line.lstrip().startswith("!")
    ]
    if not rules:
        raise IntegrityFailure("filter.txt contains no installable rules")
    return sha256_bytes("\n".join(rules).encode("utf-8"))


def _decode_json(content: bytes, label: str) -> Any:
    def reject_constant(value: str) -> Any:
        raise ValueError(f"non-finite JSON number: {value}")

    def unique_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON member: {key}")
            value[key] = item
        return value

    try:
        return json.loads(
            content.decode("utf-8"),
            parse_constant=reject_constant,
            object_pairs_hook=unique_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise IntegrityFailure(f"{label} is not valid UTF-8 JSON") from error


def _safe_error(message: str) -> str:
    sanitized = SENSITIVE_ASSIGNMENT_RE.sub(r"\1=<redacted>", str(message))
    sanitized = BEARER_CREDENTIAL_RE.sub("Bearer <redacted>", sanitized)
    return sanitized[:1000]


def _public_value(value: Any, key: str = "") -> Any:
    """Remove credentials and plaintext filter-rule collections from child JSON."""
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    if (
        any(token in normalized for token in ("token", "secret", "password", "clientid"))
        or normalized in SENSITIVE_PUBLIC_KEYS
    ):
        return "<redacted>"
    if normalized in {
        "rule", "rules", "changedrules", "candidaterules", "enabledcandidaterules",
        "beforerules", "beforedisabledrules", "userrules", "userdisabledrules",
    }:
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            encoded = canonical_json_bytes(list(value))
            return {"redacted": True, "count": len(value), "sha256": sha256_bytes(encoded)}
        return "<redacted>"
    if isinstance(value, Mapping):
        return {str(item_key): _public_value(item_value, str(item_key))
                for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_public_value(item) for item in value]
    if isinstance(value, str):
        return _safe_error(value)
    return value


def _command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def _capture_command(
    argv: Sequence[str],
    *,
    label: str,
    timeout_seconds: int = COMMAND_TIMEOUT_SECONDS,
    cwd: Path = PROJECT_ROOT,
) -> ExecutionCapture:
    if not argv or not isinstance(argv[0], str):
        raise UsageFailure("internal command contract is empty")
    if not _command_exists(argv[0]):
        raise PrerequisiteFailure(f"required executable is unavailable: {argv[0]}")
    _log(f"running allowlisted step: {label}")
    try:
        completed = subprocess.run(
            list(argv),
            cwd=str(cwd),
            check=False,
            capture_output=True,
            shell=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise TransientFailure(f"allowlisted step timed out: {label}") from error
    except OSError as error:
        raise PrerequisiteFailure(f"could not execute prerequisite for {label}") from error
    capture = ExecutionCapture(
        label=label,
        argv=tuple(argv),
        returncode=int(completed.returncode),
        stdout=bytes(completed.stdout or b""),
        stderr=bytes(completed.stderr or b""),
    )
    if capture.returncode:
        excerpt = _safe_error(
            (capture.stderr or capture.stdout).decode("utf-8", errors="replace")
        )
        if excerpt:
            _log(f"{label} failed: {excerpt}")
    return capture


def _download_gh_archive(argv: Sequence[str], output_path: Path, *, label: str) -> ExecutionCapture:
    """Stream one fixed gh API response into a create-new file without a shell."""
    if not argv or argv[0] != "gh":
        raise UsageFailure("artifact downloader accepts only the GitHub CLI")
    if not _command_exists("gh"):
        raise PrerequisiteFailure("GitHub CLI is unavailable")
    descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    _log(f"running allowlisted step: {label}")
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            try:
                completed = subprocess.run(
                    list(argv),
                    cwd=str(PROJECT_ROOT),
                    check=False,
                    stdout=output,
                    stderr=subprocess.PIPE,
                    shell=False,
                    timeout=COMMAND_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired as error:
                raise TransientFailure(f"allowlisted step timed out: {label}") from error
            except OSError as error:
                raise PrerequisiteFailure("could not execute GitHub CLI") from error
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)
    capture = ExecutionCapture(
        label=label,
        argv=tuple(argv),
        returncode=int(completed.returncode),
        stdout=b"",
        stderr=bytes(completed.stderr or b""),
    )
    if capture.returncode:
        try:
            output_path.unlink()
        except FileNotFoundError:
            pass
    return capture


def _try_source_sha() -> str | None:
    if not _command_exists("git"):
        return None
    capture = _capture_command(
        ("git", "rev-parse", "--verify", "HEAD^{commit}"),
        label="git-head",
        timeout_seconds=15,
    )
    if capture.returncode:
        return None
    value = capture.stdout.decode("ascii", errors="ignore").strip().lower()
    return value if GIT_SHA_RE.fullmatch(value) else None


def _base_result(
    command: str,
    *,
    ok: bool,
    status: str,
    source_sha: str | None = None,
    artifacts: Sequence[Mapping[str, Any]] = (),
    evidence: Mapping[str, Any] | None = None,
    **details: Any,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "command": command,
        "ok": bool(ok),
        "status": status,
        "sourceSha": source_sha,
        "artifacts": list(artifacts),
        "evidence": dict(evidence) if evidence is not None else None,
    }
    result.update(details)
    return result


def _write_new_file(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _assert_new_directory(path: Path) -> Path:
    resolved = path.expanduser().resolve(strict=False)
    if resolved.exists() or resolved.is_symlink():
        raise IntegrityFailure(f"evidence destination already exists: {resolved}")
    if resolved.name in {"", ".", ".."}:
        raise UsageFailure("evidence destination must name a new child directory")
    return resolved


def _atomic_evidence_directory(
    destination: Path,
    files: Mapping[str, bytes],
    *,
    containment_root: Path | None = None,
) -> dict[str, Any]:
    destination = _assert_new_directory(destination)
    if containment_root is not None:
        root = containment_root.expanduser().resolve(strict=False)
        try:
            destination.relative_to(root)
        except ValueError as error:
            raise UsageFailure("evidence destination escapes its declared output root") from error
        if destination == root:
            raise UsageFailure("evidence destination must be below its output root")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.tmp"
    os.mkdir(temporary)
    try:
        records: list[dict[str, Any]] = []
        seen: set[str] = set()
        for relative_name, content in sorted(files.items()):
            pure = PurePosixPath(relative_name)
            if (
                pure.is_absolute()
                or not pure.parts
                or any(part in {"", ".", ".."} for part in pure.parts)
                or "\\" in relative_name
            ):
                raise IntegrityFailure("invalid evidence file path")
            folded = relative_name.casefold()
            if folded in seen:
                raise IntegrityFailure("case-insensitive duplicate evidence path")
            seen.add(folded)
            target = temporary.joinpath(*pure.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            _write_new_file(target, content)
            records.append({
                "path": relative_name,
                "bytes": len(content),
                "sha256": sha256_bytes(content),
            })
        try:
            os.rename(temporary, destination)
        except FileExistsError as error:
            raise IntegrityFailure("evidence destination appeared concurrently") from error
        return {"directory": str(destination), "files": records}
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


def _attach_command_evidence(result: dict[str, Any], path: str | None) -> dict[str, Any]:
    if not path:
        return result
    destination = Path(path)
    public_result = {
        key: value for key, value in result.items() if not key.startswith("_")
    }
    payload = canonical_json_bytes(public_result) + b"\n"
    evidence = _atomic_evidence_directory(
        destination, {"command-evidence.json": payload}
    )
    result["evidence"] = evidence
    return result


def _attach_post_mutation_evidence(
    result: dict[str, Any],
    path: str | None,
) -> dict[str, Any]:
    if not path:
        return result
    try:
        return _attach_command_evidence(result, path)
    except (CliFailure, OSError) as error:
        preserved = dict(result)
        preserved["ok"] = False
        preserved["status"] = f"{result['status']}-evidence-failed"
        preserved["evidence"] = {
            "ok": False,
            "error": _safe_error(str(error)),
        }
        preserved["_processExitCode"] = (
            error.exit_code if isinstance(error, CliFailure) else EXIT_INTEGRITY
        )
        return preserved


def _gate_subscription_coordinates(
    value: Any,
    expected_version: str,
) -> tuple[str, str, str]:
    if not isinstance(value, str) or not SEMANTIC_VERSION_RE.fullmatch(expected_version):
        raise IntegrityFailure("gate subscription manifest fields are malformed")
    parsed = urllib.parse.urlsplit(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise IntegrityFailure("gate subscription URL has an invalid port") from error
    parts = parsed.path.split("/")
    expected_tag = f"gate-v{expected_version}"
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.query
        or parsed.fragment
        or "%" in parsed.path
        or len(parts) != 7
        or parts[0] != ""
        or parts[3:5] != ["releases", "download"]
        or parts[5] != expected_tag
        or parts[6] != "filter.txt"
        or parts[1] in {".", ".."}
        or parts[2] in {".", ".."}
        or not REPO_RE.fullmatch(f"{parts[1]}/{parts[2]}")
    ):
        raise IntegrityFailure(
            "gate subscription URL is not the exact immutable release asset contract"
        )
    return parts[1], parts[2], expected_tag


def _manifest_contract(manifest_bytes: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    value = _decode_json(manifest_bytes, "release-manifest.json")
    if not isinstance(value, dict):
        raise IntegrityFailure("release manifest root must be an object")
    if value.get("schemaVersion") != 1 or value.get("status") != "release-ready":
        raise IntegrityFailure("release manifest is not release-ready schema-v1")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != set(PUBLIC_ARTIFACT_NAMES):
        raise IntegrityFailure("release manifest public artifact set is not exact")
    filter_entry = artifacts.get("filter.txt")
    script_entry = artifacts.get("hotdeal-focus.user.js")
    if not isinstance(filter_entry, dict) or not isinstance(script_entry, dict):
        raise IntegrityFailure("release manifest artifact entry is malformed")
    for label, entry in (
        ("filter.txt", filter_entry),
        ("hotdeal-focus.user.js", script_entry),
    ):
        byte_count = entry.get("bytes")
        if type(byte_count) is not int or byte_count < 1:
            raise IntegrityFailure(f"invalid release manifest byte count: {label}")
    required_hashes = {
        "filter.txt.sha256": filter_entry.get("sha256"),
        "filter.txt.installedRulesSha256": filter_entry.get("installedRulesSha256"),
        "hotdeal-focus.user.js.sha256": script_entry.get("sha256"),
        "hotdeal-focus.user.js.canonicalTextSha256": script_entry.get(
            "canonicalTextSha256"
        ),
    }
    for label, digest in required_hashes.items():
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise IntegrityFailure(f"invalid release manifest digest: {label}")
    release_version = value.get("releaseVersion")
    gate_version = value.get("gateArtifactVersion")
    if not isinstance(release_version, str) or not SEMANTIC_VERSION_RE.fullmatch(
        release_version
    ):
        raise IntegrityFailure("release manifest has no releaseVersion")
    if not isinstance(gate_version, str) or not SEMANTIC_VERSION_RE.fullmatch(gate_version):
        raise IntegrityFailure("release manifest has no gateArtifactVersion")
    if not isinstance(value.get("protocolVersion"), int) or value["protocolVersion"] < 1:
        raise IntegrityFailure("release manifest has no positive protocolVersion")
    _gate_subscription_coordinates(value.get("filterSubscriptionUrl"), gate_version)
    if filter_entry.get("version") != gate_version:
        raise IntegrityFailure("filter artifact version differs from gateArtifactVersion")
    if script_entry.get("version") != release_version:
        raise IntegrityFailure("userscript artifact version differs from releaseVersion")
    return value, required_hashes


def _verify_release_files(
    manifest_bytes: bytes,
    artifact_bytes: Mapping[str, bytes],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest, hashes = _manifest_contract(manifest_bytes)
    if set(artifact_bytes) != set(PUBLIC_ARTIFACT_NAMES):
        raise IntegrityFailure("provided release artifact set is not exact")
    filter_bytes = artifact_bytes["filter.txt"]
    script_bytes = artifact_bytes["hotdeal-focus.user.js"]
    filter_version_match = FILTER_HEADER_VERSION_RE.search(filter_bytes)
    script_version_match = USERSCRIPT_HEADER_VERSION_RE.search(script_bytes)
    if (
        filter_version_match is None
        or filter_version_match.group(1).decode("ascii", errors="ignore")
        != manifest["gateArtifactVersion"]
    ):
        raise IntegrityFailure("filter artifact metadata version mismatch")
    if (
        script_version_match is None
        or script_version_match.group(1).decode("ascii", errors="ignore")
        != manifest["releaseVersion"]
    ):
        raise IntegrityFailure("userscript artifact metadata version mismatch")
    comparisons = {
        "filter.txt.bytes": len(filter_bytes),
        "filter.txt.sha256": sha256_bytes(filter_bytes),
        "filter.txt.installedRulesSha256": installed_filter_rules_sha256(filter_bytes),
        "hotdeal-focus.user.js.bytes": len(script_bytes),
        "hotdeal-focus.user.js.sha256": sha256_bytes(script_bytes),
        "hotdeal-focus.user.js.canonicalTextSha256": sha256_bytes(
            canonical_text_bytes(script_bytes)
        ),
    }
    for label, actual in comparisons.items():
        expected = (
            manifest["artifacts"][label.rsplit(".", 1)[0]]["bytes"]
            if label.endswith(".bytes")
            else hashes[label]
        )
        if actual != expected:
            raise IntegrityFailure(f"release artifact digest mismatch: {label}")
    records = [
        {
            "path": name,
            "bytes": len(artifact_bytes[name]),
            "sha256": sha256_bytes(artifact_bytes[name]),
        }
        for name in PUBLIC_ARTIFACT_NAMES
    ]
    records.append({
        "path": "release-manifest.json",
        "bytes": len(manifest_bytes),
        "sha256": sha256_bytes(manifest_bytes),
        "canonicalTextSha256": sha256_bytes(canonical_text_bytes(manifest_bytes)),
        "canonicalJsonSha256": sha256_bytes(canonical_json_bytes(manifest)),
    })
    return manifest, records


def _validate_locked_gate_bytes(gate_bytes: bytes) -> None:
    if (
        len(gate_bytes) != GATE_LOCK_BYTES
        or sha256_bytes(gate_bytes) != GATE_LOCK_SHA256
        or installed_filter_rules_sha256(gate_bytes)
        != GATE_LOCK_INSTALLED_RULES_SHA256
    ):
        raise IntegrityFailure("gate bytes differ from the immutable gate lock")
    installed_rule_count = sum(
        1 for line in canonical_text_bytes(gate_bytes).decode("utf-8").split("\n")
        if line.strip() and not line.lstrip().startswith("!")
    )
    if installed_rule_count != GATE_LOCK_RULE_COUNT:
        raise IntegrityFailure("immutable gate does not contain exactly fourteen rules")


def _validate_gate_artifact_lock(
    manifest: Mapping[str, Any],
    gate_bytes: bytes,
    lock_bytes: bytes | None = None,
) -> dict[str, Any]:
    _validate_locked_gate_bytes(gate_bytes)
    if lock_bytes is None:
        try:
            lock_bytes = (PROJECT_ROOT / "config" / "gate-artifacts.json").read_bytes()
        except OSError as error:
            raise IntegrityFailure("immutable gate artifact lock is unavailable") from error
    lock = _decode_json(lock_bytes, "config/gate-artifacts.json")
    required_root = {
        "schemaVersion", "protocolVersion", "gateArtifactVersion",
        "filterSubscriptionUrl", "artifact",
    }
    if not isinstance(lock, dict) or set(lock) != required_root:
        raise IntegrityFailure("immutable gate artifact lock schema is not exact")
    artifact = lock.get("artifact")
    if not isinstance(artifact, dict) or set(artifact) != {
        "path", "bytes", "sha256", "installedRulesSha256"
    }:
        raise IntegrityFailure("immutable gate artifact entry schema is not exact")
    fixed_contract = (
        lock.get("schemaVersion") == 1
        and lock.get("protocolVersion") == GATE_LOCK_PROTOCOL_VERSION
        and lock.get("gateArtifactVersion") == GATE_LOCK_ARTIFACT_VERSION
        and lock.get("filterSubscriptionUrl") == GATE_LOCK_SUBSCRIPTION_URL
        and artifact.get("path") == "filter.txt"
        and artifact.get("bytes") == GATE_LOCK_BYTES
        and artifact.get("sha256") == GATE_LOCK_SHA256
        and artifact.get("installedRulesSha256")
        == GATE_LOCK_INSTALLED_RULES_SHA256
    )
    manifest_filter = manifest.get("artifacts", {}).get("filter.txt") \
        if isinstance(manifest.get("artifacts"), Mapping) else None
    if (
        not fixed_contract
        or manifest.get("protocolVersion") != lock["protocolVersion"]
        or manifest.get("gateArtifactVersion") != lock["gateArtifactVersion"]
        or manifest.get("filterSubscriptionUrl") != lock["filterSubscriptionUrl"]
        or not isinstance(manifest_filter, Mapping)
        or manifest_filter.get("version") != lock["gateArtifactVersion"]
        or manifest_filter.get("bytes") != artifact["bytes"]
        or manifest_filter.get("sha256") != artifact["sha256"]
        or manifest_filter.get("installedRulesSha256")
        != artifact["installedRulesSha256"]
    ):
        raise IntegrityFailure("release bundle differs from the immutable gate lock")
    return lock


def _local_release_contract() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        manifest_bytes = (PROJECT_ROOT / "release-manifest.json").read_bytes()
        artifacts = {
            name: (PROJECT_ROOT / name).read_bytes() for name in PUBLIC_ARTIFACT_NAMES
        }
    except OSError as error:
        raise IntegrityFailure("local release bundle is incomplete") from error
    manifest, records = _verify_release_files(manifest_bytes, artifacts)
    _validate_gate_artifact_lock(manifest, artifacts["filter.txt"])
    return manifest, records


FAST_STEPS: tuple[tuple[str, tuple[str, ...], int], ...] = (
    ("syntax-auditor", ("node", "--check", "scripts/audit_pages.mjs"), COMMAND_TIMEOUT_SECONDS),
    ("syntax-userscript", ("node", "--check", "hotdeal-focus.user.js"), COMMAND_TIMEOUT_SECONDS),
    (
        "unit",
        ("python", "-m", "unittest", "discover", "-s", "tests", "-v"),
        COMMAND_TIMEOUT_SECONDS,
    ),
)
RELEASE_STEPS: tuple[tuple[str, tuple[str, ...], int], ...] = FAST_STEPS + (
    ("build-check", ("python", "scripts/build_release.py", "--check"), COMMAND_TIMEOUT_SECONDS),
    ("integrity", ("node", "scripts/audit_pages.mjs", "--integrity-only"), COMMAND_TIMEOUT_SECONDS),
    (
        "tamper",
        ("node", "scripts/audit_pages.mjs", "--tamper-fixture-only", "--timeout-ms", "8000"),
        COMMAND_TIMEOUT_SECONDS,
    ),
    (
        "behavior",
        ("node", "scripts/audit_pages.mjs", "--fixture-only", "--no-discover-algumon"),
        COMMAND_TIMEOUT_SECONDS,
    ),
)
LIVE_STEP = (
    "live-audit",
    (
        "node", "scripts/audit_pages.mjs", "--discover-algumon",
        "--require-algumon-discovery",
    ),
    LIVE_TIMEOUT_SECONDS,
)


def _verification_steps(profile: str) -> tuple[tuple[str, tuple[str, ...], int], ...]:
    if profile == "fast":
        return FAST_STEPS
    if profile == "release":
        return RELEASE_STEPS
    if profile == "live":
        return RELEASE_STEPS + (LIVE_STEP,)
    raise UsageFailure("unknown verification profile")


def _execute_verification(profile: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    failed: list[str] = []
    for label, argv, timeout_seconds in _verification_steps(profile):
        capture = _capture_command(
            argv, label=label, timeout_seconds=timeout_seconds
        )
        records.append(capture.summary())
        if capture.returncode:
            failed.append(label)
    if failed:
        raise VerificationFailure(
            f"verification steps failed: {', '.join(failed)}",
            details={"verification": records, "failedSteps": failed},
        )
    return records


def command_doctor(_: argparse.Namespace) -> dict[str, Any]:
    tools = {
        name: {"available": _command_exists(name), "path": shutil.which(name)}
        for name in ("python", "node", "npm", "git", "gh", "powershell.exe")
    }
    python_ok = sys.version_info >= (3, 10)
    core_ok = python_ok and all(tools[name]["available"] for name in ("node", "npm", "git"))
    capabilities = {
        "build": core_ok,
        "cloud": bool(tools["gh"]["available"]),
        "immutableGateRelease": bool(tools["gh"]["available"]),
        "adguardWindowsInspect": (
            sys.platform == "win32" and bool(tools["powershell.exe"]["available"])
        ),
        "adguardWindowsDeployment": (
            sys.platform == "win32"
            and bool(tools["powershell.exe"]["available"])
            and bool(tools["gh"]["available"])
        ),
    }
    return _base_result(
        "doctor",
        ok=core_ok,
        status="ready" if core_ok else "prerequisite-failed",
        source_sha=_try_source_sha(),
        runtime={"python": sys.version.split()[0], "platform": sys.platform},
        tools=tools,
        capabilities=capabilities,
    )


def command_build(args: argparse.Namespace) -> dict[str, Any]:
    if args.evidence_dir:
        _assert_new_directory(Path(args.evidence_dir))
    argv = ["python", "scripts/build_release.py"]
    if args.check:
        argv.append("--check")
    capture = _capture_command(argv, label="build-check" if args.check else "build")
    if capture.returncode:
        raise VerificationFailure(
            "release build failed", details={"steps": [capture.summary()]}
        )
    manifest, artifacts = _local_release_contract()
    result = _base_result(
        "build",
        ok=True,
        status="verified" if args.check else "built",
        source_sha=_try_source_sha(),
        artifacts=artifacts,
        mode="check" if args.check else "write",
        releaseVersion=manifest["releaseVersion"],
        steps=[capture.summary()],
    )
    return _attach_command_evidence(result, args.evidence_dir)


def command_verify(args: argparse.Namespace) -> dict[str, Any]:
    _assert_new_directory(Path(args.evidence_dir))
    verification = _execute_verification(args.profile)
    manifest, artifacts = _local_release_contract()
    result = _base_result(
        "verify",
        ok=True,
        status="verified",
        source_sha=_try_source_sha(),
        artifacts=artifacts,
        profile=args.profile,
        liveDiscoveryRequired=args.profile == "live",
        liveEnvironmentPolicy=(
            "Complete Algumon discovery is mandatory; an environment policy refusal, "
            "including local Arca access refusal, is a failed live verification."
            if args.profile == "live" else None
        ),
        releaseVersion=manifest["releaseVersion"],
        verification=verification,
    )
    return _attach_command_evidence(result, args.evidence_dir)


def _git_source_binding(source_ref: str) -> str:
    normalized = source_ref.lower()
    if not GIT_SHA_RE.fullmatch(normalized):
        raise UsageFailure("source-ref must be a full 40- or 64-character lowercase Git SHA")
    resolved = _capture_command(
        ("git", "rev-parse", "--verify", f"{normalized}^{{commit}}"),
        label="resolve-source-ref",
        timeout_seconds=15,
    )
    if resolved.returncode:
        raise IntegrityFailure("source-ref does not resolve to a commit")
    resolved_sha = resolved.stdout.decode("ascii", errors="ignore").strip().lower()
    if resolved_sha != normalized:
        raise IntegrityFailure("source-ref is not the exact resolved commit SHA")
    head = _capture_command(
        ("git", "rev-parse", "--verify", "HEAD^{commit}"),
        label="resolve-head",
        timeout_seconds=15,
    )
    if head.returncode or head.stdout.decode("ascii", errors="ignore").strip().lower() != normalized:
        raise IntegrityFailure("source-ref does not equal the checked-out HEAD")
    status_capture = _capture_command(
        ("git", "status", "--porcelain=v1", "--untracked-files=all"),
        label="worktree-status",
        timeout_seconds=30,
    )
    if status_capture.returncode:
        raise PrerequisiteFailure("git could not inspect the worktree")
    if status_capture.stdout.strip():
        raise IntegrityFailure("release evidence requires a clean worktree")
    return normalized


def command_release_evidence(args: argparse.Namespace) -> dict[str, Any]:
    output_dir = _assert_new_directory(Path(args.output_dir))
    source_sha = _git_source_binding(args.source_ref)
    verification = _execute_verification("release")
    manifest_bytes = (PROJECT_ROOT / "release-manifest.json").read_bytes()
    artifact_bytes = {
        name: (PROJECT_ROOT / name).read_bytes() for name in PUBLIC_ARTIFACT_NAMES
    }
    manifest, artifacts = _verify_release_files(manifest_bytes, artifact_bytes)
    manifest_record = artifacts[-1]
    evidence_payload = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": "hotdeal-focus-release-evidence",
        "sourceSha": source_sha,
        "worktreeClean": True,
        "releaseVersion": manifest["releaseVersion"],
        "releaseManifest": {
            "rawSha256": manifest_record["sha256"],
            "canonicalTextSha256": manifest_record["canonicalTextSha256"],
            "canonicalJsonSha256": manifest_record["canonicalJsonSha256"],
        },
        "artifacts": artifacts,
        "verification": verification,
        "verificationPassed": True,
    }
    evidence_bytes = canonical_json_bytes(evidence_payload) + b"\n"
    evidence = _atomic_evidence_directory(
        output_dir, {"release-evidence.json": evidence_bytes}
    )
    evidence_artifact = evidence["files"][0]
    return _base_result(
        "release-evidence",
        ok=True,
        status="sealed",
        source_sha=source_sha,
        artifacts=artifacts,
        evidence=evidence,
        releaseVersion=manifest["releaseVersion"],
        evidenceSha256=evidence_artifact["sha256"],
        verification=verification,
    )


def _require_repo(repo: str) -> str:
    if not REPO_RE.fullmatch(repo):
        raise UsageFailure("repo must be an exact OWNER/REPO name")
    return repo


def _require_run_id(run_id: str | None) -> int:
    if run_id is None or not RUN_ID_RE.fullmatch(str(run_id)):
        raise UsageFailure("run-id must be a positive decimal integer")
    return int(run_id)


def _gh_json(argv: Sequence[str], label: str, *, prerequisite: bool = False) -> Any:
    capture = _capture_command(argv, label=label, timeout_seconds=60)
    if capture.returncode:
        if prerequisite:
            raise PrerequisiteFailure(f"GitHub preflight failed: {label}")
        raise TransientFailure(f"GitHub API operation failed: {label}")
    return _decode_json(capture.stdout, label)


def _cloud_preflight(repo: str, workflow: str) -> dict[str, Any]:
    if workflow not in WORKFLOW_FILES:
        raise UsageFailure("workflow is outside the fixed allowlist")
    if not _command_exists("gh"):
        raise PrerequisiteFailure("GitHub CLI is unavailable")
    auth = _capture_command(
        ("gh", "auth", "status", "--hostname", "github.com"),
        label="github-auth",
        timeout_seconds=30,
    )
    if auth.returncode:
        raise PrerequisiteFailure("GitHub CLI is not authenticated for github.com")
    repo_info = _gh_json(
        ("gh", "repo", "view", repo, "--json", "nameWithOwner,defaultBranchRef"),
        "github-repository",
        prerequisite=True,
    )
    if not isinstance(repo_info, dict) or repo_info.get("nameWithOwner") != repo:
        raise PrerequisiteFailure("GitHub repository identity is not an exact match")
    default_branch_ref = repo_info.get("defaultBranchRef")
    if not isinstance(default_branch_ref, dict):
        raise PrerequisiteFailure("GitHub repository has no default branch")
    branch = default_branch_ref.get("name")
    if (
        not isinstance(branch, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,254}", branch)
        or ".." in branch
        or "//" in branch
        or branch.endswith(("/", ".", ".lock"))
    ):
        raise IntegrityFailure("GitHub default branch metadata is invalid")
    workflow_capture = _capture_command(
        ("gh", "workflow", "view", workflow, "--repo", repo),
        label="github-workflow",
        timeout_seconds=30,
    )
    if workflow_capture.returncode:
        raise PrerequisiteFailure("allowlisted workflow is unavailable in the repository")
    return {"repo": repo, "workflow": workflow, "defaultBranch": branch}


def _workflow_path_matches(value: Any, workflow: str) -> bool:
    if not isinstance(value, str):
        return False
    return value.split("@", 1)[0] == f".github/workflows/{workflow}"


def _run_metadata(repo: str, run_id: int, workflow: str) -> dict[str, Any]:
    value = _gh_json(
        ("gh", "api", f"repos/{repo}/actions/runs/{run_id}"),
        "github-run",
    )
    if not isinstance(value, dict) or value.get("id") != run_id:
        raise IntegrityFailure("GitHub run identity mismatch")
    if not _workflow_path_matches(value.get("path"), workflow):
        raise IntegrityFailure("GitHub run belongs to a different workflow")
    source_sha = value.get("head_sha")
    if not isinstance(source_sha, str) or not GIT_SHA_RE.fullmatch(source_sha.lower()):
        raise IntegrityFailure("GitHub run has an invalid head SHA")
    return value


def _latest_runs(repo: str, workflow: str) -> list[dict[str, Any]]:
    value = _gh_json(
        (
            "gh", "api",
            f"repos/{repo}/actions/workflows/{workflow}/runs?per_page=20&event=workflow_dispatch",
        ),
        "github-runs",
    )
    runs = value.get("workflow_runs") if isinstance(value, dict) else None
    if not isinstance(runs, list):
        raise IntegrityFailure("GitHub workflow run listing is malformed")
    return [item for item in runs if isinstance(item, dict)]


def _resolve_cloud_run(repo: str, workflow: str, run_id: str | None) -> dict[str, Any]:
    if run_id is not None:
        return _run_metadata(repo, _require_run_id(run_id), workflow)
    runs = _latest_runs(repo, workflow)
    if not runs:
        raise TransientFailure("no workflow-dispatch run is available")
    identifier = runs[0].get("id")
    if not isinstance(identifier, int) or identifier < 1:
        raise IntegrityFailure("latest GitHub run has an invalid ID")
    return _run_metadata(repo, identifier, workflow)


def _run_public_record(run: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "runId": run.get("id"),
        "headSha": str(run.get("head_sha", "")).lower(),
        "status": run.get("status"),
        "conclusion": run.get("conclusion"),
        "event": run.get("event"),
        "displayTitle": run.get("display_title"),
        "url": run.get("html_url"),
        "workflowPath": str(run.get("path", "")).split("@", 1)[0],
    }


def _repository_variables(repo: str) -> dict[str, str]:
    capture = _capture_command(
        ("gh", "variable", "list", "--repo", repo, "--json", "name,value"),
        label="github-repository-variables",
        timeout_seconds=60,
    )
    if capture.returncode:
        raise PrerequisiteFailure("GitHub repository variables are unavailable")
    value = _decode_json(capture.stdout, "GitHub repository variables")
    if not isinstance(value, list):
        raise IntegrityFailure("GitHub repository variable listing is malformed")
    variables: dict[str, str] = {}
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "value"}
            or not isinstance(item.get("name"), str)
            or not isinstance(item.get("value"), str)
            or item["name"] in variables
        ):
            raise IntegrityFailure("GitHub repository variable entry is malformed")
        variables[item["name"]] = item["value"]
    return variables


def _github_actions_permissions_state(repo: str) -> dict[str, Any]:
    permissions = _gh_json(
        (
            "gh", "api", "-H", GITHUB_JSON_ACCEPT_HEADER, "-H",
            GITHUB_API_VERSION_HEADER, f"repos/{repo}/actions/permissions",
        ),
        "github-actions-permissions",
        prerequisite=True,
    )
    if (
        not isinstance(permissions, dict)
        or type(permissions.get("enabled")) is not bool
        or permissions.get("allowed_actions") not in GITHUB_ACTIONS_ALLOWED_POLICIES
        or type(permissions.get("sha_pinning_required")) is not bool
    ):
        raise IntegrityFailure("GitHub Actions permission policy is malformed")

    selected_actions: dict[str, Any] | None = None
    if permissions["allowed_actions"] == "selected":
        selected = _gh_json(
            (
                "gh", "api", "-H", GITHUB_JSON_ACCEPT_HEADER, "-H",
                GITHUB_API_VERSION_HEADER,
                f"repos/{repo}/actions/permissions/selected-actions",
            ),
            "github-actions-selected-actions",
            prerequisite=True,
        )
        patterns = selected.get("patterns_allowed") if isinstance(selected, dict) else None
        if (
            not isinstance(selected, dict)
            or type(selected.get("github_owned_allowed")) is not bool
            or type(selected.get("verified_allowed")) is not bool
            or not isinstance(patterns, list)
            or any(not isinstance(pattern, str) or not pattern for pattern in patterns)
            or len(set(patterns)) != len(patterns)
        ):
            raise IntegrityFailure("GitHub selected-actions policy is malformed")
        selected_actions = {
            "githubOwnedAllowed": selected["github_owned_allowed"],
            "verifiedAllowed": selected["verified_allowed"],
            "patternsAllowed": list(patterns),
        }

    workflow_permissions = _gh_json(
        (
            "gh", "api", "-H", GITHUB_JSON_ACCEPT_HEADER, "-H",
            GITHUB_API_VERSION_HEADER,
            f"repos/{repo}/actions/permissions/workflow",
        ),
        "github-actions-workflow-permissions",
        prerequisite=True,
    )
    if (
        not isinstance(workflow_permissions, dict)
        or workflow_permissions.get("default_workflow_permissions") not in {"read", "write"}
        or type(workflow_permissions.get("can_approve_pull_request_reviews")) is not bool
    ):
        raise IntegrityFailure("GitHub workflow token permission policy is malformed")
    return {
        "enabled": permissions["enabled"],
        "allowedActions": permissions["allowed_actions"],
        "shaPinningRequired": permissions["sha_pinning_required"],
        "selectedActions": selected_actions,
        "defaultWorkflowPermissions": workflow_permissions[
            "default_workflow_permissions"
        ],
        "canApprovePullRequestReviews": workflow_permissions[
            "can_approve_pull_request_reviews"
        ],
    }


def _github_workflow_states(repo: str) -> dict[str, dict[str, Any]]:
    workflows: dict[str, dict[str, Any]] = {}
    for workflow in WORKFLOW_FILES:
        workflow_id = urllib.parse.quote(workflow, safe="")
        value = _gh_json(
            (
                "gh", "api", "-H", GITHUB_JSON_ACCEPT_HEADER, "-H",
                GITHUB_API_VERSION_HEADER,
                f"repos/{repo}/actions/workflows/{workflow_id}",
            ),
            f"github-workflow-state-{workflow}",
            prerequisite=True,
        )
        expected_path = f".github/workflows/{workflow}"
        if (
            not isinstance(value, dict)
            or type(value.get("id")) is not int
            or value["id"] < 1
            or value.get("path") != expected_path
            or value.get("state") not in GITHUB_WORKFLOW_STATES
        ):
            raise IntegrityFailure(f"GitHub workflow state is malformed: {workflow}")
        workflows[workflow] = {
            "id": value["id"],
            "path": value["path"],
            "state": value["state"],
        }
    return workflows


def _github_pages_state(repo: str) -> dict[str, Any]:
    capture = _capture_command(
        (
            "gh", "api", "--include", "-H", GITHUB_JSON_ACCEPT_HEADER,
            "-H", GITHUB_API_VERSION_HEADER, f"repos/{repo}/pages",
        ),
        label="github-pages-state",
        timeout_seconds=60,
    )
    normalized = capture.stdout.replace(b"\r\n", b"\n")
    header, separator, body = normalized.partition(b"\n\n")
    status_match = re.match(rb"^HTTP/\S+\s+([0-9]{3})\b", header)
    if not separator or status_match is None:
        raise IntegrityFailure("GitHub Pages response has no exact HTTP status envelope")
    status_code = int(status_match.group(1))
    if status_code == 404:
        if capture.returncode == 0:
            raise IntegrityFailure("GitHub Pages returned a contradictory missing state")
        return {"exists": False, "buildType": None}
    if capture.returncode or not 200 <= status_code < 300:
        raise TransientFailure("GitHub Pages state could not be read")
    page = _decode_json(body, "GitHub Pages state")
    if not isinstance(page, dict) or not isinstance(page.get("build_type"), str):
        raise IntegrityFailure("GitHub Pages state is malformed")
    return {"exists": True, "buildType": page["build_type"]}


def _cloud_operating_state(repo: str) -> dict[str, Any]:
    variables = _repository_variables(repo)
    pages = _github_pages_state(repo)
    return {
        "enableStateCommits": variables.get("ENABLE_STATE_COMMITS") == "true",
        "enablePagesPublish": variables.get("ENABLE_PAGES_PUBLISH") == "true",
        "pagesWorkflow": pages["exists"] and pages["buildType"] == "workflow",
        "actions": _github_actions_permissions_state(repo),
        "workflows": _github_workflow_states(repo),
        "pages": pages,
    }


def _required_cloud_configuration() -> dict[str, Any]:
    return {
        "enableStateCommits": True,
        "enablePagesPublish": True,
        "pagesWorkflow": True,
        "actions": {
            "enabled": True,
            "allowedActions": "selected",
            "shaPinningRequired": True,
            "selectedActions": {
                "githubOwnedAllowed": True,
                "verifiedAllowed": False,
                "patternsAllowed": [],
            },
            "defaultWorkflowPermissions": "read",
            "canApprovePullRequestReviews": False,
        },
        "workflows": {workflow: "active" for workflow in WORKFLOW_FILES},
    }


def _cloud_actions_contract_is_exact(
    actions: Mapping[str, Any], *, expected_enabled: bool | None
) -> bool:
    required_actions = _required_cloud_configuration()["actions"]
    for key, expected in required_actions.items():
        if key == "enabled":
            if expected_enabled is not None and actions.get(key) is not expected_enabled:
                return False
        elif actions.get(key) != expected:
            return False
    return True


def _cloud_configuration_is_exact(state: Mapping[str, Any]) -> bool:
    actions = state.get("actions")
    workflows = state.get("workflows")
    if not isinstance(actions, Mapping) or not isinstance(workflows, Mapping):
        return False
    if any(state.get(key) is not True for key in (
        "enableStateCommits", "enablePagesPublish", "pagesWorkflow",
    )):
        return False
    if not _cloud_actions_contract_is_exact(actions, expected_enabled=True):
        return False
    return set(workflows) == set(WORKFLOW_FILES) and all(
        isinstance(workflows.get(workflow), Mapping)
        and workflows[workflow].get("path") == f".github/workflows/{workflow}"
        and workflows[workflow].get("state") == "active"
        for workflow in WORKFLOW_FILES
    )


def _validate_cloud_monotonic_source(state: Mapping[str, Any]) -> None:
    actions = state.get("actions")
    if not isinstance(actions, Mapping):
        raise IntegrityFailure("GitHub Actions state is unavailable")
    if actions.get("enabled") is True:
        if actions.get("allowedActions") == "local_only":
            raise IntegrityFailure(
                "an enabled local-only Actions policy cannot be broadened to the required policy"
            )
        selected = actions.get("selectedActions")
        if (
            actions.get("allowedActions") == "selected"
            and isinstance(selected, Mapping)
            and selected.get("githubOwnedAllowed") is False
        ):
            raise IntegrityFailure(
                "an enabled selected-actions policy cannot be broadened to GitHub-owned access"
            )


def _github_api_mutation(
    endpoint: str,
    label: str,
    *,
    method: str = "PUT",
    payload: Mapping[str, Any] | None = None,
) -> ExecutionCapture:
    argv: tuple[str, ...] = (
        "gh", "api", "--method", method, "-H", GITHUB_JSON_ACCEPT_HEADER,
        "-H", GITHUB_API_VERSION_HEADER, endpoint,
    )
    if payload is None:
        return _capture_command(argv, label=label, timeout_seconds=60)
    with tempfile.TemporaryDirectory(prefix="hotdeal-focus-github-payload-") as temporary:
        payload_path = Path(temporary) / "payload.json"
        _write_new_file(payload_path, canonical_json_bytes(payload) + b"\n")
        return _capture_command(
            (*argv, "--input", str(payload_path)),
            label=label,
            timeout_seconds=60,
        )


def _configure_cloud(repo: str, apply: bool, evidence_dir: str | None) -> dict[str, Any]:
    repository_before = _gate_policy_repository(repo)
    before = _cloud_operating_state(repo)
    _validate_cloud_monotonic_source(before)
    required = _required_cloud_configuration()
    complete = _cloud_configuration_is_exact(before)
    if complete:
        result = _base_result(
            "cloud.configure",
            ok=True,
            status="already-configured",
            source_sha=_try_source_sha(),
            repo=repo,
            repository=repository_before,
            configuration=before,
            mutationApplied=False,
        )
        return _attach_command_evidence(result, evidence_dir)
    if not apply:
        result = _base_result(
            "cloud.configure",
            ok=True,
            status="dry-run",
            source_sha=_try_source_sha(),
            repo=repo,
            repository=repository_before,
            configuration=before,
            requiredConfiguration=required,
            mutationApplied=False,
        )
        return _attach_command_evidence(result, evidence_dir)
    attempts: list[dict[str, Any]] = []
    accepted_count = 0
    ambiguous = False

    def mutate(operation: Callable[[], ExecutionCapture], label: str) -> None:
        nonlocal accepted_count, ambiguous
        try:
            capture = operation()
            attempts.append(capture.summary())
            if capture.returncode == 0:
                accepted_count += 1
            else:
                ambiguous = True
        except (CliFailure, OSError) as error:
            ambiguous = True
            attempts.append({"id": label, "error": _safe_error(str(error))})

    actions = before["actions"]
    selected_required = required["actions"]["selectedActions"]
    if actions["allowedActions"] != "selected" or not actions["shaPinningRequired"]:
        mutate(
            lambda: _github_api_mutation(
                f"repos/{repo}/actions/permissions",
                "narrow-github-actions-policy",
                payload={
                    "enabled": actions["enabled"],
                    "allowed_actions": "selected",
                    "sha_pinning_required": True,
                },
            ),
            "narrow-github-actions-policy",
        )
    if actions["selectedActions"] != selected_required:
        mutate(
            lambda: _github_api_mutation(
                f"repos/{repo}/actions/permissions/selected-actions",
                "narrow-selected-actions-policy",
                payload={
                    "github_owned_allowed": True,
                    "verified_allowed": False,
                    "patterns_allowed": [],
                },
            ),
            "narrow-selected-actions-policy",
        )
    if (
        actions["defaultWorkflowPermissions"] != "read"
        or actions["canApprovePullRequestReviews"] is not False
    ):
        mutate(
            lambda: _github_api_mutation(
                f"repos/{repo}/actions/permissions/workflow",
                "narrow-workflow-token-permissions",
                payload={
                    "default_workflow_permissions": "read",
                    "can_approve_pull_request_reviews": False,
                },
            ),
            "narrow-workflow-token-permissions",
        )

    staged_actions: dict[str, Any] | None = None
    activation_precondition: dict[str, Any]
    try:
        staged_actions = _github_actions_permissions_state(repo)
    except (CliFailure, OSError) as error:
        ambiguous = True
        activation_precondition = {
            "proven": False,
            "error": _safe_error(
                f"Actions policy could not be read before activation: {error}"
            ),
        }
    else:
        actions_policy_proven = _cloud_actions_contract_is_exact(
            staged_actions, expected_enabled=None
        )
        activation_precondition = {
            "proven": actions_policy_proven,
            "actions": staged_actions,
        }
        if not actions_policy_proven:
            ambiguous = True
            activation_precondition["error"] = (
                "Actions policy was not exact; all activation substeps were skipped"
            )

    if activation_precondition["proven"]:
        for name, key in (
            ("ENABLE_STATE_COMMITS", "enableStateCommits"),
            ("ENABLE_PAGES_PUBLISH", "enablePagesPublish"),
        ):
            if not before[key]:
                mutate(
                    lambda name=name: _capture_command(
                        ("gh", "variable", "set", name, "--body", "true", "--repo", repo),
                        label=f"enable-{name.lower().replace('_', '-')}",
                        timeout_seconds=60,
                    ),
                    f"enable-{name.lower().replace('_', '-')}",
                )
        if not before["pagesWorkflow"]:
            pages_method = "PUT" if before["pages"]["exists"] else "POST"
            mutate(
                lambda: _github_api_mutation(
                    f"repos/{repo}/pages",
                    "enable-github-pages-workflow",
                    method=pages_method,
                    payload={"build_type": "workflow"},
                ),
                "enable-github-pages-workflow",
            )
        for workflow, workflow_state in before["workflows"].items():
            if workflow_state["state"] != "active":
                encoded_workflow = urllib.parse.quote(workflow, safe="")
                mutate(
                    lambda encoded_workflow=encoded_workflow, workflow=workflow: (
                        _github_api_mutation(
                            f"repos/{repo}/actions/workflows/{encoded_workflow}/enable",
                            f"enable-workflow-{workflow}",
                        )
                    ),
                    f"enable-workflow-{workflow}",
                )
        if staged_actions is not None and staged_actions["enabled"] is not True:
            mutate(
                lambda: _github_api_mutation(
                    f"repos/{repo}/actions/permissions",
                    "enable-github-actions",
                    payload={
                        "enabled": True,
                        "allowed_actions": "selected",
                        "sha_pinning_required": True,
                    },
                ),
                "enable-github-actions",
            )
    after: dict[str, Any] | None = None
    repository_after: dict[str, Any] | None = None
    verification_error: str | None = None
    for attempt in range(6):
        try:
            repository_after = _gate_policy_repository(repo)
            after = _cloud_operating_state(repo)
            if _cloud_configuration_is_exact(after):
                break
        except (CliFailure, OSError) as error:
            verification_error = _safe_error(str(error))
        if attempt < 5:
            time.sleep(5)
    verified = (
        repository_after is not None
        and after is not None
        and _cloud_configuration_is_exact(after)
    )
    if verified:
        unambiguous = bool(attempts) and accepted_count == len(attempts) and not ambiguous
        result = _base_result(
            "cloud.configure",
            ok=True,
            status=(
                "configured" if unambiguous
                else "configured-after-ambiguous-client-result"
            ),
            source_sha=_try_source_sha(),
            repo=repo,
            repository=repository_after,
            configuration=after,
            activationPrecondition=activation_precondition,
            mutations=attempts,
            mutationApplied=True if unambiguous else None,
            mutationState="applied" if unambiguous else "observed-exact",
        )
        return _attach_post_mutation_evidence(result, evidence_dir)
    result = _base_result(
        "cloud.configure",
        ok=False,
        status=(
            "configuration-applied-unverified" if accepted_count
            else "configuration-terminal-state-unknown"
        ),
        source_sha=_try_source_sha(),
        repo=repo,
        repository=repository_after,
        configuration=after,
        activationPrecondition=activation_precondition,
        requiredConfiguration=required,
        mutations=attempts,
        verificationError=verification_error,
        mutationApplied=True if accepted_count else None,
        mutationState=(
            "applied-unverified"
            if accepted_count == len(attempts) and not ambiguous
            else "partially-applied-unverified" if accepted_count
            else "unknown"
        ),
        ambiguousSubsteps=ambiguous,
    )
    result["_processExitCode"] = EXIT_ROLLBACK_INCOMPLETE
    return _attach_post_mutation_evidence(result, evidence_dir)


def _dispatch_cloud(preflight: Mapping[str, Any], apply: bool) -> dict[str, Any]:
    repo = str(preflight["repo"])
    workflow = str(preflight["workflow"])
    branch = str(preflight["defaultBranch"])
    branch_quoted = urllib.parse.quote(branch, safe="")
    commit = _gh_json(
        ("gh", "api", f"repos/{repo}/commits/{branch_quoted}"),
        "github-default-head",
    )
    source_sha = commit.get("sha") if isinstance(commit, dict) else None
    if not isinstance(source_sha, str) or not GIT_SHA_RE.fullmatch(source_sha.lower()):
        raise IntegrityFailure("default branch head SHA is invalid")
    source_sha = source_sha.lower()
    before_ids = {
        item.get("id") for item in _latest_runs(repo, workflow)
        if isinstance(item.get("id"), int)
    }
    if not apply:
        return _base_result(
            "cloud.dispatch",
            ok=True,
            status="dry-run",
            source_sha=source_sha,
            repo=repo,
            workflow=workflow,
            ref=branch,
            mutationApplied=False,
        )
    dispatch_nonce = uuid.uuid4().hex
    expected_run_title = f"{WORKFLOW_RUN_TITLE_PREFIX[workflow]}{dispatch_nonce}"
    dispatched: ExecutionCapture | None = None
    dispatch_error: str | None = None
    try:
        dispatched = _capture_command(
            (
                "gh", "workflow", "run", workflow, "--repo", repo, "--ref", branch,
                "--field", f"dispatch_nonce={dispatch_nonce}",
            ),
            label="github-dispatch",
            timeout_seconds=60,
        )
        if dispatched.returncode:
            dispatch_error = "GitHub CLI returned a nonzero dispatch result"
    except (CliFailure, OSError) as error:
        dispatch_error = _safe_error(str(error))
    observation_error: str | None = None
    for _ in range(10):
        try:
            observed_runs = _latest_runs(repo, workflow)
            observation_error = None
        except (CliFailure, OSError) as error:
            observation_error = _safe_error(str(error))
            time.sleep(2)
            continue
        candidates = [item for item in observed_runs
                      if item.get("id") not in before_ids
                      and str(item.get("head_sha", "")).lower() == source_sha
                      and item.get("event") == "workflow_dispatch"
                      and item.get("display_title") == expected_run_title]
        if candidates:
            identifier = candidates[0].get("id")
            if isinstance(identifier, int) and identifier > 0:
                try:
                    run = _run_metadata(repo, identifier, workflow)
                except (CliFailure, OSError) as error:
                    observation_error = _safe_error(str(error))
                    time.sleep(2)
                    continue
                if run.get("display_title") != expected_run_title:
                    observation_error = "GitHub run dispatch nonce changed"
                    time.sleep(2)
                    continue
                return _base_result(
                    "cloud.dispatch",
                    ok=True,
                    status=(
                        "dispatched-after-ambiguous-client-result"
                        if dispatch_error else "dispatched"
                    ),
                    source_sha=source_sha,
                    repo=repo,
                    workflow=workflow,
                    ref=branch,
                    dispatchNonce=dispatch_nonce,
                    mutationApplied=True,
                    dispatchClientError=dispatch_error,
                    run=_run_public_record(run),
                )
        time.sleep(2)
    accepted = dispatched is not None and dispatched.returncode == 0
    result = _base_result(
        "cloud.dispatch",
        ok=False,
        status=(
            "dispatch-applied-unverified" if accepted
            else "dispatch-terminal-state-unknown"
        ),
        source_sha=source_sha,
        repo=repo,
        workflow=workflow,
        ref=branch,
        dispatchNonce=dispatch_nonce,
        mutationApplied=True if accepted else None,
        mutationState="applied-unverified" if accepted else "unknown",
        dispatchClientError=dispatch_error,
        observationError=observation_error,
    )
    result["_processExitCode"] = EXIT_ROLLBACK_INCOMPLETE
    return result


def _artifact_name_allowed(name: str, workflow: str, run_id: int) -> bool:
    if name == "github-pages":
        return workflow in {"verify.yml", "watch-dom.yml"}
    escaped_id = re.escape(str(run_id))
    if workflow == "verify.yml":
        return bool(re.fullmatch(
            rf"(?:filter-integrity|release-draft)-{escaped_id}", name
        ))
    if workflow == "publish-gate.yml":
        return name == f"gate-release-evidence-{run_id}"
    prefixes = (
        "candidate-queue", "dom-audit-json", "dom-audit-failure-screenshots",
        "candidate-aggregate", "promotion",
    )
    if any(name == f"{prefix}-{run_id}" for prefix in prefixes):
        return True
    return bool(re.fullmatch(
        rf"(?:candidate-result|candidate-json|candidate-screenshots)-{escaped_id}-[0-9a-f]{{24}}",
        name,
    ))


def _artifact_inventory(repo: str, workflow: str, run_id: int) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    total_count: int | None = None
    for page in range(1, 11):
        value = _gh_json(
            (
                "gh", "api",
                f"repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100&page={page}",
            ),
            f"github-artifacts-page-{page}",
        )
        if not isinstance(value, dict) or not isinstance(value.get("artifacts"), list):
            raise IntegrityFailure("GitHub artifact listing is malformed")
        if total_count is None:
            total_count = value.get("total_count")
            if not isinstance(total_count, int) or total_count < 0 or total_count > 512:
                raise IntegrityFailure("GitHub artifact count is outside the contract")
        page_items = value["artifacts"]
        collected.extend(item for item in page_items if isinstance(item, dict))
        if len(collected) >= total_count or not page_items:
            break
    if total_count is None or len(collected) != total_count:
        raise IntegrityFailure("GitHub artifact pagination is incomplete")
    seen_ids: set[int] = set()
    seen_names: set[str] = set()
    total_size = 0
    for item in collected:
        identifier = item.get("id")
        name = item.get("name")
        digest = item.get("digest")
        size = item.get("size_in_bytes")
        if (
            not isinstance(identifier, int) or identifier < 1 or identifier in seen_ids
            or not isinstance(name, str) or not ARTIFACT_NAME_RE.fullmatch(name)
            or name.casefold() in seen_names
            or not _artifact_name_allowed(name, workflow, run_id)
            or not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            or not isinstance(size, int) or size < 0 or size > MAX_ARCHIVE_BYTES
            or item.get("expired") is True
        ):
            raise IntegrityFailure("GitHub artifact metadata violates the allowlist")
        seen_ids.add(identifier)
        seen_names.add(name.casefold())
        total_size += size
    if total_size > MAX_TOTAL_ARCHIVE_BYTES:
        raise IntegrityFailure("GitHub artifact set exceeds the byte cap")
    return sorted(collected, key=lambda item: (str(item["name"]), int(item["id"])))


def _safe_extract_zip(
    archive_path: Path,
    destination: Path,
    *,
    budget: ExtractionBudget | None = None,
) -> list[dict[str, Any]]:
    extraction_budget = budget or ExtractionBudget(
        max_bytes=MAX_EXTRACTED_BYTES,
        max_entries=MAX_EXTRACTED_ENTRIES,
    )
    destination.mkdir(parents=True, exist_ok=False)
    file_records: list[dict[str, Any]] = []
    names: set[str] = set()
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ARCHIVE_FILES:
                raise IntegrityFailure("artifact archive contains too many entries")
            for entry in entries:
                raw_name = entry.filename
                pure = PurePosixPath(raw_name)
                windows_path = PureWindowsPath(raw_name)
                mode = (entry.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(mode)
                unsafe_windows_part = any(
                    WINDOWS_UNSAFE_PATH_CHARACTER_RE.search(part) is not None
                    or part.endswith((" ", "."))
                    or part.split(".", 1)[0].casefold() in WINDOWS_RESERVED_NAMES
                    for part in pure.parts
                )
                if (
                    "\\" in raw_name
                    or pure.is_absolute()
                    or windows_path.is_absolute()
                    or bool(windows_path.drive)
                    or bool(windows_path.root)
                    or not pure.parts
                    or any(part in {"", ".", ".."} for part in pure.parts)
                    or unsafe_windows_part
                    or file_type not in (0, stat.S_IFREG, stat.S_IFDIR)
                    or stat.S_ISLNK(mode)
                ):
                    raise IntegrityFailure("artifact archive contains an unsafe path or link")
                relative = pure.as_posix().rstrip("/")
                if not relative:
                    raise IntegrityFailure("artifact archive contains an empty path")
                folded = relative.casefold()
                if folded in names:
                    raise IntegrityFailure("artifact archive contains duplicate paths")
                names.add(folded)
                extraction_budget.reserve(
                    byte_count=0 if entry.is_dir() else entry.file_size
                )
                destination_root = destination.resolve(strict=True)
                target = destination.joinpath(*pure.parts).resolve(strict=False)
                try:
                    target.relative_to(destination_root)
                except ValueError as error:
                    raise IntegrityFailure(
                        "artifact archive path escapes the extraction root"
                    ) from error
                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=False)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                digest = hashlib.sha256()
                written = 0
                try:
                    with archive.open(entry, "r") as source, os.fdopen(
                        descriptor, "wb", closefd=False
                    ) as output:
                        while True:
                            chunk = source.read(1024 * 1024)
                            if not chunk:
                                break
                            written += len(chunk)
                            if written > entry.file_size:
                                raise IntegrityFailure("artifact entry expanded beyond metadata")
                            digest.update(chunk)
                            output.write(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                finally:
                    os.close(descriptor)
                if written != entry.file_size:
                    raise IntegrityFailure("artifact entry size mismatch")
                file_records.append({
                    "path": relative,
                    "bytes": written,
                    "sha256": digest.hexdigest(),
                })
    except (zipfile.BadZipFile, OSError) as error:
        if isinstance(error, CliFailure):
            raise
        raise IntegrityFailure("downloaded artifact is not a valid safe ZIP") from error
    return sorted(file_records, key=lambda item: item["path"])


def _download_cloud_evidence(
    repo: str,
    workflow: str,
    run: Mapping[str, Any],
    output_root: Path,
) -> tuple[Path, dict[str, Any], list[dict[str, Any]]]:
    run_id = int(run["id"])
    root = output_root.expanduser().resolve(strict=False)
    destination = _assert_new_directory(root / f"run-{run_id}")
    try:
        destination.relative_to(root)
    except ValueError as error:
        raise UsageFailure("cloud evidence destination escapes output-root") from error
    artifacts = _artifact_inventory(repo, workflow, run_id)
    if not artifacts:
        raise IntegrityFailure("completed GitHub run has no allowlisted evidence artifacts")
    root.mkdir(parents=True, exist_ok=True)
    temporary = root / f".run-{run_id}.{uuid.uuid4().hex}.tmp"
    os.mkdir(temporary)
    try:
        archives_dir = temporary / "archives"
        extracted_dir = temporary / "artifacts"
        archives_dir.mkdir()
        extracted_dir.mkdir()
        artifact_records: list[dict[str, Any]] = []
        extraction_budget = ExtractionBudget(
            max_bytes=MAX_EXTRACTED_BYTES,
            max_entries=MAX_EXTRACTED_ENTRIES,
        )
        for artifact in artifacts:
            name = str(artifact["name"])
            archive_path = archives_dir / f"{name}.zip"
            capture = _download_gh_archive(
                (
                    "gh", "api", f"repos/{repo}/actions/artifacts/{artifact['id']}/zip",
                ),
                archive_path,
                label=f"download-artifact-{artifact['id']}",
            )
            if capture.returncode:
                raise TransientFailure("GitHub artifact download failed")
            if not archive_path.is_file():
                raise IntegrityFailure("GitHub CLI did not materialize the artifact archive")
            archive_size = archive_path.stat().st_size
            if (
                archive_size > MAX_ARCHIVE_BYTES
                or archive_size != int(artifact["size_in_bytes"])
            ):
                raise IntegrityFailure("GitHub artifact ZIP size differs from signed metadata")
            actual_digest = sha256_file(archive_path)
            expected_digest = str(artifact["digest"]).removeprefix("sha256:")
            if actual_digest != expected_digest:
                raise IntegrityFailure("GitHub artifact ZIP digest mismatch")
            files = _safe_extract_zip(
                archive_path,
                extracted_dir / name,
                budget=extraction_budget,
            )
            artifact_records.append({
                "artifactId": artifact["id"],
                "name": name,
                "archiveBytes": archive_size,
                "archiveSha256": actual_digest,
                "files": files,
            })
        manifest = {
            "schemaVersion": SCHEMA_VERSION,
            "kind": "hotdeal-focus-cloud-evidence",
            "repo": repo,
            "workflow": workflow,
            "run": _run_public_record(run),
            "artifacts": artifact_records,
        }
        manifest_bytes = canonical_json_bytes(manifest) + b"\n"
        _write_new_file(temporary / "cloud-evidence-manifest.json", manifest_bytes)
        try:
            os.rename(temporary, destination)
        except FileExistsError as error:
            raise IntegrityFailure("cloud evidence destination appeared concurrently") from error
        return destination, manifest, [{
            "path": "cloud-evidence-manifest.json",
            "bytes": len(manifest_bytes),
            "sha256": sha256_bytes(manifest_bytes),
        }]
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


def command_cloud(args: argparse.Namespace) -> dict[str, Any]:
    repo = _require_repo(args.repo)
    workflow = args.workflow
    if args.action == "configure":
        if args.run_id is not None or args.output_root:
            raise UsageFailure("configure does not accept run-id or output-root")
    elif args.action == "dispatch":
        if args.run_id is not None:
            raise UsageFailure("dispatch does not accept run-id")
        if args.output_root:
            raise UsageFailure("dispatch does not accept output-root")
    elif args.action in {"status", "watch"}:
        if args.apply:
            raise UsageFailure("read-only cloud commands do not accept --apply")
        if args.output_root:
            raise UsageFailure(f"{args.action} does not accept output-root")
    elif args.action == "download-evidence":
        if not args.output_root:
            raise UsageFailure("download-evidence requires --output-root")
    else:
        raise UsageFailure("unknown cloud action")
    if args.action != "configure" and args.evidence_dir:
        raise UsageFailure("evidence-dir is accepted only by cloud configure")
    preflight = _cloud_preflight(repo, workflow)
    if args.action == "configure":
        if args.evidence_dir:
            _assert_new_directory(Path(args.evidence_dir))
        return _configure_cloud(repo, bool(args.apply), args.evidence_dir)
    if args.action == "dispatch":
        return _dispatch_cloud(preflight, bool(args.apply))
    run = _resolve_cloud_run(repo, workflow, args.run_id)
    source_sha = str(run["head_sha"]).lower()
    if args.action == "status":
        return _base_result(
            "cloud.status",
            ok=True,
            status="observed",
            source_sha=source_sha,
            repo=repo,
            workflow=workflow,
            run=_run_public_record(run),
        )
    if args.action == "watch":
        if run.get("status") != "completed":
            watched = _capture_command(
                (
                    "gh", "run", "watch", str(run["id"]), "--repo", repo,
                    "--interval", "10", "--exit-status",
                ),
                label="github-watch",
                timeout_seconds=LIVE_TIMEOUT_SECONDS,
            )
            run = _run_metadata(repo, int(run["id"]), workflow)
            if watched.returncode and run.get("status") != "completed":
                raise TransientFailure("GitHub run watch ended before completion")
        record = _run_public_record(run)
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            raise VerificationFailure(
                "GitHub workflow did not complete successfully", details={"run": record}
            )
        return _base_result(
            "cloud.watch",
            ok=True,
            status="verified",
            source_sha=str(run["head_sha"]).lower(),
            repo=repo,
            workflow=workflow,
            run=record,
        )
    if args.action == "download-evidence":
        if run.get("status") != "completed":
            raise TransientFailure("GitHub run is not complete")
        destination = Path(args.output_root).expanduser().resolve(strict=False) / (
            f"run-{run['id']}"
        )
        _assert_new_directory(destination)
        if not args.apply:
            inventory = _artifact_inventory(repo, workflow, int(run["id"]))
            return _base_result(
                "cloud.download-evidence",
                ok=True,
                status="dry-run",
                source_sha=source_sha,
                artifacts=[{
                    "artifactId": item["id"],
                    "name": item["name"],
                    "bytes": item["size_in_bytes"],
                    "sha256": item["digest"].removeprefix("sha256:"),
                } for item in inventory],
                repo=repo,
                workflow=workflow,
                run=_run_public_record(run),
                destination=str(destination),
                mutationApplied=False,
            )
        downloaded, manifest, records = _download_cloud_evidence(
            repo, workflow, run, Path(args.output_root)
        )
        return _base_result(
            "cloud.download-evidence",
            ok=True,
            status="downloaded-and-verified",
            source_sha=source_sha,
            artifacts=records,
            evidence={"directory": str(downloaded), "artifactCount": len(manifest["artifacts"])},
            repo=repo,
            workflow=workflow,
            run=_run_public_record(run),
            mutationApplied=True,
        )
    raise UsageFailure("unknown cloud action")


def _validate_pages_manifest_url(value: str) -> tuple[str, str, str]:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError as error:
        raise UsageFailure("manifest-source is not a valid URL") from error
    try:
        port = parsed.port
    except ValueError as error:
        raise UsageFailure("manifest-source has an invalid port") from error
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.query
        or parsed.fragment
        or not parsed.hostname
        or "%" in parsed.path
    ):
        raise UsageFailure("manifest-source must be credential-free canonical HTTPS")
    host_match = re.fullmatch(r"([a-z0-9](?:[a-z0-9-]{0,38}))\.github\.io", parsed.hostname)
    parts = parsed.path.split("/")
    if not host_match or len(parts) != 3 or parts[0] != "" or parts[2] != "release-manifest.json":
        raise UsageFailure(
            "manifest-source must be OWNER.github.io/REPO/release-manifest.json"
        )
    owner = host_match.group(1)
    repo_name = parts[1]
    if not REPO_RE.fullmatch(f"{owner}/{repo_name}"):
        raise UsageFailure("manifest-source has an invalid OWNER/REPO binding")
    canonical = f"https://{owner}.github.io/{repo_name}/release-manifest.json"
    if value != canonical:
        raise UsageFailure("manifest-source must use its exact canonical Pages URL")
    return owner, repo_name, canonical


def _read_bounded_https(url: str, expected_binding: tuple[str, str]) -> tuple[bytes, str]:
    owner, repo_name = expected_binding
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "adguard-hotdeal-focus-orchestrator/1"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTPS_TIMEOUT_SECONDS) as response:
            final_url = response.geturl()
            status_code = getattr(response, "status", 200)
            if status_code != 200:
                raise TransientFailure("GitHub Pages returned a non-200 response")
            final_owner, final_repo, _ = (
                _validate_pages_manifest_url(final_url)
                if url.endswith("release-manifest.json")
                else _validate_pages_artifact_url(final_url, owner, repo_name)
            )
            if (final_owner, final_repo) != (owner, repo_name):
                raise IntegrityFailure("GitHub Pages redirect changed repository binding")
            content = response.read(MAX_HTTPS_BYTES + 1)
    except CliFailure:
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise TransientFailure("GitHub Pages request failed") from error
    if len(content) > MAX_HTTPS_BYTES:
        raise IntegrityFailure("GitHub Pages response exceeds the byte cap")
    return content, final_url


def _validate_pages_artifact_url(
    value: str, owner: str, repo_name: str
) -> tuple[str, str, str]:
    parsed = urllib.parse.urlsplit(value)
    expected_host = f"{owner}.github.io"
    try:
        port = parsed.port
    except ValueError as error:
        raise IntegrityFailure("GitHub Pages artifact URL has an invalid port") from error
    if (
        parsed.scheme != "https" or parsed.hostname != expected_host
        or parsed.username is not None or parsed.password is not None
        or port not in (None, 443) or parsed.query or parsed.fragment
        or "%" in parsed.path
    ):
        raise IntegrityFailure("GitHub Pages artifact redirect is outside the repository binding")
    expected_prefix = f"/{repo_name}/"
    if not parsed.path.startswith(expected_prefix):
        raise IntegrityFailure("GitHub Pages artifact path changed repository binding")
    artifact_name = parsed.path[len(expected_prefix):]
    if artifact_name not in (*PUBLIC_ARTIFACT_NAMES, "release-manifest.json"):
        raise IntegrityFailure("GitHub Pages artifact name is outside the allowlist")
    return owner, repo_name, value


def _download_exact_gate_asset(
    repo: str,
    tag: str,
    gate_bytes: bytes,
    *,
    label: str,
) -> ExecutionCapture:
    """Download one gate asset and prove its exact bytes without overwriting."""
    with tempfile.TemporaryDirectory(prefix="hotdeal-focus-gate-proof-") as temporary:
        download_directory = Path(temporary) / "release"
        download_directory.mkdir()
        download = _capture_command(
            (
                "gh", "release", "download", tag, "--repo", repo,
                "--pattern", "filter.txt", "--dir", str(download_directory),
            ),
            label=label,
            timeout_seconds=60,
        )
        if download.returncode:
            raise TransientFailure("GitHub gate asset download failed")
        downloaded = list(download_directory.iterdir())
        artifact_path = download_directory / "filter.txt"
        if (
            downloaded != [artifact_path]
            or artifact_path.is_symlink()
            or not artifact_path.is_file()
            or artifact_path.stat().st_size > MAX_HTTPS_BYTES
        ):
            raise IntegrityFailure("gate asset download shape is invalid")
        if artifact_path.read_bytes() != gate_bytes:
            raise IntegrityFailure("gate asset download bytes differ from the locked gate")
        return download


@contextmanager
def _locked_gate_asset_file(gate_bytes: bytes) -> Iterator[Path]:
    """Materialize the already-validated gate bytes under the required asset name."""
    with tempfile.TemporaryDirectory(prefix="hotdeal-focus-gate-upload-") as temporary:
        artifact_path = Path(temporary) / "filter.txt"
        _write_new_file(artifact_path, gate_bytes)
        yield artifact_path


def _verify_immutable_gate_release(
    repo: str,
    tag: str,
    subscription_url: str,
    gate_bytes: bytes,
    expected_source_sha: str | None = None,
) -> dict[str, Any]:
    if not _command_exists("gh"):
        raise PrerequisiteFailure(
            "GitHub CLI is required to verify the immutable gate release"
        )
    release = _gh_json(
        ("gh", "api", f"repos/{repo}/releases/tags/{tag}"),
        "immutable-gate-release",
        prerequisite=True,
    )
    assets = release.get("assets") if isinstance(release, dict) else None
    if (
        not isinstance(release, dict)
        or release.get("tag_name") != tag
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or release.get("immutable") is not True
        or not isinstance(release.get("published_at"), str)
        or not release["published_at"]
        or not isinstance(assets, list)
        or len(assets) != 1
    ):
        raise IntegrityFailure("gate release is not an exact published immutable release")
    source_commit = _remote_gate_tag_commit(repo, tag)
    if expected_source_sha is not None and source_commit != expected_source_sha.lower():
        raise IntegrityFailure("immutable gate tag is bound to a different source commit")
    asset = assets[0]
    expected_digest = f"sha256:{sha256_bytes(gate_bytes)}"
    if (
        not isinstance(asset, dict)
        or not isinstance(asset.get("id"), int)
        or asset["id"] < 1
        or asset.get("name") != "filter.txt"
        or asset.get("state") != "uploaded"
        or asset.get("size") != len(gate_bytes)
        or asset.get("digest") != expected_digest
        or asset.get("browser_download_url") != subscription_url
    ):
        raise IntegrityFailure("immutable gate release asset differs from the manifest")
    release_proof = _capture_command(
        ("gh", "release", "verify", tag, "--repo", repo, "--format", "json"),
        label="immutable-gate-attestation",
        timeout_seconds=60,
    )
    if release_proof.returncode:
        raise IntegrityFailure("GitHub immutable gate release attestation failed")
    _decode_json(release_proof.stdout, "immutable gate release attestation")
    download = _download_exact_gate_asset(
        repo,
        tag,
        gate_bytes,
        label="immutable-gate-asset-download",
    )
    with tempfile.TemporaryDirectory(prefix="hotdeal-focus-gate-attestation-") as temporary:
        artifact_path = Path(temporary) / "filter.txt"
        artifact_path.write_bytes(gate_bytes)
        asset_proof = _capture_command(
            (
                "gh", "release", "verify-asset", tag, str(artifact_path),
                "--repo", repo, "--format", "json",
            ),
            label="immutable-gate-asset-attestation",
            timeout_seconds=60,
        )
        if asset_proof.returncode:
            raise IntegrityFailure("GitHub immutable gate asset attestation failed")
        _decode_json(asset_proof.stdout, "immutable gate asset attestation")
    return {
        "repo": repo,
        "tag": tag,
        "immutable": True,
        "publishedAt": release["published_at"],
        "assetId": asset["id"],
        "assetBytes": len(gate_bytes),
        "assetSha256": sha256_bytes(gate_bytes),
        "sourceCommit": source_commit,
        "assetDownload": download.summary(),
        "releaseAttestation": release_proof.summary(),
        "assetAttestation": asset_proof.summary(),
    }


def _public_release_bundle(manifest_url: str) -> tuple[
    dict[str, Any],
    dict[str, bytes],
    list[dict[str, Any]],
    dict[str, str],
    dict[str, Any],
]:
    owner, repo_name, canonical_url = _validate_pages_manifest_url(manifest_url)
    binding = (owner, repo_name)
    manifest_bytes, final_manifest_url = _read_bounded_https(canonical_url, binding)
    _validate_pages_manifest_url(final_manifest_url)
    manifest, _ = _manifest_contract(manifest_bytes)
    artifact_bytes: dict[str, bytes] = {}
    artifact_urls: dict[str, str] = {}
    for name in PUBLIC_ARTIFACT_NAMES:
        url = f"https://{owner}.github.io/{repo_name}/{name}"
        content, final_url = _read_bounded_https(url, binding)
        _validate_pages_artifact_url(final_url, owner, repo_name)
        artifact_bytes[name] = content
        artifact_urls[name] = url
    manifest, records = _verify_release_files(manifest_bytes, artifact_bytes)
    _validate_gate_artifact_lock(manifest, artifact_bytes["filter.txt"])
    gate_owner, gate_repo, gate_tag = _gate_subscription_coordinates(
        manifest["filterSubscriptionUrl"], manifest["gateArtifactVersion"]
    )
    if (gate_owner.casefold(), gate_repo.casefold()) != (
        owner.casefold(), repo_name.casefold()
    ):
        raise IntegrityFailure("immutable gate release belongs to a different repository")
    gate_release = _verify_immutable_gate_release(
        f"{owner}/{repo_name}",
        gate_tag,
        manifest["filterSubscriptionUrl"],
        artifact_bytes["filter.txt"],
    )
    artifact_urls["filterMirrorUrl"] = artifact_urls["filter.txt"]
    artifact_urls["filter.txt"] = manifest["filterSubscriptionUrl"]
    artifact_urls["release-manifest.json"] = canonical_url
    return manifest, artifact_bytes, records, artifact_urls, gate_release


def _gate_release_binding(
    manifest: Mapping[str, Any],
    repo: str,
) -> tuple[str, str]:
    owner, repo_name, tag = _gate_subscription_coordinates(
        manifest.get("filterSubscriptionUrl"),
        str(manifest.get("gateArtifactVersion", "")),
    )
    bound_repo = f"{owner}/{repo_name}"
    if bound_repo.casefold() != repo.casefold():
        raise IntegrityFailure("gate release repository differs from the manifest binding")
    return bound_repo, tag


def _verify_gate_release_with_retry(
    repo: str,
    tag: str,
    subscription_url: str,
    gate_bytes: bytes,
    expected_source_sha: str | None = None,
) -> dict[str, Any]:
    last_error: CliFailure | None = None
    for attempt in range(6):
        try:
            return _verify_immutable_gate_release(
                repo, tag, subscription_url, gate_bytes, expected_source_sha
            )
        except CliFailure as error:
            last_error = error
            if attempt < 5:
                time.sleep(5)
    assert last_error is not None
    raise last_error


def _remote_gate_tag_commit(
    repo: str,
    tag: str,
    *,
    allow_missing: bool = False,
) -> str | None:
    tag_quoted = urllib.parse.quote(tag, safe="")
    capture = _capture_command(
        (
            "gh", "api", "--include", "-H",
            "X-GitHub-Api-Version: 2026-03-10",
            f"repos/{repo}/git/ref/tags/{tag_quoted}",
        ),
        label="gate-tag-reference",
        timeout_seconds=60,
    )
    normalized = capture.stdout.replace(b"\r\n", b"\n")
    header, separator, body = normalized.partition(b"\n\n")
    status_match = re.match(rb"^HTTP/\S+\s+([0-9]{3})\b", header)
    if not separator or status_match is None:
        raise IntegrityFailure("gate tag response has no exact HTTP status envelope")
    status_code = int(status_match.group(1))
    if status_code == 404:
        if capture.returncode == 0:
            raise IntegrityFailure("gate tag returned a contradictory missing state")
        if allow_missing:
            return None
        raise IntegrityFailure("immutable gate tag is missing")
    if capture.returncode or not 200 <= status_code < 300:
        raise TransientFailure("immutable gate tag could not be read")
    reference = _decode_json(body, "immutable gate tag reference")
    if (
        not isinstance(reference, dict)
        or reference.get("ref") != f"refs/tags/{tag}"
        or not isinstance(reference.get("object"), dict)
    ):
        raise IntegrityFailure("immutable gate tag reference is malformed")
    current_object = reference["object"]
    visited: set[str] = set()
    for depth in range(8):
        object_type = current_object.get("type") \
            if isinstance(current_object, dict) else None
        object_sha = current_object.get("sha") \
            if isinstance(current_object, dict) else None
        if (
            not isinstance(object_sha, str)
            or not GIT_SHA_RE.fullmatch(object_sha.lower())
            or object_sha.lower() in visited
        ):
            raise IntegrityFailure("immutable gate tag object is malformed or cyclic")
        object_sha = object_sha.lower()
        if object_type == "commit":
            return object_sha
        if object_type != "tag" or depth == 7:
            raise IntegrityFailure("immutable gate tag does not peel to one commit")
        visited.add(object_sha)
        annotated = _gh_json(
            ("gh", "api", f"repos/{repo}/git/tags/{object_sha}"),
            f"gate-annotated-tag-{depth + 1}",
        )
        current_object = annotated.get("object") \
            if isinstance(annotated, dict) else None
    raise IntegrityFailure("immutable gate tag peel exceeded its bound")


def _ensure_remote_gate_tag(repo: str, tag: str, source_sha: str) -> dict[str, Any]:
    existing = _remote_gate_tag_commit(repo, tag, allow_missing=True)
    if existing is not None:
        if existing != source_sha:
            raise IntegrityFailure("pre-existing gate tag targets a different commit")
        return {
            "verified": True,
            "status": "already-bound",
            "sourceCommit": existing,
            "mutationApplied": False,
        }
    capture: ExecutionCapture | None = None
    creation_error: str | None = None
    try:
        capture = _capture_command(
            (
                "gh", "api", "--method", "POST", "-H",
                "X-GitHub-Api-Version: 2026-03-10", f"repos/{repo}/git/refs",
                "-f", f"ref=refs/tags/{tag}", "-f", f"sha={source_sha}",
            ),
            label="create-gate-tag",
            timeout_seconds=60,
        )
        if capture.returncode:
            creation_error = "GitHub CLI returned a nonzero tag-create result"
    except (CliFailure, OSError) as error:
        creation_error = _safe_error(str(error))
    observed: str | None = None
    observation_error: str | None = None
    for attempt in range(6):
        try:
            observed = _remote_gate_tag_commit(repo, tag, allow_missing=True)
            if observed is not None:
                break
        except (CliFailure, OSError) as error:
            observation_error = _safe_error(str(error))
        if attempt < 5:
            time.sleep(5)
    accepted = capture is not None and capture.returncode == 0
    if observed == source_sha:
        return {
            "verified": True,
            "status": "created" if accepted else "observed-exact",
            "sourceCommit": observed,
            "mutationApplied": True if accepted else None,
            "creation": capture.summary() if capture else {"error": creation_error},
        }
    return {
        "verified": False,
        "status": "conflicting-target" if observed else "terminal-state-unknown",
        "sourceCommit": observed,
        "expectedSourceCommit": source_sha,
        "mutationApplied": True if accepted else None,
        "creation": capture.summary() if capture else {"error": creation_error},
        "observationError": observation_error,
    }


def _require_remote_default_head(repo: str, branch: str, source_sha: str) -> None:
    default_head = _gh_json(
        (
            "gh", "api",
            f"repos/{repo}/commits/{urllib.parse.quote(branch, safe='')}",
        ),
        "gate-release-default-head",
        prerequisite=True,
    )
    default_head_sha = default_head.get("sha") \
        if isinstance(default_head, dict) else None
    if (
        not isinstance(default_head_sha, str)
        or not GIT_SHA_RE.fullmatch(default_head_sha.lower())
        or default_head_sha.lower() != source_sha
    ):
        raise IntegrityFailure(
            "gate release source is not the current default-branch head"
        )


def _gate_release_view(
    repo: str,
    tag: str,
    *,
    allow_missing: bool = False,
) -> dict[str, Any] | None:
    capture = _capture_command(
        (
            "gh", "release", "view", tag, "--repo", repo,
            "--json", GATE_RELEASE_VIEW_FIELDS,
        ),
        label="gate-release-existence",
        timeout_seconds=60,
    )
    if capture.returncode:
        if allow_missing and _gate_release_is_definitively_absent(repo, tag):
            return None
        raise TransientFailure("GitHub gate release state could not be read")
    value = _decode_json(capture.stdout, "GitHub gate release state")
    expected_fields = set(GATE_RELEASE_VIEW_FIELDS.split(","))
    if (
        not isinstance(value, dict)
        or set(value) != expected_fields
        or not isinstance(value.get("assets"), list)
    ):
        raise IntegrityFailure("GitHub gate release view is malformed")
    return value


def _gate_release_is_definitively_absent(repo: str, tag: str) -> bool:
    """Use GitHub's exact tag lookup so transport/auth errors are never absence."""
    owner, name = _require_repo(repo).split("/", 1)
    capture = _capture_command(
        (
            "gh", "api", "graphql",
            "-f", f"query={GATE_RELEASE_EXISTENCE_QUERY}",
            "-f", f"owner={owner}",
            "-f", f"name={name}",
            "-f", f"tag={tag}",
        ),
        label="gate-release-definitive-absence",
        timeout_seconds=60,
    )
    if capture.returncode:
        raise TransientFailure("GitHub gate release absence could not be established")
    value = _decode_json(capture.stdout, "GitHub gate release absence probe")
    data = value.get("data") if isinstance(value, dict) and set(value) == {"data"} else None
    repository = (
        data.get("repository")
        if isinstance(data, dict) and set(data) == {"repository"}
        else None
    )
    if not isinstance(repository, dict) or set(repository) != {"release"}:
        raise IntegrityFailure("GitHub gate release absence probe is malformed")
    release = repository["release"]
    if release is None:
        return True
    if (
        not isinstance(release, dict)
        or set(release) != {"databaseId"}
        or type(release.get("databaseId")) is not int
        or release["databaseId"] < 1
    ):
        raise IntegrityFailure("GitHub gate release existence probe is malformed")
    return False


def _gate_release_view_summary(value: Mapping[str, Any]) -> dict[str, Any]:
    assets = value.get("assets") if isinstance(value.get("assets"), list) else []
    return {
        "databaseId": value.get("databaseId"),
        "tag": value.get("tagName"),
        "draft": value.get("isDraft"),
        "immutable": value.get("isImmutable"),
        "assetCount": len(assets),
        "assetDigests": [
            asset.get("digest") for asset in assets if isinstance(asset, Mapping)
        ],
    }


def _exact_gate_draft_has_asset(
    view: Mapping[str, Any],
    repo: str,
    tag: str,
    subscription_url: str,
    gate_bytes: bytes,
    source_sha: str,
) -> bool:
    if (
        type(view.get("databaseId")) is not int
        or view["databaseId"] < 1
        or view.get("tagName") != tag
        or view.get("name") != GATE_RELEASE_TITLE
        or view.get("body") != GATE_RELEASE_NOTES
        or view.get("isDraft") is not True
        or view.get("isPrerelease") is not False
        or view.get("isImmutable") is not False
        or view.get("publishedAt") is not None
        or not isinstance(view.get("targetCommitish"), str)
        or not isinstance(view.get("assets"), list)
        or len(view["assets"]) > 1
    ):
        raise IntegrityFailure("existing gate draft is not the exact recoverable draft")
    if _remote_gate_tag_commit(repo, tag) != source_sha:
        raise IntegrityFailure("existing gate draft tag targets a different source commit")
    if not view["assets"]:
        return False
    asset = view["assets"][0]
    expected_digest = f"sha256:{sha256_bytes(gate_bytes)}"
    if (
        not isinstance(asset, dict)
        or asset.get("name") != "filter.txt"
        or asset.get("state") != "uploaded"
        or type(asset.get("size")) is not int
        or asset["size"] != len(gate_bytes)
        or asset.get("digest") != expected_digest
        or asset.get("url") != subscription_url
    ):
        raise IntegrityFailure(
            "existing gate draft has a wrong, extra, or incomplete asset; deletion is forbidden"
        )
    return True


def _draft_recovery_failure(
    *,
    status: str,
    view: Mapping[str, Any],
    steps: Sequence[Mapping[str, Any]],
    error: str,
    accepted_mutation: bool,
    publish_accepted: bool = False,
) -> dict[str, Any]:
    return {
        "ok": False,
        "status": status,
        "release": _gate_release_view_summary(view),
        "mutations": list(steps),
        "error": _safe_error(error),
        "mutationApplied": True if accepted_mutation else None,
        "mutationState": (
            "applied-unverified"
            if publish_accepted
            else "partially-applied-unverified" if accepted_mutation
            else "unknown"
        ),
    }


def _recover_exact_gate_draft(
    repo: str,
    tag: str,
    subscription_url: str,
    gate_bytes: bytes,
    source_sha: str,
    initial_view: Mapping[str, Any],
) -> dict[str, Any]:
    """Resume only this tool's exact draft; never delete or replace an asset."""
    view = dict(initial_view)
    has_asset = _exact_gate_draft_has_asset(
        view, repo, tag, subscription_url, gate_bytes, source_sha
    )
    steps: list[dict[str, Any]] = []
    accepted_mutation = False
    ambiguous_mutation = False
    if not has_asset:
        upload: ExecutionCapture | None = None
        upload_error: str | None = None
        try:
            with _locked_gate_asset_file(gate_bytes) as artifact_path:
                upload = _capture_command(
                    (
                        "gh", "release", "upload", tag,
                        str(artifact_path), "--repo", repo,
                    ),
                    label="recover-gate-draft-asset",
                    timeout_seconds=120,
                )
            steps.append(upload.summary())
            if upload.returncode == 0:
                accepted_mutation = True
            else:
                ambiguous_mutation = True
                upload_error = "GitHub CLI returned a nonzero draft-asset upload result"
        except (CliFailure, OSError) as error:
            ambiguous_mutation = True
            upload_error = _safe_error(str(error))
            steps.append({"id": "recover-gate-draft-asset", "error": upload_error})

        observation_error: str | None = None
        observed_exact_asset = False
        for attempt in range(6):
            try:
                observed = _gate_release_view(repo, tag)
                assert observed is not None
                view = observed
                observation_error = None
                if view.get("isDraft") is not True:
                    try:
                        proof = _verify_gate_release_with_retry(
                            repo, tag, subscription_url, gate_bytes, source_sha
                        )
                    except (CliFailure, OSError) as error:
                        return _draft_recovery_failure(
                            status="draft-published-unverified",
                            view=view,
                            steps=steps,
                            error=str(error),
                            accepted_mutation=accepted_mutation,
                        )
                    return {
                        "ok": True,
                        "status": "draft-published-concurrently",
                        "release": _gate_release_view_summary(view),
                        "mutations": steps,
                        "proof": proof,
                        "mutationApplied": True if accepted_mutation else None,
                        "mutationState": "observed-exact",
                    }
                observed_exact_asset = _exact_gate_draft_has_asset(
                    view, repo, tag, subscription_url, gate_bytes, source_sha
                )
                if observed_exact_asset:
                    break
            except IntegrityFailure as error:
                return _draft_recovery_failure(
                    status="draft-asset-conflict",
                    view=view,
                    steps=steps,
                    error=str(error),
                    accepted_mutation=accepted_mutation,
                )
            except (CliFailure, OSError) as error:
                observation_error = _safe_error(str(error))
            if attempt < 5:
                time.sleep(5)
        if not observed_exact_asset:
            return _draft_recovery_failure(
                status="draft-asset-terminal-state-unknown",
                view=view,
                steps=steps,
                error=observation_error or upload_error or "exact draft asset was not observed",
                accepted_mutation=accepted_mutation,
            )

    try:
        download = _download_exact_gate_asset(
            repo,
            tag,
            gate_bytes,
            label="recover-gate-draft-asset-download",
        )
        steps.append(download.summary())
    except (CliFailure, OSError) as error:
        if not accepted_mutation and not ambiguous_mutation:
            raise
        return _draft_recovery_failure(
            status="draft-asset-download-unverified",
            view=view,
            steps=steps,
            error=str(error),
            accepted_mutation=accepted_mutation,
        )

    publish: ExecutionCapture | None = None
    publish_error: str | None = None
    try:
        publish = _capture_command(
            (
                "gh", "release", "edit", tag, "--repo", repo,
                "--draft=false", "--latest=false", "--verify-tag",
            ),
            label="publish-recovered-gate-draft",
            timeout_seconds=120,
        )
        steps.append(publish.summary())
        if publish.returncode == 0:
            accepted_mutation = True
        else:
            ambiguous_mutation = True
            publish_error = "GitHub CLI returned a nonzero draft-publish result"
    except (CliFailure, OSError) as error:
        ambiguous_mutation = True
        publish_error = _safe_error(str(error))
        steps.append({"id": "publish-recovered-gate-draft", "error": publish_error})
    publish_accepted = publish is not None and publish.returncode == 0
    try:
        proof = _verify_gate_release_with_retry(
            repo, tag, subscription_url, gate_bytes, source_sha
        )
    except (CliFailure, OSError) as error:
        return _draft_recovery_failure(
            status="draft-publication-terminal-state-unknown",
            view=view,
            steps=steps,
            error=str(error) if str(error) else (publish_error or "publication was not verified"),
            accepted_mutation=accepted_mutation,
            publish_accepted=publish_accepted,
        )
    return {
        "ok": True,
        "status": (
            "recovered-exact-draft-after-ambiguous-client-result"
            if ambiguous_mutation else "recovered-exact-draft"
        ),
        "release": _gate_release_view_summary(view),
        "mutations": steps,
        "proof": proof,
        "mutationApplied": True if accepted_mutation else None,
        "mutationState": "applied" if publish_accepted else "observed-exact",
    }


def _resume_gate_draft_after_ambiguous_create(
    repo: str,
    tag: str,
    subscription_url: str,
    gate_bytes: bytes,
    source_sha: str,
) -> dict[str, Any] | None:
    """Resume an exact draft left by a failed or interrupted create command."""
    view = _gate_release_view(repo, tag, allow_missing=True)
    if view is None or view.get("isDraft") is not True:
        return None
    return _recover_exact_gate_draft(
        repo, tag, subscription_url, gate_bytes, source_sha, view
    )


def _immutable_release_policy(repo: str) -> dict[str, Any]:
    policy = _gh_json(
        (
            "gh", "api", "-H", "X-GitHub-Api-Version: 2026-03-10",
            f"repos/{repo}/immutable-releases",
        ),
        "immutable-release-policy",
        prerequisite=True,
    )
    if not isinstance(policy, dict) or type(policy.get("enabled")) is not bool:
        raise IntegrityFailure("repository immutable-release policy is malformed")
    return policy


def _gate_policy_repository(repo: str) -> dict[str, Any]:
    repository = _gh_json(
        (
            "gh", "repo", "view", repo, "--json",
            "nameWithOwner,visibility,viewerPermission",
        ),
        "gate-policy-repository",
        prerequisite=True,
    )
    if (
        not isinstance(repository, dict)
        or str(repository.get("nameWithOwner", "")).casefold() != repo.casefold()
        or repository.get("visibility") != "PUBLIC"
        or repository.get("viewerPermission") != "ADMIN"
    ):
        raise IntegrityFailure(
            "repository operation requires the exact public repository and admin access"
        )
    return repository


def _command_gate_policy(args: argparse.Namespace, repo: str) -> dict[str, Any]:
    if args.source_ref:
        raise UsageFailure("gate-release enable-policy does not accept --source-ref")
    _gate_policy_repository(repo)
    policy = _immutable_release_policy(repo)
    if policy["enabled"]:
        result = _base_result(
            "gate-release.enable-policy",
            ok=True,
            status="already-enabled",
            source_sha=_try_source_sha(),
            repo=repo,
            immutableReleasesEnabled=True,
            mutationApplied=False,
        )
        return _attach_command_evidence(result, args.evidence_dir)
    if not args.apply:
        result = _base_result(
            "gate-release.enable-policy",
            ok=True,
            status="dry-run",
            source_sha=_try_source_sha(),
            repo=repo,
            immutableReleasesEnabled=False,
            wouldEnable=True,
            mutationApplied=False,
        )
        return _attach_command_evidence(result, args.evidence_dir)
    enable_capture: ExecutionCapture | None = None
    enable_error: str | None = None
    try:
        enable_capture = _capture_command(
            (
                "gh", "api", "--method", "PUT", "-H",
                "X-GitHub-Api-Version: 2026-03-10",
                f"repos/{repo}/immutable-releases",
            ),
            label="enable-immutable-releases",
            timeout_seconds=60,
        )
        if enable_capture.returncode:
            enable_error = "GitHub CLI returned a nonzero policy-enable result"
    except (CliFailure, OSError) as error:
        enable_error = _safe_error(str(error))
    post_policy: dict[str, Any] | None = None
    verification_error: str | None = None
    for attempt in range(6):
        try:
            post_policy = _immutable_release_policy(repo)
            if post_policy["enabled"]:
                break
        except (CliFailure, OSError) as error:
            verification_error = _safe_error(str(error))
        if attempt < 5:
            time.sleep(5)
    if post_policy is not None and post_policy["enabled"]:
        accepted = enable_capture is not None and enable_capture.returncode == 0
        result = _base_result(
            "gate-release.enable-policy",
            ok=True,
            status="enabled" if accepted else "enabled-after-ambiguous-client-result",
            source_sha=_try_source_sha(),
            repo=repo,
            immutableReleasesEnabled=True,
            policyMutation=(enable_capture.summary() if enable_capture else {
                "error": enable_error,
            }),
            mutationApplied=True if accepted else None,
            mutationState="applied" if accepted else "observed-enabled",
        )
        return _attach_post_mutation_evidence(result, args.evidence_dir)
    accepted = enable_capture is not None and enable_capture.returncode == 0
    result = _base_result(
        "gate-release.enable-policy",
        ok=False,
        status=(
            "policy-enable-applied-unverified" if accepted
            else "policy-enable-terminal-state-unknown"
        ),
        source_sha=_try_source_sha(),
        repo=repo,
        immutableReleasesEnabled=False,
        policyMutation=(enable_capture.summary() if enable_capture else {
            "error": enable_error,
        }),
        verificationError=verification_error,
        mutationApplied=True if accepted else None,
        mutationState="applied-unverified" if accepted else "unknown",
    )
    result["_processExitCode"] = EXIT_ROLLBACK_INCOMPLETE
    return _attach_post_mutation_evidence(result, args.evidence_dir)


def command_gate_release(args: argparse.Namespace) -> dict[str, Any]:
    repo = _require_repo(args.repo)
    if not _command_exists("gh"):
        raise PrerequisiteFailure("GitHub CLI is unavailable")
    if args.evidence_dir:
        _assert_new_directory(Path(args.evidence_dir))
    if args.action == "enable-policy":
        return _command_gate_policy(args, repo)
    manifest, artifacts = _local_release_contract()
    bound_repo, tag = _gate_release_binding(manifest, repo)
    gate_bytes = (PROJECT_ROOT / "filter.txt").read_bytes()
    _validate_locked_gate_bytes(gate_bytes)
    subscription_url = manifest["filterSubscriptionUrl"]
    if args.action == "verify":
        if args.apply or args.source_ref:
            raise UsageFailure("gate-release verify is read-only")
        proof = _verify_gate_release_with_retry(
            bound_repo, tag, subscription_url, gate_bytes
        )
        result = _base_result(
            "gate-release.verify",
            ok=True,
            status="verified",
            source_sha=_try_source_sha(),
            artifacts=artifacts,
            gateRelease=proof,
            mutationApplied=False,
        )
        return _attach_command_evidence(result, args.evidence_dir)
    if args.action != "publish":
        raise UsageFailure("unknown gate release action")
    if not args.apply or not args.source_ref:
        raise UsageFailure("gate-release publish requires --source-ref and --apply")
    source_sha = _git_source_binding(args.source_ref)
    repository = _gh_json(
        (
            "gh", "repo", "view", bound_repo, "--json",
            "nameWithOwner,visibility,defaultBranchRef",
        ),
        "gate-release-repository",
        prerequisite=True,
    )
    default_branch_ref = repository.get("defaultBranchRef") \
        if isinstance(repository, dict) else None
    default_branch = default_branch_ref.get("name") \
        if isinstance(default_branch_ref, dict) else None
    if (
        not isinstance(repository, dict)
        or str(repository.get("nameWithOwner", "")).casefold()
        != bound_repo.casefold()
        or repository.get("visibility") != "PUBLIC"
        or not isinstance(default_branch, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,254}", default_branch)
        or ".." in default_branch
        or "//" in default_branch
        or default_branch.endswith(("/", ".", ".lock"))
    ):
        raise IntegrityFailure("gate release repository is not the exact public repository")
    commit = _gh_json(
        ("gh", "api", f"repos/{bound_repo}/commits/{source_sha}"),
        "gate-release-source-commit",
        prerequisite=True,
    )
    if not isinstance(commit, dict) or str(commit.get("sha", "")).lower() != source_sha:
        raise IntegrityFailure("gate release source commit is not present in the repository")
    existing = _gate_release_view(bound_repo, tag, allow_missing=True)
    if existing is not None and existing.get("isDraft") is not True:
        proof = _verify_gate_release_with_retry(
            bound_repo, tag, subscription_url, gate_bytes
        )
        result = _base_result(
            "gate-release.publish",
            ok=True,
            status="already-published",
            source_sha=source_sha,
            artifacts=artifacts,
            gateRelease=proof,
            mutationApplied=False,
        )
        return _attach_command_evidence(result, args.evidence_dir)
    policy = _immutable_release_policy(bound_repo)
    if policy["enabled"] is not True:
        raise IntegrityFailure("repository immutable releases are not enabled")
    if existing is not None and existing.get("isDraft") is True:
        _require_remote_default_head(bound_repo, default_branch, source_sha)
        recovery = _recover_exact_gate_draft(
            bound_repo,
            tag,
            subscription_url,
            gate_bytes,
            source_sha,
            existing,
        )
        if not recovery["ok"]:
            result = _base_result(
                "gate-release.publish",
                ok=False,
                status=str(recovery["status"]),
                source_sha=source_sha,
                artifacts=artifacts,
                gateDraftRecovery=recovery,
                mutationApplied=recovery["mutationApplied"],
                mutationState=recovery["mutationState"],
            )
            result["_processExitCode"] = EXIT_ROLLBACK_INCOMPLETE
            return _attach_post_mutation_evidence(result, args.evidence_dir)
        result = _base_result(
            "gate-release.publish",
            ok=True,
            status=str(recovery["status"]),
            source_sha=source_sha,
            artifacts=artifacts,
            gateRelease=recovery["proof"],
            gateDraftRecovery={
                key: value for key, value in recovery.items() if key != "proof"
            },
            mutationApplied=recovery["mutationApplied"],
            mutationState=recovery["mutationState"],
        )
        return _attach_post_mutation_evidence(result, args.evidence_dir)
    _require_remote_default_head(bound_repo, default_branch, source_sha)
    tag_binding = _ensure_remote_gate_tag(bound_repo, tag, source_sha)
    if not tag_binding["verified"]:
        result = _base_result(
            "gate-release.publish",
            ok=False,
            status="gate-tag-binding-unverified",
            source_sha=source_sha,
            artifacts=artifacts,
            gateTag=tag_binding,
            mutationApplied=tag_binding["mutationApplied"],
            mutationState=(
                "partially-applied-unverified"
                if tag_binding["mutationApplied"] is True else "unknown"
            ),
        )
        result["_processExitCode"] = EXIT_ROLLBACK_INCOMPLETE
        return _attach_post_mutation_evidence(result, args.evidence_dir)
    creation: ExecutionCapture | None = None
    creation_error: str | None = None
    try:
        with _locked_gate_asset_file(gate_bytes) as artifact_path:
            creation = _capture_command(
                (
                    "gh", "release", "create", tag, str(artifact_path),
                    "--repo", bound_repo,
                    "--verify-tag",
                    "--title", GATE_RELEASE_TITLE,
                    "--notes", GATE_RELEASE_NOTES,
                    "--latest=false",
                ),
                label="publish-immutable-gate-release",
                timeout_seconds=180,
            )
    except (CliFailure, OSError) as error:
        creation_error = _safe_error(str(error))
    creation_record = (
        creation.summary() if creation is not None else {"error": creation_error}
    )
    creation_accepted = creation is not None and creation.returncode == 0
    try:
        proof = _verify_gate_release_with_retry(
            bound_repo, tag, subscription_url, gate_bytes, source_sha
        )
    except (CliFailure, OSError) as verification_error:
        recovery: dict[str, Any] | None = None
        recovery_error: str | None = None
        if not creation_accepted:
            try:
                recovery = _resume_gate_draft_after_ambiguous_create(
                    bound_repo, tag, subscription_url, gate_bytes, source_sha
                )
            except (CliFailure, OSError) as error:
                recovery_error = _safe_error(str(error))
        if recovery is not None:
            recovery_applied = recovery.get("mutationApplied") is True
            mutation_applied = (
                True
                if tag_binding["mutationApplied"] is True or recovery_applied
                else None
            )
            mutation_state = str(recovery.get("mutationState", "unknown"))
            if recovery.get("ok") is True:
                result = _base_result(
                    "gate-release.publish",
                    ok=True,
                    status=str(recovery["status"]),
                    source_sha=source_sha,
                    artifacts=artifacts,
                    gateRelease=recovery["proof"],
                    gateDraftRecovery={
                        key: value for key, value in recovery.items() if key != "proof"
                    },
                    releaseCreation=creation_record,
                    gateTag=tag_binding,
                    initialVerificationError=_safe_error(str(verification_error)),
                    mutationApplied=mutation_applied,
                    mutationState=mutation_state,
                )
                return _attach_post_mutation_evidence(result, args.evidence_dir)
            if tag_binding["mutationApplied"] is True and not recovery_applied:
                mutation_state = "partially-applied-unverified"
            result = _base_result(
                "gate-release.publish",
                ok=False,
                status=str(recovery.get("status", "draft-recovery-failed")),
                source_sha=source_sha,
                artifacts=artifacts,
                gateDraftRecovery=recovery,
                releaseCreation=creation_record,
                gateTag=tag_binding,
                initialVerificationError=_safe_error(str(verification_error)),
                mutationApplied=mutation_applied,
                mutationState=mutation_state,
            )
            result["_processExitCode"] = EXIT_ROLLBACK_INCOMPLETE
            return _attach_post_mutation_evidence(result, args.evidence_dir)
        known_mutation = creation_accepted or tag_binding["mutationApplied"] is True
        result = _base_result(
            "gate-release.publish",
            ok=False,
            status=(
                "published-unverified"
                if creation_accepted else "publication-terminal-state-unknown"
            ),
            source_sha=source_sha,
            artifacts=artifacts,
            gateRelease={
                "repo": bound_repo,
                "tag": tag,
                "subscriptionUrl": subscription_url,
                "verified": False,
                "verificationError": _safe_error(str(verification_error)),
            },
            gateDraftRecovery=(
                {
                    "ok": False,
                    "status": "draft-recovery-observation-failed",
                    "error": recovery_error,
                }
                if recovery_error is not None else None
            ),
            releaseCreation=creation_record,
            gateTag=tag_binding,
            mutationApplied=True if known_mutation else None,
            mutationState=(
                "applied-unverified"
                if creation_accepted
                else "partially-applied-unverified"
                if tag_binding["mutationApplied"] is True
                else "unknown"
            ),
        )
        result["_processExitCode"] = EXIT_ROLLBACK_INCOMPLETE
        return _attach_post_mutation_evidence(result, args.evidence_dir)
    if creation_accepted:
        status = "published"
        mutation_applied = True
    else:
        status = "published-after-ambiguous-client-result"
        mutation_applied = True if tag_binding["mutationApplied"] is True else None
    result = _base_result(
        "gate-release.publish",
        ok=True,
        status=status,
        source_sha=source_sha,
        artifacts=artifacts,
        gateRelease=proof,
        releaseCreation=creation_record,
        gateTag=tag_binding,
        mutationApplied=mutation_applied,
        mutationState="applied" if mutation_applied is True else "observed-exact",
    )
    return (
        _attach_post_mutation_evidence(result, args.evidence_dir)
        if mutation_applied is not False
        else _attach_command_evidence(result, args.evidence_dir)
    )


def _child_recovery_details(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    recovery = {
        key: value[key]
        for key in (
            "backup",
            "backup_path",
            "recovery_command",
            "recovery_command_contains_credentials",
        )
        if key in value
    }
    return {"adguardRecovery": _public_value(recovery)} if recovery else {}


def _powershell_json(argv: Sequence[str], *, apply_mutation: bool, rollback: bool) -> Any:
    try:
        capture = _capture_command(argv, label="adguard-delegation", timeout_seconds=600)
    except (TransientFailure, PrerequisiteFailure) as error:
        if apply_mutation:
            raise MutationFailure(
                "AdGuard mutation child state is unknown",
                rollback_complete=False,
            ) from error
        raise
    if capture.returncode:
        text = (capture.stdout + b"\n" + capture.stderr).decode(
            "utf-8", errors="replace"
        )
        child_failure: Any = None
        try:
            child_failure = json.loads(capture.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
        rollback_incomplete = "rollback was incomplete" in text.lower()
        if apply_mutation:
            if not isinstance(child_failure, dict):
                raise MutationFailure(
                    "AdGuard mutation child returned no trustworthy recovery state",
                    rollback_complete=False,
                )
            successful_backup = child_failure.get("backup")
            if isinstance(successful_backup, str) and successful_backup:
                recovery_details = _child_recovery_details(child_failure)
                recovery_details.update({
                    "mutationApplied": True,
                    "mutationState": "applied-process-error",
                    "adguard": _public_value(child_failure),
                })
                raise MutationFailure(
                    "AdGuard mutation reported success but the child process failed during cleanup",
                    rollback_complete=False,
                    details=recovery_details,
                )
            mutation_started = rollback or (
                isinstance(child_failure.get("backup_path"), str)
                and bool(child_failure["backup_path"])
            )
            if not mutation_started:
                raise VerificationFailure("AdGuard apply preflight failed before mutation")
            raise MutationFailure(
                "AdGuard mutation failed",
                rollback_complete=(not rollback_incomplete and not rollback),
                details=_child_recovery_details(child_failure),
            )
        raise VerificationFailure("AdGuard delegated verification or plan failed")
    try:
        value = _decode_json(capture.stdout, "AdGuard CLI output")
    except IntegrityFailure as error:
        if apply_mutation:
            raise MutationFailure(
                "AdGuard mutation child returned malformed success output",
                rollback_complete=False,
            ) from error
        raise
    if apply_mutation and not isinstance(value, dict):
        raise MutationFailure(
            "AdGuard mutation child returned an invalid success contract",
            rollback_complete=False,
        )
    if not isinstance(value, dict) or value.get("ok") is False:
        message = _safe_error(str(value.get("error", "AdGuard operation failed"))) \
            if isinstance(value, dict) else "AdGuard operation failed"
        rollback_incomplete = "rollback was incomplete" in message.lower()
        if apply_mutation:
            if not value.get("backup_path"):
                raise MutationFailure(
                    "AdGuard mutation child reported an unproven terminal state",
                    rollback_complete=False,
                )
            raise MutationFailure(
                message,
                rollback_complete=(not rollback_incomplete and not rollback),
                details=_child_recovery_details(value),
            )
        raise VerificationFailure(message)
    return _public_value(value)


def command_adguard(args: argparse.Namespace) -> dict[str, Any]:
    if sys.platform != "win32":
        raise PrerequisiteFailure("AdGuard commands are supported only on Windows")
    if not _command_exists("powershell.exe"):
        raise PrerequisiteFailure("Windows PowerShell 5.1 is unavailable")
    if args.evidence_dir:
        _assert_new_directory(Path(args.evidence_dir))
    ps_cli = PROJECT_ROOT / "scripts" / "adguard_windows_cli.ps1"
    if not ps_cli.is_file():
        raise PrerequisiteFailure("typed AdGuard PowerShell delegate is missing")
    action = args.action
    if action == "inspect":
        if args.apply or args.approve_exclusive_target_migration:
            raise UsageFailure("adguard inspect is read-only")
        child = _powershell_json(
            (
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(ps_cli), "inspect",
            ),
            apply_mutation=False,
            rollback=False,
        )
        result = _base_result(
            "adguard.inspect", ok=True, status="observed", source_sha=_try_source_sha(),
            adguard=child,
        )
        return _attach_command_evidence(result, args.evidence_dir)
    if action == "rollback":
        if not args.backup_path:
            raise UsageFailure("adguard rollback requires --backup-path")
        if args.approve_exclusive_target_migration:
            raise UsageFailure("rollback does not accept migration approval")
        child_args = [
            "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(ps_cli), "restore-backup", "-BackupPath", args.backup_path,
            "-Apply" if args.apply else "-WhatIf",
        ]
        child = _powershell_json(
            child_args, apply_mutation=bool(args.apply), rollback=True
        )
        result = _base_result(
            "adguard.rollback",
            ok=True,
            status="rolled-back" if args.apply else "dry-run",
            source_sha=_try_source_sha(),
            mutationApplied=bool(args.apply),
            adguard=child,
        )
        return (
            _attach_post_mutation_evidence(result, args.evidence_dir)
            if args.apply
            else _attach_command_evidence(result, args.evidence_dir)
        )
    if args.backup_path:
        raise UsageFailure("backup-path is accepted only by adguard rollback")
    if action in {"inspect", "plan", "verify"} and args.apply:
        raise UsageFailure(f"adguard {action} is non-mutating and rejects --apply")
    if action == "deploy" and args.apply and not args.approve_exclusive_target_migration:
        raise UsageFailure(
            "deploy --apply requires --approve-exclusive-target-migration"
        )
    if action != "deploy" and args.approve_exclusive_target_migration:
        raise UsageFailure("migration approval is accepted only by adguard deploy")
    manifest, _, artifacts, urls, gate_release = _public_release_bundle(
        args.manifest_source
    )
    filter_entry = manifest["artifacts"]["filter.txt"]
    script_entry = manifest["artifacts"]["hotdeal-focus.user.js"]
    delegated_action = "verify" if action == "verify" else "deploy"
    child_args = [
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", str(ps_cli), delegated_action,
        "-UserscriptSource", urls["hotdeal-focus.user.js"],
        "-FilterUrl", urls["filter.txt"],
        "-ReleaseManifestSource", urls["release-manifest.json"],
        "-ExpectedUserscriptSha256", script_entry["canonicalTextSha256"],
        "-ExpectedFilterSha256", filter_entry["sha256"],
        "-ExpectedInstalledFilterRulesSha256", filter_entry["installedRulesSha256"],
    ]
    apply_mutation = action == "deploy" and bool(args.apply)
    if apply_mutation:
        child_args.extend(("-ApproveExclusiveTargetMigration", "-Apply"))
    elif delegated_action == "deploy":
        child_args.append("-WhatIf")
    child = _powershell_json(
        child_args, apply_mutation=apply_mutation, rollback=False
    )
    result = _base_result(
        f"adguard.{action}",
        ok=True,
        status=("deployed" if apply_mutation else
                "verified" if action == "verify" else "dry-run"),
        source_sha=_try_source_sha(),
        artifacts=artifacts,
        releaseVersion=manifest["releaseVersion"],
        gateArtifactVersion=manifest["gateArtifactVersion"],
        gateRelease=gate_release,
        manifestSource=args.manifest_source,
        mutationApplied=apply_mutation,
        exclusiveTargetMigrationApproved=apply_mutation,
        adguard=child,
    )
    return (
        _attach_post_mutation_evidence(result, args.evidence_dir)
        if apply_mutation
        else _attach_command_evidence(result, args.evidence_dir)
    )


def build_parser() -> JsonArgumentParser:
    parser = JsonArgumentParser(prog="hotdeal-focus", add_help=True)
    commands = parser.add_subparsers(dest="top_command", required=True)

    doctor = commands.add_parser("doctor")
    doctor.add_argument("--json", action="store_true", required=True)
    doctor.set_defaults(execute=command_doctor)

    build = commands.add_parser("build")
    build.add_argument("--check", action="store_true")
    build.add_argument("--json", action="store_true", required=True)
    build.add_argument("--evidence-dir")
    build.set_defaults(execute=command_build)

    verify = commands.add_parser("verify")
    verify.add_argument("--profile", choices=("fast", "release", "live"), required=True)
    verify.add_argument("--json", action="store_true", required=True)
    verify.add_argument("--evidence-dir", required=True)
    verify.set_defaults(execute=command_verify)

    release = commands.add_parser("release-evidence")
    release.add_argument("--source-ref", required=True)
    release.add_argument("--output-dir", required=True)
    release.add_argument("--json", action="store_true", required=True)
    release.set_defaults(execute=command_release_evidence)

    cloud = commands.add_parser("cloud")
    cloud.add_argument(
        "action", choices=(
            "configure", "dispatch", "status", "watch", "download-evidence"
        )
    )
    cloud.add_argument("--repo", required=True)
    cloud.add_argument("--workflow", choices=WORKFLOW_FILES, default="verify.yml")
    cloud.add_argument("--run-id")
    cloud.add_argument("--output-root")
    cloud.add_argument("--evidence-dir")
    cloud.add_argument("--apply", action="store_true")
    cloud.add_argument("--json", action="store_true", required=True)
    cloud.set_defaults(execute=command_cloud)

    gate_release = commands.add_parser("gate-release")
    gate_release.add_argument(
        "action", choices=("enable-policy", "verify", "publish")
    )
    gate_release.add_argument("--repo", required=True)
    gate_release.add_argument("--source-ref")
    gate_release.add_argument("--evidence-dir")
    gate_release.add_argument("--apply", action="store_true")
    gate_release.add_argument("--json", action="store_true", required=True)
    gate_release.set_defaults(execute=command_gate_release)

    adguard = commands.add_parser("adguard")
    adguard.add_argument(
        "action", choices=("inspect", "plan", "deploy", "verify", "rollback")
    )
    adguard.add_argument("--manifest-source", default=DEFAULT_PAGES_MANIFEST)
    adguard.add_argument("--backup-path")
    adguard.add_argument("--evidence-dir")
    adguard.add_argument("--approve-exclusive-target-migration", action="store_true")
    adguard.add_argument("--apply", action="store_true")
    adguard.add_argument("--json", action="store_true", required=True)
    adguard.set_defaults(execute=command_adguard)
    return parser


def _failure_command(argv: Sequence[str], args: argparse.Namespace | None) -> str:
    if args is not None and getattr(args, "top_command", None):
        top = str(args.top_command)
        action = getattr(args, "action", None)
        return f"{top}.{action}" if action else top
    if argv and argv[0] in {
        "doctor", "build", "verify", "release-evidence", "cloud",
        "gate-release", "adguard",
    }:
        return str(argv[0])
    return "unknown"


def main(argv: Sequence[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    parsed: argparse.Namespace | None = None
    try:
        parsed = build_parser().parse_args(raw_args)
        result = parsed.execute(parsed)
        explicit_exit_code = result.pop("_processExitCode", None)
        exit_code = (
            int(explicit_exit_code)
            if isinstance(explicit_exit_code, int)
            else EXIT_SUCCESS if result.get("ok") else EXIT_PREREQUISITE
        )
    except CliFailure as error:
        command = _failure_command(raw_args, parsed)
        result = _base_result(
            command,
            ok=False,
            status=error.status,
            source_sha=None,
            error=_safe_error(str(error)),
            **_public_value(error.details),
        )
        exit_code = error.exit_code
        evidence_path = getattr(parsed, "evidence_dir", None) if parsed else None
        if evidence_path:
            try:
                result = _attach_command_evidence(result, evidence_path)
            except CliFailure as evidence_error:
                result["evidence"] = {
                    "ok": False,
                    "error": _safe_error(str(evidence_error)),
                }
    except Exception as error:  # Defensive boundary: never leak traceback or environment.
        command = _failure_command(raw_args, parsed)
        result = _base_result(
            command,
            ok=False,
            status="integrity-conflict",
            source_sha=None,
            error="unexpected internal failure",
            errorType=type(error).__name__,
        )
        _log(f"unexpected internal failure: {type(error).__name__}")
        exit_code = EXIT_INTEGRITY
    print(
        json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        flush=True,
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
