#!/usr/bin/env python3
"""Machine-oriented orchestration CLI for Hotdeal Focus.

The CLI deliberately exposes a small, typed command vocabulary.  Child processes
are always invoked with argument arrays and captured output, so callers receive one
JSON document on stdout and never have to scrape human-oriented command output.
"""

from __future__ import annotations

import argparse
import base64
import fnmatch
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
GATE_LOCK_PROTOCOL_VERSION = 2
GATE_LOCK_ARTIFACT_VERSION = "2.0.2"
GATE_LOCK_SUBSCRIPTION_URL = (
    "https://github.com/heelee912/adguard-hotdeal-focus/releases/download/"
    "gate-v2.0.2/filter.txt"
)
GATE_LOCK_BYTES = 70270
GATE_LOCK_SHA256 = "778c88297473f1aa94564e24780cdcc763164e6de9a7c6ab5ffd42df0e18ae38"
GATE_LOCK_INSTALLED_RULES_SHA256 = (
    "a7619be2bebf35f6f502366627697c19690c81adb6833c7cdaf7440066b593bb"
)
GATE_LOCK_RULE_COUNT = 91
READER_GATE_NAME = "AdGuard Hotdeal Focus Reader Gate"
MARKER_GATE_NAME = "AdGuard Hotdeal Focus Marker Gate"
READER_GATE_PROTOCOL_VERSION = 2
READER_GATE_GRANT = "GM_addElement"
READER_GATE_REQUIRED_HOSTS = (
    "algumon.com", "clien.net", "ppomppu.co.kr", "ruliweb.com",
    "quasarzone.com", "eomisae.co.kr", "zod.kr", "arca.live",
)
READER_GATE_REQUIRED_ATTRIBUTES = (
    "data-hotdeal-focus-lock", "data-hotdeal-focus-ready",
    "data-hotdeal-focus-keep", "data-hotdeal-focus-protocol",
    "data-hotdeal-focus-shell", "data-hotdeal-focus-deep",
    "data-hotdeal-focus-role", "data-hotdeal-focus-state",
    "data-hotdeal-focus-status",
)
READER_GATE_REQUIRED_CLASSES = (
    "hdf-v2-lock", "hdf-v2-ready", "hdf-v2-keep", "hdf-v2-shell",
    "hdf-v2-deep", "hdf-v2-role-",
)
CSP_PROBE_SOURCE_SHA256 = (
    "3797355e3257c4f2ad67cca61af1cb182b377c9b91a47b76c48cb559547d842a"
)
CSP_PROBE_ENDPOINT = (
    "https://testcases.agrd.dev/userscripts-csp/header-csp-default-src-none"
)
CSP_PROBE_PARSED_META_CONTRACT = {
    "match_count": 1,
    "match_exact": True,
    "include_count": 0,
    "exclude_count": 0,
    "grant_count": 1,
    "grant_exact": True,
    "connect_count": 0,
    "require_count": 0,
    "resource_count": 0,
    "noframes": True,
    "run_at_document_start": True,
    "namespace_exact": True,
    "download_url_absent": False,
    "download_url_is_file": True,
    "download_url_is_https": False,
    "update_url_absent": True,
    "unsafe_csp_required": True,
}
CSP_PROBE_BROWSER_KEYS = frozenset({
    "schema_version", "command", "ok", "origin_status_exact",
    "origin_content_type_exact", "origin_csp_exact", "origin_html_semantics_exact",
    "endpoint_exact", "response_status_ok", "response_content_type_exact",
    "page_identity_exact", "effective_csp_present",
    "effective_csp_directive_set_exact", "effective_csp_default_rewrite_exact",
    "effective_csp_connect_rewrite_exact", "effective_csp_script_rewrite_exact",
    "effective_csp_style_rewrite_exact", "effective_csp_restrictions_preserved",
    "adguard_content_script_request_exact", "adguard_user_script_request_exact",
    "probe_selected_exact", "probe_state_complete", "raw_style_element_present",
    "raw_style_applied", "raw_engine_attributes_absent", "gm_style_count_exact",
    "gm_style_applied", "engine_nonce_present", "engine_data_source_present",
    "userscript_marker_consistent", "computed_custom_property",
})
GATE_RELEASE_TITLE = "Hotdeal Focus Gate v2 / 핫딜 포커스 게이트 v2"
GATE_RELEASE_NOTES = (
    "Immutable protocol-v2 class-and-attribute fail-closed gate. It is the distinct "
    "successor to gate-v1.0.0; v1 remains unchanged as rollback evidence and is never "
    "overwritten. Protocol-v1 compatibility and fallback are not accepted. / "
    "프로토콜 v2 클래스·속성 fail-closed 불변 게이트입니다. gate-v1.0.0은 "
    "롤백 증거로 변경 없이 보존되며 절대 덮어쓰지 않습니다. v1 호환과 fallback은 "
    "허용하지 않습니다. / プロトコル v2 のクラス・属性 fail-closed 不変ゲートです。"
    "gate-v1.0.0 はロールバック証跡として変更せず保存し、上書きしません。v1 互換性と "
    "fallback は許容しません。 / 协议 v2 类与属性 fail-closed 不变门。"
    "gate-v1.0.0 仅作为回滚证据原样保留，永不覆盖；不接受 v1 兼容或 fallback。"
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
AUTOMATION_PUSH_SECRET_NAME = "HDF_AUTOMATION_PUSH_ED25519_PRIVATE_KEY"
AUTOMATION_PUSH_FINGERPRINT_VARIABLE = "HDF_AUTOMATION_PUSH_KEY_FINGERPRINT"
AUTOMATION_PUSH_DEPLOY_KEY_TITLE = "hotdeal-focus-automation-push-v1"
RELEASE_PUBLISHER_ENVIRONMENT = "hdf-release-publisher"
MAIN_AUTOMATION_ENVIRONMENT = "hdf-main-automation"
PAGES_ENVIRONMENT = "github-pages"
BRANCH_GOVERNANCE_PR_RULESET_NAME = "Hotdeal Focus / PR and verified CI"
BRANCH_GOVERNANCE_HISTORY_RULESET_NAME = (
    "Hotdeal Focus / immutable fast-forward history"
)
GATE_TAG_CREATION_RULESET_NAME = "Hotdeal Focus / controlled gate-v2 tag creation"
GATE_TAG_FREEZE_RULESET_NAME = "Hotdeal Focus / immutable gate-v2 tag"
GOVERNANCE_RULESET_MUTATION_ORDER = (
    "immutableFastForwardHistory",
    "prAndVerifiedCi",
    "gateTagCreation",
    "immutableGateTag",
)
GITHUB_ACTIONS_INTEGRATION_ID = 15368
GITHUB_VERIFY_STATUS_CONTEXT = "verify"
SSH_SHA256_FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
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


def _capture_command_with_private_stdin_file(
    argv: Sequence[str],
    private_input_path: Path,
    *,
    label: str,
    timeout_seconds: int = COMMAND_TIMEOUT_SECONDS,
) -> ExecutionCapture:
    """Run one fixed command without ever copying or reporting its private stdin."""
    if not argv or argv[0] != "gh":
        raise UsageFailure("private-stdin runner accepts only the GitHub CLI")
    if not _command_exists("gh"):
        raise PrerequisiteFailure("GitHub CLI is unavailable")
    _log(f"running allowlisted step: {label}")
    try:
        with private_input_path.open("rb") as private_input:
            completed = subprocess.run(
                list(argv),
                cwd=str(PROJECT_ROOT),
                check=False,
                stdin=private_input,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
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
        stdout=b"",
        stderr=b"",
    )
    if capture.returncode:
        _log(f"{label} failed without exposing private command output")
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


def _decode_release_text(content: bytes, label: str) -> str:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise IntegrityFailure(f"{label} is not valid UTF-8") from error
    if "\x00" in text:
        raise IntegrityFailure(f"{label} contains a NUL character")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _reader_gate_v2_contract(script_bytes: bytes) -> int:
    text = _decode_release_text(script_bytes, "hotdeal-focus.user.js")
    start_marker = "// ==UserScript=="
    end_marker = "// ==/UserScript=="
    if (
        not text.startswith(start_marker)
        or text.count(start_marker) != 1
        or text.count(end_marker) != 1
    ):
        raise IntegrityFailure("Reader Gate userscript metadata block is not exact")
    metadata, code = text.split(end_marker, 1)
    metadata += end_marker
    grants = re.findall(r"(?m)^//\s+@grant\s+(\S+)\s*$", metadata)
    run_at = re.findall(r"(?m)^//\s+@run-at\s+(\S+)\s*$", metadata)
    noframes = re.findall(r"(?m)^//\s+@noframes\s*$", metadata)
    names = re.findall(r"(?m)^//\s+@name\s+(.+?)\s*$", metadata)
    if grants != [READER_GATE_GRANT]:
        raise IntegrityFailure(
            "Reader Gate v2 must declare exactly one @grant GM_addElement"
        )
    if run_at != ["document-start"] or len(noframes) != 1:
        raise IntegrityFailure(
            "Reader Gate v2 must declare one document-start and one @noframes"
        )
    if names != [READER_GATE_NAME]:
        raise IntegrityFailure("Reader Gate userscript name is not exact")
    for host in READER_GATE_REQUIRED_HOSTS:
        if host not in metadata:
            raise IntegrityFailure(f"Reader Gate userscript scope is missing: {host}")

    protocol_matches = re.findall(
        r'(?m)^\s*const\s+PROTOCOL_VERSION\s*=\s*"([0-9]+)";\s*$', code
    )
    if protocol_matches != [str(READER_GATE_PROTOCOL_VERSION)]:
        raise IntegrityFailure("Reader Gate userscript protocol is not exactly 2")
    required_tokens = (
        "protocolVersion: Number(PROTOCOL_VERSION)",
        "setAttribute(ATTR.protocol, PROTOCOL_VERSION)",
        "data-hotdeal-focus-runtime-style",
        'style[data-hotdeal-focus-runtime-style="${PROTOCOL_VERSION}"]',
        "GM_addElement(",
        *READER_GATE_REQUIRED_ATTRIBUTES,
        *READER_GATE_REQUIRED_CLASSES,
    )
    for token in required_tokens:
        if token not in code:
            raise IntegrityFailure(
                f"Reader Gate v2 is missing diagnostics/runtime marker: {token}"
            )
    if code.count("protocolVersion: Number(PROTOCOL_VERSION)") != 1:
        raise IntegrityFailure("Reader Gate v2 diagnostics protocol marker is not unique")
    return READER_GATE_PROTOCOL_VERSION


def _marker_gate_v2_contract(filter_bytes: bytes) -> int:
    text = _decode_release_text(filter_bytes, "filter.txt")
    title_matches = re.findall(r"(?m)^!\s*Title:\s*(.+?)\s*$", text)
    version_matches = re.findall(r"(?m)^!\s*Version:\s*(\S+)\s*$", text)
    protocol_matches = re.findall(
        r"(?m)^!\s*Hotdeal-Focus-Protocol:\s*([0-9]+)\s*$", text
    )
    if (
        title_matches != [MARKER_GATE_NAME]
        or version_matches != [GATE_LOCK_ARTIFACT_VERSION]
        or protocol_matches != [str(GATE_LOCK_PROTOCOL_VERSION)]
    ):
        raise IntegrityFailure("Marker Gate filter metadata is not exactly v2")
    installed_rules = "\n".join(
        line for line in text.split("\n")
        if line.strip() and not line.lstrip().startswith("!")
    )
    for token in (
        "hdf-v2-lock", "hdf-v2-ready", "hdf-v2-keep", "hdf-v2-shell",
        "hdf-v2-deep", "hdf-v2-role-", 'data-hotdeal-focus-ready="1"',
        "data-hotdeal-focus-keep", 'data-hotdeal-focus-protocol="2"',
        "data-hotdeal-focus-shell", "data-hotdeal-focus-deep",
        'data-hotdeal-focus-role="', 'data-hotdeal-focus-state="ready"',
        'data-hotdeal-focus-status="ready"',
    ):
        if token not in installed_rules:
            raise IntegrityFailure(f"Marker Gate v2 is missing marker: {token}")
    if 'data-hotdeal-focus-protocol="1"' in installed_rules:
        raise IntegrityFailure("Marker Gate v2 contains a protocol-1 marker")
    return GATE_LOCK_PROTOCOL_VERSION


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
    if type(value.get("protocolVersion")) is not int or (
        value["protocolVersion"] != READER_GATE_PROTOCOL_VERSION
    ):
        raise IntegrityFailure("release manifest protocolVersion is not exactly 2")
    if gate_version != GATE_LOCK_ARTIFACT_VERSION:
        raise IntegrityFailure("release manifest gateArtifactVersion is not exactly 2.0.2")
    if value.get("filterSubscriptionUrl") != GATE_LOCK_SUBSCRIPTION_URL:
        raise IntegrityFailure("release manifest does not select the immutable v2 gate")
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
    filter_protocol = _marker_gate_v2_contract(filter_bytes)
    script_protocol = _reader_gate_v2_contract(script_bytes)
    if (
        filter_protocol != manifest["protocolVersion"]
        or script_protocol != manifest["protocolVersion"]
    ):
        raise IntegrityFailure("release artifacts form a cross-protocol combination")
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
        raise IntegrityFailure(
            f"immutable gate does not contain exactly {GATE_LOCK_RULE_COUNT} rules"
        )


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
    ("network", ("npm", "run", "test:network"), COMMAND_TIMEOUT_SECONDS),
    ("build-check", ("python", "scripts/build_release.py", "--check"), COMMAND_TIMEOUT_SECONDS),
    ("integrity", ("node", "scripts/audit_pages.mjs", "--integrity-only"), COMMAND_TIMEOUT_SECONDS),
    ("oracle", ("npm", "run", "test:oracle"), COMMAND_TIMEOUT_SECONDS),
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


def _gh_included_json(
    endpoint: str,
    label: str,
    *,
    allow_missing: bool = False,
) -> tuple[int, Any | None]:
    capture = _capture_command(
        (
            "gh", "api", "--include", "-H", GITHUB_JSON_ACCEPT_HEADER,
            "-H", GITHUB_API_VERSION_HEADER, endpoint,
        ),
        label=label,
        timeout_seconds=60,
    )
    normalized = capture.stdout.replace(b"\r\n", b"\n")
    header, separator, body = normalized.partition(b"\n\n")
    status_match = re.match(rb"^HTTP/\S+\s+([0-9]{3})\b", header)
    if not separator or status_match is None:
        raise IntegrityFailure(f"{label} response has no exact HTTP status envelope")
    status_code = int(status_match.group(1))
    if status_code == 404 and allow_missing:
        if capture.returncode == 0:
            raise IntegrityFailure(f"{label} returned a contradictory missing state")
        return status_code, None
    if capture.returncode or not 200 <= status_code < 300:
        raise TransientFailure(f"{label} could not be read")
    return status_code, _decode_json(body, label)


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


def _require_cloud_head_lease(
    repo: str,
    default_branch: str,
    source_sha: str,
    phase: str,
) -> dict[str, Any]:
    branch = urllib.parse.quote(default_branch, safe="")
    value = _gh_json(
        (
            "gh", "api", "-H", GITHUB_JSON_ACCEPT_HEADER, "-H",
            GITHUB_API_VERSION_HEADER, f"repos/{repo}/commits/{branch}",
        ),
        f"cloud-source-head-{phase}",
        prerequisite=True,
    )
    observed = value.get("sha") if isinstance(value, dict) else None
    if not isinstance(observed, str) or not GIT_SHA_RE.fullmatch(observed.lower()):
        raise IntegrityFailure("GitHub default branch head SHA is malformed")
    record = {
        "phase": phase,
        "branch": default_branch,
        "expectedSha": source_sha,
        "observedSha": observed.lower(),
        "exact": observed.lower() == source_sha,
    }
    if record["exact"] is not True:
        raise IntegrityFailure(f"default branch changed during cloud apply: {phase}")
    return record


def _workflow_blob_authority(
    repo: str, workflow: str, source_sha: str
) -> dict[str, Any]:
    path = f".github/workflows/{workflow}"
    local = _capture_command(
        ("git", "show", f"{source_sha}:{path}"),
        label=f"local-workflow-blob-{workflow}",
        timeout_seconds=30,
    )
    if local.returncode or not local.stdout or len(local.stdout) > 1_048_576:
        raise IntegrityFailure(f"local workflow blob is unavailable: {workflow}")
    encoded_path = urllib.parse.quote(path, safe="/")
    encoded_ref = urllib.parse.quote(source_sha, safe="")
    value = _gh_json(
        (
            "gh", "api", "-H", GITHUB_JSON_ACCEPT_HEADER, "-H",
            GITHUB_API_VERSION_HEADER,
            f"repos/{repo}/contents/{encoded_path}?ref={encoded_ref}",
        ),
        f"remote-workflow-blob-{workflow}",
        prerequisite=True,
    )
    if (
        not isinstance(value, dict)
        or value.get("type") != "file"
        or value.get("path") != path
        or value.get("encoding") != "base64"
        or type(value.get("size")) is not int
        or value["size"] < 1
        or value["size"] > 1_048_576
        or not isinstance(value.get("content"), str)
    ):
        raise IntegrityFailure(f"remote workflow blob is malformed: {workflow}")
    try:
        remote = base64.b64decode(
            "".join(value["content"].split()).encode("ascii"), validate=True
        )
    except (UnicodeEncodeError, ValueError) as error:
        raise IntegrityFailure(f"remote workflow blob is not base64: {workflow}") from error
    local_digest = sha256_bytes(local.stdout)
    remote_digest = sha256_bytes(remote)
    if len(remote) != value["size"] or remote_digest != local_digest:
        raise IntegrityFailure(f"workflow blob differs at source-ref: {workflow}")
    return {
        "workflow": workflow,
        "path": path,
        "bytes": len(remote),
        "sha256": remote_digest,
        "exact": True,
    }


def _verify_run_jobs_authority(
    repo: str, run: Mapping[str, Any], check_runs: Sequence[Mapping[str, Any]]
) -> dict[str, Any] | None:
    run_id = run.get("id")
    if type(run_id) is not int or run_id < 1:
        raise IntegrityFailure("GitHub verify run ID is malformed")
    value = _gh_json(
        (
            "gh", "api", "-H", GITHUB_JSON_ACCEPT_HEADER, "-H",
            GITHUB_API_VERSION_HEADER,
            f"repos/{repo}/actions/runs/{run_id}/jobs?filter=all&per_page=100",
        ),
        f"github-verify-run-jobs-{run_id}",
        prerequisite=True,
    )
    jobs = value.get("jobs") if isinstance(value, dict) else None
    total = value.get("total_count") if isinstance(value, dict) else None
    if (
        not isinstance(jobs, list)
        or type(total) is not int
        or total != len(jobs)
        or total < 1
        or total > 100
    ):
        raise IntegrityFailure("GitHub verify job listing is malformed")
    verify_jobs = [job for job in jobs if isinstance(job, dict) and job.get("name") == "verify"]
    if len(verify_jobs) != 1:
        return None
    verify_job = verify_jobs[0]
    if (
        type(verify_job.get("id")) is not int
        or verify_job.get("status") != "completed"
        or verify_job.get("conclusion") != "success"
        or not isinstance(verify_job.get("check_run_url"), str)
    ):
        return None
    failed_jobs = [
        str(job.get("name"))
        for job in jobs
        if isinstance(job, dict)
        and job.get("conclusion") not in {"success", "skipped", "neutral"}
    ]
    if failed_jobs and set(failed_jobs) != {"publish-pages"}:
        return None
    check_id_match = re.search(r"/check-runs/([1-9][0-9]*)$", verify_job["check_run_url"])
    if check_id_match is None:
        raise IntegrityFailure("GitHub verify job check-run URL is malformed")
    check_id = int(check_id_match.group(1))
    matching = [check for check in check_runs if check.get("id") == check_id]
    if len(matching) != 1:
        return None
    check = matching[0]
    app = check.get("app")
    details_url = check.get("details_url")
    details_match = re.search(
        r"/actions/runs/([1-9][0-9]*)/job/([1-9][0-9]*)(?:\?.*)?$",
        details_url or "",
    )
    if (
        check.get("name") != GITHUB_VERIFY_STATUS_CONTEXT
        or check.get("status") != "completed"
        or check.get("conclusion") != "success"
        or not isinstance(app, dict)
        or app.get("id") != GITHUB_ACTIONS_INTEGRATION_ID
        or details_match is None
        or int(details_match.group(1)) != run_id
        or int(details_match.group(2)) != verify_job["id"]
    ):
        return None
    return {
        "runId": run_id,
        "runConclusion": run.get("conclusion"),
        "event": run.get("event"),
        "verifyJobId": verify_job["id"],
        "verifyCheckRunId": check_id,
        "allowedFailedJobs": failed_jobs,
        "exact": True,
    }


def _verify_check_authority(
    repo: str, default_branch: str, source_sha: str
) -> dict[str, Any]:
    encoded_sha = urllib.parse.quote(source_sha, safe="")
    runs_value = _gh_json(
        (
            "gh", "api", "-H", GITHUB_JSON_ACCEPT_HEADER, "-H",
            GITHUB_API_VERSION_HEADER,
            f"repos/{repo}/actions/workflows/verify.yml/runs?head_sha={encoded_sha}&per_page=100",
        ),
        "github-source-verify-runs",
        prerequisite=True,
    )
    runs = runs_value.get("workflow_runs") if isinstance(runs_value, dict) else None
    total_runs = runs_value.get("total_count") if isinstance(runs_value, dict) else None
    if (
        not isinstance(runs, list)
        or type(total_runs) is not int
        or total_runs != len(runs)
        or total_runs > 100
    ):
        raise IntegrityFailure("GitHub source verify run listing is malformed")
    checks_value = _gh_json(
        (
            "gh", "api", "-H", GITHUB_JSON_ACCEPT_HEADER, "-H",
            GITHUB_API_VERSION_HEADER,
            f"repos/{repo}/commits/{encoded_sha}/check-runs?per_page=100",
        ),
        "github-source-check-runs",
        prerequisite=True,
    )
    checks = checks_value.get("check_runs") if isinstance(checks_value, dict) else None
    total_checks = checks_value.get("total_count") if isinstance(checks_value, dict) else None
    if (
        not isinstance(checks, list)
        or type(total_checks) is not int
        or total_checks != len(checks)
        or total_checks > 100
        or any(not isinstance(check, dict) for check in checks)
    ):
        raise IntegrityFailure("GitHub source check-run listing is malformed")
    candidates: list[dict[str, Any]] = []
    for run in runs:
        if (
            not isinstance(run, dict)
            or not _workflow_path_matches(run.get("path"), "verify.yml")
            or str(run.get("head_sha", "")).lower() != source_sha
            or run.get("head_branch") != default_branch
            or run.get("event") not in {"push", "workflow_dispatch"}
            or run.get("status") != "completed"
            or run.get("conclusion") not in {"success", "failure"}
        ):
            continue
        authority = _verify_run_jobs_authority(repo, run, checks)
        if authority is not None:
            candidates.append(authority)
    if not candidates:
        raise IntegrityFailure(
            "source-ref has no exact successful verify job/check authority"
        )
    candidates.sort(key=lambda item: int(item["runId"]), reverse=True)
    return candidates[0]


def _cloud_source_authority(
    repo: str, default_branch: str, source_ref: str
) -> dict[str, Any]:
    source_sha = _git_source_binding(source_ref)
    head_lease = _require_cloud_head_lease(
        repo, default_branch, source_sha, "initial-authority"
    )
    workflows = [
        _workflow_blob_authority(repo, workflow, source_sha)
        for workflow in WORKFLOW_FILES
    ]
    verify = _verify_check_authority(repo, default_branch, source_sha)
    return {
        "sourceSha": source_sha,
        "defaultBranch": default_branch,
        "workflows": workflows,
        "verify": verify,
        "headLeases": [head_lease],
        "exact": True,
    }


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


def _repository_secret_names(repo: str) -> frozenset[str]:
    capture = _capture_command(
        (
            "gh", "secret", "list", "--repo", repo,
            "--json", "name,updatedAt",
        ),
        label="github-repository-secrets",
        timeout_seconds=60,
    )
    if capture.returncode:
        raise PrerequisiteFailure("GitHub repository secrets are unavailable")
    value = _decode_json(capture.stdout, "GitHub repository secrets")
    if not isinstance(value, list):
        raise IntegrityFailure("GitHub repository secret listing is malformed")
    names: set[str] = set()
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "updatedAt"}
            or not isinstance(item.get("name"), str)
            or not item["name"]
            or not isinstance(item.get("updatedAt"), str)
            or not item["updatedAt"]
            or item["name"] in names
        ):
            raise IntegrityFailure("GitHub repository secret entry is malformed")
        names.add(item["name"])
    return frozenset(names)


def _environment_secret_names(repo: str, environment: str) -> frozenset[str]:
    capture = _capture_command(
        (
            "gh", "secret", "list", "--env", environment, "--repo", repo,
            "--json", "name,updatedAt",
        ),
        label=f"github-environment-secrets-{environment}",
        timeout_seconds=60,
    )
    if capture.returncode:
        raise PrerequisiteFailure(
            f"GitHub environment secrets are unavailable: {environment}"
        )
    value = _decode_json(capture.stdout, f"GitHub environment secrets: {environment}")
    if not isinstance(value, list):
        raise IntegrityFailure("GitHub environment secret listing is malformed")
    names: set[str] = set()
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "updatedAt"}
            or not isinstance(item.get("name"), str)
            or not item["name"]
            or not isinstance(item.get("updatedAt"), str)
            or not item["updatedAt"]
            or item["name"] in names
        ):
            raise IntegrityFailure("GitHub environment secret entry is malformed")
        names.add(item["name"])
    return frozenset(names)


def _openssh_public_key_record(public_key: str) -> dict[str, Any]:
    if (
        not isinstance(public_key, str)
        or not public_key
        or len(public_key.encode("utf-8")) > 32_768
        or "\n" in public_key
        or "\r" in public_key
        or "\x00" in public_key
    ):
        raise IntegrityFailure("GitHub deploy key is not one bounded OpenSSH public key")
    parts = public_key.strip().split()
    if len(parts) < 2:
        raise IntegrityFailure("GitHub deploy key has no OpenSSH key blob")
    key_type, encoded = parts[:2]
    try:
        blob = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as error:
        raise IntegrityFailure("GitHub deploy key has invalid base64") from error
    if len(blob) < 8:
        raise IntegrityFailure("GitHub deploy key blob is truncated")
    type_length = int.from_bytes(blob[:4], "big")
    if type_length < 1 or type_length > 256 or len(blob) < 4 + type_length:
        raise IntegrityFailure("GitHub deploy key type is malformed")
    try:
        embedded_type = blob[4:4 + type_length].decode("ascii")
    except UnicodeDecodeError as error:
        raise IntegrityFailure("GitHub deploy key type is not ASCII") from error
    if embedded_type != key_type:
        raise IntegrityFailure("GitHub deploy key type disagrees with its key blob")
    ed25519_exact = False
    if key_type == "ssh-ed25519":
        offset = 4 + type_length
        if len(blob) < offset + 4:
            raise IntegrityFailure("GitHub Ed25519 deploy key blob is truncated")
        public_length = int.from_bytes(blob[offset:offset + 4], "big")
        ed25519_exact = public_length == 32 and len(blob) == offset + 4 + 32
        if not ed25519_exact:
            raise IntegrityFailure("GitHub Ed25519 deploy key is not exactly 256 bits")
    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(blob).digest()
    ).decode("ascii").rstrip("=")
    if not SSH_SHA256_FINGERPRINT_RE.fullmatch(fingerprint):
        raise IntegrityFailure("GitHub deploy key fingerprint is malformed")
    return {
        "keyType": key_type,
        "fingerprint": fingerprint,
        "ed25519Exact": ed25519_exact,
    }


def _github_deploy_keys_state(repo: str) -> list[dict[str, Any]]:
    value = _gh_json(
        (
            "gh", "api", "-H", GITHUB_JSON_ACCEPT_HEADER, "-H",
            GITHUB_API_VERSION_HEADER,
            f"repos/{repo}/keys?per_page=100",
        ),
        "github-deploy-keys",
        prerequisite=True,
    )
    if not isinstance(value, list) or len(value) > 100:
        raise IntegrityFailure("GitHub deploy key listing is malformed")
    records: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    for item in value:
        if (
            not isinstance(item, dict)
            or type(item.get("id")) is not int
            or item["id"] < 1
            or item["id"] in seen_ids
            or not isinstance(item.get("title"), str)
            or not item["title"]
            or type(item.get("read_only")) is not bool
            or type(item.get("verified")) is not bool
            or not isinstance(item.get("key"), str)
        ):
            raise IntegrityFailure("GitHub deploy key entry is malformed")
        seen_ids.add(item["id"])
        key_record = _openssh_public_key_record(item["key"])
        records.append({
            "id": item["id"],
            "title": item["title"],
            "readOnly": item["read_only"],
            "verified": item["verified"],
            **key_record,
        })
    return records


def _automation_push_identity_state(
    repo: str,
    variables: Mapping[str, str] | None = None,
    *,
    environment_exists: bool = True,
) -> dict[str, Any]:
    current_variables = dict(variables) if variables is not None \
        else _repository_variables(repo)
    repository_secrets = _repository_secret_names(repo)
    environment_secrets = (
        _environment_secret_names(repo, MAIN_AUTOMATION_ENVIRONMENT)
        if environment_exists else frozenset()
    )
    deploy_keys = _github_deploy_keys_state(repo)
    write_keys = [item for item in deploy_keys if item["readOnly"] is False]
    reserved_title_keys = [
        item for item in deploy_keys
        if item["title"].casefold() == AUTOMATION_PUSH_DEPLOY_KEY_TITLE.casefold()
    ]
    configured_fingerprint = current_variables.get(
        AUTOMATION_PUSH_FINGERPRINT_VARIABLE
    )
    exact_key = write_keys[0] if len(write_keys) == 1 else None
    key_exact = bool(
        exact_key is not None
        and exact_key["title"] == AUTOMATION_PUSH_DEPLOY_KEY_TITLE
        and exact_key["keyType"] == "ssh-ed25519"
        and exact_key["ed25519Exact"] is True
        and exact_key["verified"] is True
        and configured_fingerprint == exact_key["fingerprint"]
        and SSH_SHA256_FINGERPRINT_RE.fullmatch(configured_fingerprint or "")
        and len(reserved_title_keys) == 1
    )
    exact = bool(
        key_exact
        and AUTOMATION_PUSH_SECRET_NAME in environment_secrets
        and AUTOMATION_PUSH_SECRET_NAME not in repository_secrets
    )
    return {
        "scopeRepository": repo,
        "environmentName": MAIN_AUTOMATION_ENVIRONMENT,
        "secretName": AUTOMATION_PUSH_SECRET_NAME,
        "environmentSecretPresent": (
            AUTOMATION_PUSH_SECRET_NAME in environment_secrets
        ),
        "repositorySecretPresent": (
            AUTOMATION_PUSH_SECRET_NAME in repository_secrets
        ),
        "fingerprintVariableName": AUTOMATION_PUSH_FINGERPRINT_VARIABLE,
        "configuredFingerprint": configured_fingerprint,
        "deployKeyTitle": AUTOMATION_PUSH_DEPLOY_KEY_TITLE,
        "deployKeys": deploy_keys,
        "writeKeyCount": len(write_keys),
        "reservedTitleKeyCount": len(reserved_title_keys),
        "keyExact": key_exact,
        "exact": exact,
    }


def _required_branch_ruleset_contracts() -> dict[str, dict[str, Any]]:
    ref_condition = {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}}
    return {
        "prAndVerifiedCi": {
            "name": BRANCH_GOVERNANCE_PR_RULESET_NAME,
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [{
                "actor_id": None,
                "actor_type": "DeployKey",
                "bypass_mode": "always",
            }],
            "conditions": ref_condition,
            "rules": [
                {
                    "type": "pull_request",
                    "parameters": {
                        "required_approving_review_count": 0,
                        "dismiss_stale_reviews_on_push": False,
                        "required_reviewers": [],
                        "require_code_owner_review": False,
                        "require_last_push_approval": False,
                        "required_review_thread_resolution": True,
                        "allowed_merge_methods": ["squash", "rebase"],
                    },
                },
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "strict_required_status_checks_policy": True,
                        "do_not_enforce_on_create": False,
                        "required_status_checks": [{
                            "context": GITHUB_VERIFY_STATUS_CONTEXT,
                            "integration_id": GITHUB_ACTIONS_INTEGRATION_ID,
                        }],
                    },
                },
            ],
        },
        "immutableFastForwardHistory": {
            "name": BRANCH_GOVERNANCE_HISTORY_RULESET_NAME,
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": ref_condition,
            "rules": [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {"type": "required_linear_history"},
            ],
        },
        "gateTagCreation": {
            "name": GATE_TAG_CREATION_RULESET_NAME,
            "target": "tag",
            "enforcement": "active",
            "bypass_actors": [{
                "actor_id": None,
                "actor_type": "DeployKey",
                "bypass_mode": "always",
            }],
            "conditions": {
                "ref_name": {
                    "include": ["refs/tags/gate-v2.0.2"],
                    "exclude": [],
                }
            },
            "rules": [{"type": "creation"}],
        },
        "immutableGateTag": {
            "name": GATE_TAG_FREEZE_RULESET_NAME,
            "target": "tag",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {
                    "include": ["refs/tags/gate-v2.0.2"],
                    "exclude": [],
                }
            },
            "rules": [
                {
                    "type": "update",
                    "parameters": {"update_allows_fetch_and_merge": False},
                },
                {"type": "deletion"},
            ],
        },
    }


def _gate_tag_bootstrap_freeze_contract() -> dict[str, Any]:
    contract = json.loads(canonical_json_bytes(
        _required_branch_ruleset_contracts()["immutableGateTag"]
    ).decode("utf-8"))
    contract["rules"] = [{"type": "creation"}, *contract["rules"]]
    return contract


def _ruleset_mutation_payload(contract: Mapping[str, Any]) -> dict[str, Any]:
    payload = json.loads(canonical_json_bytes(contract).decode("utf-8"))
    pull_request = next(
        (rule for rule in payload["rules"] if rule.get("type") == "pull_request"),
        None,
    )
    if isinstance(pull_request, dict):
        # GitHub adds this empty beta field on read. Omitting it on write keeps the
        # public API contract stable while the exact post-read still requires [].
        pull_request["parameters"].pop("required_reviewers", None)
    return payload


def _normalized_repository_ruleset(
    value: Any, repo: str, expected_contract: Mapping[str, Any]
) -> tuple[int, dict[str, Any]]:
    expected_name = str(expected_contract["name"])
    if (
        not isinstance(value, dict)
        or type(value.get("id")) is not int
        or value["id"] < 1
        or value.get("name") != expected_name
        or value.get("source_type") != "Repository"
        or str(value.get("source", "")).casefold() != repo.casefold()
        or value.get("target") != expected_contract.get("target")
        or value.get("enforcement") not in {"disabled", "active", "evaluate"}
        or not isinstance(value.get("bypass_actors"), list)
        or not isinstance(value.get("conditions"), dict)
        or not isinstance(value.get("rules"), list)
    ):
        raise IntegrityFailure(f"GitHub named ruleset is malformed: {expected_name}")
    contract = {
        "name": value["name"],
        "target": value["target"],
        "enforcement": value["enforcement"],
        "bypass_actors": value["bypass_actors"],
        "conditions": value["conditions"],
        "rules": value["rules"],
    }
    return value["id"], contract


def _ruleset_ref_scope(
    ruleset: Mapping[str, Any], default_branch: str
) -> dict[str, Any]:
    target = ruleset.get("target")
    if target not in {"branch", "tag"}:
        return {"relevant": True, "reason": "unproven-non-ref-target"}
    target_ref = (
        f"refs/heads/{default_branch}"
        if target == "branch"
        else "refs/tags/gate-v2.0.2"
    )
    conditions = ruleset.get("conditions")
    ref_name = conditions.get("ref_name") if isinstance(conditions, Mapping) else None
    includes = ref_name.get("include") if isinstance(ref_name, Mapping) else None
    excludes = ref_name.get("exclude") if isinstance(ref_name, Mapping) else None
    if (
        not isinstance(includes, list)
        or not includes
        or not isinstance(excludes, list)
        or any(not isinstance(item, str) or not item for item in includes + excludes)
    ):
        return {"relevant": True, "reason": "unproven-ref-condition"}

    def exact_match(pattern: str) -> bool:
        return bool(
            pattern == target_ref
            or pattern == "~ALL"
            or (pattern == "~DEFAULT_BRANCH" and target == "branch")
        )

    if any(exact_match(pattern) for pattern in excludes):
        return {"relevant": False, "reason": "exactly-excluded"}
    if any(exact_match(pattern) for pattern in includes):
        return {"relevant": True, "reason": "exactly-included"}
    # Only literal, different refs prove irrelevance. Pattern syntax is treated as
    # applicable unless its non-match is independently provable by GitHub.
    if all(not any(character in pattern for character in "*?[]~") for pattern in includes):
        return {"relevant": False, "reason": "literal-unrelated-ref"}
    if any(fnmatch.fnmatchcase(target_ref, pattern) for pattern in includes):
        return {"relevant": True, "reason": "pattern-match"}
    return {"relevant": True, "reason": "unproven-pattern-nonmatch"}


def _github_classic_branch_protection_state(
    repo: str, default_branch: str
) -> dict[str, Any]:
    encoded = urllib.parse.quote(default_branch, safe="")
    status, value = _gh_included_json(
        f"repos/{repo}/branches/{encoded}/protection",
        "github-classic-branch-protection",
        allow_missing=True,
    )
    if status == 404:
        return {"present": False, "compatible": True}
    if not isinstance(value, dict) or not value:
        raise IntegrityFailure("GitHub classic branch protection is malformed")
    return {
        "present": True,
        "compatible": False,
        "reason": "classic protection cannot prove deploy-key fast-forward bypass",
    }


def _github_branch_governance_state(
    repo: str, default_branch: str = "main"
) -> dict[str, Any]:
    listing = _gh_json(
        (
            "gh", "api", "-H", GITHUB_JSON_ACCEPT_HEADER, "-H",
            GITHUB_API_VERSION_HEADER,
            f"repos/{repo}/rulesets?includes_parents=true&per_page=100",
        ),
        "github-repository-rulesets",
        prerequisite=True,
    )
    if not isinstance(listing, list) or len(listing) > 75:
        raise IntegrityFailure("GitHub repository ruleset listing is malformed")
    required = _required_branch_ruleset_contracts()
    matches: dict[str, list[int]] = {name: [] for name in required}
    seen_ids: set[int] = set()
    for item in listing:
        if (
            not isinstance(item, dict)
            or type(item.get("id")) is not int
            or item["id"] < 1
            or item["id"] in seen_ids
            or not isinstance(item.get("name"), str)
            or not item["name"]
            or item.get("source_type") not in {
                "Repository", "Organization", "Enterprise"
            }
            or not isinstance(item.get("source"), str)
            or not item["source"]
        ):
            raise IntegrityFailure("GitHub repository ruleset entry is malformed")
        seen_ids.add(item["id"])
        for contract_name, contract in required.items():
            if item["name"].casefold() == contract["name"].casefold():
                if (
                    item.get("source_type") != "Repository"
                    or str(item.get("source", "")).casefold() != repo.casefold()
                ):
                    raise IntegrityFailure(
                        f"GitHub reserved ruleset name is inherited: {contract['name']}"
                    )
                matches[contract_name].append(item["id"])
    for contract_name, identifiers in matches.items():
        if len(identifiers) > 1:
            raise IntegrityFailure(
                f"GitHub named ruleset is ambiguous: {required[contract_name]['name']}"
            )
    observed: dict[str, Any] = {}
    for contract_name, contract in required.items():
        identifiers = matches[contract_name]
        if not identifiers:
            observed[contract_name] = {
                "present": False,
                "id": None,
                "exact": False,
                "contract": None,
            }
            continue
        ruleset_id = identifiers[0]
        value = _gh_json(
            (
                "gh", "api", "-H", GITHUB_JSON_ACCEPT_HEADER, "-H",
                GITHUB_API_VERSION_HEADER,
                f"repos/{repo}/rulesets/{ruleset_id}?includes_parents=true",
            ),
            f"github-ruleset-{contract_name}",
            prerequisite=True,
        )
        normalized_id, normalized = _normalized_repository_ruleset(
            value, repo, contract
        )
        if normalized_id != ruleset_id:
            raise IntegrityFailure("GitHub named ruleset ID changed during inspection")
        observed[contract_name] = {
            "present": True,
            "id": ruleset_id,
            "exact": normalized == contract,
            "contract": normalized,
        }
    required_ids = {
        item["id"] for item in observed.values() if item.get("id") is not None
    }
    extra_rulesets: list[dict[str, Any]] = []
    unproven_applicable: list[dict[str, Any]] = []
    for item in listing:
        if item["id"] in required_ids:
            continue
        value = _gh_json(
            (
                "gh", "api", "-H", GITHUB_JSON_ACCEPT_HEADER, "-H",
                GITHUB_API_VERSION_HEADER,
                f"repos/{repo}/rulesets/{item['id']}?includes_parents=true",
            ),
            f"github-extra-ruleset-{item['id']}",
            prerequisite=True,
        )
        if (
            not isinstance(value, dict)
            or value.get("id") != item["id"]
            or value.get("name") != item["name"]
            or value.get("target") not in {"branch", "tag", "push", "repository"}
            or value.get("enforcement") not in {"disabled", "active", "evaluate"}
            or not isinstance(value.get("conditions"), dict)
            or not isinstance(value.get("rules"), list)
        ):
            raise IntegrityFailure("GitHub extra ruleset is malformed")
        scope = _ruleset_ref_scope(value, default_branch)
        record = {
            "id": value["id"],
            "name": value["name"],
            "sourceType": value.get("source_type"),
            "source": value.get("source"),
            "target": value["target"],
            "enforcement": value["enforcement"],
            "scope": scope,
        }
        extra_rulesets.append(record)
        if value["enforcement"] in {"active", "evaluate"} and scope["relevant"]:
            unproven_applicable.append(record)
    classic = _github_classic_branch_protection_state(repo, default_branch)
    return {
        "target": "~DEFAULT_BRANCH and refs/tags/gate-v2.0.2",
        "namedRulesets": observed,
        "repositoryRulesetCount": len(listing),
        "extraRulesets": extra_rulesets,
        "unprovenApplicableRulesets": unproven_applicable,
        "classicBranchProtection": classic,
        "exact": bool(
            all(item["exact"] is True for item in observed.values())
            and not unproven_applicable
            and classic["compatible"] is True
        ),
    }


def _validate_governance_mutation_source(state: Mapping[str, Any]) -> None:
    identity = state.get("automationPushIdentity")
    governance = state.get("branchGovernance")
    if not isinstance(identity, Mapping) or not isinstance(governance, Mapping):
        raise IntegrityFailure("automation push governance state is unavailable")
    unproven_rulesets = governance.get("unprovenApplicableRulesets")
    classic = governance.get("classicBranchProtection")
    if not isinstance(unproven_rulesets, list):
        raise IntegrityFailure("applicable GitHub ruleset state is malformed")
    if unproven_rulesets:
        raise IntegrityFailure(
            "unproven applicable GitHub ruleset exists; refusing every mutation"
        )
    if not isinstance(classic, Mapping) or classic.get("compatible") is not True:
        raise IntegrityFailure(
            "classic branch protection compatibility is unproven; refusing every mutation"
        )
    write_key_count = identity.get("writeKeyCount")
    if type(write_key_count) is not int:
        raise IntegrityFailure("automation push key count is malformed")
    if write_key_count:
        if write_key_count != 1 or identity.get("keyExact") is not True:
            raise IntegrityFailure(
                "unknown or unbound write deploy key exists; refusing every mutation"
            )
    if type(identity.get("reservedTitleKeyCount")) is not int:
        raise IntegrityFailure("automation push reserved-title key count is malformed")
    if identity["reservedTitleKeyCount"] and identity.get("keyExact") is not True:
        raise IntegrityFailure(
            "reserved automation deploy-key title is ambiguous; refusing every mutation"
        )


@contextmanager
def _generated_automation_push_identity(repo: str) -> Iterator[dict[str, Any]]:
    if not _command_exists("ssh-keygen"):
        raise PrerequisiteFailure("OpenSSH ssh-keygen is unavailable")
    with tempfile.TemporaryDirectory(prefix="hotdeal-focus-automation-key-") as temporary:
        private_path = Path(temporary) / "automation-push-ed25519"
        generated = _capture_command(
            (
                "ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                "-C", f"hotdeal-focus-automation@{repo}",
                "-f", str(private_path),
            ),
            label="generate-automation-push-ed25519",
            timeout_seconds=60,
        )
        if generated.returncode:
            raise PrerequisiteFailure("could not generate automation Ed25519 key")
        public_path = Path(f"{private_path}.pub")
        try:
            private_size = private_path.stat().st_size
            public_text = public_path.read_text(encoding="utf-8")
        except OSError as error:
            raise IntegrityFailure("generated automation key pair is incomplete") from error
        if private_size < 100 or private_size > 16_384:
            raise IntegrityFailure("generated automation private key size is invalid")
        public_key = public_text.rstrip("\r\n")
        if "\n" in public_key or "\r" in public_key:
            raise IntegrityFailure("generated automation public key is not one line")
        public_record = _openssh_public_key_record(public_key)
        if (
            public_record["keyType"] != "ssh-ed25519"
            or public_record["ed25519Exact"] is not True
        ):
            raise IntegrityFailure("generated automation key is not exact Ed25519")
        yield {
            "privatePath": private_path,
            "publicKey": public_key,
            "fingerprint": public_record["fingerprint"],
        }


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
    status_code, page = _gh_included_json(
        f"repos/{repo}/pages", "github-pages-state", allow_missing=True
    )
    if status_code == 404:
        return {"exists": False, "buildType": None}
    if not isinstance(page, dict) or not isinstance(page.get("build_type"), str):
        raise IntegrityFailure("GitHub Pages state is malformed")
    return {"exists": True, "buildType": page["build_type"]}


def _github_environment_state(
    repo: str, environment: str, default_branch: str
) -> dict[str, Any]:
    encoded = urllib.parse.quote(environment, safe="")
    status, value = _gh_included_json(
        f"repos/{repo}/environments/{encoded}",
        f"github-environment-{environment}",
        allow_missing=True,
    )
    if status == 404:
        return {
            "name": environment,
            "present": False,
            "customBranchPolicy": False,
            "branchPolicies": [],
            "exact": False,
        }
    if (
        not isinstance(value, dict)
        or value.get("name") != environment
        or not isinstance(value.get("protection_rules"), list)
        or not isinstance(value.get("deployment_branch_policy"), dict)
    ):
        raise IntegrityFailure(f"GitHub environment is malformed: {environment}")
    deployment_policy = value["deployment_branch_policy"]
    custom = bool(
        deployment_policy.get("protected_branches") is False
        and deployment_policy.get("custom_branch_policies") is True
    )
    branch_policies: list[dict[str, Any]] = []
    if custom:
        policies = _gh_json(
            (
                "gh", "api", "-H", GITHUB_JSON_ACCEPT_HEADER, "-H",
                GITHUB_API_VERSION_HEADER,
                f"repos/{repo}/environments/{encoded}/deployment-branch-policies?per_page=100",
            ),
            f"github-environment-branch-policies-{environment}",
            prerequisite=True,
        )
        raw_policies = policies.get("branch_policies") \
            if isinstance(policies, dict) else None
        total_count = policies.get("total_count") if isinstance(policies, dict) else None
        if (
            not isinstance(raw_policies, list)
            or type(total_count) is not int
            or total_count != len(raw_policies)
            or total_count > 50
        ):
            raise IntegrityFailure("GitHub environment branch policies are malformed")
        seen_ids: set[int] = set()
        for policy in raw_policies:
            if (
                not isinstance(policy, dict)
                or type(policy.get("id")) is not int
                or policy["id"] < 1
                or policy["id"] in seen_ids
                or not isinstance(policy.get("name"), str)
                or not policy["name"]
                or policy.get("type") not in {"branch", "tag"}
            ):
                raise IntegrityFailure("GitHub environment branch policy is malformed")
            seen_ids.add(policy["id"])
            branch_policies.append({
                "id": policy["id"],
                "name": policy["name"],
                "type": policy["type"],
            })
    exact = bool(
        custom
        and len(branch_policies) == 1
        and branch_policies[0]["name"] == default_branch
        and branch_policies[0]["type"] == "branch"
    )
    return {
        "name": environment,
        "present": True,
        "canAdminsBypass": value.get("can_admins_bypass"),
        "customBranchPolicy": custom,
        "branchPolicies": branch_policies,
        "exact": exact,
    }


def _github_privileged_environments_state(
    repo: str, default_branch: str
) -> dict[str, dict[str, Any]]:
    return {
        environment: _github_environment_state(repo, environment, default_branch)
        for environment in (
            RELEASE_PUBLISHER_ENVIRONMENT,
            MAIN_AUTOMATION_ENVIRONMENT,
            PAGES_ENVIRONMENT,
        )
    }


def _cloud_operating_state(repo: str, default_branch: str = "main") -> dict[str, Any]:
    variables = _repository_variables(repo)
    pages = _github_pages_state(repo)
    environments = _github_privileged_environments_state(repo, default_branch)
    return {
        "enableStateCommits": variables.get("ENABLE_STATE_COMMITS") == "true",
        "enablePagesPublish": variables.get("ENABLE_PAGES_PUBLISH") == "true",
        "pagesWorkflow": pages["exists"] and pages["buildType"] == "workflow",
        "actions": _github_actions_permissions_state(repo),
        "workflows": _github_workflow_states(repo),
        "pages": pages,
        "privilegedEnvironments": environments,
        "automationPushIdentity": _automation_push_identity_state(
            repo,
            variables,
            environment_exists=environments[MAIN_AUTOMATION_ENVIRONMENT]["present"],
        ),
        "branchGovernance": _github_branch_governance_state(repo, default_branch),
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
        "privilegedEnvironments": {
            environment: {
                "selectedBranch": "~DEFAULT_BRANCH",
                "branchType": "branch",
            }
            for environment in (
                RELEASE_PUBLISHER_ENVIRONMENT,
                MAIN_AUTOMATION_ENVIRONMENT,
                PAGES_ENVIRONMENT,
            )
        },
        "automationPushIdentity": {
            "scope": "one repository",
            "algorithm": "Ed25519",
            "uniqueWriteDeployKey": True,
            "deployKeyTitle": AUTOMATION_PUSH_DEPLOY_KEY_TITLE,
            "secretName": AUTOMATION_PUSH_SECRET_NAME,
            "secretScope": MAIN_AUTOMATION_ENVIRONMENT,
            "fingerprintVariableName": AUTOMATION_PUSH_FINGERPRINT_VARIABLE,
            "runtimeFingerprintBinding": True,
        },
        "branchGovernance": _required_branch_ruleset_contracts(),
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
    environments = state.get("privilegedEnvironments")
    identity = state.get("automationPushIdentity")
    governance = state.get("branchGovernance")
    if (
        not isinstance(actions, Mapping)
        or not isinstance(workflows, Mapping)
        or not isinstance(environments, Mapping)
        or not isinstance(identity, Mapping)
        or not isinstance(governance, Mapping)
    ):
        return False
    if any(state.get(key) is not True for key in (
        "enableStateCommits", "enablePagesPublish", "pagesWorkflow",
    )):
        return False
    if not _cloud_actions_contract_is_exact(actions, expected_enabled=True):
        return False
    if identity.get("exact") is not True or governance.get("exact") is not True:
        return False
    if set(environments) != {
        RELEASE_PUBLISHER_ENVIRONMENT,
        MAIN_AUTOMATION_ENVIRONMENT,
        PAGES_ENVIRONMENT,
    } or any(
        not isinstance(environments.get(environment), Mapping)
        or environments[environment].get("exact") is not True
        for environment in environments
    ):
        return False
    return set(workflows) == set(WORKFLOW_FILES) and all(
        isinstance(workflows.get(workflow), Mapping)
        and workflows[workflow].get("path") == f".github/workflows/{workflow}"
        and workflows[workflow].get("state") == "active"
        for workflow in WORKFLOW_FILES
    )


def _validate_cloud_monotonic_source(state: Mapping[str, Any]) -> None:
    _validate_governance_mutation_source(state)
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


def _configure_privileged_environment(
    repo: str,
    environment: str,
    default_branch: str,
    before: Mapping[str, Any],
    mutate: Callable[[Callable[[], ExecutionCapture], str], bool],
) -> dict[str, Any]:
    if before.get("exact") is True:
        return dict(before)
    encoded_environment = urllib.parse.quote(environment, safe="")
    if before.get("customBranchPolicy") is not True:
        label = f"configure-environment-{environment}"
        mutate(
            lambda: _github_api_mutation(
                f"repos/{repo}/environments/{encoded_environment}",
                label,
                payload={
                    "deployment_branch_policy": {
                        "protected_branches": False,
                        "custom_branch_policies": True,
                    }
                },
            ),
            label,
        )
    observed = _github_environment_state(repo, environment, default_branch)
    if observed.get("customBranchPolicy") is not True:
        return observed
    exact_policy_ids = [
        policy["id"]
        for policy in observed["branchPolicies"]
        if policy["name"] == default_branch and policy["type"] == "branch"
    ]
    keep_id = exact_policy_ids[0] if len(exact_policy_ids) == 1 else None
    for policy in observed["branchPolicies"]:
        if policy["id"] == keep_id:
            continue
        label = f"remove-environment-policy-{environment}-{policy['id']}"
        mutate(
            lambda policy_id=policy["id"], label=label: _github_api_mutation(
                (
                    f"repos/{repo}/environments/{encoded_environment}/"
                    f"deployment-branch-policies/{policy_id}"
                ),
                label,
                method="DELETE",
            ),
            label,
        )
    if keep_id is None:
        label = f"create-environment-policy-{environment}"
        mutate(
            lambda: _github_api_mutation(
                (
                    f"repos/{repo}/environments/{encoded_environment}/"
                    "deployment-branch-policies"
                ),
                label,
                method="POST",
                payload={"name": default_branch, "type": "branch"},
            ),
            label,
        )
    return _github_environment_state(repo, environment, default_branch)


def _configure_cloud(
    repo: str,
    apply: bool,
    evidence_dir: str | None,
    *,
    source_authority: Mapping[str, Any] | None = None,
    default_branch: str = "main",
) -> dict[str, Any]:
    if apply and (
        not isinstance(source_authority, Mapping)
        or source_authority.get("exact") is not True
        or source_authority.get("defaultBranch") != default_branch
        or not isinstance(source_authority.get("sourceSha"), str)
    ):
        raise IntegrityFailure("cloud apply requires exact source authority")
    source_sha = (
        str(source_authority["sourceSha"])
        if isinstance(source_authority, Mapping)
        else _try_source_sha()
    )
    head_leases = (
        list(source_authority.get("headLeases", []))
        if isinstance(source_authority, Mapping)
        else []
    )

    def require_head(phase: str) -> None:
        if apply:
            head_leases.append(
                _require_cloud_head_lease(repo, default_branch, source_sha, phase)
            )

    repository_before = _gate_policy_repository(repo)
    before = _cloud_operating_state(repo, default_branch)
    _validate_cloud_monotonic_source(before)
    required = _required_cloud_configuration()
    complete = _cloud_configuration_is_exact(before)
    if complete:
        result = _base_result(
            "cloud.configure",
            ok=True,
            status="already-configured",
            source_sha=source_sha,
            repo=repo,
            repository=repository_before,
            configuration=before,
            sourceAuthority=source_authority,
            headLeases=head_leases,
            mutationApplied=False,
        )
        return _attach_command_evidence(result, evidence_dir)
    if not apply:
        result = _base_result(
            "cloud.configure",
            ok=True,
            status="dry-run",
            source_sha=source_sha,
            repo=repo,
            repository=repository_before,
            configuration=before,
            requiredConfiguration=required,
            applyRequiresSourceRef=True,
            mutationApplied=False,
        )
        return _attach_command_evidence(result, evidence_dir)
    if (
        before["automationPushIdentity"].get("exact") is not True
        and not _command_exists("ssh-keygen")
    ):
        raise PrerequisiteFailure(
            "OpenSSH ssh-keygen is required before any cloud mutation"
        )
    attempts: list[dict[str, Any]] = []
    accepted_count = 0
    ambiguous = False

    def mutate(operation: Callable[[], ExecutionCapture], label: str) -> bool:
        nonlocal accepted_count, ambiguous
        try:
            capture = operation()
            attempts.append(capture.summary())
            if capture.returncode == 0:
                accepted_count += 1
                return True
            else:
                ambiguous = True
        except (CliFailure, OSError) as error:
            ambiguous = True
            attempts.append({"id": label, "error": _safe_error(str(error))})
        return False

    require_head("immediately-before-first-mutation")

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

    governance_before = before["branchGovernance"]
    staged_governance: Mapping[str, Any] = governance_before
    governance_observation_error: str | None = None

    def observe_governance(phase: str) -> bool:
        nonlocal ambiguous, governance_observation_error, staged_governance
        try:
            staged_governance = _github_branch_governance_state(repo, default_branch)
        except (CliFailure, OSError) as error:
            ambiguous = True
            governance_observation_error = _safe_error(f"{phase}: {error}")
            return False
        return True

    def write_ruleset(
        contract_name: str, contract: Mapping[str, Any], label: str
    ) -> bool:
        named_rulesets = staged_governance.get("namedRulesets")
        if not isinstance(named_rulesets, Mapping):
            raise IntegrityFailure("GitHub named ruleset state is unavailable")
        observed_ruleset = named_rulesets.get(contract_name)
        if not isinstance(observed_ruleset, Mapping):
            raise IntegrityFailure(f"GitHub ruleset state is missing: {contract_name}")
        ruleset_id = observed_ruleset.get("id")
        if ruleset_id is not None and (type(ruleset_id) is not int or ruleset_id < 1):
            raise IntegrityFailure(f"GitHub ruleset ID is malformed: {contract_name}")
        payload = _ruleset_mutation_payload(contract)
        method = "POST" if ruleset_id is None else "PUT"
        endpoint = (
            f"repos/{repo}/rulesets"
            if ruleset_id is None
            else f"repos/{repo}/rulesets/{ruleset_id}"
        )
        require_head(f"before-{label}")
        return mutate(
            lambda: _github_api_mutation(
                endpoint,
                label,
                method=method,
                payload=payload,
            ),
            label,
        )

    if governance_before.get("exact") is not True:
        required_rulesets = _required_branch_ruleset_contracts()
        if set(GOVERNANCE_RULESET_MUTATION_ORDER) != set(required_rulesets):
            raise IntegrityFailure("governance ruleset mutation order is incomplete")

        governance_sequence_ready = True
        for contract_name in GOVERNANCE_RULESET_MUTATION_ORDER[:2]:
            observed_ruleset = staged_governance["namedRulesets"][contract_name]
            if observed_ruleset["exact"] is True:
                continue
            label = f"configure-ruleset-{contract_name}"
            if not write_ruleset(contract_name, required_rulesets[contract_name], label):
                governance_sequence_ready = False
                break
            governance_sequence_ready = observe_governance(f"observe-{contract_name}")
            if not governance_sequence_ready:
                break
            if staged_governance["namedRulesets"][contract_name]["exact"] is not True:
                ambiguous = True
                governance_observation_error = f"{label} was not observed exact"
                governance_sequence_ready = False
                break

        if governance_sequence_ready:
            named_rulesets = staged_governance["namedRulesets"]
            creation_state = named_rulesets["gateTagCreation"]
            freeze_state = named_rulesets["immutableGateTag"]
            if creation_state["exact"] is not True or freeze_state["exact"] is not True:
                bootstrap_freeze = _gate_tag_bootstrap_freeze_contract()
                if freeze_state.get("contract") != bootstrap_freeze:
                    governance_sequence_ready = write_ruleset(
                        "immutableGateTag",
                        bootstrap_freeze,
                        "bootstrap-gate-tag-freeze",
                    )
                    if governance_sequence_ready:
                        governance_sequence_ready = observe_governance(
                            "observe-bootstrap-gate-tag-freeze"
                        )
                if governance_sequence_ready:
                    freeze_state = staged_governance["namedRulesets"]["immutableGateTag"]
                    if freeze_state.get("contract") != bootstrap_freeze:
                        ambiguous = True
                        governance_observation_error = (
                            "bootstrap gate-tag freeze was not observed exact"
                        )
                        governance_sequence_ready = False

                if governance_sequence_ready:
                    creation_state = staged_governance["namedRulesets"]["gateTagCreation"]
                    if creation_state["exact"] is not True:
                        governance_sequence_ready = write_ruleset(
                            "gateTagCreation",
                            required_rulesets["gateTagCreation"],
                            "configure-ruleset-gateTagCreation",
                        )
                        if governance_sequence_ready:
                            governance_sequence_ready = observe_governance(
                                "observe-controlled-gate-tag-creation"
                            )
                if governance_sequence_ready:
                    creation_state = staged_governance["namedRulesets"]["gateTagCreation"]
                    freeze_state = staged_governance["namedRulesets"]["immutableGateTag"]
                    if (
                        creation_state["exact"] is not True
                        or freeze_state.get("contract") != bootstrap_freeze
                    ):
                        ambiguous = True
                        governance_observation_error = (
                            "controlled tag creation and bootstrap freeze were not both "
                            "observed exact"
                        )
                        governance_sequence_ready = False

                if governance_sequence_ready:
                    governance_sequence_ready = write_ruleset(
                        "immutableGateTag",
                        required_rulesets["immutableGateTag"],
                        "finalize-gate-tag-freeze",
                    )
                    if governance_sequence_ready:
                        observe_governance("observe-final-gate-tag-freeze")

    require_head("after-governance")

    staged_environments: dict[str, dict[str, Any]] = {}
    environment_error: str | None = None
    try:
        for environment in (
            RELEASE_PUBLISHER_ENVIRONMENT,
            MAIN_AUTOMATION_ENVIRONMENT,
            PAGES_ENVIRONMENT,
        ):
            staged_environments[environment] = _configure_privileged_environment(
                repo,
                environment,
                default_branch,
                before["privilegedEnvironments"][environment],
                mutate,
            )
    except (CliFailure, OSError) as error:
        ambiguous = True
        environment_error = _safe_error(str(error))
        staged_environments = dict(before["privilegedEnvironments"])
    environments_proven = bool(
        set(staged_environments) == {
            RELEASE_PUBLISHER_ENVIRONMENT,
            MAIN_AUTOMATION_ENVIRONMENT,
            PAGES_ENVIRONMENT,
        }
        and all(item.get("exact") is True for item in staged_environments.values())
    )
    require_head("before-credential-provisioning")

    credential_actions: Mapping[str, Any] | None = None
    credential_actions_error: str | None = None
    try:
        credential_actions = _github_actions_permissions_state(repo)
    except (CliFailure, OSError) as error:
        ambiguous = True
        credential_actions_error = _safe_error(str(error))
    credential_actions_proven = bool(
        credential_actions is not None
        and _cloud_actions_contract_is_exact(
            credential_actions, expected_enabled=None
        )
    )

    identity_before = before["automationPushIdentity"]
    staged_identity: Mapping[str, Any] = identity_before
    identity_observation_error: str | None = None
    if identity_before["exact"] is not True:
        try:
            staged_governance = _github_branch_governance_state(repo, default_branch)
        except (CliFailure, OSError) as error:
            ambiguous = True
            governance_observation_error = _safe_error(str(error))
        if staged_governance.get("exact") is True:
            try:
                staged_identity = _automation_push_identity_state(repo)
                _validate_governance_mutation_source({
                    "automationPushIdentity": staged_identity,
                    "branchGovernance": staged_governance,
                })
            except (CliFailure, OSError) as error:
                ambiguous = True
                identity_observation_error = _safe_error(str(error))
                staged_identity = identity_before
    if (
        staged_identity.get("exact") is not True
        and staged_governance.get("exact") is True
        and credential_actions_proven
        and environments_proven
        and identity_observation_error is None
    ):
        if before["enableStateCommits"]:
            mutate(
                lambda: _capture_command(
                    (
                        "gh", "variable", "set", "ENABLE_STATE_COMMITS",
                        "--body", "false", "--repo", repo,
                    ),
                    label="deactivate-state-commits-for-key-rotation",
                    timeout_seconds=60,
                ),
                "deactivate-state-commits-for-key-rotation",
            )
        require_head("immediately-before-environment-secret")
        with _generated_automation_push_identity(repo) as generated_identity:
            secret_write_accepted = mutate(
                lambda: _capture_command_with_private_stdin_file(
                    (
                        "gh", "secret", "set", AUTOMATION_PUSH_SECRET_NAME,
                        "--env", MAIN_AUTOMATION_ENVIRONMENT, "--repo", repo,
                    ),
                    generated_identity["privatePath"],
                    label="set-automation-push-private-key-secret",
                    timeout_seconds=60,
                ),
                "set-automation-push-private-key-secret",
            )
            mutate(
                lambda: _capture_command(
                    (
                        "gh", "variable", "set",
                        AUTOMATION_PUSH_FINGERPRINT_VARIABLE,
                        "--body", generated_identity["fingerprint"],
                        "--repo", repo,
                    ),
                    label="set-automation-push-fingerprint",
                    timeout_seconds=60,
                ),
                "set-automation-push-fingerprint",
            )
            identity_material_staged = False
            try:
                staged_variables = _repository_variables(repo)
                staged_environment_secrets = _environment_secret_names(
                    repo, MAIN_AUTOMATION_ENVIRONMENT
                )
                identity_material_staged = bool(
                    secret_write_accepted
                    and staged_variables.get(AUTOMATION_PUSH_FINGERPRINT_VARIABLE)
                    == generated_identity["fingerprint"]
                    and AUTOMATION_PUSH_SECRET_NAME in staged_environment_secrets
                )
            except (CliFailure, OSError) as error:
                ambiguous = True
                identity_observation_error = _safe_error(str(error))
            if identity_material_staged:
                for existing_key in staged_identity.get("deployKeys", []):
                    if existing_key.get("readOnly") is False:
                        label = f"rotate-automation-push-deploy-key-{existing_key['id']}"
                        mutate(
                            lambda key_id=existing_key["id"], label=label: (
                                _github_api_mutation(
                                    f"repos/{repo}/keys/{key_id}",
                                    label,
                                    method="DELETE",
                                )
                            ),
                            label,
                        )
                mutate(
                    lambda: _github_api_mutation(
                        f"repos/{repo}/keys",
                        "create-automation-push-deploy-key",
                        method="POST",
                        payload={
                            "title": AUTOMATION_PUSH_DEPLOY_KEY_TITLE,
                            "key": generated_identity["publicKey"],
                            "read_only": False,
                        },
                    ),
                    "create-automation-push-deploy-key",
                )
            else:
                ambiguous = True
                identity_observation_error = identity_observation_error or (
                    "automation secret and fingerprint were not both proven; "
                    "deploy-key creation was skipped"
                )
        try:
            staged_identity = _automation_push_identity_state(repo)
            if (
                staged_identity.get("keyExact") is True
                and staged_identity.get("environmentSecretPresent") is True
                and staged_identity.get("repositorySecretPresent") is True
            ):
                mutate(
                    lambda: _capture_command(
                        (
                            "gh", "secret", "delete", AUTOMATION_PUSH_SECRET_NAME,
                            "--repo", repo,
                        ),
                        label="remove-repository-scoped-automation-secret",
                        timeout_seconds=60,
                    ),
                    "remove-repository-scoped-automation-secret",
                )
                staged_identity = _automation_push_identity_state(repo)
        except (CliFailure, OSError) as error:
            ambiguous = True
            identity_observation_error = _safe_error(str(error))
            staged_identity = identity_before
    elif staged_identity.get("exact") is not True:
        ambiguous = True
        if identity_observation_error is None:
            identity_observation_error = (
                "branch governance was not proven; "
                "automation key provisioning was skipped"
                if staged_governance.get("exact") is not True
                else "Actions policy, privileged environments, or source lease was not "
                "proven; automation key provisioning was skipped"
            )
        if credential_actions_error:
            identity_observation_error = (
                f"{identity_observation_error}: {credential_actions_error}"
            )

    require_head("before-activation")
    staged_actions: dict[str, Any] | None = None
    activation_precondition: dict[str, Any]
    try:
        staged_actions = _github_actions_permissions_state(repo)
    except (CliFailure, OSError) as error:
        ambiguous = True
        activation_precondition = {
            "proven": False,
            "actions": None,
            "automationPushIdentity": staged_identity,
            "branchGovernance": staged_governance,
            "privilegedEnvironments": staged_environments,
            "error": _safe_error(
                f"Actions policy could not be read before activation: {error}"
            ),
        }
        if identity_observation_error:
            activation_precondition["identityObservationError"] = (
                identity_observation_error
            )
        if governance_observation_error:
            activation_precondition["governanceObservationError"] = (
                governance_observation_error
            )
    else:
        actions_policy_proven = _cloud_actions_contract_is_exact(
            staged_actions, expected_enabled=None
        )
        identity_proven = staged_identity.get("exact") is True
        governance_proven = staged_governance.get("exact") is True
        environment_policy_proven = environments_proven
        complete_precondition = (
            actions_policy_proven
            and identity_proven
            and governance_proven
            and environment_policy_proven
        )
        activation_precondition = {
            "proven": complete_precondition,
            "actions": staged_actions,
            "automationPushIdentity": staged_identity,
            "branchGovernance": staged_governance,
            "privilegedEnvironments": staged_environments,
        }
        if not complete_precondition:
            ambiguous = True
            activation_precondition["error"] = (
                "Actions policy, automation identity, branch governance, or privileged "
                "environment policy was not exact; "
                "all activation substeps were skipped"
            )
            if identity_observation_error:
                activation_precondition["identityObservationError"] = (
                    identity_observation_error
                )
            if governance_observation_error:
                activation_precondition["governanceObservationError"] = (
                    governance_observation_error
                )
            if environment_error:
                activation_precondition["environmentObservationError"] = environment_error

    if activation_precondition["proven"]:
        for name, key in (
            ("ENABLE_STATE_COMMITS", "enableStateCommits"),
            ("ENABLE_PAGES_PUBLISH", "enablePagesPublish"),
        ):
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
    require_head("after-configuration")
    after: dict[str, Any] | None = None
    repository_after: dict[str, Any] | None = None
    verification_error: str | None = None
    for attempt in range(6):
        try:
            repository_after = _gate_policy_repository(repo)
            after = _cloud_operating_state(repo, default_branch)
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
            source_sha=source_sha,
            repo=repo,
            repository=repository_after,
            configuration=after,
            activationPrecondition=activation_precondition,
            sourceAuthority=source_authority,
            headLeases=head_leases,
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
        source_sha=source_sha,
        repo=repo,
        repository=repository_after,
        configuration=after,
        activationPrecondition=activation_precondition,
        sourceAuthority=source_authority,
        headLeases=head_leases,
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


def _dispatch_cloud(
    preflight: Mapping[str, Any],
    apply: bool,
    *,
    expected_source_sha: str | None = None,
) -> dict[str, Any]:
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
    if expected_source_sha is not None and source_sha != expected_source_sha.lower():
        raise IntegrityFailure("default branch changed before workflow dispatch")
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
        dispatch_fields = ["--field", f"dispatch_nonce={dispatch_nonce}"]
        if workflow == "publish-gate.yml":
            dispatch_fields.extend(("--field", f"source_sha={source_sha}"))
        dispatched = _capture_command(
            (
                "gh", "workflow", "run", workflow, "--repo", repo, "--ref", branch,
                *dispatch_fields,
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
        "candidate-aggregate", "promotion", "promotion-push",
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
    source_ref = getattr(args, "source_ref", None)
    if args.action == "configure":
        if args.run_id is not None or args.output_root:
            raise UsageFailure("configure does not accept run-id or output-root")
        if args.apply and not source_ref:
            raise UsageFailure("cloud configure --apply requires full --source-ref")
        if not args.apply and source_ref:
            raise UsageFailure("cloud configure dry-run does not accept --source-ref")
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
    if args.action != "configure" and source_ref:
        raise UsageFailure("source-ref is accepted only by cloud configure --apply")
    preflight = _cloud_preflight(repo, workflow)
    if args.action == "configure":
        if args.evidence_dir:
            _assert_new_directory(Path(args.evidence_dir))
        authority = (
            _cloud_source_authority(
                repo, str(preflight["defaultBranch"]), str(source_ref)
            )
            if args.apply
            else None
        )
        return _configure_cloud(
            repo,
            bool(args.apply),
            args.evidence_dir,
            source_authority=authority,
            default_branch=str(preflight["defaultBranch"]),
        )
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


def _require_gate_tag_lease(repo: str, tag: str, source_sha: str) -> dict[str, Any]:
    observed = _remote_gate_tag_commit(repo, tag)
    record = {
        "tag": tag,
        "expectedCommit": source_sha,
        "observedCommit": observed,
        "exact": observed == source_sha,
    }
    if record["exact"] is not True:
        raise IntegrityFailure(
            "gate tag changed after binding and immediately before release publication"
        )
    return record


def _remote_repository_file_bytes(
    repo: str, path: str, source_sha: str, *, max_bytes: int
) -> bytes:
    encoded_path = urllib.parse.quote(path, safe="/")
    encoded_ref = urllib.parse.quote(source_sha, safe="")
    value = _gh_json(
        (
            "gh", "api", "-H", GITHUB_JSON_ACCEPT_HEADER, "-H",
            GITHUB_API_VERSION_HEADER,
            f"repos/{repo}/contents/{encoded_path}?ref={encoded_ref}",
        ),
        f"remote-source-file-{path.replace('/', '-')}",
        prerequisite=True,
    )
    if (
        not isinstance(value, dict)
        or value.get("type") != "file"
        or value.get("path") != path
        or value.get("encoding") != "base64"
        or type(value.get("size")) is not int
        or value["size"] < 1
        or value["size"] > max_bytes
        or not isinstance(value.get("content"), str)
    ):
        raise IntegrityFailure(f"remote source file is malformed: {path}")
    try:
        content = base64.b64decode(
            "".join(value["content"].split()).encode("ascii"), validate=True
        )
    except (UnicodeEncodeError, ValueError) as error:
        raise IntegrityFailure(f"remote source file is not base64: {path}") from error
    if len(content) != value["size"]:
        raise IntegrityFailure(f"remote source file size differs: {path}")
    return content


def _gate_tag_source_authority(
    repo: str, tag: str, source_sha: str, gate_bytes: bytes
) -> dict[str, Any]:
    remote_gate_bytes = _remote_repository_file_bytes(
        repo, "filter.txt", source_sha, max_bytes=MAX_HTTPS_BYTES
    )
    _validate_locked_gate_bytes(remote_gate_bytes)
    if remote_gate_bytes != gate_bytes:
        raise IntegrityFailure("frozen gate tag source contains different gate bytes")
    return {
        "tag": tag,
        "sourceCommit": source_sha,
        "filterBytes": len(remote_gate_bytes),
        "filterSha256": sha256_bytes(remote_gate_bytes),
        "exact": True,
    }


def _ensure_remote_gate_tag(
    repo: str,
    tag: str,
    source_sha: str,
    *,
    gate_bytes: bytes | None = None,
    allow_frozen_source: bool = False,
) -> dict[str, Any]:
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
    if observed is None:
        return {
            "verified": False,
            "status": "prebound-tag-missing",
            "sourceCommit": None,
            "expectedSourceCommit": source_sha,
            "mutationApplied": False,
            "observationError": observation_error,
        }
    if observed != source_sha and not allow_frozen_source:
        raise IntegrityFailure("pre-existing gate tag targets a different commit")
    authority = None
    if observed != source_sha:
        if gate_bytes is None:
            raise IntegrityFailure("frozen gate recovery requires exact gate bytes")
        authority = _gate_tag_source_authority(repo, tag, observed, gate_bytes)
    return {
        "verified": True,
        "status": (
            "already-bound" if observed == source_sha else "frozen-source-recovery"
        ),
        "sourceCommit": observed,
        "expectedSourceCommit": source_sha,
        "sourceMatchesWorkflow": observed == source_sha,
        "sourceAuthority": authority,
        "mutationApplied": False,
    }


def _require_remote_default_head(
    repo: str, branch: str, source_sha: str
) -> dict[str, Any]:
    default_head = _gh_json(
        (
            "gh", "api", "-H", GITHUB_JSON_ACCEPT_HEADER, "-H",
            GITHUB_API_VERSION_HEADER,
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
    ):
        raise IntegrityFailure("gate release default-branch head is malformed")
    observed_sha = default_head_sha.lower()
    observation = {
        "branch": branch,
        "expectedSourceCommit": source_sha,
        "observedHead": observed_sha,
        "exact": observed_sha == source_sha,
    }
    if not observation["exact"]:
        raise IntegrityFailure(
            "gate release source is not the current default-branch head",
            details={"defaultHeadObservation": observation},
        )
    return observation


def _gate_default_head_observation(
    repo: str, branch: str, source_sha: str, phase: str
) -> dict[str, Any]:
    try:
        observed = _require_remote_default_head(repo, branch, source_sha)
    except (CliFailure, OSError) as error:
        remote = (
            error.details.get("defaultHeadObservation")
            if isinstance(error, CliFailure) else None
        )
        observation = dict(remote) if isinstance(remote, Mapping) else {
            "branch": branch,
            "expectedSourceCommit": source_sha,
            "observedHead": None,
            "exact": False,
        }
        observation["phase"] = phase
        observation["error"] = _safe_error(str(error))
        return observation
    if (
        not isinstance(observed, Mapping)
        or set(observed) != {
            "branch", "expectedSourceCommit", "observedHead", "exact"
        }
        or observed.get("branch") != branch
        or observed.get("expectedSourceCommit") != source_sha
        or observed.get("observedHead") != source_sha
        or observed.get("exact") is not True
    ):
        raise IntegrityFailure("gate release default-head observation is malformed")
    observation = dict(observed)
    observation["phase"] = phase
    return observation


def _require_exact_gate_head_observation(observation: Mapping[str, Any]) -> None:
    if observation.get("exact") is not True:
        raise IntegrityFailure(
            "gate release source is not the current default-branch head",
            details={"defaultHeadObservation": dict(observation)},
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


def _gate_release_source_context(repo: str, source_sha: str) -> dict[str, Any]:
    repository = _gh_json(
        (
            "gh", "repo", "view", repo, "--json",
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
        or str(repository.get("nameWithOwner", "")).casefold() != repo.casefold()
        or repository.get("visibility") != "PUBLIC"
        or not isinstance(default_branch, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,254}", default_branch)
        or ".." in default_branch
        or "//" in default_branch
        or default_branch.endswith(("/", ".", ".lock"))
    ):
        raise IntegrityFailure("gate release repository is not the exact public repository")
    commit = _gh_json(
        ("gh", "api", f"repos/{repo}/commits/{source_sha}"),
        "gate-release-source-commit",
        prerequisite=True,
    )
    if not isinstance(commit, dict) or str(commit.get("sha", "")).lower() != source_sha:
        raise IntegrityFailure("gate release source commit is not present in the repository")
    return {"repository": repository, "defaultBranch": default_branch}


def _prepare_gate_publication(
    args: argparse.Namespace,
    repo: str,
    tag: str,
    subscription_url: str,
    gate_bytes: bytes,
    artifacts: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if args.apply or not args.source_ref:
        raise UsageFailure("gate-release prepare-publish is read-only and requires --source-ref")
    source_sha = _git_source_binding(args.source_ref)
    source_context = _gate_release_source_context(repo, source_sha)
    default_branch = str(source_context["defaultBranch"])
    existing = _gate_release_view(repo, tag, allow_missing=True)
    if existing is not None and existing.get("isDraft") is not True:
        proof = _verify_gate_release_with_retry(
            repo, tag, subscription_url, gate_bytes
        )
        result = _base_result(
            "gate-release.prepare-publish",
            ok=True,
            status="already-published",
            source_sha=source_sha,
            artifacts=artifacts,
            gateRelease=proof,
            tagPresent=True,
            tagSourceCommit=proof["sourceCommit"],
            releaseComplete=True,
            mutationApplied=False,
        )
        return _attach_command_evidence(result, args.evidence_dir)

    policy = _immutable_release_policy(repo)
    if policy["enabled"] is not True:
        raise IntegrityFailure("repository immutable releases are not enabled")
    tag_source_sha = _remote_gate_tag_commit(repo, tag, allow_missing=True)
    tag_authority = None
    if tag_source_sha is None:
        if existing is not None:
            raise IntegrityFailure("recoverable gate draft has no frozen tag")
        head = _gate_default_head_observation(
            repo, default_branch, source_sha, "prepare-before-tag"
        )
        _require_exact_gate_head_observation(head)
    else:
        tag_authority = _gate_tag_source_authority(
            repo, tag, tag_source_sha, gate_bytes
        )
        head = _gate_default_head_observation(
            repo, default_branch, source_sha, "prepare-existing-tag"
        )
        if existing is not None:
            _exact_gate_draft_has_asset(
                existing,
                repo,
                tag,
                subscription_url,
                gate_bytes,
                tag_source_sha,
            )
    result = _base_result(
        "gate-release.prepare-publish",
        ok=True,
        status=("ready-to-bind-tag" if tag_source_sha is None else "ready-to-recover"),
        source_sha=source_sha,
        artifacts=artifacts,
        immutableReleasePolicy=policy,
        defaultHeadObservation=head,
        release=(
            _gate_release_view_summary(existing) if existing is not None else None
        ),
        tagPresent=tag_source_sha is not None,
        tagSourceCommit=tag_source_sha,
        tagSourceAuthority=tag_authority,
        releaseComplete=False,
        mutationApplied=False,
    )
    return _attach_command_evidence(result, args.evidence_dir)


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
    if args.action == "prepare-publish":
        return _prepare_gate_publication(
            args,
            bound_repo,
            tag,
            subscription_url,
            gate_bytes,
            artifacts,
        )
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
    source_context = _gate_release_source_context(bound_repo, source_sha)
    default_branch = str(source_context["defaultBranch"])
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
            immutableReleasePublished=(
                isinstance(proof, Mapping) and proof.get("immutable") is True
            ),
            mutationApplied=False,
        )
        return _attach_command_evidence(result, args.evidence_dir)
    policy = _immutable_release_policy(bound_repo)
    if policy["enabled"] is not True:
        raise IntegrityFailure("repository immutable releases are not enabled")
    tag_binding = _ensure_remote_gate_tag(
        bound_repo,
        tag,
        source_sha,
        gate_bytes=gate_bytes,
        allow_frozen_source=True,
    )
    head_observations = [
        _gate_default_head_observation(
            bound_repo, default_branch, source_sha, "frozen-tag-commit-point"
        )
    ]
    if not tag_binding["verified"]:
        result = _base_result(
            "gate-release.publish",
            ok=False,
            status="gate-tag-binding-unverified",
            source_sha=source_sha,
            artifacts=artifacts,
            defaultHeadObservations=head_observations,
            gateTag=tag_binding,
            immutableReleasePublished=False,
            mutationApplied=tag_binding["mutationApplied"],
            mutationState="unknown",
        )
        result["_processExitCode"] = EXIT_ROLLBACK_INCOMPLETE
        return _attach_post_mutation_evidence(result, args.evidence_dir)
    gate_source_sha = str(tag_binding.get("sourceCommit", "")).lower()
    if not GIT_SHA_RE.fullmatch(gate_source_sha):
        raise IntegrityFailure("verified frozen gate tag has no exact source commit")
    if _github_gate_publisher_context(bound_repo, source_sha):
        workflow_gate_source = os.environ.get("HDF_GATE_TAG_SOURCE_SHA", "").lower()
        workflow_creation_state = os.environ.get("HDF_GATE_TAG_CREATED", "")
        if (
            workflow_gate_source != gate_source_sha
            or workflow_creation_state not in {"true", "false", "unknown"}
        ):
            raise IntegrityFailure("publisher workflow gate-tag evidence is malformed")
        tag_binding["workflowCreationState"] = workflow_creation_state
        tag_binding["mutationApplied"] = (
            True if workflow_creation_state == "true"
            else False if workflow_creation_state == "false"
            else None
        )
    if existing is not None and existing.get("isDraft") is True:
        recovery = _recover_exact_gate_draft(
            bound_repo,
            tag,
            subscription_url,
            gate_bytes,
            gate_source_sha,
            existing,
        )
        head_observations.append(
            _gate_default_head_observation(
                bound_repo, default_branch, source_sha, "after-draft-recovery"
            )
        )
        if not recovery["ok"]:
            result = _base_result(
                "gate-release.publish",
                ok=False,
                status=str(recovery["status"]),
                source_sha=source_sha,
                artifacts=artifacts,
                defaultHeadObservations=head_observations,
                gateDraftRecovery=recovery,
                immutableReleasePublished=None,
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
            defaultHeadObservations=head_observations,
            gateRelease=recovery["proof"],
            gateDraftRecovery={
                key: value for key, value in recovery.items() if key != "proof"
            },
            immutableReleasePublished=(
                isinstance(recovery.get("proof"), Mapping)
                and recovery["proof"].get("immutable") is True
            ),
            mutationApplied=recovery["mutationApplied"],
            mutationState=recovery["mutationState"],
        )
        return _attach_post_mutation_evidence(result, args.evidence_dir)
    head_observations.append(
        _gate_default_head_observation(
            bound_repo, default_branch, source_sha, "after-tag-before-release"
        )
    )
    pre_release_tag_lease = _require_gate_tag_lease(
        bound_repo, tag, gate_source_sha
    )
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
            bound_repo, tag, subscription_url, gate_bytes, gate_source_sha
        )
    except (CliFailure, OSError) as verification_error:
        head_observations.append(
            _gate_default_head_observation(
                bound_repo, default_branch, source_sha, "after-release-attempt"
            )
        )
        recovery: dict[str, Any] | None = None
        recovery_error: str | None = None
        if not creation_accepted:
            try:
                recovery = _resume_gate_draft_after_ambiguous_create(
                    bound_repo, tag, subscription_url, gate_bytes, gate_source_sha
                )
            except (CliFailure, OSError) as error:
                recovery_error = _safe_error(str(error))
        if recovery is not None:
            head_observations.append(
                _gate_default_head_observation(
                    bound_repo,
                    default_branch,
                    source_sha,
                    "after-ambiguous-draft-recovery",
                )
            )
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
                    defaultHeadObservations=head_observations,
                    gateRelease=recovery["proof"],
                    gateDraftRecovery={
                        key: value for key, value in recovery.items() if key != "proof"
                    },
                    releaseCreation=creation_record,
                    gateTag=tag_binding,
                    gateTagLease=pre_release_tag_lease,
                    initialVerificationError=_safe_error(str(verification_error)),
                    immutableReleasePublished=(
                        isinstance(recovery.get("proof"), Mapping)
                        and recovery["proof"].get("immutable") is True
                    ),
                    mutationApplied=mutation_applied,
                    mutationState=mutation_state,
                )
                return _attach_post_mutation_evidence(result, args.evidence_dir)
            if tag_binding["mutationApplied"] is True and not recovery_applied:
                mutation_state = "partially-applied-unverified"
            result = _base_result(
                "gate-release.publish",
                ok=False,
                status=(
                    str(recovery.get("status", "draft-recovery-failed"))
                ),
                source_sha=source_sha,
                artifacts=artifacts,
                defaultHeadObservations=head_observations,
                gateDraftRecovery=recovery,
                releaseCreation=creation_record,
                gateTag=tag_binding,
                gateTagLease=pre_release_tag_lease,
                initialVerificationError=_safe_error(str(verification_error)),
                immutableReleasePublished=None,
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
            defaultHeadObservations=head_observations,
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
            gateTagLease=pre_release_tag_lease,
            immutableReleasePublished=None,
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
    head_observations.append(
        _gate_default_head_observation(
            bound_repo, default_branch, source_sha, "after-release"
        )
    )
    if creation_accepted:
        status = "published"
        mutation_applied = True
    else:
        status = "published-after-ambiguous-client-result"
        mutation_applied = True if tag_binding["mutationApplied"] is True else None
    head_drift_observed = any(
        observation.get("exact") is not True for observation in head_observations
    )
    if head_drift_observed:
        status = f"{status}-after-default-head-drift"
    result = _base_result(
        "gate-release.publish",
        ok=True,
        status=status,
        source_sha=source_sha,
        artifacts=artifacts,
        defaultHeadObservations=head_observations,
        gateRelease=proof,
        releaseCreation=creation_record,
        gateTag=tag_binding,
        gateTagLease=pre_release_tag_lease,
        defaultHeadDriftObserved=head_drift_observed,
        immutableReleasePublished=(
            isinstance(proof, Mapping) and proof.get("immutable") is True
        ),
        mutationApplied=mutation_applied,
        mutationState="applied" if mutation_applied is True else "observed-exact",
    )
    return (
        _attach_post_mutation_evidence(result, args.evidence_dir)
        if mutation_applied is not False
        else _attach_command_evidence(result, args.evidence_dir)
    )


def _github_gate_publisher_context(repo: str, source_ref: str | None) -> bool:
    if not source_ref or not GIT_SHA_RE.fullmatch(source_ref.lower()):
        return False
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    expected_prefix = f"{repo}/.github/workflows/publish-gate.yml@refs/heads/"
    return bool(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and os.environ.get("GITHUB_REPOSITORY", "").casefold() == repo.casefold()
        and os.environ.get("GITHUB_SHA", "").lower() == source_ref.lower()
        and os.environ.get("GITHUB_WORKFLOW_SHA", "").lower() == source_ref.lower()
        and workflow_ref.startswith(expected_prefix)
        and os.environ.get("GITHUB_JOB") == "publish"
        and os.environ.get("HDF_PRIVILEGED_ENVIRONMENT")
        == MAIN_AUTOMATION_ENVIRONMENT
    )


def command_gate_release_entry(args: argparse.Namespace) -> dict[str, Any]:
    if args.action != "publish" or not args.apply:
        return command_gate_release(args)
    repo = _require_repo(args.repo)
    if _github_gate_publisher_context(repo, args.source_ref):
        return command_gate_release(args)
    if not args.source_ref:
        raise UsageFailure("gate-release publish requires --source-ref and --apply")
    preflight = _cloud_preflight(repo, "publish-gate.yml")
    default_branch = str(preflight["defaultBranch"])
    authority = _cloud_source_authority(repo, default_branch, args.source_ref)
    final_lease = _require_cloud_head_lease(
        repo,
        default_branch,
        str(authority["sourceSha"]),
        "immediately-before-gate-workflow-dispatch",
    )
    dispatched = _dispatch_cloud(
        preflight,
        True,
        expected_source_sha=str(authority["sourceSha"]),
    )
    dispatch_ok = dispatched.get("ok") is True
    result = _base_result(
        "gate-release.publish",
        ok=dispatch_ok,
        status=(
            "publisher-workflow-dispatched"
            if dispatch_ok else "publisher-workflow-dispatch-unverified"
        ),
        source_sha=str(authority["sourceSha"]),
        repo=repo,
        sourceAuthority=authority,
        headLeases=[*authority["headLeases"], final_lease],
        dispatch=dispatched,
        directPublication=False,
        mutationApplied=dispatched.get("mutationApplied"),
        mutationState=dispatched.get("mutationState"),
    )
    if not dispatch_ok:
        result["_processExitCode"] = int(
            dispatched.get("_processExitCode", EXIT_ROLLBACK_INCOMPLETE)
        )
    return _attach_post_mutation_evidence(result, args.evidence_dir)


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


def _require_csp_probe_inspection(value: Any, *, label: str) -> str:
    if not isinstance(value, Mapping):
        raise IntegrityFailure(f"{label} returned a non-object CSP probe inspection")
    state_sha = value.get("state_sha256")
    probe_count = value.get("probe_count")
    if (
        value.get("command") != "csp-probe-inspect"
        or value.get("ok") is not True
        or value.get("two_read_stable") is not True
        or value.get("read_1_sha256") != state_sha
        or value.get("read_2_sha256") != state_sha
        or not isinstance(state_sha, str)
        or not SHA256_RE.fullmatch(state_sha)
        or value.get("probe_source_sha256") != CSP_PROBE_SOURCE_SHA256
        or value.get("endpoint") != CSP_PROBE_ENDPOINT
        or type(probe_count) is not int
        or probe_count not in (0, 1)
        or value.get("probe_present") is not (probe_count == 1)
        or value.get("adguard_configuration_changed") is not False
    ):
        raise IntegrityFailure(f"{label} failed the fixed CSP probe inspection contract")
    return state_sha


def _require_csp_probe_plan(value: Any) -> None:
    if (
        not isinstance(value, Mapping)
        or value.get("command") != "csp-probe-install"
        or value.get("ok") is not True
        or value.get("what_if") is not True
        or value.get("probe_present") is not False
        or value.get("probe_source_sha256") != CSP_PROBE_SOURCE_SHA256
        or value.get("endpoint") != CSP_PROBE_ENDPOINT
        or value.get("is_custom") is not True
        or value.get("is_style") is not False
        or value.get("parsed_meta") != CSP_PROBE_PARSED_META_CONTRACT
        or value.get("adguard_configuration_changed") is not False
        or not isinstance(value.get("order"), list)
        or "validated-backup-restore" not in value["order"]
        or "two-independent-stable-post-inspections" not in value["order"]
    ):
        raise IntegrityFailure("AdGuard returned an invalid fixed CSP probe dry-run plan")


def _require_csp_probe_install(value: Any, pre_state_sha: str) -> str:
    if not isinstance(value, Mapping):
        raise IntegrityFailure("AdGuard returned a non-object CSP probe install result")
    backup = value.get("backup")
    if (
        value.get("command") != "csp-probe-install"
        or value.get("ok") is not True
        or value.get("changed") is not True
        or value.get("probe_present") is not True
        or value.get("pre_state_sha256") != pre_state_sha
        or value.get("probe_source_sha256") != CSP_PROBE_SOURCE_SHA256
        or value.get("endpoint") != CSP_PROBE_ENDPOINT
        or value.get("is_custom") is not True
        or value.get("is_style") is not False
        or not isinstance(backup, str)
        or not backup
        or not isinstance(value.get("installed_state_sha256"), str)
        or not SHA256_RE.fullmatch(value["installed_state_sha256"])
    ):
        raise IntegrityFailure("AdGuard returned an invalid fixed CSP probe install result")
    return backup


def _require_csp_probe_restore(value: Any, pre_state_sha: str) -> None:
    if (
        not isinstance(value, Mapping)
        or value.get("command") != "csp-probe-restore"
        or value.get("ok") is not True
        or value.get("verified") is not True
        or value.get("probe_present") is not False
        or value.get("state_sha256") != pre_state_sha
        or value.get("probe_source_sha256") != CSP_PROBE_SOURCE_SHA256
        or value.get("idempotent") is not True
    ):
        raise IntegrityFailure("AdGuard returned an invalid fixed CSP probe restore result")


def _create_csp_probe_backup_root() -> Path:
    return Path(tempfile.mkdtemp(prefix="hotdeal-focus-csp-probe-"))


def _discover_csp_probe_backup(backup_root: Path) -> Path | None:
    try:
        resolved_root = backup_root.resolve(strict=True)
        entries = list(resolved_root.iterdir())
    except OSError as error:
        raise IntegrityFailure("CSP probe backup root cannot be inspected") from error
    completed: list[Path] = []
    for entry in entries:
        if entry.is_symlink():
            raise IntegrityFailure("CSP probe backup root contains a reparse entry")
        if entry.name.startswith(".pending-") and entry.is_dir():
            continue
        if not entry.is_dir():
            raise IntegrityFailure("CSP probe backup root contains an unexpected entry")
        marker = entry / "backup-complete.json"
        manifest = entry / "backup-manifest.json"
        if (
            not marker.is_file()
            or marker.is_symlink()
            or not manifest.is_file()
            or manifest.is_symlink()
        ):
            raise IntegrityFailure("CSP probe backup directory is not complete and regular")
        completed.append(entry.resolve(strict=True))
    if len(completed) > 1:
        raise IntegrityFailure("CSP probe installation produced multiple completed backups")
    return completed[0] if completed else None


def _csp_probe_backup_has_transaction(backup: Path) -> bool:
    plan = backup / "transaction-plan.json"
    marker = backup / "transaction-plan.complete.json"
    plan_exists = plan.is_file() and not plan.is_symlink()
    marker_exists = marker.is_file() and not marker.is_symlink()
    if plan_exists is not marker_exists:
        raise IntegrityFailure("CSP probe transaction marker is incomplete")
    return plan_exists and marker_exists


def _require_child_backup_path(child_path: str, discovered: Path) -> None:
    try:
        child = Path(child_path).resolve(strict=True)
    except OSError as error:
        raise IntegrityFailure("AdGuard CSP probe result names an unavailable backup") from error
    if os.path.normcase(str(child)) != os.path.normcase(str(discovered)):
        raise IntegrityFailure("AdGuard CSP probe result names a different backup")


def _csp_probe_recovery_details(
    ps_cli: Path,
    backup: Path | None,
    backup_root: Path,
) -> dict[str, Any]:
    details: dict[str, Any] = {"backupRoot": str(backup_root)}
    if backup is not None:
        details.update({
            "backupPath": str(backup),
            "commandArgv": [
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(ps_cli), "csp-probe-restore", "-BackupPath",
                str(backup), "-Apply",
            ],
        })
    return details


def _run_csp_browser_probe(script_path: Path) -> dict[str, Any]:
    capture = _capture_command(
        ("node", str(script_path)),
        label="adguard-csp-browser-proof",
        timeout_seconds=150,
    )
    try:
        value = _decode_json(capture.stdout, "AdGuard CSP browser probe output")
    except IntegrityFailure as error:
        raise VerificationFailure("CSP browser probe returned no valid proof") from error
    if capture.returncode:
        failure_kind = value.get("failure_kind") if isinstance(value, Mapping) else None
        safe_kind = failure_kind if failure_kind in {
            "arguments-rejected", "origin-request-failed",
            "origin-contract-failed", "browser-launch-failed",
            "navigation-failed", "navigation-response-missing",
            "proof-failed", "proof-error",
        } else "invalid-failure-contract"
        safe_observation: dict[str, Any] = {
            "schema_version": 2,
            "command": "adguard-csp-browser-probe",
            "ok": False,
            "failure_kind": safe_kind,
        }
        if isinstance(value, Mapping):
            for key in CSP_PROBE_BROWSER_KEYS - {
                "schema_version", "command", "ok", "computed_custom_property"
            }:
                if isinstance(value.get(key), bool):
                    safe_observation[key] = value[key]
            root_state = value.get("root_state")
            if root_state in {
                "complete", "failed", "missing", "pending", "other", "unknown"
            }:
                safe_observation["root_state"] = root_state
        raise VerificationFailure(
            "CSP browser probe did not prove the fixed contract",
            details={"browserProbe": safe_observation},
        )
    if not isinstance(value, dict) or set(value) != set(CSP_PROBE_BROWSER_KEYS):
        raise IntegrityFailure("CSP browser proof has an unexpected evidence field set")
    for key in CSP_PROBE_BROWSER_KEYS - {
        "schema_version", "command", "computed_custom_property"
    }:
        if value.get(key) is not True:
            raise VerificationFailure("CSP browser proof contains a failed assertion")
    if (
        value.get("schema_version") != 2
        or value.get("command") != "adguard-csp-browser-probe"
        or value.get("computed_custom_property") != "hdf-gm-style-pass"
    ):
        raise VerificationFailure("CSP browser proof differs from the fixed result contract")
    return _public_value(value)


def _command_adguard_csp_probe(args: argparse.Namespace, ps_cli: Path) -> dict[str, Any]:
    if args.backup_path:
        raise UsageFailure("adguard csp-probe does not accept --backup-path")
    if args.approve_exclusive_target_migration:
        raise UsageFailure("adguard csp-probe does not accept migration approval")
    powershell_base = (
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", str(ps_cli),
    )
    if not args.apply:
        child = _powershell_json(
            (*powershell_base, "csp-probe-install", "-WhatIf"),
            apply_mutation=False,
            rollback=False,
        )
        _require_csp_probe_plan(child)
        result = _base_result(
            "adguard.csp-probe",
            ok=True,
            status="dry-run",
            source_sha=_try_source_sha(),
            mutationApplied=False,
            probe=child,
        )
        return _attach_command_evidence(result, args.evidence_dir)

    browser_script = PROJECT_ROOT / "scripts" / "probe_adguard_csp.mjs"
    if not browser_script.is_file():
        raise PrerequisiteFailure("fixed AdGuard CSP browser probe is missing")
    if not _command_exists("node"):
        raise PrerequisiteFailure("Node.js is unavailable for the CSP browser proof")

    pre = _powershell_json(
        (*powershell_base, "csp-probe-inspect"),
        apply_mutation=False,
        rollback=False,
    )
    pre_state_sha = _require_csp_probe_inspection(pre, label="pre-inspection")
    if pre.get("probe_present") is not False or pre.get("probe_count") != 0:
        raise IntegrityFailure("fixed CSP probe already exists before the diagnostic")

    backup_root = _create_csp_probe_backup_root()
    install: dict[str, Any] | None = None
    browser: dict[str, Any] | None = None
    operation_error: CliFailure | None = None
    discovered_backup: Path | None = None
    restore: dict[str, Any] | None = None
    recovery_contract_errors: list[CliFailure] = []
    restore_errors: list[CliFailure] = []
    restore_attempt_count = 0
    post_inspections: list[dict[str, Any]] = []
    post_errors: list[CliFailure] = []
    child_backup_path: str | None = None
    transaction_complete = False

    try:
        try:
            candidate = _powershell_json(
                (*powershell_base, "csp-probe-install", "-BackupRoot",
                 str(backup_root), "-Apply"),
                apply_mutation=True,
                rollback=False,
            )
            child_backup_path = _require_csp_probe_install(candidate, pre_state_sha)
            install = dict(candidate)
            browser = _run_csp_browser_probe(browser_script)
        except CliFailure as error:
            operation_error = error
    finally:
        try:
            discovered_backup = _discover_csp_probe_backup(backup_root)
            if discovered_backup is not None:
                transaction_complete = _csp_probe_backup_has_transaction(
                    discovered_backup
                )
            if child_backup_path is not None:
                if discovered_backup is None:
                    raise IntegrityFailure(
                        "successful CSP probe install has no completed backup"
                    )
                _require_child_backup_path(child_backup_path, discovered_backup)
        except CliFailure as error:
            recovery_contract_errors.append(error)

        if discovered_backup is not None and transaction_complete:
            restore_argv = (
                *powershell_base, "csp-probe-restore", "-BackupPath",
                str(discovered_backup), "-Apply",
            )
            for _ in range(2):
                restore_attempt_count += 1
                try:
                    restored = _powershell_json(
                        restore_argv, apply_mutation=True, rollback=True
                    )
                    _require_csp_probe_restore(restored, pre_state_sha)
                    restore = dict(restored)
                    break
                except CliFailure as error:
                    restore_errors.append(error)
        elif install is not None:
            recovery_contract_errors.append(IntegrityFailure(
                "installed CSP probe has no restorable completed transaction"
            ))

        for index in range(2):
            try:
                observed = _powershell_json(
                    (*powershell_base, "csp-probe-inspect"),
                    apply_mutation=False,
                    rollback=False,
                )
                observed_sha = _require_csp_probe_inspection(
                    observed, label=f"post-inspection-{index + 1}"
                )
                if (
                    observed_sha != pre_state_sha
                    or observed.get("probe_present") is not False
                    or observed.get("probe_count") != 0
                ):
                    raise IntegrityFailure(
                        "post-inspection differs from the exact pre-probe state"
                    )
                post_inspections.append(dict(observed))
            except CliFailure as error:
                post_errors.append(error)

    restore_was_required = discovered_backup is not None and transaction_complete
    terminal_state_proved = len(post_inspections) == 2 and not post_errors
    restoration_proved = not restore_was_required or restore is not None
    if recovery_contract_errors or not terminal_state_proved or not restoration_proved:
        raise MutationFailure(
            "CSP probe terminal restoration could not be proven",
            rollback_complete=False,
            details={
                "mutationApplied": None,
                "mutationState": "unknown-terminal-state",
                "restorationAttemptCount": restore_attempt_count,
                "restoreFailureCount": len(restore_errors),
                "postInspectionSuccessCount": len(post_inspections),
                "adguardRecovery": _csp_probe_recovery_details(
                    ps_cli, discovered_backup, backup_root
                ),
            },
        )
    if operation_error is not None:
        raise MutationFailure(
            "CSP probe failed after exact terminal restoration",
            rollback_complete=True,
            details={
                "mutationApplied": False,
                "mutationState": "rolled-back",
                "failureType": type(operation_error).__name__,
                "operationError": _public_value(operation_error.details),
                "backup": str(discovered_backup) if discovered_backup else None,
                "postStateSha256": pre_state_sha,
            },
        )
    if install is None or browser is None or restore is None:
        raise IntegrityFailure("CSP probe orchestration completed without full proof")

    result = _base_result(
        "adguard.csp-probe",
        ok=True,
        status="proved-and-restored",
        source_sha=_try_source_sha(),
        mutationApplied=False,
        mutationState="transiently-applied-and-restored",
        transientMutationApplied=True,
        restorationVerified=True,
        restorationAttemptCount=restore_attempt_count,
        probeSourceSha256=CSP_PROBE_SOURCE_SHA256,
        endpoint=CSP_PROBE_ENDPOINT,
        backup=str(discovered_backup),
        preInspection=pre,
        install=install,
        browserProof=browser,
        restore=restore,
        postInspections=post_inspections,
    )
    return _attach_command_evidence(result, args.evidence_dir)


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
    if action == "csp-probe":
        if args.manifest_source != DEFAULT_PAGES_MANIFEST:
            raise UsageFailure("adguard csp-probe does not accept --manifest-source")
        return _command_adguard_csp_probe(args, ps_cli)
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
        protocolVersion=manifest["protocolVersion"],
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
    cloud.add_argument("--source-ref")
    cloud.add_argument("--apply", action="store_true")
    cloud.add_argument("--json", action="store_true", required=True)
    cloud.set_defaults(execute=command_cloud)

    gate_release = commands.add_parser("gate-release")
    gate_release.add_argument(
        "action", choices=("enable-policy", "verify", "prepare-publish", "publish")
    )
    gate_release.add_argument("--repo", required=True)
    gate_release.add_argument("--source-ref")
    gate_release.add_argument("--evidence-dir")
    gate_release.add_argument("--apply", action="store_true")
    gate_release.add_argument("--json", action="store_true", required=True)
    gate_release.set_defaults(execute=command_gate_release_entry)

    adguard = commands.add_parser("adguard")
    adguard.add_argument(
        "action", choices=(
            "inspect", "plan", "deploy", "verify", "rollback", "csp-probe"
        )
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
