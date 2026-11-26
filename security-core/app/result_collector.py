from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import Any


class CollectorError(ValueError):
    """Raised when scanner output is malformed or violates collector policy."""


MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_FINDINGS = 1000
MAX_PATH_LENGTH = 512
MAX_RULE_LENGTH = 128
MAX_TITLE_LENGTH = 160
_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$")
_RULE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_SEVERITIES = {"low", "medium", "high", "critical"}
_BANDIT_SEVERITY = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}


@dataclass(frozen=True)
class Finding:
    scanner: str
    scanner_version: str
    rule_id: str
    severity: str
    path: str
    line: int | None
    column: int | None
    title: str
    description: str
    fingerprint: str
    commit_sha: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CollectorError("duplicate_json_key")
        result[key] = value
    return result


def _bounded_text(value: Any, *, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise CollectorError(f"invalid_{field}")
    value = value.strip()
    if not value or len(value) > maximum:
        raise CollectorError(f"invalid_{field}")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise CollectorError(f"invalid_{field}")
    return value


def _safe_path(value: Any) -> str:
    raw = _bounded_text(value, field="path", maximum=MAX_PATH_LENGTH)
    if "\\" in raw or raw.startswith("/") or "\x00" in raw:
        raise CollectorError("invalid_path")
    parts = raw.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise CollectorError("invalid_path")
    path = PurePosixPath(raw)
    if path.is_absolute() or len(path.parts) > 32:
        raise CollectorError("invalid_path")
    return path.as_posix()


def _optional_position(value: Any, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 10_000_000:
        raise CollectorError(f"invalid_{field}")
    return value


def _fingerprint(scanner: str, rule_id: str, path: str, line: int | None) -> str:
    material = "\0".join((scanner, rule_id, path, str(line or 0))).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _make_finding(
    *, scanner: str, version: str, rule_id: Any, severity: str,
    path: Any, line: Any, column: Any, title: str, description: str,
    commit_sha: str,
) -> Finding:
    rule = _bounded_text(rule_id, field="rule_id", maximum=MAX_RULE_LENGTH)
    if not _RULE_RE.fullmatch(rule):
        raise CollectorError("invalid_rule_id")
    safe_file = _safe_path(path)
    safe_line = _optional_position(line, "line")
    safe_column = _optional_position(column, "column")
    normalized_severity = severity.lower()
    if normalized_severity not in _SEVERITIES:
        raise CollectorError("invalid_severity")
    safe_title = _bounded_text(title, field="title", maximum=MAX_TITLE_LENGTH)
    safe_description = _bounded_text(description, field="description", maximum=240)
    return Finding(
        scanner=scanner,
        scanner_version=version,
        rule_id=rule,
        severity=normalized_severity,
        path=safe_file,
        line=safe_line,
        column=safe_column,
        title=safe_title,
        description=safe_description,
        fingerprint=_fingerprint(scanner, rule, safe_file, safe_line),
        commit_sha=commit_sha,
    )


def _load_json(output: bytes, max_output_bytes: int) -> Any:
    if not isinstance(output, bytes) or len(output) > max_output_bytes:
        raise CollectorError("scanner_output_too_large")
    try:
        return json.loads(output.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except CollectorError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CollectorError("invalid_scanner_json") from None


def parse_gitleaks(
    output: bytes, *, scanner_version: str, commit_sha: str,
    max_output_bytes: int = MAX_OUTPUT_BYTES, max_findings: int = MAX_FINDINGS,
) -> list[dict[str, Any]]:
    version = _bounded_text(scanner_version, field="scanner_version", maximum=64)
    if not _VERSION_RE.fullmatch(version) or not _SHA_RE.fullmatch(commit_sha):
        raise CollectorError("invalid_scan_metadata")
    if not 1 <= max_findings <= MAX_FINDINGS:
        raise CollectorError("invalid_finding_limit")
    payload = _load_json(output, max_output_bytes)
    if not isinstance(payload, list) or len(payload) > max_findings:
        raise CollectorError("invalid_gitleaks_result_count")
    findings = []
    for item in payload:
        if not isinstance(item, dict):
            raise CollectorError("invalid_gitleaks_finding")
        # Never copy Secret, Match, Raw, or any untrusted descriptive field.
        findings.append(_make_finding(
            scanner="gitleaks", version=version,
            rule_id=item.get("RuleID"), severity="high",
            path=item.get("File"), line=item.get("StartLine"),
            column=item.get("StartColumn"),
            title="Potential secret detected",
            description="A configured secret-detection rule matched this file.",
            commit_sha=commit_sha,
        ))
    return [finding.to_dict() for finding in findings]


def parse_bandit(
    output: bytes, *, scanner_version: str, commit_sha: str,
    max_output_bytes: int = MAX_OUTPUT_BYTES, max_findings: int = MAX_FINDINGS,
) -> list[dict[str, Any]]:
    version = _bounded_text(scanner_version, field="scanner_version", maximum=64)
    if not _VERSION_RE.fullmatch(version) or not _SHA_RE.fullmatch(commit_sha):
        raise CollectorError("invalid_scan_metadata")
    if not 1 <= max_findings <= MAX_FINDINGS:
        raise CollectorError("invalid_finding_limit")
    payload = _load_json(output, max_output_bytes)
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise CollectorError("invalid_bandit_payload")
    results = payload["results"]
    if len(results) > max_findings:
        raise CollectorError("too_many_findings")
    findings = []
    for item in results:
        if not isinstance(item, dict):
            raise CollectorError("invalid_bandit_finding")
        bandit_severity = item.get("issue_severity")
        if bandit_severity not in _BANDIT_SEVERITY:
            raise CollectorError("invalid_severity")
        test_id = item.get("test_id")
        findings.append(_make_finding(
            scanner="bandit", version=version,
            rule_id=test_id, severity=_BANDIT_SEVERITY[bandit_severity],
            path=item.get("filename"), line=item.get("line_number"),
            column=None,
            title=f"Bandit rule {test_id}",
            # issue_text and code are intentionally excluded: they can contain source.
            description="Static analysis identified a potential Python security issue.",
            commit_sha=commit_sha,
        ))
    return [finding.to_dict() for finding in findings]


def collect_findings(
    scanner: str, output: bytes, *, scanner_version: str, commit_sha: str,
    max_output_bytes: int = MAX_OUTPUT_BYTES, max_findings: int = MAX_FINDINGS,
) -> list[dict[str, Any]]:
    """Normalize allowlisted scanner output; never persist raw output."""
    if scanner == "gitleaks":
        return parse_gitleaks(
            output, scanner_version=scanner_version, commit_sha=commit_sha,
            max_output_bytes=max_output_bytes, max_findings=max_findings,
        )
    if scanner == "bandit":
        return parse_bandit(
            output, scanner_version=scanner_version, commit_sha=commit_sha,
            max_output_bytes=max_output_bytes, max_findings=max_findings,
        )
    raise CollectorError("scanner_not_allowed")
