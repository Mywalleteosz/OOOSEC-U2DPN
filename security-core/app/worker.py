from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Callable

from pymongo import UpdateOne

from .job_queue import claim_next_job, complete_job, fail_job
from .result_collector import CollectorError, collect_findings
from .sandbox import SandboxPolicyError, run_sandbox, scanner_profile
from .source_fetcher import SourcePolicyError, extract_source_archive, fetch_repository_archive


class WorkerFailure(RuntimeError):
    """A bounded, safe worker failure code; never contains source or exception text."""

    def __init__(self, code: str) -> None:
        if not code or len(code) > 64 or not code.replace("_", "").isalnum():
            raise ValueError("invalid_worker_error_code")
        self.code = code
        super().__init__(code)


def _error_code(error: Exception) -> str:
    if isinstance(error, WorkerFailure):
        return error.code
    if isinstance(error, SourcePolicyError):
        return "source_policy_rejected"
    if isinstance(error, SandboxPolicyError):
        return "sandbox_policy_rejected"
    if isinstance(error, CollectorError):
        return "scanner_output_rejected"
    if isinstance(error, OSError):
        return "worker_io_error"
    return "worker_internal_error"


async def process_claimed_job(
    database: Any,
    job: dict[str, Any],
    worker_id: str,
    *,
    scanner_images: dict[str, str],
    fetch_archive: Callable = fetch_repository_archive,
    extract_archive: Callable = extract_source_archive,
    sandbox_runner: Callable = run_sandbox,
    findings_collector: Callable = collect_findings,
) -> dict[str, Any]:
    """Process one leased job; only sanitized findings are persisted."""
    job_id = job.get("id") if isinstance(job, dict) else None
    if (
        not isinstance(job_id, str)
        or job.get("status") != "running"
        or job.get("worker_id") != worker_id
    ):
        return {"status": "lease_lost"}

    try:
        scanner = job.get("scanner")
        if scanner not in {"gitleaks", "bandit"}:
            raise WorkerFailure("scanner_not_implemented")
        commit_sha = job.get("commit_sha")
        if not isinstance(commit_sha, str) or len(commit_sha) not in {40, 64}:
            raise WorkerFailure("immutable_commit_sha_required")
        if any(char not in "0123456789abcdef" for char in commit_sha):
            raise WorkerFailure("immutable_commit_sha_required")

        image = scanner_images.get(scanner, "")
        if not image:
            raise WorkerFailure("scanner_image_not_configured")
        asset = await database.security_assets.find_one(
            {"id": job.get("asset_id"), "status": "active"}
        )
        if not asset or not isinstance(asset.get("repository_url"), str):
            raise WorkerFailure("asset_not_active")

        profile = scanner_profile(scanner, {scanner: image})
        image_digest = image.partition("@sha256:")[2]
        if len(image_digest) != 64:
            raise WorkerFailure("scanner_image_not_configured")
        scanner_identity = image_digest

        with tempfile.TemporaryDirectory(prefix="ooosec-worker-") as staging:
            root = Path(staging)
            archive = root / "source.archive"
            source = root / "source"
            fetch_archive(asset["repository_url"], commit_sha, archive)
            extract_archive(archive, source)
            result = sandbox_runner(
                profile,
                source,
                timeout_seconds=300,
                max_output_bytes=2 * 1024 * 1024,
            )
            if result.returncode != 0:
                raise WorkerFailure("scanner_execution_failed")
            findings = findings_collector(
                scanner,
                result.output,
                scanner_version=scanner_identity,
                commit_sha=commit_sha,
            )

        if findings:
            operations = [
                UpdateOne(
                    {"job_id": job_id, "fingerprint": finding["fingerprint"]},
                    {"$setOnInsert": {"job_id": job_id, **finding}},
                    upsert=True,
                )
                for finding in findings
            ]
            await database.security_findings.bulk_write(operations, ordered=False)

        completed = await complete_job(
            database,
            job_id,
            worker_id,
            findings_count=len(findings),
        )
        if not completed:
            return {"status": "lease_lost"}
        return {"status": "completed", "findings_count": len(findings)}
    except Exception as error:
        code = _error_code(error)
        failed = await fail_job(database, job_id, worker_id, error_code=code)
        if not failed:
            return {"status": "lease_lost"}
        return {"status": "failed", "error_code": code}


async def process_next_job(
    database: Any,
    worker_id: str,
    *,
    scanner_images: dict[str, str],
    lease_seconds: int = 600,
    max_attempts: int = 3,
) -> dict[str, Any]:
    """Atomically claim and process at most one job; suitable for a worker loop."""
    job = await claim_next_job(
        database,
        worker_id,
        lease_seconds=lease_seconds,
        max_attempts=max_attempts,
    )
    if job is None:
        return {"status": "idle"}
    return await process_claimed_job(
        database,
        job,
        worker_id,
        scanner_images=scanner_images,
    )
