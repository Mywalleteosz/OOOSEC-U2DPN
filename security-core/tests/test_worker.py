from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.sandbox import SandboxResult
from app.worker import process_claimed_job, process_next_job


IMAGE = "ghcr.io/gitleaks/gitleaks:v8.24.2@sha256:" + "a" * 64
COMMIT = "b" * 40


def make_database(*, asset=None, modified_count=1):
    return SimpleNamespace(
        security_assets=SimpleNamespace(find_one=AsyncMock(return_value=asset or {
            "id": "asset-1",
            "status": "active",
            "repository_url": "https://github.com/example/repo",
        })),
        security_scan_jobs=SimpleNamespace(
            find_one_and_update=AsyncMock(return_value=None),
            update_one=AsyncMock(return_value=SimpleNamespace(modified_count=modified_count)),
        ),
        security_findings=SimpleNamespace(bulk_write=AsyncMock()),
    )


def make_job(**overrides):
    job = {
        "id": "job-1",
        "asset_id": "asset-1",
        "scanner": "gitleaks",
        "commit_sha": COMMIT,
        "status": "running",
        "worker_id": "worker-a",
    }
    job.update(overrides)
    return job


def fake_fetch(repository_url, commit_sha, destination):
    assert repository_url == "https://github.com/example/repo"
    assert commit_sha == COMMIT
    destination.write_bytes(b"archive")


def fake_extract(archive, destination):
    destination.mkdir()
    return destination


def fake_sandbox(profile, source, **kwargs):
    assert profile.name == "gitleaks"
    assert source.is_dir()
    assert kwargs["timeout_seconds"] == 300
    return SandboxResult(returncode=0, output=b"[]")


@pytest.mark.asyncio
async def test_worker_processes_job_and_completes_current_lease():
    db = make_database()
    result = await process_claimed_job(
        db, make_job(), "worker-a",
        scanner_images={"gitleaks": IMAGE},
        fetch_archive=fake_fetch,
        extract_archive=fake_extract,
        sandbox_runner=fake_sandbox,
    )
    assert result == {"status": "completed", "findings_count": 0}
    update = db.security_scan_jobs.update_one.await_args.args[1]
    assert update["$set"]["status"] == "completed"


@pytest.mark.asyncio
async def test_worker_persists_only_normalized_findings():
    db = make_database()

    def sandbox_with_finding(profile, source, **kwargs):
        return SandboxResult(0, b'[{"RuleID":"generic-api-key","File":"src/app.py","StartLine":7,"StartColumn":1,"Secret":"must-not-persist"}]')

    result = await process_claimed_job(
        db, make_job(), "worker-a",
        scanner_images={"gitleaks": IMAGE},
        fetch_archive=fake_fetch,
        extract_archive=fake_extract,
        sandbox_runner=sandbox_with_finding,
    )
    assert result == {"status": "completed", "findings_count": 1}
    operations = db.security_findings.bulk_write.await_args.args[0]
    update = operations[0]._doc
    assert "Secret" not in str(update)
    assert update["$setOnInsert"]["title"] == "Potential secret detected"


@pytest.mark.asyncio
async def test_worker_rejects_unimplemented_scanner_without_running_fetcher():
    db = make_database()
    result = await process_claimed_job(
        db, make_job(scanner="pip-audit"), "worker-a",
        scanner_images={"gitleaks": IMAGE},
    )
    assert result == {"status": "failed", "error_code": "scanner_not_implemented"}


@pytest.mark.asyncio
async def test_worker_fails_closed_when_scanner_image_is_not_configured():
    db = make_database()
    result = await process_claimed_job(
        db, make_job(), "worker-a",
        scanner_images={},
    )
    assert result == {"status": "failed", "error_code": "scanner_image_not_configured"}


@pytest.mark.asyncio
async def test_worker_does_not_complete_when_lease_is_lost():
    db = make_database(modified_count=0)
    result = await process_claimed_job(
        db, make_job(), "worker-a",
        scanner_images={"gitleaks": IMAGE},
        fetch_archive=fake_fetch,
        extract_archive=fake_extract,
        sandbox_runner=fake_sandbox,
    )
    assert result == {"status": "lease_lost"}


@pytest.mark.asyncio
async def test_worker_rejects_job_owned_by_another_worker():
    db = make_database()
    result = await process_claimed_job(
        db, make_job(worker_id="worker-b"), "worker-a",
        scanner_images={"gitleaks": IMAGE},
    )
    assert result == {"status": "lease_lost"}
    db.security_assets.find_one.assert_not_awaited()


@pytest.mark.asyncio
async def test_worker_never_persists_raw_scanner_output_on_failure():
    db = make_database()

    def failed_sandbox(profile, source, **kwargs):
        raise RuntimeError("secret=do-not-store")

    result = await process_claimed_job(
        db, make_job(), "worker-a",
        scanner_images={"gitleaks": IMAGE},
        fetch_archive=fake_fetch,
        extract_archive=fake_extract,
        sandbox_runner=failed_sandbox,
    )
    assert result == {"status": "failed", "error_code": "worker_internal_error"}
    update = db.security_scan_jobs.update_one.await_args.args[1]
    assert update["$set"]["error_code"] == "worker_internal_error"
    assert "do-not-store" not in str(update)


@pytest.mark.asyncio
async def test_process_next_job_returns_idle_when_queue_is_empty():
    db = make_database()
    result = await process_next_job(db, "worker-a", scanner_images={})
    assert result == {"status": "idle"}
