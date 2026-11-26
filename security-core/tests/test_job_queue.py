from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pymongo import ReturnDocument

from app.job_queue import claim_next_job, complete_job, fail_job


@pytest.fixture
def database():
    return SimpleNamespace(
        security_scan_jobs=SimpleNamespace(
            find_one_and_update=AsyncMock(return_value={"id": "job-1", "status": "running"}),
            update_one=AsyncMock(return_value=SimpleNamespace(modified_count=1)),
        )
    )


@pytest.mark.asyncio
async def test_claim_is_atomic_and_uses_a_lease(database):
    now = datetime.now(timezone.utc)
    job = await claim_next_job(database, "worker-a", lease_seconds=60, now=now)

    assert job["status"] == "running"
    args = database.security_scan_jobs.find_one_and_update.await_args
    assert args.kwargs["return_document"] == ReturnDocument.AFTER
    assert args.args[0]["$or"][0] == {"status": "queued"}
    assert args.args[1]["$inc"] == {"attempts": 1}
    assert args.args[1]["$set"]["lease_until"] == now + timedelta(seconds=60)


@pytest.mark.asyncio
async def test_claim_rejects_invalid_lease(database):
    with pytest.raises(ValueError):
        await claim_next_job(database, "worker-a", lease_seconds=1)


@pytest.mark.asyncio
async def test_complete_requires_current_worker_lease(database):
    result = await complete_job(
        database, "job-1", "worker-a", findings_count=3
    )
    assert result is True
    query = database.security_scan_jobs.update_one.await_args.args[0]
    assert query["worker_id"] == "worker-a"
    assert query["status"] == "running"
    assert "lease_until" in query


@pytest.mark.asyncio
async def test_complete_returns_false_if_lease_was_lost(database):
    database.security_scan_jobs.update_one.return_value.modified_count = 0
    result = await complete_job(
        database, "job-1", "worker-a", findings_count=0
    )
    assert result is False


@pytest.mark.asyncio
async def test_failure_stores_only_bounded_error_code(database):
    result = await fail_job(
        database, "job-1", "worker-a", error_code="scanner_timeout"
    )
    assert result is True
    update = database.security_scan_jobs.update_one.await_args.args[1]
    assert update["$set"]["error_code"] == "scanner_timeout"
    assert "traceback" not in str(update).lower()


@pytest.mark.asyncio
async def test_failure_rejects_raw_exception_text(database):
    with pytest.raises(ValueError):
        await fail_job(
            database, "job-1", "worker-a", error_code="token=secret-value"
        )
