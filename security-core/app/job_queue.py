from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from pymongo import ReturnDocument


async def claim_next_job(
    database: Any,
    worker_id: str,
    *,
    lease_seconds: int = 120,
    max_attempts: int = 3,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    """Atomically claim an eligible job or reclaim an expired lease."""
    if not worker_id or len(worker_id) > 128:
        raise ValueError("worker_id must contain 1..128 characters")
    if not 10 <= lease_seconds <= 900:
        raise ValueError("lease_seconds must be between 10 and 900")
    if not 1 <= max_attempts <= 10:
        raise ValueError("max_attempts must be between 1 and 10")

    claimed_at = now or datetime.now(timezone.utc)
    return await database.security_scan_jobs.find_one_and_update(
        {
            "$and": [
                {
                    "$or": [
                        {"status": "queued"},
                        {"status": "running", "lease_until": {"$lte": claimed_at}},
                    ]
                },
                {
                    "$or": [
                        {"attempts": {"$lt": max_attempts}},
                        {"attempts": {"$exists": False}},
                    ]
                },
            ]
        },
        {
            "$set": {
                "status": "running",
                "worker_id": worker_id,
                "claimed_at": claimed_at,
                "lease_until": claimed_at + timedelta(seconds=lease_seconds),
            },
            "$inc": {"attempts": 1},
        },
        sort=[("created_at", 1)],
        return_document=ReturnDocument.AFTER,
    )


async def complete_job(
    database: Any,
    job_id: str,
    worker_id: str,
    *,
    findings_count: int,
    now: datetime | None = None,
) -> bool:
    if findings_count < 0:
        raise ValueError("findings_count cannot be negative")
    completed_at = now or datetime.now(timezone.utc)
    result = await database.security_scan_jobs.update_one(
        {
            "id": job_id,
            "status": "running",
            "worker_id": worker_id,
            "lease_until": {"$gt": completed_at},
        },
        {
            "$set": {
                "status": "completed",
                "findings_count": findings_count,
                "completed_at": completed_at,
            },
            "$unset": {"worker_id": "", "lease_until": ""},
        },
    )
    return result.modified_count == 1


async def fail_job(
    database: Any,
    job_id: str,
    worker_id: str,
    *,
    error_code: str,
    now: datetime | None = None,
) -> bool:
    """Store a bounded error code, never exception text or secrets."""
    if not error_code or len(error_code) > 64 or not error_code.replace("_", "").isalnum():
        raise ValueError("error_code must be a short alphanumeric code")
    failed_at = now or datetime.now(timezone.utc)
    result = await database.security_scan_jobs.update_one(
        {
            "id": job_id,
            "status": "running",
            "worker_id": worker_id,
            "lease_until": {"$gt": failed_at},
        },
        {
            "$set": {
                "status": "failed",
                "error_code": error_code,
                "completed_at": failed_at,
            },
            "$unset": {"worker_id": "", "lease_until": ""},
        },
    )
    return result.modified_count == 1
