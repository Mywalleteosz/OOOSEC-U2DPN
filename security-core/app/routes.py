from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pymongo.errors import DuplicateKeyError

from .auth import require_api_token
from .database import get_database
from .schemas import AssetCreate, AssetResponse, AssetStatus, ScanCreate, ScanResponse

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_api_token)])


@router.post("/assets", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(payload: AssetCreate, database=Depends(get_database)):
    document = {
        "id": str(uuid4()),
        "name": payload.name,
        "repository_url": payload.repository_url,
        "description": payload.description,
        "status": AssetStatus.active.value,
        "created_at": datetime.now(timezone.utc),
    }
    try:
        await database.security_assets.insert_one(document)
    except DuplicateKeyError as exc:
        raise HTTPException(status_code=409, detail="Repository is already registered") from exc
    return document


@router.post("/scans", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    payload: ScanCreate,
    database=Depends(get_database),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=128),
):
    asset = await database.security_assets.find_one(
        {"id": payload.asset_id, "status": AssetStatus.active.value}
    )
    if asset is None:
        raise HTTPException(status_code=404, detail="Active asset not found")

    if idempotency_key:
        existing = await database.security_scan_jobs.find_one({"idempotency_key": idempotency_key})
        if existing:
            return existing

    document = {
        "id": str(uuid4()),
        "asset_id": payload.asset_id,
        "scanner": payload.scanner.value,
        "commit_sha": payload.commit_sha,
        "status": "queued",
        "attempts": 0,
        "created_at": datetime.now(timezone.utc),
    }
    if idempotency_key:
        document["idempotency_key"] = idempotency_key

    try:
        await database.security_scan_jobs.insert_one(document)
    except DuplicateKeyError as exc:
        if idempotency_key:
            existing = await database.security_scan_jobs.find_one({"idempotency_key": idempotency_key})
            if existing:
                return existing
        raise HTTPException(status_code=409, detail="Duplicate scan request") from exc
    return document


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, database=Depends(get_database)):
    scan = await database.security_scan_jobs.find_one({"id": scan_id})
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
