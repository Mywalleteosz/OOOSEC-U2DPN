from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pymongo import ASCENDING, AsyncMongoClient

from .config import Settings
from .routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = Settings.from_env()
    if len(settings.api_token) < 32:
        raise RuntimeError("SECURITY_CORE_API_TOKEN must contain at least 32 characters")

    client = AsyncMongoClient(settings.mongodb_uri, serverSelectionTimeoutMS=5000)
    try:
        await client.admin.command("ping")
        database = client[settings.database_name]
        await database.security_assets.create_index(
            [("repository_url", ASCENDING)], unique=True, name="uniq_repository_url"
        )
        await database.security_scan_jobs.create_index(
            [("idempotency_key", ASCENDING)],
            unique=True,
            sparse=True,
            name="uniq_scan_idempotency_key",
        )
        await database.security_scan_jobs.create_index(
            [("asset_id", ASCENDING), ("created_at", ASCENDING)],
            name="scan_asset_created",
        )
        app.state.db = database
        app.state.api_token = settings.api_token
        app.state.mongo_client = client
        yield
    finally:
        await client.close()


def create_app() -> FastAPI:
    app = FastAPI(
        title="OOOSEC Security Core",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @app.get("/health/live", tags=["health"])
    async def liveness():
        return {"status": "ok"}

    @app.get("/health/ready", tags=["health"])
    async def readiness():
        database = getattr(app.state, "db", None)
        if database is None:
            raise HTTPException(status_code=503, detail="Database unavailable")
        await database.command("ping")
        return {"status": "ready"}

    app.include_router(router)
    return app


app = create_app()
