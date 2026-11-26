from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import create_app

TOKEN = "test-token-for-security-core-with-at-least-32-chars"


@pytest.fixture
def app():
    application = create_app()
    application.state.api_token = TOKEN
    application.state.db = SimpleNamespace(
        security_assets=SimpleNamespace(
            insert_one=AsyncMock(),
            find_one=AsyncMock(),
        ),
        security_scan_jobs=SimpleNamespace(
            insert_one=AsyncMock(),
            find_one=AsyncMock(),
        ),
    )
    return application


@pytest.fixture
async def client(app):
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as test_client:
        yield test_client


@pytest.mark.asyncio
async def test_health_is_public(client):
    response = await client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_api_requires_bearer_token(client):
    response = await client.post(
        "/api/v1/assets",
        json={
            "name": "test",
            "repository_url": "https://github.com/example/project",
        },
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_asset_rejects_non_github_target(client):
    response = await client.post(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={
            "name": "test",
            "repository_url": "https://example.com/owner/repo",
        },
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_asset_is_registered(client, app):
    response = await client.post(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={
            "name": "OOOSEC test",
            "repository_url": "https://github.com/example/project",
        },
    )
    assert response.status_code == 201
    assert response.json()["repository_url"] == "https://github.com/example/project"
    app.state.db.security_assets.insert_one.assert_awaited_once()


@pytest.mark.asyncio
async def test_scan_requires_active_registered_asset(client, app):
    app.state.db.security_assets.find_one.return_value = None
    response = await client.post(
        "/api/v1/scans",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={
            "asset_id": "00000000-0000-4000-8000-000000000001",
            "scanner": "bandit",
        },
    )
    assert response.status_code == 404
    app.state.db.security_scan_jobs.insert_one.assert_not_awaited()


@pytest.mark.asyncio
async def test_scan_is_queued_for_registered_asset(client, app):
    app.state.db.security_assets.find_one.return_value = {
        "id": "00000000-0000-4000-8000-000000000001",
        "status": "active",
    }
    response = await client.post(
        "/api/v1/scans",
        headers={"Authorization": f"Bearer {TOKEN}", "Idempotency-Key": "test-run-1"},
        json={
            "asset_id": "00000000-0000-4000-8000-000000000001",
            "scanner": "bandit",
        },
    )
    assert response.status_code == 202
    assert response.json()["status"] == "queued"
    app.state.db.security_scan_jobs.insert_one.assert_awaited_once()
