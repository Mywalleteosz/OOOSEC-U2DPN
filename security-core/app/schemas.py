from __future__ import annotations

from datetime import datetime
from enum import Enum
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AssetStatus(str, Enum):
    active = "active"
    disabled = "disabled"


class ScannerName(str, Enum):
    gitleaks = "gitleaks"
    bandit = "bandit"
    pip_audit = "pip-audit"
    trivy = "trivy"


class AssetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=2, max_length=100, pattern=r"^[A-Za-z0-9_. -]+$")
    repository_url: str = Field(min_length=20, max_length=300)
    description: str | None = Field(default=None, max_length=500)

    @field_validator("repository_url")
    @classmethod
    def validate_repository_url(cls, value: str) -> str:
        parsed = urlsplit(value.strip())
        segments = [part for part in parsed.path.strip("/").split("/") if part]
        if (
            parsed.scheme != "https"
            or parsed.hostname != "github.com"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
            or parsed.query
            or parsed.fragment
            or len(segments) != 2
        ):
            raise ValueError("Only canonical https://github.com/{owner}/{repository} URLs are allowed")
        owner, repository = segments
        if repository.endswith(".git"):
            repository = repository[:-4]
        if not owner or not repository or owner in {".", ".."} or repository in {".", ".."}:
            raise ValueError("Invalid GitHub repository path")
        return f"https://github.com/{owner}/{repository}"


class AssetResponse(BaseModel):
    id: str
    name: str
    repository_url: str
    description: str | None
    status: AssetStatus
    created_at: datetime


class ScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(min_length=36, max_length=36)
    scanner: ScannerName
    commit_sha: str = Field(pattern=r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")

    @field_validator("commit_sha")
    @classmethod
    def normalize_commit_sha(cls, value: str) -> str:
        return value.lower()


class ScanResponse(BaseModel):
    id: str
    asset_id: str
    scanner: ScannerName
    commit_sha: str
    status: str
    created_at: datetime
