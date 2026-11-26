from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    mongodb_uri: str
    database_name: str
    api_token: str

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            mongodb_uri=os.getenv("MONGODB_URI", "mongodb://mongo:27017"),
            database_name=os.getenv("SECURITY_DB_NAME", "ooosec_security"),
            api_token=os.getenv("SECURITY_CORE_API_TOKEN", ""),
        )
