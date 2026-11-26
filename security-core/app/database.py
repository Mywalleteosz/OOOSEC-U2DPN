from __future__ import annotations

from typing import Any

from fastapi import Request


def get_database(request: Request) -> Any:
    database = getattr(request.app.state, "db", None)
    if database is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=503, detail="Database unavailable")
    return database
