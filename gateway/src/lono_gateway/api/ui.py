"""Local web console (single-page, no build step)."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

_INDEX = Path(__file__).resolve().parents[1] / "ui" / "index.html"


@router.get("/ui", include_in_schema=False)
async def console() -> HTMLResponse:
    if _INDEX.exists():
        return HTMLResponse(_INDEX.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Lono</h1><p>Console assets are missing from this build.</p>")