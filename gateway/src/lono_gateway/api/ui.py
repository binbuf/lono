"""Local web console (prebuilt single-page app served under /ui)."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()

_UI_DIR = Path(__file__).resolve().parents[1] / "ui"
_DIST = _UI_DIR / "dist"
_INDEX = _DIST / "index.html"

_FALLBACK = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Lono Console</title>
<style>body{font:14px system-ui,sans-serif;background:#0b0e13;color:#d8e0ea;padding:40px}
code{background:#1e2733;padding:2px 6px;border-radius:4px}</style></head>
<body><h1>Lono</h1>
<p>The console assets are not built in this checkout.</p>
<p>Run <code>cd gateway/ui &amp;&amp; npm install &amp;&amp; npm run build</code>, then reload.</p>
</body></html>"""


def dist_dir() -> Path | None:
    """Directory holding the built SPA assets, if the build is present."""
    return _DIST if (_DIST / "assets").is_dir() else None


@router.get("/ui", include_in_schema=False)
async def console() -> HTMLResponse:
    if _INDEX.exists():
        return HTMLResponse(_INDEX.read_text(encoding="utf-8"))
    return HTMLResponse(_FALLBACK)


@router.get("/ui/{path:path}", include_in_schema=False)
async def console_spa(path: str) -> HTMLResponse:
    """Serve index.html for any client-side route (the SPA does not use them,
    but this keeps deep links and refreshes working)."""
    if _INDEX.exists():
        return HTMLResponse(_INDEX.read_text(encoding="utf-8"))
    return HTMLResponse(_FALLBACK)