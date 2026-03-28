"""FastAPI web dashboard with per-module APIs and SSE live updates."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI(title="Reconify Dashboard", version="0.2.0")

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# SSE event queues — one per scan_id
_sse_queues: dict[int, asyncio.Queue] = {}


def _cfg() -> dict:
    return json.loads(os.getenv("RECONIFY_CONFIG", "{}"))


def _db() -> str:
    return os.getenv("RECONIFY_DB_PATH", str(Path.home() / ".reconify" / "reconify.db"))


# ── HTML Pages ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    from reconify.core.storage import list_scans
    scans = list_scans(_db())
    return templates.TemplateResponse("index.html", {"request": request, "scans": scans})


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_view(request: Request, scan_id: int):
    from reconify.core.storage import get_scan_data
    data = get_scan_data(scan_id, _db())
    if data["scan"] is None:
        return HTMLResponse(
            f'<html><body style="background:#0a0a0a;color:#ccc;font-family:monospace;padding:2rem">'
            f'<h2>Scan #{scan_id} not found</h2><a href="/" style="color:#22d3ee">← Back to dashboard</a>'
            f'</body></html>',
            status_code=404,
        )
    return templates.TemplateResponse("scan.html", {
        "request": request,
        "scan": data["scan"],
        "subdomains": data["subdomains"],
        "js_findings": data["js_findings"],
        "ports": data["ports"],
        "urls": data["urls"][:500],
        "ai_reports": data["ai_reports"],
        "module_runs": data.get("module_runs", {}),
    })


# ── Scan CRUD ──────────────────────────────────────────────────────────────────

@app.get("/api/scans")
async def api_list_scans():
    from reconify.core.storage import list_scans
    return [_m(s) for s in list_scans(_db())]


@app.post("/api/scan", status_code=201)
async def api_create_scan(request: Request):
    """
    Create a scan record immediately and return the scan_id.
    Does NOT start running — call POST /api/scan/{id}/run to start.
    """
    body = await request.json()
    target = body.get("target", "").strip()
    modules = body.get("modules", ["sub", "js", "ports", "content"])
    if not target:
        return JSONResponse({"error": "target is required"}, status_code=400)
    if not isinstance(modules, list) or not modules:
        return JSONResponse({"error": "modules must be a non-empty list"}, status_code=400)

    from reconify.core.storage import create_scan
    scan = create_scan(target, modules, _db())
    return {"scan_id": scan.id, "target": scan.target, "modules": modules, "status": scan.status}


@app.post("/api/scan/{scan_id}/run")
async def api_run_scan(scan_id: int, background_tasks: BackgroundTasks):
    """Start running all modules for an existing scan (non-blocking)."""
    from reconify.core.storage import get_session
    from sqlmodel import select
    from reconify.core.storage import Scan

    with get_session(_db()) as s:
        scan = s.get(Scan, scan_id)
    if not scan:
        return JSONResponse({"error": "scan not found"}, status_code=404)
    if scan.status in ("running", "done"):
        return JSONResponse({"error": f"scan is already {scan.status}"}, status_code=409)

    queue: asyncio.Queue = asyncio.Queue()
    _sse_queues[scan_id] = queue

    async def _do():
        from reconify.core.runner import run_scan_by_id

        def on_event(ev: dict):
            asyncio.create_task(queue.put(ev))
            if ev.get("type") in ("scan_done", "scan_error"):
                asyncio.create_task(queue.put(None))  # sentinel

        await run_scan_by_id(scan_id, _cfg(), _db(), on_event=on_event)

    background_tasks.add_task(_do)
    return {"scan_id": scan_id, "status": "started"}


@app.post("/api/scan/{scan_id}/module/{module}")
async def api_run_module(scan_id: int, module: str, background_tasks: BackgroundTasks):
    """Run a single module against an existing scan (non-blocking)."""
    valid = {"sub", "js", "ports", "content"}
    if module not in valid:
        return JSONResponse({"error": f"unknown module '{module}', choose from {valid}"}, status_code=400)

    from reconify.core.storage import get_session, Scan
    with get_session(_db()) as s:
        scan = s.get(Scan, scan_id)
    if not scan:
        return JSONResponse({"error": "scan not found"}, status_code=404)

    # Ensure there's a queue for this scan
    if scan_id not in _sse_queues:
        _sse_queues[scan_id] = asyncio.Queue()
    queue = _sse_queues[scan_id]

    async def _do():
        from reconify.core.runner import run_module

        def on_event(ev: dict):
            asyncio.create_task(queue.put(ev))

        await run_module(scan_id, module, _cfg(), _db(), on_event=on_event)
        # Emit a partial-done so the UI knows this module finished
        asyncio.create_task(queue.put({"type": "module_saved", "module": module, "scan_id": scan_id}))

    background_tasks.add_task(_do)
    return {"scan_id": scan_id, "module": module, "status": "started"}


@app.delete("/api/scan/{scan_id}")
async def api_delete_scan(scan_id: int):
    from reconify.core.storage import get_session, Scan, Subdomain, JsFinding, Port, Url, AiReport, ModuleRun
    from sqlmodel import select, delete
    with get_session(_db()) as s:
        scan = s.get(Scan, scan_id)
        if not scan:
            return JSONResponse({"error": "not found"}, status_code=404)
        for model in (Subdomain, JsFinding, Port, Url, AiReport, ModuleRun):
            rows = s.exec(select(model).where(model.scan_id == scan_id)).all()  # type: ignore[attr-defined]
            for r in rows:
                s.delete(r)
        s.delete(scan)
        s.commit()
    _sse_queues.pop(scan_id, None)
    return {"deleted": scan_id}


# ── Module-level data endpoints ────────────────────────────────────────────────

@app.get("/api/scan/{scan_id}/modules")
async def api_module_status(scan_id: int):
    """Return the status of every module for a scan."""
    from reconify.core.storage import get_module_runs
    runs = get_module_runs(scan_id, _db())
    return [_m(r) for r in runs]


@app.get("/api/scan/{scan_id}/module/{module}")
async def api_module_data(scan_id: int, module: str):
    """Return the saved findings for a specific module."""
    from reconify.core.storage import get_module_data
    data = get_module_data(scan_id, module, _db())
    return {
        "run": _m(data["run"]) if data["run"] else None,
        "items": [_m(i) for i in data["items"]],
        "count": len(data["items"]),
    }


@app.get("/api/scan/{scan_id}/module/{module}/stream")
async def api_module_stream(scan_id: int, module: str):
    """
    SSE stream scoped to a single module.
    Subscribes to the scan's queue and filters to this module's events.
    """
    queue = _sse_queues.get(scan_id)

    async def gen() -> AsyncIterator[str]:
        if queue is None:
            yield _sse({"type": "error", "message": "no active stream for this scan"})
            return
        while True:
            ev = await queue.get()
            if ev is None:
                yield _sse({"type": "done"})
                break
            if ev.get("module") == module or ev.get("type") in ("scan_done", "scan_error"):
                yield _sse(ev)
                if ev.get("type") in ("module_done", "scan_done", "scan_error") and ev.get("module") == module:
                    break

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── Full scan stream / data ────────────────────────────────────────────────────

@app.get("/api/scan/{scan_id}/events")
async def api_scan_events(scan_id: int):
    """SSE stream for the full scan — all modules."""
    queue = _sse_queues.get(scan_id)

    async def gen() -> AsyncIterator[str]:
        if queue is None:
            yield _sse({"type": "error", "message": "no active stream for this scan"})
            return
        while True:
            ev = await queue.get()
            if ev is None:
                yield _sse({"type": "done"})
                break
            yield _sse(ev)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/scan/{scan_id}/data")
async def api_scan_data(scan_id: int):
    from reconify.core.storage import get_scan_data
    data = get_scan_data(scan_id, _db())
    return {
        "scan": _m(data["scan"]),
        "module_runs": {k: _m(v) for k, v in data.get("module_runs", {}).items()},
        "subdomains": [_m(s) for s in data["subdomains"]],
        "js_findings": [_m(j) for j in data["js_findings"]],
        "ports": [_m(p) for p in data["ports"]],
        "urls": [_m(u) for u in data["urls"][:500]],
        "ai_reports": data["ai_reports"],
    }


@app.get("/api/scan/{scan_id}/export")
async def api_export(scan_id: int):
    from reconify.core.storage import get_scan_data
    data = get_scan_data(scan_id, _db())
    out = {
        "scan": _m(data["scan"]),
        "subdomains": [_m(s) for s in data["subdomains"]],
        "js_findings": [_m(j) for j in data["js_findings"]],
        "ports": [_m(p) for p in data["ports"]],
        "urls": [_m(u) for u in data["urls"]],
        "ai_reports": data["ai_reports"],
    }
    return JSONResponse(out, headers={
        "Content-Disposition": f"attachment; filename=reconify_scan_{scan_id}.json"
    })


# ── Helpers ────────────────────────────────────────────────────────────────────

def _m(obj) -> dict:
    if obj is None:
        return {}
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    return vars(obj)


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"
