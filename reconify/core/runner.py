"""Orchestrates recon modules — supports full scan or per-module runs."""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Callable

from reconify.core import storage
from reconify.modules.base import BaseModule

# How often to emit a progress tick (every N findings within a module)
_PROGRESS_EVERY = 5


async def run_module(
    scan_id: int,
    module_name: str,
    config: dict,
    db_path: str,
    on_event: Callable[[dict], None] | None = None,
) -> int:
    """
    Run a single module against an existing scan. Persists results and updates
    ModuleRun status in the DB. Returns finding count.
    """
    def emit(event: dict):
        if on_event:
            on_event(event)

    # Look up target from scan record
    with storage.get_session(db_path) as s:
        scan = s.get(storage.Scan, scan_id)
        if not scan:
            emit({"type": "error", "module": module_name, "message": f"Scan {scan_id} not found"})
            return 0
        target = scan.target

    mod = _load_module(module_name, target, scan_id, config, db_path)
    if mod is None:
        storage.module_done(scan_id, module_name, 0, db_path, error="unknown module")
        emit({"type": "module_skip", "module": module_name, "reason": "unknown module"})
        return 0

    storage.module_start(scan_id, module_name, db_path)
    emit({"type": "module_start", "module": module_name, "scan_id": scan_id, "target": target})

    count = 0
    started = time.monotonic()
    error_msg = None

    try:
        async for result in mod.run():
            _persist(result, scan_id, db_path)
            emit(result)
            count += 1
            # Emit a progress tick every N findings so the UI counter updates smoothly
            if count % _PROGRESS_EVERY == 0:
                emit({
                    "type": "module_progress",
                    "module": module_name,
                    "count": count,
                    "elapsed": round(time.monotonic() - started, 1),
                })
    except Exception as exc:
        error_msg = str(exc)
        emit({"type": "module_error", "module": module_name, "error": error_msg})

    elapsed = round(time.monotonic() - started, 1)
    storage.module_done(scan_id, module_name, count, db_path, error=error_msg)
    emit({
        "type": "module_done",
        "module": module_name,
        "count": count,
        "elapsed": elapsed,
        "error": error_msg,
    })
    return count


async def run_scan(
    target: str,
    modules: list[str],
    config: dict,
    db_path: str,
    on_event: Callable[[dict], None] | None = None,
) -> dict:
    """
    Create a new scan and run all requested modules sequentially.
    Returns final scan data dict.
    """
    def emit(event: dict):
        if on_event:
            on_event(event)

    scan = storage.create_scan(target, modules, db_path)
    scan_id = scan.id
    storage.start_scan(scan_id, db_path)

    emit({"type": "scan_start", "scan_id": scan_id, "target": target, "modules": modules})

    try:
        for mod_name in modules:
            await run_module(scan_id, mod_name, config, db_path, on_event=on_event)

        # AI analysis after all modules
        if config.get("anthropic_api_key"):
            storage.module_start(scan_id, "ai", db_path)
            emit({"type": "module_start", "module": "ai", "scan_id": scan_id, "target": target})
            try:
                from reconify.ai.analyzer import analyze_scan
                report = await analyze_scan(scan_id, config, db_path)
                emit({"type": "ai_report", "module": "aggregate", "report": report})
                storage.module_done(scan_id, "ai", len(report), db_path)
                emit({"type": "module_done", "module": "ai", "count": len(report), "elapsed": 0})
            except Exception as exc:
                storage.module_done(scan_id, "ai", 0, db_path, error=str(exc))
                emit({"type": "module_error", "module": "ai", "error": str(exc)})

        storage.finish_scan(scan_id, db_path)
        emit({"type": "scan_done", "scan_id": scan_id})
    except Exception as exc:
        storage.finish_scan(scan_id, db_path, error=True)
        emit({"type": "scan_error", "scan_id": scan_id, "error": str(exc)})

    return storage.get_scan_data(scan_id, db_path)


async def run_scan_by_id(
    scan_id: int,
    config: dict,
    db_path: str,
    on_event: Callable[[dict], None] | None = None,
) -> dict:
    """
    Run all modules for an already-created scan record.
    Used by the web API: POST /api/scan creates the record, then POST /api/scan/{id}/run triggers this.
    """
    def emit(event: dict):
        if on_event:
            on_event(event)

    with storage.get_session(db_path) as s:
        scan = s.get(storage.Scan, scan_id)
        if not scan:
            return {}
        modules = [m for m in scan.modules.split(",") if m]
        target = scan.target

    storage.start_scan(scan_id, db_path)
    emit({"type": "scan_start", "scan_id": scan_id, "target": target, "modules": modules})

    try:
        for mod_name in modules:
            await run_module(scan_id, mod_name, config, db_path, on_event=on_event)

        if config.get("anthropic_api_key"):
            storage.module_start(scan_id, "ai", db_path)
            emit({"type": "module_start", "module": "ai", "scan_id": scan_id, "target": target})
            try:
                from reconify.ai.analyzer import analyze_scan
                report = await analyze_scan(scan_id, config, db_path)
                emit({"type": "ai_report", "module": "aggregate", "report": report})
                storage.module_done(scan_id, "ai", len(report), db_path)
                emit({"type": "module_done", "module": "ai", "count": len(report), "elapsed": 0})
            except Exception as exc:
                storage.module_done(scan_id, "ai", 0, db_path, error=str(exc))

        storage.finish_scan(scan_id, db_path)
        emit({"type": "scan_done", "scan_id": scan_id})
    except Exception as exc:
        storage.finish_scan(scan_id, db_path, error=True)
        emit({"type": "scan_error", "scan_id": scan_id, "error": str(exc)})

    return storage.get_scan_data(scan_id, db_path)


# ── Private helpers ───────────────────────────────────────────────────────────

def _load_module(
    name: str, target: str, scan_id: int, config: dict, db_path: str
) -> BaseModule | None:
    if name == "sub":
        from reconify.modules.subdomain import SubdomainModule
        return SubdomainModule(target, scan_id, config, db_path)
    if name == "js":
        from reconify.modules.js_recon import JsReconModule
        return JsReconModule(target, scan_id, config, db_path)
    if name == "ports":
        from reconify.modules.ports import PortModule
        return PortModule(target, scan_id, config, db_path)
    if name == "content":
        from reconify.modules.content import ContentModule
        return ContentModule(target, scan_id, config, db_path)
    return None


def _persist(result: dict, scan_id: int, db_path: str):
    rtype = result.get("type")
    with storage.get_session(db_path) as s:
        if rtype == "subdomain":
            s.add(storage.Subdomain(
                scan_id=scan_id,
                host=result["host"],
                source=result.get("source", ""),
                is_live=result.get("is_live", False),
                status_code=result.get("status_code"),
                ip=result.get("ip"),
            ))
        elif rtype == "js_finding":
            s.add(storage.JsFinding(
                scan_id=scan_id,
                js_url=result["js_url"],
                finding_type=result["finding_type"],
                value=result["value"],
                secret_type=result.get("secret_type"),
            ))
        elif rtype == "port":
            s.add(storage.Port(
                scan_id=scan_id,
                host=result["host"],
                port=result["port"],
                protocol=result.get("protocol", "tcp"),
                state=result.get("state", "open"),
                service=result.get("service"),
                version=result.get("version"),
            ))
        elif rtype == "url":
            s.add(storage.Url(
                scan_id=scan_id,
                url=result["url"],
                source=result.get("source", ""),
                status_code=result.get("status_code"),
            ))
        s.commit()
