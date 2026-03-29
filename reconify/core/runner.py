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

# Dependency-ordered execution stages. Modules within a stage are independent
# and will run concurrently. Stages must complete before the next stage begins.
MODULE_STAGES: list[set[str]] = [
    {"sub"},
    {"js", "ports", "content"},
    {"params"},
    {"xss", "ssrf"},
]


async def run_module(
    scan_id: int,
    module_name: str,
    config: dict,
    db_path: str,
    on_event: Callable[[dict], None] | None = None,
    notifier=None,
) -> int:
    """
    Run a single module against an existing scan. Persists results and updates
    ModuleRun status in the DB. Returns finding count.
    """
    def emit(event: dict):
        if on_event:
            on_event(event)
        if notifier:
            asyncio.create_task(notifier.on_event(event))

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
    from reconify.notify.telegram import TelegramNotifier
    notifier = TelegramNotifier(config)

    def emit(event: dict):
        if on_event:
            on_event(event)
        asyncio.create_task(notifier.on_event(event))

    scan = storage.create_scan(target, modules, db_path)
    scan_id = scan.id
    storage.start_scan(scan_id, db_path)

    emit({"type": "scan_start", "scan_id": scan_id, "target": target, "modules": modules})

    try:
        await _run_stages(scan_id, target, modules, config, db_path, emit, notifier)

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
        # Send summary to Telegram
        data = storage.get_scan_data(scan_id, db_path)
        summary = {
            "Subdomains": len(data["subdomains"]),
            "Live": sum(1 for s in data["subdomains"] if s.is_live),
            "JS Findings": len(data["js_findings"]),
            "Params": len(data.get("parameters", [])),
            "XSS": len(data.get("xss_findings", [])),
            "SSRF": len(data.get("ssrf_findings", [])),
            "Ports": len(data["ports"]),
            "URLs": len(data["urls"]),
        }
        asyncio.create_task(notifier.bot.send_scan_done(scan_id, target, summary) if notifier.enabled else asyncio.sleep(0))
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
    from reconify.notify.telegram import TelegramNotifier
    notifier = TelegramNotifier(config)

    def emit(event: dict):
        if on_event:
            on_event(event)
        asyncio.create_task(notifier.on_event(event))

    with storage.get_session(db_path) as s:
        scan = s.get(storage.Scan, scan_id)
        if not scan:
            return {}
        modules = [m for m in scan.modules.split(",") if m]
        target = scan.target

    storage.start_scan(scan_id, db_path)
    emit({"type": "scan_start", "scan_id": scan_id, "target": target, "modules": modules})

    try:
        await _run_stages(scan_id, target, modules, config, db_path, emit, notifier)

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


async def _run_stages(
    scan_id: int,
    target: str,
    modules: list[str],
    config: dict,
    db_path: str,
    emit: Callable[[dict], None],
    notifier,
) -> None:
    """
    Run requested modules in parallel within each dependency stage.
    Stages execute sequentially; modules within a stage run concurrently.
    One module failing does not prevent sibling modules from completing.
    """
    requested = set(modules)
    scheduled: set[str] = set()

    for stage in MODULE_STAGES:
        stage_modules = sorted(stage & requested)
        if not stage_modules:
            continue
        scheduled.update(stage_modules)

        results = await asyncio.gather(
            *[run_module(scan_id, m, config, db_path, on_event=emit, notifier=notifier)
              for m in stage_modules],
            return_exceptions=True,
        )
        for mod_name, result in zip(stage_modules, results):
            if isinstance(result, BaseException):
                emit({"type": "module_error", "module": mod_name,
                      "error": f"Unhandled exception: {result}"})

    # Future-proof: run any modules not covered by MODULE_STAGES sequentially
    for m in sorted(requested - scheduled):
        await run_module(scan_id, m, config, db_path, on_event=emit, notifier=notifier)


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
    if name == "params":
        from reconify.modules.params import ParamModule
        return ParamModule(target, scan_id, config, db_path)
    if name == "xss":
        from reconify.modules.xss import XssModule
        return XssModule(target, scan_id, config, db_path)
    if name == "ssrf":
        from reconify.modules.ssrf import SsrfModule
        return SsrfModule(target, scan_id, config, db_path)
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
        elif rtype == "parameter":
            s.add(storage.Parameter(
                scan_id=scan_id,
                url=result["url"],
                param=result["param"],
                method=result.get("method", "GET"),
                source=result.get("source", ""),
                param_type=result.get("param_type", "generic"),
            ))
        elif rtype == "xss_finding":
            s.add(storage.XssFinding(
                scan_id=scan_id,
                url=result["url"],
                param=result.get("param", ""),
                payload=result.get("payload", ""),
                finding_type=result["finding_type"],
                evidence=result.get("evidence"),
                confirmed=result.get("confirmed", False),
                tool=result.get("tool", ""),
            ))
        elif rtype == "ssrf_finding":
            s.add(storage.SsrfFinding(
                scan_id=scan_id,
                url=result["url"],
                param=result.get("param", ""),
                payload=result.get("payload", ""),
                finding_type=result["finding_type"],
                callback_id=result.get("callback_id"),
                metadata_path=result.get("metadata_path"),
                confirmed=result.get("confirmed", False),
            ))
        s.commit()
