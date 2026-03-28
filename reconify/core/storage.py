"""SQLite persistence via SQLModel."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, Session, SQLModel, create_engine, select


# ── Models ────────────────────────────────────────────────────────────────────

class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    target: str
    modules: str  # comma-separated
    status: str = "pending"  # pending | running | done | error
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None


class ModuleRun(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id")
    module: str            # sub | js | ports | content | ai
    status: str = "pending"  # pending | running | done | error | skipped
    count: int = 0
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class Subdomain(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id")
    host: str
    source: str
    is_live: bool = False
    status_code: Optional[int] = None
    ip: Optional[str] = None


class JsFinding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id")
    js_url: str
    finding_type: str  # endpoint | secret | source_map
    value: str
    secret_type: Optional[str] = None


class Port(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id")
    host: str
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    version: Optional[str] = None


class Url(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id")
    url: str
    source: str
    status_code: Optional[int] = None


class AiReport(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id")
    module: str
    report_json: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Parameter(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id")
    url: str
    param: str
    method: str = "GET"         # GET | POST
    source: str = ""            # wayback | js | crawl | bruteforce
    param_type: str = ""        # xss | ssrf | redirect | generic


class XssFinding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id")
    url: str
    param: str
    payload: str
    finding_type: str           # reflected | dom | blind | csti | header
    evidence: Optional[str] = None   # snippet of response proving reflection
    confirmed: bool = False
    tool: str = ""              # dalfox | manual | nuclei


class SsrfFinding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id")
    url: str
    param: str
    payload: str
    finding_type: str           # blind | metadata | open_redirect_chain | internal_port
    callback_id: Optional[str] = None  # interactsh interaction ID
    metadata_path: Optional[str] = None  # what cloud metadata was reached
    confirmed: bool = False


# ── Engine factory ────────────────────────────────────────────────────────────

_engines: dict[str, object] = {}


def get_engine(db_path: str = "~/.reconify/reconify.db"):
    import pathlib
    path = db_path.replace("~", str(pathlib.Path.home()))
    pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
    if path not in _engines:
        engine = create_engine(
            f"sqlite:///{path}",
            echo=False,
            connect_args={"check_same_thread": False},
        )
        SQLModel.metadata.create_all(engine)
        _engines[path] = engine
    return _engines[path]


def get_session(db_path: str = "~/.reconify/reconify.db") -> Session:
    return Session(get_engine(db_path), expire_on_commit=False)


# ── Scan helpers ──────────────────────────────────────────────────────────────

def create_scan(target: str, modules: list[str], db_path: str) -> Scan:
    with get_session(db_path) as s:
        scan = Scan(target=target, modules=",".join(modules), status="pending")
        s.add(scan)
        s.commit()
        s.refresh(scan)
        scan_id = scan.id
        # Pre-create ModuleRun rows so the UI can show them immediately
        for mod in modules:
            s.add(ModuleRun(scan_id=scan_id, module=mod))
        s.commit()
        s.expunge(scan)
        return scan


def start_scan(scan_id: int, db_path: str):
    with get_session(db_path) as s:
        scan = s.get(Scan, scan_id)
        if scan:
            scan.status = "running"
            s.add(scan)
            s.commit()


def finish_scan(scan_id: int, db_path: str, error: bool = False):
    with get_session(db_path) as s:
        scan = s.get(Scan, scan_id)
        if scan:
            scan.status = "error" if error else "done"
            scan.finished_at = datetime.now(timezone.utc)
            s.add(scan)
            s.commit()


def list_scans(db_path: str) -> list[Scan]:
    with get_session(db_path) as s:
        rows = s.exec(select(Scan).order_by(Scan.started_at.desc())).all()  # type: ignore[arg-type]
        for r in rows:
            s.expunge(r)
        return list(rows)


# ── ModuleRun helpers ─────────────────────────────────────────────────────────

def module_start(scan_id: int, module: str, db_path: str):
    with get_session(db_path) as s:
        row = s.exec(
            select(ModuleRun)
            .where(ModuleRun.scan_id == scan_id)
            .where(ModuleRun.module == module)
        ).first()
        if row:
            row.status = "running"
            row.started_at = datetime.now(timezone.utc)
            s.add(row)
        else:
            s.add(ModuleRun(scan_id=scan_id, module=module, status="running",
                            started_at=datetime.now(timezone.utc)))
        s.commit()


def module_done(scan_id: int, module: str, count: int, db_path: str, error: str | None = None):
    with get_session(db_path) as s:
        row = s.exec(
            select(ModuleRun)
            .where(ModuleRun.scan_id == scan_id)
            .where(ModuleRun.module == module)
        ).first()
        if row:
            row.status = "error" if error else "done"
            row.count = count
            row.error = error
            row.finished_at = datetime.now(timezone.utc)
            s.add(row)
            s.commit()


def get_module_runs(scan_id: int, db_path: str) -> list[ModuleRun]:
    with get_session(db_path) as s:
        rows = s.exec(select(ModuleRun).where(ModuleRun.scan_id == scan_id)).all()
        for r in rows:
            s.expunge(r)
        return list(rows)


# ── Data accessors ────────────────────────────────────────────────────────────

def get_scan_data(scan_id: int, db_path: str) -> dict:
    with get_session(db_path) as s:
        scan = s.get(Scan, scan_id)
        subdomains = list(s.exec(select(Subdomain).where(Subdomain.scan_id == scan_id)).all())
        js_findings = list(s.exec(select(JsFinding).where(JsFinding.scan_id == scan_id)).all())
        ports = list(s.exec(select(Port).where(Port.scan_id == scan_id)).all())
        urls = list(s.exec(select(Url).where(Url.scan_id == scan_id)).all())
        reports = list(s.exec(select(AiReport).where(AiReport.scan_id == scan_id)).all())
        module_runs = list(s.exec(select(ModuleRun).where(ModuleRun.scan_id == scan_id)).all())
        parameters = list(s.exec(select(Parameter).where(Parameter.scan_id == scan_id)).all())
        xss_findings = list(s.exec(select(XssFinding).where(XssFinding.scan_id == scan_id)).all())
        ssrf_findings = list(s.exec(select(SsrfFinding).where(SsrfFinding.scan_id == scan_id)).all())

        ai_reports = {r.module: json.loads(r.report_json) for r in reports}
        module_run_map = {r.module: r for r in module_runs}

        all_objs = subdomains + js_findings + ports + urls + reports + module_runs + parameters + xss_findings + ssrf_findings
        for obj in all_objs:
            s.expunge(obj)
        if scan:
            s.expunge(scan)

        return {
            "scan": scan,
            "subdomains": subdomains,
            "js_findings": js_findings,
            "ports": ports,
            "urls": urls,
            "parameters": parameters,
            "xss_findings": xss_findings,
            "ssrf_findings": ssrf_findings,
            "ai_reports": ai_reports,
            "module_runs": module_run_map,
        }


def get_module_data(scan_id: int, module: str, db_path: str) -> dict:
    with get_session(db_path) as s:
        run = s.exec(
            select(ModuleRun)
            .where(ModuleRun.scan_id == scan_id)
            .where(ModuleRun.module == module)
        ).first()

        items: list = []
        if module == "sub":
            items = list(s.exec(select(Subdomain).where(Subdomain.scan_id == scan_id)).all())
        elif module == "js":
            items = list(s.exec(select(JsFinding).where(JsFinding.scan_id == scan_id)).all())
        elif module == "ports":
            items = list(s.exec(select(Port).where(Port.scan_id == scan_id)).all())
        elif module == "content":
            items = list(s.exec(select(Url).where(Url.scan_id == scan_id)).all())
        elif module == "params":
            items = list(s.exec(select(Parameter).where(Parameter.scan_id == scan_id)).all())
        elif module == "xss":
            items = list(s.exec(select(XssFinding).where(XssFinding.scan_id == scan_id)).all())
        elif module == "ssrf":
            items = list(s.exec(select(SsrfFinding).where(SsrfFinding.scan_id == scan_id)).all())
        elif module == "ai":
            items = list(s.exec(select(AiReport).where(AiReport.scan_id == scan_id)).all())

        for obj in items:
            s.expunge(obj)
        if run:
            s.expunge(run)

        return {"run": run, "items": items}
