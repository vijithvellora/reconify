"""Reconify CLI — built with Typer."""
from __future__ import annotations

import asyncio
import json
from typing import Optional

import typer
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from reconify.core.config import load_config, ensure_output_dir
from reconify.core.storage import get_scan_data, list_scans

app = typer.Typer(
    name="reconify",
    help="Bug bounty recon tool with AI-powered analysis.",
    add_completion=False,
)
console = Console()

VALID_MODULES = ["sub", "js", "ports", "content"]


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target domain (e.g. example.com)"),
    modules: str = typer.Option(
        "sub,js,ports,content",
        "--modules", "-m",
        help="Comma-separated modules to run: sub,js,ports,content",
    ),
    threads: int = typer.Option(20, "--threads", "-t", help="Concurrent request threads"),
    output: str = typer.Option("table", "--output", "-o", help="Output format: table|json"),
    config_path: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI analysis"),
):
    """Run recon against a target domain."""
    cfg = load_config(config_path)
    cfg["threads"] = threads

    mod_list = [m.strip() for m in modules.split(",") if m.strip() in VALID_MODULES]
    if not mod_list:
        rprint("[red]No valid modules specified. Choose from: sub, js, ports, content[/red]")
        raise typer.Exit(1)

    if no_ai:
        cfg["anthropic_api_key"] = ""

    ensure_output_dir(cfg)
    db_path = str(__import__("pathlib").Path(cfg["output_dir"]).parent / "reconify.db")

    console.print(Panel(
        f"[bold cyan]Target:[/bold cyan] {target}\n"
        f"[bold cyan]Modules:[/bold cyan] {', '.join(mod_list)}\n"
        f"[bold cyan]Threads:[/bold cyan] {threads}\n"
        f"[bold cyan]AI:[/bold cyan] {'enabled' if cfg.get('anthropic_api_key') else 'disabled (set ANTHROPIC_API_KEY)'}",
        title="[bold green]Reconify[/bold green]",
    ))

    events: list[dict] = []

    def on_event(event: dict):
        events.append(event)
        _print_event(event)

    from reconify.core.runner import run_scan
    data = asyncio.run(run_scan(target, mod_list, cfg, db_path, on_event=on_event))

    if output == "json":
        rprint(json.dumps(_serialize_data(data), indent=2))
    else:
        _print_summary_tables(data)


@app.command()
def web(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address"),
    port: int = typer.Option(8000, "--port", "-p", help="Port"),
    config_path: Optional[str] = typer.Option(None, "--config", "-c"),
):
    """Launch the web dashboard."""
    import uvicorn
    cfg = load_config(config_path)
    db_path = str(__import__("pathlib").Path(cfg["output_dir"]).parent / "reconify.db")

    # Pass config to web app via env
    import os
    os.environ["RECONIFY_DB_PATH"] = db_path
    os.environ["RECONIFY_CONFIG"] = json.dumps(cfg)

    console.print(f"[green]Starting web UI at http://{host}:{port}[/green]")
    uvicorn.run("reconify.web.app:app", host=host, port=port, reload=False)


@app.command()
def report(
    scan_id: int = typer.Argument(..., help="Scan ID to show report for"),
    config_path: Optional[str] = typer.Option(None, "--config", "-c"),
):
    """Show AI report for a past scan."""
    cfg = load_config(config_path)
    db_path = str(__import__("pathlib").Path(cfg["output_dir"]).parent / "reconify.db")
    data = get_scan_data(scan_id, db_path)

    if not data["scan"]:
        rprint(f"[red]Scan {scan_id} not found[/red]")
        raise typer.Exit(1)

    console.print(Panel(
        f"[bold]Target:[/bold] {data['scan'].target}\n"
        f"[bold]Status:[/bold] {data['scan'].status}\n"
        f"[bold]Started:[/bold] {data['scan'].started_at}",
        title=f"Scan #{scan_id}",
    ))

    reports = data.get("ai_reports", {})
    if not reports:
        rprint("[yellow]No AI reports found for this scan.[/yellow]")
        return

    for module, rep in reports.items():
        rprint(f"\n[bold cyan]=== {module.upper()} ===[/bold cyan]")
        rprint(json.dumps(rep, indent=2))


@app.command("list")
def list_cmd(config_path: Optional[str] = typer.Option(None, "--config", "-c")):
    """List all past scans."""
    cfg = load_config(config_path)
    db_path = str(__import__("pathlib").Path(cfg["output_dir"]).parent / "reconify.db")
    scans = list_scans(db_path)

    if not scans:
        rprint("[yellow]No scans found.[/yellow]")
        return

    table = Table(title="Past Scans")
    table.add_column("ID", style="cyan")
    table.add_column("Target", style="green")
    table.add_column("Modules")
    table.add_column("Status")
    table.add_column("Started")

    for s in scans:
        status_color = {"done": "green", "running": "yellow", "error": "red"}.get(s.status, "white")
        table.add_row(
            str(s.id),
            s.target,
            s.modules,
            f"[{status_color}]{s.status}[/{status_color}]",
            str(s.started_at)[:19],
        )
    console.print(table)


# ── Event printer ──────────────────────────────────────────────────────────────

def _print_event(event: dict):
    t = event.get("type", "")
    if t == "module_start":
        console.print(f"\n[bold yellow]▶ Starting module: {event['module']}[/bold yellow]")
    elif t == "module_done":
        console.print(f"[green]✓ {event['module']}: {event['count']} findings[/green]")
    elif t == "module_skip":
        console.print(f"[dim]⊘ Skipping {event['module']}: {event['reason']}[/dim]")
    elif t == "subdomain":
        live = " [green][LIVE][/green]" if event.get("is_live") else ""
        sc = f" ({event['status_code']})" if event.get("status_code") else ""
        console.print(f"  [cyan]SUB[/cyan] {event['host']}{sc}{live}")
    elif t == "js_finding":
        ft = event.get("finding_type", "")
        if ft == "secret":
            console.print(f"  [red]SECRET[/red] [{event.get('secret_type')}] {event['value'][:80]}")
        elif ft == "endpoint":
            console.print(f"  [blue]ENDPOINT[/blue] {event['value'][:100]}")
        elif ft == "source_map":
            console.print(f"  [magenta]SOURCEMAP[/magenta] {event['value'][:100]}")
    elif t == "port":
        svc = f" ({event.get('service', '')} {event.get('version', '')})".rstrip()
        console.print(f"  [yellow]PORT[/yellow] {event['host']}:{event['port']}/{event.get('protocol','tcp')}{svc}")
    elif t == "url":
        console.print(f"  [dim]URL[/dim] {event['url'][:120]}")
    elif t == "ai_report":
        console.print(f"\n[bold magenta]AI Report ready: {event['module']}[/bold magenta]")
    elif t == "scan_error":
        console.print(f"[red]Error: {event.get('error')}[/red]")
    elif t == "warning":
        console.print(f"[yellow]⚠ {event.get('message')}[/yellow]")


def _print_summary_tables(data: dict):
    scan = data["scan"]
    console.print(f"\n[bold green]Scan complete — {scan.target} (ID: {scan.id})[/bold green]")

    counts = {
        "Subdomains": len(data["subdomains"]),
        "Live subdomains": sum(1 for s in data["subdomains"] if s.is_live),
        "JS findings": len(data["js_findings"]),
        "Secrets found": sum(1 for j in data["js_findings"] if j.finding_type == "secret"),
        "Open ports": len(data["ports"]),
        "URLs discovered": len(data["urls"]),
    }

    table = Table(title="Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="bold")
    for k, v in counts.items():
        table.add_row(k, str(v))
    console.print(table)

    if data.get("ai_reports", {}).get("aggregate"):
        agg = data["ai_reports"]["aggregate"]
        console.print(Panel(
            agg.get("executive_summary", "No summary."),
            title="[bold magenta]AI Executive Summary[/bold magenta]",
        ))
        for vec in agg.get("top_attack_vectors", [])[:5]:
            pri = vec.get("priority", "?")
            color = {"critical": "red", "high": "yellow", "medium": "blue"}.get(pri, "white")
            console.print(f"  [{color}][{pri.upper()}][/{color}] {vec.get('title')}: {vec.get('description', '')[:120]}")


def _serialize_data(data: dict) -> dict:
    out = {}
    for k, v in data.items():
        if isinstance(v, list):
            out[k] = [_item_to_dict(i) for i in v]
        elif hasattr(v, "model_dump"):
            out[k] = v.model_dump(mode="json")
        else:
            out[k] = v
    return out


def _item_to_dict(item) -> dict:
    if hasattr(item, "model_dump"):
        return item.model_dump(mode="json")
    return vars(item)


if __name__ == "__main__":
    app()
