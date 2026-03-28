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

VALID_MODULES = ["sub", "js", "ports", "content", "params", "xss", "ssrf"]


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target domain (e.g. example.com)"),
    modules: str = typer.Option(
        "sub,js,ports,content,params,xss,ssrf",
        "--modules", "-m",
        help="Comma-separated modules: sub,js,ports,content,params,xss,ssrf",
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
    elif t == "parameter":
        ptype = event.get("param_type", "")
        color = {"xss": "yellow", "ssrf": "red", "redirect": "magenta"}.get(ptype, "dim")
        console.print(f"  [{color}]PARAM[/{color}] [{ptype}] {event['param']} @ {event['url'][:80]}")
    elif t == "xss_finding":
        confirmed = "[bold red]✓ CONFIRMED[/bold red]" if event.get("confirmed") else "[yellow]potential[/yellow]"
        ftype = event.get("finding_type", "")
        console.print(f"  [bold red]XSS[/bold red] {confirmed} [{ftype}] param={event.get('param','')} — {event.get('evidence','')[:80]}")
    elif t == "ssrf_finding":
        confirmed = "[bold red]✓ CONFIRMED[/bold red]" if event.get("confirmed") else "[yellow]potential[/yellow]"
        ftype = event.get("finding_type", "")
        meta = event.get("metadata_path") or event.get("callback_id") or ""
        console.print(f"  [bold magenta]SSRF[/bold magenta] {confirmed} [{ftype}] param={event.get('param','')} — {meta[:80]}")
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
        "Parameters": len(data.get("parameters", [])),
        "XSS findings": len(data.get("xss_findings", [])),
        "XSS confirmed": sum(1 for x in data.get("xss_findings", []) if x.confirmed),
        "SSRF findings": len(data.get("ssrf_findings", [])),
        "SSRF confirmed": sum(1 for x in data.get("ssrf_findings", []) if x.confirmed),
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


@app.command()
def tgbot(
    config_path: Optional[str] = typer.Option(None, "--config", "-c"),
):
    """
    Run the Telegram bot listener — accept /scan, /status, /list commands via Telegram.

    Setup:
      1. Create a bot via @BotFather, get your token
      2. Add to config.yaml:  telegram_token: "..." and telegram_chat_id: "..."
      3. Run: reconify tgbot
    """
    cfg = load_config(config_path)
    db_path = str(__import__("pathlib").Path(cfg["output_dir"]).parent / "reconify.db")

    token = cfg.get("telegram_token") or __import__("os").getenv("TELEGRAM_TOKEN", "")
    chat_id = cfg.get("telegram_chat_id") or __import__("os").getenv("TELEGRAM_CHAT_ID", "")

    if not token or not chat_id:
        rprint("[red]Error: telegram_token and telegram_chat_id must be configured.[/red]")
        rprint("Set them in ~/.reconify/config.yaml or as env vars TELEGRAM_TOKEN / TELEGRAM_CHAT_ID")
        raise typer.Exit(1)

    from reconify.notify.telegram import TelegramBot
    bot = TelegramBot(token, chat_id)

    console.print(Panel(
        "[bold cyan]Telegram bot started[/bold cyan]\n"
        "Commands:\n"
        "  /scan <target> [modules]  — start a scan\n"
        "  /list                     — list recent scans\n"
        "  /status <scan_id>         — check scan status\n"
        "  /report <scan_id>         — get AI report\n"
        "  /stop                     — stop the bot",
        title="Reconify Telegram Bot",
    ))

    async def on_command(cmd: str, args: list[str]):
        if cmd == "scan":
            if not args:
                await bot.send("Usage: /scan <target> [modules]\nExample: /scan example.com sub,js,xss,ssrf")
                return
            target = args[0]
            mod_list = args[1].split(",") if len(args) > 1 else ["sub", "js", "params", "xss", "ssrf"]
            mod_list = [m for m in mod_list if m in VALID_MODULES]

            await bot.send(f"🚀 Starting scan: <code>{target}</code>\nModules: {', '.join(mod_list)}")

            from reconify.core.runner import run_scan

            def on_event(ev: dict):
                __import__("asyncio").create_task(bot.send_finding(ev) if bot else __import__("asyncio").sleep(0))

            asyncio.create_task(_run_and_notify(target, mod_list, cfg, db_path, bot))

        elif cmd == "list":
            scans = list_scans(db_path)[:5]
            if not scans:
                await bot.send("No scans yet.")
                return
            lines = ["<b>Recent scans:</b>"]
            for s in scans:
                lines.append(f"#{s.id} <code>{s.target}</code> [{s.status}] {str(s.started_at)[:16]}")
            await bot.send("\n".join(lines))

        elif cmd == "status":
            if not args:
                await bot.send("Usage: /status <scan_id>")
                return
            try:
                scan_id = int(args[0])
                data = get_scan_data(scan_id, db_path)
                s = data["scan"]
                if not s:
                    await bot.send(f"Scan #{scan_id} not found.")
                    return
                runs = data.get("module_runs", {})
                lines = [f"<b>Scan #{scan_id}</b> — {s.target} [{s.status}]", ""]
                for mod, run in runs.items():
                    lines.append(f"  {mod}: {run.status} ({run.count} findings)")
                await bot.send("\n".join(lines))
            except Exception as e:
                await bot.send(f"Error: {e}")

        elif cmd == "report":
            if not args:
                await bot.send("Usage: /report <scan_id>")
                return
            try:
                scan_id = int(args[0])
                data = get_scan_data(scan_id, db_path)
                agg = data.get("ai_reports", {}).get("aggregate", {})
                if not agg:
                    await bot.send("No AI report for this scan. Run with ANTHROPIC_API_KEY set.")
                    return
                summary = agg.get("executive_summary", "No summary.")
                vecs = agg.get("top_attack_vectors", [])[:3]
                lines = [f"<b>AI Report — Scan #{scan_id}</b>", "", summary, ""]
                for v in vecs:
                    lines.append(f"[{v.get('priority','?').upper()}] {v.get('title','')}: {v.get('description','')[:100]}")
                await bot.send("\n".join(lines))
            except Exception as e:
                await bot.send(f"Error: {e}")

        elif cmd == "stop":
            await bot.send("👋 Bot stopped.")
            raise SystemExit(0)

    asyncio.run(bot.poll(on_command))


async def _run_and_notify(target: str, modules: list[str], cfg: dict, db_path: str, bot):
    from reconify.core.runner import run_scan

    def on_event(ev: dict):
        t = ev.get("type", "")
        if t in ("xss_finding", "ssrf_finding") and ev.get("confirmed"):
            __import__("asyncio").create_task(bot.send_finding(ev))

    data = await run_scan(target, modules, cfg, db_path, on_event=on_event)
    scan = data["scan"]
    summary = {
        "Subdomains": len(data["subdomains"]),
        "Parameters": len(data.get("parameters", [])),
        "XSS": len(data.get("xss_findings", [])),
        "XSS confirmed": sum(1 for x in data.get("xss_findings", []) if x.confirmed),
        "SSRF": len(data.get("ssrf_findings", [])),
        "SSRF confirmed": sum(1 for x in data.get("ssrf_findings", []) if x.confirmed),
    }
    await bot.send_scan_done(scan.id, target, summary)


if __name__ == "__main__":
    app()
