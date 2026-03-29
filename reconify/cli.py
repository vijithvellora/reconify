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
    interactsh_url: Optional[str] = typer.Option(
        None,
        "--interactsh-url",
        help="Interactsh callback URL for blind SSRF detection (e.g. abc123.oast.pro)",
    ),
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

    if interactsh_url:
        cfg["interactsh_url"] = interactsh_url

    ensure_output_dir(cfg)
    db_path = str(__import__("pathlib").Path(cfg["output_dir"]).parent / "reconify.db")

    console.print(Panel(
        f"[bold cyan]Target:[/bold cyan] {target}\n"
        f"[bold cyan]Modules:[/bold cyan] {', '.join(mod_list)}\n"
        f"[bold cyan]Threads:[/bold cyan] {threads}\n"
        f"[bold cyan]AI:[/bold cyan] {'enabled' if cfg.get('anthropic_api_key') else 'disabled (set ANTHROPIC_API_KEY)'}\n"
        f"[bold cyan]Interactsh:[/bold cyan] {cfg.get('interactsh_url') or 'not configured (blind SSRF disabled)'}",
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

    _HELP = (
        "🤖 <b>Reconify Bot Commands</b>\n\n"
        "<b>Scanning</b>\n"
        "/scan &lt;target&gt; [modules] — start a full scan\n"
        "/quickscan &lt;target&gt; — fast scan (sub+js only)\n"
        "/module &lt;id&gt; &lt;module&gt; — re-run one module on existing scan\n\n"
        "<b>Results</b>\n"
        "/list — recent scans\n"
        "/status &lt;id&gt; — per-module progress\n"
        "/findings &lt;id&gt; — top findings summary\n"
        "/subdomains &lt;id&gt; — list live subdomains\n"
        "/ports &lt;id&gt; — open ports\n"
        "/secrets &lt;id&gt; — JS secrets found\n"
        "/xss &lt;id&gt; — XSS findings\n"
        "/ssrf &lt;id&gt; — SSRF findings\n"
        "/report &lt;id&gt; — full AI report\n\n"
        "<b>Management</b>\n"
        "/delete &lt;id&gt; — delete a scan\n"
        "/modules — list available modules\n"
        "/stop — stop the bot\n"
        "/help — show this message"
    )

    console.print(Panel(
        "[bold cyan]Telegram bot started[/bold cyan]\n"
        "Send /help to your bot for the full command list.",
        title="Reconify Telegram Bot",
    ))

    async def on_command(cmd: str, args: list[str]):
        try:
            await _dispatch(cmd, args, bot, cfg, db_path)
        except Exception as e:
            await bot.send(f"❌ Error: {e}")

    async def _dispatch(cmd: str, args: list[str], bot, cfg, db_path):
        if cmd in ("help", "start"):
            await bot.send(_HELP)

        elif cmd == "modules":
            mods = "\n".join(f"  <code>{m}</code>" for m in VALID_MODULES)
            await bot.send(f"<b>Available modules:</b>\n{mods}")

        elif cmd == "scan":
            if not args:
                await bot.send("Usage: /scan &lt;target&gt; [mod1,mod2]\nExample: /scan example.com sub,js,xss,ssrf")
                return
            target = args[0]
            mod_list = args[1].split(",") if len(args) > 1 else list(VALID_MODULES)
            mod_list = [m for m in mod_list if m in VALID_MODULES]
            await bot.send(f"🚀 Starting scan: <code>{target}</code>\nModules: <code>{', '.join(mod_list)}</code>")
            asyncio.create_task(_run_and_notify(target, mod_list, cfg, db_path, bot))

        elif cmd == "quickscan":
            if not args:
                await bot.send("Usage: /quickscan &lt;target&gt;")
                return
            target = args[0]
            mod_list = ["sub", "js"]
            await bot.send(f"⚡ Quick scan: <code>{target}</code> (sub + js)")
            asyncio.create_task(_run_and_notify(target, mod_list, cfg, db_path, bot))

        elif cmd == "module":
            if len(args) < 2:
                await bot.send("Usage: /module &lt;scan_id&gt; &lt;module&gt;")
                return
            scan_id, module = int(args[0]), args[1]
            if module not in VALID_MODULES:
                await bot.send(f"Unknown module. Choose from: {', '.join(VALID_MODULES)}")
                return
            from reconify.core.runner import run_module
            await bot.send(f"▶️ Running <code>{module}</code> on scan #{scan_id}…")
            asyncio.create_task(_run_module_and_notify(scan_id, module, cfg, db_path, bot))

        elif cmd == "list":
            scans = list_scans(db_path)[:8]
            if not scans:
                await bot.send("No scans yet. Use /scan &lt;target&gt; to start one.")
                return
            status_icon = {"done": "✅", "running": "🔄", "error": "❌", "pending": "⏳"}
            lines = ["<b>Recent scans:</b>"]
            for s in scans:
                icon = status_icon.get(s.status, "•")
                lines.append(f"{icon} <b>#{s.id}</b> <code>{s.target}</code> — {s.status} ({str(s.started_at)[:16]})")
            await bot.send("\n".join(lines))

        elif cmd == "status":
            if not args:
                await bot.send("Usage: /status &lt;scan_id&gt;")
                return
            scan_id = int(args[0])
            data = get_scan_data(scan_id, db_path)
            s = data["scan"]
            if not s:
                await bot.send(f"Scan #{scan_id} not found.")
                return
            runs = data.get("module_runs", {})
            status_icon = {"done": "✅", "running": "🔄", "error": "❌", "pending": "⏳", "skipped": "⏭️"}
            lines = [f"<b>Scan #{scan_id}</b> — <code>{s.target}</code> [{s.status}]", ""]
            for mod, run in runs.items():
                icon = status_icon.get(run.status, "•")
                elapsed = f" {run.elapsed_seconds:.0f}s" if run.elapsed_seconds else ""
                lines.append(f"  {icon} {mod}: {run.count} findings{elapsed}")
            await bot.send("\n".join(lines))

        elif cmd == "findings":
            if not args:
                await bot.send("Usage: /findings &lt;scan_id&gt;")
                return
            scan_id = int(args[0])
            data = get_scan_data(scan_id, db_path)
            s = data["scan"]
            if not s:
                await bot.send(f"Scan #{scan_id} not found.")
                return
            xss_c = sum(1 for x in data.get("xss_findings", []) if x.confirmed)
            ssrf_c = sum(1 for x in data.get("ssrf_findings", []) if x.confirmed)
            secrets = [j for j in data.get("js_findings", []) if j.finding_type == "secret"]
            live = [d for d in data.get("subdomains", []) if d.is_live]
            lines = [
                f"<b>Findings — Scan #{scan_id}</b> (<code>{s.target}</code>)",
                "",
                f"🌐 Subdomains: {len(data['subdomains'])} ({len(live)} live)",
                f"🔌 Open ports: {len(data['ports'])}",
                f"🗂️ URLs discovered: {len(data['urls'])}",
                f"🔍 Parameters: {len(data.get('parameters', []))}",
                f"🔑 JS secrets: {len(secrets)}",
                f"💥 XSS: {len(data.get('xss_findings', []))} ({xss_c} confirmed)",
                f"🔗 SSRF: {len(data.get('ssrf_findings', []))} ({ssrf_c} confirmed)",
            ]
            await bot.send("\n".join(lines))

        elif cmd == "subdomains":
            if not args:
                await bot.send("Usage: /subdomains &lt;scan_id&gt;")
                return
            scan_id = int(args[0])
            data = get_scan_data(scan_id, db_path)
            subs = data.get("subdomains", [])
            if not subs:
                await bot.send("No subdomains found for this scan.")
                return
            live = [s for s in subs if s.is_live]
            lines = [f"<b>Subdomains #{scan_id}</b> — {len(subs)} total, {len(live)} live\n"]
            for s in live[:30]:
                lines.append(f"  ✅ <code>{s.host}</code> {s.http_status or ''}")
            if len(live) > 30:
                lines.append(f"  … and {len(live)-30} more")
            await bot.send("\n".join(lines))

        elif cmd == "ports":
            if not args:
                await bot.send("Usage: /ports &lt;scan_id&gt;")
                return
            scan_id = int(args[0])
            data = get_scan_data(scan_id, db_path)
            ports = data.get("ports", [])
            if not ports:
                await bot.send("No open ports found for this scan.")
                return
            lines = [f"<b>Open ports — Scan #{scan_id}</b>\n"]
            for p in ports[:30]:
                svc = f" {p.service}" if p.service else ""
                ver = f" {p.version}" if p.version else ""
                lines.append(f"  <code>{p.host}:{p.port}/{p.protocol}</code>{svc}{ver}")
            if len(ports) > 30:
                lines.append(f"  … and {len(ports)-30} more")
            await bot.send("\n".join(lines))

        elif cmd == "secrets":
            if not args:
                await bot.send("Usage: /secrets &lt;scan_id&gt;")
                return
            scan_id = int(args[0])
            data = get_scan_data(scan_id, db_path)
            secrets = [j for j in data.get("js_findings", []) if j.finding_type == "secret"]
            if not secrets:
                await bot.send("No secrets found for this scan.")
                return
            lines = [f"<b>Secrets — Scan #{scan_id}</b>\n"]
            for s in secrets[:20]:
                val = (s.value or "")[:60]
                lines.append(f"🔑 <b>{s.secret_type}</b>: <code>{val}</code>")
            if len(secrets) > 20:
                lines.append(f"  … and {len(secrets)-20} more")
            await bot.send("\n".join(lines))

        elif cmd == "xss":
            if not args:
                await bot.send("Usage: /xss &lt;scan_id&gt;")
                return
            scan_id = int(args[0])
            data = get_scan_data(scan_id, db_path)
            findings = data.get("xss_findings", [])
            if not findings:
                await bot.send("No XSS findings for this scan.")
                return
            confirmed = [f for f in findings if f.confirmed]
            lines = [f"<b>XSS — Scan #{scan_id}</b> ({len(confirmed)} confirmed / {len(findings)} total)\n"]
            for f in (confirmed or findings)[:15]:
                badge = "✅" if f.confirmed else "⚠️"
                lines.append(f"{badge} [{f.finding_type}] <code>{f.param}</code>\n   <code>{(f.url or '')[:70]}</code>")
            await bot.send("\n".join(lines))

        elif cmd == "ssrf":
            if not args:
                await bot.send("Usage: /ssrf &lt;scan_id&gt;")
                return
            scan_id = int(args[0])
            data = get_scan_data(scan_id, db_path)
            findings = data.get("ssrf_findings", [])
            if not findings:
                await bot.send("No SSRF findings for this scan.")
                return
            confirmed = [f for f in findings if f.confirmed]
            lines = [f"<b>SSRF — Scan #{scan_id}</b> ({len(confirmed)} confirmed / {len(findings)} total)\n"]
            for f in (confirmed or findings)[:15]:
                badge = "✅" if f.confirmed else "⚠️"
                meta = f.metadata_path or f.callback_id or ""
                lines.append(f"{badge} [{f.finding_type}] <code>{f.param}</code>\n   {meta[:80]}")
            await bot.send("\n".join(lines))

        elif cmd == "report":
            if not args:
                await bot.send("Usage: /report &lt;scan_id&gt;")
                return
            scan_id = int(args[0])
            data = get_scan_data(scan_id, db_path)
            agg = data.get("ai_reports", {}).get("aggregate", {})
            if not agg:
                await bot.send("No AI report for this scan. Run with ANTHROPIC_API_KEY set.")
                return
            summary = agg.get("executive_summary", "No summary.")
            vecs = agg.get("top_attack_vectors", [])[:5]
            lines = [f"<b>AI Report — Scan #{scan_id}</b>", "", summary]
            if vecs:
                lines += ["", "<b>Top attack vectors:</b>"]
                for v in vecs:
                    pri = v.get("priority", "?").upper()
                    lines.append(f"[{pri}] <b>{v.get('title','')}</b>: {v.get('description','')[:120]}")
            await bot.send("\n".join(lines))

        elif cmd == "delete":
            if not args:
                await bot.send("Usage: /delete &lt;scan_id&gt;")
                return
            scan_id = int(args[0])
            from reconify.core.storage import get_session, Scan, Subdomain, JsFinding, Port, Url, AiReport, ModuleRun
            from sqlmodel import select
            with get_session(db_path) as sess:
                scan = sess.get(Scan, scan_id)
                if not scan:
                    await bot.send(f"Scan #{scan_id} not found.")
                    return
                target = scan.target
                for model in (Subdomain, JsFinding, Port, Url, AiReport, ModuleRun):
                    rows = sess.exec(select(model).where(model.scan_id == scan_id)).all()
                    for r in rows:
                        sess.delete(r)
                sess.delete(scan)
                sess.commit()
            await bot.send(f"🗑️ Scan #{scan_id} (<code>{target}</code>) deleted.")

        elif cmd == "stop":
            await bot.send("👋 Bot stopped.")
            raise SystemExit(0)

        else:
            await bot.send(f"Unknown command: /{cmd}\nSend /help for the full list.")

    asyncio.run(bot.poll(on_command))


async def _run_and_notify(target: str, modules: list[str], cfg: dict, db_path: str, bot):
    from reconify.core.runner import run_scan

    def on_event(ev: dict):
        t = ev.get("type", "")
        if t in ("xss_finding", "ssrf_finding") and ev.get("confirmed"):
            asyncio.create_task(bot.send_finding(ev))
        elif t == "js_finding" and ev.get("finding_type") == "secret":
            asyncio.create_task(bot.send_finding(ev))
        elif t == "module_done":
            asyncio.create_task(bot.send_module_done(
                ev["module"], ev.get("count", 0), ev.get("elapsed", 0)
            ))

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


async def _run_module_and_notify(scan_id: int, module: str, cfg: dict, db_path: str, bot):
    from reconify.core.runner import run_module

    count = 0

    def on_event(ev: dict):
        nonlocal count
        if ev.get("type") not in ("module_start", "module_done", "module_skip"):
            count += 1

    await run_module(scan_id, module, cfg, db_path, on_event=on_event)
    await bot.send(f"✅ Module <code>{module}</code> finished — {count} findings.")


if __name__ == "__main__":
    app()
