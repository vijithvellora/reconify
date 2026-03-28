"""
Telegram bot interface for Reconify.

Features:
  - Receive scan results as messages
  - Start/stop scans via bot commands
  - Get notified on critical findings (confirmed XSS, SSRF metadata, secrets)
  - Query scan status

Setup:
  1. Create a bot via @BotFather, get the token
  2. Get your chat_id by messaging your bot and calling getUpdates
  3. Set in config.yaml:
       telegram_token: "123456:ABC-..."
       telegram_chat_id: "987654321"
  Or via env vars: TELEGRAM_TOKEN, TELEGRAM_CHAT_ID
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Callable

import httpx

_BASE = "https://api.telegram.org/bot{token}/{method}"


class TelegramBot:
    def __init__(self, token: str, chat_id: str):
        self.token = token
        self.chat_id = str(chat_id)
        self._offset = 0
        self._handlers: dict[str, Callable] = {}
        self._client: httpx.AsyncClient | None = None

    # ── Sending ────────────────────────────────────────────────────────────────

    async def send(self, text: str, parse_mode: str = "HTML") -> bool:
        url = _BASE.format(token=self.token, method="sendMessage")
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.post(url, json={
                    "chat_id": self.chat_id,
                    "text": text[:4096],
                    "parse_mode": parse_mode,
                })
                return r.json().get("ok", False)
        except Exception:
            return False

    async def send_finding(self, event: dict):
        """Format and send a single finding event."""
        t = event.get("type", "")
        msg = _format_event(event)
        if msg:
            await self.send(msg)

    async def send_module_done(self, module: str, count: int, elapsed: float):
        icon = {"sub": "🌐", "js": "📜", "ports": "🔌", "content": "🗂️",
                "params": "🔍", "xss": "💥", "ssrf": "🔗", "ai": "✨"}.get(module, "📦")
        await self.send(f"{icon} <b>{module}</b> done — <b>{count}</b> findings in {elapsed}s")

    async def send_scan_start(self, scan_id: int, target: str, modules: list[str]):
        await self.send(
            f"🚀 <b>Scan #{scan_id} started</b>\n"
            f"🎯 Target: <code>{target}</code>\n"
            f"📦 Modules: <code>{', '.join(modules)}</code>"
        )

    async def send_scan_done(self, scan_id: int, target: str, summary: dict):
        lines = [f"✅ <b>Scan #{scan_id} complete</b>", f"🎯 <code>{target}</code>", ""]
        for k, v in summary.items():
            if v:
                lines.append(f"  • {k}: <b>{v}</b>")
        await self.send("\n".join(lines))

    # ── Polling for commands ───────────────────────────────────────────────────

    async def poll(self, on_command: Callable[[str, list[str]], None]):
        """Long-poll for incoming messages and dispatch commands."""
        while True:
            try:
                updates = await self._get_updates()
                for update in updates:
                    msg = update.get("message", {})
                    text = msg.get("text", "")
                    if text.startswith("/"):
                        parts = text.strip().split()
                        cmd = parts[0][1:].split("@")[0]  # strip @botname
                        args = parts[1:]
                        await on_command(cmd, args)
                    self._offset = update["update_id"] + 1
            except Exception:
                pass
            await asyncio.sleep(2)

    async def _get_updates(self) -> list[dict]:
        url = _BASE.format(token=self.token, method="getUpdates")
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get(url, params={"offset": self._offset, "timeout": 25})
            return r.json().get("result", [])


# ── Event formatter ────────────────────────────────────────────────────────────

def _format_event(event: dict) -> str | None:
    t = event.get("type", "")

    if t == "xss_finding":
        confirmed = "✅ CONFIRMED" if event.get("confirmed") else "⚠️ Potential"
        ftype = event.get("finding_type", "")
        return (
            f"💥 <b>XSS {confirmed}</b> [{ftype}]\n"
            f"🔗 <code>{event.get('url', '')[:80]}</code>\n"
            f"🎯 Param: <code>{event.get('param', '')}</code>\n"
            f"📦 Payload: <code>{event.get('payload', '')[:80]}</code>\n"
            f"📋 Evidence: {(event.get('evidence') or '')[:120]}"
        )

    if t == "ssrf_finding":
        confirmed = "✅ CONFIRMED" if event.get("confirmed") else "⚠️ Potential"
        ftype = event.get("finding_type", "")
        meta = event.get("metadata_path") or event.get("callback_id") or ""
        return (
            f"🔗 <b>SSRF {confirmed}</b> [{ftype}]\n"
            f"🔗 <code>{event.get('url', '')[:80]}</code>\n"
            f"🎯 Param: <code>{event.get('param', '')}</code>\n"
            f"📍 {meta[:120]}"
        )

    if t == "js_finding" and event.get("finding_type") == "secret":
        return (
            f"🔑 <b>Secret Found</b> [{event.get('secret_type')}]\n"
            f"📄 <code>{event.get('js_url', '')[:80]}</code>\n"
            f"📦 <code>{event.get('value', '')[:100]}</code>"
        )

    if t == "scan_error":
        return f"❌ <b>Scan Error</b>\n{event.get('error', '')[:200]}"

    return None


# ── Notifier (used by runner) ──────────────────────────────────────────────────

class TelegramNotifier:
    """
    Thin wrapper used by the runner to send notifications without blocking.
    Instantiated from config if token + chat_id are present.
    """
    def __init__(self, config: dict):
        token = config.get("telegram_token") or os.getenv("TELEGRAM_TOKEN", "")
        chat_id = config.get("telegram_chat_id") or os.getenv("TELEGRAM_CHAT_ID", "")
        self.enabled = bool(token and chat_id)
        if self.enabled:
            self.bot = TelegramBot(token, chat_id)

    async def on_event(self, event: dict):
        if not self.enabled:
            return
        t = event.get("type", "")
        # Only notify on high-signal events to avoid spam
        if t in ("xss_finding", "ssrf_finding") and event.get("confirmed"):
            await self.bot.send_finding(event)
        elif t == "js_finding" and event.get("finding_type") == "secret":
            await self.bot.send_finding(event)
        elif t == "module_done":
            await self.bot.send_module_done(
                event["module"], event.get("count", 0), event.get("elapsed", 0)
            )
        elif t == "scan_start":
            await self.bot.send_scan_start(
                event["scan_id"], event["target"], event.get("modules", [])
            )
        elif t == "scan_done":
            pass  # summary sent separately by runner
        elif t == "scan_error":
            await self.bot.send_finding(event)
