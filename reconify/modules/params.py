"""
Parameter Discovery Module.

Sources:
  - Wayback Machine / GAU URL mining (ParamSpider-style)
  - JS file analysis (from existing JsFinding records)
  - Lightweight param bruteforce via GET/POST (Arjun-style)
  - GF-style classification: xss | ssrf | redirect | generic

Feeds downstream into xss.py and ssrf.py modules.
"""
from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from reconify.modules.base import BaseModule

# ── GF-style param classification ─────────────────────────────────────────────

XSS_PARAMS = {
    "q", "s", "search", "query", "keyword", "keywords", "term", "terms",
    "p", "page", "name", "id", "input", "text", "comment", "description",
    "message", "msg", "title", "subject", "content", "body", "data",
    "value", "val", "v", "url", "src", "href", "ref", "return",
    "redirect", "next", "back", "goto", "redir", "target", "to",
    "out", "view", "show", "type", "category", "tag", "lang", "language",
    "format", "output", "sort", "order", "filter", "mode", "style",
    "theme", "color", "size", "email", "username", "user", "login",
    "token", "code", "key", "action", "callback", "function", "method",
    "error", "warning", "notice", "info", "status", "result",
}

SSRF_PARAMS = {
    "url", "uri", "path", "dest", "destination", "redirect", "redirect_url",
    "redirect_to", "redirect_uri", "next", "back", "goto", "return",
    "return_url", "return_to", "redir", "redir_url", "location",
    "callback", "callback_url", "webhook", "webhook_url", "notify",
    "notify_url", "endpoint", "api", "api_url", "api_endpoint",
    "fetch", "proxy", "proxy_url", "forward", "forward_url",
    "target", "link", "nav", "navigation", "site", "domain", "host",
    "image", "image_url", "img", "img_url", "avatar", "avatar_url",
    "photo", "photo_url", "picture", "picture_url", "logo", "logo_url",
    "file", "file_url", "document", "document_url", "pdf", "pdf_url",
    "load", "load_url", "resource", "resource_url", "service",
    "server", "origin", "base_url", "baseurl", "base", "root",
    "source", "src", "from", "feed", "import", "export",
    "open", "data", "ref", "request", "req", "ping", "trace",
}

REDIRECT_PARAMS = {
    "redirect", "redirect_url", "redirect_to", "redirect_uri",
    "next", "back", "goto", "return", "return_url", "return_to",
    "redir", "location", "url", "dest", "destination", "forward", "target",
    "continue", "after", "followup", "success", "cancel", "logout",
}

# Common params to bruteforce
_BRUTE_PARAMS = list(XSS_PARAMS | SSRF_PARAMS | REDIRECT_PARAMS)


class ParamModule(BaseModule):
    name = "params"

    async def run(self) -> AsyncIterator[dict]:
        seen: set[str] = set()  # url|param dedup key

        async with httpx.AsyncClient(
            follow_redirects=True, verify=False,
            headers={"User-Agent": "Mozilla/5.0 reconify/0.1"},
            timeout=15,
        ) as client:
            # 1. Mine Wayback Machine URLs for params
            async for result in self._wayback_params(client, seen):
                yield result

            # 2. Extract params from JS findings already in DB
            async for result in self._js_params(seen):
                yield result

            # 3. Lightweight param bruteforce on live hosts
            async for result in self._bruteforce_params(client, seen):
                yield result

    # ── Wayback Mining ─────────────────────────────────────────────────────────

    async def _wayback_params(self, client: httpx.AsyncClient, seen: set) -> AsyncIterator[dict]:
        url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=*.{self.target}/*&output=json&fl=original&collapse=urlkey"
            f"&filter=statuscode:200&limit=10000"
        )
        try:
            r = await client.get(url, timeout=30)
            if r.status_code != 200:
                return
            rows = r.json()
            for row in rows[1:]:
                raw_url = row[0]
                parsed = urlparse(raw_url)
                params = parse_qs(parsed.query)
                for param in params:
                    key = f"{_strip_query(raw_url)}|{param}"
                    if key in seen:
                        continue
                    seen.add(key)
                    ptype = _classify(param)
                    yield {
                        "type": "parameter",
                        "url": _strip_query(raw_url),
                        "param": param,
                        "method": "GET",
                        "source": "wayback",
                        "param_type": ptype,
                    }
        except Exception:
            pass

    # ── JS Param Extraction ────────────────────────────────────────────────────

    async def _js_params(self, seen: set) -> AsyncIterator[dict]:
        """Re-analyze JsFinding endpoints already saved for embedded params."""
        try:
            from reconify.core.storage import get_session, JsFinding
            from sqlmodel import select
            with get_session(self.db_path) as s:
                findings = list(s.exec(
                    select(JsFinding)
                    .where(JsFinding.scan_id == self.scan_id)
                    .where(JsFinding.finding_type == "endpoint")
                ).all())
            for f in findings:
                parsed = urlparse(f.value)
                params = parse_qs(parsed.query)
                for param in params:
                    base = _strip_query(f.value)
                    key = f"{base}|{param}"
                    if key in seen:
                        continue
                    seen.add(key)
                    ptype = _classify(param)
                    yield {
                        "type": "parameter",
                        "url": base,
                        "param": param,
                        "method": "GET",
                        "source": "js",
                        "param_type": ptype,
                    }
        except Exception:
            pass

    # ── Lightweight Bruteforce ─────────────────────────────────────────────────

    async def _bruteforce_params(self, client: httpx.AsyncClient, seen: set) -> AsyncIterator[dict]:
        """
        Test a small set of high-value param names on the root endpoint to see
        which ones cause response differences (reflected params = testable).
        """
        target_url = f"https://{self.target}/"
        sem = asyncio.Semaphore(10)
        canary = "xrKy7zQ"  # random canary value

        # Get baseline response
        try:
            baseline = await client.get(target_url, timeout=8)
            baseline_len = len(baseline.text)
        except Exception:
            return

        async def test_param(p: str):
            async with sem:
                test_url = f"{target_url}?{p}={canary}"
                try:
                    r = await client.get(test_url, timeout=8)
                    # Param is interesting if: canary reflected OR response length changed
                    reflected = canary in r.text
                    changed = abs(len(r.text) - baseline_len) > 50
                    if reflected or changed:
                        return p
                except Exception:
                    pass
            return None

        tasks = [test_param(p) for p in _BRUTE_PARAMS]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                key = f"{target_url}|{result}"
                if key not in seen:
                    seen.add(key)
                    yield {
                        "type": "parameter",
                        "url": target_url,
                        "param": result,
                        "method": "GET",
                        "source": "bruteforce",
                        "param_type": _classify(result),
                    }


# ── Helpers ────────────────────────────────────────────────────────────────────

def _classify(param: str) -> str:
    p = param.lower()
    if p in SSRF_PARAMS:
        return "ssrf"
    if p in XSS_PARAMS:
        return "xss"
    if p in REDIRECT_PARAMS:
        return "redirect"
    return "generic"


def _strip_query(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query="", fragment=""))
