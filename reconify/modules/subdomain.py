"""
Subdomain enumeration module.

Free sources:
  - crt.sh (Certificate Transparency)
  - HackerTarget API
  - AlienVault OTX
  - Wayback Machine CDX API
  - DNS brute-force via aiodns
  - subfinder subprocess (if installed)

Then probes live hosts with httpx.
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import quote

import aiodns
import httpx

from reconify.modules.base import BaseModule


class SubdomainModule(BaseModule):
    name = "sub"

    async def run(self) -> AsyncIterator[dict]:
        found: set[str] = set()

        # ── Passive sources ────────────────────────────────────────────────
        sources = [
            self._crtsh(),
            self._hackertarget(),
            self._alienvault(),
            self._wayback(),
            self._subfinder(),
        ]

        async with httpx.AsyncClient(
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 reconify/0.1"},
            verify=False,
        ) as client:
            self._client = client

            # Gather passive results
            for coro in sources:
                async for host in coro:
                    host = _clean(host)
                    if host and host not in found:
                        found.add(host)
                        yield {"type": "subdomain", "host": host, "source": "passive", "is_live": False}

            # DNS brute-force
            async for host in self._dns_bruteforce(found):
                found.add(host)
                yield {"type": "subdomain", "host": host, "source": "bruteforce", "is_live": False}

            # Probe live hosts
            async for result in self._probe_live(list(found), client):
                yield result

    # ── Source implementations ─────────────────────────────────────────────

    async def _crtsh(self) -> AsyncIterator[str]:
        url = f"https://crt.sh/?q=%25.{self.target}&output=json"
        try:
            async with httpx.AsyncClient(verify=False, timeout=20) as c:
                r = await c.get(url)
                if r.status_code == 200:
                    for entry in r.json():
                        for name in entry.get("name_value", "").split("\n"):
                            yield name.strip().lstrip("*.")
        except Exception:
            pass

    async def _hackertarget(self) -> AsyncIterator[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"
        try:
            async with httpx.AsyncClient(verify=False, timeout=15) as c:
                r = await c.get(url)
                if r.status_code == 200 and "error" not in r.text.lower()[:50]:
                    for line in r.text.strip().splitlines():
                        parts = line.split(",")
                        if parts:
                            yield parts[0].strip()
        except Exception:
            pass

    async def _alienvault(self) -> AsyncIterator[str]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target}/passive_dns"
        try:
            async with httpx.AsyncClient(verify=False, timeout=15) as c:
                r = await c.get(url)
                if r.status_code == 200:
                    for entry in r.json().get("passive_dns", []):
                        hostname = entry.get("hostname", "")
                        if hostname.endswith(self.target):
                            yield hostname
        except Exception:
            pass

    async def _wayback(self) -> AsyncIterator[str]:
        url = (
            f"http://web.archive.org/cdx/search/cdx?url=*.{self.target}"
            "&output=json&fl=original&collapse=urlkey&limit=5000"
        )
        try:
            async with httpx.AsyncClient(verify=False, timeout=20) as c:
                r = await c.get(url)
                if r.status_code == 200:
                    for row in r.json()[1:]:  # skip header
                        match = re.match(r"https?://([^/]+)", row[0])
                        if match:
                            yield match.group(1).split(":")[0]
        except Exception:
            pass

    async def _subfinder(self) -> AsyncIterator[str]:
        if not shutil.which("subfinder"):
            return
        try:
            proc = await asyncio.create_subprocess_exec(
                "subfinder", "-d", self.target, "-silent",
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            for line in stdout.decode().splitlines():
                host = line.strip()
                if host:
                    yield host
        except Exception:
            pass

    async def _dns_bruteforce(self, known: set[str]) -> AsyncIterator[str]:
        wordlist_path = Path(self.config.get("dns_wordlist", ""))
        if not wordlist_path.exists():
            # Use built-in mini wordlist
            words = _MINI_WORDLIST
        else:
            words = wordlist_path.read_text().splitlines()

        resolver = aiodns.DNSResolver()
        semaphore = asyncio.Semaphore(100)

        async def resolve(sub: str) -> str | None:
            host = f"{sub}.{self.target}"
            if host in known:
                return None
            async with semaphore:
                try:
                    await resolver.query(host, "A")
                    return host
                except Exception:
                    return None

        tasks = [resolve(w.strip()) for w in words if w.strip() and not w.startswith("#")]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                yield result

    async def _probe_live(self, hosts: list[str], client: httpx.AsyncClient) -> AsyncIterator[dict]:
        semaphore = asyncio.Semaphore(self.config.get("threads", 20))

        async def check(host: str) -> dict | None:
            async with semaphore:
                for scheme in ("https", "http"):
                    try:
                        r = await client.get(
                            f"{scheme}://{host}",
                            timeout=8,
                            follow_redirects=True,
                        )
                        ip = None
                        try:
                            import socket
                            ip = socket.gethostbyname(host)
                        except Exception:
                            pass
                        return {
                            "type": "subdomain",
                            "host": host,
                            "source": "probe",
                            "is_live": True,
                            "status_code": r.status_code,
                            "ip": ip,
                        }
                    except Exception:
                        continue
            return None

        tasks = [check(h) for h in hosts]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                yield result


def _clean(host: str) -> str:
    host = host.strip().lower().lstrip("*.").rstrip(".")
    # Remove protocol if accidentally included
    host = re.sub(r"^https?://", "", host)
    host = host.split("/")[0].split(":")[0]
    return host


_MINI_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "admin", "portal", "dev", "staging",
    "test", "app", "shop", "ftp", "cloud", "m", "mobile", "support",
    "status", "cdn", "media", "static", "assets", "img", "images",
    "dashboard", "auth", "login", "sso", "internal", "intranet", "corp",
    "beta", "docs", "help", "wiki", "forum", "community", "git", "gitlab",
    "jenkins", "ci", "jira", "confluence", "grafana", "monitor", "prometheus",
    "s3", "storage", "backup", "db", "database", "mysql", "redis", "kafka",
    "elasticsearch", "kibana", "analytics", "tracking", "pixel", "webhooks",
    "notifications", "push", "ws", "websocket", "gateway", "proxy", "edge",
]
