"""
JS Recon module.

Steps:
  1. Crawl target homepage (and subpages) to collect JS file URLs
  2. Fetch historical JS URLs from Wayback Machine
  3. Download each JS file and run regex patterns for:
     - API endpoints / paths
     - Secrets (AWS keys, GCP, GitHub tokens, Slack tokens, JWTs, Firebase, etc.)
     - Source map references
  4. Yield findings as structured dicts
"""
from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from reconify.modules.base import BaseModule

# ── Secret patterns ────────────────────────────────────────────────────────────

SECRET_PATTERNS: list[tuple[str, str]] = [
    ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    ("aws_secret_key", r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("google_api_key", r"AIza[0-9A-Za-z_-]{35}"),
    ("google_oauth", r"ya29\.[0-9A-Za-z_-]+"),
    ("github_token", r"gh[pousr]_[0-9A-Za-z]{36,}"),
    ("slack_token", r"xox[baprs]-[0-9A-Za-z]{10,48}"),
    ("slack_webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"),
    ("firebase_url", r"https://[a-z0-9-]+\.firebaseio\.com"),
    ("firebase_config", r"apiKey:\s*['\"][A-Za-z0-9_-]+['\"]"),
    ("jwt_token", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
    ("private_key", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    ("heroku_api_key", r"[hH]eroku.{0,20}['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]"),
    ("stripe_key", r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}"),
    ("twilio_key", r"SK[0-9a-fA-F]{32}"),
    ("sendgrid_key", r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"),
    ("mailchimp_key", r"[0-9a-f]{32}-us[0-9]{1,2}"),
    ("generic_secret", r"(?i)(?:secret|password|passwd|token|apikey|api_key)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
    ("basic_auth_url", r"https?://[^:@\s]+:[^@\s]+@[^/\s]+"),
    ("internal_ip", r"(?:^|[^0-9])10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+"),
]

# ── Endpoint extraction patterns ────────────────────────────────────────────────

ENDPOINT_PATTERNS = [
    r"""(?:url\s*[:=]\s*|fetch\s*\(|axios\.\w+\s*\(|http\.\w+\s*\()['"`]([^'"`\s]{1,200})['"`]""",
    r"""['"`](/(?:api|v\d+|graphql|rest|rpc|ws|wss)[^'"`\s]*)['"`]""",
    r"""['"`]((?:https?://)[^'"`\s]{5,200})['"`]""",
    r"""path\s*[:=]\s*['"`]([^'"`\s]+)['"`]""",
    r"""route\s*[:=]\s*['"`]([^'"`\s]+)['"`]""",
    r"""endpoint\s*[:=]\s*['"`]([^'"`\s]+)['"`]""",
]


class JsReconModule(BaseModule):
    name = "js"

    async def run(self) -> AsyncIterator[dict]:
        async with httpx.AsyncClient(
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 reconify/0.1"},
            timeout=15,
        ) as client:
            # Collect JS URLs from crawl + wayback
            js_urls: set[str] = set()

            async for url in self._crawl_js_urls(client):
                js_urls.add(url)
            async for url in self._wayback_js_urls(client):
                js_urls.add(url)

            # Analyze each JS file
            seen_values: set[str] = set()
            sem = asyncio.Semaphore(self.config.get("threads", 20))

            async def process(js_url: str):
                async with sem:
                    content = await self._fetch_js(client, js_url)
                    if not content:
                        return
                    results = []
                    # Endpoints
                    for result in _extract_endpoints(js_url, content):
                        if result["value"] not in seen_values:
                            seen_values.add(result["value"])
                            results.append(result)
                    # Secrets
                    for result in _extract_secrets(js_url, content):
                        if result["value"] not in seen_values:
                            seen_values.add(result["value"])
                            results.append(result)
                    # Source maps
                    if "sourceMappingURL" in content:
                        match = re.search(r"sourceMappingURL=([^\s]+)", content)
                        if match:
                            map_url = urljoin(js_url, match.group(1))
                            key = f"sourcemap:{map_url}"
                            if key not in seen_values:
                                seen_values.add(key)
                                results.append({
                                    "type": "js_finding",
                                    "js_url": js_url,
                                    "finding_type": "source_map",
                                    "value": map_url,
                                    "secret_type": None,
                                })
                    return results

            tasks = [process(url) for url in js_urls]
            for coro in asyncio.as_completed(tasks):
                results = await coro
                if results:
                    for r in results:
                        yield r

    # ── Crawl helpers ──────────────────────────────────────────────────────────

    async def _crawl_js_urls(self, client: httpx.AsyncClient) -> AsyncIterator[str]:
        targets = [f"https://{self.target}", f"http://{self.target}"]
        visited: set[str] = set()
        queue = list(targets)

        for base_url in queue:
            if base_url in visited:
                continue
            visited.add(base_url)
            try:
                r = await client.get(base_url, timeout=10)
                soup = BeautifulSoup(r.text, "html.parser")

                for tag in soup.find_all("script", src=True):
                    src = tag["src"]
                    full = urljoin(base_url, src)
                    if _is_same_origin(full, self.target):
                        yield full
                    elif full.endswith(".js"):
                        yield full  # external JS may still have secrets

                # Also yield inline script src patterns
                for tag in soup.find_all("script"):
                    if not tag.get("src"):
                        # Extract URLs from inline scripts
                        inline = tag.get_text()
                        for match in re.finditer(r"['\"`](/[^'\"` \n]{3,100}\.js)['\"`]", inline):
                            yield urljoin(base_url, match.group(1))

            except Exception:
                pass

    async def _wayback_js_urls(self, client: httpx.AsyncClient) -> AsyncIterator[str]:
        url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=*.{self.target}/*.js&output=json&fl=original&collapse=urlkey&limit=500"
        )
        try:
            r = await client.get(url, timeout=20)
            if r.status_code == 200:
                rows = r.json()
                for row in rows[1:]:  # skip header
                    yield row[0]
        except Exception:
            pass

    async def _fetch_js(self, client: httpx.AsyncClient, url: str) -> str | None:
        try:
            r = await client.get(url, timeout=10)
            if r.status_code == 200:
                return r.text
        except Exception:
            pass
        return None


# ── Pattern helpers ────────────────────────────────────────────────────────────

def _extract_endpoints(js_url: str, content: str) -> list[dict]:
    results = []
    for pattern in ENDPOINT_PATTERNS:
        for match in re.finditer(pattern, content):
            value = match.group(1)
            if len(value) < 3 or value.startswith("//"):
                continue
            results.append({
                "type": "js_finding",
                "js_url": js_url,
                "finding_type": "endpoint",
                "value": value,
                "secret_type": None,
            })
    return results


def _extract_secrets(js_url: str, content: str) -> list[dict]:
    results = []
    for secret_type, pattern in SECRET_PATTERNS:
        for match in re.finditer(pattern, content):
            value = match.group(0)
            # Skip obviously fake or test values
            if any(fake in value.lower() for fake in ["example", "placeholder", "your_", "xxxxxx"]):
                continue
            results.append({
                "type": "js_finding",
                "js_url": js_url,
                "finding_type": "secret",
                "value": value[:500],  # cap length
                "secret_type": secret_type,
            })
    return results


def _is_same_origin(url: str, target: str) -> bool:
    try:
        return urlparse(url).netloc.endswith(target)
    except Exception:
        return False
