"""
Content discovery module.

Sources:
  - Wayback Machine CDX API
  - CommonCrawl index API
  - URLScan.io (free, no key)
  - robots.txt parsing
  - sitemap.xml parsing (recursive)
  - ffuf subprocess for directory fuzzing (if installed)
"""
from __future__ import annotations

import asyncio
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import AsyncIterator
from urllib.parse import urljoin, urlparse

import httpx

from reconify.modules.base import BaseModule


class ContentModule(BaseModule):
    name = "content"

    async def run(self) -> AsyncIterator[dict]:
        seen: set[str] = set()

        async with httpx.AsyncClient(
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 reconify/0.1"},
            timeout=15,
        ) as client:
            sources = [
                self._wayback(client),
                self._commoncrawl(client),
                self._urlscan(client),
                self._robots(client),
                self._sitemap(client),
            ]

            for source_coro in sources:
                async for result in source_coro:
                    if result["url"] not in seen:
                        seen.add(result["url"])
                        yield result

            # ffuf fuzzing
            if shutil.which("ffuf"):
                async for result in self._ffuf():
                    if result.get("url") and result["url"] not in seen:
                        seen.add(result["url"])
                        yield result

    async def _wayback(self, client: httpx.AsyncClient) -> AsyncIterator[dict]:
        url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=*.{self.target}/*&output=json&fl=original,statuscode"
            f"&collapse=urlkey&limit=5000&filter=statuscode:200"
        )
        try:
            r = await client.get(url, timeout=30)
            if r.status_code == 200:
                rows = r.json()
                for row in rows[1:]:
                    orig_url = row[0] if row else ""
                    status = int(row[1]) if len(row) > 1 and row[1].isdigit() else None
                    if orig_url:
                        yield {"type": "url", "url": orig_url, "source": "wayback", "status_code": status}
        except Exception:
            pass

    async def _commoncrawl(self, client: httpx.AsyncClient) -> AsyncIterator[dict]:
        # Use CommonCrawl index API (latest index)
        index_url = "http://index.commoncrawl.org/collinfo.json"
        try:
            r = await client.get(index_url, timeout=10)
            if r.status_code != 200:
                return
            indexes = r.json()
            if not indexes:
                return
            latest = indexes[0]["cdx-api"]

            search_url = f"{latest}?url=*.{self.target}/*&output=json&limit=1000"
            r2 = await client.get(search_url, timeout=20)
            if r2.status_code == 200:
                for line in r2.text.strip().splitlines():
                    try:
                        import json
                        entry = json.loads(line)
                        orig_url = entry.get("url", "")
                        if orig_url:
                            yield {"type": "url", "url": orig_url, "source": "commoncrawl", "status_code": None}
                    except Exception:
                        pass
        except Exception:
            pass

    async def _urlscan(self, client: httpx.AsyncClient) -> AsyncIterator[dict]:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.target}&size=100"
        try:
            r = await client.get(url, timeout=15)
            if r.status_code == 200:
                for result in r.json().get("results", []):
                    page = result.get("page", {})
                    orig_url = page.get("url", "")
                    if orig_url:
                        yield {
                            "type": "url",
                            "url": orig_url,
                            "source": "urlscan",
                            "status_code": page.get("status"),
                        }
        except Exception:
            pass

    async def _robots(self, client: httpx.AsyncClient) -> AsyncIterator[dict]:
        for scheme in ("https", "http"):
            base = f"{scheme}://{self.target}"
            try:
                r = await client.get(f"{base}/robots.txt", timeout=10)
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        line = line.strip()
                        if line.startswith(("Allow:", "Disallow:")):
                            path = line.split(":", 1)[-1].strip()
                            if path and path != "/":
                                yield {
                                    "type": "url",
                                    "url": urljoin(base, path),
                                    "source": "robots",
                                    "status_code": None,
                                }
                    break
            except Exception:
                pass

    async def _sitemap(self, client: httpx.AsyncClient) -> AsyncIterator[dict]:
        queue = [
            f"https://{self.target}/sitemap.xml",
            f"https://{self.target}/sitemap_index.xml",
        ]
        visited: set[str] = set()

        while queue:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            try:
                r = await client.get(url, timeout=10)
                if r.status_code != 200:
                    continue
                root = ET.fromstring(r.text)
                ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                # Sitemap index
                for loc in root.findall(".//sm:sitemap/sm:loc", ns):
                    child_url = loc.text.strip()
                    if child_url not in visited:
                        queue.append(child_url)
                # URL set
                for loc in root.findall(".//sm:url/sm:loc", ns):
                    page_url = loc.text.strip()
                    yield {"type": "url", "url": page_url, "source": "sitemap", "status_code": None}
            except Exception:
                pass

    async def _ffuf(self) -> AsyncIterator[dict]:
        wordlist = self.config.get("ffuf_wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")
        import os
        if not os.path.exists(wordlist):
            return

        for scheme in ("https", "http"):
            target_url = f"{scheme}://{self.target}/FUZZ"
            try:
                proc = await asyncio.create_subprocess_exec(
                    "ffuf", "-u", target_url, "-w", wordlist,
                    "-mc", "200,201,204,301,302,307,401,403",
                    "-o", "/tmp/reconify_ffuf.json", "-of", "json",
                    "-s",
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                await asyncio.wait_for(proc.wait(), timeout=180)

                import json
                with open("/tmp/reconify_ffuf.json") as f:
                    data = json.load(f)
                for result in data.get("results", []):
                    yield {
                        "type": "url",
                        "url": result.get("url", ""),
                        "source": "ffuf",
                        "status_code": result.get("status"),
                    }
                break
            except Exception:
                pass
