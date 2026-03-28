"""
Port scanning module.

Primary: python-nmap (requires nmap installed)
Fallback: naabu subprocess (if nmap not available)
"""
from __future__ import annotations

import asyncio
import shutil
import subprocess
from collections.abc import AsyncIterator

from reconify.modules.base import BaseModule


class PortModule(BaseModule):
    name = "ports"

    async def run(self) -> AsyncIterator[dict]:
        # Determine hosts to scan (target + live subdomains from DB if available)
        hosts = await self._collect_hosts()

        if shutil.which("nmap"):
            async for result in self._scan_nmap(hosts):
                yield result
        elif shutil.which("naabu"):
            async for result in self._scan_naabu(hosts):
                yield result
        else:
            yield {
                "type": "warning",
                "module": "ports",
                "message": "Neither nmap nor naabu found. Install one to enable port scanning.",
            }

    async def _collect_hosts(self) -> list[str]:
        hosts = [self.target]
        # Pull live subdomains from DB
        try:
            from reconify.core.storage import get_session, Subdomain
            from sqlmodel import select
            with get_session(self.db_path) as s:
                subs = s.exec(
                    select(Subdomain)
                    .where(Subdomain.scan_id == self.scan_id)
                    .where(Subdomain.is_live == True)
                ).all()
                for sub in subs:
                    if sub.host not in hosts:
                        hosts.append(sub.host)
        except Exception:
            pass
        return hosts

    async def _scan_nmap(self, hosts: list[str]) -> AsyncIterator[dict]:
        import nmap
        nm = nmap.PortScanner()

        for host in hosts:
            try:
                # Run in thread pool to avoid blocking
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None,
                    lambda h=host: nm.scan(h, arguments="-sV --top-ports 1000 -T4 --open"),
                )
                for scanned_host in nm.all_hosts():
                    for proto in nm[scanned_host].all_protocols():
                        for port, info in nm[scanned_host][proto].items():
                            if info["state"] == "open":
                                yield {
                                    "type": "port",
                                    "host": scanned_host,
                                    "port": port,
                                    "protocol": proto,
                                    "state": "open",
                                    "service": info.get("name", ""),
                                    "version": f"{info.get('product', '')} {info.get('version', '')}".strip(),
                                }
            except Exception as e:
                yield {"type": "warning", "module": "ports", "message": f"nmap error on {host}: {e}"}

    async def _scan_naabu(self, hosts: list[str]) -> AsyncIterator[dict]:
        target_str = ",".join(hosts)
        try:
            proc = await asyncio.create_subprocess_exec(
                "naabu", "-host", target_str, "-top-ports", "1000",
                "-silent", "-json",
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            import json
            for line in stdout.decode().splitlines():
                try:
                    entry = json.loads(line)
                    yield {
                        "type": "port",
                        "host": entry.get("ip", entry.get("host", "")),
                        "port": entry.get("port", 0),
                        "protocol": entry.get("protocol", "tcp"),
                        "state": "open",
                        "service": None,
                        "version": None,
                    }
                except Exception:
                    pass
        except Exception as e:
            yield {"type": "warning", "module": "ports", "message": f"naabu error: {e}"}
