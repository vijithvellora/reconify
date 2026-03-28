"""Base class for all recon modules."""
from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import AsyncIterator, Any


class BaseModule(ABC):
    name: str = ""

    def __init__(self, target: str, scan_id: int, config: dict, db_path: str):
        self.target = target
        self.scan_id = scan_id
        self.config = config
        self.db_path = db_path
        self._semaphore = asyncio.Semaphore(config.get("threads", 20))

    @abstractmethod
    async def run(self) -> AsyncIterator[dict]:
        """Yield result dicts as they are discovered. Each dict must have 'type' key."""
        ...

    async def _fetch(self, client, url: str, **kwargs) -> Any | None:
        async with self._semaphore:
            try:
                resp = await client.get(url, timeout=self.config.get("timeout", 10), **kwargs)
                return resp
            except Exception:
                return None
