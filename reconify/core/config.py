"""Configuration management — reads from config.yaml and .env"""
from __future__ import annotations

import os
from pathlib import Path

import yaml
from dotenv import load_dotenv

load_dotenv()

_DEFAULT_CONFIG = {
    "threads": 20,
    "timeout": 10,
    "dns_wordlist": str(Path(__file__).parent.parent.parent / "wordlists" / "subdomains.txt"),
    "ffuf_wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "output_dir": str(Path.home() / ".reconify" / "scans"),
    "anthropic_api_key": "",
    "modules": ["sub", "js", "ports", "content"],
    "web_host": "127.0.0.1",
    "web_port": 8000,
}


def load_config(path: str | None = None) -> dict:
    cfg = dict(_DEFAULT_CONFIG)

    # Load from YAML if present
    yaml_path = Path(path) if path else Path.home() / ".reconify" / "config.yaml"
    if yaml_path.exists():
        with yaml_path.open() as f:
            file_cfg = yaml.safe_load(f) or {}
        cfg.update(file_cfg)

    # Env vars override everything
    if key := os.getenv("ANTHROPIC_API_KEY"):
        cfg["anthropic_api_key"] = key
    if threads := os.getenv("RECONIFY_THREADS"):
        cfg["threads"] = int(threads)
    if interactsh := os.getenv("RECONIFY_INTERACTSH_URL"):
        cfg["interactsh_url"] = interactsh

    return cfg


def ensure_output_dir(cfg: dict) -> Path:
    out = Path(cfg["output_dir"])
    out.mkdir(parents=True, exist_ok=True)
    return out
