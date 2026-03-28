"""
AI-powered analysis of recon findings using Claude API.

Produces:
  - Per-module summary (sub, js, ports, content)
  - Aggregate prioritized attack surface report
"""
from __future__ import annotations

import json

import anthropic

from reconify.core.storage import AiReport, get_scan_data, get_session


MODEL = "claude-sonnet-4-6"

_MODULE_PROMPTS = {
    "sub": """You are a bug bounty security expert analyzing subdomain enumeration results.

Target: {target}

Subdomains found ({count} total):
{data}

Analyze these subdomains and identify:
1. HIGH PRIORITY targets (dev/staging/admin/internal subdomains, unusual patterns)
2. Potential subdomain takeover candidates (look for unusual or orphaned subdomains)
3. Infrastructure insights (cloud services, third-party integrations visible in naming)
4. Recommended next steps for each interesting subdomain

Respond as JSON with this structure:
{{
  "summary": "brief overview",
  "high_priority": [
    {{"host": "...", "reason": "...", "attack_vector": "...", "priority": "critical|high|medium"}}
  ],
  "subdomain_takeover_candidates": ["..."],
  "infrastructure_insights": ["..."],
  "next_steps": ["..."]
}}""",

    "js": """You are a bug bounty security expert analyzing JavaScript recon findings.

Target: {target}

JS findings ({count} total):
{data}

Analyze these JavaScript findings and identify:
1. CRITICAL secrets (API keys, credentials, tokens) — flag exact values
2. Interesting API endpoints that could be tested for IDOR, auth bypass, etc.
3. Internal URLs or IP addresses revealing infrastructure
4. Source maps that could expose full source code

Respond as JSON:
{{
  "summary": "brief overview",
  "critical_secrets": [
    {{"type": "...", "value": "...", "js_url": "...", "risk": "...", "priority": "critical|high|medium"}}
  ],
  "interesting_endpoints": [
    {{"endpoint": "...", "potential_vulnerability": "...", "priority": "high|medium|low"}}
  ],
  "source_maps": ["..."],
  "next_steps": ["..."]
}}""",

    "ports": """You are a bug bounty security expert analyzing port scan results.

Target: {target}

Open ports ({count} total):
{data}

Analyze these port/service findings and identify:
1. Services that are commonly misconfigured or vulnerable
2. Unexpected/unusual open ports
3. Service versions with known CVEs
4. Attack surface expansion opportunities

Respond as JSON:
{{
  "summary": "brief overview",
  "high_priority_services": [
    {{"host": "...", "port": ..., "service": "...", "risk": "...", "priority": "critical|high|medium"}}
  ],
  "unexpected_ports": [
    {{"host": "...", "port": ..., "note": "..."}}
  ],
  "cve_candidates": ["..."],
  "next_steps": ["..."]
}}""",

    "content": """You are a bug bounty security expert analyzing content discovery results.

Target: {target}

URLs discovered ({count} total, showing sample):
{data}

Analyze these URLs and identify:
1. Admin panels, dashboards, management interfaces
2. API endpoints (REST, GraphQL)
3. Sensitive paths (backups, configs, source code, debugging endpoints)
4. Authentication pages worth testing (login, register, password reset)

Respond as JSON:
{{
  "summary": "brief overview",
  "admin_panels": ["..."],
  "api_endpoints": ["..."],
  "sensitive_paths": [
    {{"url": "...", "reason": "...", "priority": "critical|high|medium"}}
  ],
  "auth_endpoints": ["..."],
  "next_steps": ["..."]
}}""",

    "aggregate": """You are a senior bug bounty hunter. You have completed full recon on a target.
Synthesize all findings into a final prioritized attack plan.

Target: {target}

=== SUBDOMAIN SUMMARY ===
{sub_summary}

=== JS RECON SUMMARY ===
{js_summary}

=== PORT SCAN SUMMARY ===
{ports_summary}

=== CONTENT DISCOVERY SUMMARY ===
{content_summary}

Produce a comprehensive, prioritized attack plan. Focus on:
1. The 3-5 most likely paths to finding a valid bug
2. Quick wins (low-hanging fruit)
3. Chains / combinations of findings that amplify each other
4. Specific test cases to run

Respond as JSON:
{{
  "executive_summary": "...",
  "top_attack_vectors": [
    {{
      "priority": "critical|high|medium",
      "title": "...",
      "description": "...",
      "evidence": ["..."],
      "test_steps": ["..."]
    }}
  ],
  "quick_wins": ["..."],
  "finding_chains": ["..."],
  "recommended_tools": ["..."]
}}""",
}


async def analyze_scan(scan_id: int, config: dict, db_path: str) -> dict:
    api_key = config.get("anthropic_api_key", "")
    if not api_key:
        return {"error": "No ANTHROPIC_API_KEY configured"}

    client = anthropic.AsyncAnthropic(api_key=api_key)
    data = get_scan_data(scan_id, db_path)
    target = data["scan"].target

    module_reports: dict[str, dict] = {}

    # Per-module analysis
    tasks = [
        ("sub", data["subdomains"], "host"),
        ("js", data["js_findings"], None),
        ("ports", data["ports"], None),
        ("content", data["urls"], "url"),
    ]

    for module, items, _ in tasks:
        if not items:
            continue
        report = await _analyze_module(client, module, target, items, scan_id, db_path)
        module_reports[module] = report

    # Aggregate report
    agg_report = await _analyze_aggregate(client, target, module_reports, scan_id, db_path)
    module_reports["aggregate"] = agg_report

    return module_reports


async def _analyze_module(
    client: anthropic.AsyncAnthropic,
    module: str,
    target: str,
    items: list,
    scan_id: int,
    db_path: str,
) -> dict:
    prompt_template = _MODULE_PROMPTS.get(module, "")
    if not prompt_template:
        return {}

    # Serialize items (cap at 200 for token budget)
    sample = items[:200]
    data_str = json.dumps([_item_to_dict(i) for i in sample], indent=2)

    prompt = prompt_template.format(
        target=target,
        count=len(items),
        data=data_str,
    )

    try:
        msg = await client.messages.create(
            model=MODEL,
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}],
        )
        text = msg.content[0].text
        # Extract JSON from response
        report = _parse_json(text)
    except Exception as e:
        report = {"error": str(e)}

    # Persist to DB
    _save_report(scan_id, module, report, db_path)
    return report


async def _analyze_aggregate(
    client: anthropic.AsyncAnthropic,
    target: str,
    module_reports: dict,
    scan_id: int,
    db_path: str,
) -> dict:
    def summarize(report: dict) -> str:
        if not report or "error" in report:
            return "No data."
        return json.dumps(report.get("summary", report), ensure_ascii=False)[:1000]

    prompt = _MODULE_PROMPTS["aggregate"].format(
        target=target,
        sub_summary=summarize(module_reports.get("sub", {})),
        js_summary=summarize(module_reports.get("js", {})),
        ports_summary=summarize(module_reports.get("ports", {})),
        content_summary=summarize(module_reports.get("content", {})),
    )

    try:
        msg = await client.messages.create(
            model=MODEL,
            max_tokens=3000,
            messages=[{"role": "user", "content": prompt}],
        )
        text = msg.content[0].text
        report = _parse_json(text)
    except Exception as e:
        report = {"error": str(e)}

    _save_report(scan_id, "aggregate", report, db_path)
    return report


def _save_report(scan_id: int, module: str, report: dict, db_path: str):
    with get_session(db_path) as s:
        s.add(AiReport(
            scan_id=scan_id,
            module=module,
            report_json=json.dumps(report),
        ))
        s.commit()


def _item_to_dict(item) -> dict:
    if hasattr(item, "model_dump"):
        return item.model_dump(exclude={"id", "scan_id"})
    return vars(item)


def _parse_json(text: str) -> dict:
    """Extract JSON from Claude's response (may have markdown fences)."""
    # Strip markdown code fences
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
    try:
        return json.loads(text)
    except Exception:
        # Return raw text if JSON parsing fails
        return {"raw": text}
