"""LLM triage: summary, recommendations, per-finding patches and refactors (Groq, OpenAI-compatible API)."""
from __future__ import annotations

import json
import logging
import os
from typing import List

import httpx

from .models import BugRisk, Finding, SourceFile

log = logging.getLogger(__name__)
ENDPOINT = os.environ.get("AI_BASE_URL", "https://api.groq.com/openai/v1") + "/chat/completions"
MODEL = os.environ.get("AI_MODEL", "llama-3.3-70b-versatile")
MAX_CONTEXT_CHARS = 9000
EMPTY = {"summary": "", "recommendations": [], "fixes": [], "refactors": []}


def _api_key() -> str:
    return os.environ.get("GROQ_API_KEY") or os.environ.get("EMERGENT_LLM_KEY") or ""


def ai_enabled() -> bool:
    return bool(_api_key())


def _context(files: List[SourceFile], findings: List[Finding], risks: List[BugRisk]) -> str:
    wanted = [f.file_path for f in findings if f.severity in ("critical", "high") and f.scanner != "osv"][:4]
    wanted += [r.file_path for r in risks[:2]]
    by_path = {f.path: f for f in files}
    chunks, used = [], 0
    for path in dict.fromkeys(wanted):
        f = by_path.get(path)
        if not f:
            continue
        body = f.content[: MAX_CONTEXT_CHARS - used]
        chunks.append(f"### File: {path}\n```{f.language}\n{body}\n```")
        used += len(body)
        if used >= MAX_CONTEXT_CHARS:
            break
    return "\n\n".join(chunks)


def _sanitize(result: dict) -> dict:
    out = dict(EMPTY)
    out["summary"] = str(result.get("summary", ""))[:1200]
    out["recommendations"] = [str(r) for r in result.get("recommendations", [])][:6]
    out["fixes"] = [f for f in result.get("fixes", []) if isinstance(f, dict) and f.get("fix_code")][:15]
    out["refactors"] = [r for r in result.get("refactors", []) if isinstance(r, dict) and r.get("refined_code")][:3]
    return out


async def triage(files: List[SourceFile], findings: List[Finding], risks: List[BugRisk]) -> dict:
    key = _api_key()
    if not key:
        return {**EMPTY, "summary": "AI triage is disabled (set GROQ_API_KEY on the server)."}

    issues = [
        {"type": f.type, "severity": f.severity, "file_path": f.file_path, "line": f.line_number, "cwe": f.cwe,
         "snippet": f.snippet}
        for f in findings if f.scanner != "osv"
    ][:30]
    deps = [f.type for f in findings if f.scanner == "osv"][:10]
    hot = [{"file_path": r.file_path, "risk": r.risk_score, "issues": r.issues} for r in risks[:2]]

    prompt = f"""You are a staff application-security engineer reviewing a codebase.

CODE CONTEXT:
{_context(files, findings, risks)}

STATIC-ANALYSIS FINDINGS (JSON): {json.dumps(issues)}
VULNERABLE DEPENDENCIES: {json.dumps(deps)}
COMPLEXITY HOTSPOTS: {json.dumps(hot)}

Respond with a JSON object with exactly these keys:
- "summary": 2-3 sentences on overall security posture, naming the single most urgent risk.
- "recommendations": 5 short, specific, prioritized actions.
- "fixes": one entry per real (non-false-positive) code finding, each with "issue_type" (copy the finding's "type" exactly),
  "file_path", "line" (number), "explanation" (why it is exploitable, 1-2 sentences), "fix_code" (the corrected code snippet only).
- "refactors": for each hotspot file, "file_path", "explanation", and "refined_code" (the COMPLETE rewritten source, not prose).
"""
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                ENDPOINT,
                headers={"Authorization": f"Bearer {key}"},
                json={
                    "model": MODEL,
                    "messages": [
                        {"role": "system", "content": "You are a precise security reviewer. Output valid JSON only."},
                        {"role": "user", "content": prompt},
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.2,
                },
            )
        if resp.status_code != 200:
            log.warning("AI call failed: %s %s", resp.status_code, resp.text[:200])
            return {**EMPTY, "summary": "AI triage failed — static results are still complete."}
        return _sanitize(json.loads(resp.json()["choices"][0]["message"]["content"]))
    except (httpx.HTTPError, KeyError, ValueError) as e:
        log.warning("AI triage error: %s", e)
        return {**EMPTY, "summary": "AI triage unavailable — static results are still complete."}
