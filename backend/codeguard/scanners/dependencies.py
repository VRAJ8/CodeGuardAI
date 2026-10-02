"""Software composition analysis (SCA).

Parses npm, PyPI and Go manifests, queries the OSV.dev batch API, then enriches
each advisory with severity (GHSA rating or a computed CVSS v3 base score) and
the earliest fixed version.
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
import re
from typing import Dict, List, Optional, Tuple

import httpx

from ..models import Dependency, Finding, SourceFile, Vulnerability
from ..taxonomy import owasp_for_cwe

log = logging.getLogger(__name__)
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
MAX_DETAIL_LOOKUPS = 80

# ---------------------------------------------------------------- manifests

def _clean_version(spec: str) -> Optional[str]:
    m = re.search(r"\d+(\.\d+){0,3}([-.+][0-9A-Za-z.-]+)?", spec or "")
    if not m or any(x in spec for x in ("git", "http", "file:", "link:", "workspace:")):
        return None
    return m.group(0)


def parse_package_json(content: str, path: str) -> List[Dependency]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    deps = []
    for section, dev in (("dependencies", False), ("devDependencies", True)):
        for name, spec in (data.get(section) or {}).items():
            if isinstance(spec, str):
                deps.append(Dependency(name=name, version=_clean_version(spec) or "", ecosystem="npm", manifest=path, dev=dev))
    return deps


def parse_requirements(content: str, path: str) -> List[Dependency]:
    deps = []
    for raw in content.splitlines():
        line = raw.split("#")[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(==|>=|~=|<=|>|<)?\s*([^;,\s]*)", line)
        if m:
            version = _clean_version(m.group(4)) if m.group(3) in ("==", "~=", ">=") else None
            deps.append(Dependency(name=m.group(1), version=version or "", ecosystem="PyPI", manifest=path))
    return deps


def parse_go_mod(content: str, path: str) -> List[Dependency]:
    deps = []
    in_block = False
    for raw in content.splitlines():
        line = raw.split("//")[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        m = re.match(r"^(?:require\s+)?([\w./\-]+)\s+v([\w.\-+]+)", line) if (in_block or line.startswith("require ")) else None
        if m:
            deps.append(Dependency(name=m.group(1), version=m.group(2), ecosystem="Go", manifest=path))
    return deps


def collect_dependencies(files: List[SourceFile]) -> List[Dependency]:
    deps: List[Dependency] = []
    for f in files:
        name = f.path.rsplit("/", 1)[-1]
        if name == "package.json":
            deps += parse_package_json(f.content, f.path)
        elif re.match(r"requirements([-_.\w]*)\.txt$", name):
            deps += parse_requirements(f.content, f.path)
        elif name == "go.mod":
            deps += parse_go_mod(f.content, f.path)
    return deps

# --------------------------------------------------------------------- CVSS

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0}, "I": {"H": 0.56, "L": 0.22, "N": 0},
    "A": {"H": 0.56, "L": 0.22, "N": 0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> Optional[float]:
    """Compute a CVSS v3.x base score from its vector string (FIRST.org spec)."""
    if not vector or not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(part.split(":") for part in vector.split("/")[1:])
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        exploit = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        raw = 1.08 * (impact + exploit) if scope_changed else impact + exploit
        return _roundup(min(raw, 10))
    except (KeyError, ValueError):
        return None


def severity_from_score(score: float) -> str:
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


GHSA_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def _version_key(v: str) -> Tuple:
    return tuple(int(p) if p.isdigit() else 0 for p in re.split(r"[.\-+]", v)[:4])


def parse_vuln(detail: dict, dep: Dependency) -> Vulnerability:
    score = None
    for s in detail.get("severity", []) or []:
        score = cvss3_base_score(s.get("score", "")) or score
    ghsa = GHSA_SEVERITY.get(str((detail.get("database_specific") or {}).get("severity", "")).upper())
    severity = ghsa or (severity_from_score(score) if score is not None else "medium")

    fixed: List[str] = []
    for aff in detail.get("affected", []) or []:
        if (aff.get("package") or {}).get("name", "").lower() != dep.name.lower():
            continue
        for rng in aff.get("ranges", []) or []:
            fixed += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    current = _version_key(dep.version) if dep.version else ()
    newer = sorted((f for f in fixed if _version_key(f) > current), key=_version_key)
    refs = detail.get("references") or []
    return Vulnerability(
        id=detail.get("id", ""),
        aliases=detail.get("aliases", []) or [],
        summary=(detail.get("summary") or detail.get("details", "")[:200]).strip(),
        severity=severity,
        cvss=score,
        fixed_in=newer[0] if newer else (sorted(fixed, key=_version_key)[-1] if fixed else None),
        url=next((r["url"] for r in refs if r.get("type") == "ADVISORY"), refs[0]["url"] if refs else None),
    )

# ---------------------------------------------------------------- OSV lookup

async def enrich_with_osv(deps: List[Dependency], client: Optional[httpx.AsyncClient] = None) -> List[Dependency]:
    queryable = [d for d in deps if d.version]
    if not queryable:
        return deps
    own_client = client is None
    client = client or httpx.AsyncClient(timeout=20)
    try:
        ids_per_dep: Dict[int, List[str]] = {}
        for start in range(0, len(queryable), 500):
            chunk = queryable[start:start + 500]
            resp = await client.post(OSV_BATCH, json={"queries": [
                {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version} for d in chunk]})
            resp.raise_for_status()
            for i, result in enumerate(resp.json().get("results", [])):
                ids = [v["id"] for v in result.get("vulns", []) or []]
                if ids:
                    ids_per_dep[start + i] = ids

        unique_ids = list(dict.fromkeys(i for ids in ids_per_dep.values() for i in ids))[:MAX_DETAIL_LOOKUPS]
        sem = asyncio.Semaphore(10)

        async def fetch(vid: str):
            async with sem:
                r = await client.get(OSV_VULN.format(id=vid))
                return vid, (r.json() if r.status_code == 200 else {"id": vid})

        details = dict(await asyncio.gather(*(fetch(v) for v in unique_ids)))
        for idx, ids in ids_per_dep.items():
            dep = queryable[idx]
            dep.vulnerabilities = [parse_vuln(details.get(v, {"id": v}), dep) for v in ids]
    except (httpx.HTTPError, ValueError) as e:
        log.warning("OSV lookup failed: %s", e)
    finally:
        if own_client:
            await client.aclose()
    return deps


SEV_ORDER = ["low", "medium", "high", "critical"]


def dependency_findings(deps: List[Dependency], files: List[SourceFile]) -> List[Finding]:
    contents = {f.path: f.content.split("\n") for f in files}
    findings = []
    for d in deps:
        if not d.vulnerabilities:
            continue
        worst = max(d.vulnerabilities, key=lambda v: (SEV_ORDER.index(v.severity), v.cvss or 0))
        fixes = [v.fixed_in for v in d.vulnerabilities if v.fixed_in]
        target = sorted(fixes, key=_version_key)[-1] if fixes else None
        pattern = re.compile(rf"['\"]?{re.escape(d.name)}['\"]?\s*[:=<>~ ]")
        line = next((n for n, text in enumerate(contents.get(d.manifest, []), 1) if pattern.search(text)), None)
        ids = ", ".join((v.aliases[0] if v.aliases else v.id) for v in d.vulnerabilities[:5])
        findings.append(Finding(
            rule_id=f"OSV-{worst.id}",
            scanner="osv",
            severity=worst.severity,
            type=f"Vulnerable dependency: {d.name}@{d.version}",
            description=f"{len(d.vulnerabilities)} known advisory(ies): {ids}. {worst.summary}".strip(),
            file_path=d.manifest,
            line_number=line,
            recommendation=f"Upgrade {d.name} to {target} or later." if target else f"No fixed release yet — consider replacing {d.name}.",
            cwe="CWE-1395",
            owasp=owasp_for_cwe("CWE-1395"),
            snippet=f"{d.name}@{d.version}",
        ).with_fingerprint())
    return findings
