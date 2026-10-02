"""Scan orchestration: runs every scanner over a set of files and builds a ScanReport."""
from __future__ import annotations

import asyncio
import time
from collections import Counter
from typing import Awaitable, Callable, Dict, List, Optional

from .models import SEVERITIES, BugRisk, Finding, Metrics, ScanReport, SourceFile
from .scanners.complexity import analyze_file
from .scanners.dependencies import OSVUnavailable, collect_dependencies, dependency_findings, enrich_with_osv
from .scanners.external import bandit_available, run_bandit, run_semgrep, semgrep_available
from .scanners.patterns import scan_patterns
from .scanners.secrets import scan_secrets
from .scoring import overall
from .sources import iter_code
from .suppressions import apply as apply_suppressions

ProgressFn = Callable[[str, int], Awaitable[None]]
# When two scanners flag the same line+CWE, keep the more precise tool's result.
SCANNER_PRIORITY = {"semgrep": 4, "bandit": 3, "osv": 3, "secrets": 2, "patterns": 1}
SEV_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}


async def _noop(stage: str, pct: int) -> None:
    return None


def dedupe(findings: List[Finding]) -> List[Finding]:
    best: Dict[tuple, Finding] = {}
    for f in findings:
        key = (f.file_path, f.line_number, f.cwe or f.rule_id)
        cur = best.get(key)
        if cur is None or (SCANNER_PRIORITY.get(f.scanner, 0), SEV_RANK[f.severity]) > \
                (SCANNER_PRIORITY.get(cur.scanner, 0), SEV_RANK[cur.severity]):
            best[key] = f
    return sorted(best.values(), key=lambda f: (-SEV_RANK[f.severity], f.file_path, f.line_number or 0))


def _normalize_newlines(f: SourceFile) -> SourceFile:
    if "\r" not in f.content:
        return f
    content = f.content.replace("\r\n", "\n").replace("\r", "\n")
    return f.model_copy(update={"content": content, "lines": content.count("\n") + 1})


def _fingerprint_from_source(findings: List[Finding], files: List[SourceFile]) -> None:
    """Fingerprint every finding from the flagged source line itself, then disambiguate repeats."""
    lines_by_path = {f.path: f.content.split("\n") for f in files}
    for f in findings:
        lines = lines_by_path.get(f.file_path)
        line = lines[f.line_number - 1] if lines and f.line_number and 0 < f.line_number <= len(lines) else None
        f.with_fingerprint(source_line=line)
    disambiguate_fingerprints(findings)


def disambiguate_fingerprints(findings: List[Finding]) -> None:
    """Identical code lines in one file share a content fingerprint; suffix repeats in line order."""
    seen: Counter = Counter()
    for f in sorted(findings, key=lambda f: (f.file_path, f.line_number or 0, f.rule_id)):
        seen[f.fingerprint] += 1
        if seen[f.fingerprint] > 1:
            f.fingerprint = f"{f.fingerprint}-{seen[f.fingerprint]}"


async def scan(
    files: List[SourceFile],
    progress: Optional[ProgressFn] = None,
    use_bandit: bool = True,
    use_semgrep: bool = True,
    use_osv: bool = True,
) -> ScanReport:
    progress = progress or _noop
    started = time.monotonic()
    # One line-ending convention for every engine (CPython/Bandit treat a lone CR as a line break, the regex
    # scanners split on LF), so a finding, its marker and its fingerprint always agree on line numbers.
    files = [_normalize_newlines(f) for f in files]
    scanners_run = ["patterns", "secrets", "radon"]
    errors: List[str] = []  # engines that were requested but could not run
    use_bandit = use_bandit and bandit_available()
    use_semgrep = use_semgrep and semgrep_available()

    await progress("Running secret & pattern rules", 20)

    def _regex_pass() -> List[Finding]:
        out: List[Finding] = []
        for f in files:
            out += scan_secrets(f.content, f.path)
            out += scan_patterns(f.content, f.path, f.language, skip_bandit_overlap=use_bandit)
        return out

    # CPU-bound work runs in a worker thread so a large repo can't stall the API's event loop.
    findings: List[Finding] = await asyncio.to_thread(_regex_pass)

    await progress("Running SAST engines (Bandit, Semgrep)", 35)
    jobs = []
    if use_bandit:
        jobs.append(asyncio.to_thread(run_bandit, files)); scanners_run.append("bandit")
    if use_semgrep:
        jobs.append(asyncio.to_thread(run_semgrep, files)); scanners_run.append("semgrep")
    for result in await asyncio.gather(*jobs):
        findings += result

    await progress("Resolving dependencies against OSV.dev", 55)
    deps = collect_dependencies(files)
    if deps and use_osv:
        try:
            deps = await enrich_with_osv(deps)
            scanners_run.append("osv")
        except OSVUnavailable as e:
            errors.append(f"osv: dependency audit did not run ({e})")
    findings += dependency_findings(deps, files)

    await progress("Measuring complexity & maintainability", 70)
    code_files = list(iter_code(files))
    all_health: List[BugRisk] = await asyncio.to_thread(
        lambda: [analyze_file(f.content, f.path, f.language) for f in code_files])
    risks = sorted((r for r in all_health if r.risk_score > 0), key=lambda r: -r.risk_score)

    # Suppress before dedupe, so a rule-scoped marker means the same thing whichever engines are installed.
    active, suppressed_raw, warnings = await asyncio.to_thread(apply_suppressions, findings, files)
    findings, suppressed = dedupe(active), dedupe(suppressed_raw)
    _fingerprint_from_source(findings + suppressed, files)
    languages = Counter()
    for f in code_files:
        languages[f.language] += f.lines
    avg_cc = sum(h.cyclomatic for h in all_health) / max(len(all_health), 1)
    avg_mi = sum(h.maintainability or 0 for h in all_health) / max(len(all_health), 1) if all_health else 100.0

    score, grade, _ = overall(findings, risks, len(code_files))
    return ScanReport(
        metrics=Metrics(
            total_files=len(files),
            total_lines=sum(f.lines for f in files),
            languages=dict(languages.most_common()),
            avg_complexity=round(avg_cc, 2),
            maintainability_index=round(avg_mi, 1),
        ),
        security_issues=findings,
        bug_risks=risks,
        dependencies=deps,
        overall_score=score,
        grade=grade,
        severity_counts={s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES},
        owasp_counts=dict(Counter(f.owasp for f in findings if f.owasp).most_common()),
        scanner_counts=dict(Counter(f.scanner for f in findings).most_common()),
        scanners_run=scanners_run,
        suppressed=len(suppressed),
        suppressed_issues=suppressed,
        errors=errors,
        warnings=warnings,
        duration_ms=int((time.monotonic() - started) * 1000),
    )
