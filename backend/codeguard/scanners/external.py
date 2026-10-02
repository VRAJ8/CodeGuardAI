"""Adapters for industry SAST tools: Bandit (Python) and Semgrep (multi-language).

Both run as subprocesses against a sandboxed temp copy of the scanned files and
are optional: if a tool isn't installed, the engine reports it as skipped.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Tuple

from ..models import Finding, SourceFile
from ..taxonomy import owasp_for_cwe

log = logging.getLogger(__name__)
RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

# Bandit tests we skip: asserts and shell=False subprocess calls (noise), import-only warnings, and hardcoded-password
# checks (the secrets scanner covers those with redaction).
BANDIT_SKIP = "B101,B105,B106,B107,B403,B404,B603"
BANDIT_SEVERITY = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
BANDIT_TITLES = {
    "B102": "Use of exec()", "B104": "Server binds to all interfaces", "B108": "Insecure temp file path",
    "B110": "Exception silently swallowed (try/except/pass)", "B113": "HTTP request without a timeout",
    "B201": "Flask debug mode enabled", "B301": "Unsafe pickle deserialization", "B303": "Weak hash / cipher",
    "B307": "Use of eval()", "B311": "Non-cryptographic random generator", "B324": "Weak hash algorithm (MD5/SHA1)",
    "B501": "TLS certificate verification disabled", "B506": "Unsafe yaml.load()", "B602": "Shell injection (shell=True)",
    "B605": "Shell injection via os.system", "B608": "SQL injection via string-built query",
    "B701": "Jinja2 autoescape disabled",
}
BANDIT_CRITICAL = {"B102", "B307", "B602", "B605", "B608"}  # exec, eval, shell=True, os.system-shell, SQLi


def _safe_rel(path: str) -> Optional[PurePosixPath]:
    p = PurePosixPath(path)
    if p.is_absolute() or ".." in p.parts:
        return None
    return p


def materialize(files: List[SourceFile], languages: Optional[set] = None) -> Tuple[str, Dict[str, str]]:
    """Write files into a fresh temp dir. Returns (dir, abs_path -> original_path)."""
    tmp = tempfile.mkdtemp(prefix="codeguard-")
    mapping: Dict[str, str] = {}
    for f in files:
        if languages and f.language not in languages:
            continue
        rel = _safe_rel(f.path)
        if rel is None:
            continue
        dest = Path(tmp, *rel.parts)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(f.content, encoding="utf-8")
        mapping[str(dest.resolve())] = f.path
    return tmp, mapping


def bandit_available() -> bool:
    try:
        import bandit  # noqa: F401
        return True
    except ImportError:
        return False


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None and os.environ.get("CODEGUARD_DISABLE_SEMGREP") != "1"


def _original(mapping: Dict[str, str], tmp: str, filename: str) -> str:
    resolved = str(Path(filename if os.path.isabs(filename) else os.path.join(tmp, filename)).resolve())
    return mapping.get(resolved, os.path.relpath(resolved, tmp))


def run_bandit(files: List[SourceFile], timeout: int = 90) -> List[Finding]:
    py = [f for f in files if f.language == "python"]
    if not py:
        return []
    tmp, mapping = materialize(py)
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", tmp, "-f", "json", "-q", "--skip", BANDIT_SKIP],
            capture_output=True, text=True, timeout=timeout,
        )
        data = json.loads(proc.stdout or "{}")
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        log.warning("bandit failed: %s", e)
        return []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    findings = []
    for r in data.get("results", []):
        if r.get("issue_confidence") == "LOW":
            continue
        test_id = r.get("test_id", "B000")
        severity = "critical" if test_id in BANDIT_CRITICAL and r.get("issue_severity") == "HIGH" \
            else BANDIT_SEVERITY.get(r.get("issue_severity"), "low")
        cwe_id = (r.get("issue_cwe") or {}).get("id")
        cwe = f"CWE-{cwe_id}" if cwe_id else None
        findings.append(Finding(
            rule_id=f"BANDIT-{test_id}",
            scanner="bandit",
            severity=severity,
            type=BANDIT_TITLES.get(test_id) or r.get("test_name", "bandit").replace("_", " ").capitalize(),
            description=r.get("issue_text", ""),
            file_path=_original(mapping, tmp, r.get("filename", "")),
            line_number=r.get("line_number"),
            recommendation=f"See {r.get('more_info', 'https://bandit.readthedocs.io')}",
            cwe=cwe,
            owasp=owasp_for_cwe(cwe),
            snippet=(r.get("code") or "").strip()[:300],
        ).with_fingerprint())
    return findings


SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def run_semgrep(files: List[SourceFile], timeout: int = 120) -> List[Finding]:
    code = [f for f in files if f.language not in {"json", "config", "unknown"}]
    if not code or not RULES_DIR.exists():
        return []
    tmp, mapping = materialize(code)
    try:
        proc = subprocess.run(
            ["semgrep", "scan", "--config", str(RULES_DIR), "--json", "--metrics=off",
             "--disable-version-check", "--quiet", "--timeout", "20", tmp],
            capture_output=True, text=True, timeout=timeout,
        )
        data = json.loads(proc.stdout or "{}")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        log.warning("semgrep failed: %s", e)
        return []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        cwe_raw = meta.get("cwe")
        cwe = (cwe_raw[0] if isinstance(cwe_raw, list) else cwe_raw or "").split(":")[0] or None
        rule = r.get("check_id", "semgrep").split(".")[-1]
        findings.append(Finding(
            rule_id=f"SEMGREP-{rule}",
            scanner="semgrep",
            severity=meta.get("codeguard-severity") or SEMGREP_SEVERITY.get(extra.get("severity"), "medium"),
            type=meta.get("title") or rule.replace("-", " ").capitalize(),
            description=extra.get("message", ""),
            file_path=_original(mapping, tmp, r.get("path", "")),
            line_number=(r.get("start") or {}).get("line"),
            recommendation=meta.get("fix") or "Review the flagged data flow and apply the remediation in the message.",
            cwe=cwe,
            owasp=owasp_for_cwe(cwe),
            snippet=(extra.get("lines") or "").strip()[:300],
        ).with_fingerprint())
    return findings
