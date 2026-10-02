"""Core data model shared by every scanner, the API, and the CLI."""
from __future__ import annotations

import hashlib
import re
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

SEVERITIES = ["critical", "high", "medium", "low"]
_SUPPRESSION_TAIL = re.compile(r"\s*(?:#|//|/\*|<!--|--|\{/\*)\s*codeguard-ignore.*$")
SEVERITY_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # low=0 ... critical=3


class SourceFile(BaseModel):
    path: str
    content: str
    language: str
    lines: int


class Suppression(BaseModel):
    """An in-source suppression (codeguard-ignore). Mirrors SARIF 2.1.0's suppression object."""

    kind: str = "inSource"
    justification: str = ""
    marker_line: Optional[int] = None


class Finding(BaseModel):
    """A single security finding. Field names stay compatible with the v1 `security_issues` shape."""

    rule_id: str
    scanner: str  # patterns | secrets | bandit | osv
    severity: str  # critical | high | medium | low
    type: str  # short human title
    description: str
    file_path: str
    line_number: Optional[int] = None
    recommendation: str
    cwe: Optional[str] = None  # e.g. "CWE-798"
    owasp: Optional[str] = None  # e.g. "A07:2021"
    snippet: Optional[str] = None
    fingerprint: str = ""
    suppression: Optional[Suppression] = None

    def with_fingerprint(self) -> "Finding":
        """Stable identity across re-scans: rule + file + normalized code, not the line number, so code
        moving up/down or gaining a trailing comment (e.g. a codeguard-ignore marker) keeps its identity.
        The engine appends an occurrence index when identical lines repeat within a file."""
        code = " ".join(_SUPPRESSION_TAIL.sub("", self.snippet or "").split())
        raw = f"{self.rule_id}|{self.file_path}|{code or f'line:{self.line_number}'}"
        self.fingerprint = hashlib.sha1(raw.encode(), usedforsecurity=False).hexdigest()[:16]
        return self


class FunctionMetric(BaseModel):
    name: str
    line: int
    complexity: int
    rank: str  # radon A-F


class BugRisk(BaseModel):
    """Per-file code-health result. Compatible with the v1 `bug_risks` shape."""

    file_path: str
    risk_score: float  # 0-100
    complexity: str  # low | medium | high
    issues: List[str]
    language: str = "unknown"
    lines: int = 0
    cyclomatic: float = 0.0  # avg cyclomatic complexity per block
    max_cyclomatic: int = 0
    maintainability: Optional[float] = None  # radon MI 0-100
    hotspots: List[FunctionMetric] = []


class Vulnerability(BaseModel):
    id: str
    aliases: List[str] = []
    summary: str = ""
    severity: str = "medium"
    cvss: Optional[float] = None
    fixed_in: Optional[str] = None
    url: Optional[str] = None


class Dependency(BaseModel):
    name: str
    version: str
    ecosystem: str  # npm | PyPI | Go
    manifest: str
    dev: bool = False
    vulnerabilities: List[Vulnerability] = []

    @property
    def purl(self) -> str:
        eco = {"npm": "npm", "PyPI": "pypi", "Go": "golang"}.get(self.ecosystem, self.ecosystem.lower())
        return f"pkg:{eco}/{self.name}@{self.version}" if self.version else f"pkg:{eco}/{self.name}"


class Metrics(BaseModel):
    total_files: int
    total_lines: int
    languages: Dict[str, int]
    avg_complexity: float
    maintainability_index: float


class ScanReport(BaseModel):
    metrics: Metrics
    security_issues: List[Finding]
    bug_risks: List[BugRisk]
    dependencies: List[Dependency] = []
    overall_score: float
    grade: str
    severity_counts: Dict[str, int]
    owasp_counts: Dict[str, int]
    scanner_counts: Dict[str, int]
    scanners_run: List[str] = Field(default_factory=list)
    suppressed: int = 0  # len(suppressed_issues), kept for API compatibility
    suppressed_issues: List[Finding] = Field(default_factory=list)  # excluded from score/counts/gating, still reported
    errors: List[str] = Field(default_factory=list)  # requested engines that failed to run (fails a --fail-on gate)
    warnings: List[str] = Field(default_factory=list)  # e.g. malformed suppression markers that were ignored
    duration_ms: int = 0
