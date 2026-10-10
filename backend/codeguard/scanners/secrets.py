"""Hardcoded-secret detection: provider-specific signatures plus a Shannon-entropy check
for generic `password = "..."` style assignments. Matches are always redacted."""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import List, Tuple

from ..models import Finding
from ..taxonomy import owasp_for_cwe

# (rule_id, title, regex, severity)
SIGNATURES: List[Tuple[str, str, str, str]] = [
    ("SEC-AWS-KEY", "AWS access key ID", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "critical"),
    ("SEC-AWS-SECRET", "AWS secret access key", r"(?i)aws.{0,20}(secret|private).{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "critical"),
    ("SEC-GITHUB", "GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b", "critical"),
    ("SEC-STRIPE", "Stripe secret key", r"\b(sk|rk)_(live|test)_[0-9a-zA-Z]{24,}\b", "critical"),
    ("SEC-GOOGLE", "Google API key", r"\bAIza[0-9A-Za-z\-_]{35}\b", "high"),
    ("SEC-SLACK", "Slack token", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", "critical"),
    ("SEC-SLACK-HOOK", "Slack webhook URL", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "high"),
    ("SEC-OPENAI", "OpenAI API key", r"\bsk-(proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b", "critical"),
    ("SEC-ANTHROPIC", "Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{80,}\b", "critical"),
    ("SEC-GROQ", "Groq API key", r"\bgsk_[A-Za-z0-9]{48,}\b", "critical"),
    ("SEC-PRIVATE-KEY", "Private key block", r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----", "critical"),
    ("SEC-JWT", "Hardcoded JSON Web Token", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "medium"),
    ("SEC-DB-URL", "Database URL with embedded credentials",
     r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://[^\s:'\"/@]+:([^\s@'\"/]+)@[^\s'\"]+", "critical"),
]
_COMPILED = [(rid, title, re.compile(rx), sev) for rid, title, rx, sev in SIGNATURES]

GENERIC = re.compile(
    r"(?i)\b([\w.-]*(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)[\w-]*)"
    r"\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"
)
PLACEHOLDER_HINTS = ("${", "{{", "<", "process.env", "os.environ", "getenv", "your", "example", "changeme", "xxx",
                     "***", "placeholder", "dummy", "sample", "redacted", "replace", "todo", "none", "null", "undefined")

RECOMMENDATION = ("Revoke and rotate this credential now, then load it from an environment variable or a secrets "
                  "manager (Vault, AWS Secrets Manager, Doppler). Purge it from git history with git filter-repo.")
MAX_LINE = 2000  # longer lines (minified bundles) are not searched
MIN_ENTROPY = 3.0  # bits/char a generic `password = "..."` value needs to be reported
MIN_DISTINCT = 4  # values with fewer distinct characters are placeholders ("xxxxxxxx", "abababab")
# redact(): values longer than REDACT_MIN keep their first/last few characters around a fixed-width mask.
REDACT_MIN, REDACT_HEAD, REDACT_TAIL, REDACT_MASK = 10, 4, 2, "*" * 8


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((c / len(value)) * math.log2(c / len(value)) for c in counts.values())


def redact(value: str) -> str:
    return f"{value[:REDACT_HEAD]}{REDACT_MASK}{value[-REDACT_TAIL:]}" if len(value) > REDACT_MIN else REDACT_MASK


def _looks_placeholder(value: str) -> bool:
    low = value.lower()
    return any(h in low for h in PLACEHOLDER_HINTS) or len(set(value)) < MIN_DISTINCT


def scan_secrets(content: str, file_path: str) -> List[Finding]:
    findings: List[Finding] = []
    seen_lines = set()
    for lineno, line in enumerate(content.split("\n"), 1):
        if len(line) > MAX_LINE:
            continue
        for rid, title, rx, sev in _COMPILED:
            m = rx.search(line)
            if not m:
                continue
            if rid == "SEC-DB-URL" and _looks_placeholder(m.group(4) or ""):
                continue
            findings.append(_make(rid, title, sev, file_path, lineno, m.group(0), line=line))
            seen_lines.add(lineno)
        if lineno in seen_lines:
            continue
        m = GENERIC.search(line)
        if m:
            value = m.group(3)
            if _looks_placeholder(value) or shannon_entropy(value) < MIN_ENTROPY:
                continue
            findings.append(_make("SEC-GENERIC", f"Hardcoded credential in `{m.group(1)[:40]}`", "high",
                                  file_path, lineno, value, entropy=shannon_entropy(value), line=line))
    return findings


def _make(rule_id: str, title: str, severity: str, file_path: str, lineno: int, raw: str, entropy: float = None,
          line: str = "") -> Finding:
    extra = f" (entropy {entropy:.2f} bits/char)" if entropy else ""
    return Finding(
        rule_id=rule_id,
        scanner="secrets",
        severity=severity,
        type=f"Hardcoded secret: {title}",
        description=f"Potential {title} committed to source{extra}. Value: {redact(raw)}",
        file_path=file_path,
        line_number=lineno,
        recommendation=RECOMMENDATION,
        cwe="CWE-798",
        owasp=owasp_for_cwe("CWE-798"),
        snippet=redact(raw),
        fp_basis=(line or "").replace(raw, "<secret>") or None,
    ).with_fingerprint()
