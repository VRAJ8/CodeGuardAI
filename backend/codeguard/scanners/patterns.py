"""Lightweight regex SAST rules with CWE / OWASP classification.

These run on every file. Python-specific rules that Bandit covers better are
flagged ``bandit_overlap`` and are skipped when Bandit is available.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Set

from ..models import Finding
from ..taxonomy import owasp_for_cwe

JS_LIKE = {"javascript", "typescript"}
ALL_CODE = {"python", "javascript", "typescript", "java", "go", "rust", "cpp", "c", "ruby", "php", "csharp", "kotlin", "swift"}


@dataclass
class Rule:
    id: str
    title: str
    pattern: str
    severity: str
    cwe: str
    recommendation: str
    languages: Set[str] = field(default_factory=lambda: set(ALL_CODE))
    bandit_overlap: bool = False
    flags: int = 0

    def __post_init__(self):
        self.regex = re.compile(self.pattern, self.flags)


RULES: List[Rule] = [
    Rule("CG-EVAL", "Dynamic code evaluation (eval)", r"(?<![\w.$])eval\s*\(", "high", "CWE-95",
         "Never evaluate strings as code. Parse data explicitly (JSON.parse / ast.literal_eval).",
         languages=JS_LIKE | {"python", "php", "ruby"}, bandit_overlap=True),
    Rule("CG-EXEC", "Dynamic code execution (exec)", r"(?<![\w.$])exec\s*\(", "high", "CWE-95",
         "Avoid exec(); replace with explicit dispatch over a fixed set of operations.",
         languages={"python"}, bandit_overlap=True),
    Rule("CG-NEW-FUNCTION", "Function constructor builds code from strings", r"\bnew\s+Function\s*\(", "high", "CWE-95",
         "Replace `new Function(...)` with a static function.", languages=JS_LIKE),
    Rule("CG-XSS-INNERHTML", "Unsanitized HTML sink (innerHTML / document.write)",
         r"\.(inner|outer)HTML\s*=(?!=)|\bdocument\.write(ln)?\s*\(", "high", "CWE-79",
         "Use textContent, or sanitize with DOMPurify before inserting HTML.", languages=JS_LIKE),
    Rule("CG-XSS-REACT", "dangerouslySetInnerHTML used", r"dangerouslySetInnerHTML", "medium", "CWE-79",
         "Make sure the HTML is sanitized (e.g. DOMPurify.sanitize) before rendering.", languages=JS_LIKE),
    Rule("CG-CMD-NODE", "OS command execution via child_process",
         r"\b(child_process\.)?(exec|execSync)\s*\(\s*[`'\"][^`'\"]*(\$\{|['\"]\s*\+)", "critical", "CWE-78",
         "Use execFile/spawn with an argument array instead of interpolating into a shell string.", languages=JS_LIKE),
    Rule("CG-CMD-PY", "Shell command with shell=True", r"subprocess\.\w+\(.*shell\s*=\s*True", "critical", "CWE-78",
         "Pass an argument list and keep shell=False.", languages={"python"}, bandit_overlap=True),
    Rule("CG-CMD-OS", "os.system / os.popen call", r"\bos\.(system|popen)\s*\(", "high", "CWE-78",
         "Use subprocess.run([...]) with an argument list and validated input.", languages={"python"}, bandit_overlap=True),
    Rule("CG-CMD-PHP", "Shell execution function", r"\b(system|shell_exec|passthru|proc_open|popen)\s*\(", "high", "CWE-78",
         "Avoid shell functions; if unavoidable, escape with escapeshellarg().", languages={"php"}),
    Rule("CG-SQLI-CONCAT", "SQL built with string concatenation",
         r"(SELECT\s.+\sFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)[^;\n]*['\"`]\s*\+\s*[\w(]",
         "critical", "CWE-89", "Use parameterized queries / prepared statements.", flags=re.IGNORECASE),
    Rule("CG-SQLI-FORMAT", "SQL built with string formatting",
         r"(f['\"](SELECT\s.+\sFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)[^'\"]*\{)|"
         r"(['\"](SELECT\s.+\sFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)[^'\"]*['\"]\s*(%|\.format\())|"
         r"(`(SELECT\s.+\sFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)[^`]*\$\{)",
         "critical", "CWE-89", "Use parameterized queries; never interpolate user input into SQL.", flags=re.IGNORECASE),
    Rule("CG-WEAK-HASH", "Weak hash algorithm (MD5/SHA1)",
         r"hashlib\.(md5|sha1)\s*\((?![^\n]*usedforsecurity\s*=\s*False)|createHash\(\s*['\"](md5|sha1)['\"]|MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"",
         "medium", "CWE-327", "Use SHA-256+ for integrity, and bcrypt/argon2 for passwords.", bandit_overlap=False),
    Rule("CG-TLS-OFF", "TLS certificate verification disabled",
         r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|InsecureSkipVerify:\s*true",
         "high", "CWE-295", "Keep certificate verification on; pin a CA bundle if you need a private CA."),
    Rule("CG-CORS-WILDCARD", "CORS allows any origin",
         r"allow_origins\s*=\s*\[\s*['\"]\*['\"]|Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*['\"]|origin\s*:\s*['\"]\*['\"]",
         "medium", "CWE-942", "Restrict CORS to an explicit allow-list of trusted origins."),
    Rule("CG-DEBUG-ON", "Debug mode enabled", r"\.run\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True\b", "medium", "CWE-489",
         "Drive debug mode from an environment variable and keep it off in production.", languages={"python"},
         bandit_overlap=True),
    Rule("CG-DEBUGGER", "Leftover debugger statement", r"^\s*debugger\s*;?\s*$", "low", "CWE-489",
         "Remove debugger statements before shipping.", languages=JS_LIKE),
    Rule("CG-JWT-NOVERIFY", "JWT signature verification disabled",
         r"jwt\.decode\([^)]*(verify\s*=\s*False|verify_signature['\"]\s*:\s*False)|algorithms\s*=\s*\[\s*['\"]none['\"]",
         "high", "CWE-347", "Always verify JWT signatures with an explicit algorithm allow-list."),
    Rule("CG-DESERIALIZE", "Unsafe deserialization", r"\bpickle\.loads?\s*\(|\byaml\.load\s*\((?![^)]*SafeLoader)",
         "high", "CWE-502", "Use json, or yaml.safe_load; never unpickle untrusted data.",
         languages={"python"}, bandit_overlap=True),
    Rule("CG-SSRF-REQUEST", "Outbound request to a user-controlled URL",
         r"(requests\.(get|post)|httpx\.(get|post)|fetch|axios\.(get|post))\(\s*(req\.(query|body|params)|request\.(args|form|json))",
         "high", "CWE-918", "Validate outbound URLs against an allow-list of hosts."),
    Rule("CG-PATH-TRAVERSAL", "File path built from request input",
         r"(open|readFile|readFileSync|sendFile|createReadStream)\(\s*[^)]*(req\.(query|body|params)|request\.(args|form))",
         "high", "CWE-22", "Resolve the path and check it stays inside an allowed base directory."),
]

COMMENT_PREFIXES = ("#", "//", "*", "/*", "--")


def _is_comment(line: str) -> bool:
    return line.lstrip().startswith(COMMENT_PREFIXES)


def scan_patterns(content: str, file_path: str, language: str, skip_bandit_overlap: bool = False) -> List[Finding]:
    findings: List[Finding] = []
    skip = skip_bandit_overlap and language == "python"
    rules = [r for r in RULES if language in r.languages and not (skip and r.bandit_overlap)]
    if not rules:
        return findings
    for lineno, line in enumerate(content.split("\n"), 1):
        if len(line) > 1000 or _is_comment(line):
            continue
        for rule in rules:
            if rule.regex.search(line):
                findings.append(_finding(rule, file_path, lineno, line))
    return findings


def _finding(rule: Rule, file_path: str, lineno: int, line: str, snippet: Optional[str] = None) -> Finding:
    return Finding(
        rule_id=rule.id,
        scanner="patterns",
        severity=rule.severity,
        type=rule.title,
        description=f"Found: {line.strip()[:140]}",
        file_path=file_path,
        line_number=lineno,
        recommendation=rule.recommendation,
        cwe=rule.cwe,
        owasp=owasp_for_cwe(rule.cwe),
        snippet=snippet or line.strip()[:200],
    ).with_fingerprint()
