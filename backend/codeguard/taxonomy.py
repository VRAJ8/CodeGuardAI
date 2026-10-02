"""CWE -> OWASP Top 10 (2021) mapping used to classify every finding."""
from typing import Optional

OWASP_TOP10 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable & Outdated Components",
    "A07:2021": "Identification & Auth Failures",
    "A08:2021": "Software & Data Integrity Failures",
    "A09:2021": "Logging & Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

# Subset of the official OWASP mapping, covering the CWEs our scanners emit.
CWE_TO_OWASP = {
    22: "A01:2021", 284: "A01:2021", 601: "A01:2021", 352: "A01:2021", 377: "A01:2021", 732: "A01:2021",
    259: "A07:2021", 287: "A07:2021", 295: "A07:2021", 521: "A07:2021", 798: "A07:2021",
    261: "A02:2021", 319: "A02:2021", 326: "A02:2021", 327: "A02:2021", 328: "A02:2021", 330: "A02:2021", 347: "A02:2021",
    20: "A03:2021", 74: "A03:2021", 77: "A03:2021", 78: "A03:2021", 79: "A03:2021", 89: "A03:2021",
    94: "A03:2021", 95: "A03:2021", 643: "A03:2021", 917: "A03:2021",
    209: "A04:2021", 400: "A04:2021", 703: "A04:2021", 754: "A04:2021",
    16: "A05:2021", 489: "A05:2021", 611: "A05:2021", 605: "A05:2021", 1004: "A05:2021", 942: "A05:2021",
    1104: "A06:2021", 1395: "A06:2021",
    345: "A08:2021", 494: "A08:2021", 502: "A08:2021", 829: "A08:2021",
    117: "A09:2021", 532: "A09:2021", 778: "A09:2021",
    918: "A10:2021",
}


def owasp_for_cwe(cwe: Optional[str]) -> Optional[str]:
    if not cwe:
        return None
    try:
        num = int(str(cwe).upper().replace("CWE-", ""))
    except ValueError:
        return None
    return CWE_TO_OWASP.get(num)
