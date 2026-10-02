"""Standard-format exports: SARIF 2.1.0 (GitHub Code Scanning) and CycloneDX 1.5 SBOM."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from . import __version__
from .models import Dependency, Finding
from .taxonomy import OWASP_TOP10

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "2.0"}


def to_sarif(findings: List[Finding], suppressed: Optional[List[Finding]] = None) -> dict:
    """Active findings become results; suppressed ones are emitted too, carrying SARIF `suppressions`."""
    rules: Dict[str, dict] = {}
    results = []
    for f in list(findings) + list(suppressed or []):
        if f.rule_id not in rules:
            tags = ["security", f.scanner]
            if f.cwe:
                tags.append(f"external/cwe/{f.cwe.lower()}")
            if f.owasp:
                tags.append(f"owasp/{f.owasp}")
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.type,
                "shortDescription": {"text": f.type},
                "fullDescription": {"text": f.description[:1000]},
                "help": {"text": f.recommendation, "markdown": f"**Fix:** {f.recommendation}"},
                "defaultConfiguration": {"level": SARIF_LEVEL[f.severity]},
                "properties": {"tags": tags, "security-severity": SECURITY_SEVERITY[f.severity], "precision": "medium"},
            }
        location = {"physicalLocation": {"artifactLocation": {"uri": f.file_path}}}
        if f.line_number:
            location["physicalLocation"]["region"] = {"startLine": f.line_number}
        results.append({
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.description}\n\nFix: {f.recommendation}"},
            "locations": [location],
            "partialFingerprints": {"codeguard/v1": f.fingerprint},
            "properties": {"severity": f.severity, "cwe": f.cwe, "owasp": f.owasp},
        })
        if f.suppression:
            results[-1]["suppressions"] = [{
                "kind": "inSource", "status": "accepted",
                "justification": f.suppression.justification or "codeguard-ignore marker",
            }]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "CodeGuard AI",
                "informationUri": "https://github.com/VRAJ8/CodeGuardAI",
                "semanticVersion": __version__,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def to_cyclonedx(deps: List[Dependency], project_name: str) -> dict:
    components, vulns = [], []
    for d in deps:
        components.append({
            "type": "library",
            "bom-ref": d.purl,
            "name": d.name,
            "version": d.version or "unknown",
            "purl": d.purl,
            "scope": "optional" if d.dev else "required",
            "properties": [{"name": "codeguard:manifest", "value": d.manifest}],
        })
        for v in d.vulnerabilities:
            entry = {
                "bom-ref": f"{v.id}:{d.purl}",
                "id": v.id,
                "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{v.id}"},
                "ratings": [{"severity": v.severity, **({"score": v.cvss, "method": "CVSSv31"} if v.cvss else {})}],
                "description": v.summary,
                "affects": [{"ref": d.purl}],
            }
            if v.fixed_in:
                entry["recommendation"] = f"Upgrade to {v.fixed_in}"
            vulns.append(entry)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {"components": [{"type": "application", "name": "CodeGuard AI", "version": __version__}]},
            "component": {"type": "application", "name": project_name, "bom-ref": "root"},
        },
        "components": components,
        "vulnerabilities": vulns,
    }


def owasp_label(code: str) -> str:
    return f"{code.split(':')[0]} {OWASP_TOP10.get(code, '')}".strip()
