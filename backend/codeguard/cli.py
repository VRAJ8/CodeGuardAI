"""`python -m codeguard scan <path>` — run CodeGuard locally or in CI.

Exit code 1 when any finding meets --fail-on, so it can gate pull requests.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from . import __version__
from .engine import scan
from .exporters import to_cyclonedx, to_sarif
from .models import SEVERITIES
from .sources import load_directory

COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}
RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"


def _table(report, use_color: bool) -> str:
    c = (lambda code: code) if use_color else (lambda code: "")
    out = [f"{c(BOLD)}CodeGuard AI v{__version__}{c(RESET)}  "
           f"grade {c(BOLD)}{report.grade}{c(RESET)}  score {report.overall_score}/100  "
           f"{report.metrics.total_files} files · {report.metrics.total_lines:,} lines · {report.duration_ms} ms",
           f"{c(DIM)}scanners: {', '.join(report.scanners_run)}{c(RESET)}"]
    out += [f"{c(COLORS['high'])}error: {e}{c(RESET)}" for e in report.errors]
    out += [f"{c(COLORS['medium'])}warning: {w}{c(RESET)}" for w in report.warnings] + [""]
    for f in report.security_issues:
        loc = f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path
        out.append(f"  {c(COLORS[f.severity])}{f.severity.upper():<8}{c(RESET)} {f.type}")
        out.append(f"           {c(DIM)}{loc}  [{f.rule_id}{' · ' + f.cwe if f.cwe else ''}]{c(RESET)}")
    counts = " ".join(f"{s}={report.severity_counts[s]}" for s in SEVERITIES)
    for f in report.suppressed_issues:
        why = f" -- {f.suppression.justification}" if f.suppression and f.suppression.justification else ""
        out.append(f"  {c(DIM)}SUPPRESSED {f.type}  {f.file_path}:{f.line_number}  [{f.rule_id}]{why}{c(RESET)}")
    suppressed = f", {report.suppressed} suppressed inline (listed above, not counted)" if report.suppressed else ""
    out += ["", f"{len(report.security_issues)} findings ({counts}){suppressed}"]
    return "\n".join(out)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="codeguard", description="DevSecOps scanner: SAST, secrets, SCA, code health.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a directory")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--format", choices=["table", "json", "sarif", "sbom"], default="table")
    s.add_argument("--output", "-o", help="write the report to this file instead of stdout")
    s.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="high",
                   help="exit 1 if a finding at or above this severity exists (default: high)")
    s.add_argument("--no-bandit", action="store_true")
    s.add_argument("--no-semgrep", action="store_true")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="skip paths matching this glob or directory prefix (repeatable)")
    s.add_argument("--offline", action="store_true", help="skip the OSV.dev dependency lookup")
    parser.add_argument("--version", action="version", version=f"codeguard {__version__}")
    args = parser.parse_args(argv)

    root = Path(args.path)
    if not root.is_dir():
        parser.error(f"{root} is not a directory")
    files = load_directory(str(root), exclude=args.exclude)
    report = asyncio.run(scan(files, use_bandit=not args.no_bandit, use_semgrep=not args.no_semgrep,
                              use_osv=not args.offline))

    if args.format == "table":
        text = _table(report, use_color=sys.stdout.isatty() and not args.output)
    elif args.format == "json":
        text = report.model_dump_json(indent=2)
    elif args.format == "sarif":
        text = json.dumps(to_sarif(report.security_issues, report.suppressed_issues), indent=2)
    else:
        text = json.dumps(to_cyclonedx(report.dependencies, root.resolve().name), indent=2)

    if args.output:
        Path(args.output).write_text(text)
        print(f"wrote {args.format} report to {args.output} — grade {report.grade}, "
              f"{len(report.security_issues)} findings", file=sys.stderr)
    else:
        print(text)

    if args.fail_on != "none":
        if report.errors:
            # Fail closed: a gate whose audit did not run must not report a pass.
            for e in report.errors:
                print(f"codeguard: {e}; failing because --fail-on is set (use --offline to skip OSV explicitly)",
                      file=sys.stderr)
            return 2
        threshold = SEVERITIES.index(args.fail_on)
        if any(SEVERITIES.index(f.severity) <= threshold for f in report.security_issues):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
