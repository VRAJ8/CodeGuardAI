import io
import json
import zipfile

import pytest

from codeguard import cli
from codeguard.engine import scan
from codeguard.exporters import to_cyclonedx, to_sarif
from codeguard.scanners.external import semgrep_available
from codeguard.scoring import grade_for, security_score
from codeguard.sources import load_directory, load_zip, parse_github_url, SourceError



def make_zip(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


class TestSources:
    def test_zip_strips_github_prefix_and_skips_vendor_dirs(self):
        data = make_zip({
            "owner-repo-abc123/src/app.py": "print('hi')",
            "owner-repo-abc123/node_modules/x/index.js": "eval(x)",
            "owner-repo-abc123/package-lock.json": "{}",
            "owner-repo-abc123/dist/app.min.js": "x",
            "owner-repo-abc123/.env": "SECRET=1",
        })
        assert sorted(f.path for f in load_zip(data)) == [".env", "src/app.py"]

    def test_zip_rejects_path_traversal(self):
        assert [f.path for f in load_zip(make_zip({"../../etc/evil.py": "x", "ok.py": "y"}))] == ["ok.py"]

    def test_invalid_zip(self):
        with pytest.raises(SourceError):
            load_zip(b"not a zip")

    @pytest.mark.parametrize("url,expected", [
        ("https://github.com/psf/requests", ("psf", "requests", None)),
        ("https://github.com/psf/requests.git", ("psf", "requests", None)),
        ("https://github.com/vercel/next.js/tree/canary", ("vercel", "next.js", "canary")),
    ])
    def test_parse_github_url(self, url, expected):
        assert parse_github_url(url) == expected

    def test_parse_github_url_rejects_other_hosts(self):
        with pytest.raises(SourceError):
            parse_github_url("https://gitlab.com/a/b")


class TestScoring:
    def test_grades(self):
        assert [grade_for(s) for s in (95, 85, 75, 65, 10)] == ["A", "B", "C", "D", "F"]

    def test_security_score_is_monotonic(self):
        from codeguard.models import Finding
        f = lambda sev: Finding(rule_id="x", scanner="patterns", severity=sev, type="t", description="d",
                                file_path="a", recommendation="r")
        assert security_score([]) == 100
        assert security_score([f("low")]) > security_score([f("critical")]) > security_score([f("critical")] * 3)


@pytest.mark.asyncio
async def test_fixture_scan_end_to_end(vulnerable_app):
    report = await scan(load_directory(str(vulnerable_app)), use_osv=False)
    ids = {f.rule_id for f in report.security_issues}
    assert {"SEC-STRIPE", "SEC-GENERIC", "CG-XSS-INNERHTML", "CG-EVAL"} <= ids
    assert any(f.cwe == "CWE-89" for f in report.security_issues)
    assert any(f.cwe == "CWE-78" for f in report.security_issues)
    assert report.grade == "F" and report.severity_counts["critical"] >= 3
    assert report.owasp_counts["A03:2021"] >= 3
    assert {d.ecosystem for d in report.dependencies} == {"npm", "PyPI"}
    assert report.bug_risks[0].file_path == "app.py"
    # No duplicate findings for the same line + weakness.
    keys = [(f.file_path, f.line_number, f.cwe) for f in report.security_issues]
    assert len(keys) == len(set(keys))


@pytest.mark.asyncio
@pytest.mark.skipif(not semgrep_available(), reason="semgrep not installed")
async def test_semgrep_rule_pack(vulnerable_app):
    report = await scan(load_directory(str(vulnerable_app)), use_osv=False, use_bandit=False)
    ids = {f.rule_id for f in report.security_issues if f.scanner == "semgrep"}
    assert {"SEMGREP-flask-ssti", "SEMGREP-express-sqli-taint", "SEMGREP-jwt-hardcoded-secret"} <= ids


@pytest.mark.asyncio
async def test_sarif_and_sbom_shapes(vulnerable_app):
    report = await scan(load_directory(str(vulnerable_app)), use_osv=False)
    sarif = to_sarif(report.security_issues)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "CodeGuard AI"
    assert len(run["results"]) == len(report.security_issues)
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert all(r["ruleId"] in rule_ids for r in run["results"])
    assert all("security-severity" in r["properties"] for r in run["tool"]["driver"]["rules"])

    bom = to_cyclonedx(report.dependencies, "demo")
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
    assert "pkg:npm/lodash@4.17.11" in {c["purl"] for c in bom["components"]}


def test_cli_exit_codes_and_sarif_output(tmp_path, capsys, vulnerable_app):
    out = tmp_path / "r.sarif"
    assert cli.main(["scan", str(vulnerable_app), "--offline", "--format", "sarif", "-o", str(out)]) == 1
    assert json.loads(out.read_text())["version"] == "2.1.0"
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "ok.py").write_text("def add(a, b):\n    return a + b\n")
    assert cli.main(["scan", str(clean), "--offline"]) == 0
    assert "grade A" in capsys.readouterr().out


def test_cli_exclude(tmp_path):
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "bad.js").write_text("eval(x)\n")
    (tmp_path / "ok.py").write_text("x = 1\n")
    assert cli.main(["scan", str(tmp_path), "--offline"]) == 1
    assert cli.main(["scan", str(tmp_path), "--offline", "--exclude", "fixtures"]) == 0
    assert cli.main(["scan", str(tmp_path), "--offline", "--exclude", "*.js"]) == 0
