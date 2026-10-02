import pytest

from codeguard.engine import scan
from codeguard.exporters import to_sarif
from codeguard.models import SourceFile
from codeguard.suppressions import parse


def src(path, content, lang="javascript"):
    return SourceFile(path=path, content=content, language=lang, lines=content.count("\n") + 1)


async def run(*files, **kw):
    return await scan(list(files), use_bandit=False, use_semgrep=False, use_osv=False, **kw)


def rules_by_line(content):
    return {line: [sorted(d.rules) for d in ds] for line, ds in parse(content).by_line.items()}


class TestParsing:
    def test_valid_markers(self):
        assert rules_by_line(
            "a()  // codeguard-ignore\n"
            "# codeguard-ignore-next-line: CG-EVAL, bandit-b307 -- reviewed\n"
            "b()\n"
            "{/* codeguard-ignore */}\n"
            "c() /* codeguard-ignore: CG-EVAL */\n"
        ) == {1: [["*"]], 3: [["BANDIT-B307", "CG-EVAL"]], 4: [["*"]], 5: [["CG-EVAL"]]}

    def test_justification_is_captured(self):
        [d] = parse("// codeguard-ignore-next-line: CG-EVAL -- demo only\nx\n").by_line[2]
        assert d.justification == "demo only" and d.marker_line == 1

    @pytest.mark.parametrize("line", [
        'const s = "codeguard-ignore"; eval(a);',                # inside a string literal
        "const s = '// codeguard-ignore'; eval(a);",             # comment leader inside a string
        "fetch('https://x.test/codeguard-ignored'); eval(a);",   # URL / longer word
        "eval(x); // nocodeguard-ignore",                        # lookalike word
        "eval(x); // see codeguard-ignore docs",                 # prose, not directly after the leader
        "eval(x); // codeguard-ignore-file",                     # unknown directive
    ])
    def test_non_markers_are_not_markers(self, line):
        assert parse(line).by_line == {}

    @pytest.mark.parametrize("line", [
        "eval(x); // codeguard-ignore CG-EVAL",       # missing colon
        "eval(x); // codeguard-ignore(CG-EVAL)",
        "eval(x); // codeguard-ignore=CG-EVAL",
        "eval(x); // codeguard-ignore: false positive, reviewed",  # prose where rule ids belong
    ])
    def test_malformed_markers_fail_closed_with_a_warning(self, line):
        result = parse(line, "a.js")
        assert result.by_line == {} or all("*" not in d.rules for ds in result.by_line.values() for d in ds)
        if not result.by_line:
            assert result.warnings and "malformed" in result.warnings[0]

    def test_crlf_files(self):
        assert rules_by_line("x // codeguard-ignore\r\ny\r\n") == {1: [["*"]]}


@pytest.mark.asyncio
async def test_suppressed_findings_are_kept_reported_and_not_scored():
    code = (
        "el.innerHTML = a;  // codeguard-ignore -- sanitized upstream\n"
        "// codeguard-ignore-next-line: cg-eval\n"
        "eval(b);\n"
        "eval(c);\n"
    )
    report = await run(src("a.js", code))
    assert [(f.rule_id, f.line_number) for f in report.security_issues] == [("CG-EVAL", 4)]
    assert {(f.rule_id, f.line_number) for f in report.suppressed_issues} == {("CG-XSS-INNERHTML", 1), ("CG-EVAL", 3)}
    assert report.suppressed == 2
    assert report.severity_counts["high"] == 1  # only the unsuppressed eval counts
    xss = next(f for f in report.suppressed_issues if f.rule_id == "CG-XSS-INNERHTML")
    assert xss.suppression.justification == "sanitized upstream"

    sarif = to_sarif(report.security_issues, report.suppressed_issues)
    results = sarif["runs"][0]["results"]
    assert len(results) == 3
    marked = [r for r in results if "suppressions" in r]
    assert len(marked) == 2 and all(r["suppressions"][0]["kind"] == "inSource" for r in marked)


@pytest.mark.asyncio
async def test_rule_scoped_marker_does_not_hide_other_rules():
    code = "// codeguard-ignore-next-line: CG-SQLI-CONCAT\nel.innerHTML = q; eval(q);\n"
    report = await run(src("a.js", code))
    assert {f.rule_id for f in report.security_issues} == {"CG-XSS-INNERHTML", "CG-EVAL"}
    assert report.suppressed == 0


@pytest.mark.asyncio
async def test_malformed_marker_is_reported_and_hides_nothing():
    report = await run(src("a.js", "el.innerHTML = q; eval(q);  // codeguard-ignore CG-EVAL\n"))
    assert {f.rule_id for f in report.security_issues} == {"CG-XSS-INNERHTML", "CG-EVAL"}
    assert report.warnings and "a.js:1" in report.warnings[0]


@pytest.mark.asyncio
async def test_fingerprints_survive_line_shifts_and_markers():
    before = await run(src("a.js", "eval(a);\nel.innerHTML = b;\neval(a);\n"))
    after = await run(src("a.js", "// new header line\neval(a);\nel.innerHTML = b;  // codeguard-ignore\neval(a);\n"))
    fp = lambda r: {(f.rule_id, f.fingerprint) for f in r.security_issues + r.suppressed_issues}  # noqa: E731
    assert fp(before) == fp(after)
    # identical lines in one file still get distinct identities
    assert len({f.fingerprint for f in before.security_issues}) == len(before.security_issues) == 3
