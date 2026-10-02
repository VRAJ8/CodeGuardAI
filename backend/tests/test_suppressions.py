import pytest

from codeguard.engine import scan
from codeguard.models import SourceFile
from codeguard.suppressions import directives


def src(path, content, lang="javascript"):
    return SourceFile(path=path, content=content, language=lang, lines=content.count("\n") + 1)


def test_directive_parsing():
    d = directives("a()  // codeguard-ignore\n# codeguard-ignore-next-line: CG-EVAL, BANDIT-B307\nb()\n")
    assert d == {1: {"*"}, 3: {"CG-EVAL", "BANDIT-B307"}}


@pytest.mark.asyncio
async def test_same_line_and_next_line_suppression_are_counted():
    code = (
        "el.innerHTML = a;  // codeguard-ignore\n"
        "// codeguard-ignore-next-line: CG-EVAL\n"
        "eval(b);\n"
        "eval(c);\n"
    )
    report = await scan([src("a.js", code)], use_bandit=False, use_semgrep=False, use_osv=False)
    assert [(f.rule_id, f.line_number) for f in report.security_issues] == [("CG-EVAL", 4)]
    assert report.suppressed == 2


@pytest.mark.asyncio
async def test_rule_scoped_marker_does_not_hide_other_rules():
    code = "// codeguard-ignore-next-line: CG-SQLI-CONCAT\nel.innerHTML = q; eval(q);\n"
    report = await scan([src("a.js", code)], use_bandit=False, use_semgrep=False, use_osv=False)
    assert {f.rule_id for f in report.security_issues} == {"CG-XSS-INNERHTML", "CG-EVAL"}
    assert report.suppressed == 0
