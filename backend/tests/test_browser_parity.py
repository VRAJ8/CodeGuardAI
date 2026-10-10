"""The in-browser engine reads rules.generated.json and is held to parity.golden.json, both generated from this
engine by codeguard.browser_export. These tests fail when either is stale, so changing a rule means regenerating."""
import asyncio
import re

import pytest

from codeguard import browser_export as bx
from codeguard.engine import scan
from codeguard.models import SourceFile
from codeguard.scanners.complexity import analyze_file


@pytest.fixture(scope="module")
def outputs():
    # build() also proves the golden is identical under 3.11/3.12 summation and nudged libm, and that no
    # provider-format secret ends up in anything committed.
    return bx.build()


def test_generated_files_are_up_to_date(outputs):
    stale = [str(p.relative_to(bx.BACKEND.parent)) for p in bx.stale(outputs)]
    assert not stale, f"{', '.join(stale)} out of date with the Python engine: run `{bx.REGEN}`"


def test_secret_self_check_catches_provider_literals(outputs):
    assert bx.secret_hits({"x": bx.substitute("token = '__FAKE_GITHUB_TOKEN__'")}) == ["x: SEC-GITHUB"]
    assert bx.secret_hits({str(p): text for p, text in outputs.items()}) == []


@pytest.mark.parametrize("pattern", [
    r"\Aabc", r"abc\Z", r"\Bx", r"a*+", r"a{2}+", r"(?>a)", r"(a)?(?(1)b|c)", r"(?i:a)b", r"(?x)a b", r"(?a)\w",
    r"(?i)(a)\1", r"[\W.]", r"x(?#c)\N{BULLET}\u00e9\0",
])
def test_regex_translation_fails_loudly_instead_of_approximating(pattern):
    if pattern.startswith("x(?#"):  # the control: these are supported
        assert bx.regex(pattern, "search")["pattern"] == r"x\u{2022}\u{e9}\u{0}"
        return
    with pytest.raises(bx.Untranslatable):
        bx.regex(pattern, "search")


def test_ignorecase_is_compiled_into_explicit_sets():
    spec = bx.regex(re.compile(r"(?i)kiss"), "search")
    assert spec["flags"] == "u" and spec["pattern"] == r"[Kk\u{212a}][Ii\u{130}\u{131}][Ss\u{17f}][Ss\u{17f}]"


def test_match_specs_are_anchored():
    assert bx.regex(re.compile(r"a|b"), "match")["pattern"] == "^(?:a|b)"


def test_heuristic_complexity_is_opt_in_for_python():
    src = "def f(a):\n    if a:\n        return {'k': {'v': 1}}\n"
    radon, heuristic = analyze_file(src, "f.py", "python"), analyze_file(src, "f.py", "python", heuristic=True)
    assert (radon.cyclomatic, radon.max_cyclomatic) == (2.0, 2)  # Radon by default
    # heuristic=True measures Python exactly as any other language
    assert heuristic == analyze_file(src, "f.js", "javascript").model_copy(update={"file_path": "f.py", "language": "python"})


def test_browser_scan_semantics():
    files = [SourceFile(path="a.py", content="eval(x)\n", language="python", lines=2)]
    report = asyncio.run(scan(files, use_bandit=False, use_semgrep=False, use_osv=False, radon=False))
    assert report.scanners_run == ["patterns", "secrets", "complexity"]
    assert [f.rule_id for f in report.security_issues] == ["CG-EVAL"]  # Bandit-overlap rules stay on without Bandit
