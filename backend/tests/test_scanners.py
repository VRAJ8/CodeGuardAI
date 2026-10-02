from codeguard.scanners.complexity import analyze_file
from conftest import FAKE_STRIPE
from codeguard.scanners.patterns import scan_patterns
from codeguard.scanners.secrets import redact, scan_secrets, shannon_entropy


def rules(findings):
    return {f.rule_id for f in findings}


class TestSecrets:
    def test_provider_signatures_with_line_numbers(self):
        src = f'a = 1\nKEY = "AKIAIOSFODNN7EXAMPLQ"\nstripe = "{FAKE_STRIPE}"\n'
        found = scan_secrets(src, "cfg.py")
        assert {"SEC-AWS-KEY", "SEC-STRIPE"} <= rules(found)
        assert {f.line_number for f in found} == {2, 3}
        assert all(f.cwe == "CWE-798" and f.owasp == "A07:2021" for f in found)

    def test_values_are_redacted(self):
        found = scan_secrets('token = "ghp_' + "a1B2" * 9 + '"', "x.js")
        assert found and "a1B2a1B2" not in found[0].description
        assert redact("supersecretvalue") == "supe********ue"

    def test_generic_assignment_needs_entropy(self):
        assert rules(scan_secrets('DB_PASSWORD = "Xk9#mQ2vLp8$wZr4"', "a.py")) == {"SEC-GENERIC"}
        assert scan_secrets('password = "aaaaaaaaaa"', "a.py") == []

    def test_placeholders_are_ignored(self):
        src = 'api_key = "${API_KEY}"\nsecret = "your-secret-here"\nurl = "postgres://user:<password>@db/app"'
        assert scan_secrets(src, "a.py") == []

    def test_db_url_with_real_password(self):
        assert rules(scan_secrets('URL = "postgres://admin:Pr0dP4ss!@db.internal:5432/app"', "a.py")) == {"SEC-DB-URL"}

    def test_entropy(self):
        assert shannon_entropy("aaaa") == 0
        assert shannon_entropy("abcd") == 2


class TestPatterns:
    def test_js_eval_and_xss(self):
        src = "el.innerHTML = userInput;\nconst r = eval(code);\nmodel.eval();\n"
        found = scan_patterns(src, "a.js", "javascript")
        assert rules(found) == {"CG-XSS-INNERHTML", "CG-EVAL"}

    def test_comments_are_skipped(self):
        assert scan_patterns("// eval(x)\n# eval(y)", "a.js", "javascript") == []

    def test_bandit_overlap_only_skips_python(self):
        assert scan_patterns("eval(x)", "a.py", "python", skip_bandit_overlap=True) == []
        assert rules(scan_patterns("eval(x)", "a.js", "javascript", skip_bandit_overlap=True)) == {"CG-EVAL"}

    def test_sql_injection_variants(self):
        src = ('q = f"SELECT * FROM users WHERE id = {uid}"\n'
               'db.query("SELECT * FROM t WHERE a = \'" + name + "\'")\n'
               'cur.execute("SELECT * FROM t WHERE id = %s", (uid,))\n')
        found = scan_patterns(src, "a.py", "python")
        assert {f.line_number for f in found if f.cwe == "CWE-89"} == {1, 2}

    def test_weak_hash_respects_usedforsecurity(self):
        assert rules(scan_patterns("hashlib.md5(data)", "a.py", "python")) == {"CG-WEAK-HASH"}
        assert scan_patterns("hashlib.sha1(raw.encode(), usedforsecurity=False)", "a.py", "python") == []

    def test_tls_verification_disabled(self):
        assert rules(scan_patterns("requests.get(u, verify=False)", "a.py", "python")) == {"CG-TLS-OFF"}


class TestComplexity:
    NESTED = """
def tangled(a, b, c, d):
    if a:
        if b:
            for i in range(10):
                if c:
                    while d:
                        if i > 3 and a or b:
                            try:
                                d -= 1
                            except Exception:
                                pass
    elif b and c:
        return 1
    return 0
"""

    def test_python_uses_radon_and_real_nesting(self):
        r = analyze_file(self.NESTED, "t.py", "python")
        assert r.max_cyclomatic >= 9
        assert r.hotspots and r.hotspots[0].name == "tangled"
        assert any("nested" in i.lower() for i in r.issues)
        assert any("empty exception" in i for i in r.issues)
        assert r.maintainability is not None

    def test_clean_file_has_no_risk(self):
        r = analyze_file("def add(a, b):\n    return a + b\n", "ok.py", "python")
        assert r.risk_score == 0 and r.complexity == "low"

    def test_js_heuristics(self):
        src = "function f(x){ try { g() } catch (e) {} if (x && y || z) { return 1 } }"
        r = analyze_file(src, "a.js", "javascript")
        assert r.cyclomatic > 1 and any("empty exception" in i for i in r.issues)

    def test_unparseable_python_does_not_crash(self):
        assert "File could not be parsed" in analyze_file("def (:\n", "bad.py", "python").issues
