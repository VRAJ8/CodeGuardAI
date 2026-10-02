"""API tests against an in-memory Mongo (mongomock-motor). Background tasks run inline in TestClient."""
import io
import os
import zipfile
from pathlib import Path

import pytest

os.environ["ALLOW_DEV_LOGIN"] = "true"
os.environ.pop("GROQ_API_KEY", None)
os.environ.pop("EMERGENT_LLM_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402
from mongomock_motor import AsyncMongoMockClient  # noqa: E402

import codeguard.engine  # noqa: E402
import server  # noqa: E402
from conftest import FAKE_STRIPE  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable_app"


async def _no_osv(deps, client=None):
    return deps


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setattr(server, "db", AsyncMongoMockClient()["test"])
    monkeypatch.setattr(server, "ALLOW_DEV_LOGIN", True)
    monkeypatch.setattr(codeguard.engine, "enrich_with_osv", _no_osv)
    with TestClient(server.app, base_url="https://testserver") as c:
        yield c


def fixture_zip(extra: dict = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for p in FIXTURE.iterdir():
            zf.writestr(f"vulnerable_app/{p.name}", p.read_text().replace("__FAKE_STRIPE_KEY__", FAKE_STRIPE))
        for name, content in (extra or {}).items():
            zf.writestr(f"vulnerable_app/{name}", content)
    return buf.getvalue()


def login(c):
    r = c.post("/api/auth/dev-login")
    assert r.status_code == 200
    return r.json()


def upload(c, data: bytes, name="demo.zip"):
    r = c.post("/api/analysis/upload", files={"file": (name, data, "application/zip")})
    assert r.status_code == 202, r.text
    return r.json()["analysis_id"]


def test_requires_auth(api):
    assert api.get("/api/analysis/list").status_code == 401


def test_dev_login_disabled_by_default(api, monkeypatch):
    monkeypatch.setattr(server, "ALLOW_DEV_LOGIN", False)
    assert api.post("/api/auth/dev-login").status_code == 404


def test_health_reports_engines(api):
    body = api.get("/api/health").json()
    assert body["status"] == "healthy" and body["engines"]["radon"] is True


def test_upload_scan_lifecycle(api):
    login(api)
    aid = upload(api, fixture_zip())
    doc = api.get(f"/api/analysis/{aid}").json()
    assert doc["status"] == "completed", doc.get("error")
    assert doc["grade"] == "F" and doc["progress"]["pct"] == 100
    assert doc["severity_counts"]["critical"] >= 3
    assert any(i["file_path"] == "app.py" and i["line_number"] for i in doc["security_issues"])
    assert doc["baseline"] is None

    listing = api.get("/api/analysis/list").json()
    assert listing[0]["analysis_id"] == aid and "security_issues" not in listing[0]
    assert listing[0]["issue_count"] == len(doc["security_issues"])

    sarif = api.get(f"/api/analysis/{aid}/sarif")
    assert sarif.status_code == 200 and "attachment" in sarif.headers["content-disposition"]
    assert sarif.json()["version"] == "2.1.0"
    sbom = api.get(f"/api/analysis/{aid}/sbom").json()
    assert sbom["bomFormat"] == "CycloneDX" and len(sbom["components"]) == 7

    badge = api.get(f"/api/badge/{aid}.svg")
    assert badge.headers["content-type"].startswith("image/svg") and b"codeguard" in badge.content


def test_rescan_tracks_new_and_fixed_findings(api):
    login(api)
    upload(api, fixture_zip())
    aid = upload(api, fixture_zip({"extra.js": "el.innerHTML = location.hash;\n"}))
    doc = api.get(f"/api/analysis/{aid}").json()
    assert doc["baseline"]["new"] == 1 and doc["baseline"]["fixed"] == 0
    assert [i["file_path"] for i in doc["security_issues"] if i.get("is_new")] == ["extra.js"]


def test_suppressing_a_finding_is_not_counted_as_fixed(api):
    login(api)
    upload(api, fixture_zip({"extra.js": "el.innerHTML = location.hash;\n"}))
    aid = upload(api, fixture_zip({"extra.js": "el.innerHTML = location.hash;  // codeguard-ignore -- trusted\n"}))
    doc = api.get(f"/api/analysis/{aid}").json()
    assert doc["baseline"]["fixed"] == 0 and doc["baseline"]["suppressed"] == 1
    assert [i["file_path"] for i in doc["suppressed_issues"]] == ["extra.js"]
    assert doc["suppressed_issues"][0]["suppression"]["justification"] == "trusted"
    sarif = api.get(f"/api/analysis/{aid}/sarif").json()
    assert any(r.get("suppressions") for r in sarif["runs"][0]["results"])
    assert "suppressed_issues" not in api.get("/api/analysis/list").json()[0]


def _upload_files(api, files: dict):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(f"proj/{name}", content)
    return api.get(f"/api/analysis/{upload(api, buf.getvalue(), 'proj.zip')}").json()


def test_rotated_credential_is_new_and_old_one_fixed(api):
    login(api)
    _upload_files(api, {"cfg.py": 'db_password = "Xk9mQ2pL"\n\n\n'})
    doc = _upload_files(api, {"cfg.py": '\n\n\napi_secret = "Zr7wT4nB"\n'})
    assert doc["baseline"]["new"] == 1 and doc["baseline"]["fixed"] == 1
    assert [i["line_number"] for i in doc["security_issues"] if i.get("is_new")] == [4]


def test_new_finding_after_a_scan_with_only_suppressed_findings_is_new(api):
    login(api)
    _upload_files(api, {"a.js": "el.innerHTML = location.hash;  // codeguard-ignore -- trusted\n"})
    doc = _upload_files(api, {"a.js": "el.innerHTML = location.hash;  // codeguard-ignore -- trusted\neval(location.hash);\n"})
    assert doc["baseline"]["comparable"] is True
    assert [i["rule_id"] for i in doc["security_issues"] if i.get("is_new")] == ["CG-EVAL"]


def test_bandit_marker_is_not_counted_as_fixed(api):
    login(api)
    body = "import pickle\n\n\ndef load(blob):\n    return pickle.loads(blob)\n"
    _upload_files(api, {"m.py": body})
    doc = _upload_files(api, {"m.py": "# header\n" + body.replace("loads(blob)", "loads(blob)  # codeguard-ignore -- trusted")})
    assert doc["baseline"]["fixed"] == 0 and doc["baseline"]["new"] == 0 and doc["baseline"]["suppressed"] == 1


V2_ISSUES = [
    {"severity": "critical", "type": "Hardcoded Secret Detection", "description": "Potential AWS_KEY found", "file_path": "a.py",
     "line_number": None, "recommendation": "rotate"},
    {"severity": "critical", "type": "Hardcoded Secret Detection", "description": "Potential GENERIC_SECRET found",
     "file_path": "a.py", "line_number": None, "recommendation": "rotate"},
    {"severity": "high", "type": "Vulnerable Dependency (CVE-2021-23337)", "description": "lodash", "file_path": "package.json",
     "line_number": None, "recommendation": "upgrade"},
    {"severity": "low", "type": "Code annotation found", "description": "Found: # TODO", "file_path": "b.py", "line_number": 3,
     "recommendation": "address"},
]


def _insert_v2(api, user_id, **extra):
    from datetime import datetime, timedelta, timezone
    doc = {"analysis_id": extra.pop("analysis_id", "analysis_v2doc"), "user_id": user_id, "name": "acme/legacy",
           "source_type": "github", "source_url": "https://github.com/acme/legacy", "status": "completed",
           "created_at": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(), "overall_score": 12.0,
           "metrics": {"total_files": 3, "total_lines": 100, "languages": {"python": 100}}, "security_issues": V2_ISSUES,
           "bug_risks": [], "ai_summary": "", "recommendations": [], "ai_fixes": [], "ai_refactors": [], **extra}
    api.portal.call(server.db.analyses.insert_one, doc)
    return doc["analysis_id"]


def test_stale_processing_scans_expire_instead_of_locking_the_user_out(api):
    from datetime import datetime, timedelta, timezone
    user = login(api)
    old = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
    for n in range(3):
        _insert_v2(api, user["user_id"], analysis_id=f"analysis_stuck{n}", status="processing", created_at=old)
    fresh = _insert_v2(api, user["user_id"], analysis_id="analysis_fresh", status="processing",
                       created_at=datetime.now(timezone.utc).isoformat())
    assert api.get("/api/analysis/stats/dashboard").json()["running"] == 1  # only the fresh one
    stuck = api.get("/api/analysis/analysis_stuck0").json()
    assert stuck["status"] == "failed" and "interrupted" in stuck["error"]
    assert api.get(f"/api/analysis/{fresh}").json()["status"] == "processing"
    assert api.post("/api/analysis/upload", files={"file": ("x.zip", fixture_zip(), "application/zip")}).status_code == 202


def test_v2_documents_render_correctly_through_the_v3_api(api):
    user = login(api)
    aid = _insert_v2(api, user["user_id"])
    stats = api.get("/api/analysis/stats/dashboard").json()
    assert stats["secrets"] == 2 and stats["vulnerable_dependencies"] == 1
    assert stats["scanners"] == {"secrets": 2, "osv": 1, "patterns": 1}

    sarif = api.get(f"/api/analysis/{aid}/sarif").json()["runs"][0]
    rules = {r["id"]: r for r in sarif["tool"]["driver"]["rules"]}
    assert "LEGACY-Code-annotation-found" in rules and rules["LEGACY-Code-annotation-found"]["defaultConfiguration"]["level"] == "note"
    fps = [r["partialFingerprints"]["codeguard/v2"] for r in sarif["results"]]
    assert len(fps) == len(set(fps)) == 4

    sbom = api.get(f"/api/analysis/{aid}/sbom")
    assert sbom.status_code == 409 and "predates" in sbom.json()["detail"]


def test_no_score_delta_against_a_v2_scan(api):
    user = login(api)
    _insert_v2(api, user["user_id"], name="vulnerable_app", source_url=None, source_type="zip")
    aid = upload(api, fixture_zip(), "vulnerable_app.zip")
    baseline = api.get(f"/api/analysis/{aid}").json()["baseline"]
    assert baseline["score_delta"] is None and baseline["comparable"] is False
    assert baseline["new"] == 0 and baseline["fixed"] == 0


def test_dashboard_aggregates(api):
    login(api)
    upload(api, fixture_zip())
    stats = api.get("/api/analysis/stats/dashboard").json()
    assert stats["total_analyses"] == 1 and stats["projects"] == 1
    assert stats["posture_grade"] == "F"
    assert sum(stats["severity"].values()) == stats["total_issues"] > 0
    assert len(stats["owasp"]) == 10 and stats["secrets"] >= 2
    assert len(stats["activity"]) == 28 and stats["activity"][-1]["count"] == 1 and stats["streak"] == 1
    assert stats["riskiest"][0]["grade"] == "F"


def test_rejects_bad_input(api):
    login(api)
    assert api.post("/api/analysis/upload", files={"file": ("x.txt", b"hi")}).status_code == 400
    assert api.post("/api/analysis/github", json={"github_url": "https://gitlab.com/a/b"}).status_code == 400
    aid = upload(api, b"not-a-zip")
    doc = api.get(f"/api/analysis/{aid}").json()
    assert doc["status"] == "failed" and "valid ZIP" in doc["error"]


def test_users_cannot_read_each_others_scans(api):
    login(api)
    aid = upload(api, fixture_zip())
    api.portal.call(server.db.users.insert_one, {"user_id": "user_other", "email": "o@x.io", "name": "Other"})
    api.portal.call(server.db.user_sessions.insert_one, {
        "user_id": "user_other", "session_token": "other-token", "expires_at": "2999-01-01T00:00:00+00:00"})
    api.cookies.clear()
    headers = {"Authorization": "Bearer other-token"}
    assert api.get(f"/api/analysis/{aid}", headers=headers).status_code == 404
    assert api.delete(f"/api/analysis/{aid}", headers=headers).status_code == 404
    assert api.get(f"/api/analysis/{aid}/sarif", headers=headers).status_code == 404
    assert api.get("/api/analysis/list", headers=headers).json() == []


def test_delete(api):
    login(api)
    aid = upload(api, fixture_zip())
    assert api.delete(f"/api/analysis/{aid}").status_code == 200
    assert api.get(f"/api/analysis/{aid}").status_code == 404
