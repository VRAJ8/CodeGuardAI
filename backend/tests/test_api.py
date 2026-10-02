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
