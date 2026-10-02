"""CodeGuard AI — FastAPI service.

Scans run as background jobs: POST returns immediately with an analysis_id and the
client polls GET /api/analysis/{id} for `status` + `progress`.
"""
from __future__ import annotations

import logging
import os
import uuid
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

import httpx
from dotenv import load_dotenv
from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware

from codeguard import __version__
from codeguard.ai import ai_enabled, triage
from codeguard.engine import disambiguate_fingerprints, scan
from codeguard.exporters import to_cyclonedx, to_sarif
from codeguard.models import SEVERITIES, Dependency, Finding
from codeguard.scanners.external import bandit_available, semgrep_available
from codeguard.scoring import grade_for
from codeguard.sources import SourceError, load_github, load_zip, parse_github_url
from codeguard.taxonomy import OWASP_TOP10

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("codeguard")

client = AsyncIOMotorClient(os.environ.get("MONGO_URL", "mongodb://localhost:27017"))
db = client[os.environ.get("DB_NAME", "codeguard")]

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_CONCURRENT_SCANS = 3
FINGERPRINT_VERSION = 2  # bump whenever Finding.with_fingerprint changes; see _baseline comparisons
# Scans run in-process, so one still "processing" after this long was killed by a restart or crash (or is a
# v2 leftover) and would otherwise hold a concurrency slot forever. Real scans finish in a few minutes.
STALE_SCAN_AFTER = timedelta(minutes=30)
STALE_SCAN_ERROR = "Scan interrupted (the server restarted or the scan stalled). Re-scan to try again."


async def expire_stale_scans(user_id: Optional[str] = None) -> int:
    cutoff = (datetime.now(timezone.utc) - STALE_SCAN_AFTER).isoformat()
    query = {"status": "processing", "created_at": {"$lt": cutoff}}
    if user_id:
        query["user_id"] = user_id
    result = await db.analyses.update_many(query, {"$set": {
        "status": "failed", "error": STALE_SCAN_ERROR, "progress": {"stage": "Failed", "pct": 100}}})
    return result.modified_count
ALLOW_DEV_LOGIN = os.environ.get("ALLOW_DEV_LOGIN", "").lower() == "true"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        await db.analyses.create_index("analysis_id", unique=True)
        await db.analyses.create_index([("user_id", 1), ("created_at", -1)])
        await db.user_sessions.create_index("session_token")
    except Exception as e:  # pragma: no cover - index creation is best-effort
        log.warning("index creation skipped: %s", e)
    try:
        if expired := await expire_stale_scans():
            log.info("marked %d stale processing scans as failed", expired)
    except Exception as e:  # pragma: no cover
        log.warning("stale-scan cleanup skipped: %s", e)
    yield
    client.close()


app = FastAPI(title="CodeGuard AI", version=__version__, lifespan=lifespan)
api_router = APIRouter(prefix="/api")
auth_router = APIRouter(prefix="/api/auth")
analysis_router = APIRouter(prefix="/api/analysis")


class User(BaseModel):
    user_id: str
    email: str
    name: str
    picture: Optional[str] = None


class AnalysisRequest(BaseModel):
    github_url: Optional[str] = None
    name: Optional[str] = None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# ==================== AUTH ====================

async def get_current_user(request: Request) -> User:
    token = request.cookies.get("session_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else None
    if not token:
        raise HTTPException(401, "Not authenticated")
    session = await db.user_sessions.find_one({"session_token": token}, {"_id": 0})
    if not session:
        raise HTTPException(401, "Invalid session")
    expires = session["expires_at"]
    expires = datetime.fromisoformat(expires) if isinstance(expires, str) else expires
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires < datetime.now(timezone.utc):
        raise HTTPException(401, "Session expired")
    user = await db.users.find_one({"user_id": session["user_id"]}, {"_id": 0})
    if not user:
        raise HTTPException(401, "User not found")
    return User(**user)


async def _start_session(response: Response, email: str, name: str, picture: Optional[str], token: str) -> dict:
    existing = await db.users.find_one({"email": email}, {"_id": 0})
    if existing:
        user_id = existing["user_id"]
        await db.users.update_one({"user_id": user_id}, {"$set": {"name": name, "picture": picture}})
    else:
        user_id = f"user_{uuid.uuid4().hex[:12]}"
        await db.users.insert_one({"user_id": user_id, "email": email, "name": name, "picture": picture,
                                   "created_at": now_iso()})
    await db.user_sessions.insert_one({
        "user_id": user_id, "session_token": token, "created_at": now_iso(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
    })
    response.set_cookie("session_token", token, httponly=True, secure=True, samesite="none", path="/",
                        max_age=7 * 24 * 3600)
    return await db.users.find_one({"user_id": user_id}, {"_id": 0})


@auth_router.post("/session")
async def create_session(request: Request, response: Response):
    """Exchange an Emergent OAuth session_id for a session token."""
    session_id = (await request.json()).get("session_id")
    if not session_id:
        raise HTTPException(400, "session_id required")
    async with httpx.AsyncClient(timeout=15) as http:
        resp = await http.get("https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data",
                              headers={"X-Session-ID": session_id})
    if resp.status_code != 200:
        raise HTTPException(401, "Invalid session_id")
    data = resp.json()
    return await _start_session(response, data.get("email"), data.get("name"), data.get("picture"),
                                data.get("session_token"))


@auth_router.post("/dev-login")
async def dev_login(response: Response):
    """Local-only login for docker-compose / development. Disabled unless ALLOW_DEV_LOGIN=true."""
    if not ALLOW_DEV_LOGIN:
        raise HTTPException(404, "Not found")
    return await _start_session(response, "dev@codeguard.local", "Dev User", None, uuid.uuid4().hex)


@auth_router.get("/me")
async def get_me(user: User = Depends(get_current_user)):
    return user.model_dump()


@auth_router.post("/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get("session_token")
    if token:
        await db.user_sessions.delete_one({"session_token": token})
    response.delete_cookie("session_token", path="/")
    return {"message": "Logged out"}

# ==================== SCAN PIPELINE ====================

def _new_doc(analysis_id: str, user: User, name: str, source_type: str, source_url: Optional[str]) -> dict:
    return {
        "analysis_id": analysis_id, "user_id": user.user_id, "name": name, "source_type": source_type,
        "source_url": source_url, "status": "processing", "progress": {"stage": "Queued", "pct": 5},
        "created_at": now_iso(), "completed_at": None, "metrics": None, "security_issues": [], "bug_risks": [],
        "dependencies": [], "overall_score": None, "grade": None, "ai_summary": None, "recommendations": [],
        "ai_fixes": [], "ai_refactors": [], "engine_version": __version__,
    }


async def _guard_concurrency(user: User):
    await expire_stale_scans(user.user_id)
    running = await db.analyses.count_documents({"user_id": user.user_id, "status": "processing"})
    if running >= MAX_CONCURRENT_SCANS:
        raise HTTPException(429, f"You already have {running} scans running. Wait for one to finish, "
                                 "or delete a stuck one from your scan history.")


async def _baseline(user_id: str, name: str, source_url: Optional[str], analysis_id: str) -> Optional[dict]:
    query = {"user_id": user_id, "status": "completed", "analysis_id": {"$ne": analysis_id}}
    query.update({"source_url": source_url} if source_url else {"name": name})
    cur = db.analyses.find(query, {"_id": 0, "analysis_id": 1, "overall_score": 1, "security_issues.fingerprint": 1,
                                   "suppressed_issues.fingerprint": 1, "fingerprint_version": 1, "engine_version": 1,
                                   "created_at": 1}).sort("created_at", -1).limit(1)
    docs = await cur.to_list(1)
    return docs[0] if docs else None


async def run_pipeline(analysis_id: str, user_id: str, name: str, source_url: Optional[str],
                       zip_bytes: Optional[bytes] = None):
    async def progress(stage: str, pct: int):
        await db.analyses.update_one({"analysis_id": analysis_id}, {"$set": {"progress": {"stage": stage, "pct": pct}}})

    try:
        repo_meta = None
        await progress("Fetching source", 10)
        if source_url:
            files, repo_meta = await load_github(source_url)
        else:
            files = load_zip(zip_bytes or b"")
        if not files:
            raise SourceError("No supported source files were found.")

        report = await scan(files, progress=progress)

        ai = {"summary": "", "recommendations": [], "fixes": [], "refactors": []}
        if ai_enabled():
            await progress("AI triage & patch generation", 85)
            ai = await triage(files, report.security_issues, report.bug_risks)

        prev = await _baseline(user_id, name, source_url, analysis_id)
        baseline = None
        issues = [f.model_dump() for f in report.security_issues]
        if prev:
            # Fingerprints are only comparable within one scheme; older scans (v2 engine, or v3 before
            # fingerprint scheme 2) get a score delta but no new/fixed claims.
            comparable = prev.get("fingerprint_version") == FINGERPRINT_VERSION
            fps = lambda key: {i.get("fingerprint") for i in prev.get(key) or [] if i.get("fingerprint")}  # noqa: E731
            old, old_suppressed = fps("security_issues"), fps("suppressed_issues")
            new_fps = {i["fingerprint"] for i in issues}
            # A finding silenced by a codeguard-ignore marker is not "fixed", and one that was merely
            # un-suppressed is not "new": only real code changes move these numbers.
            suppressed_fps = {f.fingerprint for f in report.suppressed_issues}
            for i in issues:
                i["is_new"] = comparable and i["fingerprint"] not in old | old_suppressed
            baseline = {
                "analysis_id": prev["analysis_id"], "created_at": prev.get("created_at"),
                # v2 used a different scoring formula, so a delta against it would be noise, not progress
                "score_delta": (round(report.overall_score - (prev.get("overall_score") or 0), 1)
                                if prev.get("engine_version") else None),
                "new": sum(1 for i in issues if i.get("is_new")),
                "fixed": len(old - new_fps - suppressed_fps) if comparable else 0,
                "suppressed": len(old & suppressed_fps) if comparable else 0,
                "comparable": comparable,
            }

        await db.analyses.update_one({"analysis_id": analysis_id}, {"$set": {
            "status": "completed",
            "completed_at": now_iso(),
            "progress": {"stage": "Done", "pct": 100},
            "metrics": report.metrics.model_dump(),
            "security_issues": issues,
            "bug_risks": [r.model_dump() for r in report.bug_risks],
            "dependencies": [d.model_dump() for d in report.dependencies],
            "overall_score": report.overall_score,
            "grade": report.grade,
            "severity_counts": report.severity_counts,
            "owasp_counts": report.owasp_counts,
            "scanner_counts": report.scanner_counts,
            "scanners_run": report.scanners_run,
            "suppressed": report.suppressed,
            "suppressed_issues": [f.model_dump() for f in report.suppressed_issues],
            "fingerprint_version": FINGERPRINT_VERSION,
            "scan_errors": report.errors,
            "scan_warnings": report.warnings,
            "duration_ms": report.duration_ms,
            "repo_meta": repo_meta,
            "baseline": baseline,
            "ai_summary": ai.get("summary", ""),
            "recommendations": ai.get("recommendations", []),
            "ai_fixes": ai.get("fixes", []),
            "ai_refactors": ai.get("refactors", []),
        }})
    except SourceError as e:
        await _fail(analysis_id, str(e))
    except Exception as e:
        log.exception("scan %s failed", analysis_id)
        await _fail(analysis_id, f"Scan failed: {type(e).__name__}")


async def _fail(analysis_id: str, message: str):
    await db.analyses.update_one({"analysis_id": analysis_id}, {"$set": {
        "status": "failed", "error": message, "ai_summary": message, "progress": {"stage": "Failed", "pct": 100}}})

# ==================== ANALYSIS ENDPOINTS ====================

@analysis_router.post("/github", status_code=202)
async def analyze_github(req: AnalysisRequest, background: BackgroundTasks, user: User = Depends(get_current_user)):
    if not req.github_url:
        raise HTTPException(400, "github_url is required")
    try:
        owner, repo, _ = parse_github_url(req.github_url)
    except SourceError as e:
        raise HTTPException(400, str(e)) from None
    await _guard_concurrency(user)
    analysis_id = f"analysis_{uuid.uuid4().hex[:12]}"
    name = req.name or f"{owner}/{repo}"
    url = req.github_url.strip()
    await db.analyses.insert_one(_new_doc(analysis_id, user, name, "github", url))
    background.add_task(run_pipeline, analysis_id, user.user_id, name, url)
    return {"analysis_id": analysis_id, "status": "processing"}


@analysis_router.post("/upload", status_code=202)
async def analyze_upload(background: BackgroundTasks, file: UploadFile = File(...),
                         user: User = Depends(get_current_user)):
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(400, "Only ZIP files are supported")
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "ZIP must be 25 MB or smaller")
    await _guard_concurrency(user)
    analysis_id = f"analysis_{uuid.uuid4().hex[:12]}"
    name = Path(file.filename).stem
    await db.analyses.insert_one(_new_doc(analysis_id, user, name, "zip", None))
    background.add_task(run_pipeline, analysis_id, user.user_id, name, None, data)
    return {"analysis_id": analysis_id, "status": "processing"}


LIST_PROJECTION = {"_id": 0, "ai_refactors": 0, "ai_fixes": 0, "dependencies": 0, "bug_risks": 0, "suppressed_issues": 0}


def _counts(doc: dict) -> dict:
    if doc.get("severity_counts"):
        return doc["severity_counts"]
    c = Counter(i.get("severity") for i in doc.get("security_issues", []))
    return {s: c.get(s, 0) for s in SEVERITIES}


def _light(doc: dict) -> dict:
    doc = dict(doc)
    issues = doc.pop("security_issues", []) or []
    doc["severity_counts"] = _counts({**doc, "security_issues": issues})
    doc["issue_count"] = len(issues)
    if doc.get("overall_score") is not None and not doc.get("grade"):
        doc["grade"] = grade_for(doc["overall_score"])
    return doc


@analysis_router.get("/list")
async def list_analyses(user: User = Depends(get_current_user)):
    await expire_stale_scans(user.user_id)
    docs = await db.analyses.find({"user_id": user.user_id}, LIST_PROJECTION).sort("created_at", -1).to_list(200)
    return [_light(d) for d in docs]


@analysis_router.get("/stats/dashboard")
async def dashboard_stats(user: User = Depends(get_current_user)):
    await expire_stale_scans(user.user_id)
    docs = await db.analyses.find(
        {"user_id": user.user_id},
        {"_id": 0, "ai_refactors": 0, "ai_fixes": 0, "bug_risks": 0, "security_issues.description": 0,
         "security_issues.recommendation": 0, "security_issues.snippet": 0, "suppressed_issues": 0},
    ).sort("created_at", -1).to_list(500)
    return build_dashboard(docs)


def _scanner_of(issue: dict) -> str:
    """v2 findings carry no scanner; infer it from the v2 scanners' fixed `type` strings (mirrors frontend api.js)."""
    if issue.get("scanner"):
        return issue["scanner"]
    kind = issue.get("type") or ""
    if "secret" in kind.lower():
        return "secrets"
    return "osv" if kind.lower().startswith("vulnerable dependency") else "patterns"


def _vulnerable_dependency_count(doc: dict) -> int:
    if doc.get("dependencies"):
        return sum(1 for dep in doc["dependencies"] if dep.get("vulnerabilities"))
    return sum(1 for i in doc.get("security_issues", []) if _scanner_of(i) == "osv")  # v2: no inventory, count findings


def build_dashboard(docs: List[dict]) -> dict:
    completed = [d for d in docs if d.get("status") == "completed" and d.get("overall_score") is not None]
    latest = {}
    for d in completed:  # docs are newest-first, so the first seen per project is its latest scan
        latest.setdefault(d.get("source_url") or d.get("name"), d)
    projects = list(latest.values())

    severity = Counter()
    owasp = Counter()
    scanners = Counter()
    for d in projects:
        for i in d.get("security_issues", []):
            severity[i.get("severity")] += 1
            if i.get("owasp"):
                owasp[i["owasp"]] += 1
            scanners[_scanner_of(i)] += 1

    languages = Counter()
    for d in projects:
        languages.update((d.get("metrics") or {}).get("languages", {}))

    now = datetime.now(timezone.utc)

    def ts(d):
        try:
            t = datetime.fromisoformat(d["created_at"])
            return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
        except (KeyError, ValueError, TypeError):
            return now

    def avg(xs):
        return round(sum(xs) / len(xs), 1) if xs else None

    last7 = [d["overall_score"] for d in completed if now - ts(d) <= timedelta(days=7)]
    prev7 = [d["overall_score"] for d in completed if timedelta(days=7) < now - ts(d) <= timedelta(days=14)]
    per_day = Counter(ts(d).date().isoformat() for d in docs)
    activity = [{"date": (now - timedelta(days=i)).date().isoformat(),
                 "count": per_day.get((now - timedelta(days=i)).date().isoformat(), 0)} for i in range(27, -1, -1)]
    streak = 0
    for day in reversed(activity):
        if day["count"] == 0:
            if streak == 0 and day is activity[-1]:
                continue  # today without a scan doesn't break the streak yet
            break
        streak += 1

    posture = avg([d["overall_score"] for d in projects]) or 0
    deps_vulnerable = sum(_vulnerable_dependency_count(d) for d in projects)
    deps_total = sum(len(d.get("dependencies", [])) for d in projects)

    return {
        "total_analyses": len(completed),
        "projects": len(projects),
        "running": sum(1 for d in docs if d.get("status") == "processing"),
        "avg_score": avg([d["overall_score"] for d in completed]) or 0,
        "posture_score": posture,
        "posture_grade": grade_for(posture) if projects else None,
        "score_delta_7d": round(avg(last7) - avg(prev7), 1) if last7 and prev7 else None,
        "total_issues": sum(severity.values()),
        "severity": {s: severity.get(s, 0) for s in SEVERITIES},
        "secrets": sum(1 for d in projects for i in d.get("security_issues", []) if _scanner_of(i) == "secrets"),
        "vulnerable_dependencies": deps_vulnerable,
        "total_dependencies": deps_total,
        "lines_scanned": sum((d.get("metrics") or {}).get("total_lines", 0) for d in completed),
        "fixed_total": sum((d.get("baseline") or {}).get("fixed", 0) for d in completed),
        "owasp": [{"code": c, "name": n, "count": owasp.get(c, 0)} for c, n in OWASP_TOP10.items()],
        "scanners": dict(scanners.most_common()),
        "languages": dict(languages.most_common(8)),
        "trend": [{"date": d["created_at"], "score": d["overall_score"], "name": d["name"],
                   "grade": d.get("grade") or grade_for(d["overall_score"])} for d in reversed(completed[:30])],
        "activity": activity,
        "streak": streak,
        "riskiest": [
            {"analysis_id": d["analysis_id"], "name": d["name"], "score": d["overall_score"],
             "grade": d.get("grade") or grade_for(d["overall_score"]), "severity": _counts(d)}
            for d in sorted(projects, key=lambda d: d["overall_score"])[:5]
        ],
        "recent_analyses": [_light(d) for d in docs[:6]],
    }


async def _get_owned(analysis_id: str, user: User) -> dict:
    doc = await db.analyses.find_one({"analysis_id": analysis_id, "user_id": user.user_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Analysis not found")
    return doc


@analysis_router.get("/{analysis_id}")
async def get_analysis(analysis_id: str, user: User = Depends(get_current_user)):
    await expire_stale_scans(user.user_id)  # so a page polling a dead scan sees it fail
    doc = await _get_owned(analysis_id, user)
    if doc.get("overall_score") is not None and not doc.get("grade"):
        doc["grade"] = grade_for(doc["overall_score"])
    return doc


def _download(payload: dict, filename: str, media_type: str) -> JSONResponse:
    return JSONResponse(payload, media_type=media_type,
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def _slug(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "-" for c in name)[:60]


@analysis_router.get("/{analysis_id}/sarif")
async def export_sarif(analysis_id: str, user: User = Depends(get_current_user)):
    doc = await _get_owned(analysis_id, user)
    def load(items):
        out = []
        for i in items or []:
            if i.get("rule_id"):
                out.append(Finding(**i))
                continue
            # v2 finding: give each finding type its own rule so names and severities don't bleed together
            rule = "LEGACY-" + ("".join(c if c.isalnum() else "-" for c in (i.get("type") or "finding")).strip("-")[:60] or "finding")
            out.append(Finding(**{"scanner": _scanner_of(i), **i, "rule_id": rule}).with_fingerprint(
                source_line=i.get("description")))
        disambiguate_fingerprints(out)
        return out
    sarif = to_sarif(load(doc.get("security_issues")), load(doc.get("suppressed_issues")))
    return _download(sarif, f"codeguard-{_slug(doc['name'])}.sarif", "application/sarif+json")


@analysis_router.get("/{analysis_id}/sbom")
async def export_sbom(analysis_id: str, user: User = Depends(get_current_user)):
    doc = await _get_owned(analysis_id, user)
    if not doc.get("engine_version"):
        raise HTTPException(409, "This scan predates the dependency inventory. Re-scan the project to export an SBOM.")
    deps = [Dependency(**d) for d in doc.get("dependencies", [])]
    return _download(to_cyclonedx(deps, doc["name"]), f"codeguard-{_slug(doc['name'])}.cdx.json",
                     "application/vnd.cyclonedx+json")


@analysis_router.delete("/{analysis_id}")
async def delete_analysis(analysis_id: str, user: User = Depends(get_current_user)):
    result = await db.analyses.delete_one({"analysis_id": analysis_id, "user_id": user.user_id})
    if result.deleted_count == 0:
        raise HTTPException(404, "Analysis not found")
    return {"message": "Analysis deleted"}

# ==================== PUBLIC ====================

BADGE_COLORS = {"A": "#16a34a", "B": "#65a30d", "C": "#ca8a04", "D": "#ea580c", "F": "#dc2626"}


@api_router.get("/badge/{analysis_id}.svg")
async def badge(analysis_id: str):
    """Shields-style README badge. Exposes only the grade and score of that scan."""
    doc = await db.analyses.find_one({"analysis_id": analysis_id, "status": "completed"},
                                     {"_id": 0, "overall_score": 1, "grade": 1})
    grade = (doc or {}).get("grade") or (grade_for(doc["overall_score"]) if doc else "?")
    value = f"{grade} · {doc['overall_score']:.0f}" if doc else "unknown"
    color = BADGE_COLORS.get(grade, "#6b7280")
    lw, vw = 78, 8 + 7 * len(value)
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{lw + vw}" height="20" role="img" aria-label="codeguard: {value}">
<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<clipPath id="r"><rect width="{lw + vw}" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#18181b"/><rect x="{lw}" width="{vw}" height="20" fill="{color}"/>
<rect width="{lw + vw}" height="20" fill="url(#s)"/></g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
<text x="{lw / 2}" y="14">codeguard</text><text x="{lw + vw / 2}" y="14">{value}</text></g></svg>"""
    return Response(svg, media_type="image/svg+xml", headers={"Cache-Control": "max-age=300"})


@api_router.get("/")
async def root():
    return {"message": "CodeGuard AI API", "version": __version__}


@api_router.get("/health")
async def health():
    return {
        "status": "healthy", "version": __version__,
        "engines": {"patterns": True, "secrets": True, "radon": True, "osv": True,
                    "bandit": bandit_available(), "semgrep": semgrep_available(), "ai": ai_enabled()},
    }


app.include_router(api_router)
app.include_router(auth_router)
app.include_router(analysis_router)

DEFAULT_ORIGINS = "http://localhost:3000,https://codevigil.netlify.app"
origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", DEFAULT_ORIGINS).split(",") if o.strip()]
# Opt-in pattern for preview deploys, e.g. ^https://deploy-preview-\d+--codevigil\.netlify\.app$
# Credentialed CORS for previews means any deploy preview can call the API as the visitor, so only
# enable it when previews are never built from untrusted (fork) pull requests.
origin_regex = os.environ.get("CORS_ORIGIN_REGEX") or None
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origin_regex=origin_regex if os.environ.get("ENV") == "prod" else None,
    allow_origins=origins if os.environ.get("ENV") == "prod" else ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
