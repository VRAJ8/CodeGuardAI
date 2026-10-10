# 🛡️ CodeGuard AI

**A DevSecOps scanner that grades your repo A–F.** It runs SAST, secret detection, dependency CVE checks and code-health analysis in one pass, maps every finding to CWE and the OWASP Top 10, and uses an LLM to write patches for what it finds.

**Live demo:** [codevigil.netlify.app](https://codevigil.netlify.app) · **API docs:** `/docs` on the backend

[![CI](https://github.com/VRAJ8/CodeGuardAI/actions/workflows/ci.yml/badge.svg)](https://github.com/VRAJ8/CodeGuardAI/actions/workflows/ci.yml)

---

## What it does

| Layer | Engine | Details |
|---|---|---|
| **SAST** | [Bandit](https://bandit.readthedocs.io), [Semgrep](https://semgrep.dev), custom rule pack | Python AST checks, Semgrep **taint-mode** rules ([`rules/codeguard.yml`](backend/codeguard/rules/codeguard.yml)) for SQLi / SSRF / SSTI / open redirect, and a regex pack covering 20 cross-language patterns |
| **Secrets** | Signatures + Shannon entropy | 13 provider formats (AWS, GitHub, Stripe, OpenAI, Anthropic, Slack, private keys, DB URLs…) plus entropy-gated generic matches. Values are always redacted |
| **SCA** | [OSV.dev](https://osv.dev) batch API | `package.json`, `requirements*.txt`, `go.mod` → advisories with a **CVSS v3.1 base score computed from the vector** and the lowest fixed version |
| **Code health** | [Radon](https://radon.readthedocs.io) | McCabe cyclomatic complexity, Maintainability Index, AST nesting depth, swallowed exceptions, per-function hotspots |
| **Triage** | Llama 3.3 70B (Groq) | Executive summary, prioritized actions, copy-paste patches, full-file refactors |

All findings are **deduplicated across engines** (same file + line + CWE keeps the most precise tool), tagged with **CWE + OWASP Top 10 (2021)**, and scored. Scoring uses exponential decay so severity matters more than volume.

### Outputs
- **SARIF 2.1.0**: upload to GitHub Code Scanning so findings show in the repo's Security tab
- **CycloneDX 1.5 SBOM** with embedded vulnerabilities
- **PDF audit report**, raw JSON
- **README badge**: `GET /api/badge/{analysis_id}.svg`
- **Regression tracking**: each re-scan reports *new* vs *fixed* findings and the score delta against the previous scan

### Dashboard
Posture grade, critical/high count, leaked secrets, vulnerable dependencies, score trend, 4-week activity heatmap with scan streak, OWASP Top 10 exposure, severity mix, per-engine attribution, riskiest projects and language mix.

### Browser mode (no sign-up, no server)
[`/scan`](https://codevigil.netlify.app/scan) runs the scan entirely in your browser, in a Web Worker: drop a folder, a `.zip` or files, or paste a public GitHub repo. It runs the rule pack, secrets detection with entropy checks, inline suppressions, OSV.dev dependency audit with CVSS scoring and the complexity heuristic, and exports SARIF, CycloneDX and PDF.

- **Privacy:** folders, ZIPs and files never leave the browser. The only request is the optional OSV.dev lookup, which sends package names and versions, never code. OSV's API doesn't accept browser requests, so it goes through a same-origin relay rule in [`_redirects`](frontend/public/_redirects). GitHub repos are read from `api.github.com` and `raw.githubusercontent.com` (the zipball endpoint doesn't allow browser downloads).
- **Same results as the server:** the browser engine has no hand-copied rules. `python -m codeguard.browser_export` exports every rule and threshold from the Python engine to [`rules.generated.json`](frontend/src/lib/engine/rules.generated.json), and records the Python engine's output on a test corpus in [`parity.golden.json`](frontend/src/lib/engine/parity.golden.json). Jest requires the browser engine to reproduce it exactly, fingerprints included; pytest fails if either file is stale.
- **Cloud-only:** Bandit, Semgrep, AI triage and scan history across devices. Browser scans are kept in that browser only (last 8).

---

## Use it in CI (GitHub Action)

```yaml
# .github/workflows/codeguard.yml
name: CodeGuard
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: VRAJ8/CodeGuardAI@main
        with:
          fail-on: high            # critical | high | medium | low | none
          exclude: "tests docs"    # optional globs / dir prefixes
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: codeguard.sarif
```

This repo uses its own Action: the `self-scan` job in [`ci.yml`](.github/workflows/ci.yml) scans CodeGuard and uploads the results to Code Scanning.

## Use it as a CLI

```bash
cd backend
pip install -r requirements-cli.txt        # + `pipx install semgrep` for the Semgrep layer
python -m codeguard scan /path/to/repo                       # colored table, exit 1 on high+
python -m codeguard scan . --format sarif -o codeguard.sarif
python -m codeguard scan . --format sbom  -o sbom.cdx.json
python -m codeguard scan . --fail-on critical --exclude "tests/*" --offline
```

---

## Architecture

```
frontend/ (React + Tailwind + Recharts)          backend/
  pages/Dashboard  ── /api/analysis/stats ──►      server.py         FastAPI: auth, background scan jobs,
  pages/AnalysisDetail ◄─ poll status/progress ─                     exports, badge, dashboard aggregation
  pages/NewAnalysis ── POST /github | /upload ─►   codeguard/        reusable engine (API + CLI + Action)
                                                     sources.py      GitHub zipball / ZIP (zip-bomb + traversal safe)
                                                     engine.py       orchestration, dedupe, scoring
                                                     scanners/       patterns · secrets · external (bandit, semgrep)
                                                                     dependencies (OSV + CVSS) · complexity (radon)
                                                     exporters.py    SARIF · CycloneDX
                                                     ai.py           LLM triage
                                                   MongoDB (motor)
```

Scans run as background jobs. `POST` returns `202` with an `analysis_id`, and the UI polls for `status` and `progress.stage`. Each user can run at most 3 concurrent scans.

---

## Run it locally

### Docker (whole stack)
```bash
GROQ_API_KEY=... docker compose up --build     # GROQ key optional
open http://localhost:3000                     # click "Dev login" (enabled only in compose)
```

### Manual
```bash
# backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt && pipx install semgrep
cp .env.example .env                           # set MONGO_URL, optional GROQ_API_KEY / GITHUB_TOKEN
uvicorn server:app --reload --port 8000

# frontend
cd frontend
echo 'REACT_APP_BACKEND_URL=http://localhost:8000' > .env
yarn install && yarn start
```

### Tests & lint
```bash
cd backend && pytest -q && ruff check .
cd frontend && CI=true yarn test --watchAll=false   # browser engine, incl. parity with the Python engine
cd backend && python -m codeguard.browser_export    # regenerate the browser rules + golden after changing a rule
```
The suite covers every scanner, CVSS math checked against FIRST.org reference vectors, ZIP path-traversal handling, SARIF/SBOM shape, CLI exit codes, and the full API lifecycle (in-memory Mongo), including per-user isolation and regression tracking. [`tests/fixtures/vulnerable_app`](backend/tests/fixtures/vulnerable_app) is a deliberately vulnerable Flask + Express app.

## Configuration

| Variable | Purpose |
|---|---|
| `MONGO_URL`, `DB_NAME` | MongoDB connection |
| `GROQ_API_KEY` | Enables AI triage (`EMERGENT_LLM_KEY` still accepted); `AI_MODEL`, `AI_BASE_URL` to swap models/providers |
| `GITHUB_TOKEN` | Raises the GitHub API limit from 60/h; allows private repos the token can read |
| `CORS_ORIGINS` | Comma-separated frontend origins allowed to call the API with the session cookie (default: `localhost:3000` and `codevigil.netlify.app`). `*` is ignored, since it would let any site read signed-in users' data |
| `ALLOW_DEV_LOGIN` | Passwordless local login. **Never enable in production** |
| `CODEGUARD_MAX_FILES` | Max files per scan (default 400) |

## Tech stack
**Backend:** Python 3.12, FastAPI, Motor/MongoDB, Pydantic v2, Bandit, Semgrep, Radon, httpx · **Frontend:** React 18, Tailwind, Recharts, Radix UI, jsPDF · **DevOps:** Docker, Compose, GitHub Actions, SARIF, CycloneDX
