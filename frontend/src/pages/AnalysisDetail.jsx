import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import axios from "axios";
import { toast } from "sonner";
import {
  ExternalLink, Trash2, Download, FileText, FileJson, ShieldCheck, Package, Gauge, Rocket, Search, ChevronDown,
  Sparkles, Copy, Check, RefreshCw, AlertTriangle, CheckCircle2, Clock, FileCode, Code2, KeyRound, XCircle, Star,
} from "lucide-react";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import AppShell from "@/components/AppShell";
import { Delta, EmptyState, GradeSticker, SeverityBadge, SeverityBar, Spinner } from "@/components/viz";
import { API, BACKEND_URL, compact, downloadFromApi, severityCounts, timeAgo } from "@/lib/api";
import { exportPdf } from "@/lib/report";
import { GRADE, SCANNERS, SEVERITY_ORDER, gradeFor, languageColor } from "@/lib/theme";

const STAGES = [
  "Fetching source", "Running secret & pattern rules", "Running SAST engines (Bandit, Semgrep)",
  "Resolving dependencies against OSV.dev", "Measuring complexity & maintainability", "AI triage & patch generation",
];
const OWASP_NAMES = {
  "A01:2021": "Broken Access Control", "A02:2021": "Cryptographic Failures", "A03:2021": "Injection",
  "A04:2021": "Insecure Design", "A05:2021": "Security Misconfiguration", "A06:2021": "Vulnerable Components",
  "A07:2021": "Auth Failures", "A08:2021": "Integrity Failures", "A09:2021": "Logging Failures", "A10:2021": "SSRF",
};

function CopyButton({ text, label = "Copy", dark = false }) {
  const [done, setDone] = useState(false);
  return (
    <button className={`${dark ? "btn-dark" : "btn-secondary"} btn-sm`} onClick={() => {
      navigator.clipboard.writeText(text);
      setDone(true);
      setTimeout(() => setDone(false), 1500);
    }}>
      {done ? <Check className="w-3.5 h-3.5" strokeWidth={3} /> : <Copy className="w-3.5 h-3.5" strokeWidth={2.5} />} {done ? "Copied!" : label}
    </button>
  );
}

function ScanningView({ analysis }) {
  const current = analysis.progress?.stage || "Queued";
  const idx = STAGES.indexOf(current);
  return (
    <div className="max-w-2xl mx-auto py-6">
      <div className="card p-8">
        <span className="sticker bg-cobalt text-white"><span className="w-2 h-2 rounded-full bg-yel blink" /> Scanning</span>
        <h1 className="mt-4 font-display text-4xl font-extrabold break-words">{analysis.name}</h1>
        <div className="mt-6 h-7 rounded-full border-[2.5px] border-ink bg-snow overflow-hidden p-[3px]">
          <div className="h-full rounded-full progress-stripes transition-all duration-700" style={{ width: `${analysis.progress?.pct || 5}%` }} />
        </div>
        <div className="mt-1.5 text-right font-mono text-xs font-bold">{analysis.progress?.pct || 5}%</div>
        <ol className="mt-6 space-y-2">
          {STAGES.map((s, i) => {
            const state = idx > i ? "done" : idx === i ? "active" : "todo";
            return (
              <li key={s} className={`flex items-center gap-3 p-2.5 rounded-[10px] border-2 text-[15px] font-semibold ${
                state === "active" ? "border-ink bg-yel shadow-brut-sm" : state === "done" ? "border-transparent" : "border-transparent text-faint"}`}>
                {state === "done" ? <span className="w-6 h-6 grid place-items-center rounded-md border-2 border-ink bg-mint"><Check className="w-3.5 h-3.5" strokeWidth={3.5} /></span> :
                 state === "active" ? <span className="w-6 h-6 rounded-md border-2 border-ink bg-snow grid place-items-center"><span className="w-2.5 h-2.5 bg-ink rounded-sm animate-spin" /></span> :
                 <span className="w-6 h-6 rounded-md border-2 border-faint" />}
                {s}
              </li>
            );
          })}
        </ol>
        <p className="mt-6 text-[13px] text-sub">You can leave this page. The scan keeps running and shows up in your history.</p>
      </div>
    </div>
  );
}

function FindingRow({ issue, fix, open, onToggle }) {
  return (
    <div className={`border-b-2 border-ink/10 last:border-0 ${open ? "bg-cream/60" : ""}`}>
      <button onClick={onToggle} className="w-full flex items-start gap-3 px-4 py-4 text-left hover:bg-cream/60">
        <span className="w-[84px] shrink-0"><SeverityBadge severity={issue.severity} /></span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-bold">{issue.type}</span>
            {issue.is_new && <span className="sticker !h-5 !px-1.5 !text-[10px] bg-yel rotate-3">NEW</span>}
            {fix && <span className="sticker !h-5 !px-1.5 !text-[10px] bg-lilac -rotate-2"><Sparkles className="w-2.5 h-2.5" strokeWidth={3} /> AI patch</span>}
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-sub">
            <code className="font-mono font-bold text-ink">{issue.file_path}{issue.line_number ? `:${issue.line_number}` : ""}</code>
            {issue.cwe && <span className="font-mono">{issue.cwe}</span>}
            {issue.owasp && <span>{issue.owasp.split(":")[0]} {OWASP_NAMES[issue.owasp]}</span>}
            {issue.scanner && <span>via {SCANNERS[issue.scanner]?.label || issue.scanner}</span>}
          </div>
        </div>
        <ChevronDown className={`w-5 h-5 mt-0.5 transition-transform ${open ? "rotate-180" : ""}`} strokeWidth={2.5} />
      </button>
      {open && (
        <div className="px-4 pb-5 md:pl-[112px] space-y-4">
          {!(issue.snippet && issue.description?.startsWith("Found:")) && <p className="text-[15px] text-sub">{issue.description}</p>}
          {issue.snippet && issue.scanner !== "secrets" && <pre className="code-block">{issue.snippet}</pre>}
          <div className="flex gap-2.5 p-3.5 rounded-[10px] border-2 border-ink bg-mint/50 text-[15px]">
            <ShieldCheck className="w-5 h-5 mt-0.5 shrink-0" strokeWidth={2.5} />
            <span className="font-medium">{issue.recommendation}</span>
          </div>
          {fix && (
            <div className="rounded-[12px] border-[2.5px] border-ink overflow-hidden shadow-brut">
              <div className="flex items-center justify-between px-4 py-2.5 bg-lilac border-b-[2.5px] border-ink">
                <span className="flex items-center gap-2 text-sm font-extrabold"><Sparkles className="w-4 h-4" strokeWidth={2.5} /> Suggested patch</span>
                <CopyButton text={fix.fix_code} label="Copy patch" />
              </div>
              <div className="p-4 space-y-3 bg-snow">
                {fix.explanation && <p className="text-sm text-sub">{fix.explanation}</p>}
                <pre className="code-block">{fix.fix_code}</pre>
              </div>
            </div>
          )}
          {issue.cwe && (
            <a className="inline-flex items-center gap-1 text-[13px] font-bold underline decoration-2 underline-offset-4 hover:text-cobalt" target="_blank" rel="noreferrer"
               href={`https://cwe.mitre.org/data/definitions/${issue.cwe.replace("CWE-", "")}.html`}>
              Read about {issue.cwe} <ExternalLink className="w-3.5 h-3.5" strokeWidth={2.5} />
            </a>
          )}
        </div>
      )}
    </div>
  );
}

function FindingsTab({ analysis }) {
  const issues = analysis.security_issues || [];
  const counts = severityCounts(analysis);
  const [sev, setSev] = useState(null);
  const [scanner, setScanner] = useState(null);
  const [onlyNew, setOnlyNew] = useState(false);
  const [q, setQ] = useState("");
  const [open, setOpen] = useState({});
  const scanners = [...new Set(issues.map((i) => i.scanner).filter(Boolean))];

  const findFix = (issue) => (analysis.ai_fixes || []).find((f) =>
    (f.file_path === issue.file_path || issue.file_path.endsWith(f.file_path || "~")) &&
    (f.issue_type === issue.type || f.type === issue.type) && (!f.line || !issue.line_number || Number(f.line) === issue.line_number));

  const shown = issues.filter((i) =>
    (!sev || i.severity === sev) && (!scanner || i.scanner === scanner) && (!onlyNew || i.is_new) &&
    (!q || `${i.type} ${i.file_path} ${i.cwe || ""} ${i.description}`.toLowerCase().includes(q.toLowerCase())));

  if (!issues.length) {
    return <EmptyState icon={CheckCircle2} title="Zero findings. Clean." body="Every engine came back empty. Go touch grass. 🌱" />;
  }

  return (
    <div className="card overflow-hidden">
      <div className="p-4 border-b-[2.5px] border-ink flex flex-col lg:flex-row gap-3 lg:items-center bg-cream/50">
        <div className="relative flex-1 max-w-sm">
          <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2" strokeWidth={2.5} />
          <input className="input !h-10 pl-10 text-sm" placeholder="Search file, CWE, rule…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="flex flex-wrap gap-1.5">
          <button className={`chip ${!sev ? "chip-active" : ""}`} onClick={() => setSev(null)}>All {issues.length}</button>
          {SEVERITY_ORDER.filter((s) => counts[s]).map((s) => (
            <button key={s} className={`chip capitalize ${sev === s ? "chip-active" : ""}`} onClick={() => setSev(sev === s ? null : s)}>{s} {counts[s]}</button>
          ))}
          {scanners.length > 1 && <span className="w-[2px] h-7 bg-ink/20 mx-1" />}
          {scanners.length > 1 && scanners.map((s) => (
            <button key={s} className={`chip ${scanner === s ? "chip-active" : ""}`} onClick={() => setScanner(scanner === s ? null : s)}>{SCANNERS[s]?.label || s}</button>
          ))}
          {analysis.baseline?.new > 0 && (
            <button className={`chip ${onlyNew ? "chip-active" : "!bg-yel"}`} onClick={() => setOnlyNew(!onlyNew)}>New only {analysis.baseline.new}</button>
          )}
        </div>
      </div>
      {shown.length ? shown.map((issue, i) => {
        const key = issue.fingerprint || `${issue.file_path}-${issue.line_number}-${i}`;
        return <FindingRow key={key} issue={issue} fix={findFix(issue)} open={!!open[key]} onToggle={() => setOpen((o) => ({ ...o, [key]: !o[key] }))} />;
      }) : <div className="p-10 text-center text-sub">No findings match those filters.</div>}
    </div>
  );
}

function DependenciesTab({ analysis }) {
  const deps = analysis.dependencies || [];
  const [vulnOnly, setVulnOnly] = useState(true);
  const vulnerable = deps.filter((d) => d.vulnerabilities?.length);
  const rows = (vulnOnly && vulnerable.length ? vulnerable : deps).slice().sort((a, b) => (b.vulnerabilities?.length || 0) - (a.vulnerabilities?.length || 0));
  if (!deps.length) return <EmptyState icon={Package} title="No dependency manifests found" body="We read package.json, requirements*.txt and go.mod." />;
  return (
    <div className="card overflow-hidden">
      <div className="p-4 border-b-[2.5px] border-ink flex flex-wrap items-center justify-between gap-3 bg-cream/50">
        <div className="font-semibold"><span className="font-display text-2xl font-extrabold">{vulnerable.length}</span> of {deps.length} packages have known advisories</div>
        <div className="flex flex-wrap gap-2">
          <button className={`chip ${vulnOnly ? "chip-active" : ""}`} onClick={() => setVulnOnly(true)}>Vulnerable</button>
          <button className={`chip ${!vulnOnly ? "chip-active" : ""}`} onClick={() => setVulnOnly(false)}>All packages</button>
          <button className="btn-secondary btn-sm" onClick={() => downloadFromApi(`/analysis/${analysis.analysis_id}/sbom`, `${analysis.name}.cdx.json`)}>
            <Download className="w-3.5 h-3.5" strokeWidth={2.5} /> SBOM
          </button>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-left">
            <tr className="border-b-2 border-ink">
              {["Package", "Version", "Ecosystem", "Advisories", "Fixed in"].map((h) => <th key={h} className="px-4 py-3 eyebrow !text-ink">{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {rows.map((d) => {
              const worst = SEVERITY_ORDER.find((s) => d.vulnerabilities?.some((v) => v.severity === s));
              const fix = d.vulnerabilities?.map((v) => v.fixed_in).filter(Boolean).sort().pop();
              return (
                <tr key={`${d.manifest}-${d.name}`} className="border-b-2 border-ink/10 last:border-0 hover:bg-cream/60">
                  <td className="px-4 py-3"><div className="font-bold">{d.name}</div><div className="text-[11px] text-sub font-mono">{d.manifest}{d.dev ? " · dev" : ""}</div></td>
                  <td className="px-4 py-3 font-mono text-xs font-bold tabular">{d.version || <span className="text-faint">unpinned</span>}</td>
                  <td className="px-4 py-3"><span className="chip !h-6">{d.ecosystem}</span></td>
                  <td className="px-4 py-3">
                    {d.vulnerabilities?.length ? (
                      <div className="flex flex-wrap items-center gap-1.5">
                        <SeverityBadge severity={worst} />
                        {d.vulnerabilities.slice(0, 3).map((v) => (
                          <a key={v.id} href={`https://osv.dev/vulnerability/${v.id}`} target="_blank" rel="noreferrer"
                             className="font-mono text-[11px] font-bold underline decoration-2 underline-offset-2 hover:text-cobalt" title={v.summary}>
                            {v.aliases?.find((a) => a.startsWith("CVE")) || v.id}
                          </a>
                        ))}
                        {d.vulnerabilities.length > 3 && <span className="text-[11px] text-sub">+{d.vulnerabilities.length - 3}</span>}
                      </div>
                    ) : <span className="text-xs text-faint">{d.version ? "none known" : "not checked"}</span>}
                  </td>
                  <td className="px-4 py-3">{fix ? <span className="font-mono text-xs font-bold px-1.5 py-0.5 rounded border-2 border-ink bg-mint">{fix}</span> : <span className="text-faint">—</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function HealthTab({ analysis }) {
  const risks = (analysis.bug_risks || []).slice().sort((a, b) => b.risk_score - a.risk_score);
  const [open, setOpen] = useState(null);
  const refactorFor = (path) => (analysis.ai_refactors || []).find((r) => path.endsWith(r.file_path) || r.file_path?.endsWith(path));
  const m = analysis.metrics || {};
  const langs = Object.entries(m.languages || {});
  const langTotal = langs.reduce((s, [, n]) => s + n, 0) || 1;
  const riskColor = (r) => (r > 50 ? "#FF5A5F" : r > 25 ? "#FFE14D" : "#7CF0B4");
  return (
    <div className="space-y-5">
      <div className="grid md:grid-cols-3 gap-5">
        <div className="card p-5 bg-lime">
          <div className="eyebrow !text-ink">Maintainability index</div>
          <div className="mt-2 font-display text-5xl font-extrabold tabular">{Math.round(m.maintainability_index || 0)}<span className="text-xl">/100</span></div>
          <div className="mt-3 h-4 rounded-full border-2 border-ink bg-snow p-[2px]"><div className="h-full rounded-full bg-ink" style={{ width: `${m.maintainability_index || 0}%` }} /></div>
        </div>
        <div className="card p-5 bg-lilac">
          <div className="eyebrow !text-ink">Avg cyclomatic complexity</div>
          <div className="mt-2 font-display text-5xl font-extrabold tabular">{(m.avg_complexity || 0).toFixed(1)}</div>
          <div className="mt-2 text-[13px] font-semibold">per function · ≤5 is great, &gt;10 is spicy 🌶️</div>
        </div>
        <div className="card p-5">
          <div className="eyebrow">Languages</div>
          <div className="mt-3 flex h-5 gap-[2px] p-[2px] rounded-full border-2 border-ink overflow-hidden">
            {langs.map(([l, n]) => <div key={l} className="rounded-full" style={{ width: `${(n / langTotal) * 100}%`, background: languageColor(l) }} title={`${l}: ${n} lines`} />)}
          </div>
          <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-[13px]">
            {langs.map(([l, n]) => (
              <span key={l} className="flex items-center gap-1.5"><span className="w-3 h-3 rounded border-2 border-ink" style={{ background: languageColor(l) }} />
                <span className="capitalize font-semibold">{l}</span><span className="font-mono text-xs">{Math.round((n / langTotal) * 100)}%</span></span>
            ))}
          </div>
        </div>
      </div>

      {!risks.length ? <EmptyState icon={Gauge} title="No complexity hotspots" body="Every file is within healthy thresholds." /> : (
        <div className="card overflow-hidden">
          <div className="hidden md:grid grid-cols-[1fr_80px_80px_80px_80px_170px_24px] gap-4 px-4 py-3 border-b-[2.5px] border-ink bg-cream/50">
            {["File", "Lines", "Avg CC", "Max CC", "MI"].map((h, i) => <span key={h} className={`eyebrow !text-ink ${i ? "text-right" : ""}`}>{h}</span>)}
            <span className="eyebrow !text-ink">Risk</span><span />
          </div>
          {risks.map((r) => {
            const refactor = refactorFor(r.file_path);
            const isOpen = open === r.file_path;
            return (
              <div key={r.file_path} className="border-b-2 border-ink/10 last:border-0">
                <button onClick={() => setOpen(isOpen ? null : r.file_path)}
                        className="w-full grid grid-cols-[1fr_auto] md:grid-cols-[1fr_80px_80px_80px_80px_170px_24px] gap-4 items-center px-4 py-3.5 text-left hover:bg-cream/60">
                  <span className="min-w-0 flex items-center gap-2">
                    <FileCode className="w-4 h-4 shrink-0" strokeWidth={2.5} />
                    <code className="truncate font-mono text-[13px] font-bold">{r.file_path}</code>
                    {refactor && <span className="sticker !h-5 !px-1.5 !text-[10px] bg-lilac"><Sparkles className="w-2.5 h-2.5" strokeWidth={3} /> AI</span>}
                  </span>
                  {[r.lines || "—", r.cyclomatic ? r.cyclomatic.toFixed(1) : "—", r.max_cyclomatic || "—", r.maintainability != null ? Math.round(r.maintainability) : "—"].map((v, i) => (
                    <span key={i} className="hidden md:block text-right font-mono text-sm tabular">{v}</span>
                  ))}
                  <span className="flex items-center gap-2">
                    <span className="hidden md:block flex-1 h-4 rounded-full border-2 border-ink bg-snow p-[2px]">
                      <span className="block h-full rounded-full" style={{ width: `${r.risk_score}%`, background: riskColor(r.risk_score) }} />
                    </span>
                    <span className="font-mono text-xs font-bold w-7 text-right tabular">{Math.round(r.risk_score)}</span>
                  </span>
                  <ChevronDown className={`hidden md:block w-5 h-5 transition-transform ${isOpen ? "rotate-180" : ""}`} strokeWidth={2.5} />
                </button>
                {isOpen && (
                  <div className="px-4 pb-5 md:pl-10 space-y-4">
                    <ul className="space-y-1.5">
                      {r.issues.map((i) => <li key={i} className="flex gap-2 text-[15px]"><XCircle className="w-4 h-4 mt-1 shrink-0 text-[#C2410C]" strokeWidth={2.5} />{i}</li>)}
                    </ul>
                    {r.hotspots?.length > 0 && (
                      <div>
                        <div className="eyebrow mb-2">Hotspot functions</div>
                        <div className="flex flex-wrap gap-2">
                          {r.hotspots.map((h) => (
                            <span key={`${h.name}-${h.line}`} className="chip !h-8 font-mono">
                              {h.name}<span className="text-sub">:{h.line}</span>
                              <span className="px-1.5 rounded border-[1.5px] border-ink" style={{ background: GRADE[h.rank === "A" || h.rank === "B" ? "A" : h.rank === "C" ? "C" : "F"].color }}>CC {h.complexity} · {h.rank}</span>
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                    {refactor && (
                      <div className="rounded-[12px] border-[2.5px] border-ink overflow-hidden shadow-brut">
                        <div className="flex items-center justify-between px-4 py-2.5 bg-lilac border-b-[2.5px] border-ink">
                          <span className="flex items-center gap-2 text-sm font-extrabold"><Sparkles className="w-4 h-4" strokeWidth={2.5} /> AI refactor</span>
                          <CopyButton text={refactor.refined_code} label="Copy code" />
                        </div>
                        <div className="p-4 space-y-3 bg-snow">
                          <p className="text-sm text-sub">{refactor.explanation}</p>
                          <pre className="code-block max-h-96">{refactor.refined_code}</pre>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function CodeCard({ title, body, code, bg = "bg-snow" }) {
  return (
    <div className="card overflow-hidden">
      <div className={`flex items-center justify-between gap-3 px-5 py-4 border-b-[2.5px] border-ink ${bg}`}>
        <div><div className="font-display text-lg font-extrabold">{title}</div><div className="text-[13px] mt-0.5">{body}</div></div>
        <CopyButton text={code} />
      </div>
      <pre className="code-block !rounded-none !border-0 m-0">{code}</pre>
    </div>
  );
}

function ShipTab({ analysis }) {
  const badgeUrl = `${BACKEND_URL}/api/badge/${analysis.analysis_id}.svg`;
  const badgeMd = `[![CodeGuard](${badgeUrl})](${window.location.href})`;
  const workflow = `# .github/workflows/codeguard.yml
name: CodeGuard
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: VRAJ8/CodeGuardAI@main
        with:
          fail-on: high          # block merges on high/critical findings
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: codeguard.sarif`;
  const cli = `git clone https://github.com/VRAJ8/CodeGuardAI && cd CodeGuardAI/backend
pip install -r requirements-cli.txt
python -m codeguard scan /path/to/repo --fail-on high
python -m codeguard scan /path/to/repo --format sarif -o codeguard.sarif`;
  return (
    <div className="grid xl:grid-cols-2 gap-5">
      <CodeCard bg="bg-yel" title="Block risky PRs" body="Fails CI on high-severity findings and publishes them to GitHub's Security tab." code={workflow} />
      <div className="space-y-5">
        <div className="card p-5 bg-pink">
          <div className="font-display text-lg font-extrabold">README badge</div>
          <div className="text-[13px] mt-0.5">Show off your grade. The badge reveals only this scan's grade and score.</div>
          <div className="mt-4 p-4 rounded-[10px] border-2 border-ink bg-snow flex flex-wrap items-center justify-between gap-3">
            <img src={badgeUrl} alt="CodeGuard badge" className="h-5" />
            <CopyButton text={badgeMd} label="Copy markdown" dark />
          </div>
        </div>
        <CodeCard bg="bg-lime" title="Run it locally" body="Same engine as this dashboard, as a CLI." code={cli} />
        <div className="card p-5 flex flex-wrap gap-2">
          <button className="btn-secondary btn-sm" onClick={() => downloadFromApi(`/analysis/${analysis.analysis_id}/sarif`, `${analysis.name}.sarif`)}>
            <Download className="w-3.5 h-3.5" strokeWidth={2.5} /> SARIF 2.1.0
          </button>
          <button className="btn-secondary btn-sm" onClick={() => downloadFromApi(`/analysis/${analysis.analysis_id}/sbom`, `${analysis.name}.cdx.json`)}>
            <Download className="w-3.5 h-3.5" strokeWidth={2.5} /> CycloneDX SBOM
          </button>
        </div>
      </div>
    </div>
  );
}

const TABS = [
  { key: "findings", label: "Findings", icon: AlertTriangle },
  { key: "deps", label: "Dependencies", icon: Package },
  { key: "health", label: "Code health", icon: Gauge },
  { key: "ship", label: "Ship it", icon: Rocket },
];

export default function AnalysisDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [analysis, setAnalysis] = useState(null);
  const [tab, setTab] = useState("findings");
  const [confirmDelete, setConfirmDelete] = useState(false);
  const timer = useRef();
  const wasProcessing = useRef(false);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const { data } = await axios.get(`${API}/analysis/${id}`);
        if (cancelled) return;
        setAnalysis(data);
        if (data.status === "processing") {
          wasProcessing.current = true;
          timer.current = setTimeout(load, 1500);
        } else if (data.status === "completed" && wasProcessing.current) {
          toast.success(`Scan complete: grade ${data.grade} ${GRADE[data.grade]?.emoji || ""}`);
        }
      } catch {
        toast.error("Analysis not found");
        navigate("/dashboard");
      }
    };
    load();
    return () => { cancelled = true; clearTimeout(timer.current); };
  }, [id, navigate]);

  const counts = useMemo(() => severityCounts(analysis), [analysis]);

  const rescan = async () => {
    try {
      const { data } = await axios.post(`${API}/analysis/github`, { github_url: analysis.source_url, name: analysis.name });
      navigate(`/analysis/${data.analysis_id}`);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Couldn't start re-scan");
    }
  };

  const remove = async () => {
    try {
      await axios.delete(`${API}/analysis/${id}`);
      toast.success("Scan deleted");
      navigate("/history");
    } catch {
      toast.error("Delete failed");
    }
  };

  if (!analysis) return <AppShell title="Scan"><Spinner /></AppShell>;
  if (analysis.status === "processing") return <AppShell title={analysis.name}><ScanningView analysis={analysis} /></AppShell>;

  if (analysis.status === "failed") {
    return (
      <AppShell title={analysis.name}>
        <div className="max-w-xl mx-auto py-10">
          <EmptyState icon={XCircle} title="Scan failed 💀" body={analysis.error || analysis.ai_summary || "Something went wrong."}
            action={<div className="flex justify-center gap-2">
              {analysis.source_url && <button className="btn-primary" onClick={rescan}><RefreshCw className="w-4 h-4" strokeWidth={2.5} /> Retry</button>}
              <button className="btn-secondary" onClick={() => navigate("/new-analysis")}>New scan</button>
            </div>} />
        </div>
      </AppShell>
    );
  }

  const grade = analysis.grade || gradeFor(analysis.overall_score);
  const g = GRADE[grade] || {};
  const m = analysis.metrics || {};
  const vulnDeps = (analysis.dependencies || []).filter((d) => d.vulnerabilities?.length).length;
  const secrets = (analysis.security_issues || []).filter((i) => i.scanner === "secrets").length;
  const tabCount = { findings: analysis.security_issues?.length, deps: vulnDeps || undefined, health: analysis.bug_risks?.length };

  const actions = (
    <>
      {analysis.source_url && (
        <button className="btn-ghost btn-sm hidden sm:inline-flex" onClick={rescan}><RefreshCw className="w-4 h-4" strokeWidth={2.5} /> Re-scan</button>
      )}
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button className="btn-primary btn-sm"><Download className="w-4 h-4" strokeWidth={2.5} /> Export</button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56 bg-snow border-[2.5px] border-ink shadow-brut rounded-[12px] p-1.5 text-ink font-semibold">
          <DropdownMenuItem className="rounded-lg focus:bg-yel" onClick={() => { exportPdf(analysis); toast.success("PDF report generated"); }}><FileText className="w-4 h-4 mr-2" /> PDF audit report</DropdownMenuItem>
          <DropdownMenuItem className="rounded-lg focus:bg-yel" onClick={() => downloadFromApi(`/analysis/${id}/sarif`, `${analysis.name}.sarif`)}><ShieldCheck className="w-4 h-4 mr-2" /> SARIF (Code Scanning)</DropdownMenuItem>
          <DropdownMenuItem className="rounded-lg focus:bg-yel" onClick={() => downloadFromApi(`/analysis/${id}/sbom`, `${analysis.name}.cdx.json`)}><Package className="w-4 h-4 mr-2" /> CycloneDX SBOM</DropdownMenuItem>
          <DropdownMenuSeparator className="bg-ink/20" />
          <DropdownMenuItem className="rounded-lg focus:bg-yel" onClick={() => {
            const url = URL.createObjectURL(new Blob([JSON.stringify(analysis, null, 2)], { type: "application/json" }));
            Object.assign(document.createElement("a"), { href: url, download: `${analysis.name}.json` }).click();
            URL.revokeObjectURL(url);
          }}><FileJson className="w-4 h-4 mr-2" /> Raw JSON</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      {confirmDelete ? (
        <span className="flex items-center gap-1">
          <button className="btn btn-sm !bg-cherry" onClick={remove}>Delete</button>
          <button className="btn-ghost btn-sm" onClick={() => setConfirmDelete(false)}>Cancel</button>
        </span>
      ) : (
        <button className="btn-secondary btn-sm !px-2.5" onClick={() => setConfirmDelete(true)} aria-label="Delete scan"><Trash2 className="w-4 h-4" strokeWidth={2.5} /></button>
      )}
    </>
  );

  return (
    <AppShell title={analysis.name} actions={actions}>
      {/* Hero */}
      <section className="card p-6 md:p-8 fade-up">
        <div className="grid lg:grid-cols-[auto_1fr_auto] gap-8 items-center">
          <GradeSticker score={analysis.overall_score} grade={grade} label="Overall score" />
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 text-[13px]">
              <span className="chip">{analysis.source_type === "github" ? "GitHub" : "ZIP upload"}</span>
              {analysis.repo_meta?.ref && <span className="chip font-mono">{analysis.repo_meta.ref}</span>}
              {analysis.repo_meta?.stars != null && <span className="chip"><Star className="w-3 h-3" strokeWidth={3} /> {compact(analysis.repo_meta.stars)}</span>}
              <span className="flex items-center gap-1 text-sub font-medium"><Clock className="w-3.5 h-3.5" strokeWidth={2.5} /> {timeAgo(analysis.created_at)}</span>
              {analysis.duration_ms && <span className="text-sub font-medium">· scanned in {(analysis.duration_ms / 1000).toFixed(1)}s</span>}
            </div>
            <h1 className="mt-3 font-display text-4xl md:text-5xl font-extrabold leading-none break-words">{analysis.name}</h1>
            <div className="mt-3"><span className="sticker -rotate-2" style={{ background: g.color }}>{g.emoji} {g.vibe}</span></div>
            {analysis.repo_meta?.description && <p className="mt-3 text-sub line-clamp-2">{analysis.repo_meta.description}</p>}
            {analysis.baseline && (
              <div className="mt-4 inline-flex flex-wrap items-center gap-3 px-3 py-2 rounded-[10px] border-2 border-ink bg-cream text-[13px] font-semibold">
                <span>vs previous scan</span>
                <Delta value={analysis.baseline.score_delta} suffix=" pts" />
                <span className="px-2 rounded border-2 border-ink bg-yel">{analysis.baseline.new} new</span>
                <span className="px-2 rounded border-2 border-ink bg-mint">{analysis.baseline.fixed} fixed</span>
              </div>
            )}
            <div className="mt-5 max-w-xl"><SeverityBar counts={counts} /></div>
          </div>
          <div className="grid grid-cols-2 lg:grid-cols-1 gap-2.5 lg:w-52">
            {[
              [FileCode, "Files", m.total_files, "bg-snow"],
              [Code2, "Lines", compact(m.total_lines), "bg-snow"],
              [KeyRound, "Secrets", secrets, secrets ? "bg-yel" : "bg-snow"],
              [Package, "Vuln deps", vulnDeps, vulnDeps ? "bg-tang" : "bg-snow"],
            ].map(([Icon, label, v, bg]) => (
              <div key={label} className={`flex items-center gap-3 px-3 py-2.5 rounded-[10px] border-2 border-ink ${bg}`}>
                <Icon className="w-4 h-4" strokeWidth={2.5} />
                <span className="text-[13px] font-semibold">{label}</span>
                <span className="ml-auto font-display text-xl font-extrabold tabular">{v ?? 0}</span>
              </div>
            ))}
          </div>
        </div>
        {analysis.scanners_run && (
          <div className="mt-6 pt-5 border-t-2 border-ink flex flex-wrap items-center gap-2">
            <span className="eyebrow mr-1">Engines</span>
            {analysis.scanners_run.map((s) => (
              <span key={s} className="chip" title={SCANNERS[s]?.blurb}>
                <span className="w-2 h-2 rounded-full bg-mint border border-ink" /> {SCANNERS[s]?.label || s}
                {analysis.scanner_counts?.[s] ? <span className="font-mono text-sub">{analysis.scanner_counts[s]}</span> : null}
              </span>
            ))}
          </div>
        )}
      </section>

      {/* AI summary */}
      {analysis.ai_summary && (
        <section className="card mt-5 p-6 bg-lilac fade-up d-1">
          <span className="sticker bg-snow -rotate-2"><Sparkles className="w-3.5 h-3.5" strokeWidth={3} /> AI triage</span>
          <p className="mt-4 text-lg font-medium leading-relaxed">{analysis.ai_summary}</p>
          {analysis.recommendations?.length > 0 && (
            <ol className="mt-5 grid md:grid-cols-2 gap-3">
              {analysis.recommendations.map((r, i) => (
                <li key={r} className="flex gap-3 p-3 rounded-[10px] border-2 border-ink bg-snow text-[15px]">
                  <span className="font-mono text-sm font-bold">{String(i + 1).padStart(2, "0")}</span>{r}
                </li>
              ))}
            </ol>
          )}
        </section>
      )}

      {/* Tabs */}
      <div className="mt-7 mb-5 flex gap-2 overflow-x-auto pb-1" role="tablist">
        {TABS.map(({ key, label, icon: Icon }) => (
          <button key={key} role="tab" aria-selected={tab === key} onClick={() => setTab(key)}
                  className={`flex items-center gap-2 px-4 h-11 rounded-[10px] border-[2.5px] text-[15px] font-bold whitespace-nowrap transition-all ${
                    tab === key ? "bg-ink text-white border-ink shadow-[3px_3px_0_0_#3B5BFF]" : "bg-snow border-ink hover:-translate-y-0.5"}`}>
            <Icon className="w-4 h-4" strokeWidth={2.5} /> {label}
            {tabCount[key] ? <span className={`text-[11px] font-mono px-1.5 rounded ${tab === key ? "bg-yel text-ink" : "bg-cream border border-ink"}`}>{tabCount[key]}</span> : null}
          </button>
        ))}
      </div>

      <div className="fade-up">
        {tab === "findings" && <FindingsTab analysis={analysis} />}
        {tab === "deps" && <DependenciesTab analysis={analysis} />}
        {tab === "health" && <HealthTab analysis={analysis} />}
        {tab === "ship" && <ShipTab analysis={analysis} />}
      </div>
    </AppShell>
  );
}
