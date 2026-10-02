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
import { Delta, EmptyState, GradeRing, SeverityBadge, SeverityBar, Spinner } from "@/components/viz";
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

function CopyButton({ text, label = "Copy" }) {
  const [done, setDone] = useState(false);
  return (
    <button className="btn-ghost btn-sm" onClick={() => {
      navigator.clipboard.writeText(text);
      setDone(true);
      setTimeout(() => setDone(false), 1500);
    }}>
      {done ? <Check className="w-3.5 h-3.5 text-[#00e599]" /> : <Copy className="w-3.5 h-3.5" />} {done ? "Copied" : label}
    </button>
  );
}

function ScanningView({ analysis }) {
  const current = analysis.progress?.stage || "Queued";
  const idx = STAGES.indexOf(current);
  return (
    <div className="max-w-2xl mx-auto py-8">
      <div className="card relative overflow-hidden p-8">
        <div className="absolute inset-x-0 top-0 h-24 bg-gradient-to-b from-[#00e599]/20 to-transparent scan-line pointer-events-none" />
        <div className="relative">
          <div className="flex items-center gap-2 text-sm text-[#7cf5c8]"><span className="w-2 h-2 rounded-full bg-[#00e599] pulse-dot" /> Scanning</div>
          <h1 className="mt-3 text-2xl font-semibold">{analysis.name}</h1>
          <div className="mt-6 h-1.5 rounded-full bg-[#1c1c20] overflow-hidden">
            <div className="h-full rounded-full bg-gradient-to-r from-[#00e599] to-[#5eead4] transition-all duration-700"
                 style={{ width: `${analysis.progress?.pct || 5}%` }} />
          </div>
          <ol className="mt-8 space-y-3">
            {STAGES.map((s, i) => {
              const state = idx > i ? "done" : idx === i ? "active" : "todo";
              return (
                <li key={s} className={`flex items-center gap-3 text-sm ${state === "todo" ? "text-[#52525b]" : "text-[#e4e4e7]"}`}>
                  {state === "done" ? <CheckCircle2 className="w-4 h-4 text-[#00e599]" /> :
                   state === "active" ? <span className="w-4 h-4 rounded-full border-2 border-[#00e599] border-t-transparent animate-spin" /> :
                   <span className="w-4 h-4 rounded-full border border-[#3f3f46]" />}
                  {s}
                </li>
              );
            })}
          </ol>
          <p className="mt-8 text-xs text-[#71717a]">You can leave this page — the scan keeps running and shows up in your history.</p>
        </div>
      </div>
    </div>
  );
}

function FindingRow({ issue, fix, open, onToggle }) {
  return (
    <div className={`border-b border-white/[0.05] last:border-0 ${open ? "bg-white/[0.015]" : ""}`}>
      <button onClick={onToggle} className="w-full flex items-start gap-3 px-4 py-3.5 text-left hover:bg-white/[0.02]">
        <span className="w-[76px] shrink-0"><SeverityBadge severity={issue.severity} /></span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium text-sm">{issue.type}</span>
            {issue.is_new && <span className="chip h-5 text-[10px] text-[#fcd34d] border-[#fcd34d]/30 bg-[#fcd34d]/10">NEW</span>}
            {fix && <span className="chip h-5 text-[10px] text-[#c4b5fd] border-[#a78bfa]/30 bg-[#a78bfa]/10"><Sparkles className="w-2.5 h-2.5" /> AI patch</span>}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-[#71717a]">
            <code className="text-[#a1a1aa]">{issue.file_path}{issue.line_number ? `:${issue.line_number}` : ""}</code>
            {issue.cwe && <span>{issue.cwe}</span>}
            {issue.owasp && <span>{issue.owasp.split(":")[0]} {OWASP_NAMES[issue.owasp]}</span>}
            {issue.scanner && <span>via {SCANNERS[issue.scanner]?.label || issue.scanner}</span>}
          </div>
        </div>
        <ChevronDown className={`w-4 h-4 mt-0.5 text-[#52525b] transition-transform ${open ? "rotate-180" : ""}`} />
      </button>
      {open && (
        <div className="px-4 pb-5 pl-4 md:pl-[104px] space-y-4">
          {!(issue.snippet && issue.description?.startsWith("Found:")) && <p className="text-sm text-[#a1a1aa]">{issue.description}</p>}
          {issue.snippet && issue.scanner !== "secrets" && <pre className="code-block">{issue.snippet}</pre>}
          <div className="flex gap-2.5 p-3 rounded-xl bg-[#00e599]/[0.05] border border-[#00e599]/15 text-sm">
            <ShieldCheck className="w-4 h-4 mt-0.5 shrink-0 text-[#00e599]" />
            <span className="text-[#d4d4d8]">{issue.recommendation}</span>
          </div>
          {fix && (
            <div className="rounded-xl border border-[#a78bfa]/25 overflow-hidden">
              <div className="flex items-center justify-between px-4 py-2 bg-[#a78bfa]/[0.08] border-b border-[#a78bfa]/20">
                <span className="flex items-center gap-2 text-xs font-medium text-[#c4b5fd]"><Sparkles className="w-3.5 h-3.5" /> Suggested patch</span>
                <CopyButton text={fix.fix_code} label="Copy patch" />
              </div>
              <div className="p-4 space-y-3">
                {fix.explanation && <p className="text-xs text-[#a1a1aa]">{fix.explanation}</p>}
                <pre className="code-block">{fix.fix_code}</pre>
              </div>
            </div>
          )}
          {issue.cwe && (
            <a className="inline-flex items-center gap-1 text-xs text-[#71717a] hover:text-white" target="_blank" rel="noreferrer"
               href={`https://cwe.mitre.org/data/definitions/${issue.cwe.replace("CWE-", "")}.html`}>
              Read about {issue.cwe} <ExternalLink className="w-3 h-3" />
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
    return <EmptyState icon={CheckCircle2} title="No security findings" body="Every engine came back clean. Go touch grass. 🌱" />;
  }

  return (
    <div className="card overflow-hidden">
      <div className="p-4 border-b border-white/[0.06] flex flex-col lg:flex-row gap-3 lg:items-center">
        <div className="relative flex-1 max-w-sm">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#71717a]" />
          <input className="input h-9 pl-9 text-sm" placeholder="Search file, CWE, rule…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="flex flex-wrap gap-1.5">
          <button className={`chip h-7 px-3 ${!sev ? "chip-active" : ""}`} onClick={() => setSev(null)}>All {issues.length}</button>
          {SEVERITY_ORDER.filter((s) => counts[s]).map((s) => (
            <button key={s} className={`chip h-7 px-3 capitalize ${sev === s ? "chip-active" : ""}`} onClick={() => setSev(sev === s ? null : s)}>
              {s} {counts[s]}
            </button>
          ))}
          {scanners.length > 1 && <span className="w-px h-7 bg-white/10 mx-1" />}
          {scanners.length > 1 && scanners.map((s) => (
            <button key={s} className={`chip h-7 px-3 ${scanner === s ? "chip-active" : ""}`} onClick={() => setScanner(scanner === s ? null : s)}>
              {SCANNERS[s]?.label || s}
            </button>
          ))}
          {analysis.baseline?.new > 0 && (
            <button className={`chip h-7 px-3 ${onlyNew ? "chip-active" : ""}`} onClick={() => setOnlyNew(!onlyNew)}>New only {analysis.baseline.new}</button>
          )}
        </div>
      </div>
      {shown.length ? shown.map((issue, i) => {
        const key = issue.fingerprint || `${issue.file_path}-${issue.line_number}-${i}`;
        return <FindingRow key={key} issue={issue} fix={findFix(issue)} open={!!open[key]} onToggle={() => setOpen((o) => ({ ...o, [key]: !o[key] }))} />;
      }) : <div className="p-10 text-center text-sm text-[#71717a]">No findings match those filters.</div>}
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
      <div className="p-4 border-b border-white/[0.06] flex flex-wrap items-center justify-between gap-3">
        <div className="text-sm"><span className="font-semibold">{vulnerable.length}</span> <span className="text-[#71717a]">of {deps.length} packages have known advisories</span></div>
        <div className="flex gap-2">
          <button className={`chip h-7 px-3 ${vulnOnly ? "chip-active" : ""}`} onClick={() => setVulnOnly(true)}>Vulnerable</button>
          <button className={`chip h-7 px-3 ${!vulnOnly ? "chip-active" : ""}`} onClick={() => setVulnOnly(false)}>All packages</button>
          <button className="btn-secondary btn-sm" onClick={() => downloadFromApi(`/analysis/${analysis.analysis_id}/sbom`, `${analysis.name}.cdx.json`)}>
            <Download className="w-3.5 h-3.5" /> SBOM
          </button>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-left text-xs text-[#71717a]">
            <tr className="border-b border-white/[0.06]">
              <th className="px-4 py-3 font-medium">Package</th><th className="px-4 py-3 font-medium">Version</th>
              <th className="px-4 py-3 font-medium">Ecosystem</th><th className="px-4 py-3 font-medium">Advisories</th>
              <th className="px-4 py-3 font-medium">Fixed in</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((d) => {
              const worst = SEVERITY_ORDER.find((s) => d.vulnerabilities?.some((v) => v.severity === s));
              const fix = d.vulnerabilities?.map((v) => v.fixed_in).filter(Boolean).sort().pop();
              return (
                <tr key={`${d.manifest}-${d.name}`} className="border-b border-white/[0.04] last:border-0 hover:bg-white/[0.015]">
                  <td className="px-4 py-3"><div className="font-medium">{d.name}</div><div className="text-[11px] text-[#52525b]">{d.manifest}{d.dev ? " · dev" : ""}</div></td>
                  <td className="px-4 py-3 font-mono text-xs tabular">{d.version || <span className="text-[#52525b]">unpinned</span>}</td>
                  <td className="px-4 py-3 text-[#a1a1aa]">{d.ecosystem}</td>
                  <td className="px-4 py-3">
                    {d.vulnerabilities?.length ? (
                      <div className="flex flex-wrap items-center gap-1.5">
                        <SeverityBadge severity={worst} />
                        {d.vulnerabilities.slice(0, 3).map((v) => (
                          <a key={v.id} href={`https://osv.dev/vulnerability/${v.id}`} target="_blank" rel="noreferrer"
                             className="font-mono text-[11px] text-[#a1a1aa] hover:text-white underline decoration-white/20" title={v.summary}>
                            {v.aliases?.find((a) => a.startsWith("CVE")) || v.id}
                          </a>
                        ))}
                        {d.vulnerabilities.length > 3 && <span className="text-[11px] text-[#71717a]">+{d.vulnerabilities.length - 3}</span>}
                      </div>
                    ) : <span className="text-xs text-[#52525b]">{d.version ? "none known" : "not checked"}</span>}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-[#7cf5c8]">{fix || <span className="text-[#52525b]">—</span>}</td>
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
  return (
    <div className="space-y-4">
      <div className="grid md:grid-cols-3 gap-4">
        <div className="card p-5">
          <div className="eyebrow">Maintainability index</div>
          <div className="mt-2 text-3xl font-semibold tabular">{Math.round(m.maintainability_index || 0)}<span className="text-base text-[#71717a]">/100</span></div>
          <div className="mt-3 h-1.5 rounded-full bg-[#1c1c20]"><div className="h-full rounded-full bg-[#00e599]" style={{ width: `${m.maintainability_index || 0}%` }} /></div>
        </div>
        <div className="card p-5">
          <div className="eyebrow">Avg cyclomatic complexity</div>
          <div className="mt-2 text-3xl font-semibold tabular">{(m.avg_complexity || 0).toFixed(1)}</div>
          <div className="mt-2 text-xs text-[#71717a]">per function · ≤5 is great, &gt;10 is spicy</div>
        </div>
        <div className="card p-5">
          <div className="eyebrow">Languages</div>
          <div className="mt-3 flex h-2.5 gap-[2px] rounded-full overflow-hidden">
            {langs.map(([l, n]) => <div key={l} style={{ width: `${(n / langTotal) * 100}%`, background: languageColor(l) }} title={`${l}: ${n} lines`} />)}
          </div>
          <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-xs">
            {langs.map(([l, n]) => (
              <span key={l} className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-sm" style={{ background: languageColor(l) }} />
                <span className="capitalize">{l}</span><span className="text-[#71717a]">{Math.round((n / langTotal) * 100)}%</span></span>
            ))}
          </div>
        </div>
      </div>

      {!risks.length ? <EmptyState icon={Gauge} title="No complexity hotspots" body="Every file is within healthy thresholds." /> : (
        <div className="card overflow-hidden">
          <div className="hidden md:grid grid-cols-[1fr_80px_80px_80px_80px_160px_24px] gap-4 px-4 py-3 text-xs text-[#71717a] border-b border-white/[0.06]">
            <span>File</span><span className="text-right">Lines</span><span className="text-right">Avg CC</span><span className="text-right">Max CC</span>
            <span className="text-right">MI</span><span>Risk</span><span />
          </div>
          {risks.map((r) => {
            const refactor = refactorFor(r.file_path);
            const isOpen = open === r.file_path;
            const color = r.risk_score > 50 ? "#d03b3b" : r.risk_score > 25 ? "#fab219" : "#00e599";
            return (
              <div key={r.file_path} className="border-b border-white/[0.04] last:border-0">
                <button onClick={() => setOpen(isOpen ? null : r.file_path)}
                        className="w-full grid grid-cols-[1fr_auto] md:grid-cols-[1fr_80px_80px_80px_80px_160px_24px] gap-4 items-center px-4 py-3 text-left text-sm hover:bg-white/[0.02]">
                  <span className="min-w-0 flex items-center gap-2">
                    <FileCode className="w-4 h-4 shrink-0 text-[#71717a]" />
                    <code className="truncate text-[13px]">{r.file_path}</code>
                    {refactor && <Sparkles className="w-3.5 h-3.5 shrink-0 text-[#a78bfa]" />}
                  </span>
                  <span className="hidden md:block text-right tabular text-[#a1a1aa]">{r.lines || "—"}</span>
                  <span className="hidden md:block text-right tabular text-[#a1a1aa]">{r.cyclomatic ? r.cyclomatic.toFixed(1) : "—"}</span>
                  <span className="hidden md:block text-right tabular text-[#a1a1aa]">{r.max_cyclomatic || "—"}</span>
                  <span className="hidden md:block text-right tabular text-[#a1a1aa]">{r.maintainability != null ? Math.round(r.maintainability) : "—"}</span>
                  <span className="flex items-center gap-2">
                    <span className="hidden md:block flex-1 h-1.5 rounded-full bg-[#1c1c20]"><span className="block h-full rounded-full" style={{ width: `${r.risk_score}%`, background: color }} /></span>
                    <span className="tabular text-xs w-7 text-right" style={{ color }}>{Math.round(r.risk_score)}</span>
                  </span>
                  <ChevronDown className={`hidden md:block w-4 h-4 text-[#52525b] transition-transform ${isOpen ? "rotate-180" : ""}`} />
                </button>
                {isOpen && (
                  <div className="px-4 pb-5 md:pl-10 space-y-4">
                    <ul className="space-y-1.5">
                      {r.issues.map((i) => <li key={i} className="flex gap-2 text-sm text-[#a1a1aa]"><XCircle className="w-4 h-4 mt-0.5 shrink-0 text-[#ec835a]" />{i}</li>)}
                    </ul>
                    {r.hotspots?.length > 0 && (
                      <div>
                        <div className="eyebrow mb-2">Hotspot functions</div>
                        <div className="flex flex-wrap gap-2">
                          {r.hotspots.map((h) => (
                            <span key={`${h.name}-${h.line}`} className="chip h-7 px-3 font-mono">
                              {h.name}<span className="text-[#71717a]">:{h.line}</span>
                              <span className="font-semibold" style={{ color: GRADE[h.rank === "A" || h.rank === "B" ? "A" : h.rank === "C" ? "C" : "F"]?.color }}>CC {h.complexity} · {h.rank}</span>
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                    {refactor && (
                      <div className="rounded-xl border border-[#a78bfa]/25 overflow-hidden">
                        <div className="flex items-center justify-between px-4 py-2 bg-[#a78bfa]/[0.08] border-b border-[#a78bfa]/20">
                          <span className="flex items-center gap-2 text-xs font-medium text-[#c4b5fd]"><Sparkles className="w-3.5 h-3.5" /> AI refactor</span>
                          <CopyButton text={refactor.refined_code} label="Copy code" />
                        </div>
                        <div className="p-4 space-y-3">
                          <p className="text-xs text-[#a1a1aa]">{refactor.explanation}</p>
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

function CodeCard({ title, body, code, lang }) {
  return (
    <div className="card overflow-hidden">
      <div className="flex items-center justify-between px-5 py-4 border-b border-white/[0.06]">
        <div><div className="font-medium text-[15px]">{title}</div><div className="text-xs text-[#71717a] mt-0.5">{body}</div></div>
        <CopyButton text={code} />
      </div>
      <pre className="code-block rounded-none border-0 m-0" data-lang={lang}>{code}</pre>
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
    <div className="grid xl:grid-cols-2 gap-4">
      <CodeCard title="Gate pull requests" body="Fails CI on high-severity findings and publishes results to GitHub's Security tab." code={workflow} lang="yaml" />
      <div className="space-y-4">
        <div className="card p-5">
          <div className="font-medium text-[15px]">README badge</div>
          <div className="text-xs text-[#71717a] mt-0.5">Flex your grade. Shows only the grade and score of this scan.</div>
          <div className="mt-4 p-4 rounded-xl bg-[#0b0b0d] border border-white/[0.06] flex items-center justify-between gap-3">
            <img src={badgeUrl} alt="CodeGuard badge" className="h-5" />
            <CopyButton text={badgeMd} label="Copy markdown" />
          </div>
        </div>
        <CodeCard title="Run locally" body="Same engine as this dashboard, as a CLI." code={cli} lang="bash" />
        <div className="card p-5 flex flex-wrap gap-2">
          <button className="btn-secondary btn-sm" onClick={() => downloadFromApi(`/analysis/${analysis.analysis_id}/sarif`, `${analysis.name}.sarif`)}>
            <Download className="w-3.5 h-3.5" /> SARIF 2.1.0
          </button>
          <button className="btn-secondary btn-sm" onClick={() => downloadFromApi(`/analysis/${analysis.analysis_id}/sbom`, `${analysis.name}.cdx.json`)}>
            <Download className="w-3.5 h-3.5" /> CycloneDX SBOM
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
          toast.success(`Scan complete — grade ${data.grade}`);
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
          <EmptyState icon={XCircle} title="Scan failed" body={analysis.error || analysis.ai_summary || "Something went wrong."}
            action={<div className="flex justify-center gap-2">
              {analysis.source_url && <button className="btn-primary" onClick={rescan}><RefreshCw className="w-4 h-4" /> Retry</button>}
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
        <button className="btn-ghost btn-sm hidden sm:inline-flex" onClick={rescan}><RefreshCw className="w-3.5 h-3.5" /> Re-scan</button>
      )}
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button className="btn-secondary btn-sm"><Download className="w-3.5 h-3.5" /> Export</button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-52 bg-[#18181b] border-white/10 text-[#e4e4e7]">
          <DropdownMenuItem onClick={() => { exportPdf(analysis); toast.success("PDF report generated"); }}><FileText className="w-4 h-4 mr-2" /> PDF audit report</DropdownMenuItem>
          <DropdownMenuItem onClick={() => downloadFromApi(`/analysis/${id}/sarif`, `${analysis.name}.sarif`)}><ShieldCheck className="w-4 h-4 mr-2" /> SARIF (Code Scanning)</DropdownMenuItem>
          <DropdownMenuItem onClick={() => downloadFromApi(`/analysis/${id}/sbom`, `${analysis.name}.cdx.json`)}><Package className="w-4 h-4 mr-2" /> CycloneDX SBOM</DropdownMenuItem>
          <DropdownMenuSeparator className="bg-white/10" />
          <DropdownMenuItem onClick={() => {
            const url = URL.createObjectURL(new Blob([JSON.stringify(analysis, null, 2)], { type: "application/json" }));
            Object.assign(document.createElement("a"), { href: url, download: `${analysis.name}.json` }).click();
            URL.revokeObjectURL(url);
          }}><FileJson className="w-4 h-4 mr-2" /> Raw JSON</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      {confirmDelete ? (
        <span className="flex items-center gap-1">
          <button className="btn-sm btn bg-[#d03b3b] text-white hover:bg-[#b83232]" onClick={remove}>Delete</button>
          <button className="btn-ghost btn-sm" onClick={() => setConfirmDelete(false)}>Cancel</button>
        </span>
      ) : (
        <button className="btn-ghost btn-sm text-[#f87171]" onClick={() => setConfirmDelete(true)} aria-label="Delete scan"><Trash2 className="w-3.5 h-3.5" /></button>
      )}
    </>
  );

  return (
    <AppShell title={analysis.name} actions={actions}>
      {/* Hero */}
      <section className="card relative overflow-hidden p-6 md:p-8 fade-up">
        <div className="glow-orb w-96 h-96 -top-40 -left-24" style={{ background: `${g.color}1c` }} />
        <div className="relative grid lg:grid-cols-[auto_1fr_auto] gap-8 items-center">
          <GradeRing score={analysis.overall_score} grade={grade} size={176} label="Overall score" />
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 text-xs text-[#71717a]">
              <span className="chip">{analysis.source_type === "github" ? "GitHub" : "ZIP upload"}</span>
              {analysis.repo_meta?.ref && <span className="chip font-mono">{analysis.repo_meta.ref}</span>}
              {analysis.repo_meta?.stars != null && <span className="chip"><Star className="w-3 h-3" /> {compact(analysis.repo_meta.stars)}</span>}
              <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> {timeAgo(analysis.created_at)}</span>
              {analysis.duration_ms && <span>· scanned in {(analysis.duration_ms / 1000).toFixed(1)}s</span>}
            </div>
            <h1 className="mt-3 text-2xl md:text-3xl font-semibold truncate">{analysis.name}</h1>
            <div className="mt-1 text-lg font-medium" style={{ color: g.color }}>{g.vibe}</div>
            {analysis.repo_meta?.description && <p className="mt-2 text-sm text-[#71717a] line-clamp-2">{analysis.repo_meta.description}</p>}
            {analysis.baseline && (
              <div className="mt-4 inline-flex flex-wrap items-center gap-4 px-3 py-2 rounded-xl bg-white/[0.03] border border-white/[0.06] text-xs">
                <span className="text-[#71717a]">vs previous scan</span>
                <Delta value={analysis.baseline.score_delta} suffix=" pts" />
                <span><span className="text-[#fcd34d] font-semibold">{analysis.baseline.new}</span> <span className="text-[#71717a]">new</span></span>
                <span><span className="text-[#4ade80] font-semibold">{analysis.baseline.fixed}</span> <span className="text-[#71717a]">fixed</span></span>
              </div>
            )}
            <div className="mt-5 max-w-lg"><SeverityBar counts={counts} /></div>
          </div>
          <div className="grid grid-cols-2 lg:grid-cols-1 gap-3 lg:w-48">
            {[
              [FileCode, "Files", m.total_files],
              [Code2, "Lines", compact(m.total_lines)],
              [KeyRound, "Secrets", secrets],
              [Package, "Vulnerable deps", vulnDeps],
            ].map(([Icon, label, v]) => (
              <div key={label} className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-white/[0.025] border border-white/[0.05]">
                <Icon className="w-4 h-4 text-[#71717a]" />
                <span className="text-xs text-[#a1a1aa]">{label}</span>
                <span className="ml-auto font-semibold tabular">{v ?? 0}</span>
              </div>
            ))}
          </div>
        </div>
        {analysis.scanners_run && (
          <div className="relative mt-6 pt-5 border-t border-white/[0.06] flex flex-wrap items-center gap-2">
            <span className="eyebrow mr-1">Engines</span>
            {analysis.scanners_run.map((s) => (
              <span key={s} className="chip" title={SCANNERS[s]?.blurb}>
                <span className="w-1.5 h-1.5 rounded-full bg-[#00e599]" /> {SCANNERS[s]?.label || s}
                {analysis.scanner_counts?.[s] ? <span className="text-[#71717a]">{analysis.scanner_counts[s]}</span> : null}
              </span>
            ))}
          </div>
        )}
      </section>

      {/* AI summary */}
      {analysis.ai_summary && (
        <section className="card mt-4 p-6 border-[#a78bfa]/20 bg-gradient-to-br from-[#a78bfa]/[0.06] to-transparent fade-up d-1">
          <div className="flex items-center gap-2 text-sm font-semibold text-[#c4b5fd]"><Sparkles className="w-4 h-4" /> AI triage</div>
          <p className="mt-3 text-[15px] text-[#e4e4e7] leading-relaxed">{analysis.ai_summary}</p>
          {analysis.recommendations?.length > 0 && (
            <ol className="mt-5 grid md:grid-cols-2 gap-x-8 gap-y-3">
              {analysis.recommendations.map((r, i) => (
                <li key={r} className="flex gap-3 text-sm text-[#a1a1aa]">
                  <span className="font-mono text-xs text-[#a78bfa] mt-0.5">{String(i + 1).padStart(2, "0")}</span>{r}
                </li>
              ))}
            </ol>
          )}
        </section>
      )}

      {/* Tabs */}
      <div className="mt-6 mb-4 flex gap-1 overflow-x-auto border-b border-white/[0.06]" role="tablist">
        {TABS.map(({ key, label, icon: Icon }) => (
          <button key={key} role="tab" aria-selected={tab === key} onClick={() => setTab(key)}
                  className={`relative flex items-center gap-2 px-4 h-11 text-sm whitespace-nowrap transition-colors ${tab === key ? "text-white" : "text-[#71717a] hover:text-[#d4d4d8]"}`}>
            <Icon className="w-4 h-4" /> {label}
            {tabCount[key] ? <span className="text-[11px] px-1.5 rounded-md bg-white/[0.06] tabular">{tabCount[key]}</span> : null}
            {tab === key && <span className="absolute inset-x-3 -bottom-px h-0.5 rounded-full bg-[#00e599]" />}
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
