import { useEffect, useRef, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import { useDropzone } from "react-dropzone";
import {
  Github, FolderOpen, Files, FileArchive, Lock, ScanSearch, Download, FileText, FileJson, ShieldCheck, Package,
  Trash2, ArrowRight, X, Info,
} from "lucide-react";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import AppShell from "@/components/AppShell";
import { EmptyState, GradePill } from "@/components/viz";
import { normalizeAnalysis, timeAgo } from "@/lib/api";
import { runLocalScan } from "@/lib/engine/client";
import { toCycloneDx, toSarif } from "@/lib/engine/exporters";
import { getLocalScan, listLocalScans, removeLocalScan, saveLocalScan } from "@/lib/localHistory";
import { exportPdf } from "@/lib/report";
import { ReportBody, ReportExports } from "@/pages/AnalysisDetail";
import { DEMO_REPOS } from "@/pages/Dashboard";

const GITHUB_URL = /^https?:\/\/(www\.)?github\.com\/[^/\s]+\/[^/\s]+/;

function saveJson(data, filename) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  Object.assign(document.createElement("a"), { href: url, download: filename }).click();
  URL.revokeObjectURL(url);
}

// SARIF and SBOM for browser scans are built from the report itself; there is no API to download them from.
const BROWSER_EXPORTS = {
  sarif: (a) => saveJson(toSarif(a.security_issues || [], a.suppressed_issues || []), `${a.name}.sarif`),
  sbom: (a) => saveJson(toCycloneDx(a.dependencies || [], a.name), `${a.name}.cdx.json`),
};

export default function LocalScan() {
  const navigate = useNavigate();
  const [url, setUrl] = useState("");
  const [token, setToken] = useState(""); // this component's memory only
  const [osv, setOsv] = useState(true);
  const [job, setJob] = useState(null); // { stage, pct, cancel }
  const [error, setError] = useState("");
  const [recent, setRecent] = useState(listLocalScans);
  const folderInput = useRef();
  const running = useRef(null);

  useEffect(() => () => running.current?.cancel(), []);

  const start = (kind, input, name) => {
    setError("");
    const scan = runLocalScan({ kind, input, name, token: token.trim() || undefined, osv },
      (stage, pct) => setJob((j) => j && { ...j, stage, pct }));
    running.current = scan;
    setJob({ stage: "Starting", pct: 0, cancel: scan.cancel });
    scan.promise.then((analysis) => {
      if (!saveLocalScan(analysis)) toast.message("This browser couldn't store the scan, so it won't appear under recent scans.");
      navigate(`/scan/${analysis.analysis_id}`, { state: { analysis } });
    }).catch((err) => {
      if (err.name !== "AbortError") setError(err.message);
    }).finally(() => {
      running.current = null;
      setJob(null);
    });
  };

  const scanRepo = () => {
    if (!GITHUB_URL.test(url.trim())) {
      setError("Paste a public GitHub repo URL like https://github.com/owner/repo");
      return;
    }
    start("github", url.trim());
  };

  const scanFiles = (files) => {
    if (!files.length) return;
    const zip = files.length === 1 && /\.zip$/i.test(files[0].name);
    start(zip ? "zip" : "files", zip ? files[0] : files, zip ? files[0].name.replace(/\.zip$/i, "") : undefined);
  };

  const { getRootProps, getInputProps, open, isDragActive } = useDropzone({ onDrop: scanFiles, noClick: true, noKeyboard: true });

  const forget = (id) => {
    removeLocalScan(id);
    setRecent(listLocalScans());
  };

  return (
    <AppShell title="Browser scan">
      <div className="max-w-4xl mx-auto">
        <span className="sticker bg-lime -rotate-2"><Lock className="w-3.5 h-3.5" strokeWidth={3} /> no sign-up, no server</span>
        <h1 className="mt-4 font-display text-4xl md:text-5xl font-extrabold">scan it in your browser 🔍</h1>
        <p className="mt-2 text-[15px] text-sub max-w-2xl">
          Folders, ZIPs and files are scanned on this device, and your code never leaves the browser. GitHub repos are fetched straight from GitHub.
        </p>

        {job ? (
          <div className="card p-6 mt-6" aria-live="polite">
            <div className="flex items-center justify-between gap-3">
              <div className="font-bold">{job.stage}…</div>
              <button className="btn-secondary btn-sm" onClick={job.cancel}><X className="w-4 h-4" strokeWidth={2.5} /> Cancel</button>
            </div>
            <div className="mt-4 h-4 rounded-full border-2 border-ink bg-cream overflow-hidden" role="progressbar"
                 aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(job.pct)} aria-label="Scan progress">
              <div className="h-full bg-cobalt transition-all" style={{ width: `${Math.max(4, job.pct)}%` }} />
            </div>
          </div>
        ) : (
          <>
            <section className="card p-5 md:p-6 mt-6">
              <label htmlFor="repo-url" className="font-display text-xl font-extrabold flex items-center gap-2">
                <Github className="w-5 h-5" strokeWidth={2.5} /> Public GitHub repo
              </label>
              <div className="mt-3 flex flex-col sm:flex-row gap-2">
                <input id="repo-url" className="input flex-1" placeholder="https://github.com/owner/repo" value={url}
                       onChange={(e) => setUrl(e.target.value)} onKeyDown={(e) => e.key === "Enter" && scanRepo()} />
                <button className="btn-primary" onClick={scanRepo}>Scan repo <ArrowRight className="w-4 h-4" strokeWidth={3} /></button>
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                {DEMO_REPOS.map((r) => <button key={r.url} className="chip" onClick={() => setUrl(r.url)}>{r.label}</button>)}
              </div>
              <details className="mt-3 text-[13px]">
                <summary className="cursor-pointer font-semibold">Private repo or rate-limited? Add a GitHub token</summary>
                <label htmlFor="gh-token" className="sr-only">GitHub token</label>
                <input id="gh-token" type="password" autoComplete="off" className="input mt-2" placeholder="ghp_… (read-only is enough)"
                       value={token} onChange={(e) => setToken(e.target.value)} />
                <p className="mt-1 text-sub">Kept in this tab's memory only. It is sent to GitHub and nowhere else, and never saved.</p>
              </details>
            </section>

            <section {...getRootProps({
              className: `card p-6 mt-5 border-dashed text-center transition-colors ${isDragActive ? "bg-yel" : ""}`,
            })}>
              <input {...getInputProps()} aria-label="Choose files to scan" />
              <input ref={folderInput} type="file" className="hidden" webkitdirectory="" directory="" multiple aria-label="Choose a folder to scan"
                     onChange={(e) => { scanFiles(Array.from(e.target.files || [])); e.target.value = ""; }} />
              <FileArchive className="w-9 h-9 mx-auto" strokeWidth={2} />
              <div className="mt-3 font-display text-xl font-extrabold">Drop a folder, a .zip, or files</div>
              <div className="text-[13px] text-sub mt-1">node_modules, build output and lockfiles are skipped. Up to 400 files.</div>
              <div className="mt-4 flex flex-wrap justify-center gap-2">
                <button className="btn-secondary btn-sm" onClick={() => folderInput.current?.click()}><FolderOpen className="w-4 h-4" strokeWidth={2.5} /> Choose folder</button>
                <button className="btn-secondary btn-sm" onClick={open}><Files className="w-4 h-4" strokeWidth={2.5} /> Choose files or ZIP</button>
              </div>
            </section>

            <label className="mt-4 flex items-start gap-3 text-[13px] cursor-pointer">
              <input type="checkbox" className="mt-0.5 w-4 h-4 accent-[#111]" checked={osv} onChange={(e) => setOsv(e.target.checked)} />
              <span><b>Check dependencies against OSV.dev.</b> Sends package names and versions to OSV.dev (relayed through this site), never your code.</span>
            </label>
            {error && <div role="alert" className="mt-4 p-3 rounded-[10px] border-2 border-ink bg-cherry/30 text-sm font-semibold">{error}</div>}
          </>
        )}

        <div className="mt-6 p-4 rounded-[12px] border-2 border-ink bg-cream text-[13px] flex gap-3">
          <Info className="w-4 h-4 shrink-0 mt-0.5" strokeWidth={2.5} />
          <span>Runs the rule pack, secrets detection (with entropy checks), OSV.dev dependency audit and a complexity heuristic. They're held to the
            server engine by parity tests. Bandit, Semgrep, AI triage and scan history across devices need a <b>cloud scan</b>.</span>
        </div>

        {recent.length > 0 && (
          <section className="mt-8">
            <h2 className="font-display text-2xl font-extrabold">Recent scans in this browser</h2>
            <div className="card mt-3 overflow-hidden">
              {recent.map((a) => (
                <div key={a.analysis_id} className="flex items-center gap-3 px-4 py-3 border-b-2 border-ink/10 last:border-0 hover:bg-yel/40">
                  <GradePill grade={a.grade} />
                  <button className="min-w-0 flex-1 text-left" onClick={() => navigate(`/scan/${a.analysis_id}`)}>
                    <div className="font-bold truncate">{a.name}</div>
                    <div className="text-[12px] text-sub">{a.issue_count} findings · {timeAgo(a.created_at)}</div>
                  </button>
                  <button className="p-1.5 rounded-md border-2 border-transparent hover:border-ink hover:bg-cherry" aria-label={`Forget ${a.name}`}
                          onClick={() => forget(a.analysis_id)}>
                    <Trash2 className="w-4 h-4" strokeWidth={2.5} />
                  </button>
                </div>
              ))}
            </div>
          </section>
        )}
      </div>
    </AppShell>
  );
}

export function LocalReport() {
  const { localId } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const raw = location.state?.analysis?.analysis_id === localId ? location.state.analysis : getLocalScan(localId);

  if (!raw) {
    return (
      <AppShell title="Browser scan">
        <EmptyState icon={ScanSearch} title="Scan not found in this browser"
                    body="Browser scans are kept on the device that ran them, and only the last few."
                    action={<button className="btn-primary" onClick={() => navigate("/scan")}>New browser scan</button>} />
      </AppShell>
    );
  }
  const analysis = normalizeAnalysis(raw);

  const actions = (
    <>
      <button className="btn-ghost btn-sm hidden sm:inline-flex" onClick={() => navigate("/scan")}><ScanSearch className="w-4 h-4" strokeWidth={2.5} /> New scan</button>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button className="btn-primary btn-sm"><Download className="w-4 h-4" strokeWidth={2.5} /> Export</button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56 bg-snow border-[2.5px] border-ink shadow-brut rounded-[12px] p-1.5 text-ink font-semibold">
          <DropdownMenuItem className="rounded-lg focus:bg-yel" onClick={() => { exportPdf(analysis); toast.success("PDF report generated"); }}><FileText className="w-4 h-4 mr-2" /> PDF audit report</DropdownMenuItem>
          <DropdownMenuItem className="rounded-lg focus:bg-yel" onClick={() => BROWSER_EXPORTS.sarif(analysis)}><ShieldCheck className="w-4 h-4 mr-2" /> SARIF (Code Scanning)</DropdownMenuItem>
          <DropdownMenuItem className="rounded-lg focus:bg-yel" onClick={() => BROWSER_EXPORTS.sbom(analysis)}><Package className="w-4 h-4 mr-2" /> CycloneDX SBOM</DropdownMenuItem>
          <DropdownMenuSeparator className="bg-ink/20" />
          <DropdownMenuItem className="rounded-lg focus:bg-yel" onClick={() => saveJson(analysis, `${analysis.name}.json`)}><FileJson className="w-4 h-4 mr-2" /> Raw JSON</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </>
  );

  return (
    <AppShell title={analysis.name} actions={actions}>
      <ReportExports.Provider value={BROWSER_EXPORTS}>
        {analysis.trimmed && (
          <div className="mb-4 p-3 rounded-[10px] border-2 border-ink bg-tang text-[13px] font-semibold">
            This report was too large to keep in full, so the saved copy shows its top findings only. Re-scan for everything.
          </div>
        )}
        <ReportBody analysis={analysis} />
      </ReportExports.Provider>
    </AppShell>
  );
}
