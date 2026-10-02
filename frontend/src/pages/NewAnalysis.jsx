import { useCallback, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import axios from "axios";
import { toast } from "sonner";
import { useDropzone } from "react-dropzone";
import { Github, FileArchive, Loader2, AlertCircle, ArrowRight, X, ShieldCheck, KeyRound, Package, Gauge, Sparkles } from "lucide-react";
import AppShell from "@/components/AppShell";
import { API } from "@/lib/api";
import { DEMO_REPOS } from "@/pages/Dashboard";

const PIPELINE = [
  { icon: KeyRound, name: "Secrets", body: "13 provider signatures + Shannon entropy", bg: "bg-yel" },
  { icon: ShieldCheck, name: "SAST", body: "Bandit, Semgrep taint rules, cross-language rule pack", bg: "bg-pink" },
  { icon: Package, name: "SCA", body: "npm · PyPI · Go manifests vs OSV.dev", bg: "bg-lilac" },
  { icon: Gauge, name: "Code health", body: "Radon cyclomatic complexity & maintainability", bg: "bg-lime" },
  { icon: Sparkles, name: "AI triage", body: "Llama 3.3 writes patches & refactors", bg: "bg-tang" },
];

export default function NewAnalysis() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [mode, setMode] = useState("github");
  const [githubUrl, setGithubUrl] = useState(params.get("repo") || "");
  const [name, setName] = useState("");
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const onDrop = useCallback((accepted, rejected) => {
    if (accepted[0]) {
      setFile(accepted[0]);
      setError("");
    } else if (rejected.length) {
      setError("Only .zip files up to 25 MB are supported");
    }
  }, []);
  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop, accept: { "application/zip": [".zip"], "application/x-zip-compressed": [".zip"] }, maxFiles: 1, maxSize: 25 * 1024 * 1024,
  });

  const start = async () => {
    setError("");
    if (mode === "github" && !/^https?:\/\/(www\.)?github\.com\/[^/]+\/[^/]+/.test(githubUrl.trim())) {
      setError("Paste a GitHub repo URL like https://github.com/owner/repo");
      return;
    }
    if (mode === "zip" && !file) {
      setError("Drop a ZIP file first");
      return;
    }
    setLoading(true);
    try {
      let res;
      if (mode === "github") {
        res = await axios.post(`${API}/analysis/github`, { github_url: githubUrl.trim(), name: name || undefined });
      } else {
        const form = new FormData();
        form.append("file", file);
        res = await axios.post(`${API}/analysis/upload`, form);
      }
      toast.success("Scan started 🚀");
      navigate(`/analysis/${res.data.analysis_id}`);
    } catch (err) {
      setError(err.response?.data?.detail || "Couldn't start the scan");
      setLoading(false);
    }
  };

  return (
    <AppShell title="New scan">
      <div className="grid lg:grid-cols-[1fr_360px] gap-6 max-w-6xl">
        <div>
          <h1 className="font-display text-5xl md:text-6xl font-extrabold leading-[0.95] fade-up">
            drop a repo.<br /><span className="highlight">get roasted.</span>
          </h1>
          <p className="mt-4 text-lg text-sub fade-up d-1">Public GitHub repo or a ZIP. Results stream in live.</p>

          <div className="mt-7 inline-flex p-1 gap-1 rounded-[12px] border-[2.5px] border-ink bg-snow shadow-brut-sm fade-up d-2" role="tablist">
            {[["github", Github, "GitHub repo"], ["zip", FileArchive, "Upload ZIP"]].map(([key, Icon, label]) => (
              <button key={key} role="tab" aria-selected={mode === key} onClick={() => { setMode(key); setError(""); }}
                      className={`flex items-center gap-2 px-4 h-10 rounded-lg text-sm font-bold transition-colors ${
                        mode === key ? "bg-ink text-white" : "hover:bg-cream"}`}>
                <Icon className="w-4 h-4" strokeWidth={2.5} /> {label}
              </button>
            ))}
          </div>

          <div className="card p-6 md:p-7 mt-5 fade-up d-3">
            {mode === "github" ? (
              <div className="space-y-6">
                <div>
                  <label className="font-bold" htmlFor="repo">Repository URL</label>
                  <div className="relative mt-2">
                    <Github className="w-5 h-5 absolute left-4 top-1/2 -translate-y-1/2" strokeWidth={2.5} />
                    <input id="repo" className="input pl-12 font-mono text-sm" placeholder="https://github.com/owner/repo"
                           value={githubUrl} onChange={(e) => setGithubUrl(e.target.value)} onKeyDown={(e) => e.key === "Enter" && start()}
                           autoFocus data-testid="github-url-input" />
                  </div>
                  <p className="mt-2 text-[13px] text-sub">The default branch is detected automatically. Add <code className="font-mono bg-cream px-1 rounded border border-ink/20">/tree/branch</code> to scan another one.</p>
                </div>
                <div>
                  <label className="font-bold" htmlFor="name">Display name <span className="font-normal text-sub">(optional)</span></label>
                  <input id="name" className="input mt-2" placeholder="owner/repo" value={name} onChange={(e) => setName(e.target.value)} />
                </div>
                <div>
                  <div className="eyebrow mb-2.5">no repo handy? try a deliberately vulnerable one</div>
                  <div className="flex flex-wrap gap-2">
                    {DEMO_REPOS.map((r) => (
                      <button key={r.url} onClick={() => setGithubUrl(r.url)} className={`chip h-9 px-4 ${githubUrl === r.url ? "chip-active" : ""}`}>
                        {r.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div {...getRootProps()} data-testid="dropzone"
                   className={`rounded-[12px] border-[3px] border-dashed border-ink p-12 text-center cursor-pointer transition-colors ${
                     isDragActive ? "bg-yel" : file ? "bg-mint/40" : "bg-cream hover:bg-[#fff6c4]"}`}>
                <input {...getInputProps()} />
                {file ? (
                  <div className="flex items-center justify-center gap-4">
                    <span className="w-12 h-12 grid place-items-center rounded-xl border-2 border-ink bg-mint shadow-brut-sm"><FileArchive className="w-6 h-6" strokeWidth={2.5} /></span>
                    <div className="text-left">
                      <div className="font-bold">{file.name}</div>
                      <div className="text-[13px] font-mono">{(file.size / 1024 / 1024).toFixed(2)} MB</div>
                    </div>
                    <button className="ml-2 p-1.5 rounded-lg border-2 border-ink bg-snow hover:bg-cherry" aria-label="Remove file"
                            onClick={(e) => { e.stopPropagation(); setFile(null); }}><X className="w-4 h-4" strokeWidth={3} /></button>
                  </div>
                ) : (
                  <>
                    <div className="mx-auto w-16 h-16 rounded-2xl grid place-items-center border-[2.5px] border-ink bg-snow shadow-brut -rotate-6">
                      <FileArchive className="w-7 h-7" strokeWidth={2.5} />
                    </div>
                    <div className="mt-5 font-display text-2xl font-extrabold">{isDragActive ? "yes, drop it 👇" : "drag & drop a .zip"}</div>
                    <div className="mt-1 text-sm text-sub">or click to browse · max 25 MB · node_modules & build dirs are skipped</div>
                  </>
                )}
              </div>
            )}

            {error && (
              <div className="mt-5 flex items-center gap-2 p-3 rounded-[10px] border-2 border-ink bg-cherry font-semibold text-sm">
                <AlertCircle className="w-4 h-4 shrink-0" strokeWidth={2.5} /> {error}
              </div>
            )}

            <button className="btn-primary w-full h-14 mt-7 text-lg" onClick={start} disabled={loading} data-testid="start-scan">
              {loading ? <><Loader2 className="w-5 h-5 animate-spin" /> Starting…</> : <>Start scan <ArrowRight className="w-5 h-5" strokeWidth={3} /></>}
            </button>
          </div>
        </div>

        <aside className="card p-6 h-fit fade-up d-4">
          <h3 className="font-display text-2xl font-extrabold">What runs</h3>
          <ol className="mt-5 space-y-4">
            {PIPELINE.map(({ icon: Icon, name: n, body, bg }, i) => (
              <li key={n} className="flex gap-3">
                <span className={`w-10 h-10 shrink-0 rounded-[10px] grid place-items-center border-2 border-ink shadow-brut-sm ${bg} ${i % 2 ? "rotate-3" : "-rotate-3"}`}>
                  <Icon className="w-5 h-5" strokeWidth={2.5} />
                </span>
                <div>
                  <div className="font-bold">{n}</div>
                  <div className="text-[13px] text-sub mt-0.5">{body}</div>
                </div>
              </li>
            ))}
          </ol>
        </aside>
      </div>
    </AppShell>
  );
}
