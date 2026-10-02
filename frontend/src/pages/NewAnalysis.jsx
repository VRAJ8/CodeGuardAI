import { useCallback, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import axios from "axios";
import { toast } from "sonner";
import { useDropzone } from "react-dropzone";
import { Github, FileArchive, Loader2, AlertCircle, ArrowRight, X, ShieldCheck, Bug, KeyRound, Package, Gauge, Sparkles } from "lucide-react";
import AppShell from "@/components/AppShell";
import { API } from "@/lib/api";
import { DEMO_REPOS } from "@/pages/Dashboard";

const PIPELINE = [
  { icon: KeyRound, name: "Secrets", body: "13 provider signatures + Shannon entropy" },
  { icon: ShieldCheck, name: "SAST", body: "Bandit, Semgrep taint rules, cross-language rule pack" },
  { icon: Package, name: "SCA", body: "npm · PyPI · Go manifests checked against OSV.dev" },
  { icon: Gauge, name: "Code health", body: "Radon cyclomatic complexity & maintainability index" },
  { icon: Sparkles, name: "AI triage", body: "Llama 3.3 writes patches & refactors for real findings" },
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
      toast.success("Scan started");
      navigate(`/analysis/${res.data.analysis_id}`);
    } catch (err) {
      setError(err.response?.data?.detail || "Couldn't start the scan");
      setLoading(false);
    }
  };

  return (
    <AppShell title="New scan">
      <div className="grid lg:grid-cols-[1fr_340px] gap-6 max-w-5xl">
        <div>
          <h1 className="text-2xl md:text-3xl font-semibold fade-up">Scan a codebase</h1>
          <p className="mt-2 text-[#a1a1aa] fade-up d-1">Public GitHub repo or a ZIP — results stream in live.</p>

          <div className="mt-6 inline-flex p-1 rounded-xl bg-[#111113] border border-white/[0.07] fade-up d-2" role="tablist">
            {[["github", Github, "GitHub repo"], ["zip", FileArchive, "Upload ZIP"]].map(([key, Icon, label]) => (
              <button key={key} role="tab" aria-selected={mode === key} onClick={() => { setMode(key); setError(""); }}
                      className={`flex items-center gap-2 px-4 h-9 rounded-lg text-sm transition-all ${
                        mode === key ? "bg-white/[0.08] text-white shadow-sm" : "text-[#a1a1aa] hover:text-white"}`}>
                <Icon className="w-4 h-4" /> {label}
              </button>
            ))}
          </div>

          <div className="card p-6 mt-4 fade-up d-3">
            {mode === "github" ? (
              <div className="space-y-5">
                <div>
                  <label className="text-sm text-[#a1a1aa]" htmlFor="repo">Repository URL</label>
                  <div className="relative mt-2">
                    <Github className="w-4 h-4 absolute left-4 top-1/2 -translate-y-1/2 text-[#71717a]" />
                    <input id="repo" className="input pl-11 font-mono text-[13px]" placeholder="https://github.com/owner/repo"
                           value={githubUrl} onChange={(e) => setGithubUrl(e.target.value)} onKeyDown={(e) => e.key === "Enter" && start()}
                           autoFocus data-testid="github-url-input" />
                  </div>
                  <p className="mt-2 text-xs text-[#71717a]">Default branch is detected automatically. Use <code className="text-[#a1a1aa]">/tree/branch</code> for another branch.</p>
                </div>
                <div>
                  <label className="text-sm text-[#a1a1aa]" htmlFor="name">Display name <span className="text-[#52525b]">(optional)</span></label>
                  <input id="name" className="input mt-2" placeholder="owner/repo" value={name} onChange={(e) => setName(e.target.value)} />
                </div>
                <div>
                  <div className="eyebrow mb-2">Try a deliberately vulnerable repo</div>
                  <div className="flex flex-wrap gap-2">
                    {DEMO_REPOS.map((r) => (
                      <button key={r.url} onClick={() => setGithubUrl(r.url)}
                              className={`chip h-7 px-3 hover:text-white ${githubUrl === r.url ? "chip-active" : ""}`}>
                        {r.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div {...getRootProps()} data-testid="dropzone"
                   className={`rounded-xl border-2 border-dashed p-10 text-center cursor-pointer transition-all ${
                     isDragActive || file ? "border-[#00e599]/60 bg-[#00e599]/[0.04]" : "border-white/10 hover:border-white/20"}`}>
                <input {...getInputProps()} />
                {file ? (
                  <div className="flex items-center justify-center gap-3">
                    <FileArchive className="w-8 h-8 text-[#00e599]" />
                    <div className="text-left">
                      <div className="font-medium">{file.name}</div>
                      <div className="text-xs text-[#71717a]">{(file.size / 1024 / 1024).toFixed(2)} MB</div>
                    </div>
                    <button className="ml-2 p-1.5 rounded-md hover:bg-white/5 text-[#a1a1aa]" aria-label="Remove file"
                            onClick={(e) => { e.stopPropagation(); setFile(null); }}><X className="w-4 h-4" /></button>
                  </div>
                ) : (
                  <>
                    <div className="mx-auto w-12 h-12 rounded-2xl grid place-items-center bg-white/[0.04] border border-white/[0.07]">
                      <FileArchive className="w-5 h-5 text-[#a1a1aa]" />
                    </div>
                    <div className="mt-4 font-medium">{isDragActive ? "Drop it 👇" : "Drag & drop a .zip"}</div>
                    <div className="mt-1 text-sm text-[#71717a]">or click to browse · max 25 MB · node_modules & build dirs are skipped</div>
                  </>
                )}
              </div>
            )}

            {error && (
              <div className="mt-5 flex items-center gap-2 p-3 rounded-xl bg-[#d03b3b]/10 border border-[#d03b3b]/30 text-sm text-[#fca5a5]">
                <AlertCircle className="w-4 h-4 shrink-0" /> {error}
              </div>
            )}

            <button className="btn-primary w-full h-11 mt-6" onClick={start} disabled={loading} data-testid="start-scan">
              {loading ? <><Loader2 className="w-4 h-4 animate-spin" /> Starting…</> : <>Start scan <ArrowRight className="w-4 h-4" /></>}
            </button>
          </div>
        </div>

        <aside className="card p-6 h-fit fade-up d-4">
          <div className="flex items-center gap-2">
            <Bug className="w-4 h-4 text-[#00e599]" />
            <h3 className="font-semibold text-[15px]">What runs</h3>
          </div>
          <ol className="mt-5 space-y-5">
            {PIPELINE.map(({ icon: Icon, name: n, body }, i) => (
              <li key={n} className="flex gap-3">
                <div className="relative">
                  <div className="w-8 h-8 rounded-lg grid place-items-center bg-white/[0.04] border border-white/[0.07]">
                    <Icon className="w-4 h-4 text-[#a1a1aa]" />
                  </div>
                  {i < PIPELINE.length - 1 && <div className="absolute left-1/2 top-9 w-px h-5 bg-white/[0.07]" />}
                </div>
                <div>
                  <div className="text-sm font-medium">{n}</div>
                  <div className="text-xs text-[#71717a] mt-0.5">{body}</div>
                </div>
              </li>
            ))}
          </ol>
        </aside>
      </div>
    </AppShell>
  );
}
