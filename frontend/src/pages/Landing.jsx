import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { toast } from "sonner";
import {
  ArrowRight, Github, KeyRound, Package, Gauge, Sparkles, GitPullRequest, FileCheck2, Terminal, ShieldCheck, Radar, Boxes,
} from "lucide-react";
import { Logo } from "@/components/AppShell";
import { SeverityBadge } from "@/components/viz";
import { API, DEV_LOGIN } from "@/lib/api";

const FEATURES = [
  { icon: ShieldCheck, title: "Multi-engine SAST", body: "Bandit's Python AST checks, Semgrep taint-tracking rules and a cross-language rule pack, deduped into one list.", tag: "Bandit · Semgrep" },
  { icon: KeyRound, title: "Secret detection", body: "13 provider signatures (AWS, Stripe, GitHub, OpenAI…) plus Shannon-entropy checks. Values are redacted.", tag: "CWE-798" },
  { icon: Package, title: "Dependency audit + SBOM", body: "npm, PyPI and Go manifests checked against OSV.dev, with CVSS v3 scores and the version that fixes each one.", tag: "OSV · CycloneDX" },
  { icon: Radar, title: "OWASP Top 10 mapping", body: "Every finding is tagged with a CWE and an OWASP 2021 category, so you see where the risk actually sits.", tag: "A01 – A10" },
  { icon: Gauge, title: "Code health", body: "Radon cyclomatic complexity, maintainability index and nesting depth highlight the functions most likely to break.", tag: "Radon" },
  { icon: Sparkles, title: "AI patches", body: "An LLM triages real findings and writes copy-paste fixes and refactors for the riskiest files.", tag: "Llama 3.3" },
];

const CI_YAML = `- uses: VRAJ8/CodeGuardAI@main
  with:
    fail-on: high
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: codeguard.sarif`;

export default function Landing() {
  const navigate = useNavigate();
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    axios.get(`${API}/auth/me`).then(() => navigate("/dashboard")).catch(() => setChecking(false));
  }, [navigate]);

  // REMINDER: DO NOT HARDCODE THE URL, OR ADD ANY FALLBACKS OR REDIRECT URLS, THIS BREAKS THE AUTH
  const handleLogin = () => {
    const redirectUrl = window.location.origin + "/dashboard";
    window.location.href = `https://auth.emergentagent.com/?redirect=${encodeURIComponent(redirectUrl)}`;
  };

  const devLogin = async () => {
    try {
      const { data } = await axios.post(`${API}/auth/dev-login`);
      navigate("/dashboard", { state: { user: data } });
    } catch {
      toast.error("Dev login is disabled on this server");
    }
  };

  if (checking) {
    return <div className="min-h-screen bg-[#09090b] grid place-items-center"><div className="w-8 h-8 border-2 border-[#00e599] border-t-transparent rounded-full animate-spin" /></div>;
  }

  return (
    <div className="min-h-screen bg-[#09090b] overflow-x-hidden">
      <nav className="fixed top-0 inset-x-0 z-50 glass border-b border-white/[0.06]">
        <div className="max-w-6xl mx-auto px-4 md:px-6 h-16 flex items-center justify-between">
          <Logo />
          <div className="flex items-center gap-2">
            <a className="btn-ghost btn-sm hidden sm:inline-flex" href="https://github.com/VRAJ8/CodeGuardAI" target="_blank" rel="noreferrer"><Github className="w-4 h-4" /> GitHub</a>
            {DEV_LOGIN && <button className="btn-secondary btn-sm" onClick={devLogin}>Dev login</button>}
            <button className="btn-primary btn-sm" onClick={handleLogin} data-testid="login-btn">Get started</button>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="relative pt-32 md:pt-40 pb-20 px-4 md:px-6">
        <div className="absolute inset-0 bg-grid" />
        <div className="glow-orb w-[520px] h-[520px] -top-40 left-1/2 -translate-x-1/2 bg-[#00e599]/[0.12]" />
        <div className="glow-orb w-[380px] h-[380px] top-40 right-0 bg-[#a78bfa]/[0.10]" />
        <div className="relative max-w-6xl mx-auto grid lg:grid-cols-[1.1fr_1fr] gap-12 items-center">
          <div>
            <span className="chip chip-active fade-up"><span className="w-1.5 h-1.5 rounded-full bg-[#00e599] pulse-dot" /> v3 · SARIF, SBOM & CI gating</span>
            <h1 className="mt-6 text-5xl md:text-7xl font-semibold leading-[0.95] tracking-[-0.04em] fade-up d-1">
              Ship code that<br /><span className="text-gradient">isn't cooked.</span>
            </h1>
            <p className="mt-6 text-lg text-[#a1a1aa] max-w-xl fade-up d-2">
              A DevSecOps scanner for your repos: SAST, secret detection, dependency CVEs and code health in a single pass,
              with a letter grade and AI-written fixes for what it finds.
            </p>
            <div className="mt-8 flex flex-wrap gap-3 fade-up d-3">
              <button className="btn-primary h-12 px-6 text-[15px]" onClick={handleLogin}>Scan a repo free <ArrowRight className="w-4 h-4" /></button>
              <a className="btn-secondary h-12 px-6 text-[15px]" href="https://github.com/VRAJ8/CodeGuardAI" target="_blank" rel="noreferrer"><Github className="w-4 h-4" /> Star on GitHub</a>
            </div>
            <div className="mt-10 flex flex-wrap gap-x-6 gap-y-2 text-xs text-[#71717a] font-mono fade-up d-4">
              <span>Bandit</span><span>Semgrep</span><span>OSV.dev</span><span>Radon</span><span>SARIF 2.1</span><span>CycloneDX 1.5</span>
            </div>
          </div>

          {/* Product preview */}
          <div className="relative fade-up d-3">
            <div className="card p-5 shadow-[0_40px_120px_-40px_rgba(0,229,153,.35)]">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm"><Github className="w-4 h-4 text-[#71717a]" /> acme/payments-api</div>
                <span className="chip">main</span>
              </div>
              <div className="mt-5 flex items-center gap-5">
                <div className="w-20 h-20 rounded-2xl grid place-items-center text-4xl font-bold text-[#ec835a] bg-[#ec835a]/10 ring-1 ring-[#ec835a]/30">D</div>
                <div>
                  <div className="text-xl font-semibold">62<span className="text-[#71717a] text-sm">/100</span></div>
                  <div className="text-sm text-[#ec835a]">Risky</div>
                  <div className="mt-1 text-xs text-[#4ade80]">+14 pts · 6 fixed since last scan</div>
                </div>
              </div>
              <div className="mt-5 space-y-2">
                {[
                  ["critical", "SQL injection via Express request data", "routes/charge.js:42", "Semgrep"],
                  ["critical", "Hardcoded secret: Stripe secret key", "config/index.js:7", "Secrets"],
                  ["high", "Vulnerable dependency: lodash@4.17.11", "package.json:14", "OSV"],
                  ["medium", "Weak hash algorithm (MD5/SHA1)", "utils/token.py:19", "Bandit"],
                ].map(([sev, t, loc, eng]) => (
                  <div key={t} className="flex items-center gap-3 p-2.5 rounded-xl bg-white/[0.025] border border-white/[0.05]">
                    <SeverityBadge severity={sev} />
                    <div className="min-w-0 flex-1">
                      <div className="text-[13px] truncate">{t}</div>
                      <div className="text-[11px] text-[#71717a] font-mono">{loc}</div>
                    </div>
                    <span className="text-[10px] text-[#71717a]">{eng}</span>
                  </div>
                ))}
              </div>
              <div className="mt-4 p-3 rounded-xl border border-[#a78bfa]/25 bg-[#a78bfa]/[0.06]">
                <div className="flex items-center gap-1.5 text-xs text-[#c4b5fd]"><Sparkles className="w-3 h-3" /> Suggested patch</div>
                <pre className="mt-2 text-[11px] font-mono text-[#d4d4d8] overflow-x-auto">{`- db.query("SELECT * FROM charges WHERE id='" + id + "'")
+ db.query("SELECT * FROM charges WHERE id = $1", [id])`}</pre>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="px-4 md:px-6 py-20 border-t border-white/[0.06]">
        <div className="max-w-6xl mx-auto">
          <div className="eyebrow">What's inside</div>
          <h2 className="mt-3 text-3xl md:text-5xl font-semibold max-w-2xl">One scan, six engines.</h2>
          <div className="mt-12 grid md:grid-cols-2 lg:grid-cols-3 gap-4">
            {FEATURES.map(({ icon: Icon, title, body, tag }) => (
              <div key={title} className="card card-hover p-6">
                <div className="flex items-center justify-between">
                  <div className="w-10 h-10 rounded-xl grid place-items-center bg-white/[0.04] border border-white/[0.07]"><Icon className="w-5 h-5 text-[#00e599]" /></div>
                  <span className="chip font-mono">{tag}</span>
                </div>
                <h3 className="mt-5 text-lg font-semibold">{title}</h3>
                <p className="mt-2 text-sm text-[#a1a1aa] leading-relaxed">{body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CI */}
      <section className="px-4 md:px-6 py-20 border-t border-white/[0.06]">
        <div className="max-w-6xl mx-auto grid lg:grid-cols-2 gap-12 items-center">
          <div>
            <div className="eyebrow">Shift left</div>
            <h2 className="mt-3 text-3xl md:text-5xl font-semibold">Block vulns before they merge.</h2>
            <p className="mt-4 text-[#a1a1aa]">
              The engine behind this dashboard also runs as a CLI and a GitHub Action. It fails the build when a high-severity
              finding shows up, and the SARIF output appears in GitHub's Security tab next to CodeQL.
            </p>
            <div className="mt-8 grid sm:grid-cols-3 gap-3">
              {[[GitPullRequest, "PR gating"], [FileCheck2, "SARIF upload"], [Boxes, "Docker ready"]].map(([Icon, t]) => (
                <div key={t} className="card p-4 flex items-center gap-3 text-sm"><Icon className="w-4 h-4 text-[#00e599]" /> {t}</div>
              ))}
            </div>
          </div>
          <div className="card overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-white/[0.06] text-xs text-[#71717a]">
              <Terminal className="w-3.5 h-3.5" /> .github/workflows/security.yml
            </div>
            <pre className="p-5 text-[13px] leading-6 font-mono text-[#d4d4d8] overflow-x-auto">{CI_YAML}</pre>
            <div className="px-5 py-3 border-t border-white/[0.06] font-mono text-xs text-[#71717a]">
              <span className="text-[#00e599]">$</span> python -m codeguard scan . --fail-on high
            </div>
          </div>
        </div>
      </section>

      <section className="px-4 md:px-6 py-24 border-t border-white/[0.06] text-center relative overflow-hidden">
        <div className="glow-orb w-[600px] h-[300px] left-1/2 -translate-x-1/2 bottom-0 bg-[#00e599]/[0.10]" />
        <div className="relative">
          <h2 className="text-3xl md:text-5xl font-semibold">What's your repo's grade?</h2>
          <p className="mt-4 text-[#a1a1aa]">Takes about 20 seconds. No credit card, no config.</p>
          <button className="btn-primary h-12 px-6 mt-8 text-[15px]" onClick={handleLogin}>Find out <ArrowRight className="w-4 h-4" /></button>
        </div>
      </section>

      <footer className="border-t border-white/[0.06] px-4 md:px-6 py-8">
        <div className="max-w-6xl mx-auto flex flex-wrap items-center justify-between gap-4 text-xs text-[#71717a]">
          <Logo />
          <span>FastAPI · React · MongoDB · Bandit · Semgrep · OSV.dev</span>
        </div>
      </footer>
    </div>
  );
}
