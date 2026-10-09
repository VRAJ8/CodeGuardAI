import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { toast } from "sonner";
import {
  ArrowRight, Github, KeyRound, Package, Gauge, Sparkles, GitPullRequest, FileCheck2, Terminal, ShieldCheck, Radar, Boxes, Star,
} from "lucide-react";
import { Logo } from "@/components/AppShell";
import { SeverityBadge } from "@/components/viz";
import { API, DEV_LOGIN } from "@/lib/api";

const FEATURES = [
  { icon: ShieldCheck, title: "Multi-engine SAST", body: "Bandit's Python AST checks, Semgrep taint-tracking rules and a cross-language rule pack, deduped into one list.", tag: "Bandit · Semgrep", bg: "bg-yel" },
  { icon: KeyRound, title: "Secret detection", body: "13 provider signatures (AWS, Stripe, GitHub, OpenAI…) plus Shannon-entropy checks. Values are always redacted.", tag: "CWE-798", bg: "bg-pink" },
  { icon: Package, title: "Dependency audit + SBOM", body: "npm, PyPI and Go manifests checked against OSV.dev, with CVSS v3 scores and the version that fixes each one.", tag: "OSV · CycloneDX", bg: "bg-lilac" },
  { icon: Radar, title: "OWASP Top 10 mapping", body: "Every finding gets a CWE and an OWASP 2021 category, so you see exactly where the risk sits.", tag: "A01 – A10", bg: "bg-lime" },
  { icon: Gauge, title: "Code health", body: "Radon cyclomatic complexity, maintainability index and nesting depth point at the functions most likely to break.", tag: "Radon", bg: "bg-tang" },
  { icon: Sparkles, title: "AI patches", body: "An LLM triages real findings and writes copy-paste fixes and refactors for the riskiest files.", tag: "Llama 3.3", bg: "bg-mint" },
];

const ENGINES = ["Bandit", "Semgrep", "OSV.dev", "Radon", "SARIF 2.1", "CycloneDX 1.5", "OWASP Top 10", "CVSS v3.1", "GitHub Actions", "Docker"];

// Illustrative before/after diff for the hero mock-up. The "before" line is deliberately vulnerable.
const DEMO_PATCH = [
  // codeguard-ignore-next-line: CG-SQLI-CONCAT -- marketing copy showing what CodeGuard catches
  `- db.query("SELECT * FROM charges WHERE id='" + id + "'")`,
  `+ db.query("SELECT * FROM charges WHERE id = $1", [id])`,
].join("\n");

const CI_YAML = `- uses: VRAJ8/CodeGuardAI@main
  with:
    fail-on: high
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: codeguard.sarif`;

function Marquee() {
  const row = ENGINES.map((e) => (
    <span key={e} className="flex items-center gap-8 pr-8 whitespace-nowrap">{e}<span className="text-yel">✦</span></span>
  ));
  return (
    <div className="relative -rotate-1 border-y-[3px] border-ink bg-ink text-snow overflow-hidden">
      <div className="marquee flex w-max py-4 font-display text-2xl md:text-3xl font-extrabold uppercase">{row}{row}</div>
    </div>
  );
}

export default function Landing() {
  const navigate = useNavigate();
  const [checking, setChecking] = useState(true);
  const [apiDown, setApiDown] = useState(false);

  useEffect(() => {
    let done = false;
    // Never hold the landing page behind a slow API; a signed-in visitor still gets redirected when it answers.
    const reveal = setTimeout(() => setChecking(false), 2500);
    axios.get(`${API}/auth/me`)
      .then(() => { if (!done) navigate("/dashboard"); })
      .catch((err) => { if (!done) { setApiDown(!err.response); setChecking(false); } });
    return () => { done = true; clearTimeout(reveal); };
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
    return <div className="min-h-screen grid place-items-center"><div className="w-12 h-12 rounded-xl border-[3px] border-ink bg-yel shadow-brut animate-spin [animation-duration:1.4s]" /></div>;
  }

  return (
    <div className="min-h-screen overflow-x-hidden">
      <nav className="fixed top-0 inset-x-0 z-50 bg-cream/90 backdrop-blur border-b-[2.5px] border-ink">
        <div className="max-w-6xl mx-auto px-4 md:px-6 h-16 flex items-center justify-between">
          <Logo />
          <div className="flex items-center gap-2">
            <a className="btn-ghost btn-sm hidden sm:inline-flex" href="https://github.com/VRAJ8/CodeGuardAI" target="_blank" rel="noreferrer"><Github className="w-4 h-4" strokeWidth={2.5} /> GitHub</a>
            {DEV_LOGIN && <button className="btn-secondary btn-sm" onClick={devLogin}>Dev login</button>}
            <button className="btn-dark btn-sm" onClick={handleLogin} data-testid="login-btn">Get started</button>
          </div>
        </div>
        {apiDown && (
          <div role="status" className="border-t-[2.5px] border-ink bg-tang px-4 py-2 text-center text-sm font-bold">
            Heads up: the CodeGuard API isn't responding right now, so sign-in will fail until it's back.
          </div>
        )}
      </nav>

      {/* Hero */}
      <section className="relative pt-32 md:pt-36 pb-20 px-4 md:px-6">
        <div className="relative max-w-6xl mx-auto grid lg:grid-cols-[1.15fr_1fr] gap-14 items-center">
          <div className="relative min-w-0">
            <span className="sticker bg-lime -rotate-2 fade-up">✦ v3 · SARIF, SBOM & CI gating</span>
            <h1 className="mt-6 font-display text-[64px] md:text-[104px] font-extrabold leading-[0.86] tracking-[-0.05em] fade-up d-1">
              ship code<br />that isn't<br />
              <span className="relative inline-block">
                <span className="relative z-10">cooked.</span>
                <span className="absolute left-0 right-0 bottom-[0.08em] h-[0.32em] bg-pink -z-0 -rotate-1" />
              </span>
            </h1>
            <span className="hidden md:inline-flex absolute top-24 right-4 sticker bg-yel rotate-12 text-sm h-9 px-3 shadow-brut">no config 🙅</span>
            <p className="mt-7 text-xl text-sub max-w-lg fade-up d-2">
              A DevSecOps scanner that grades your repo <b className="text-ink">A–F</b>. SAST, secrets, dependency CVEs and code health in one pass,
              with AI-written fixes for what it finds.
            </p>
            <div className="mt-9 flex flex-wrap gap-3 fade-up d-3">
              <button className="btn-primary h-14 px-7 text-lg" onClick={handleLogin}>Scan a repo, free <ArrowRight className="w-5 h-5" strokeWidth={3} /></button>
              <a className="btn-secondary h-14 px-6 text-lg" href="https://github.com/VRAJ8/CodeGuardAI" target="_blank" rel="noreferrer"><Star className="w-5 h-5" strokeWidth={2.5} /> Star it</a>
            </div>
          </div>

          {/* Product preview */}
          <div className="relative min-w-0 fade-up d-3">
            <div className="absolute -top-6 -left-6 w-24 h-24 rounded-full bg-cobalt border-[3px] border-ink hidden md:block" />
            <div className="absolute -bottom-5 -right-4 w-20 h-20 rotate-12 bg-lime border-[3px] border-ink hidden md:block" />
            <div className="relative card p-5 rotate-[1.5deg] shadow-[10px_10px_0_0_#111]">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 font-bold"><Github className="w-4 h-4" strokeWidth={2.5} /> acme/payments-api</div>
                <span className="chip font-mono">main</span>
              </div>
              <div className="mt-5 flex items-center gap-5">
                <div className="w-24 h-24 rounded-[18px] grid place-items-center font-display text-6xl font-extrabold bg-tang border-[3px] border-ink shadow-brut -rotate-6">D</div>
                <div>
                  <div className="font-display text-3xl font-extrabold">62<span className="text-base text-sub">/100</span></div>
                  <span className="sticker bg-tang mt-1">⚠️ Risky</span>
                  <div className="mt-2 text-[13px] font-semibold">+14 pts · 6 fixed since last scan</div>
                </div>
              </div>
              <div className="mt-5 space-y-2">
                {[
                  ["critical", "SQL injection via Express request data", "routes/charge.js:42", "Semgrep"],
                  ["critical", "Hardcoded secret: Stripe secret key", "config/index.js:7", "Secrets"],
                  ["high", "Vulnerable dependency: lodash@4.17.11", "package.json:14", "OSV"],
                  ["medium", "Weak hash algorithm (MD5/SHA1)", "utils/token.py:19", "Bandit"],
                ].map(([sev, t, loc, eng]) => (
                  <div key={t} className="flex items-center gap-3 p-2.5 rounded-[10px] border-2 border-ink bg-cream/60">
                    <span className="w-[84px] shrink-0"><SeverityBadge severity={sev} /></span>
                    <div className="min-w-0 flex-1">
                      <div className="text-[13px] font-bold truncate">{t}</div>
                      <div className="text-[11px] font-mono text-sub">{loc}</div>
                    </div>
                    <span className="text-[10px] font-mono font-bold">{eng}</span>
                  </div>
                ))}
              </div>
              <div className="mt-4 rounded-[10px] border-2 border-ink overflow-hidden">
                <div className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-extrabold bg-lilac border-b-2 border-ink"><Sparkles className="w-3.5 h-3.5" strokeWidth={3} /> Suggested patch</div>
                <pre className="code-block !rounded-none !border-0 !text-[11px] !leading-5 !p-3">{DEMO_PATCH}</pre>
              </div>
            </div>
          </div>
        </div>
      </section>

      <Marquee />

      {/* Features */}
      <section className="px-4 md:px-6 py-24">
        <div className="max-w-6xl mx-auto">
          <span className="sticker bg-snow">What's inside</span>
          <h2 className="mt-4 font-display text-5xl md:text-7xl font-extrabold leading-[0.9] max-w-3xl">
            one scan.<br /><span className="highlight">six engines.</span>
          </h2>
          <div className="mt-14 grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {FEATURES.map(({ icon: Icon, title, body, tag, bg }, i) => (
              <div key={title} className={`card card-hover p-6 ${bg} ${i % 3 === 1 ? "lg:translate-y-6" : ""}`}>
                <div className="flex items-center justify-between">
                  <div className="w-12 h-12 rounded-[12px] grid place-items-center bg-snow border-[2.5px] border-ink shadow-brut-sm -rotate-6"><Icon className="w-6 h-6" strokeWidth={2.5} /></div>
                  <span className="chip font-mono">{tag}</span>
                </div>
                <h3 className="mt-6 font-display text-2xl font-extrabold">{title}</h3>
                <p className="mt-2 text-[15px] leading-relaxed">{body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CI */}
      <section className="px-4 md:px-6 py-24 border-t-[3px] border-ink bg-snow">
        <div className="max-w-6xl mx-auto grid lg:grid-cols-2 gap-14 items-center">
          <div className="min-w-0">
            <span className="sticker bg-cobalt text-white">Shift left</span>
            <h2 className="mt-4 font-display text-5xl md:text-6xl font-extrabold leading-[0.9]">block vulns before they merge.</h2>
            <p className="mt-5 text-lg text-sub">
              The engine behind the dashboard also runs as a CLI and a GitHub Action. It fails the build when a high-severity
              finding shows up, and the SARIF output appears in GitHub's Security tab next to CodeQL.
            </p>
            <div className="mt-8 grid sm:grid-cols-3 gap-3">
              {[[GitPullRequest, "PR gating", "bg-yel"], [FileCheck2, "SARIF upload", "bg-pink"], [Boxes, "Docker ready", "bg-lime"]].map(([Icon, t, bg]) => (
                <div key={t} className={`card-flat shadow-brut-sm p-4 flex items-center gap-3 font-bold ${bg}`}><Icon className="w-5 h-5" strokeWidth={2.5} /> {t}</div>
              ))}
            </div>
          </div>
          <div className="card overflow-hidden min-w-0 -rotate-1 shadow-[10px_10px_0_0_#3B5BFF]">
            <div className="flex items-center gap-2 px-4 py-3 border-b-[2.5px] border-ink bg-yel font-mono text-xs font-bold">
              <span className="flex gap-1.5 mr-2">{["bg-cherry", "bg-tang", "bg-mint"].map((c) => <span key={c} className={`w-3 h-3 rounded-full border-2 border-ink ${c}`} />)}</span>
              <Terminal className="w-3.5 h-3.5" strokeWidth={2.5} /> .github/workflows/security.yml
            </div>
            <pre className="code-block !rounded-none !border-0 !text-[14px] !leading-7 !p-6">{CI_YAML}</pre>
            <div className="px-5 py-3 border-t-[2.5px] border-ink bg-ink text-snow font-mono text-sm">
              <span className="text-yel">$</span> python -m codeguard scan . --fail-on high<span className="blink">▌</span>
            </div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="px-4 md:px-6 py-24">
        <div className="max-w-5xl mx-auto card bg-yel p-10 md:p-16 text-center relative overflow-hidden">
          <span className="absolute top-6 left-6 sticker bg-pink -rotate-12 hidden md:inline-flex">free 💸</span>
          <span className="absolute bottom-8 right-8 sticker bg-snow rotate-6 hidden md:inline-flex">~20s scans ⚡</span>
          <h2 className="font-display text-5xl md:text-7xl font-extrabold leading-[0.9]">what's your<br />repo's grade?</h2>
          <p className="mt-5 text-lg font-medium">No credit card. No config. Just paste a GitHub URL.</p>
          <button className="btn-dark h-14 px-8 mt-9 text-lg" onClick={handleLogin}>Find out <ArrowRight className="w-5 h-5" strokeWidth={3} /></button>
        </div>
      </section>

      <footer className="border-t-[2.5px] border-ink bg-snow px-4 md:px-6 py-8">
        <div className="max-w-6xl mx-auto flex flex-wrap items-center justify-between gap-4 text-sm font-semibold">
          <Logo />
          <span className="font-mono text-xs">FastAPI · React · MongoDB · Bandit · Semgrep · OSV.dev</span>
        </div>
      </footer>
    </div>
  );
}
