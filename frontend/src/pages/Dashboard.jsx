import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { toast } from "sonner";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import {
  Plus, KeyRound, Package, AlertOctagon, Code2, Flame, ArrowUpRight, Sparkles, Radar, Loader2, ChevronRight, Wrench,
} from "lucide-react";
import AppShell from "@/components/AppShell";
import {
  ActivityHeatmap, ChartTooltip, Delta, EmptyState, GradePill, GradeRing, SeverityBar, Spinner, StatTile,
} from "@/components/viz";
import { API, compact, timeAgo } from "@/lib/api";
import { CHART, GRADE, SCANNERS, languageColor } from "@/lib/theme";

export const DEMO_REPOS = [
  { url: "https://github.com/OWASP/NodeGoat", label: "OWASP/NodeGoat", lang: "Node.js" },
  { url: "https://github.com/anxolerd/dvpwa", label: "anxolerd/dvpwa", lang: "Python" },
  { url: "https://github.com/digininja/DVWA", label: "digininja/DVWA", lang: "PHP" },
];

function Card({ title, subtitle, right, children, className = "" }) {
  return (
    <section className={`card p-5 md:p-6 fade-up ${className}`}>
      {(title || right) && (
        <div className="flex items-start justify-between gap-4 mb-5">
          <div>
            <h3 className="text-[15px] font-semibold">{title}</h3>
            {subtitle && <p className="text-xs text-[#71717a] mt-0.5">{subtitle}</p>}
          </div>
          {right}
        </div>
      )}
      {children}
    </section>
  );
}

function Onboarding({ navigate }) {
  return (
    <div className="space-y-6">
      <div className="card relative overflow-hidden p-8 md:p-12">
        <div className="glow-orb w-80 h-80 -top-32 -right-20 bg-[#00e599]/20" />
        <div className="glow-orb w-72 h-72 -bottom-40 left-10 bg-[#a78bfa]/15" />
        <div className="relative max-w-2xl">
          <span className="chip chip-active"><Sparkles className="w-3 h-3" /> First scan takes ~20s</span>
          <h1 className="mt-4 text-3xl md:text-4xl font-semibold">Let's find out how cooked your code is.</h1>
          <p className="mt-3 text-[#a1a1aa]">
            Point CodeGuard at a public GitHub repo or drop a ZIP. You'll get a letter grade, OWASP-mapped findings,
            a dependency SBOM and AI-written patches.
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            <button className="btn-primary" onClick={() => navigate("/new-analysis")}><Plus className="w-4 h-4" /> Run your first scan</button>
          </div>
          <div className="mt-8">
            <div className="eyebrow mb-3">Or speedrun it with a deliberately vulnerable repo</div>
            <div className="flex flex-wrap gap-2">
              {DEMO_REPOS.map((r) => (
                <button key={r.url} className="chip hover:border-white/20 hover:text-white h-8 px-3"
                        onClick={() => navigate(`/new-analysis?repo=${encodeURIComponent(r.url)}`)}>
                  {r.label} <span className="text-[#71717a]">· {r.lang}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
      <div className="grid md:grid-cols-3 gap-4">
        {[
          ["01", "Scan", "Bandit, Semgrep, secret signatures, OSV.dev and Radon run in parallel."],
          ["02", "Triage", "Findings are deduped, CWE-tagged and mapped to the OWASP Top 10."],
          ["03", "Ship", "Export SARIF to GitHub Code Scanning, a CycloneDX SBOM, or gate PRs with the CLI."],
        ].map(([n, t, b]) => (
          <div key={n} className="card p-5">
            <div className="font-mono text-xs text-[#00e599]">{n}</div>
            <div className="mt-2 font-medium">{t}</div>
            <p className="mt-1 text-sm text-[#71717a]">{b}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [user, setUser] = useState(null);

  useEffect(() => {
    let timer;
    const load = async () => {
      try {
        const [s, u] = await Promise.all([axios.get(`${API}/analysis/stats/dashboard`), axios.get(`${API}/auth/me`)]);
        setStats(s.data);
        setUser(u.data);
        if (s.data.running > 0) timer = setTimeout(load, 4000);
      } catch {
        toast.error("Couldn't load your dashboard");
        setStats((prev) => prev || { total_analyses: 0, recent_analyses: [] });
      }
    };
    load();
    return () => clearTimeout(timer);
  }, []);

  const actions = (
    <button className="btn-primary btn-sm" onClick={() => navigate("/new-analysis")}>
      <Plus className="w-3.5 h-3.5" /> New scan
    </button>
  );

  if (!stats) return <AppShell title="Overview" actions={actions}><Spinner /></AppShell>;

  const first = user?.name?.split(" ")[0] || "there";
  if (!stats.total_analyses && !stats.running) {
    return (
      <AppShell title="Overview" actions={actions}>
        <h1 className="text-2xl font-semibold mb-6">Hey {first} 👋</h1>
        <Onboarding navigate={navigate} />
      </AppShell>
    );
  }

  const grade = stats.posture_grade;
  const g = GRADE[grade] || {};
  const owaspMax = Math.max(1, ...(stats.owasp || []).map((o) => o.count));
  const langTotal = Object.values(stats.languages || {}).reduce((a, b) => a + b, 0) || 1;
  const scannerTotal = Object.values(stats.scanners || {}).reduce((a, b) => a + b, 0) || 1;
  const trend = (stats.trend || []).map((t, i) => ({ ...t, i }));

  return (
    <AppShell title="Overview" actions={actions}>
      <div className="flex flex-wrap items-end justify-between gap-3 mb-6">
        <div>
          <h1 className="text-2xl md:text-[28px] font-semibold">Hey {first} 👋</h1>
          <p className="text-sm text-[#71717a] mt-1">
            {stats.projects} project{stats.projects === 1 ? "" : "s"} tracked · {stats.total_analyses} scans ·{" "}
            {compact(stats.lines_scanned)} lines reviewed
          </p>
        </div>
        {stats.running > 0 && (
          <span className="chip chip-active h-7 px-3"><Loader2 className="w-3 h-3 animate-spin" /> {stats.running} scan running</span>
        )}
      </div>

      {/* Row 1 — posture hero + KPIs */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
        <section className="card relative overflow-hidden p-6 xl:col-span-5 fade-up">
          <div className="glow-orb w-64 h-64 -top-24 -right-24" style={{ background: `${g.color || "#00e599"}22` }} />
          <div className="relative flex flex-col sm:flex-row items-center gap-6">
            <GradeRing score={stats.posture_score} grade={grade} />
            <div className="text-center sm:text-left">
              <div className="eyebrow">Security posture</div>
              <div className="mt-2 text-2xl font-semibold" style={{ color: g.color }}>{g.vibe || "No data yet"}</div>
              <p className="mt-2 text-sm text-[#a1a1aa] max-w-xs">
                Average of each project's latest scan. Weighted 70% security findings, 30% code health.
              </p>
              <div className="mt-3 flex items-center justify-center sm:justify-start gap-3 text-xs text-[#71717a]">
                {stats.score_delta_7d != null ? <><Delta value={stats.score_delta_7d} suffix=" pts" /> vs last week</> : "Scan again to see your trend"}
              </div>
            </div>
          </div>
        </section>

        <div className="xl:col-span-7 grid grid-cols-2 gap-4">
          <StatTile className="fade-up d-1" label="Critical + high" icon={AlertOctagon} accent="#d03b3b"
                    value={(stats.severity?.critical || 0) + (stats.severity?.high || 0)}
                    hint={`${stats.severity?.critical || 0} critical across latest scans`} />
          <StatTile className="fade-up d-2" label="Secrets leaked" icon={KeyRound} accent="#fab219"
                    value={stats.secrets || 0} hint={stats.secrets ? "Rotate these first — seriously" : "No hardcoded creds 🎉"} />
          <StatTile className="fade-up d-3" label="Vulnerable deps" icon={Package} accent="#ec835a"
                    value={<>{stats.vulnerable_dependencies || 0}<span className="text-base text-[#71717a] font-normal"> / {stats.total_dependencies || 0}</span></>}
                    hint="Known CVEs via OSV.dev" />
          <StatTile className="fade-up d-4" label="Fixed since last scan" icon={Wrench} accent="#00e599"
                    value={stats.fixed_total || 0} hint="Findings that disappeared on re-scan" />
        </div>
      </div>

      {/* Row 2 — trend + activity */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 mt-4">
        <Card className="xl:col-span-8" title="Score over time" subtitle={`Overall score of your last ${trend.length} scans`}>
          <div className="h-[240px] -ml-2">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trend} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
                <defs>
                  <linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={CHART.brand} stopOpacity={0.28} />
                    <stop offset="100%" stopColor={CHART.brand} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke={CHART.grid} vertical={false} />
                <XAxis dataKey="i" tickLine={false} axisLine={{ stroke: CHART.axis }} tick={{ fill: CHART.muted, fontSize: 11 }}
                       tickFormatter={(i) => trend[i] && new Date(trend[i].date).toLocaleDateString(undefined, { month: "short", day: "numeric" })}
                       minTickGap={24} />
                <YAxis domain={[0, 100]} ticks={[0, 50, 100]} width={32} tickLine={false} axisLine={false} tick={{ fill: CHART.muted, fontSize: 11 }} />
                <Tooltip
                  cursor={{ stroke: "#52525b", strokeWidth: 1 }}
                  content={<ChartTooltip formatter={(v, p) => `${v} · grade ${p.payload.grade}`}
                                         labelFormatter={(i) => trend[i] && `${trend[i].name} · ${timeAgo(trend[i].date)}`} />}
                />
                <Area type="monotone" dataKey="score" stroke={CHART.brand} strokeWidth={2} fill="url(#scoreFill)"
                      dot={trend.length < 15 ? { r: 3, fill: CHART.brand, stroke: "#111113", strokeWidth: 2 } : false}
                      activeDot={{ r: 5, fill: CHART.brand, stroke: "#111113", strokeWidth: 2 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card className="xl:col-span-4" title="Activity" subtitle="Scans per day"
              right={<span className="chip h-7 px-3"><Flame className="w-3.5 h-3.5 text-[#fb923c]" /><span className="text-white font-semibold tabular">{stats.streak}</span> day streak</span>}>
          <ActivityHeatmap days={stats.activity || []} />
          <div className="mt-5 pt-5 border-t border-white/[0.06] grid grid-cols-2 gap-4">
            <div>
              <div className="eyebrow">Avg score</div>
              <div className="mt-1 text-xl font-semibold tabular">{stats.avg_score}</div>
            </div>
            <div>
              <div className="eyebrow">Open findings</div>
              <div className="mt-1 text-xl font-semibold tabular">{stats.total_issues}</div>
            </div>
          </div>
        </Card>
      </div>

      {/* Row 3 — OWASP + severity/scanners */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 mt-4">
        <Card className="xl:col-span-7" title="OWASP Top 10 exposure" subtitle="Findings in each project's latest scan, by 2021 category"
              right={<Radar className="w-4 h-4 text-[#71717a]" />}>
          <div className="space-y-2.5">
            {stats.owasp.map((o) => (
              <div key={o.code} className="group grid grid-cols-[44px_1fr_32px] sm:grid-cols-[44px_220px_1fr_32px] items-center gap-3 text-sm"
                   title={`${o.code} ${o.name}: ${o.count} finding${o.count === 1 ? "" : "s"}`}>
                <span className="font-mono text-xs text-[#71717a]">{o.code.split(":")[0]}</span>
                <span className={`hidden sm:block truncate ${o.count ? "text-[#e4e4e7]" : "text-[#52525b]"}`}>{o.name}</span>
                <div className="h-2 rounded-full bg-[#1c1c20] overflow-hidden">
                  <div className="h-full rounded-full transition-all duration-700 group-hover:brightness-125"
                       style={{ width: `${(o.count / owaspMax) * 100}%`, background: CHART.brand }} />
                </div>
                <span className={`text-right tabular text-xs ${o.count ? "text-white" : "text-[#52525b]"}`}>{o.count}</span>
              </div>
            ))}
          </div>
        </Card>

        <div className="xl:col-span-5 grid gap-4">
          <Card title="Severity mix" subtitle={`${stats.total_issues} open findings`}>
            <SeverityBar counts={stats.severity} />
          </Card>
          <Card title="Detected by" subtitle="Which engine caught each finding">
            <div className="space-y-3">
              {Object.entries(stats.scanners || {}).map(([k, n]) => (
                <div key={k} className="flex items-center gap-3 text-sm">
                  <span className="w-24 shrink-0">{SCANNERS[k]?.label || k}</span>
                  <div className="flex-1 h-1.5 rounded-full bg-[#1c1c20] overflow-hidden">
                    <div className="h-full rounded-full bg-[#a78bfa]" style={{ width: `${(n / scannerTotal) * 100}%` }} />
                  </div>
                  <span className="w-8 text-right tabular text-xs text-[#a1a1aa]">{n}</span>
                </div>
              ))}
              {!Object.keys(stats.scanners || {}).length && <p className="text-sm text-[#71717a]">Nothing detected. Clean.</p>}
            </div>
          </Card>
        </div>
      </div>

      {/* Row 4 — riskiest + languages */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 mt-4">
        <Card className="xl:col-span-7" title="Needs attention" subtitle="Lowest-scoring projects first">
          <div className="divide-y divide-white/[0.05] -my-2">
            {stats.riskiest.map((p, idx) => (
              <button key={p.analysis_id} onClick={() => navigate(`/analysis/${p.analysis_id}`)}
                      className="w-full flex items-center gap-4 py-3 text-left group">
                <span className="w-5 font-mono text-xs text-[#52525b]">{idx + 1}</span>
                <GradePill grade={p.grade} />
                <div className="min-w-0 flex-1">
                  <div className="truncate font-medium group-hover:text-white">{p.name}</div>
                  <div className="mt-1.5 max-w-[220px]"><SeverityBar counts={p.severity} showLegend={false} height={4} /></div>
                </div>
                <span className="tabular text-sm text-[#a1a1aa]">{Math.round(p.score)}</span>
                <ArrowUpRight className="w-4 h-4 text-[#52525b] group-hover:text-white" />
              </button>
            ))}
          </div>
        </Card>
        <Card className="xl:col-span-5" title="Languages" subtitle="Lines of code across latest scans">
          <div className="flex h-3 gap-[2px] rounded-full overflow-hidden">
            {Object.entries(stats.languages || {}).map(([lang, n]) => (
              <div key={lang} style={{ width: `${(n / langTotal) * 100}%`, background: languageColor(lang) }} title={`${lang}: ${n.toLocaleString()} lines`} />
            ))}
          </div>
          <div className="mt-4 grid grid-cols-2 gap-x-6 gap-y-2.5">
            {Object.entries(stats.languages || {}).map(([lang, n]) => (
              <div key={lang} className="flex items-center gap-2 text-sm">
                <span className="w-2.5 h-2.5 rounded-sm" style={{ background: languageColor(lang) }} />
                <span className="capitalize">{lang}</span>
                <span className="ml-auto tabular text-xs text-[#71717a]">{Math.round((n / langTotal) * 100)}%</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Recent */}
      <Card className="mt-4" title="Recent scans"
            right={<button className="btn-ghost btn-sm" onClick={() => navigate("/history")}>View all <ChevronRight className="w-3.5 h-3.5" /></button>}>
        {stats.recent_analyses?.length ? (
          <div className="divide-y divide-white/[0.05] -my-2">
            {stats.recent_analyses.map((a) => (
              <button key={a.analysis_id} onClick={() => navigate(`/analysis/${a.analysis_id}`)}
                      className="w-full flex items-center gap-4 py-3 text-left group">
                {a.status === "processing" ? (
                  <span className="w-8 h-8 grid place-items-center rounded-lg bg-[#00e599]/10"><Loader2 className="w-4 h-4 text-[#00e599] animate-spin" /></span>
                ) : <GradePill grade={a.status === "failed" ? null : a.grade} />}
                <div className="min-w-0 flex-1">
                  <div className="truncate font-medium">{a.name}</div>
                  <div className="text-xs text-[#71717a] mt-0.5">
                    {a.status === "failed" ? <span className="text-[#f87171]">Failed · {a.error || "error"}</span> :
                     a.status === "processing" ? a.progress?.stage || "Scanning…" :
                     <>{a.metrics?.total_files || 0} files · {a.issue_count} findings</>}
                    {" · "}{timeAgo(a.created_at)}
                  </div>
                </div>
                {a.baseline && <Delta value={a.baseline.score_delta} />}
                <ChevronRight className="w-4 h-4 text-[#52525b] group-hover:text-white" />
              </button>
            ))}
          </div>
        ) : (
          <EmptyState icon={Code2} title="No scans yet" />
        )}
      </Card>
    </AppShell>
  );
}
