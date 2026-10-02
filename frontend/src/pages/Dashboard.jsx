import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { toast } from "sonner";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import {
  Plus, KeyRound, Package, AlertOctagon, Code2, Flame, ArrowUpRight, Radar, Loader2, ChevronRight, Wrench, Zap,
} from "lucide-react";
import AppShell from "@/components/AppShell";
import {
  ActivityHeatmap, ChartTooltip, Delta, EmptyState, GradePill, GradeSticker, SeverityBar, Spinner, StatTile,
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
            <h3 className="font-display text-xl font-extrabold">{title}</h3>
            {subtitle && <p className="text-[13px] text-sub mt-0.5">{subtitle}</p>}
          </div>
          {right}
        </div>
      )}
      {children}
    </section>
  );
}

function Ticker({ items }) {
  const row = items.map((t, i) => (
    <span key={i} className="flex items-center gap-6 pr-6">
      <span className="whitespace-nowrap">{t}</span>
      <span className="text-yel">✦</span>
    </span>
  ));
  return (
    <div className="relative overflow-hidden rounded-[12px] border-[2.5px] border-ink bg-ink text-snow shadow-brut font-mono text-[13px] font-bold uppercase tracking-wide">
      <div className="marquee flex w-max py-2.5">{row}{row}</div>
    </div>
  );
}

function Onboarding({ navigate, first }) {
  return (
    <div className="space-y-6">
      <section className="card relative overflow-hidden p-8 md:p-12 bg-snow">
        <div className="absolute -right-6 -top-6 w-40 h-40 rounded-full bg-pink border-[2.5px] border-ink hidden md:block" />
        <div className="absolute right-24 top-24 w-20 h-20 rotate-12 bg-lime border-[2.5px] border-ink hidden md:block" />
        <div className="relative max-w-2xl">
          <span className="sticker bg-yel"><Zap className="w-3.5 h-3.5" strokeWidth={3} /> First scan ≈ 20s</span>
          <h1 className="mt-5 font-display text-4xl md:text-6xl font-extrabold leading-[0.95]">
            hey {first}, let's see how <span className="highlight">cooked</span> your code is.
          </h1>
          <p className="mt-4 text-lg text-sub">
            Give CodeGuard a public GitHub repo or a ZIP. You'll get a letter grade, findings mapped to the OWASP Top 10,
            a dependency SBOM, and AI-written patches.
          </p>
          <button className="btn-primary h-12 px-6 mt-7 text-base" onClick={() => navigate("/new-analysis")}>
            <Plus className="w-5 h-5" strokeWidth={3} /> Run your first scan
          </button>
          <div className="mt-8">
            <div className="eyebrow mb-3">or speedrun it with a deliberately vulnerable repo →</div>
            <div className="flex flex-wrap gap-2">
              {DEMO_REPOS.map((r) => (
                <button key={r.url} className="chip h-9 px-4" onClick={() => navigate(`/new-analysis?repo=${encodeURIComponent(r.url)}`)}>
                  {r.label} <span className="font-normal text-sub">· {r.lang}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </section>
      <div className="grid md:grid-cols-3 gap-5">
        {[
          ["01", "Scan", "Bandit, Semgrep, secret signatures, OSV.dev and Radon run in parallel.", "bg-yel"],
          ["02", "Triage", "Findings are deduped, tagged with a CWE and mapped to the OWASP Top 10.", "bg-lilac"],
          ["03", "Ship", "Export SARIF to GitHub Code Scanning, a CycloneDX SBOM, or block PRs with the CLI.", "bg-lime"],
        ].map(([n, t, b, bg]) => (
          <div key={n} className={`card card-hover p-6 ${bg}`}>
            <div className="font-mono text-sm font-bold">{n}</div>
            <div className="mt-2 font-display text-2xl font-extrabold">{t}</div>
            <p className="mt-1 text-[15px]">{b}</p>
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
      <Plus className="w-4 h-4" strokeWidth={3} /> New scan
    </button>
  );

  if (!stats) return <AppShell title="Overview" actions={actions}><Spinner /></AppShell>;

  const first = (user?.name?.split(" ")[0] || "there").toLowerCase();
  if (!stats.total_analyses && !stats.running) {
    return <AppShell title="Overview" actions={actions}><Onboarding navigate={navigate} first={first} /></AppShell>;
  }

  const grade = stats.posture_grade;
  const g = GRADE[grade] || {};
  const critHigh = (stats.severity?.critical || 0) + (stats.severity?.high || 0);
  const owaspMax = Math.max(1, ...(stats.owasp || []).map((o) => o.count));
  const langTotal = Object.values(stats.languages || {}).reduce((a, b) => a + b, 0) || 1;
  const scannerTotal = Object.values(stats.scanners || {}).reduce((a, b) => a + b, 0) || 1;
  const trend = (stats.trend || []).map((t, i) => ({ ...t, i }));

  return (
    <AppShell title="Overview" actions={actions}>
      <div className="flex flex-wrap items-end justify-between gap-4 mb-6 fade-up">
        <h1 className="font-display text-4xl md:text-5xl font-extrabold leading-[0.95]">
          hey {first} 👋<br />
          your code is <span className="highlight">{(g.vibe || "unscanned").toLowerCase()}</span>.
        </h1>
        {stats.running > 0 && (
          <span className="sticker bg-cobalt text-white"><Loader2 className="w-3.5 h-3.5 animate-spin" /> {stats.running} scan running</span>
        )}
      </div>

      <div className="mb-6 fade-up d-1">
        <Ticker items={[
          `${stats.projects} projects tracked`, `${stats.total_analyses} scans`, `${compact(stats.lines_scanned)} lines reviewed`,
          `${critHigh} critical + high`, `${stats.secrets} secrets leaked`, `${stats.vulnerable_dependencies} vulnerable deps`,
          `${stats.fixed_total} findings fixed`, `${stats.streak} day streak`,
        ]} />
      </div>

      {/* Row 1: posture + KPI blocks */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        <section className="card p-6 md:p-8 xl:col-span-5 fade-up d-1">
          <div className="flex flex-col sm:flex-row items-center gap-8">
            <GradeSticker score={stats.posture_score} grade={grade} />
            <div className="text-center sm:text-left">
              <div className="eyebrow">Security posture</div>
              <div className="mt-2 font-display text-4xl font-extrabold">{g.emoji} {g.vibe || "No data"}</div>
              <p className="mt-3 text-[15px] text-sub max-w-xs">
                Average of each project's latest scan. Security findings count for 70%, code health for 30%.
              </p>
              <div className="mt-4 flex items-center justify-center sm:justify-start gap-2 text-[13px] font-semibold">
                {stats.score_delta_7d != null ? <><Delta value={stats.score_delta_7d} suffix=" pts" /> vs last week</> : "Scan again to see your trend"}
              </div>
            </div>
          </div>
        </section>

        <div className="xl:col-span-7 grid grid-cols-1 sm:grid-cols-2 gap-5">
          <StatTile className="fade-up d-2" label="Critical + high" icon={AlertOctagon} bg="#FF5A5F" value={critHigh}
                    hint={`${stats.severity?.critical || 0} critical across latest scans`} />
          <StatTile className="fade-up d-3" label="Secrets leaked" icon={KeyRound} bg="#FFE14D" value={stats.secrets || 0}
                    hint={stats.secrets ? "Rotate these first. Seriously." : "No hardcoded creds 🎉"} />
          <StatTile className="fade-up d-4" label="Vulnerable deps" icon={Package} bg="#C9B6FF"
                    value={<>{stats.vulnerable_dependencies || 0}<span className="text-2xl text-ink/60"> / {stats.total_dependencies || 0}</span></>}
                    hint="Known CVEs via OSV.dev" />
          <StatTile className="fade-up d-5" label="Fixed on re-scan" icon={Wrench} bg="#7CF0B4" value={stats.fixed_total || 0}
                    hint="Findings that disappeared. W." />
        </div>
      </div>

      {/* Row 2: trend + activity */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 mt-5">
        <Card className="xl:col-span-8" title="Score over time" subtitle={`Overall score across your last ${trend.length} scans`}>
          <div className="h-[250px] -ml-2">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trend} margin={{ top: 10, right: 28, bottom: 0, left: 0 }}>
                <CartesianGrid stroke={CHART.grid} vertical={false} />
                <XAxis dataKey="i" tickLine={false} axisLine={{ stroke: CHART.axis, strokeWidth: 2 }}
                       tick={{ fill: CHART.muted, fontSize: 11, fontFamily: "Space Mono" }}
                       tickFormatter={(i) => trend[i] && new Date(trend[i].date).toLocaleDateString(undefined, { month: "short", day: "numeric" })}
                       minTickGap={24} />
                <YAxis domain={[0, 100]} ticks={[0, 50, 100]} width={34} tickLine={false} axisLine={false}
                       tick={{ fill: CHART.muted, fontSize: 11, fontFamily: "Space Mono" }} />
                <Tooltip
                  cursor={{ stroke: CHART.axis, strokeWidth: 1.5, strokeDasharray: "0" }}
                  content={<ChartTooltip formatter={(v, p) => `${v} · grade ${p.payload.grade}`}
                                         labelFormatter={(i) => trend[i] && `${trend[i].name} · ${timeAgo(trend[i].date)}`} />}
                />
                <Area type="linear" dataKey="score" stroke={CHART.axis} strokeWidth={2.5} fill={CHART.fill} fillOpacity={0.85}
                      dot={{ r: 4, fill: "#FFFDF8", stroke: CHART.axis, strokeWidth: 2.5 }}
                      activeDot={{ r: 6, fill: CHART.brand, stroke: CHART.axis, strokeWidth: 2.5 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card className="xl:col-span-4" title="Activity" subtitle="Scans per day"
              right={<span className="sticker bg-tang rotate-3"><Flame className="w-3.5 h-3.5" strokeWidth={3} /> {stats.streak} day streak</span>}>
          <ActivityHeatmap days={stats.activity || []} />
          <div className="mt-5 pt-5 border-t-2 border-ink grid grid-cols-2 gap-4">
            <div>
              <div className="eyebrow">Avg score</div>
              <div className="mt-1 font-display text-3xl font-extrabold tabular">{stats.avg_score}</div>
            </div>
            <div>
              <div className="eyebrow">Open findings</div>
              <div className="mt-1 font-display text-3xl font-extrabold tabular">{stats.total_issues}</div>
            </div>
          </div>
        </Card>
      </div>

      {/* Row 3: OWASP + severity/scanners */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 mt-5">
        <Card className="xl:col-span-7" title="OWASP Top 10 exposure" subtitle="Findings in each project's latest scan, by 2021 category"
              right={<span className="w-9 h-9 grid place-items-center rounded-lg border-2 border-ink bg-lilac"><Radar className="w-4 h-4" strokeWidth={2.5} /></span>}>
          <div className="space-y-2.5">
            {stats.owasp.map((o) => (
              <div key={o.code} className="group grid grid-cols-[46px_1fr_30px] sm:grid-cols-[46px_230px_1fr_30px] items-center gap-3 text-[14px]"
                   title={`${o.code} ${o.name}: ${o.count} finding${o.count === 1 ? "" : "s"}`}>
                <span className={`font-mono text-[11px] font-bold text-center rounded border-2 border-ink py-0.5 ${o.count ? "bg-ink text-snow" : "bg-snow text-faint border-faint"}`}>
                  {o.code.split(":")[0]}
                </span>
                <span className={`hidden sm:block truncate font-semibold ${o.count ? "" : "text-faint"}`}>{o.name}</span>
                <div className="h-4 rounded-full border-2 border-ink bg-snow overflow-hidden p-[2px]">
                  <div className="h-full rounded-full bg-cobalt transition-all duration-700 group-hover:brightness-110"
                       style={{ width: `${(o.count / owaspMax) * 100}%` }} />
                </div>
                <span className={`text-right font-mono text-xs font-bold tabular ${o.count ? "" : "text-faint"}`}>{o.count}</span>
              </div>
            ))}
          </div>
        </Card>

        <div className="xl:col-span-5 grid gap-5">
          <Card title="Severity mix" subtitle={`${stats.total_issues} open findings`}>
            <SeverityBar counts={stats.severity} />
          </Card>
          <Card title="Detected by" subtitle="Which engine caught each finding">
            <div className="space-y-3">
              {Object.entries(stats.scanners || {}).map(([k, n]) => (
                <div key={k} className="flex items-center gap-3 text-sm">
                  <span className="w-24 shrink-0 font-bold">{SCANNERS[k]?.label || k}</span>
                  <div className="flex-1 h-3.5 rounded-full border-2 border-ink bg-snow overflow-hidden p-[2px]">
                    <div className="h-full rounded-full bg-ink" style={{ width: `${(n / scannerTotal) * 100}%` }} />
                  </div>
                  <span className="w-8 text-right font-mono text-xs font-bold tabular">{n}</span>
                </div>
              ))}
              {!Object.keys(stats.scanners || {}).length && <p className="text-sm text-sub">Nothing detected. Clean.</p>}
            </div>
          </Card>
        </div>
      </div>

      {/* Row 4: riskiest + languages */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5 mt-5">
        <Card className="xl:col-span-7" title="Needs attention 🚨" subtitle="Lowest-scoring projects first">
          <div className="-my-1">
            {stats.riskiest.map((p, idx) => (
              <button key={p.analysis_id} onClick={() => navigate(`/analysis/${p.analysis_id}`)}
                      className="w-full flex items-center gap-4 p-2.5 -mx-2.5 rounded-xl text-left group border-2 border-transparent hover:border-ink hover:bg-cream transition-colors">
                <span className="w-5 font-mono text-sm font-bold text-faint">{idx + 1}</span>
                <GradePill grade={p.grade} />
                <div className="min-w-0 flex-1">
                  <div className="truncate font-bold">{p.name}</div>
                  <div className="mt-1.5 max-w-[240px]"><SeverityBar counts={p.severity} showLegend={false} height={5} /></div>
                </div>
                <span className="font-mono font-bold tabular">{Math.round(p.score)}</span>
                <ArrowUpRight className="w-5 h-5 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" strokeWidth={2.5} />
              </button>
            ))}
          </div>
        </Card>
        <Card className="xl:col-span-5" title="Languages" subtitle="Lines of code across latest scans">
          <div className="flex h-6 gap-[2px] p-[2px] rounded-full border-2 border-ink bg-snow overflow-hidden">
            {Object.entries(stats.languages || {}).map(([lang, n], i, arr) => (
              <div key={lang} className={`${i === 0 ? "rounded-l-full" : ""} ${i === arr.length - 1 ? "rounded-r-full" : ""}`}
                   style={{ width: `${(n / langTotal) * 100}%`, background: languageColor(lang) }} title={`${lang}: ${n.toLocaleString()} lines`} />
            ))}
          </div>
          <div className="mt-4 grid grid-cols-2 gap-x-6 gap-y-2.5">
            {Object.entries(stats.languages || {}).map(([lang, n]) => (
              <div key={lang} className="flex items-center gap-2 text-[15px]">
                <span className="w-3.5 h-3.5 rounded border-2 border-ink" style={{ background: languageColor(lang) }} />
                <span className="capitalize font-semibold">{lang}</span>
                <span className="ml-auto font-mono text-xs font-bold tabular">{Math.round((n / langTotal) * 100)}%</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Card className="mt-5" title="Recent scans"
            right={<button className="btn-secondary btn-sm" onClick={() => navigate("/history")}>View all <ChevronRight className="w-4 h-4" strokeWidth={2.5} /></button>}>
        {stats.recent_analyses?.length ? (
          <div className="-my-1">
            {stats.recent_analyses.map((a) => (
              <button key={a.analysis_id} onClick={() => navigate(`/analysis/${a.analysis_id}`)}
                      className="w-full flex items-center gap-4 p-2.5 -mx-2.5 rounded-xl text-left group border-2 border-transparent hover:border-ink hover:bg-cream transition-colors">
                {a.status === "processing" ? (
                  <span className="w-9 h-9 grid place-items-center rounded-lg border-2 border-ink bg-cobalt text-white"><Loader2 className="w-4 h-4 animate-spin" /></span>
                ) : <GradePill grade={a.status === "failed" ? null : a.grade} />}
                <div className="min-w-0 flex-1">
                  <div className="truncate font-bold">{a.name}</div>
                  <div className="text-[13px] text-sub mt-0.5">
                    {a.status === "failed" ? <span className="text-[#B42318] font-semibold">Failed · {a.error || "error"}</span> :
                     a.status === "processing" ? a.progress?.stage || "Scanning…" :
                     <>{a.metrics?.total_files || 0} files · {a.issue_count} findings</>}
                    {" · "}{timeAgo(a.created_at)}
                  </div>
                </div>
                {a.baseline && <Delta value={a.baseline.score_delta} />}
                <ChevronRight className="w-5 h-5" strokeWidth={2.5} />
              </button>
            ))}
          </div>
        ) : <EmptyState icon={Code2} title="No scans yet" />}
      </Card>
    </AppShell>
  );
}
