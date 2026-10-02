import { useState } from "react";
import { AlertOctagon, AlertTriangle, AlertCircle, Info, TrendingUp, TrendingDown } from "lucide-react";
import { ACTIVITY_RAMP, GRADE, SEVERITY, SEVERITY_ORDER } from "@/lib/theme";

const SEVERITY_ICON = { critical: AlertOctagon, high: AlertTriangle, medium: AlertCircle, low: Info };

export function SeverityBadge({ severity, size = "sm" }) {
  const s = SEVERITY[severity] || SEVERITY.low;
  const Icon = SEVERITY_ICON[severity] || Info;
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md font-medium uppercase tracking-wide ${
        size === "sm" ? "text-[10px] px-1.5 h-5" : "text-xs px-2 h-6"
      }`}
      style={{ color: s.color, background: `${s.color}1f`, boxShadow: `inset 0 0 0 1px ${s.color}40` }}
    >
      <Icon className="w-3 h-3" strokeWidth={2.5} />
      {s.label}
    </span>
  );
}

export function GradePill({ grade, className = "" }) {
  if (!grade) return <span className={`text-[#71717a] ${className}`}>—</span>;
  const g = GRADE[grade];
  return (
    <span
      className={`inline-grid place-items-center w-8 h-8 rounded-lg font-bold text-sm ${className}`}
      style={{ color: g.color, background: g.bg, boxShadow: `inset 0 0 0 1px ${g.color}40` }}
      title={`Grade ${grade} — ${g.vibe}`}
    >
      {grade}
    </span>
  );
}

/** Radial gauge with the letter grade as the hero and the score underneath. */
export function GradeRing({ score, grade, size = 168, label = "Security posture" }) {
  const g = GRADE[grade] || { color: "#71717a" };
  const r = size / 2 - 10;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score || 0)) / 100;
  return (
    <div className="relative" style={{ width: size, height: size }} role="img" aria-label={`${label}: grade ${grade}, ${Math.round(score || 0)} out of 100`}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1f1f23" strokeWidth="8" />
        <circle
          cx={size / 2} cy={size / 2} r={r} fill="none" stroke={g.color} strokeWidth="8" strokeLinecap="round"
          strokeDasharray={`${c * pct} ${c}`} style={{ transition: "stroke-dasharray 1s cubic-bezier(.2,.7,.2,1)", filter: `drop-shadow(0 0 10px ${g.color}66)` }}
        />
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">
        <div>
          <div className="font-bold leading-none" style={{ color: g.color, fontSize: size * 0.34 }}>{grade || "—"}</div>
          <div className="mt-1 text-xs text-[#a1a1aa] tabular">{score != null ? `${Math.round(score)}/100` : "no data"}</div>
        </div>
      </div>
    </div>
  );
}

export function Delta({ value, suffix = "", invert = false }) {
  if (value == null || value === 0) return null;
  const good = invert ? value < 0 : value > 0;
  const Icon = value > 0 ? TrendingUp : TrendingDown;
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-medium ${good ? "text-[#4ade80]" : "text-[#f87171]"}`}>
      <Icon className="w-3.5 h-3.5" />
      {value > 0 ? "+" : ""}{value}{suffix}
    </span>
  );
}

export function StatTile({ label, value, hint, icon: Icon, accent = "#a1a1aa", delta, className = "" }) {
  return (
    <div className={`card p-5 ${className}`}>
      <div className="flex items-center justify-between">
        <span className="eyebrow">{label}</span>
        {Icon && <Icon className="w-4 h-4" style={{ color: accent }} />}
      </div>
      <div className="mt-3 flex items-baseline gap-2">
        <span className="text-[28px] font-semibold tracking-tight leading-none">{value}</span>
        {delta}
      </div>
      {hint && <div className="mt-2 text-xs text-[#71717a]">{hint}</div>}
    </div>
  );
}

/** Part-to-whole bar for severity counts. Status colors always paired with icon + label. */
export function SeverityBar({ counts, showLegend = true, height = 10 }) {
  const total = SEVERITY_ORDER.reduce((s, k) => s + (counts?.[k] || 0), 0);
  const [hover, setHover] = useState(null);
  return (
    <div>
      <div className="relative flex gap-[2px] rounded-full overflow-hidden bg-[#1c1c20]" style={{ height }}>
        {total > 0 &&
          SEVERITY_ORDER.filter((k) => counts?.[k]).map((k) => (
            <div
              key={k}
              className="h-full transition-opacity"
              style={{ width: `${(counts[k] / total) * 100}%`, background: SEVERITY[k].color, opacity: hover && hover !== k ? 0.35 : 1 }}
              onMouseEnter={() => setHover(k)}
              onMouseLeave={() => setHover(null)}
              title={`${SEVERITY[k].label}: ${counts[k]} (${Math.round((counts[k] / total) * 100)}%)`}
            />
          ))}
      </div>
      {showLegend && (
        <div className="mt-3 grid grid-cols-2 sm:grid-cols-4 gap-2">
          {SEVERITY_ORDER.map((k) => {
            const Icon = SEVERITY_ICON[k];
            return (
              <div key={k} className="flex items-center gap-2 text-xs" onMouseEnter={() => setHover(k)} onMouseLeave={() => setHover(null)}>
                <Icon className="w-3.5 h-3.5" style={{ color: SEVERITY[k].color }} />
                <span className="text-[#a1a1aa]">{SEVERITY[k].label}</span>
                <span className="ml-auto sm:ml-0 font-medium tabular text-white">{counts?.[k] || 0}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export function ChartTooltip({ active, payload, label, formatter, labelFormatter }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-white/10 bg-[#18181b]/95 backdrop-blur px-3 py-2 shadow-xl text-xs">
      {label != null && <div className="text-[#a1a1aa] mb-1">{labelFormatter ? labelFormatter(label, payload) : label}</div>}
      {payload.map((p) => (
        <div key={p.dataKey} className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-sm" style={{ background: p.color || p.payload?.fill }} />
          <span className="font-medium text-white tabular">{formatter ? formatter(p.value, p) : p.value}</span>
        </div>
      ))}
    </div>
  );
}

/** GitHub-style contribution grid: 4 weeks x 7 days of scan activity. */
export function ActivityHeatmap({ days }) {
  const max = Math.max(1, ...days.map((d) => d.count));
  const level = (n) => (n === 0 ? 0 : Math.min(4, Math.ceil((n / max) * 4)));
  const [hover, setHover] = useState(null);
  return (
    <div>
      <div className="grid grid-flow-col grid-rows-7 gap-1 w-fit">
        {days.map((d) => (
          <div
            key={d.date}
            className="w-[22px] h-[22px] rounded-[4px] transition-transform hover:scale-110"
            style={{ background: ACTIVITY_RAMP[level(d.count)] }}
            onMouseEnter={() => setHover(d)}
            onMouseLeave={() => setHover(null)}
            aria-label={`${d.date}: ${d.count} scans`}
          />
        ))}
      </div>
      <div className="mt-3 flex items-center justify-between text-[11px] text-[#71717a] h-4">
        <span>
          {hover
            ? `${new Date(hover.date + "T00:00:00").toLocaleDateString(undefined, { month: "short", day: "numeric" })} · ${hover.count} scan${hover.count === 1 ? "" : "s"}`
            : "Last 4 weeks"}
        </span>
        <span className="flex items-center gap-1">
          less
          {ACTIVITY_RAMP.map((c) => <span key={c} className="w-2.5 h-2.5 rounded-[2px]" style={{ background: c }} />)}
          more
        </span>
      </div>
    </div>
  );
}

export function EmptyState({ icon: Icon, title, body, action }) {
  return (
    <div className="card p-10 text-center">
      {Icon && (
        <div className="mx-auto mb-4 w-12 h-12 rounded-2xl grid place-items-center bg-white/[0.04] border border-white/[0.07]">
          <Icon className="w-5 h-5 text-[#a1a1aa]" />
        </div>
      )}
      <div className="font-medium">{title}</div>
      {body && <p className="mt-1 text-sm text-[#71717a] max-w-sm mx-auto">{body}</p>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function Spinner({ label }) {
  return (
    <div className="min-h-[60vh] grid place-items-center">
      <div className="text-center">
        <div className="w-8 h-8 mx-auto rounded-full border-2 border-[#00e599] border-t-transparent animate-spin" />
        {label && <p className="mt-3 text-sm text-[#71717a]">{label}</p>}
      </div>
    </div>
  );
}
