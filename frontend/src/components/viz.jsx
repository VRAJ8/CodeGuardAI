import { useState } from "react";
import { AlertOctagon, AlertTriangle, AlertCircle, Info, TrendingUp, TrendingDown } from "lucide-react";
import { ACTIVITY_RAMP, GRADE, SEVERITY, SEVERITY_ORDER } from "@/lib/theme";

const SEVERITY_ICON = { critical: AlertOctagon, high: AlertTriangle, medium: AlertCircle, low: Info };

export function SeverityBadge({ severity, size = "sm" }) {
  const s = SEVERITY[severity] || SEVERITY.low;
  const Icon = SEVERITY_ICON[severity] || Info;
  return (
    <span
      className={`inline-flex items-center gap-1 border-2 border-ink rounded-md font-extrabold uppercase tracking-wide text-ink ${
        size === "sm" ? "text-[10px] px-1.5 h-[22px]" : "text-xs px-2 h-7"
      }`}
      style={{ background: s.color }}
    >
      <Icon className="w-3 h-3" strokeWidth={3} />
      {s.label}
    </span>
  );
}

export function GradePill({ grade, className = "" }) {
  if (!grade) {
    return <span className={`inline-grid place-items-center w-9 h-9 rounded-lg border-2 border-ink bg-snow font-bold text-faint ${className}`}>?</span>;
  }
  return (
    <span
      className={`inline-grid place-items-center w-9 h-9 rounded-lg border-2 border-ink shadow-brut-sm font-display font-extrabold text-lg text-ink ${className}`}
      style={{ background: GRADE[grade].color }}
      title={`Grade ${grade}: ${GRADE[grade].vibe}`}
    >
      {grade}
    </span>
  );
}

/** The hero: a tilted sticker with the letter grade, score bar underneath. */
export function GradeSticker({ score, grade, size = "lg", label = "Security posture" }) {
  const g = GRADE[grade] || { color: "#fffdf8" };
  const big = size === "lg";
  const pct = Math.max(0, Math.min(100, score || 0));
  return (
    <div className="flex flex-col items-center" role="img" aria-label={`${label}: grade ${grade || "none"}, ${Math.round(score || 0)} out of 100`}>
      <div
        className={`wiggle relative grid place-items-center border-[3px] border-ink rounded-[22px] shadow-brut-lg -rotate-3 ${big ? "w-40 h-40" : "w-28 h-28"}`}
        style={{ background: g.color }}
      >
        <span className={`font-display font-extrabold leading-none ${big ? "text-[104px]" : "text-[72px]"}`}>{grade || "–"}</span>
        <span className="absolute -top-3 -right-3 rotate-12 bg-snow border-2 border-ink rounded-full px-2 h-7 grid place-items-center text-xs font-mono font-bold">
          {score != null ? Math.round(score) : "–"}
        </span>
      </div>
      <div className={`mt-6 ${big ? "w-40" : "w-28"} h-3 rounded-full border-2 border-ink bg-snow overflow-hidden`}>
        <div className="h-full bg-ink" style={{ width: `${pct}%`, transition: "width 1s cubic-bezier(.2,.7,.2,1)" }} />
      </div>
      <div className="mt-1.5 text-[11px] font-mono font-bold">{score != null ? `${Math.round(score)}/100` : "no data"}</div>
    </div>
  );
}

export function Delta({ value, suffix = "", invert = false }) {
  if (value == null || value === 0) return null;
  const good = invert ? value < 0 : value > 0;
  const Icon = value > 0 ? TrendingUp : TrendingDown;
  return (
    <span className={`inline-flex items-center gap-1 h-6 px-2 rounded-full border-2 border-ink text-[11px] font-extrabold ${good ? "bg-mint" : "bg-cherry"}`}>
      <Icon className="w-3 h-3" strokeWidth={3} />
      {value > 0 ? "+" : ""}{value}{suffix}
    </span>
  );
}

/** KPI block: flat color fill, ink outline, hard shadow. */
export function StatTile({ label, value, hint, icon: Icon, bg = "#fffdf8", delta, className = "" }) {
  return (
    <div className={`card card-hover p-5 ${className}`} style={{ background: bg }}>
      <div className="flex items-center justify-between">
        <span className="eyebrow !text-ink">{label}</span>
        {Icon && (
          <span className="w-8 h-8 grid place-items-center rounded-lg border-2 border-ink bg-snow">
            <Icon className="w-4 h-4" strokeWidth={2.5} />
          </span>
        )}
      </div>
      <div className="mt-3 flex items-baseline gap-2">
        <span className="font-display text-[44px] font-extrabold tracking-tight leading-none">{value}</span>
        {delta}
      </div>
      {hint && <div className="mt-2 text-[13px] font-medium text-ink/70">{hint}</div>}
    </div>
  );
}

/** Part-to-whole bar for severity counts. Status colors always paired with icon + label. */
export function SeverityBar({ counts, showLegend = true, height = 14 }) {
  const total = SEVERITY_ORDER.reduce((s, k) => s + (counts?.[k] || 0), 0);
  const [hover, setHover] = useState(null);
  return (
    <div>
      <div className="flex gap-[2px] p-[2px] rounded-full border-2 border-ink bg-snow overflow-hidden" style={{ height: height + 8 }}>
        {total > 0 ? SEVERITY_ORDER.filter((k) => counts?.[k]).map((k, i, arr) => (
          <div
            key={k}
            className={`h-full transition-opacity ${i === 0 ? "rounded-l-full" : ""} ${i === arr.length - 1 ? "rounded-r-full" : ""}`}
            style={{ width: `${(counts[k] / total) * 100}%`, background: SEVERITY[k].color, opacity: hover && hover !== k ? 0.3 : 1 }}
            onMouseEnter={() => setHover(k)}
            onMouseLeave={() => setHover(null)}
            title={`${SEVERITY[k].label}: ${counts[k]} (${Math.round((counts[k] / total) * 100)}%)`}
          />
        )) : height >= 10 && <div className="w-full grid place-items-center text-[10px] font-mono font-bold text-faint">ALL CLEAR</div>}
      </div>
      {showLegend && (
        <div className="mt-3 grid grid-cols-2 sm:grid-cols-4 gap-2">
          {SEVERITY_ORDER.map((k) => {
            const Icon = SEVERITY_ICON[k];
            return (
              <div key={k} className="flex items-center gap-2 text-[13px]" onMouseEnter={() => setHover(k)} onMouseLeave={() => setHover(null)}>
                <span className="w-5 h-5 grid place-items-center rounded border-2 border-ink" style={{ background: SEVERITY[k].color }}>
                  <Icon className="w-3 h-3" strokeWidth={3} />
                </span>
                <span className="font-semibold">{SEVERITY[k].label}</span>
                <span className="ml-auto sm:ml-0 font-mono font-bold tabular">{counts?.[k] || 0}</span>
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
    <div className="rounded-lg border-2 border-ink bg-snow shadow-brut px-3 py-2 text-xs">
      {label != null && <div className="font-semibold mb-1">{labelFormatter ? labelFormatter(label, payload) : label}</div>}
      {payload.map((p) => (
        <div key={p.dataKey} className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-sm border border-ink" style={{ background: p.color || p.payload?.fill }} />
          <span className="font-mono font-bold tabular">{formatter ? formatter(p.value, p) : p.value}</span>
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
      <div className="grid grid-flow-col grid-rows-7 gap-1.5 w-fit">
        {days.map((d) => (
          <div
            key={d.date}
            className="w-[22px] h-[22px] rounded-[5px] border-2 border-ink transition-transform hover:scale-110 hover:-rotate-6"
            style={{ background: ACTIVITY_RAMP[level(d.count)] }}
            onMouseEnter={() => setHover(d)}
            onMouseLeave={() => setHover(null)}
            aria-label={`${d.date}: ${d.count} scans`}
          />
        ))}
      </div>
      <div className="mt-3 flex items-center justify-between gap-3 text-[11px] font-mono text-sub h-4">
        <span>
          {hover
            ? `${new Date(hover.date + "T00:00:00").toLocaleDateString(undefined, { month: "short", day: "numeric" })} · ${hover.count} scan${hover.count === 1 ? "" : "s"}`
            : "last 4 weeks"}
        </span>
        <span className="flex items-center gap-1">
          less
          {ACTIVITY_RAMP.map((c) => <span key={c} className="w-3 h-3 rounded-[3px] border border-ink" style={{ background: c }} />)}
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
        <div className="mx-auto mb-4 w-14 h-14 rounded-2xl grid place-items-center border-2 border-ink bg-yel shadow-brut-sm -rotate-6">
          <Icon className="w-6 h-6" strokeWidth={2.5} />
        </div>
      )}
      <div className="font-display text-xl font-extrabold">{title}</div>
      {body && <p className="mt-1 text-sm text-sub max-w-sm mx-auto">{body}</p>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function Spinner({ label }) {
  return (
    <div className="min-h-[60vh] grid place-items-center">
      <div className="text-center">
        <div className="w-12 h-12 mx-auto rounded-xl border-[3px] border-ink bg-yel shadow-brut animate-spin [animation-duration:1.4s]" />
        {label && <p className="mt-4 text-sm font-mono">{label}</p>}
      </div>
    </div>
  );
}
