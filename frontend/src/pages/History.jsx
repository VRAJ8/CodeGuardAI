import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { toast } from "sonner";
import { Search, Plus, Github, FileArchive, Loader2, Trash2, ChevronRight, History as HistoryIcon } from "lucide-react";
import AppShell from "@/components/AppShell";
import { Delta, EmptyState, GradePill, SeverityBar, Spinner } from "@/components/viz";
import { API, compact, timeAgo } from "@/lib/api";

const SORTS = { recent: "Newest", score_asc: "Lowest score", score_desc: "Highest score", issues: "Most findings" };

export default function History() {
  const navigate = useNavigate();
  const [items, setItems] = useState(null);
  const [q, setQ] = useState("");
  const [grade, setGrade] = useState(null);
  const [status, setStatus] = useState(null);
  const [sort, setSort] = useState("recent");

  useEffect(() => {
    let timer;
    const load = () =>
      axios.get(`${API}/analysis/list`).then((r) => {
        setItems(r.data);
        if (r.data.some((a) => a.status === "processing")) timer = setTimeout(load, 4000);
      }).catch(() => { toast.error("Couldn't load scans"); setItems([]); });
    load();
    return () => clearTimeout(timer);
  }, []);

  const shown = useMemo(() => {
    const list = (items || []).filter((a) =>
      (!q || `${a.name} ${a.source_url || ""}`.toLowerCase().includes(q.toLowerCase())) &&
      (!grade || a.grade === grade) && (!status || a.status === status));
    const by = {
      recent: (a, b) => b.created_at.localeCompare(a.created_at),
      score_asc: (a, b) => (a.overall_score ?? 101) - (b.overall_score ?? 101),
      score_desc: (a, b) => (b.overall_score ?? -1) - (a.overall_score ?? -1),
      issues: (a, b) => (b.issue_count || 0) - (a.issue_count || 0),
    };
    return list.sort(by[sort]);
  }, [items, q, grade, status, sort]);

  const remove = async (e, id) => {
    e.stopPropagation();
    if (!window.confirm("Delete this scan? This can't be undone.")) return;
    try {
      await axios.delete(`${API}/analysis/${id}`);
      setItems((xs) => xs.filter((x) => x.analysis_id !== id));
      toast.success("Scan deleted");
    } catch {
      toast.error("Delete failed");
    }
  };

  const actions = <button className="btn-primary btn-sm" onClick={() => navigate("/new-analysis")}><Plus className="w-3.5 h-3.5" /> New scan</button>;
  if (!items) return <AppShell title="Scans" actions={actions}><Spinner /></AppShell>;

  return (
    <AppShell title="Scans" actions={actions}>
      <div className="flex flex-wrap items-end justify-between gap-3 mb-5">
        <div>
          <h1 className="text-2xl font-semibold">Scan history</h1>
          <p className="text-sm text-[#71717a] mt-1">{items.length} scans · re-scan a repo to track new vs fixed findings</p>
        </div>
      </div>

      {!items.length ? (
        <EmptyState icon={HistoryIcon} title="No scans yet" body="Your scans show up here, with grade, findings and trend."
                    action={<button className="btn-primary" onClick={() => navigate("/new-analysis")}><Plus className="w-4 h-4" /> Start scanning</button>} />
      ) : (
        <div className="card overflow-hidden">
          <div className="p-4 border-b border-white/[0.06] flex flex-col md:flex-row gap-3 md:items-center">
            <div className="relative flex-1 max-w-sm">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#71717a]" />
              <input className="input h-9 pl-9 text-sm" placeholder="Search repos…" value={q} onChange={(e) => setQ(e.target.value)} />
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              {["A", "B", "C", "D", "F"].map((g) => (
                <button key={g} className={`chip h-7 w-8 justify-center ${grade === g ? "chip-active" : ""}`} onClick={() => setGrade(grade === g ? null : g)}>{g}</button>
              ))}
              <span className="w-px h-6 bg-white/10 mx-1" />
              {["processing", "failed"].map((s) => (
                <button key={s} className={`chip h-7 px-3 capitalize ${status === s ? "chip-active" : ""}`} onClick={() => setStatus(status === s ? null : s)}>{s}</button>
              ))}
              <select value={sort} onChange={(e) => setSort(e.target.value)} aria-label="Sort"
                      className="h-7 ml-1 rounded-full bg-[#18181b] border border-white/[0.07] text-[11px] text-[#a1a1aa] px-2 outline-none">
                {Object.entries(SORTS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
            </div>
          </div>

          <div className="hidden md:grid grid-cols-[40px_1fr_200px_90px_90px_90px_64px] gap-4 px-4 py-2.5 text-xs text-[#71717a] border-b border-white/[0.06]">
            <span /><span>Project</span><span>Severity</span><span className="text-right">Findings</span><span className="text-right">Lines</span><span className="text-right">When</span><span />
          </div>
          {shown.map((a) => (
            <div key={a.analysis_id} role="button" tabIndex={0} onClick={() => navigate(`/analysis/${a.analysis_id}`)}
                 onKeyDown={(e) => e.key === "Enter" && navigate(`/analysis/${a.analysis_id}`)}
                 className="group grid grid-cols-[40px_1fr_auto] md:grid-cols-[40px_1fr_200px_90px_90px_90px_64px] gap-4 items-center px-4 py-3 border-b border-white/[0.04] last:border-0 cursor-pointer hover:bg-white/[0.02]">
              {a.status === "processing" ? (
                <span className="w-8 h-8 grid place-items-center rounded-lg bg-[#00e599]/10"><Loader2 className="w-4 h-4 text-[#00e599] animate-spin" /></span>
              ) : <GradePill grade={a.status === "failed" ? null : a.grade} />}
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  {a.source_type === "github" ? <Github className="w-3.5 h-3.5 text-[#71717a]" /> : <FileArchive className="w-3.5 h-3.5 text-[#71717a]" />}
                  <span className="truncate font-medium">{a.name}</span>
                  {a.baseline && <Delta value={a.baseline.score_delta} />}
                </div>
                <div className="text-xs text-[#71717a] mt-0.5 truncate">
                  {a.status === "failed" ? <span className="text-[#f87171]">{a.error || "Failed"}</span>
                    : a.status === "processing" ? a.progress?.stage : `score ${Math.round(a.overall_score ?? 0)} · ${(a.scanners_run || []).length || 2} engines`}
                </div>
              </div>
              <div className="hidden md:block">{a.status === "completed" && <SeverityBar counts={a.severity_counts} showLegend={false} height={6} />}</div>
              <span className="hidden md:block text-right tabular text-sm">{a.status === "completed" ? a.issue_count : "—"}</span>
              <span className="hidden md:block text-right tabular text-sm text-[#a1a1aa]">{compact(a.metrics?.total_lines)}</span>
              <span className="hidden md:block text-right text-xs text-[#71717a]">{timeAgo(a.created_at)}</span>
              <span className="flex items-center justify-end gap-1">
                <button onClick={(e) => remove(e, a.analysis_id)} aria-label="Delete scan"
                        className="p-1.5 rounded-md text-[#52525b] opacity-0 group-hover:opacity-100 hover:text-[#f87171] hover:bg-white/5">
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
                <ChevronRight className="w-4 h-4 text-[#52525b] group-hover:text-white" />
              </span>
            </div>
          ))}
          {!shown.length && <div className="p-10 text-center text-sm text-[#71717a]">Nothing matches those filters.</div>}
        </div>
      )}
    </AppShell>
  );
}
