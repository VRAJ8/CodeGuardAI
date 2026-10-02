import { useEffect, useState } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import axios from "axios";
import { toast } from "sonner";
import { LayoutGrid, History, Plus, LogOut, Github, ShieldCheck, Menu, X, BookOpen } from "lucide-react";
import { API } from "@/lib/api";
import { SCANNERS } from "@/lib/theme";

export function Logo({ className = "" }) {
  return (
    <div className={`flex items-center gap-2.5 ${className}`}>
      <div className="relative w-8 h-8 rounded-[10px] grid place-items-center bg-gradient-to-br from-[#00e599] to-[#0ea5e9] shadow-[0_0_24px_-6px_rgba(0,229,153,.8)]">
        <ShieldCheck className="w-[18px] h-[18px] text-black" strokeWidth={2.5} />
      </div>
      <span className="font-semibold tracking-tight text-[15px]">
        CodeGuard<span className="text-[#71717a] font-normal"> AI</span>
      </span>
    </div>
  );
}

const NAV = [
  { to: "/dashboard", label: "Overview", icon: LayoutGrid },
  { to: "/history", label: "Scans", icon: History },
  { to: "/new-analysis", label: "New scan", icon: Plus },
];

function NavItems({ onNavigate }) {
  return (
    <nav className="flex flex-col gap-1">
      {NAV.map(({ to, label, icon: Icon }) => (
        <NavLink
          key={to}
          to={to}
          onClick={onNavigate}
          className={({ isActive }) =>
            `flex items-center gap-3 px-3 h-9 rounded-lg text-sm transition-colors ${
              isActive ? "bg-white/[0.06] text-white" : "text-[#a1a1aa] hover:text-white hover:bg-white/[0.03]"
            }`
          }
        >
          <Icon className="w-4 h-4" />
          {label}
        </NavLink>
      ))}
    </nav>
  );
}

export default function AppShell({ children, title, actions }) {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [engines, setEngines] = useState(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    axios.get(`${API}/auth/me`).then((r) => setUser(r.data)).catch(() => {});
    axios.get(`${API}/health`).then((r) => setEngines(r.data.engines)).catch(() => {});
  }, []);

  const logout = async () => {
    try {
      await axios.post(`${API}/auth/logout`);
      toast.success("Logged out");
    } finally {
      navigate("/");
    }
  };

  const sidebar = (
    <div className="flex flex-col h-full p-4">
      <button onClick={() => navigate("/dashboard")} className="px-2 py-1 mb-6 text-left">
        <Logo />
      </button>
      <NavItems onNavigate={() => setOpen(false)} />

      {engines && (
        <div className="mt-8 px-2">
          <div className="eyebrow mb-3">Engines</div>
          <div className="space-y-2">
            {Object.entries(engines).map(([name, on]) => (
              <div key={name} className="flex items-center justify-between text-xs">
                <span className="text-[#a1a1aa]">{name === "ai" ? "AI triage" : SCANNERS[name]?.label || name}</span>
                <span className={`flex items-center gap-1.5 ${on ? "text-[#7cf5c8]" : "text-[#71717a]"}`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${on ? "bg-[#00e599]" : "bg-[#3f3f46]"}`} />
                  {on ? "on" : "off"}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="mt-auto space-y-1">
        <a href="https://github.com/VRAJ8/CodeGuardAI" target="_blank" rel="noreferrer"
           className="flex items-center gap-3 px-3 h-9 rounded-lg text-sm text-[#a1a1aa] hover:text-white hover:bg-white/[0.03]">
          <Github className="w-4 h-4" /> Source
        </a>
        <a href={`${API.replace(/\/api$/, "")}/docs`} target="_blank" rel="noreferrer"
           className="flex items-center gap-3 px-3 h-9 rounded-lg text-sm text-[#a1a1aa] hover:text-white hover:bg-white/[0.03]">
          <BookOpen className="w-4 h-4" /> API docs
        </a>
        <div className="flex items-center gap-3 p-2 mt-3 rounded-xl border border-white/[0.07] bg-white/[0.02]">
          {user?.picture ? (
            <img src={user.picture} alt="" className="w-8 h-8 rounded-full" />
          ) : (
            <div className="w-8 h-8 rounded-full grid place-items-center bg-gradient-to-br from-[#a78bfa] to-[#00e599] text-black text-xs font-bold">
              {(user?.name || "?").slice(0, 1).toUpperCase()}
            </div>
          )}
          <div className="min-w-0 flex-1">
            <div className="text-sm truncate">{user?.name || "…"}</div>
            <div className="text-[11px] text-[#71717a] truncate">{user?.email}</div>
          </div>
          <button onClick={logout} className="p-1.5 rounded-md text-[#71717a] hover:text-white hover:bg-white/5" aria-label="Log out">
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-[#09090b]">
      <aside className="hidden lg:block fixed inset-y-0 left-0 w-60 border-r border-white/[0.06] bg-[#0b0b0d]">{sidebar}</aside>

      {open && (
        <div className="lg:hidden fixed inset-0 z-50 flex">
          <div className="absolute inset-0 bg-black/70" onClick={() => setOpen(false)} />
          <aside className="relative w-64 bg-[#0b0b0d] border-r border-white/[0.06]">
            <button className="absolute top-4 right-3 p-1.5 text-[#a1a1aa]" onClick={() => setOpen(false)} aria-label="Close menu">
              <X className="w-4 h-4" />
            </button>
            {sidebar}
          </aside>
        </div>
      )}

      <div className="lg:pl-60">
        <header className="sticky top-0 z-40 glass border-b border-white/[0.06]">
          <div className="flex items-center gap-3 h-14 px-4 md:px-8">
            <button className="lg:hidden p-1.5 -ml-1.5 text-[#a1a1aa]" onClick={() => setOpen(true)} aria-label="Open menu">
              <Menu className="w-5 h-5" />
            </button>
            <div className="min-w-0 flex-1 text-sm font-medium truncate">{title}</div>
            <div className="flex items-center gap-2">{actions}</div>
          </div>
        </header>
        <main className="px-4 md:px-8 py-6 md:py-8 max-w-[1400px] mx-auto">{children}</main>
      </div>
    </div>
  );
}
