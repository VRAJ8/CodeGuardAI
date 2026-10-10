import { useEffect, useState } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import axios from "axios";
import { toast } from "sonner";
import { LayoutGrid, History, Plus, LogOut, Github, ShieldCheck, Menu, X, BookOpen, ScanSearch } from "lucide-react";
import { API } from "@/lib/api";
import { SCANNERS } from "@/lib/theme";

export function Logo({ className = "" }) {
  return (
    <div className={`flex items-center gap-2.5 ${className}`}>
      <div className="w-9 h-9 rounded-[10px] grid place-items-center bg-yel border-[2.5px] border-ink shadow-brut-sm -rotate-6">
        <ShieldCheck className="w-5 h-5" strokeWidth={2.75} />
      </div>
      <span className="font-display font-extrabold tracking-tight text-[18px] leading-none">
        codeguard<span className="text-cobalt">.ai</span>
      </span>
    </div>
  );
}

const NAV = [
  { to: "/dashboard", label: "Overview", icon: LayoutGrid },
  { to: "/history", label: "Scans", icon: History },
  { to: "/new-analysis", label: "New scan", icon: Plus },
  { to: "/scan", label: "Browser scan", icon: ScanSearch },
];

function NavItems({ onNavigate }) {
  return (
    <nav className="flex flex-col gap-1.5">
      {NAV.map(({ to, label, icon: Icon }) => (
        <NavLink
          key={to}
          to={to}
          onClick={onNavigate}
          className={({ isActive }) =>
            `flex items-center gap-3 px-3 h-11 rounded-[10px] text-[15px] font-bold border-2 transition-all ${
              isActive
                ? "bg-ink text-white border-ink shadow-[3px_3px_0_0_#3B5BFF]"
                : "border-transparent hover:border-ink hover:bg-snow"
            }`
          }
        >
          <Icon className="w-[18px] h-[18px]" strokeWidth={2.5} />
          {label}
        </NavLink>
      ))}
    </nav>
  );
}

export default function AppShell({ children, title, actions }) {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [signedOut, setSignedOut] = useState(false); // browser scans work without a session
  const [engines, setEngines] = useState(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    axios.get(`${API}/auth/me`).then((r) => setUser(r.data)).catch(() => setSignedOut(true));
    axios.get(`${API}/health`).then((r) => setEngines(r.data.engines)).catch(() => {});
  }, []);

  const logout = async () => {
    try {
      await axios.post(`${API}/auth/logout`);
      toast.success("Logged out. See ya ✌️");
    } finally {
      navigate("/");
    }
  };

  const sidebar = (
    <div className="flex flex-col h-full p-4">
      <button onClick={() => navigate("/dashboard")} className="px-1 py-1 mb-7 text-left">
        <Logo />
      </button>
      <NavItems onNavigate={() => setOpen(false)} />

      {engines && (
        <div className="mt-8 card-flat p-3 bg-cream">
          <div className="eyebrow mb-2.5">Engines</div>
          <div className="space-y-1.5">
            {Object.entries(engines).map(([name, on]) => (
              <div key={name} className="flex items-center justify-between text-[13px]">
                <span className="font-semibold">{name === "ai" ? "AI triage" : SCANNERS[name]?.label || name}</span>
                <span className={`font-mono text-[10px] font-bold px-1.5 rounded border-[1.5px] border-ink ${on ? "bg-mint" : "bg-snow text-faint"}`}>
                  {on ? "ON" : "OFF"}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="mt-auto space-y-1">
        <a href="https://github.com/VRAJ8/CodeGuardAI" target="_blank" rel="noreferrer" className="btn-ghost w-full !justify-start">
          <Github className="w-4 h-4" /> Source
        </a>
        <a href={`${API.replace(/\/api$/, "")}/docs`} target="_blank" rel="noreferrer" className="btn-ghost w-full !justify-start">
          <BookOpen className="w-4 h-4" /> API docs
        </a>
        {signedOut ? (
          <button onClick={() => navigate("/")} className="btn-secondary w-full mt-3">Sign in for cloud scans</button>
        ) : (
        <div className="flex items-center gap-3 p-2 mt-3 card-flat">
          {user?.picture ? (
            <img src={user.picture} alt="" className="w-9 h-9 rounded-lg border-2 border-ink" />
          ) : (
            <div className="w-9 h-9 rounded-lg grid place-items-center bg-pink border-2 border-ink font-display font-extrabold">
              {(user?.name || "?").slice(0, 1).toUpperCase()}
            </div>
          )}
          <div className="min-w-0 flex-1">
            <div className="text-sm font-bold truncate">{user?.name || "…"}</div>
            <div className="text-[11px] text-sub truncate">{user?.email}</div>
          </div>
          <button onClick={logout} className="p-1.5 rounded-md hover:bg-cherry border-2 border-transparent hover:border-ink" aria-label="Log out">
            <LogOut className="w-4 h-4" strokeWidth={2.5} />
          </button>
        </div>
        )}
      </div>
    </div>
  );

  return (
    <div className="min-h-screen">
      <aside className="hidden lg:block fixed inset-y-0 left-0 w-64 border-r-[2.5px] border-ink bg-snow">{sidebar}</aside>

      {open && (
        <div className="lg:hidden fixed inset-0 z-50 flex">
          <div className="absolute inset-0 bg-ink/50" onClick={() => setOpen(false)} />
          <aside className="relative w-72 bg-snow border-r-[2.5px] border-ink">
            <button className="absolute top-4 right-3 p-1.5" onClick={() => setOpen(false)} aria-label="Close menu">
              <X className="w-5 h-5" strokeWidth={2.5} />
            </button>
            {sidebar}
          </aside>
        </div>
      )}

      <div className="lg:pl-64">
        <header className="sticky top-0 z-40 bg-cream/90 backdrop-blur border-b-[2.5px] border-ink">
          <div className="flex items-center gap-3 h-16 px-4 md:px-8">
            <button className="lg:hidden p-1.5 -ml-1.5" onClick={() => setOpen(true)} aria-label="Open menu">
              <Menu className="w-5 h-5" strokeWidth={2.5} />
            </button>
            <div className="min-w-0 flex-1 font-display text-lg font-extrabold truncate">{title}</div>
            <div className="flex items-center gap-2">{actions}</div>
          </div>
        </header>
        <main className="px-4 md:px-8 py-6 md:py-8 max-w-[1400px] mx-auto">{children}</main>
      </div>
    </div>
  );
}
