import { useEffect, useState, useRef } from "react";
import { BrowserRouter, Routes, Route, Navigate, useNavigate, useLocation } from "react-router-dom";
import axios from "axios";
import { Toaster } from "@/components/ui/sonner";
import { toast } from "sonner";
import { API } from "@/lib/api";

import Landing from "./pages/Landing";
import Dashboard from "./pages/Dashboard";
import NewAnalysis from "./pages/NewAnalysis";
import AnalysisDetail from "./pages/AnalysisDetail";
import History from "./pages/History";

const FullscreenSpinner = ({ label }) => (
  <div className="min-h-screen grid place-items-center">
    <div className="text-center">
      <div className="w-12 h-12 mx-auto rounded-xl border-[3px] border-ink bg-yel shadow-brut animate-spin [animation-duration:1.4s]" />
      {label && <p className="mt-4 text-sm font-mono">{label}</p>}
    </div>
  </div>
);

// REMINDER: DO NOT HARDCODE THE URL, OR ADD ANY FALLBACKS OR REDIRECT URLS, THIS BREAKS THE AUTH
const AuthCallback = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const hasProcessed = useRef(false);

  useEffect(() => {
    if (hasProcessed.current) return;
    hasProcessed.current = true;
    const match = location.hash.match(/session_id=([^&]+)/);
    if (!match) {
      navigate("/", { replace: true });
      return;
    }
    axios
      .post(`${API}/auth/session`, { session_id: match[1] })
      .then((res) => {
        toast.success(`Welcome, ${res.data.name?.split(" ")[0] || "dev"} 👋`);
        navigate("/dashboard", { state: { user: res.data }, replace: true });
      })
      .catch(() => {
        toast.error("Authentication failed");
        navigate("/", { replace: true });
      });
  }, [location, navigate]);

  return <FullscreenSpinner label="Authenticating…" />;
};

const ProtectedRoute = ({ children }) => {
  const location = useLocation();
  const [status, setStatus] = useState(location.state?.user ? "ok" : "checking");

  useEffect(() => {
    if (location.state?.user) return;
    axios
      .get(`${API}/auth/me`)
      .then(() => setStatus("ok"))
      .catch(() => setStatus("denied"));
  }, [location]);

  if (status === "checking") return <FullscreenSpinner />;
  if (status === "denied") return <Navigate to="/" replace />;
  return children;
};

function AppRouter() {
  const location = useLocation();
  if (location.hash?.includes("session_id=")) return <AuthCallback />;

  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
      <Route path="/new-analysis" element={<ProtectedRoute><NewAnalysis /></ProtectedRoute>} />
      <Route path="/analysis/:id" element={<ProtectedRoute><AnalysisDetail /></ProtectedRoute>} />
      <Route path="/history" element={<ProtectedRoute><History /></ProtectedRoute>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <AppRouter />
      </BrowserRouter>
      <Toaster
        position="bottom-right"
        toastOptions={{ style: { background: "#FFFDF8", border: "2.5px solid #111", boxShadow: "4px 4px 0 0 #111", color: "#111", borderRadius: 12, fontWeight: 600 } }}
      />
    </div>
  );
}

export { API };
