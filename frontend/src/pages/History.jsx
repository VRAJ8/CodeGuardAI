import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { API } from "@/App";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { 
  Shield, ArrowLeft, FileCode, Trash2, Search, 
  ChevronRight, AlertTriangle, CheckCircle, Clock,
  Plus, History as HistoryIcon, LogOut, User
} from "lucide-react";
import { toast } from "sonner";

export default function History() {
  const navigate = useNavigate();
  const [analyses, setAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [user, setUser] = useState(null);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [userRes, analysesRes] = await Promise.all([
        axios.get(`${API}/auth/me`),
        axios.get(`${API}/analysis/list`)
      ]);
      setUser(userRes.data);
      setAnalyses(analysesRes.data);
    } catch (error) {
      console.error("Error fetching data:", error);
      toast.error("Failed to load history");
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (analysisId, e) => {
    e.stopPropagation();
    if (!window.confirm("Are you sure you want to delete this analysis?")) return;
    
    try {
      await axios.delete(`${API}/analysis/${analysisId}`);
      setAnalyses(analyses.filter(a => a.analysis_id !== analysisId));
      toast.success("Analysis deleted");
    } catch (error) {
      toast.error("Failed to delete analysis");
    }
  };

  const handleLogout = async () => {
    try {
      await axios.post(`${API}/auth/logout`);
      toast.success("Logged out");
      navigate("/");
    } catch (error) {
      console.error("Logout error:", error);
    }
  };

  const getScoreColor = (score) => {
    if (score >= 80) return "#00E599";
    if (score >= 60) return "#F59E0B";
    return "#FF4D4D";
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case "completed":
        return <CheckCircle className="w-4 h-4 text-[#00E599]" />;
      case "processing":
        return <Clock className="w-4 h-4 text-[#F59E0B] animate-pulse" />;
      case "failed":
        return <AlertTriangle className="w-4 h-4 text-[#FF4D4D]" />;
      default:
        return null;
    }
  };

  const filteredAnalyses = analyses.filter(a => 
    a.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    a.source_url?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  if (loading) {
    return (
      <div className="min-h-screen bg-[#050505] flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-[#00E599] border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#050505]" data-testid="history-page">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 glass border-b border-white/5">
        <div className="max-w-7xl mx-auto px-6 md:px-12">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2 cursor-pointer" onClick={() => navigate("/dashboard")}>
                <Shield className="w-6 h-6 text-[#00E599]" />
                <span className="font-bold text-lg tracking-tight">CodeGuard AI</span>
              </div>
              <div className="hidden md:flex items-center gap-4">
                <Button 
                  variant="ghost" 
                  className="btn-ghost"
                  onClick={() => navigate("/dashboard")}
                  data-testid="nav-dashboard"
                >
                  Dashboard
                </Button>
                <Button 
                  variant="ghost" 
                  className="btn-ghost bg-[#171717]"
                  onClick={() => navigate("/history")}
                  data-testid="nav-history"
                >
                  <HistoryIcon className="w-4 h-4 mr-2" />
                  History
                </Button>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              <Button 
                onClick={() => navigate("/new-analysis")}
                className="btn-primary px-4 py-2 flex items-center gap-2"
                data-testid="new-analysis-btn"
              >
                <Plus className="w-4 h-4" />
                New Analysis
              </Button>
              <div className="flex items-center gap-3">
                {user?.picture ? (
                  <img 
                    src={user.picture} 
                    alt={user.name} 
                    className="w-8 h-8 rounded-full border border-[#27272A]"
                  />
                ) : (
                  <div className="w-8 h-8 rounded-full bg-[#171717] flex items-center justify-center">
                    <User className="w-4 h-4 text-[#A1A1AA]" />
                  </div>
                )}
                <Button 
                  variant="ghost" 
                  size="icon"
                  onClick={handleLogout}
                  className="btn-ghost"
                  data-testid="logout-btn"
                >
                  <LogOut className="w-4 h-4" />
                </Button>
              </div>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="pt-24 pb-12 px-6 md:px-12">
        <div className="max-w-5xl mx-auto">
          {/* Header */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
            <div>
              <h1 className="text-3xl md:text-4xl tracking-tight mb-2">
                Analysis <span className="text-[#00E599]">History</span>
              </h1>
              <p className="text-[#A1A1AA]">
                {analyses.length} total analyses
              </p>
            </div>
            
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#52525B]" />
              <Input
                type="text"
                placeholder="Search analyses..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="input-dark pl-10 w-full md:w-64"
                data-testid="search-input"
              />
            </div>
          </div>

          {/* Analyses List */}
          <div className="space-y-3">
            {filteredAnalyses.length > 0 ? (
              filteredAnalyses.map((analysis) => (
                <div 
                  key={analysis.analysis_id}
                  className="card-dark card-hover p-4 cursor-pointer"
                  onClick={() => navigate(`/analysis/${analysis.analysis_id}`)}
                  data-testid={`analysis-row-${analysis.analysis_id}`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="w-12 h-12 rounded-sm bg-[#171717] flex items-center justify-center">
                        <FileCode className="w-6 h-6 text-[#6366F1]" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-medium">{analysis.name}</span>
                          {getStatusIcon(analysis.status)}
                        </div>
                        <div className="text-sm text-[#A1A1AA] mt-1">
                          {new Date(analysis.created_at).toLocaleDateString()} at{" "}
                          {new Date(analysis.created_at).toLocaleTimeString()}
                          <span className="mx-2">•</span>
                          <span className="capitalize">{analysis.source_type}</span>
                          {analysis.metrics && (
                            <>
                              <span className="mx-2">•</span>
                              {analysis.metrics.total_files} files
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                    
                    <div className="flex items-center gap-4">
                      {analysis.status === "completed" && (
                        <div className="text-right hidden md:block">
                          <div 
                            className="text-xl font-bold"
                            style={{ color: getScoreColor(analysis.overall_score) }}
                          >
                            {analysis.overall_score?.toFixed(0)}%
                          </div>
                          <div className="text-xs text-[#A1A1AA]">
                            {analysis.security_issues?.length || 0} issues
                          </div>
                        </div>
                      )}
                      
                      <div className="flex items-center gap-2">
                        <Button 
                          variant="ghost" 
                          size="icon"
                          className="btn-ghost text-[#FF4D4D] hover:text-[#FF4D4D] hover:bg-[#FF4D4D]/10"
                          onClick={(e) => handleDelete(analysis.analysis_id, e)}
                          data-testid={`delete-${analysis.analysis_id}`}
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                        <ChevronRight className="w-5 h-5 text-[#A1A1AA]" />
                      </div>
                    </div>
                  </div>
                </div>
              ))
            ) : (
              <div className="card-dark p-12 text-center">
                {searchQuery ? (
                  <>
                    <Search className="w-12 h-12 text-[#27272A] mx-auto mb-4" />
                    <p className="text-[#A1A1AA] mb-2">No analyses found matching "{searchQuery}"</p>
                    <Button 
                      variant="ghost" 
                      className="btn-ghost"
                      onClick={() => setSearchQuery("")}
                    >
                      Clear search
                    </Button>
                  </>
                ) : (
                  <>
                    <FileCode className="w-12 h-12 text-[#27272A] mx-auto mb-4" />
                    <p className="text-[#A1A1AA] mb-4">No analyses yet</p>
                    <Button 
                      onClick={() => navigate("/new-analysis")}
                      className="btn-primary"
                      data-testid="start-first-analysis"
                    >
                      <Plus className="w-4 h-4 mr-2" />
                      Start Your First Analysis
                    </Button>
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
