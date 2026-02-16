import { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import axios from "axios";
import { API } from "@/App";
import { Button } from "@/components/ui/button";
import { 
  Shield, Plus, History, LogOut, TrendingUp, AlertTriangle, 
  FileCode, Bug, ChevronRight, User
} from "lucide-react";
import { toast } from "sonner";
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from "recharts";

export default function Dashboard() {
  const navigate = useNavigate();
  const location = useLocation();
  const [user, setUser] = useState(location.state?.user || null);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      // Fetch user if not in state
      if (!user) {
        const userRes = await axios.get(`${API}/auth/me`);
        setUser(userRes.data);
      }
      
      // Fetch dashboard stats
      const statsRes = await axios.get(`${API}/analysis/stats/dashboard`);
      setStats(statsRes.data);
    } catch (error) {
      console.error("Error fetching data:", error);
      toast.error("Failed to load dashboard");
    } finally {
      setLoading(false);
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

  const languageColors = {
    python: "#3572A5",
    javascript: "#F7DF1E",
    typescript: "#3178C6",
    java: "#B07219",
    go: "#00ADD8",
    rust: "#DEA584",
    unknown: "#6366F1"
  };

  const getScoreColor = (score) => {
    if (score >= 80) return "#00E599";
    if (score >= 60) return "#F59E0B";
    return "#FF4D4D";
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#050505] flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-[#00E599] border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  const languageData = stats?.languages ? 
    Object.entries(stats.languages).map(([name, value]) => ({
      name,
      value,
      color: languageColors[name] || languageColors.unknown
    })) : [];

  return (
    <div className="min-h-screen bg-[#050505]" data-testid="dashboard">
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
                  className="btn-ghost"
                  onClick={() => navigate("/history")}
                  data-testid="nav-history"
                >
                  <History className="w-4 h-4 mr-2" />
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
        <div className="max-w-7xl mx-auto">
          {/* Welcome Header */}
          <div className="mb-8">
            <h1 className="text-3xl md:text-4xl tracking-tight mb-2">
              Welcome back, <span className="text-[#00E599]">{user?.name?.split(' ')[0] || 'Developer'}</span>
            </h1>
            <p className="text-[#A1A1AA]">
              {stats?.total_analyses > 0 
                ? `You've analyzed ${stats.total_analyses} repositories`
                : "Start by analyzing your first repository"
              }
            </p>
          </div>

          {/* Stats Grid */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <div className="card-dark p-6" data-testid="stat-analyses">
              <div className="flex items-center justify-between mb-4">
                <FileCode className="w-5 h-5 text-[#6366F1]" />
                <span className="text-xs text-[#A1A1AA] uppercase tracking-wide">Total Analyses</span>
              </div>
              <div className="text-3xl font-bold">{stats?.total_analyses || 0}</div>
            </div>
            
            <div className="card-dark p-6" data-testid="stat-score">
              <div className="flex items-center justify-between mb-4">
                <TrendingUp className="w-5 h-5 text-[#00E599]" />
                <span className="text-xs text-[#A1A1AA] uppercase tracking-wide">Avg Score</span>
              </div>
              <div className="text-3xl font-bold" style={{ color: getScoreColor(stats?.avg_score || 0) }}>
                {stats?.avg_score || 0}%
              </div>
            </div>
            
            <div className="card-dark p-6" data-testid="stat-issues">
              <div className="flex items-center justify-between mb-4">
                <AlertTriangle className="w-5 h-5 text-[#FF4D4D]" />
                <span className="text-xs text-[#A1A1AA] uppercase tracking-wide">Total Issues</span>
              </div>
              <div className="text-3xl font-bold text-[#FF4D4D]">{stats?.total_issues || 0}</div>
            </div>
            
            <div className="card-dark p-6" data-testid="stat-bugs">
              <div className="flex items-center justify-between mb-4">
                <Bug className="w-5 h-5 text-[#F59E0B]" />
                <span className="text-xs text-[#A1A1AA] uppercase tracking-wide">Bug Risks</span>
              </div>
              <div className="text-3xl font-bold text-[#F59E0B]">
                {stats?.recent_analyses?.reduce((acc, a) => acc + (a.bug_risks?.length || 0), 0) || 0}
              </div>
            </div>
          </div>

          {/* Charts and Recent */}
          <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
            {/* Language Distribution */}
            <div className="md:col-span-4 card-dark p-6" data-testid="language-chart">
              <h3 className="text-lg mb-4">Languages Analyzed</h3>
              {languageData.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={languageData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={80}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {languageData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[200px] flex items-center justify-center text-[#A1A1AA]">
                  No data yet
                </div>
              )}
              <div className="flex flex-wrap gap-2 mt-4">
                {languageData.map((lang) => (
                  <div key={lang.name} className="flex items-center gap-2 text-sm">
                    <div className="w-3 h-3 rounded-sm" style={{ backgroundColor: lang.color }} />
                    <span className="capitalize">{lang.name}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Recent Analyses */}
            <div className="md:col-span-8 card-dark p-6" data-testid="recent-analyses">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg">Recent Analyses</h3>
                <Button 
                  variant="ghost" 
                  className="btn-ghost text-sm"
                  onClick={() => navigate("/history")}
                >
                  View All
                  <ChevronRight className="w-4 h-4 ml-1" />
                </Button>
              </div>
              
              {stats?.recent_analyses?.length > 0 ? (
                <div className="space-y-3">
                  {stats.recent_analyses.map((analysis) => (
                    <div 
                      key={analysis.analysis_id}
                      className="flex items-center justify-between p-4 bg-[#171717] rounded-sm cursor-pointer hover:bg-[#1F1F1F] transition-colors"
                      onClick={() => navigate(`/analysis/${analysis.analysis_id}`)}
                      data-testid={`analysis-${analysis.analysis_id}`}
                    >
                      <div className="flex items-center gap-4">
                        <div className="w-10 h-10 rounded-sm bg-[#0A0A0A] flex items-center justify-center">
                          <FileCode className="w-5 h-5 text-[#6366F1]" />
                        </div>
                        <div>
                          <div className="font-medium">{analysis.name}</div>
                          <div className="text-sm text-[#A1A1AA]">
                            {new Date(analysis.created_at).toLocaleDateString()} • {analysis.metrics?.total_files || 0} files
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="text-right">
                          <div 
                            className="text-lg font-bold"
                            style={{ color: getScoreColor(analysis.overall_score) }}
                          >
                            {analysis.overall_score?.toFixed(0)}%
                          </div>
                          <div className="text-xs text-[#A1A1AA]">
                            {analysis.security_issues?.length || 0} issues
                          </div>
                        </div>
                        <ChevronRight className="w-5 h-5 text-[#A1A1AA]" />
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-12">
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
                </div>
              )}
            </div>
          </div>

          {/* Quick Actions */}
          <div className="mt-8 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div 
              className="card-dark card-hover p-6 cursor-pointer"
              onClick={() => navigate("/new-analysis")}
              data-testid="quick-github"
            >
              <div className="flex items-center gap-4">
                <div className="p-3 bg-[#00E599]/10 rounded-sm">
                  <Shield className="w-6 h-6 text-[#00E599]" />
                </div>
                <div>
                  <h3 className="font-medium">Analyze GitHub Repository</h3>
                  <p className="text-sm text-[#A1A1AA]">Paste any public GitHub URL to start analysis</p>
                </div>
              </div>
            </div>
            
            <div 
              className="card-dark card-hover p-6 cursor-pointer"
              onClick={() => navigate("/new-analysis")}
              data-testid="quick-upload"
            >
              <div className="flex items-center gap-4">
                <div className="p-3 bg-[#6366F1]/10 rounded-sm">
                  <FileCode className="w-6 h-6 text-[#6366F1]" />
                </div>
                <div>
                  <h3 className="font-medium">Upload ZIP Archive</h3>
                  <p className="text-sm text-[#A1A1AA]">Upload your codebase as a ZIP file</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
