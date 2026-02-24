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
import { 
  PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip as RechartsTooltip, 
  BarChart, Bar, XAxis, YAxis, CartesianGrid 
} from 'recharts';

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
      if (!user) {
        const userRes = await axios.get(`${API}/auth/me`);
        setUser(userRes.data);
      }
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

  // --- DATA PROCESSING FOR CHARTS ---
  const languageData = stats?.languages ? 
    Object.entries(stats.languages).map(([name, value]) => ({
      name: name.toUpperCase(),
      value,
      color: languageColors[name] || languageColors.unknown
    })) : [];

  // Calculate severity distribution from recent analyses
  const severityCounts = stats?.recent_analyses?.reduce((acc, analysis) => {
    analysis.security_issues?.forEach(issue => {
      acc[issue.severity] = (acc[issue.severity] || 0) + 1;
    });
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0 }) || {};

  const severityData = [
    { name: 'Critical', count: severityCounts.critical, fill: '#FF4D4D' },
    { name: 'High', count: severityCounts.high, fill: '#F97316' },
    { name: 'Medium', count: severityCounts.medium, fill: '#F59E0B' },
    { name: 'Low', count: severityCounts.low, fill: '#00E599' },
  ];

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
                <Button variant="ghost" className="btn-ghost" onClick={() => navigate("/dashboard")}>
                  Dashboard
                </Button>
                <Button variant="ghost" className="btn-ghost" onClick={() => navigate("/history")}>
                  <History className="w-4 h-4 mr-2" />
                  History
                </Button>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              <Button onClick={() => navigate("/new-analysis")} className="btn-primary px-4 py-2 flex items-center gap-2">
                <Plus className="w-4 h-4" />
                New Analysis
              </Button>
              <div className="flex items-center gap-3">
                {user?.picture ? (
                  <img src={user.picture} alt={user.name} className="w-8 h-8 rounded-full border border-[#27272A]" />
                ) : (
                  <div className="w-8 h-8 rounded-full bg-[#171717] flex items-center justify-center">
                    <User className="w-4 h-4 text-[#A1A1AA]" />
                  </div>
                )}
                <Button variant="ghost" size="icon" onClick={handleLogout} className="btn-ghost">
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
            {/* Find this h1 tag around line 150-160 */}
<h1 className="text-3xl md:text-4xl tracking-tight mb-2">
  Welcome back, <span className="text-[#00E599]">{user?.name?.split(' ')[0] || 'Developer'}</span>
  <span className="text-[10px] ml-2 opacity-30 text-white">v2.1-charts</span> 
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
            <div className="card-dark p-6">
              <div className="flex items-center justify-between mb-4">
                <FileCode className="w-5 h-5 text-[#6366F1]" />
                <span className="text-xs text-[#A1A1AA] uppercase tracking-wide">Total Analyses</span>
              </div>
              <div className="text-3xl font-bold">{stats?.total_analyses || 0}</div>
            </div>
            
            <div className="card-dark p-6">
              <div className="flex items-center justify-between mb-4">
                <TrendingUp className="w-5 h-5 text-[#00E599]" />
                <span className="text-xs text-[#A1A1AA] uppercase tracking-wide">Avg Score</span>
              </div>
              <div className="text-3xl font-bold" style={{ color: getScoreColor(stats?.avg_score || 0) }}>
                {stats?.avg_score || 0}%
              </div>
            </div>
            
            <div className="card-dark p-6">
              <div className="flex items-center justify-between mb-4">
                <AlertTriangle className="w-5 h-5 text-[#FF4D4D]" />
                <span className="text-xs text-[#A1A1AA] uppercase tracking-wide">Total Issues</span>
              </div>
              <div className="text-3xl font-bold text-[#FF4D4D]">{stats?.total_issues || 0}</div>
            </div>
            
            <div className="card-dark p-6">
              <div className="flex items-center justify-between mb-4">
                <Bug className="w-5 h-5 text-[#F59E0B]" />
                <span className="text-xs text-[#A1A1AA] uppercase tracking-wide">Bug Risks</span>
              </div>
              <div className="text-3xl font-bold text-[#F59E0B]">
                {stats?.recent_analyses?.reduce((acc, a) => acc + (a.bug_risks?.length || 0), 0) || 0}
              </div>
            </div>
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            {/* Language Chart */}
            <div className="card-dark p-6 min-h-[400px]">
              <h3 className="text-lg font-medium mb-6 flex items-center gap-2">
                <FileCode className="w-4 h-4 text-[#6366F1]" />
                Language Distribution
              </h3>
              {languageData.length > 0 ? (
                <div className="h-[250px] w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={languageData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={80}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {languageData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <RechartsTooltip 
                          contentStyle={{ 
                            backgroundColor: '#171717', 
                            border: '1px solid #27272A', 
                            borderRadius: '6px',
                            color: '#E4E4E7', // This makes the title text light gray
                            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.5)'
                          }}
                          itemStyle={{ color: '#00E599', fontWeight: 'bold' }} // This highlights the count number
                          formatter={(value, name) => [value, name]} // Ensures consistent text
                        />
                      <Legend verticalAlign="bottom" />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <div className="h-[250px] flex items-center justify-center text-[#A1A1AA]">No language data</div>
              )}
            </div>

            {/* Severity Chart */}
            <div className="card-dark p-6 min-h-[400px]">
              <h3 className="text-lg font-medium mb-6 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-[#FF4D4D]" />
                Vulnerability Severity
              </h3>
              <div className="h-[250px] w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={severityData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#27272A" vertical={false} />
                    <XAxis dataKey="name" stroke="#A1A1AA" fontSize={12} tickLine={false} axisLine={false} />
                    <YAxis stroke="#A1A1AA" fontSize={12} tickLine={false} axisLine={false} />
                    <RechartsTooltip 
                        cursor={{ fill: '#171717' }} // Subtle background highlight on hover
                        contentStyle={{ 
                          backgroundColor: '#171717', 
                          border: '1px solid #27272A', 
                          borderRadius: '6px',
                          color: '#E4E4E7', // Light text for readability
                          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.5)'
                        }}
                        itemStyle={{ color: '#00E599', fontWeight: 'bold' }}
                      />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* Recent Analyses List */}
          <div className="card-dark p-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-medium">Recent Activity</h3>
              <Button variant="ghost" className="btn-ghost text-sm" onClick={() => navigate("/history")}>
                View All <ChevronRight className="w-4 h-4 ml-1" />
              </Button>
            </div>
            
            {stats?.recent_analyses?.length > 0 ? (
              <div className="grid grid-cols-1 gap-3">
                {stats.recent_analyses.map((analysis) => (
                  <div 
                    key={analysis.analysis_id}
                    className="flex items-center justify-between p-4 bg-[#0A0A0A] border border-[#1A1A1A] rounded-md cursor-pointer hover:border-[#27272A] hover:bg-[#111] transition-all"
                    onClick={() => navigate(`/analysis/${analysis.analysis_id}`)}
                  >
                    <div className="flex items-center gap-4">
                      <div className="w-10 h-10 rounded bg-[#171717] flex items-center justify-center">
                        <FileCode className="w-5 h-5 text-[#6366F1]" />
                      </div>
                      <div>
                        <div className="font-medium text-white">{analysis.name}</div>
                        <div className="text-xs text-[#A1A1AA]">
                          {new Date(analysis.created_at).toLocaleDateString()} • {analysis.metrics?.total_files || 0} files
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-6">
                      <div className="text-right hidden sm:block">
                        <div className="text-xs text-[#A1A1AA] mb-1 uppercase">Score</div>
                        <div className="font-bold" style={{ color: getScoreColor(analysis.overall_score) }}>
                          {analysis.overall_score?.toFixed(0)}%
                        </div>
                      </div>
                      <ChevronRight className="w-5 h-5 text-[#3F3F46]" />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-12 bg-[#0A0A0A] rounded-md border border-dashed border-[#27272A]">
                <p className="text-[#A1A1AA] mb-4">No security scans found in your history.</p>
                <Button onClick={() => navigate("/new-analysis")} className="btn-primary">
                  Start First Scan
                </Button>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}