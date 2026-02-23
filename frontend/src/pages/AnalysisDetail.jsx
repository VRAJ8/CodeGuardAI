import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import axios from "axios";
import { API } from "@/App";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { 
  Shield, ArrowLeft, AlertTriangle, Bug, FileCode, 
  ExternalLink, Trash2, Clock, CheckCircle, XCircle,
  ChevronDown, ChevronUp, Code2, Download, FileText, FileJson
} from "lucide-react";
import { toast } from "sonner";
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from "recharts";
import { jsPDF } from "jspdf"; 
import autoTable from "jspdf-autotable";

export default function AnalysisDetail() {
  const navigate = useNavigate();
  const { id } = useParams();
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [expandedRisks, setExpandedRisks] = useState({});
  // Add this near your other useState hooks (around line 24)
const [viewingFix, setViewingFix] = useState(null);
  const languageColors = {
    python: "#3572A5",
    javascript: "#F7DF1E",
    typescript: "#3178C6",
    java: "#B07219",
    go: "#00ADD8",
    rust: "#DEA584",
    unknown: "#6366F1"
  };

  useEffect(() => {
    fetchAnalysis();
  }, [id]);

  const fetchAnalysis = async () => {
    try {
      const response = await axios.get(`${API}/analysis/${id}`);
      setAnalysis(response.data);
    } catch (error) {
      console.error("Error fetching analysis:", error);
      toast.error("Failed to load analysis");
      navigate("/dashboard");
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!window.confirm("Are you sure you want to delete this analysis?")) return;
    
    try {
      await axios.delete(`${API}/analysis/${id}`);
      toast.success("Analysis deleted");
      navigate("/dashboard");
    } catch (error) {
      toast.error("Failed to delete analysis");
    }
  };

  // --- EXPORT LOGIC ---
  const handleExportJSON = () => {
    try {
      const dataStr = JSON.stringify(analysis, null, 2);
      const blob = new Blob([dataStr], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `CodeGuard_Audit_${analysis.name}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      toast.success("JSON report downloaded!");
    } catch (error) {
      toast.error("Failed to generate JSON");
    }
  };

  const handleExportPDF = () => {
    try {
      const doc = new jsPDF();
      
      doc.setFontSize(20);
      doc.setTextColor(0, 229, 153);
      doc.text("CodeGuard AI Security Audit", 14, 20);
      
      doc.setFontSize(10);
      doc.setTextColor(100, 100, 100);
      doc.text(`Project: ${analysis?.name || "N/A"}`, 14, 30);
      doc.text(`Status: COMPLETED`, 14, 35);
      doc.text(`Score: ${analysis?.overall_score || 0}%`, 14, 40);

      doc.setFontSize(14);
      doc.setTextColor(0, 0, 0);
      doc.text("AI Summary", 14, 50);
      doc.setFontSize(10);
      doc.setTextColor(60, 60, 60);
      const summary = analysis?.ai_summary || "AI analysis completed based on code heuristics.";
      const splitSummary = doc.splitTextToSize(summary, 180);
      doc.text(splitSummary, 14, 56);

      const tableStartY = 60 + (splitSummary.length * 5);
      
      const tableData = (analysis?.security_issues || []).map(issue => [
        (issue?.severity || "LOW").toUpperCase(),
        issue?.type || "General Issue",
        issue?.file_path || "Unknown",
        issue?.line_number?.toString() || "-"
      ]);

      autoTable(doc, {
        startY: tableStartY,
        head: [["Severity", "Issue", "File", "Line"]],
        body: tableData,
        theme: 'grid',
        headStyles: { fillColor: [23, 23, 23] },
        styles: { fontSize: 8 },
        didParseCell: (data) => {
          if (data.section === 'body' && data.column.index === 0) {
            if (data.cell.raw === 'CRITICAL') data.cell.styles.textColor = [255, 77, 77];
            if (data.cell.raw === 'HIGH') data.cell.styles.textColor = [245, 158, 11];
          }
        }
      });

      doc.save(`CodeGuard_${analysis?.name || 'Report'}.pdf`);
      toast.success("PDF report generated!");
    } catch (error) {
      console.error("PDF EXPORT ERROR:", error);
      toast.error("Generation failed. See F12 Console.");
    }
  };

  const toggleRisk = (path) => {
    setExpandedRisks(prev => ({ ...prev, [path]: !prev[path] }));
  };

  const getScoreColor = (score) => {
    if (score >= 80) return "#00E599";
    if (score >= 60) return "#F59E0B";
    return "#FF4D4D";
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case "critical": return "#FF4D4D";
      case "high": return "#F59E0B";
      case "medium": return "#6366F1";
      case "low": return "#00E599";
      default: return "#A1A1AA";
    }
  };

  // --- RENDERING LOGIC ---
  if (loading) {
    return (
      <div className="min-h-screen bg-[#050505] flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-[#00E599] border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!analysis || Object.keys(analysis).length === 0) {
    return (
      <div className="min-h-screen bg-[#050505] flex flex-col items-center justify-center text-[#A1A1AA]">
        <div className="w-8 h-8 border-2 border-[#6366F1] border-t-transparent rounded-full animate-spin mb-4" />
        <p className="animate-pulse font-mono text-sm tracking-widest">SYNCHRONIZING ANALYSIS DATA...</p>
      </div>
    );
  }

  const languageData = analysis.metrics?.languages ? 
    Object.entries(analysis.metrics.languages).map(([name, value]) => ({
      name,
      value,
      color: languageColors[name] || languageColors.unknown
    })) : [];

  const severityCounts = {
    critical: analysis.security_issues?.filter(i => i.severity === "critical").length || 0,
    high: analysis.security_issues?.filter(i => i.severity === "high").length || 0,
    medium: analysis.security_issues?.filter(i => i.severity === "medium").length || 0,
    low: analysis.security_issues?.filter(i => i.severity === "low").length || 0,
  };

  return (
    <div className="min-h-screen bg-[#050505]" data-testid="analysis-detail">
      <nav className="fixed top-0 left-0 right-0 z-50 glass border-b border-white/5">
        <div className="max-w-7xl mx-auto px-6 md:px-12">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-4">
              <Button 
                variant="ghost" 
                size="icon"
                onClick={() => navigate("/dashboard")}
                className="btn-ghost"
              >
                <ArrowLeft className="w-5 h-5" />
              </Button>
              <div>
                <div className="font-bold text-lg tracking-tight">{analysis.name}</div>
                <div className="text-xs text-[#A1A1AA]">
                  {new Date(analysis.created_at).toLocaleString()}
                </div>
              </div>
            </div>
            
            <div className="flex items-center gap-2">
              <Button 
                variant="ghost" 
                className="btn-ghost text-xs bg-[#171717] hover:bg-[#27272A]"
                onClick={handleExportPDF}
              >
                <FileText className="w-4 h-4 mr-2 text-[#00E599]" />
                PDF
              </Button>
              <Button 
                variant="ghost" 
                className="btn-ghost text-xs bg-[#171717] hover:bg-[#27272A]"
                onClick={handleExportJSON}
              >
                <FileJson className="w-4 h-4 mr-2 text-[#6366F1]" />
                JSON
              </Button>

              <div className="w-px h-6 bg-[#27272A] mx-2"></div>

              {analysis.source_url && (
                <Button 
                  variant="ghost" 
                  className="btn-ghost"
                  onClick={() => window.open(analysis.source_url, "_blank")}
                >
                  <ExternalLink className="w-4 h-4 mr-2" />
                  Source
                </Button>
              )}
              <Button 
                variant="ghost" 
                className="btn-ghost text-[#FF4D4D] hover:text-[#FF4D4D] hover:bg-[#FF4D4D]/10"
                onClick={handleDelete}
              >
                <Trash2 className="w-4 h-4" />
              </Button>
            </div>
          </div>
        </div>
      </nav>

      <main className="pt-24 pb-12 px-6 md:px-12">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <div className="md:col-span-1 card-dark p-6">
              <div className="text-center">
                <div className="relative w-32 h-32 mx-auto mb-4">
                  <svg className="w-full h-full transform -rotate-90">
                    <circle cx="64" cy="64" r="56" fill="none" stroke="#171717" strokeWidth="8" />
                    <circle
                      cx="64" cy="64" r="56" fill="none"
                      stroke={getScoreColor(analysis.overall_score)}
                      strokeWidth="8"
                      strokeDasharray={`${(analysis.overall_score / 100) * 352} 352`}
                      strokeLinecap="round"
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span 
                      className="text-4xl font-bold"
                      style={{ color: getScoreColor(analysis.overall_score) }}
                    >
                      {analysis.overall_score?.toFixed(0)}
                    </span>
                  </div>
                </div>
                <div className="text-sm text-[#A1A1AA]">Overall Score</div>
              </div>
            </div>

            <div className="md:col-span-3 grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="card-dark p-4">
                <FileCode className="w-5 h-5 text-[#6366F1] mb-2" />
                <div className="text-2xl font-bold">{analysis.metrics?.total_files || 0}</div>
                <div className="text-xs text-[#A1A1AA]">Files Analyzed</div>
              </div>
              <div className="card-dark p-4">
                <Code2 className="w-5 h-5 text-[#00E599] mb-2" />
                <div className="text-2xl font-bold">{analysis.metrics?.total_lines?.toLocaleString() || 0}</div>
                <div className="text-xs text-[#A1A1AA]">Lines of Code</div>
              </div>
              <div className="card-dark p-4">
                <AlertTriangle className="w-5 h-5 text-[#FF4D4D] mb-2" />
                <div className="text-2xl font-bold">{analysis.security_issues?.length || 0}</div>
                <div className="text-xs text-[#A1A1AA]">Security Issues</div>
              </div>
              <div className="card-dark p-4">
                <Bug className="w-5 h-5 text-[#F59E0B] mb-2" />
                <div className="text-2xl font-bold">{analysis.bug_risks?.length || 0}</div>
                <div className="text-xs text-[#A1A1AA]">Bug Risks</div>
              </div>
            </div>
          </div>

          {analysis.ai_summary && (
            <div className="card-dark p-6 mb-8 border-l-4 border-[#00E599]">
              <h3 className="text-lg font-medium mb-2 flex items-center gap-2">
                <Shield className="w-5 h-5 text-[#00E599]" />
                AI Analysis Summary
              </h3>
              <p className="text-[#A1A1AA]">{analysis.ai_summary}</p>
              {analysis.recommendations?.length > 0 && (
                <div className="mt-4">
                  <h4 className="text-sm font-medium mb-2">Recommendations:</h4>
                  <ul className="space-y-2">
                    {analysis.recommendations.map((rec, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-[#A1A1AA]">
                        <CheckCircle className="w-4 h-4 text-[#00E599] mt-0.5 shrink-0" />
                        {rec}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          <Tabs defaultValue="security" className="w-full">
            <TabsList className="bg-[#0A0A0A] border border-[#27272A] rounded-sm p-1 mb-6">
              <TabsTrigger value="security" className="data-[state=active]:bg-[#171717] data-[state=active]:text-white rounded-sm">
                <AlertTriangle className="w-4 h-4 mr-2" />
                Security Issues ({analysis.security_issues?.length || 0})
              </TabsTrigger>
              <TabsTrigger value="bugs" className="data-[state=active]:bg-[#171717] data-[state=active]:text-white rounded-sm">
                <Bug className="w-4 h-4 mr-2" />
                Bug Risks ({analysis.bug_risks?.length || 0})
              </TabsTrigger>
              <TabsTrigger value="metrics" className="data-[state=active]:bg-[#171717] data-[state=active]:text-white rounded-sm">
                <FileCode className="w-4 h-4 mr-2" />
                Metrics
              </TabsTrigger>
            </TabsList>

            <TabsContent value="security">
              <div className="grid grid-cols-4 gap-4 mb-6">
                {Object.entries(severityCounts).map(([severity, count]) => (
                  <div key={severity} className={`card-dark p-4 border-l-4`} style={{ borderLeftColor: getSeverityColor(severity) }}>
                    <div className="text-2xl font-bold">{count}</div>
                    <div className="text-xs text-[#A1A1AA] capitalize">{severity}</div>
                  </div>
                ))}
              </div>
              <div className="space-y-3">
                {analysis.security_issues?.length > 0 ? (
                  analysis.security_issues.map((issue, i) => (
                    <div key={i} className="card-dark p-4">
                      <div className="flex items-start justify-between">
                        <div className="flex items-start gap-3">
                          <div 
                            className="px-2 py-1 rounded-sm text-xs font-medium uppercase"
                            style={{ 
                              backgroundColor: `${getSeverityColor(issue.severity)}20`,
                              color: getSeverityColor(issue.severity),
                              border: `1px solid ${getSeverityColor(issue.severity)}30`
                            }}
                          >
                            {issue.severity}
                          </div>
                          <div>
                            <div className="font-medium">{issue.type}</div>
                            <div className="text-sm text-[#A1A1AA] mt-1">
                              <code className="bg-[#171717] px-2 py-0.5 rounded-sm">
                                {issue.file_path}
                                {issue.line_number && `:${issue.line_number}`}
                              </code>
                            </div>
                            <p className="text-sm text-[#A1A1AA] mt-2">{issue.description}</p>
                            <div className="flex items-start gap-2 mt-3 p-3 bg-[#171717] rounded-sm">
                              <CheckCircle className="w-4 h-4 text-[#00E599] mt-0.5 shrink-0" />
                              <span className="text-sm text-[#A1A1AA]">{issue.recommendation}</span>
                              {/* --- AI FIX SECTION --- */}
                              {/* AI Fix Integration */}
                              {analysis.ai_fixes && analysis.ai_fixes.map((fix, fixIdx) => {
                              // Check if this fix belongs to the current issue 
                              // We check for BOTH 'issue_type' and 'type' to be safe
                              const isMatch = fix.file_path === issue.file_path && 
                                              (fix.issue_type === issue.type || fix.type === issue.type);
                              
                              if (!isMatch) return null;

                              return (
                                <div key={fixIdx} className="mt-4 p-4 bg-[#0A0A0A] border border-[#00E599]/20 rounded-sm animate-in fade-in slide-in-from-top-1">
                                  <div className="flex items-center justify-between mb-2">
                                    <h4 className="text-xs font-bold text-[#00E599] uppercase tracking-widest flex items-center gap-2">
                                      <span className="relative flex h-2 w-2">
                                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00E599] opacity-75"></span>
                                        <span className="relative inline-flex rounded-full h-2 w-2 bg-[#00E599]"></span>
                                      </span>
                                      AI Suggested Patch
                                    </h4>
                                    <Button 
                                      variant="ghost" 
                                      size="sm" 
                                      className="h-6 text-[10px] bg-[#171717] hover:bg-[#27272A] border border-white/5"
                                      onClick={() => {
                                        navigator.clipboard.writeText(fix.fix_code);
                                        toast.success("Patch copied to clipboard");
                                      }}
                                    >
                                      Copy Fix
                                    </Button>
                                  </div>
                                  <p className="text-xs text-[#A1A1AA] mb-3 italic">
                                    // {fix.explanation}
                                  </p>
                                  <pre className="text-[11px] font-mono text-gray-300 bg-[#050505] p-3 rounded border border-white/5 overflow-x-auto leading-relaxed">
                                    <code>{fix.fix_code}</code>
                                  </pre>
                                </div>
                              );
                            })}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="card-dark p-12 text-center">
                    <CheckCircle className="w-12 h-12 text-[#00E599] mx-auto mb-4" />
                    <p className="text-[#A1A1AA]">No security issues detected!</p>
                  </div>
                )}
              </div>
            </TabsContent>

            <TabsContent value="bugs">
              <div className="space-y-3">
                {analysis.bug_risks?.length > 0 ? (
                  analysis.bug_risks
                    .sort((a, b) => b.risk_score - a.risk_score)
                    .map((risk, i) => (
                      <div key={i} className="card-dark overflow-hidden">
                        <div className="p-4 cursor-pointer" onClick={() => toggleRisk(risk.file_path)}>
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                              <Bug className="w-5 h-5" style={{ color: getScoreColor(100 - risk.risk_score) }} />
                              <div>
                                <div className="font-mono text-sm">{risk.file_path}</div>
                                <div className="text-xs text-[#A1A1AA] mt-1">
                                  Complexity: <span className="capitalize">{risk.complexity}</span>
                                </div>
                              </div>
                            </div>
                            <div className="flex items-center gap-4">
                              <div className="text-right">
                                <div className="text-lg font-bold" style={{ color: getScoreColor(100 - risk.risk_score) }}>
                                  {risk.risk_score.toFixed(0)}%
                                </div>
                                <div className="text-xs text-[#A1A1AA]">Risk</div>
                              </div>
                              {expandedRisks[risk.file_path] ? <ChevronUp className="w-5 h-5 text-[#A1A1AA]" /> : <ChevronDown className="w-5 h-5 text-[#A1A1AA]" />}
                            </div>
                          </div>
                          <div className="mt-3">
                            <Progress value={risk.risk_score} className="h-2 bg-[#171717]" />
                          </div>
                        </div>
                        {expandedRisks[risk.file_path] && risk.issues?.length > 0 && (
                          <div className="px-4 pb-4 border-t border-[#27272A]">
                            <div className="pt-4 space-y-2">
                              {risk.issues.map((issue, j) => (
                                <div key={j} className="flex items-start gap-2 text-sm">
                                  <XCircle className="w-4 h-4 text-[#FF4D4D] mt-0.5 shrink-0" />
                                  <span className="text-[#A1A1AA]">{issue}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ))
                ) : (
                  <div className="card-dark p-12 text-center">
                    <CheckCircle className="w-12 h-12 text-[#00E599] mx-auto mb-4" />
                    <p className="text-[#A1A1AA]">No high-risk files detected!</p>
                  </div>
                )}
              </div>
            </TabsContent>

            <TabsContent value="metrics">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="card-dark p-6">
                  <h3 className="text-lg mb-4">Language Distribution</h3>
                  {languageData.length > 0 ? (
                    <>
                      <ResponsiveContainer width="100%" height={200}>
                        <PieChart>
                          <Pie data={languageData} cx="50%" cy="50%" innerRadius={60} outerRadius={80} paddingAngle={2} dataKey="value">
                            {languageData.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={entry.color} />
                            ))}
                          </Pie>
                          <Tooltip contentStyle={{ background: '#0A0A0A', border: '1px solid #27272A', borderRadius: '2px' }} />
                        </PieChart>
                      </ResponsiveContainer>
                      <div className="flex flex-wrap gap-3 mt-4">
                        {languageData.map((lang) => (
                          <div key={lang.name} className="flex items-center gap-2 text-sm">
                            <div className="w-3 h-3 rounded-sm" style={{ backgroundColor: lang.color }} />
                            <span className="capitalize">{lang.name}</span>
                            <span className="text-[#A1A1AA]">({lang.value} lines)</span>
                          </div>
                        ))}
                      </div>
                    </>
                  ) : (
                    <div className="h-[200px] flex items-center justify-center text-[#A1A1AA]">No language data</div>
                  )}
                </div>

                <div className="card-dark p-6">
                  <h3 className="text-lg mb-4">Quality Metrics</h3>
                  <div className="space-y-4">
                    <div>
                      <div className="flex items-center justify-between text-sm mb-2">
                        <span className="text-[#A1A1AA]">Maintainability Index</span>
                        <span className="font-medium" style={{ color: getScoreColor(analysis.metrics?.maintainability_index || 0) }}>
                          {analysis.metrics?.maintainability_index?.toFixed(0) || 0}%
                        </span>
                      </div>
                      <Progress value={analysis.metrics?.maintainability_index || 0} className="h-2 bg-[#171717]" />
                    </div>
                    <div>
                      <div className="flex items-center justify-between text-sm mb-2">
                        <span className="text-[#A1A1AA]">Average Complexity</span>
                        <span className="font-medium">{analysis.metrics?.avg_complexity?.toFixed(1) || 0}</span>
                      </div>
                      <Progress value={Math.min(analysis.metrics?.avg_complexity || 0, 100)} className="h-2 bg-[#171717]" />
                    </div>
                    <div className="pt-4 border-t border-[#27272A]">
                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                          <div className="text-[#A1A1AA]">Total Files</div>
                          <div className="text-xl font-bold">{analysis.metrics?.total_files || 0}</div>
                        </div>
                        <div>
                          <div className="text-[#A1A1AA]">Total Lines</div>
                          <div className="text-xl font-bold">{analysis.metrics?.total_lines?.toLocaleString() || 0}</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </div>
      </main>
    </div>
  );
}