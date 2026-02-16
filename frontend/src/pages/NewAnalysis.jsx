import { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { API } from "@/App";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  Shield, ArrowLeft, GitBranch, Upload, Loader2, 
  CheckCircle, AlertCircle, FileArchive
} from "lucide-react";
import { toast } from "sonner";
import { useDropzone } from "react-dropzone";

export default function NewAnalysis() {
  const navigate = useNavigate();
  const [githubUrl, setGithubUrl] = useState("");
  const [repoName, setRepoName] = useState("");
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const onDrop = useCallback((acceptedFiles) => {
    if (acceptedFiles.length > 0) {
      const uploadedFile = acceptedFiles[0];
      if (uploadedFile.name.endsWith(".zip")) {
        setFile(uploadedFile);
        setError("");
      } else {
        setError("Only ZIP files are supported");
      }
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/zip': ['.zip']
    },
    maxFiles: 1
  });

  const handleGithubAnalysis = async () => {
    if (!githubUrl) {
      setError("Please enter a GitHub URL");
      return;
    }

    // Validate GitHub URL
    const urlPattern = /^https?:\/\/github\.com\/[^/]+\/[^/]+/;
    if (!urlPattern.test(githubUrl)) {
      setError("Please enter a valid GitHub repository URL");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const response = await axios.post(`${API}/analysis/github`, {
        github_url: githubUrl,
        name: repoName || undefined
      });

      if (response.data.status === "completed") {
        toast.success("Analysis completed!");
        navigate(`/analysis/${response.data.analysis_id}`);
      } else if (response.data.status === "failed") {
        setError("Analysis failed. Please check the repository is public and accessible.");
      }
    } catch (err) {
      console.error("Analysis error:", err);
      setError(err.response?.data?.detail || "Failed to analyze repository");
      toast.error("Analysis failed");
    } finally {
      setLoading(false);
    }
  };

  const handleUploadAnalysis = async () => {
    if (!file) {
      setError("Please select a ZIP file");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await axios.post(`${API}/analysis/upload`, formData, {
        headers: {
          "Content-Type": "multipart/form-data"
        }
      });

      if (response.data.status === "completed") {
        toast.success("Analysis completed!");
        navigate(`/analysis/${response.data.analysis_id}`);
      } else if (response.data.status === "failed") {
        setError("Analysis failed. Please check the ZIP file contains code files.");
      }
    } catch (err) {
      console.error("Upload error:", err);
      setError(err.response?.data?.detail || "Failed to analyze upload");
      toast.error("Analysis failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#050505]" data-testid="new-analysis-page">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 glass border-b border-white/5">
        <div className="max-w-7xl mx-auto px-6 md:px-12">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-4">
              <Button 
                variant="ghost" 
                size="icon"
                onClick={() => navigate("/dashboard")}
                className="btn-ghost"
                data-testid="back-btn"
              >
                <ArrowLeft className="w-5 h-5" />
              </Button>
              <div className="flex items-center gap-2">
                <Shield className="w-6 h-6 text-[#00E599]" />
                <span className="font-bold text-lg tracking-tight">New Analysis</span>
              </div>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="pt-24 pb-12 px-6 md:px-12">
        <div className="max-w-2xl mx-auto">
          <div className="text-center mb-8">
            <h1 className="text-3xl md:text-4xl tracking-tight mb-2">
              Analyze Your <span className="text-[#00E599]">Code</span>
            </h1>
            <p className="text-[#A1A1AA]">
              Choose how you want to submit your codebase for analysis
            </p>
          </div>

          <Tabs defaultValue="github" className="w-full">
            <TabsList className="grid w-full grid-cols-2 bg-[#0A0A0A] border border-[#27272A] rounded-sm p-1">
              <TabsTrigger 
                value="github" 
                className="data-[state=active]:bg-[#171717] data-[state=active]:text-white rounded-sm"
                data-testid="tab-github"
              >
                <GitBranch className="w-4 h-4 mr-2" />
                GitHub URL
              </TabsTrigger>
              <TabsTrigger 
                value="upload"
                className="data-[state=active]:bg-[#171717] data-[state=active]:text-white rounded-sm"
                data-testid="tab-upload"
              >
                <Upload className="w-4 h-4 mr-2" />
                Upload ZIP
              </TabsTrigger>
            </TabsList>

            <TabsContent value="github" className="mt-6">
              <div className="card-dark p-8 space-y-6">
                <div>
                  <label className="block text-sm text-[#A1A1AA] mb-2">
                    GitHub Repository URL *
                  </label>
                  <Input
                    type="url"
                    placeholder="https://github.com/owner/repository"
                    value={githubUrl}
                    onChange={(e) => setGithubUrl(e.target.value)}
                    className="input-dark"
                    data-testid="github-url-input"
                  />
                  <p className="text-xs text-[#52525B] mt-2">
                    Enter the URL of any public GitHub repository
                  </p>
                </div>

                <div>
                  <label className="block text-sm text-[#A1A1AA] mb-2">
                    Custom Name (optional)
                  </label>
                  <Input
                    type="text"
                    placeholder="My Project Analysis"
                    value={repoName}
                    onChange={(e) => setRepoName(e.target.value)}
                    className="input-dark"
                    data-testid="repo-name-input"
                  />
                </div>

                {error && (
                  <div className="flex items-center gap-2 p-3 bg-[#FF4D4D]/10 border border-[#FF4D4D]/30 rounded-sm text-[#FF4D4D] text-sm">
                    <AlertCircle className="w-4 h-4 shrink-0" />
                    {error}
                  </div>
                )}

                <Button
                  onClick={handleGithubAnalysis}
                  disabled={loading || !githubUrl}
                  className="btn-primary w-full py-3"
                  data-testid="analyze-github-btn"
                >
                  {loading ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Shield className="w-4 h-4 mr-2" />
                      Start Analysis
                    </>
                  )}
                </Button>
              </div>
            </TabsContent>

            <TabsContent value="upload" className="mt-6">
              <div className="card-dark p-8 space-y-6">
                <div
                  {...getRootProps()}
                  className={`border-2 border-dashed rounded-sm p-12 text-center cursor-pointer transition-colors ${
                    isDragActive 
                      ? 'border-[#00E599] bg-[#00E599]/5' 
                      : file 
                        ? 'border-[#00E599] bg-[#00E599]/5'
                        : 'border-[#27272A] hover:border-[#3F3F46]'
                  }`}
                  data-testid="dropzone"
                >
                  <input {...getInputProps()} data-testid="file-input" />
                  {file ? (
                    <div className="space-y-3">
                      <CheckCircle className="w-12 h-12 text-[#00E599] mx-auto" />
                      <div>
                        <p className="font-medium">{file.name}</p>
                        <p className="text-sm text-[#A1A1AA]">
                          {(file.size / 1024 / 1024).toFixed(2)} MB
                        </p>
                      </div>
                      <Button 
                        variant="ghost"
                        className="btn-ghost text-sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          setFile(null);
                        }}
                      >
                        Remove
                      </Button>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      <FileArchive className="w-12 h-12 text-[#27272A] mx-auto" />
                      <div>
                        <p className="font-medium">
                          {isDragActive ? "Drop the ZIP file here" : "Drag & drop a ZIP file"}
                        </p>
                        <p className="text-sm text-[#A1A1AA]">
                          or click to browse
                        </p>
                      </div>
                    </div>
                  )}
                </div>

                {error && (
                  <div className="flex items-center gap-2 p-3 bg-[#FF4D4D]/10 border border-[#FF4D4D]/30 rounded-sm text-[#FF4D4D] text-sm">
                    <AlertCircle className="w-4 h-4 shrink-0" />
                    {error}
                  </div>
                )}

                <Button
                  onClick={handleUploadAnalysis}
                  disabled={loading || !file}
                  className="btn-primary w-full py-3"
                  data-testid="analyze-upload-btn"
                >
                  {loading ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Shield className="w-4 h-4 mr-2" />
                      Start Analysis
                    </>
                  )}
                </Button>
              </div>
            </TabsContent>
          </Tabs>

          {/* Info Section */}
          <div className="mt-8 card-dark p-6">
            <h3 className="font-medium mb-4">What We Analyze</h3>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div className="flex items-start gap-2">
                <CheckCircle className="w-4 h-4 text-[#00E599] mt-0.5 shrink-0" />
                <span className="text-[#A1A1AA]">Security vulnerabilities</span>
              </div>
              <div className="flex items-start gap-2">
                <CheckCircle className="w-4 h-4 text-[#00E599] mt-0.5 shrink-0" />
                <span className="text-[#A1A1AA]">Bug-prone code patterns</span>
              </div>
              <div className="flex items-start gap-2">
                <CheckCircle className="w-4 h-4 text-[#00E599] mt-0.5 shrink-0" />
                <span className="text-[#A1A1AA]">Code complexity metrics</span>
              </div>
              <div className="flex items-start gap-2">
                <CheckCircle className="w-4 h-4 text-[#00E599] mt-0.5 shrink-0" />
                <span className="text-[#A1A1AA]">Best practice violations</span>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
