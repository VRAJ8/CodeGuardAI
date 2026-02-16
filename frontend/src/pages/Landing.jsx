import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Shield, Bug, GitBranch, Zap, ArrowRight, Code2, Lock, BarChart3 } from "lucide-react";
import axios from "axios";
import { API } from "@/App";

export default function Landing() {
  const navigate = useNavigate();
  const [isChecking, setIsChecking] = useState(true);

  useEffect(() => {
    // Check if already authenticated
    const checkAuth = async () => {
      try {
        await axios.get(`${API}/auth/me`);
        navigate("/dashboard");
      } catch {
        setIsChecking(false);
      }
    };
    checkAuth();
  }, [navigate]);

  // REMINDER: DO NOT HARDCODE THE URL, OR ADD ANY FALLBACKS OR REDIRECT URLS, THIS BREAKS THE AUTH
  const handleLogin = () => {
    const redirectUrl = window.location.origin + '/dashboard';
    window.location.href = `https://auth.emergentagent.com/?redirect=${encodeURIComponent(redirectUrl)}`;
  };

  if (isChecking) {
    return (
      <div className="min-h-screen bg-[#050505] flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-[#00E599] border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#050505] overflow-hidden">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 glass border-b border-white/5">
        <div className="max-w-7xl mx-auto px-6 md:px-12 lg:px-24">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-2">
              <Shield className="w-6 h-6 text-[#00E599]" />
              <span className="font-bold text-lg tracking-tight" data-testid="logo">CodeGuard AI</span>
            </div>
            <Button 
              onClick={handleLogin}
              className="btn-primary px-6 py-2"
              data-testid="login-btn"
            >
              Get Started
            </Button>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative pt-32 pb-24 px-6 md:px-12 lg:px-24">
        <div className="absolute inset-0 hero-glow" />
        
        <div className="max-w-7xl mx-auto relative">
          <div className="grid grid-cols-1 md:grid-cols-12 gap-8">
            <div className="md:col-span-7 space-y-8">
              <div className="inline-flex items-center gap-2 px-4 py-2 bg-[#0A0A0A] border border-[#27272A] rounded-sm text-sm animate-fade-in">
                <Zap className="w-4 h-4 text-[#00E599]" />
                <span className="text-[#A1A1AA]">Powered by GPT-5.2</span>
              </div>
              
              <h1 className="text-5xl md:text-7xl tracking-tighter leading-none animate-fade-in stagger-1" data-testid="hero-title">
                Autonomous<br />
                <span className="text-[#00E599]">Code Reviewer</span>
              </h1>
              
              <p className="text-lg text-[#A1A1AA] max-w-xl animate-fade-in stagger-2">
                AI-powered code analysis that predicts bugs, detects security vulnerabilities, 
                and provides actionable recommendations. Stop bugs before they ship.
              </p>
              
              <div className="flex flex-wrap gap-4 animate-fade-in stagger-3">
                <Button 
                  onClick={handleLogin}
                  className="btn-primary px-8 py-3 text-lg flex items-center gap-2"
                  data-testid="hero-cta"
                >
                  Start Free Analysis
                  <ArrowRight className="w-5 h-5" />
                </Button>
                <Button 
                  variant="outline"
                  className="btn-secondary px-8 py-3 text-lg"
                  data-testid="hero-demo"
                >
                  View Demo
                </Button>
              </div>

              {/* Stats */}
              <div className="grid grid-cols-3 gap-8 pt-8 border-t border-[#27272A] animate-fade-in stagger-4">
                <div>
                  <div className="text-3xl font-bold text-[#00E599]">98%</div>
                  <div className="text-sm text-[#A1A1AA]">Bug Detection</div>
                </div>
                <div>
                  <div className="text-3xl font-bold text-[#00E599]">50+</div>
                  <div className="text-sm text-[#A1A1AA]">Security Patterns</div>
                </div>
                <div>
                  <div className="text-3xl font-bold text-[#00E599]">&lt;30s</div>
                  <div className="text-sm text-[#A1A1AA]">Analysis Time</div>
                </div>
              </div>
            </div>

            {/* Hero Image */}
            <div className="md:col-span-5 relative animate-fade-in stagger-5">
              <div className="relative aspect-square rounded-sm overflow-hidden border border-[#27272A]">
                <img 
                  src="https://images.unsplash.com/photo-1607184023678-63ea486d62cd?crop=entropy&cs=srgb&fm=jpg&ixid=M3w3NTY2Nzh8MHwxfHNlYXJjaHwxfHxmdXR1cmlzdGljJTIwZGF0YSUyMGNlbnRlciUyMG5lb24lMjBsaWdodHN8ZW58MHx8fGJsYWNrfDE3NjY3MzM2Mzd8MA&ixlib=rb-4.1.0&q=85"
                  alt="AI Code Analysis"
                  className="w-full h-full object-cover opacity-60"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-[#050505] via-transparent to-transparent" />
                
                {/* Floating Code Preview */}
                <div className="absolute bottom-4 left-4 right-4 glass border border-white/10 rounded-sm p-4">
                  <pre className="text-xs font-mono text-[#00E599] overflow-hidden">
{`// Bug Risk: HIGH
function processData(input) {
  eval(input); // ⚠️ Critical
  return data;
}`}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-24 px-6 md:px-12 lg:px-24 bg-[#0A0A0A]">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-5xl tracking-tight mb-4">
              Everything You Need to<br />
              <span className="text-[#00E599]">Ship Better Code</span>
            </h2>
            <p className="text-[#A1A1AA] max-w-2xl mx-auto">
              Our AI analyzes your codebase using advanced static analysis and machine learning 
              to find issues before they become problems.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
            {/* Feature 1 - Large */}
            <div className="md:col-span-8 card-dark card-hover p-8" data-testid="feature-security">
              <div className="flex items-start gap-6">
                <div className="p-3 bg-[#00E599]/10 rounded-sm">
                  <Lock className="w-8 h-8 text-[#00E599]" />
                </div>
                <div>
                  <h3 className="text-xl mb-2">Security Vulnerability Detection</h3>
                  <p className="text-[#A1A1AA] mb-4">
                    Automatically scan for SQL injection, XSS, hardcoded secrets, and 50+ security patterns. 
                    Get detailed remediation steps for each issue.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <span className="badge-critical px-2 py-1 text-xs rounded-sm">SQL Injection</span>
                    <span className="badge-critical px-2 py-1 text-xs rounded-sm">XSS</span>
                    <span className="badge-high px-2 py-1 text-xs rounded-sm">Secrets</span>
                    <span className="badge-medium px-2 py-1 text-xs rounded-sm">CSRF</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Feature 2 */}
            <div className="md:col-span-4 card-dark card-hover p-8" data-testid="feature-bugs">
              <div className="p-3 bg-[#FF4D4D]/10 rounded-sm w-fit mb-4">
                <Bug className="w-8 h-8 text-[#FF4D4D]" />
              </div>
              <h3 className="text-xl mb-2">Bug Prediction</h3>
              <p className="text-[#A1A1AA] text-sm">
                ML-powered analysis predicts which files are most likely to contain bugs based on complexity metrics.
              </p>
            </div>

            {/* Feature 3 */}
            <div className="md:col-span-4 card-dark card-hover p-8" data-testid="feature-github">
              <div className="p-3 bg-[#6366F1]/10 rounded-sm w-fit mb-4">
                <GitBranch className="w-8 h-8 text-[#6366F1]" />
              </div>
              <h3 className="text-xl mb-2">GitHub Integration</h3>
              <p className="text-[#A1A1AA] text-sm">
                Paste any public GitHub URL and get instant analysis. Private repos supported with upload.
              </p>
            </div>

            {/* Feature 4 - Large */}
            <div className="md:col-span-8 card-dark card-hover p-8" data-testid="feature-metrics">
              <div className="flex items-start gap-6">
                <div className="p-3 bg-[#F59E0B]/10 rounded-sm">
                  <BarChart3 className="w-8 h-8 text-[#F59E0B]" />
                </div>
                <div className="flex-1">
                  <h3 className="text-xl mb-2">Code Quality Metrics</h3>
                  <p className="text-[#A1A1AA] mb-4">
                    Track complexity, maintainability, and code health scores across your entire codebase.
                  </p>
                  <div className="grid grid-cols-3 gap-4">
                    <div className="text-center p-4 bg-[#171717] rounded-sm">
                      <div className="text-2xl font-bold text-[#00E599]">A+</div>
                      <div className="text-xs text-[#A1A1AA]">Code Grade</div>
                    </div>
                    <div className="text-center p-4 bg-[#171717] rounded-sm">
                      <div className="text-2xl font-bold text-[#F59E0B]">85</div>
                      <div className="text-xs text-[#A1A1AA]">Maintainability</div>
                    </div>
                    <div className="text-center p-4 bg-[#171717] rounded-sm">
                      <div className="text-2xl font-bold text-[#6366F1]">12</div>
                      <div className="text-xs text-[#A1A1AA]">Avg Complexity</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Languages Section */}
      <section className="py-24 px-6 md:px-12 lg:px-24">
        <div className="max-w-7xl mx-auto text-center">
          <h2 className="text-2xl tracking-tight mb-8 text-[#A1A1AA]">
            Supports Your Favorite Languages
          </h2>
          <div className="flex flex-wrap justify-center gap-8">
            {["Python", "JavaScript", "TypeScript", "Java", "Go", "Rust", "C++", "Ruby"].map((lang) => (
              <div 
                key={lang}
                className="flex items-center gap-2 px-6 py-3 bg-[#0A0A0A] border border-[#27272A] rounded-sm"
              >
                <Code2 className="w-5 h-5 text-[#00E599]" />
                <span>{lang}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-24 px-6 md:px-12 lg:px-24 bg-[#0A0A0A]">
        <div className="max-w-3xl mx-auto text-center">
          <h2 className="text-3xl md:text-5xl tracking-tight mb-6">
            Ready to Find Bugs<br />
            <span className="text-[#00E599]">Before They Find You?</span>
          </h2>
          <p className="text-[#A1A1AA] mb-8">
            Start analyzing your code in seconds. No credit card required.
          </p>
          <Button 
            onClick={handleLogin}
            className="btn-primary px-12 py-4 text-lg"
            data-testid="cta-btn"
          >
            Start Free Analysis
          </Button>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 px-6 md:px-12 lg:px-24 border-t border-[#27272A]">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-[#00E599]" />
            <span className="font-bold">CodeGuard AI</span>
          </div>
          <div className="text-sm text-[#A1A1AA]">
            © 2024 CodeGuard AI. Built with GPT-5.2
          </div>
        </div>
      </footer>
    </div>
  );
}
