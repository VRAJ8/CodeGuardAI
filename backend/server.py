from fastapi import FastAPI, APIRouter, HTTPException, UploadFile, File, Response, Request, Depends
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import aiofiles
import tempfile
import zipfile
import io
import httpx # Using standard HTTP client for stability
import ast
import re
import json
from secret_scanner import SecretScanner
from dependency_scanner import DependencyScanner

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app
app = FastAPI(title="CodeGuard AI - Code Reviewer & Bug Predictor")
secret_detector = SecretScanner()
dependency_detector = DependencyScanner()

# Create routers
api_router = APIRouter(prefix="/api")
auth_router = APIRouter(prefix="/api/auth")
analysis_router = APIRouter(prefix="/api/analysis")

# ==================== MODELS ====================

class User(BaseModel):
    user_id: str
    email: str
    name: str
    picture: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserSession(BaseModel):
    session_id: str
    user_id: str
    session_token: str
    expires_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AnalysisRequest(BaseModel):
    github_url: Optional[str] = None
    name: Optional[str] = None

class CodeFile(BaseModel):
    path: str
    content: str
    language: str
    lines: int

class SecurityIssue(BaseModel):
    severity: str  # critical, high, medium, low
    type: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    recommendation: str

class BugRisk(BaseModel):
    file_path: str
    risk_score: float  # 0-100
    complexity: str  # low, medium, high
    issues: List[str]

class CodeMetrics(BaseModel):
    total_files: int
    total_lines: int
    languages: Dict[str, int]
    avg_complexity: float
    maintainability_index: float

class AnalysisResult(BaseModel):
    analysis_id: str
    user_id: str
    name: str
    source_type: str  # github or zip
    source_url: Optional[str] = None
    status: str  # pending, processing, completed, failed
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    metrics: Optional[CodeMetrics] = None
    security_issues: List[SecurityIssue] = []
    bug_risks: List[BugRisk] = []
    overall_score: Optional[float] = None  # 0-100
    ai_summary: Optional[str] = None
    recommendations: List[str] = []

# ==================== AUTH HELPERS ====================

async def get_current_user(request: Request) -> User:
    """Get current user from session token in cookies or Authorization header"""
    session_token = request.cookies.get("session_token")
    
    if not session_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            session_token = auth_header[7:]
    
    if not session_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    session_doc = await db.user_sessions.find_one(
        {"session_token": session_token},
        {"_id": 0}
    )
    
    if not session_doc:
        raise HTTPException(status_code=401, detail="Invalid session")
    
    expires_at = session_doc["expires_at"]
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Session expired")
    
    user_doc = await db.users.find_one(
        {"user_id": session_doc["user_id"]},
        {"_id": 0}
    )
    
    if not user_doc:
        raise HTTPException(status_code=401, detail="User not found")
    
    return User(**user_doc)

# ==================== AUTH ENDPOINTS ====================

@auth_router.post("/session")
async def create_session(request: Request, response: Response):
    """Exchange session_id for session_token"""
    body = await request.json()
    session_id = body.get("session_id")
    
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id required")
    
    # Fetch user data from Emergent Auth
    async with httpx.AsyncClient() as client_http:
        resp = await client_http.get(
            "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data",
            headers={"X-Session-ID": session_id}
        )
        
        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid session_id")
        
        user_data = resp.json()
    
    email = user_data.get("email")
    name = user_data.get("name")
    picture = user_data.get("picture")
    session_token = user_data.get("session_token")
    
    # Check if user exists
    existing_user = await db.users.find_one({"email": email}, {"_id": 0})
    
    if existing_user:
        user_id = existing_user["user_id"]
        # Update user info
        await db.users.update_one(
            {"user_id": user_id},
            {"$set": {"name": name, "picture": picture}}
        )
    else:
        # Create new user
        user_id = f"user_{uuid.uuid4().hex[:12]}"
        user_doc = {
            "user_id": user_id,
            "email": email,
            "name": name,
            "picture": picture,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.users.insert_one(user_doc)
    
    # Create session
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    session_doc = {
        "user_id": user_id,
        "session_token": session_token,
        "expires_at": expires_at.isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.user_sessions.insert_one(session_doc)
    
    # Set cookie
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        secure=True,
        samesite="none",
        path="/",
        max_age=7 * 24 * 60 * 60
    )
    
    user_doc = await db.users.find_one({"user_id": user_id}, {"_id": 0})
    return user_doc

@auth_router.get("/me")
async def get_me(user: User = Depends(get_current_user)):
    """Get current authenticated user"""
    return {
        "user_id": user.user_id,
        "email": user.email,
        "name": user.name,
        "picture": user.picture
    }

@auth_router.post("/logout")
async def logout(request: Request, response: Response):
    """Logout user"""
    session_token = request.cookies.get("session_token")
    if session_token:
        await db.user_sessions.delete_one({"session_token": session_token})
    
    response.delete_cookie(key="session_token", path="/")
    return {"message": "Logged out"}

# ==================== CODE ANALYSIS HELPERS ====================

def detect_language(filename: str) -> str:
    """Detect programming language from file extension"""
    ext_map = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".go": "go",
        ".rs": "rust",
        ".cpp": "cpp",
        ".c": "c",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
        ".swift": "swift",
        ".kt": "kotlin",
        ".json": "json"
    }
    ext = Path(filename).suffix.lower()
    return ext_map.get(ext, "unknown")

def count_lines(content: str) -> int:
    """Count lines of code"""
    return len(content.split("\n"))

def analyze_python_complexity(content: str) -> dict:
    """Analyze Python code complexity"""
    try:
        tree = ast.parse(content)
        functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
        classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        
        # Count nested structures
        max_depth = 0
        for node in ast.walk(tree):
            depth = 0
            parent = node
            while hasattr(parent, '_parent'):
                parent = parent._parent
                depth += 1
            max_depth = max(max_depth, depth)
        
        return {
            "functions": len(functions),
            "classes": len(classes),
            "max_nesting": max_depth,
            "complexity": "high" if len(functions) > 20 or max_depth > 5 else "medium" if len(functions) > 10 else "low"
        }
    except:
        return {"functions": 0, "classes": 0, "max_nesting": 0, "complexity": "unknown"}

def detect_security_issues(content: str, file_path: str, language: str) -> List[SecurityIssue]:
    """Detect security issues in code"""
    issues = []
    lines = content.split("\n")
    
    # Common patterns to detect
    patterns = [
        (r"eval\s*\(", "Dangerous eval() usage", "critical", "Avoid using eval() as it can execute arbitrary code"),
        (r"exec\s*\(", "Dangerous exec() usage", "critical", "Avoid using exec() as it can execute arbitrary code"),
        (r"password\s*=\s*['\"][^'\"]+['\"]", "Hardcoded password", "critical", "Use environment variables for sensitive data"),
        (r"api[_-]?key\s*=\s*['\"][^'\"]+['\"]", "Hardcoded API key", "critical", "Use environment variables for API keys"),
        (r"secret\s*=\s*['\"][^'\"]+['\"]", "Hardcoded secret", "high", "Use environment variables for secrets"),
        (r"TODO|FIXME|HACK|XXX", "Code annotation found", "low", "Address TODO/FIXME comments"),
        (r"console\.log\(", "Console logging in production", "low", "Remove debug logging in production"),
        (r"debugger", "Debugger statement", "medium", "Remove debugger statements"),
        (r"pickle\.load", "Unsafe pickle usage", "high", "Pickle can execute arbitrary code, use JSON instead"),
        (r"subprocess\.call\(.*shell\s*=\s*True", "Shell injection risk", "critical", "Avoid shell=True in subprocess"),
        (r"os\.system\(", "OS command execution", "high", "Use subprocess with proper input validation"),
        (r"sql\s*=.*\+.*\+", "Potential SQL injection", "critical", "Use parameterized queries"),
        (r"innerHTML\s*=", "XSS vulnerability", "high", "Use textContent or sanitize HTML"),
    ]
    
    for i, line in enumerate(lines, 1):
        for pattern, issue_type, severity, recommendation in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                issues.append(SecurityIssue(
                    severity=severity,
                    type=issue_type,
                    description=f"Found: {line.strip()[:100]}",
                    file_path=file_path,
                    line_number=i,
                    recommendation=recommendation
                ))
    
    return issues

def calculate_bug_risk(content: str, file_path: str, language: str) -> BugRisk:
    """Calculate bug risk for a file"""
    issues = []
    risk_score = 0
    
    lines = content.split("\n")
    line_count = len(lines)
    
    # File size risk
    if line_count > 500:
        risk_score += 20
        issues.append("File is too large (>500 lines)")
    elif line_count > 200:
        risk_score += 10
        issues.append("File is moderately large (>200 lines)")
    
    # Check for complexity indicators
    if language == "python":
        complexity = analyze_python_complexity(content)
        if complexity["complexity"] == "high":
            risk_score += 30
            issues.append("High cyclomatic complexity")
        elif complexity["complexity"] == "medium":
            risk_score += 15
        
        if complexity["functions"] > 15:
            risk_score += 10
            issues.append("Too many functions in one file")
    
    # Check for code smells
    long_lines = sum(1 for line in lines if len(line) > 120)
    if long_lines > 10:
        risk_score += 10
        issues.append(f"{long_lines} lines exceed 120 characters")
    
    # Check for TODO/FIXME
    todos = sum(1 for line in lines if "TODO" in line or "FIXME" in line)
    if todos > 5:
        risk_score += 15
        issues.append(f"{todos} TODO/FIXME comments found")
    
    # Check for empty catch blocks (generic pattern)
    empty_catches = len(re.findall(r"except\s*:\s*pass|catch\s*\([^)]*\)\s*\{\s*\}", content))
    if empty_catches > 0:
        risk_score += 20
        issues.append(f"{empty_catches} empty exception handlers")
    
    complexity_level = "high" if risk_score > 50 else "medium" if risk_score > 25 else "low"
    
    return BugRisk(
        file_path=file_path,
        risk_score=min(risk_score, 100),
        complexity=complexity_level,
        issues=issues
    )

# FIX: DIRECT API CALL TO GROQ (Bypassing libraries to avoid version conflicts)
async def analyze_with_ai(files: List[CodeFile], existing_issues: List[SecurityIssue], existing_risks: List[BugRisk]) -> dict:
    """Analyze code and generate specific patches for detected vulnerabilities"""
    
    api_key = os.environ.get("EMERGENT_LLM_KEY")
    if not api_key:
        return {"summary": "AI key not configured", "recommendations": []}

    # Focus context on the files that actually have security issues
    relevant_files = [i.file_path for i in existing_issues]
    code_context = "\n".join([f"File: {f.path}\nContent:\n{f.content}" for f in files if f.path in relevant_files][:2])
    
    # Format the issues so the AI knows exactly what to fix
    issues_to_fix = "\n".join([f"- Issue: {i.type} in {i.file_path} (Severity: {i.severity})" for i in existing_issues])
    
    prompt = f"""
    You are a Senior Security Engineer. Analyze the provided code and the issues detected.
    
    CODE CONTENT:
    {code_context}
    
    DETECTED ISSUES:
    {issues_to_fix}
    
    For each issue, you MUST provide a corrected code snippet.
    
    Provide a JSON response with:
    1. 'summary': A brief 2-sentence quality report.
    2. 'recommendations': A list of 5 improvements.
    3. 'fixes': A list of objects, each containing:
       - 'issue_type': The name of the issue.
       - 'file_path': The file it belongs to.
       - 'explanation': Why this fix is better.
       - 'fix_code': The exact corrected line or block of code.
    """

    model_name = "llama-3.3-70b-versatile" 

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": model_name,
                    "messages": [
                        {"role": "system", "content": "You are a specialized security bot. Output valid JSON only."},
                        {"role": "user", "content": prompt}
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.2 # Lower temperature for more stable code generation
                },
                timeout=45.0 # Increased timeout for larger code generation tasks
            )
            
            if response.status_code == 200:
                return json.loads(response.json()['choices'][0]['message']['content'])
            return {"summary": "AI Fix Generation failed.", "recommendations": [], "fixes": []}

    except Exception as e:
        logging.error(f"AI Auto-Fix Error: {e}")
        return {"summary": "AI analysis error.", "recommendations": [], "fixes": []}

# ==================== ANALYSIS ENDPOINTS ====================

@analysis_router.post("/github")
async def analyze_github(request: AnalysisRequest, user: User = Depends(get_current_user)):
    """Start analysis of a GitHub repository"""
    if not request.github_url:
        raise HTTPException(status_code=400, detail="github_url is required")
    
    # Parse GitHub URL
    url_match = re.match(r"https?://github\.com/([^/]+)/([^/]+)(?:/.*)?", request.github_url)
    if not url_match:
        raise HTTPException(status_code=400, detail="Invalid GitHub URL format")
    
    owner, repo = url_match.groups()
    repo = repo.replace(".git", "")
    
    analysis_id = f"analysis_{uuid.uuid4().hex[:12]}"
    
    analysis_doc = {
        "analysis_id": analysis_id,
        "user_id": user.user_id,
        "name": request.name or f"{owner}/{repo}",
        "source_type": "github",
        "source_url": request.github_url,
        "status": "processing",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "metrics": None,
        "security_issues": [],
        "bug_risks": [],
        "overall_score": None,
        "ai_summary": None,
        "recommendations": []
    }
    
    await db.analyses.insert_one(analysis_doc)
    
    try:
        async with httpx.AsyncClient() as client_http:
            # Get repository contents
            api_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/main?recursive=1"
            resp = await client_http.get(api_url, headers={"Accept": "application/vnd.github.v3+json"})
            
            if resp.status_code == 404:
                # Try master branch
                api_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/master?recursive=1"
                resp = await client_http.get(api_url, headers={"Accept": "application/vnd.github.v3+json"})
            
            if resp.status_code != 200:
                await db.analyses.update_one(
                    {"analysis_id": analysis_id},
                    {"$set": {"status": "failed", "ai_summary": "Could not access repository. Make sure it's public."}}
                )
                return {"analysis_id": analysis_id, "status": "failed"}
            
            tree_data = resp.json()
            files = []
            all_security_issues = []
            all_bug_risks = []
            language_stats = {}
            total_lines = 0
            
            # Filter and process code files
            code_extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rs", ".cpp", ".c", ".rb", ".php", ".json"}
            code_files = [f for f in tree_data.get("tree", []) if f["type"] == "blob" and Path(f["path"]).suffix in code_extensions][:50]
            
            for file_info in code_files:
                file_path = file_info["path"]
                language = detect_language(file_path)
                
                # Fetch file content
                raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/{file_path}"
                file_resp = await client_http.get(raw_url)
                
                if file_resp.status_code == 404:
                    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/master/{file_path}"
                    file_resp = await client_http.get(raw_url)
                
                if file_resp.status_code == 200:
                    content = file_resp.text
                    
                    # ==========================================
                    # NEW LEVEL-0 SECRET SCANNER INTEGRATION
                    # ==========================================
                    secret_findings = secret_detector.scan_content(content, file_path)
                    for secret in secret_findings:
                        all_security_issues.append(SecurityIssue(
                            severity=secret["severity"],
                            type=secret["type"],
                            description=secret["description"],
                            file_path=secret["file_path"],
                            line_number=None,
                            recommendation=secret["recommendation"]
                        ))

                if file_path.endswith("package.json"):
                    # We use await because the OSV API call is asynchronous
                    dep_findings = await dependency_detector.scan_package_json(content, file_path)
                    for dep in dep_findings:
                        all_security_issues.append(SecurityIssue(
                            severity=dep["severity"],
                            type=dep["type"],
                            description=dep["description"],
                            file_path=dep["file_path"],
                            line_number=None,
                            recommendation=dep["recommendation"]
                        ))
                    # ==========================================

                    lines = count_lines(content)
                    total_lines += lines
                    
                    language_stats[language] = language_stats.get(language, 0) + lines
                    
                    files.append(CodeFile(
                        path=file_path,
                        content=content,
                        language=language,
                        lines=lines
                    ))
                    
                    # Analyze security
                    security_issues = detect_security_issues(content, file_path, language)
                    all_security_issues.extend(security_issues)
                    
                    # Calculate bug risk
                    bug_risk = calculate_bug_risk(content, file_path, language)
                    if bug_risk.risk_score > 0:
                        all_bug_risks.append(bug_risk)
            
            # Get AI analysis
            ai_result = await analyze_with_ai(files, all_security_issues, all_bug_risks)
            
            # Calculate overall score
            security_penalty = len([i for i in all_security_issues if i.severity in ["critical", "high"]]) * 10
            risk_penalty = sum(r.risk_score for r in all_bug_risks) / max(len(all_bug_risks), 1) / 2
            overall_score = max(0, 100 - security_penalty - risk_penalty)
            
            # Calculate metrics
            avg_complexity = sum(r.risk_score for r in all_bug_risks) / max(len(all_bug_risks), 1)
            maintainability = 100 - avg_complexity
            
            metrics = {
                "total_files": len(files),
                "total_lines": total_lines,
                "languages": language_stats,
                "avg_complexity": round(avg_complexity, 2),
                "maintainability_index": round(maintainability, 2)
            }
            
            # Update analysis
            await db.analyses.update_one(
                {"analysis_id": analysis_id},
                {"$set": {
                    "status": "completed",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "metrics": metrics,
                    "security_issues": [i.model_dump() for i in all_security_issues],
                    "bug_risks": [r.model_dump() for r in all_bug_risks],
                    "overall_score": round(overall_score, 2),
                    "ai_summary": ai_result.get("summary", ""),
                    "recommendations": ai_result.get("recommendations", []),
                    "ai_fixes": ai_result.get("fixes", [])
                }}
            )
            
            return {"analysis_id": analysis_id, "status": "completed"}
            
    except Exception as e:
        logging.error(f"Analysis error: {e}")
        await db.analyses.update_one(
            {"analysis_id": analysis_id},
            {"$set": {"status": "failed", "ai_summary": str(e)}}
        )
        return {"analysis_id": analysis_id, "status": "failed"}

@analysis_router.post("/upload")
async def analyze_upload(file: UploadFile = File(...), user: User = Depends(get_current_user)):
    """Analyze uploaded ZIP file"""
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP files are supported")
    
    analysis_id = f"analysis_{uuid.uuid4().hex[:12]}"
    
    analysis_doc = {
        "analysis_id": analysis_id,
        "user_id": user.user_id,
        "name": file.filename.replace(".zip", ""),
        "source_type": "zip",
        "source_url": None,
        "status": "processing",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "metrics": None,
        "security_issues": [],
        "bug_risks": [],
        "overall_score": None,
        "ai_summary": None,
        "recommendations": []
    }
    
    await db.analyses.insert_one(analysis_doc)
    
    try:
        content = await file.read()
        zip_buffer = io.BytesIO(content)
        
        files = []
        all_security_issues = []
        all_bug_risks = []
        language_stats = {}
        total_lines = 0
        
        code_extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rs", ".cpp", ".c", ".rb", ".php", ".json"}
        
        with zipfile.ZipFile(zip_buffer, 'r') as zip_file:
            for zip_info in zip_file.infolist()[:100]:
                if zip_info.is_dir() or zip_info.filename.startswith('__MACOSX/'):
                    continue
                
                file_path = zip_info.filename
                if Path(file_path).suffix.lower() not in code_extensions:
                    continue
                
                try:
                    with zip_file.open(zip_info) as f:
                        file_content = f.read().decode('utf-8', errors='ignore')
                except Exception as e:
                    print(f"DEBUG: Failed to read {file_path}: {e}")
                    continue

                # ==========================================
                # NEW LEVEL-0 SECRET SCANNER INTEGRATION
                # ==========================================
                secret_findings = secret_detector.scan_content(file_content, file_path)
                for secret in secret_findings:
                    all_security_issues.append(SecurityIssue(
                        severity=secret["severity"],
                        type=secret["type"],
                        description=secret["description"],
                        file_path=secret["file_path"],
                        line_number=None,
                        recommendation=secret["recommendation"]
                    ))

                # Dependency Scanner Integration
                if file_path.endswith("package.json"):
                    print(f"DEBUG: Found package.json! Path: {file_path}") # This must show in logs
                    dep_findings = await dependency_detector.scan_package_json(file_content, file_path)
                    for dep in dep_findings:
                        all_security_issues.append(SecurityIssue(
                            severity=dep["severity"],
                            type=dep["type"],
                            description=dep["description"],
                            file_path=dep["file_path"],
                            line_number=None,
                            recommendation=dep["recommendation"]
                        ))    
                # ==========================================
                
                lines = count_lines(file_content)
                total_lines += lines
                
                language = detect_language(file_path)
                language_stats[language] = language_stats.get(language, 0) + lines
                
                files.append(CodeFile(
                    path=file_path,
                    content=file_content,
                    language=language,
                    lines=lines
                ))
                
                security_issues = detect_security_issues(file_content, file_path, language)
                all_security_issues.extend(security_issues)
                
                bug_risk = calculate_bug_risk(file_content, file_path, language)
                if bug_risk.risk_score > 0:
                    all_bug_risks.append(bug_risk)
        
        if not files:
            await db.analyses.update_one(
                {"analysis_id": analysis_id},
                {"$set": {"status": "failed", "ai_summary": "No valid code files found in ZIP archive."}}
            )
            return {"analysis_id": analysis_id, "status": "failed"}

        ai_result = await analyze_with_ai(files, all_security_issues, all_bug_risks)
        
        security_penalty = len([i for i in all_security_issues if i.severity in ["critical", "high"]]) * 10
        risk_penalty = sum(r.risk_score for r in all_bug_risks) / max(len(all_bug_risks), 1) / 2
        overall_score = max(0, 100 - security_penalty - risk_penalty)
        
        avg_complexity = sum(r.risk_score for r in all_bug_risks) / max(len(all_bug_risks), 1)
        maintainability = 100 - avg_complexity
        
        metrics = {
            "total_files": len(files),
            "total_lines": total_lines,
            "languages": language_stats,
            "avg_complexity": round(avg_complexity, 2),
            "maintainability_index": round(maintainability, 2)
        }
        
        await db.analyses.update_one(
            {"analysis_id": analysis_id},
            {"$set": {
                "status": "completed",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "metrics": metrics,
                "security_issues": [i.model_dump() for i in all_security_issues],
                "bug_risks": [r.model_dump() for r in all_bug_risks],
                "overall_score": round(overall_score, 2),
                "ai_summary": ai_result.get("summary", ""),
                "recommendations": ai_result.get("recommendations", []),
                "ai_fixes": ai_result.get("fixes", [])
            }}
        )
        
        return {"analysis_id": analysis_id, "status": "completed"}
        
    except Exception as e:
        logging.error(f"Upload analysis error: {e}")
        await db.analyses.update_one(
            {"analysis_id": analysis_id},
            {"$set": {"status": "failed", "ai_summary": str(e)}}
        )
        return {"analysis_id": analysis_id, "status": "failed"}
        
@analysis_router.get("/list")
async def list_analyses(user: User = Depends(get_current_user)):
    """List all analyses for the current user"""
    analyses = await db.analyses.find(
        {"user_id": user.user_id},
        {"_id": 0}
    ).sort("created_at", -1).to_list(100)
    
    return analyses

@analysis_router.get("/{analysis_id}")
async def get_analysis(analysis_id: str, user: User = Depends(get_current_user)):
    """Get a specific analysis"""
    analysis = await db.analyses.find_one(
        {"analysis_id": analysis_id, "user_id": user.user_id},
        {"_id": 0}
    )
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    return analysis

@analysis_router.delete("/{analysis_id}")
async def delete_analysis(analysis_id: str, user: User = Depends(get_current_user)):
    """Delete an analysis"""
    result = await db.analyses.delete_one(
        {"analysis_id": analysis_id, "user_id": user.user_id}
    )
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    return {"message": "Analysis deleted"}

@analysis_router.get("/stats/dashboard")
async def get_dashboard_stats(user: User = Depends(get_current_user)):
    """Get dashboard statistics"""
    analyses = await db.analyses.find(
        {"user_id": user.user_id, "status": "completed"},
        {"_id": 0}
    ).to_list(100)
    
    if not analyses:
        return {
            "total_analyses": 0,
            "avg_score": 0,
            "total_issues": 0,
            "languages": {},
            "recent_analyses": []
        }
    
    total_score = sum(a.get("overall_score", 0) for a in analyses)
    total_issues = sum(len(a.get("security_issues", [])) for a in analyses)
    
    language_stats = {}
    for a in analyses:
        metrics = a.get("metrics", {})
        for lang, lines in metrics.get("languages", {}).items():
            language_stats[lang] = language_stats.get(lang, 0) + lines
    
    return {
        "total_analyses": len(analyses),
        "avg_score": round(total_score / len(analyses), 2),
        "total_issues": total_issues,
        "languages": language_stats,
        "recent_analyses": analyses[:5]
    }

# ==================== ROOT ENDPOINTS ====================

@api_router.get("/")
async def root():
    return {"message": "CodeGuard AI - Autonomous Code Reviewer API"}

@api_router.get("/health")
async def health():
    return {"status": "healthy"}

# Include routers
app.include_router(api_router)
app.include_router(auth_router)
app.include_router(analysis_router)

# CORS middleware
# FIX: Updated to prioritize local development and your specific Netlify domain
origins = [
    "http://localhost:3000",
    "https://codevigil.netlify.app" # Add your actual Netlify URL here
]

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=origins if os.environ.get('ENV') == 'prod' else ['*'],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

