🛡️ CodeGuard AI
Live Demo: codevigil.netlify.app (Replace with your actual CodeVigil link)

CodeGuard AI is an autonomous, AI-powered code review and static analysis tool. It goes beyond traditional linters by not only detecting security vulnerabilities and code smells but actively generating ready-to-use surgical patches and architectural refactors using LLMs.

✨ Key Features
🔍 Multi-Layered Static Analysis:

Secret Detection: Scans for hardcoded API keys, tokens, and credentials (AWS, Stripe, etc.) before they hit production.

Dependency Scanning: Cross-references package.json dependencies against the OSV (Open Source Vulnerability) database.

🧠 AI Auto-Patching (Phase 2): Uses the Llama-3.3-70b model to analyze detected security flaws and generate copy-pasteable, context-aware code fixes directly in the dashboard.

🏗️ Architectural Refactoring (Phase 3): Calculates a heuristic "Bug Risk Score" based on cyclomatic complexity, nesting depth, and code smells. High-risk files are automatically rewritten by the AI into clean, modularized architecture.

📊 Executive Dashboard: A rich, dark-mode UI built with React and Recharts, offering visual breakdowns of language distribution, maintainability indices, and vulnerability severity.

📄 Professional Reporting: Instantly generate detailed PDF and JSON security audit reports, complete with AI summaries and refactored code snippets.

🛠️ Tech Stack
Frontend

Framework: React.js, React Router

Styling: Tailwind CSS, custom dark-mode glassmorphism UI

Data Visualization: Recharts

Export: jsPDF, autoTable

Backend

Framework: FastAPI (Python)

Database: MongoDB (Motor AsyncIO)

AI Integration: Groq Cloud API (Llama-3.3-70b-versatile)

Security: OSV Database API, Custom Regex Heuristics

🚀 Getting Started
Prerequisites
Node.js (v18+)

Python (3.10+)

MongoDB instance (local or Atlas)

Groq API Key

Backend Setup
Clone the repository and navigate to the backend directory.

Create a virtual environment:

Bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
Install dependencies:

Bash
pip install -r requirements.txt
Create a .env file in the root directory:

Code snippet
MONGO_URL=your_mongodb_connection_string
DB_NAME=codeguard_db
EMERGENT_LLM_KEY=your_groq_api_key
ENV=dev
Start the FastAPI server:

Bash
uvicorn server:app --reload --port 8080
Frontend Setup
Navigate to the frontend directory.

Install dependencies:

Bash
npm install
Start the development server:

Bash
npm start
📸 Screenshots
(Pro-tip: Add images here once you upload them to your repo!)

![Dashboard](link-to-dashboard-image.png) - Executive dashboard showing metrics and charts.

![Security Fixes](link-to-fixes-image.png) - AI generating a patch for a hardcoded AWS key.

![Refactoring](link-to-refactor-image.png) - Side-by-side view of messy logic vs. AI modularized code.

🧠 How the AI Engine Works
CodeGuard AI uses a tiered analysis approach to save tokens and reduce latency:

Level 0 (RegEx & AST): Python's ast module and custom Regex patterns rapidly scan for obvious flaws, calculating a baseline Risk Score.

Level 1 (OSV API): Dependencies are checked against live vulnerability databases.

Level 2 (LLM Contextualization): Only files that fail Level 0 or Level 1 are packaged with specific system prompts and sent to Llama-3.3. This ensures the AI acts as a "Senior Architect" focused purely on the problem areas, returning structured JSON containing the fix_code and refined_code.
