# 🛡️ CodeGuard AI
**Live Demo:** [codevigil.netlify.app](https://codevigil.netlify.app)

CodeGuard AI is an autonomous, AI-powered code review and static analysis tool. It goes beyond traditional linters by not only detecting security vulnerabilities and code smells but actively generating **ready-to-use surgical patches** and **architectural refactors** using LLMs.

## ✨ Key Features

* **🔍 Multi-Layered Static Analysis:**
    * **Secret Detection:** Scans for hardcoded API keys, tokens, and credentials (AWS, Stripe, etc.) before they hit production.
    * **Dependency Scanning:** Cross-references `package.json` dependencies against the OSV (Open Source Vulnerability) database.
* **🧠 AI Auto-Patching (Phase 2):** Uses the Llama-3.3-70b model to analyze detected security flaws and generate copy-pasteable, context-aware code fixes directly in the dashboard.
* **🏗️ Architectural Refactoring (Phase 3):** Calculates a heuristic "Bug Risk Score" based on cyclomatic complexity, nesting depth, and code smells. High-risk files are automatically rewritten by the AI into clean, modularized architecture.
* **📊 Executive Dashboard:** A rich, dark-mode UI built with React and Recharts, offering visual breakdowns of language distribution, maintainability indices, and vulnerability severity.
* **📄 Professional Reporting:** Instantly generate detailed PDF and JSON security audit reports, complete with AI summaries and refactored code snippets.

---

## 🛠️ Tech Stack

**Frontend**
* **Framework:** React.js, React Router
* **Styling:** Tailwind CSS, custom dark-mode glassmorphism UI
* **Data Visualization:** Recharts
* **Export:** jsPDF, autoTable

**Backend**
* **Framework:** FastAPI (Python)
* **Database:** MongoDB (Motor AsyncIO)
* **AI Integration:** Groq Cloud API (Llama-3.3-70b-versatile)
* **Security:** OSV Database API, Custom Regex Heuristics

---

## 🚀 Getting Started

### Prerequisites
* Node.js (v18+)
* Python (3.10+)
* MongoDB instance (local or Atlas)
* Groq API Key

### Backend Setup
1. Clone the repository and navigate to the backend directory.
2. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
