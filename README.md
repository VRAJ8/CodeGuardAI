CodeGuardAI: Autonomous Code Reviewer & Bug Predictor
CodeGuardAI is an intelligent, full-stack application designed to automate the code review process. By leveraging AI, it predicts potential bug risks, analyzes code quality, and suggests optimizations in real-time, helping developers maintain high-standard codebases effortlessly.

🚀 Features
AI-Powered Code Analysis: Scans code files to identify logic errors, security vulnerabilities, and "code smells."

Bug Risk Prediction: Assigns risk scores to different modules based on complexity and patterns.

Asynchronous Processing: Built with FastAPI and Motor for high-performance, non-blocking database operations.

Modern UI/UX: A responsive dashboard built with React and Tailwind CSS for a seamless developer experience.

MERN-Python Hybrid Architecture: Combines the speed of Node-like reactivity with the power of Python’s AI libraries.

🛠️ Tech Stack
Frontend: React.js, Tailwind CSS, Lucide React (Icons), Craco.

Backend: Python 3.12, FastAPI, Uvicorn (ASGI Server).

Database: MongoDB Atlas (via Motor async driver).

Environment: Python Virtual Environments (venv), Dotenv for secret management.

💻 Local Setup & Installation
Follow these steps to get a local development environment running.

1. Prerequisites
Python 3.12+

Node.js (v18 or higher)

MongoDB Atlas Account

2. Backend Setup
Bash
# Navigate to backend
cd backend

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\activate  # Windows
source venv/bin/activate # Mac/Linux

# Install dependencies
pip install -r requirements.txt
# If requirements.txt is missing, install core packages:
pip install fastapi uvicorn motor python-dotenv aiofiles
3. Frontend Setup
Bash
# Navigate to frontend
cd frontend

# Install dependencies (Note: uses --legacy-peer-deps for compatibility)
npm install --legacy-peer-deps

# Start the development server
npm start
4. Configuration (.env)
Create a .env file in the backend folder:

Code snippet
MONGO_URL=your_mongodb_connection_string
PORT=8000
Create a .env file in the frontend folder:

Code snippet
REACT_APP_BACKEND_URL=http://127.0.0.1:8000
📁 Project Structure
Plaintext
CodeGuardAI/
├── backend/            # FastAPI Server & AI Logic
│   ├── venv/           # Python Virtual Env (Ignored by Git)
│   ├── server.py       # Main Entry Point
│   └── .env            # Private Backend Config
├── frontend/           # React Application
│   ├── src/            # Components & Logic
│   ├── public/         # Static Assets
│   └── .env            # Frontend API Environment
└── README.md           # Project Documentation
🛡️ Security Note
This project utilizes .gitignore to ensure sensitive credentials (like MongoDB strings) are never pushed to public repositories. Ensure your .env files are kept local.

Developed by Vraj Patel
B.Tech CSE Student 
