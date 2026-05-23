# CyberSentinel AI

> Autonomous AI Security Threat Monitoring Agent

CyberSentinel AI is an AI-powered cybersecurity monitoring platform that analyzes security logs, detects suspicious activities, prioritizes genuine threats, filters false positives, and explains cyber attacks in simple language using an autonomous AI agent powered by Claude.

Built for the Agentic AI Hackathon 2026.

---

# Features

## AI-Powered Threat Analysis
- Autonomous AI security agent
- Intelligent threat prioritization
- Plain-English attack explanations
- Recommended mitigation steps
- Confidence scoring

---

## Threat Detection Engine
Detects:

- Brute force attacks
- SQL injection attempts
- Cross-site scripting (XSS)
- Port scanning activity
- Unauthorized access attempts

---

## Interactive Dashboard
- Cyberpunk terminal UI
- Real-time threat feed
- Severity-based alerts
- Expandable threat cards
- Live monitoring animations
- Threat statistics panel

---

## Log Management
- Upload raw security logs
- Paste custom logs
- Generate realistic mock logs
- Analyze authentication events
- Scan suspicious payloads

---

# Problem Statement

Security teams receive thousands of alerts daily, making it difficult to prioritize genuine threats.

CyberSentinel AI solves this problem by using an AI agent to analyze logs, detect malicious behavior, prioritize critical threats, and explain attack patterns in simple language.

---

# Tech Stack

## Frontend
- React
- Pure CSS
- Axios

## Backend
- FastAPI
- Python
- Pydantic

## AI Agent
- Anthropic Claude API
- Claude Sonnet 4

---

# System Architecture

```
Security Logs
      ↓
Threat Detection Engine
      ↓
Threat Classification
      ↓
Claude AI Security Agent
      ↓
AI Threat Analysis
      ↓
Frontend Dashboard
```

---

# Threat Detection Rules

| Threat Type | Detection Logic |
|---|---|
| Brute Force | 5+ failed logins from same IP |
| SQL Injection | SQL keywords detected |
| XSS Attack | Script tags or payloads detected |
| Port Scanning | Multiple ports accessed from same IP |
| Unauthorized Access | Repeated 401/403 responses |

---

# API Endpoints

## Logs
```http
POST /logs/ingest
GET  /logs/mock
```

## Threats
```http
POST /threats/scan
GET  /threats/list
GET  /threats/stats
```

## AI Analysis
```http
POST /analyze/threat
```

---

# Project Structure

```
cybersentinel-ai/
├── frontend/
│   └── src/
│       ├── App.jsx
│       ├── App.css
│       ├── api/
│       └── components/
│
├── backend/
│   ├── main.py
│   ├── routers/
│   ├── services/
│   ├── models/
│   └── requirements.txt
│
└── README.md
```

---

# Installation

## Backend Setup

```bash
cd backend

pip install -r requirements.txt

uvicorn main:app --reload
```

---

## Frontend Setup

```bash
cd frontend

npm install

npm start
```

---

# Environment Variables

Create a .env file inside backend folder.

```env
ANTHROPIC_API_KEY=your_api_key_here
```

---

# Example Threat Detection

## Input Log

```
Failed login attempt from 192.168.1.25
```

## AI Analysis

```
Potential brute force attack detected.

Multiple failed authentication attempts from the same source IP indicate credential stuffing or password guessing activity.

Recommended Action:
- Temporarily block IP
- Enable MFA
- Review authentication logs
```

---

# Screenshots

Add screenshots after frontend completion.

Suggested screenshots:
- Dashboard
- Threat feed
- AI explanation modal
- Mock log generator

---

# Future Improvements

- Real-time SIEM integration
- WebSocket live monitoring
- Threat intelligence feeds
- ML anomaly detection
- Multi-agent orchestration
- Kubernetes deployment
- SOC analyst copilot mode

---

# Hackathon Submission

## Demo Includes
- Log ingestion
- Threat detection
- AI-powered explanations
- Real-time dashboard
- Autonomous security analysis

---

# Team

Built during Agentic AI Hackathon 2026.

CyberSentinel AI © 2026
