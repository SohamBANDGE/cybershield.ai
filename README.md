# CyberShield AI
# 🛡️ CyberShield AI — Explainable Cybersecurity Assistant

**An AI-inspired cybersecurity assistant that detects suspicious URLs and potential scam messages using explainable, rule-based risk analysis.**

CyberShield AI helps users recognize common phishing indicators, suspicious domains, fraudulent prize claims, and social-engineering tactics. It assigns a risk score and explains the signals behind its assessment.

## 🚀 Features

- **🔗 Suspicious URL Analysis** — Identifies suspicious domain patterns, look-alike brand names, risky top-level domains, raw IP addresses, URL shorteners, and insecure HTTP links.
- **💬 Scam Message Detection** — Flags urgency, account-threat language, credential requests, suspicious payment requests, and unsolicited prize claims.
- **📊 Risk Scoring** — Produces a score from 0 to 100 with a risk classification.
- **🔍 Explainable Results** — Displays the reasons that contributed to a detection.
- **🛡️ Privacy-Conscious Design** — URL analysis inspects the supplied string without visiting the destination.
- **🌐 Web Interface** — Provides a browser-based interface for testing suspicious URLs and messages.

## 🧰 Tech Stack

| Technology | Purpose |
|---|---|
| Python | Detection logic and backend |
| FastAPI | Backend API |
| Regular Expressions | Pattern-based threat detection |
| HTML, CSS, JavaScript | Frontend interface |
| Uvicorn | Local development server |
| Git & GitHub | Version control and project hosting |

## 🏗️ Project Structure

```text
cybershield/
├── backend/
│   ├── main.py
│   ├── analyzer.py
│   └── .gitignore
├── frontend/
│   └── index.html
├── .gitignore
├── Dockerfile
├── requirements.txt
└── README.md
```

## ⚙️ Installation and Setup

### Prerequisites

- Python 3.10 or a compatible version supported by your dependencies
- Git
- Visual Studio Code (recommended)

### 1. Clone
