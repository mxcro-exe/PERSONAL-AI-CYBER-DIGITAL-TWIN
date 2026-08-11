<div align="center">

<img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/FastAPI-0.104+-009688?style=for-the-badge&logo=fastapi&logoColor=white"/>
<img src="https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-red?style=for-the-badge"/>
<img src="https://img.shields.io/badge/D3.js-Attack_Graph-F9A03C?style=for-the-badge&logo=d3.js"/>
<img src="https://img.shields.io/badge/ONNX-ML_Model-005CED?style=for-the-badge&logo=onnx"/>

# 🛡️ Personal AI Cyber Digital Twin

### *A Real-Time Local Endpoint Security Intelligence Platform*

> **An AI-powered cybersecurity command centre that creates a living digital replica of your laptop's security posture — monitoring every process, network socket, clipboard event, USB device, and file in real-time.**

</div>

---

## 🚀 Features

| Module | Description | MITRE ATT&CK |
|--------|-------------|--------------|
| ⚡ **Real-Time Process Sentinel** | Captures every new process launched. Flags suspicious executables, encoded PowerShell, and hidden windows. SHA-256 hashes each binary. | T1059, T1055 |
| 🌐 **Network Socket Tracker** | Monitors all active TCP/UDP connections, detects anomalous external IPs and suspicious ports. | T1071, T1043 |
| 📋 **Clipboard Privacy Guard** | Intercepts clipboard copies in real-time. Auto-redacts passwords, card numbers, and API keys before storage. | T1115 |
| 🔌 **USB Device Intelligence** | Tracks all hardware plug/unplug events. Identifies mass-storage and HID attack vectors. | T1091 |
| 🪤 **FIM Canary Ransomware Defense** | Deploys hidden canary files and auto-terminates any process that modifies them — blocks ransomware instantly. | T1486 |
| 📈 **CPU & I/O Anomaly Meter** | Monitors disk write spikes (>15 MB/2s) and CPU spikes (>85%) to detect background encryption loops. | T1496, T1486 |
| 🧠 **Behavioral Twin Baselines** | Exponential Moving Average models build statistical baselines for each monitored metric. Deviation = anomaly. | TA0007 |
| 🔍 **Phishing URL Detector** | Hybrid ONNX ML + heuristic classifier for phishing URL detection with confidence scores. | T1566 |
| 🔬 **Malware YARA Scanner** | Static file scanner with custom YARA rules covering ransomware, reverse shells, and credential stealers. | T1204 |
| 🛡️ **Firewall Quarantine Playbook** | One-click outbound firewall block rule registration via Windows Defender Firewall (`netsh`). | TA0011 |
| 🤖 **Multi-Agent SOC AI Suite** | Threat Classifier + Forensic Agent + XAI Explainer working together for incident response. | TA0040 |
| 🖨️ **NIST Forensic Report** | Print-ready investigation report following NIST SP 800-86 evidence protocol with chain of custody logs. | — |
| 📊 **D3.js Attack Graph** | Interactive force-directed graph visualising process lineages and network socket attack paths. | — |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   Frontend (HTML/CSS/JS)                        │
│  Dashboard • Threat Studio • Behavioral Twin • Forensics Tab    │
│  D3.js Attack Graph • Real-Time WebSocket Telemetry Stream      │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTP + WebSocket
┌──────────────────────────▼──────────────────────────────────────┐
│               FastAPI Backend (Python)                          │
│   /api/v1/dashboard  /api/v1/malware  /api/v1/remediation      │
│   /api/v1/incidents  /api/v1/graph   /api/v1/forensics         │
└──────────┬──────────────────────────────────────────────────────┘
           │
┌──────────▼──────────────────────────────────────────────────────┐
│               Real-Time Collectors (Background Loop)            │
│  ProcessCollector • NetworkCollector • ClipboardCollector       │
│  DeviceCollector  • FileIntegrityMonitor                        │
└──────────┬──────────────────────────────────────────────────────┘
           │
┌──────────▼──────────────────────────────────────────────────────┐
│               SQLite Database (WAL Mode)                        │
│  telemetry_events • behavioral_baseline • incidents             │
└─────────────────────────────────────────────────────────────────┘
```

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.11+
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/personal-ai-cyber-digital-twin.git
cd personal-ai-cyber-digital-twin
```

### 2. Install Python Dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 3. Start the Server
```bash
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### 4. Open the Dashboard
Open your browser and navigate to: **http://127.0.0.1:8000**

---

## 📂 Project Structure

```
personal-ai-cyber-digital-twin/
├── backend/
│   ├── app/
│   │   ├── api/               # FastAPI route handlers
│   │   ├── collectors/        # Real-time OS telemetry collectors
│   │   │   ├── process_collector.py
│   │   │   ├── network_collector.py
│   │   │   ├── clipboard_collector.py
│   │   │   ├── device_collector.py
│   │   │   └── fim_monitor.py  # Canary file watcher
│   │   ├── core/              # Privacy guard, settings
│   │   ├── digital_twin/      # Behavioral baseline engine
│   │   ├── remediation/       # Playbook engine, firewall rules
│   │   ├── threat_intel/      # ONNX phishing detector
│   │   └── main.py            # Application entry point
│   ├── data/                  # Runtime database & test payloads
│   ├── models/                # ONNX ML model weights
│   └── requirements.txt
├── frontend/
│   ├── css/                   # Styles & design system
│   ├── js/                    # Dashboard logic & WebSocket client
│   ├── index.html             # Main dashboard
│   └── report.html            # NIST Forensic Report template
├── .gitignore
└── README.md
```

---

## 🔬 Live Testing Guide

| Test | Steps | Expected Result |
|------|-------|----------------|
| **Canary Defense** | Edit `backend/data/canaries/passwords_vault.txt` | Dashboard flashes `INTRUSION BLOCKED`, process killed |
| **Clipboard Guard** | Copy `password = "admin123"` | Stream shows `T1115` warning, data redacted |
| **Process Monitor** | Open Notepad or Calculator | New process event appears instantly in stream |
| **Malware Scanner** | Scan `backend/data/test_payloads/ransomware_trigger.txt` | `MALICIOUS_PAYLOAD, Risk: 95/100` |
| **IP Quarantine** | Click "Quarantine IP" on any network event | Windows Firewall rule registered |
| **Forensic PDF** | Click "Export Forensics" on any incident | Print-ready NIST report opens |

---

## 🛠️ Tech Stack

- **Backend**: FastAPI, Uvicorn, SQLite, psutil, pyperclip, ONNX Runtime
- **Frontend**: Vanilla HTML5, CSS3, JavaScript ES6+, D3.js v7
- **ML**: ONNX binary classifier for phishing detection
- **Security**: YARA rules, MITRE ATT&CK framework mapping
- **Privacy**: SHA-256 anonymisation, PII regex scrubbing

---

## 📜 License

MIT License — Free for educational and research use.

---

<div align="center">

**Built as a Final Year Engineering Project demonstrating AI-driven endpoint detection and response.**

</div>
