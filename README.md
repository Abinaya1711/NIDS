🛡️ AI-Powered Network Intrusion Detection System Using Suricata and Llama 3

## 📖 Overview

The AI-Powered Network Intrusion Detection System (AI-NIDS) is a real-time cybersecurity solution designed to monitor network traffic, detect malicious activities, analyze security threats, and provide intelligent threat explanations using Artificial Intelligence.

The system leverages **Suricata** for intrusion detection, **Llama 3** running locally through **Ollama** for AI-powered threat analysis, **SQLite** for secure data storage, and **Flask** for a web-based Security Operations Center (SOC) dashboard.

By combining traditional intrusion detection techniques with Large Language Models (LLMs), the project enables security analysts to understand attacks more effectively and respond to incidents faster.

---

# 🎯 Objectives

* Monitor network traffic in real time.
* Detect suspicious and malicious network activities.
* Generate intrusion alerts using Suricata.
* Store security events in a database.
* Analyze threats using Llama 3.
* Provide AI-generated threat explanations.
* Recommend mitigation strategies.
* Visualize attack trends through an interactive dashboard.

---

# 🚨 Problem Statement

Modern computer networks are continuously exposed to cyber threats such as:

* Port Scanning
* Brute Force Attacks
* Malware Communication
* Denial of Service (DoS/DDoS)
* Unauthorized Access Attempts
* Network Reconnaissance

Traditional Intrusion Detection Systems can identify attacks but often require security analysts to manually interpret alerts and determine appropriate responses.

This project enhances conventional intrusion detection by integrating Artificial Intelligence capable of automatically explaining security alerts, assessing risks, and recommending mitigation actions.

---

# 💡 Proposed Solution

The proposed solution combines a signature-based intrusion detection system with an AI-powered threat analysis engine.

### Workflow

```text
Network Traffic
        │
        ▼
    Suricata
        │
        ▼
     eve.json
        │
        ▼
  Alert Processor
        │
        ▼
     SQLite DB
        │
 ┌──────┴──────┐
 ▼             ▼
Llama 3     Dashboard
 ▼             ▼
AI Analysis  Visualizations
```

---

# 🏗️ System Architecture

```text
┌─────────────────────┐
│ Network Traffic     │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Suricata IDS        │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ eve.json Logs       │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Python Log Monitor  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ SQLite Database     │
└──────┬───────┬──────┘
       │       │
       ▼       ▼
┌─────────┐ ┌──────────┐
│ Llama 3 │ │ Dashboard │
└─────────┘ └──────────┘
```

---

# ⚙️ Features

## 🔍 Real-Time Network Monitoring

* Continuous packet inspection
* Traffic monitoring using Suricata
* Detection of suspicious activities
* Event logging

## 🚨 Intrusion Detection

Detects:

* Port Scanning
* Ping Sweeps
* Brute Force Attempts
* Malware Communication
* Network Reconnaissance
* Suspicious Traffic Patterns

## 🤖 AI Threat Analysis

Using Llama 3:

* Threat Explanation
* Risk Assessment
* Severity Classification
* Mitigation Recommendations
* Incident Report Generation

## 📊 Security Dashboard

* Total Alerts
* Attack Statistics
* Severity Distribution
* Top Attacker IPs
* Alert Timeline
* AI Analysis Viewer

## 📄 Incident Reporting

Automatically generates:

* Security Reports
* Risk Summaries
* Mitigation Recommendations

---

# 🧠 Role of Llama 3

Unlike traditional IDS solutions that only generate alerts, this system uses Llama 3 to explain security incidents.

### Example

#### Suricata Alert

```text
ET SCAN Potential Nmap Scan
```

#### Llama 3 Analysis

```text
Threat Explanation:
A host is attempting to discover open ports and services.

Risk Level:
Medium

Recommendations:
- Monitor source IP
- Restrict exposed services
- Enable firewall monitoring
```

---

# 🛠️ Technology Stack

| Component            | Technology           |
| -------------------- | -------------------- |
| IDS Engine           | Suricata             |
| AI Model             | Llama 3              |
| LLM Runtime          | Ollama               |
| Backend              | Flask                |
| Database             | SQLite               |
| Frontend             | HTML, CSS, Bootstrap |
| Visualization        | Chart.js             |
| Programming Language | Python               |
| Operating System     | Kali Linux           |

---

# 📁 Project Structure

```text
AI_NIDS/
│
├── app.py
├── database.py
├── suricata_monitor.py
├── ai_engine.py
├── report_generator.py
├── requirements.txt
├── README.md
│
├── database/
│   └── alerts.db
│
├── logs/
│   └── eve.json
│
├── static/
│   ├── css/
│   ├── js/
│   └── images/
│
├── templates/
│   ├── dashboard.html
│   ├── analytics.html
│   ├── analysis.html
│   └── reports.html
│
└── docs/
```

---

# 🚀 Installation

## Clone Repository

```bash
git clone https://github.com/yourusername/AI_NIDS.git
cd AI_NIDS
```

## Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# 🔧 Installing Suricata

```bash
sudo apt update
sudo apt install suricata -y
```

Verify Installation:

```bash
suricata --build-info
```

---

# 🤖 Installing Ollama

Install Ollama:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Download Llama 3:

```bash
ollama pull llama3
```

Run Model:

```bash
ollama run llama3
```

---

# ▶️ Running the Project

## Start Suricata

```bash
sudo suricata -i eth0
```

Replace eth0 with your active network interface.

---

## Start Flask Application

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

---

# 🧪 Testing

## Ping Detection

```bash
ping google.com
```

## Port Scan Detection

```bash
nmap localhost
```

Suricata should generate alerts which will appear in the dashboard and AI analysis section.

---

# 📊 Dashboard Features

### Dashboard

* Total Alerts
* Severity Counts
* Recent Alerts

### Analytics

* Severity Distribution
* Attack Type Statistics
* Top Source IPs
* Timeline Analysis

### AI Analysis

* Threat Explanation
* Risk Level
* Recommendations

### Reports

* Generated Incident Reports
* Downloadable Summaries

---

# 🔐 Security Considerations

* Parameterized SQL Queries
* Input Validation
* Error Handling
* Secure Log Processing
* Local LLM Execution
* No External AI APIs Required

---

# 🔮 Future Enhancements

* Machine Learning-Based Anomaly Detection
* SIEM Integration
* Email Notifications
* Threat Intelligence Feeds
* Automated Firewall Response
* Multi-Node Monitoring
* Cloud Deployment
* Explainable AI Security Analytics

---

# 🎓 Academic Significance

This project demonstrates:

* Network Security
* Intrusion Detection Systems
* Cyber Threat Analysis
* Artificial Intelligence Integration
* Web Application Development
* Database Management
* Security Visualization

The project provides a practical implementation of AI-assisted cybersecurity monitoring suitable for academic research, final-year engineering projects, and cybersecurity demonstrations.

---

# 👨‍💻 Developed By

Final Year B.E. Computer Science and Engineering (Cyber Security)

Academic Project – AI-Powered Network Intrusion Detection System

---

# 📜 License

This project is developed for educational and research purposes only.
