# 🛡️ AI Based Threat Detection

A beginner-friendly cybersecurity web application built with **Python** and **Flask**.
Detect phishing URLs, analyze password strength, scan text for sensitive data,
generate cryptographic hashes — all in one modern dark-themed website.

---

## 👤 Project Author

| Field | Details |
|---|---|
| **Name** | Kailash Singh Bisht |
| **University** | Faculty of Technology, Veer Madho Singh Bhandari Uttarakhand Technical University |
| **Department** | B.Tech Cyber Security |
| **Roll Number** | 240000173009 |
| **Year** | 3rd Year |
| **Submission** | IBM Project |

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.8 or higher → https://www.python.org/downloads/
- During Python install, **check ✅ "Add Python to PATH"**

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Application
```bash
python app.py
```

### 4. Open in Browser
```
http://127.0.0.1:5000
```

You should see the terminal output:
```
====================================================
  🛡  AI Based Threat Detection
  🌐  Open: http://127.0.0.1:5000
====================================================
```

---

## 🛠️ Features

| Feature | Description |
|---|---|
| 🔍 **Phishing URL Scanner** | Detects suspicious domains, risky TLDs, missing HTTPS, and phishing keywords |
| 🔑 **Password Strength Analyzer** | Scores passwords on entropy, length, and character variety with tips |
| 📄 **Text Threat Scanner** | Finds credit cards, SSNs, API keys, SQL injection, and XSS patterns in text |
| 🔒 **Hash Generator** | Generates MD5, SHA-1, SHA-256, SHA-512 hashes for any string |
| 📡 **Live Threat Log** | Simulated real-time security event feed with start/stop control |
| 📊 **Stats Dashboard** | Tracks total scans, threats found, safe results, and hashes generated |

---

## 📁 Project Structure

```
IBM PROJECT/
├── app.py            ← Entire application (backend + frontend in one file)
├── requirements.txt  ← Python dependencies (only Flask)
├── REPORT.md         ← Detailed project report
└── README.md         ← This file
```

---

## 🧰 Technology Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.8+, Flask |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Hashing | Python built-in `hashlib` |
| Pattern Matching | Python built-in `re` |
| Templating | Flask `render_template_string` |

> **No database. No external APIs. No extra files.** Just Python + Flask.

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves the main web page |
| `POST` | `/scan-url` | Analyzes a URL for threats |
| `POST` | `/check-password` | Evaluates password strength |
| `POST` | `/scan-text` | Scans text for sensitive data |
| `POST` | `/get-hash` | Returns hashes for input text |

### Example API Call
```bash
curl -X POST http://127.0.0.1:5000/scan-url \
     -H "Content-Type: application/json" \
     -d '{"url": "http://secure-login.tk/verify?account=1"}'
```

### Example Response
```json
{
  "score": 75,
  "level": "HIGH",
  "url": "http://secure-login.tk/verify?account=1",
  "findings": [
    "⚠️ Not using HTTPS — data may be unencrypted",
    "⚠️ Suspicious keywords found: login, secure, verify",
    "🚨 High-risk domain extension: .tk"
  ]
}
```

---

## 🎨 UI Preview

- **Dark Theme** — GitHub-style dark background (`#0d1117`)
- **Color-coded Risk Levels** — 🟢 Safe / 🟡 Medium / 🔴 High
- **Animated Score Bars** — visual risk indicator for each scan
- **Responsive Grid** — works on desktop and mobile browsers

---

## ⚠️ Disclaimer

> This project is built **strictly for educational purposes**.  
> It demonstrates cybersecurity concepts in a safe, local environment.  
> Do not scan systems, URLs, or data you do not own or have explicit permission to test.

---

## 📄 License

This project is open for educational use.  
Built as part of an IBM Project submission by **Kailash Singh Bisht**,
B.Tech Cyber Security — Uttarakhand Technical University.

---

*Made with Python 🐍 + Flask 🌶️*
