# Project Report — AI Based Threat Detection

---

## 👤 Student Details

| Field | Details |
|---|---|
| **Name** | Kailash Singh Bisht |
| **Roll Number** | 240000173009 |
| **Department** | B.Tech Cyber Security |
| **University** | Faculty of Technology, Veer Madho Singh Bhandari Uttarakhand Technical University |
| **Year** | 3rd Year |
| **Submission** | IBM Project |

---

## 1. Project Overview

**Project Title:** AI Based Threat Detection
**Author:** Kailash Singh Bisht (Roll No: 240000173009)
**Type:** Cybersecurity Web Application
**Technology Stack:** Python, Flask, HTML, CSS, JavaScript
**Architecture:** Single-file application (`app.py`)
**Purpose:** An educational, beginner-friendly cybersecurity tool that provides real-time threat analysis across multiple domains including URL phishing detection, password strength evaluation, sensitive data scanning, and cryptographic hashing.

---

## 2. Objectives

- Build a fully functional cybersecurity website using Python and Flask.
- Implement multiple threat detection modules in a single, readable file.
- Provide an intuitive dark-themed UI accessible in any modern browser.
- Demonstrate core cybersecurity concepts (hashing, risk scoring, pattern detection) in a beginner-friendly manner.

---

## 3. Features & Modules

### 3.1 Phishing URL Scanner
- Checks whether the URL uses HTTPS.
- Scans for suspicious keywords (e.g., `login`, `verify`, `paypal`, `amazon`).
- Detects high-risk TLDs (`.tk`, `.xyz`, `.ml`, `.ga`, etc.).
- Identifies IP-address-based URLs, `@` symbols, and double-slash patterns.
- Flags excessively long URLs (>100 characters).
- Outputs a **risk score (0–100)** and a **risk level** (LOW / MEDIUM / HIGH).

### 3.2 Password Strength Analyzer
- Evaluates password length (8, 12, 16+ character thresholds).
- Checks for uppercase, lowercase, numeric, and special characters.
- Flags passwords matching a list of common/weak passwords.
- Calculates **Shannon entropy** (bits) based on character set size.
- Returns a **strength rating** (WEAK / MODERATE / STRONG) with actionable feedback.

### 3.3 Text Threat Scanner
- Detects sensitive data patterns using regular expressions:
  - Credit card numbers
  - US Social Security Numbers (SSN)
  - Email addresses
  - Phone numbers
  - IP addresses
  - API keys / long tokens
  - Passwords embedded in plain text
  - SQL injection patterns (`SELECT`, `DROP`, `UNION`, etc.)
  - Cross-Site Scripting (XSS) patterns (`<script>`, `javascript:`)
- Returns a **threat level** (SAFE / LOW / MEDIUM / HIGH) and findings list.

### 3.4 Cryptographic Hash Generator
- Generates four standard hashes for any input string:
  - **MD5** (128-bit)
  - **SHA-1** (160-bit)
  - **SHA-256** (256-bit)
  - **SHA-512** (512-bit)
- Uses Python's built-in `hashlib` library — no external dependencies.

### 3.5 Live Threat Simulation Log
- Simulates a real-time security event feed using JavaScript `setInterval`.
- Displays timestamped log entries categorized as INFO, WARN, and ALERT.
- Events include: port scans, brute-force attempts, SQL injection, malware signatures, and geo-blocking.
- Start/stop toggle button controls the feed.

### 3.6 Statistics Dashboard
- Tracks and displays live counters:
  - Total Scans performed
  - Threats Found
  - Safe Results
  - Hashes Generated

---

## 4. Technology Stack

| Component  | Technology                        |
|------------|-----------------------------------|
| Backend    | Python 3.8+, Flask                |
| Frontend   | HTML5, CSS3, Vanilla JavaScript   |
| Templating | Flask `render_template_string`    |
| Hashing    | Python `hashlib` (built-in)       |
| Pattern    | Python `re` (built-in)            |
| Transport  | Flask JSON API (`/scan-url`, etc.)|

---

## 5. System Architecture

```
Browser (Client)
     │
     │  HTTP GET /          → Renders HTML page
     │  HTTP POST /scan-url  → Returns JSON risk analysis
     │  HTTP POST /check-password → Returns JSON strength report
     │  HTTP POST /scan-text → Returns JSON threat findings
     │  HTTP POST /get-hash  → Returns JSON hash values
     ▼
Flask Application (app.py)
     │
     ├── analyze_url(url)       → URL risk scoring
     ├── analyze_password(pw)   → Password entropy & checks
     ├── analyze_text(text)     → Regex-based threat detection
     └── get_hash(text)         → hashlib MD5/SHA hashes
```

---

## 6. Risk Scoring Methodology

Each module uses an **additive risk scoring** system:

| Condition                    | Points Added |
|------------------------------|-------------|
| No HTTPS                     | +20         |
| Suspicious keyword found     | +10 each (max 30) |
| High-risk TLD                | +25         |
| IP-based URL                 | +20         |
| URL length > 100 chars       | +10         |
| Credit card pattern found    | +30         |
| SSN pattern found            | +40         |
| SQL injection pattern found  | +35         |
| XSS pattern found            | +35         |

All scores are capped at **100**. Thresholds:
- **0–39** → LOW / SAFE
- **40–69** → MEDIUM
- **70–100** → HIGH

---

## 7. Project Structure

```
IBM PROJECT/
├── app.py            ← Entire application (backend + frontend)
├── requirements.txt  ← Python dependencies
├── REPORT.md         ← This project report
└── README.md         ← Setup and usage guide
```

---

## 8. Limitations & Future Improvements

| Limitation | Suggested Improvement |
|---|---|
| URL analysis is heuristic-only | Integrate VirusTotal or Google Safe Browsing API |
| No persistent storage | Add SQLite database to log scan history |
| Password check is local | Integrate Have I Been Pwned (HIBP) API |
| Live log is simulated | Connect to a real SIEM or syslog feed |
| No user authentication | Add login system with Flask-Login |
| Single-file architecture | Modularize into blueprints for larger teams |

---

## 9. Security Notice

> This application is built **strictly for educational purposes**.  
> It demonstrates cybersecurity concepts in a controlled, local environment.  
> Do not use it to scan systems, URLs, or data you do not own or have permission to test.

---

## 10. Conclusion

The **AI Based Threat Detection** project successfully demonstrates multiple cybersecurity analysis techniques in a single, beginner-friendly Python application. It covers URL phishing detection, password security, sensitive data exposure, and cryptographic hashing — all wrapped in a modern dark-themed web interface. The project serves as a strong foundation for further development into a production-grade security tool.

---

*Report generated for: IBM Project Submission*
*Author: Kailash Singh Bisht | Roll No: 240000173009*
*B.Tech Cyber Security — Uttarakhand Technical University*
*Stack: Python + Flask | Theme: Dark | File: app.py*
