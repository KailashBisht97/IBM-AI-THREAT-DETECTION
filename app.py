"""
AI Based Threat Detection - Cybersecurity Website
A beginner-friendly Flask web app with a modern dark theme.
Run: python app.py  then open http://127.0.0.1:5000

─────────────────────────────────────────────────────
  Author      : Kailash Singh Bisht
  Roll No     : 240000173009
  Department  : B.Tech Cyber Security
  University  : Faculty of Technology, Veer Madho Singh
                Bhandari Uttarakhand Technical University
  Year        : 3rd Year
  Submission  : IBM Project
─────────────────────────────────────────────────────
"""

from flask import Flask, render_template_string, request, jsonify
import re
import hashlib
import urllib.parse
import math
import datetime
import random

app = Flask(__name__)

# ─────────────────────────────────────────────
#  ANALYSIS HELPERS
# ─────────────────────────────────────────────

def analyze_url(url):
    """Check a URL for common phishing / malicious indicators."""
    risk_score = 0
    findings = []

    suspicious_keywords = ["login", "verify", "account", "update", "secure",
                           "banking", "paypal", "amazon", "apple", "microsoft",
                           "password", "confirm", "wallet", "free", "prize"]
    suspicious_tlds     = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top",
                           ".click", ".link", ".info"]
    phishing_patterns   = [r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",   # IP address
                            r"[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.",       # triple-hyphen
                            r"@",                                        # @ in URL
                            r"//.*//"]                                   # double slash

    url_lower = url.lower()

    # HTTPS check
    if not url_lower.startswith("https://"):
        risk_score += 20
        findings.append("⚠️ Not using HTTPS — data may be unencrypted")
    else:
        findings.append("✅ Uses HTTPS")

    # Suspicious keywords
    found_kw = [kw for kw in suspicious_keywords if kw in url_lower]
    if found_kw:
        risk_score += min(len(found_kw) * 10, 30)
        findings.append(f"⚠️ Suspicious keywords found: {', '.join(found_kw)}")

    # Suspicious TLDs
    found_tld = [t for t in suspicious_tlds if url_lower.endswith(t) or (t + "/") in url_lower]
    if found_tld:
        risk_score += 25
        findings.append(f"🚨 High-risk domain extension: {', '.join(found_tld)}")

    # Regex patterns
    for pat in phishing_patterns:
        if re.search(pat, url):
            risk_score += 20
            if r"\d" in pat:
                findings.append("🚨 IP address used instead of domain name")
            elif "@" in pat:
                findings.append("🚨 '@' symbol detected in URL")
            else:
                findings.append("⚠️ Unusual URL structure detected")

    # URL length
    if len(url) > 100:
        risk_score += 10
        findings.append(f"⚠️ Very long URL ({len(url)} chars) — common in phishing")

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        level = "HIGH"
    elif risk_score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"score": risk_score, "level": level, "findings": findings, "url": url}


def analyze_password(password):
    """Score a password and give improvement tips."""
    score = 0
    feedback = []

    checks = [
        (len(password) >= 8,  10, "✅ At least 8 characters",          "❌ Too short — use at least 8 characters"),
        (len(password) >= 12, 15, "✅ Good length (12+ chars)",         None),
        (len(password) >= 16, 10, "✅ Excellent length (16+ chars)",    None),
        (bool(re.search(r"[A-Z]", password)), 15, "✅ Contains uppercase letters", "❌ Add uppercase letters (A-Z)"),
        (bool(re.search(r"[a-z]", password)), 15, "✅ Contains lowercase letters", "❌ Add lowercase letters (a-z)"),
        (bool(re.search(r"\d",    password)), 15, "✅ Contains numbers",            "❌ Add numbers (0-9)"),
        (bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)), 20,
         "✅ Contains special characters", "❌ Add special characters (!@#$%^&*)"),
    ]

    for passed, pts, good_msg, bad_msg in checks:
        if passed:
            score += pts
            feedback.append(good_msg)
        elif bad_msg:
            feedback.append(bad_msg)

    # Common passwords
    common = ["password", "123456", "qwerty", "admin", "letmein",
              "welcome", "monkey", "dragon", "master", "sunshine"]
    if password.lower() in common:
        score = min(score, 10)
        feedback.append("🚨 This is a commonly used password!")

    score = min(score, 100)

    if score >= 80:
        strength = "STRONG"
    elif score >= 50:
        strength = "MODERATE"
    else:
        strength = "WEAK"

    # Entropy
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"\d",    password): charset += 10
    if re.search(r"[^a-zA-Z0-9]",    password): charset += 32
    entropy = round(len(password) * math.log2(charset), 1) if charset else 0

    return {"score": score, "strength": strength, "feedback": feedback,
            "length": len(password), "entropy": entropy}


def analyze_text(text):
    """Detect threats / sensitive data patterns in free text."""
    findings = []
    risk_score = 0

    patterns = {
        "Credit Card Number":   (r"\b(?:\d{4}[-\s]?){3}\d{4}\b",     30, "🚨"),
        "Email Address":        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", 10, "ℹ️"),
        "IP Address":           (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", 15, "⚠️"),
        "Phone Number":         (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",   10, "ℹ️"),
        "SSN (US)":             (r"\b\d{3}-\d{2}-\d{4}\b",           40, "🚨"),
        "API Key / Token":      (r"\b[A-Za-z0-9]{32,}\b",            20, "⚠️"),
        "Password in Text":     (r"password\s*[:=]\s*\S+",           25, "🚨"),
        "SQL Injection":        (r"(\bSELECT\b|\bDROP\b|\bINSERT\b|\bUNION\b).*\b(FROM|TABLE|INTO)\b", 35, "🚨"),
        "XSS Pattern":          (r"<script.*?>|javascript:",         35, "🚨"),
    }

    for name, (pattern, points, icon) in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            risk_score += points
            count = len(matches) if isinstance(matches[0], str) else len(matches)
            findings.append(f"{icon} {name} detected ({count} occurrence{'s' if count > 1 else ''})")

    risk_score = min(risk_score, 100)

    if risk_score >= 60:
        level = "HIGH"
    elif risk_score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW" if findings else "SAFE"

    return {"score": risk_score, "level": level, "findings": findings,
            "char_count": len(text), "word_count": len(text.split())}


def get_hash(text):
    """Return common hashes for a given string."""
    return {
        "MD5":    hashlib.md5(text.encode()).hexdigest(),
        "SHA1":   hashlib.sha1(text.encode()).hexdigest(),
        "SHA256": hashlib.sha256(text.encode()).hexdigest(),
        "SHA512": hashlib.sha512(text.encode()).hexdigest(),
    }


# ─────────────────────────────────────────────
#  HTML TEMPLATE  (single-file, inline CSS/JS)
# ─────────────────────────────────────────────

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>AI Based Threat Detection</title>
<style>
  :root {
    --bg:      #0d1117;
    --surface: #161b22;
    --card:    #1c2128;
    --border:  #30363d;
    --accent:  #58a6ff;
    --green:   #3fb950;
    --yellow:  #d29922;
    --red:     #f85149;
    --text:    #c9d1d9;
    --muted:   #8b949e;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif;
         font-size: 14px; line-height: 1.6; }

  /* NAV */
  nav { background: var(--surface); border-bottom: 1px solid var(--border);
        padding: 12px 24px; display: flex; align-items: center; justify-content: space-between;
        position: sticky; top: 0; z-index: 100; }
  nav .logo { font-size: 18px; font-weight: 700; color: var(--accent); letter-spacing: 1px; }
  nav .logo span { color: var(--green); }
  nav .nav-links a { color: var(--muted); text-decoration: none; margin-left: 20px;
                     font-size: 13px; transition: color .2s; }
  nav .nav-links a:hover { color: var(--accent); }

  /* HERO */
  .hero { text-align: center; padding: 60px 20px 40px;
          background: linear-gradient(180deg, #0d1117 0%, #161b22 100%); }
  .hero h1 { font-size: 2.4rem; font-weight: 800; color: #fff; margin-bottom: 12px; }
  .hero h1 span { color: var(--accent); }
  .hero p { color: var(--muted); font-size: 15px; max-width: 560px; margin: 0 auto 30px; }
  .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px;
           font-weight: 600; margin: 4px; }
  .badge-blue   { background: #1f3a5f; color: var(--accent); }
  .badge-green  { background: #1a3a28; color: var(--green); }
  .badge-yellow { background: #3a2e0d; color: var(--yellow); }

  /* STATS BAR */
  .stats { display: flex; gap: 16px; justify-content: center; flex-wrap: wrap; padding: 20px; }
  .stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px;
               padding: 16px 28px; text-align: center; min-width: 140px; }
  .stat-card .num  { font-size: 1.8rem; font-weight: 700; color: var(--accent); }
  .stat-card .lbl  { font-size: 12px; color: var(--muted); margin-top: 4px; }

  /* MAIN GRID */
  .container { max-width: 1100px; margin: 0 auto; padding: 30px 20px 60px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px;
          padding: 24px; }
  .card h2 { font-size: 15px; font-weight: 700; color: #fff; margin-bottom: 6px;
             display: flex; align-items: center; gap: 8px; }
  .card p.desc { color: var(--muted); font-size: 12px; margin-bottom: 16px; }

  /* FORM ELEMENTS */
  textarea, input[type=text], input[type=password] {
    width: 100%; background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; color: var(--text); padding: 10px 12px; font-size: 13px;
    resize: vertical; outline: none; transition: border-color .2s; }
  textarea:focus, input:focus { border-color: var(--accent); }
  button { width: 100%; margin-top: 12px; padding: 10px; border: none; border-radius: 8px;
           background: var(--accent); color: #fff; font-size: 13px; font-weight: 600;
           cursor: pointer; transition: opacity .2s; }
  button:hover { opacity: .85; }

  /* RESULT BOX */
  .result { margin-top: 16px; padding: 14px; border-radius: 8px; display: none;
            font-size: 13px; border: 1px solid var(--border); }
  .result.show { display: block; }
  .result.safe   { border-color: var(--green);  background: #1a3a28; }
  .result.warn   { border-color: var(--yellow); background: #3a2e0d; }
  .result.danger { border-color: var(--red);    background: #2d1a1a; }
  .result.info   { border-color: var(--accent); background: #1f3a5f22; }

  /* SCORE BAR */
  .score-bar { height: 8px; border-radius: 4px; background: var(--border); margin: 10px 0; }
  .score-fill { height: 100%; border-radius: 4px; transition: width .6s; }

  /* FINDING LIST */
  .finding { padding: 6px 0; border-bottom: 1px solid var(--border); }
  .finding:last-child { border-bottom: none; }

  /* HASH TABLE */
  .hash-table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 12px; }
  .hash-table td { padding: 6px 8px; border-bottom: 1px solid var(--border); word-break: break-all; }
  .hash-table td:first-child { color: var(--accent); font-weight: 600; width: 70px; }

  /* LIVE LOG */
  #live-log { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
              padding: 12px; height: 200px; overflow-y: auto; font-family: monospace;
              font-size: 12px; color: var(--green); }
  .log-entry { margin: 2px 0; }
  .log-entry.warn   { color: var(--yellow); }
  .log-entry.danger { color: var(--red); }

  /* FOOTER */
  footer { text-align: center; padding: 24px; color: var(--muted); font-size: 12px;
           border-top: 1px solid var(--border); }
</style>
</head>
<body>

<!-- NAV -->
<nav>
  <div class="logo">🛡 AI<span>Threat</span>Detect</div>
  <div class="nav-links">
    <a href="#url-section">URL Scanner</a>
    <a href="#pw-section">Password</a>
    <a href="#text-section">Text Analysis</a>
    <a href="#hash-section">Hash Tool</a>
    <a href="#log-section">Live Log</a>
  </div>
</nav>

<!-- HERO -->
<div class="hero">
  <h1>AI Based <span>Threat Detection</span></h1>
  <p>Real-time cybersecurity analysis tools — detect phishing URLs, weak passwords,
     sensitive data leaks, and generate cryptographic hashes.</p>
  <span class="badge badge-blue">🔍 URL Scanner</span>
  <span class="badge badge-green">🔑 Password Analyzer</span>
  <span class="badge badge-yellow">📄 Text Threat Scanner</span>
  <span class="badge badge-blue">🔒 Hash Generator</span>
</div>

<!-- STATS -->
<div class="stats">
  <div class="stat-card"><div class="num" id="s-scans">0</div><div class="lbl">Total Scans</div></div>
  <div class="stat-card"><div class="num" id="s-threats">0</div><div class="lbl">Threats Found</div></div>
  <div class="stat-card"><div class="num" id="s-safe">0</div><div class="lbl">Safe Results</div></div>
  <div class="stat-card"><div class="num" id="s-hashes">0</div><div class="lbl">Hashes Generated</div></div>
</div>

<!-- TOOLS GRID -->
<div class="container">
<div class="grid">

  <!-- 1. URL SCANNER -->
  <div class="card" id="url-section">
    <h2>🔍 Phishing URL Scanner</h2>
    <p class="desc">Paste any URL to check for phishing indicators, suspicious domains, and unsafe patterns.</p>
    <input type="text" id="url-input" placeholder="https://example.com/login?verify=1"/>
    <button onclick="scanURL()">Scan URL</button>
    <div id="url-result" class="result"></div>
  </div>

  <!-- 2. PASSWORD ANALYZER -->
  <div class="card" id="pw-section">
    <h2>🔑 Password Strength Analyzer</h2>
    <p class="desc">Check how strong your password is and get actionable improvement tips.</p>
    <input type="password" id="pw-input" placeholder="Enter a password to analyze"/>
    <button onclick="checkPassword()">Analyze Password</button>
    <div id="pw-result" class="result"></div>
  </div>

  <!-- 3. TEXT THREAT SCANNER -->
  <div class="card" id="text-section" style="grid-column: span 2;">
    <h2>📄 Text Threat Scanner</h2>
    <p class="desc">Paste any text, email, or log snippet to detect sensitive data — credit cards, SSNs, API keys, SQL injection, and more.</p>
    <textarea id="text-input" rows="4" placeholder="Paste text, email body, or log data here..."></textarea>
    <button onclick="scanText()">Scan Text</button>
    <div id="text-result" class="result"></div>
  </div>

  <!-- 4. HASH GENERATOR -->
  <div class="card" id="hash-section">
    <h2>🔒 Cryptographic Hash Generator</h2>
    <p class="desc">Generate MD5, SHA-1, SHA-256, and SHA-512 hashes for any input string.</p>
    <input type="text" id="hash-input" placeholder="Enter text to hash"/>
    <button onclick="generateHash()">Generate Hashes</button>
    <div id="hash-result" class="result"></div>
  </div>

  <!-- 5. LIVE THREAT LOG -->
  <div class="card" id="log-section">
    <h2>📡 Live Threat Simulation Log</h2>
    <p class="desc">Simulated real-time feed of network threat events for demonstration purposes.</p>
    <div id="live-log"></div>
    <button onclick="toggleLog()" id="log-btn" style="margin-top:10px;">▶ Start Live Feed</button>
  </div>

</div>
</div>

<footer>
  🛡️ AI Based Threat Detection &nbsp;|&nbsp; Built with Python & Flask &nbsp;|&nbsp;
  For educational purposes only &nbsp;|&nbsp; {{ year }}
</footer>

<script>
  // ── counters ──────────────────────────────────
  let scans=0, threats=0, safe=0, hashes=0;
  function updateStats(isThreat, isHash=false) {
    if (isHash) { hashes++; document.getElementById('s-hashes').textContent = hashes; return; }
    scans++;
    document.getElementById('s-scans').textContent = scans;
    if (isThreat) { threats++; document.getElementById('s-threats').textContent = threats; }
    else          { safe++;    document.getElementById('s-safe').textContent = safe; }
  }

  // ── score colour ──────────────────────────────
  function scoreColor(score) {
    if (score >= 70) return '#f85149';
    if (score >= 40) return '#d29922';
    return '#3fb950';
  }
  function levelClass(level) {
    if (level === 'HIGH' || level === 'DANGER') return 'danger';
    if (level === 'MEDIUM') return 'warn';
    return 'safe';
  }

  // ── URL SCANNER ───────────────────────────────
  async function scanURL() {
    const url = document.getElementById('url-input').value.trim();
    if (!url) { alert('Please enter a URL'); return; }
    const res  = await fetch('/scan-url', { method:'POST',
                  headers:{'Content-Type':'application/json'},
                  body: JSON.stringify({url}) });
    const data = await res.json();
    const el   = document.getElementById('url-result');
    const isBad = data.level !== 'LOW';
    updateStats(isBad);
    el.className = 'result show ' + levelClass(data.level);
    el.innerHTML = `
      <strong>Risk Level: ${data.level}</strong> &nbsp; Score: ${data.score}/100
      <div class="score-bar"><div class="score-fill"
           style="width:${data.score}%;background:${scoreColor(data.score)}"></div></div>
      ${data.findings.map(f=>`<div class="finding">${f}</div>`).join('')}`;
  }

  // ── PASSWORD ──────────────────────────────────
  async function checkPassword() {
    const pw = document.getElementById('pw-input').value;
    if (!pw) { alert('Please enter a password'); return; }
    const res  = await fetch('/check-password', { method:'POST',
                  headers:{'Content-Type':'application/json'},
                  body: JSON.stringify({password:pw}) });
    const data = await res.json();
    const el   = document.getElementById('pw-result');
    updateStats(data.strength === 'WEAK');
    el.className = 'result show ' + (data.strength==='STRONG'?'safe':data.strength==='MODERATE'?'warn':'danger');
    el.innerHTML = `
      <strong>Strength: ${data.strength}</strong> &nbsp; Score: ${data.score}/100
      &nbsp; Entropy: ${data.entropy} bits &nbsp; Length: ${data.length}
      <div class="score-bar"><div class="score-fill"
           style="width:${data.score}%;background:${scoreColor(100-data.score)}"></div></div>
      ${data.feedback.map(f=>`<div class="finding">${f}</div>`).join('')}`;
  }

  // ── TEXT SCANNER ──────────────────────────────
  async function scanText() {
    const text = document.getElementById('text-input').value.trim();
    if (!text) { alert('Please enter some text'); return; }
    const res  = await fetch('/scan-text', { method:'POST',
                  headers:{'Content-Type':'application/json'},
                  body: JSON.stringify({text}) });
    const data = await res.json();
    const el   = document.getElementById('text-result');
    const isBad = data.level !== 'SAFE' && data.level !== 'LOW';
    updateStats(isBad);
    el.className = 'result show ' + levelClass(data.level);
    el.innerHTML = `
      <strong>Threat Level: ${data.level}</strong> &nbsp; Score: ${data.score}/100
      &nbsp; Words: ${data.word_count} &nbsp; Chars: ${data.char_count}
      <div class="score-bar"><div class="score-fill"
           style="width:${data.score}%;background:${scoreColor(data.score)}"></div></div>
      ${data.findings.length
          ? data.findings.map(f=>`<div class="finding">${f}</div>`).join('')
          : '<div class="finding">✅ No threats or sensitive data detected</div>'}`;
  }

  // ── HASH GENERATOR ────────────────────────────
  async function generateHash() {
    const text = document.getElementById('hash-input').value;
    if (!text) { alert('Please enter text to hash'); return; }
    const res  = await fetch('/get-hash', { method:'POST',
                  headers:{'Content-Type':'application/json'},
                  body: JSON.stringify({text}) });
    const data = await res.json();
    const el   = document.getElementById('hash-result');
    updateStats(false, true);
    el.className = 'result show info';
    el.innerHTML = `<table class="hash-table">` +
      Object.entries(data.hashes).map(([k,v])=>
        `<tr><td>${k}</td><td>${v}</td></tr>`).join('') +
      `</table>`;
  }

  // ── LIVE LOG ──────────────────────────────────
  const logEvents = [
    { msg:'[INFO]  System monitoring started',            cls:'' },
    { msg:'[WARN]  Port scan detected from 192.168.1.45', cls:'warn' },
    { msg:'[INFO]  DNS query: secure-login-amazon.tk',    cls:'warn' },
    { msg:'[ALERT] Brute-force attempt on SSH port 22',   cls:'danger' },
    { msg:'[INFO]  Firewall blocked outbound on port 4444',cls:'warn' },
    { msg:'[ALERT] SQL injection pattern in HTTP request', cls:'danger' },
    { msg:'[INFO]  TLS handshake completed with 10.0.0.3',cls:'' },
    { msg:'[WARN]  Unusual login time: 3:42 AM',          cls:'warn' },
    { msg:'[ALERT] Credential stuffing attack detected',   cls:'danger' },
    { msg:'[INFO]  Geo-block: request from blacklisted IP',cls:'warn' },
    { msg:'[INFO]  Malware signature match: Trojan.GenX', cls:'danger' },
    { msg:'[INFO]  User agent spoofing detected',          cls:'warn' },
    { msg:'[INFO]  Safe scan completed — no threats',      cls:'' },
  ];

  let logInterval = null;
  function toggleLog() {
    const btn = document.getElementById('log-btn');
    if (logInterval) {
      clearInterval(logInterval); logInterval = null;
      btn.textContent = '▶ Start Live Feed';
    } else {
      btn.textContent = '⏹ Stop Live Feed';
      logInterval = setInterval(() => {
        const log = document.getElementById('live-log');
        const ev  = logEvents[Math.floor(Math.random() * logEvents.length)];
        const ts  = new Date().toLocaleTimeString();
        const div = document.createElement('div');
        div.className = 'log-entry ' + ev.cls;
        div.textContent = `${ts}  ${ev.msg}`;
        log.appendChild(div);
        log.scrollTop = log.scrollHeight;
        if (log.children.length > 100) log.removeChild(log.firstChild);
      }, 1200);
    }
  }
</script>
</body>
</html>
"""

# ─────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML, year=datetime.datetime.now().year)

@app.route("/scan-url", methods=["POST"])
def route_scan_url():
    data = request.get_json()
    return jsonify(analyze_url(data.get("url", "")))

@app.route("/check-password", methods=["POST"])
def route_check_password():
    data = request.get_json()
    return jsonify(analyze_password(data.get("password", "")))

@app.route("/scan-text", methods=["POST"])
def route_scan_text():
    data = request.get_json()
    return jsonify(analyze_text(data.get("text", "")))

@app.route("/get-hash", methods=["POST"])
def route_get_hash():
    data = request.get_json()
    hashes = get_hash(data.get("text", ""))
    return jsonify({"hashes": hashes})

# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 52)
    print("  🛡  AI Based Threat Detection")
    print("  🌐  Open: http://127.0.0.1:5000")
    print("=" * 52)
    app.run(debug=True)
