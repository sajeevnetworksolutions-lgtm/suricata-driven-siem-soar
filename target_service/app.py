from flask import Flask, request, jsonify, render_template_string
import requests
from datetime import datetime, timezone
import os

app = Flask(__name__)
SOAR_URL = os.getenv("SOAR_URL", "http://127.0.0.1:8000")

PORTAL_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Interactive Threat Simulator & Canary Trap Portal</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <script>
    tailwind.config = {
      theme: {
        extend: {
          colors: {
            brand: { 500: '#2563eb', 600: '#1d4ed8' }
          }
        }
      }
    }
  </script>
</head>
<body class="bg-slate-100 text-slate-800 font-sans min-h-screen antialiased flex flex-col items-center justify-center p-4 sm:p-6">

  <div class="max-w-4xl w-full space-y-6">
    
    <!-- Header Banner (Light Mode) -->
    <div class="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm flex flex-col sm:flex-row items-center justify-between gap-4">
      <div class="flex items-center space-x-4">
        <div class="h-12 w-12 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-600 flex items-center justify-center text-white text-2xl shadow-md shadow-blue-500/20">
          <i class="fa-solid fa-crosshairs"></i>
        </div>
        <div>
          <h1 class="text-xl font-bold text-slate-900 flex items-center gap-2">
            Interactive Threat Simulator
            <span class="text-xs bg-red-100 text-red-700 border border-red-200 px-2.5 py-0.5 rounded-full font-mono font-semibold">LIVE LAB</span>
          </h1>
          <p class="text-xs text-slate-500">Click any button below to fire an attack and watch the SOAR engine react in real time!</p>
        </div>
      </div>
      <a href="http://localhost:8000" target="_blank" class="bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold px-4 py-2.5 rounded-xl shadow-sm transition flex items-center gap-2">
        <i class="fa-solid fa-desktop"></i> Open Live SOAR Dashboard
      </a>
    </div>

    <!-- Interactive Attack Launcher Grid (Light Mode) -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      
      <!-- Attack 1: SQL Injection -->
      <div class="bg-white border border-slate-200 rounded-xl p-5 shadow-sm hover:border-red-400 hover:shadow-md transition flex flex-col justify-between space-y-4">
        <div>
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold text-red-700 bg-red-50 border border-red-200 px-2.5 py-0.5 rounded-full">SQL INJECTION</span>
            <i class="fa-solid fa-database text-red-500"></i>
          </div>
          <h3 class="text-sm font-bold text-slate-900 mt-2.5">Database Extraction Attack</h3>
          <p class="text-xs text-slate-500 mt-1">Sends <code class="text-amber-700 font-mono bg-amber-50 px-1 py-0.5 rounded">' UNION SELECT ...</code> to extract admin credentials.</p>
        </div>
        <button onclick="triggerAttack('sqli')" class="w-full bg-red-600 hover:bg-red-700 text-white text-xs font-semibold py-2.5 rounded-lg shadow-sm transition flex items-center justify-center gap-2">
          <i class="fa-solid fa-play"></i> Trigger SQL Injection
        </button>
      </div>

      <!-- Attack 2: Password Brute-Force -->
      <div class="bg-white border border-slate-200 rounded-xl p-5 shadow-sm hover:border-amber-400 hover:shadow-md transition flex flex-col justify-between space-y-4">
        <div>
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold text-amber-700 bg-amber-50 border border-amber-200 px-2.5 py-0.5 rounded-full">BRUTE FORCE</span>
            <i class="fa-solid fa-key text-amber-500"></i>
          </div>
          <h3 class="text-sm font-bold text-slate-900 mt-2.5">Credential Stuffing Burst</h3>
          <p class="text-xs text-slate-500 mt-1">Fires 5 rapid login attempts with password dictionaries to trigger HTTP 401s.</p>
        </div>
        <button onclick="triggerAttack('bruteforce')" class="w-full bg-amber-600 hover:bg-amber-700 text-white text-xs font-semibold py-2.5 rounded-lg shadow-sm transition flex items-center justify-center gap-2">
          <i class="fa-solid fa-play"></i> Trigger Brute Force
        </button>
      </div>

      <!-- Attack 3: Malware C2 Beacon -->
      <div class="bg-white border border-slate-200 rounded-xl p-5 shadow-sm hover:border-purple-400 hover:shadow-md transition flex flex-col justify-between space-y-4">
        <div>
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold text-purple-700 bg-purple-50 border border-purple-200 px-2.5 py-0.5 rounded-full">MALWARE C2</span>
            <i class="fa-solid fa-virus text-purple-500"></i>
          </div>
          <h3 class="text-sm font-bold text-slate-900 mt-2.5">Botnet C2 Heartbeat</h3>
          <p class="text-xs text-slate-500 mt-1">Sends an emulated malware check-in beacon to <code class="text-purple-700 font-mono bg-purple-50 px-1 py-0.5 rounded">/api/v1/heartbeat</code>.</p>
        </div>
        <button onclick="triggerAttack('c2_beacon')" class="w-full bg-purple-600 hover:bg-purple-700 text-white text-xs font-semibold py-2.5 rounded-lg shadow-sm transition flex items-center justify-center gap-2">
          <i class="fa-solid fa-play"></i> Send C2 Beacon
        </button>
      </div>

      <!-- Attack 4: Cross-Site Scripting (XSS) -->
      <div class="bg-white border border-slate-200 rounded-xl p-5 shadow-sm hover:border-blue-400 hover:shadow-md transition flex flex-col justify-between space-y-4">
        <div>
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold text-blue-700 bg-blue-50 border border-blue-200 px-2.5 py-0.5 rounded-full">XSS EXPLOIT</span>
            <i class="fa-solid fa-code text-blue-500"></i>
          </div>
          <h3 class="text-sm font-bold text-slate-900 mt-2.5">Client-Side Script Injection</h3>
          <p class="text-xs text-slate-500 mt-1">Injects malicious <code class="text-blue-700 font-mono bg-blue-50 px-1 py-0.5 rounded">&lt;script&gt;alert(1)&lt;/script&gt;</code> into search.</p>
        </div>
        <button onclick="triggerAttack('xss')" class="w-full bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold py-2.5 rounded-lg shadow-sm transition flex items-center justify-center gap-2">
          <i class="fa-solid fa-play"></i> Trigger XSS Attack
        </button>
      </div>

      <!-- Attack 5: Data Exfiltration -->
      <div class="bg-white border border-slate-200 rounded-xl p-5 shadow-sm hover:border-emerald-400 hover:shadow-md transition flex flex-col justify-between space-y-4">
        <div>
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-2.5 py-0.5 rounded-full">DATA EXFIL</span>
            <i class="fa-solid fa-file-export text-emerald-500"></i>
          </div>
          <h3 class="text-sm font-bold text-slate-900 mt-2.5">Sensitive Key Exfiltration</h3>
          <p class="text-xs text-slate-500 mt-1">Transfers an unencrypted RSA Private Key payload to an external endpoint.</p>
        </div>
        <button onclick="triggerAttack('exfil')" class="w-full bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold py-2.5 rounded-lg shadow-sm transition flex items-center justify-center gap-2">
          <i class="fa-solid fa-play"></i> Exfiltrate RSA Key
        </button>
      </div>

      <!-- Attack 6: Honeypot Canary Link Trap -->
      <div class="bg-gradient-to-br from-pink-50 to-purple-50 border border-pink-200 rounded-xl p-5 shadow-sm hover:border-pink-400 hover:shadow-md transition flex flex-col justify-between space-y-4">
        <div>
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold text-pink-700 bg-pink-100 border border-pink-300 px-2.5 py-0.5 rounded-full">HONEYPOT TRAP</span>
            <i class="fa-solid fa-skull text-pink-500"></i>
          </div>
          <h3 class="text-sm font-bold text-slate-900 mt-2.5">Canary Token Click Trap</h3>
          <p class="text-xs text-slate-600 mt-1">Clicking this link simulates an employee or attacker clicking a restricted lure file.</p>
        </div>
        <a href="/canary/trap?target=Confidential_Employee_Salaries_2026.xlsx" class="w-full bg-gradient-to-r from-pink-600 to-purple-600 hover:from-pink-700 hover:to-purple-700 text-white text-xs font-semibold py-2.5 rounded-lg shadow-sm transition flex items-center justify-center gap-2 text-center">
          <i class="fa-solid fa-triangle-exclamation"></i> Click Honeypot Trap Link
        </a>
      </div>

    </div>

    <!-- Live Execution Terminal / Response Box (Pure Light Mode) -->
    <div class="bg-white border border-slate-200 rounded-2xl p-5 shadow-sm">
      <div class="flex items-center justify-between pb-3 border-b border-slate-200">
        <h3 class="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2 font-mono">
          <i class="fa-solid fa-terminal text-blue-600"></i> Live Defense Response Console
        </h3>
        <span id="console-status" class="text-[11px] font-mono text-emerald-600 font-semibold">Ready for user input</span>
      </div>
      <div id="output-box" class="mt-3 bg-slate-50 border border-slate-200 rounded-xl p-4 font-mono text-xs text-slate-800 min-h-[140px] max-h-[220px] overflow-y-auto space-y-1 shadow-inner">
        <p class="text-slate-500">// Welcome to the Interactive Cyber Attack Simulation Lab.</p>
        <p class="text-slate-500">// Click any attack button above or the Canary Trap link to test detection &amp; SOAR response.</p>
      </div>
    </div>

  </div>

  <script>
    async function triggerAttack(type) {
      const out = document.getElementById('output-box');
      const status = document.getElementById('console-status');
      
      status.innerHTML = '<span class="text-amber-600 animate-pulse font-semibold">Firing Attack Payload...</span>';
      out.innerHTML += `<p class="text-amber-700 pt-2 font-bold">&gt;&gt;&gt; [ACTION] Initiating Attack: ${type.toUpperCase()} ...</p>`;
      out.scrollTop = out.scrollHeight;

      try {
        const res = await fetch(`/api/trigger-test/${type}`, { method: 'POST' });
        const data = await res.json();
        
        status.innerHTML = '<span class="text-emerald-600 font-semibold">Response &amp; Automated Containment Triggered</span>';
        out.innerHTML += `
          <p class="text-blue-700">    [+] Server Payload Response: HTTP ${data.http_status}</p>
          <p class="text-amber-700">    [+] Suricata Signature: "${data.signature}"</p>
          <p class="text-red-700 font-bold">    [SOAR REACTION] ${data.soar_action}</p>
          <p class="text-purple-700">    [+] Threat Intel IP: ${data.src_ip} | Score: ${data.intel_score}/100</p>
          <p class="text-emerald-700 font-semibold">    [OK] Live Dashboard updated at: <a href="http://localhost:8000" target="_blank" class="underline">http://localhost:8000</a></p>
        `;
        out.scrollTop = out.scrollHeight;
      } catch (err) {
        out.innerHTML += `<p class="text-red-600 font-semibold">[-] Error executing attack: ${err}</p>`;
      }
    }
  </script>
</body>
</html>
"""

CANARY_TRAP_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>RESTRICTED RESOURCE - ACCESS DENIED</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="bg-slate-100 text-slate-800 min-h-screen flex items-center justify-center p-6 antialiased">
  <div class="max-w-lg w-full bg-white border border-red-200 rounded-2xl p-8 text-center space-y-4 shadow-xl">
    <div class="h-16 w-16 bg-red-100 text-red-600 rounded-full flex items-center justify-center mx-auto text-3xl border border-red-200 animate-pulse">
      <i class="fa-solid fa-hand"></i>
    </div>
    <h1 class="text-xl font-bold text-slate-900">🚨 HONEYPOT CANARY TRAP TRIPPED!</h1>
    <p class="text-xs text-slate-600">
      You accessed a restricted honeypot canary resource: <br>
      <code class="text-amber-700 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded font-mono font-bold">{{ file_name }}</code>
    </p>
    <div class="bg-slate-50 p-4 rounded-xl text-left font-mono text-xs space-y-1.5 text-slate-700 border border-slate-200">
      <p><span class="text-slate-400">Client IP:</span> <span class="text-red-600 font-bold">{{ client_ip }}</span></p>
      <p><span class="text-slate-400">Timestamp:</span> {{ timestamp }}</p>
      <p><span class="text-slate-400">SOAR Defense:</span> <span class="text-emerald-600 font-bold">Automated Quarantine Enforced (300s TTL)</span></p>
      <p><span class="text-slate-400">Forensics:</span> Case dossier generated for SOC investigation</p>
    </div>
    <div class="pt-2 flex justify-center gap-3">
      <a href="/" class="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-xs text-slate-700 rounded-lg transition font-semibold border border-slate-300">Back to Lab</a>
      <a href="http://localhost:8000" target="_blank" class="px-4 py-2 bg-red-600 hover:bg-red-700 text-xs text-white rounded-lg transition font-semibold shadow-sm">View in SOAR Dashboard</a>
    </div>
  </div>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(PORTAL_HTML)

@app.route('/canary/trap')
def canary_trap():
    file_name = request.args.get('target', 'Secret_Financial_Records_2026.pdf')
    client_ip = request.remote_addr or "127.0.0.1"
    if client_ip in ["127.0.0.1", "::1"]:
        client_ip = "192.168.1.99"

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    try:
        requests.post(f"{SOAR_URL}/api/webhook/alert", json={
            "src_ip": client_ip,
            "dest_ip": "127.0.0.1",
            "dest_port": 8080,
            "proto": "HTTP",
            "signature": f"SIEM-HONEYPOT: Restricted Canary File Access Attempt ({file_name})",
            "category": "Deception-Detection",
            "severity": 1,
            "mitre_tactic": "TA0007 - Discovery",
            "mitre_technique": "T1083 - File and Directory Discovery",
            "payload": f"GET /canary/trap?target={file_name} HTTP/1.1",
            "timestamp": now_iso
        }, timeout=2)
    except Exception:
        pass

    return render_template_string(CANARY_TRAP_HTML, file_name=file_name, client_ip=client_ip, timestamp=now_iso)

@app.route('/api/trigger-test/<attack_type>', methods=['POST'])
def trigger_test_attack(attack_type):
    client_ip = request.remote_addr or "127.0.0.1"
    
    mapping = {
        "sqli": {
            "signature": "SIEM-WEB: SQL Injection Attempt (UNION SELECT detected)",
            "severity": 1,
            "category": "Web-Application-Attack",
            "mock_ip": "192.168.1.150",
            "intel_score": 90,
            "mitre_tactic": "TA0001 - Initial Access",
            "mitre_technique": "T1190 - Exploit Public-Facing Application",
            "payload": "GET /search?q=1' UNION SELECT null,username,password FROM users-- HTTP/1.1",
            "action": "Quarantined IP 192.168.1.150 (300s TTL) + Case File Created"
        },
        "bruteforce": {
            "signature": "SIEM-AUTH: Multiple HTTP 401 Unauthorized Responses (Web Brute Force)",
            "severity": 1,
            "category": "Attempted-Admin",
            "mock_ip": "172.28.0.105",
            "intel_score": 85,
            "mitre_tactic": "TA0006 - Credential Access",
            "mitre_technique": "T1110.001 - Password Guessing",
            "payload": "POST /login HTTP/1.1 [x5 401 Unauthorized bursts for user 'admin']",
            "action": "Quarantined IP 172.28.0.105 (300s TTL) + Auth Alert Sent"
        },
        "c2_beacon": {
            "signature": "SIEM-C2: Emulated Malware C2 Heartbeat Beacon Detected",
            "severity": 1,
            "category": "Trojan-Activity",
            "mock_ip": "172.28.0.200",
            "intel_score": 88,
            "mitre_tactic": "TA0011 - Command and Control",
            "mitre_technique": "T1071.001 - Web Protocols Beaconing",
            "payload": "POST /api/v1/heartbeat HTTP/1.1\r\nbeacon_id=BOTNET-77&cmd=POLL",
            "action": "Quarantined C2 IP 172.28.0.200 (300s TTL) + Tagged as Botnet Host"
        },
        "xss": {
            "signature": "SIEM-WEB: Cross-Site Scripting (XSS) Tag Injection Detected",
            "severity": 2,
            "category": "Web-Application-Attack",
            "mock_ip": "198.51.100.55",
            "intel_score": 72,
            "mitre_tactic": "TA0002 - Execution",
            "mitre_technique": "T1059.007 - JavaScript",
            "payload": "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1",
            "action": "Flagged High-Risk XSS Attempt & Enriched Source IP"
        },
        "exfil": {
            "signature": "SIEM-EXFIL: Unencrypted RSA Private Key Exfiltration Attempt",
            "severity": 1,
            "category": "Policy-Violation",
            "mock_ip": "172.28.0.110",
            "intel_score": 92,
            "mitre_tactic": "TA0010 - Exfiltration",
            "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
            "payload": "POST /upload?file=id_rsa\r\n-----BEGIN RSA PRIVATE KEY-----",
            "action": "Quarantined IP 172.28.0.110 (300s TTL) + Forensic Evidence Dumped"
        }
    }

    item = mapping.get(attack_type, mapping["sqli"])
    src_ip = item["mock_ip"] if client_ip in ["127.0.0.1", "::1"] else client_ip
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    try:
        requests.post(f"{SOAR_URL}/api/webhook/alert", json={
            "src_ip": src_ip,
            "dest_ip": "127.0.0.1",
            "dest_port": 8080,
            "proto": "HTTP",
            "signature": item["signature"],
            "category": item["category"],
            "severity": item["severity"],
            "mitre_tactic": item["mitre_tactic"],
            "mitre_technique": item["mitre_technique"],
            "payload": item["payload"],
            "timestamp": now_iso
        }, timeout=2)
    except Exception:
        pass

    return jsonify({
        "http_status": 200,
        "signature": item["signature"],
        "src_ip": src_ip,
        "soar_action": item["action"],
        "intel_score": item["intel_score"]
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401
    return 'Login Form'

@app.route('/search')
def search():
    query = request.args.get('q', '')
    return f"Search results for: {query}"

@app.route('/api/v1/heartbeat', methods=['POST'])
def heartbeat():
    return jsonify({"status": "ACK", "cmd": "IDLE"})

@app.route('/upload', methods=['POST'])
def upload():
    return jsonify({"status": "uploaded"})

if __name__ == '__main__':
    port = int(os.getenv("TARGET_PORT", "8080"))
    app.run(host='0.0.0.0', port=port)
