from flask import Flask, request, jsonify, render_template_string
import requests
from datetime import datetime
import os

app = Flask(__name__)
SOAR_URL = os.getenv("SOAR_URL", "http://127.0.0.1:8000")

PORTAL_HTML = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Interactive Threat Simulator & Canary Trap Portal</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            brand: { 500: '#3b82f6', 600: '#2563eb' }
          }
        }
      }
    }
  </script>
</head>
<body class="bg-[#0b0f19] text-gray-200 font-sans min-h-screen antialiased flex flex-col items-center justify-center p-4 sm:p-6">

  <div class="max-w-4xl w-full space-y-6">
    
    <!-- Header Banner -->
    <div class="bg-[#111827] border border-gray-800 rounded-2xl p-6 shadow-2xl flex flex-col sm:flex-row items-center justify-between gap-4">
      <div class="flex items-center space-x-4">
        <div class="h-12 w-12 rounded-xl bg-gradient-to-tr from-red-600 to-amber-500 flex items-center justify-center text-white text-2xl shadow-lg shadow-red-500/20">
          <i class="fa-solid fa-crosshairs"></i>
        </div>
        <div>
          <h1 class="text-xl font-bold text-white flex items-center gap-2">
            Interactive Threat Simulator
            <span class="text-xs bg-red-500/20 text-red-400 border border-red-500/30 px-2 py-0.5 rounded-full font-mono">LIVE LAB</span>
          </h1>
          <p class="text-xs text-gray-400">Click any button below to fire an attack and watch the SOAR engine react in real time!</p>
        </div>
      </div>
      <a href="http://localhost:8000" target="_blank" class="bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold px-4 py-2.5 rounded-xl shadow transition flex items-center gap-2 border border-blue-500/30">
        <i class="fa-solid fa-desktop"></i> Open Live SOAR Dashboard
      </a>
    </div>

    <!-- Interactive Attack Launcher Grid -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      
      <!-- Attack 1: SQL Injection -->
      <div class="bg-[#131b2e] border border-gray-800 rounded-xl p-5 shadow hover:border-red-500/50 transition flex flex-col justify-between space-y-4">
        <div>
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">SQL INJECTION</span>
            <i class="fa-solid fa-database text-red-400"></i>
          </div>
          <h3 class="text-sm font-bold text-white mt-2">Database Extraction Attack</h3>
          <p class="text-xs text-gray-400 mt-1">Sends <code class="text-amber-300 font-mono">' UNION SELECT ...</code> to extract admin credentials.</p>
        </div>
        <button onclick="triggerAttack('sqli')" class="w-full bg-red-600 hover:bg-red-700 text-white text-xs font-semibold py-2.5 rounded-lg shadow transition flex items-center justify-center gap-2">
          <i class="fa-solid fa-play"></i> Trigger SQL Injection
        </button>
      </div>

      <!-- Attack 2: Password Brute-Force -->
      <div class="bg-[#131b2e] border border-gray-800 rounded-xl p-5 shadow hover:border-amber-500/50 transition flex flex-col justify-between space-y-4">
        <div>
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">BRUTE FORCE</span>
            <i class="fa-solid fa-key text-amber-400"></i>
          </div>
          <h3 class="text-sm font-bold text-white mt-2">Credential Stuffing Burst</h3>
          <p class="text-xs text-gray-400 mt-1">Fires 5 rapid login attempts with password dictionaries to trigger HTTP 401s.</p>
        </div>
        <button onclick="triggerAttack('bruteforce')" class="w-full bg-amber-600 hover:bg-amber-700 text-white text-xs font-semibold py-2.5 rounded-lg shadow transition flex items-center justify-center gap-2">
          <i class="fa-solid fa-play"></i> Trigger Brute Force
        </button>
      </div>

      <!-- Attack 3: Malware C2 Beacon -->
      <div class="bg-[#131b2e] border border-gray-800 rounded-xl p-5 shadow hover:border-purple-500/50 transition flex flex-col justify-between space-y-4">
        <div>
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold text-purple-400 bg-purple-500/10 px-2 py-0.5 rounded border border-purple-500/20">MALWARE C2</span>
            <i class="fa-solid fa-virus text-purple-400"></i>
          </div>
          <h3 class="text-sm font-bold text-white mt-2">Botnet C2 Heartbeat</h3>
          <p class="text-xs text-gray-400 mt-1">Sends an emulated malware check-in beacon to <code class="text-purple-300 font-mono">/api/v1/heartbeat</code>.</p>
        </div>
        <button onclick="triggerAttack('c2_beacon')" class="w-full bg-purple-600 hover:bg-purple-700 text-white text-xs font-semibold py-2.5 rounded-lg shadow transition flex items-center justify-center gap-2">
          <i class="fa-solid fa-play"></i> Send C2 Beacon
        </button>
      </div>

      <!-- Attack 4: Cross-Site Scripting (XSS) -->
      <div class="bg-[#131b2e] border border-gray-800 rounded-xl p-5 shadow hover:border-blue-500/50 transition flex flex-col justify-between space-y-4">
        <div>
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">XSS EXPLOIT</span>
            <i class="fa-solid fa-code text-blue-400"></i>
          </div>
          <h3 class="text-sm font-bold text-white mt-2">Client-Side Script Injection</h3>
          <p class="text-xs text-gray-400 mt-1">Injects malicious <code class="text-blue-300 font-mono">&lt;script&gt;alert(1)&lt;/script&gt;</code> into the search field.</p>
        </div>
        <button onclick="triggerAttack('xss')" class="w-full bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold py-2.5 rounded-lg shadow transition flex items-center justify-center gap-2">
          <i class="fa-solid fa-play"></i> Trigger XSS Attack
        </button>
      </div>

      <!-- Attack 5: Data Exfiltration -->
      <div class="bg-[#131b2e] border border-gray-800 rounded-xl p-5 shadow hover:border-emerald-500/50 transition flex flex-col justify-between space-y-4">
        <div>
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">DATA EXFIL</span>
            <i class="fa-solid fa-file-export text-emerald-400"></i>
          </div>
          <h3 class="text-sm font-bold text-white mt-2">Sensitive Key Exfiltration</h3>
          <p class="text-xs text-gray-400 mt-1">Transfers an unencrypted RSA Private Key payload to an external endpoint.</p>
        </div>
        <button onclick="triggerAttack('exfil')" class="w-full bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold py-2.5 rounded-lg shadow transition flex items-center justify-center gap-2">
          <i class="fa-solid fa-play"></i> Exfiltrate RSA Key
        </button>
      </div>

      <!-- Attack 6: Honeypot Canary Link Trap -->
      <div class="bg-[#1e1528] border border-purple-900/50 rounded-xl p-5 shadow hover:border-pink-500/50 transition flex flex-col justify-between space-y-4">
        <div>
          <div class="flex items-center justify-between">
            <span class="text-xs font-bold text-pink-400 bg-pink-500/10 px-2 py-0.5 rounded border border-pink-500/20">HONEYPOT TRAP</span>
            <i class="fa-solid fa-skull text-pink-400"></i>
          </div>
          <h3 class="text-sm font-bold text-white mt-2">Canary Token Click Trap</h3>
          <p class="text-xs text-gray-400 mt-1">Clicking this link simulates an employee or attacker clicking a restricted lure file.</p>
        </div>
        <a href="/canary/trap?target=Confidential_Employee_Salaries_2026.xlsx" class="w-full bg-gradient-to-r from-pink-600 to-purple-600 hover:from-pink-700 hover:to-purple-700 text-white text-xs font-semibold py-2.5 rounded-lg shadow transition flex items-center justify-center gap-2 text-center">
          <i class="fa-solid fa-triangle-exclamation"></i> Click Honeypot Trap Link
        </a>
      </div>

    </div>

    <!-- Live Execution Terminal / Response Box -->
    <div class="bg-[#111827] border border-gray-800 rounded-2xl p-5 shadow-2xl">
      <div class="flex items-center justify-between pb-3 border-b border-gray-800">
        <h3 class="text-xs font-bold uppercase tracking-wider text-gray-400 flex items-center gap-2 font-mono">
          <i class="fa-solid fa-terminal text-emerald-400"></i> Live Defense Response Console
        </h3>
        <span id="console-status" class="text-[11px] font-mono text-emerald-400">Ready for user input</span>
      </div>
      <div id="output-box" class="mt-3 bg-black/60 border border-gray-900 rounded-xl p-4 font-mono text-xs text-gray-300 min-h-[140px] max-h-[220px] overflow-y-auto space-y-1">
        <p class="text-gray-500">// Welcome to the Interactive Cyber Attack Simulation Lab.</p>
        <p class="text-gray-500">// Click any attack button above or the Canary Trap link to test detection & SOAR response.</p>
      </div>
    </div>

  </div>

  <script>
    async function triggerAttack(type) {
      const out = document.getElementById('output-box');
      const status = document.getElementById('console-status');
      
      status.innerHTML = '<span class="text-amber-400 animate-pulse">Firing Attack Payload...</span>';
      out.innerHTML += `<p class="text-yellow-400 pt-2 font-bold">>>> [ACTION] Initiating Attack: ${type.toUpperCase()} ...</p>`;
      out.scrollTop = out.scrollHeight;

      try {
        const res = await fetch(`/api/trigger-test/${type}`, { method: 'POST' });
        const data = await res.json();
        
        status.innerHTML = '<span class="text-emerald-400">Response & Automated Containment Triggered</span>';
        out.innerHTML += `
          <p class="text-cyan-300">    [+] Server Payload Response: HTTP ${data.http_status}</p>
          <p class="text-amber-300">    [+] Suricata Signature: "${data.signature}"</p>
          <p class="text-red-400 font-bold">    [🚨 SOAR REACTION] ${data.soar_action}</p>
          <p class="text-purple-300">    [+] Threat Intel IP: ${data.src_ip} | Score: ${data.intel_score}/100</p>
          <p class="text-emerald-400">    [✔] Live Dashboard updated at: <a href="http://localhost:8000" target="_blank" class="underline">http://localhost:8000</a></p>
        `;
        out.scrollTop = out.scrollHeight;
      } catch (err) {
        out.innerHTML += `<p class="text-red-500">[-] Error executing attack: ${err}</p>`;
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
<body class="bg-[#0b0f19] text-gray-200 min-h-screen flex items-center justify-center p-6">
  <div class="max-w-lg w-full bg-[#182235] border border-red-700/60 rounded-2xl p-8 text-center space-y-4 shadow-2xl">
    <div class="h-16 w-16 bg-red-600/20 text-red-500 rounded-full flex items-center justify-center mx-auto text-3xl border border-red-500/40 animate-pulse">
      <i class="fa-solid fa-hand"></i>
    </div>
    <h1 class="text-xl font-bold text-white">🚨 HONEYPOT CANARY TRAP TRIPPED!</h1>
    <p class="text-xs text-gray-300">
      You accessed a restricted honeypot canary resource: <br>
      <code class="text-amber-300 font-mono font-bold">{{ file_name }}</code>
    </p>
    <div class="bg-black/50 p-4 rounded-xl text-left font-mono text-xs space-y-1 text-gray-300 border border-gray-800">
      <p><span class="text-gray-500">Client IP:</span> <span class="text-red-400 font-bold">{{ client_ip }}</span></p>
      <p><span class="text-gray-500">Timestamp:</span> {{ timestamp }}</p>
      <p><span class="text-gray-500">SOAR Defense:</span> <span class="text-emerald-400">Automated Quarantine Enforced (300s TTL)</span></p>
      <p><span class="text-gray-500">Forensics:</span> Case dossier generated for SOC investigation</p>
    </div>
    <div class="pt-2 flex justify-center gap-3">
      <a href="/" class="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-xs text-white rounded-lg transition font-semibold">Back to Lab</a>
      <a href="http://localhost:8000" target="_blank" class="px-4 py-2 bg-red-600 hover:bg-red-700 text-xs text-white rounded-lg transition font-semibold">View in SOAR Dashboard</a>
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
        client_ip = "192.168.1.99" # Realistic attacker IP for local demo

    # Trigger SOAR Canary Alarm
    try:
        requests.post(f"{SOAR_URL}/api/webhook/alert", json={
            "src_ip": client_ip,
            "dest_ip": "127.0.0.1",
            "signature": f"SIEM-HONEYPOT: Restricted Canary File Access Attempt ({file_name})",
            "category": "Policy-Violation",
            "severity": 1,
            "mitre_tactic": "TA0001",
            "mitre_technique": "T1190"
        }, timeout=2)
    except Exception:
        pass

    return render_template_string(CANARY_TRAP_HTML, file_name=file_name, client_ip=client_ip, timestamp=datetime.utcnow().isoformat())

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
            "action": "Quarantined IP 192.168.1.150 (300s TTL) + Case File Created"
        },
        "bruteforce": {
            "signature": "SIEM-AUTH: Multiple HTTP 401 Unauthorized Responses (Web Brute Force)",
            "severity": 1,
            "category": "Attempted-Admin",
            "mock_ip": "172.28.0.105",
            "intel_score": 85,
            "action": "Quarantined IP 172.28.0.105 (300s TTL) + Auth Alert Sent"
        },
        "c2_beacon": {
            "signature": "SIEM-C2: Emulated Malware C2 Heartbeat Beacon Detected",
            "severity": 1,
            "category": "Trojan-Activity",
            "mock_ip": "172.28.0.200",
            "intel_score": 88,
            "action": "Quarantined C2 IP 172.28.0.200 (300s TTL) + Tagged as Botnet Host"
        },
        "xss": {
            "signature": "SIEM-WEB: Cross-Site Scripting (XSS) Tag Injection Detected",
            "severity": 2,
            "category": "Web-Application-Attack",
            "mock_ip": "198.51.100.55",
            "intel_score": 65,
            "action": "Flagged High-Risk XSS Attempt & Enriched Source IP"
        },
        "exfil": {
            "signature": "SIEM-EXFIL: Unencrypted RSA Private Key Exfiltration Attempt",
            "severity": 1,
            "category": "Policy-Violation",
            "mock_ip": "172.28.0.110",
            "intel_score": 92,
            "action": "Quarantined IP 172.28.0.110 (300s TTL) + Forensic Evidence Dumped"
        }
    }

    item = mapping.get(attack_type, mapping["sqli"])
    src_ip = item["mock_ip"] if client_ip in ["127.0.0.1", "::1"] else client_ip

    # Forward alert to SOAR engine
    try:
        requests.post(f"{SOAR_URL}/api/webhook/alert", json={
            "src_ip": src_ip,
            "dest_ip": "127.0.0.1",
            "signature": item["signature"],
            "category": item["category"],
            "severity": item["severity"],
            "timestamp": datetime.utcnow().isoformat()
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
