# 🚀 Master Guide: How to Run, Test, and Present this Project

Welcome to the **Suricata SIEM + SOAR Autonomous Incident Response Platform**. This document is your complete cheat sheet to run the project, understand how every piece fits together, and give an impressive demonstration to professors, interviewers, or colleagues.

---

## ⚡ Quickstart: Run in 1 Click (Windows)

You don't need to memorize any command lines. In the project folder, simply:

1. **Double-click `START_PROJECT.bat`**
   - It automatically checks your Python environment.
   - Starts both the SOAR Engine (`:8000`) and the Vulnerable Target Lab (`:8080`).
   - Automatically opens your web browser to **`http://localhost:8000`**.

2. **To stop everything later:**
   - Double-click **`STOP_PROJECT.bat`** or press `CTRL+C` in the terminal.

---

## 🎯 The 30-Second Elevator Pitch (What to Say)

> *"Modern Security Operations Centers (SOCs) suffer from severe alert fatigue. When a typical Intrusion Detection System (IDS) flags an attack, human analysts take an average of 15 to 30 minutes to investigate and manually block the malicious IP address.*
>
> *This project implements a **closed-loop autonomous SOAR platform** powered by Suricata 7.x. When an adversary attempts an attack (such as SQL injection, SSH brute-forcing, or Cobalt Strike C2 beaconing), our system detects it via custom MITRE ATT&CK rules, parses the EVE JSON telemetry, enriches the threat intelligence with GeoIP and Abuse confidence scores, and **autonomously enforces a dynamic firewall quarantine in under 120 milliseconds**—with automatic TTL cooling to prevent permanent lockouts."*

---

## 🎬 Step-by-Step Live Demo Script (What to Click & Show)

Follow this 2-minute walkthrough during your presentation:

### Step 1: Show the Command Center (`http://localhost:8000`)
- Open **`http://localhost:8000`**.
- **Point out:**
  - **KPI Cards:** Mean Time to Respond (MTTR) is **< 120 ms** (meeting enterprise SLA).
  - **Analytics Charts:** Live **MITRE ATT&CK Matrix distribution** bar chart and **Severity profile** doughnut chart.
  - **Clean Enterprise Light UI:** Designed for high-clarity SOC room visibility.

### Step 2: Trigger an Attack from the 1-Click Simulator Bar
- At the top of the dashboard, you will see the **Threat Simulator Bar**.
- Click the **`[ 💥 SQL Injection ]`** button.
- **Observe what happens immediately:**
  1. 🔊 An audio radar ping sounds.
  2. 🚨 A floating red toast notification pops up: *"SQL Injection Attempt contained! Quarantined 198.51.100.44"*.
  3. 📊 The KPI counters and charts update in real-time.
  4. 🛡️ The attacker's IP (`198.51.100.44`) appears in the **Active Quarantines** panel with a **live ticking countdown timer** (`⏱ 4m 59s`).

### Step 3: Inspect the Investigation Dossier
- In the **Live Security Incident Stream**, find the top alert and click **`View Dossier →`**.
- **Show your audience:**
  - **Visual Containment Workflow:** Adversary ➔ Network Tap ➔ Suricata IDS 7.x ➔ SOAR Engine ➔ Quarantined.
  - **MITRE ATT&CK Tag:** `T1190 - Exploit Public-Facing Application`.
  - **Raw Packet / Payload Inspection:** Shows the extracted `' UNION SELECT id,username...` payload in high-contrast syntax highlighting.

### Step 4: Demonstrate Active Defense & Threat Intel
- Click on the blue **`198.51.100.44`** IP address in any alert card.
- A **Threat Intelligence Card** will pop up showing the country, ISP, and abuse reputation score.
- In the **Active Quarantines** panel, demonstrate flexibility by clicking **`+10 Min`** (to extend containment) or **`Pardon / Unban`** (to release the IP).

### Step 5: Test Other Attack Scenarios
- Click **`[ 🔑 SSH Brute-Force ]`** (MITRE T1110.001) or **`[ 🛰️ Cobalt Strike C2 ]`** (MITRE T1071.001).
- Show how the system categorizes each tactic into the MITRE ATT&CK chart and logs every step in the immutable audit trail table at the bottom.

### Step 6: Export SOC Executive Report
- Click the **`📥 Export CSV`** button in the top navigation bar.
- It will instantly download a clean, structured `suricata_soar_incidents.csv` file ready for SOC shift handover or compliance audits.

---

## 🛠️ Architecture & Frequently Asked Questions (FAQ)

### Q: Where are the Suricata detection rules located?
**A:** In `config/suricata/rules/`:
- `web_attacks.rules` (T1190 - SQL Injection, XSS, Path Traversal)
- `auth_bruteforce.rules` (T1110.001 - SSH & HTTP 401 bursts)
- `malware_c2.rules` (T1071.001 - Cobalt Strike beaconing)
- `recon.rules` (T1595.001 - Port scan sweeps)
- `data_exfil.rules` (T1048 - RSA private key leakage)
- `dns_exfil.rules` (T1048.003 - DNS tunneling oversized subdomains)

### Q: How does the SOAR engine avoid permanently blocking innocent users?
**A:** The engine uses **TTL (Time-To-Live) auto-cooling**. Quarantined IPs are assigned an expiration timestamp (default: 300 seconds). The background loop checks expired bans every second, pardons the IP, and records an unban action in the audit trail.

### Q: Can this be deployed in a real enterprise container cluster?
**A:** Yes! The project includes a 6-container `docker-compose.yml` orchestrating:
1. `suricata`: High-performance AF_PACKET multi-threaded IDS.
2. `filebeat`: ECS log normalizer.
3. `elasticsearch`: Elastic 8.x search & analytics cluster.
4. `kibana`: Visual SIEM dashboards (pre-built `.ndjson` dashboards included in `config/kibana/dashboards/`).
5. `soar-engine`: FastAPI real-time automation engine.
6. `target-service`: Mock vulnerable application.

---

## 📂 Key File Locations

- **1-Click Launcher:** `START_PROJECT.bat`
- **Attack Suite Runner:** `RUN_ATTACKS.bat`
- **Formal Academic Synopsis PDF:** `docs/Suricata_SIEM_SOAR_Project_Synopsis.pdf`
- **Interactive Kibana Dashboard Templates:** `config/kibana/dashboards/suricata_siem_dashboards.ndjson`
- **Sample Libpcap Network Capture:** `pcaps/suricata_attack_suite.pcap`
- **GitHub Repository:** [https://github.com/sajeevnetworksolutions-lgtm/suricata-driven-siem-soar](https://github.com/sajeevnetworksolutions-lgtm/suricata-driven-siem-soar)
