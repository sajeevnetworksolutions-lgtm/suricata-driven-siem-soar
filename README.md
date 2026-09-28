# Suricata-Driven SIEM with Automated Incident Response (SOAR)

An enterprise-grade, lightweight, open-source Security Information and Event Management (SIEM) platform integrated with an automated Security Orchestration, Automation, and Response (SOAR) engine.

---

## 🌟 Key Features

1. **Real-time Network Threat Detection**: Suricata 7.x multi-threaded IDS monitoring network traffic with custom detection rules covering 6 major cyber threat categories.
2. **Standardized Telemetry Ingestion**: EVE JSON structured log output streamed via Filebeat with Elastic Common Schema (ECS) normalization.
3. **Centralized SIEM Analytics**: Elasticsearch + Kibana 8.x for log aggregation, timeline analysis, and threat hunting.
4. **Automated Incident Response (SOAR)**:
   - **Dynamic IP Quarantine**: Automatically bans malicious source IPs with customizable TTL cooling-off timers.
   - **Threat Intelligence Enrichment**: Enriches attacker IPs with GeoIP, ISP, and AbuseIPDB reputation scores.
   - **Automated Forensics**: Generates case dossiers with payload dumps for rapid analyst triage.
   - **Multi-channel Alerting**: Dispatches real-time cards to Discord, Slack, and Webhooks.
   - **Interactive Dark-Mode SOC UI**: Live WebSocket streaming, active defense manager, and manual analyst override controls.
5. **Attack Simulator Suite**: Python-based threat generator simulating all 6 security scenarios from the research paper.

---

## 📁 Repository Structure

```text
suricata-siem-soar/
├── docker-compose.yml              # Multi-container orchestrator
├── README.md                       # Documentation & quickstart
├── config/
│   ├── suricata/
│   │   ├── suricata.yaml           # Suricata configuration & EVE JSON logger
│   │   └── rules/                  # Detection rules mapped to MITRE ATT&CK
│   │       ├── recon.rules         # Port scanning / sweeps
│   │       ├── auth_bruteforce.rules # SSH & HTTP login brute-force
│   │       ├── web_attacks.rules   # SQLi, XSS, Path Traversal, Cmd Injection
│   │       ├── malware_c2.rules    # C2 heartbeat beacons & suspicious scanners
│   │       ├── dns_exfil.rules     # DNS tunneling & high-entropy queries
│   │       └── data_exfil.rules    # Sensitive database & private key exfiltration
│   └── filebeat/
│       └── filebeat.yml            # ECS mapper & Elasticsearch pipeline
├── soar_engine/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app.py                      # FastAPI web server & WebSocket broadcaster
│   ├── engine.py                   # Real-time EVE JSON tailing & playbook trigger
│   ├── models.py                   # Incident, Ban, & Playbook data models
│   ├── config.py                   # SOAR response policies & thresholds
│   ├── playbooks/
│   │   ├── ip_block.py             # Dynamic IP ban & TTL unban manager
│   │   ├── threat_intel.py         # AbuseIPDB / IOC reputation enricher
│   │   ├── notification.py         # Discord & Slack webhook dispatcher
│   │   └── forensic_dump.py        # Automated case dossier generator
│   └── static/
│       └── index.html              # Dark-mode SOC & SOAR Web Dashboard
├── target_service/
│   ├── Dockerfile
│   └── app.py                      # Realistic vulnerable endpoint testbed
├── attack_simulator/
│   ├── requirements.txt
│   ├── run_attack_suite.py         # Master CLI attack generator
│   └── scenarios/                  # Individual attack scripts (1-6)
└── docs/
    ├── ARCHITECTURE.md
    └── SOAR_PLAYBOOKS.md
```

---

## 🚀 Quickstart Guide

### Step 1: Start the SIEM & SOAR Docker Stack
Make sure Docker is running on your system, then launch the stack:

```bash
cd C:\Users\91990\.gemini\antigravity\scratch\suricata-siem-soar
docker compose up -d --build
```

### Step 2: Access the Dashboards
Once the containers are up:
- **SOAR Operations Center**: [http://localhost:8000](http://localhost:8000)
- **Kibana SIEM & Dashboards**: [http://localhost:5601](http://localhost:5601)
- **Elasticsearch API**: [http://localhost:9200](http://localhost:9200)
- **Vulnerable Target App**: [http://localhost:8080](http://localhost:8080)

---

## ⚔️ Running the Attack Simulator

Install simulator dependencies (or run inside python):

```bash
cd attack_simulator
pip install -r requirements.txt
```

### Run All Attack Scenarios (Full Suite)
```bash
python run_attack_suite.py --target 127.0.0.1 --port 8080 --scenario all
```

### Run Individual Threat Scenarios:
- **Scenario 1 (Port Scan & Recon)**: `python run_attack_suite.py --scenario 1`
- **Scenario 2 (Auth Brute Force)**: `python run_attack_suite.py --scenario 2`
- **Scenario 3 (Web Exploits - SQLi/XSS/LFI)**: `python run_attack_suite.py --scenario 3`
- **Scenario 4 (Malware C2 Beaconing)**: `python run_attack_suite.py --scenario 4`
- **Scenario 5 (DNS Tunneling Exfil)**: `python run_attack_suite.py --scenario 5`
- **Scenario 6 (Data Exfiltration)**: `python run_attack_suite.py --scenario 6`

### Continuous Demo Loop (For Presentations / Lab Demos):
```bash
python run_attack_suite.py --loop --interval 5
```

---

## 🛡️ Verifying SOAR Automated Response

1. Open [http://localhost:8000](http://localhost:8000) in your browser.
2. Trigger an attack scenario (e.g. `python run_attack_suite.py --scenario 3`).
3. Observe in real time:
   - Incoming security alert cards streaming via WebSockets.
   - Offending IP automatically placed into **Active Defense / Quarantine** table with a 300s TTL countdown.
   - Threat intelligence reputation score and country enrichment attached to the event.
   - Automated forensic case dossier generated in `/app/data/forensics/`.
   - Ability for the SOC analyst to click **"Pardon / Unban"** or **"Manual IP Quarantine"** at any time.
