<div align="center">

# 🛡️ Suricata-Driven SIEM with Automated Incident Response (SOAR)
### *Next-Generation Autonomous Network Threat Detection, Centralized Analytics, and Dynamic Containment*

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.11%2B-brightgreen.svg)](https://python.org)
[![Suricata](https://img.shields.io/badge/Suricata-7.x%20IDS-red.svg)](https://suricata.io)
[![Elastic Stack](https://img.shields.io/badge/Elasticsearch-8.12-005571.svg)](https://elastic.co)
[![Kibana](https://img.shields.io/badge/Kibana-8.12-E8488B.svg)](https://elastic.co)
[![Docker](https://img.shields.io/badge/Docker-Compose_v2-2496ED.svg)](https://docker.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Aligned-orange.svg)](docs/MITRE_ATTACK_MAPPING.md)
[![Status](https://img.shields.io/badge/Build-Passing%20100%25-success.svg)](docs/PERFORMANCE_BENCHMARKS.md)

[Overview](#-overview) •
[Architecture](#-system-architecture) •
[Threat Scenarios](#-mitre-attck-threat-matrix) •
[Quickstart](#-quickstart-guide) •
[Interactive Demo](#-interactive-threat-portal--canary-lab) •
[SOAR Playbooks](#-soar-automated-response-playbooks) •
[Benchmarks](#-performance-benchmarks) •
[Documentation](#-documentation-suite)

---

</div>

## 📌 Overview

The **Suricata-Driven SIEM + SOAR Platform** is an enterprise-grade, lightweight, open-source cyber defense system designed to bridge the operational gap between **Intrusion Detection Systems (IDS)**, **Centralized SIEM Analytics**, and **Automated Incident Response (SOAR)**.

Traditional network security relies on standalone IDSs that flood security analysts with thousands of un-triaged text alerts without automated containment capabilities, leading to severe **alert fatigue** and multi-hour **Mean Time to Respond (MTTR)**. 

This platform eliminates manual response latency by marrying **Suricata 7.x** multi-threaded deep packet inspection with an **Autonomous SOAR Engine**. When high-severity attacks strike, the platform:
1. **Instantly Quarantines Malicious IPs** via dynamic firewall drop rules with a **Time-To-Live (TTL)** auto-expiration timer (preventing permanent lockouts).
2. **Enriches Indicators of Compromise (IOCs)** with real-time Threat Intelligence (AbuseIPDB, GeoIP, and ISP reputation).
3. **Generates Structured Forensic Evidence Dossiers** (`CASE-*.json`) capturing decoded payloads and protocol headers.
4. **Pushes Real-Time Alerts** to a high-visibility light-mode WebSocket SOC Operations Dashboard, Slack, and Discord.

---

## 🏗️ System Architecture

The architecture implements a decoupled 5-tier pipeline separating packet capture, log shipping, analytical indexing, automated containment, and analyst operations:

<div align="center">

![System Architecture](docs/assets/architecture_diagram.png)

</div>

### Architectural Tiers:
- **Tier 1 (Traffic Source & Ingress):** Monitors live network interfaces using `AF_PACKET` memory-mapped rings, target web services, and attack simulation harnesses.
- **Tier 2 (Intrusion Detection Layer):** Suricata 7.x multi-threaded engine inspects L3–L7 packets against custom MITRE-aligned `.rules` and outputs structured `eve.json` telemetry.
- **Tier 3 (Log Shipper & SIEM Storage):** Filebeat tails the EVE JSON stream, normalizes fields into the **Elastic Common Schema (ECS)**, and streams records into an **Elasticsearch 8.x** cluster.
- **Tier 4 (SOC Visualization & Hunting):** **Kibana 8.x** provides interactive SIEM dashboards, timeline analysis, top-N attacker rankings, and geographic threat maps.
- **Tier 5 (Autonomous SOAR Engine):** Event-driven FastAPI/WebSocket orchestrator executing sub-second containment playbooks, forensic evidence assembly, and analyst pardon controls.

---

## 🔄 Automated SOAR Workflow Lifecycle

<div align="center">

![SOAR Workflow Lifecycle](docs/assets/workflow_diagram.png)

</div>

When an incident occurs, the SOAR engine executes a closed-loop incident response lifecycle:
1. **Ingestion & Signature Match:** Suricata matches packet payloads against custom detection signatures and appends to `eve.json`.
2. **Async Tailing & Severity Evaluation:** SOAR async log consumer detects the alert; severity $\le 1$ triggers critical containment playbooks.
3. **Dynamic IP Quarantine:** The attacker's source IP is placed into the active defense blacklist with an auto-expiring TTL countdown (default: 300s).
4. **Threat Intelligence Enrichment:** IOC is checked against AbuseIPDB and GeoIP databases; reputation scores (0–100) and threat tags are appended.
5. **Forensic Evidence Capture:** A timestamped case file is generated containing raw network bytes, decoded URIs, and protocol headers.
6. **Live Notification & Analyst Override:** Real-time alert cards are pushed to analysts over WebSockets with one-click **Pardon / Unban** capability.

---

## 🎯 MITRE ATT&CK Threat Matrix

The platform includes engineered signatures covering the 6 major threat scenarios from the original research specification:

| # | Threat Scenario | MITRE Tactic & ID | Detection Signature Logic | Automated SOAR Action |
|:---:|---|---|---|---|
| **1** | **Network Reconnaissance** | Reconnaissance (`TA0043` / `T1595.001`) | TCP SYN/FIN/Xmas port sweep across $\ge 10$ ports in $\le 5$s (`sid:1000001`) | Enriches source IP profile, logs in SIEM, notifies SOC |
| **2** | **Authentication Attacks** | Credential Access (`TA0006` / `T1110.001`) | $\ge 5$ HTTP 401 Unauthorized responses or rapid SSH connection bursts (`sid:1000012`) | **Auto-Quarantines IP (300s TTL)** + Auth Alert |
| **3** | **Web Application Exploits** | Initial Access (`TA0001` / `T1190`) | SQLi (`UNION SELECT`, boolean logic), XSS tags, Directory Traversal (`/etc/passwd`) | **Auto-Quarantines IP (300s TTL)** + Dumps Forensic Dossier |
| **4** | **Malware C2 Communication** | Command & Control (`TA0011` / `T1071.001`) | Periodic HTTP POST heartbeats to `/api/v1/heartbeat` with beacon IDs (`sid:1000030`) | **Auto-Quarantines C2 Host** + Attaches Botnet Tag |
| **5** | **DNS Tunneling Exfiltration** | Exfiltration (`TA0010` / `T1048.003`) | Base64-encoded secret chunks in oversized subdomain queries $>50$ chars (`sid:1000040`) | Flags Malicious Domain, alerts SOC analysts |
| **6** | **Sensitive Data Exfiltration** | Exfiltration (`TA0010` / `T1048`) | Outbound transfer matching `BEGIN RSA PRIVATE KEY` or archive dumps (`sid:1000052`) | **Instant IP Quarantine** + Forensic Evidence Capture |

*Full technical details in [docs/MITRE_ATTACK_MAPPING.md](docs/MITRE_ATTACK_MAPPING.md).*

---

## 🚀 Quickstart Guide

> 📖 **Presenting or evaluating this project?** See our step-by-step [Master Presentation & Demo Guide (HOW_TO_RUN_AND_PRESENT.md)](HOW_TO_RUN_AND_PRESENT.md).

### Option A: 1-Click Launch on Windows (Recommended)
Simply double-click:
```cmd
START_PROJECT.bat
```
* Automatically verifies Python, starts the SOAR Engine and Target Portal, and opens your browser directly to **`http://localhost:8000`**!
* To stop services anytime: double-click **`STOP_PROJECT.bat`**.

---

### Option B: Standalone Terminal Mode (Linux / Mac / Windows)
Ideal for presentations, local development, and rapid testing without downloading multi-gigabyte container images.

```bash
# 1. Clone the repository
git clone https://github.com/sajeevnetworksolutions-lgtm/suricata-driven-siem-soar.git
cd suricata-driven-siem-soar

# 2. Install dependencies
pip install fastapi uvicorn requests flask jinja2 pydantic websockets reportlab

# 3. Launch the SOAR Engine & Interactive Target Portal
python run_local_demo.py
```

- **SOAR Operations Dashboard:** [http://localhost:8000](http://localhost:8000)
- **Interactive Threat Portal & Canary Lab:** [http://localhost:8080](http://localhost:8080)

---

### Option C: Full Docker Compose Cluster Mode
Launches the full containerized stack including Elasticsearch 8.x, Kibana 8.x, Suricata 7.x, Filebeat 8.x, the SOAR Engine, and the Target Service.

```bash
# Start all containers
docker compose up -d --build

# View container status
docker compose ps
```

- **Kibana SIEM Visual Dashboards:** [http://localhost:5601](http://localhost:5601)
- **SOAR Operations Dashboard:** [http://localhost:8000](http://localhost:8000)
- **Elasticsearch API:** [http://localhost:9200](http://localhost:9200)
- **Target Web Application:** [http://localhost:8080](http://localhost:8080)

---

## 🎮 Interactive Threat Portal & Canary Lab

Open **[http://localhost:8080](http://localhost:8080)** in your browser for an interactive one-click attack demonstration:

- 🔴 **"Trigger SQL Injection":** Injects `' UNION SELECT null,username,password FROM users--` $\rightarrow$ Extracted data is intercepted and the attacking IP is quarantined immediately.
- 🔴 **"Trigger Brute Force":** Fires rapid credential guessing bursts resulting in HTTP 401s.
- 🔴 **"Send C2 Beacon":** Sends malware check-in pulses.
- 🔴 **"Trigger XSS Attack":** Fires `<script>alert(1)</script>` injection payloads.
- 🔴 **"Exfiltrate RSA Key":** Transfers unencrypted private keys.
- 🪤 **"Click Honeypot Canary Trap Link":** A restricted lure link (`Confidential_Employee_Salaries_2026.xlsx`). Clicking this trips a silent tripwire that instantly logs the client IP and enforces active quarantine!

---

## 🧪 Automated Testing & Verification

### Run the Complete Automated Test Suite:
```bash
python run_and_test.py
```
This in-process runner starts all services, executes all 6 attack vectors and honeypot canary traps, verifies quarantine rules and threat intelligence lookups, and stops cleanly with a full evaluation report.

### Run Individual Threat Scenarios via CLI:
```bash
# Run Web Application Exploits
python attack_simulator/run_attack_suite.py --scenario 3

# Run Continuous Demo Loop (cycles every 5 seconds for live presentations)
python attack_simulator/run_attack_suite.py --loop --interval 5
```

### Offline PCAP Replay Evaluation:
We include a standard binary packet capture (`pcaps/suricata_attack_suite.pcap`) containing real Ethernet/IP/TCP/UDP frames for all 6 scenarios:
```bash
suricata -c config/suricata/suricata.yaml -r pcaps/suricata_attack_suite.pcap
```

---

## 📊 Performance Benchmarks

Evaluated under multi-vector attack scenarios against traditional SOC operational baselines:

```text
┌─────────────────────────────────┬──────────────────────┬──────────────────────┬────────────────────────────┐
│ Performance Metric              │ Traditional Manual   │ Suricata SIEM + SOAR │ Measured Improvement       │
├─────────────────────────────────┼──────────────────────┼──────────────────────┼────────────────────────────┤
│ Mean Time to Detect (MTTD)      │ 5 – 45 Minutes       │ < 85 Milliseconds    │ > 99.7% Latency Reduction  │
│ Mean Time to Respond (MTTR)     │ 30 Mins – 4 Hours    │ < 320 Milliseconds   │ Sub-Second Containment     │
│ Threat Intelligence Enrichment  │ 5 – 15 Minutes       │ < 180 Milliseconds   │ 100% Automated             │
│ Forensic Case Assembly          │ 1 – 2 Hours          │ < 45 Milliseconds    │ Instant JSON Case Dossier  │
│ False-Positive Ban Downtime     │ Permanent lockout    │ 300s TTL Auto-Unban  │ Self-Healing Network       │
│ Detection Coverage across 6 Cat │ ~40 – 60% Partial    │ 100% (6/6 Detected)  │ Full MITRE Alignment       │
└─────────────────────────────────┴──────────────────────┴──────────────────────┴────────────────────────────┘
```

*Comprehensive metrics in [docs/PERFORMANCE_BENCHMARKS.md](docs/PERFORMANCE_BENCHMARKS.md).*

---

## 📁 Repository Structure

```text
suricata-driven-siem-soar/
├── docker-compose.yml              # 6-container production orchestration stack
├── README.md                       # Master enterprise documentation & guide
├── LICENSE                         # Apache 2.0 open-source license
├── CONTRIBUTING.md                 # Contributor guidelines & PR workflow
├── .env.example                    # Documented configuration template
├── run_local_demo.py               # Standalone runner for zero-docker demo
├── run_and_test.py                 # Automated end-to-end verification runner
├── test_verification.py            # Diagnostic test suite
├── test_live_all.py                # Multi-attack button verification script
├── generate_detailed_synopsis_pdf.py # High-res ReportLab PDF compiler
├── generate_diagrams.py            # Matplotlib architecture & workflow visualizer
├── generate_sample_pcap.py         # Pure-Python PCAP binary generator
├── config/
│   ├── suricata/
│   │   ├── suricata.yaml           # Multi-threaded IDS engine & EVE output
│   │   └── rules/                  # Custom MITRE ATT&CK detection rulesets
│   │       ├── recon.rules         # T1595: Port scanning & network sweeps
│   │       ├── auth_bruteforce.rules # T1110: SSH & HTTP login brute force
│   │       ├── web_attacks.rules   # T1190: SQLi, XSS, Path Traversal
│   │       ├── malware_c2.rules    # T1071: C2 beacons & scanner agents
│   │       ├── dns_exfil.rules     # T1048.003: DNS tunneling queries
│   │       └── data_exfil.rules    # T1048: Private keys & database dumps
│   ├── filebeat/
│   │   └── filebeat.yml            # ECS event parser & Elasticsearch pipeline
│   └── kibana/
│       └── dashboards/
│           └── suricata_siem_dashboards.ndjson # Instant 1-click Kibana import
├── soar_engine/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app.py                      # FastAPI REST API & WebSocket broadcaster
│   ├── engine.py                   # Async EVE JSON log tailer & playbook runner
│   ├── models.py                   # Pydantic data schemas (Incidents, Bans)
│   ├── config.py                   # Response policies & TTL configuration
│   ├── playbooks/
│   │   ├── ip_block.py             # Dynamic IP quarantine & TTL unban manager
│   │   ├── threat_intel.py         # AbuseIPDB & GeoIP reputation enricher
│   │   ├── forensic_dump.py        # Case dossier generator (CASE-*.json)
│   │   └── notification.py         # Discord & Slack alert dispatcher
│   ├── static/
│   │   └── index.html              # Dark-mode SOC Web Operations Center
│   └── data/
│       └── forensics/
│           └── sample_case_dossier.json # Example evidentiary case snapshot
├── target_service/
│   ├── Dockerfile
│   └── app.py                      # Interactive Attack Portal & Honeypot Lab
├── attack_simulator/
│   ├── requirements.txt
│   ├── run_attack_suite.py         # Master CLI threat generator
│   └── scenarios/                  # Modular Python attack scripts (1-6)
├── pcaps/
│   └── suricata_attack_suite.pcap  # Replayable raw Ethernet/IP/TCP/UDP capture
└── docs/
    ├── PROJECT_SYNOPSIS.md         # Formal academic synopsis & design report
    ├── ARCHITECTURE.md             # In-depth architectural specifications
    ├── SOAR_PLAYBOOKS.md           # SOC standard operating procedures
    ├── MITRE_ATTACK_MAPPING.md     # Complete MITRE ATT&CK signature matrix
    ├── API_REFERENCE.md            # REST & WebSocket API reference
    ├── PERFORMANCE_BENCHMARKS.md   # Empirical latency & throughput metrics
    ├── Suricata_SIEM_SOAR_Project_Synopsis.pdf # 4-page design PDF with diagrams
    └── assets/
        ├── architecture_diagram.png # 300 DPI system block diagram
        └── workflow_diagram.png     # 300 DPI SOAR lifecycle diagram
```

---

## 📚 Documentation Suite

| Document | Description |
|---|---|
| 📄 **[docs/PROJECT_SYNOPSIS.md](docs/PROJECT_SYNOPSIS.md)** | Formal academic and technical synopsis document. |
| 📑 **[docs/Suricata_SIEM_SOAR_Project_Synopsis.pdf](docs/Suricata_SIEM_SOAR_Project_Synopsis.pdf)** | Ready-to-print 4-page technical design report with diagrams. |
| 🗺️ **[docs/MITRE_ATTACK_MAPPING.md](docs/MITRE_ATTACK_MAPPING.md)** | Signature IDs, MITRE techniques, and detection rules. |
| 🔌 **[docs/API_REFERENCE.md](docs/API_REFERENCE.md)** | Complete REST and WebSocket API documentation. |
| 📈 **[docs/PERFORMANCE_BENCHMARKS.md](docs/PERFORMANCE_BENCHMARKS.md)** | Latency, throughput, and resource utilization benchmarks. |
| 🛡️ **[docs/SOAR_PLAYBOOKS.md](docs/SOAR_PLAYBOOKS.md)** | SOC standard operating procedures & response playbooks. |

---

## ⚖️ License

This project is licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Developed with ❤️ by Sajeev Network Solutions**  
*Empowering Security Operations Centers with Open-Source Autonomous Defense.*

</div>
