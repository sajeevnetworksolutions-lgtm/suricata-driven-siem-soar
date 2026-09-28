# PROJECT SYNOPSIS

## 1. PROJECT TITLE
**Suricata-Driven SIEM with Automated Incident Response and SOAR Integration**

---

## 2. DOMAIN & AREA OF STUDY
- **Domain:** Cyber Security & Information Assurance
- **Specialization:** Network Security Monitoring (NSM), Threat Hunting, Security Information & Event Management (SIEM), Security Orchestration, Automation, and Response (SOAR).

---

## 3. ABSTRACT
Modern enterprise networks face an unprecedented volume of sophisticated cyber threats ranging from stealthy reconnaissance and credential brute-forcing to complex web application exploitation, malware Command-and-Control (C2) communications, and data exfiltration. While traditional Intrusion Detection Systems (IDS) inspect network traffic and generate alerts, they operate in silos without centralized correlation, visual analytics, or rapid containment capabilities, causing critical alert fatigue among Security Operations Center (SOC) analysts.

This project presents an end-to-end, lightweight, open-source **Network Security Monitoring (NSM) and SOAR framework**. The proposed architecture integrates **Suricata IDS** for multi-threaded deep packet inspection, **EVE JSON** structured telemetry generation, **Filebeat** with Elastic Common Schema (ECS) normalization, **Elasticsearch** for high-volume indexing, **Kibana** for interactive SOC visualization, and an **Automated SOAR Engine**. The system autonomously detects cyber attacks, queries live Threat Intelligence feeds (AbuseIPDB/GeoIP), enforces dynamic IP quarantines with Time-To-Live (TTL) auto-cooling timers, generates structured forensic evidence dossiers, and streams real-time telemetry to security analysts.

---

## 4. PROBLEM STATEMENT & RESEARCH GAP
Traditional security monitoring architectures suffer from four critical deficiencies:
1. **Disconnected Tool Silos:** Standalone firewalls, IDS sensors, and application logs remain isolated, preventing end-to-end attack correlation.
2. **Alert Fatigue & Inaction:** Standalone IDSs merely log attacks without automated intervention, forcing analysts to manually sift through thousands of alerts.
3. **Slow Mean Time to Respond (MTTR):** In manual triage workflows, human response time (often measured in hours) allows attackers to exfiltrate critical assets before containment is achieved.
4. **Rigid Permanent IP Bans:** Legacy automated scripts apply permanent firewall bans, leading to accidental denial of service for legitimate traffic and self-lockouts due to IP spoofing.

**Research Gap Addressed:** The lack of an open-source, reproducible, lightweight pipeline connecting **Deep Packet Inspection $\rightarrow$ Centralized SIEM Analytics $\rightarrow$ Dynamic, Reversible SOAR Containment $\rightarrow$ Automated Forensic Evidence Collection**.

---

## 5. OBJECTIVES OF THE PROJECT
1. **Real-Time Threat Detection:** Implement multi-threaded network inspection using Suricata 7.x with custom detection signatures mapped to the **MITRE ATT&CK framework**.
2. **Standardized Log Shipping & ECS Mapping:** Ingest heterogeneous network events into Elasticsearch using Filebeat and Elastic Common Schema (ECS) standards.
3. **Centralized SOC Visibility:** Design real-time Kibana visual dashboards tracking attack trends, top attacker IPs, protocols, and severity distributions.
4. **Autonomous Incident Response (SOAR):** Build an event-driven automation engine that dynamically quarantines malicious source IPs, enriches IOCs with Threat Intelligence, and generates forensic dossiers without human latency.
5. **Safe Cooling-off Mitigation:** Implement Time-To-Live (TTL) auto-expiration timers for banned IPs to eliminate permanent denial-of-service risks.
6. **Multi-Vector Attack Validation:** Develop a modular Attack Simulation Suite and Honeypot Canary Trap Lab to empirically validate detection rate and response latency across 6 threat vectors.

---

## 6. PROPOSED SYSTEM ARCHITECTURE & DATA FLOW

```text
  [ Network Traffic / Attack Simulation / Canary Traps ]
                           │
                           ▼
             ┌───────────────────────────┐
             │    Suricata 7.x (NIDS)    │ <── Custom Rulesets (MITRE ATT&CK)
             └─────────────┬─────────────┘
                           │ (eve.json structured logs)
              ┌────────────┴────────────┐
              ▼                         ▼
  ┌───────────────────────┐ ┌──────────────────────────────────────┐
  │   Filebeat Shipper    │ │       Automated SOAR Engine          │
  └───────────┬───────────┘ └──────────────────┬───────────────────┘
              │ (ECS JSON over HTTP)           ├── 1. Dynamic IP Quarantine (TTL)
              ▼                                ├── 2. Threat Intel Enrichment
  ┌───────────────────────┐                    ├── 3. Forensic Case Dossier
  │     Elasticsearch     │                    ├── 4. Discord / Slack Alerts
  └───────────┬───────────┘                    └── 5. Live WebSocket SOC Web UI
              ▼
  ┌───────────────────────┐
  │      Kibana SOC       │
  │ (Dashboards & Search) │
  └───────────────────────┘
```

---

## 7. MODULE DESCRIPTION & THREAT VECTORS

### Module 1: Detection Engine (Suricata IDS)
- Implements custom `.rules` signatures with thresholding and protocol parsers covering:
  - **Reconnaissance & Port Scanning:** TCP SYN/FIN/Xmas sweeps, ICMP discovery.
  - **Authentication Attacks:** HTTP 401 Unauthorized bursts, SSH connection floods.
  - **Web Exploits:** SQL Injection (`UNION SELECT`, boolean logic), XSS tags, Directory Traversal (`/etc/passwd`), Command Injection.
  - **Malware & C2 Activity:** Periodic heartbeat beacons (`/api/v1/heartbeat`), suspicious scanners (`sqlmap`, `nikto`).
  - **DNS Threats:** High-entropy oversized query names (DNS data exfiltration/tunneling).
  - **Data Exfiltration:** Outbound RSA private keys and unencrypted database dumps.

### Module 2: Centralized Ingestion & SIEM (Filebeat + ELK)
- Parses `eve.json` records and maps fields into standard ECS fields (`source.ip`, `destination.port`, `event.severity`, `rule.name`).
- Provides centralized storage, indexing, and visualization via Kibana.

### Module 3: Automated Incident Response & SOAR Hub
- **IP Quarantine Playbook:** Enforces dynamic firewall bans for Severity 1 incidents with automated countdown timers (default: 300s TTL).
- **Threat Intel Playbook:** Queries AbuseIPDB / GeoIP to evaluate reputation scores (0–100) and ISP origin.
- **Forensics Playbook:** Automatically captures raw network payloads and headers into timestamped case files (`CASE-*.json`).
- **Analyst Web Portal:** Real-time WebSocket stream with one-click **Pardon / Unban** and **Manual Quarantine** controls.

### Module 4: Interactive Attack Simulator & Canary Trap Lab
- A web portal (`:8080`) providing interactive one-click attack triggers and honeypot canary tokens for live demonstration and validation.

---

## 8. HARDWARE & SOFTWARE SPECIFICATIONS

### Software Requirements:
- **Operating System:** Windows 10/11, Linux (Ubuntu 22.04+), or macOS
- **Programming Languages:** Python 3.11+, HTML5/JavaScript, YAML
- **IDS Engine:** Suricata 7.x
- **SIEM & Ingestion:** Elasticsearch 8.x, Kibana 8.x, Filebeat 8.x
- **SOAR Web Framework:** FastAPI, Uvicorn, WebSockets, Jinja2, Requests
- **Frontend Technologies:** Tailwind CSS (Dark Mode), Chart.js, FontAwesome
- **Containerization:** Docker & Docker Compose v2

### Hardware Requirements:
- **Processor:** Multi-core Intel Core i5/i7 or AMD Ryzen 5/7 (4+ physical cores recommended)
- **RAM:** 8 GB minimum (16 GB recommended for full Elastic cluster)
- **Storage:** 20 GB free disk space (SSD recommended)
- **Network:** Standard 1 Gbps Ethernet/Wi-Fi NIC

---

## 9. EXPECTED OUTCOMES & NOVEL CONTRIBUTIONS
1. **Zero-Latency Threat Neutralization:** Reduces Mean Time to Respond (MTTR) from minutes/hours to sub-second automatic containment.
2. **Self-Healing Network Defense:** Automatic expiration (TTL) of quarantine rules prevents permanent lockouts and accidental denial of service.
3. **Structured Forensic Preservation:** Automated creation of evidentiary case dossiers accelerates post-incident analysis.
4. **Cost-Effective & Open-Source:** Replaces costly enterprise solutions with a fully modular, transparent, and reproducible security platform.

---

## 10. CONCLUSION & FUTURE SCOPE
The **Suricata-Driven SIEM with SOAR Integration** demonstrates that enterprise-level threat detection, analytics, and automated response can be successfully unified using open-source technologies. 

**Future Enhancements:**
- Integrating **Machine Learning / Isolation Forests** for zero-day behavioral anomaly detection.
- Cloud-native expansion with Kubernetes DaemonSets and AWS VPC Traffic Mirroring.
- Automated generation of YARA rules and STIX/TAXII threat intelligence sharing.
