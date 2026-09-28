# Suricata-Driven SIEM + SOAR Platform Architecture

## 1. System Overview
The **Suricata-Driven SIEM with Automated Incident Response (SOAR)** is a network security monitoring, threat detection, and automated containment pipeline.

It integrates:
- **Suricata IDS**: High-performance multi-threaded network threat detection sensor.
- **EVE JSON Logging**: Standardized structured security telemetry containing layer 3–7 network metadata and signatures.
- **Filebeat Log Shipper**: Elastic Common Schema (ECS) normalization and resilient log forwarding.
- **Elasticsearch**: Centralized high-performance indexing and analytical search engine.
- **Kibana**: Interactive SOC visualization, timeline investigation, and threat hunting UI.
- **SOAR Engine**: Real-time event-driven automation framework that executes dynamic IP quarantines, threat intelligence enrichments, forensic case generation, and instant incident notifications.

---

## 2. End-to-End Data & Action Flow

```text
+-----------------------+
| Network Packet Stream |
+-----------+-----------+
            | (AF_PACKET / PCAP)
            v
+-----------------------+
|  Suricata IDS Engine  | <--- Custom Signatures (Recon, Brute-Force, Web, C2, DNS, Exfil)
+-----------+-----------+
            | (eve.json)
            +------------------------------------+
            |                                    |
            v                                    v
+-----------------------+            +-----------------------+
|   Filebeat Shipper    |            |      SOAR Engine      |
+-----------+-----------+            +-----------+-----------+
            | (ECS JSON over HTTP)               |
            v                                    +---> Automated IP Quarantine (iptables / TTL)
+-----------------------+                        +---> Threat Intel Enrichment (AbuseIPDB/VT)
|     Elasticsearch     |                        +---> Forensic Case Dossier (.json)
+-----------+-----------+                        +---> Discord / Slack Webhook Alerts
            |                                    +---> WebSocket Live SOC Dashboard (Port 8000)
            v
+-----------------------+
|      Kibana SOC       |
| (Dashboards / SIEM)   |
+-----------------------+
```

---

## 3. Threat Scenarios & Detection-to-Response Matrix

| Threat Scenario | Suricata Detection Technique | MITRE ATT&CK Mapping | Automated SOAR Action |
|---|---|---|---|
| **Network Reconnaissance** | TCP SYN/FIN/Xmas port sweep thresholding (`sid:1000001`) | **TA0043 / T1595** | Log, Enrich IP, Alert SOC |
| **Authentication Attacks** | HTTP 401 burst & SSH connection burst (`sid:1000010`) | **TA0006 / T1110** | **Quarantine Attacker IP (300s TTL)** |
| **Web App Exploitation** | SQLi (`UNION SELECT`), XSS, Path Traversal, Cmd Injection (`sid:1000020-25`) | **TA0001 / T1190** | **Quarantine Attacker IP**, Dump Forensic Dossier |
| **Malware C2 Communication** | HTTP POST heartbeat payload & malicious user agents (`sid:1000030`) | **TA0011 / T1071** | **Quarantine Host**, Notify SOC with High Severity |
| **DNS Threats / Tunneling** | High-entropy & oversized base64 query names (`sid:1000040`) | **TA0010 / T1048** | Flag Malicious Domain, Isolate Query Source |
| **Data Exfiltration** | Sensitive database backups & RSA key strings in transit (`sid:1000050`) | **TA0010 / T1048** | **Instant Connection Drop**, Open Forensic Investigation |
