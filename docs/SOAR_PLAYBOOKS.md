# SOAR Incident Response Playbooks

This document outlines the standard operating procedures and automated playbooks triggered by the SOAR engine upon detecting security events.

---

## Playbook 1: Automated IP Quarantine & Containment (`playbook_ip_block`)
- **Trigger**: Any Alert with Severity 1 (Critical) or repeated Severity 2 (High) within 15 seconds.
- **Workflow**:
  1. Parse attacker IP (`src_ip`).
  2. Check if IP is in private whitelist or default gateway.
  3. Apply network drop rule via iptables / firewall API.
  4. Schedule automatic TTL expiration timer (default: 300 seconds).
  5. Log containment action with timestamp to immutable audit ledger.
  6. Broadcast live `QUARANTINE_ACTIVE` notification to SOC dashboard.

---

## Playbook 2: Threat Intelligence Enrichment (`playbook_threat_intel`)
- **Trigger**: Every inbound or outbound alert.
- **Workflow**:
  1. Extract target IOC (IP, domain name, payload hash).
  2. Query live Threat Intel APIs (AbuseIPDB, VirusTotal, AlienVault OTX) or cached IOC DB.
  3. Extract Reputation Score (0–100), Country, ISP, and Abuse Confidence Score.
  4. Attach enrichment profile to the incident ticket.

---

## Playbook 3: High-Severity Incident Notification (`playbook_notification`)
- **Trigger**: Severity 1 & 2 incidents.
- **Workflow**:
  1. Construct rich JSON embed with MITRE ATT&CK tags, source/destination IPs, ports, and payload snippets.
  2. Dispatch payload to Slack, Discord, or SIEM webhook.
  3. Log delivery status in the execution log.

---

## Playbook 4: Automated Forensic Dossier Generation (`playbook_forensic_dump`)
- **Trigger**: Web application exploit attempts, C2 beaconing, or data exfiltration events.
- **Workflow**:
  1. Extract full raw EVE JSON event, decoded payload strings, and protocol headers.
  2. Generate unique Case ID: `CASE-YYYYMMDDHHMMSS-<UID>`.
  3. Write case file into `/app/data/forensics/<CASE_ID>.json`.
  4. Link case file to analyst dashboard.
