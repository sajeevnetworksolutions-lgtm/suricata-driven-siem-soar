# MITRE ATT&CK Framework Mapping & Detection Matrix

This document maps all threat scenarios, custom Suricata detection rules, and automated SOAR playbooks implemented in the platform to the globally recognized **MITRE ATT&CK Matrix for Enterprise**.

---

## 🗺️ Tactic & Technique Overview

```text
+---------------------+---------------------+---------------------+---------------------+---------------------+
| Reconnaissance      | Initial Access      | Credential Access   | Command & Control   | Exfiltration        |
| (TA0043)            | (TA0001)            | (TA0006)            | (TA0011)            | (TA0010)            |
+---------------------+---------------------+---------------------+---------------------+---------------------+
| • T1595.001         | • T1190             | • T1110.001         | • T1071.001         | • T1048.003         |
|   Port Scanning     |   Exploit Public    |   Password Guessing |   Web Protocols     |   DNS Tunneling     |
| • T1595.002         |   Facing App        | • T1110.003         | • T1095             | • T1048.002         |
|   Vulnerability     | • T1059.007         |   Password Spraying |   Non-Application   |   Exfil over Web    |
|   Scanning          |   JavaScript (XSS)  |                     |   Protocols         | • T1567             |
|                     | • T1083             |                     |                     |   Exfil to Cloud    |
|                     |   File Discovery    |                     |                     |   / Archive         |
+---------------------+---------------------+---------------------+---------------------+---------------------+
```

---

## 📋 Comprehensive Signature & Response Matrix

| SID | Rule Name | MITRE Tactic | MITRE Technique | Classtype | Detection Logic / Trigger Heuristic | Automated SOAR Action |
|:---:|---|---|---|---|---|---|
| **1000001** | `SIEM-RECON: Potential TCP SYN Port Scan Detected` | Reconnaissance (TA0043) | Active Scanning: Port Scanning (T1595.001) | `attempted-recon` | TCP SYN packet flag sweep across $\ge 10$ unique ports in $\le 5$s. | Enrich IP with Threat Intel, log in SIEM, flag in SOC |
| **1000002** | `SIEM-RECON: TCP NULL Scan Detected` | Reconnaissance (TA0043) | Active Scanning (T1595.001) | `attempted-recon` | Packets with no TCP flags set (`flags:0`). | Log reconnaissance attempt, alert analyst |
| **1000003** | `SIEM-RECON: TCP FIN Scan Detected` | Reconnaissance (TA0043) | Active Scanning (T1595.001) | `attempted-recon` | Packets with only FIN flag set (`flags:F,12`). | Log reconnaissance attempt, alert analyst |
| **1000004** | `SIEM-RECON: TCP Xmas Scan Detected` | Reconnaissance (TA0043) | Active Scanning (T1595.001) | `attempted-recon` | Packets with FIN, PSH, and URG flags set (`flags:FPU,12`). | Log reconnaissance attempt, alert analyst |
| **1000005** | `SIEM-RECON: ICMP Ping Sweep Detected` | Reconnaissance (TA0043) | Active Scanning (T1595.001) | `attempted-recon` | $\ge 8$ ICMP echo requests (type:8) within 4 seconds. | Log network mapping activity |
| **1000006** | `SIEM-RECON: Nmap Scripting Engine (NSE) User-Agent` | Reconnaissance (TA0043) | Vulnerability Scanning (T1595.002) | `attempted-recon` | HTTP User-Agent matching `Nmap Scripting Engine`. | Tag scanning host |
| **1000010** | `SIEM-AUTH: Potential SSH Brute Force Inbound Rate` | Credential Access (TA0006) | Brute Force: Password Guessing (T1110.001) | `attempted-admin` | $\ge 6$ inbound TCP SYN connections to port 22 within 15s. | **Quarantine Attacker IP (300s TTL)** |
| **1000011** | `SIEM-AUTH: Potential SSH Brute Force (Port 2222)` | Credential Access (TA0006) | Brute Force: Password Guessing (T1110.001) | `attempted-admin` | $\ge 6$ inbound connections to port 2222 within 15s. | **Quarantine Attacker IP (300s TTL)** |
| **1000012** | `SIEM-AUTH: Multiple HTTP 401 Unauthorized Responses` | Credential Access (TA0006) | Brute Force: Password Guessing (T1110.001) | `attempted-user` | $\ge 5$ HTTP 401 responses returned to destination IP in 10s. | **Quarantine Attacker IP (300s TTL)** + Auth Alert |
| **1000013** | `SIEM-AUTH: Automated Credential Tool User-Agent` | Credential Access (TA0006) | Brute Force (T1110.001) | `attempted-admin` | User-Agent regex matching `hydra`, `medusa`, `patator`, `crowbar`. | **Quarantine Attacker IP (300s TTL)** |
| **1000020** | `SIEM-WEB: SQL Injection Attempt (UNION SELECT detected)` | Initial Access (TA0001) | Exploit Public-Facing App (T1190) | `web-application-attack` | URI payload containing `union` followed by `select`. | **Quarantine Attacker IP** + Forensic Case Dossier |
| **1000021** | `SIEM-WEB: SQL Injection Attempt (Boolean / OR syntax)` | Initial Access (TA0001) | Exploit Public-Facing App (T1190) | `web-application-attack` | URI regex matching `' OR 1=1` or `' AND 1=1` syntax. | **Quarantine Attacker IP** + Forensic Case Dossier |
| **1000022** | `SIEM-WEB: Cross-Site Scripting (XSS) Tag Injection` | Initial Access (TA0001) | Command & Scripting Interpreter (T1059.007) | `web-application-attack` | URI matching `<script>` or encoded `%3Cscript`. | Flag XSS exploit, enrich IP profile |
| **1000023** | `SIEM-WEB: Cross-Site Scripting (XSS) Event Handler` | Initial Access (TA0001) | Command & Scripting Interpreter (T1059.007) | `web-application-attack` | URI regex matching `onerror=`, `onload=`, `javascript:`. | Flag XSS exploit, enrich IP profile |
| **1000024** | `SIEM-WEB: Directory / Path Traversal (etc/passwd)` | Initial Access (TA0001) | File and Directory Discovery (T1083) | `web-application-attack` | URI regex matching `../etc/passwd` or `win.ini`. | **Quarantine Attacker IP** + Forensic Case Dossier |
| **1000025** | `SIEM-WEB: OS Command Injection Attempt Detected` | Execution (TA0002) | Command & Scripting Interpreter (T1059) | `web-application-attack` | Shell pipe/command operators `; cat`, `| whoami`, `&& ls`. | **Quarantine Attacker IP** + Forensic Case Dossier |
| **1000030** | `SIEM-C2: Emulated Malware C2 Heartbeat Beacon Detected` | Command and Control (TA0011) | Application Layer Protocol: Web (T1071.001) | `trojan-activity` | HTTP POST to `/api/v1/heartbeat` with `beacon_id=` payload. | **Quarantine C2 IP** + Tag Botnet Node |
| **1000031** | `SIEM-C2: Malicious Web Scanner / Exploit Framework` | Reconnaissance (TA0043) | Active Scanning (T1595.002) | `attempted-recon` | Scanner User-Agents: `sqlmap`, `nikto`, `wpscan`, `gobuster`. | Flag scanner, enrich threat reputation |
| **1000033** | `SIEM-C2: Outbound Connection to Reverse Shell Port` | Command and Control (TA0011) | Non-Application Layer Protocol (T1095) | `trojan-activity` | Outbound TCP SYN to common reverse shell ports `4444, 5555, 1337`. | **Quarantine Host** + Critical Notification |
| **1000040** | `SIEM-DNS: Potential DNS Data Exfiltration / Tunneling` | Exfiltration (TA0010) | Exfiltration Over Alternative Protocol: DNS (T1048.003) | `bad-unknown` | DNS query name length exceeding 50 characters. | Flag malicious domain, isolate querying host |
| **1000041** | `SIEM-DNS: Encoded Data in DNS Request Header` | Exfiltration (TA0010) | Exfiltration Over Alternative Protocol: DNS (T1048.003) | `bad-unknown` | Base64/Hex character chunk ($\ge 30$ chars) in subdomain. | Flag malicious domain, isolate querying host |
| **1000050** | `SIEM-EXFIL: High Volume HTTP POST / Potential Exfil` | Exfiltration (TA0010) | Exfiltration Over Asymmetric Encrypted Channel (T1048.002) | `suspicious-traffic` | HTTP POST payload body containing `filename=` with $>5000$ bytes. | Alert SOC, dump payload capture |
| **1000051** | `SIEM-EXFIL: Outbound Transfer of Database or Archive` | Exfiltration (TA0010) | Exfiltration to Cloud Storage / Archive (T1567) | `suspicious-traffic` | Outbound URI matching `.sql`, `.tar.gz`, `.dump`, `.kdbx`. | Flag exfiltration attempt, alert SOC |
| **1000052** | `SIEM-EXFIL: Unencrypted RSA Private Key Exfiltration` | Exfiltration (TA0010) | Exfiltration Over Asymmetric Encrypted Channel (T1048) | `policy-violation` | Packet payload matching `-----BEGIN RSA PRIVATE KEY-----`. | **Quarantine Source IP** + Dump Forensic Evidence |
