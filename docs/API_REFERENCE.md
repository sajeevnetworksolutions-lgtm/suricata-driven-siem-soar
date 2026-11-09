# SOAR Platform API Reference Manual

The **Suricata SIEM + SOAR Platform** exposes RESTful endpoints and real-time WebSockets to facilitate SIEM integration, automated incident triage, dynamic quarantine enforcement, and threat intelligence enrichment.

---

## Base URLs
- **SOAR Operations & Containment API:** `http://localhost:8000`
- **Target Service & Threat Simulation API:** `http://localhost:8080`

---

## 🛡️ SOAR Engine Endpoints (:8000)

### 1. Retrieve System Statistics
Retrieves aggregate real-time metrics across telemetry, detections, active quarantines, and playbooks.

- **Endpoint:** `GET /api/stats`
- **Response:** `200 OK`
```json
{
  "total_events_processed": 1420,
  "total_alerts_detected": 12,
  "critical_alerts": 9,
  "high_alerts": 2,
  "active_banned_ips": 4,
  "total_playbooks_executed": 35,
  "automated_containments": 9
}
```

---

### 2. List Recent Incidents
Returns a reverse-chronological list of security incidents detected by Suricata and enriched by SOAR.

- **Endpoint:** `GET /api/incidents`
- **Query Params:** None (returns last 500 records)
- **Response:** `200 OK`
```json
[
  {
    "id": "88cc571c-f815-49bb-95c8-aef1c062813b",
    "timestamp": "2026-11-09T18:00:00.000Z",
    "src_ip": "192.168.1.150",
    "src_port": 49152,
    "dest_ip": "10.0.0.80",
    "dest_port": 80,
    "proto": "TCP",
    "signature": "SIEM-WEB: SQL Injection Attempt (UNION SELECT detected)",
    "category": "Web-Application-Attack",
    "severity": 1,
    "mitre_tactic": "TA0001",
    "mitre_technique": "T1190",
    "threat_intel": {
      "ip": "192.168.1.150",
      "reputation_score": 90,
      "is_malicious": true,
      "country": "CN",
      "isp": "Known APT Subnet",
      "abuse_confidence_score": 90,
      "tags": ["Exploit Scanner"]
    }
  }
]
```

---

### 3. Retrieve Active Quarantined IPs
Lists all IP addresses currently blocked under active defense policies.

- **Endpoint:** `GET /api/bans`
- **Response:** `200 OK`
```json
[
  {
    "ip": "192.168.1.150",
    "banned_at": "2026-11-09T18:00:00.000Z",
    "expires_at": "2026-11-09T18:05:00.000Z",
    "reason": "Automated SOAR Quarantine: SIEM-WEB: SQL Injection Attempt",
    "associated_signature": "SIEM-WEB: SQL Injection Attempt (UNION SELECT detected)",
    "severity": 1,
    "status": "ACTIVE"
  }
]
```

---

### 4. Manually Quarantine an Attacker IP
Allows a SOC analyst to manually enforce quarantine on an IP with customizable cooling-off duration.

- **Endpoint:** `POST /api/bans`
- **Content-Type:** `application/json`
- **Request Body:**
```json
{
  "ip": "198.51.100.77",
  "reason": "Observed reconnaissance sweep on database subnet",
  "ttl_seconds": 600
}
```
- **Response:** `200 OK`

---

### 5. Pardon / Unban an IP
Lifts quarantine restriction immediately before the TTL timer expires.

- **Endpoint:** `DELETE /api/bans/{ip}`
- **Response:** `200 OK`
```json
{
  "status": "success",
  "message": "IP 198.51.100.77 unbanned"
}
```

---

### 6. Threat Intelligence Lookup
Queries local heuristic threat cache and live reputation feeds (AbuseIPDB / VirusTotal).

- **Endpoint:** `GET /api/threat-intel/{ip}`
- **Response:** `200 OK`
```json
{
  "ip": "172.28.0.200",
  "reputation_score": 88,
  "is_malicious": true,
  "country": "RU",
  "country_code": "RU",
  "isp": "Bulletproof Host",
  "abuse_confidence_score": 88,
  "tags": ["C2 Server", "Botnet"]
}
```

---

### 7. SIEM / Webhook Alert Ingestion
Enables third-party systems (Kibana Watcher, Elastic Alerting, Grafana, Honeytokens) to trigger the SOAR pipeline.

- **Endpoint:** `POST /api/webhook/alert`
- **Content-Type:** `application/json`
- **Request Body:**
```json
{
  "src_ip": "203.0.113.88",
  "dest_ip": "10.0.0.80",
  "signature": "SIEM-AUTH: Multiple HTTP 401 Unauthorized Responses (Web Brute Force)",
  "category": "Attempted-Admin",
  "severity": 1,
  "timestamp": "2026-11-09T18:00:00Z"
}
```
- **Response:** `200 OK`

---

### 8. Live WebSocket Stream
Provides real-time event streaming for SOC analysts and live operations dashboards.

- **Endpoint:** `WS /ws/live`
- **Payload Events:**
  - `NEW_INCIDENT`: Emitted when an alert is detected and processed.
  - `STATS_UPDATE`: Emitted when metric counts update.
  - `MANUAL_BAN`: Emitted when an analyst enforces quarantine.
  - `MANUAL_UNBAN`: Emitted when an analyst pardons an IP.

---

## 🎯 Threat Simulation & Honeypot Endpoints (:8080)

| Endpoint | Method | Description |
|---|---|---|
| `/` | `GET` | Interactive Attack Portal & Honeypot Control Lab |
| `/login` | `POST` | Simulates failed authentication brute force (returns 401) |
| `/search?q={query}` | `GET` | Simulates query reflection for SQLi and XSS payloads |
| `/api/v1/heartbeat` | `POST` | Simulates periodic malware check-in beacon |
| `/upload` | `POST` | Simulates sensitive database and RSA key exfiltration |
| `/canary/trap?target={file}` | `GET` | Tripping restricted canary lure file alarm |
| `/api/trigger-test/{attack}` | `POST` | One-click triggers: `sqli`, `bruteforce`, `c2_beacon`, `xss`, `exfil` |
