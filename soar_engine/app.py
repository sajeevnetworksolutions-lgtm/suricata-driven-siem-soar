import asyncio
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, Response
import csv
import io
import json

from pydantic import BaseModel
from typing import Dict, Any, Optional
import uvicorn
import os

from engine import soar_engine
from playbooks.ip_block import ip_blocker
from playbooks.threat_intel import enrich_ip
from config import config

app = FastAPI(title="Suricata SIEM + SOAR Automated Response Hub", version="2.0.0")

# Mount static files for the SOC UI
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.on_event("startup")
async def startup_event():
    # Start background task to tail Suricata EVE logs
    asyncio.create_task(soar_engine.tail_eve_log())

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    return FileResponse("static/index.html")

@app.get("/api/stats")
async def get_stats():
    soar_engine.stats.active_banned_ips = len(ip_blocker.get_all_active_bans())
    return soar_engine.stats

@app.get("/api/incidents")
async def get_incidents():
    return soar_engine.incidents

@app.get("/api/bans")
async def get_active_bans():
    return ip_blocker.get_all_active_bans()

class ManualBanRequest(BaseModel):
    ip: str
    reason: str = "Manual SOC Analyst Quarantine"
    ttl_seconds: int = 600

@app.post("/api/bans")
async def manual_ban(req: ManualBanRequest):
    ban = ip_blocker.ban_ip(
        ip=req.ip,
        reason=req.reason,
        signature="Manual SOC Analyst Enforcement",
        severity=1,
        ttl_seconds=req.ttl_seconds
    )
    soar_engine.record_playbook_action(
        playbook_name="ManualAnalystQuarantine",
        target_ip=req.ip,
        action_type="BAN",
        status="SUCCESS",
        details={"reason": req.reason, "ttl": req.ttl_seconds}
    )
    await soar_engine.broadcast_event("MANUAL_BAN", ban.dict())
    return {"status": "success", "ban": ban}

@app.delete("/api/bans/{ip}")
async def manual_unban(ip: str):
    ban = ip_blocker.unban_ip(ip, reason="Manual SOC Analyst Pardon")
    if not ban:
        raise HTTPException(status_code=404, detail="IP not actively banned")
    
    soar_engine.record_playbook_action(
        playbook_name="ManualAnalystPardon",
        target_ip=ip,
        action_type="UNBAN",
        status="SUCCESS",
        details={"ip": ip}
    )
    await soar_engine.broadcast_event("MANUAL_UNBAN", {"ip": ip})
    return {"status": "success", "message": f"IP {ip} unbanned"}

@app.get("/api/threat-intel/{ip}")
async def lookup_threat_intel(ip: str):
    return enrich_ip(ip)

@app.get("/api/audit-logs")
async def get_audit_logs():
    return soar_engine.audit_logs

@app.post("/api/webhook/alert")
async def incoming_siem_webhook(alert_payload: Dict[str, Any]):
    """Receives alerts from external SIEM / Kibana Watcher and triggers SOAR pipeline."""
    ts = alert_payload.get("timestamp")
    if not ts:
        ts = datetime.utcnow().isoformat()

    eve_format = {
        "event_type": "alert",
        "timestamp": ts,
        "src_ip": alert_payload.get("src_ip", alert_payload.get("source", {}).get("ip", "127.0.0.1")),
        "src_port": alert_payload.get("src_port", alert_payload.get("source", {}).get("port", 0)),
        "dest_ip": alert_payload.get("dest_ip", alert_payload.get("destination", {}).get("ip", "127.0.0.1")),
        "dest_port": alert_payload.get("dest_port", alert_payload.get("destination", {}).get("port", 80)),
        "proto": alert_payload.get("proto", "TCP"),
        "alert": {
            "signature": alert_payload.get("rule_name", alert_payload.get("signature", "External SIEM Triggered Alert")),
            "severity": alert_payload.get("severity", 1),
            "category": alert_payload.get("category", "SIEM-Correlation")
        }
    }
    await soar_engine.handle_alert_event(eve_format)
    return {"status": "processed", "message": "Alert fed into SOAR automation pipeline"}

SIMULATED_ATTACKS = {
    "sqli": {
        "signature": "SIEM-WEB: SQL Injection Attempt (UNION SELECT detected)",
        "category": "Web-Application-Attack",
        "severity": 1,
        "src_ip": "198.51.100.44",
        "src_port": 49210,
        "dest_ip": "172.28.0.50",
        "dest_port": 8080,
        "proto": "TCP",
        "mitre_tactic": "TA0001 - Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "payload": "GET /api/v1/search?q=' UNION SELECT id,username,password_hash FROM users-- HTTP/1.1"
    },
    "bruteforce": {
        "signature": "SIEM-AUTH: Multiple SSH/HTTP 401 Unauthorized Responses (Credential Stuffing)",
        "category": "Attempted-Admin",
        "severity": 1,
        "src_ip": "203.0.113.88",
        "src_port": 55432,
        "dest_ip": "172.28.0.50",
        "dest_port": 22,
        "proto": "TCP",
        "mitre_tactic": "TA0006 - Credential Access",
        "mitre_technique": "T1110.001 - Password Guessing",
        "payload": "SSH-2.0-OpenSSH_8.2p1 auth failure for user 'root' from 203.0.113.88 port 55432"
    },
    "c2_beacon": {
        "signature": "SIEM-C2: Emulated Cobalt Strike C2 Heartbeat Beacon Detected",
        "category": "Trojan-Activity",
        "severity": 1,
        "src_ip": "195.123.245.12",
        "src_port": 4444,
        "dest_ip": "172.28.0.50",
        "dest_port": 443,
        "proto": "TCP",
        "mitre_tactic": "TA0011 - Command and Control",
        "mitre_technique": "T1071.001 - Web Protocols Beaconing",
        "payload": "POST /api/v1/heartbeat HTTP/1.1\\r\\nHost: c2.apt29-adversary.org\\r\\nX-Beacon-Id: CS-0xDEADBEEF"
    },
    "portscan": {
        "signature": "SIEM-RECON: High-Rate TCP SYN Port Sweep Detected (Nmap / Masscan)",
        "category": "Attempted-Information-Leak",
        "severity": 2,
        "src_ip": "185.220.101.5",
        "src_port": 60100,
        "dest_ip": "172.28.0.50",
        "dest_port": 445,
        "proto": "TCP",
        "mitre_tactic": "TA0043 - Reconnaissance",
        "mitre_technique": "T1595.001 - Active Scanning: Port Scans",
        "payload": "TCP SYN sweep probe flags: [S], seq 3829104, win 1024, length 0"
    },
    "exfil": {
        "signature": "SIEM-EXFIL: Unencrypted RSA Private Key Exfiltration Attempt",
        "category": "Policy-Violation",
        "severity": 1,
        "src_ip": "91.240.118.172",
        "src_port": 49912,
        "dest_ip": "172.28.0.50",
        "dest_port": 8443,
        "proto": "TCP",
        "mitre_tactic": "TA0010 - Exfiltration",
        "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
        "payload": "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0lX..."
    },
    "dns_tunnel": {
        "signature": "SIEM-DNS: DNS Tunneling Exfiltration via Oversized Base64 Query",
        "category": "Data-Loss",
        "severity": 1,
        "src_ip": "45.154.255.89",
        "src_port": 53022,
        "dest_ip": "172.28.0.50",
        "dest_port": 53,
        "proto": "UDP",
        "mitre_tactic": "TA0010 - Exfiltration",
        "mitre_technique": "T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol (DNS)",
        "payload": "DNS Standard query A 0x41.ZGF0YV9leGZpbHRyYXRpb25fdGVzdF9rZXk.exfil.darkops.io"
    },
    "canary_trap": {
        "signature": "SIEM-HONEYPOT: Sensitive Canary Token Trap File Triggered",
        "category": "Deception-Detection",
        "severity": 1,
        "src_ip": "172.16.55.101",
        "src_port": 51234,
        "dest_ip": "172.28.0.50",
        "dest_port": 8080,
        "proto": "HTTP",
        "mitre_tactic": "TA0007 - Discovery",
        "mitre_technique": "T1083 - File and Directory Discovery",
        "payload": "GET /canary/trap?target=Confidential_Employee_Salaries_2026.xlsx HTTP/1.1"
    }
}

@app.post("/api/simulate/{scenario}")
async def simulate_attack_scenario(scenario: str):
    if scenario not in SIMULATED_ATTACKS:
        raise HTTPException(status_code=400, detail=f"Unknown scenario. Choose from: {list(SIMULATED_ATTACKS.keys())}")
    
    spec = SIMULATED_ATTACKS[scenario]
    now_iso = datetime.utcnow().isoformat()
    
    eve_format = {
        "event_type": "alert",
        "timestamp": now_iso,
        "src_ip": spec["src_ip"],
        "src_port": spec["src_port"],
        "dest_ip": spec["dest_ip"],
        "dest_port": spec["dest_port"],
        "proto": spec["proto"],
        "payload": spec["payload"],
        "alert": {
            "signature": spec["signature"],
            "severity": spec["severity"],
            "category": spec["category"],
            "metadata": {
                "mitre_tactic_id": [spec["mitre_tactic"]],
                "mitre_technique_id": [spec["mitre_technique"]]
            }
        }
    }
    
    # Process through SOAR pipeline
    await soar_engine.handle_alert_event(eve_format)
    
    # Also log to file so EVE file reflects the event
    try:
        with open(config.EVE_LOG_PATH, "a") as f:
            f.write(json.dumps(eve_format) + "\\n")
    except Exception:
        pass
        
    return {
        "status": "success",
        "scenario": scenario,
        "signature": spec["signature"],
        "attacker_ip": spec["src_ip"],
        "mitre_tactic": spec["mitre_tactic"],
        "mitre_technique": spec["mitre_technique"],
        "containment_action": f"Quarantined {spec['src_ip']} (300s TTL) + Case File Created"
    }

@app.post("/api/incidents/clear")
async def clear_all_incidents():
    soar_engine.incidents.clear()
    soar_engine.audit_logs.clear()
    soar_engine.stats.total_alerts_detected = 0
    soar_engine.stats.critical_alerts = 0
    soar_engine.stats.high_alerts = 0
    await soar_engine.broadcast_event("STATS_UPDATE", soar_engine.stats.dict())
    return {"status": "cleared"}

@app.get("/api/export/csv")
async def export_incidents_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Incident ID", "Timestamp", "Severity", "Signature", "Category", "Source IP", "Source Port", "Dest IP", "Dest Port", "Protocol", "MITRE Tactic", "MITRE Technique"])
    for inc in soar_engine.incidents:
        writer.writerow([inc.id, inc.timestamp, inc.severity, inc.signature, inc.category, inc.src_ip, inc.src_port, inc.dest_ip, inc.dest_port, inc.proto, inc.mitre_tactic, inc.mitre_technique])
    
    csv_data = output.getvalue()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=suricata_soar_incidents.csv"}
    )

@app.post("/api/bans/{ip}/extend")
async def extend_ban_duration(ip: str):
    ban = ip_blocker.ban_ip(
        ip=ip,
        reason="Manual SOC Analyst Quarantine Extension (+600s)",
        signature="Quarantine Extension",
        severity=1,
        ttl_seconds=600
    )
    soar_engine.record_playbook_action(
        playbook_name="ManualQuarantineExtension",
        target_ip=ip,
        action_type="BAN_EXTEND",
        status="SUCCESS",
        details={"ip": ip, "new_ttl": 600}
    )
    await soar_engine.broadcast_event("BAN_UPDATE", ban.dict())
    return {"status": "success", "ban": ban}

@app.websocket("/ws/live")
async def websocket_live_stream(websocket: WebSocket):
    await websocket.accept()
    queue = asyncio.Queue()
    soar_engine.websocket_subscribers.append(queue)
    try:
        while True:
            msg = await queue.get()
            await websocket.send_text(msg)
    except WebSocketDisconnect:
        soar_engine.websocket_subscribers.remove(queue)

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)
