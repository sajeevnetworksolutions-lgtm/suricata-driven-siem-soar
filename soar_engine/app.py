import os
import io
import csv
import json
import asyncio
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, Response
from pydantic import BaseModel
import uvicorn

from engine import soar_engine, utc_now_iso, to_dict
from playbooks.ip_block import ip_blocker
from playbooks.threat_intel import enrich_ip
from config import config


@asynccontextmanager
async def lifespan(app: FastAPI):
    eve_task = asyncio.create_task(soar_engine.tail_eve_log())
    ttl_task = asyncio.create_task(soar_engine.monitor_ban_ttl())
    try:
        yield
    finally:
        eve_task.cancel()
        ttl_task.cancel()


app = FastAPI(
    title="Suricata SIEM + SOAR Automated Response Hub",
    version="2.0.0",
    lifespan=lifespan
)

# Mount static files for the SOC UI
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    return FileResponse(os.path.join(static_dir, "index.html"))


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


class PolicyUpdateRequest(BaseModel):
    auto_ban_enabled: bool
    ban_threshold_severity: int
    ban_ttl_seconds: int


@app.get("/api/policy")
async def get_policy():
    return {
        "auto_ban_enabled": config.AUTO_BAN_ENABLED,
        "ban_threshold_severity": config.BAN_THRESHOLD_SEVERITY,
        "ban_ttl_seconds": config.BAN_TTL_SECONDS
    }


@app.post("/api/policy")
async def update_policy(req: PolicyUpdateRequest):
    config.AUTO_BAN_ENABLED = req.auto_ban_enabled
    config.BAN_THRESHOLD_SEVERITY = max(1, min(3, req.ban_threshold_severity))
    config.BAN_TTL_SECONDS = max(30, min(86400, req.ban_ttl_seconds))
    soar_engine.record_playbook_action(
        playbook_name="PolicyConfigUpdate",
        target_ip="SYSTEM",
        action_type="POLICY_UPDATE",
        status="SUCCESS",
        details={
            "auto_ban_enabled": config.AUTO_BAN_ENABLED,
            "ban_threshold_severity": config.BAN_THRESHOLD_SEVERITY,
            "ban_ttl_seconds": config.BAN_TTL_SECONDS
        }
    )
    return {"status": "updated", **await get_policy()}


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
    await soar_engine.broadcast_event("MANUAL_BAN", to_dict(ban))
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


@app.post("/api/bans/{ip}/extend")
async def extend_ban_duration(ip: str):
    existing = ip_blocker.active_bans.get(ip)
    reason = existing.reason if existing else "Manual SOC Analyst Quarantine Extension (+600s)"
    sig = existing.associated_signature if existing else "Quarantine Extension"
    ban = ip_blocker.ban_ip(
        ip=ip,
        reason=reason,
        signature=sig,
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
    await soar_engine.broadcast_event("BAN_UPDATE", to_dict(ban))
    return {"status": "success", "ban": ban}


@app.get("/api/threat-intel/{ip}")
async def lookup_threat_intel(ip: str):
    return enrich_ip(ip)


@app.get("/api/audit-logs")
async def get_audit_logs():
    return soar_engine.audit_logs


@app.post("/api/webhook/alert")
async def incoming_siem_webhook(alert_payload: Dict[str, Any]):
    """Receives alerts from external SIEM / Kibana Watcher / Target App and triggers SOAR pipeline."""
    ts = alert_payload.get("timestamp") or utc_now_iso()
    mitre_tactic = alert_payload.get("mitre_tactic") or alert_payload.get("tactic")
    mitre_technique = alert_payload.get("mitre_technique") or alert_payload.get("technique")

    metadata: Dict[str, Any] = {}
    if mitre_tactic:
        metadata["mitre_tactic_id"] = [mitre_tactic]
    if mitre_technique:
        metadata["mitre_technique_id"] = [mitre_technique]

    eve_format = {
        "event_type": "alert",
        "timestamp": ts,
        "src_ip": alert_payload.get("src_ip", alert_payload.get("source", {}).get("ip", "127.0.0.1")),
        "src_port": alert_payload.get("src_port", alert_payload.get("source", {}).get("port", 0)),
        "dest_ip": alert_payload.get("dest_ip", alert_payload.get("destination", {}).get("ip", "127.0.0.1")),
        "dest_port": alert_payload.get("dest_port", alert_payload.get("destination", {}).get("port", 80)),
        "proto": alert_payload.get("proto", "TCP"),
        "payload": alert_payload.get("payload"),
        "alert": {
            "signature": alert_payload.get("rule_name", alert_payload.get("signature", "External SIEM Triggered Alert")),
            "severity": alert_payload.get("severity", 1),
            "category": alert_payload.get("category", "SIEM-Correlation"),
            "metadata": metadata
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
        "payload": "POST /api/v1/heartbeat HTTP/1.1\r\nHost: c2.apt29-adversary.org\r\nX-Beacon-Id: CS-0xDEADBEEF"
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
        "payload": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0lX..."
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
    now_iso = utc_now_iso()

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

    await soar_engine.handle_alert_event(eve_format)

    try:
        os.makedirs(os.path.dirname(config.EVE_LOG_PATH), exist_ok=True)
        with open(config.EVE_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(eve_format) + "\n")
    except Exception:
        pass

    containment = (
        f"Quarantined {spec['src_ip']} ({config.BAN_TTL_SECONDS}s TTL) + Case File Created"
        if (config.AUTO_BAN_ENABLED and spec["severity"] <= config.BAN_THRESHOLD_SEVERITY)
        else "Enriched + Forensic Case Created"
    )

    return {
        "status": "success",
        "scenario": scenario,
        "signature": spec["signature"],
        "attacker_ip": spec["src_ip"],
        "mitre_tactic": spec["mitre_tactic"],
        "mitre_technique": spec["mitre_technique"],
        "containment_action": containment
    }


@app.post("/api/incidents/clear")
async def clear_all_incidents():
    soar_engine.clear_state()
    await soar_engine.broadcast_event("STATS_UPDATE", to_dict(soar_engine.stats))
    return {"status": "cleared"}


@app.get("/api/case/{incident_id}")
async def download_case_dossier(incident_id: str):
    inc = next((i for i in soar_engine.incidents if i.id == incident_id), None)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident case not found")
    content = json.dumps(to_dict(inc), indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=case_{incident_id[:8]}.json"}
    )


@app.get("/api/export/csv")
async def export_incidents_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Incident ID", "Timestamp", "Severity", "Signature", "Category", "Source IP", "Source Port", "Dest IP", "Dest Port", "Protocol", "MITRE Tactic", "MITRE Technique"])
    for inc in soar_engine.incidents:
        writer.writerow([inc.id, inc.timestamp, inc.severity, inc.signature, inc.category, inc.src_ip, inc.src_port, inc.dest_ip, inc.dest_port, inc.proto, inc.mitre_tactic, inc.mitre_technique])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=suricata_soar_incidents.csv"}
    )


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
        if queue in soar_engine.websocket_subscribers:
            soar_engine.websocket_subscribers.remove(queue)


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)
