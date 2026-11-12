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
from ban_manager import WhitelistedIPError, InvalidIPError, BanCapacityError
from dossier import verify_chain
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
        await asyncio.gather(eve_task, ttl_task, return_exceptions=True)


app = FastAPI(
    title="Suricata SIEM + SOAR Automated Response Hub",
    version="2.1.0",
    lifespan=lifespan,
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
    ttl_seconds: int = 300


class PolicyUpdateRequest(BaseModel):
    auto_ban_enabled: bool
    ban_threshold_severity: int
    ban_ttl_seconds: int
    enable_ttl: Optional[bool] = None
    enable_threat_intel: Optional[bool] = None
    enable_ecs: Optional[bool] = None
    enable_forensics: Optional[bool] = None
    async_mode: Optional[bool] = None
    poll_interval_ms: Optional[int] = None


@app.get("/api/policy")
async def get_policy():
    return {
        "auto_ban_enabled": config.AUTO_BAN_ENABLED,
        "ban_threshold_severity": config.BAN_THRESHOLD_SEVERITY,
        "ban_ttl_seconds": config.BAN_TTL_SECONDS,
        "poll_interval_ms": config.POLL_INTERVAL_MS,
        "enable_ttl": config.ENABLE_TTL,
        "enable_threat_intel": config.ENABLE_THREAT_INTEL,
        "enable_ecs": config.ENABLE_ECS,
        "enable_forensics": config.ENABLE_FORENSICS,
        "async_mode": config.ASYNC_MODE,
    }


@app.post("/api/policy")
async def update_policy(req: PolicyUpdateRequest):
    config.AUTO_BAN_ENABLED = req.auto_ban_enabled
    config.BAN_THRESHOLD_SEVERITY = max(1, min(3, req.ban_threshold_severity))
    config.BAN_TTL_SECONDS = max(0, min(86400, req.ban_ttl_seconds))
    if req.enable_ttl is not None:
        config.ENABLE_TTL = req.enable_ttl
    if req.enable_threat_intel is not None:
        config.ENABLE_THREAT_INTEL = req.enable_threat_intel
    if req.enable_ecs is not None:
        config.ENABLE_ECS = req.enable_ecs
    if req.enable_forensics is not None:
        config.ENABLE_FORENSICS = req.enable_forensics
    if req.async_mode is not None:
        config.ASYNC_MODE = req.async_mode
    if req.poll_interval_ms is not None:
        config.POLL_INTERVAL_MS = max(10, min(10000, req.poll_interval_ms))

    soar_engine.record_playbook_action(
        playbook_name="PolicyConfigUpdate",
        target_ip="SYSTEM",
        action_type="POLICY_UPDATE",
        status="SUCCESS",
        details=await get_policy(),
    )
    return {"status": "updated", **await get_policy()}


@app.post("/api/bans")
async def manual_ban(req: ManualBanRequest):
    try:
        ban = ip_blocker.ban_ip(
            ip=req.ip,
            reason=req.reason,
            signature="Manual SOC Analyst Enforcement",
            severity=1,
            ttl_seconds=req.ttl_seconds,
            enable_ttl=config.ENABLE_TTL if req.ttl_seconds <= 0 else True,
        )
    except WhitelistedIPError as exc:
        soar_engine.record_playbook_action(
            playbook_name="ManualAnalystQuarantine",
            target_ip=req.ip,
            action_type="BAN",
            status="SKIPPED",
            details={"reason": str(exc)},
        )
        raise HTTPException(status_code=400, detail=str(exc))
    except InvalidIPError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except BanCapacityError as exc:
        raise HTTPException(status_code=429, detail=str(exc))

    soar_engine.record_playbook_action(
        playbook_name="ManualAnalystQuarantine",
        target_ip=ban.ip,
        action_type="BAN",
        status="SUCCESS",
        details={"reason": req.reason, "ttl": ban.ttl_seconds},
    )
    soar_engine.stats.active_banned_ips = len(ip_blocker.get_all_active_bans())
    await soar_engine.broadcast_event("BAN_ACTIVE", to_dict(ban))
    await soar_engine.broadcast_event("STATS_UPDATE", to_dict(soar_engine.stats))
    return {"status": "success", "ban": ban}


@app.delete("/api/bans/{ip}")
async def manual_unban(ip: str):
    try:
        ban = ip_blocker.pardon_ip(ip, reason="Manual SOC Analyst Pardon")
    except InvalidIPError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if not ban:
        raise HTTPException(status_code=404, detail="IP not actively banned")

    soar_engine.record_playbook_action(
        playbook_name="ManualAnalystPardon",
        target_ip=ban.ip,
        action_type="PARDON",
        status="SUCCESS",
        details={"ip": ban.ip, "status": ban.status.value, "pardoned_at": ban.pardoned_at},
    )
    soar_engine.stats.active_banned_ips = len(ip_blocker.get_all_active_bans())
    await soar_engine.broadcast_event("BAN_PARDONED", to_dict(ban))
    await soar_engine.broadcast_event("STATS_UPDATE", to_dict(soar_engine.stats))
    return {"status": "success", "message": f"IP {ban.ip} pardoned", "ban": ban}


@app.post("/api/bans/{ip}/extend")
async def extend_ban_duration(ip: str):
    existing = ip_blocker.active_bans.get(ip)
    reason = existing.reason if existing else "Manual SOC Analyst Quarantine Extension (+600s)"
    sig = existing.associated_signature if existing else "Quarantine Extension"
    try:
        ban = ip_blocker.ban_ip(
            ip=ip,
            reason=reason,
            signature=sig,
            severity=1,
            ttl_seconds=600,
            enable_ttl=True,
        )
    except (WhitelistedIPError, InvalidIPError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except BanCapacityError as exc:
        raise HTTPException(status_code=429, detail=str(exc))

    soar_engine.record_playbook_action(
        playbook_name="ManualQuarantineExtension",
        target_ip=ban.ip,
        action_type="BAN_EXTEND",
        status="SUCCESS",
        details={"ip": ban.ip, "new_ttl": 600},
    )
    await soar_engine.broadcast_event("BAN_ACTIVE", to_dict(ban))
    return {"status": "success", "ban": ban}


@app.get("/api/threat-intel/{ip}")
async def lookup_threat_intel(ip: str):
    return enrich_ip(ip)


@app.get("/api/audit-logs")
async def get_audit_logs():
    return soar_engine.audit_logs


@app.get("/api/metrics/latencies")
async def get_latency_metrics():
    return {
        "summary": to_dict(soar_engine.stats),
        "count": len(soar_engine.latency_records),
        "records": soar_engine.latency_records,
    }


@app.post("/api/metrics/reset")
async def reset_latency_metrics():
    soar_engine.reset_latency_metrics()
    return {"status": "reset"}


@app.get("/api/forensics/verify")
async def verify_forensics_chain():
    return verify_chain()


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
            "signature_id": alert_payload.get("sid") or alert_payload.get("signature_id"),
            "signature": alert_payload.get("rule_name", alert_payload.get("signature", "External SIEM Triggered Alert")),
            "severity": alert_payload.get("severity", 1),
            "category": alert_payload.get("category", "SIEM-Correlation"),
            "metadata": metadata,
        },
    }
    await soar_engine.handle_alert_event(eve_format)
    return {
        "status": "processed",
        "message": "Alert fed into SOAR automation pipeline",
        "latencies_ms": soar_engine.incidents[0].stage_latencies_ms if soar_engine.incidents else {},
    }


SIMULATED_ATTACKS = {
    "sqli": {
        "sid": 1000020,
        "signature": "SIEM-WEB: SQL Injection Attempt (UNION SELECT detected)",
        "category": "Web-Application-Attack",
        "severity": 1,
        "src_ip": "198.51.100.44",
        "src_port": 49210,
        "dest_ip": "172.28.0.10",
        "dest_port": 80,
        "proto": "TCP",
        "mitre_tactic": "TA0001 - Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "payload": "GET /search?q=1' UNION SELECT null,username,password FROM users-- HTTP/1.1",
    },
    "bruteforce": {
        "sid": 1000012,
        "signature": "SIEM-AUTH: Multiple HTTP 401 Unauthorized Responses (Web Brute Force)",
        "category": "Attempted-Admin",
        "severity": 1,
        "src_ip": "172.28.0.105",
        "src_port": 55432,
        "dest_ip": "172.28.0.10",
        "dest_port": 80,
        "proto": "TCP",
        "mitre_tactic": "TA0006 - Credential Access",
        "mitre_technique": "T1110.001 - Password Guessing",
        "payload": "POST /login HTTP/1.1 [5x 401 Unauthorized within 10s for user 'admin']",
    },
    "c2_beacon": {
        "sid": 1000030,
        "signature": "SIEM-C2: Emulated Malware C2 Heartbeat Beacon Detected",
        "category": "Trojan-Activity",
        "severity": 1,
        "src_ip": "172.28.0.200",
        "src_port": 4444,
        "dest_ip": "172.28.0.10",
        "dest_port": 80,
        "proto": "TCP",
        "mitre_tactic": "TA0011 - Command and Control",
        "mitre_technique": "T1071.001 - Web Protocols Beaconing",
        "payload": "POST /api/v1/heartbeat HTTP/1.1\r\nbeacon_id=BOTNET-HOST-092&cmd=POLL",
    },
    "portscan": {
        "sid": 1000001,
        "signature": "SIEM-RECON: Potential TCP SYN Port Scan Detected",
        "category": "Attempted-Recon",
        "severity": 1,
        "src_ip": "185.220.101.5",
        "src_port": 60100,
        "dest_ip": "172.28.0.10",
        "dest_port": 445,
        "proto": "TCP",
        "mitre_tactic": "TA0043 - Reconnaissance",
        "mitre_technique": "T1595.001 - Active Scanning: Port Scans",
        "payload": "TCP SYN sweep probe (10+ packets within 5s) flags: [S], win 1024",
    },
    "exfil": {
        "sid": 1000052,
        "signature": "SIEM-EXFIL: Unencrypted RSA Private Key Exfiltration Attempt",
        "category": "Policy-Violation",
        "severity": 1,
        "src_ip": "91.240.118.172",
        "src_port": 49912,
        "dest_ip": "172.28.0.10",
        "dest_port": 80,
        "proto": "TCP",
        "mitre_tactic": "TA0010 - Exfiltration",
        "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
        "payload": "POST /upload HTTP/1.1\r\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0lX...",
    },
    "dns_tunnel": {
        "sid": 1000040,
        "signature": "SIEM-DNS: Potential DNS Data Exfiltration / Tunneling (Oversized Query Name)",
        "category": "Data-Loss",
        "severity": 1,
        "src_ip": "45.154.255.89",
        "src_port": 53022,
        "dest_ip": "172.28.0.10",
        "dest_port": 53,
        "proto": "UDP",
        "mitre_tactic": "TA0010 - Exfiltration",
        "mitre_technique": "T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol (DNS)",
        "payload": "DNS Standard query A ZGF0YV9leGZpbHRyYXRpb25fdGVzdF9rZXk.tunnel.exfiltration.threat.internal (>50 B)",
    },
    "canary_trap": {
        "sid": 1000099,
        "signature": "SIEM-HONEYPOT: Sensitive Canary Token Trap File Triggered",
        "category": "Deception-Detection",
        "severity": 1,
        "src_ip": "172.16.55.101",
        "src_port": 51234,
        "dest_ip": "172.28.0.10",
        "dest_port": 8080,
        "proto": "HTTP",
        "mitre_tactic": "TA0007 - Discovery",
        "mitre_technique": "T1083 - File and Directory Discovery",
        "payload": "GET /canary/trap?target=Confidential_Employee_Salaries_2026.xlsx HTTP/1.1",
    },
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
        "_processed_by_api": True,
        "alert": {
            "signature_id": spec["sid"],
            "signature": spec["signature"],
            "severity": spec["severity"],
            "category": spec["category"],
            "metadata": {
                "mitre_tactic_id": [spec["mitre_tactic"]],
                "mitre_technique_id": [spec["mitre_technique"]],
            },
        },
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
        "containment_action": containment,
        "latencies_ms": soar_engine.incidents[0].stage_latencies_ms if soar_engine.incidents else {},
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
        headers={"Content-Disposition": f"attachment; filename=case_{incident_id[:8]}.json"},
    )


@app.get("/api/export/csv")
async def export_incidents_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "Incident ID",
            "Timestamp",
            "Severity",
            "Signature",
            "Category",
            "Source IP",
            "Source Port",
            "Dest IP",
            "Dest Port",
            "Protocol",
            "MITRE Tactic",
            "MITRE Technique",
        ]
    )
    for inc in soar_engine.incidents:
        writer.writerow(
            [
                inc.id,
                inc.timestamp,
                inc.severity,
                inc.signature,
                inc.category,
                inc.src_ip,
                inc.src_port,
                inc.dest_ip,
                inc.dest_port,
                inc.proto,
                inc.mitre_tactic,
                inc.mitre_technique,
            ]
        )

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=suricata_soar_incidents.csv"},
    )


@app.websocket("/ws/live")
async def websocket_live_stream(websocket: WebSocket):
    await websocket.accept()
    queue = asyncio.Queue()
    soar_engine.websocket_subscribers.append(queue)

    async def sender():
        while True:
            msg = await queue.get()
            await websocket.send_text(msg)

    async def receiver():
        while True:
            msg = await websocket.receive()
            if msg.get("type") == "websocket.disconnect":
                break

    send_task = asyncio.create_task(sender())
    recv_task = asyncio.create_task(receiver())
    try:
        done, pending = await asyncio.wait(
            [send_task, recv_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        for task in done:
            # Propagate non-disconnect errors if any, swallow WebSocketDisconnect
            exc = task.exception()
            if exc and not isinstance(exc, WebSocketDisconnect):
                raise exc
    except WebSocketDisconnect:
        pass
    finally:
        for task in (send_task, recv_task):
            if not task.done():
                task.cancel()
        if queue in soar_engine.websocket_subscribers:
            soar_engine.websocket_subscribers.remove(queue)


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)
