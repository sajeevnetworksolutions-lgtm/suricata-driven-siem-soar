import asyncio
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
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
