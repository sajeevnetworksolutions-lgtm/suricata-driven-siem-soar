import os
import json
import uuid
import asyncio
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

from config import config
from models import IncidentAlert, BanRecord, PlaybookExecutionLog, SOARStats, ThreatIntel
from playbooks.threat_intel import enrich_ip
from playbooks.ip_block import ip_blocker
from playbooks.notification import send_incident_notification
from playbooks.forensic_dump import create_forensic_dossier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("soar.engine")

class SOAREngine:
    def __init__(self):
        self.incidents: List[IncidentAlert] = []
        self.audit_logs: List[PlaybookExecutionLog] = []
        self.stats = SOARStats()
        self.websocket_subscribers: List[asyncio.Queue] = []
        os.makedirs(config.DATA_DIR, exist_ok=True)

    async def broadcast_event(self, event_type: str, data: Any):
        """Broadcast real-time events to all connected SOC analysts on WebSockets."""
        payload = json.dumps({"type": event_type, "timestamp": datetime.utcnow().isoformat(), "data": data})
        for queue in self.websocket_subscribers:
            try:
                await queue.put(payload)
            except Exception:
                pass

    def record_playbook_action(self, playbook_name: str, target_ip: str, action_type: str, status: str, details: Dict[str, Any], alert_id: Optional[str] = None):
        log_entry = PlaybookExecutionLog(
            id=f"PB-{uuid.uuid4().hex[:8]}",
            timestamp=datetime.utcnow().isoformat(),
            playbook_name=playbook_name,
            target_ip=target_ip,
            trigger_alert_id=alert_id,
            action_type=action_type,
            status=status,
            details=details
        )
        self.audit_logs.insert(0, log_entry)
        self.stats.total_playbooks_executed += 1

    async def handle_alert_event(self, eve_event: Dict[str, Any]):
        """Evaluate an alert event against SOAR playbooks."""
        self.stats.total_alerts_detected += 1
        alert_info = eve_event.get("alert", {})
        severity = alert_info.get("severity", 3)
        src_ip = eve_event.get("src_ip", "0.0.0.0")
        dest_ip = eve_event.get("dest_ip", "0.0.0.0")
        signature = alert_info.get("signature", "Unknown Security Alert")
        category = alert_info.get("category", "General Security Event")
        
        metadata = alert_info.get("metadata", {})
        mitre_tactic = metadata.get("mitre_tactic_id", ["TA0000"])[0] if isinstance(metadata.get("mitre_tactic_id"), list) else "N/A"
        mitre_technique = metadata.get("mitre_technique_id", ["T0000"])[0] if isinstance(metadata.get("mitre_technique_id"), list) else "N/A"

        if severity == 1:
            self.stats.critical_alerts += 1
        elif severity == 2:
            self.stats.high_alerts += 1

        # 1. Playbook: Threat Intelligence Enrichment
        intel = enrich_ip(src_ip)

        raw_ts = eve_event.get("timestamp")
        event_ts = raw_ts if raw_ts else datetime.utcnow().isoformat()

        incident = IncidentAlert(
            id=str(uuid.uuid4()),
            timestamp=event_ts,
            src_ip=src_ip,
            src_port=eve_event.get("src_port", 0),
            dest_ip=dest_ip,
            dest_port=eve_event.get("dest_port", 0),
            proto=eve_event.get("proto", "TCP"),
            signature=signature,
            category=category,
            severity=severity,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            raw_event=eve_event,
            threat_intel=intel
        )
        
        self.incidents.insert(0, incident)
        if len(self.incidents) > 500:
            self.incidents.pop()

        self.record_playbook_action(
            playbook_name="ThreatIntelEnrichment",
            target_ip=src_ip,
            action_type="THREAT_INTEL",
            status="SUCCESS",
            details={"score": intel.reputation_score, "country": intel.country, "isp": intel.isp},
            alert_id=incident.id
        )

        actions_summary = []

        # 2. Playbook: Automated IP Quarantine (if severity meets policy threshold)
        if config.AUTO_BAN_ENABLED and severity <= config.BAN_THRESHOLD_SEVERITY:
            ban_rec = ip_blocker.ban_ip(
                ip=src_ip,
                reason=f"Automated SOAR Quarantine: {signature}",
                signature=signature,
                severity=severity,
                ttl_seconds=config.BAN_TTL_SECONDS
            )
            self.stats.automated_containments += 1
            actions_summary.append(f"Quarantined {src_ip} ({config.BAN_TTL_SECONDS}s TTL)")
            
            self.record_playbook_action(
                playbook_name="AutoIPQuarantine",
                target_ip=src_ip,
                action_type="BAN",
                status="SUCCESS",
                details={"ttl": config.BAN_TTL_SECONDS, "expires_at": ban_rec.expires_at},
                alert_id=incident.id
            )

        # 3. Playbook: Automated Forensic Case File
        case_id = create_forensic_dossier(incident)
        actions_summary.append(f"Forensic Case {case_id}")
        self.record_playbook_action(
            playbook_name="ForensicCollector",
            target_ip=src_ip,
            action_type="FORENSIC_DUMP",
            status="SUCCESS",
            details={"case_id": case_id},
            alert_id=incident.id
        )

        # 4. Playbook: Webhook / SOC Notification
        action_str = " | ".join(actions_summary) if actions_summary else "Logged & Enriched"
        send_incident_notification(incident, action_str)

        # Update stats
        self.stats.active_banned_ips = len(ip_blocker.get_all_active_bans())

        # Real-time WebSocket Broadcast
        await self.broadcast_event("NEW_INCIDENT", incident.dict())
        await self.broadcast_event("STATS_UPDATE", self.stats.dict())

    async def tail_eve_log(self):
        """Asynchronously stream and monitor Suricata EVE JSON log file in real time."""
        logger.info(f"[*] SOAR Engine monitoring EVE log at: {config.EVE_LOG_PATH}")
        
        while not os.path.exists(config.EVE_LOG_PATH):
            logger.info("Waiting for Suricata eve.json log file to be created...")
            await asyncio.sleep(2)

        with open(config.EVE_LOG_PATH, "r") as f:
            # Seek to end of file
            f.seek(0, os.SEEK_END)
            
            while True:
                line = f.readline()
                if line:
                    try:
                        self.stats.total_events_processed += 1
                        event = json.loads(line.strip())
                        if event.get("event_type") == "alert":
                            await self.handle_alert_event(event)
                    except Exception as e:
                        logger.error(f"Error processing EVE event: {e}")
                else:
                    await asyncio.sleep(0.2)

soar_engine = SOAREngine()
