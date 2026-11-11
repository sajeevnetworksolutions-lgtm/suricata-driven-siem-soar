import os
import time
import json
import uuid
import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from config import config
from models import IncidentAlert, BanRecord, PlaybookExecutionLog, SOARStats
from playbooks.threat_intel import enrich_ip
from playbooks.ip_block import ip_blocker
from playbooks.notification import send_incident_notification
from playbooks.forensic_dump import create_forensic_dossier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("soar.engine")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def to_dict(obj: Any) -> Dict[str, Any]:
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    return obj.dict()


def infer_mitre_from_signature(signature: str, category: str) -> Tuple[str, str]:
    """Infer MITRE ATT&CK tactic and technique when explicit Suricata metadata is omitted."""
    sig_lower = (signature or "").lower()
    cat_lower = (category or "").lower()

    if "sql" in sig_lower or "union select" in sig_lower:
        return "TA0001 - Initial Access", "T1190 - Exploit Public-Facing Application"
    if "xss" in sig_lower or "script" in sig_lower or "command injection" in sig_lower:
        return "TA0002 - Execution", "T1059 - Command and Scripting Interpreter"
    if "brute" in sig_lower or "401" in sig_lower or "ssh" in sig_lower or "auth" in sig_lower:
        return "TA0006 - Credential Access", "T1110.001 - Password Guessing"
    if "c2" in sig_lower or "heartbeat" in sig_lower or "beacon" in sig_lower or "trojan" in cat_lower:
        return "TA0011 - Command and Control", "T1071.001 - Web Protocols Beaconing"
    if "dns" in sig_lower and ("tunnel" in sig_lower or "exfil" in sig_lower):
        return "TA0010 - Exfiltration", "T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol (DNS)"
    if "exfil" in sig_lower or "rsa" in sig_lower or "private key" in sig_lower:
        return "TA0010 - Exfiltration", "T1048 - Exfiltration Over Alternative Protocol"
    if "canary" in sig_lower or "honeypot" in sig_lower or "traversal" in sig_lower:
        return "TA0007 - Discovery", "T1083 - File and Directory Discovery"
    if "scan" in sig_lower or "sweep" in sig_lower or "recon" in sig_lower:
        return "TA0043 - Reconnaissance", "T1595.001 - Active Scanning: Port Scans"

    return "TA0043 - Reconnaissance", "T1595 - Active Scanning"


class SOAREngine:
    def __init__(self):
        self.incidents: List[IncidentAlert] = []
        self.audit_logs: List[PlaybookExecutionLog] = []
        self.stats = SOARStats()
        self.websocket_subscribers: List[asyncio.Queue] = []
        self._latency_samples: List[float] = []
        os.makedirs(config.DATA_DIR, exist_ok=True)
        self._load_state()

    def _load_state(self):
        try:
            if os.path.exists(config.INCIDENTS_FILE):
                with open(config.INCIDENTS_FILE, "r", encoding="utf-8") as f:
                    raw_incidents = json.load(f)
                self.incidents = [IncidentAlert(**item) for item in raw_incidents[:200]]

            if os.path.exists(config.AUDIT_FILE):
                with open(config.AUDIT_FILE, "r", encoding="utf-8") as f:
                    raw_audits = json.load(f)
                self.audit_logs = [PlaybookExecutionLog(**item) for item in raw_audits[:300]]

            self._recompute_stats()
        except Exception as e:
            logger.debug(f"Could not restore persisted SOAR state: {e}")

    def _save_state(self):
        try:
            os.makedirs(config.DATA_DIR, exist_ok=True)
            with open(config.INCIDENTS_FILE, "w", encoding="utf-8") as f:
                json.dump([to_dict(i) for i in self.incidents[:200]], f, indent=2)
            with open(config.AUDIT_FILE, "w", encoding="utf-8") as f:
                json.dump([to_dict(a) for a in self.audit_logs[:300]], f, indent=2)
        except Exception as e:
            logger.debug(f"Could not save SOAR state: {e}")

    def _recompute_stats(self):
        self.stats.total_alerts_detected = len(self.incidents)
        self.stats.critical_alerts = sum(1 for i in self.incidents if i.severity == 1)
        self.stats.high_alerts = sum(1 for i in self.incidents if i.severity == 2)
        self.stats.total_playbooks_executed = len(self.audit_logs)
        self.stats.automated_containments = sum(1 for a in self.audit_logs if a.action_type == "BAN" and a.playbook_name == "AutoIPQuarantine")
        self.stats.active_banned_ips = len(ip_blocker.get_all_active_bans())
        if self.stats.total_events_processed < self.stats.total_alerts_detected:
            self.stats.total_events_processed = self.stats.total_alerts_detected

    async def broadcast_event(self, event_type: str, data: Any):
        """Broadcast real-time events to all connected SOC analysts on WebSockets."""
        payload = json.dumps({"type": event_type, "timestamp": utc_now_iso(), "data": data})
        for queue in list(self.websocket_subscribers):
            try:
                await queue.put(payload)
            except Exception:
                pass

    def record_playbook_action(
        self,
        playbook_name: str,
        target_ip: str,
        action_type: str,
        status: str,
        details: Dict[str, Any],
        alert_id: Optional[str] = None,
        persist: bool = True
    ):
        log_entry = PlaybookExecutionLog(
            id=f"PB-{uuid.uuid4().hex[:8]}",
            timestamp=utc_now_iso(),
            playbook_name=playbook_name,
            target_ip=target_ip,
            trigger_alert_id=alert_id,
            action_type=action_type,
            status=status,
            details=details
        )
        self.audit_logs.insert(0, log_entry)
        if len(self.audit_logs) > 500:
            self.audit_logs.pop()
        self.stats.total_playbooks_executed += 1
        if persist:
            self._save_state()

    def clear_state(self):
        self.incidents.clear()
        self.audit_logs.clear()
        self._latency_samples.clear()
        self.stats.total_alerts_detected = 0
        self.stats.critical_alerts = 0
        self.stats.high_alerts = 0
        self.stats.total_playbooks_executed = 0
        self.stats.automated_containments = 0
        self._save_state()

    async def handle_alert_event(self, eve_event: Dict[str, Any]):
        """Evaluate an alert event against SOAR playbooks and measure containment latency."""
        t_start = time.perf_counter()

        self.stats.total_alerts_detected += 1
        if self.stats.total_events_processed < self.stats.total_alerts_detected:
            self.stats.total_events_processed += 1

        alert_info = eve_event.get("alert", {})
        severity = alert_info.get("severity", 3)
        src_ip = eve_event.get("src_ip", "0.0.0.0")
        dest_ip = eve_event.get("dest_ip", "0.0.0.0")
        signature = alert_info.get("signature", "Unknown Security Alert")
        category = alert_info.get("category", "General Security Event")

        metadata = alert_info.get("metadata", {})
        raw_tactic = metadata.get("mitre_tactic_id")
        raw_tech = metadata.get("mitre_technique_id")
        mitre_tactic = raw_tactic[0] if isinstance(raw_tactic, list) and raw_tactic else None
        mitre_technique = raw_tech[0] if isinstance(raw_tech, list) and raw_tech else None

        if not mitre_tactic or not mitre_technique:
            inferred_tactic, inferred_tech = infer_mitre_from_signature(signature, category)
            mitre_tactic = mitre_tactic or inferred_tactic
            mitre_technique = mitre_technique or inferred_tech

        if severity == 1:
            self.stats.critical_alerts += 1
        elif severity == 2:
            self.stats.high_alerts += 1

        # 1. Playbook: Threat Intelligence Enrichment
        intel = enrich_ip(src_ip)

        raw_ts = eve_event.get("timestamp")
        event_ts = raw_ts if raw_ts else utc_now_iso()

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
            payload=eve_event.get("payload"),
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
            alert_id=incident.id,
            persist=False
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
                alert_id=incident.id,
                persist=False
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
            alert_id=incident.id,
            persist=False
        )

        # 4. Playbook: Webhook / SOC Notification
        action_str = " | ".join(actions_summary) if actions_summary else "Logged & Enriched"
        send_incident_notification(incident, action_str)

        # Update live MTTR latency measurement
        elapsed_ms = max(1.0, round((time.perf_counter() - t_start) * 1000.0, 2))
        self._latency_samples.append(elapsed_ms)
        if len(self._latency_samples) > 50:
            self._latency_samples.pop(0)
        self.stats.avg_response_time_ms = round(sum(self._latency_samples) / len(self._latency_samples), 1)
        self.stats.active_banned_ips = len(ip_blocker.get_all_active_bans())

        self._save_state()

        # Real-time WebSocket Broadcast
        await self.broadcast_event("NEW_INCIDENT", to_dict(incident))
        await self.broadcast_event("STATS_UPDATE", to_dict(self.stats))

    async def monitor_ban_ttl(self):
        """Background task that auto-expires quarantined IPs when their TTL reaches 0."""
        while True:
            try:
                expired = ip_blocker.expire_stale_bans()
                if expired:
                    for rec in expired:
                        self.record_playbook_action(
                            playbook_name="TTLCoolingUnban",
                            target_ip=rec.ip,
                            action_type="UNBAN",
                            status="SUCCESS",
                            details={"reason": "TTL_EXPIRED", "banned_at": rec.banned_at},
                            persist=False
                        )
                    self.stats.active_banned_ips = len(ip_blocker.get_all_active_bans())
                    self._save_state()
                    await self.broadcast_event("BAN_EXPIRED", {"ips": [r.ip for r in expired]})
                    await self.broadcast_event("STATS_UPDATE", to_dict(self.stats))
            except Exception as e:
                logger.error(f"Error in TTL monitor loop: {e}")
            await asyncio.sleep(5)

    async def tail_eve_log(self):
        """Asynchronously stream and monitor Suricata EVE JSON log file in real time."""
        logger.info(f"[*] SOAR Engine monitoring EVE log at: {config.EVE_LOG_PATH}")

        while not os.path.exists(config.EVE_LOG_PATH):
            logger.info("Waiting for Suricata eve.json log file to be created...")
            await asyncio.sleep(2)

        with open(config.EVE_LOG_PATH, "r", encoding="utf-8") as f:
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
