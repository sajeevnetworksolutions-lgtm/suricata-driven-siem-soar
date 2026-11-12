import os
import time
import json
import uuid
import asyncio
import logging
import requests
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from config import config
from models import IncidentAlert, BanRecord, PlaybookExecutionLog, SOARStats
from ban_manager import WhitelistedIPError, InvalidIPError, BanCapacityError
from dossier import create_forensic_dossier as create_chained_dossier, verify_chain
from playbooks.threat_intel import enrich_ip
from playbooks.ip_block import ip_blocker
from playbooks.notification import send_incident_notification

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("soar.engine")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_timestamp_utc(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        cleaned = ts.strip()
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        elif len(cleaned) >= 5 and (cleaned[-5] in "+-") and cleaned[-4:].isdigit():
            # Suricata format e.g. 2026-11-11T12:00:00.123456+0000 -> +00:00
            cleaned = f"{cleaned[:-2]}:{cleaned[-2:]}"
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


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


def normalize_to_ecs(
    eve_event: Dict[str, Any],
    offender_ip: str,
    signature: str,
    category: str,
    severity: int,
    sid: Optional[int],
    mitre_tactic: str,
    mitre_technique: str,
) -> Dict[str, Any]:
    """Normalize raw Suricata EVE JSON event into Elastic Common Schema (ECS) structure."""
    return {
        "@timestamp": eve_event.get("timestamp") or utc_now_iso(),
        "ecs": {"version": "8.12"},
        "event": {
            "kind": "alert",
            "category": ["intrusion_detection", "network"],
            "action": eve_event.get("event_type", "alert"),
            "severity": severity,
        },
        "source": {
            "ip": offender_ip,
            "port": eve_event.get("src_port", 0),
        },
        "destination": {
            "ip": eve_event.get("dest_ip", "0.0.0.0"),
            "port": eve_event.get("dest_port", 0),
        },
        "network": {
            "transport": str(eve_event.get("proto", "TCP")).lower(),
        },
        "rule": {
            "id": str(sid) if sid is not None else "custom",
            "name": signature,
            "category": category,
        },
        "threat": {
            "framework": "MITRE ATT&CK",
            "tactic": {"id": [mitre_tactic]},
            "technique": {"id": [mitre_technique]},
        },
    }


class SOAREngine:
    def __init__(self):
        self.incidents: List[IncidentAlert] = []
        self.audit_logs: List[PlaybookExecutionLog] = []
        self.latency_records: List[Dict[str, Any]] = []
        self.stats = SOARStats()
        self.websocket_subscribers: List[asyncio.Queue] = []
        self._latency_samples: List[float] = []
        self._mttd_samples: List[float] = []
        self._ti_samples: List[float] = []
        self._ban_samples: List[float] = []
        self._forensic_samples: List[float] = []
        self._notify_samples: List[float] = []
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
        self.stats.automated_containments = sum(
            1 for a in self.audit_logs if a.action_type == "BAN" and a.playbook_name == "AutoIPQuarantine"
        )
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
        persist: bool = True,
    ):
        log_entry = PlaybookExecutionLog(
            id=f"PB-{uuid.uuid4().hex[:8]}",
            timestamp=utc_now_iso(),
            playbook_name=playbook_name,
            target_ip=target_ip,
            trigger_alert_id=alert_id,
            action_type=action_type,
            status=status,
            details=details,
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
        self.latency_records.clear()
        self._latency_samples.clear()
        self._mttd_samples.clear()
        self._ti_samples.clear()
        self._ban_samples.clear()
        self._forensic_samples.clear()
        self._notify_samples.clear()
        self.stats = SOARStats(active_banned_ips=len(ip_blocker.get_all_active_bans()))
        self._save_state()

    def reset_latency_metrics(self):
        self.latency_records.clear()
        self._latency_samples.clear()
        self._mttd_samples.clear()
        self._ti_samples.clear()
        self._ban_samples.clear()
        self._forensic_samples.clear()
        self._notify_samples.clear()

    @staticmethod
    def resolve_offender_ip(eve_event: Dict[str, Any], alert_info: Dict[str, Any]) -> str:
        """
        Determine true attacking host IP from EVE telemetry.
        Server-to-client rules (e.g. SID 1000012 HTTP 401 burst, SID 1000014 FTP 530 burst)
        log `src_ip` as the target server and `dest_ip` as the offending client.
        """
        src_ip = eve_event.get("src_ip", "0.0.0.0")
        dest_ip = eve_event.get("dest_ip", "0.0.0.0")
        sid = alert_info.get("signature_id")
        signature = (alert_info.get("signature") or "").lower()

        is_server_response_rule = (
            sid in (1000012, 1000014)
            or "http 401" in signature
            or "530 login incorrect" in signature
        )

        if (is_server_response_rule or ip_blocker.is_whitelisted(src_ip)) and dest_ip and not ip_blocker.is_whitelisted(dest_ip):
            if src_ip != dest_ip and dest_ip != "0.0.0.0":
                return dest_ip
        return src_ip

    # ---- Separate Instrumented Playbook Tasks ----

    @staticmethod
    def _exec_ti_task(ip: str):
        t0 = time.perf_counter()
        if not config.ENABLE_THREAT_INTEL:
            return None, 0.0
        intel = enrich_ip(ip)
        return intel, round((time.perf_counter() - t0) * 1000.0, 3)

    @staticmethod
    def _exec_ban_task(ip: str, signature: str, severity: int) -> Tuple[Optional[BanRecord], str, float]:
        t0 = time.perf_counter()
        try:
            rec = ip_blocker.ban_ip(
                ip=ip,
                reason=f"Automated SOAR Quarantine: {signature}",
                signature=signature,
                severity=severity,
                ttl_seconds=config.BAN_TTL_SECONDS,
                enable_ttl=config.ENABLE_TTL,
            )
            return rec, "SUCCESS", round((time.perf_counter() - t0) * 1000.0, 3)
        except (WhitelistedIPError, InvalidIPError, BanCapacityError) as exc:
            logger.info(f"[SOAR-POLICY] Quarantine skipped for {ip}: {exc}")
            return None, "SKIPPED", round((time.perf_counter() - t0) * 1000.0, 3)

    @staticmethod
    def _exec_forensic_task(incident: IncidentAlert) -> Tuple[Optional[Dict[str, Any]], float]:
        t0 = time.perf_counter()
        if not config.ENABLE_FORENSICS:
            return None, 0.0
        res = create_chained_dossier(incident)
        return res, round((time.perf_counter() - t0) * 1000.0, 3)

    @staticmethod
    def _exec_notify_task(incident: IncidentAlert, action_str: str) -> Tuple[bool, float]:
        t0 = time.perf_counter()
        ok = send_incident_notification(incident, action_str)
        return ok, round((time.perf_counter() - t0) * 1000.0, 3)

    async def handle_alert_event(self, eve_event: Dict[str, Any]):
        """Evaluate an alert event against SOAR playbooks and record instrumented per-stage latencies."""
        t_start = time.perf_counter()
        t_recv_dt = datetime.now(timezone.utc)

        self.stats.total_alerts_detected += 1
        if self.stats.total_events_processed < self.stats.total_alerts_detected:
            self.stats.total_events_processed += 1

        alert_info = eve_event.get("alert", {})
        severity = int(alert_info.get("severity", 3))
        sid = alert_info.get("signature_id")
        signature = alert_info.get("signature", "Unknown Security Alert")
        category = alert_info.get("category", "General Security Event")
        raw_src_ip = eve_event.get("src_ip", "0.0.0.0")
        dest_ip = eve_event.get("dest_ip", "0.0.0.0")
        offender_ip = self.resolve_offender_ip(eve_event, alert_info)

        # Compute MTTD from EVE emission timestamp -> SOAR intake if within realistic window
        raw_ts = eve_event.get("timestamp")
        event_dt = parse_timestamp_utc(raw_ts)
        event_ts = raw_ts if raw_ts else utc_now_iso()

        metadata = alert_info.get("metadata", {})
        raw_tactic = metadata.get("mitre_tactic_id")
        raw_tech = metadata.get("mitre_technique_id")
        mitre_tactic = raw_tactic[0] if isinstance(raw_tactic, list) and raw_tactic else None
        mitre_technique = raw_tech[0] if isinstance(raw_tech, list) and raw_tech else None

        if not mitre_tactic or not mitre_technique:
            inferred_tactic, inferred_tech = infer_mitre_from_signature(signature, category)
            mitre_tactic = mitre_tactic or inferred_tactic
            mitre_technique = mitre_technique or inferred_tech

        ecs_doc = (
            normalize_to_ecs(eve_event, offender_ip, signature, category, severity, sid, mitre_tactic, mitre_technique)
            if config.ENABLE_ECS
            else None
        )

        if severity == 1:
            self.stats.critical_alerts += 1
        elif severity == 2:
            self.stats.high_alerts += 1

        t_parsed = time.perf_counter()
        parse_ms = round((t_parsed - t_start) * 1000.0, 3)
        if event_dt is not None:
            raw_mttd = (t_recv_dt - event_dt).total_seconds() * 1000.0
            mttd_ms = round(raw_mttd + parse_ms, 3) if 0.0 <= raw_mttd <= 30000.0 else parse_ms
        else:
            mttd_ms = parse_ms

        should_ban = config.AUTO_BAN_ENABLED and severity <= config.BAN_THRESHOLD_SEVERITY

        # Step 1: Threat Intel & Auto-Quarantine Playbooks
        ban_rec: Optional[BanRecord] = None
        ban_status = "SKIPPED"
        ban_ms = 0.0

        if config.ASYNC_MODE:
            tasks = [asyncio.to_thread(self._exec_ti_task, offender_ip)]
            if should_ban:
                tasks.append(asyncio.to_thread(self._exec_ban_task, offender_ip, signature, severity))
            results = await asyncio.gather(*tasks)
            intel, ti_ms = results[0]
            if should_ban:
                ban_rec, ban_status, ban_ms = results[1]
        else:
            intel, ti_ms = self._exec_ti_task(offender_ip)
            if should_ban:
                ban_rec, ban_status, ban_ms = self._exec_ban_task(offender_ip, signature, severity)

        incident = IncidentAlert(
            id=str(uuid.uuid4()),
            timestamp=event_ts,
            src_ip=offender_ip,
            src_port=eve_event.get("src_port", 0),
            dest_ip=dest_ip,
            dest_port=eve_event.get("dest_port", 0),
            proto=eve_event.get("proto", "TCP"),
            signature=signature,
            category=category,
            severity=severity,
            sid=sid,
            offender_ip=offender_ip,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            payload=eve_event.get("payload"),
            raw_event=eve_event,
            ecs_normalized=ecs_doc,
            threat_intel=intel,
        )

        self.incidents.insert(0, incident)
        if len(self.incidents) > 500:
            self.incidents.pop()

        if config.ENABLE_THREAT_INTEL and intel is not None:
            self.record_playbook_action(
                playbook_name="ThreatIntelEnrichment",
                target_ip=offender_ip,
                action_type="THREAT_INTEL",
                status="SUCCESS",
                details={
                    "score": intel.reputation_score,
                    "country": intel.country,
                    "isp": intel.isp,
                    "source": intel.intel_source,
                    "latency_ms": ti_ms,
                },
                alert_id=incident.id,
                persist=False,
            )

        actions_summary = []
        if should_ban:
            if ban_rec is not None:
                self.stats.automated_containments += 1
                ttl_label = "PERMANENT" if ban_rec.permanent else f"{ban_rec.ttl_seconds}s TTL"
                actions_summary.append(f"Quarantined {offender_ip} ({ttl_label})")
                self.record_playbook_action(
                    playbook_name="AutoIPQuarantine",
                    target_ip=offender_ip,
                    action_type="BAN",
                    status="SUCCESS",
                    details={"ttl": ban_rec.ttl_seconds, "expires_at": ban_rec.expires_at, "latency_ms": ban_ms},
                    alert_id=incident.id,
                    persist=False,
                )
            else:
                self.record_playbook_action(
                    playbook_name="AutoIPQuarantine",
                    target_ip=offender_ip,
                    action_type="BAN",
                    status="SKIPPED",
                    details={"reason": "WHITELIST_OR_CAPACITY", "raw_src_ip": raw_src_ip, "latency_ms": ban_ms},
                    alert_id=incident.id,
                    persist=False,
                )

        # Step 2: Forensic Dossier & Webhook/SOC Notification Playbooks
        action_str = " | ".join(actions_summary) if actions_summary else "Logged & Enriched"
        if config.ASYNC_MODE:
            (dossier_res, forensic_ms), (notify_ok, notify_ms) = await asyncio.gather(
                asyncio.to_thread(self._exec_forensic_task, incident),
                asyncio.to_thread(self._exec_notify_task, incident, action_str),
            )
        else:
            dossier_res, forensic_ms = self._exec_forensic_task(incident)
            notify_ok, notify_ms = self._exec_notify_task(incident, action_str)

        if config.ENABLE_FORENSICS and dossier_res is not None:
            actions_summary.append(f"Forensic Case {dossier_res['case_id']}")
            self.record_playbook_action(
                playbook_name="ForensicCollector",
                target_ip=offender_ip,
                action_type="FORENSIC_DUMP",
                status="SUCCESS",
                details={
                    "case_id": dossier_res["case_id"],
                    "sha256": dossier_res["sha256"][:16],
                    "chain_index": dossier_res["chain_index"],
                    "latency_ms": forensic_ms,
                },
                alert_id=incident.id,
                persist=False,
            )

        self.record_playbook_action(
            playbook_name="IncidentNotifier",
            target_ip=offender_ip,
            action_type="NOTIFICATION",
            status="SUCCESS" if notify_ok else "FAILED",
            details={"action": action_str, "latency_ms": notify_ms},
            alert_id=incident.id,
            persist=False,
        )

        # Total MTTR measurement
        mttr_ms = round((time.perf_counter() - t_start) * 1000.0, 3)
        incident.stage_latencies_ms = {
            "mttd_ms": mttd_ms,
            "ti_latency_ms": ti_ms,
            "ban_latency_ms": ban_ms,
            "forensic_latency_ms": forensic_ms,
            "notify_latency_ms": notify_ms,
            "mttr_ms": mttr_ms,
        }

        self._record_latency_point(incident, ban_rec is not None)
        self.stats.active_banned_ips = len(ip_blocker.get_all_active_bans())

        if config.ASYNC_MODE:
            await asyncio.to_thread(self._save_state)
        else:
            self._save_state()

        # Real-time WebSocket broadcasts (incident + ban active announcement + stats)
        await self.broadcast_event("NEW_INCIDENT", to_dict(incident))
        if ban_rec is not None:
            await self.broadcast_event("BAN_ACTIVE", to_dict(ban_rec))
        await self.broadcast_event("STATS_UPDATE", to_dict(self.stats))

    def _record_latency_point(self, incident: IncidentAlert, contained: bool):
        lat = incident.stage_latencies_ms
        rec = {
            "incident_id": incident.id,
            "timestamp": utc_now_iso(),
            "signature": incident.signature,
            "sid": incident.sid,
            "severity": incident.severity,
            "src_ip": incident.src_ip,
            "contained": contained,
            **lat,
        }
        self.latency_records.append(rec)
        if len(self.latency_records) > 1000:
            self.latency_records.pop(0)

        for buf, key in (
            (self._latency_samples, "mttr_ms"),
            (self._mttd_samples, "mttd_ms"),
            (self._ti_samples, "ti_latency_ms"),
            (self._ban_samples, "ban_latency_ms"),
            (self._forensic_samples, "forensic_latency_ms"),
            (self._notify_samples, "notify_latency_ms"),
        ):
            buf.append(lat[key])
            if len(buf) > 200:
                buf.pop(0)

        self.stats.avg_response_time_ms = round(sum(self._latency_samples) / len(self._latency_samples), 2)
        self.stats.avg_mttd_ms = round(sum(self._mttd_samples) / len(self._mttd_samples), 2)
        self.stats.avg_ti_ms = round(sum(self._ti_samples) / len(self._ti_samples), 2)
        self.stats.avg_ban_ms = round(sum(self._ban_samples) / len(self._ban_samples), 2)
        self.stats.avg_forensic_ms = round(sum(self._forensic_samples) / len(self._forensic_samples), 2)
        self.stats.avg_notify_ms = round(sum(self._notify_samples) / len(self._notify_samples), 2)

    async def monitor_ban_ttl(self):
        """Background task that auto-expires quarantined IPs when their TTL elapses."""
        while True:
            try:
                if config.ENABLE_TTL:
                    expired = ip_blocker.expire_stale_bans()
                    if expired:
                        for rec in expired:
                            self.record_playbook_action(
                                playbook_name="TTLCoolingUnban",
                                target_ip=rec.ip,
                                action_type="UNBAN",
                                status="SUCCESS",
                                details={"reason": "TTL_EXPIRED", "banned_at": rec.banned_at, "status": rec.status.value},
                                persist=False,
                            )
                        self.stats.active_banned_ips = len(ip_blocker.get_all_active_bans())
                        self._save_state()
                        await self.broadcast_event(
                            "BAN_EXPIRED",
                            {"ips": [r.ip for r in expired], "records": [to_dict(r) for r in expired]},
                        )
                        await self.broadcast_event("STATS_UPDATE", to_dict(self.stats))
            except Exception as e:
                logger.error(f"Error in TTL monitor loop: {e}")
            await asyncio.sleep(1)

    async def poll_elasticsearch_ecs(self):
        """Optional ingestion path polling Elasticsearch ECS documents (used for Table IV ECS comparison)."""
        poll_sec = max(0.05, config.POLL_INTERVAL_MS / 1000.0)
        seen_ids = set()
        last_ts = utc_now_iso()
        logger.info(f"[*] SOAR Engine polling Elasticsearch ECS stream at: {config.ELASTICSEARCH_URL}")

        while True:
            try:
                query = {
                    "size": 50,
                    "sort": [{"@timestamp": {"order": "asc"}}],
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"event.action": "alert"}},
                                {"range": {"@timestamp": {"gte": last_ts}}},
                            ]
                        }
                    },
                }
                resp = await asyncio.to_thread(
                    requests.post,
                    f"{config.ELASTICSEARCH_URL}/suricata-events-*/_search",
                    json=query,
                    timeout=3,
                )
                if resp.status_code == 200:
                    hits = resp.json().get("hits", {}).get("hits", [])
                    for hit in hits:
                        doc_id = hit.get("_id")
                        if doc_id in seen_ids:
                            continue
                        seen_ids.add(doc_id)
                        if len(seen_ids) > 5000:
                            seen_ids.clear()
                        src = hit.get("_source", {})
                        last_ts = src.get("@timestamp", last_ts)
                        suricata_eve = src.get("suricata", {}).get("eve", {})
                        if suricata_eve:
                            self.stats.total_events_processed += 1
                            await self.handle_alert_event(suricata_eve)
            except Exception as e:
                logger.debug(f"Elasticsearch poll error: {e}")
            await asyncio.sleep(poll_sec)

    async def tail_eve_log(self):
        """Asynchronously stream and monitor Suricata EVE JSON log file every POLL_INTERVAL_MS (200 ms)."""
        if config.SOAR_INPUT_MODE == "elasticsearch":
            await self.poll_elasticsearch_ecs()
            return

        poll_sec = max(0.01, config.POLL_INTERVAL_MS / 1000.0)
        logger.info(f"[*] SOAR Engine monitoring EVE log at: {config.EVE_LOG_PATH} (poll={config.POLL_INTERVAL_MS}ms)")

        while not os.path.exists(config.EVE_LOG_PATH):
            logger.info("Waiting for Suricata eve.json log file to be created...")
            await asyncio.sleep(0.5)

        with open(config.EVE_LOG_PATH, "r", encoding="utf-8") as f:
            f.seek(0, os.SEEK_END)
            while True:
                # Handle log rotation / truncation
                try:
                    if os.path.exists(config.EVE_LOG_PATH) and os.path.getsize(config.EVE_LOG_PATH) < f.tell():
                        f.seek(0, os.SEEK_SET)
                except OSError:
                    pass

                line = f.readline()
                if line:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        self.stats.total_events_processed += 1
                        event = json.loads(stripped)
                        if event.get("event_type") == "alert" and not event.get("_processed_by_api"):
                            await self.handle_alert_event(event)
                    except Exception as e:
                        logger.error(f"Error processing EVE event: {e}")
                else:
                    await asyncio.sleep(poll_sec)


soar_engine = SOAREngine()
