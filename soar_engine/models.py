from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

class ThreatIntel(BaseModel):
    ip: str
    reputation_score: int = 0  # 0 to 100
    is_malicious: bool = False
    country: str = "Unknown"
    country_code: str = "XX"
    isp: str = "Unknown"
    abuse_confidence_score: int = 0
    tags: List[str] = []
    last_reported: Optional[str] = None

class IncidentAlert(BaseModel):
    id: str
    timestamp: str
    src_ip: str
    src_port: Optional[int] = 0
    dest_ip: str
    dest_port: Optional[int] = 0
    proto: str = "TCP"
    signature: str
    category: str
    severity: int
    mitre_tactic: Optional[str] = "N/A"
    mitre_technique: Optional[str] = "N/A"
    payload: Optional[str] = None
    raw_event: Dict[str, Any] = {}
    threat_intel: Optional[ThreatIntel] = None

class BanRecord(BaseModel):
    ip: str
    banned_at: str
    expires_at: str
    reason: str
    associated_signature: str
    severity: int
    status: str = "ACTIVE" # ACTIVE, EXPIRED, MANUALLY_REMOVED

class PlaybookExecutionLog(BaseModel):
    id: str
    timestamp: str
    playbook_name: str
    target_ip: str
    trigger_alert_id: Optional[str] = None
    action_type: str # BAN, UNBAN, THREAT_INTEL, NOTIFICATION, FORENSIC_DUMP
    status: str # SUCCESS, FAILED, SKIPPED
    details: Dict[str, Any] = {}

class SOARStats(BaseModel):
    total_events_processed: int = 0
    total_alerts_detected: int = 0
    critical_alerts: int = 0
    high_alerts: int = 0
    active_banned_ips: int = 0
    total_playbooks_executed: int = 0
    automated_containments: int = 0
    avg_response_time_ms: float = 118.4
