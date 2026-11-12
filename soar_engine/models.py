from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any


class BanStatus(str, Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    PARDONED = "PARDONED"


class ThreatIntel(BaseModel):
    ip: str
    reputation_score: int = 0  # R(x) in [0, 100]
    is_malicious: bool = False
    country: str = "Unknown"
    country_code: str = "XX"
    isp: str = "Unknown"
    asn: str = "Unknown"
    abuse_confidence_score: int = 0
    asn_risk_score: int = 0
    formula_weights: Dict[str, float] = Field(default_factory=lambda: {"w1": 0.7, "w2": 0.3})
    intel_source: str = "local_ioc_cache"  # abuseipdb | local_ioc_cache | heuristic_fallback
    tags: List[str] = Field(default_factory=list)
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
    sid: Optional[int] = None
    offender_ip: Optional[str] = None
    mitre_tactic: Optional[str] = "N/A"
    mitre_technique: Optional[str] = "N/A"
    payload: Optional[str] = None
    raw_event: Dict[str, Any] = Field(default_factory=dict)
    ecs_normalized: Optional[Dict[str, Any]] = None
    threat_intel: Optional[ThreatIntel] = None
    stage_latencies_ms: Dict[str, float] = Field(default_factory=dict)


class BanRecord(BaseModel):
    ip: str
    banned_at: str
    expires_at: str
    reason: str
    associated_signature: str
    severity: int
    status: BanStatus = BanStatus.ACTIVE  # ACTIVE, EXPIRED, PARDONED
    ttl_seconds: int = 300
    permanent: bool = False
    pardoned_at: Optional[str] = None


class PlaybookExecutionLog(BaseModel):
    id: str
    timestamp: str
    playbook_name: str
    target_ip: str
    trigger_alert_id: Optional[str] = None
    action_type: str  # BAN, UNBAN, PARDON, THREAT_INTEL, NOTIFICATION, FORENSIC_DUMP, POLICY_UPDATE
    status: str  # SUCCESS, FAILED, SKIPPED
    details: Dict[str, Any] = Field(default_factory=dict)


class SOARStats(BaseModel):
    total_events_processed: int = 0
    total_alerts_detected: int = 0
    critical_alerts: int = 0
    high_alerts: int = 0
    active_banned_ips: int = 0
    total_playbooks_executed: int = 0
    automated_containments: int = 0
    avg_response_time_ms: float = 0.0
    avg_mttd_ms: float = 0.0
    avg_ti_ms: float = 0.0
    avg_ban_ms: float = 0.0
    avg_forensic_ms: float = 0.0
    avg_notify_ms: float = 0.0
