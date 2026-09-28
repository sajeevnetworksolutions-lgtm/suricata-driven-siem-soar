import os
import json
import logging
from datetime import datetime
from typing import Dict, Any
from models import IncidentAlert
from config import config

logger = logging.getLogger("soar.playbook.forensic_dump")

def create_forensic_dossier(alert: IncidentAlert) -> str:
    """Creates a structured forensic case file with network payload, headers, and metadata."""
    os.makedirs(os.path.join(config.DATA_DIR, "forensics"), exist_ok=True)
    case_id = f"CASE-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{alert.id[:8]}"
    file_path = os.path.join(config.DATA_DIR, "forensics", f"{case_id}.json")
    
    dossier = {
        "case_id": case_id,
        "investigation_opened_at": datetime.utcnow().isoformat(),
        "triggering_alert": {
            "id": alert.id,
            "timestamp": alert.timestamp,
            "signature": alert.signature,
            "severity": alert.severity,
            "category": alert.category,
            "source": f"{alert.src_ip}:{alert.src_port}",
            "destination": f"{alert.dest_ip}:{alert.dest_port}",
            "protocol": alert.proto,
            "mitre_tactic": alert.mitre_tactic,
            "mitre_technique": alert.mitre_technique
        },
        "threat_intelligence": alert.threat_intel.dict() if alert.threat_intel else None,
        "raw_eve_payload": alert.raw_event
    }
    
    with open(file_path, "w") as f:
        json.dump(dossier, f, indent=2)
        
    logger.info(f"📁 [SOAR-FORENSICS] Forensic Case Dossier created at: {file_path}")
    return case_id
