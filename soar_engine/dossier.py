import os
import json
import shutil
import hashlib
import logging
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from models import IncidentAlert
from config import config

logger = logging.getLogger("soar.dossier")

GENESIS_HASH = "0" * 64


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _compute_entry_sha256(
    case_id: str,
    t: str,
    alert: Dict[str, Any],
    r_x: Optional[Dict[str, Any]],
    payload: Any,
    prev_hash: str,
) -> str:
    body = {
        "case_id": case_id,
        "t": t,
        "alert": alert,
        "r_x": r_x,
        "payload": payload,
        "prev_hash": prev_hash,
    }
    return hashlib.sha256(_canonical_json(body).encode("utf-8")).hexdigest()


def _try_set_append_only(path: str):
    """Set OS append-only attribute (chattr +a) on POSIX when CAP_LINUX_IMMUTABLE is available."""
    if not config.ENABLE_CHATTR or os.name != "posix":
        return False
    chattr_bin = shutil.which("chattr")
    if not chattr_bin:
        return False
    try:
        res = subprocess.run([chattr_bin, "+a", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
        return res.returncode == 0
    except Exception:
        return False


def _try_set_readonly(path: str):
    try:
        if os.name == "posix":
            os.chmod(path, 0o444)
    except Exception:
        pass


def _read_last_hash(ledger_path: str) -> tuple[int, str]:
    if not os.path.exists(ledger_path):
        return 0, GENESIS_HASH
    last_seq = 0
    last_hash = GENESIS_HASH
    with open(ledger_path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            rec = json.loads(stripped)
            last_seq = int(rec.get("chain_index", last_seq + 1))
            last_hash = rec["sha256"]
    return last_seq, last_hash


def create_forensic_dossier(
    incident: IncidentAlert,
    dossier_dir: Optional[str] = None,
    ledger_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create Eq. 12 Forensic Dossier:
      D = <CaseID, t, alert, R(x), payload, SHA256>
    with cryptographic chaining to previous ledger entry (`prev_hash`).
    Also retains dashboard/test compatibility keys (`investigation_opened_at`,
    `triggering_alert`, `threat_intelligence`, `raw_eve_payload`).
    """
    target_dir = dossier_dir or config.DOSSIER_DIR
    os.makedirs(target_dir, exist_ok=True)
    target_ledger = ledger_path or os.path.join(target_dir, "chain_ledger.jsonl")

    now_utc = datetime.now(timezone.utc)
    t_iso = now_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    case_id = f"CASE-{now_utc.strftime('%Y%m%d%H%M%S')}-{incident.id[:8]}"
    file_path = os.path.join(target_dir, f"{case_id}.json")

    alert_summary = {
        "id": incident.id,
        "timestamp": incident.timestamp,
        "sid": incident.sid,
        "signature": incident.signature,
        "severity": incident.severity,
        "category": incident.category,
        "source": f"{incident.src_ip}:{incident.src_port}",
        "destination": f"{incident.dest_ip}:{incident.dest_port}",
        "offender_ip": incident.offender_ip or incident.src_ip,
        "protocol": incident.proto,
        "mitre_tactic": incident.mitre_tactic,
        "mitre_technique": incident.mitre_technique,
    }

    r_x_obj = None
    if incident.threat_intel is not None:
        r_x_obj = (
            incident.threat_intel.model_dump()
            if hasattr(incident.threat_intel, "model_dump")
            else incident.threat_intel.dict()
        )

    payload_obj = incident.payload if incident.payload is not None else incident.raw_event

    last_seq, prev_hash = _read_last_hash(target_ledger)
    chain_index = last_seq + 1
    sha256_hex = _compute_entry_sha256(
        case_id=case_id,
        t=t_iso,
        alert=alert_summary,
        r_x=r_x_obj,
        payload=payload_obj,
        prev_hash=prev_hash,
    )

    ledger_entry = {
        "chain_index": chain_index,
        "case_id": case_id,
        "t": t_iso,
        "alert": alert_summary,
        "r_x": r_x_obj,
        "payload": payload_obj,
        "prev_hash": prev_hash,
        "sha256": sha256_hex,
    }

    # Append to chained ledger, then enforce append-only attribute if supported
    with open(target_ledger, "a", encoding="utf-8") as lf:
        lf.write(_canonical_json(ledger_entry) + "\n")
    append_only_enforced = _try_set_append_only(target_ledger)

    # Full per-case file (Eq. 12 tuple + dashboard compatibility fields)
    dossier_doc = {
        **ledger_entry,
        "append_only_chattr": append_only_enforced,
        "investigation_opened_at": t_iso,
        "triggering_alert": alert_summary,
        "threat_intelligence": r_x_obj,
        "raw_eve_payload": incident.raw_event,
    }

    with open(file_path, "w", encoding="utf-8") as cf:
        json.dump(dossier_doc, cf, indent=2)
    _try_set_readonly(file_path)

    logger.info(f"[SOAR-FORENSICS] Dossier {case_id} written & chained (#{chain_index}, sha256={sha256_hex[:12]}...)")
    return {"case_id": case_id, "sha256": sha256_hex, "prev_hash": prev_hash, "chain_index": chain_index, "file_path": file_path}


def verify_chain(dossier_dir: Optional[str] = None, ledger_path: Optional[str] = None) -> Dict[str, Any]:
    """Verify hash-chain integrity across `chain_ledger.jsonl` and individual `CASE-*.json` files."""
    target_dir = dossier_dir or config.DOSSIER_DIR
    target_ledger = ledger_path or os.path.join(target_dir, "chain_ledger.jsonl")

    if not os.path.exists(target_ledger):
        return {"valid": True, "total_entries": 0, "broken_index": None, "reason": "Empty ledger", "head_hash": GENESIS_HASH}

    expected_prev = GENESIS_HASH
    count = 0

    try:
        with open(target_ledger, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                count += 1
                entry = json.loads(stripped)

                if int(entry.get("chain_index", -1)) != count:
                    return {
                        "valid": False,
                        "total_entries": count,
                        "broken_index": count,
                        "reason": f"Sequence mismatch at line {idx}: got {entry.get('chain_index')}, expected {count}",
                        "head_hash": expected_prev,
                    }

                if entry.get("prev_hash") != expected_prev:
                    return {
                        "valid": False,
                        "total_entries": count,
                        "broken_index": count,
                        "reason": f"prev_hash link broken at entry {count}",
                        "head_hash": expected_prev,
                    }

                recomputed = _compute_entry_sha256(
                    case_id=entry["case_id"],
                    t=entry["t"],
                    alert=entry["alert"],
                    r_x=entry.get("r_x"),
                    payload=entry.get("payload"),
                    prev_hash=entry["prev_hash"],
                )
                if recomputed != entry.get("sha256"):
                    return {
                        "valid": False,
                        "total_entries": count,
                        "broken_index": count,
                        "reason": f"SHA-256 tamper detected in ledger at entry {count} ({entry.get('case_id')})",
                        "head_hash": expected_prev,
                    }

                # Cross-check case file if present in target_dir
                case_file = os.path.join(target_dir, f"{entry['case_id']}.json")
                if os.path.exists(case_file):
                    with open(case_file, "r", encoding="utf-8") as cf:
                        case_doc = json.load(cf)
                    case_recomputed = _compute_entry_sha256(
                        case_id=case_doc["case_id"],
                        t=case_doc["t"],
                        alert=case_doc["alert"],
                        r_x=case_doc.get("r_x"),
                        payload=case_doc.get("payload"),
                        prev_hash=case_doc["prev_hash"],
                    )
                    if case_recomputed != entry["sha256"] or case_doc.get("sha256") != entry["sha256"]:
                        return {
                            "valid": False,
                            "total_entries": count,
                            "broken_index": count,
                            "reason": f"Case file tampered for {entry['case_id']}",
                            "head_hash": expected_prev,
                        }

                expected_prev = entry["sha256"]
    except Exception as exc:
        return {
            "valid": False,
            "total_entries": count,
            "broken_index": count + 1,
            "reason": f"Ledger parse error: {exc}",
            "head_hash": expected_prev,
        }

    return {
        "valid": True,
        "total_entries": count,
        "broken_index": None,
        "reason": "Hash chain intact",
        "head_hash": expected_prev,
    }
