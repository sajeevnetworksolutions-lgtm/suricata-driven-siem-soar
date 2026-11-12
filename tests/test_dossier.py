import os
import sys
import json

SOAR_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "soar_engine"))
if SOAR_DIR not in sys.path:
    sys.path.insert(0, SOAR_DIR)

from models import IncidentAlert, ThreatIntel
import dossier


def _sample_incident(idx: int) -> IncidentAlert:
    return IncidentAlert(
        id=f"inc-{idx:04d}-deadbeef",
        timestamp="2026-11-11T12:00:00.000000Z",
        src_ip="172.28.0.105",
        src_port=51000 + idx,
        dest_ip="172.28.0.10",
        dest_port=80,
        proto="TCP",
        signature="SIEM-WEB: SQL Injection Attempt",
        category="Web-Application-Attack",
        severity=1,
        sid=1000020,
        offender_ip="172.28.0.105",
        payload=f"GET /search?q=UNION+SELECT+{idx} HTTP/1.1",
        raw_event={"event_type": "alert", "sid": 1000020, "idx": idx},
        threat_intel=ThreatIntel(ip="172.28.0.105", reputation_score=85, is_malicious=True),
    )


def test_dossier_eq12_fields_and_hash_chain_verification(tmp_path):
    fdir = str(tmp_path / "forensics")
    ledger = str(tmp_path / "forensics" / "chain_ledger.jsonl")

    r1 = dossier.create_forensic_dossier(_sample_incident(1), dossier_dir=fdir, ledger_path=ledger)
    r2 = dossier.create_forensic_dossier(_sample_incident(2), dossier_dir=fdir, ledger_path=ledger)

    assert r2["prev_hash"] == r1["sha256"]
    assert r1["chain_index"] == 1 and r2["chain_index"] == 2

    with open(r1["file_path"], "r", encoding="utf-8") as cf:
        doc = json.load(cf)
    for field in ("case_id", "t", "alert", "r_x", "payload", "prev_hash", "sha256"):
        assert field in doc

    check = dossier.verify_chain(dossier_dir=fdir, ledger_path=ledger)
    assert check["valid"] is True
    assert check["total_entries"] == 2

    # Tamper with first ledger line and confirm verify_chain() fails loudly
    with open(ledger, "r", encoding="utf-8") as f:
        lines = f.readlines()
    tampered = json.loads(lines[0])
    tampered["payload"] = "TAMPERED_PAYLOAD"
    lines[0] = json.dumps(tampered) + "\n"
    with open(ledger, "w", encoding="utf-8") as f:
        f.writelines(lines)

    bad = dossier.verify_chain(dossier_dir=fdir, ledger_path=ledger)
    assert bad["valid"] is False
    assert bad["broken_index"] == 1
