import os
import sys
import asyncio

from fastapi.testclient import TestClient

SOAR_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "soar_engine"))
if SOAR_DIR not in sys.path:
    sys.path.insert(0, SOAR_DIR)

import app as soar_app
from engine import soar_engine
from playbooks.ip_block import ip_blocker
from config import config


def test_api_bans_pardon_whitelist_and_websocket():
    ip_blocker.clear_all()
    soar_engine.clear_state()

    with TestClient(soar_app.app) as client:
        # Whitelisted gateway rejected
        r_wl = client.post("/api/bans", json={"ip": "172.28.0.1", "reason": "Test", "ttl_seconds": 300})
        assert r_wl.status_code == 400

        # WebSocket receives BAN_ACTIVE and BAN_PARDONED announcements
        with client.websocket_connect("/ws/live") as ws:
            r_ban = client.post("/api/bans", json={"ip": "198.51.100.77", "reason": "Test Ban", "ttl_seconds": 300})
            assert r_ban.status_code == 200
            msg1 = ws.receive_json()
            assert msg1["type"] == "BAN_ACTIVE"
            assert msg1["data"]["ip"] == "198.51.100.77"
            _ = ws.receive_json()  # STATS_UPDATE

            r_pardon = client.delete("/api/bans/198.51.100.77")
            assert r_pardon.status_code == 200
            assert r_pardon.json()["ban"]["status"] == "PARDONED"

            msg2 = ws.receive_json()
            assert msg2["type"] == "BAN_PARDONED"
            assert msg2["data"]["status"] == "PARDONED"

        # Audit log records ManualAnalystPardon
        audits = client.get("/api/audit-logs").json()
        assert any(a["playbook_name"] == "ManualAnalystPardon" and a["target_ip"] == "198.51.100.77" for a in audits)


def test_server_response_rule_sid_1000012_bans_attacker_not_target():
    ip_blocker.clear_all()
    soar_engine.clear_state()

    eve_event = {
        "event_type": "alert",
        "timestamp": "2026-11-11T12:00:00.000000Z",
        "src_ip": "172.28.0.10",   # Target web server responding HTTP 401
        "src_port": 80,
        "dest_ip": "172.28.0.105", # Actual attacker receiving 5x 401
        "dest_port": 55432,
        "proto": "TCP",
        "alert": {
            "signature_id": 1000012,
            "signature": "SIEM-AUTH: Multiple HTTP 401 Unauthorized Responses",
            "category": "Attempted-Admin",
            "severity": 1,
        },
    }
    asyncio.run(soar_engine.handle_alert_event(eve_event))
    assert ip_blocker.is_banned("172.28.0.105")
    assert not ip_blocker.is_banned("172.28.0.10")
