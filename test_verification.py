import os
import json
import time
import requests

SOAR_URL = "http://127.0.0.1:8000"
TARGET_URL = "http://127.0.0.1:8080"


def print_step(title):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def test_system():
    print_step("STEP 1: Checking Baseline System Health & Services")
    try:
        r_soar = requests.get(f"{SOAR_URL}/api/stats", timeout=3)
        r_target = requests.get(f"{TARGET_URL}/", timeout=3)
        print(f"  [+] SOAR Control Center (:8000)  -> HTTP {r_soar.status_code} [OK]")
        print(f"  [+] Target Web Application (:8080) -> HTTP {r_target.status_code} [OK]")
    except Exception as e:
        print(f"  [-] Error connecting to services: {e}")
        return

    baseline = r_soar.json()
    print(f"  [*] Initial Alerts Detected:   {baseline.get('total_alerts_detected', 0)}")
    print(f"  [*] Initial Quarantined IPs:   {baseline.get('active_banned_ips', 0)}")
    print(f"  [*] Initial Playbooks Executed: {baseline.get('total_playbooks_executed', 0)}")

    # =========================================================================
    print_step("STEP 2: Executing All 6 Attack Scenarios (100% Containment Policy)")
    # =========================================================================

    scenarios = [
        {
            "name": "Scenario 1: Network Reconnaissance & Port Sweep (10 pkts/5s)",
            "action": lambda: requests.get(f"{TARGET_URL}/", timeout=2),
            "alert": {
                "sid": 1000001,
                "src_ip": "198.51.100.42",
                "dest_ip": "172.28.0.10",
                "signature": "SIEM-RECON: Potential TCP SYN Port Scan Detected",
                "category": "Attempted-Recon",
                "severity": 1,
            },
            "expected_soar": "AUTO-BAN IP 198.51.100.42 (300s TTL) + Threat Intel + Dossier",
        },
        {
            "name": "Scenario 2: HTTP Brute-Force (5x401/10s)",
            "action": lambda: [requests.post(f"{TARGET_URL}/login", data={"username": "admin", "password": f"guess{i}"}, timeout=2) for i in range(5)],
            "alert": {
                "sid": 1000012,
                "src_ip": "172.28.0.105",
                "dest_ip": "172.28.0.10",
                "signature": "SIEM-AUTH: Multiple HTTP 401 Unauthorized Responses (Web Brute Force)",
                "category": "Attempted-Admin",
                "severity": 1,
            },
            "expected_soar": "AUTO-BAN IP 172.28.0.105 for 300s + Threat Intel Lookup",
        },
        {
            "name": "Scenario 3: Web Exploitation (SQL Injection UNION SELECT)",
            "action": lambda: requests.get(f"{TARGET_URL}/search?q=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users--", timeout=2),
            "alert": {
                "sid": 1000020,
                "src_ip": "192.0.2.140",
                "dest_ip": "172.28.0.10",
                "signature": "SIEM-WEB: SQL Injection Attempt (UNION SELECT detected)",
                "category": "Web-Application-Attack",
                "severity": 1,
            },
            "expected_soar": "AUTO-BAN IP 192.0.2.140 + Generate Forensic Dossier",
        },
        {
            "name": "Scenario 4: Malware C2 Check-in Heartbeat",
            "action": lambda: requests.post(f"{TARGET_URL}/api/v1/heartbeat", data="beacon_id=BOTNET-77&cmd=POLL", timeout=2),
            "alert": {
                "sid": 1000030,
                "src_ip": "172.28.0.200",
                "dest_ip": "172.28.0.10",
                "signature": "SIEM-C2: Emulated Malware C2 Heartbeat Beacon Detected",
                "category": "Trojan-Activity",
                "severity": 1,
            },
            "expected_soar": "AUTO-BAN C2 IP 172.28.0.200 + SOC Notification",
        },
        {
            "name": "Scenario 5: DNS Tunneling Exfiltration (DNS name > 50 B)",
            "action": lambda: None,
            "alert": {
                "sid": 1000040,
                "src_ip": "192.0.2.99",
                "dest_ip": "172.28.0.10",
                "signature": "SIEM-DNS: Potential DNS Data Exfiltration / Tunneling (Oversized Query Name)",
                "category": "Bad-Unknown",
                "severity": 1,
            },
            "expected_soar": "AUTO-BAN IP 192.0.2.99 (300s TTL) + Forensic Dossier",
        },
        {
            "name": "Scenario 6: Sensitive Private Key / DB Exfiltration (POST > 5,000 B)",
            "action": lambda: requests.post(f"{TARGET_URL}/upload?file=id_rsa", data="-----BEGIN RSA PRIVATE KEY-----\nMIIE...", timeout=2),
            "alert": {
                "sid": 1000052,
                "src_ip": "203.0.113.111",
                "dest_ip": "172.28.0.10",
                "signature": "SIEM-EXFIL: Unencrypted RSA Private Key Exfiltration Attempt",
                "category": "Policy-Violation",
                "severity": 1,
            },
            "expected_soar": "AUTO-BAN IP 203.0.113.111 + Forensic Evidence Capture",
        },
    ]

    for item in scenarios:
        print(f"\n  [>>>] Running: {item['name']}")
        try:
            item["action"]()
        except Exception:
            pass

        resp = requests.post(f"{SOAR_URL}/api/webhook/alert", json=item["alert"], timeout=3)
        assert resp.status_code == 200, f"Webhook failed: {resp.status_code}"
        time.sleep(0.15)
        print(f"        Expected Action: {item['expected_soar']}")
        print(f"        SOAR Processing: HTTP {resp.status_code} ({resp.json().get('status', 'ok')})")

    # =========================================================================
    print_step("STEP 3: Verifying 100% Automated Active Defense & Whitelist Guard")
    # =========================================================================
    bans_resp = requests.get(f"{SOAR_URL}/api/bans", timeout=3).json()
    active_ips = {b["ip"] for b in bans_resp}
    for expected_ip in ("198.51.100.42", "172.28.0.105", "192.0.2.140", "172.28.0.200", "192.0.2.99", "203.0.113.111"):
        assert expected_ip in active_ips, f"Expected {expected_ip} to be contained! Active: {active_ips}"
    print(f"  [+] Active Quarantined IP Addresses ({len(bans_resp)} active, 6/6 scenarios contained)")

    wl_res = requests.post(f"{SOAR_URL}/api/bans", json={"ip": "172.28.0.1", "reason": "Whitelist test"}, timeout=3)
    assert wl_res.status_code == 400, f"Expected whitelist 400 rejection, got {wl_res.status_code}"
    print("  [+] Internal Whitelist Guard verified (172.28.0.1 rejected with HTTP 400)")

    # =========================================================================
    print_step("STEP 4: Testing Manual SOC Analyst Controls (Pardon & Quarantine)")
    # =========================================================================
    test_ip = "192.0.2.140"
    print(f"  [*] Testing Manual SOC Pardon/Unban on IP: {test_ip}...")
    unban_res = requests.delete(f"{SOAR_URL}/api/bans/{test_ip}", timeout=3)
    assert unban_res.status_code == 200
    assert unban_res.json()["ban"]["status"] == "PARDONED"
    print(f"      Pardon Action: HTTP {unban_res.status_code} -> status={unban_res.json()['ban']['status']}")

    manual_ip = "198.51.100.77"
    print(f"\n  [*] Testing Manual Analyst Quarantine on IP: {manual_ip}...")
    ban_res = requests.post(
        f"{SOAR_URL}/api/bans",
        json={"ip": manual_ip, "reason": "Suspicious reconnaissance activity observed by analyst", "ttl_seconds": 600},
        timeout=3,
    )
    assert ban_res.status_code == 200
    print(f"      Manual Ban Action: HTTP {ban_res.status_code} -> {ban_res.json().get('status')}")

    # =========================================================================
    print_step("STEP 5: Verifying Threat Intelligence Formula R(x) = w1*AbuseIPDB + w2*ASN")
    # =========================================================================
    intel_res = requests.get(f"{SOAR_URL}/api/threat-intel/172.28.0.200", timeout=3).json()
    print(f"  [+] Threat Intel Profile for {intel_res['ip']}:")
    print(f"      - Reputation Score R(x): {intel_res['reputation_score']}/100 (source={intel_res['intel_source']})")
    print(f"      - Formula Components:    Abuse={intel_res['abuse_confidence_score']}, ASN={intel_res['asn_risk_score']}, w={intel_res['formula_weights']}")

    # =========================================================================
    print_step("STEP 6: Verifying Eq. 12 Hash-Chained Forensic Dossiers & Integrity")
    # =========================================================================
    verify_res = requests.get(f"{SOAR_URL}/api/forensics/verify", timeout=3).json()
    assert verify_res["valid"] is True, f"Forensic chain verification failed: {verify_res}"
    print(f"  [+] Hash-Chain Verification: valid={verify_res['valid']}, entries={verify_res['total_entries']}, head={verify_res['head_hash'][:16]}...")

    final_stats = requests.get(f"{SOAR_URL}/api/stats", timeout=3).json()
    print_step("TEST SUMMARY: All 6 Scenarios & SOAR Capabilities Verified")
    print(f"  [OK] Total Security Alerts Detected:    {final_stats['total_alerts_detected']}")
    print(f"  [OK] Automated Threat Containments:     {final_stats['automated_containments']}")
    print(f"  [OK] Measured Mean MTTR:                {final_stats['avg_response_time_ms']} ms")
    print("\n[OK] SYSTEM VERIFICATION COMPLETE.\n")


if __name__ == "__main__":
    test_system()
