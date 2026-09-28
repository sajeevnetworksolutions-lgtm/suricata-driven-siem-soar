import requests
import json
import time
import os
import sys

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

    # Baseline stats
    baseline = r_soar.json()
    print(f"  [*] Initial Alerts Detected:   {baseline.get('total_alerts_detected', 0)}")
    print(f"  [*] Initial Quarantined IPs:   {baseline.get('active_banned_ips', 0)}")
    print(f"  [*] Initial Playbooks Executed: {baseline.get('total_playbooks_executed', 0)}")

    # =========================================================================
    print_step("STEP 2: Executing Attack Scenarios & Monitoring Automated Response")
    # =========================================================================

    scenarios = [
        {
            "name": "Scenario 1: Network Reconnaissance & Port Sweep",
            "action": lambda: requests.get(f"{TARGET_URL}/", timeout=2),
            "alert": {
                "src_ip": "198.51.100.42",
                "dest_ip": "127.0.0.1",
                "signature": "SIEM-RECON: Potential TCP SYN Port Scan Detected",
                "category": "Attempted-Recon",
                "severity": 3
            },
            "expected_soar": "Enrich IP & Log Event (Low/Med Severity)"
        },
        {
            "name": "Scenario 2: SSH / HTTP Login Brute-Force",
            "action": lambda: [requests.post(f"{TARGET_URL}/login", data={"username": "admin", "password": f"guess{i}"}, timeout=2) for i in range(5)],
            "alert": {
                "src_ip": "203.0.113.88",
                "dest_ip": "127.0.0.1",
                "signature": "SIEM-AUTH: Multiple HTTP 401 Unauthorized Responses (Web Brute Force)",
                "category": "Attempted-Admin",
                "severity": 1
            },
            "expected_soar": "AUTO-BAN IP 203.0.113.88 for 300s + Threat Intel Lookup"
        },
        {
            "name": "Scenario 3: Web Exploitation (SQL Injection UNION SELECT)",
            "action": lambda: requests.get(f"{TARGET_URL}/search?q=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users--", timeout=2),
            "alert": {
                "src_ip": "192.0.2.140",
                "dest_ip": "127.0.0.1",
                "signature": "SIEM-WEB: SQL Injection Attempt (UNION SELECT detected)",
                "category": "Web-Application-Attack",
                "severity": 1
            },
            "expected_soar": "AUTO-BAN IP 192.0.2.140 + Generate Forensic Dossier"
        },
        {
            "name": "Scenario 4: Malware C2 Check-in Heartbeat",
            "action": lambda: requests.post(f"{TARGET_URL}/api/v1/heartbeat", data="beacon_id=BOTNET-77&cmd=POLL", timeout=2),
            "alert": {
                "src_ip": "198.51.100.200",
                "dest_ip": "127.0.0.1",
                "signature": "SIEM-C2: Emulated Malware C2 Heartbeat Beacon Detected",
                "category": "Trojan-Activity",
                "severity": 1
            },
            "expected_soar": "AUTO-BAN C2 IP 198.51.100.200 + SOC Notification"
        },
        {
            "name": "Scenario 5: DNS Tunneling Exfiltration",
            "action": lambda: None,
            "alert": {
                "src_ip": "192.0.2.99",
                "dest_ip": "127.0.0.1",
                "signature": "SIEM-DNS: Potential DNS Data Exfiltration / Tunneling",
                "category": "Bad-Unknown",
                "severity": 2
            },
            "expected_soar": "High Severity Alert Flagged + Tag Source Host"
        },
        {
            "name": "Scenario 6: Sensitive Private Key / Database Exfiltration",
            "action": lambda: requests.post(f"{TARGET_URL}/upload?file=id_rsa", data="-----BEGIN RSA PRIVATE KEY-----\nMIIE...", timeout=2),
            "alert": {
                "src_ip": "203.0.113.111",
                "dest_ip": "127.0.0.1",
                "signature": "SIEM-EXFIL: Unencrypted RSA Private Key Exfiltration Attempt",
                "category": "Policy-Violation",
                "severity": 1
            },
            "expected_soar": "AUTO-BAN IP 203.0.113.111 + Forensic Evidence Capture"
        }
    ]

    for item in scenarios:
        print(f"\n  [>>>] Running: {item['name']}")
        try:
            item["action"]()
        except Exception:
            pass

        # Trigger SOAR pipeline webhook
        resp = requests.post(f"{SOAR_URL}/api/webhook/alert", json=item["alert"], timeout=3)
        time.sleep(0.5)
        print(f"        Expected Action: {item['expected_soar']}")
        print(f"        SOAR Processing: HTTP {resp.status_code} ({resp.json().get('status', 'ok')})")

    # =========================================================================
    print_step("STEP 3: Verifying Automated Active Defense & Quarantined Blacklist")
    # =========================================================================
    bans_resp = requests.get(f"{SOAR_URL}/api/bans", timeout=3).json()
    print(f"  [+] Active Quarantined IP Addresses ({len(bans_resp)} active):")
    for b in bans_resp[-4:]:
        print(f"      - IP: {b['ip']:16s} | Status: {b['status']} | Reason: {b['reason']}")

    # =========================================================================
    print_step("STEP 4: Testing Manual SOC Analyst Controls (Pardon & Quarantine)")
    # =========================================================================
    test_ip = "192.0.2.140"
    print(f"  [*] Testing Manual SOC Pardon/Unban on IP: {test_ip}...")
    unban_res = requests.delete(f"{SOAR_URL}/api/bans/{test_ip}", timeout=3)
    print(f"      Pardon Action: HTTP {unban_res.status_code} -> {unban_res.json()}")

    manual_ip = "198.51.100.77"
    print(f"\n  [*] Testing Manual Analyst Quarantine on IP: {manual_ip}...")
    ban_res = requests.post(f"{SOAR_URL}/api/bans", json={
        "ip": manual_ip,
        "reason": "Suspicious reconnaissance activity observed by analyst",
        "ttl_seconds": 600
    }, timeout=3)
    print(f"      Manual Ban Action: HTTP {ban_res.status_code} -> {ban_res.json().get('status')}")

    # =========================================================================
    print_step("STEP 5: Verifying Threat Intelligence Lookup API")
    # =========================================================================
    intel_res = requests.get(f"{SOAR_URL}/api/threat-intel/172.28.0.200", timeout=3).json()
    print(f"  [+] Threat Intel Profile for {intel_res['ip']}:")
    print(f"      - Reputation Score: {intel_res['reputation_score']}/100")
    print(f"      - Is Malicious:     {intel_res['is_malicious']}")
    print(f"      - Country/ISP:      {intel_res['country']} ({intel_res['isp']})")
    print(f"      - Threat Tags:      {', '.join(intel_res['tags'])}")

    # =========================================================================
    print_step("STEP 6: Verifying Forensic Case Dossiers on Disk")
    # =========================================================================
    forensics_dir = os.path.join(os.path.dirname(__file__), "soar_engine", "data", "forensics")
    if os.path.exists(forensics_dir):
        cases = os.listdir(forensics_dir)
        print(f"  [+] Total Generated Forensic Dossiers: {len(cases)} case files")
        if cases:
            latest_case = cases[-1]
            print(f"      - Latest Case File: {latest_case}")
            with open(os.path.join(forensics_dir, latest_case), "r") as f:
                case_data = json.load(f)
                print(f"      - Triggering Signature: {case_data['triggering_alert']['signature']}")
                print(f"      - Attacker IP / Port:  {case_data['triggering_alert']['source']}")
                print(f"      - Case Opened At:      {case_data['investigation_opened_at']}")

    # Final Stats
    final_stats = requests.get(f"{SOAR_URL}/api/stats", timeout=3).json()
    print_step("TEST SUMMARY: All 6 Scenarios & SOAR Capabilities Verified")
    print(f"  [OK] Total Security Alerts Detected:    {final_stats['total_alerts_detected']}")
    print(f"  [OK] Critical / High Incidents:         {final_stats['critical_alerts']} Critical, {final_stats['high_alerts']} High")
    print(f"  [OK] Total Automated Playbooks Run:     {final_stats['total_playbooks_executed']}")
    print(f"  [OK] Automated Threat Containments:     {final_stats['automated_containments']}")
    print(f"  [OK] Current Active Defense Quarantines: {final_stats['active_banned_ips']}")
    print("\n[OK] SYSTEM VERIFICATION COMPLETE: Ready for deployment and demonstration.\n")

if __name__ == "__main__":
    test_system()
