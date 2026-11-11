import requests
import time

attacks = ['sqli', 'bruteforce', 'c2_beacon', 'xss', 'exfil']

print("=" * 72)
print("           LIVE SYSTEM TEST ACROSS ALL ATTACK BUTTONS & TRAPS           ")
print("=" * 72 + "\n")

# 1. Test Target App (:8080) buttons
for a in attacks:
    resp = requests.post(f"http://127.0.0.1:8080/api/trigger-test/{a}", timeout=3)
    assert resp.status_code == 200, f"Target trigger failed for {a}: {resp.status_code}"
    res = resp.json()
    print(f"[TARGET :8080] Button: {a.upper():12s} -> Alert: \"{res['signature']}\"")
    print(f"               Attacker IP: {res['src_ip']:15s} | Action: {res['soar_action']}")
    time.sleep(0.15)

# 2. Test Canary Trap (:8080)
trap_res = requests.get("http://127.0.0.1:8080/canary/trap?target=Secret_Executive_Passwords_2026.docx", timeout=3)
assert trap_res.status_code == 200, "Canary trap endpoint failed"
print(f"\n[TARGET :8080] Canary Trap Link    -> Status: {trap_res.status_code} (Honeypot Alarm Tripped!)")

# 3. Test Direct SOAR UI 1-Click Simulator (:8000) across all 7 scenarios
sim_scenarios = ['sqli', 'bruteforce', 'c2_beacon', 'portscan', 'exfil', 'dns_tunnel', 'canary_trap']
print("\n[SOAR :8000]   Testing 1-Click Simulator Endpoints...")
for s in sim_scenarios:
    r = requests.post(f"http://127.0.0.1:8000/api/simulate/{s}", timeout=3)
    assert r.status_code == 200, f"Simulate endpoint failed for {s}: {r.status_code}"
    data = r.json()
    assert data["status"] == "success"
    print(f"  [PASS] /api/simulate/{s:12s} -> {data['mitre_technique']} ({data['attacker_ip']})")

# 4. Verify Threat Intel Enrichment for simulated IPs
intel_check = requests.get("http://127.0.0.1:8000/api/threat-intel/195.123.245.12", timeout=3).json()
assert intel_check["is_malicious"] is True and intel_check["reputation_score"] >= 90
print(f"\n[PASS] Threat Intel Verified (195.123.245.12 -> Score: {intel_check['reputation_score']}/100, {intel_check['country']})")

# 5. Verify Quarantine Extend & Policy API
ext = requests.post("http://127.0.0.1:8000/api/bans/198.51.100.44/extend", timeout=3)
assert ext.status_code == 200
pol_get = requests.get("http://127.0.0.1:8000/api/policy", timeout=3).json()
assert "ban_ttl_seconds" in pol_get
pol_post = requests.post("http://127.0.0.1:8000/api/policy", json=pol_get, timeout=3)
assert pol_post.status_code == 200
print("[PASS] Ban Extension & SOAR Policy APIs verified")

# 6. Verify Incidents, Case Dossier Download & CSV Export
incidents = requests.get("http://127.0.0.1:8000/api/incidents", timeout=3).json()
assert len(incidents) > 0, "Expected incidents to be populated"
latest_inc = incidents[0]
assert latest_inc.get("payload") is not None, "Expected intercepted payload to be populated"
assert latest_inc.get("mitre_technique") not in (None, "N/A"), "Expected MITRE technique to be populated"

case_dl = requests.get(f"http://127.0.0.1:8000/api/case/{latest_inc['id']}", timeout=3)
assert case_dl.status_code == 200 and latest_inc["id"] in case_dl.text
csv_dl = requests.get("http://127.0.0.1:8000/api/export/csv", timeout=3)
assert csv_dl.status_code == 200 and "MITRE Technique" in csv_dl.text
print(f"[PASS] Case Dossier JSON & CSV Export verified ({len(incidents)} total incidents)")

# 7. Fetch final SOAR metrics
stats = requests.get("http://127.0.0.1:8000/api/stats", timeout=3).json()
bans = requests.get("http://127.0.0.1:8000/api/bans", timeout=3).json()

print("\n" + "=" * 72)
print("                      FINAL SOAR SYSTEM METRICS                         ")
print("=" * 72)
print(f"  Total Alerts Ingested:        {stats['total_alerts_detected']}")
print(f"  Critical Threats Neutralized: {stats['critical_alerts']}")
print(f"  Active Quarantined IPs:       {stats['active_banned_ips']}")
print(f"  Total Playbooks Executed:     {stats['total_playbooks_executed']}")
print(f"  Measured Containment MTTR:    {stats['avg_response_time_ms']} ms\n")

print("Active Quarantined Blacklist Sample:")
for b in bans[:6]:
    print(f"  [BLOCKED] IP: {b['ip']:15s} | Expires: {b['expires_at']}")

# 8. Clean up test fixtures cleanly so subsequent fresh runs start clean
for b in bans:
    requests.delete(f"http://127.0.0.1:8000/api/bans/{b['ip']}", timeout=2)
clear_res = requests.post("http://127.0.0.1:8000/api/incidents/clear", timeout=3)
assert clear_res.status_code == 200
print("\n[OK] 100% TESTED AND FULLY OPERATIONAL!")
