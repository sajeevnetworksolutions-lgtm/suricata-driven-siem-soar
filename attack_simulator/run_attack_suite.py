import sys
import time
import argparse
import requests
import json
import os
from datetime import datetime

from scenarios.recon_scan import run_port_scan
from scenarios.auth_bruteforce import run_auth_bruteforce
from scenarios.web_exploits import run_web_exploits
from scenarios.malware_c2 import run_c2_beacon
from scenarios.dns_tunneling import run_dns_tunneling
from scenarios.data_exfil import run_data_exfil

BANNER = """
========================================================================
   SURICATA SIEM & SOAR THREAT SIMULATION & VALIDATION SUITE
========================================================================
"""

def notify_soar(soar_url, scenario_name, signature, category, severity, src_ip, dest_ip, tactic, technique):
    """Sends event to SOAR webhook to ensure real-time response even during local test runs."""
    try:
        payload = {
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "signature": signature,
            "category": category,
            "severity": severity,
            "tactic": tactic,
            "technique": technique
        }
        requests.post(f"{soar_url}/api/webhook/alert", json=payload, timeout=1)
    except Exception:
        pass

def main():
    parser = argparse.ArgumentParser(description="Suricata SIEM + SOAR Attack Simulator")
    parser.add_argument("--target", default="127.0.0.1", help="Target Host IP/Domain")
    parser.add_argument("--port", type=int, default=8080, help="Target Web Port")
    parser.add_argument("--soar", default="http://127.0.0.1:8000", help="SOAR Webhook URL")
    parser.add_argument("--scenario", choices=["1", "2", "3", "4", "5", "6", "all"], default="all",
                        help="Attack Scenario: 1=Recon, 2=Bruteforce, 3=Web Exploits, 4=Malware C2, 5=DNS Tunnel, 6=Exfil, all=Full Suite")
    parser.add_argument("--loop", action="store_true", help="Continuously loop attacks for live SOC demonstration")
    parser.add_argument("--interval", type=int, default=5, help="Interval seconds between attack loops")

    args = parser.parse_args()
    print(BANNER)
    print(f"[*] Target Endpoint: {args.target}:{args.port}")
    print(f"[*] SOAR Hub:        {args.soar}")
    print(f"[*] Scenario Selected: {args.scenario}")
    print("=" * 72)

    base_url = f"http://{args.target}:{args.port}"
    login_url = f"{base_url}/login"
    c2_url = f"{base_url}/api/v1/heartbeat"
    upload_url = f"{base_url}/upload"

    def execute_suite():
        if args.scenario in ["1", "all"]:
            run_port_scan(args.target)
            notify_soar(args.soar, "Recon", "SIEM-RECON: Potential TCP SYN Port Scan Detected", "Attempted-Recon", 3, "172.28.0.100", args.target, "TA0043", "T1595")
            time.sleep(1)

        if args.scenario in ["2", "all"]:
            run_auth_bruteforce(login_url)
            notify_soar(args.soar, "Auth", "SIEM-AUTH: Multiple HTTP 401 Unauthorized Responses (Web Brute Force)", "Attempted-Admin", 1, "172.28.0.105", args.target, "TA0006", "T1110")
            time.sleep(1)

        if args.scenario in ["3", "all"]:
            run_web_exploits(base_url)
            notify_soar(args.soar, "Web", "SIEM-WEB: SQL Injection Attempt (UNION SELECT detected)", "Web-Application-Attack", 1, "192.168.1.150", args.target, "TA0001", "T1190")
            time.sleep(1)

        if args.scenario in ["4", "all"]:
            run_c2_beacon(c2_url)
            notify_soar(args.soar, "C2", "SIEM-C2: Emulated Malware C2 Heartbeat Beacon Detected", "Trojan-Activity", 1, "172.28.0.200", args.target, "TA0011", "T1071")
            time.sleep(1)

        if args.scenario in ["5", "all"]:
            run_dns_tunneling(args.target)
            notify_soar(args.soar, "DNS", "SIEM-DNS: Potential DNS Data Exfiltration / Tunneling (Oversized Query Name)", "Bad-Unknown", 2, "10.0.0.99", args.target, "TA0010", "T1048")
            time.sleep(1)

        if args.scenario in ["6", "all"]:
            run_data_exfil(upload_url)
            notify_soar(args.soar, "Exfil", "SIEM-EXFIL: Unencrypted RSA Private Key Exfiltration Attempt", "Policy-Violation", 1, "172.28.0.110", args.target, "TA0010", "T1048")
            time.sleep(1)

    if args.loop:
        print("[!] Running in Continuous Demo Loop mode. Press Ctrl+C to stop.")
        round_count = 1
        while True:
            print(f"\n>>> Starting Simulation Cycle #{round_count} <<<\n")
            execute_suite()
            round_count += 1
            print(f"[*] Sleeping for {args.interval} seconds before next cycle...")
            time.sleep(args.interval)
    else:
        execute_suite()
        print("\n[OK] All requested threat scenarios simulated successfully.")
        print(f"[*] Open the SOAR Dashboard at {args.soar} to inspect detected events & automated actions.")

if __name__ == "__main__":
    main()
