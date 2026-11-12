import time
import json
import argparse
import urllib.request
from datetime import datetime, timezone

from scenarios.recon_scan import run_port_scan
from scenarios.auth_bruteforce import run_auth_bruteforce
from scenarios.web_exploits import run_web_exploits
from scenarios.malware_c2 import run_c2_beacon
from scenarios.dns_tunneling import run_dns_tunneling
from scenarios.data_exfil import run_data_exfil

BANNER = """
========================================================================
   SURICATA SIEM & SOAR THREAT SIMULATION & VALIDATION SUITE (TABLE II)
========================================================================
"""


def notify_soar(soar_url, sid, signature, category, severity, src_ip, dest_ip, tactic, technique):
    """Send alert event to SOAR webhook during local non-Suricata test runs."""
    try:
        payload = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "sid": sid,
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "signature": signature,
            "category": category,
            "severity": severity,
            "tactic": tactic,
            "technique": technique,
        }
        req = urllib.request.Request(
            f"{soar_url}/api/webhook/alert",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=2):
            pass
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="Suricata SIEM + SOAR Attack Simulator (Table II)")
    parser.add_argument("--target", default="127.0.0.1", help="Target Host IP/Domain")
    parser.add_argument("--port", type=int, default=8080, help="Target Web Port (80 in Docker, 8080 local)")
    parser.add_argument("--soar", default="http://127.0.0.1:8000", help="SOAR Webhook URL")
    parser.add_argument(
        "--scenario",
        choices=["1", "2", "3", "4", "5", "6", "all"],
        default="all",
        help="1=Recon, 2=Bruteforce, 3=Web Exploits, 4=Malware C2, 5=DNS Tunnel, 6=Exfil, all=Full Suite",
    )
    parser.add_argument("--loop", action="store_true", help="Continuously loop attacks for live SOC demonstration")
    parser.add_argument("--interval", type=int, default=5, help="Interval seconds between attack loops")
    parser.add_argument("--beacon-interval", type=float, default=3.0, help="C2 beacon interval in seconds (Table II: 3.0s)")
    parser.add_argument("--no-webhook", action="store_true", help="Send wire packets only (let live Suricata detect)")

    args = parser.parse_args()
    print(BANNER)
    print(f"[*] Target Endpoint:    {args.target}:{args.port}")
    print(f"[*] SOAR Hub:           {args.soar}")
    print(f"[*] Scenario Selected:  {args.scenario}")
    print(f"[*] Wire-only Mode:     {args.no_webhook}")
    print("=" * 72)

    base_url = f"http://{args.target}:{args.port}"
    login_url = f"{base_url}/login"
    c2_url = f"{base_url}/api/v1/heartbeat"
    upload_url = f"{base_url}/upload"

    def maybe_notify(*nargs):
        if not args.no_webhook:
            notify_soar(*nargs)

    def execute_suite():
        if args.scenario in ["1", "all"]:
            run_port_scan(args.target)
            maybe_notify(
                args.soar,
                1000001,
                "SIEM-RECON: Potential TCP SYN Port Scan Detected",
                "Attempted-Recon",
                1,
                "172.28.0.100",
                args.target,
                "TA0043",
                "T1595.001",
            )
            time.sleep(0.5)

        if args.scenario in ["2", "all"]:
            run_auth_bruteforce(login_url, count=5)
            maybe_notify(
                args.soar,
                1000012,
                "SIEM-AUTH: Multiple HTTP 401 Unauthorized Responses (Web Brute Force)",
                "Attempted-Admin",
                1,
                "172.28.0.105",
                args.target,
                "TA0006",
                "T1110.001",
            )
            time.sleep(0.5)

        if args.scenario in ["3", "all"]:
            run_web_exploits(base_url)
            maybe_notify(
                args.soar,
                1000020,
                "SIEM-WEB: SQL Injection Attempt (UNION SELECT detected)",
                "Web-Application-Attack",
                1,
                "192.168.1.150",
                args.target,
                "TA0001",
                "T1190",
            )
            time.sleep(0.5)

        if args.scenario in ["4", "all"]:
            run_c2_beacon(c2_url, pulses=3, interval=args.beacon_interval)
            maybe_notify(
                args.soar,
                1000030,
                "SIEM-C2: Emulated Malware C2 Heartbeat Beacon Detected",
                "Trojan-Activity",
                1,
                "172.28.0.200",
                args.target,
                "TA0011",
                "T1071.001",
            )
            time.sleep(0.5)

        if args.scenario in ["5", "all"]:
            run_dns_tunneling(args.target)
            maybe_notify(
                args.soar,
                1000040,
                "SIEM-DNS: Potential DNS Data Exfiltration / Tunneling (Oversized Query Name)",
                "Bad-Unknown",
                1,
                "45.154.255.89",
                args.target,
                "TA0010",
                "T1048.003",
            )
            time.sleep(0.5)

        if args.scenario in ["6", "all"]:
            run_data_exfil(upload_url)
            maybe_notify(
                args.soar,
                1000052,
                "SIEM-EXFIL: Unencrypted RSA Private Key Exfiltration Attempt",
                "Policy-Violation",
                1,
                "172.28.0.110",
                args.target,
                "TA0010",
                "T1048",
            )
            time.sleep(0.5)

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
