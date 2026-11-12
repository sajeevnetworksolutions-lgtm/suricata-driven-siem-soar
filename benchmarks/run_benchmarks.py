import os
import sys
import csv
import time
import json
import uuid
import shutil
import tempfile
import argparse
import statistics
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import psutil
import requests

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SOAR_DIR = os.path.join(PROJECT_ROOT, "soar_engine")
TARGET_DIR = os.path.join(PROJECT_ROOT, "target_service")
ATTACK_SIM_DIR = os.path.join(PROJECT_ROOT, "attack_simulator")

if ATTACK_SIM_DIR not in sys.path:
    sys.path.insert(0, ATTACK_SIM_DIR)

from benign_traffic import run_benign_traffic


SCENARIO_SPECS = [
    {
        "scenario": "recon",
        "sid": 1000001,
        "signature": "SIEM-RECON: Potential TCP SYN Port Scan Detected",
        "category": "Attempted-Recon",
        "severity": 1,
        "dest_port": 445,
        "proto": "TCP",
        "mitre_tactic": "TA0043",
        "mitre_technique": "T1595.001",
        "payload": "TCP SYN port sweep (10 pkts/5s)",
        "src_pool_prefix": "198.51.100.",
    },
    {
        "scenario": "auth_bruteforce",
        "sid": 1000012,
        "signature": "SIEM-AUTH: Multiple HTTP 401 Unauthorized Responses (Web Brute Force)",
        "category": "Attempted-Admin",
        "severity": 1,
        "dest_port": 80,
        "proto": "TCP",
        "mitre_tactic": "TA0006",
        "mitre_technique": "T1110.001",
        "payload": "POST /login 5x401/10s user=admin",
        "src_pool_prefix": "172.28.1.",
    },
    {
        "scenario": "web_exploits",
        "sid": 1000020,
        "signature": "SIEM-WEB: SQL Injection Attempt (UNION SELECT detected)",
        "category": "Web-Application-Attack",
        "severity": 1,
        "dest_port": 80,
        "proto": "TCP",
        "mitre_tactic": "TA0001",
        "mitre_technique": "T1190",
        "payload": "GET /search?q=' UNION SELECT null,username,password FROM users-- HTTP/1.1",
        "src_pool_prefix": "192.0.2.",
    },
    {
        "scenario": "malware_c2",
        "sid": 1000030,
        "signature": "SIEM-C2: Emulated Malware C2 Heartbeat Beacon Detected",
        "category": "Trojan-Activity",
        "severity": 1,
        "dest_port": 80,
        "proto": "TCP",
        "mitre_tactic": "TA0011",
        "mitre_technique": "T1071.001",
        "payload": "POST /api/v1/heartbeat beacon_id=BOTNET-HOST-092&interval=3.0s",
        "src_pool_prefix": "172.28.2.",
    },
    {
        "scenario": "dns_tunneling",
        "sid": 1000040,
        "signature": "SIEM-DNS: Potential DNS Data Exfiltration / Tunneling (Oversized Query Name)",
        "category": "Bad-Unknown",
        "severity": 1,
        "dest_port": 53,
        "proto": "UDP",
        "mitre_tactic": "TA0010",
        "mitre_technique": "T1048.003",
        "payload": "ZGF0YV9leGZpbHRyYXRpb25fdGVzdF9rZXk.tunnel.exfiltration.threat.internal",
        "src_pool_prefix": "203.0.113.",
    },
    {
        "scenario": "data_exfil",
        "sid": 1000050,
        "signature": "SIEM-EXFIL: High Volume HTTP POST / Unencrypted RSA Private Key Exfiltration",
        "category": "Policy-Violation",
        "severity": 1,
        "dest_port": 80,
        "proto": "TCP",
        "mitre_tactic": "TA0010",
        "mitre_technique": "T1048.002",
        "payload": "POST /upload filename=customer_database_2026.sql (>5000 B) + RSA PRIVATE KEY",
        "src_pool_prefix": "172.28.3.",
    },
]

VARIANT_CONFIGS = {
    "full": {"enable_ttl": True, "enable_threat_intel": True, "enable_ecs": True, "enable_forensics": True, "async_mode": True},
    "no_ttl": {"enable_ttl": False, "enable_threat_intel": True, "enable_ecs": True, "enable_forensics": True, "async_mode": True},
    "no_ti": {"enable_ttl": True, "enable_threat_intel": False, "enable_ecs": True, "enable_forensics": True, "async_mode": True},
    "no_ecs": {"enable_ttl": True, "enable_threat_intel": True, "enable_ecs": False, "enable_forensics": True, "async_mode": True},
    "no_async": {"enable_ttl": True, "enable_threat_intel": True, "enable_ecs": True, "enable_forensics": True, "async_mode": False},
    "no_forensics": {"enable_ttl": True, "enable_threat_intel": True, "enable_ecs": True, "enable_forensics": False, "async_mode": True},
}


def utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class ManagedStack:
    """Starts clean isolated Target (:18080) & SOAR (:18000) servers with temp state for reproducible benchmarks."""

    def __init__(self, soar_port: int = 18000, target_port: int = 18080):
        self.soar_port = soar_port
        self.target_port = target_port
        self.tmp_dir = tempfile.mkdtemp(prefix="soar_bench_")
        self.eve_path = os.path.join(self.tmp_dir, "eve.json")
        self.data_dir = os.path.join(self.tmp_dir, "data")
        os.makedirs(self.data_dir, exist_ok=True)
        with open(self.eve_path, "w", encoding="utf-8") as f:
            pass
        self.p_target: Optional[subprocess.Popen] = None
        self.p_soar: Optional[subprocess.Popen] = None
        self.soar_proc: Optional[psutil.Process] = None

    def __enter__(self):
        env_t = os.environ.copy()
        env_t["TARGET_PORT"] = str(self.target_port)
        env_t["SOAR_URL"] = f"http://127.0.0.1:{self.soar_port}"
        self.p_target = subprocess.Popen(
            [sys.executable, os.path.join(TARGET_DIR, "app.py")],
            cwd=TARGET_DIR,
            env=env_t,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        env_s = os.environ.copy()
        env_s["EVE_LOG_PATH"] = self.eve_path
        env_s["DATA_DIR"] = self.data_dir
        env_s["BAN_DB"] = os.path.join(self.data_dir, "bans.db")
        env_s["BAN_AUDIT_LOG"] = os.path.join(self.data_dir, "audit.jsonl")
        env_s["DOSSIER_DIR"] = os.path.join(self.data_dir, "forensics")
        env_s["DRY_RUN"] = "true" if os.name != "posix" else "false"
        env_s["ENABLE_CHATTR"] = "false"
        env_s["POLL_INTERVAL_MS"] = "200"
        self.p_soar = subprocess.Popen(
            [sys.executable, "-c", f"import uvicorn, app; uvicorn.run(app.app, host='127.0.0.1', port={self.soar_port}, log_level='warning')"],
            cwd=SOAR_DIR,
            env=env_s,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        deadline = time.perf_counter() + 20.0
        while time.perf_counter() < deadline:
            if self.p_target.poll() is not None:
                raise RuntimeError(f"Managed target exited early with code {self.p_target.returncode}")
            if self.p_soar.poll() is not None:
                raise RuntimeError(f"Managed SOAR exited early with code {self.p_soar.returncode}")
            try:
                r1 = requests.get(f"http://127.0.0.1:{self.soar_port}/api/stats", timeout=1)
                r2 = requests.get(f"http://127.0.0.1:{self.target_port}/", timeout=1)
                if r1.status_code == 200 and r2.status_code == 200:
                    self.soar_proc = psutil.Process(self.p_soar.pid)
                    self.soar_proc.cpu_percent(interval=None)
                    return self
            except Exception:
                pass
            time.sleep(0.25)
        raise RuntimeError("Timed out starting managed benchmark SOAR & Target services")

    def __exit__(self, exc_type, exc, tb):
        for p in (self.p_target, self.p_soar):
            if p:
                p.terminate()
                try:
                    p.wait(timeout=3)
                except Exception:
                    p.kill()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)


def run_variant(
    variant: str,
    rounds: int,
    cycles_per_round: int,
    benign_count: int,
    ingest_path: str,
    soar_url: str,
    target_host: str,
    target_port: int,
    eve_path: str,
    soar_proc: Optional[psutil.Process],
    results_dir: str,
) -> Dict[str, Any]:
    flags = VARIANT_CONFIGS[variant]
    policy_payload = {
        "auto_ban_enabled": True,
        "ban_threshold_severity": 1,
        "ban_ttl_seconds": 300,
        "poll_interval_ms": 200,
        **flags,
    }
    requests.post(f"{soar_url}/api/policy", json=policy_payload, timeout=5).raise_for_status()

    # Clear active bans & state cleanly before variant run
    for b in requests.get(f"{soar_url}/api/bans", timeout=5).json():
        requests.delete(f"{soar_url}/api/bans/{b['ip']}", timeout=2)
    requests.post(f"{soar_url}/api/incidents/clear", timeout=5).raise_for_status()
    requests.post(f"{soar_url}/api/metrics/reset", timeout=5).raise_for_status()

    raw_csv_path = os.path.join(results_dir, f"raw_cycles_{variant}.csv")
    fieldnames = [
        "variant",
        "round",
        "cycle",
        "scenario",
        "sid",
        "src_ip",
        "detected",
        "contained",
        "mttd_ms",
        "ti_latency_ms",
        "ban_latency_ms",
        "forensic_latency_ms",
        "notify_latency_ms",
        "mttr_ms",
        "cpu_pct",
        "ram_mb",
    ]

    all_rows: List[Dict[str, Any]] = []
    sess = requests.Session()

    benign_per_round = max(0, benign_count // max(1, rounds))
    benign_totals = {"sent_total": 0, "http_ok": 0, "dns_sent": 0, "errors": 0, "false_positives": 0}

    print(f"\n[VARIANT={variant}] Running {rounds} rounds x {cycles_per_round} cycles (ingest={ingest_path})...")

    with open(raw_csv_path, "w", newline="", encoding="utf-8") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=fieldnames)
        writer.writeheader()

        for rnd in range(1, rounds + 1):
            round_t0 = time.perf_counter()

            # Execute benign background slice alongside round attacks (e.g. 2,000 per round across 5 rounds = 10,000)
            if benign_per_round > 0:
                alerts_before_benign = sess.get(f"{soar_url}/api/stats", timeout=3).json()["total_alerts_detected"]
                b_stat = run_benign_traffic(
                    target_host=target_host,
                    target_port=target_port,
                    total_requests=benign_per_round,
                    http_ratio=0.7,
                    workers=16,
                )
                alerts_after_benign = sess.get(f"{soar_url}/api/stats", timeout=3).json()["total_alerts_detected"]
                fp_delta = max(0, alerts_after_benign - alerts_before_benign)
                benign_totals["sent_total"] += int(b_stat["sent_total"])
                benign_totals["http_ok"] += int(b_stat["http_ok"])
                benign_totals["dns_sent"] += int(b_stat["dns_sent"])
                benign_totals["errors"] += int(b_stat["errors"])
                benign_totals["false_positives"] += fp_delta

            for cyc in range(1, cycles_per_round + 1):
                spec = SCENARIO_SPECS[(cyc - 1) % len(SCENARIO_SPECS)]
                octet = 10 + (((rnd - 1) * cycles_per_round + (cyc - 1)) % 220)
                attacker_ip = f"{spec['src_pool_prefix']}{octet}"

                # For SID 1000012 (server-to-client HTTP 401 rule), test authentic reverse-flow direction
                if spec["sid"] == 1000012:
                    eve_src, eve_dst = "172.28.0.10", attacker_ip
                else:
                    eve_src, eve_dst = attacker_ip, "172.28.0.10"

                if ingest_path == "eve":
                    prev_count = sess.get(f"{soar_url}/api/metrics/latencies", timeout=3).json()["count"]
                    event_doc = {
                        "event_type": "alert",
                        "timestamp": utc_iso(),
                        "src_ip": eve_src,
                        "src_port": 50000 + (cyc % 1000),
                        "dest_ip": eve_dst,
                        "dest_port": spec["dest_port"],
                        "proto": spec["proto"],
                        "payload": spec["payload"],
                        "alert": {
                            "signature_id": spec["sid"],
                            "signature": spec["signature"],
                            "category": spec["category"],
                            "severity": spec["severity"],
                            "metadata": {
                                "mitre_tactic_id": [spec["mitre_tactic"]],
                                "mitre_technique_id": [spec["mitre_technique"]],
                            },
                        },
                    }
                    with open(eve_path, "a", encoding="utf-8") as ef:
                        ef.write(json.dumps(event_doc) + "\n")

                    rec = None
                    deadline = time.perf_counter() + 5.0
                    while time.perf_counter() < deadline:
                        m = sess.get(f"{soar_url}/api/metrics/latencies", timeout=3).json()
                        if m["count"] > prev_count:
                            rec = m["records"][-1]
                            break
                        time.sleep(0.01)
                    detected = 1 if rec is not None else 0
                else:
                    payload = {
                        "timestamp": utc_iso(),
                        "sid": spec["sid"],
                        "src_ip": eve_src,
                        "dest_ip": eve_dst,
                        "dest_port": spec["dest_port"],
                        "proto": spec["proto"],
                        "signature": spec["signature"],
                        "category": spec["category"],
                        "severity": spec["severity"],
                        "tactic": spec["mitre_tactic"],
                        "technique": spec["mitre_technique"],
                        "payload": spec["payload"],
                    }
                    resp = sess.post(f"{soar_url}/api/webhook/alert", json=payload, timeout=5)
                    detected = 1 if resp.status_code == 200 else 0
                    m = sess.get(f"{soar_url}/api/metrics/latencies", timeout=3).json()
                    rec = m["records"][-1] if m["records"] else None

                # Verify real containment state and pardon so next cycles start unblocked
                active_bans = sess.get(f"{soar_url}/api/bans", timeout=3).json()
                contained = 1 if any(b["ip"] == attacker_ip and b["status"] == "ACTIVE" for b in active_bans) else 0
                if contained:
                    sess.delete(f"{soar_url}/api/bans/{attacker_ip}", timeout=2)

                cpu_pct = round(soar_proc.cpu_percent(interval=None), 2) if soar_proc else 0.0
                ram_mb = round(soar_proc.memory_info().rss / (1024 * 1024), 2) if soar_proc else 0.0

                row = {
                    "variant": variant,
                    "round": rnd,
                    "cycle": cyc,
                    "scenario": spec["scenario"],
                    "sid": spec["sid"],
                    "src_ip": attacker_ip,
                    "detected": detected,
                    "contained": contained,
                    "mttd_ms": rec.get("mttd_ms", 0.0) if rec else 0.0,
                    "ti_latency_ms": rec.get("ti_latency_ms", 0.0) if rec else 0.0,
                    "ban_latency_ms": rec.get("ban_latency_ms", 0.0) if rec else 0.0,
                    "forensic_latency_ms": rec.get("forensic_latency_ms", 0.0) if rec else 0.0,
                    "notify_latency_ms": rec.get("notify_latency_ms", 0.0) if rec else 0.0,
                    "mttr_ms": rec.get("mttr_ms", 0.0) if rec else 0.0,
                    "cpu_pct": cpu_pct,
                    "ram_mb": ram_mb,
                }
                writer.writerow(row)
                all_rows.append(row)

            rnd_s = round(time.perf_counter() - round_t0, 2)
            print(f"    Round {rnd}/{rounds} complete ({cycles_per_round} cycles, elapsed={rnd_s}s)")

    fpr_pct = round((benign_totals["false_positives"] / benign_totals["sent_total"]) * 100.0, 4) if benign_totals["sent_total"] > 0 else 0.0
    benign_csv = os.path.join(results_dir, f"benign_summary_{variant}.csv")
    with open(benign_csv, "w", newline="", encoding="utf-8") as bf:
        bw = csv.DictWriter(bf, fieldnames=[*benign_totals.keys(), "fpr_pct"])
        bw.writeheader()
        bw.writerow({**benign_totals, "fpr_pct": fpr_pct})

    detected_rows = [r for r in all_rows if r["detected"] == 1]
    n_total = len(all_rows)
    return {
        "variant": variant,
        "cycles": n_total,
        "recall_pct": round((len(detected_rows) / n_total) * 100.0, 2) if n_total else 0.0,
        "containment_pct": round((sum(r["contained"] for r in all_rows) / n_total) * 100.0, 2) if n_total else 0.0,
        "fpr_pct": fpr_pct,
        "mean_mttd_ms": round(statistics.mean(r["mttd_ms"] for r in detected_rows), 3) if detected_rows else 0.0,
        "mean_mttr_ms": round(statistics.mean(r["mttr_ms"] for r in detected_rows), 3) if detected_rows else 0.0,
        "sd_mttr_ms": round(statistics.stdev(r["mttr_ms"] for r in detected_rows), 3) if len(detected_rows) > 1 else 0.0,
        "mean_ti_ms": round(statistics.mean(r["ti_latency_ms"] for r in detected_rows), 3) if detected_rows else 0.0,
        "mean_ban_ms": round(statistics.mean(r["ban_latency_ms"] for r in detected_rows), 3) if detected_rows else 0.0,
        "mean_forensic_ms": round(statistics.mean(r["forensic_latency_ms"] for r in detected_rows), 3) if detected_rows else 0.0,
        "mean_notify_ms": round(statistics.mean(r["notify_latency_ms"] for r in detected_rows), 3) if detected_rows else 0.0,
        "mean_cpu_pct": round(statistics.mean(r["cpu_pct"] for r in all_rows), 2) if all_rows else 0.0,
        "mean_ram_mb": round(statistics.mean(r["ram_mb"] for r in all_rows), 2) if all_rows else 0.0,
    }


def main():
    parser = argparse.ArgumentParser(description="Suricata SIEM+SOAR Empirical 5x100 Benchmark Runner")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--cycles", type=int, default=100)
    parser.add_argument("--benign-count", type=int, default=10000)
    parser.add_argument("--ingest-path", choices=["eve", "webhook"], default="eve")
    parser.add_argument("--variant", choices=[*VARIANT_CONFIGS.keys(), "all"], default="all")
    parser.add_argument("--external-soar-url", default=None, help="Connect to already-running SOAR stack (e.g. Docker)")
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=18080)
    parser.add_argument("--eve-path", default=os.path.join(PROJECT_ROOT, "logs", "eve.json"))
    parser.add_argument("--results-dir", default=os.path.join(os.path.dirname(__file__), "results"))
    args = parser.parse_args()

    os.makedirs(args.results_dir, exist_ok=True)
    variants = list(VARIANT_CONFIGS.keys()) if args.variant == "all" else [args.variant]

    summaries: List[Dict[str, Any]] = []
    if args.external_soar_url:
        for v in variants:
            b_count = args.benign_count if v == "full" else 0
            s = run_variant(
                variant=v,
                rounds=args.rounds,
                cycles_per_round=args.cycles,
                benign_count=b_count,
                ingest_path=args.ingest_path,
                soar_url=args.external_soar_url,
                target_host=args.target_host,
                target_port=args.target_port,
                eve_path=args.eve_path,
                soar_proc=None,
                results_dir=args.results_dir,
            )
            summaries.append(s)
    else:
        with ManagedStack(soar_port=18000, target_port=args.target_port) as stack:
            soar_url = f"http://127.0.0.1:{stack.soar_port}"
            for v in variants:
                # Run full 10,000 benign load on primary `full` variant (and 1,000-check or 0 on ablations unless desired)
                b_count = args.benign_count if v == "full" else min(args.benign_count, 500)
                s = run_variant(
                    variant=v,
                    rounds=args.rounds,
                    cycles_per_round=args.cycles,
                    benign_count=b_count,
                    ingest_path=args.ingest_path,
                    soar_url=soar_url,
                    target_host="127.0.0.1",
                    target_port=stack.target_port,
                    eve_path=stack.eve_path,
                    soar_proc=stack.soar_proc,
                    results_dir=args.results_dir,
                )
                summaries.append(s)

    summary_csv = os.path.join(args.results_dir, "summary_variants.csv")
    if summaries:
        merged = {s["variant"]: s for s in summaries}
        if args.variant != "all" and os.path.exists(summary_csv):
            with open(summary_csv, "r", encoding="utf-8") as ef:
                existing = {row["variant"]: row for row in csv.DictReader(ef) if "variant" in row}
            for k, v in existing.items():
                merged.setdefault(k, v)
        ordered = [merged[v] for v in VARIANT_CONFIGS.keys() if v in merged]
        with open(summary_csv, "w", newline="", encoding="utf-8") as sf:
            sw = csv.DictWriter(sf, fieldnames=list(summaries[0].keys()))
            sw.writeheader()
            sw.writerows(ordered)
        print(f"\n[OK] Wrote summary table to: {summary_csv}")
        for s in ordered:
            print("  ", s)


if __name__ == "__main__":
    main()
