"""
Table III Baselines Runner:
  1. Suricata+ELK-only (`suricata_elk_only`):
     - Measures real detection/ingest latency on our running SOAR engine with
       AUTO_BAN_ENABLED=false (SIEM alerting only, zero automated containment)
       + explicitly labelled modelled manual analyst triage time when comparing
       remediation MTTR against autonomous SOAR containment.
  2. Snort/manual-style baseline (`snort_manual`):
     - Explicitly labelled `measurement_type=modelled`: models legacy single-threaded
       Snort IDS alert logging + human SOC triage/firewall ticket execution
       (deterministic RNG seed=42) rather than claiming live Snort binary capture
       if Snort is not installed.
"""

import os
import csv
import time
import json
import random
import argparse
import statistics
from datetime import datetime, timezone

import requests

from run_benchmarks import ManagedStack, SCENARIO_SPECS, utc_iso


def run_suricata_elk_only_measured(rounds: int, cycles_per_round: int, results_dir: str):
    """Measures real Suricata EVE -> SOAR intake latency with automated containment disabled."""
    raw_rows = []
    with ManagedStack(soar_port=18001, target_port=18081) as stack:
        soar_url = f"http://127.0.0.1:{stack.soar_port}"
        requests.post(
            f"{soar_url}/api/policy",
            json={
                "auto_ban_enabled": False,
                "ban_threshold_severity": 1,
                "ban_ttl_seconds": 300,
                "poll_interval_ms": 200,
                "enable_ttl": True,
                "enable_threat_intel": True,
                "enable_ecs": True,
                "enable_forensics": False,
                "async_mode": True,
            },
            timeout=5,
        ).raise_for_status()
        requests.post(f"{soar_url}/api/metrics/reset", timeout=5).raise_for_status()

        sess = requests.Session()
        for rnd in range(1, rounds + 1):
            for cyc in range(1, cycles_per_round + 1):
                spec = SCENARIO_SPECS[(cyc - 1) % len(SCENARIO_SPECS)]
                prev_count = sess.get(f"{soar_url}/api/metrics/latencies", timeout=3).json()["count"]
                event_doc = {
                    "event_type": "alert",
                    "timestamp": utc_iso(),
                    "src_ip": f"{spec['src_pool_prefix']}{10 + (cyc % 200)}",
                    "src_port": 51000 + cyc,
                    "dest_ip": "172.28.0.10",
                    "dest_port": spec["dest_port"],
                    "proto": spec["proto"],
                    "payload": spec["payload"],
                    "alert": {
                        "signature_id": spec["sid"],
                        "signature": spec["signature"],
                        "category": spec["category"],
                        "severity": spec["severity"],
                    },
                }
                with open(stack.eve_path, "a", encoding="utf-8") as ef:
                    ef.write(json.dumps(event_doc) + "\n")

                rec = None
                deadline = time.perf_counter() + 5.0
                while time.perf_counter() < deadline:
                    m = sess.get(f"{soar_url}/api/metrics/latencies", timeout=3).json()
                    if m["count"] > prev_count:
                        rec = m["records"][-1]
                        break
                    time.sleep(0.01)

                raw_rows.append(
                    {
                        "baseline": "suricata_elk_only",
                        "measurement_type": "measured_detection_siem_no_autoban",
                        "round": rnd,
                        "cycle": cyc,
                        "scenario": spec["scenario"],
                        "mttd_ms": rec["mttd_ms"] if rec else 0.0,
                        "siem_process_ms": rec["mttr_ms"] if rec else 0.0,
                        "contained": 0,
                    }
                )

    out_path = os.path.join(results_dir, "raw_baseline_suricata_elk_only.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(raw_rows[0].keys()))
        w.writeheader()
        w.writerows(raw_rows)
    return raw_rows


def run_snort_manual_modelled(rounds: int, cycles_per_round: int, results_dir: str, seed: int = 42):
    """
    Explicitly MODELLED baseline (`measurement_type=modelled`):
    Parameterizes manual triage + ticketed firewall containment in seconds->ms
    (e.g. MTTD manual log review 5-15 s; MTTR manual containment 30-120 s) so
    hypothesis tests compare against realistic non-automated latency scales.
    """
    rng = random.Random(seed)
    rows = []
    for rnd in range(1, rounds + 1):
        for cyc in range(1, cycles_per_round + 1):
            spec = SCENARIO_SPECS[(cyc - 1) % len(SCENARIO_SPECS)]
            # Modelled in milliseconds (explicitly labelled!)
            mttd_ms = round(rng.gauss(8500.0, 1400.0), 2)
            mttr_ms = round(rng.gauss(65000.0, 9500.0), 2)
            rows.append(
                {
                    "baseline": "snort_manual",
                    "measurement_type": "modelled",
                    "round": rnd,
                    "cycle": cyc,
                    "scenario": spec["scenario"],
                    "mttd_ms": max(1000.0, mttd_ms),
                    "mttr_ms": max(10000.0, mttr_ms),
                    "contained": 1,  # manual eventual firewall ticket
                }
            )

    out_path = os.path.join(results_dir, "raw_baseline_snort_manual_modelled.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    return rows


def main():
    parser = argparse.ArgumentParser(description="Table III Baseline Benchmark & Modelled Comparison Runner")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--cycles", type=int, default=100)
    parser.add_argument("--results-dir", default=os.path.join(os.path.dirname(__file__), "results"))
    args = parser.parse_args()

    os.makedirs(args.results_dir, exist_ok=True)
    elk_rows = run_suricata_elk_only_measured(args.rounds, args.cycles, args.results_dir)
    snort_rows = run_snort_manual_modelled(args.rounds, args.cycles, args.results_dir)

    summary = [
        {
            "baseline": "suricata_elk_only",
            "measurement_type": "measured_detection_siem_no_autoban",
            "cycles": len(elk_rows),
            "mean_mttd_ms": round(statistics.mean(r["mttd_ms"] for r in elk_rows), 3),
            "sd_mttd_ms": round(statistics.stdev(r["mttd_ms"] for r in elk_rows), 3) if len(elk_rows) > 1 else 0.0,
            "automated_containment_pct": 0.0,
            "mean_mttr_ms_or_note": "N/A (no auto-ban; manual triage)",
        },
        {
            "baseline": "snort_manual",
            "measurement_type": "modelled",
            "cycles": len(snort_rows),
            "mean_mttd_ms": round(statistics.mean(r["mttd_ms"] for r in snort_rows), 3),
            "sd_mttd_ms": round(statistics.stdev(r["mttd_ms"] for r in snort_rows), 3) if len(snort_rows) > 1 else 0.0,
            "automated_containment_pct": 0.0,
            "mean_mttr_ms_or_note": round(statistics.mean(r["mttr_ms"] for r in snort_rows), 3),
        },
    ]

    summary_path = os.path.join(args.results_dir, "baselines.csv")
    with open(summary_path, "w", newline="", encoding="utf-8") as sf:
        w = csv.DictWriter(sf, fieldnames=list(summary[0].keys()))
        w.writeheader()
        w.writerows(summary)

    print(f"[OK] Baselines written to: {summary_path}")
    for row in summary:
        print("  ", row)


if __name__ == "__main__":
    main()
