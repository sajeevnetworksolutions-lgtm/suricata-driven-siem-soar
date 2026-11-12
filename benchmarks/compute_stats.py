"""
Compute statistical summaries and hypothesis tests (Welch/Student t-test and
Wilcoxon / Mann-Whitney U tests at alpha = 0.001) directly from raw benchmark CSVs.
Reports exact computed statistics with zero post-hoc adjustments.
"""

import os
import csv
import glob
import argparse
from typing import Dict, List, Any

import numpy as np
from scipy import stats


def load_csv(path: str) -> List[Dict[str, str]]:
    with open(path, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def percentile(arr: np.ndarray, q: float) -> float:
    return float(np.percentile(arr, q)) if len(arr) else 0.0


def analyze_results(results_dir: str, alpha: float = 0.001):
    full_csv = os.path.join(results_dir, "raw_cycles_full.csv")
    if not os.path.exists(full_csv):
        raise FileNotFoundError(f"Missing primary benchmark CSV: {full_csv}")

    full_rows = load_csv(full_csv)
    full_mttr = np.array([float(r["mttr_ms"]) for r in full_rows], dtype=float)
    full_mttd = np.array([float(r["mttd_ms"]) for r in full_rows], dtype=float)

    comparisons: List[Dict[str, Any]] = []

    # 1. Per-variant summary & significance tests vs `full`
    variant_files = sorted(glob.glob(os.path.join(results_dir, "raw_cycles_*.csv")))
    for vf in variant_files:
        name = os.path.basename(vf).replace("raw_cycles_", "").replace(".csv", "")
        rows = load_csv(vf)
        mttr = np.array([float(r["mttr_ms"]) for r in rows], dtype=float)
        mttd = np.array([float(r["mttd_ms"]) for r in rows], dtype=float)
        ti = np.array([float(r["ti_latency_ms"]) for r in rows], dtype=float)
        ban = np.array([float(r["ban_latency_ms"]) for r in rows], dtype=float)
        forensic = np.array([float(r["forensic_latency_ms"]) for r in rows], dtype=float)
        notify = np.array([float(r["notify_latency_ms"]) for r in rows], dtype=float)
        cpu = np.array([float(r["cpu_pct"]) for r in rows], dtype=float)
        ram = np.array([float(r["ram_mb"]) for r in rows], dtype=float)
        recall = np.mean([float(r["detected"]) for r in rows]) * 100.0
        containment = np.mean([float(r["contained"]) for r in rows]) * 100.0

        t_stat, t_p = (0.0, 1.0)
        w_stat, w_p = (0.0, 1.0)
        if name != "full":
            t_res = stats.ttest_ind(full_mttr, mttr, equal_var=False)
            t_stat = float(t_res.statistic)
            t_p = float(t_res.pvalue)
            if len(full_mttr) == len(mttr):
                diff = mttr - full_mttr
                if np.any(diff != 0):
                    w_res = stats.wilcoxon(full_mttr, mttr)
                    w_stat = float(w_res.statistic)
                    w_p = float(w_res.pvalue)
            else:
                u_res = stats.mannwhitneyu(full_mttr, mttr, alternative="two-sided")
                w_stat = float(u_res.statistic)
                w_p = float(u_res.pvalue)

        comparisons.append(
            {
                "series": name,
                "kind": "soar_variant_measured",
                "n": len(mttr),
                "recall_pct": round(float(recall), 2),
                "containment_pct": round(float(containment), 2),
                "mttd_mean_ms": round(float(np.mean(mttd)), 3),
                "mttr_mean_ms": round(float(np.mean(mttr)), 3),
                "mttr_sd_ms": round(float(np.std(mttr, ddof=1)), 3) if len(mttr) > 1 else 0.0,
                "mttr_median_ms": round(percentile(mttr, 50), 3),
                "mttr_p95_ms": round(percentile(mttr, 95), 3),
                "ti_mean_ms": round(float(np.mean(ti)), 3),
                "ban_mean_ms": round(float(np.mean(ban)), 3),
                "forensic_mean_ms": round(float(np.mean(forensic)), 3),
                "notify_mean_ms": round(float(np.mean(notify)), 3),
                "cpu_mean_pct": round(float(np.mean(cpu)), 2),
                "ram_mean_mb": round(float(np.mean(ram)), 2),
                "t_stat_vs_full": round(t_stat, 4),
                "t_pvalue": f"{t_p:.6e}",
                "wilcoxon_stat_vs_full": round(w_stat, 4),
                "wilcoxon_pvalue": f"{w_p:.6e}",
                "significant_alpha_0_001": bool(name != "full" and t_p < alpha and w_p < alpha),
            }
        )

    # 2. Modelled manual baseline statistical comparison vs `full`
    snort_csv = os.path.join(results_dir, "raw_baseline_snort_manual_modelled.csv")
    if os.path.exists(snort_csv):
        s_rows = load_csv(snort_csv)
        s_mttr = np.array([float(r["mttr_ms"]) for r in s_rows], dtype=float)
        s_mttd = np.array([float(r["mttd_ms"]) for r in s_rows], dtype=float)
        t_res = stats.ttest_ind(full_mttr, s_mttr, equal_var=False)
        if len(full_mttr) == len(s_mttr):
            w_res = stats.wilcoxon(full_mttr, s_mttr)
        else:
            w_res = stats.mannwhitneyu(full_mttr, s_mttr, alternative="two-sided")

        comparisons.append(
            {
                "series": "snort_manual_modelled",
                "kind": "baseline_modelled",
                "n": len(s_mttr),
                "recall_pct": 100.0,
                "containment_pct": 0.0,  # 0% automated containment
                "mttd_mean_ms": round(float(np.mean(s_mttd)), 3),
                "mttr_mean_ms": round(float(np.mean(s_mttr)), 3),
                "mttr_sd_ms": round(float(np.std(s_mttr, ddof=1)), 3),
                "mttr_median_ms": round(percentile(s_mttr, 50), 3),
                "mttr_p95_ms": round(percentile(s_mttr, 95), 3),
                "ti_mean_ms": 0.0,
                "ban_mean_ms": 0.0,
                "forensic_mean_ms": 0.0,
                "notify_mean_ms": 0.0,
                "cpu_mean_pct": 0.0,
                "ram_mean_mb": 0.0,
                "t_stat_vs_full": round(float(t_res.statistic), 4),
                "t_pvalue": f"{float(t_res.pvalue):.6e}",
                "wilcoxon_stat_vs_full": round(float(w_res.statistic), 4),
                "wilcoxon_pvalue": f"{float(w_res.pvalue):.6e}",
                "significant_alpha_0_001": bool(float(t_res.pvalue) < alpha and float(w_res.pvalue) < alpha),
            }
        )

    # Write statistical CSV report
    report_csv = os.path.join(results_dir, "statistical_report.csv")
    with open(report_csv, "w", newline="", encoding="utf-8") as cf:
        w = csv.DictWriter(cf, fieldnames=list(comparisons[0].keys()))
        w.writeheader()
        w.writerows(comparisons)

    # Write Markdown summary report
    report_md = os.path.join(results_dir, "statistical_report.md")
    lines = [
        "# Statistical Evaluation Report (Computed Directly from Raw CSVs)",
        "",
        f"- Significance threshold: `alpha = {alpha}`",
        f"- Primary Full SOAR sample size: `n = {len(full_mttr)}`",
        "",
        "| Series | Type | n | Recall % | Contain % | MTTD Mean (ms) | MTTR Mean (ms) | MTTR SD (ms) | p95 MTTR (ms) | Forensic Mean (ms) | t-stat | t p-value | Wilcoxon W | Wilcoxon p-value | Sig (p<0.001) |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|",
    ]
    for c in comparisons:
        lines.append(
            f"| `{c['series']}` | {c['kind']} | {c['n']} | {c['recall_pct']} | {c['containment_pct']} | "
            f"{c['mttd_mean_ms']} | {c['mttr_mean_ms']} | {c['mttr_sd_ms']} | {c['mttr_p95_ms']} | "
            f"{c['forensic_mean_ms']} | {c['t_stat_vs_full']} | {c['t_pvalue']} | {c['wilcoxon_stat_vs_full']} | "
            f"{c['wilcoxon_pvalue']} | {'YES' if c['significant_alpha_0_001'] else 'NO'} |"
        )

    with open(report_md, "w", encoding="utf-8") as mf:
        mf.write("\n".join(lines) + "\n")

    print(f"[OK] Statistical report written to:\n  - {report_csv}\n  - {report_md}")
    for c in comparisons:
        print("  ", c)


def main():
    parser = argparse.ArgumentParser(description="Compute t-test and Wilcoxon statistics from benchmark CSVs")
    parser.add_argument("--results-dir", default=os.path.join(os.path.dirname(__file__), "results"))
    parser.add_argument("--alpha", type=float, default=0.001)
    args = parser.parse_args()
    analyze_results(args.results_dir, alpha=args.alpha)


if __name__ == "__main__":
    main()
