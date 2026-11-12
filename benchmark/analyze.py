#!/usr/bin/env python3
"""
Turn raw benchmark CSVs into the paper's tables with correctly computed statistics.
  python benchmark/analyze.py results/full [results/no_ttl ...] [--baseline benchmark/manual_triage.csv]
Everything in the paper's Sec. 6 comes from this script, so numbers cannot drift from the data.
"""
import argparse, glob, math, os, sys
import numpy as np, pandas as pd
from scipy import stats


def fmt_p(p):
    return "<1e-300" if p < 1e-300 else f"{p:.2e}"


def ci_mean(x, conf=0.999):
    x = np.asarray(x, float)
    if len(x) < 2:
        return (float("nan"), float("nan"))
    h = stats.sem(x) * stats.t.ppf((1 + conf) / 2, len(x) - 1)
    return float(x.mean() - h), float(x.mean() + h)


def dist(x):
    x = pd.Series(x).dropna().astype(float)
    if x.empty:
        return dict(n=0, mean=np.nan, median=np.nan, p95=np.nan, p99=np.nan, max=np.nan, sd=np.nan)
    return dict(n=len(x), mean=x.mean(), median=x.median(), p95=x.quantile(.95),
                p99=x.quantile(.99), max=x.max(), sd=x.std(ddof=1) if len(x) > 1 else 0.0)


def per_scenario(raw):
    rows = []
    for name, g in raw.groupby("name", sort=False):
        rows.append({"scenario": name, "runs": len(g), "recall_%": 100 * g.detected.mean(),
                     "contained_%": 100 * g.contained.mean(),
                     "blocked_verified_%": 100 * (g.blocked_probe == 1).sum() / max(1, g.contained.sum()),
                     "mttd_ms_med": g.mttd_ms.median(), "mttr_ms_med": g.mttr_ms.median(),
                     "total_ms_med": g.total_ms.median(), "total_ms_p95": g.total_ms.quantile(.95)})
    return pd.DataFrame(rows)


def overall(label_dir):
    raw = pd.read_csv(os.path.join(label_dir, "raw.csv"))
    for c in ("mttd_ms", "mttr_ms", "total_ms", "blocked_probe"):
        raw[c] = pd.to_numeric(raw[c], errors="coerce")
    out = {"label": os.path.basename(label_dir.rstrip("/")), "raw": raw}
    out["mttd"], out["mttr"], out["total"] = dist(raw.mttd_ms), dist(raw.mttr_ms), dist(raw.total_ms)
    out["ci_total"] = ci_mean(raw.total_ms.dropna())
    out["recall"], out["contained"] = 100 * raw.detected.mean(), 100 * raw.contained.mean()
    p = os.path.join(label_dir, "benign.csv")
    if os.path.exists(p):
        b = pd.read_csv(p).iloc[0]
        out["fpr"] = 100 * b.benign_alerts / b.benign_sent if b.benign_sent else float("nan")
        out["lockout"] = 100 * b.benign_bans / b.benign_sent if b.benign_sent else float("nan")
        out["benign_sent"], out["benign_alerts"] = int(b.benign_sent), int(b.benign_alerts)
    p = os.path.join(label_dir, "resources.csv")
    if os.path.exists(p):
        r = pd.read_csv(p).groupby("sample").agg(cpu=("cpu_pct", "sum"), mem=("mem_mb", "sum"))
        out["cpu_mean"], out["cpu_peak"], out["mem_mean"], out["mem_peak"] = (
            r.cpu.mean(), r.cpu.max(), r.mem.mean(), r.mem.max())
    p = os.path.join(label_dir, "ttl.csv")
    if os.path.exists(p):
        t = pd.read_csv(p)
        out["ttl"] = {"trials": len(t), "removed_%": 100 * t.rule_removed.mean(),
                      "reachable_%": 100 * t.reachable_after.mean(),
                      "ttl_mean_s": pd.to_numeric(t.ttl_observed_s, errors="coerce").mean()}
    return out


def compare(auto_ms, base_ms, paired=False):
    a, b = np.asarray(auto_ms, float), np.asarray(base_ms, float)
    a, b = a[~np.isnan(a)], b[~np.isnan(b)]
    res = {"n_auto": len(a), "n_base": len(b), "median_ratio": float(np.median(b) / np.median(a))}
    if paired and len(a) == len(b):
        res["t"] = stats.ttest_rel(b, a); res["w"] = stats.wilcoxon(b, a); res["test"] = "paired"
    else:
        res["t"] = stats.ttest_ind(b, a, equal_var=False); res["w"] = stats.mannwhitneyu(b, a, alternative="two-sided")
        res["test"] = "independent (Welch t, Mann-Whitney U)"
    d = (b.mean() - a.mean()) / math.sqrt((a.var(ddof=1) + b.var(ddof=1)) / 2)
    res["cohens_d"] = float(d)
    return res


def report(dirs, baseline=None, paired=False):
    L = []
    results = [overall(d) for d in dirs]
    full = results[0]
    L.append("## Per-scenario results (%s)\n" % full["label"])
    L.append(per_scenario(full["raw"]).round(2).to_markdown(index=False))
    L.append("\n## Latency distribution, ms (%s)\n" % full["label"])
    tbl = pd.DataFrame({k: full[k] for k in ("mttd", "mttr", "total")}).T.round(1)
    L.append(tbl.to_markdown())
    lo, hi = full["ci_total"]
    L.append(f"\n99.9% CI of mean end-to-end latency: [{lo:.1f}, {hi:.1f}] ms  (CI of the mean, NOT a latency bound; see p99/max)")
    L.append(f"Recall {full['recall']:.2f}%  |  Containment {full['contained']:.2f}%")
    if "fpr" in full:
        L.append(f"FPR {full['fpr']:.3f}% ({full['benign_alerts']} alerts / {full['benign_sent']} benign requests)  |  benign lockout {full['lockout']:.3f}%")
    if "cpu_mean" in full:
        L.append(f"Stack CPU mean {full['cpu_mean']:.1f}% / peak {full['cpu_peak']:.1f}% (sum over containers, % of one core)  |  RAM mean {full['mem_mean']:.0f} MB / peak {full['mem_peak']:.0f} MB")
    if "ttl" in full:
        t = full["ttl"]
        L.append(f"TTL self-healing: {t['trials']} trials, rule removed {t['removed_%']:.0f}%, target reachable again {t['reachable_%']:.0f}%, mean observed TTL {t['ttl_mean_s']:.1f}s")
    if len(results) > 1:
        L.append("\n## Ablation (cf. paper Table IV)\n")
        rows = []
        for r in results:
            m = r["total"]["mean"]
            rows.append({"config": r["label"], "mean_total_ms": round(m, 1),
                         "delta_vs_full_%": round(100 * (m / full["total"]["mean"] - 1), 1),
                         "contained_%": round(r["contained"], 1), "lockout_%": round(r.get("lockout", float("nan")), 2)})
        L.append(pd.DataFrame(rows).to_markdown(index=False))
    if baseline:
        b = pd.read_csv(baseline)
        c = compare(full["raw"].total_ms, b["mttr_ms"], paired)
        L.append(f"\n## Significance vs baseline ({c['test']}; n_auto={c['n_auto']}, n_base={c['n_base']})\n")
        L.append(f"Welch/paired t: t={c['t'].statistic:.2f}, p={fmt_p(c['t'].pvalue)}")
        L.append(f"Rank test:      stat={c['w'].statistic:.1f}, p={fmt_p(c['w'].pvalue)}")
        L.append(f"Median speed-up {c['median_ratio']:.0f}x, Cohen's d = {c['cohens_d']:.1f}")
        L.append("(With effect sizes this large the p-value is uninformative; report the medians and effect size.)")
    return "\n".join(L)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+"); ap.add_argument("--baseline"); ap.add_argument("--paired", action="store_true")
    a = ap.parse_args()
    text = report(a.dirs, a.baseline, a.paired)
    print(text)
    open(os.path.join(a.dirs[0], "summary.md"), "w").write(text + "\n")
