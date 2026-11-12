# Statistical Evaluation Report (Computed Directly from Raw CSVs)

- Significance threshold: `alpha = 0.001`
- Primary Full SOAR sample size: `n = 500`

| Series | Type | n | Recall % | Contain % | MTTD Mean (ms) | MTTR Mean (ms) | MTTR SD (ms) | p95 MTTR (ms) | Forensic Mean (ms) | t-stat | t p-value | Wilcoxon W | Wilcoxon p-value | Sig (p<0.001) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|
| `full` | soar_variant_measured | 500 | 100.0 | 100.0 | 176.974 | 45.617 | 17.899 | 66.212 | 25.436 | 0.0 | 1.000000e+00 | 0.0 | 1.000000e+00 | NO |
| `no_async` | soar_variant_measured | 500 | 100.0 | 100.0 | 98.794 | 56.715 | 18.905 | 89.322 | 42.993 | -9.5321 | 1.138680e-20 | 19709.0 | 3.142390e-40 | YES |
| `no_ecs` | soar_variant_measured | 500 | 100.0 | 100.0 | 172.29 | 74.758 | 40.978 | 149.11 | 53.454 | -14.5722 | 4.430218e-42 | 5551.0 | 8.949730e-70 | YES |
| `no_forensics` | soar_variant_measured | 500 | 100.0 | 100.0 | 176.7 | 20.962 | 38.778 | 31.479 | 0.0 | 12.9079 | 2.337738e-34 | 1017.0 | 5.432338e-81 | YES |
| `no_ti` | soar_variant_measured | 500 | 100.0 | 100.0 | 176.867 | 63.158 | 32.849 | 91.226 | 39.797 | -10.4849 | 3.886726e-24 | 10093.0 | 2.159520e-59 | YES |
| `no_ttl` | soar_variant_measured | 500 | 100.0 | 100.0 | 176.866 | 63.824 | 32.293 | 125.878 | 39.664 | -11.0264 | 2.259709e-26 | 18910.5 | 1.126255e-41 | YES |
| `snort_manual_modelled` | baseline_modelled | 500 | 100.0 | 0.0 | 8511.05 | 64577.9 | 9576.308 | 81750.867 | 0.0 | -150.6826 | 0.000000e+00 | 0.0 | 1.264719e-83 | YES |
