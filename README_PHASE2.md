# Phase 2: benchmark harness (paper Sec. 4.3 -> Sec. 5 tables)

This zip is cumulative: it contains the Phase 1 files plus the harness. `docker-compose.yml` here supersedes Phase 1's
(ablation flags are now env-interpolated).

## Run order (Linux + Docker)
    pip install -r benchmark/requirements.txt
    make test          # 21 unit tests, no Docker needed
    make up            # stack + lab clients (bench override exposes eve.json / audit.jsonl on the host)
    make quick         # smoke run: 1 round x 5 cycles -> results/smoke/
    make bench         # full protocol: 5 rounds x 100 cycles x 6 scenarios, 10,000 benign requests
    make ttl           # self-healing test: 5 trials x ~5 min
    make ablate        # Table IV: full / no_ttl / no_threat_intel / no_forensics / sync_batch
    python benchmark/analyze.py results/full --baseline benchmark/manual_triage.csv

## What each paper claim maps to
| Paper claim | Produced by |
|---|---|
| MTTD / MTTR / total latency, p95 | `analyze.py` from raw.csv (t0, t_alert, t_ban on one host clock) |
| Recall, containment per scenario | raw.csv `detected`, `contained`, `blocked_probe` (real reachability probe) |
| FPR over 10,000 benign requests | benign.csv (alerts attributed to 172.28.0.50 / requests sent) |
| CPU / RAM | resources.csv from `docker stats` every 2 s |
| 300 s TTL self-healing | ttl.csv (rule removed? target reachable again?) |
| Table IV ablation | `run_ablations.sh` + `analyze.py` ablation table |
| t-test / Wilcoxon | `analyze.py --baseline` (p-values computed by scipy, never typed in) |

## Definitions used (state these in the paper's Sec. 4.3)
- t0: attacker's first malicious packet. t_alert: moment the harness reads the matching EVE alert line.
  t_ban: BanManager `ban` event time (written after the iptables call returns).
- MTTD = t_alert - t0.  MTTR = t_ban - t_alert.  Total = t_ban - t0.
- Contained = ban event recorded AND a post-ban probe from the attacker cannot reach the target.

## Needs engine support (not in the zip, as I have not seen engine.py)
- BanManager wired in and writing `audit.jsonl` (`audit_path`), with `on_event` -> WebSocket.
- `ENABLE_TTL`, `ENABLE_THREAT_INTEL`, `ENABLE_FORENSICS`, `ASYNC_MODE` read from the environment.
  (`ENABLE_TTL=false` -> pass a huge ttl; `ASYNC_MODE=false` -> poll in batches). "w/o ECS" needs the SOAR to read
  from Elasticsearch instead of eve.json; add it as a separate mode only if you want that row.
- `DELETE /api/bans/{ip}` returning after the rule is removed (BanManager.pardon does this).
- Severity-1 bans for recon (1000001) and DNS tunnelling (1000040/41), otherwise containment will honestly show <100%.
- The 401 rule (1000012) fires on the *response*, so EVE src_ip is the target and dest_ip is the attacker. The engine
  must ban the correct side. The harness accepts either side when matching alerts.

## Honest-reporting rules
- Report whatever `analyze.py` prints. If MTTR is not 412 ms, change the number in the paper, not the experiment.
- The manual baseline must come from a real tabletop exercise (template provided), or be labelled "modelled".
