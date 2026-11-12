#!/usr/bin/env bash
# Runs the full benchmark once per configuration (paper Table IV). Needs the stack up.
set -euo pipefail
ROUNDS=${ROUNDS:-5}; CYCLES=${CYCLES:-100}
run() {  # label  ENV=VAL ...
  label=$1; shift
  env "$@" docker compose -f docker-compose.yml -f docker-compose.bench.yml up -d --force-recreate soar-engine
  sleep 8
  python benchmark/run_benchmark.py --rounds "$ROUNDS" --cycles "$CYCLES" --label "$label"
}
run full            ENABLE_TTL=true  ENABLE_THREAT_INTEL=true  ENABLE_FORENSICS=true  ASYNC_MODE=true
run no_ttl          ENABLE_TTL=false ENABLE_THREAT_INTEL=true  ENABLE_FORENSICS=true  ASYNC_MODE=true
run no_threat_intel ENABLE_TTL=true  ENABLE_THREAT_INTEL=false ENABLE_FORENSICS=true  ASYNC_MODE=true
run no_forensics    ENABLE_TTL=true  ENABLE_THREAT_INTEL=true  ENABLE_FORENSICS=false ASYNC_MODE=true
run sync_batch      ENABLE_TTL=true  ENABLE_THREAT_INTEL=true  ENABLE_FORENSICS=true  ASYNC_MODE=false
python benchmark/analyze.py results/full results/no_ttl results/no_threat_intel results/no_forensics results/sync_batch
