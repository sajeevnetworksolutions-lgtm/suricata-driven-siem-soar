COMPOSE = docker compose -f docker-compose.yml -f docker-compose.bench.yml
.PHONY: up down test bench ablate analyze ttl
up:      ; mkdir -p logs/suricata soar_engine/data && $(COMPOSE) up -d --build
down:    ; $(COMPOSE) down
test:    ; python -m pytest -q tests
bench:   ; python benchmark/run_benchmark.py --rounds 5 --cycles 100 --label full
quick:   ; python benchmark/run_benchmark.py --rounds 1 --cycles 5 --benign-per-round 200 --label smoke
ttl:     ; python benchmark/run_benchmark.py --rounds 0 --ttl-trials 5 --label ttl
ablate:  ; ./benchmark/run_ablations.sh
analyze: ; python benchmark/analyze.py results/full
