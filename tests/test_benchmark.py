import base64, json, os, struct, sys, tempfile, time, threading
HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "benchmark"))
import numpy as np, pandas as pd
import attacks, run_benchmark as rb, analyze


# ---- attack payloads must satisfy the thresholds in paper Table II --------------------------
def test_dns_tunnel_name_exceeds_50_and_is_valid_dns():
    name = attacks.tunnel_name()
    assert len(name) > 50
    pkt = attacks.dns_query(name)
    assert struct.unpack(">H", pkt[4:6])[0] == 1                     # QDCOUNT
    assert all(len(l) <= 63 for l in name.split("."))                # legal label length

def test_exfil_body_over_5000_bytes_with_rsa_marker():
    b = attacks.exfil_body()
    assert len(b) > 5000 and b"-----BEGIN RSA PRIVATE KEY-----" in b and b"filename=" in b

def test_sqli_payload_matches_rule_1000020_logic():
    assert "UNION SELECT".lower() in attacks.SQLI.lower()

def test_all_six_scenarios_registered():
    assert set(attacks.SCENARIOS) == {1, 2, 3, 4, 5, 6}


# ---- matching logic ------------------------------------------------------------------------
def test_match_cycle_counts_alert_on_dst_side_for_401_rule():
    alerts = [{"t": 10.05, "src": "172.28.0.10", "dst": "172.28.0.105", "sid": 1000012, "sev": 1}]
    audits = [{"event": "ban", "ip": "172.28.0.105", "ts": 10.30}]
    m = rb.match_cycle(alerts, audits, "172.28.0.105", 10.0, rb.EXPECTED[2])
    assert m["detected"] and m["contained"] and m["sid"] == 1000012

def test_match_cycle_ignores_wrong_sid_old_events_and_other_ips():
    alerts = [{"t": 9.0, "src": "172.28.0.105", "dst": "x", "sid": 1000020, "sev": 1},     # before t0
              {"t": 10.1, "src": "172.28.0.105", "dst": "x", "sid": 1000999, "sev": 1},    # wrong sid
              {"t": 10.1, "src": "172.28.0.200", "dst": "x", "sid": 1000020, "sev": 1}]    # other ip
    m = rb.match_cycle(alerts, [], "172.28.0.105", 10.0, rb.EXPECTED[3])
    assert not m["detected"] and not m["contained"]

def test_detected_but_not_contained_for_flag_only_rules():
    alerts = [{"t": 5.1, "src": "172.28.0.105", "dst": "x", "sid": 1000001, "sev": 2}]
    m = rb.match_cycle(alerts, [], "172.28.0.105", 5.0, rb.EXPECTED[1])
    assert m["detected"] and not m["contained"]


# ---- tailer handles partial lines and appends ----------------------------------------------
def test_tailer_reads_only_new_complete_lines():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "eve.json")
        open(p, "w").write(json.dumps({"event_type": "alert", "src_ip": "old", "alert": {"signature_id": 1}}) + "\n")
        t = rb.Tailer(p, rb.parse_eve); t.start(); time.sleep(0.2)
        with open(p, "a") as fh:
            fh.write(json.dumps({"event_type": "flow"}) + "\n")
            line = json.dumps({"event_type": "alert", "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2",
                               "alert": {"signature_id": 1000020, "severity": 1}})
            fh.write(line[:20]); fh.flush(); time.sleep(0.1); fh.write(line[20:] + "\n")
        time.sleep(0.3); items = t.snapshot(); t.stop()
        assert len(items) == 1 and items[0]["src"] == "1.1.1.1" and items[0]["sid"] == 1000020

def test_parse_mem():
    assert abs(rb.parse_mem("185.3MiB") - 185.3) < 1e-6
    assert abs(rb.parse_mem(" 1.5GiB ") - 1536) < 1e-6
    assert abs(rb.parse_mem("512KiB") - 0.5) < 1e-6


# ---- statistics ---------------------------------------------------------------------------
def test_fmt_p_never_reports_impossible_values():
    assert analyze.fmt_p(1e-320) == "<1e-300" and analyze.fmt_p(0.02) == "2.00e-02"

def test_compare_gives_consistent_pvalues_and_effect_size():
    rng = np.random.default_rng(1)
    auto = rng.normal(412, 43, 100); base = rng.normal(52.6 * 60e3, 5e3, 100)
    c = analyze.compare(auto, base, paired=True)
    assert c["t"].pvalue < 1e-50 and c["w"].pvalue < 1e-15 and c["median_ratio"] > 1000

def test_ci_and_dist_and_end_to_end_report():
    rng = np.random.default_rng(7)
    with tempfile.TemporaryDirectory() as d:
        lab = os.path.join(d, "full"); os.makedirs(lab)
        rows = []
        for i in range(120):
            sc = i % 6 + 1; mttd = rng.normal(70, 8); mttr = rng.normal(300, 30)
            contained = int(sc not in (1, 5))
            rows.append(dict(label="full", round=1, cycle=i, scenario=sc, name=rb.SCEN[sc], attacker_ip="172.28.0.105",
                             t0=0, t_alert=1, t_ban=2 if contained else "", detected=1, contained=contained,
                             blocked_probe=1 if contained else "", sid=1, mttd_ms=mttd,
                             mttr_ms=mttr if contained else "", total_ms=mttd + mttr if contained else ""))
        pd.DataFrame(rows).to_csv(os.path.join(lab, "raw.csv"), index=False)
        pd.DataFrame([dict(benign_sent=10000, benign_alerts=12, benign_bans=0)]).to_csv(os.path.join(lab, "benign.csv"), index=False)
        pd.DataFrame([dict(trial=0, ttl_observed_s=300.2, rule_removed=1, reachable_after=1)]).to_csv(os.path.join(lab, "ttl.csv"), index=False)
        text = analyze.report([lab])
        assert "FPR 0.120%" in text and "Containment 66.67%" in text and "TTL self-healing" in text
        assert "p99" in text
