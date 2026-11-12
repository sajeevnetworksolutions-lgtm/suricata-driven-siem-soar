#!/usr/bin/env python3
"""
Host-side benchmark runner implementing paper Sec. 4.3.
  python benchmark/run_benchmark.py --rounds 5 --cycles 100 --label full
Per cycle, per scenario it records (all from one host clock):
  t0      attacker's first malicious packet            (attacks.py)
  t_alert first matching Suricata EVE alert line seen   (tail of eve.json)
  t_ban   SOAR 'ban' event timestamp                    (audit.jsonl written by BanManager)
and then probes whether the target is really unreachable, and pardons the attacker.
Writes <out>/<label>/raw.csv, resources.csv, benign.csv, ttl.csv  (nothing is aggregated here).
"""
import argparse, csv, json, os, re, subprocess, threading, time, urllib.error, urllib.request

SCEN = {1: "recon", 2: "auth", 3: "web", 4: "c2", 5: "dns", 6: "exfil"}
EXPECTED = {1: set(range(1000001, 1000007)), 2: {1000010, 1000011, 1000012, 1000013},
            3: set(range(1000020, 1000026)), 4: {1000030, 1000031, 1000033},
            5: {1000040, 1000041}, 6: {1000050, 1000051, 1000052}}
ATTACKERS = {"default": ("lab-attacker-auth", "172.28.0.105"), "c2": ("lab-attacker-c2", "172.28.0.200")}
BENIGN_IP = "172.28.0.50"
FIELDS = ["label", "round", "cycle", "scenario", "name", "attacker_ip", "t0", "t_alert", "t_ban",
          "detected", "contained", "blocked_probe", "sid", "mttd_ms", "mttr_ms", "total_ms"]


# ------------------------------------------------------------------ tailing
class Tailer(threading.Thread):
    def __init__(self, path, parse):
        super().__init__(daemon=True)
        self.path, self.parse, self.items = path, parse, []
        self.lock, self._halt = threading.Lock(), threading.Event()

    def run(self):
        while not os.path.exists(self.path) and not self._halt.is_set():
            time.sleep(0.05)
        if self._halt.is_set():
            return
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(0, os.SEEK_END)
            buf = ""
            while not self._halt.is_set():
                chunk = fh.read()
                if not chunk:
                    time.sleep(0.001)
                    continue
                t = time.time()
                *lines, buf = (buf + chunk).split("\n")
                for ln in lines:
                    item = self.parse(ln, t)
                    if item:
                        with self.lock:
                            self.items.append(item)

    def snapshot(self):
        with self.lock:
            return list(self.items)

    def stop(self):
        self._halt.set()
        if threading.current_thread() is not self and self.is_alive():
            self.join(timeout=2.0)


def parse_eve(line, t):
    try:
        o = json.loads(line)
    except ValueError:
        return None
    if o.get("event_type") != "alert":
        return None
    a = o.get("alert", {})
    return {"t": t, "src": o.get("src_ip"), "dst": o.get("dest_ip"),
            "sid": a.get("signature_id"), "sev": a.get("severity")}


def parse_audit(line, t):
    try:
        o = json.loads(line)
    except ValueError:
        return None
    return o if "event" in o and "ip" in o else None


def match_cycle(alerts, audits, ip, t0, expected):
    """Pure function. An alert counts if the attacker is src OR dst (e.g. 401 rule fires on the response)."""
    hits = [a for a in alerts if a["t"] >= t0 and a["sid"] in expected and ip in (a["src"], a["dst"])]
    first = min(hits, key=lambda a: a["t"]) if hits else None
    bans = [b for b in audits if b.get("event") == "ban" and b.get("ip") == ip and b.get("ts", 0) >= t0]
    ban = min(bans, key=lambda b: b["ts"]) if bans else None
    return {"detected": first is not None, "t_alert": first["t"] if first else None,
            "sid": first["sid"] if first else None, "contained": ban is not None,
            "t_ban": ban["ts"] if ban else None}


# ------------------------------------------------------------------ docker / http helpers
def dexec(container, *cmd, timeout=60):
    r = subprocess.run(["docker", "exec", container, *cmd], capture_output=True, text=True, timeout=timeout)
    for line in reversed(r.stdout.strip().splitlines()):
        try:
            return json.loads(line)
        except ValueError:
            continue
    raise RuntimeError(f"no JSON from {container} {cmd}: {r.stdout!r} {r.stderr!r}")


def pardon(soar_url, ip):
    req = urllib.request.Request(f"{soar_url}/api/bans/{ip}", method="DELETE")
    try:
        urllib.request.urlopen(req, timeout=3).read()
    except urllib.error.HTTPError:
        pass                                            # 404 -> nothing to pardon
    except OSError:
        pass


def wait_for(fn, timeout, step=0.01):
    end = time.time() + timeout
    while time.time() < end:
        r = fn()
        if r:
            return r
        time.sleep(step)
    return fn()


def parse_mem(text):
    """'185.3MiB' / '1.2GiB' / '900KiB' -> MB (float)."""
    m = re.match(r"\s*([\d.]+)\s*([KMG]?)i?B", text, re.I)
    if not m:
        raise ValueError(text)
    return float(m.group(1)) * {"K": 1 / 1024, "M": 1, "G": 1024, "": 1 / 1048576}[m.group(2).upper()]


class ResourceSampler(threading.Thread):
    def __init__(self, path, every=2.0):
        super().__init__(daemon=True)
        self.path, self.every, self._halt = path, every, threading.Event()

    def run(self):
        n = 0
        with open(self.path, "w", newline="") as fh:
            w = csv.writer(fh); w.writerow(["sample", "t", "container", "cpu_pct", "mem_mb"])
            while not self._halt.is_set():
                r = subprocess.run(["docker", "stats", "--no-stream", "--format",
                                    "{{.Name}},{{.CPUPerc}},{{.MemUsage}}"], capture_output=True, text=True)
                t = time.time()
                for line in r.stdout.strip().splitlines():
                    try:
                        name, cpu, mem = line.split(",", 2)
                        mb = parse_mem(mem.split('/')[0])
                        w.writerow([n, t, name, float(cpu.strip("%")), round(mb, 1)])
                    except ValueError:
                        continue
                fh.flush(); n += 1
                self._halt.wait(self.every)

    def stop(self):
        self._halt.set()
        if threading.current_thread() is not self and self.is_alive():
            self.join(timeout=2.0)


# ------------------------------------------------------------------ main loops
def run_cycle(args, eve, aud, scn, rnd, cyc, writer):
    cname, ip = ATTACKERS["c2"] if scn == 4 else ATTACKERS["default"]
    out = dexec(cname, "python", "/bench/attacks.py", "--scenario", str(scn),
                "--target", args.target, "--port", str(args.port), timeout=90)
    t0 = out["t0"]
    res = wait_for(lambda: (lambda m: m if m["contained"] else None)(
        match_cycle(eve.snapshot(), aud.snapshot(), ip, t0, EXPECTED[scn])), args.wait)
    m = res or match_cycle(eve.snapshot(), aud.snapshot(), ip, t0, EXPECTED[scn])
    blocked = ""
    if m["contained"]:
        blocked = dexec(cname, "python", "/bench/attacks.py", "--probe",
                        "--target", args.target, "--port", str(args.port))["blocked"]
    ms = lambda a, b: round((a - b) * 1000, 2) if a and b else ""
    writer.writerow({"label": args.label, "round": rnd, "cycle": cyc, "scenario": scn, "name": SCEN[scn],
                     "attacker_ip": ip, "t0": t0, "t_alert": m["t_alert"] or "", "t_ban": m["t_ban"] or "",
                     "detected": int(m["detected"]), "contained": int(m["contained"]),
                     "blocked_probe": blocked if blocked == "" else int(blocked), "sid": m["sid"] or "",
                     "mttd_ms": ms(m["t_alert"], t0), "mttr_ms": ms(m["t_ban"], m["t_alert"]),
                     "total_ms": ms(m["t_ban"], t0)})
    pardon(args.soar_url, ip)
    time.sleep(args.settle)


def ttl_trials(args, aud, path):
    """Self-healing test: ban -> rule removed after TTL -> previously banned IP reachable again."""
    cname, ip = ATTACKERS["default"]
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["trial", "ttl_observed_s", "rule_removed", "reachable_after"])
        for i in range(args.ttl_trials):
            t0 = dexec(cname, "python", "/bench/attacks.py", "--scenario", "3", "--target", args.target,
                       "--port", str(args.port))["t0"]
            ban = wait_for(lambda: next((b for b in aud.snapshot() if b["event"] == "ban"
                                         and b["ip"] == ip and b["ts"] >= t0), None), args.wait)
            if not ban:
                w.writerow([i, "", 0, 0]); continue
            exp = wait_for(lambda: next((b for b in aud.snapshot() if b["event"] == "expired"
                                         and b["ip"] == ip and b["ts"] >= ban["ts"]), None), args.ttl + 30, 0.5)
            gone = subprocess.run(["docker", "exec", "siem-target-app", "iptables", "-C", "INPUT", "-s", ip,
                                   "-m", "comment", "--comment", "siem-soar", "-j", "DROP"],
                                  capture_output=True).returncode != 0
            reach = not dexec(cname, "python", "/bench/attacks.py", "--probe", "--target", args.target,
                              "--port", str(args.port))["blocked"]
            w.writerow([i, round(exp["ts"] - ban["ts"], 3) if exp else "", int(gone), int(reach)])
            fh.flush()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=5); ap.add_argument("--cycles", type=int, default=100)
    ap.add_argument("--scenarios", default="1,2,3,4,5,6"); ap.add_argument("--label", default="full")
    ap.add_argument("--out", default="results")
    ap.add_argument("--eve", default="logs/suricata/eve.json")
    ap.add_argument("--audit", default="soar_engine/data/audit.jsonl")
    ap.add_argument("--soar-url", default="http://localhost:8000")
    ap.add_argument("--target", default="172.28.0.10"); ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--benign-per-round", type=int, default=2000)   # 5 x 2,000 = 10,000 (paper)
    ap.add_argument("--wait", type=float, default=3.0); ap.add_argument("--settle", type=float, default=0.3)
    ap.add_argument("--ttl", type=float, default=300.0); ap.add_argument("--ttl-trials", type=int, default=0)
    args = ap.parse_args()
    d = os.path.join(args.out, args.label); os.makedirs(d, exist_ok=True)
    eve, aud = Tailer(args.eve, parse_eve), Tailer(args.audit, parse_audit)
    eve.start(); aud.start(); res = ResourceSampler(os.path.join(d, "resources.csv")); res.start()
    time.sleep(1.0)
    scns = [int(s) for s in args.scenarios.split(",")]
    benign_sent = 0
    with open(os.path.join(d, "raw.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, FIELDS); w.writeheader()
        for rnd in range(1, args.rounds + 1):
            bp = subprocess.Popen(["docker", "exec", "lab-benign", "python", "/bench/benign_traffic.py",
                                   "--target", args.target, "--port", str(args.port),
                                   "--count", str(args.benign_per_round)], stdout=subprocess.PIPE, text=True)
            for cyc in range(1, args.cycles + 1):
                for scn in scns:
                    run_cycle(args, eve, aud, scn, rnd, cyc, w)
                fh.flush()
                print(f"round {rnd}/{args.rounds} cycle {cyc}/{args.cycles}", flush=True)
            out, _ = bp.communicate()
            try:
                benign_sent += json.loads(out.strip().splitlines()[-1])["sent"]
            except (ValueError, IndexError):
                pass
    alerts, bans = eve.snapshot(), aud.snapshot()
    with open(os.path.join(d, "benign.csv"), "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["benign_sent", "benign_alerts", "benign_bans"])
        w.writerow([benign_sent, sum(BENIGN_IP in (a["src"], a["dst"]) for a in alerts),
                    sum(b.get("event") == "ban" and b.get("ip") == BENIGN_IP for b in bans)])
    if args.ttl_trials:
        ttl_trials(args, aud, os.path.join(d, "ttl.csv"))
    eve.stop(); aud.stop(); res.stop()
    print("done ->", d)


if __name__ == "__main__":
    main()
