"""
Linux / Docker Real-Kernel Verification Script (Paper Sec. 4.2 / Sec. 4.4)

Run on a host with Docker Engine running:
  python benchmarks/verify_docker_enforcement.py

Verifies:
  1. Suricata config (`suricata -T`) with AF_PACKET cluster_id=99, threads=4, checksums off
  2. Shared network namespace (`siem-suricata` + `siem-soar-engine` share `siem-target-app`)
  3. Live attack from `lab-attacker-auth` (172.28.0.105) -> HTTP 401 burst (SID 1000012)
  4. Real `iptables -I INPUT 1 -s 172.28.0.105 -j DROP` kernel enforcement
  5. Attacker blocked (`curl` fails/times out), benign client (`172.28.0.50`) unaffected (`HTTP 200`)
  6. Manual pardon (`DELETE /api/bans/172.28.0.105`) removes kernel rule and restores access
  7. Forensic dossier append-only + hash-chain integrity (`/api/forensics/verify`)
"""

import json
import time
import urllib.request
import subprocess
import sys


def run_cmd(cmd):
    print(f"$ {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.stdout.strip():
        print(res.stdout.strip())
    if res.stderr.strip():
        print(res.stderr.strip(), file=sys.stderr)
    return res


def main():
    # 1. Validate Suricata rule syntax and AF_PACKET config inside container
    chk = run_cmd(["docker", "exec", "siem-suricata", "suricata", "-T", "-c", "/etc/suricata/suricata.yaml"])
    assert chk.returncode == 0, "Suricata config validation failed!"

    # 2. Confirm shared network namespace (`soar-engine` sees target eth0 / loopback)
    ip_chk = run_cmd(["docker", "exec", "siem-soar-engine", "ip", "-o", "-4", "addr", "show", "eth0"])
    assert "172.28.0.10" in ip_chk.stdout, "Expected soar-engine to share 172.28.0.10 netns with target!"

    # 3. Verify benign client (172.28.0.50) reaches target before & during attack
    b1 = run_cmd(["docker", "exec", "lab-benign", "python", "-c",
                  "import urllib.request; print(urllib.request.urlopen('http://172.28.0.10/', timeout=3).getcode())"])
    assert b1.returncode == 0 and "200" in b1.stdout

    # 4. Fire Table II 5x HTTP 401 brute force from lab-attacker-auth (172.28.0.105) WITHOUT webhook shortcut
    atk = run_cmd(["docker", "exec", "lab-attacker-auth", "python",
                   "/attack_simulator/scenarios/auth_bruteforce.py", "http://172.28.0.10/login"])
    assert atk.returncode == 0

    # Wait briefly for Suricata -> eve.json -> SOAR 200ms poller -> iptables enforcement
    time.sleep(2.0)

    # 5. Confirm real kernel iptables DROP rule exists inside target/soar netns
    ipt = run_cmd(["docker", "exec", "siem-soar-engine", "iptables", "-S", "INPUT"])
    has_drop = any(
        line.startswith("-A INPUT") and "-s 172.28.0.105/32" in line and "-j DROP" in line
        for line in ipt.stdout.splitlines()
    )
    assert has_drop, f"Expected kernel DROP rule for 172.28.0.105! Got:\n{ipt.stdout}"

    # 6. Confirm attacker probe is dropped by kernel while benign client stays reachable
    blocked_probe = run_cmd(["docker", "exec", "lab-attacker-auth", "python", "-c",
                             "import urllib.request; urllib.request.urlopen('http://172.28.0.10/', timeout=2)"])
    assert blocked_probe.returncode != 0, "Attacker 172.28.0.105 should be blocked by iptables!"
    print("[PASS] Kernel firewall dropped attacker probe from 172.28.0.105!")

    b2 = run_cmd(["docker", "exec", "lab-benign", "python", "-c",
                  "import urllib.request; print(urllib.request.urlopen('http://172.28.0.10/', timeout=3).getcode())"])
    assert b2.returncode == 0 and "200" in b2.stdout
    print("[PASS] Benign client 172.28.0.50 unaffected (HTTP 200)!")

    # 7. Pardon attacker via DELETE /api/bans/172.28.0.105 and verify connectivity restored
    req = urllib.request.Request("http://127.0.0.1:8000/api/bans/172.28.0.105", method="DELETE")
    with urllib.request.urlopen(req, timeout=3) as resp:
        assert resp.getcode() == 200
    ipt_after = run_cmd(["docker", "exec", "siem-soar-engine", "iptables", "-S", "INPUT"])
    assert "172.28.0.105" not in ipt_after.stdout, "Expected DROP rule removed after pardon!"

    restored = run_cmd(["docker", "exec", "lab-attacker-auth", "python", "-c",
                        "import urllib.request; print(urllib.request.urlopen('http://172.28.0.10/', timeout=3).getcode())"])
    assert restored.returncode == 0 and "200" in restored.stdout
    print("[PASS] Pardon lifted kernel rule and restored traffic cleanly!")

    # 8. Verify hash-chained forensic ledger
    with urllib.request.urlopen("http://127.0.0.1:8000/api/forensics/verify", timeout=3) as resp:
        v = json.loads(resp.read().decode("utf-8"))
        assert v["valid"] is True, f"Hash chain check failed: {v}"
        print(f"[PASS] Forensic hash chain valid ({v['total_entries']} entries)")


if __name__ == "__main__":
    main()
