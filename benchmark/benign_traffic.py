#!/usr/bin/env python3
"""Benign background load (paper Sec. 4.3): N HTTP + DNS requests, incl. benign high-entropy URI params."""
import argparse, base64, json, os, random, socket, time
from attacks import raw_http, dns_query

PATHS = ["/", "/about", "/contact", "/static/app.css", "/search?q=hello+world", "/search?q=quarterly+report"]
NAMES = ["www.corp.local", "mail.corp.local", "intranet.corp.local", "files.corp.local"]

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="172.28.0.10"); ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--count", type=int, default=2000); ap.add_argument("--rate", type=float, default=100.0)
    ap.add_argument("--dns-share", type=float, default=0.2)
    a = ap.parse_args()
    udp, sent, gap = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0, 1.0 / a.rate
    for _ in range(a.count):
        if random.random() < a.dns_share:
            udp.sendto(dns_query(random.choice(NAMES)), (a.target, 53))
        else:
            path = random.choice(PATHS)
            if random.random() < 0.15:     # benign high-entropy parameter (session token)
                path = "/?session=" + base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
            raw_http(a.target, a.port, "GET", path, timeout=1.0)
        sent += 1
        time.sleep(gap)
    print(json.dumps({"sent": sent}))
