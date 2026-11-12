import argparse
import http.client
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict

from scenarios.dns_tunneling import build_dns_query_packet

BENIGN_PATHS = [
    "/",
    "/search?q=quarterly+report",
    "/search?q=employee+directory",
    "/search?q=security+policy+overview",
    "/login",
]

# Short legitimate domains (< 30 B) that never trip SID 1000040 (>50 B) or SID 1000041 (Base64 >=30)
BENIGN_DOMAINS = [
    "portal.corp.local",
    "assets.cdn.local",
    "mail.corp.local",
    "docs.intranet.local",
    "status.service.local",
]


def _worker_batch(
    host: str,
    port: int,
    dns_host: str,
    count: int,
    http_ratio: float,
    worker_id: int,
) -> Dict[str, int]:
    stats = {"http_sent": 0, "http_ok": 0, "dns_sent": 0, "errors": 0}
    conn = None
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.settimeout(0.5)

    try:
        http_threshold = int(round(max(0.0, min(1.0, http_ratio)) * 100))
        for idx in range(count):
            global_idx = worker_id * count + idx
            do_http = (global_idx % 100) < http_threshold
            if do_http:
                path = BENIGN_PATHS[global_idx % len(BENIGN_PATHS)]
                try:
                    if conn is None:
                        conn = http.client.HTTPConnection(host, port, timeout=2.0)
                    conn.request("GET", path, headers={"User-Agent": "Mozilla/5.0 Benign-Corp-Browser/1.0"})
                    resp = conn.getresponse()
                    resp.read()
                    stats["http_sent"] += 1
                    if 200 <= resp.status < 400:
                        stats["http_ok"] += 1
                except Exception:
                    stats["errors"] += 1
                    try:
                        if conn:
                            conn.close()
                    except Exception:
                        pass
                    conn = None
            else:
                domain = BENIGN_DOMAINS[global_idx % len(BENIGN_DOMAINS)]
                pkt = build_dns_query_packet(domain)
                try:
                    udp_sock.sendto(pkt, (dns_host, 53))
                    stats["dns_sent"] += 1
                except Exception:
                    stats["errors"] += 1
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass
        udp_sock.close()
    return stats


def run_benign_traffic(
    target_host: str = "127.0.0.1",
    target_port: int = 8080,
    dns_host: str = None,
    total_requests: int = 10000,
    http_ratio: float = 0.7,
    workers: int = 16,
) -> Dict[str, float]:
    """Generate clean background HTTP + DNS traffic (default 10,000 requests per paper Sec. 5)."""
    dns_target = dns_host or target_host
    t0 = time.perf_counter()
    per_worker = total_requests // workers
    remainder = total_requests % workers

    totals = {"http_sent": 0, "http_ok": 0, "dns_sent": 0, "errors": 0}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = []
        for w in range(workers):
            n = per_worker + (1 if w < remainder else 0)
            if n > 0:
                futures.append(pool.submit(_worker_batch, target_host, target_port, dns_target, n, http_ratio, w))
        for fut in as_completed(futures):
            batch = fut.result()
            for k, v in batch.items():
                totals[k] += v

    elapsed_s = max(0.001, time.perf_counter() - t0)
    sent_total = totals["http_sent"] + totals["dns_sent"]
    return {
        "target_requests": total_requests,
        "sent_total": sent_total,
        "http_sent": totals["http_sent"],
        "http_ok": totals["http_ok"],
        "dns_sent": totals["dns_sent"],
        "errors": totals["errors"],
        "elapsed_s": round(elapsed_s, 3),
        "rps": round(sent_total / elapsed_s, 1),
    }


def main():
    parser = argparse.ArgumentParser(description="Benign HTTP & DNS Background Traffic Generator")
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--dns", default=None)
    parser.add_argument("--count", type=int, default=10000)
    parser.add_argument("--http-ratio", type=float, default=0.7)
    parser.add_argument("--workers", type=int, default=16)
    args = parser.parse_args()

    print(f"[*] Generating {args.count} benign HTTP/DNS requests -> {args.target}:{args.port} ...")
    summary = run_benign_traffic(
        target_host=args.target,
        target_port=args.port,
        dns_host=args.dns,
        total_requests=args.count,
        http_ratio=args.http_ratio,
        workers=args.workers,
    )
    print(f"[OK] Benign traffic finished: {summary}")


if __name__ == "__main__":
    main()
