import socket
import sys
import time


DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 9200]


def run_port_scan(target_host: str = "127.0.0.1", ports=None, interval: float = 0.05):
    """Table II Scenario 1: >= 10 TCP SYN probes within 5 seconds (10 pkts / 5 s)."""
    scan_ports = ports if ports is not None else DEFAULT_PORTS
    print(f"\n[*] [ATTACK 1] Starting Network Reconnaissance ({len(scan_ports)} SYN probes in <5s) against {target_host}...")
    results = []
    for port in scan_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.25)
            result = s.connect_ex((target_host, port))
            state = "OPEN" if result == 0 else "CLOSED/FILTERED"
            results.append((port, state))
            print(f"    [SCAN] Target Port {port:5d}/TCP -> {state}")
            s.close()
            if interval > 0:
                time.sleep(interval)
        except Exception as e:
            results.append((port, f"ERR:{e}"))
            print(f"    [!] Error scanning port {port}: {e}")
    print("[+] Reconnaissance scan complete.\n")
    return results


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    run_port_scan(host)
