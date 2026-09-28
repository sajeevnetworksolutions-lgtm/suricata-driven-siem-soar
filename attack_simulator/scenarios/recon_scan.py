import socket
import time
import sys

def run_port_scan(target_host="127.0.0.1", ports=None):
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 9200]
    
    print(f"\n[*] [ATTACK 1] Starting Network Reconnaissance / Port Scan against {target_host}...")
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            result = s.connect_ex((target_host, port))
            state = "OPEN" if result == 0 else "CLOSED"
            print(f"    [SCAN] Target Port {port:5d}/TCP -> {state}")
            s.close()
            time.sleep(0.05)
        except Exception as e:
            print(f"    [!] Error scanning port {port}: {e}")
    print("[+] Reconnaissance scan complete.\n")

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    run_port_scan(host)
