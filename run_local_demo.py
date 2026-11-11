"""
Local Live Demonstration & SOAR Hub Runner
Allows running the SIEM & SOAR Engine directly on the local machine (Windows/Linux)
without needing full Docker overhead.
"""

import os
import sys
import time
import argparse
import subprocess
import webbrowser
import urllib.request

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
SOAR_DIR = os.path.join(PROJECT_ROOT, "soar_engine")
TARGET_DIR = os.path.join(PROJECT_ROOT, "target_service")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
EVE_LOG_PATH = os.path.join(LOGS_DIR, "eve.json")

os.makedirs(LOGS_DIR, exist_ok=True)
if not os.path.exists(EVE_LOG_PATH):
    with open(EVE_LOG_PATH, "w", encoding="utf-8") as f:
        pass


def start_target_app():
    print("[*] Starting Local Vulnerable Target App on http://127.0.0.1:8080 ...")
    env = os.environ.copy()
    env["TARGET_PORT"] = "8080"
    return subprocess.Popen([sys.executable, os.path.join(TARGET_DIR, "app.py")], cwd=TARGET_DIR, env=env)


def start_soar_engine():
    print("[*] Starting SOAR Automated Incident Response Hub on http://127.0.0.1:8000 ...")
    env = os.environ.copy()
    env["EVE_LOG_PATH"] = EVE_LOG_PATH
    env["DATA_DIR"] = os.path.join(SOAR_DIR, "data")
    return subprocess.Popen([sys.executable, os.path.join(SOAR_DIR, "app.py")], cwd=SOAR_DIR, env=env)


def wait_for_services(timeout_sec: int = 20) -> bool:
    for _ in range(timeout_sec * 2):
        try:
            r1 = urllib.request.urlopen("http://127.0.0.1:8000/api/stats", timeout=1)
            r2 = urllib.request.urlopen("http://127.0.0.1:8080/", timeout=1)
            if r1.getcode() == 200 and r2.getcode() == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Suricata SIEM + SOAR Local Runner")
    parser.add_argument("--open-browser", action="store_true", help="Open SOAR Dashboard in browser once ready")
    args = parser.parse_args()

    print("=" * 75)
    print("       SURICATA SIEM + SOAR AUTOMATED RESPONSE SYSTEM (STANDALONE RUNNER)  ")
    print("=" * 75)

    p_target = start_target_app()
    p_soar = start_soar_engine()

    if wait_for_services():
        print("\n[OK] System Services Initialized Successfully!")
        print("    - SOAR Operations Web Center: http://localhost:8000")
        print("    - Target Vulnerable Service:   http://localhost:8080")
        print("    - Monitored EVE Log:           " + EVE_LOG_PATH)
        print("\n[*] You can now run attack simulations using:")
        print("    python attack_simulator/run_attack_suite.py --scenario all")
        print("[*] Press CTRL+C to shut down both servers cleanly.\n")

        if args.open_browser:
            webbrowser.open("http://localhost:8000")
    else:
        print("\n[!] Warning: One or more services took longer than expected to respond.")

    try:
        while True:
            if p_soar.poll() is not None or p_target.poll() is not None:
                print("\n[!] A background service exited unexpectedly.")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down local services...")
    finally:
        for proc in (p_target, p_soar):
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
        print("[OK] All services stopped cleanly.")
