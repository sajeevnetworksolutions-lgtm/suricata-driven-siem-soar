"""
Automated Test Runner
Starts SOAR Engine and Target App in-process/subprocesses, executes full end-to-end verification,
and stops servers cleanly.
"""

import os
import sys
import time
import subprocess
import requests

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
SOAR_DIR = os.path.join(PROJECT_ROOT, "soar_engine")
TARGET_DIR = os.path.join(PROJECT_ROOT, "target_service")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
EVE_LOG_PATH = os.path.join(LOGS_DIR, "eve.json")

os.makedirs(LOGS_DIR, exist_ok=True)
if not os.path.exists(EVE_LOG_PATH):
    with open(EVE_LOG_PATH, "w") as f:
        pass

def run_test():
    print("=" * 75)
    print("      STARTING IN-PROCESS LIVE TEST OF SURICATA SIEM + SOAR SYSTEM        ")
    print("=" * 75)

    env_target = os.environ.copy()
    env_target["TARGET_PORT"] = "8080"
    p_target = subprocess.Popen([sys.executable, os.path.join(TARGET_DIR, "app.py")], cwd=TARGET_DIR, env=env_target)

    env_soar = os.environ.copy()
    env_soar["EVE_LOG_PATH"] = EVE_LOG_PATH
    env_soar["DATA_DIR"] = os.path.join(SOAR_DIR, "data")
    p_soar = subprocess.Popen([sys.executable, os.path.join(SOAR_DIR, "app.py")], cwd=SOAR_DIR, env=env_soar)

    try:
        # Wait for services to respond
        print("[*] Waiting for SOAR Hub (:8000) and Target App (:8080) to initialize...")
        ready = False
        for _ in range(20):
            time.sleep(1)
            try:
                r1 = requests.get("http://127.0.0.1:8000/api/stats", timeout=1)
                r2 = requests.get("http://127.0.0.1:8080/", timeout=1)
                if r1.status_code == 200 and r2.status_code == 200:
                    ready = True
                    break
            except Exception:
                pass

        if not ready:
            print("[-] Error: Services failed to become ready in time.")
            return False

        print("[OK] Both services responsive!\n")

        # Run verification suite
        import test_verification
        test_verification.test_system()

        print("\n" + "=" * 75)
        print("          RUNNING LIVE INTERACTIVE ATTACK BUTTONS & CANARY TRAPS          ")
        print("=" * 75)
        import test_live_all

        return True

    finally:
        print("\n[*] Shutting down test services cleanly...")
        p_target.terminate()
        p_soar.terminate()
        try:
            p_target.wait(timeout=3)
            p_soar.wait(timeout=3)
        except Exception:
            p_target.kill()
            p_soar.kill()
        print("[OK] All processes stopped.")

if __name__ == "__main__":
    success = run_test()
    if not success:
        sys.exit(1)
