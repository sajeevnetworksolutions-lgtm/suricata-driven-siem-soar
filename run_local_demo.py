"""
Local Live Demonstration & SOAR Hub Runner
Allows running the SIEM & SOAR Engine directly on the local machine (Windows/Linux)
without needing full Docker overhead.
"""

import os
import sys
import time
import subprocess
import threading
import json
from datetime import datetime

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
SOAR_DIR = os.path.join(PROJECT_ROOT, "soar_engine")
TARGET_DIR = os.path.join(PROJECT_ROOT, "target_service")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
EVE_LOG_PATH = os.path.join(LOGS_DIR, "eve.json")

os.makedirs(LOGS_DIR, exist_ok=True)
if not os.path.exists(EVE_LOG_PATH):
    with open(EVE_LOG_PATH, "w") as f:
        pass

def start_target_app():
    print("[*] Starting Local Vulnerable Target App on http://127.0.0.1:8080 ...")
    env = os.environ.copy()
    subprocess.Popen([sys.executable, os.path.join(TARGET_DIR, "app.py")], cwd=TARGET_DIR, env=env)

def start_soar_engine():
    print("[*] Starting SOAR Automated Incident Response Hub on http://127.0.0.1:8000 ...")
    env = os.environ.copy()
    env["EVE_LOG_PATH"] = EVE_LOG_PATH
    env["DATA_DIR"] = os.path.join(SOAR_DIR, "data")
    subprocess.Popen([sys.executable, os.path.join(SOAR_DIR, "app.py")], cwd=SOAR_DIR, env=env)

def simulate_eve_telemetry_loop():
    """Generates realistic EVE JSON telemetry from simulated detections when testing."""
    print(f"[*] EVE Telemetry stream active at: {EVE_LOG_PATH}")

if __name__ == "__main__":
    print("=" * 75)
    print("       SURICATA SIEM + SOAR AUTOMATED RESPONSE SYSTEM (STANDALONE RUNNER)  ")
    print("=" * 75)
    start_target_app()
    time.sleep(1)
    start_soar_engine()
    time.sleep(2)
    print("\n[OK] System Services Initialized Successfully!")
    print("    - SOAR Operations Web Center: http://127.0.0.1:8000")
    print("    - Target Vulnerable Service:   http://127.0.0.1:8080")
    print("    - Monitored EVE Log:           " + EVE_LOG_PATH)
    print("\n[*] You can now run attack simulations using:")
    print("    python attack_simulator/run_attack_suite.py --scenario all\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down local services.")
