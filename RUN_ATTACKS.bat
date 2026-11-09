@echo off
title Suricata Attack Suite Runner
color 0C
cls

echo ========================================================================
echo         SURICATA SIEM + SOAR : AUTOMATED ATTACK SUITE RUNNER
echo ========================================================================
echo.
echo [*] Executing MITRE ATT&CK Simulation Scenarios against local target...
echo.

python attack_simulator\run_attack_suite.py --scenario all

echo.
echo ========================================================================
echo [OK] Attack suite complete! Check http://localhost:8000 for SOAR reaction.
echo ========================================================================
echo.
pause
