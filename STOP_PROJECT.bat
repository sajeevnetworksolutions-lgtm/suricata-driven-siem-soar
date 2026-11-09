@echo off
title Stop Suricata SIEM + SOAR Services
color 0E
cls

echo ========================================================================
echo         STOPPING SURICATA SIEM + SOAR LOCAL SERVICES
echo ========================================================================
echo.
echo [*] Terminating python uvicorn/flask instances on ports 8000 and 8080...

powershell -Command "Get-Process -Name python -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*app.py*' -or $_.CommandLine -like '*run_local_demo*' } | Stop-Process -Force"

echo.
echo [OK] All local demo services stopped cleanly.
echo.
pause
