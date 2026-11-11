@echo off
title Suricata SIEM + SOAR Autonomous Incident Response Hub
color 0B
cls

echo ========================================================================
echo    SURICATA SIEM + SOAR : AUTONOMOUS THREAT RESPONSE PLATFORM
echo ========================================================================
echo.
echo [*] Checking Python environment...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not found in your PATH!
    echo Please install Python 3.10+ from python.org and ensure "Add to PATH" is checked.
    pause
    exit /b 1
)

echo [*] Verifying dependencies (FastAPI, Uvicorn, Flask, Requests, WebSockets)...
python -c "import fastapi, uvicorn, flask, requests, pydantic, websockets" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Installing required lightweight dependencies...
    pip install fastapi uvicorn flask requests pydantic websockets
)

echo.
echo [OK] Dependencies verified.
echo [*] Starting SOAR Engine (:8000) and Attack Simulation Portal (:8080)...
echo [*] Browser will open automatically once both servers are healthy.
echo.

python run_local_demo.py --open-browser

pause
