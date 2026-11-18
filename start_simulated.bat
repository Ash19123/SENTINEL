@echo off
rem Laptop-only demo: a simulated ESP32 runs on this machine, so no hardware or Wi-Fi is needed.
rem The first start learns normal traffic for about 4 minutes. Add --retrain to learn again.
cd /d "%~dp0Lightweight_IoT_IDS"
python run_system.py --simulate %*
pause
