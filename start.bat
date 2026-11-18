@echo off
rem Starts the whole IoT IDS (gateway + Wireshark capture + detector + dashboard).
rem Add --retrain to learn the ESP32's normal traffic again.
cd /d "%~dp0Lightweight_IoT_IDS"
python run_system.py %*
pause
