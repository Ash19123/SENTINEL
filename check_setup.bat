@echo off
rem Checks that this laptop is ready to run the SENTINEL demo.
rem Use "check_setup.bat --hardware" when you will use a real ESP32 (also checks the Wi-Fi band).
cd /d "%~dp0Lightweight_IoT_IDS"
python tools\check_setup.py %*
pause
