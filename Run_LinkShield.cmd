@echo off
setlocal
cd /d "%~dp0"
title LinkShield SIEM - Standard User Launcher

if not exist "start_linkshield.py" (
    echo [ERROR] Put this file beside start_linkshield.py
    pause
    exit /b 2
)

if exist "agent\.venv\Scripts\python.exe" (
    "agent\.venv\Scripts\python.exe" -u "start_linkshield.py" %*
) else (
    echo [ERROR] agent virtual environment missing.
    echo Create agent\.venv before running LinkShield.
    pause
    exit /b 2
)

set "CODE=%ERRORLEVEL%"
echo.
echo LinkShield stopped [exit code %CODE%].
pause
exit /b %CODE%
