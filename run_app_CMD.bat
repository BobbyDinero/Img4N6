@echo off
title IMG/4N6 Image Threat Scanner
color 0A

echo.
echo ========================================================
echo                     IMG/4N6
echo           Forensic Image Threat Scanner
echo                Professional Edition
echo ========================================================
echo.

REM Check if virtual environment exists
if exist "venv\Scripts\activate.bat" (
    echo [INFO] Activating virtual environment...
    call venv\Scripts\activate.bat
    echo [OK] Virtual environment activated.
    echo.
) else (
    echo [WARNING] Virtual environment not found. Using system Python.
    echo [INFO] If you encounter import errors, please run: python -m venv venv
    echo [INFO] Then install requirements: pip install -r requirements.txt
    echo.
)

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo [INFO] Please install Python 3.8+ and try again.
    pause
    exit /b 1
)

REM Check if main scanner file exists
if not exist "image_threat_scanner.py" (
    echo [ERROR] image_threat_scanner.py not found in current directory.
    echo [INFO] Please ensure you're running this from the correct folder.
    pause
    exit /b 1
)

REM Check if YARA rules file exists
if not exist "rules.yar" (
    echo [WARNING] rules.yar not found. Scanner will prompt for rules file path.
    echo.
)

echo [INFO] Starting Forensic Image Threat Scanner...
echo [INFO] Press Ctrl+C at any time to exit.
echo.

REM Run the scanner
python image_threat_scanner.py

echo.
echo ========================================================
echo           Scan Complete - Scanner Exited
echo ========================================================
echo.

REM Keep window open if running from double-click
echo Press any key to close this window...
pause >nul