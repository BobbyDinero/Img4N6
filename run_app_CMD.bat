@echo off
REM ============================================================
REM   IMG4N6 - Image Threat Scanner  (Command Prompt launcher)
REM ============================================================
cls
echo ============================================================
echo   IMG4N6 - IMAGE THREAT SCANNER
echo ============================================================
echo.

REM Activate virtual environment if present
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
) else (
    echo NOTE: No venv found. Run setup.bat first for an isolated install.
    echo Continuing with system Python...
    echo.
)

REM Safety: debugger stays OFF unless you explicitly opt in
set FLASK_DEBUG=0

echo Starting server at http://127.0.0.1:5000
echo Press Ctrl+C to stop.
echo.
python app.py

pause
