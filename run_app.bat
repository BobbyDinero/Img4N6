@echo off
cls
echo =====================================================
echo         IMG/4N6 --- IMAGE THREAT SCANNER
echo =====================================================
echo.
echo Starting Flask server...
echo Dashboard will be available at: http://localhost:5000
echo.
echo Press Ctrl+C to stop the server
echo =====================================================
echo.

REM Check if virtual environment exists and activate it
if exist "venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call venv\Scripts\activate.bat
    echo.
)

REM Wait a moment then prompt to open dashboard
timeout /t 3 /nobreak >nul
echo.
set /p "openDashboard=Open dashboard in browser? (y/n): "
if /i "%openDashboard%"=="y" (
    echo Opening dashboard...
    start http://localhost:5000
) else if /i "%openDashboard%"=="yes" (
    echo Opening dashboard...
    start http://localhost:5000
)
echo.

REM Start the Flask application
python app.py

echo.
echo Server stopped. Press any key to exit...
pause >nul