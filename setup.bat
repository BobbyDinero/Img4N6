@echo off
cls
echo ===========================================
echo   IMAGE THREAT SCANNER - AUTOMATED SETUP
echo ===========================================
echo.
echo This script will set up the complete environment for you.
echo.

REM Check if running as Administrator
net session >nul 2>&1
if not %errorLevel% == 0 (
    echo NOTE: Some operations may require administrator privileges
    echo If you encounter permission errors, try running as Administrator
    echo.
)

REM Check if Python is installed
echo [1/8] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo ERROR: Python is not installed or not in PATH
    echo.
    echo Please install Python 3.8 or higher from: https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    echo.
    echo After installing Python:
    echo 1. Restart Command Prompt
    echo 2. Run this setup script again
    echo.
    pause
    exit /b 1
) else (
    python --version
    echo ✓ Python found
)

REM Get Python version and check if it's 3.8+
echo [2/8] Validating Python version...
python -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if errorlevel 1 (
    echo.
    echo ERROR: Python 3.8 or higher required
    echo Please upgrade your Python installation
    echo.
    pause
    exit /b 1
) else (
    echo ✓ Python version compatible
)

REM Check if git is installed (optional)
echo [3/8] Checking Git installation...
git --version >nul 2>&1
if errorlevel 1 (
    echo ⚠ Git not found (optional for manual download)
) else (
    git --version
    echo ✓ Git found
)

REM Create virtual environment
echo [4/8] Creating virtual environment...
if exist "venv\" (
    echo ✓ Virtual environment already exists
) else (
    python -m venv venv
    if errorlevel 1 (
        echo.
        echo ERROR: Failed to create virtual environment
        echo This might be due to permissions or Python installation issues
        echo.
        pause
        exit /b 1
    ) else (
        echo ✓ Virtual environment created
    )
)

REM Activate virtual environment
echo [5/8] Activating virtual environment...
if not exist "venv\Scripts\activate.bat" (
    echo ERROR: Virtual environment activation script not found
    echo Please delete the 'venv' folder and run setup again
    pause
    exit /b 1
)

call venv\Scripts\activate.bat
if errorlevel 1 (
    echo ERROR: Failed to activate virtual environment
    pause
    exit /b 1
) else (
    echo ✓ Virtual environment activated
)

REM Upgrade pip
echo [6/8] Upgrading pip...
python -m pip install --upgrade pip --quiet
if errorlevel 1 (
    echo ⚠ Pip upgrade failed, continuing with existing version
) else (
    echo ✓ Pip upgraded
)

REM Install requirements
echo [7/8] Installing Python packages...
echo This may take a few minutes...
if exist "requirements.txt" (
    pip install -r requirements.txt --quiet --disable-pip-version-check
    if errorlevel 1 (
        echo.
        echo ERROR: Failed to install some packages
        echo.
        echo Common solutions:
        echo 1. Check your internet connection
        echo 2. Try running as Administrator
        echo 3. Temporarily disable antivirus
        echo 4. Install packages individually:
        echo    pip install Flask Pillow opencv-python numpy scipy requests
        echo.
        echo You can still try to run the application...
        pause
    ) else (
        echo ✓ All packages installed successfully
    )
) else (
    echo WARNING: requirements.txt not found
    echo Installing basic packages...
    pip install Flask Pillow opencv-python numpy scipy requests yara-python gunicorn --quiet --disable-pip-version-check
    if errorlevel 1 (
        echo ERROR: Failed to install basic packages
        pause
        exit /b 1
    ) else (
        echo ✓ Basic packages installed
    )
)

REM Create directory structure
echo [8/8] Setting up directory structure...
if not exist "templates\" mkdir templates
if not exist "static\" mkdir static
if not exist "static\css\" mkdir static\css
if not exist "static\js\" mkdir static\js
if not exist "static\images\" mkdir static\images
if not exist "uploads\" mkdir uploads
if not exist "temp_sessions\" mkdir temp_sessions
if not exist "logs\" mkdir logs
if not exist "docs\" mkdir docs
echo ✓ Directory structure created

REM Check required files
echo.
echo Checking required application files...
if not exist "app.py" (
    echo ⚠ WARNING: app.py not found - main application file missing
)
if not exist "image_threat_scanner.py" (
    echo ⚠ WARNING: image_threat_scanner.py not found - scanner module missing
)
if not exist "templates\index.html" (
    echo ⚠ WARNING: templates\index.html not found - web interface missing
)
if not exist "static\css\styles.css" (
    echo ⚠ WARNING: static\css\styles.css not found - styling missing
)
if not exist "static\js\main.js" (
    echo ⚠ WARNING: static\js\main.js not found - frontend logic missing
)
if not exist "rules.yar" (
    echo ⚠ WARNING: rules.yar not found - YARA rules missing
)

REM Test Python imports
echo.
echo Testing critical Python imports...
python -c "import flask" 2>nul && echo ✓ Flask || echo ✗ Flask import failed
python -c "import PIL" 2>nul && echo ✓ Pillow || echo ✗ Pillow import failed
python -c "import cv2" 2>nul && echo ✓ OpenCV || echo ✗ OpenCV import failed
python -c "import numpy" 2>nul && echo ✓ NumPy || echo ✗ NumPy import failed
python -c "import scipy" 2>nul && echo ✓ SciPy || echo ✗ SciPy import failed

echo.
echo ===========================================
echo           SETUP COMPLETE!
echo ===========================================
echo.
echo Directory Structure:
echo   ├── venv/                 (Python virtual environment)
echo   ├── templates/           (HTML templates)
echo   ├── static/              (CSS, JS, images)
echo   ├── uploads/             (Temporary file storage)
echo   ├── temp_sessions/       (Session data)
echo   └── logs/                (Application logs)
echo.
echo Next Steps:
echo   1. Run: run_app.bat      (Start the application)
echo   2. Open: http://127.0.0.1:5000 (Access web interface)
echo   3. Scan your first folder for threats!
echo.
echo Troubleshooting:
echo   - If you get import errors, try: pip install -r requirements.txt
echo   - For permission issues, run Command Prompt as Administrator
echo   - Check the README.md for detailed usage instructions
echo.

REM Create a desktop shortcut (optional)
set /p createShortcut="Create desktop shortcut? (y/n): "
if /i "%createShortcut%"=="y" (
    echo Creating desktop shortcut...
    echo @echo off > "%USERPROFILE%\Desktop\Image Threat Scanner.bat"
    echo cd /d "%CD%" >> "%USERPROFILE%\Desktop\Image Threat Scanner.bat"
    echo call run_app.bat >> "%USERPROFILE%\Desktop\Image Threat Scanner.bat"
    echo ✓ Desktop shortcut created
)

echo.
echo Setup completed successfully!
echo Press any key to exit or run 'run_app.bat' to start the application.
pause >nul