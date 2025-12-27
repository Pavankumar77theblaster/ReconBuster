@echo off
echo.
echo ============================================================
echo   ReconBuster - Advanced Security Reconnaissance Tool
echo ============================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

REM Check if venv exists, if not create it
if not exist "venv" (
    echo [*] Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Install requirements if needed
echo [*] Checking dependencies...
pip install -r requirements.txt -q

echo.
echo [*] Starting ReconBuster Web Interface...
echo [*] Open your browser to: http://localhost:5000
echo.
echo Press Ctrl+C to stop the server
echo.

python app.py

pause
