@echo off
echo.
echo ============================================================
echo   ReconBuster CLI - Advanced Security Reconnaissance Tool
echo ============================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Activate virtual environment if exists
if exist "venv" (
    call venv\Scripts\activate.bat
)

REM Run CLI with passed arguments
python cli.py %*

pause
