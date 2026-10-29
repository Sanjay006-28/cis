@echo off
setlocal
title Android Malware Analysis - Streamlit Dashboard (Port 8501)
cd /d "%~dp0"

:: Activate virtual environment
if exist "%~dp0venv\Scripts\activate.bat" (
    call "%~dp0venv\Scripts\activate.bat"
) else if exist "%~dp0..\venv\Scripts\activate.bat" (
    call "%~dp0..\venv\Scripts\activate.bat"
)

echo ===============================================================================
echo            Streamlit Dashboard (Port 8501)
echo ===============================================================================
echo  Dashboard: http://localhost:8501
echo ===============================================================================
echo.

python -m streamlit run app.py
if errorlevel 1 (
    echo.
    echo [ERROR] Streamlit encountered an error.
    pause
)
