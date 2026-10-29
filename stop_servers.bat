@echo off
title Stop Malware Analysis Servers
echo ===============================================================================
echo Stopping Android Malware Detection Development Servers...
echo ===============================================================================

set "FOUND=0"

:: Check port 8001 (FastAPI fallback)
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":8001 " ^| findstr /i "LISTENING" 2^>nul') do (
    echo [INFO] Stopping backend process %%a on port 8001
    taskkill /f /pid %%a >nul 2>&1
    set "FOUND=1"
)

:: Check port 8000 (FastAPI primary - only if python.exe)
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":8000 " ^| findstr /i "LISTENING" 2^>nul') do (
    for /f "tokens=1" %%p in ('tasklist /nh /fi "PID eq %%a" 2^>nul') do (
        if /i "%%p"=="python.exe" (
            echo [INFO] Stopping backend process %%a on port 8000
            taskkill /f /pid %%a >nul 2>&1
            set "FOUND=1"
        )
    )
)

:: Check port 5173 (React Frontend / Vite)
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":5173 " ^| findstr /i "LISTENING" 2^>nul') do (
    echo [INFO] Stopping frontend process %%a on port 5173
    taskkill /f /pid %%a >nul 2>&1
    set "FOUND=1"
)

:: Check port 8501 (Streamlit Dashboard)
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":8501 " ^| findstr /i "LISTENING" 2^>nul') do (
    echo [INFO] Stopping Streamlit process %%a on port 8501
    taskkill /f /pid %%a >nul 2>&1
    set "FOUND=1"
)

if "%FOUND%"=="0" (
    echo [INFO] No active development servers were found running on ports 8000, 8001, 5173, or 8501.
) else (
    echo [INFO] Server shutdown completed.
)
echo ===============================================================================
