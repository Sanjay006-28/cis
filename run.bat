@echo off
setlocal

title Android Malware Detection - React Web App

:: -------------------------------------------------------------------------------
:: 1. Navigate to malware root directory
:: -------------------------------------------------------------------------------
if exist "%~dp0backend\main.py" (
    cd /d "%~dp0"
) else if exist "%~dp0malware\backend\main.py" (
    cd /d "%~dp0malware"
) else (
    cd /d "%~dp0"
)
set "PROJ_DIR=%CD%"

echo ===============================================================================
echo       Starting Android Malware Detection Platform (React + FastAPI)
echo ===============================================================================
echo.

:: -------------------------------------------------------------------------------
:: 2. Locate Virtual Environment Python
:: -------------------------------------------------------------------------------
set "PYTHON_EXE="
if exist "%PROJ_DIR%\venv\Scripts\python.exe" (
    set "PYTHON_EXE=%PROJ_DIR%\venv\Scripts\python.exe"
) else if exist "%PROJ_DIR%\..\venv\Scripts\python.exe" (
    set "PYTHON_EXE=%PROJ_DIR%\..\venv\Scripts\python.exe"
)

if not defined PYTHON_EXE (
    where python >nul 2>&1
    if not errorlevel 1 (
        set "PYTHON_EXE=python"
        echo [WARN] Virtual environment not found. Falling back to system Python.
    ) else (
        echo [ERROR] Python was not found in venv or system PATH!
        echo Please ensure Python is installed and configured.
        pause
        exit /b 1
    )
) else (
    echo [1/4] Found Python virtual environment: %PYTHON_EXE%
)

:: -------------------------------------------------------------------------------
:: 3. Verify Node.js and npm
:: -------------------------------------------------------------------------------
where npm >nul 2>&1
if errorlevel 1 (
    echo [ERROR] npm was not found in PATH!
    echo Node.js is required to run the React frontend.
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

:: Install node_modules if missing
if not exist "%PROJ_DIR%\frontend\node_modules" (
    echo [INFO] Installing frontend dependencies
    cd /d "%PROJ_DIR%\frontend"
    call npm install
    cd /d "%PROJ_DIR%"
)

:: -------------------------------------------------------------------------------
:: 4. Port Auto-Detection (Checks if port 8000 is occupied by Splunk or another service)
:: -------------------------------------------------------------------------------
set "API_PORT=8000"
netstat -aon 2>nul | findstr ":8000 " | findstr /i "LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo [2/4] Port 8000 is occupied by another service. Using port 8001 for FastAPI.
    set "API_PORT=8001"
) else (
    echo [2/4] Using port 8000 for FastAPI backend.
)

:: Stop any old leftover Python server on this port before starting
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":%API_PORT% " ^| findstr /i "LISTENING" 2^>nul') do (
    for /f "tokens=1" %%p in ('tasklist /nh /fi "PID eq %%a" 2^>nul') do (
        if /i "%%p"=="python.exe" taskkill /f /pid %%a >nul 2>&1
    )
)

:: -------------------------------------------------------------------------------
:: 5. Launch FastAPI Backend in a companion window
:: -------------------------------------------------------------------------------
echo [3/4] Starting FastAPI Backend on http://127.0.0.1:%API_PORT%
start "Android Malware Analysis - Backend API (Port %API_PORT%)" cmd /c "title Backend API (Port %API_PORT%) && cd /d "%PROJ_DIR%" && "%PYTHON_EXE%" -m uvicorn backend.main:app --host 127.0.0.1 --port %API_PORT%"

:: Wait 2 seconds for backend to bind
timeout /t 2 /nobreak >nul 2>&1

:: -------------------------------------------------------------------------------
:: 6. Launch Browser and React Frontend
:: -------------------------------------------------------------------------------
echo [4/4] Opening browser to http://localhost:5173
start http://localhost:5173

:: Explicitly set Vite proxy target to match backend port (avoids WSL discovery delay)
set "VITE_API_PROXY_TARGET=http://127.0.0.1:%API_PORT%"

echo.
echo ===============================================================================
echo  Application is running!
echo  - Frontend Web UI:  http://localhost:5173
echo  - Backend API:      http://127.0.0.1:%API_PORT%
echo  - API Swagger Docs: http://127.0.0.1:%API_PORT%/docs
echo.
echo  Backend logs are streaming in the companion window.
echo  Press Ctrl+C in THIS window when you want to stop the application.
echo ===============================================================================
echo.

cd /d "%PROJ_DIR%\frontend"
call npm run dev

:: -------------------------------------------------------------------------------
:: 7. Clean Shutdown when frontend stops
:: -------------------------------------------------------------------------------
echo.
echo [INFO] Stopping backend server
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":%API_PORT% " ^| findstr /i "LISTENING" 2^>nul') do (
    for /f "tokens=1" %%p in ('tasklist /nh /fi "PID eq %%a" 2^>nul') do (
        if /i "%%p"=="python.exe" taskkill /f /pid %%a >nul 2>&1
    )
)

:: Also clean up port 5173 if node remains
for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":5173 " ^| findstr /i "LISTENING" 2^>nul') do (
    taskkill /f /pid %%a >nul 2>&1
)

echo [INFO] All application servers have stopped.
exit /b 0
