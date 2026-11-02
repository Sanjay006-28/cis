@echo off
setlocal EnableExtensions

title Android Malware Detection Platform (All-In-One Launcher)

:: -------------------------------------------------------------------------------
:: 1. Navigate to malware root directory
:: -------------------------------------------------------------------------------
cd /d "%~dp0"
set "PROJ_DIR=%CD%"

echo ===============================================================================
echo       Starting Android Malware Detection Platform (FastAPI + React)
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
    echo [INFO] Installing frontend dependencies: npm install
    cd /d "%PROJ_DIR%\frontend"
    call npm install
    cd /d "%PROJ_DIR%"
)

:: -------------------------------------------------------------------------------
:: 4. Intelligent Backend Port Determination (checks 8000, 8001, permissions, etc.)
:: -------------------------------------------------------------------------------
set "BACKEND_ALREADY_RUNNING=0"
set "BACKEND_STARTED_BY_US=0"
for /f "tokens=1" %%p in ('"%PYTHON_EXE%" "%PROJ_DIR%\check_service.py" pick_backend_port') do (
    set "API_PORT=%%p"
)

if not defined API_PORT set "API_PORT=8001"

"%PYTHON_EXE%" "%PROJ_DIR%\check_service.py" health --port %API_PORT% >nul 2>&1
if not errorlevel 1 (
    echo [2/4] FastAPI backend is ALREADY active on port %API_PORT%. Reusing it.
    set "BACKEND_ALREADY_RUNNING=1"
    goto :CHECK_FRONTEND_STEP
) else (
    echo [2/4] Selected port %API_PORT% for FastAPI backend.
)

:: -------------------------------------------------------------------------------
:: 5. Launch FastAPI Backend (if not already running)
:: -------------------------------------------------------------------------------
echo [3/4] Starting FastAPI backend on http://127.0.0.1:%API_PORT% ...
start "Android Malware Analysis - Backend API (Port %API_PORT%)" cmd /k "title Backend API (Port %API_PORT%) && cd /d "%PROJ_DIR%" && "%PYTHON_EXE%" -m uvicorn backend.main:app --host 127.0.0.1 --port %API_PORT%"
set "BACKEND_STARTED_BY_US=1"

:: Wait up to 6 seconds for backend to become responsive
echo [INFO] Waiting for backend to become ready...
for /l %%i in (1,1,6) do (
    "%PYTHON_EXE%" "%PROJ_DIR%\check_service.py" health --port %API_PORT% >nul 2>&1
    if not errorlevel 1 goto :BACKEND_READY_OK
    timeout /t 1 /nobreak >nul 2>&1
)
:BACKEND_READY_OK
echo [INFO] Backend is active on http://127.0.0.1:%API_PORT%

:CHECK_FRONTEND_STEP
:: Explicitly set Vite proxy target to match active backend port
set "VITE_API_PROXY_TARGET=http://127.0.0.1:%API_PORT%"

:: -------------------------------------------------------------------------------
:: 6. Check if Frontend is ALREADY Running on Port 5173
:: -------------------------------------------------------------------------------
set "FRONTEND_ALREADY_RUNNING=0"
"%PYTHON_EXE%" "%PROJ_DIR%\check_service.py" frontend --port 5173 >nul 2>&1
if not errorlevel 1 (
    echo [4/4] React + Vite frontend is ALREADY running on port 5173. Reusing it.
    set "FRONTEND_ALREADY_RUNNING=1"
)

echo.
echo ===============================================================================
echo  Platform Services Status:
echo  - Frontend Web UI:  http://localhost:5173
echo  - Backend API:      http://127.0.0.1:%API_PORT%
echo  - API Swagger Docs: http://127.0.0.1:%API_PORT%/docs
echo ===============================================================================
echo.

:: Open browser
start http://localhost:5173

if "%FRONTEND_ALREADY_RUNNING%"=="1" (
    echo [INFO] Frontend is already running in an active session.
    echo Backend remains running at http://127.0.0.1:%API_PORT%.
    echo You can safely close this launcher window without stopping services.
    pause
    exit /b 0
)

echo [4/4] Starting React frontend dev server...
echo Press Ctrl+C in THIS window when you want to stop the application.
echo.

cd /d "%PROJ_DIR%\frontend"
call npm run dev

:: -------------------------------------------------------------------------------
:: 7. Clean Shutdown (Only stop backend IF this launcher started it)
:: -------------------------------------------------------------------------------
if "%BACKEND_STARTED_BY_US%"=="1" (
    echo.
    echo [INFO] Stopping backend server started by this session on port %API_PORT%...
    for /f "tokens=5" %%a in ('netstat -aon 2^>nul ^| findstr ":%API_PORT% " ^| findstr /i "LISTENING" 2^>nul') do (
        for /f "tokens=1" %%p in ('tasklist /nh /fi "PID eq %%a" 2^>nul') do (
            if /i "%%p"=="python.exe" taskkill /f /pid %%a >nul 2>&1
        )
    )
) else (
    echo.
    echo [INFO] Backend was already running prior to this session; leaving it active.
)

echo [INFO] Launcher session finished.
exit /b 0
