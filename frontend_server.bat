@echo off
setlocal EnableExtensions

title Android Malware Detection - React Frontend (Port 5173)

:: -------------------------------------------------------------------------------
:: 1. Navigate to malware root directory
:: -------------------------------------------------------------------------------
cd /d "%~dp0"
set "PROJ_DIR=%CD%"

:: -------------------------------------------------------------------------------
:: 2. Locate Virtual Environment Python for health checks
:: -------------------------------------------------------------------------------
set "PYTHON_EXE="
if exist "%PROJ_DIR%\venv\Scripts\python.exe" (
    set "PYTHON_EXE=%PROJ_DIR%\venv\Scripts\python.exe"
) else if exist "%PROJ_DIR%\..\venv\Scripts\python.exe" (
    set "PYTHON_EXE=%PROJ_DIR%\..\venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

:: -------------------------------------------------------------------------------
:: 3. Determine Target Backend Port
:: -------------------------------------------------------------------------------
set "API_PORT=%~1"
if "%API_PORT%"=="" (
    for /f "tokens=1" %%p in ('"%PYTHON_EXE%" "%PROJ_DIR%\check_service.py" pick_backend_port') do (
        set "API_PORT=%%p"
    )
)
if not defined API_PORT set "API_PORT=8001"

:: Set Vite proxy target explicitly to match active backend port
set "VITE_API_PROXY_TARGET=http://127.0.0.1:%API_PORT%"

:: -------------------------------------------------------------------------------
:: 4. Verify Node.js / npm
:: -------------------------------------------------------------------------------
where npm >nul 2>&1
if errorlevel 1 (
    echo.
    echo [ERROR] npm was not found in PATH!
    echo Node.js is required to run the React web frontend.
    echo Please install Node.js from https://nodejs.org/
    echo.
    pause
    exit /b 1
)

:: Install dependencies if node_modules is missing
if not exist "%PROJ_DIR%\frontend\node_modules" (
    echo [INFO] First run: Installing frontend dependencies: npm install
    cd /d "%PROJ_DIR%\frontend"
    call npm install
    cd /d "%PROJ_DIR%"
)

:: -------------------------------------------------------------------------------
:: 5. Check if Frontend is ALREADY Running on Port 5173
:: -------------------------------------------------------------------------------
"%PYTHON_EXE%" "%PROJ_DIR%\check_service.py" frontend --port 5173 >nul 2>&1
if not errorlevel 1 (
    echo [SUCCESS] React + Vite frontend is ALREADY running on http://localhost:5173.
    echo Reusing existing frontend service.
    pause
    exit /b 0
)

echo ===============================================================================
echo            React + Vite Frontend (Port 5173)
echo ===============================================================================
echo  Local UI:      http://localhost:5173
echo  Proxy Target:  %VITE_API_PROXY_TARGET%
echo ===============================================================================
echo.

cd /d "%PROJ_DIR%\frontend"
call npm run dev
if errorlevel 1 (
    echo.
    echo [ERROR] Frontend server encountered an error.
    pause
    exit /b 1
)
