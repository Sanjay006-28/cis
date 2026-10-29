@echo off
setlocal
cd /d "%~dp0frontend"

:: Determine Target Backend Port
set "API_PORT=%~1"
if "%API_PORT%"=="" (
    set "API_PORT=8000"
    netstat -aon 2>nul | findstr ":8000 " | findstr /i "LISTENING" >nul 2>&1
    if not errorlevel 1 set "API_PORT=8001"
)

title Android Malware Analysis - React Frontend (Port 5173)

:: Set Vite proxy target explicitly to avoid WSL discovery timeout
set "VITE_API_PROXY_TARGET=http://127.0.0.1:%API_PORT%"

:: Check if Node.js / npm is installed
where npm >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] npm was not found in PATH!
    echo Node.js is required to run the React web frontend.
    echo Please install Node.js from https://nodejs.org/
    echo.
    pause
    exit /b 1
)

:: Install dependencies if node_modules is missing
if not exist "%~dp0frontend\node_modules" (
    echo [INFO] First run: Installing frontend dependencies (npm install)...
    call npm install
)

echo ===============================================================================
echo            React + Vite Frontend (Port 5173)
echo ===============================================================================
echo  Local UI:      http://localhost:5173
echo  Proxy Target:  %VITE_API_PROXY_TARGET%
echo ===============================================================================
echo.

call npm run dev
if errorlevel 1 (
    echo.
    echo [ERROR] Frontend server encountered an error.
    pause
)
