@echo off
setlocal
cd /d "%~dp0"

:: Activate virtual environment
if exist "%~dp0venv\Scripts\activate.bat" (
    call "%~dp0venv\Scripts\activate.bat"
) else if exist "%~dp0..\venv\Scripts\activate.bat" (
    call "%~dp0..\venv\Scripts\activate.bat"
)

:: Determine API Port
set "PORT=%~1"
if "%PORT%"=="" (
    set "PORT=8000"
    netstat -aon 2>nul | findstr ":8000 " | findstr /i "LISTENING" >nul 2>&1
    if not errorlevel 1 set "PORT=8001"
)

title Android Malware Analysis - FastAPI Backend (Port %PORT%)

echo ===============================================================================
echo            FastAPI Backend Service (Port %PORT%)
echo ===============================================================================
echo  API Base:   http://127.0.0.1:%PORT%
echo  Health:     http://127.0.0.1:%PORT%/api/health
echo  Swagger UI: http://127.0.0.1:%PORT%/docs
echo  ReDoc:      http://127.0.0.1:%PORT%/redoc
echo ===============================================================================
echo.

python -m uvicorn backend.main:app --host 127.0.0.1 --port %PORT%
if errorlevel 1 (
    echo.
    echo [ERROR] Backend server stopped or encountered an error.
    pause
)
