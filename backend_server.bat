@echo off
setlocal EnableExtensions

title Android Malware Detection - FastAPI Backend

:: -------------------------------------------------------------------------------
:: 1. Navigate to malware root directory
:: -------------------------------------------------------------------------------
cd /d "%~dp0"
set "PROJ_DIR=%CD%"

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
    echo [INFO] Python interpreter: %PYTHON_EXE%
)

:: -------------------------------------------------------------------------------
:: 3. Port Selection (Honors parameter if provided, else auto-picks valid port)
:: -------------------------------------------------------------------------------
set "PORT=%~1"
if "%PORT%"=="" (
    for /f "tokens=1" %%p in ('"%PYTHON_EXE%" "%PROJ_DIR%\check_service.py" pick_backend_port') do (
        set "PORT=%%p"
    )
)
if not defined PORT set "PORT=8001"

"%PYTHON_EXE%" "%PROJ_DIR%\check_service.py" health --port %PORT% >nul 2>&1
if not errorlevel 1 (
    echo [SUCCESS] FastAPI backend is ALREADY running on http://127.0.0.1:%PORT%/api/health.
    echo Reusing existing backend service.
    pause
    exit /b 0
)

title Android Malware Analysis - FastAPI Backend (Port %PORT%)

echo ===============================================================================
echo            FastAPI Backend Service (Port %PORT%)
echo ===============================================================================
echo  API Base:   http://127.0.0.1:%PORT%
echo  Health:     http://127.0.0.1:%PORT%/api/health
echo  Swagger UI: http://127.0.0.1:%PORT%/docs
echo ===============================================================================
echo.

"%PYTHON_EXE%" -m uvicorn backend.main:app --host 127.0.0.1 --port %PORT%
if errorlevel 1 (
    echo.
    echo [ERROR] Backend server stopped or encountered an error.
    pause
    exit /b 1
)
