@echo off
cd /d "%~dp0"

:: Start Docker Desktop only if not already running
docker info >nul 2>&1
if errorlevel 1 (
    echo Starting Docker Desktop...
    start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
) else (
    echo Docker is already running.
)

:: Wait for Docker with a timeout (max ~60s)
echo Waiting for Docker to be ready...
set /a retries=0
:wait_for_docker
docker info >nul 2>&1
if errorlevel 1 (
    set /a retries+=1
    if %retries% geq 30 (
        echo ERROR: Docker did not start within 60 seconds.
        pause
        exit /b 1
    )
    timeout /t 2 /nobreak >nul
    goto wait_for_docker
)
echo Docker is ready!

docker compose up --build -d
if errorlevel 1 (
    echo ERROR: docker compose up failed.
    pause
    exit /b 1
)
echo All services are up.
