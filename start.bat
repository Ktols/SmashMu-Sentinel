@echo off
cd /d "%~dp0"
title Smash MU Sentinel - Estacion Forense & Telemetria en Vivo
color 0B
cls
echo ========================================================
echo   🛡️ SMASH MU SENTINEL - ESTACION FORENSE & TELEMETRIA
echo ========================================================
echo.

echo [1/3] Liberando instancias previas en segundo plano...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :4444 ^| findstr LISTENING') do (
    taskkill /F /PID %%a >nul 2>&1
)

echo [2/3] Abriendo panel web en el navegador (http://localhost:4444)...
start "" "http://localhost:4444"

echo [3/3] Iniciando motor de telemetria en vivo y captura de paquetes...
echo ========================================================
node server.js
pause
