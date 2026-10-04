@echo off
cd /d "%~dp0"

echo [Cyrene] Setting up...

set NPM_CMD=npm
where npm >nul 2>nul
if not errorlevel 1 goto have_npm

rem npm not on PATH - try common install locations
if exist "%ProgramFiles%\nodejs\npm.cmd" (
    set "NPM_CMD=%ProgramFiles%\nodejs\npm.cmd"
    goto have_npm
)
echo [ERROR] npm not found. Install Node.js (https://nodejs.org) first, then re-run setup.bat.
echo [INFO] If dependencies are already installed, just double-click start.bat to launch.
pause
exit /b 1

:have_npm
echo [1/3] Installing dependencies...
call %NPM_CMD% install
if errorlevel 1 (
    echo [ERROR] npm install failed.
    pause
    exit /b 1
)

echo [2/3] Building the app...
call %NPM_CMD% run build
if errorlevel 1 (
    echo [ERROR] npm run build failed.
    pause
    exit /b 1
)

echo [3/3] Fixing Electron GPU sandbox ACL (electron issue #51761)...
icacls "%~dp0node_modules\electron\dist" /grant *S-1-15-2-2:(OI)(CI)(RX) /C >nul 2>nul

echo.
echo [Cyrene] Setup complete. Double-click start.bat to launch.
pause