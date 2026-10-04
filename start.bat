@echo off
cd /d "%~dp0"

if not exist "node_modules\electron\dist\electron.exe" (
    echo [ERROR] Dependencies not found. Please run setup.bat once on a machine with Node.js installed.
    pause
    exit /b 1
)

rem Launch directly with the bundled Electron runtime (no npm/node needed on PATH).
start "" "%~dp0node_modules\electron\dist\electron.exe" .
exit /b 0