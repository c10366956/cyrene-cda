@echo off
cd /d "%~dp0"

rem Run tests with the local node runtime (no npm/node required on PATH).
set NODE_EXE=node
where node >nul 2>nul
if not errorlevel 1 goto have_node

if exist "%ProgramFiles%\nodejs\node.exe" (
    set "NODE_EXE=%ProgramFiles%\nodejs\node.exe"
    goto have_node
)
echo [ERROR] node not found. Install Node.js (https://nodejs.org) first.
pause
exit /b 1

:have_node
"%NODE_EXE%" node_modules\vitest\vitest.mjs run %*
if errorlevel 1 (
    echo.
    echo [Cyrene] Tests failed.
    pause
    exit /b 1
)
echo.
echo [Cyrene] Tests passed.
pause
