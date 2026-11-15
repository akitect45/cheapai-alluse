@echo off
setlocal
where node >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    if exist "%~dp0bin\alluse.js" (
        endlocal
        node "%~dp0bin\alluse.js" %*
        exit /b %ERRORLEVEL%
    )
)
endlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0alluse.ps1" %*
exit /b %ERRORLEVEL%
