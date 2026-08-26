@echo off
setlocal

set "PWSH=pwsh.exe"
where pwsh.exe >nul 2>nul
if not errorlevel 1 goto launch

set "PWSH=%ProgramFiles%\PowerShell\7\pwsh.exe"
if exist "%PWSH%" goto launch

set "PWSH=%LOCALAPPDATA%\Microsoft\WindowsApps\pwsh.exe"
if exist "%PWSH%" goto launch

set "PWSH=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\powershell\pwsh.exe"
if exist "%PWSH%" goto launch

echo FastPAS requires PowerShell 7 or newer.
echo Install it from: https://aka.ms/powershell-release?tag=stable
pause
exit /b 1

:launch
"%PWSH%" -NoLogo -NoProfile -File "%~dp0FastPAS.ps1" %*
if errorlevel 1 pause
exit /b %errorlevel%
