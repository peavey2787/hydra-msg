@echo off
setlocal EnableExtensions
for %%I in ("%~dp0..") do set "HYDRA_ROOT=%%~fI\"

if exist "%HYDRA_ROOT%scripts\install-hydra-windows.cmd" call "%HYDRA_ROOT%scripts\install-hydra-windows.cmd" -Quiet >nul 2>&1

set "HYDRA_LAUNCHER=%HYDRA_ROOT%examples\hydra-gui\scripts\run-app-windows.cmd"
if not exist "%HYDRA_LAUNCHER%" (
  echo.
  echo HYDRA Windows app launcher not found:
  echo   "%HYDRA_LAUNCHER%"
  echo.
  pause
  endlocal & exit /b 1
)

call "%HYDRA_LAUNCHER%" %*
set "HYDRA_EXIT=%ERRORLEVEL%"
endlocal & exit /b %HYDRA_EXIT%
