@echo off
setlocal EnableExtensions
set "HYDRA_ROOT=%~dp0"
cd /d "%HYDRA_ROOT%"

if exist "%HYDRA_ROOT%scripts\install-hydra-windows.cmd" call "%HYDRA_ROOT%scripts\install-hydra-windows.cmd" -Quiet >nul 2>&1
if exist "%USERPROFILE%\.cargo\bin" set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"

set "HYDRA_CHECK=%HYDRA_ROOT%qa\ci\check-all.ps1"
if not exist "%HYDRA_CHECK%" (
  echo.
  echo HYDRA Windows validation runner not found:
  echo   "%HYDRA_CHECK%"
  echo.
  pause
  endlocal & exit /b 1
)

echo HYDRA-MSG Windows validation repo: %HYDRA_ROOT%
echo Forwarding to shared qa\ci\run_all.py via the Windows adapter
echo.

%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%HYDRA_CHECK%" %*
set "HYDRA_EXIT=%ERRORLEVEL%"
if not "%HYDRA_EXIT%"=="0" (
  echo.
  echo ============================================================
  echo HYDRA validation failed with exit code %HYDRA_EXIT%.
  echo The error above is preserved so it can be copied or photographed.
  echo ============================================================
) else (
  echo.
  echo ============================================================
  echo HYDRA Windows validation completed successfully.
  echo ============================================================
)
echo.
if /I not "%HYDRA_NO_PAUSE%"=="1" pause
endlocal & exit /b %HYDRA_EXIT%
