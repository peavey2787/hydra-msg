@echo off
setlocal EnableExtensions EnableDelayedExpansion
for %%I in ("%~dp0..") do set "HYDRA_ROOT=%%~fI\"
set "HYDRA_QUIET="
if /I "%~1"=="-Quiet" set "HYDRA_QUIET=1"

set "HYDRA_RUN_TARGET=%HYDRA_ROOT%scripts\run-hydra-windows.cmd"
set "HYDRA_CHECK_TARGET=%HYDRA_ROOT%run-check-all-windows.cmd"
if not exist "%HYDRA_RUN_TARGET%" (
  echo Required HYDRA launcher not found: "%HYDRA_RUN_TARGET%" 1>&2
  endlocal & exit /b 1
)
if not exist "%HYDRA_CHECK_TARGET%" (
  echo Required HYDRA validation launcher not found: "%HYDRA_CHECK_TARGET%" 1>&2
  endlocal & exit /b 1
)

set "HYDRA_COMMAND_DIR=%LOCALAPPDATA%\Microsoft\WindowsApps"
if not exist "%HYDRA_COMMAND_DIR%" mkdir "%HYDRA_COMMAND_DIR%" >nul 2>&1
set "HYDRA_PROBE=%HYDRA_COMMAND_DIR%\.hydra-write-test-%RANDOM%-%RANDOM%.tmp"
>"%HYDRA_PROBE%" echo ok 2>nul
if errorlevel 1 goto :fallback_bin
del /q "%HYDRA_PROBE%" >nul 2>&1
goto :write_shims

:fallback_bin
set "HYDRA_COMMAND_DIR=%LOCALAPPDATA%\HYDRA\bin"
if not exist "%HYDRA_COMMAND_DIR%" mkdir "%HYDRA_COMMAND_DIR%" >nul 2>&1
if not exist "%HYDRA_COMMAND_DIR%" (
  echo Could not create a writable per-user HYDRA command directory. 1>&2
  endlocal & exit /b 1
)
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -Command "$d=$env:HYDRA_COMMAND_DIR; $p=[Environment]::GetEnvironmentVariable('Path','User'); if(-not $p){$p=''}; $parts=@($p -split ';' | Where-Object { $_ }); if(-not ($parts | Where-Object { $_.TrimEnd('\\') -ieq $d.TrimEnd('\\') })){ [Environment]::SetEnvironmentVariable('Path', (($d + ';' + $p).TrimEnd(';')), 'User') }"
if errorlevel 1 (
  echo Could not update the per-user PATH for HYDRA commands. 1>&2
  endlocal & exit /b 1
)

:write_shims
>"%HYDRA_COMMAND_DIR%\run-hydra-windows.cmd" (
  echo @echo off
  echo call "%HYDRA_RUN_TARGET%" %%*
  echo exit /b %%ERRORLEVEL%%
)
if errorlevel 1 (
  echo Could not install run-hydra-windows.cmd in "%HYDRA_COMMAND_DIR%". 1>&2
  endlocal & exit /b 1
)
>"%HYDRA_COMMAND_DIR%\run-check-all-windows.cmd" (
  echo @echo off
  echo call "%HYDRA_CHECK_TARGET%" %%*
  echo exit /b %%ERRORLEVEL%%
)
if errorlevel 1 (
  echo Could not install run-check-all-windows.cmd in "%HYDRA_COMMAND_DIR%". 1>&2
  endlocal & exit /b 1
)

if exist "%HYDRA_ROOT%examples\hydra-gui\scripts\install-windows-shortcut.cmd" call "%HYDRA_ROOT%examples\hydra-gui\scripts\install-windows-shortcut.cmd" -Quiet >nul 2>&1

if not defined HYDRA_QUIET (
  echo.
  echo HYDRA Windows commands installed for this user.
  echo Command directory: %HYDRA_COMMAND_DIR%
  echo.
  echo Commands:
  echo   run-hydra-windows
  echo   run-check-all-windows
  echo.
  echo If this installer had to add a new PATH directory, open one new
  echo PowerShell/CMD window before using the bare command names.
  echo.
  pause
)
endlocal & exit /b 0
