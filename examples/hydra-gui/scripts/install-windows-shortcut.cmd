@echo off
setlocal EnableExtensions
for %%I in ("%~dp0..\..\..") do set "HYDRA_REPO=%%~fI"
set "HYDRA_SHORTCUT=%APPDATA%\Microsoft\Windows\Start Menu\Programs\HYDRA.lnk"
set "HYDRA_SHORTCUT_TARGET=%HYDRA_REPO%\scripts\run-hydra-windows.cmd"
set "HYDRA_SHORTCUT_ICON=%HYDRA_REPO%\examples\hydra-gui\assets\hydra.ico"

if not exist "%HYDRA_SHORTCUT_TARGET%" (
  echo HYDRA launcher not found: "%HYDRA_SHORTCUT_TARGET%" 1>&2
  endlocal & exit /b 1
)
if not exist "%HYDRA_SHORTCUT_ICON%" (
  echo HYDRA icon not found: "%HYDRA_SHORTCUT_ICON%" 1>&2
  endlocal & exit /b 1
)

%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -Command "$w=New-Object -ComObject WScript.Shell; $s=$w.CreateShortcut($env:HYDRA_SHORTCUT); $s.TargetPath=$env:HYDRA_SHORTCUT_TARGET; $s.WorkingDirectory=$env:HYDRA_REPO; $s.IconLocation=$env:HYDRA_SHORTCUT_ICON + ',0'; $s.Description='HYDRA private local chat'; $s.Save()"
if errorlevel 1 (
  echo Could not install the HYDRA Start Menu shortcut. 1>&2
  endlocal & exit /b 1
)

if /I not "%~1"=="-Quiet" echo Installed HYDRA Start Menu shortcut: "%HYDRA_SHORTCUT%"
endlocal & exit /b 0
