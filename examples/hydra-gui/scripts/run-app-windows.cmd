@echo off
setlocal EnableExtensions EnableDelayedExpansion

for %%I in ("%~dp0..\..\..") do set "HYDRA_REPO=%%~fI"
cd /d "%HYDRA_REPO%"

if not defined HYDRA_GUI_ADDRESS set "HYDRA_GUI_ADDRESS=127.0.0.1:8787"
set "HYDRA_URL=http://%HYDRA_GUI_ADDRESS%/"
set "HYDRA_TARGET=%HYDRA_REPO%\target"
set "HYDRA_PROFILE=%HYDRA_TARGET%\hydra-gui-browser-profile-windows"
set "HYDRA_LOG_DIR=%HYDRA_TARGET%\hydra-gui-logs"
set "HYDRA_STDOUT=%HYDRA_LOG_DIR%\host.stdout.log"
set "HYDRA_STDERR=%HYDRA_LOG_DIR%\host.stderr.log"
set "HYDRA_HOST=%HYDRA_TARGET%\debug\hydra-msg-example-gui.exe"
set "HYDRA_WASM_JS=%HYDRA_REPO%\examples\hydra-gui\web\pkg\hydra_msg_wasm.js"
set "HYDRA_WASM_BIN=%HYDRA_REPO%\examples\hydra-gui\web\pkg\hydra_msg_wasm_bg.wasm"
set "HYDRA_ERROR="

if exist "%USERPROFILE%\.cargo\bin" set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"

echo HYDRA Windows launcher
echo Repository: %HYDRA_REPO%
echo URL:        %HYDRA_URL%
echo.

where cargo.exe >nul 2>&1
if errorlevel 1 (
  set "HYDRA_ERROR=Rust/Cargo was not found. Install Rust with rustup, then reopen this launcher."
  goto :failure
)

if not exist "%HYDRA_PROFILE%" mkdir "%HYDRA_PROFILE%" >nul 2>&1
if not exist "%HYDRA_LOG_DIR%" mkdir "%HYDRA_LOG_DIR%" >nul 2>&1

if exist "%HYDRA_WASM_JS%" if exist "%HYDRA_WASM_BIN%" goto :wasm_ready

echo [1/4] HYDRA WASM package is missing; building it now...
where wasm-pack.exe >nul 2>&1
if errorlevel 1 (
  echo wasm-pack is not installed. Installing it with Cargo...
  cargo install wasm-pack --locked
  if errorlevel 1 (
    set "HYDRA_ERROR=Could not install wasm-pack."
    goto :failure
  )
)

where rustup.exe >nul 2>&1
if not errorlevel 1 (
  rustup target add wasm32-unknown-unknown
  if errorlevel 1 (
    set "HYDRA_ERROR=Could not install the wasm32-unknown-unknown Rust target."
    goto :failure
  )
)

set "HYDRA_SAVED_RUSTFLAGS=%RUSTFLAGS%"
if not defined HYDRA_WASM_STACK_SIZE set "HYDRA_WASM_STACK_SIZE=16777216"
set "RUSTFLAGS=-C link-arg=-zstack-size=%HYDRA_WASM_STACK_SIZE%"
if exist "%HYDRA_REPO%\examples\hydra-gui\web\pkg" rmdir /s /q "%HYDRA_REPO%\examples\hydra-gui\web\pkg"
wasm-pack build crates\hydra-msg-wasm --target web --release --out-dir ..\..\examples\hydra-gui\web\pkg
set "HYDRA_WASM_EXIT=!ERRORLEVEL!"
set "RUSTFLAGS=%HYDRA_SAVED_RUSTFLAGS%"
if not "!HYDRA_WASM_EXIT!"=="0" (
  set "HYDRA_ERROR=HYDRA WASM build failed with exit code !HYDRA_WASM_EXIT!."
  goto :failure
)
:wasm_ready
echo [2/4] Building the native HYDRA host...
cargo build --manifest-path examples\hydra-gui\Cargo.toml
if errorlevel 1 (
  set "HYDRA_ERROR=HYDRA GUI host build failed."
  goto :failure
)
if not exist "%HYDRA_HOST%" (
  set "HYDRA_ERROR=HYDRA GUI host binary was not produced at %HYDRA_HOST%."
  goto :failure
)

>"%HYDRA_STDOUT%" echo HYDRA host stdout
>"%HYDRA_STDERR%" echo HYDRA host stderr

echo [3/4] Starting the HYDRA host...
start "HYDRA Host" /b "%HYDRA_HOST%" "%HYDRA_GUI_ADDRESS%" 1>>"%HYDRA_STDOUT%" 2>>"%HYDRA_STDERR%"

set /a HYDRA_READY_ATTEMPT=0
:wait_for_host
curl.exe -fsS --max-time 1 "%HYDRA_URL%api/health" >nul 2>&1
if not errorlevel 1 goto :host_ready
set /a HYDRA_READY_ATTEMPT+=1
if !HYDRA_READY_ATTEMPT! GEQ 80 (
  set "HYDRA_ERROR=HYDRA GUI host did not become ready at %HYDRA_URL%."
  goto :failure_cleanup
)
timeout /t 1 /nobreak >nul
goto :wait_for_host

:host_ready
set "HYDRA_BROWSER="
if exist "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" set "HYDRA_BROWSER=%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"
if not defined HYDRA_BROWSER if exist "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe" set "HYDRA_BROWSER=%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"
if not defined HYDRA_BROWSER if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" set "HYDRA_BROWSER=%ProgramFiles%\Google\Chrome\Application\chrome.exe"
if not defined HYDRA_BROWSER if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" set "HYDRA_BROWSER=%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"
if not defined HYDRA_BROWSER if exist "%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe" set "HYDRA_BROWSER=%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"
if not defined HYDRA_BROWSER if exist "%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe" set "HYDRA_BROWSER=%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe"
if not defined HYDRA_BROWSER if exist "%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe" set "HYDRA_BROWSER=%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe"

if not defined HYDRA_BROWSER (
  set "HYDRA_ERROR=Edge, Chrome, or Brave was not found. A Chromium-family browser is required for HYDRA app-window mode."
  goto :failure_cleanup
)

echo [4/4] Opening HYDRA...
echo Browser: %HYDRA_BROWSER%
echo.
echo Keep this launcher window open while HYDRA is running.
echo Closing the HYDRA app window will stop the local host.
echo.
start "" /wait "%HYDRA_BROWSER%" "--user-data-dir=%HYDRA_PROFILE%" "--app=%HYDRA_URL%"
set "HYDRA_BROWSER_EXIT=%ERRORLEVEL%"

taskkill /IM hydra-msg-example-gui.exe /F >nul 2>&1
if not "%HYDRA_BROWSER_EXIT%"=="0" (
  set "HYDRA_ERROR=The HYDRA browser app exited with code %HYDRA_BROWSER_EXIT%."
  goto :failure
)

echo HYDRA closed normally.
echo.
if /I not "%HYDRA_NO_PAUSE%"=="1" pause
endlocal & exit /b 0

:failure_cleanup
taskkill /IM hydra-msg-example-gui.exe /F >nul 2>&1

:failure
echo.
echo ============================================================
echo HYDRA could not start.
echo %HYDRA_ERROR%
echo ============================================================
if exist "%HYDRA_STDERR%" (
  echo.
  echo Host error log: %HYDRA_STDERR%
  type "%HYDRA_STDERR%"
)
echo.
if /I not "%HYDRA_NO_PAUSE%"=="1" pause
endlocal & exit /b 1
