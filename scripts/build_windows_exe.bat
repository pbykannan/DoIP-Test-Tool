@echo off
setlocal EnableExtensions
REM Run from repo root: scripts\build_windows_exe.bat [version]
REM Example: scripts\build_windows_exe.bat 26.05.09.03
chcp 65001 >nul 2>&1
cd /d "%~dp0.."

if exist ".venv\Scripts\python.exe" (
  set "PY=%CD%\.venv\Scripts\python.exe"
) else (
  set "PY=python"
)

set HTTP_PROXY=
set HTTPS_PROXY=
set http_proxy=
set https_proxy=
set ALL_PROXY=
set ALL_PROXIES=
set PIP_PROXY=
set NO_PROXY=*

echo Using Python: %PY%

REM pip_no_proxy.py disables Windows registry proxy (browser OK != pip OK)
"%PY%" scripts\pip_no_proxy.py install --upgrade pip -q --default-timeout=120
if errorlevel 1 goto pip_fail

"%PY%" scripts\pip_no_proxy.py install -r requirements.txt pyinstaller -q --default-timeout=120
if errorlevel 1 goto pip_fail
goto pip_ok

:pip_fail
echo.
echo pip install failed — often a broken system or pip.ini proxy.
echo   - Windows: Settings - Network - Proxy
echo   - Remove proxy line from %%APPDATA%%\pip\pip.ini
echo   - Retry: "%PY%" scripts\pip_no_proxy.py install -r requirements.txt pyinstaller
pause
exit /b 1

:pip_ok

echo.
echo Close any running DoIPTester*.exe before build, or dist overwrite may fail.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'DoIPTester*' } | Stop-Process -Force -ErrorAction SilentlyContinue" >nul 2>&1
timeout /t 1 /nobreak >nul

if not "%~1"=="" (
  "%PY%" scripts\write_embedded_version.py %~1
) else (
  "%PY%" scripts\write_embedded_version.py
)
if errorlevel 1 exit /b 1

"%PY%" -m PyInstaller --noconfirm --clean DoIPTester.spec
if errorlevel 1 (
  echo.
  echo Build failed. Close DoIPTester.exe, check Task Manager, or disable AV lock on dist\
  pause
  exit /b 1
)

if exist "dist\project_configs" rd /s /q "dist\project_configs"
mkdir "dist\project_configs"
xcopy /y /q "project_configs\*.yaml" "dist\project_configs\" >nul
echo Synced project_configs to dist\project_configs\

set /p BUILD_VER=<src\doip_tester\_embedded_version.txt
echo.
echo OK: dist\DoIPTester_%BUILD_VER%.exe
pause
endlocal
