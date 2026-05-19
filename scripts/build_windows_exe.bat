@echo off
REM Run from repo root: scripts\build_windows_exe.bat [version]
REM Example: scripts\build_windows_exe.bat 26.05.09.03
REM If no version argument is given, write today's yy.mm.dd.00
REM See src\doip_tester\_embedded_version.txt
chcp 65001 >nul 2>&1
cd /d "%~dp0.."

REM Pip: clear broken proxy env
set HTTP_PROXY=
set HTTPS_PROXY=
set http_proxy=
set https_proxy=
set ALL_PROXY=
set ALL_PROXIES=

python -m pip install --upgrade pip -q --proxy ""
python -m pip install -r requirements.txt pyinstaller -q --proxy ""

echo.
echo Close any running DoIPTester*.exe before build, or dist overwrite may fail (Access denied).
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'DoIPTester*' } | Stop-Process -Force -ErrorAction SilentlyContinue" >nul 2>&1
timeout /t 1 /nobreak >nul

REM Embed app version into _embedded_version.txt (yy.mm.dd.nn)
if not "%~1"=="" (
  python scripts\write_embedded_version.py %~1
) else (
  python scripts\write_embedded_version.py
)
if errorlevel 1 exit /b 1

python -m PyInstaller --noconfirm --clean DoIPTester.spec
if errorlevel 1 (
  echo.
  echo Build failed. Close DoIPTester.exe, check Task Manager, or disable AV lock on dist\, then retry.
  pause
  exit /b 1
)

REM Fresh mirror: exe startup does not overwrite existing YAML beside exe.
REM Keep dist\project_configs in sync with repo templates.
if exist "dist\project_configs" rd /s /q "dist\project_configs"
mkdir "dist\project_configs"
xcopy /y /q "project_configs\*.yaml" "dist\project_configs\" >nul
echo Synced project_configs to dist\project_configs\

set /p BUILD_VER=<src\doip_tester\_embedded_version.txt
echo.
echo OK: dist\DoIPTester_%BUILD_VER%.exe
echo Beside-exe YAML is copied on first run only; upgrades do not overwrite existing files.
echo To pull templates from the new exe: delete project_configs next to that exe, OR set DOIP_REFRESH_PROJECT_YAML=1 once.
pause
