@echo off
setlocal
rem Build BAIC_B50_SeedKey.dll for x86 and x64 (static CRT, no VC redist needed)
cd /d "%~dp0"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VSROOT="
if exist "%VSWHERE%" (
    for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%i"
)
if not defined VSROOT (
    echo [ERROR] Visual Studio with C++ tools not found
    exit /b 1
)
set "VCVARS=%VSROOT%\VC\Auxiliary\Build\vcvarsall.bat"

call :build x64 || exit /b 1
call :build x86 || exit /b 1
echo.
echo Done: build\x64\BAIC_B50_SeedKey.dll  build\x86\BAIC_B50_SeedKey.dll
exit /b 0

:build
setlocal
set "ARCH=%~1"
call "%VCVARS%" %ARCH% >nul || exit /b 1
if not exist "build\%ARCH%" mkdir "build\%ARCH%"
cl /nologo /utf-8 /O2 /MT /W4 /LD baic_b50_seedkey.c /Fo"build\%ARCH%\\" /Fe"build\%ARCH%\BAIC_B50_SeedKey.dll" /link /DEF:baic_b50_seedkey.def bcrypt.lib || exit /b 1
del /q "build\%ARCH%\*.obj" "build\%ARCH%\*.exp" 2>nul
echo [OK] %ARCH%
endlocal & exit /b 0
