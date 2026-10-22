@echo off
setlocal

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
  for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSDIR=%%i"
)
if defined VSDIR if exist "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" (
  call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
  cl /nologo /LD /O2 /EHsc dllmain.cpp /Fe:MPtool.dll
  if errorlevel 1 (
    echo [build] FAILED
    exit /b 1
  )
  echo [build] OK ^(MSVC^): MPtool.dll
  dir MPtool.dll
  exit /b 0
)

where x86_64-w64-mingw32-g++ >nul 2>&1
if errorlevel 1 (
  echo [build] No MSVC Build Tools and x86_64-w64-mingw32-g++ not on PATH.
  echo [build] Install VS Build Tools ^(C++ workload^) or WinLibs, then retry.
  exit /b 1
)
x86_64-w64-mingw32-g++ -shared -static -O2 -s -o MPtool.dll dllmain.cpp -lkernel32
if errorlevel 1 (
  echo [build] FAILED
  exit /b 1
)
echo [build] OK ^(MinGW^): MPtool.dll
dir MPtool.dll
