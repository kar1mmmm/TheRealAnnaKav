@echo off
title TheRealAnnaKav v0.1.4 - Desktop GUI Launcher
cd /d "%~dp0"

echo ========================================================
echo   TheRealAnnaKav v0.1.4 - Electron GUI Launcher
echo ========================================================
echo.

if exist "node_modules\electron\dist\electron.exe" (
    echo [OK] Binary Electron ditemukan. Membuka GUI...
    call npx electron .
    exit /b 0
)

if exist "..\guiFAIZ\node_modules\electron\dist\electron.exe" (
    echo [OK] Menggunakan Electron yang sudah terinstall di D:\guiFAIZ...
    "..\guiFAIZ\node_modules\electron\dist\electron.exe" "%~dp0"
    exit /b 0
)

if exist "D:\guiFAIZ\node_modules\electron\dist\electron.exe" (
    echo [OK] Menggunakan Electron yang sudah terinstall di D:\guiFAIZ...
    "D:\guiFAIZ\node_modules\electron\dist\electron.exe" "%~dp0"
    exit /b 0
)

echo [INFO] Mengunduh & menyiapkan Electron secara otomatis...
call npm config set ignore-scripts false
set ELECTRON_SKIP_BINARY_DOWNLOAD=
set ELECTRON_MIRROR=https://npmmirror.com/mirrors/electron/
call npm install electron@latest --foreground-scripts --save-dev

echo.
echo [OK] Menjalankan TheRealAnnaKav GUI...
call npm start
pause
