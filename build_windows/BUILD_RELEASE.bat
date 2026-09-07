@echo off
title RAVENLOCK - Build Release
color 0C
cd /d "%~dp0\.."

echo ============================================================
echo RAVENLOCK - BUILD RELEASE
echo xtr4ng3
echo ============================================================
echo.

where cargo >nul 2>nul
if %errorlevel% neq 0 (
    echo No se encontro Cargo/Rust.
    echo Instala Rust desde rustup.rs
    pause
    exit /b
)

cargo build --release

if %errorlevel% neq 0 (
    echo Fallo compilacion.
    pause
    exit /b
)

mkdir CLIENTE_PORTABLE 2>nul
copy /Y target\release\ravenlock.exe CLIENTE_PORTABLE\ravenlock.exe
copy /Y README.md CLIENTE_PORTABLE\README.txt

echo.
echo Build listo:
echo CLIENTE_PORTABLE\ravenlock.exe
pause
