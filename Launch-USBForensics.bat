@echo off
title USB Forensic Viewer Launcher
echo.
echo  [USB FORENSIC VIEWER] Starting...
echo  Tip: Run as Administrator for full registry access.
echo.
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0USB-Forensic-Viewer.ps1"
if %errorlevel% neq 0 (
    echo.
    echo  Error launching. Try right-clicking and "Run as administrator".
    pause
)
