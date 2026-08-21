@echo off
title Il2Cpp Offset Explorer
cd /d "%~dp0"
py gui.py
if %ERRORLEVEL% NEQ 0 (
    python gui.py
)
pause
