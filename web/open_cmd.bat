@echo off
REM Start Command Prompt window with preloaded shell command
start cmd /k "adb -s %1 shell"
