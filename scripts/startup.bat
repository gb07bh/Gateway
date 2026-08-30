@echo off
REM Windows Batch Lifecycle Script for Gateway Application
set SCRIPT_DIR=%~dp0
python "%SCRIPT_DIR%startup.py" %*
exit /b %ERRORLEVEL%
