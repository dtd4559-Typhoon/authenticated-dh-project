@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel% equ 0 (
    set "TASK_PYTHON=py -3"
) else (
    set "TASK_PYTHON=python"
)
if not exist ".venv\Scripts\python.exe" (
    %TASK_PYTHON% -m venv .venv
    if errorlevel 1 goto failed
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed
".venv\Scripts\python.exe" main.py
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m unittest discover -v
if errorlevel 1 goto failed
".venv\Scripts\python.exe" main.py --mode benchmark --trials 3
if errorlevel 1 goto failed
echo.
echo Project completed. Open the results folder for the measured timing files.
pause
exit /b 0
:failed
echo.
echo A command failed. Read the error above before submitting.
echo Confirm Python is installed and internet access is available for setup.
pause
exit /b 1
