@echo off
cd /d "%~dp0"
python -m py_compile bh.py deep.py platforms.py contract.py manual.py
if errorlevel 1 goto fail
python -c "import bh, deep, platforms, contract, manual; print('imports ok')"
if errorlevel 1 goto fail
start "" http://127.0.0.1:8787
python bh.py
goto :eof
:fail
echo.
echo compile or import failed - nothing started
pause