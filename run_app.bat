@echo off
REM IMG4N6 launcher - opens the browser then starts the server.
if exist "venv\Scripts\activate.bat" call venv\Scripts\activate.bat
set FLASK_DEBUG=0
start "" http://127.0.0.1:5000
python app.py
