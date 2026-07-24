@echo off
cd /d "%~dp0"

echo [+] Creando entorno virtual...
python -m venv venv
call venv\Scripts\activate.bat

echo [+] Instalando dependencias...
python -m pip install --upgrade pip
pip install -r requirements.txt

echo [+] Creando directorios necesarios...
if not exist reports mkdir reports
if not exist generated_exploits mkdir generated_exploits
if not exist explorer_downloads mkdir explorer_downloads

echo [+] Todo listo.
echo     Para iniciar el servidor:
echo       call venv\Scripts\activate.bat
echo       python main.py
