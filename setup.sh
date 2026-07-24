#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "[+] Creando entorno virtual..."
python3 -m venv venv
source venv/bin/activate

echo "[+] Instalando dependencias..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[+] Creando directorios necesarios..."
mkdir -p reports generated_exploits explorer_downloads

echo "[+] Todo listo."
echo "    Para iniciar el servidor:"
echo "      source venv/bin/activate"
echo "      python main.py"
