# Handoff Artifact

## Header
- Agent: oracle
- Child Session ID: ses_06a80f547ffeY2S7VKxa8bp70e
- Parent Orchestrator Session ID: ses_06a8e9784ffeMbZIBamLurHMCu
- Artifact Path: .opencode-dux/oracle/ses_06a80f547ffeY2S7VKxa8bp70e_20260724-185931_work-in-d-proyectos-metatron.md
- Model: opencode/deepseek-v4-flash-free
- Variant: max
- Mode: blocking
- Purpose: WORK IN D:\Proyectos\METATRON
- Created: 2026-07-24T18:59:31.569Z
- Updated: 2026-07-24T18:59:31.614Z
- Latest Status: completed

## Context
### Referenced Upstream Artifacts
- (none)

### Original Delegation Prompt
```text
<upstream_handoff_artifacts>
HARD REQUIREMENT:
- You MUST read the relevant handoff artifact files listed below before proceeding.
- Treat these files as canonical prior findings from earlier subagents in the same orchestrator session.
- Do NOT ask for context that is already present in these artifacts.
- If a listed artifact is missing or unreadable, report that exact path in <blocked>.

- Orchestrator index (relative): .opencode-dux/orchestrator/ses_06a8e9784ffeMbZIBamLurHMCu.md

- Agent: fixer
  - Child session: ses_06a818e5fffelrhU0alQ5aklVH
  - Status: completed
  - Variant: max
  - Purpose: WORK IN D:\Proyectos\METATRON
  - Relative artifact path: .opencode-dux/fixer/ses_06a818e5fffelrhU0alQ5aklVH_20260724-185859_work-in-d-proyectos-metatron.md
</upstream_handoff_artifacts>

WORK IN D:\Proyectos\METATRON

## Tarea: Reescribir agent_v2.py y crear agent_tools.py para hacer el agente METATRON mucho más potente

Lee estos archivos primero para entender la arquitectura actual:
- D:\Proyectos\METATRON\agent_v2.py (actual - ~330 líneas)
- D:\Proyectos\METATRON\tools.py (para entender cómo se ejecutan comandos localmente)
- D:\Proyectos\METATRON\db.py (para entender la DB)
- D:\Proyectos\METATRON\llm.py (para entender la comunicación con la IA)
- D:\Proyectos\METATRON\search.py (búsquedas web)
- D:\Proyectos\METATRON\cve_engine.py (generación de CVEs/exploits)
- D:\Proyectos\METATRON\victim_explorer.py (exploración de víctima)
- D:\Proyectos\METATRON\main.py (solo las rutas /api/agent/* y /api/exploit/*)

## Lo que necesito

### 1. AGENT_V2.PY (REESCRITO)

Mantener interfaz pública:
```python
def run_autonomous_scan(target, scan_id, recon_data="", lhost="", lport=4444) -> dict
class AgentSession:
    def __init__(self, target, scan_id, lhost="", lport=4444)
    def run_cycle(self, recon_data="") -> dict
```

Nuevas capacidades:

#### ParallelExecutor
- Ejecuta tareas en paralelo usando ProcessPoolExecutor o threading
- `run_parallel(tasks: list[dict]) -> list[dict]`
- Cada task: `{"type": "LOCAL|SESSION|SEARCH", "command": "", "query": ""}`
- Útil para: nmap + gobuster + whatweb simultáneamente

#### StrategyPlanner
- Biblioteca de estrategias predefinidas:
  - `"webapp"`: whatweb → gobuster → nikto → sqlmap → searchsploit → reverse shell
  - `"network"`: nmap -sV → service enumeration → searchsploit → metasploit
  - `"brute"`: nmap → hydra SSH/FTP/MySQL → shell
  - `"aggressive"`: full nmap + gobuster + nikto + whatweb + searchsploit en paralelo
  - `"stealth"`: slow scan, minimal packets, no aggressive probes
- `plan_strategy(strategy_name, target, services) -> list[Action]`

#### DecisionEngine
- Scoring system: `score_action(action, context) -> float`
- Factores: prior successes, service criticality, probability of success, detection risk
- Elige la mejor acción basada en el contexto actual

#### AutoHeal
- Si un comando falla, prueba alternativas automáticamente
- Ej: nmap fails → masscan → rustscan → nc -zv
- Ej: hydra fails → medusa → ncrack → python hydra script
- `heal_command(failed_command, error) -> str|None`

#### ContextManager
- Compresión automática del contexto
- Resume resultados antiguos, prioriza información relevante
- `build_prompt_context() -> str`

#### SessionManager
- Manejo de múltiples sesiones (bindshell, meterpreter, webshell)
- `get_session(type) -> Session`
- `list_sessions() -> list`

#### AgentConfig
- `Config(max_steps=50, parallel=True, strategy="auto", risk_level="normal", stealth=False, proxy="")`
- Configurable por request y por scan

Mejor logging con eventos estructurados:
```python
self.log("parallel_task", "Ejecutando tareas en paralelo", json.dumps(tasks), "agent")
```

### 2. AGENT_TOOLS.PY (NUEVO)

Módulo de herramientas instanciables:

```python
class PortScannerTool:
    def check_available(self) -> bool
    def run(target, ports="", scan_type="quick", proxy="") -> dict
    # Returns: {"success": bool, "open_ports": [...], "os_detected": "", "command": "", "error": ""}

class WebScannerTool:
    def check_available(self) -> bool
    def run(target, scan_type="dirbust") -> dict
    # dirbust → directories found
    # fingerprint → whatweb/nikto results
    # full → both

class BruteForcerTool:
    def check_available(self) -> bool
    def run(target, service, username="", userlist=None, passlist=None) -> dict
    # Supports: ssh, ftp, mysql, http-post, smb, rdp

class PrivEscHelper:
    def check_available(self) -> bool
    def run(session_or_target, os_type="linux") -> dict
    # Enumerates: sudo -l, SUID, capabilities, cron, writable scripts

class Persistence:
    def check_available(self) -> bool
    def run(session_or_target, method, lhost, lport) -> dict
    # Methods: cron_reverse, ssh_key, systemd, scheduled_task

class LateralMovement:
    def check_available(self) -> bool
    def run(session_or_target, target, method, username, password, domain="") -> dict

class DataExfiltrator:
    def check_available(self) -> bool
    def run(session_or_target, file_path, method, lhost, lport=0) -> dict

class LogCleaner:
    def check_available(self) -> bool
    def run(session_or_target, target_logs=None) -> dict

class NetworkPivot:
    def check_available(self) -> bool
    def run(session_or_target, action, target="", port=0) -> dict

class ReverseShellGenerator:
    @staticmethod
    def generate(lhost, lport, type="bash", obfuscate=False) -> str
    @staticmethod
    def list_types() -> list[str]
    # Types: bash, python, php, ruby, perl, nc, powershell, socat, telnet
```

### IMPORTANTE:
- Usar `is_blocked_command` y `run_tool_by_command` de `tools.py` para ejecución local
- Usar `VictimExplorer` para comandos remotos (importar de `victim_explorer`)
- No romper compatibilidad con `db.py`, `llm.py`, `cve_engine.py`
- Todas las herramientas deben ser no-interactivas (timeout, flags "-n" "-b")
- El código debe ser robusto: try/except en todas partes
- Loggear cada acción con add_scan_event

Devuelve el contenido COMPLETO de AMBOS archivos listo para escribir a disco.
```

## Turn 1
- Timestamp: 2026-07-24T18:59:31.614Z
- Status: completed

```text



```

## Parsed Summary
- Detected needs_user: no
- Detected blocked: no
- Inline Handoff Sections:
- (none)