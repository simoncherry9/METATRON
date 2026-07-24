#!/usr/bin/env python3
"""
PenTool - llm.py
LLM interface, tool-dispatch loop, and parsers.
"""

import re
import requests

from db import add_scan_event, update_scan_run
from llm_config import load_llm_config, run_llm_chat
from search import handle_search_dispatch
from tools import run_tool_by_command

MAX_TOOL_LOOPS = 9

SYSTEM_PROMPT = """Eres PenTool, un asistente elite de pentesting ejecutandose en Parrot OS.
Debes responder siempre en espanol. Se preciso, tecnico y directo. Sin relleno.

Tienes acceso a herramientas reales. Para usarlas, escribe etiquetas en tu respuesta:

  [TOOL: nmap -sV 192.168.1.1] -> runs nmap or any CLI tool
  [SEARCH: CVE-2021-44228 exploit] -> searches the web via DuckDuckGo

Rules:
- Analiza en profundidad los datos del escaneo antes de sugerir exploits
- Lista las vulnerabilidades con: nombre, severidad (critical/high/medium/low), puerto y servicio
- Para cada vulnerabilidad da una descripcion concreta y una remediacion concreta
- Si necesitas mas informacion usa [SEARCH:] o [TOOL:]
- Formatea las vulnerabilidades exactamente como se indica para poder guardarlas en base de datos
- Se especifico con IDs CVE cuando los conozcas
- Termina siempre con una calificacion final de riesgo: CRITICAL / HIGH / MEDIUM / LOW
- Nunca mezcles comentarios extra dentro del campo PORT o SERVICE
- DESC debe tener entre 1 y 3 frases tecnicas utiles
- FIX debe contener una accion clara y concreta

Output format for vulnerabilities (use this exactly):
VULN: <name> | SEVERITY: <level> | PORT: <port> | SERVICE: <service>
DESC: <description>
FIX: <fix recommendation>

Output format for exploits:
EXPLOIT: <name> | TOOL: <tool> | PAYLOAD: <payload or description>
RESULT: <expected result>
NOTES: <any notes>

Finaliza tu analisis con:
RISK_LEVEL: <CRITICAL|HIGH|MEDIUM|LOW>
SUMMARY: <resumen general de 2-3 frases>
IMPORTANTE: usa texto plano solamente. Sin markdown.
REGLAS DE EXACTITUD:
- nmap filtered o no-response significa INCONCLUSIVE y no vulnerable
- Nunca afirmes una version del servidor si no aparece en la salida del escaneo
- Nunca infieras CVEs desde versiones adivinadas
- curl timeouts y HTTP_CODE=000 significan host no alcanzable, no explotable
- ab y stress no son Slowloris salvo confirmacion
- Solo marca CRITICAL si hay evidencia directa de explotabilidad
- Si la evidencia es debil usa LOW e indica que no esta confirmado
- No inventes servicios, versiones ni puertos que no aparezcan en el recon
- No emitas EXPLOIT si no hay vulnerabilidad confirmada y una ruta tecnica concreta
- Nunca uses EXPLOIT: N/A, TOOL: unknown ni payloads de shell genericos como evidencia"""


def ask_lm_studio(messages: list) -> str:
    import time
    try:
        config = load_llm_config()
        print(f"\n[*] Sending to {config['provider']} model {config['model']}...")
        print(f"[*] API base: {config['api_base']}")
        print(f"[*] Timeout: {config['timeout']}s")
        
        start_time = time.time()
        response = run_llm_chat(messages, config)
        elapsed = time.time() - start_time
        
        print(f"[*] Response received in {elapsed:.1f}s")
        if not response:
            print("[!] Model returned an empty response.")
            return "[!] Model returned an empty response."
        return response
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Connection error: {e}")
        return "[!] Cannot connect to the configured LLM provider. Verify the API base URL."
    except requests.exceptions.Timeout as e:
        print(f"[!] Timeout error: {e}")
        return "[!] The configured LLM provider timed out. The model may be overloaded."
    except requests.exceptions.HTTPError as exc:
        print(f"[!] LLM provider HTTP error: {exc}")
        return f"[!] LLM provider HTTP error: {exc}"
    except Exception as exc:
        print(f"[!] Unexpected error: {exc}")
        return f"[!] Unexpected error: {exc}"


def extract_tool_calls(response: str) -> list:
    calls = []
    for match in re.findall(r'\[TOOL:\s*(.+?)\]', response):
        calls.append(("TOOL", match.strip()))
    for match in re.findall(r'\[SEARCH:\s*(.+?)\]', response):
        calls.append(("SEARCH", match.strip()))
    return calls


def summarize_tool_output(raw_output: str) -> str:
    if len(raw_output) < 500:
        return raw_output

    try:
        config = load_llm_config()
        config["temperature"] = 0.2
        config["max_tokens"] = 512
        summary = run_llm_chat(
            [
                {
                    "role": "system",
                    "content": "You are a security data compressor. Extract only security-relevant facts. Return maximum 15 bullet points. Plain text only. No markdown.",
                },
                {
                    "role": "user",
                    "content": f"Compress this tool output:\n{raw_output[:6000]}",
                },
            ],
            config,
        )
        return summary if summary else raw_output
    except Exception:
        return raw_output


def run_tool_calls(calls: list, scan_id: str = None, target: str = "") -> str:
    if not calls:
        return ""

    results = ""
    for call_type, call_content in calls:
        print(f"\n  [DISPATCH] {call_type}: {call_content}")

        if call_type == "TOOL":
            output = run_tool_by_command(call_content, scan_id=scan_id or "manual", target=target or "remote")
        elif call_type == "SEARCH":
            output = handle_search_dispatch(call_content)
            if scan_id:
                add_scan_event(scan_id, "llm_search", "Busqueda solicitada por la IA", call_content, "analysis")
                add_scan_event(scan_id, "llm_search_output", f"Resultado de busqueda: {call_content}", output, "analysis")
        else:
            output = f"[!] Unknown call type: {call_type}"

        compressed = summarize_tool_output(output.strip())
        results += f"\n[{call_type} RESULT: {call_content}]\n"
        results += "-" * 40 + "\n"
        results += compressed + "\n"

    return results


def _clean(line: str) -> str:
    return re.sub(r'\*+', '', line).strip()


def _normalize_severity(value: str) -> str:
    text = (value or "").lower()
    for level in ("critical", "high", "medium", "low"):
        if level in text:
            return level
    if "crit" in text:
        return "critical"
    return "medium"


def _normalize_port(value: str) -> str:
    text = (value or "").strip()
    match = re.search(r'(\d+(?:/\w+)?)', text)
    return match.group(1) if match else text[:100]


def _normalize_service(value: str) -> str:
    text = (value or "").strip()
    return text if text else "N/A"


def parse_vulnerabilities(response: str) -> list:
    vulns = []
    lines = response.splitlines()
    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if line.startswith("VULN:"):
            vuln = {
                "vuln_name": "",
                "severity": "medium",
                "port": "",
                "service": "",
                "description": "",
                "fix": "",
            }
            for part in line.split("|"):
                part = part.strip()
                if part.startswith("VULN:"):
                    vuln["vuln_name"] = part.replace("VULN:", "").strip()
                elif part.startswith("SEVERITY:"):
                    vuln["severity"] = _normalize_severity(part.replace("SEVERITY:", "").strip())
                elif part.startswith("PORT:"):
                    vuln["port"] = _normalize_port(part.replace("PORT:", "").strip())
                elif part.startswith("SERVICE:"):
                    vuln["service"] = _normalize_service(part.replace("SERVICE:", "").strip())

            j = i + 1
            while j < len(lines) and j <= i + 5:
                next_line = _clean(lines[j])
                if next_line.startswith(("VULN:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if next_line.startswith("DESC:"):
                    vuln["description"] = next_line.replace("DESC:", "").strip()
                elif vuln["description"] and not next_line.startswith("FIX:"):
                    vuln["description"] = f"{vuln['description']} {next_line}".strip()
                elif next_line.startswith("FIX:"):
                    vuln["fix"] = next_line.replace("FIX:", "").strip()
                elif vuln["fix"]:
                    vuln["fix"] = f"{vuln['fix']} {next_line}".strip()
                j += 1

            if vuln["vuln_name"]:
                vuln["severity"] = _normalize_severity(vuln["severity"])
                vuln["port"] = _normalize_port(vuln["port"])
                vuln["service"] = _normalize_service(vuln["service"])
                vulns.append(vuln)
        i += 1
    return vulns


def parse_exploits(response: str) -> list:
    exploits = []
    lines = response.splitlines()
    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if line.startswith("EXPLOIT:"):
            exploit = {
                "exploit_name": "",
                "tool_used": "",
                "payload": "",
                "result": "unknown",
                "notes": "",
                "executable": False,
            }
            for part in line.split("|"):
                part = part.strip()
                if part.startswith("EXPLOIT:"):
                    exploit["exploit_name"] = part.replace("EXPLOIT:", "").strip()
                elif part.startswith("TOOL:"):
                    exploit["tool_used"] = part.replace("TOOL:", "").strip()
                elif part.startswith("PAYLOAD:"):
                    exploit["payload"] = part.replace("PAYLOAD:", "").strip()
            # Only mark payloads executable when they are concrete local commands.
            # Narrative exploit descriptions are stored as suggestions and handled
            # later by the controlled Metasploit module mapping.
            tool_used_lower = exploit["tool_used"].lower()
            payload_lower = exploit["payload"].lower()

            if tool_used_lower in {"bash", "sh", "python", "python3", "msfconsole"}:
                exploit["executable"] = True
            elif payload_lower.startswith(("bash ", "sh ", "python ", "python3 ", "msfconsole ")):
                exploit["executable"] = True
            elif payload_lower.startswith(("./", "/usr/bin/", "/bin/")):
                exploit["executable"] = True

            j = i + 1
            while j < len(lines) and j <= i + 4:
                next_line = _clean(lines[j])
                if next_line.startswith(("VULN:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if next_line.startswith("RESULT:"):
                    exploit["result"] = next_line.replace("RESULT:", "").strip()
                elif next_line.startswith("NOTES:"):
                    exploit["notes"] = next_line.replace("NOTES:", "").strip()
                j += 1

            name = _clean(exploit["exploit_name"]).lower()
            tool = _clean(exploit["tool_used"]).lower()
            payload = _clean(exploit["payload"]).lower()
            result = _clean(exploit["result"]).lower()
            is_placeholder = (
                not name
                or name in {"n/a", "na", "none", "ninguno", "no aplica"}
                or tool in {"unknown", "desconocido", "n/a"}
                or "no se encontraron vulnerabilidades" in result
                or "no hay" in result and "explot" in result
                or payload in {"", "n/a", "none", "no aplica"}
            )
            if exploit["exploit_name"] and not is_placeholder:
                exploits.append(exploit)
        i += 1
    return exploits


def parse_risk_level(response: str) -> str:
    match = re.search(r'RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)', response, re.IGNORECASE)
    return match.group(1).upper() if match else "UNKNOWN"


def parse_summary(response: str) -> str:
    match = re.search(r'SUMMARY:\s*(.+)', response, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def analyse_target(target: str, raw_scan: str, scan_id: str = None) -> dict:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": f"""TARGET: {target}

RECON DATA:
{raw_scan}

Analyze this target completely. Use [TOOL:] or [SEARCH:] if you need more information.
List all vulnerabilities, fixes, and suggest exploits where applicable.""",
        },
    ]

    final_response = ""
    executed_calls = set()

    for loop in range(MAX_TOOL_LOOPS):
        response = ask_lm_studio(messages)
        if scan_id:
            add_scan_event(scan_id, "llm_response", f"Respuesta del LLM - ronda {loop + 1}", response, "analysis")
            update_scan_run(scan_id, phase="analysis", llm_response=response)

        print("\n" + "-" * 60)
        print(f"[PenTool - Round {loop + 1}]")
        print("-" * 60)
        print(response)

        final_response = response
        tool_calls = extract_tool_calls(response)
        new_tool_calls = [call for call in tool_calls if call not in executed_calls]
        repeated_tool_calls = [call for call in tool_calls if call in executed_calls]

        if scan_id and tool_calls:
            add_scan_event(
                scan_id,
                "llm_plan",
                f"Llamadas de herramientas - ronda {loop + 1}",
                "\n".join([f"{call_type}: {call_content}" for call_type, call_content in tool_calls]),
                "analysis",
            )
        if scan_id and repeated_tool_calls:
            add_scan_event(
                scan_id,
                "llm_repeated_tools",
                f"Herramientas repetidas omitidas - ronda {loop + 1}",
                "\n".join([f"{call_type}: {call_content}" for call_type, call_content in repeated_tool_calls]),
                "analysis",
            )

        if not tool_calls:
            print("\n[*] No tool calls. Analysis complete.")
            break
        if not new_tool_calls:
            print("\n[*] Only repeated tool calls were requested. Analysis complete.")
            break

        executed_calls.update(new_tool_calls)
        tool_results = run_tool_calls(new_tool_calls, scan_id=scan_id, target=target)
        messages.append({"role": "assistant", "content": response})
        messages.append(
            {
                "role": "user",
                "content": f"""[TOOL RESULTS]
{tool_results}

Continue your analysis with this new information.
Do not request the same TOOL or SEARCH again. If the new results are enough, give the final RISK_LEVEL and SUMMARY without any [TOOL:] or [SEARCH:] tags.""",
            }
        )

    vulnerabilities = parse_vulnerabilities(final_response)
    exploits = parse_exploits(final_response)
    risk_level = parse_risk_level(final_response)
    summary = parse_summary(final_response)

    print(f"\n[+] Parsed: {len(vulnerabilities)} vulns, {len(exploits)} exploits | Risk: {risk_level}")
    if scan_id:
        add_scan_event(scan_id, "analysis_summary", "Resumen final del modelo", final_response, "analysis")

    return {
        "full_response": final_response,
        "vulnerabilities": vulnerabilities,
        "exploits": exploits,
        "risk_level": risk_level,
        "summary": summary,
        "raw_scan": raw_scan,
    }


if __name__ == "__main__":
    print("[ llm.py test - direct AI query ]\n")
    target = input("Test target: ").strip()
    test_scan = f"Test recon for {target} - nmap and whois data would appear here."
    result = analyse_target(target, test_scan)
    print(f"\nRisk Level : {result['risk_level']}")
    print(f"Summary    : {result['summary']}")
    print(f"Vulns found: {len(result['vulnerabilities'])}")
    print(f"Exploits   : {len(result['exploits'])}")
