#!/usr/bin/env python3
"""
PenTool - tools.py
Recon tool runners and safe command dispatch.
"""

import subprocess
import paramiko
import shlex
import os
import platform
import re
import shutil
import socket
from urllib.parse import urlparse

import requests

from db import add_scan_event, get_connection


CORE_TOOL_DEFINITIONS = [
    {"id": "nmap", "label": "Nmap", "category": "Reconocimiento", "fallback": "Escáner TCP nativo"},
    {"id": "whois", "label": "WHOIS", "category": "Inteligencia", "fallback": "Cliente WHOIS nativo"},
    {"id": "whatweb", "label": "WhatWeb", "category": "Web", "fallback": "Fingerprint HTTP nativo"},
    {"id": "curl", "label": "cURL", "category": "Web", "fallback": None},
    {"id": "dig", "label": "dig", "category": "DNS", "fallback": "nslookup / resolución nativa"},
    {"id": "nikto", "label": "Nikto", "category": "Web", "fallback": "Baseline de cabeceras"},
    {"id": "searchsploit", "label": "SearchSploit", "category": "Explotación", "fallback": None},
    {"id": "msfconsole", "label": "Metasploit", "category": "Explotación", "fallback": None},
    {"id": "sqlmap", "label": "sqlmap", "category": "Validación", "fallback": None},
    {"id": "gobuster", "label": "Gobuster", "category": "Enumeración", "fallback": None},
    {"id": "ffuf", "label": "ffuf", "category": "Enumeración", "fallback": None},
    {"id": "ssh", "label": "OpenSSH", "category": "Acceso", "fallback": None},
]


def get_tool_inventory() -> dict:
    tools = []
    for definition in CORE_TOOL_DEFINITIONS:
        path = shutil.which(definition["id"])
        fallback = definition.get("fallback")
        tools.append({
            **definition,
            "available": bool(path),
            "path": path or "",
            "operational": bool(path or fallback),
            "mode": "external" if path else "fallback" if fallback else "unavailable",
        })
    return {
        "platform": platform.platform(),
        "tools": tools,
        "operational": sum(1 for tool in tools if tool["operational"]),
        "external": sum(1 for tool in tools if tool["available"]),
        "total": len(tools),
    }


def _target_host(target: str) -> str:
    value = str(target or "").strip()
    parsed = urlparse(value if "://" in value else f"//{value}", scheme="")
    return parsed.hostname or value.split("/")[0].split(":")[0]


def _native_tcp_scan(target: str) -> str:
    host = _target_host(target)
    common_ports = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
        80: "http", 110: "pop3", 139: "netbios-ssn", 143: "imap",
        443: "https", 445: "microsoft-ds", 3306: "mysql", 3389: "ms-wbt-server",
        5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http-alt",
        8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    }
    try:
        address = socket.gethostbyname(host)
    except OSError as exc:
        return f"[!] No se pudo resolver {host}: {exc}"

    open_ports = []
    for port, service in common_ports.items():
        try:
            with socket.create_connection((address, port), timeout=0.35):
                open_ports.append((port, service))
        except OSError:
            continue

    lines = [
        f"Native TCP connect scan for {host} ({address})",
        "PORT     STATE SERVICE",
    ]
    lines.extend(f"{port}/tcp  open  {service}" for port, service in open_ports)
    if not open_ports:
        lines.append("No common TCP ports responded. This is not proof that the host has no open ports.")
    lines.append("NOTE: Native fallback scans common ports only; install Nmap for full service and script detection.")
    return "\n".join(lines)


def _native_whois(target: str) -> str:
    query = _target_host(target)

    def ask(server: str, value: str) -> str:
        with socket.create_connection((server, 43), timeout=8) as connection:
            connection.sendall(f"{value}\r\n".encode("utf-8"))
            chunks = []
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")

    try:
        iana = ask("whois.iana.org", query)
        referral = re.search(r"(?im)^refer:\s*(\S+)", iana)
        return ask(referral.group(1), query) if referral else iana
    except Exception as exc:
        return f"[!] WHOIS nativo no disponible para {query}: {exc}"


def _native_web_fingerprint(target: str) -> str:
    value = str(target or "").strip()
    urls = [value] if "://" in value else [f"https://{value}", f"http://{value}"]
    errors = []
    for url in urls:
        try:
            response = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                verify=False,
                headers={"User-Agent": "PenTool/1.0 security-assessment"},
            )
            body = response.text[:250000]
            title_match = re.search(r"(?is)<title[^>]*>(.*?)</title>", body)
            generator_match = re.search(
                r"(?is)<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)",
                body,
            )
            indicators = []
            lower_body = body.lower()
            for needle, label in (
                ("wp-content", "WordPress"),
                ("drupal-settings-json", "Drupal"),
                ("__next_data__", "Next.js"),
                ("ng-version=", "Angular"),
            ):
                if needle in lower_body:
                    indicators.append(label)
            return "\n".join([
                f"URL: {response.url}",
                f"Status: {response.status_code}",
                f"Title: {plain_text(title_match.group(1)) if title_match else '-'}",
                f"Server: {response.headers.get('Server', '-')}",
                f"X-Powered-By: {response.headers.get('X-Powered-By', '-')}",
                f"Generator: {generator_match.group(1).strip() if generator_match else '-'}",
                f"Technologies: {', '.join(indicators) if indicators else 'No obvious framework markers'}",
                "NOTE: Native fallback fingerprint; install WhatWeb for deeper detection.",
            ])
        except requests.RequestException as exc:
            errors.append(f"{url}: {exc}")
    return "[!] No se pudo obtener el objetivo.\n" + "\n".join(errors)


def plain_text(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def run_tool(command: list, timeout: int = 120) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        output = result.stdout.strip()
        errors = result.stderr.strip()

        if output and errors:
            return output + "\n[STDERR]\n" + errors
        if output:
            return output
        if errors:
            return errors
        return "[!] Tool returned no output."
    except subprocess.TimeoutExpired:
        return f"[!] Timed out after {timeout}s: {' '.join(command)}"
    except FileNotFoundError:
        return f"[!] Tool not found: {command[0]}"
    except Exception as exc:
        return f"[!] Unexpected error running {command[0]}: {exc}"


def run_nmap(target: str) -> str:
    if not shutil.which("nmap"):
        return _native_tcp_scan(target)
    print(f"  [*] nmap -sV -sC -T4 --open {target}")
    return run_tool(["nmap", "-sV", "-sC", "-T4", "--open", target], timeout=180)


def run_whois(target: str) -> str:
    if not shutil.which("whois"):
        return _native_whois(target)
    print(f"  [*] whois {target}")
    return run_tool(["whois", target], timeout=30)


def run_whatweb(target: str) -> str:
    if not shutil.which("whatweb"):
        return _native_web_fingerprint(target)
    print(f"  [*] whatweb -a 3 {target}")
    return run_tool(["whatweb", "-a", "3", target], timeout=60)


def run_curl_headers(target: str) -> str:
    print(f"  [*] curl -sI http://{target}")
    output = run_tool(["curl", "-sI", "--max-time", "10", "--location", f"http://{target}"], timeout=20)
    https_output = run_tool(["curl", "-sI", "--max-time", "10", "--location", "-k", f"https://{target}"], timeout=20)
    return f"[HTTP Headers]\n{output}\n\n[HTTPS Headers]\n{https_output}"


def run_dig(target: str) -> str:
    if not shutil.which("dig"):
        nslookup = shutil.which("nslookup")
        if not nslookup:
            try:
                host = _target_host(target)
                addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
                return "[Resolved addresses]\n" + "\n".join(addresses)
            except OSError as exc:
                return f"[!] DNS resolution failed: {exc}"
        outputs = []
        for record_type in ("A", "MX", "NS", "TXT"):
            result = run_tool([nslookup, f"-type={record_type}", _target_host(target)], timeout=15)
            outputs.append(f"[{record_type} Records]\n{result}")
        return "\n\n".join(outputs)
    print(f"  [*] dig {target} ANY")
    a_record = run_tool(["dig", "+short", "A", target], timeout=15)
    mx_record = run_tool(["dig", "+short", "MX", target], timeout=15)
    ns_record = run_tool(["dig", "+short", "NS", target], timeout=15)
    txt_record = run_tool(["dig", "+short", "TXT", target], timeout=15)
    return (
        f"[A Records]\n{a_record}\n\n"
        f"[MX Records]\n{mx_record}\n\n"
        f"[NS Records]\n{ns_record}\n\n"
        f"[TXT Records]\n{txt_record}"
    )


def run_nikto(target: str) -> str:
    if not shutil.which("nikto"):
        value = str(target or "").strip()
        urls = [value] if "://" in value else [f"https://{value}", f"http://{value}"]
        errors = []
        for url in urls:
            try:
                response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
                expected_headers = {
                    "Strict-Transport-Security": "HSTS",
                    "Content-Security-Policy": "CSP",
                    "X-Content-Type-Options": "MIME sniffing protection",
                    "X-Frame-Options": "clickjacking protection",
                    "Referrer-Policy": "referrer policy",
                    "Permissions-Policy": "browser capability policy",
                }
                missing = [label for header, label in expected_headers.items() if header not in response.headers]
                return "\n".join([
                    f"Native HTTP security baseline for {response.url}",
                    f"Status: {response.status_code}",
                    f"Missing defensive headers: {', '.join(missing) if missing else 'None'}",
                    f"Server disclosure: {response.headers.get('Server', 'not exposed')}",
                    "NOTE: This baseline is not a Nikto replacement; install Nikto for its complete test database.",
                ])
            except requests.RequestException as exc:
                errors.append(f"{url}: {exc}")
        return "[!] HTTP baseline failed.\n" + "\n".join(errors)
    print(f"  [*] nikto -h {target}  (this may take a while...)")
    return run_tool(["nikto", "-h", target, "-nointeractive"], timeout=300)


TOOLS_MENU = {
    "1": ("nmap", run_nmap),
    "2": ("whois", run_whois),
    "3": ("whatweb", run_whatweb),
    "4": ("curl headers", run_curl_headers),
    "5": ("dig DNS", run_dig),
    "6": ("nikto", run_nikto),
    "7": ("ssh command", lambda target: "Use [TOOL: ssh user@host 'command'] via LLM"),
}


def _persist_command(scan_id: str, command: str, output: str, target: str):
    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute(
            "INSERT INTO scan_results (scan_id, command, output, target) VALUES (?, ?, ?, ?)",
            (scan_id, command, output, target),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def run_default_recon(
    target: str,
    scan_id: str = None,
    scan_type: str = "standard",
    options: dict = None,
) -> dict:
    print(f"\n[*] Starting recon on: {target}")
    print("-" * 50)

    results = {}
    options = options or {}
    scan_type = str(scan_type or "standard").lower()

    def run_and_log(name: str, command_label: str, runner):
        if scan_id:
            add_scan_event(scan_id, "recon_command", f"Recon: {name}", command_label, "recon")
        output = runner(target)
        if scan_id:
            _persist_command(scan_id, command_label, output, target)
            add_scan_event(scan_id, "recon_output", f"Salida {name}", output, "recon")
        results[name] = output

    service_detection = options.get("service_detect", True)
    dns_enum = options.get("dns_enum", scan_type != "quick")
    web_crawl = options.get("web_crawl", True)

    if service_detection:
        run_and_log("nmap", f"nmap -sV -sC -T4 --open {target}", run_nmap)
    if scan_type != "quick":
        run_and_log("whois", f"whois {target}", run_whois)
    if web_crawl:
        run_and_log("whatweb", f"whatweb -a 3 {target}", run_whatweb)
        run_and_log("curl_headers", f"curl -sI http://{target} && curl -sI https://{target}", run_curl_headers)
    if dns_enum:
        run_and_log("dig", f"dig {target} A/MX/NS/TXT", run_dig)
    if scan_type == "deep" or options.get("nikto", False):
        run_and_log("nikto", f"nikto -h {target} -nointeractive", run_nikto)

    print("-" * 50)
    print("[+] Recon complete.\n")
    return results


def run_single_tool(tool_key: str, target: str) -> str:
    if tool_key in TOOLS_MENU:
        return TOOLS_MENU[tool_key][1](target)
    return f"[!] Unknown tool key: {tool_key}"


def format_recon_for_llm(results: dict) -> str:
    output = ""
    for tool, data in results.items():
        output += f"\n{'=' * 50}\n"
        output += f"[ {tool.upper()} OUTPUT ]\n"
        output += f"{'=' * 50}\n"
        output += data.strip() + "\n"
    return output


ALLOWED_TOOLS = {
    "nmap",
    "whois",
    "whatweb",
    "curl",
    "dig",
    "nikto",
    "searchsploit",
    "msfconsole",
    "ftp",
    "mysql",
    "psql",
    "smbclient",
    "enum4linux",
    "nc",
    "netcat",
    "telnet",
    "ssh",
}
ALLOW_ANY_LOCAL_TOOL = os.getenv("PENTOOL_ALLOW_ANY_LOCAL_TOOL", "1").lower() in {"1", "true", "yes"}

BLOCKED_COMMAND_PATTERNS = (
    " rm ",
    " rm -",
    "dd ",
    "mkfs",
    "shutdown",
    "reboot",
    "poweroff",
    "halt",
    ":(){",
)

INTERACTIVE_LOCAL_TOOLS = {"ftp", "telnet", "nc", "netcat", "mysql", "psql", "ssh", "msfconsole"}


def is_likely_interactive_command(parts: list) -> bool:
    if not parts:
        return False

    tool = parts[0].lower().split("/")[-1]
    joined = " ".join(parts).lower()

    if tool in {"bash", "sh"} and "-lc" in parts:
        return False
    if tool in {"timeout"}:
        return False
    if tool == "curl":
        return False
    if tool == "ftp":
        return not any(flag in parts for flag in ["-inv", "-in", "-v"]) and "<<" not in joined
    if tool in {"mysql", "psql", "ssh"}:
        return "-e" not in parts and "-c" not in parts and "batchmode=yes" not in joined
    if tool in {"nc", "netcat"} and "-lvnp" in joined:
        return True
    if tool in {"nc", "netcat", "telnet", "msfconsole"}:
        return "-x" not in parts and "-r" not in parts and "-q" not in parts and "-z" not in parts
    return tool in INTERACTIVE_LOCAL_TOOLS


def is_blocked_command(command_str: str) -> bool:
    normalized = f" {command_str.strip().lower()} "
    return any(pattern in normalized for pattern in BLOCKED_COMMAND_PATTERNS)


def run_tool_by_command(command_str: str, scan_id: str = "manual", target: str = "remote") -> str:
    if is_blocked_command(command_str):
        return "[!] Command blocked by safety policy."

    try:
        parts = shlex.split(command_str.strip())
    except ValueError as exc:
        return f"[!] Could not parse command: {exc}"
    if not parts:
        return "[!] Empty command."

    tool = parts[0].lower().split("/")[-1]
    if not ALLOW_ANY_LOCAL_TOOL and tool not in ALLOWED_TOOLS:
        return f"[!] Tool '{parts[0]}' is not permitted. Allowed: {ALLOWED_TOOLS}"
    if is_likely_interactive_command(parts):
        return (
            "[!] Refusing likely-interactive local command. Use a non-interactive/scripted form, for example: "
            "curl ftp://anonymous:@TARGET/, "
            "bash -lc \"printf 'user anonymous anonymous\\nls\\nbye\\n' | timeout 15 ftp -inv TARGET\", "
            "mysql --connect-timeout=10 -h TARGET -e 'SHOW DATABASES;', "
            "or msfconsole -q -x 'use ...; set RHOSTS TARGET; run; exit'."
        )

    if tool == "searchsploit":
        if any(arg.endswith(".py") for arg in parts[1:]) and "-m" not in parts:
            return (
                "[!] Invalid searchsploit usage. Use searchsploit -m <exploit_path> to copy the exploit to the local directory, "
                "for example: searchsploit -m unix/remote/49757.py"
            )

    if tool == "nmap" and any(part.startswith("--top-ports") for part in parts):
        for idx, part in enumerate(parts):
            if part == "--top-ports" and idx + 1 < len(parts) and not parts[idx + 1].isdigit():
                return "[!] Invalid nmap syntax: --top-ports requires a numeric port count, for example --top-ports 100."
            if part.startswith("--top-ports=") and not part.split("=", 1)[1].isdigit():
                return "[!] Invalid nmap syntax: --top-ports requires a numeric port count, for example --top-ports=100."

    if tool == "sqlmap" and (any(part in {"--host", "-host", "--port"} for part in parts) or "-p" in parts and "-u" not in parts):
        return (
            "[!] Invalid sqlmap usage for this context. sqlmap is not a raw MySQL host/port client. "
            "Use sqlmap with a parameterized HTTP URL/request, for example "
            "sqlmap -u 'http://TARGET/page.php?id=1' --batch --dbs, or first find URLs/forms with curl/gobuster/nikto. "
            "For direct MySQL exposure use nmap -p3306 --script mysql-info,mysql-empty-password TARGET "
            "or mysql --connect-timeout=10 -h TARGET -u USER -pPASS -e 'SHOW DATABASES;'."
        )

    timeout = 180 if tool in {"nmap", "nikto", "sqlmap", "gobuster", "ffuf"} else 60
    output = run_tool(parts, timeout=timeout)
    _persist_command(scan_id, command_str, output, target)

    if scan_id:
        add_scan_event(scan_id, "llm_tool_command", "Herramienta lanzada por la IA", command_str, "analysis")
        add_scan_event(scan_id, "llm_tool_output", f"Salida de {parts[0]}", output, "analysis")
    return output


def interactive_tool_run(target: str) -> str:
    print("\n[ SELECT TOOLS TO RUN ]")
    for key, (name, _) in TOOLS_MENU.items():
        print(f"  [{key}] {name}")
    print("  [a] Run all (except nikto)")
    print("  [n] Run all + nikto (slow)")

    choice = input("\nChoice(s) e.g. 1 2 4 or a: ").strip().lower()
    if choice == "a":
        return format_recon_for_llm(run_default_recon(target))
    if choice == "n":
        results = run_default_recon(target)
        results["nikto"] = run_nikto(target)
        return format_recon_for_llm(results)

    combined = {}
    for key in choice.split():
        if key in TOOLS_MENU:
            name, func = TOOLS_MENU[key]
            print(f"\n[*] Running {name}...")
            combined[name] = func(target)
        else:
            print(f"[!] Unknown option: {key}")
    return format_recon_for_llm(combined)


if __name__ == "__main__":
    target = input("Enter test target (IP or domain): ").strip()
    print(format_recon_for_llm(run_default_recon(target)))
