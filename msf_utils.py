#!/usr/bin/env python3
"""
PenTool - msf_utils.py
Metasploit RPC integration via pymetasploit3.
"""

try:
    from pymetasploit3.msfrpc import MsfRpcClient, MsfAuthError
    MSF_AVAILABLE = True
except ImportError:
    MsfRpcClient = None
    MsfAuthError = Exception
    MSF_AVAILABLE = False
import os
from db import get_connection

MSF_RPC_HOST = os.getenv("METASPLOIT_RPC_HOST", "127.0.0.1")
MSF_RPC_PORT = int(os.getenv("METASPLOIT_RPC_PORT", "55552"))
MSF_RPC_PASSWORD = os.getenv("METASPLOIT_RPC_PASSWORD", "pentool")
MSF_RPC_SSL = os.getenv("METASPLOIT_RPC_SSL", "true").lower() in ("1", "true", "yes", "on")


class Metasploit:
    def __init__(self, password: str = None, sudo_password: str = None):
        """Initialize Metasploit RPC client."""
        self.client = None
        self.sudo_password = sudo_password
        if not MSF_AVAILABLE:
            raise Exception("pymetasploit3 is not installed. Metasploit integration is unavailable.")
        try:
            self.client = MsfRpcClient(
                password or MSF_RPC_PASSWORD,
                ssl=MSF_RPC_SSL,
                server=MSF_RPC_HOST,
                port=MSF_RPC_PORT
            )
        except MsfAuthError:
            raise Exception("Metasploit RPC authentication failed. Is msfrpcd running?")
        except Exception as e:
            raise Exception(f"Metasploit RPC error: {e}")

    def execute_module(self, module_type: str, module_name: str, options: dict) -> dict:
        """Execute a Metasploit module (exploit, auxiliary, etc).
        Args:
            module_type: "exploit", "auxiliary", etc.
            module_name: e.g., "unix/ftp/vsftpd_234_backdoor".
            options: Dict of options (e.g., {"RHOSTS": "10.0.0.1", "RPORT": 21}).
        Returns:
            Dict with job_id, uuid, and session_id (if applicable).
        """
        try:
            module = self.client.modules.use(module_type, module_name)
            
            # Set options
            for key, value in options.items():
                module[key] = value
            
            # Execute
            if module_type == "exploit":
                exploit_result = module.execute(payload="cmd/unix/interact")
                return {
                    "job_id": exploit_result["job_id"],
                    "uuid": exploit_result["uuid"],
                    "session_id": exploit_result.get("sessionid")
                }
            else:
                # Auxiliary modules return a job_id
                return {"job_id": module.execute()}
        except Exception as e:
            return {"error": str(e)}

    def execute_exploit(self, module_name: str, options: dict) -> dict:
        """Execute a Metasploit exploit module.
        This is an alias that preserves existing exploit_utils expectations.
        """
        return self.execute_module("exploit", module_name, options)

    def list_sessions(self) -> list:
        """List all active Metasploit sessions.
        Returns a list of dicts with id, type, target, info, and tunnel info.
        """
        try:
            raw = self.client.sessions.list
            if not raw:
                return []
            sessions = []
            for sid, data in raw.items():
                sid = int(sid)
                sessions.append({
                    "id": sid,
                    "type": data.get("type", "unknown"),
                    "target": data.get("session_host", data.get("target_host", "unknown")),
                    "info": data.get("info", data.get("desc", "")),
                    "tunnel_local": data.get("tunnel_local", ""),
                    "tunnel_peer": data.get("tunnel_peer", ""),
                    "via_exploit": data.get("via_exploit", ""),
                    "via_payload": data.get("via_payload", ""),
                    "platform": data.get("platform", ""),
                    "arch": data.get("arch", ""),
                    "desc": data.get("desc", ""),
                    "username": data.get("username", ""),
                    "source": "metasploit",
                })
            return sessions
        except Exception as e:
            return []

    def session_interact(self, session_id: int, command: str) -> str:
        """Interact with a meterpreter session."""
        try:
            # Handle sudo commands if we have a sudo password
            if self.sudo_password and command.strip().startswith("sudo "):
                # Use echo to pipe password to sudo -S
                sudo_cmd = command.replace("sudo ", "", 1).strip()
                command = f"echo '{self.sudo_password}' | sudo -S {sudo_cmd}"
            
            session = self.client.sessions.session(session_id)
            result = session.run_with_output(command)
            return result
        except Exception as e:
            return f"[!] Session interaction failed: {e}"

    def stop_session(self, session_id: int) -> bool:
        """Stop a meterpreter session."""
        try:
            session = self.client.sessions.session(session_id)
            session.stop()
            return True
        except Exception as e:
            print(f"[!] Failed to stop session {session_id}: {e}")
            return False

    def destroy_session(self, session_id: int) -> bool:
        """Destroy a meterpreter session."""
        try:
            session = self.client.sessions.session(session_id)
            session.destroy()
            return True
        except Exception as e:
            print(f"[!] Failed to destroy session {session_id}: {e}")
            return False

    def check_if_root(self, session_id: int) -> bool:
        """Check if the current session has root privileges."""
        try:
            # Try whoami first
            whoami_result = self.session_interact(session_id, "whoami")
            if "root" in whoami_result.lower():
                return True
            
            # Try id command as fallback
            id_result = self.session_interact(session_id, "id")
            if "uid=0" in id_result or "root" in id_result:
                return True
                
            return False
        except Exception:
            return False

    def run_post_exploitation_commands(self, session_id: int, commands: list = None) -> dict:
        """Run a series of post-exploitation commands and return results."""
        if commands is None:
            commands = [
                "whoami",
                "id",
                "uname -a",
                "ls -la /root",
                "cat /etc/passwd | grep -E '(root|sudo)'",
                "netstat -tulpn",
                "ps aux | grep -E '(sshd|apache|mysql)'"
            ]
        
        results = {}
        for cmd in commands:
            try:
                output = self.session_interact(session_id, cmd)
                results[cmd] = output
            except Exception as e:
                results[cmd] = f"[!] Failed to execute {cmd}: {e}"
        
        return results

    def save_to_db(self, scan_id: str, module_name: str, options: dict, result: dict):
        """Save Metasploit execution to SQLite."""
        try:
            conn = get_connection()
            c = conn.cursor()
            c.execute(
                "INSERT INTO scan_results (scan_id, command, output, target) VALUES (?, ?, ?, ?)",
                (
                    scan_id,
                    f"msfconsole -x 'use {module_name}; set {'; set '.join([f'{k} {v}' for k, v in options.items()])}; run'",
                    str(result),
                    options.get("RHOSTS", "unknown")
                )
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[!] Failed to save Metasploit result: {e}")

    def save_to_db(self, scan_id: str, module_name: str, options: dict, result: dict):
        """Save Metasploit execution to SQLite."""
        try:
            conn = get_connection()
            c = conn.cursor()
            c.execute(
                "INSERT INTO scan_results (scan_id, command, output, target) VALUES (?, ?, ?, ?)",
                (
                    scan_id,
                    f"msfconsole -x 'use {module_name}; set {'; set '.join([f'{k} {v}' for k, v in options.items()])}; run'",
                    str(result),
                    options.get("RHOSTS", "unknown")
                )
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[!] Failed to save Metasploit result: {e}")


def start_msfrpcd():
    """Start msfrpcd (Metasploit RPC server).
    Requires: sudo msfrpcd -P <password> -S (for production)
    """
    import subprocess
    rpc_host = os.getenv("METASPLOIT_RPC_HOST", MSF_RPC_HOST)
    rpc_port = os.getenv("METASPLOIT_RPC_PORT", str(MSF_RPC_PORT))
    rpc_password = os.getenv("METASPLOIT_RPC_PASSWORD", MSF_RPC_PASSWORD)
    bind_addr = os.getenv("METASPLOIT_RPC_BIND", rpc_host)
    try:
        subprocess.Popen([
            "msfrpcd", "-P", rpc_password, "-S", "-f", "-a", bind_addr, "-p", str(rpc_port)
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"[*] msfrpcd started on {bind_addr}:{rpc_port}. Ensure Metasploit is installed.")
    except FileNotFoundError:
        print("[!] Failed to start msfrpcd: command not found. Is Metasploit installed?")
    except Exception as e:
        print(f"[!] Failed to start msfrpcd: {e}")
