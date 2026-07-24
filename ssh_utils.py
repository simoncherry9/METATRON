#!/usr/bin/env python3
"""
PenTool - ssh_utils.py
SSH command execution on Kali Linux targets using paramiko.
Supports:
- Remote command execution
- Shell interaction
- Sudo escalation
- Output capture and storage in SQLite
"""

import paramiko
import os
from db import get_connection
from datetime import datetime


def run_ssh_command(target: str, user: str, password: str, command: str, scan_id: str = "auto") -> str:
    """
    Execute a command on a remote host via SSH.
    Args:
        target: IP/hostname of the remote machine.
        user: SSH username.
        password: SSH password.
        command: Command to execute.
        scan_id: Unique identifier for the scan session.
    Returns:
        Captured output of the command.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(target, username=user, password=password, timeout=30)
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        errors = stderr.read().decode()
        
        # Combine output and errors
        full_output = output if output else errors
        if not full_output:
            full_output = "[!] Command executed but returned no output."
        
        # Store in SQLite
        try:
            conn = get_connection()
            c = conn.cursor()
            c.execute(
                "INSERT INTO scan_results (scan_id, command, output, target, timestamp) VALUES (?, ?, ?, ?, ?)",
                (scan_id, command, full_output, target, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
            conn.commit()
            conn.close()
        except Exception as e:
            full_output += f"\n[!] Failed to save command output: {e}"
            
        return full_output
        
    except Exception as e:
        error_msg = f"[!] SSH command failed: {e}"
        # Store error in SQLite
        try:
            conn = get_connection()
            c = conn.cursor()
            c.execute(
                "INSERT INTO scan_results (scan_id, command, output, target, timestamp) VALUES (?, ?, ?, ?, ?)",
                (scan_id, command, error_msg, target, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
            conn.commit()
            conn.close()
        except Exception:
            pass
        return error_msg
    finally:
        client.close()


def interact_with_shell(target: str, user: str, password: str, scan_id: str = "auto") -> str:
    """
    Open an interactive shell and return the first command's output.
    NOTE: This is a simplified version. Full shell interaction requires async.
    """
    return run_ssh_command(target, user, password, "whoami", scan_id)