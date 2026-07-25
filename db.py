#!/usr/bin/env python3
"""
PenTool - db.py
MariaDB connection + all read/write/edit/delete operations
Database: pentool
"""

import sqlite3
import os
import shutil
import json
from datetime import datetime

# ─────────────────────────────────────────────
# CONNECTION
# ─────────────────────────────────────────────

def _database_path():
    base_dir = os.path.dirname(__file__)
    db_path = os.path.join(base_dir, "pentool.db")
    legacy_path = os.path.join(base_dir, f"{'meta'}{'tron'}.db")
    if not os.path.exists(db_path) and os.path.exists(legacy_path):
        shutil.copy2(legacy_path, db_path)
    return db_path


def get_connection():
    """Returns a SQLite connection with WAL mode for better concurrency."""
    conn = sqlite3.connect(_database_path(), timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db():
    """Create runtime tables required by the web dashboard if they do not exist."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS scan_runs (
        scan_id TEXT PRIMARY KEY,
        target TEXT NOT NULL,
        status TEXT NOT NULL,
        phase TEXT,
        started_at TEXT,
        updated_at TEXT,
        completed_at TEXT,
        sl_no INTEGER,
        risk_level TEXT,
        summary TEXT,
        llm_response TEXT,
        raw_scan TEXT,
        error TEXT
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS scan_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        phase TEXT,
        title TEXT,
        content TEXT,
        created_at TEXT,
        FOREIGN KEY (scan_id) REFERENCES scan_runs(scan_id) ON DELETE CASCADE
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        command TEXT,
        output TEXT,
        target TEXT,
        timestamp TEXT,
        FOREIGN KEY (scan_id) REFERENCES scan_runs(scan_id) ON DELETE CASCADE
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS history (
        sl_no INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        scan_date TEXT,
        status TEXT
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sl_no INTEGER NOT NULL,
        vuln_name TEXT,
        severity TEXT,
        port TEXT,
        service TEXT,
        description TEXT,
        FOREIGN KEY (sl_no) REFERENCES history(sl_no) ON DELETE CASCADE
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS fixes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sl_no INTEGER NOT NULL,
        vuln_id INTEGER NOT NULL,
        fix_text TEXT,
        source TEXT,
        FOREIGN KEY (sl_no) REFERENCES history(sl_no) ON DELETE CASCADE,
        FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_time TEXT,
        actor TEXT,
        event_type TEXT,
        details TEXT,
        scan_id TEXT,
        vuln_id INTEGER,
        schedule_id INTEGER
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS scheduled_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        scan_type TEXT,
        intensity TEXT,
        options TEXT,
        schedule_at TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT,
        last_run_at TEXT,
        status TEXT DEFAULT 'scheduled'
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS exploits_attempted (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sl_no INTEGER NOT NULL,
        exploit_name TEXT,
        tool_used TEXT,
        payload TEXT,
        result TEXT,
        notes TEXT,
        FOREIGN KEY (sl_no) REFERENCES history(sl_no) ON DELETE CASCADE
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS exploit_library (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        scan_id TEXT,
        sl_no INTEGER,
        vuln_id INTEGER,
        title TEXT,
        cve TEXT,
        language TEXT,
        filename TEXT,
        code TEXT,
        notes TEXT,
        status TEXT,
        created_at TEXT,
        updated_at TEXT,
        last_result TEXT,
        FOREIGN KEY (sl_no) REFERENCES history(sl_no) ON DELETE SET NULL,
        FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id) ON DELETE SET NULL
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS summary (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sl_no INTEGER NOT NULL,
        raw_scan TEXT,
        ai_analysis TEXT,
        risk_level TEXT,
        generated_at TEXT,
        FOREIGN KEY (sl_no) REFERENCES history(sl_no) ON DELETE CASCADE
    )
    """)
    c.execute("PRAGMA table_info(scan_runs)")
    columns = [row[1] for row in c.fetchall()]
    if "session_id" not in columns:
        c.execute("ALTER TABLE scan_runs ADD COLUMN session_id INTEGER")
    if "sudo_password" not in columns:
        c.execute("ALTER TABLE scan_runs ADD COLUMN sudo_password TEXT")
    conn.commit()
    conn.close()


def _now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


init_db()


# ─────────────────────────────────────────────
# WRITE FUNCTIONS
# ─────────────────────────────────────────────

def create_session(target: str) -> int:
    """Insert new row into history. Returns sl_no."""
    conn = get_connection()
    c = conn.cursor()
    now = _now_str()
    c.execute(
        "INSERT INTO history (target, scan_date, status) VALUES (?, ?, ?)",
        (target, now, "active")
    )
    conn.commit()
    sl_no = c.lastrowid
    conn.close()
    return sl_no


def save_vulnerability(sl_no: int, vuln_name: str, severity: str,
                     port: str, service: str, description: str) -> int:
    """Insert a vulnerability. Returns its id."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO vulnerabilities (sl_no, vuln_name, severity, port, service, description)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (sl_no, vuln_name, severity, port, service, description))
    conn.commit()
    vuln_id = c.lastrowid
    conn.close()
    return vuln_id


def save_fix(sl_no: int, vuln_id: int, fix_text: str, source: str = "ai"):
    """Insert a fix linked to a vulnerability."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO fixes (sl_no, vuln_id, fix_text, source)
        VALUES (?, ?, ?, ?)
    """, (sl_no, vuln_id, fix_text, source))
    conn.commit()
    conn.close()


def save_exploit(sl_no, exploit_name, tool_used, payload, result, notes):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO exploits_attempted
    (sl_no, exploit_name, tool_used, payload, result, notes)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        sl_no,
        str(exploit_name or "")[:1000],
        str(tool_used or "")[:500],
        str(payload or ""),
        str(result or "")[:2000],
        str(notes or "")
    ))
    conn.commit()
    conn.close()


def save_exploit_artifact(target: str, scan_id: str = None, sl_no: int = None, vuln_id: int = None,
                          title: str = "", cve: str = "", language: str = "text",
                          filename: str = "", code: str = "", notes: str = "",
                          status: str = "draft"):
    conn = get_connection()
    c = conn.cursor()
    now = _now_str()
    c.execute("""
    INSERT INTO exploit_library
    (target, scan_id, sl_no, vuln_id, title, cve, language, filename, code, notes, status, created_at, updated_at, last_result)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (target, scan_id, sl_no, vuln_id, title, cve, language, filename, code, notes, status, now, now, ""))
    conn.commit()
    artifact_id = c.lastrowid
    conn.close()
    return artifact_id


def update_exploit_artifact(artifact_id: int, **fields):
    allowed = {"target", "scan_id", "sl_no", "vuln_id", "title", "cve", "language", "filename", "code", "notes", "status", "last_result"}
    updates = {key: value for key, value in fields.items() if key in allowed}
    if not updates:
        return
    updates["updated_at"] = _now_str()
    conn = get_connection()
    c = conn.cursor()
    set_clause = ", ".join(f"{key} = ?" for key in updates)
    c.execute(f"UPDATE exploit_library SET {set_clause} WHERE id = ?", [*updates.values(), artifact_id])
    conn.commit()
    conn.close()


def get_exploit_artifact(artifact_id: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    SELECT id, target, scan_id, sl_no, vuln_id, title, cve, language, filename, code, notes, status, created_at, updated_at, last_result
    FROM exploit_library
    WHERE id = ?
    """, (artifact_id,))
    row = c.fetchone()
    conn.close()
    return row


def list_exploit_artifacts(target: str = None):
    conn = get_connection()
    c = conn.cursor()
    if target:
        c.execute("""
        SELECT id, target, scan_id, sl_no, vuln_id, title, cve, language, filename, code, notes, status, created_at, updated_at, last_result
        FROM exploit_library
        WHERE target = ?
        ORDER BY updated_at DESC, id DESC
        """, (target,))
    else:
        c.execute("""
        SELECT id, target, scan_id, sl_no, vuln_id, title, cve, language, filename, code, notes, status, created_at, updated_at, last_result
        FROM exploit_library
        ORDER BY updated_at DESC, id DESC
        """)
    rows = c.fetchall()
    conn.close()
    return rows


def delete_exploit_artifact(artifact_id: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM exploit_library WHERE id = ?", (artifact_id,))
    conn.commit()
    conn.close()


def save_summary(sl_no: int, raw_scan: str, ai_analysis: str, risk_level: str):
    """Insert or update the full session summary."""
    conn = get_connection()
    c = conn.cursor()
    now = _now_str()
    c.execute("SELECT id FROM summary WHERE sl_no = ? LIMIT 1", (sl_no,))
    existing = c.fetchone()
    if existing:
        c.execute("""
        UPDATE summary
        SET raw_scan = ?, ai_analysis = ?, risk_level = ?, generated_at = ?
        WHERE id = ?
        """, (raw_scan, ai_analysis, risk_level, now, existing[0]))
    else:
        c.execute("""
        INSERT INTO summary (sl_no, raw_scan, ai_analysis, risk_level, generated_at)
        VALUES (?, ?, ?, ?, ?)
        """, (sl_no, raw_scan, ai_analysis, risk_level, now))
    conn.commit()
    conn.close()


def save_audit_log(actor: str, event_type: str, details: str, scan_id: str = None, vuln_id: int = None, schedule_id: int = None):
    conn = get_connection()
    c = conn.cursor()
    now = _now_str()
    c.execute("""
    INSERT INTO audit_logs (event_time, actor, event_type, details, scan_id, vuln_id, schedule_id)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (now, actor, event_type, details, scan_id, vuln_id, schedule_id))
    conn.commit()
    conn.close()


def list_audit_logs(limit: int = 200):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, event_time, actor, event_type, details, scan_id, vuln_id, schedule_id FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows


def save_scheduled_scan(target: str, scan_type: str, intensity: str, options: dict, schedule_at: str, enabled: bool = True):
    conn = get_connection()
    c = conn.cursor()
    now = _now_str()
    c.execute("""
    INSERT INTO scheduled_scans (target, scan_type, intensity, options, schedule_at, enabled, created_at, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        target,
        scan_type,
        intensity,
        json.dumps(options or {}),
        schedule_at,
        1 if enabled else 0,
        now,
        "scheduled"
    ))
    conn.commit()
    schedule_id = c.lastrowid
    conn.close()
    return schedule_id


def get_scheduled_scan(schedule_id: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM scheduled_scans WHERE id = ?", (schedule_id,))
    row = c.fetchone()
    conn.close()
    return row


def list_scheduled_scans():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, target, scan_type, intensity, options, schedule_at, enabled, created_at, last_run_at, status FROM scheduled_scans ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return rows


def get_enabled_scheduled_scans():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, target, scan_type, intensity, options, schedule_at FROM scheduled_scans WHERE enabled = 1 ORDER BY schedule_at ASC")
    rows = c.fetchall()
    conn.close()
    return rows


def update_scheduled_scan_status(schedule_id: int, status: str, enabled: bool = None, last_run_at: str = None):
    conn = get_connection()
    c = conn.cursor()
    updates = ["status = ?"]
    values = [status]
    if enabled is not None:
        updates.append("enabled = ?")
        values.append(1 if enabled else 0)
    if last_run_at is not None:
        updates.append("last_run_at = ?")
        values.append(last_run_at)
    values.append(schedule_id)
    c.execute(f"UPDATE scheduled_scans SET {', '.join(updates)} WHERE id = ?", tuple(values))
    conn.commit()
    conn.close()


def delete_scheduled_scan(schedule_id: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM scheduled_scans WHERE id = ?", (schedule_id,))
    conn.commit()
    conn.close()


def update_history_status(sl_no: int, status: str):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE history SET status = ? WHERE sl_no = ?", (status, sl_no))
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# READ FUNCTIONS
# ─────────────────────────────────────────────

def get_all_history():
    """Return all rows from history ordered by newest first."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    SELECT h.sl_no, h.target, h.scan_date, COALESCE(sr.status, h.status), sr.scan_id
    FROM history h
    LEFT JOIN scan_runs sr ON sr.sl_no = h.sl_no
    ORDER BY h.sl_no DESC
    """)
    rows = c.fetchall()
    conn.close()
    return rows


def get_session(sl_no: int) -> dict:
    """Return everything linked to a sl_no across all tables."""
    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM history WHERE sl_no = ?", (sl_no,))
    history = c.fetchone()

    c.execute("SELECT * FROM vulnerabilities WHERE sl_no = ?", (sl_no,))
    vulns = c.fetchall()

    c.execute("SELECT * FROM fixes WHERE sl_no = ?", (sl_no,))
    fixes = c.fetchall()

    c.execute("SELECT * FROM exploits_attempted WHERE sl_no = ?", (sl_no,))
    exploits = c.fetchall()

    c.execute("SELECT * FROM summary WHERE sl_no = ?", (sl_no,))
    summary = c.fetchone()

    conn.close()

    return {
        "history": history,
        "vulns": vulns,
        "fixes": fixes,
        "exploits": exploits,
        "summary": summary
    }


def get_vulnerabilities(sl_no: int = None):
    conn = get_connection()
    c = conn.cursor()
    if sl_no is None:
        c.execute("SELECT * FROM vulnerabilities ORDER BY id DESC")
    else:
        c.execute("SELECT * FROM vulnerabilities WHERE sl_no = ?", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_vulnerability(vuln_id: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,))
    row = c.fetchone()
    conn.close()
    return row


def create_scan_run(scan_id: str, target: str, status: str = "queued", phase: str = "queued", sudo_password: str = None):
    conn = get_connection()
    c = conn.cursor()
    now = _now_str()
    c.execute("""
    INSERT OR REPLACE INTO scan_runs
    (scan_id, target, status, phase, started_at, updated_at, sudo_password)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (scan_id, target, status, phase, now, now, sudo_password))
    conn.commit()
    conn.close()


def update_scan_run(scan_id: str, **fields):
    if not fields:
        return

    fields = dict(fields)
    fields["updated_at"] = _now_str()

    if fields.get("status") in {"completed", "failed"} and "completed_at" not in fields:
        fields["completed_at"] = _now_str()

    assignments = ", ".join([f"{key} = ?" for key in fields.keys()])
    values = list(fields.values()) + [scan_id]

    conn = get_connection()
    c = conn.cursor()
    c.execute(f"UPDATE scan_runs SET {assignments} WHERE scan_id = ?", values)

    if "sl_no" in fields and fields.get("sl_no"):
        c.execute("UPDATE history SET status = ? WHERE sl_no = ?", (fields.get("status", "active"), fields.get("sl_no")))
    elif "status" in fields:
        c.execute("SELECT sl_no FROM scan_runs WHERE scan_id = ?", (scan_id,))
        row = c.fetchone()
        if row and row[0]:
            c.execute("UPDATE history SET status = ? WHERE sl_no = ?", (fields["status"], row[0]))

    conn.commit()
    conn.close()


def add_scan_event(scan_id: str, event_type: str, title: str, content: str = "", phase: str = None):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    INSERT INTO scan_events (scan_id, event_type, phase, title, content, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (scan_id, event_type, phase, title, content, _now_str()))
    conn.commit()
    conn.close()


def get_scan_run(scan_id: str):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    SELECT scan_id, target, status, phase, started_at, updated_at, completed_at,
           sl_no, risk_level, summary, llm_response, raw_scan, error, session_id
    FROM scan_runs
    WHERE scan_id = ?
    """, (scan_id,))
    row = c.fetchone()
    conn.close()
    return row


def get_scan_run_by_sl_no(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    SELECT scan_id, target, status, phase, started_at, updated_at, completed_at,
           sl_no, risk_level, summary, llm_response, raw_scan, error, session_id
    FROM scan_runs
    WHERE sl_no = ?
    ORDER BY started_at DESC
    LIMIT 1
    """, (sl_no,))
    row = c.fetchone()
    conn.close()
    return row


def get_scan_sudo_password(scan_id: str) -> str:
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT sudo_password FROM scan_runs WHERE scan_id = ?", (scan_id,))
    row = c.fetchone()
    conn.close()
    return row[0] if row and row[0] else None


def get_scan_status(scan_id: str) -> str:
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT status FROM scan_runs WHERE scan_id = ?", (scan_id,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else ""


def list_scan_events(scan_id: str):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    SELECT id, scan_id, event_type, phase, title, content, created_at
    FROM scan_events
    WHERE scan_id = ?
    ORDER BY id ASC
    """, (scan_id,))
    rows = c.fetchall()
    conn.close()
    return rows


def list_scan_results(scan_id: str):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    SELECT id, scan_id, command, output, target, timestamp
    FROM scan_results
    WHERE scan_id = ?
    ORDER BY id ASC
    """, (scan_id,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_fixes(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM fixes WHERE sl_no = ?", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_all_fixes():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM fixes ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return rows


def get_exploits(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM exploits_attempted WHERE sl_no = ?", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_all_exploits():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM exploits_attempted")
    rows = c.fetchall()
    conn.close()
    return rows


# ─────────────────────────────────────────────
# EDIT FUNCTIONS
# ─────────────────────────────────────────────

def edit_vulnerability(vuln_id: int, field: str, value: str):
    """Edit a single field in vulnerabilities by id."""
    allowed = {"vuln_name", "severity", "port", "service", "description"}
    if field not in allowed:
        print(f"[!] Invalid field: {field}. Allowed: {allowed}")
        return
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"UPDATE vulnerabilities SET {field} = ? WHERE id = ?",
        (value, vuln_id)
    )
    conn.commit()
    conn.close()
    print(f"[+] vulnerabilities.{field} updated for id={vuln_id}")


def edit_fix(fix_id: int, fix_text: str):
    """Edit the fix_text of a fix by id."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE fixes SET fix_text = ? WHERE id = ?", (fix_text, fix_id))
    conn.commit()
    conn.close()
    print(f"[+] fix id={fix_id} updated.")


def edit_exploit(exploit_id: int, field: str, value: str):
    """Edit a single field in exploits_attempted by id."""
    allowed = {"exploit_name", "tool_used", "payload", "result", "notes"}
    if field not in allowed:
        print(f"[!] Invalid field: {field}. Allowed: {allowed}")
        return
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"UPDATE exploits_attempted SET {field} = ? WHERE id = ?",
        (value, exploit_id)
    )
    conn.commit()
    conn.close()
    print(f"[+] exploits_attempted.{field} updated for id={exploit_id}")


def edit_summary_risk(sl_no: int, risk_level: str):
    """Update the risk level on a summary."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE summary SET risk_level = ? WHERE sl_no = ?", (risk_level, sl_no))
    conn.commit()
    conn.close()
    print(f"[+] Summary risk_level updated for SL#{sl_no}")


# ─────────────────────────────────────────────
# DELETE FUNCTIONS
# ─────────────────────────────────────────────

def delete_vulnerability(vuln_id: int):
    """Delete a single vulnerability and its linked fixes."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes WHERE vuln_id = ?", (vuln_id,))
    c.execute("DELETE FROM vulnerabilities WHERE id = ?", (vuln_id,))
    conn.commit()
    conn.close()
    print(f"[+] Vulnerability id={vuln_id} and its fixes deleted.")


def delete_exploit(exploit_id: int):
    """Delete a single exploit attempt."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM exploits_attempted WHERE id = ?", (exploit_id,))
    conn.commit()
    conn.close()
    print(f"[+] Exploit id={exploit_id} deleted.")


def delete_fix(fix_id: int):
    """Delete a single fix."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes WHERE id = ?", (fix_id,))
    conn.commit()
    conn.close()
    print(f"[+] Fix id={fix_id} deleted.")


def delete_full_session(sl_no: int):
    """
    Wipe everything linked to a sl_no across all 5 tables.
    Order matters — delete children before parent (FK constraints).
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes WHERE sl_no = ?", (sl_no,))
    c.execute("DELETE FROM exploits_attempted WHERE sl_no = ?", (sl_no,))
    c.execute("DELETE FROM vulnerabilities WHERE sl_no = ?", (sl_no,))
    c.execute("DELETE FROM summary WHERE sl_no = ?", (sl_no,))
    c.execute("DELETE FROM scan_results WHERE scan_id IN (SELECT scan_id FROM scan_runs WHERE sl_no = ?)", (sl_no,))
    c.execute("DELETE FROM scan_events WHERE scan_id IN (SELECT scan_id FROM scan_runs WHERE sl_no = ?)", (sl_no,))
    c.execute("DELETE FROM scan_runs WHERE sl_no = ?", (sl_no,))
    c.execute("DELETE FROM history WHERE sl_no = ?", (sl_no,))
    conn.commit()
    conn.close()
    print(f"[+] Full session SL#{sl_no} deleted from all tables.")


# ─────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────

def print_history(rows):
    print("\n" + "─"*65)
    print(f"{'SL#':<6} {'TARGET':<28} {'DATE':<22} {'STATUS'}")
    print("─"*65)
    for row in rows:
        print(f"{row[0]:<6} {row[1]:<28} {str(row[2]):<22} {row[3]}")
    print()


def print_session(data: dict):
    h = data["history"]
    print(f"\n{'═'*60}")
    print(f"  SL# {h[0]} | Target: {h[1]} | {h[2]} | {h[3]}")
    print(f"{'═'*60}")

    print("\n[ VULNERABILITIES ]")
    if data["vulns"]:
        for v in data["vulns"]:
            print(f"  id={v[0]} | {v[2]} | Severity: {v[3]} | Port: {v[4]} | Service: {v[5]}")
            print(f"           {v[6]}")
    else:
        print("  None recorded.")

    print("\n[ FIXES ]")
    if data["fixes"]:
        for f in data["fixes"]:
            print(f"  id={f[0]} | vuln_id={f[2]} | [{f[4]}] {f[3]}")
    else:
        print("  None recorded.")

    print("\n[ EXPLOITS ATTEMPTED ]")
    if data["exploits"]:
        for e in data["exploits"]:
            print(f"  id={e[0]} | {e[2]} | Tool: {e[3]} | Result: {e[5]}")
            print(f"           Payload: {e[4]}")
            print(f"           Notes:   {e[6]}")
    else:
        print("  None recorded.")

    print("\n[ SUMMARY ]")
    if data["summary"]:
        s = data["summary"]
        print(f"  Risk Level : {s[4]}")
        print(f"  Generated  : {s[5]}")
        print(f"\n  AI Analysis:\n  {s[3][:500]}{'...' if len(str(s[3])) > 500 else ''}")
    else:
        print("  None recorded.")
    print()


# ─────────────────────────────────────────────
# QUICK CONNECTION TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    try:
        init_db()
        conn = get_connection()
        print("[+] MariaDB connection successful.")
        print("[+] Database: pentool")
        conn.close()
    except Exception as e:
        print(f"[!] Connection failed: {e}")
