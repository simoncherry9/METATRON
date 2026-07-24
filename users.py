import hashlib, os, secrets, sqlite3, json
from datetime import datetime, timedelta
import jwt

JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
JWT_ALGO = "HS256"
JWT_EXP = 86400

def _db():
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), "pentool.db"))
    conn.row_factory = sqlite3.Row
    return conn

def _hash(password: str) -> str:
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return salt.hex() + ":" + key.hex()

def _verify(password: str, stored: str) -> bool:
    try:
        salt_hex, key_hex = stored.split(":")
        salt = bytes.fromhex(salt_hex)
        expected = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
        return secrets.compare_digest(expected, bytes.fromhex(key_hex))
    except Exception:
        return False

def init_users_table():
    conn = _db()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        is_active INTEGER DEFAULT 1,
        created_at TEXT,
        last_login TEXT,
        allowed_targets TEXT DEFAULT ''
    )
    """)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS user_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        created_at TEXT,
        expires_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)
    conn.commit()
    conn.close()

def create_user(username: str, email: str, password: str, role: str = "user") -> dict:
    conn = _db()
    now = datetime.utcnow().isoformat()
    try:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (username, email, _hash(password), role, now),
        )
        conn.commit()
        uid = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]
        conn.close()
        return {"id": uid, "username": username, "email": email, "role": role}
    except sqlite3.IntegrityError as e:
        conn.close()
        field = "username" if "username" in str(e) else "email"
        return {"error": f"El {field} ya está registrado"}

def authenticate_user(username: str, password: str) -> dict:
    conn = _db()
    user = conn.execute(
        "SELECT id, username, email, password_hash, role, is_active FROM users WHERE username = ? OR email = ?",
        (username, username),
    ).fetchone()
    conn.close()
    if not user:
        return {"error": "Credenciales inválidas"}
    if not user["is_active"]:
        return {"error": "Cuenta desactivada"}
    if not _verify(password, user["password_hash"]):
        return {"error": "Credenciales inválidas"}
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
    }

def create_session(user_id: int) -> str:
    token = jwt.encode({
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(seconds=JWT_EXP),
        "jti": secrets.token_hex(16),
    }, JWT_SECRET, algorithm=JWT_ALGO)
    conn = _db()
    now = datetime.utcnow().isoformat()
    expires = (datetime.utcnow() + timedelta(seconds=JWT_EXP)).isoformat()
    conn.execute(
        "INSERT INTO user_sessions (user_id, token, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (user_id, token, now, expires),
    )
    conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, user_id))
    conn.commit()
    conn.close()
    return token

def verify_session(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        conn = _db()
        session = conn.execute(
            "SELECT id FROM user_sessions WHERE token = ? AND user_id = ?",
            (token, payload["user_id"]),
        ).fetchone()
        user = conn.execute(
            "SELECT id, username, email, role, is_active FROM users WHERE id = ?",
            (payload["user_id"],),
        ).fetchone()
        conn.close()
        if not session or not user or not user["is_active"]:
            return {"error": "Sesión inválida"}
        return {"id": user["id"], "username": user["username"], "email": user["email"], "role": user["role"]}
    except jwt.ExpiredSignatureError:
        return {"error": "Sesión expirada"}
    except Exception:
        return {"error": "Sesión inválida"}

def logout_session(token: str):
    conn = _db()
    conn.execute("DELETE FROM user_sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()

def get_user(user_id: int) -> dict:
    conn = _db()
    user = conn.execute(
        "SELECT id, username, email, role, is_active, created_at, last_login FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    conn.close()
    return dict(user) if user else None

def list_users() -> list:
    conn = _db()
    users = conn.execute(
        "SELECT id, username, email, role, is_active, created_at, last_login FROM users ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return [dict(u) for u in users]

def update_user(user_id: int, **kwargs) -> dict:
    allowed = {"username", "email", "role", "is_active"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return {"error": "No hay campos válidos para actualizar"}
    conn = _db()
    for key, value in updates.items():
        conn.execute(f"UPDATE users SET {key} = ? WHERE id = ?", (value, user_id))
    conn.commit()
    conn.close()
    return get_user(user_id)

def change_password(user_id: int, old_password: str, new_password: str) -> dict:
    conn = _db()
    user = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or not _verify(old_password, user["password_hash"]):
        conn.close()
        return {"error": "Contraseña actual incorrecta"}
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (_hash(new_password), user_id))
    conn.commit()
    conn.close()
    return {"success": True}

def delete_user(user_id: int) -> bool:
    conn = _db()
    conn.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return True

init_users_table()

def ensure_admin_exists():
    conn = _db()
    admin = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
    conn.close()
    if not admin:
        create_user("admin", "admin@metatron.local", "metatron", role="admin")
        print("[+] Admin user created: admin / metatron")

ensure_admin_exists()
