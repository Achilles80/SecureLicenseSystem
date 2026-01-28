"""
Database Models and Operations - handles users, OTPs, licenses, and audit logs.

Tables:
- users         - User accounts with password hashes and roles
- otp_codes     - One-time passwords for MFA
- licenses      - Generated license tokens
- audit_logs    - Security event tracking
- login_attempts - Rate limiting data
"""

import sqlite3
from datetime import datetime, timedelta
from config import DATABASE_PATH


def get_db_connection():
    """Create database connection with row factory."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize all database tables."""
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            otp_code TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            is_used INTEGER DEFAULT 0,
            FOREIGN KEY (username) REFERENCES users(username)
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issued_to TEXT NOT NULL,
            issued_by TEXT NOT NULL,
            token_blob TEXT NOT NULL,
            signature TEXT NOT NULL,
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT,
            attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            success INTEGER DEFAULT 0
        )
    ''')
    
    conn.commit()
    conn.close()
    print("[+] Database initialized")


def seed_default_users():
    """Seed default demo users: admin, user, guest."""
    from utils.crypto import hash_password
    
    default_users = [
        ("admin", "admin123", "admin"),
        ("user", "user123", "user"),
        ("guest", "guest123", "guest"),
    ]
    
    conn = get_db_connection()
    c = conn.cursor()
    
    for username, password, role in default_users:
        try:
            password_hash, salt = hash_password(password)
            c.execute(
                "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
                (username, password_hash, salt, role)
            )
            print(f"  ✅ Created {role} user: {username}")
        except sqlite3.IntegrityError:
            pass
    
    conn.commit()
    conn.close()


# User Operations

def create_user(username: str, password_hash: str, salt: str, role: str = "user"):
    """Create a new user. Returns True on success, False if exists."""
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
            (username, password_hash, salt, role)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_user(username: str):
    """Get user by username. Returns dict or None."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    return dict(user) if user else None


def get_all_users():
    """Get all users (for admin view)."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT username, role FROM users")
    users = [{"username": row[0], "role": row[1], "created_at": "N/A"} for row in c.fetchall()]
    conn.close()
    return users


def update_user_password(username: str, password_hash: str, salt: str) -> bool:
    """Update user's password. Returns True on success."""
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute(
            "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
            (password_hash, salt, username)
        )
        conn.commit()
        return c.rowcount > 0
    finally:
        conn.close()


# OTP Operations

def create_otp(username: str, otp_code: str, expiry_minutes: int = 5):
    """Store new OTP with expiry time."""
    conn = get_db_connection()
    c = conn.cursor()
    expires_at = datetime.now() + timedelta(minutes=expiry_minutes)
    c.execute(
        "INSERT INTO otp_codes (username, otp_code, expires_at) VALUES (?, ?, ?)",
        (username, otp_code, expires_at)
    )
    conn.commit()
    conn.close()


def verify_otp(username: str, otp_code: str) -> bool:
    """Verify OTP. Returns True if valid and not expired. Marks as used."""
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("""
        SELECT id, otp_code, expires_at 
        FROM otp_codes 
        WHERE username = ? AND is_used = 0 
        ORDER BY created_at DESC 
        LIMIT 1
    """, (username,))
    
    record = c.fetchone()
    
    if not record:
        conn.close()
        return False
    
    if record['otp_code'] == otp_code:
        expires_at = datetime.fromisoformat(record['expires_at'])
        if datetime.now() < expires_at:
            c.execute("UPDATE otp_codes SET is_used = 1 WHERE id = ?", (record['id'],))
            conn.commit()
            conn.close()
            return True
    
    conn.close()
    return False


# License Operations

def save_license(issued_to: str, issued_by: str, token_blob: str, signature: str, expires_at: str = None):
    """Save generated license. Returns license ID."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO licenses (issued_to, issued_by, token_blob, signature, expires_at) VALUES (?, ?, ?, ?, ?)",
        (issued_to, issued_by, token_blob, signature, expires_at)
    )
    conn.commit()
    license_id = c.lastrowid
    conn.close()
    return license_id


def get_all_licenses():
    """Get all licenses (for admin view)."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, issued_to, issued_by, token_blob, expires_at, created_at FROM licenses")
    licenses = [dict(row) for row in c.fetchall()]
    conn.close()
    return licenses


def get_licenses_filtered(username_filter: str = None):
    """Get licenses with optional client name filter (partial match)."""
    conn = get_db_connection()
    c = conn.cursor()
    
    if username_filter and username_filter.strip():
        c.execute(
            "SELECT id, issued_to, issued_by, token_blob, expires_at, created_at FROM licenses WHERE issued_to LIKE ?",
            (f"%{username_filter.strip()}%",)
        )
    else:
        c.execute("SELECT id, issued_to, issued_by, token_blob, expires_at, created_at FROM licenses")
    
    licenses = [dict(row) for row in c.fetchall()]
    conn.close()
    return licenses


def delete_license(license_id: int):
    """Delete license by ID. Returns True if deleted."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM licenses WHERE id = ?", (license_id,))
    rows_deleted = c.rowcount
    conn.commit()
    conn.close()
    return rows_deleted > 0


def get_user_licenses(username: str):
    """Get licenses issued to a specific user."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, issued_to, issued_by, token_blob, expires_at, created_at FROM licenses WHERE issued_to = ?",
        (username,)
    )
    licenses = [dict(row) for row in c.fetchall()]
    conn.close()
    return licenses


def license_exists_in_db(token_blob: str) -> bool:
    """Check if a license token exists in the database (not deleted)."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM licenses WHERE token_blob = ?", (token_blob,))
    result = c.fetchone()
    conn.close()
    return result is not None


# Audit Logging

def log_audit(username: str, action: str, details: str = None, ip_address: str = None):
    """Log security event for monitoring."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO audit_logs (username, action, details, ip_address) VALUES (?, ?, ?, ?)",
        (username, action, details, ip_address)
    )
    conn.commit()
    conn.close()


def get_audit_logs(limit: int = 100):
    """Get recent audit logs (for admin view)."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    logs = [dict(row) for row in c.fetchall()]
    conn.close()
    return logs


# Rate Limiting

def record_login_attempt(username: str, success: bool, ip_address: str = None):
    """Record login attempt for rate limiting."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)",
        (username, ip_address, 1 if success else 0)
    )
    conn.commit()
    conn.close()


def get_failed_attempts(username: str, minutes: int = 15) -> int:
    """Count failed login attempts in last N minutes."""
    conn = get_db_connection()
    c = conn.cursor()
    cutoff = datetime.now() - timedelta(minutes=minutes)
    c.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE username = ? AND success = 0 AND attempt_time > ?",
        (username, cutoff)
    )
    count = c.fetchone()[0]
    conn.close()
    return count


def is_rate_limited(username: str, max_attempts: int = 5, window_minutes: int = 15) -> bool:
    """Check if user is rate limited (5+ failed attempts in 15 min)."""
    return get_failed_attempts(username, window_minutes) >= max_attempts
