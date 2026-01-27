"""
Database Models and Operations for SecureLicenseSystem
Handles all database interactions for users, OTPs, and licenses.
"""

import sqlite3
from datetime import datetime, timedelta
from config import DATABASE_PATH


def get_db_connection():
    """Create a database connection with row factory."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Initialize database tables.
    Creates users, otp_codes, licenses, audit_logs, and login_attempts tables.
    """
    conn = get_db_connection()
    c = conn.cursor()
    
    # Users table with role for Access Control
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # OTP codes table for Multi-Factor Authentication
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
    
    # Licenses table with expiry
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
    
    # Audit Logs table - tracks all security events
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
    
    # Login Attempts table - for rate limiting
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
    """
    Seed default users for demo purposes.
    Creates admin, user, and guest accounts with predefined passwords.
    """
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
            pass  # User already exists
    
    conn.commit()
    conn.close()


# =============================================================================
# USER OPERATIONS
# =============================================================================

def create_user(username: str, password_hash: str, salt: str, role: str = "user"):
    """Create a new user in the database."""
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
    """Retrieve a user by username."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    return dict(user) if user else None


def get_all_users():
    """Retrieve all users (for admin view)."""
    conn = get_db_connection()
    c = conn.cursor()
    # Only select columns that exist in both old and new schema
    c.execute("SELECT username, role FROM users")
    users = [{"username": row[0], "role": row[1], "created_at": "N/A"} for row in c.fetchall()]
    conn.close()
    return users


def update_user_password(username: str, password_hash: str, salt: str) -> bool:
    """Update a user's password in the database."""
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute(
            "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
            (password_hash, salt, username)
        )
        conn.commit()
        updated = c.rowcount > 0
        return updated
    finally:
        conn.close()

# =============================================================================
# OTP OPERATIONS
# =============================================================================

def create_otp(username: str, otp_code: str, expiry_minutes: int = 5):
    """Store a new OTP code for a user."""
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
    """
    Verify an OTP code for a user.
    Returns True if valid and not expired, False otherwise.
    Marks OTP as used after successful verification.
    """
    conn = get_db_connection()
    c = conn.cursor()
    
    # Find the most recent unused OTP for this user
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
    
    # Check if OTP matches and is not expired
    if record['otp_code'] == otp_code:
        expires_at = datetime.fromisoformat(record['expires_at'])
        if datetime.now() < expires_at:
            # Mark as used
            c.execute("UPDATE otp_codes SET is_used = 1 WHERE id = ?", (record['id'],))
            conn.commit()
            conn.close()
            return True
    
    conn.close()
    return False


# =============================================================================
# LICENSE OPERATIONS
# =============================================================================

def save_license(issued_to: str, issued_by: str, token_blob: str, signature: str, expires_at: str = None):
    """Save a generated license to the database with optional expiry."""
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
    """Retrieve all licenses (for admin view)."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, issued_to, issued_by, token_blob, expires_at, created_at FROM licenses")
    licenses = [dict(row) for row in c.fetchall()]
    conn.close()
    return licenses


def get_licenses_filtered(username_filter: str = None):
    """
    Retrieve licenses with optional username filter.
    Filters by issued_to (client name) matching the filter string.
    """
    conn = get_db_connection()
    c = conn.cursor()
    
    if username_filter and username_filter.strip():
        # Use LIKE for partial matching
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
    """Delete a license by its ID."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM licenses WHERE id = ?", (license_id,))
    rows_deleted = c.rowcount
    conn.commit()
    conn.close()
    return rows_deleted > 0


def get_user_licenses(username: str):
    """Retrieve licenses issued TO a specific user."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, issued_to, issued_by, token_blob, expires_at, created_at FROM licenses WHERE issued_to = ?",
        (username,)
    )
    licenses = [dict(row) for row in c.fetchall()]
    conn.close()
    return licenses


# =============================================================================
# AUDIT LOGGING
# =============================================================================

def log_audit(username: str, action: str, details: str = None, ip_address: str = None):
    """Log an audit event for security monitoring."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO audit_logs (username, action, details, ip_address) VALUES (?, ?, ?, ?)",
        (username, action, details, ip_address)
    )
    conn.commit()
    conn.close()


def get_audit_logs(limit: int = 100):
    """Retrieve recent audit logs (for admin view)."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
    logs = [dict(row) for row in c.fetchall()]
    conn.close()
    return logs


# =============================================================================
# RATE LIMITING
# =============================================================================

def record_login_attempt(username: str, success: bool, ip_address: str = None):
    """Record a login attempt for rate limiting."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)",
        (username, ip_address, 1 if success else 0)
    )
    conn.commit()
    conn.close()


def get_failed_attempts(username: str, minutes: int = 15) -> int:
    """Get number of failed login attempts in the last N minutes."""
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
    """Check if user is rate limited due to too many failed attempts."""
    failed = get_failed_attempts(username, window_minutes)
    return failed >= max_attempts
