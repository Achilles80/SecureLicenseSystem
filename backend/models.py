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
    Creates users, otp_codes, and licenses tables if they don't exist.
    Also seeds default users for testing.
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
    
    # Licenses table for audit trail
    c.execute('''
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            issued_to TEXT NOT NULL,
            issued_by TEXT NOT NULL,
            token_blob TEXT NOT NULL,
            signature TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized")


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

def save_license(issued_to: str, issued_by: str, token_blob: str, signature: str):
    """Save a generated license to the database."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO licenses (issued_to, issued_by, token_blob, signature) VALUES (?, ?, ?, ?)",
        (issued_to, issued_by, token_blob, signature)
    )
    conn.commit()
    license_id = c.lastrowid
    conn.close()
    return license_id


def get_all_licenses():
    """Retrieve all licenses (for admin view)."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, issued_to, issued_by, created_at FROM licenses")
    licenses = [dict(row) for row in c.fetchall()]
    conn.close()
    return licenses
