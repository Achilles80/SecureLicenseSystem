"""
Configuration for SecureLicenseSystem.
Contains cryptographic keys, database settings, and access control matrix.
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa

# Database path
DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'secure_storage.db')

# RSA-2048 Key Pair (regenerated on each server restart)
# Note: In production, persist these keys to maintain license validity
print("🔐 Generating RSA-2048 Key Pair...")
PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
PUBLIC_KEY = PRIVATE_KEY.public_key()

# AES-256 Key (32 bytes = 256 bits)
AES_KEY = os.urandom(32)
print("✅ AES-256 Key Generated")

# JWT Configuration
JWT_SECRET = os.urandom(32).hex()
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24

# OTP Configuration  
OTP_LENGTH = 6
OTP_EXPIRY_MINUTES = 5

# Access Control Matrix (RBAC)
# Implements NIST SP 800-63-2 with least privilege principle
ACCESS_CONTROL_MATRIX = {
    "admin": {
        "generate_license": True,
        "validate_license": True,
        "view_users": True,
        "manage_licenses": True,
    },
    "user": {
        "generate_license": False,
        "validate_license": True,
        "view_users": False,
        "manage_licenses": False,
    },
    "guest": {
        "generate_license": False,
        "validate_license": True,
        "view_users": False,
        "manage_licenses": False,
    }
}

"""
SECURITY REFERENCE (For Viva):

Encoding (Base64)      - Format conversion, NOT encryption. Anyone can decode.
Encryption (AES-256)   - Provides confidentiality. Data unreadable without key.
Hashing (PBKDF2)       - One-way function with salt. Used for passwords.
Digital Signature (RSA)- Provides integrity + authenticity. Detects tampering.

Countermeasures:
- Brute Force         → PBKDF2 with 100k iterations
- Rainbow Table       → Random salt per password  
- SQL Injection       → Parameterized queries
- Token Tampering     → RSA digital signature
- Session Hijacking   → JWT with 24h expiry
- MFA Bypass          → OTP with 5-minute expiry
- Privilege Escalation→ Role-based access control
"""
