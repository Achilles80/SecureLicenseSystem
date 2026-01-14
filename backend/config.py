"""
Configuration module for SecureLicenseSystem
Contains all security keys, database settings, and constants.
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================
DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'secure_storage.db')

# =============================================================================
# CRYPTOGRAPHIC KEYS
# Security Note: In production, these should be loaded from secure storage
# (e.g., HSM, AWS KMS, or encrypted files). For this lab demo, we generate
# them in memory on startup.
# =============================================================================

print("🔐 Generating RSA-2048 Key Pair...")
PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
PUBLIC_KEY = PRIVATE_KEY.public_key()

# AES-256 Key (32 bytes = 256 bits)
AES_KEY = os.urandom(32)
print("✅ AES-256 Key Generated")

# =============================================================================
# JWT CONFIGURATION
# =============================================================================
JWT_SECRET = os.urandom(32).hex()  # Secret key for signing JWT tokens
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24

# =============================================================================
# OTP CONFIGURATION
# =============================================================================
OTP_LENGTH = 6
OTP_EXPIRY_MINUTES = 5

# =============================================================================
# ACCESS CONTROL MATRIX
# This defines who can access what resources in the system.
# 
# Roles: admin, user, guest
# Resources: generate_license, validate_license, view_users
#
# NIST SP 800-63-2 Compliance Notes:
# - Separation of privileges based on role
# - Least privilege principle applied
# =============================================================================

ACCESS_CONTROL_MATRIX = {
    # Admin has full access to all resources
    "admin": {
        "generate_license": True,
        "validate_license": True,
        "view_users": True,
        "manage_licenses": True,
    },
    # User can only validate licenses (their own or public)
    "user": {
        "generate_license": False,
        "validate_license": True,
        "view_users": False,
        "manage_licenses": False,
    },
    # Guest has minimal access (public validation only)
    "guest": {
        "generate_license": False,
        "validate_license": True,
        "view_users": False,
        "manage_licenses": False,
    }
}

# =============================================================================
# SECURITY DOCUMENTATION FOR VIVA
# =============================================================================
"""
SECURITY LEVELS & RISKS:

1. ENCODING (Base64):
   - NOT ENCRYPTION! Just format conversion
   - Risk: Anyone can decode, provides NO security
   - Use case: Transmitting binary data over text protocols

2. ENCRYPTION (AES-256):
   - Provides CONFIDENTIALITY - data is unreadable without key
   - Risk: Key management is critical
   - Use case: Protecting license data at rest and in transit

3. HASHING (PBKDF2-SHA256):
   - ONE-WAY function - cannot reverse
   - With SALT prevents rainbow table attacks
   - Use case: Password storage

4. DIGITAL SIGNATURE (RSA-PSS):
   - Provides INTEGRITY and AUTHENTICITY
   - Proves data hasn't been tampered with
   - Use case: License validation

POSSIBLE ATTACKS & COUNTERMEASURES:

| Attack               | Countermeasure in This App           |
|---------------------|--------------------------------------|
| Brute Force         | PBKDF2 with 100k iterations          |
| Rainbow Table       | Random salt per password             |
| SQL Injection       | Parameterized queries                |
| Token Tampering     | RSA digital signature                |
| Session Hijacking   | JWT with short expiry                |
| MFA Bypass          | OTP with 5-minute expiry             |
| Privilege Escalation| Role-based access control            |
"""
