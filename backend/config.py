"""
Configuration for SecureLicenseSystem.
Contains cryptographic keys, database settings, and access control matrix.
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Database path
DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'secure_storage.db')

# Key file paths (for persistence across restarts)
KEYS_DIR = os.path.join(os.path.dirname(__file__), 'keys')
PRIVATE_KEY_FILE = os.path.join(KEYS_DIR, 'private_key.pem')
PUBLIC_KEY_FILE = os.path.join(KEYS_DIR, 'public_key.pem')
AES_KEY_FILE = os.path.join(KEYS_DIR, 'aes_key.bin')


def load_or_generate_rsa_keys():
    """Load RSA keys from file, or generate new ones if not found."""
    # Create keys directory if it doesn't exist
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)
    
    # Try to load existing keys
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        print("🔐 Loading existing RSA-2048 Key Pair...")
        with open(PRIVATE_KEY_FILE, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(PUBLIC_KEY_FILE, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
        print("✅ RSA Keys Loaded from file")
        return private_key, public_key
    
    # Generate new keys
    print("🔐 Generating new RSA-2048 Key Pair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Save to files
    with open(PRIVATE_KEY_FILE, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(PUBLIC_KEY_FILE, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print("✅ RSA Keys Generated and saved to /keys/")
    return private_key, public_key


def load_or_generate_aes_key():
    """Load AES key from file, or generate new one if not found."""
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)
    
    if os.path.exists(AES_KEY_FILE):
        print("🔑 Loading existing AES-256 Key...")
        with open(AES_KEY_FILE, 'rb') as f:
            aes_key = f.read()
        print("✅ AES Key Loaded from file")
        return aes_key
    
    # Generate new key
    print("🔑 Generating new AES-256 Key...")
    aes_key = os.urandom(32)
    
    with open(AES_KEY_FILE, 'wb') as f:
        f.write(aes_key)
    
    print("✅ AES Key Generated and saved to /keys/")
    return aes_key


# Load or generate keys
PRIVATE_KEY, PUBLIC_KEY = load_or_generate_rsa_keys()
AES_KEY = load_or_generate_aes_key()

# JWT Configuration
JWT_SECRET = "secure_license_system_jwt_secret_key_2024"  # Fixed secret for persistence
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24

# OTP Configuration  
OTP_LENGTH = 6
OTP_EXPIRY_MINUTES = 5

# Access Control Matrix (RBAC)
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
