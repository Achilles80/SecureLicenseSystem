"""
Cryptographic Utilities for SecureLicenseSystem.

Provides:
- Password hashing (PBKDF2-SHA256 with salt, 100k iterations)
- AES-256-CBC encryption/decryption
- RSA-PSS digital signatures
- License token creation and validation
"""

import hashlib
import os
import base64
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

from config import PRIVATE_KEY, PUBLIC_KEY, AES_KEY


# Password Hashing (PBKDF2-HMAC-SHA256)

def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
    """
    Hash password with PBKDF2. Returns (hash_hex, salt_hex).
    Uses 100k iterations to resist brute-force attacks.
    """
    if salt is None:
        salt = os.urandom(16)
    
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return password_hash.hex(), salt.hex()


def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    """Verify password against stored hash and salt."""
    salt = bytes.fromhex(stored_salt)
    computed_hash, _ = hash_password(password, salt)
    return computed_hash == stored_hash


# AES-256-CBC Encryption

def encrypt_data(data: dict) -> tuple[bytes, bytes]:
    """
    Encrypt dictionary with AES-256-CBC. Returns (iv, ciphertext).
    Random IV ensures same data encrypts differently each time.
    """
    payload = json.dumps(data).encode('utf-8')
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(payload) + padder.finalize()
    
    encrypted_blob = encryptor.update(padded_data) + encryptor.finalize()
    return iv, encrypted_blob


def decrypt_data(iv: bytes, encrypted_blob: bytes) -> dict:
    """Decrypt AES-256-CBC data back to dictionary."""
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(encrypted_blob) + decryptor.finalize()
    
    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return json.loads(data.decode('utf-8'))


# RSA-PSS Digital Signatures

def sign_data(data: bytes) -> bytes:
    """Create RSA-PSS signature. Only private key holder can sign."""
    return PRIVATE_KEY.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_signature(data: bytes, signature: bytes) -> bool:
    """Verify RSA-PSS signature. Returns True if valid."""
    try:
        PUBLIC_KEY.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# License Token Operations

def create_license_token(client_name: str) -> str:
    """
    Create complete license token.
    Process: Encrypt payload → Sign ciphertext → Base64 encode
    Format: Base64(IV[16] + Signature[256] + Ciphertext)
    """
    payload = {"client": client_name, "valid": True}
    iv, encrypted_blob = encrypt_data(payload)
    signature = sign_data(encrypted_blob)
    
    combined = iv + signature + encrypted_blob
    return base64.b64encode(combined).decode('utf-8')


def validate_license_token(token: str) -> tuple[bool, str]:
    """
    Validate license token.
    Process: Base64 decode → Verify signature → Decrypt payload
    Returns: (is_valid, message)
    """
    try:
        raw = base64.b64decode(token)
        
        iv = raw[:16]
        signature = raw[16:272]  # RSA-2048 = 256 bytes
        encrypted_blob = raw[272:]
        
        if not verify_signature(encrypted_blob, signature):
            return False, "Invalid signature - data may have been tampered"
        
        data = decrypt_data(iv, encrypted_blob)
        return True, f"Valid license for: {data.get('client', 'Unknown')}"
    
    except Exception as e:
        return False, f"Validation failed: {str(e)}"
