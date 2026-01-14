"""
Cryptographic Utilities for SecureLicenseSystem

This module handles:
- Password hashing with PBKDF2-SHA256 + salt
- AES-256-CBC encryption/decryption
- RSA-PSS digital signatures

Security Notes:
- PBKDF2 uses 100,000 iterations to resist brute-force attacks
- Salt is 16 bytes (128-bit) random per password
- AES uses CBC mode with random IV per encryption
- RSA-PSS is preferred over PKCS#1v1.5 for signatures
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


# =============================================================================
# PASSWORD HASHING
# =============================================================================

def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
    """
    Hash a password using PBKDF2-HMAC-SHA256 with salt.
    
    Args:
        password: The plaintext password
        salt: Optional salt bytes. If None, generates random 16 bytes.
    
    Returns:
        Tuple of (password_hash_hex, salt_hex)
    
    Security:
        - PBKDF2 with 100k iterations makes brute-force expensive
        - Random salt prevents rainbow table attacks
        - Each password gets unique salt
    """
    if salt is None:
        salt = os.urandom(16)
    
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000  # Iterations - higher = more secure but slower
    )
    
    return password_hash.hex(), salt.hex()


def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    """
    Verify a password against stored hash and salt.
    
    Args:
        password: The plaintext password to verify
        stored_hash: The hex-encoded stored hash
        stored_salt: The hex-encoded stored salt
    
    Returns:
        True if password matches, False otherwise
    """
    salt = bytes.fromhex(stored_salt)
    computed_hash, _ = hash_password(password, salt)
    return computed_hash == stored_hash


# =============================================================================
# AES ENCRYPTION
# =============================================================================

def encrypt_data(data: dict) -> tuple[bytes, bytes]:
    """
    Encrypt data using AES-256-CBC.
    
    Args:
        data: Dictionary to encrypt (will be JSON serialized)
    
    Returns:
        Tuple of (iv, encrypted_blob)
    
    Security:
        - AES-256 provides strong symmetric encryption
        - Random IV ensures same data encrypts differently each time
        - PKCS7 padding handles arbitrary data lengths
    """
    payload = json.dumps(data).encode('utf-8')
    
    # Generate random Initialization Vector
    iv = os.urandom(16)
    
    # Create cipher with AES-256 in CBC mode
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Pad data to block size (128 bits for AES)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(payload) + padder.finalize()
    
    # Encrypt
    encrypted_blob = encryptor.update(padded_data) + encryptor.finalize()
    
    return iv, encrypted_blob


def decrypt_data(iv: bytes, encrypted_blob: bytes) -> dict:
    """
    Decrypt AES-256-CBC encrypted data.
    
    Args:
        iv: Initialization Vector used during encryption
        encrypted_blob: The encrypted data
    
    Returns:
        Decrypted data as dictionary
    """
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    # Decrypt
    padded_data = decryptor.update(encrypted_blob) + decryptor.finalize()
    
    # Unpad
    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return json.loads(data.decode('utf-8'))


# =============================================================================
# RSA DIGITAL SIGNATURES
# =============================================================================

def sign_data(data: bytes) -> bytes:
    """
    Create RSA-PSS digital signature for data.
    
    Args:
        data: The data to sign
    
    Returns:
        The signature bytes
    
    Security:
        - RSA-PSS is probabilistic, more secure than PKCS#1v1.5
        - SHA-256 hash ensures any data change invalidates signature
        - Only holder of private key can create valid signatures
    """
    signature = PRIVATE_KEY.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(data: bytes, signature: bytes) -> bool:
    """
    Verify RSA-PSS digital signature.
    
    Args:
        data: The original data
        signature: The signature to verify
    
    Returns:
        True if signature is valid, False otherwise
    """
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


# =============================================================================
# LICENSE TOKEN OPERATIONS
# =============================================================================

def create_license_token(client_name: str) -> str:
    """
    Create a complete license token with encryption, signature, and encoding.
    
    Process:
    1. Create payload with client info
    2. Encrypt with AES-256
    3. Sign encrypted blob with RSA
    4. Encode everything with Base64
    
    Token format: Base64(IV + Signature + EncryptedBlob)
    """
    # Create payload
    payload = {"client": client_name, "valid": True}
    
    # Encrypt
    iv, encrypted_blob = encrypt_data(payload)
    
    # Sign the encrypted blob
    signature = sign_data(encrypted_blob)
    
    # Combine and encode
    # Format: IV (16 bytes) + Signature (256 bytes for RSA-2048) + Encrypted data
    combined = iv + signature + encrypted_blob
    token = base64.b64encode(combined).decode('utf-8')
    
    return token


def validate_license_token(token: str) -> tuple[bool, str]:
    """
    Validate a license token.
    
    Process:
    1. Decode from Base64
    2. Extract IV, signature, and encrypted blob
    3. Verify RSA signature
    4. Optionally decrypt to get client info
    
    Returns:
        Tuple of (is_valid, message)
    """
    try:
        # Decode
        raw = base64.b64decode(token)
        
        # Extract components
        iv = raw[:16]
        signature = raw[16:272]  # RSA-2048 signature is 256 bytes
        encrypted_blob = raw[272:]
        
        # Verify signature
        if not verify_signature(encrypted_blob, signature):
            return False, "Invalid signature - data may have been tampered"
        
        # Decrypt to verify structure
        data = decrypt_data(iv, encrypted_blob)
        
        return True, f"Valid license for: {data.get('client', 'Unknown')}"
    
    except Exception as e:
        return False, f"Validation failed: {str(e)}"
