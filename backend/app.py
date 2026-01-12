from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import os
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

app = Flask(__name__)
CORS(app)  # Enables frontend to talk to backend

# 1. GENERATE KEYS (In memory for this lab)
print("Generating RSA Keys... (This may take a second)")
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
AES_KEY = os.urandom(32) # 256-bit AES Key

# 2. DATABASE SETUP
def init_db():
    conn = sqlite3.connect('secure_storage.db')
    c = conn.cursor()
    # Create tables if they don't exist
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (username TEXT PRIMARY KEY, password_hash TEXT, salt TEXT, role TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS licenses 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, issued_to TEXT, token_blob TEXT, signature TEXT)''')
    conn.commit()
    conn.close()

init_db() # Run once on startup

# ================= ROUTES =================

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    conn = sqlite3.connect('secure_storage.db')
    c = conn.cursor()
    c.execute("SELECT password_hash, salt, role FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()

    if user:
        stored_hash, stored_salt, role = user
        # Re-hash input to verify
        input_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(stored_salt), 100000).hex()
        
        if input_hash == stored_hash:
            return jsonify({"message": "Success", "role": role, "mfa_required": True, "debug_otp": "1234"}), 200

    return jsonify({"error": "Invalid Credentials"}), 401

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')

    # Salt & Hash
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

    try:
        conn = sqlite3.connect('secure_storage.db')
        c = conn.cursor()
        c.execute("INSERT INTO users VALUES (?, ?, ?, ?)", (username, pwd_hash.hex(), salt.hex(), role))
        conn.commit()
        conn.close()
        return jsonify({"message": "User registered"}), 201
    except:
        return jsonify({"error": "User exists"}), 400

@app.route('/generate_license', methods=['POST'])
def generate_license():
    data = request.json
    client_name = data.get('client_name')

    # 1. Encrypt Data (AES)
    payload = json.dumps({"client": client_name, "valid": True})
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(payload.encode()) + padder.finalize()
    encrypted_blob = encryptor.update(padded_data) + encryptor.finalize()

    # 2. Sign Data (RSA)
    signature = private_key.sign(
        encrypted_blob,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    # 3. Encode (Base64)
    token = base64.b64encode(iv + signature + encrypted_blob).decode('utf-8')
    
    return jsonify({"license_key": token})

@app.route('/validate_license', methods=['POST'])
def validate_license():
    token = request.json.get('license_key')
    try:
        raw = base64.b64decode(token)
        iv = raw[:16]
        signature = raw[16:272]
        encrypted_blob = raw[272:]

        # Verify Signature
        public_key.verify(
            signature,
            encrypted_blob,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return jsonify({"valid": True, "message": "Signature Verified & Data Decrypted"})
    except:
        return jsonify({"valid": False, "error": "Tampering Detected"}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)