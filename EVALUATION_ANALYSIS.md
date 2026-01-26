# SecureLicenseSystem - Lab Evaluation 1 Analysis
## Foundations of Cyber Security (23CSE313)

---

## EXECUTIVE SUMMARY - MARKS BREAKDOWN

| Component | Sub-Component | Expected | Implemented | Status | Marks |
|-----------|---------------|----------|-------------|--------|-------|
| **1. Authentication** | Single-Factor (Password) | 1.5m | ✅ Full | Complete | **1.5m** |
| | Multi-Factor (OTP) | 1.5m | ✅ Full | Complete | **1.5m** |
| **2. Authorization & Access Control** | Policy Definition & Justification | 1.5m | ✅ Full | Complete | **1.5m** |
| | Implementation (ACM with 3 subjects, 3 objects) | 1.5m | ✅ Full | Complete | **1.5m** |
| **3. Encryption** | Key Exchange Mechanism | 1.5m | ✅ Partial | RSA-2048 only, no DH/ECDH | **1.2m** |
| | Encryption & Decryption (AES-256) | 1.5m | ✅ Full | Complete | **1.5m** |
| **4. Hashing & Digital Signature** | Hashing with Salt (PBKDF2) | 1.5m | ✅ Full | Complete | **1.5m** |
| | Digital Signature using Hash | 1.5m | ✅ Full | Complete | **1.5m** |
| **5. Encoding Techniques** | Encoding/Decoding (Base64) | 1m | ✅ Full | Complete | **1m** |
| | Security Levels & Risks (Theory) | 1m | ✅ Full | Complete | **1m** |
| | Possible Attacks (Theory) | 1m | ✅ Full | Complete | **1m** |
| **6. Viva & Participation** | *Not yet evaluated - depends on oral exam* |
| **TOTAL EXPECTED MARKS (Practical)** | | **15m** | | | **~14.7m** |

---

## DETAILED RUBRIC ANALYSIS

### 1️⃣ AUTHENTICATION (3 marks total)

#### ✅ Single-Factor Authentication (1.5 marks) - **FULL MARKS**

**Requirement**: Password/PIN/username-based login  
**Your Implementation**:
- **File**: [backend/routes/auth.py](backend/routes/auth.py#L70-L107)
- **What you have**:
  - Username & password registration with strong password policy
  - Password validation: min 8 chars, uppercase, lowercase, special character
  - PBKDF2-HMAC-SHA256 hashing with 16-byte random salt
  - Secure password verification using constant-time comparison

**Code Flow**:
```
User Signup → Validate Password Policy → PBKDF2 Hash with Salt → Store in DB
User Login → Fetch User → Verify Password → On Success → Generate OTP
```

**Module Used**: 
- `hash_password()` & `verify_password()` in [utils/crypto.py](backend/utils/crypto.py#L27-L68)
- Database: SQLite with parameterized queries (SQL injection prevention)

**Tool**: Python `hashlib.pbkdf2_hmac` with 100,000 iterations

#### ✅ Multi-Factor Authentication (1.5 marks) - **FULL MARKS**

**Requirement**: At least two factors (e.g., password + OTP, password + email code)  
**Your Implementation**:
- **File**: [backend/routes/auth.py](backend/routes/auth.py#L115-L170)
- **What you have**:
  - Factor 1: Password (knowledge-based)
  - Factor 2: 6-digit OTP (possession-based)
  - OTP valid for 5 minutes only
  - OTP invalidated after single use (anti-replay)

**MFA Flow**:
```
POST /auth/login (username + password)
  ↓
[Password verified? No → Return error]
  ↓ Yes
[Generate 6-digit OTP via os.urandom] → Store in DB with 5-min expiry
  ↓
Send OTP to console (simulated SMS/Email)
  ↓
User submits: POST /auth/verify-otp (username + otp)
  ↓
[OTP valid & not expired & not used?]
  ↓ Yes
[Issue JWT token with user role] → Store in localStorage
  ↓
Redirect to dashboard
```

**Module Used**: 
- `generate_otp()` in [utils/otp.py](backend/utils/otp.py#L18-L37)
- OTP storage in SQLite `otp_codes` table with expiry timestamp
- JWT creation in [utils/access_control.py](backend/utils/access_control.py#L45-L72)

**Security Features**:
- Cryptographically secure PRNG (os.urandom)
- Time-based expiry in database
- Single-use enforcement via `is_used` flag
- JWT token signed with HS256

---

### 2️⃣ AUTHORIZATION - ACCESS CONTROL (3 marks total)

#### ✅ Policy Definition & Justification (1.5 marks) - **FULL MARKS**

**Requirement**: Clearly define and justify access rights (who can access what and why)  
**Your Implementation**:
- **File**: [SECURITY.md](SECURITY.md#L76-L90) + [backend/utils/access_control.py](backend/utils/access_control.py#L1-L30)
- **Access Control Matrix**:

| Role | generate_license | validate_license | view_users |
|------|-----------------|------------------|------------|
| Admin | ✅ | ✅ | ✅ |
| User | ❌ | ✅ | ❌ |
| Guest | ❌ | ✅ | ❌ |

**Justification Provided**:
- **Admin**: System administrators need full control to issue licenses and manage users
- **User**: Regular authenticated users only validate licenses (least privilege)
- **Guest**: Minimal access for unauthenticated validation only
- **Principle Applied**: Least Privilege - users get minimum required access

#### ✅ Implementation of Access Control (1.5 marks) - **FULL MARKS**

**Requirement**: Implement ACL/ACM with minimum 3 subjects and 3 objects  
**Your Implementation**:
- **Subjects (Roles)**: 3
  - admin
  - user
  - guest

- **Objects (Resources)**: 3+
  - generate_license
  - validate_license
  - view_users

- **Code Implementation**:
  - [config.py](backend/config.py) - ACCESS_CONTROL_MATRIX definition
  - [utils/access_control.py](backend/utils/access_control.py#L105-L120) - `check_permission()` function
  - Decorator: `@require_role('generate_license')` enforces at route level

**Enforcement Flow**:
```
User Request with JWT Token
  ↓
Extract role from JWT
  ↓
@require_role decorator checks: role in ACCESS_CONTROL_MATRIX?
  ↓
Check: ACCESS_CONTROL_MATRIX[role]['resource'] = True/False?
  ↓
If True → Allow access to route
If False → Return 403 Forbidden with message
```

**Routes Protected**:
- POST /generate_license → `@require_role('generate_license')` → Admin only
- POST /validate_license → `@require_role('validate_license')` → All authenticated users
- GET /users → `@require_role('view_users')` → Admin only

---

### 3️⃣ ENCRYPTION (3 marks total)

#### ⚠️ Key Exchange Mechanism (1.5 marks) - **PARTIAL MARKS (1.2m)**

**Requirement**: Demonstrate secure key generation or key exchange method  
**Your Implementation**:
- **File**: [backend/config.py](backend/config.py)
- **What you have**:
  - RSA-2048 key pair generated for digital signatures
  - AES-256 symmetric key generated
  - Both keys pre-generated and stored in config

**Gap**:
- ❌ Missing: Actual key exchange protocol
  - No Diffie-Hellman (DH)
  - No Elliptic Curve Diffie-Hellman (ECDH)
  - No TLS/SSL key negotiation
- Keys are hardcoded in config (acceptable for lab demo)

**Recommendation to get full marks**:
Add a `/key-exchange` endpoint using DH or ECDH to demonstrate key negotiation

**Current Implementation**:
```python
# RSA-2048 for digital signatures
PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
PUBLIC_KEY = PRIVATE_KEY.public_key()

# AES-256 for symmetric encryption
AES_KEY = os.urandom(32)  # 256 bits
```

#### ✅ Encryption & Decryption (1.5 marks) - **FULL MARKS**

**Requirement**: Implement secure encryption/decryption (AES, RSA, hybrid)  
**Your Implementation**:
- **Algorithm**: AES-256-CBC (symmetric encryption)
- **Mode**: CBC with random IV per encryption
- **Padding**: PKCS7

**Encryption Flow for License Token**:
```
License Data (JSON)
  ↓
[Encrypt with AES-256-CBC]
  ↓ (uses random IV)
Encrypted blob + IV
  ↓
[Sign with RSA-2048 PSS]
  ↓
Signature + IV + Encrypted blob
  ↓
[Encode with Base64]
  ↓
License Token (transmissible)
```

**Code Files**:
- Encryption: `encrypt_data()` in [utils/crypto.py](backend/utils/crypto.py#L72-L105)
- Decryption: `decrypt_data()` in [utils/crypto.py](backend/utils/crypto.py#L108-L128)
- Token creation: `create_license_token()` in [utils/crypto.py](backend/utils/crypto.py#L235-L262)
- Token validation: `validate_license_token()` in [utils/crypto.py](backend/utils/crypto.py#L265+)

**Security Features**:
- Random IV per encryption (prevents pattern analysis)
- PKCS7 padding (handles arbitrary lengths)
- 256-bit key (2^256 combinations - unbreakable with current tech)

---

### 4️⃣ HASHING & DIGITAL SIGNATURE (3 marks total)

#### ✅ Hashing with Salt (1.5 marks) - **FULL MARKS**

**Requirement**: Secure storage of passwords/data using hashing along with salt  
**Your Implementation**:
- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: 100,000 (makes brute-force expensive)
- **Salt**: 16 bytes (128-bit) random per password
- **File**: [utils/crypto.py](backend/utils/crypto.py#L27-L68)

**Hashing Flow**:
```
User Password: "MySecurePass123!"
  ↓
[Generate random 16-byte salt]
  ↓
[Apply PBKDF2-SHA256 with 100k iterations]
  ↓
Stored in DB: 
  password_hash = "f3d2e1a9..." (hex)
  salt = "a7b8c9d0..." (hex)
  ↓
Verification: hash(stored_salt + input_password) == stored_hash?
```

**Security Against Attacks**:
- **Brute Force**: 100,000 iterations × ~1ms per iteration = 100s per guess
- **Rainbow Tables**: Random salt = unique hash even for same password
- **Dictionary Attack**: High iteration count defeats pre-computed tables

#### ✅ Digital Signature using Hash (1.5 marks) - **FULL MARKS**

**Requirement**: Demonstrate data integrity and authenticity using hash-based digital signatures  
**Your Implementation**:
- **Algorithm**: RSA-2048 with PSS padding
- **Hash**: SHA-256
- **Files**: [utils/crypto.py](backend/utils/crypto.py#L131-L181)

**Digital Signature Flow**:
```
License Data (JSON serialized to bytes)
  ↓
[Hash with SHA-256]
  ↓
[Sign hash with RSA Private Key (PSS)]
  ↓
Signature stored with token
  ↓
On Verification:
  Extract data from token
    ↓
  Compute hash of data
    ↓
  Verify signature with RSA Public Key
    ↓
  If signature is valid → Data is authentic & unaltered
  If signature is invalid → Data has been tampered!
```

**Security Guarantees**:
- **Authenticity**: Only holder of private key can create valid signature
- **Integrity**: Any modification to data invalidates signature
- **Non-repudiation**: Signer cannot deny creating the signature
- **RSA-PSS vs PKCS#1v1.5**: PSS is randomized (more secure)

**Code Example**:
```python
def sign_data(data: bytes) -> bytes:
    signature = PRIVATE_KEY.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature
```

---

### 5️⃣ ENCODING TECHNIQUES (3 marks total)

#### ✅ Encoding & Decoding Implementation (1 mark) - **FULL MARKS**

**Requirement**: Implement encoding/decoding using Base64, QR Code, Barcode, or CodeChef  
**Your Implementation**:
- **Technique**: Base64 encoding
- **File**: [utils/crypto.py](backend/utils/crypto.py#L235-L262)
- **Usage**: Convert IV + Signature + Encrypted blob to Base64 for transmission

**Encoding Flow**:
```
Binary Data (IV + Signature + Encrypted blob)
  ↓
[Base64 encode]
  ↓
License Token (ASCII-safe, URL-safe)
  ↓
On Decoding:
  Base64 Token
    ↓
  [Base64 decode]
    ↓
  Extract: IV, Signature, Encrypted blob
    ↓
  Verify signature & decrypt
```

**Example Token**:
```
Qy7DhJ3xK9nL2pQ8m4sR1vW6...xYzA5bC9dE3fG2hI1jK0
```

#### ✅ Security Levels & Risks (Theory) (1 mark) - **FULL MARKS**

**Requirement**: Document security levels and explain risks  
**Your Implementation**:
- **File**: [SECURITY.md](SECURITY.md#L8-L42)

**Documented Levels**:
| Technique | Purpose | Reversible | Security Level |
|-----------|---------|-----------|----------------|
| Base64 | Format conversion | ✅ Yes, by anyone | 🔴 NONE |
| AES-256 | Confidentiality | ✅ Yes, key only | 🟢 HIGH |
| PBKDF2 | Integrity, Passwords | ❌ No, one-way | 🟢 HIGH |

**Risk Documentation**:
- Base64 Encoding: "Provides ZERO security - anyone can decode"
- AES-256 Encryption: "Key compromise exposes all data"
- PBKDF2 Hashing: "Computationally expensive to brute-force"

#### ✅ Possible Attacks (Theory) (1 mark) - **FULL MARKS**

**Requirement**: Document possible attacks and countermeasures  
**Your Implementation**:
- **File**: [SECURITY.md](SECURITY.md#L47-L105)

**Attacks Documented**:

| Attack | Description | Countermeasure | Your Implementation |
|--------|-------------|-----------------|-------------------|
| Brute Force | Try all password combinations | High iteration PBKDF2 | ✅ 100k iterations |
| Rainbow Table | Pre-computed hash lookup | Random salt per password | ✅ 16-byte random salt |
| SQL Injection | Malicious SQL via input | Parameterized queries | ✅ Using `?` placeholders |
| Token Tampering | Modify license data | RSA-PSS signature | ✅ Signature verification on every validation |
| Session Hijacking | Steal JWT token | JWT expiry + HTTPS in prod | ✅ 24h JWT expiry |
| Privilege Escalation | Access higher-level resources | Role-based access control | ✅ @require_role decorator |
| MFA Bypass | Skip second factor | OTP expiry + single-use | ✅ 5min expiry + is_used flag |

---

## PROJECT ARCHITECTURE FLOW DIAGRAM

```
┌─────────────────────────────────────────────────────────────────┐
│                         FRONTEND (React/Next.js)                 │
│                                                                   │
│  ┌────────────────┐  ┌──────────────────┐  ┌──────────────────┐ │
│  │  Login Page    │  │  Signup Page     │  │  Dashboard       │ │
│  │  (Single-Auth) │  │  (Register)      │  │  (Protected)     │ │
│  └────────────────┘  └──────────────────┘  └──────────────────┘ │
│         │                    │                       │            │
│         │                    │                       │            │
│         └────────────────────┼───────────────────────┘            │
│                              │                                    │
└──────────────────────────────┼────────────────────────────────────┘
                               │ HTTP/JSON
                               ↓
┌─────────────────────────────────────────────────────────────────┐
│                  BACKEND API (Flask + Python)                    │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │         AUTHENTICATION ROUTES (/auth/*)                 │    │
│  │                                                         │    │
│  │  POST /auth/register                                   │    │
│  │    → validate_password()                               │    │
│  │    → hash_password(PBKDF2)                             │    │
│  │    → Store in DB                                       │    │
│  │                                                         │    │
│  │  POST /auth/login                                      │    │
│  │    → verify_password()                                 │    │
│  │    → generate_otp()                                    │    │
│  │    → Store OTP in DB (5-min expiry)                    │    │
│  │    → Return: "mfa_required"                            │    │
│  │                                                         │    │
│  │  POST /auth/verify-otp                                 │    │
│  │    → Check OTP (valid, not expired, not used)          │    │
│  │    → Mark OTP as used                                  │    │
│  │    → create_jwt_token(username, role)                  │    │
│  │    → Return: JWT token                                 │    │
│  └─────────────────────────────────────────────────────────┘    │
│                               ↓                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │         AUTHORIZATION LAYER (Access Control)             │    │
│  │                                                         │    │
│  │  @require_auth decorator:                              │    │
│  │    → Extract JWT from Authorization header             │    │
│  │    → Decode JWT (verify HS256 signature)               │    │
│  │    → Get user role from payload                        │    │
│  │    → Set g.current_user                                │    │
│  │                                                         │    │
│  │  @require_role('resource') decorator:                  │    │
│  │    → check_permission(role, resource)                  │    │
│  │    → Lookup ACCESS_CONTROL_MATRIX[role][resource]      │    │
│  │    → Return 403 if denied                              │    │
│  └─────────────────────────────────────────────────────────┘    │
│                               ↓                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │         LICENSE ROUTES (/license/*)                     │    │
│  │                                                         │    │
│  │  POST /generate_license (@require_role('admin'))        │    │
│  │    → create_license_token()                            │    │
│  │      ├─ JSON: {client, timestamp, random}              │    │
│  │      ├─ encrypt_data() [AES-256-CBC + random IV]       │    │
│  │      ├─ sign_data() [RSA-PSS-SHA256]                   │    │
│  │      └─ Base64 encode [IV|Signature|Encrypted]         │    │
│  │    → Save to DB for audit                              │    │
│  │    → Return: license_key                               │    │
│  │                                                         │    │
│  │  POST /validate_license (@require_role('user'))         │    │
│  │    → validate_license_token()                          │    │
│  │      ├─ Base64 decode                                  │    │
│  │      ├─ Extract: IV, Signature, Encrypted              │    │
│  │      ├─ verify_signature() [RSA public key]             │    │
│  │      ├─ decrypt_data() [AES-256-CBC]                   │    │
│  │      └─ Validate JSON structure                        │    │
│  │    → Return: License valid/invalid + details           │    │
│  └─────────────────────────────────────────────────────────┘    │
│                               ↓                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │         SECURITY UTILITIES (/utils/*)                   │    │
│  │                                                         │    │
│  │  crypto.py:                                            │    │
│  │    • hash_password() → PBKDF2-HMAC-SHA256             │    │
│  │    • verify_password()                                 │    │
│  │    • encrypt_data() → AES-256-CBC + random IV          │    │
│  │    • decrypt_data()                                    │    │
│  │    • sign_data() → RSA-PSS-SHA256                       │    │
│  │    • verify_signature()                                │    │
│  │    • create_license_token()                            │    │
│  │    • validate_license_token()                          │    │
│  │                                                         │    │
│  │  otp.py:                                               │    │
│  │    • generate_otp() → 6-digit via os.urandom           │    │
│  │    • send_otp() → Console simulation                   │    │
│  │                                                         │    │
│  │  access_control.py:                                    │    │
│  │    • create_jwt_token() → HS256 signed                 │    │
│  │    • decode_jwt_token()                                │    │
│  │    • check_permission() → ACM lookup                   │    │
│  │    • require_auth decorator                            │    │
│  │    • require_role decorator                            │    │
│  └─────────────────────────────────────────────────────────┘    │
│                               ↓                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │         DATABASE (SQLite)                               │    │
│  │                                                         │    │
│  │  users:                                                │    │
│  │    username (PK), password_hash, salt, role            │    │
│  │                                                         │    │
│  │  otp_codes:                                            │    │
│  │    id (PK), username (FK), otp_code, expires_at,       │    │
│  │    is_used, created_at                                 │    │
│  │                                                         │    │
│  │  licenses:                                             │    │
│  │    id (PK), issued_to, issued_by, token_blob,          │    │
│  │    signature, created_at                               │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

---

## RUBRIC-BY-RUBRIC SATISFACTION MATRIX

| Rubric | Expected Implementation | Your Implementation | Status | Evidence |
|--------|------------------------|--------------------|--------|----------|
| **Single-Factor Auth** | Password login | Username + password with policy validation | ✅ Complete | [auth.py#L70-L107](backend/routes/auth.py#L70-L107) |
| **Multi-Factor Auth** | 2+ factors required | Password + 6-digit OTP (5-min expiry) | ✅ Complete | [auth.py#L115-L170](backend/routes/auth.py#L115-L170), [otp.py](backend/utils/otp.py) |
| **Access Control Policy** | Define who accesses what & why | 3 roles × 3 resources ACM with justification | ✅ Complete | [SECURITY.md#L76-L90](SECURITY.md#L76-L90) |
| **Access Control Implementation** | Enforce ACM in code | @require_role decorator + check_permission() | ✅ Complete | [access_control.py#L105-L140](backend/utils/access_control.py#L105-L140) |
| **Key Exchange** | Secure key generation/exchange | RSA-2048 & AES-256 key generation | ⚠️ Partial | [config.py](backend/config.py) - Missing DH/ECDH |
| **Encryption/Decryption** | AES/RSA/Hybrid encryption | AES-256-CBC + RSA-PSS signatures | ✅ Complete | [crypto.py#L72-L181](backend/utils/crypto.py#L72-L181) |
| **Hashing with Salt** | PBKDF2/Bcrypt with salt | PBKDF2-HMAC-SHA256 × 100k + 16-byte salt | ✅ Complete | [crypto.py#L27-L68](backend/utils/crypto.py#L27-L68) |
| **Digital Signature** | Hash-based signatures | RSA-PSS-SHA256 on license tokens | ✅ Complete | [crypto.py#L131-L181](backend/utils/crypto.py#L131-L181) |
| **Encoding/Decoding** | Base64/QR/Barcode | Base64 for license tokens | ✅ Complete | [crypto.py#L235-L262](backend/utils/crypto.py#L235-L262) |
| **Security Levels (Theory)** | Document encoding vs encryption vs hashing | Table comparing Base64/AES/PBKDF2 | ✅ Complete | [SECURITY.md#L8-L42](SECURITY.md#L8-L42) |
| **Possible Attacks (Theory)** | Document 6+ attacks & countermeasures | 7 attacks documented with mitigations | ✅ Complete | [SECURITY.md#L47-L105](SECURITY.md#L47-L105) |

---

## ESTIMATED MARKS: **14.7 / 20**

### Breakdown:
1. **Authentication**: 3.0 / 3.0 marks ✅
   - Single-Factor: 1.5/1.5
   - Multi-Factor: 1.5/1.5

2. **Authorization**: 3.0 / 3.0 marks ✅
   - Policy: 1.5/1.5
   - Implementation: 1.5/1.5

3. **Encryption**: 2.7 / 3.0 marks ⚠️
   - Key Exchange: 1.2/1.5 (Missing DH/ECDH demonstration)
   - Encryption: 1.5/1.5

4. **Hashing & Signature**: 3.0 / 3.0 marks ✅
   - Hashing with Salt: 1.5/1.5
   - Digital Signature: 1.5/1.5

5. **Encoding**: 3.0 / 3.0 marks ✅
   - Encoding/Decoding: 1.0/1.0
   - Security Levels: 1.0/1.0
   - Possible Attacks: 1.0/1.0

### **Total Practical: 14.7 / 15 marks**

### Not Evaluated Yet:
- **Viva Examination (2m)**: Pending oral examination
- **Class Participation/Assignments (3m)**: Pending evaluation
- **Complete Viva (5m)**: Pending evaluation

---

## HOW TO GET FULL MARKS (15/15)

### Gap: Key Exchange Mechanism (0.3 marks missing)

To get the missing 0.3 marks, implement one of these:

#### Option 1: Diffie-Hellman Key Exchange (Recommended)
```python
# In crypto.py
from cryptography.hazmat.primitives.asymmetric import dh

def dh_key_exchange():
    """Generate DH parameters and keys"""
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    
    # Share public_key, receive peer's public_key
    shared_key = private_key.exchange(peer_public_key)
    # shared_key can now be used as symmetric key
```

#### Option 2: Elliptic Curve Diffie-Hellman (ECDH) - More efficient
```python
from cryptography.hazmat.primitives.asymmetric import ec

def ecdh_key_exchange():
    """Generate ECDH parameters"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    # Exchange with peer
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
```

#### Option 3: Add endpoint to API
```python
@license_bp.route('/dh-key-exchange', methods=['POST'])
def dh_exchange():
    """Demonstrate DH key exchange"""
    # Accept peer's public key
    # Return server's public key
    # Generate shared secret
```

**Implementation Time**: ~30 minutes

---

## VIVA EXAMINATION PREPARATION (Important!)

### Expected Questions (Based on your implementation):

#### 1. **Authentication & MFA** (2-3 questions likely)

**Q1: Explain the MFA flow in your application**
- Answer: Users login with password (factor 1), receive 6-digit OTP via console (factor 2). OTP valid for 5 minutes, single-use only. After OTP verification, JWT token issued.
- Evidence: Point to [auth.py](backend/routes/auth.py#L115-L170)

**Q2: Why did you choose OTP instead of email/SMS/biometric?**
- Answer: OTP is simplest for lab demo. In production, would use Twilio/AWS SNS for SMS (faster), or email (more reliable), or biometric (most secure but harder to implement). OTP demonstrates possession factor well.

**Q3: What is PBKDF2? Why 100,000 iterations?**
- Answer: PBKDF2 = Password-Based Key Derivation Function. It applies hash function repeatedly (100k times). Each iteration adds ~1ms delay, so 1 billion combinations would take ~11 days of computation, making brute-force infeasible. Without iterations, attacker could try 10 billion/second.

**Q4: What is a salt? Why is it random?**
- Answer: Salt is random bytes mixed with password before hashing. Random salt prevents rainbow table attacks - same password hashes to different values. Attacker must pre-compute tables for every possible salt (impossible).

---

#### 2. **Authorization & Access Control** (2-3 questions likely)

**Q5: Describe your Access Control Matrix**
- Answer: 3 roles (admin, user, guest) × 3 resources (generate_license, validate_license, view_users). Admin has all permissions. User can only validate. Guest can only validate. Justification: Least Privilege principle.
- Evidence: [SECURITY.md table](SECURITY.md#L76-L90)

**Q6: How do you enforce access control in code?**
- Answer: @require_role decorator on each route. On request, decorator extracts JWT role and checks ACCESS_CONTROL_MATRIX. If denied, returns 403. Prevents unauthorized access.
- Evidence: [access_control.py#L117-L140](backend/utils/access_control.py#L117-L140)

**Q7: Can a user escalate their privileges to admin?**
- Answer: No, because:
  1. Role is set server-side in JWT creation, not from user input
  2. JWT is signed with HS256, cannot be forged
  3. Role is hardcoded as 'user' in registration endpoint
  4. @require_role checks access before route execution

---

#### 3. **Encryption** (2-3 questions likely)

**Q8: Explain your encryption scheme for license tokens**
- Answer: License data (JSON) is encrypted using AES-256-CBC with random IV. Then encrypted blob is signed with RSA-PSS-SHA256. Both IV and signature are Base64 encoded together with encrypted blob. Result is license token.
- Evidence: [crypto.py#L235-L262](backend/utils/crypto.py#L235-L262)

**Q9: Why use both AES (symmetric) and RSA (asymmetric)?**
- Answer: AES is fast for encrypting large data. RSA is slow but provides digital signatures for authenticity. Hybrid approach: encrypt with AES for performance, sign with RSA for integrity. This is industry standard.

**Q10: What is the advantage of random IV in CBC mode?**
- Answer: Same plaintext encrypted twice with same key but different IVs produces different ciphertexts. Prevents pattern analysis attacks. Attacker cannot recognize repeated data.

**Q11: Explain RSA-PSS vs PKCS#1v1.5 for signatures**
- Answer: PSS is probabilistic - same signature is never exactly same twice, even for same data. PKCS#1v1.5 is deterministic - signature is same every time. PSS is more secure against adaptive chosen ciphertext attacks.

---

#### 4. **Hashing & Digital Signature** (1-2 questions likely)

**Q12: What is the difference between hashing and encryption?**
- Answer: 
  - Hashing: One-way function. Hash("password") → "a7f3d1e2...". Cannot reverse. Used for password storage.
  - Encryption: Reversible. Encrypt("data", key) → "k9x2q..." Can decrypt with key. Used for confidentiality.

**Q13: Explain the license validation process**
- Answer: Token is Base64 decoded into IV, signature, and ciphertext. Signature is verified with RSA public key - if valid, data is authentic. Ciphertext is decrypted with AES-256 using IV. Decrypted JSON is parsed. If any step fails, license is invalid.

**Q14: Can an attacker modify the license without detection?**
- Answer: No, because any modification to encrypted data will fail RSA signature verification. Signature proves authenticity and integrity. Attacker cannot forge signature without private key.

---

#### 5. **Encoding** (1 question likely)

**Q15: Why use Base64 encoding if it provides no security?**
- Answer: Base64 is not for security, it's for encoding. Makes binary data transmissible as text via HTTP/JSON. Receiver can decode and process. In combination with encryption, it's safe (encode the ciphertext, not plaintext).

---

#### 6. **Security Concepts** (1-2 questions likely)

**Q16: What are the 7 attacks you identified and your countermeasures?**
- Answer:
  1. **Brute Force** → PBKDF2 100k iterations (expensive)
  2. **Rainbow Table** → Random salt per password
  3. **SQL Injection** → Parameterized queries
  4. **Token Tampering** → RSA-PSS signature verification
  5. **Session Hijacking** → JWT expiry (24h)
  6. **Privilege Escalation** → RBAC @require_role
  7. **MFA Bypass** → OTP expiry + single-use flag

**Q17: Explain NIST SP 800-63-2 E-Authentication**
- Answer: NIST standard for e-authentication. Your app follows it:
  1. Registration: Username/password
  2. Password Storage: PBKDF2 (not plaintext)
  3. MFA: Password + OTP
  4. Session: JWT with signature
  5. Access Control: Role-based with least privilege

---

### Viva Tips:

✅ **DO THIS**:
- Run the app and demonstrate the full flow (signup → login → OTP → generate license → validate)
- Show the code files on screen (GitHub repo)
- Explain WHY you chose each algorithm
- Know all 7 attacks and countermeasures by heart
- Draw the data flow diagram during viva
- Discuss security trade-offs (performance vs security)

❌ **DON'T DO THIS**:
- Memorize code line-by-line (it's boring)
- Say "I copied from GitHub" (be honest but brief)
- Claim features not implemented
- Panic if asked tough question (say "Let me think about it")

---

## QUICK REFERENCE FOR VIVA

### Key Facts to Remember:

| Topic | Your Implementation |
|-------|-------------------|
| **Password Hashing** | PBKDF2-HMAC-SHA256, 100k iterations, 16-byte random salt |
| **Symmetric Encryption** | AES-256-CBC with random IV per encryption, PKCS7 padding |
| **Asymmetric Signature** | RSA-2048 with PSS padding, SHA-256 hash |
| **MFA Implementation** | Password + 6-digit OTP, 5-min expiry, single-use, anti-replay |
| **Access Control** | RBAC with 3 roles × 3 resources, @require_role decorator |
| **Encoding** | Base64 for license token transmission |
| **Token Format** | Base64(IV + Signature + AES-Ciphertext) |
| **JWT Signing** | HS256 with 24-hour expiry |
| **Attacks Covered** | 7 attacks with documented countermeasures |
| **Gap** | Missing DH/ECDH key exchange (0.3m lost) |

---

## FINAL RECOMMENDATION

Your project demonstrates strong understanding of security concepts. The implementation is clean, well-documented, and comprehensive. You will likely score **14.7-16/20** on practical evaluation.

### To Get Full Marks:
1. **Implement DH or ECDH** for key exchange (~30 mins) → +0.3m
2. **Prepare viva thoroughly** using the Q&A above → +2-5m (viva marks)
3. **Demonstrate the app** running and all features working → +1m (participation)

**Total Potential: 20/20** ✅

---

**Generated**: January 26, 2026
**Evaluated By**: GitHub Copilot
**Status**: Ready for Viva Preparation
