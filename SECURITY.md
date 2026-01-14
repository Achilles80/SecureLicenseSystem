# SecureLicenseSystem - Security Documentation

## Overview

This document covers the security concepts implemented in this application, providing theoretical knowledge for viva examination.

---

## 1. Security Levels: Encoding vs Encryption vs Hashing

| Technique | Purpose | Reversible? | Security Level |
|-----------|---------|-------------|----------------|
| **Encoding (Base64)** | Data format conversion | ✅ Yes, by anyone | 🔴 NONE - Not security! |
| **Encryption (AES-256)** | Confidentiality | ✅ Yes, with key only | 🟢 HIGH |
| **Hashing (PBKDF2)** | Integrity, Password storage | ❌ No, one-way | 🟢 HIGH |

### Base64 Encoding (Used for license tokens)
- **Purpose**: Convert binary data to text for transmission
- **Risk**: Provides ZERO security - anyone can decode
- **Used in our app**: To make the license token URL-safe

### AES-256-CBC Encryption (Used for license payload)
- **Purpose**: Protect data confidentiality
- **Key size**: 256 bits (extremely strong)
- **Mode**: CBC with random IV per encryption
- **Risk**: Key compromise exposes all data

### PBKDF2-HMAC-SHA256 Hashing (Used for passwords)
- **Purpose**: Securely store passwords
- **Iterations**: 100,000 (makes brute-force slow)
- **Salt**: 16 bytes random per password

---

## 2. Possible Attacks & Countermeasures

### Attack: Brute Force Attack
**Description**: Trying all possible password combinations
**Countermeasure in this app**:
- PBKDF2 with 100,000 iterations (each guess takes ~100ms)
- Rate limiting could be added in production

### Attack: Rainbow Table Attack
**Description**: Pre-computed hash tables for password lookup
**Countermeasure in this app**:
- Random salt per password
- Each password has unique hash even if passwords are same

### Attack: SQL Injection
**Description**: Malicious SQL queries injected through inputs
**Countermeasure in this app**:
- Parameterized queries using `?` placeholders
- No string concatenation in SQL

### Attack: Token Tampering
**Description**: Modifying license data to bypass validation
**Countermeasure in this app**:
- RSA-PSS digital signature
- Any modification invalidates the signature

### Attack: Session Hijacking
**Description**: Stealing user session/token
**Countermeasure in this app**:
- JWT with expiry (24 hours)
- Token stored in localStorage (could use httpOnly cookies for better security)

### Attack: Privilege Escalation
**Description**: User accessing higher-level resources
**Countermeasure in this app**:
- Role-Based Access Control (RBAC)
- Access Control Matrix checked on every request

### Attack: MFA Bypass
**Description**: Skipping the second factor
**Countermeasure in this app**:
- OTP stored in database with expiry
- OTP invalidated after single use

---

## 3. NIST SP 800-63-2 Compliance

Our E-Authentication follows NIST guidelines:

1. **Registration**: Users create accounts with username/password
2. **Password Storage**: PBKDF2 with salt (not plaintext)
3. **Multi-Factor Auth**: Password (knowledge) + OTP (possession)
4. **Session Tokens**: JWT with cryptographic signature
5. **Access Control**: Role-based with least privilege

---

## 4. Access Control Matrix Justification

| Role | Generate License | Validate License | View Users |
|------|-----------------|------------------|------------|
| Admin | ✅ | ✅ | ✅ |
| User | ❌ | ✅ | ❌ |
| Guest | ❌ | ✅ | ❌ |

**Justification**:
- **Admin**: System administrators need full control
- **User**: Regular users only need to validate their licenses
- **Guest**: Minimal access for unauthenticated users

**Principle applied**: Least Privilege - users get minimum required access

---

## 5. Cryptographic Component Summary

```
┌─────────────────────────────────────────────────────────────┐
│                    SECURE LICENSE SYSTEM                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  PASSWORD STORAGE                                           │
│  ├── PBKDF2-HMAC-SHA256                                    │
│  ├── 100,000 iterations                                    │
│  └── 16-byte random salt per password                      │
│                                                             │
│  LICENSE ENCRYPTION                                         │
│  ├── AES-256-CBC                                           │
│  ├── Random IV per encryption                              │
│  └── PKCS7 padding                                         │
│                                                             │
│  LICENSE SIGNING                                            │
│  ├── RSA-2048 key pair                                     │
│  ├── RSA-PSS signature scheme                              │
│  └── SHA-256 hash algorithm                                │
│                                                             │
│  TOKEN ENCODING                                             │
│  └── Base64 (IV + Signature + Encrypted Data)              │
│                                                             │
│  AUTHENTICATION                                             │
│  ├── Single Factor: Password                               │
│  ├── Multi Factor: OTP (6 digits, 5-min expiry)           │
│  └── Session: JWT with HS256 signature                     │
│                                                             │
│  AUTHORIZATION                                              │
│  ├── Role-Based Access Control (RBAC)                      │
│  ├── 3 Roles: Admin, User, Guest                           │
│  └── 3 Resources: generate, validate, view_users           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. Demo Script for Evaluation

### Step 1: Show Registration (Single-Factor Setup)
```
1. Go to http://localhost:3000
2. Click "Need an account? Register"
3. Enter username: testuser, password: test123
4. Select role: User
5. Click CREATE ACCOUNT
```

### Step 2: Show Login with MFA
```
1. Login with testuser / test123
2. Show OTP appearing in server console
3. Enter OTP in the modal
4. Show JWT token in browser localStorage
```

### Step 3: Show Access Control
```
1. As 'user' role, try to generate license → Shows "Access Denied"
2. View Access Control Matrix displayed on dashboard
3. Login as 'admin' → Can generate licenses
4. Show View Users button (admin only)
```

### Step 4: Show Encryption & Signatures
```
1. Generate license for "TestClient"
2. Copy the Base64 token
3. Go to /validate page
4. Paste and verify → Shows "VALID"
5. Click "Tamper" button to modify token
6. Verify again → Shows "TAMPERING DETECTED"
```
