Roll No: CB.SC.U4CSE23102
23CSE313: Foundations of CyberSecurity Lab Evaluation-1
# 🔐 SecureLicenseSystem

A comprehensive demonstration of cybersecurity concepts including encryption, digital signatures, multi-factor authentication, and role-based access control.

## Features

| Feature | Implementation |
|---------|---------------|
| **Encryption** | AES-256-CBC with random IV |
| **Digital Signatures** | RSA-2048 PSS with SHA-256 |
| **Password Hashing** | PBKDF2-HMAC-SHA256 (100k iterations) |
| **Authentication** | JWT tokens with 24h expiry |
| **MFA** | 6-digit OTP with 5-minute expiry |
| **Access Control** | Role-Based Access Control (RBAC) |
| **Encoding** | Base64 for token transmission |

## Architecture

```
SecureLicenseSystem/
├── backend/                 # Flask API Server
│   ├── app.py              # Entry point
│   ├── config.py           # Keys & settings
│   ├── models.py           # Database operations
│   ├── routes/
│   │   ├── auth.py         # Authentication endpoints
│   │   └── license.py      # License management
│   └── utils/
│       ├── access_control.py  # RBAC & JWT
│       ├── crypto.py          # Encryption & signing
│       └── otp.py             # MFA utilities
│
└── frontend/               # Next.js Web App
    └── app/
        ├── page.tsx        # Login page
        ├── dashboard/      # Main dashboard
        ├── validate/       # Public validator
        ├── signup/         # Registration
        └── reset-password/ # Password reset
```

## Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+

### Backend Setup
```bash
cd backend
pip install -r requirements.txt
python app.py
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000 in your browser.

## Demo Accounts

| Username | Password | Role | Permissions |
|----------|----------|------|-------------|
| `admin` | `admin123` | Admin | Generate + Validate + View Users |
| `user` | `user123` | User | Validate only |
| `guest` | `guest123` | Guest | Validate only |

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Create new user |
| POST | `/auth/login` | Login (sends OTP) |
| POST | `/auth/verify-otp` | Complete MFA |
| POST | `/auth/guest-login` | Guest access (no MFA) |
| POST | `/auth/forgot-password` | Request reset OTP |
| POST | `/auth/reset-password` | Reset with OTP |
| GET | `/auth/me` | Current user info |

### License Management
| Method | Endpoint | Description | Access |
|--------|----------|-------------|--------|
| POST | `/generate_license` | Create license | Admin |
| POST | `/validate_license` | Validate (auth) | All |
| POST | `/validate_public` | Validate (public) | Public |
| GET | `/licenses` | List all licenses | Admin |
| DELETE | `/licenses/<id>` | Delete license | Admin |
| GET | `/my-licenses` | User's licenses | Auth |

### Admin
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/users` | List all users |
| GET | `/audit-logs` | Security logs |
| GET | `/access-control` | View ACM |

## Security Concepts Demonstrated

### 1. Encoding vs Encryption
- **Base64**: Format conversion (NOT security) - anyone can decode
- **AES-256**: Symmetric encryption - data unreadable without key

### 2. Hashing vs Encryption
- **Hashing (PBKDF2)**: One-way, used for passwords
- **Encryption (AES)**: Two-way, used for license data

### 3. Digital Signatures
- **RSA-PSS**: Proves authenticity + integrity
- Any tampering invalidates the signature

### 4. Access Control Matrix

| Role | Generate | Validate | View Users |
|------|----------|----------|------------|
| Admin | ✅ | ✅ | ✅ |
| User | ❌ | ✅ | ❌ |
| Guest | ❌ | ✅ | ❌ |

## 🔒 Attack Countermeasures

| Attack | Countermeasure |
|--------|----------------|
| Brute Force | PBKDF2 with 100k iterations |
| Rainbow Table | Random salt per password |
| SQL Injection | Parameterized queries |
| Token Tampering | RSA digital signature |
| Session Hijacking | JWT with 24h expiry |
| MFA Bypass | OTP with 5-min expiry |
| Privilege Escalation | Role-based access control |

## License Token Format

```
Base64( IV[16 bytes] + Signature[256 bytes] + Ciphertext )
```

1. **IV**: Random initialization vector for AES
2. **Signature**: RSA-PSS signature of ciphertext
3. **Ciphertext**: AES-256-CBC encrypted payload

## Important Notes

- RSA keys are regenerated on server restart (demo mode)
- Licenses created before restart will show as "tampered"
- In production, persist keys to maintain license validity
- OTPs are displayed in server console (demo mode)

## Testing the Tamper Detection

1. Generate a license from the dashboard
2. Click "Validate" - should show ✅ Valid
3. Click "Tamper" button to modify the token
4. Click "Validate" again - should show ❌ Invalid (tampering detected)

## Tech Stack

- **Backend**: Python, Flask, SQLite, cryptography library
- **Frontend**: Next.js 14, React, TypeScript, TailwindCSS
- **Security**: JWT (PyJWT), PBKDF2, AES-256, RSA-2048

---


