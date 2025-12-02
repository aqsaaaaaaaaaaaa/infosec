# Secure Authentication & Encrypted Chat System

A comprehensive demonstration of applied cryptography including PKI, mutual authentication, secure credential transport, and message integrity verification.

## Features Implemented

### 1. Public Key Infrastructure (PKI)
- **Root Certificate Authority (CA)** created with OpenSSL
- **Server Certificate** issued and signed by root CA
- **Client Certificate** issued and signed by root CA
- All certificates include expiry validation and hostname verification

### 2. Mutual Authentication
- Client verifies server certificate (signature, expiry, hostname)
- Server verifies client certificate (signature, expiry, hostname)
- Invalid/expired/self-signed certificates are rejected with specific error codes

### 3. Secure Credential Transport
- **Diffie-Hellman (DH)** key agreement using RFC 3526 2048-bit MODP
- Session key derived: `K = Trunc16(SHA256(shared_secret))`
- Credentials encrypted with **AES-128-CBC** (PKCS#7 padding)
- No plaintext passwords transmitted over network

### 4. Secure Password Storage
- Passwords stored as **Salted SHA-256 hashes**
- Random salt: 16 bytes (128 bits) per user
- Salt stored in database alongside hash
- Login verifies hash match with provided password

### 5. Message Integrity & Authenticity
- Each message signed with **RSA-2048 + SHA256 + PKCS#1 v1.5**
- Signature covers: `seqno || ts || ciphertext`
- Server maintains **append-only transcript** of all sessions
- Transcript signed by server for non-repudiation

### 6. Offline Verification
- **Session Receipt** contains transcript hash and signature
- Student can verify transcript offline using server certificate
- Tampering detection: any modification invalidates signature

## Project Structure

```
IS/
├── certs/                      # PKI certificates and keys
│   ├── rootCA.pem             # Root CA certificate (public)
│   ├── rootCA.key             # Root CA private key (NOT committed)
│   ├── server.pem             # Server certificate (public)
│   ├── server.key             # Server private key (NOT committed)
│   ├── client.pem             # Client certificate (public)
│   └── client.key             # Client private key (NOT committed)
├── demo/
│   ├── server.py              # Server implementation
│   ├── client.py              # Client implementation
│   ├── crypto_helpers.py      # Cryptographic utilities (DH, KDF, padding)
│   ├── check_certs.py         # Certificate verification helper
│   ├── verify_features.py     # Automated feature verification
│   ├── verify_integrity.py    # Message integrity & offline verification demo
│   ├── test_dh_aes.py         # Comprehensive DH & AES testing
│   ├── transcript.log         # Append-only session transcript (NOT committed)
│   └── users.db               # User database (NOT committed)
├── scripts/
│   ├── gen_ca.sh              # Generate root CA
│   └── gen_cert.sh            # Generate and sign certificates
├── .gitignore                 # Excludes private keys and sensitive files
├── README.md                  # This file
├── PROJECT_REPORT.md          # Detailed technical report
├── KEY_AGREEMENT_VERIFICATION.md  # DH & AES verification details
├── DEMO_GUIDE.md              # Step-by-step demo instructions
├── CHECKLIST_FOR_TA.md        # TA evaluation checklist
└── run_server.ps1, run_client.ps1  # PowerShell launchers
```

## Quick Start

### Prerequisites
- Python 3.10+
- OpenSSL
- pip packages: `pycryptodome`, `cryptography`

### Installation

```bash
# Clone repository
git clone https://github.com/aqsaaaaaaaaaaaa/infosec.git
cd IS

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install pycryptodome cryptography
```

### Generate PKI

```bash
# Generate Root CA
bash scripts/gen_ca.sh

# Generate and sign server certificate
bash scripts/gen_cert.sh server server.local

# Generate and sign client certificate
bash scripts/gen_cert.sh client client.local
```

### Run Demo

**Terminal 1 (Server):**
```bash
cd demo
python server.py
```

**Terminal 2 (Client):**
```bash
cd demo
python client.py
```

### Verify Features

```bash
cd demo
python verify_features.py         # Comprehensive feature verification
python verify_integrity.py        # Message integrity & offline verification
python test_dh_aes.py            # DH key agreement & AES encryption tests
```

## Security Properties

| Property | Implementation | Status |
|----------|----------------|--------|
| **Confidentiality** | AES-128-CBC with random IV | ✅ |
| **Key Agreement** | RFC 3526 2048-bit DH | ✅ |
| **Key Derivation** | Trunc16(SHA256(shared_secret)) | ✅ |
| **Integrity** | RSA-2048 signatures (seq\|\|ts\|\|ct) | ✅ |
| **Authentication** | Mutual certificate validation | ✅ |
| **Non-Repudiation** | Signed transcript + session receipt | ✅ |
| **Password Storage** | Salted SHA-256 (16-byte salt) | ✅ |
| **Offline Verification** | Session receipt with RSA signature | ✅ |

## Cryptographic Constants

- **DH Group:** RFC 3526 Group 14 (2048-bit MODP)
- **Generator:** g = 2
- **Key Length:** AES-128 (16 bytes)
- **Symmetric Cipher:** AES in CBC mode
- **Padding:** PKCS#7
- **Asymmetric Cipher:** RSA-2048
- **Signing Algorithm:** RSA-SHA256 with PKCS#1 v1.5
- **Hash Function:** SHA-256
- **Salt Size:** 16 bytes (128 bits)

## Testing & Verification

### Run All Tests
```bash
cd demo
python verify_features.py      # All features checked
python test_dh_aes.py          # DH & encryption verified
python verify_integrity.py     # Message integrity verified
```

### Manual Testing

**Registration:**
```python
# In demo/client.py, set use_login = False
python server.py  # Terminal 1
python client.py  # Terminal 2
# Check: users.db contains new user with salted hash
```

**Login:**
```python
# In demo/client.py, set use_login = True
python server.py  # Terminal 1
python client.py  # Terminal 2
# Check: Server shows "Login successful" and last_login timestamp updated
```

**Offline Verification:**
```bash
cd demo
python verify_integrity.py
# Shows: Transcript signature VALID, tampering detection works
```

## Repository Hygiene

### What IS Committed
- ✅ Public certificates (`*.pem`)
- ✅ Source code (implementation)
- ✅ Documentation and guides
- ✅ Test scripts
- ✅ Scripts to generate credentials

### What IS NOT Committed
- ❌ Private keys (`*.key`)
- ❌ Database files (`users.db`)
- ❌ Session artifacts (`transcript.log`, `transcript.log.sig`)
- ❌ Virtual environment (`.venv/`)
- ❌ `.env` files

See `.gitignore` for complete list.

## Important: Security Notes

**CRITICAL:** This project does not commit private keys to the repository, ensuring security of sensitive cryptographic material. All `.key` files are listed in `.gitignore`.

## Project Documentation

1. **PROJECT_REPORT.md** - Complete technical report
2. **KEY_AGREEMENT_VERIFICATION.md** - DH & AES verification
3. **DEMO_GUIDE.md** - Step-by-step demo instructions
4. **CHECKLIST_FOR_TA.md** - TA evaluation checklist

## Commit History

The repository contains meaningful commits showing development progress:

1. Initial certificate verification fix (PKCS#1 v1.5 padding)
2. Public key export correction
3. Signature handling improvements
4. Client/server handshake verification
5. Certificate validation enhancements
6. Password security implementation
7. Login logic implementation
8. Database schema improvements
9. Documentation and guides
10. Feature verification scripts
11. Integrity verification implementation
12. Repository hygiene improvements

See `git log` for full commit details.

## Contact & Attribution

**Author:** Aqsa  
**Repository:** https://github.com/aqsaaaaaaaaaaaa/infosec  
**Branch:** fix/demo-cert-handshake  
**Last Updated:** 2025-12-02

---

**For TA:** Please see `CHECKLIST_FOR_TA.md` for evaluation guide and demo commands.
