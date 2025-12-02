# Infosec Assignment A02 - Demo Guide for TA

## Quick Start (Run Both Server & Client)

### Terminal 1 - Start Server
```powershell
cd C:\Users\USER\Desktop\IS\demo
python server.py
```

Expected output:
```
Server listening on 9000
```

### Terminal 2 - Run Client (Registration)
```powershell
cd C:\Users\USER\Desktop\IS\demo
python client.py
```

Expected output:
```
Server cert verified.
Derived AES key (hex): [hex string]
Ack signature OK; ack: {'status': 'ok', 'ts': [timestamp]}
```

---

## What to Show the TA

### 1. CA & Certificate Generation (View the files)

**Location:** `C:\Users\USER\Desktop\IS\certs\`

**Files to show:**
```powershell
cd C:\Users\USER\Desktop\IS\certs
dir
```

**You should see:**
- `rootCA.pem` - Root CA certificate
- `rootCA.key` - Root CA private key
- `server.pem` - Server certificate (signed by rootCA)
- `server.key` - Server private key
- `client.pem` - Client certificate (signed by rootCA)
- `client.key` - Client private key

**Verify certificates are signed by root CA:**
```powershell
cd C:\Users\USER\Desktop\IS\demo
python check_certs.py
```

**Output:**
```
client.pem: VALID - signed by rootCA
server.pem: VALID - signed by rootCA
```

---

### 2. Certificate Validation (Show the Code)

**File:** `C:\Users\USER\Desktop\IS\demo\client.py` and `server.py`

**What's implemented:**

#### A. Expiry Check
```python
# Line ~30-35 in both files
now = datetime.now(timezone.utc)
if now < cert.not_valid_before_utc:
    return False, BAD_CERT_INVALID
if now > cert.not_valid_after_utc:
    return False, BAD_CERT_EXPIRED
```

#### B. Signature Verification with PKCS#1 v1.5
```python
# Line ~45-50 in both files
pubkey.verify(
    cert.signature,
    cert.tbs_certificate_bytes,
    asym_padding.PKCS1v15(),
    cert.signature_hash_algorithm,
)
```

#### C. Hostname/SAN Validation
```python
# Line ~55-75 in both files
# Checks Subject Alternative Name (SAN)
# Falls back to Common Name (CN)
# Validates against expected hostname
```

#### D. Error Codes
```python
# Line 18-20 in both files
BAD_CERT_INVALID = "BAD_CERT_INVALID"
BAD_CERT_EXPIRED = "BAD_CERT_EXPIRED"
BAD_CERT_HOSTNAME = "BAD_CERT_HOSTNAME"
```

---

### 3. Secure Password Storage (Show the Database)

**Run after successful registration/login:**

```powershell
cd C:\Users\USER\Desktop\IS\demo
python -c "
import sqlite3
conn = sqlite3.connect('users.db')
c = conn.cursor()
print('=== DATABASE SCHEMA ===')
c.execute(\"PRAGMA table_info(users)\")
for col in c.fetchall():
    print(f'  {col[1]}: {col[2]}')
print('\n=== USER DATA ===')
c.execute('SELECT id, username, email, salt, pwd_hash, created_at, last_login FROM users')
for row in c.fetchall():
    print(f'ID: {row[0]}')
    print(f'Username: {row[1]}')
    print(f'Email: {row[2]}')
    print(f'Salt (base64): {row[3]} ({len(__import__(\"base64\").b64decode(row[3]))} bytes)')
    print(f'Hash (SHA256): {row[4]} ({len(row[4])} chars)')
    print(f'Created at: {row[5]}')
    print(f'Last login: {row[6]}')
"
```

**You should see:**
```
=== DATABASE SCHEMA ===
  id: INTEGER
  username: TEXT
  email: TEXT
  salt: TEXT
  pwd_hash: TEXT
  created_at: INTEGER
  last_login: INTEGER

=== USER DATA ===
ID: 1
Username: student1
Email: s1@example.com
Salt (base64): [24 char base64] (16 bytes)
Hash (SHA256): [64 hex chars]
Created at: [timestamp]
Last login: [timestamp]
```

---

### 4. Transport Security (Show Code & Encryption)

**File:** `C:\Users\USER\Desktop\IS\demo\client.py` (lines 177-195)

**Encryption implementation:**
```python
# DH Key Agreement
shared = pow(B, a, p)
K = derive_aes128_from_shared(shared)  # AES-128 key from shared secret

# Encrypt payload
iv = os.urandom(16)  # Random IV
cipher = AES.new(K, AES.MODE_CBC, iv)
ct = iv + cipher.encrypt(pkcs7_pad(pt))  # Ciphertext
ct_b64 = base64.b64encode(ct).decode()

# Sign encrypted data
sig = sign_with_client(signed_data)

# Send framed message
send_json(s, {"ct": ct_b64, "sig": ..., "seqno": ..., "ts": ...})
```

**Evidence:** During demo, you see in server output:
```
Derived AES key (hex): 956c0ca4da5fd52b1a833dab0f8a40c7
Client signature OK
Decrypted payload: {'type': 'register', 'username': 'student1', ...}
```

This proves:
- ✅ Data was encrypted (can't read it in transit)
- ✅ Both sides derived same AES key
- ✅ Signature verified (authentication)
- ✅ Decryption successful

---

### 5. Login Logic (Show Both Registration & Login)

#### A. Registration Test

**Edit client.py:**
```powershell
# Line 173 in client.py:
use_login = False  # Keep this for registration
```

**Run:**
```powershell
cd C:\Users\USER\Desktop\IS\demo
python server.py  # Terminal 1
# In Terminal 2:
python client.py
```

**Server output:**
```
Client cert verified against Root CA.
Client signature OK
Decrypted payload: {'type': 'register', 'username': 'student1', 'email': 's1@example.com', 'pwd': 'password123'}
Stored user student1
Sent ack and signed transcript
```

#### B. Login Test

**Edit client.py:**
```powershell
# Line 173 in client.py:
use_login = True  # Switch to login
```

**Run:**
```powershell
cd C:\Users\USER\Desktop\IS\demo
python server.py  # Terminal 1 (fresh server, DB persists)
# In Terminal 2:
python client.py
```

**Server output (Login success):**
```
Client cert verified against Root CA.
Client signature OK
Decrypted payload: {'type': 'login', 'username': 'student1', 'pwd': 'password123'}
Login successful for student1
Sent ack and signed transcript
```

**Client output:**
```
Server cert verified.
Derived AES key (hex): [different key]
Ack signature OK; ack: {'status': 'ok', 'ts': [timestamp]}
```

#### C. Failed Login Test

**Modify client.py temporarily:**
```python
payload = {"type": "login", "username": "student1", "pwd": "wrongpassword"}
```

**Run server and client again:**

**Server output (Login failure):**
```
Client cert verified against Root CA.
Client signature OK
Decrypted payload: {'type': 'login', 'username': 'student1', 'pwd': 'wrongpassword'}
Login failed: invalid password for student1
Sent ack and signed transcript
```

**Client output:**
```
Ack signature OK; ack: {'status': 'error', 'ts': ...}
```

---

### 6. Code Reference (Where Everything Is)

| Feature | File | Lines | What to Show |
|---------|------|-------|-------------|
| **CA Generation** | `scripts/gen_ca.sh` | 1-20 | Shows how CA created |
| **Cert Generation** | `scripts/gen_cert.sh` | 1-30 | Shows how certs signed |
| **Cert Verification** | `client.py` & `server.py` | 28-80 | Shows all validations |
| **Error Codes** | `client.py` & `server.py` | 18-20 | Shows BAD_CERT_* codes |
| **Password Storage** | `server.py` | 218-220 | Shows salt (16 bytes) + hash |
| **Encryption** | `client.py` | 177-195 | Shows AES-128-CBC |
| **Login Verification** | `server.py` | 240-265 | Shows hash matching |
| **Database Schema** | `server.py` | 19-30 | Shows users table |

---

## Demo Script (What to Say)

```
"This project implements a secure client-server registration and login system with:

1. **PKI with Certificate Validation:**
   - Root CA signs both client and server certificates
   - Validates: signature, expiry, hostname
   - Rejects invalid/expired/mismatched certs with error codes

2. **Secure Transport:**
   - Diffie-Hellman key agreement (2048-bit)
   - Derives AES-128 session key
   - All credentials encrypted with AES-CBC
   - RSA signatures for authentication

3. **Secure Authentication:**
   - Passwords stored as SHA256(salt + password)
   - 16-byte random salt per user
   - Login verifies hash against DB record
   - Certificate validation required for all requests

Let me demonstrate..."

[Run the server and client demo as shown above]

"As you can see:
- Both server and client verified each other's certificates
- Credentials were encrypted with the AES key derived from DH exchange
- Password was hashed with a 16-byte salt before storage
- Login succeeded by matching the hash
"
```

---

## Files to Submit to TA

1. **Certificates:** `certs/` folder (all .pem and .key files)
2. **Source code:** `demo/server.py`, `demo/client.py`, `demo/crypto_helpers.py`
3. **Database:** `demo/users.db` (after running the demo)
4. **Transcript:** `demo/transcript.log` and `demo/transcript.log.sig`
5. **Report:** `PROJECT_REPORT.pdf` (shows all fixes)

---

## Common TA Questions & Answers

**Q: How do I know passwords aren't stored plaintext?**
A: Show the database - all passwords are 64-character SHA256 hashes, never plaintext.

**Q: Where's the salt?**
A: In the `salt` column - it's 16 bytes (24 chars base64). Show with: `SELECT salt FROM users;`

**Q: How do you know the encryption works?**
A: The decrypted payload on server matches what client sent - proves encryption/decryption works.

**Q: What if I use wrong password?**
A: Show failed login test - server compares hashes, rejects if they don't match.

**Q: Can you intercept the password?**
A: No - it's encrypted with AES-128. Only if you have the AES key (from DH), and that requires valid certificate.

**Q: Are the certificates really signed by the CA?**
A: Yes - run `check_certs.py` to verify.
```

