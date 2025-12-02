#!/usr/bin/env python3
# demo/server.py
import socket, json, base64, os, sqlite3, time
from datetime import datetime, timezone
from crypto_helpers import RFC3526_2048 as p, g, derive_aes128_from_shared, pkcs7_unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import serialization

# Certificate error codes
BAD_CERT_INVALID = "BAD_CERT_INVALID"
BAD_CERT_EXPIRED = "BAD_CERT_EXPIRED"
BAD_CERT_HOSTNAME = "BAD_CERT_HOSTNAME"

CERT_DIR = "../certs"  # relative to demo/
SERVER_KEY = os.path.join(CERT_DIR, "server.key")
SERVER_PEM = os.path.join(CERT_DIR, "server.pem")
ROOT_PEM = os.path.join(CERT_DIR, "rootCA.pem")
DB_PATH = "users.db"
TRANSCRIPT = "transcript.log"

# Ensure DB
conn_db = sqlite3.connect(DB_PATH)
c = conn_db.cursor()
c.execute("""CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    salt TEXT NOT NULL,
    pwd_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_login INTEGER
)""")
# Create index on username for faster lookups
c.execute("CREATE INDEX IF NOT EXISTS idx_username ON users(username)")
conn_db.commit()

# load keys & certs
with open(SERVER_KEY,'rb') as f: server_key = RSA.import_key(f.read())
with open(SERVER_PEM,'rb') as f: server_pem = f.read()
with open(ROOT_PEM,'rb') as f: root_pem = f.read()

root_cert = x509.load_pem_x509_certificate(root_pem, default_backend())

def verify_cert_signed_by_root(pem_bytes, expected_hostname=None):
    """
    Verify that a certificate (PEM format) is signed by the root CA.
    Also checks: expiry, signature validity, and hostname/SAN.
    
    Args:
        pem_bytes (bytes): Certificate in PEM format
        expected_hostname (str): Expected hostname (CN or SAN) to validate against
        
    Returns:
        tuple: (bool, cert_object_or_error_code) — True if valid, False otherwise
    """
    try:
        cert = x509.load_pem_x509_certificate(pem_bytes, default_backend())
        
        # 1) Check expiry
        now = datetime.now(timezone.utc)
        if now < cert.not_valid_before_utc:
            return False, BAD_CERT_INVALID  # Not yet valid
        if now > cert.not_valid_after_utc:
            return False, BAD_CERT_EXPIRED  # Expired
        
        # 2) Verify signature with root CA
        pubkey = root_cert.public_key()
        try:
            pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                asym_padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except Exception:
            return False, BAD_CERT_INVALID
        
        # 3) Check hostname/SAN if provided
        if expected_hostname:
            hostname_valid = False
            
            # Check SAN (Subject Alternative Name)
            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                for name in san_ext.value:
                    if isinstance(name, x509.DNSName):
                        if name.value.lower() == expected_hostname.lower():
                            hostname_valid = True
                            break
            except x509.ExtensionNotFound:
                pass  # No SAN extension
            
            # Check CN (Common Name) if SAN not found
            if not hostname_valid:
                try:
                    cn_attr = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                    if cn_attr:
                        cn_value = cn_attr[0].value.lower()
                        if cn_value == expected_hostname.lower():
                            hostname_valid = True
                except Exception:
                    pass
            
            if not hostname_valid:
                return False, BAD_CERT_HOSTNAME
        
        return True, cert
    except Exception as e:
        return False, BAD_CERT_INVALID

def sign_with_server(data_bytes):
    h = SHA256.new(data_bytes)
    return pkcs1_15.new(server_key).sign(h)

def verify_signature_with_rsa_pub(pem_client_cert, data_bytes, sig_bytes):
    cert = x509.load_pem_x509_certificate(pem_client_cert, default_backend())
    pub = cert.public_key()
    pub_pem = pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    rsa_pub = RSA.import_key(pub_pem)
    h = SHA256.new(data_bytes)
    try:
        pkcs1_15.new(rsa_pub).verify(h, sig_bytes)
        return True
    except:
        return False

# --- New reliable recv_json ---
def recvall(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Socket closed before receiving all data")
        data += packet
    return data

def recv_json(sock):
    L_bytes = recvall(sock, 4)
    L = int.from_bytes(L_bytes, 'big')
    data = recvall(sock, L)
    return json.loads(data.decode())

def send_json(sock, obj):
    data = json.dumps(obj).encode()
    sock.send(len(data).to_bytes(4,'big') + data)

# Start server socket
sock = socket.socket()
sock.bind(('0.0.0.0', 9000))
sock.listen(1)
print("Server listening on 9000")
conn, addr = sock.accept()
print("Accepted", addr)

# 1) receive client hello
hello = recv_json(conn)
client_pem = hello.get("client_cert").encode()
A = int(hello.get("A"))

ok, info = verify_cert_signed_by_root(client_pem, expected_hostname="client.local")
if not ok:
    error_msg = "Client cert verification failed"
    if info == BAD_CERT_EXPIRED:
        error_msg += ": Certificate expired"
    elif info == BAD_CERT_HOSTNAME:
        error_msg += ": Hostname mismatch"
    elif info == BAD_CERT_INVALID:
        error_msg += ": Invalid certificate"
    print(error_msg)
    conn.close()
    exit(1)
print("Client cert verified against Root CA.")

# 2) DH server side
b = int.from_bytes(os.urandom(32),'big')
B = pow(g, b, p)
send_json(conn, {"B": str(B), "server_cert": server_pem.decode()})

shared = pow(A, b, p)
K = derive_aes128_from_shared(shared)
print("Derived AES key (hex):", K.hex())

# 3) receive encrypted message
msg = recv_json(conn)
ct_b64 = msg['ct']
sig_b64 = msg['sig']
seqno = msg.get('seqno')
ts = msg.get('ts')

ct = base64.b64decode(ct_b64)
sig = base64.b64decode(sig_b64)

signed_data = (str(seqno) + "|" + str(ts) + "|" + ct_b64).encode()
if not verify_signature_with_rsa_pub(client_pem, signed_data, sig):
    print("Signature verification failed")
    conn.close(); exit(1)
print("Client signature OK")

# Decrypt
iv = ct[:16]
cipher = AES.new(K, AES.MODE_CBC, iv)
pt = pkcs7_unpad(cipher.decrypt(ct[16:])).decode()
payload = json.loads(pt)
print("Decrypted payload:", payload)

# Store user if registration
if payload.get("type") == "register":
    username = payload.get("username")
    email = payload.get("email")
    pwd = payload.get("pwd")
    salt = base64.b64encode(os.urandom(16)).decode()  # 16 bytes = 128 bits salt
    h = SHA256.new((salt + pwd).encode()).hexdigest()
    try:
        c.execute("INSERT INTO users(username,email,salt,pwd_hash,created_at) VALUES (?,?,?,?,?)",
                  (username,email,salt,h,int(time.time())))
        conn_db.commit()
        print("Stored user", username)
        status = "ok"
    except Exception as e:
        print("DB error:", e)
        status = "error"
elif payload.get("type") == "login":
    username = payload.get("username")
    pwd = payload.get("pwd")
    try:
        c.execute("SELECT salt, pwd_hash FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        if row:
            stored_salt, stored_hash = row
            # Recompute hash with provided password and stored salt
            computed_hash = SHA256.new((stored_salt + pwd).encode()).hexdigest()
            if computed_hash == stored_hash:
                # Update last_login
                c.execute("UPDATE users SET last_login = ? WHERE username = ?",
                         (int(time.time()), username))
                conn_db.commit()
                print("Login successful for", username)
                status = "ok"
                payload_response = {"type": "login_response", "result": "success"}
            else:
                print("Login failed: invalid password for", username)
                status = "error"
                payload_response = {"type": "login_response", "result": "invalid_password"}
        else:
            print("Login failed: user not found")
            status = "error"
            payload_response = {"type": "login_response", "result": "user_not_found"}
    except Exception as e:
        print("Login error:", e)
        status = "error"
        payload_response = {"type": "login_response", "result": "error"}
else:
    status = "unknown_type"
    payload_response = None

# Append transcript and sign
entry = {"ts": int(time.time()*1000), "from": str(addr), "seqno": seqno, "ct": ct_b64, "payload_type": payload.get("type")}
with open(TRANSCRIPT,'a') as tf:
    tf.write(json.dumps(entry) + "\n")

with open(TRANSCRIPT,'rb') as tf:
    tdata = tf.read()
t_sig = sign_with_server(tdata)
with open(TRANSCRIPT + ".sig", "wb") as sf:
    sf.write(t_sig)

ack = {"status": status, "ts": int(time.time()*1000)}
ack_bytes = json.dumps(ack).encode()
ack_sig = sign_with_server(ack_bytes)
send_json(conn, {"ack": ack, "sig": base64.b64encode(ack_sig).decode()})
print("Sent ack and signed transcript")

conn.close()
sock.close()
