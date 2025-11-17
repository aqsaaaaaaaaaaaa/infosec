#!/usr/bin/env python3
# demo/server.py
import socket, json, base64, os, sqlite3, time
from crypto_helpers import RFC3526_2048 as p, g, derive_aes128_from_shared, pkcs7_unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import serialization

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
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    email TEXT,
    salt TEXT,
    pwd_hash TEXT,
    created_at INTEGER
)""")
conn_db.commit()

# load keys & certs
with open(SERVER_KEY,'rb') as f: server_key = RSA.import_key(f.read())
with open(SERVER_PEM,'rb') as f: server_pem = f.read()
with open(ROOT_PEM,'rb') as f: root_pem = f.read()

root_cert = x509.load_pem_x509_certificate(root_pem, default_backend())

def verify_cert_signed_by_root(pem_bytes):
    cert = x509.load_pem_x509_certificate(pem_bytes, default_backend())
    pubkey = root_cert.public_key()
    try:
        pubkey.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            asym_padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True, cert
    except Exception as e:
        return False, str(e)

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

ok, info = verify_cert_signed_by_root(client_pem)
if not ok:
    print("Client cert verification failed:", info)
    conn.close(); exit(1)
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
    salt = base64.b64encode(os.urandom(8)).decode()
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
else:
    status = "unknown_type"

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
