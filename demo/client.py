#!/usr/bin/env python3
# demo/client.py
import socket, json, os, base64, time
from crypto_helpers import RFC3526_2048 as p, g, derive_aes128_from_shared, pkcs7_pad
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import serialization

CERT_DIR = "../certs"
CLIENT_KEY = os.path.join(CERT_DIR, "client.key")
CLIENT_PEM = os.path.join(CERT_DIR, "client.pem")
ROOT_PEM = os.path.join(CERT_DIR, "rootCA.pem")

with open(CLIENT_KEY,'rb') as f: client_key = RSA.import_key(f.read())
with open(CLIENT_PEM,'rb') as f: client_pem = f.read()
with open(ROOT_PEM,'rb') as f: root_pem = f.read()

root_cert = x509.load_pem_x509_certificate(root_pem, default_backend())

def verify_cert_signed_by_root(pem_bytes):
    """
    Verify that a certificate (PEM format) is signed by the root CA.
    
    Args:
        pem_bytes (bytes): Certificate in PEM format
        
    Returns:
        tuple: (bool, cert_object) — True if valid, False otherwise; cert_object or error string
    """
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

def sign_with_client(data_bytes):
    """
    Sign data with the client's private RSA key using SHA-256 and PKCS#1 v1.5.
    
    Args:
        data_bytes (bytes): Data to sign
        
    Returns:
        bytes: RSA signature
    """
    h = SHA256.new(data_bytes)
    return pkcs1_15.new(client_key).sign(h)

# --- Reliable recv_json ---
def recvall(sock, n):
    """Receive exactly n bytes from the socket, blocking until all data arrives."""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Socket closed before receiving all data")
        data += packet
    return data

def recv_json(sock):
    """
    Receive a JSON message from the socket using length-prefixed framing.
    
    Reads 4-byte big-endian length prefix, then reads that many bytes, decodes JSON.
    
    Args:
        sock: Socket object
        
    Returns:
        dict: Decoded JSON object
        
    Raises:
        ConnectionError: If socket closes before all data is received
        json.JSONDecodeError: If data is not valid JSON
    """
    # First 4 bytes = message length
    L_bytes = recvall(sock, 4)
    L = int.from_bytes(L_bytes, 'big')
    data_bytes = recvall(sock, L)
    return json.loads(data_bytes.decode())


def send_json(sock, obj):
    """
    Send a JSON message using length-prefixed framing.
    
    Encodes object as JSON, prefixes with 4-byte big-endian length, sends all.
    
    Args:
        sock: Socket object
        obj (dict): Object to serialize and send
    """
    data = json.dumps(obj).encode()
    sock.send(len(data).to_bytes(4,'big') + data)

# Connect
s = socket.socket()
s.connect(('127.0.0.1', 9000))

# DH handshake
a = int.from_bytes(os.urandom(32),'big')
A = pow(g, a, p)
hello = {"client_cert": client_pem.decode(), "A": str(A)}
send_json(s, hello)

resp = recv_json(s)
server_pem = resp.get("server_cert").encode()
B = int(resp.get("B"))

ok, info = verify_cert_signed_by_root(server_pem)
if not ok:
    print("Server cert verification failed:", info); s.close(); exit(1)
print("Server cert verified.")

shared = pow(B, a, p)
K = derive_aes128_from_shared(shared)
print("Derived AES key (hex):", K.hex())

# Prepare payload
payload = {"type":"register","username":"student1","email":"s1@example.com","pwd":"password123"}
pt = json.dumps(payload).encode()
iv = os.urandom(16)
cipher = AES.new(K, AES.MODE_CBC, iv)
ct = iv + cipher.encrypt(pkcs7_pad(pt))
ct_b64 = base64.b64encode(ct).decode()

seqno = 1
ts = int(time.time()*1000)
signed_data = (str(seqno) + "|" + str(ts) + "|" + ct_b64).encode()
sig = sign_with_client(signed_data)

send_json(s, {"ct": ct_b64, "sig": base64.b64encode(sig).decode(), "seqno": seqno, "ts": ts})

# Receive ack
ack_msg = recv_json(s)
ack = ack_msg.get("ack")
ack_sig = base64.b64decode(ack_msg.get("sig"))

server_cert = x509.load_pem_x509_certificate(server_pem, default_backend())
pub = server_cert.public_key()
pub_pem = pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
rsa_pub = RSA.import_key(pub_pem)
h = SHA256.new(json.dumps(ack).encode())
try:
    pkcs1_15.new(rsa_pub).verify(h, ack_sig)
    print("Ack signature OK; ack:", ack)
except Exception as e:
    print("Ack signature FAIL", e)

s.close()
