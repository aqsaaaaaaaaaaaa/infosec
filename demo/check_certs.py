#!/usr/bin/env python3
"""Quick helper to verify that client.pem and server.pem are signed by rootCA.pem.

Usage:
  python demo/check_certs.py

Runs locally in the repo and prints whether each cert is validly signed by the root.
"""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
import os

CERT_DIR = os.path.join(os.path.dirname(__file__), '..', 'certs')

def load_cert(path):
    with open(path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

root_path = os.path.join(CERT_DIR, 'rootCA.pem')
client_path = os.path.join(CERT_DIR, 'client.pem')
server_path = os.path.join(CERT_DIR, 'server.pem')

root = load_cert(root_path)
root_pub = root.public_key()

for name, path in (('client', client_path), ('server', server_path)):
    cert = load_cert(path)
    try:
        root_pub.verify(cert.signature, cert.tbs_certificate_bytes,
                        padding.PKCS1v15(), cert.signature_hash_algorithm)
        print(f"{name}.pem: VALID - signed by rootCA")
    except Exception as e:
        print(f"{name}.pem: INVALID - {e}")
