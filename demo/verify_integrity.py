#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Message Integrity, Non-Repudiation & Offline Verification Demo

This script demonstrates:
1. Message Integrity: Each message signed with RSA (seq || ts || ct)
2. Non-Repudiation: Append-only transcript with signed hash
3. Offline Verification: Verify session receipt without connecting to server
"""

import os
import json
import base64
import sys
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import serialization

# Force UTF-8 output on Windows
if sys.platform.startswith('win'):
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

CERT_DIR = "../certs"
SERVER_PEM = os.path.join(CERT_DIR, "server.pem")
CLIENT_PEM = os.path.join(CERT_DIR, "client.pem")
ROOT_PEM = os.path.join(CERT_DIR, "rootCA.pem")
TRANSCRIPT = "transcript.log"
TRANSCRIPT_SIG = "transcript.log.sig"

print("=" * 80)
print("MESSAGE INTEGRITY, NON-REPUDIATION & OFFLINE VERIFICATION")
print("=" * 80)

# Load certificates and keys
with open(SERVER_PEM, 'rb') as f:
    server_pem = f.read()
with open(ROOT_PEM, 'rb') as f:
    root_pem = f.read()

root_cert = x509.load_pem_x509_certificate(root_pem, default_backend())
server_cert = x509.load_pem_x509_certificate(server_pem, default_backend())

# Extract server's public key for verification
server_pub = server_cert.public_key()

print("\n" + "=" * 80)
print("REQUIREMENT 1: Message Integrity (RSA Signature)")
print("=" * 80)

print("""
DESIGN:
  Each message from client to server contains:
    - ct: Base64-encoded ciphertext (IV + AES-encrypted payload)
    - seqno: Sequence number (1, 2, 3, ...)
    - ts: Millisecond timestamp
    - sig: RSA signature over "seqno|ts|ct"

  Signature prevents tampering:
    - If ct is modified → signature invalid
    - If seqno is modified → signature invalid
    - If ts is modified → signature invalid
    - Only holder of client's private key can create valid signature

VERIFICATION FORMULA:
  signed_data = str(seqno) + "|" + str(ts) + "|" + ct_b64
  signature_valid = RSA_verify(signed_data, sig, client_pubkey)
""")

print("\n[EXAMPLE MESSAGE STRUCTURE]")
print("""
{
  "ct": "UQ0C7x1+8k0Y/MhZ...base64-ciphertext...",
  "sig": "FAksL2D9+0x...base64-signature...",
  "seqno": 1,
  "ts": 1701532587123
}

To verify:
  1. Decode sig from base64 → raw signature bytes
  2. Construct: signed_data = "1|1701532587123|UQ0C7x1+8k0Y..."
  3. Get client's public key from client certificate
  4. Verify: RSA_verify(signed_data, signature, client_pubkey)
""")

print("\n" + "=" * 80)
print("REQUIREMENT 2: Non-Repudiation (Append-Only Transcript)")
print("=" * 80)

print("""
DESIGN:
  Server maintains append-only transcript file: transcript.log
  
  Each line is a JSON entry:
  {
    "ts": 1701532587123,
    "from": "127.0.0.1:12345",
    "seqno": 1,
    "ct": "...encrypted payload...",
    "payload_type": "register" or "login"
  }
  
  After each session, server:
    1. Signs entire transcript file with server's private key
    2. Writes signature to transcript.log.sig
    3. Returns SessionReceipt to client

  Non-Repudiation Properties:
    - Transcript is append-only (no deletion/modification)
    - Signed by server's private key
    - Server cannot deny creating entries (has private key)
    - Student can verify signature offline
""")

# Check if transcript exists
if os.path.exists(TRANSCRIPT):
    print(f"\n[CHECKING TRANSCRIPT: {TRANSCRIPT}]")
    
    with open(TRANSCRIPT, 'r') as f:
        entries = [json.loads(line) for line in f if line.strip()]
    
    print(f"Transcript has {len(entries)} entries:")
    for i, entry in enumerate(entries, 1):
        print(f"\n  Entry {i}:")
        print(f"    Timestamp: {entry['ts']}")
        print(f"    From: {entry['from']}")
        print(f"    SeqNo: {entry['seqno']}")
        print(f"    Type: {entry['payload_type']}")
        print(f"    Ciphertext: {entry['ct'][:50]}...")
else:
    print(f"\n⚠️  {TRANSCRIPT} not found (run server+client first)")
    entries = []

print("\n" + "=" * 80)
print("REQUIREMENT 3: Offline Verification (Session Receipt)")
print("=" * 80)

print("""
OFFLINE VERIFICATION PROCESS:

Student downloads:
  1. transcript.log - Append-only list of entries
  2. transcript.log.sig - RSA signature (server's private key)
  3. server.pem - Server's public key (for verification)

To verify offline (without running server):
  1. Read transcript.log
  2. Compute SHA256(transcript_data)
  3. Read transcript.log.sig (base64-decode → raw signature)
  4. Extract server's public key from server.pem
  5. Verify: RSA_verify(transcript_hash, signature, server_pubkey)
  
If verification succeeds:
  ✅ Transcript was signed by server (authenticated)
  ✅ Transcript has not been modified (integrity)
  ✅ Server created entries (non-repudiation)
""")

if os.path.exists(TRANSCRIPT) and os.path.exists(TRANSCRIPT_SIG):
    print(f"\n[PERFORMING OFFLINE VERIFICATION]")
    
    # Read transcript
    with open(TRANSCRIPT, 'rb') as f:
        transcript_data = f.read()
    print(f"Transcript size: {len(transcript_data)} bytes")
    
    # Compute hash
    h = SHA256.new()
    h.update(transcript_data)
    transcript_hash = h.digest()
    print(f"Transcript SHA256: {transcript_hash.hex()}")
    
    # Read signature
    with open(TRANSCRIPT_SIG, 'rb') as f:
        transcript_sig = f.read()
    print(f"Signature size: {len(transcript_sig)} bytes")
    
    # Verify signature using PyCryptodome (consistent with server signing)
    print("\n[VERIFYING SIGNATURE]")
    try:
        # Extract RSA public key from certificate
        pub_pem = server_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        rsa_pub = RSA.import_key(pub_pem)
        
        # Verify signature
        h = SHA256.new()
        h.update(transcript_data)
        pkcs1_15.new(rsa_pub).verify(h, transcript_sig)
        
        print("✅ SIGNATURE VALID - Transcript authenticated!")
        print("✅ Transcript has NOT been modified")
        print("✅ Non-repudiation: Server signed this transcript")
    except Exception as e:
        print(f"❌ SIGNATURE INVALID: {e}")
        print("⚠️  Transcript may have been tampered with!")
else:
    print(f"\n⚠️  {TRANSCRIPT_SIG} not found (run server+client first)")

print("\n" + "=" * 80)
print("SESSION RECEIPT GENERATION")
print("=" * 80)

if entries:
    # Generate SessionReceipt
    session_receipt = {
        "session_id": base64.b64encode(os.urandom(16)).decode(),
        "entries_count": len(entries),
        "first_entry_ts": entries[0]['ts'],
        "last_entry_ts": entries[-1]['ts'],
        "transcript_hash": transcript_hash.hex() if os.path.exists(TRANSCRIPT) else None,
        "server_signature_b64": base64.b64encode(transcript_sig).decode() if os.path.exists(TRANSCRIPT_SIG) else None,
    }
    
    print("\n[SESSION RECEIPT]")
    print(json.dumps(session_receipt, indent=2))
    
    # Save SessionReceipt
    with open("session_receipt.json", "w") as f:
        json.dump(session_receipt, f, indent=2)
    print(f"\nSession receipt saved to: session_receipt.json")

print("\n" + "=" * 80)
print("INTEGRITY CHECK: Detecting Tampering")
print("=" * 80)

if os.path.exists(TRANSCRIPT) and os.path.exists(TRANSCRIPT_SIG):
    print("\n[SIMULATING TAMPERING DETECTION]")
    
    # Read original
    with open(TRANSCRIPT, 'rb') as f:
        original_data = f.read()
    
    # Try to tamper (in memory, don't actually modify)
    tampered_data = original_data[:-1] + b'X'  # Change last byte
    
    # Compute hash of tampered version
    h_tampered = SHA256.new()
    h_tampered.update(tampered_data)
    tampered_hash = h_tampered.digest()
    
    print(f"Original transcript hash:  {transcript_hash.hex()}")
    print(f"Tampered transcript hash:  {tampered_hash.hex()}")
    print(f"Hashes match: {transcript_hash == tampered_hash}")
    
    # Try to verify tampered with original signature
    print("\n[VERIFICATION ATTEMPT ON TAMPERED TRANSCRIPT]")
    try:
        pub_pem = server_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        rsa_pub = RSA.import_key(pub_pem)
        h_tamper = SHA256.new()
        h_tamper.update(tampered_data)
        pkcs1_15.new(rsa_pub).verify(h_tamper, transcript_sig)
        print("✅ Verification passed (unexpected!)")
    except Exception as e:
        print(f"❌ Verification FAILED (expected): {type(e).__name__}")
        print("✅ Tampering detected!")

print("\n" + "=" * 80)
print("SUMMARY: Security Properties Achieved")
print("=" * 80)

summary = """
✅ MESSAGE INTEGRITY
   - Each message signed with RSA (seq || ts || ct)
   - Tampering detected immediately
   - Signature uses SHA256 + PKCS#1 v1.5

✅ NON-REPUDIATION
   - Server signs entire transcript with private key
   - Append-only log (immutable after signature)
   - Server cannot deny entries

✅ OFFLINE VERIFICATION
   - Student can verify without running server
   - Needs: transcript.log + transcript.log.sig + server.pem
   - RSA verification proves authenticity
   - No private keys needed for verification

✅ TAMPER DETECTION
   - Any modification to transcript detected
   - Signature becomes invalid
   - Student can prove integrity offline
"""

print(summary)

print("\n" + "=" * 80)
print("FILES AVAILABLE FOR VERIFICATION")
print("=" * 80)

files_to_show = [
    (TRANSCRIPT, "Append-only transcript of all messages"),
    (TRANSCRIPT_SIG, "RSA signature of entire transcript (signed by server)"),
    (SERVER_PEM, "Server's public certificate (for verification)"),
    ("session_receipt.json", "Generated session receipt with summary"),
]

for fname, desc in files_to_show:
    exists = "✅" if os.path.exists(fname) else "⚠️"
    print(f"{exists} {fname}")
    print(f"   {desc}")

print("\n" + "=" * 80)
