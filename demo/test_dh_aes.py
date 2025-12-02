#!/usr/bin/env python3
"""
Test suite for:
1. Diffie-Hellman (DH) key agreement correctness
2. Session key derivation using Trunc16(SHA256(SharedSecret))
3. AES-128-CBC encryption with PKCS#7 padding (no crashes)
"""

import os
import json
import base64
from crypto_helpers import RFC3526_2048 as p, g, derive_aes128_from_shared, pkcs7_pad, pkcs7_unpad
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

print("=" * 70)
print("TEST 1: Diffie-Hellman Key Agreement")
print("=" * 70)

# Simulate client side DH
print("\n[CLIENT SIDE]")
a = int.from_bytes(os.urandom(32), 'big')  # Client's secret exponent
A = pow(g, a, p)                            # Client's public value
print(f"Client's secret exponent a: {hex(a)[:32]}... (32 bytes)")
print(f"Client's public value A: {hex(A)[:64]}... (2048-bit)")
print(f"A bit length: {A.bit_length()} bits")

# Simulate server side DH
print("\n[SERVER SIDE]")
b = int.from_bytes(os.urandom(32), 'big')  # Server's secret exponent
B = pow(g, b, p)                            # Server's public value
print(f"Server's secret exponent b: {hex(b)[:32]}... (32 bytes)")
print(f"Server's public value B: {hex(B)[:64]}... (2048-bit)")
print(f"B bit length: {B.bit_length()} bits")

# Derive shared secret on both sides
print("\n[SHARED SECRET DERIVATION]")
shared_client = pow(B, a, p)  # Client: (B^a mod p)
shared_server = pow(A, b, p)  # Server: (A^b mod p)

print(f"Client computed shared secret: {hex(shared_client)[:64]}...")
print(f"Server computed shared secret: {hex(shared_server)[:64]}...")
print(f"Shared secrets match: {shared_client == shared_server} ✅" if shared_client == shared_server else "⚠️ MISMATCH!")

# Verify shared secret has 2048 bits
print(f"Shared secret bit length: {shared_client.bit_length()} bits")
assert shared_client == shared_server, "DH key agreement failed!"

print("\n" + "=" * 70)
print("TEST 2: Key Derivation - Trunc16(SHA256(SharedSecret))")
print("=" * 70)

print("\n[KEY DERIVATION PROCESS]")

# Convert shared secret to bytes for hashing
sb = shared_client.to_bytes((shared_client.bit_length() + 7) // 8 or 1, 'big')
print(f"Shared secret as bytes: {len(sb)} bytes")

# Compute SHA256 hash
h = SHA256.new()
h.update(sb)
full_hash = h.digest()
print(f"SHA256(shared_secret): {len(full_hash)} bytes")
print(f"  Hex: {full_hash.hex()}")

# Truncate to 16 bytes for AES-128
K_client = full_hash[:16]
print(f"\nTrunc16(SHA256(shared_secret)): {len(K_client)} bytes (128 bits)")
print(f"  Hex: {K_client.hex()}")

# Using helper function on both sides
K_client_helper = derive_aes128_from_shared(shared_client)
K_server_helper = derive_aes128_from_shared(shared_server)

print(f"\nUsing derive_aes128_from_shared():")
print(f"  Client key: {K_client_helper.hex()}")
print(f"  Server key: {K_server_helper.hex()}")
print(f"  Keys match: {K_client_helper == K_server_helper} ✅" if K_client_helper == K_server_helper else "⚠️ MISMATCH!")

assert K_client == K_client_helper, "Key derivation mismatch with helper!"
assert K_client_helper == K_server_helper, "Client and server derived different keys!"

print("\n" + "=" * 70)
print("TEST 3: AES-128-CBC Encryption with PKCS#7 Padding")
print("=" * 70)

K = K_client_helper

# Test various payload sizes to verify padding works correctly
test_cases = [
    {"type": "register", "username": "alice", "pwd": "password123"},
    {"type": "login", "username": "bob", "pwd": "xyz"},
    {"type": "login", "username": "charlie", "pwd": "veryverylongpassword"},
    {"type": "register", "username": "x" * 100, "pwd": "y" * 100},  # Large payload
]

print(f"\nAES Key: {K.hex()} ({len(K)} bytes)")

for idx, payload in enumerate(test_cases, 1):
    print(f"\n[TEST CASE {idx}]")
    
    # Convert payload to bytes
    pt = json.dumps(payload).encode()
    print(f"Plaintext: {pt[:60]}{'...' if len(pt) > 60 else ''}")
    print(f"Plaintext length: {len(pt)} bytes")
    
    # Generate random IV
    iv = os.urandom(16)
    print(f"IV: {iv.hex()}")
    
    # Apply PKCS#7 padding
    padded = pkcs7_pad(pt)
    print(f"After PKCS#7 padding: {len(padded)} bytes (multiple of 16: {len(padded) % 16 == 0})")
    
    # Encrypt with AES-128-CBC
    cipher = AES.new(K, AES.MODE_CBC, iv)
    ct = cipher.encrypt(padded)
    print(f"Ciphertext: {len(ct)} bytes")
    
    # Base64 encode for transport
    ct_b64 = base64.b64encode(ct).decode()
    print(f"Base64 encoded: {len(ct_b64)} chars")
    
    # Decrypt (simulate receiving on server)
    cipher_dec = AES.new(K, AES.MODE_CBC, iv)
    decrypted = cipher_dec.decrypt(ct)
    print(f"Decrypted (with padding): {len(decrypted)} bytes")
    
    # Remove padding
    unpadded = pkcs7_unpad(decrypted)
    print(f"After removing PKCS#7 padding: {len(unpadded)} bytes")
    
    # Verify we got the original
    assert unpadded == pt, f"Decryption failed for test case {idx}!"
    recovered = json.loads(unpadded.decode())
    print(f"Recovered payload: {recovered}")
    
    assert recovered == payload, f"Payload mismatch for test case {idx}!"
    print(f"✅ Encryption/Decryption successful!")

print("\n" + "=" * 70)
print("TEST 4: No Crashes on Send/Receive (Simulated)")
print("=" * 70)

print("\nSimulating message framing and encryption/decryption...")

def send_frame(payload_dict):
    """Simulate sending encrypted message"""
    pt = json.dumps(payload_dict).encode()
    iv = os.urandom(16)
    cipher = AES.new(K, AES.MODE_CBC, iv)
    ct = iv + cipher.encrypt(pkcs7_pad(pt))
    ct_b64 = base64.b64encode(ct).decode()
    
    # Create message frame
    msg = {
        "ct": ct_b64,
        "seqno": 1,
        "ts": 1701532587000
    }
    
    # Serialize to JSON
    frame = json.dumps(msg).encode()
    # Add length prefix
    length_prefix = len(frame).to_bytes(4, 'big')
    return length_prefix + frame

def recv_frame(data):
    """Simulate receiving encrypted message"""
    length_prefix = data[:4]
    frame_len = int.from_bytes(length_prefix, 'big')
    frame_data = data[4:4+frame_len]
    
    msg = json.loads(frame_data.decode())
    ct_b64 = msg['ct']
    ct = base64.b64decode(ct_b64)
    
    iv = ct[:16]
    cipher = AES.new(K, AES.MODE_CBC, iv)
    pt = pkcs7_unpad(cipher.decrypt(ct[16:]))
    
    return json.loads(pt.decode())

# Test send/receive
test_payload = {"type": "register", "username": "testuser", "email": "test@example.com", "pwd": "testpass"}

try:
    print(f"\n1. Creating message frame...")
    frame = send_frame(test_payload)
    print(f"   ✅ Frame created: {len(frame)} bytes")
    
    print(f"2. Receiving message frame...")
    received_payload = recv_frame(frame)
    print(f"   ✅ Frame received: {received_payload}")
    
    print(f"3. Verifying payload integrity...")
    assert received_payload == test_payload
    print(f"   ✅ Payload matches original")
    
except Exception as e:
    print(f"   ❌ ERROR: {e}")
    raise

print("\n" + "=" * 70)
print("✅ ALL TESTS PASSED")
print("=" * 70)
print("\nSUMMARY:")
print("  ✅ Diffie-Hellman: Both sides derive identical 2048-bit shared secret")
print("  ✅ Key Derivation: Trunc16(SHA256(SharedSecret)) = 16 bytes (AES-128)")
print("  ✅ AES-128-CBC: Correct encryption/decryption with PKCS#7 padding")
print("  ✅ Message Framing: Length-prefixed JSON transport works correctly")
print("  ✅ No crashes on send/receive with various payload sizes")
