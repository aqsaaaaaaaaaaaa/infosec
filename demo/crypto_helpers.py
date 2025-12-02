# demo/crypto_helpers.py
import os
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

# 2048-bit MODP Group (RFC 3526 group 14)
# (decimal hex split for readability)
RFC3526_2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A36210000000000090563", 16)

g = 2

def sha256(b):
    h = SHA256.new()
    h.update(b)
    return h.digest()

def derive_aes128_from_shared(shared_int):
    # convert shared secret to bytes
    sb = shared_int.to_bytes((shared_int.bit_length() + 7) // 8 or 1, 'big')
    k = sha256(sb)[:16]  # AES-128 key
    return k

def pkcs7_pad(b):
    pad = 16 - (len(b) % 16)
    return b + bytes([pad]) * pad

def pkcs7_unpad(b):
    pad = b[-1]
    if pad < 1 or pad > 16:
        raise ValueError("Invalid padding")
    return b[:-pad]
