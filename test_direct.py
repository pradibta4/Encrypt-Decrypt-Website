#!/usr/bin/env python3
"""Test simple_sbox_encrypt directly"""

import sys
sys.path.insert(0, 'd:/kriptograf/Encrypt-Decrypt-Website')

from app.aes_core import simple_sbox_encrypt, simple_sbox_decrypt, SBOX_44
import numpy as np
from PIL import Image
import io

# Create test image
arr = np.zeros((64, 64, 3), dtype=np.uint8)
for i in range(64):
    arr[i, :, 0] = int(255 * i / 64)
    arr[i, :, 1] = 128
    arr[i, :, 2] = 64

flat_bytes = arr.tobytes()
print(f"Plaintext size: {len(flat_bytes)} bytes")

key = "mysecretkey123"

try:
    # Test encryption
    print("\n[1] Testing encryption...")
    ciphertext = simple_sbox_encrypt(flat_bytes, key, SBOX_44)
    print(f"✓ Encryption successful!")
    print(f"  Ciphertext size: {len(ciphertext)} bytes")
    
    # Test differential
    print("\n[2] Testing differential...")
    mod_plaintext = bytearray(flat_bytes)
    mod_plaintext[0] = (mod_plaintext[0] + 1) % 256
    ciphertext2 = simple_sbox_encrypt(bytes(mod_plaintext), key, SBOX_44)
    print(f"✓ Differential encryption successful!")
    
    # Check NPCR
    diff = sum(1 for a, b in zip(ciphertext, ciphertext2) if a != b)
    npcr = (diff / len(ciphertext)) * 100
    print(f"  Different bytes: {diff} / {len(ciphertext)}")
    print(f"  NPCR: {npcr:.4f}%")
    
    # Test decryption
    print("\n[3] Testing decryption...")
    plaintext_recovered = simple_sbox_decrypt(ciphertext, key, SBOX_44)
    print(f"✓ Decryption successful!")
    
    # Verify
    if plaintext_recovered == flat_bytes:
        print(f"✓ Plaintext matches!")
    else:
        diff_count = sum(1 for a, b in zip(plaintext_recovered, flat_bytes) if a != b)
        print(f"❌ Plaintext mismatch! {diff_count} bytes different")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
