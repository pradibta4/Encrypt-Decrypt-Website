#!/usr/bin/env python3
"""
Test Image Encryption Metrics
Verify NPCR, UACI, and Entropy are calculated correctly
"""

import requests
import base64
from PIL import Image
import numpy as np
import io
import sys

API_URL = "http://localhost:8000"

def create_test_image(width=256, height=256):
    """Create a simple test image"""
    # Create a gradient image
    arr = np.zeros((height, width, 3), dtype=np.uint8)
    for i in range(height):
        arr[i, :, 0] = int(255 * i / height)  # Red gradient
        arr[i, :, 1] = int(255 * (1 - i / height))  # Green inverse gradient
        arr[i, :, 2] = 128  # Blue constant
    
    img = Image.fromarray(arr, "RGB")
    return img

def test_image_encryption():
    """Test image encryption with metrics"""
    print("=" * 70)
    print("IMAGE ENCRYPTION METRICS TEST")
    print("=" * 70)
    
    # Create test image
    print("\n[1] Creating test image (256x256 gradient)...")
    test_img = create_test_image(256, 256)
    
    # Save to bytes
    img_buffer = io.BytesIO()
    test_img.save(img_buffer, format="PNG")
    img_buffer.seek(0)
    
    # Test encryption with different modes
    modes = ["standard", "sbox44"]
    key = "mysecretkey123"
    
    results = {}
    
    for mode in modes:
        print(f"\n[2] Testing encryption with mode: {mode.upper()}")
        print("-" * 70)
        
        # Reset buffer
        img_buffer.seek(0)
        
        # Encrypt
        files = {'file': ('test.png', img_buffer, 'image/png')}
        data = {'mode': mode, 'key_hex': key}
        
        try:
            response = requests.post(f"{API_URL}/image/encrypt", files=files, data=data)
            
            if response.status_code != 200:
                print(f"❌ Encryption failed: {response.status_code}")
                print(f"   Error: {response.json()}")
                continue
            
            result = response.json()
            results[mode] = result
            
            # Display metrics
            print(f"✅ Encryption successful!")
            print(f"\n   📊 METRICS:")
            print(f"   ├─ NPCR (Number of Pixels Change Rate):  {result['npcr']:.4f}% ⚠️" if result['npcr'] < 99.5 else f"   ├─ NPCR (Number of Pixels Change Rate):  {result['npcr']:.4f}% ✓")
            print(f"   ├─ UACI (Unified Avg Changing Intensity): {result['uaci']:.4f}% ⚠️" if result['uaci'] < 32.5 else f"   ├─ UACI (Unified Avg Changing Intensity): {result['uaci']:.4f}% ✓")
            print(f"   ├─ NPR (Number of Pixel Rate):           {result['npr']:.4f}% ⚠️" if result['npr'] < 99.5 else f"   ├─ NPR (Number of Pixel Rate):           {result['npr']:.4f}% ✓")
            print(f"   │")
            print(f"   ├─ Original Entropy:  {result['original_entropy']:.4f}")
            print(f"   └─ Encrypted Entropy: {result['encrypted_entropy']:.4f}")
            
            print(f"\n   📐 IMAGE SIZE: {result['image_size']['width']} x {result['image_size']['height']}")
            
            # Decode encrypted image for verification
            enc_img_data = base64.b64decode(result['encrypted_image_base64'])
            enc_img = Image.open(io.BytesIO(enc_img_data))
            print(f"   ✓ Encrypted image format: {enc_img.format} ({enc_img.mode})")
            
        except Exception as e:
            print(f"❌ Error during encryption: {e}")
            continue
    
    # Comparison
    print("\n" + "=" * 70)
    print("COMPARISON TABLE")
    print("=" * 70)
    
    if len(results) > 1:
        print(f"\n{'Metric':<35} {'Standard':<18} {'S-Box 44':<18}")
        print("-" * 71)
        print(f"{'NPCR (%)':<35} {results['standard']['npcr']:>17.4f} {results['sbox44']['npcr']:>17.4f}")
        print(f"{'UACI (%)':<35} {results['standard']['uaci']:>17.4f} {results['sbox44']['uaci']:>17.4f}")
        print(f"{'NPR (%)':<35} {results['standard']['npr']:>17.4f} {results['sbox44']['npr']:>17.4f}")
        print(f"{'Original Entropy':<35} {results['standard']['original_entropy']:>17.4f} {results['sbox44']['original_entropy']:>17.4f}")
        print(f"{'Encrypted Entropy':<35} {results['standard']['encrypted_entropy']:>17.4f} {results['sbox44']['encrypted_entropy']:>17.4f}")
    
    # Ideal values check
    print("\n" + "=" * 70)
    print("IDEAL VALUES CHECK (for good encryption)")
    print("=" * 70)
    print(f"✓ NPCR should be > 99.5% (≈ 99.6%)")
    print(f"✓ UACI should be > 32.5% (≈ 33%)")
    print(f"✓ NPR should be > 99.5% (≈ 99.6%)")
    print(f"✓ Entropy should approach 8.0")
    print(f"✓ Image size should remain same after encryption")

if __name__ == "__main__":
    try:
        test_image_encryption()
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to API. Make sure server is running:")
        print("   python -m uvicorn app.main:app --reload --port 8000")
        sys.exit(1)
