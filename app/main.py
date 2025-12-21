from __future__ import annotations

import json
import secrets
import hashlib
import math
import numpy as np
from PIL import Image
import io
import base64
from typing import Optional, Dict, List

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware

from . import schemas
from .aes_core import (
    AES_INVERSE_TABLE,
    AES_STANDARD_SBOX,
    SBOX_44,
    K44_AFFINE_MATRIX,  
    derive_key_from_input,
    decrypt_hex_to_text,
    encrypt_text_to_hex,
    validate_sbox,
    aes_encrypt_ecb,
    aes_decrypt_ecb,
    build_inv_sbox,
    pkcs7_pad # Pastikan fungsi ini ada di aes_core.py atau di-import
)
from .sbox_metrics import analyze_sbox

app = FastAPI(
    title="AES Custom S-Box API",
    version="0.3.0",
    description="Backend untuk enkripsi AES dengan S-Box standard, S-box 44 (paper), & custom.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health_check():
    return {"status": "ok"}

# --- Helper Functions ---

def _resolve_sbox_from_body(mode: str, sbox: list[int] | None) -> list[int]:
    if mode == "standard":
        return AES_STANDARD_SBOX
    if mode == "sbox44":
        return SBOX_44
    if mode == "custom":
        if sbox is None:
            raise HTTPException(status_code=400, detail="sbox wajib diisi untuk mode custom")
        if not validate_sbox(sbox):
            raise HTTPException(status_code=400, detail="sbox tidak valid (harus permutasi 0..255)")
        return sbox
    raise HTTPException(status_code=400, detail="mode harus 'standard', 'sbox44', atau 'custom'")

def _resolve_sbox_from_form(mode: str, sbox_json: str | None) -> list[int]:
    if mode == "standard":
        return AES_STANDARD_SBOX
    if mode == "sbox44":
        return SBOX_44
    if mode == "custom":
        if not sbox_json:
            raise HTTPException(status_code=400, detail="sbox_json wajib diisi untuk mode custom")
        try:
            parsed = json.loads(sbox_json)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="sbox_json bukan JSON yang valid")
        if not validate_sbox(parsed):
            raise HTTPException(status_code=400, detail="sbox tidak valid (harus permutasi 0..255)")
        return parsed
    raise HTTPException(status_code=400, detail="mode harus 'standard', 'sbox44', atau 'custom'")

# --- Text Endpoints ---

@app.post("/encrypt", response_model=schemas.EncryptResponse)
def encrypt(req: schemas.EncryptRequest):
    if req.plaintext_hex:
        try:
            pt_bytes = bytes.fromhex(req.plaintext_hex)
            plaintext_str = pt_bytes.decode("utf-8", errors="ignore")
        except ValueError:
            raise HTTPException(status_code=400, detail="plaintext_hex tidak valid")
    elif req.plaintext:
        plaintext_str = req.plaintext
    else:
        raise HTTPException(status_code=400, detail="plaintext atau plaintext_hex harus diisi")

    sbox = _resolve_sbox_from_body(req.mode, req.sbox)

    try:
        ciphertext_hex = encrypt_text_to_hex(plaintext_str, req.key_hex, sbox)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return schemas.EncryptResponse(
        ciphertext_hex=ciphertext_hex,
        used_mode=req.mode,
        plaintext_len=len(plaintext_str.encode("utf-8")),
    )

@app.post("/decrypt", response_model=schemas.DecryptResponse)
def decrypt(req: schemas.DecryptRequest):
    sbox = _resolve_sbox_from_body(req.mode, req.sbox)

    try:
        plaintext_str = decrypt_hex_to_text(req.ciphertext_hex, req.key_hex, sbox)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return schemas.DecryptResponse(
        plaintext=plaintext_str,
        plaintext_hex=plaintext_str.encode("utf-8").hex(),
        used_mode=req.mode,
    )

# --- S-Box Info Endpoints ---

@app.get("/sbox/paper44", response_model=schemas.SBoxPaper44Response)
def get_sbox_44():
    metrics = analyze_sbox(SBOX_44)
    return schemas.SBoxPaper44Response(
        sbox=SBOX_44,
        metrics=schemas.SBoxMetricsResponse(**metrics),
        affine_matrix=K44_AFFINE_MATRIX,
        paper_info={
            "title": "AES S-box modification uses affine matrices exploration",
            "authors": "Alamsyah et al.",
            "year": 2024,
            "description": "S-box 44 merupakan hasil terbaik dengan NL=112, SAC=0.50073, BIC-SAC=0.50237"
        }
    )

@app.get("/sbox/standard", response_model=schemas.SBoxStandardResponse)
def get_sbox_standard():
    metrics = analyze_sbox(AES_STANDARD_SBOX)
    return schemas.SBoxStandardResponse(
        sbox=AES_STANDARD_SBOX,
        metrics=schemas.SBoxMetricsResponse(**metrics),
        affine_matrix=None
    )

@app.post("/sbox/metrics", response_model=schemas.SBoxMetricsResponse)
def sbox_metrics(req: schemas.SBoxMetricsRequest):
    if not validate_sbox(req.sbox):
        raise HTTPException(status_code=400, detail="sbox tidak valid (harus permutasi 0..255)")
    try:
        metrics = analyze_sbox(req.sbox)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return schemas.SBoxMetricsResponse(**metrics)

# --- Image Utility Functions ---

def calculate_image_entropy(image: Image.Image) -> float:
    """Hitung entropy gambar."""
    img_array = np.array(image)
    if len(img_array.shape) == 3:
        entropies = []
        for channel in range(img_array.shape[2]):
            channel_data = img_array[:, :, channel].flatten()
            histogram, _ = np.histogram(channel_data, bins=256, range=(0, 256))
            histogram = histogram[histogram > 0]
            probabilities = histogram / histogram.sum()
            entropy = -np.sum(probabilities * np.log2(probabilities))
            entropies.append(entropy)
        return np.mean(entropies)
    else:
        channel_data = img_array.flatten()
        histogram, _ = np.histogram(channel_data, bins=256, range=(0, 256))
        histogram = histogram[histogram > 0]
        probabilities = histogram / histogram.sum()
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return entropy

def calculate_npcr_uaci_bytes(c1_bytes: bytes, c2_bytes: bytes) -> Dict[str, float]:
    """
    Hitung NPCR & UACI berdasarkan dua array bytes Ciphertext.
    Ini adalah implementasi Differential Attack yang benar.
    """
    arr1 = np.frombuffer(c1_bytes, dtype=np.uint8)
    arr2 = np.frombuffer(c2_bytes, dtype=np.uint8)
    
    # Samakan ukuran jika beda (seharusnya sama jika padding benar)
    min_len = min(len(arr1), len(arr2))
    arr1 = arr1[:min_len]
    arr2 = arr2[:min_len]
    
    # NPCR
    diff = (arr1 != arr2)
    npcr_val = (np.sum(diff) / min_len) * 100.0
    
    # UACI
    abs_diff = np.abs(arr1.astype(int) - arr2.astype(int))
    uaci_val = (np.sum(abs_diff) / (min_len * 255.0)) * 100.0
    
    return {"npcr": npcr_val, "uaci": uaci_val}

# --- Image Encryption Endpoints (REVISED) ---

@app.post("/image/encrypt", response_model=schemas.ImageEncryptResponse)
async def encrypt_image(
    mode: str = Form(...),
    key_hex: str = Form(...),
    file: UploadFile = File(...),
    sbox_json: Optional[str] = Form(None)
):
    sbox = _resolve_sbox_from_form(mode, sbox_json)

    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="File harus berupa gambar")

    contents = await file.read()
    original_image = Image.open(io.BytesIO(contents)).convert("RGB")
    width, height = original_image.size
    
    # Ambil raw bytes dari pixel
    img_array = np.array(original_image)
    flat_bytes = img_array.tobytes()
    
    key = derive_key_from_input(key_hex)

    # --- 1. ENKRIPSI UTAMA (Ciphertext 1) ---
    # Gunakan AES Padding (PKCS7) karena AES bekerja per blok 16-byte
    # Gunakan use_padding=True agar aes_core melakukan padding otomatis
    encrypted_bytes = aes_encrypt_ecb(flat_bytes, key, sbox, use_padding=True)
    
    # --- 2. ANALISIS DIFFERENTIAL (Ciphertext 2) ---
    # Buat modifikasi 1 pixel pada plaintext
    mod_flat_bytes = bytearray(flat_bytes)
    if len(mod_flat_bytes) > 0:
        mod_flat_bytes[0] = (mod_flat_bytes[0] + 1) % 256 # Ubah 1 nilai byte
    
    # Enkripsi plaintext modifikasi
    encrypted_bytes_2 = aes_encrypt_ecb(bytes(mod_flat_bytes), key, sbox, use_padding=True)
    
    # Hitung NPCR & UACI (C1 vs C2)
    npcr_uaci = calculate_npcr_uaci_bytes(encrypted_bytes, encrypted_bytes_2)

    # --- 3. PEMBUATAN GAMBAR VISUALISASI ---
    # Karena padding, ukuran data bertambah. Kita perlu menyesuaikan ukuran gambar hasil.
    # Hitung pixel yang dibutuhkan untuk menampung semua encrypted bytes
    total_bytes = len(encrypted_bytes)
    pixels_needed = math.ceil(total_bytes / 3)
    
    # Kita pertahankan width, sesuaikan height
    new_height = math.ceil(pixels_needed / width)
    
    # Buat array baru dengan padding visual (0xFF) untuk mengisi pixel terakhir
    # Gunakan 0xFF bukan 0x00 agar mudah dibedakan dari ciphertext saat dekripsi
    vis_array_len = new_height * width * 3
    vis_bytes = bytearray(encrypted_bytes)
    # Simpan panjang ciphertext asli di 4 byte pertama visual padding
    padding_len = vis_array_len - total_bytes
    if padding_len > 0:
        # Encode total_bytes sebagai 4-byte integer di awal visual padding
        vis_bytes.extend(total_bytes.to_bytes(4, 'big'))
        # Sisanya diisi 0xFF
        vis_bytes.extend(b'\xFF' * (padding_len - 4))
    
    vis_array = np.frombuffer(vis_bytes, dtype=np.uint8).reshape((new_height, width, 3))
    encrypted_image_vis = Image.fromarray(vis_array, "RGB")

    # Simpan sebagai PNG
    buffer = io.BytesIO()
    encrypted_image_vis.save(buffer, format="PNG", compress_level=9)
    buffer.seek(0)
    encrypted_base64 = base64.b64encode(buffer.getvalue()).decode()

    # Hitung metrik lain
    orig_entropy = calculate_image_entropy(original_image)
    enc_entropy = calculate_image_entropy(encrypted_image_vis)
    
    # Histogram
    orig_hist = {
        "R": np.histogram(img_array[:,:,0], bins=256, range=(0,256))[0].tolist(),
        "G": np.histogram(img_array[:,:,1], bins=256, range=(0,256))[0].tolist(),
        "B": np.histogram(img_array[:,:,2], bins=256, range=(0,256))[0].tolist()
    }
    enc_hist = {
        "R": np.histogram(vis_array[:,:,0], bins=256, range=(0,256))[0].tolist(),
        "G": np.histogram(vis_array[:,:,1], bins=256, range=(0,256))[0].tolist(),
        "B": np.histogram(vis_array[:,:,2], bins=256, range=(0,256))[0].tolist()
    }

    return {
        "encrypted_image_base64": encrypted_base64,
        "original_entropy": round(orig_entropy, 4),
        "encrypted_entropy": round(enc_entropy, 4),
        "npcr": round(npcr_uaci["npcr"], 4),
        "uaci": round(npcr_uaci["uaci"], 4),
        "npr": 0, # Redundant dengan NPCR
        "original_histogram": orig_hist,
        "encrypted_histogram": enc_hist,
        "used_mode": mode,
        "image_size": {"width": width, "height": new_height}
    }

@app.post("/image/decrypt", response_model=schemas.ImageDecryptResponse)
async def decrypt_image(
    mode: str = Form(...),
    key_hex: str = Form(...),
    file: UploadFile = File(...),
    sbox_json: Optional[str] = Form(None)
):
    sbox = _resolve_sbox_from_form(mode, sbox_json)
    
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="File harus berupa gambar")
    
    key = derive_key_from_input(key_hex)
    inv_sbox = build_inv_sbox(sbox)

    contents = await file.read()
    enc_image = Image.open(io.BytesIO(contents)).convert("RGB")
    width = enc_image.width
    
    # Ambil bytes dari gambar terenkripsi
    enc_array = np.array(enc_image)
    enc_bytes_with_visual_padding = enc_array.tobytes()
    
    # --- PROSES DEKRIPSI ---
    # 1. Ekstrak ciphertext asli dari visual padding
    # Cari metadata panjang ciphertext (4 byte di posisi setelah ciphertext)
    # Coba deteksi panjang ciphertext yang valid (kelipatan 16)
    
    # Strategi: Cari dari belakang untuk menemukan blok yang valid
    # Visual padding menggunakan 0xFF, jadi cari transisi dari data ke 0xFF
    max_valid_len = (len(enc_bytes_with_visual_padding) // 16) * 16
    
    # Coba ekstrak 4 byte metadata dari area padding
    ciphertext = None
    for test_len in range(max_valid_len, 15, -16):  # Test setiap kelipatan 16
        if test_len + 4 <= len(enc_bytes_with_visual_padding):
            # Baca 4 byte metadata
            try:
                stored_len = int.from_bytes(enc_bytes_with_visual_padding[test_len:test_len+4], 'big')
                if stored_len == test_len and stored_len % 16 == 0:
                    # Metadata cocok! Ini adalah panjang ciphertext yang benar
                    ciphertext = enc_bytes_with_visual_padding[:stored_len]
                    break
            except:
                pass
    
    # Fallback: Jika tidak menemukan metadata, gunakan seluruh data yang valid (kelipatan 16)
    if ciphertext is None:
        # Hapus trailing 0xFF (visual padding lama) atau 0x00
        enc_bytes_trimmed = enc_bytes_with_visual_padding.rstrip(b'\xFF').rstrip(b'\x00')
        valid_len = (len(enc_bytes_trimmed) // 16) * 16
        if valid_len == 0:
            raise HTTPException(status_code=400, detail="Ciphertext tidak valid atau kosong")
        ciphertext = enc_bytes_trimmed[:valid_len]
    
    # 2. Dekripsi menggunakan AES (aes_decrypt_ecb akan handle PKCS7 unpadding)
    try:
        decrypted_bytes = aes_decrypt_ecb(ciphertext, key, sbox, inv_sbox, use_padding=True)
    except ValueError as e:
         raise HTTPException(status_code=400, detail=f"Dekripsi gagal: {str(e)} (Cek Key/S-Box)")

    # 3. Rekonstruksi Gambar Asli
    # Kita perlu tahu dimensi asli. Karena stateless, kita estimasi height dari jumlah pixel.
    total_pixels = len(decrypted_bytes) // 3
    original_height = total_pixels // width
    
    # Reshape
    try:
        dec_array = np.frombuffer(decrypted_bytes, dtype=np.uint8).reshape((original_height, width, 3))
        decrypted_image = Image.fromarray(dec_array, "RGB")
    except ValueError:
         # Fallback jika dimensi tidak pas (misal karena width berubah/crop)
         raise HTTPException(status_code=400, detail="Gagal merekonstruksi dimensi gambar asli.")

    buffer = io.BytesIO()
    decrypted_image.save(buffer, format="PNG", compress_level=9)
    buffer.seek(0)
    decrypted_base64 = base64.b64encode(buffer.getvalue()).decode()

    return {
        "decrypted_image_base64": decrypted_base64,
        "used_mode": mode
    }

# --- S-Box Generation/Upload Endpoints ---

def apply_affine_transform(val_byte: int, matrix: list[list[int]], constant: int) -> int:
    bits = [(val_byte >> i) & 1 for i in range(8)]
    new_bits = [0] * 8
    for row in range(8):
        acc = 0
        for col in range(8):
            acc ^= (matrix[row][col] & bits[col])
        new_bits[row] = acc
    res = 0
    for i in range(8):
        res |= (new_bits[i] << i)
    return res ^ constant

def random_invertible_matrix_8() -> list[list[int]]:
    rng = secrets.SystemRandom()
    mat = [[1 if i == j else 0 for j in range(8)] for i in range(8)]
    for _ in range(32):
        i = rng.randrange(8)
        j = rng.randrange(8)
        if i == j: continue
        if rng.randrange(2) == 0:
            mat[i], mat[j] = mat[j], mat[i]
        else:
            mat[i] = [a ^ b for a, b in zip(mat[i], mat[j])]
    return mat

@app.get("/sbox/generate", response_model=schemas.SBoxGenerateResponse)
def sbox_generate():
    affine_matrix = random_invertible_matrix_8()
    generated_sbox = []
    for x in range(256):
        inv_val = AES_INVERSE_TABLE[x]
        val = apply_affine_transform(inv_val, affine_matrix, 0x63)
        generated_sbox.append(val)
    metrics = analyze_sbox(generated_sbox)
    return schemas.SBoxGenerateResponse(
        sbox=generated_sbox,
        metrics=schemas.SBoxMetricsResponse(**metrics),
        affine_matrix=affine_matrix,
    )

@app.post("/sbox/upload", response_model=schemas.SBoxUploadResponse)
async def sbox_upload(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".json"):
        raise HTTPException(status_code=400, detail="File harus berformat .json")
    try:
        raw = await file.read()
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Gagal membaca/parse JSON")

    if isinstance(data, list):
        sbox = data
    elif isinstance(data, dict) and "sbox" in data:
        sbox = data.get("sbox")
    else:
        raise HTTPException(status_code=400, detail="JSON harus berupa array atau object dengan key 'sbox'")

    if not validate_sbox(sbox):
        raise HTTPException(status_code=400, detail="sbox tidak valid (harus permutasi unik 0..255)")

    metrics = analyze_sbox(sbox)
    return schemas.SBoxUploadResponse(sbox=sbox, metrics=schemas.SBoxMetricsResponse(**metrics))

@app.post("/sbox/upload_json", response_model=schemas.SBoxUploadResponse)
async def sbox_upload_json(data: dict):
    if isinstance(data, list):
        sbox = data
    elif isinstance(data, dict) and "sbox" in data:
        sbox = data.get("sbox")
    else:
        raise HTTPException(status_code=400, detail="Data harus berupa array atau object dengan key 'sbox'")

    if not validate_sbox(sbox):
        raise HTTPException(status_code=400, detail="sbox tidak valid (harus permutasi unik 0..255)")

    metrics = analyze_sbox(sbox)
    return schemas.SBoxUploadResponse(sbox=sbox, metrics=schemas.SBoxMetricsResponse(**metrics))