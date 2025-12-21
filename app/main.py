from __future__ import annotations

import json
import secrets
import hashlib
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
    build_inv_sbox
)
from .sbox_metrics import analyze_sbox

app = FastAPI(
    title="AES Custom S-Box API",
    version="0.2.0",
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


def _resolve_sbox_from_body(mode: str, sbox: list[int] | None) -> list[int]:
    if mode == "standard":
        return AES_STANDARD_SBOX
    if mode == "sbox44":  # ← TAMBAHKAN INI
        return SBOX_44
    if mode == "custom":
        if sbox is None:
            raise HTTPException(status_code=400, detail="sbox wajib diisi untuk mode custom")
        if not validate_sbox(sbox):
            raise HTTPException(status_code=400, detail="sbox tidak valid (harus permutasi 0..255)")
        return sbox
    raise HTTPException(status_code=400, detail="mode harus 'standard', 'sbox44', atau 'custom'")  # ← UPDATE ERROR MESSAGE


def _resolve_sbox_from_form(mode: str, sbox_json: str | None) -> list[int]:
    if mode == "standard":
        return AES_STANDARD_SBOX
    if mode == "sbox44":  # ← TAMBAHKAN INI
        return SBOX_44
    if mode != "custom":
        raise HTTPException(status_code=400, detail="mode harus 'standard', 'sbox44', atau 'custom'")  # ← UPDATE ERROR MESSAGE
    if not sbox_json:
        raise HTTPException(status_code=400, detail="sbox_json wajib diisi untuk mode custom")
    try:
        parsed = json.loads(sbox_json)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="sbox_json bukan JSON yang valid")
    if not validate_sbox(parsed):
        raise HTTPException(status_code=400, detail="sbox tidak valid (harus permutasi 0..255)")
    return parsed


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


@app.get("/sbox/paper44", response_model=schemas.SBoxPaper44Response)
def get_sbox_44():
    """Endpoint untuk mendapatkan S-box 44 dari paper beserta metriknya"""
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
    """Endpoint untuk mendapatkan S-box AES standard beserta metriknya"""
    metrics = analyze_sbox(AES_STANDARD_SBOX)
    return schemas.SBoxStandardResponse(
        sbox=AES_STANDARD_SBOX,
        metrics=schemas.SBoxMetricsResponse(**metrics),
        affine_matrix=None  # AES standard tidak menggunakan affine matrix custom
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


def random_invertible_matrix_8() -> list[list[int]]:
    rng = secrets.SystemRandom()
    mat = [[1 if i == j else 0 for j in range(8)] for i in range(8)]
    for _ in range(32):
        i = rng.randrange(8)
        j = rng.randrange(8)
        if i == j:
            continue
        if rng.randrange(2) == 0:
            mat[i], mat[j] = mat[j], mat[i]
        else:
            mat[i] = [a ^ b for a, b in zip(mat[i], mat[j])]
    return mat


AES_CONSTANT_C = 0x63
def calculate_image_entropy(image: Image.Image) -> float:
    """
    Hitung entropy gambar sesuai paper:
    H(X) = -Sigma p(xi) log2(p(xi))
    di mana p(xi) adalah probabilitas kemunculan pixel dengan intensitas xi
    """
    img_array = np.array(image)
    
    # Untuk gambar RGB, hitung entropy untuk setiap channel
    if len(img_array.shape) == 3:
        entropies = []
        for channel in range(img_array.shape[2]):
            channel_data = img_array[:, :, channel].flatten()
            histogram, _ = np.histogram(channel_data, bins=256, range=(0, 256))
            histogram = histogram[histogram > 0]  # Hapus bins dengan nilai 0
            probabilities = histogram / histogram.sum()
            entropy = -np.sum(probabilities * np.log2(probabilities))
            entropies.append(entropy)
        return np.mean(entropies)  # Rata-rata entropy dari semua channel
    else:
        # Untuk grayscale
        channel_data = img_array.flatten()
        histogram, _ = np.histogram(channel_data, bins=256, range=(0, 256))
        histogram = histogram[histogram > 0]
        probabilities = histogram / histogram.sum()
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return entropy

def calculate_npcr_uaci(orig_img: Image.Image, enc_img: Image.Image) -> Dict[str, float]:
    """
    Hitung NPCR dan UACI sesuai paper:
    
    NPCR (Number of Pixels Change Rate):
    NPCR = (Sigma D(i,j) / (M x N)) x 100%
    di mana D(i,j) = 0 jika C1(i,j) = C2(i,j), dan D(i,j) = 1 jika C1(i,j) != C2(i,j)
    
    UACI (Unified Average Changing Intensity):
    UACI = (1/(M x N)) x Sigma |C1(i,j) - C2(i,j)| / 255 x 100%
    
    Nilai ideal: NPCR sekitar 99.6094%, UACI sekitar 33.4635%
    """
    orig_array = np.array(orig_img, dtype=np.float64)
    enc_array = np.array(enc_img, dtype=np.float64)
    
    if orig_array.shape != enc_array.shape:
        raise ValueError("Ukuran gambar tidak sama")
    
    # NPCR: persentase pixel yang berubah
    diff = (orig_array != enc_array).astype(np.float64)
    total_pixels = diff.size
    npcr_val = (np.sum(diff) / total_pixels) * 100.0
    
    # UACI: rata-rata intensitas perubahan
    intensity_diff = np.abs(orig_array - enc_array)
    uaci_val = (np.sum(intensity_diff) / (255.0 * total_pixels)) * 100.0
    
    return {"npcr": npcr_val, "uaci": uaci_val}

def calculate_npr(orig_img: Image.Image, enc_img: Image.Image) -> float:
    """
    Hitung NPR (Number of Pixel Rate) - sama dengan NPCR tapi dalam konteks berbeda
    NPR = (jumlah pixel yang berubah / total pixel) * 100%
    Nilai ideal: mendekati 100%
    """
    orig_array = np.array(orig_img, dtype=np.uint8)
    enc_array = np.array(enc_img, dtype=np.uint8)
    
    if orig_array.shape != enc_array.shape:
        raise ValueError("Ukuran gambar tidak sama")
    
    # Hitung jumlah pixel yang berubah
    changed = np.sum(orig_array != enc_array)
    total = orig_array.size
    
    return (changed / total) * 100.0

def image_encrypt_pixels(image: Image.Image, key: bytes, sbox: list[int]):
    """
    Enkripsi gambar menggunakan S-box substitution dengan key stream
    - Menggunakan S-box AES atau S-box 44 dari paper
    - Cepat dengan hasil full noise
    """
    img_array = np.array(image, dtype=np.uint8)
    shape = img_array.shape
    
    # Flatten array menjadi bytes
    flat_bytes = bytearray(img_array.tobytes())
    original_length = len(flat_bytes)
    
    # Generate key stream dari key menggunakan SHA256 (deterministic)
    hash_obj = hashlib.sha256(key)
    key_stream = bytearray()
    while len(key_stream) < original_length:
        key_stream.extend(hash_obj.digest())
        hash_obj = hashlib.sha256(key_stream[-32:])
    
    # Enkripsi menggunakan S-box substitution + XOR
    # Setiap byte: cipher[i] = sbox[(plain[i] ^ key[i % 256])]
    cipher_bytes = bytearray(original_length)
    for i in range(original_length):
        xored_val = flat_bytes[i] ^ key_stream[i]
        cipher_bytes[i] = sbox[xored_val]  # Substitusi dengan S-box
    
    # Reshape kembali ke gambar dengan ukuran SAMA
    cipher_array = np.frombuffer(cipher_bytes, dtype=np.uint8)
    cipher_array = cipher_array.reshape(shape)

    return Image.fromarray(cipher_array, mode="RGB")





def image_decrypt_pixels(enc_image: Image.Image, key: bytes, sbox: list[int]):
    """
    Dekripsi gambar - reverse dari S-box substitution + XOR
    """
    enc_array = np.array(enc_image, dtype=np.uint8)
    shape = enc_array.shape
    
    # Flatten encrypted bytes
    flat_bytes = bytearray(enc_array.tobytes())
    original_length = len(flat_bytes)
    
    # Generate key stream (harus sama dengan encryption)
    hash_obj = hashlib.sha256(key)
    key_stream = bytearray()
    while len(key_stream) < original_length:
        key_stream.extend(hash_obj.digest())
        hash_obj = hashlib.sha256(key_stream[-32:])
    
    # Buat inverse S-box
    inv_sbox = [0] * 256
    for i, val in enumerate(sbox):
        inv_sbox[val] = i
    
    # Dekripsi: plain[i] = inv_sbox[cipher[i]] ^ key[i]
    plain_bytes = bytearray(original_length)
    for i in range(original_length):
        sbox_inverted = inv_sbox[flat_bytes[i]]
        plain_bytes[i] = sbox_inverted ^ key_stream[i]
    
    # Reshape ke gambar
    plain_array = np.frombuffer(plain_bytes, dtype=np.uint8)
    plain_array = plain_array.reshape(shape)

    return Image.fromarray(plain_array, mode="RGB")





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

    key = derive_key_from_input(key_hex)

    # 🔥 ENKRIPSI SESUAI PAPER
    encrypted_image = image_encrypt_pixels(original_image, key, sbox)

    # Simpan encrypted image sebagai PNG (lossless) untuk memastikan bisa didekripsi sempurna
    # Catatan: JPEG bersifat lossy sehingga akan merusak nilai piksel terenkripsi dan mengganggu dekripsi.
    buffer = io.BytesIO()
    encrypted_image.save(buffer, format="PNG", compress_level=9)
    
    buffer.seek(0)  # PENTING: Seek ke awal sebelum getvalue
    encrypted_base64 = base64.b64encode(buffer.getvalue()).decode()

    # 🔬 HITUNG METRIK - ORIGINAL DAN ENCRYPTED
    # Original image metrics
    orig_entropy = calculate_image_entropy(original_image)
    orig_array = np.array(original_image, dtype=np.uint8)
    # Histogram dengan R, G, B channels terpisah
    orig_hist_r = np.histogram(orig_array[:, :, 0].flatten(), bins=256, range=(0, 256))[0].tolist()
    orig_hist_g = np.histogram(orig_array[:, :, 1].flatten(), bins=256, range=(0, 256))[0].tolist()
    orig_hist_b = np.histogram(orig_array[:, :, 2].flatten(), bins=256, range=(0, 256))[0].tolist()
    orig_hist = {"R": orig_hist_r, "G": orig_hist_g, "B": orig_hist_b}
    
    # Encrypted image metrics
    enc_entropy = calculate_image_entropy(encrypted_image)
    enc_array = np.array(encrypted_image, dtype=np.uint8)
    # Histogram dengan R, G, B channels terpisah
    enc_hist_r = np.histogram(enc_array[:, :, 0].flatten(), bins=256, range=(0, 256))[0].tolist()
    enc_hist_g = np.histogram(enc_array[:, :, 1].flatten(), bins=256, range=(0, 256))[0].tolist()
    enc_hist_b = np.histogram(enc_array[:, :, 2].flatten(), bins=256, range=(0, 256))[0].tolist()
    enc_hist = {"R": enc_hist_r, "G": enc_hist_g, "B": enc_hist_b}
    
    # Comparison metrics
    npcr_uaci = calculate_npcr_uaci(original_image, encrypted_image)
    npr_val = calculate_npr(original_image, encrypted_image)

    return {
        "encrypted_image_base64": encrypted_base64,
        "original_entropy": round(orig_entropy, 4),
        "encrypted_entropy": round(enc_entropy, 4),
        "npcr": round(npcr_uaci["npcr"], 4),
        "uaci": round(npcr_uaci["uaci"], 4),
        "npr": round(npr_val, 4),
        "original_histogram": orig_hist,
        "encrypted_histogram": enc_hist,
        "used_mode": mode,
        "image_size": {
            "width": original_image.width,
            "height": original_image.height
        }
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

    contents = await file.read()
    enc_image = Image.open(io.BytesIO(contents)).convert("RGB")

    decrypted_image = image_decrypt_pixels(enc_image, key, sbox)

    # Simpan hasil dekripsi sebagai PNG (lossless) agar sesuai piksel asli
    buffer = io.BytesIO()
    decrypted_image.save(buffer, format="PNG", compress_level=9)
    buffer.seek(0)  # PENTING: Seek ke awal sebelum getvalue
    decrypted_base64 = base64.b64encode(buffer.getvalue()).decode()

    return {
        "decrypted_image_base64": decrypted_base64,
        "used_mode": mode
    }



def apply_affine_transform(val_byte: int, matrix: list[list[int]], constant: int) -> int:
    """Transformasi affine untuk generate S-box custom"""
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