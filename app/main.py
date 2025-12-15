from __future__ import annotations

import json
import secrets

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

from . import schemas
from .aes_core import (
    AES_INVERSE_TABLE,
    AES_STANDARD_SBOX,
    derive_key_from_input,
    decrypt_hex_to_text,
    encrypt_text_to_hex,
    validate_sbox,
)
from .sbox_metrics import analyze_sbox

app = FastAPI(
    title="AES Custom S-Box API",
    version="0.1.0",
    description="Backend untuk enkripsi AES dengan S-Box standard & custom.",
)

# Biar frontend beda origin bisa akses
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # nanti bisa dipersempit
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
    if mode == "custom":
        if sbox is None:
            raise HTTPException(status_code=400, detail="sbox wajib diisi untuk mode custom")
        if not validate_sbox(sbox):
            raise HTTPException(status_code=400, detail="sbox tidak valid (harus permutasi 0..255)")
        return sbox
    raise HTTPException(status_code=400, detail="mode harus 'standard' atau 'custom'")


def _resolve_sbox_from_form(mode: str, sbox_json: str | None) -> list[int]:
    if mode == "standard":
        return AES_STANDARD_SBOX
    if mode != "custom":
        raise HTTPException(status_code=400, detail="mode harus 'standard' atau 'custom'")
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
    # pilih plaintext
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

    # pilih S-Box
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
    # pilih S-Box
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
    """
    Generate matriks 8x8 invertible di GF(2) dengan operasi baris acak.
    Mulai dari identity lalu swap/XOR baris.
    """
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

def apply_affine_transform(val_byte: int, matrix: list[list[int]], constant: int) -> int:
    """
    Melakukan transformasi Affine: A * x + c
    val_byte: nilai input (dari tabel invers)
    matrix: matriks 8x8 (list of lists)
    constant: konstanta 8-bit (misal 0x63)
    """
    # 1. Ubah byte ke bits (LSB first atau MSB first tergantung konvensi matriks)
    # Standar AES biasanya melihat bit sebagai vektor kolom [b0, b1, ..., b7]
    bits = [(val_byte >> i) & 1 for i in range(8)]
    
    new_bits = [0] * 8
    
    # 2. Perkalian Matriks (GF(2) -> XOR)
    for row in range(8):
        acc = 0
        for col in range(8):
            # Matriks dikali vektor bits
            acc ^= (matrix[row][col] & bits[col])
        new_bits[row] = acc
    
    # 3. Ubah kembali bits ke integer
    res = 0
    for i in range(8):
        res |= (new_bits[i] << i)
    
    # 4. Tambahkan (XOR) konstanta
    return res ^ constant

@app.get("/sbox/generate", response_model=schemas.SBoxGenerateResponse)
def sbox_generate():
    # 1. Generate Matriks Affine Acak (Eksplorasi sesuai paper)
    # Paper mencoba miliaran matriks, kita coba generate satu yang random invertible
    affine_matrix = random_invertible_matrix_8()
    
    # 2. Konstruksi S-box menggunakan Invers + Affine
    # S[x] = Affine(Invers[x])
    generated_sbox = []
    for x in range(256):
        # Ambil nilai invers
        inv_val = AES_INVERSE_TABLE[x]
        
        # Lakukan transformasi affine
        # Menggunakan konstanta standar 0x63 seperti di paper (C_AES)
        val = apply_affine_transform(inv_val, affine_matrix, 0x63)
        generated_sbox.append(val)
    
    # 3. Hitung Metrics
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
