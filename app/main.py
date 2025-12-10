from __future__ import annotations

import json

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware

from . import schemas
from .aes_core import (
    AES_STANDARD_SBOX,
    aes_encrypt_ecb,
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


@app.post("/encrypt-file", response_model=schemas.EncryptFileResponse)
async def encrypt_file(
    mode: str = Form(...),
    key_hex: str = Form(...),
    file: UploadFile = File(...),
    sbox_json: str | None = Form(None),
):
    sbox = _resolve_sbox_from_form(mode, sbox_json)

    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        raise HTTPException(status_code=400, detail="key_hex bukan hex yang valid")
    if len(key) != 16:
        raise HTTPException(status_code=400, detail="Key harus 128-bit (16 byte, 32 hex char)")

    data = await file.read()
    ct_bytes = aes_encrypt_ecb(data, key, sbox)
    return {
        "filename": file.filename,
        "size_plain": len(data),
        "size_cipher": len(ct_bytes),
        "ciphertext_hex": ct_bytes.hex(),
    }


@app.post("/sbox/metrics", response_model=schemas.SBoxMetricsResponse)
def sbox_metrics(req: schemas.SBoxMetricsRequest):
    if not validate_sbox(req.sbox):
        raise HTTPException(status_code=400, detail="sbox tidak valid (harus permutasi 0..255)")
    try:
        metrics = analyze_sbox(req.sbox)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return schemas.SBoxMetricsResponse(**metrics)
