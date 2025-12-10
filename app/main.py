from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from . import schemas
from .aes_core import encrypt_text_to_hex, AES_STANDARD_SBOX, validate_sbox

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
    if req.mode == "standard":
        sbox = AES_STANDARD_SBOX
    elif req.mode == "custom":
        if req.sbox is None:
            raise HTTPException(status_code=400, detail="sbox wajib diisi untuk mode custom")
        if not validate_sbox(req.sbox):
            raise HTTPException(status_code=400, detail="sbox tidak valid (harus permutasi 0..255)")
        sbox = req.sbox
    else:
        raise HTTPException(status_code=400, detail="mode harus 'standard' atau 'custom'")

    try:
        ciphertext_hex = encrypt_text_to_hex(plaintext_str, req.key_hex, sbox)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return schemas.EncryptResponse(
        ciphertext_hex=ciphertext_hex,
        used_mode=req.mode,
        plaintext_len=len(plaintext_str.encode("utf-8")),
    )
