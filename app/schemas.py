from typing import List, Optional
from pydantic import BaseModel, Field


class EncryptMode(str):
    STANDARD = "standard"
    CUSTOM = "custom"


class EncryptRequest(BaseModel):
    mode: str = Field(..., description="standard atau custom")
    key_hex: str = Field(..., description="kunci input (teks bebas atau 32 char hex)")
    plaintext: Optional[str] = Field(
        None,
        description="plaintext dalam bentuk string biasa, akan di-encode UTF-8",
    )
    plaintext_hex: Optional[str] = Field(
        None,
        description="opsional: plaintext langsung dalam hex",
    )
    sbox: Optional[List[int]] = Field(
        None,
        description="list 256 angka 0-255 untuk custom S-Box (wajib kalau mode=custom)",
    )


class EncryptResponse(BaseModel):
    ciphertext_hex: str
    used_mode: str
    plaintext_len: int


class SBoxMetricsRequest(BaseModel):
    sbox: List[int]


class SBoxMetricsResponse(BaseModel):
    nl_min: float
    sac_avg: float
    bic_nl_min: float
    bic_sac_score: float
    lap_max_bias: float
    du: int
    dap_max: float
    ad_min: int
    to_value: float
    ci_min: int


class SBoxGenerateResponse(BaseModel):
    sbox: List[int]
    metrics: SBoxMetricsResponse
    affine_matrix: List[List[int]]

# --- Tambahkan ini ---
class SBoxUploadResponse(BaseModel):
    sbox: List[int]
    metrics: SBoxMetricsResponse
# ---------------------

class DecryptRequest(BaseModel):
    mode: str = Field(..., description="standard atau custom")
    key_hex: str = Field(..., description="kunci input (teks bebas atau 32 char hex)")
    ciphertext_hex: str = Field(..., description="ciphertext dalam hex (hasil encrypt)")
    sbox: Optional[List[int]] = Field(
        None,
        description="list 256 angka 0-255 untuk custom S-Box (wajib kalau mode=custom)",
    )


class DecryptResponse(BaseModel):
    plaintext: str
    plaintext_hex: str
    used_mode: str