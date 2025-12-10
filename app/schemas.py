from typing import List, Optional
from pydantic import BaseModel, Field


class EncryptMode(str):
    STANDARD = "standard"
    CUSTOM = "custom"


class EncryptRequest(BaseModel):
    mode: str = Field(..., description="standard atau custom")
    key_hex: str = Field(..., description="kunci AES 128-bit dalam hex (32 char)")
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
    ad_min: int
    to_value: float
    ci_min: int
