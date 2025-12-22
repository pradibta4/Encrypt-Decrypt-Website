from __future__ import annotations

import hashlib
from typing import List

AES_STANDARD_SBOX: List[int] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

# S-box 44 dari paper - hasil terbaik dengan metrik superior
SBOX_44: List[int] = [
    99, 205, 85, 71, 25, 127, 113, 219, 63, 244, 109, 159, 11, 228, 94, 214,
    77, 177, 201, 78, 5, 48, 29, 30, 87, 96, 193, 80, 156, 200, 216, 86,
    116, 143, 10, 14, 54, 169, 148, 68, 49, 75, 171, 157, 92, 114, 188, 194,
    121, 220, 131, 210, 83, 135, 250, 149, 253, 72, 182, 33, 190, 141, 249, 82,
    232, 50, 21, 84, 215, 242, 180, 198, 168, 167, 103, 122, 152, 162, 145, 184,
    43, 237, 119, 183, 7, 12, 125, 55, 252, 206, 235, 160, 140, 133, 179, 192,
    110, 176, 221, 134, 19, 6, 187, 59, 26, 129, 112, 73, 175, 45, 24, 218,
    44, 66, 151, 32, 137, 31, 35, 147, 236, 247, 117, 132, 79, 136, 154, 105,
    199, 101, 203, 52, 57, 4, 153, 197, 88, 76, 202, 174, 233, 62, 208, 91,
    231, 53, 1, 124, 0, 28, 142, 170, 158, 51, 226, 65, 123, 186, 239, 246,
    38, 56, 36, 108, 8, 126, 9, 189, 81, 234, 212, 224, 13, 3, 40, 64,
    172, 74, 181, 118, 39, 227, 130, 89, 245, 166, 16, 61, 106, 196, 211, 107,
    229, 195, 138, 18, 93, 207, 240, 95, 58, 255, 209, 217, 15, 111, 46, 173,
    223, 42, 115, 238, 139, 243, 23, 98, 100, 178, 37, 97, 191, 213, 222, 155,
    165, 2, 146, 204, 120, 241, 163, 128, 22, 90, 60, 185, 67, 34, 27, 248,
    164, 69, 41, 230, 104, 47, 144, 251, 20, 17, 150, 225, 254, 161, 102, 70
]

AES_INVERSE_TABLE = [
    0x00, 0x01, 0x8d, 0xf6, 0xcb, 0x52, 0x7b, 0xd1, 0xe8, 0x4f, 0x29, 0xc0, 0xb0, 0xe1, 0xe5, 0xc7,
    0x74, 0xb4, 0xaa, 0x4b, 0x99, 0x2b, 0x60, 0x5f, 0x58, 0x3f, 0xfd, 0xcc, 0xff, 0x40, 0xee, 0xb2,
    0x3a, 0x6e, 0x5a, 0xf1, 0x55, 0x4d, 0xa8, 0xc9, 0xc1, 0x0a, 0x98, 0x15, 0x30, 0x44, 0xa2, 0xc2,
    0x2c, 0x45, 0x92, 0x6c, 0xf3, 0x39, 0x66, 0x42, 0xf2, 0x35, 0x20, 0x6f, 0x77, 0xbb, 0x59, 0x19,
    0x1d, 0xfe, 0x37, 0x67, 0x2d, 0x31, 0xf5, 0x69, 0xa7, 0x64, 0xab, 0x13, 0x54, 0x25, 0xe9, 0x09,
    0xed, 0x5c, 0x05, 0xca, 0x4c, 0x24, 0x87, 0xbf, 0x18, 0x3e, 0x22, 0xf0, 0x51, 0xec, 0x61, 0x17,
    0x16, 0x5e, 0xaf, 0xd3, 0x49, 0xa6, 0x36, 0x43, 0xf4, 0x47, 0x91, 0xdf, 0x33, 0x93, 0x21, 0x3b,
    0x79, 0xb7, 0x97, 0x85, 0x10, 0xb5, 0xba, 0x3c, 0xb6, 0x70, 0xd0, 0x06, 0xa1, 0xfa, 0x81, 0x82,
    0x83, 0x7e, 0x7f, 0x80, 0x96, 0x73, 0xbe, 0x56, 0x9b, 0x9e, 0x95, 0xd9, 0xf7, 0x02, 0xb9, 0xa4,
    0xde, 0x6a, 0x32, 0x6d, 0xd8, 0x8a, 0x84, 0x72, 0x2a, 0x14, 0x9f, 0x88, 0xf9, 0xdc, 0x89, 0x9a,
    0xfb, 0x7c, 0x2e, 0xc3, 0x8f, 0xb8, 0x65, 0x48, 0x26, 0xc8, 0x12, 0x4a, 0xce, 0xe7, 0xd2, 0x62,
    0x0c, 0xe0, 0x1f, 0xef, 0x11, 0x75, 0x78, 0x71, 0xa5, 0x8e, 0x76, 0x3d, 0xbd, 0xbc, 0x86, 0x57,
    0x0b, 0x28, 0x2f, 0xa3, 0xda, 0xd4, 0xe4, 0x0f, 0xa9, 0x27, 0x53, 0x04, 0x1b, 0xfc, 0xac, 0xe6,
    0x7a, 0x07, 0xae, 0x63, 0xc5, 0xdb, 0xe2, 0xea, 0x94, 0x8b, 0xc4, 0xd5, 0x9d, 0xf8, 0x90, 0x6b,
    0xb1, 0x0d, 0xd6, 0xeb, 0xc6, 0x0e, 0xcf, 0xad, 0x08, 0x4e, 0xd7, 0xe3, 0x5d, 0x50, 0x1e, 0xb3,
    0x5b, 0x23, 0x38, 0x34, 0x68, 0x46, 0x03, 0x8c, 0xdd, 0x9c, 0x7d, 0xa0, 0xcd, 0x1a, 0x41, 0x1c
]

# Affine matrix K44 dari paper
K44_AFFINE_MATRIX = [
    [0, 1, 0, 1, 0, 1, 1, 1],
    [1, 0, 1, 0, 1, 0, 1, 1],
    [1, 1, 0, 1, 0, 1, 0, 1],
    [1, 1, 1, 0, 1, 0, 1, 0],
    [0, 1, 1, 1, 0, 1, 0, 1],
    [1, 0, 1, 1, 1, 0, 1, 0],
    [0, 1, 0, 1, 1, 1, 0, 1],
    [1, 0, 1, 0, 1, 1, 1, 0]
]

NB = 4
NK = 4
NR = 10


def validate_sbox(sbox: List[int]) -> bool:
    if not isinstance(sbox, list):
        return False
    if len(sbox) != 256:
        return False
    try:
        if any((not isinstance(x, int)) or x < 0 or x > 255 for x in sbox):
            return False
    except TypeError:
        return False
    if len(set(sbox)) != 256:
        return False
    return True


def derive_key_from_input(key_input: str) -> bytes:
    key_str = key_input.strip()
    if not key_str:
        raise ValueError("Key tidak boleh kosong")

    try:
        key_bytes = bytes.fromhex(key_str)
        if len(key_bytes) == 16:
            return key_bytes
    except ValueError:
        key_bytes = None

    digest = hashlib.sha256(key_str.encode("utf-8")).digest()
    return digest[:16]


def bytes_to_state(block: bytes) -> List[List[int]]:
    assert len(block) == 16
    return [[block[row + 4 * col] for col in range(4)] for row in range(4)]


def state_to_bytes(state: List[List[int]]) -> bytes:
    out = bytearray(16)
    for row in range(4):
        for col in range(4):
            out[row + 4 * col] = state[row][col]
    return bytes(out)


def sub_bytes(state: List[List[int]], sbox: List[int]) -> List[List[int]]:
    return [[sbox[byte] for byte in row] for row in state]


def shift_rows(state: List[List[int]]) -> List[List[int]]:
    new_state = [row[:] for row in state]
    for r in range(4):
        new_state[r] = state[r][r:] + state[r][:r]
    return new_state


def xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def mix_single_column(col: List[int]) -> List[int]:
    t = col[0] ^ col[1] ^ col[2] ^ col[3]
    u0 = col[0]
    col[0] ^= t ^ xtime(col[0] ^ col[1])
    col[1] ^= t ^ xtime(col[1] ^ col[2])
    col[2] ^= t ^ xtime(col[2] ^ col[3])
    col[3] ^= t ^ xtime(col[3] ^ u0)
    return col


def mix_columns(state: List[List[int]]) -> List[List[int]]:
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        col = mix_single_column(col)
        for r in range(4):
            new_state[r][c] = col[r]
    return new_state


def add_round_key(state: List[List[int]], round_key: List[int]) -> List[List[int]]:
    new_state = [[0] * 4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            new_state[r][c] = state[r][c] ^ round_key[r + 4 * c]
    return new_state


RCON = [
    0x00,
    0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36
]


def rot_word(word: List[int]) -> List[int]:
    return word[1:] + word[:1]


def sub_word(word: List[int], sbox: List[int]) -> List[int]:
    return [sbox[b] for b in word]


def key_expansion(key: bytes, sbox: List[int]) -> List[List[int]]:
    assert len(key) == 16
    w: List[int] = list(key)

    for i in range(NK, NB * (NR + 1)):
        temp = w[4*(i-1):4*i]
        if i % NK == 0:
            temp = rot_word(temp)
            temp = sub_word(temp, sbox)
            temp[0] ^= RCON[i // NK]
        for j in range(4):
            temp[j] ^= w[4*(i-NK) + j]
        w.extend(temp)

    round_keys: List[List[int]] = []
    for r in range(NR + 1):
        rk = w[16*r:16*(r+1)]
        round_keys.append(rk)
    return round_keys


def aes_encrypt_block(block: bytes, key: bytes, sbox: List[int]) -> bytes:
    assert len(block) == 16
    state = bytes_to_state(block)
    round_keys = key_expansion(key, sbox)

    state = add_round_key(state, round_keys[0])

    for rnd in range(1, NR):
        state = sub_bytes(state, sbox)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])

    state = sub_bytes(state, sbox)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[NR])

    return state_to_bytes(state)


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)


def aes_encrypt_ecb(plaintext: bytes, key: bytes, sbox: List[int], use_padding: bool = True) -> bytes:
    """
    AES ECB encryption.
    use_padding=True untuk text encryption (default)
    use_padding=False untuk image encryption (no padding)
    """
    if use_padding:
        plaintext = pkcs7_pad(plaintext, 16)
    
    out = bytearray()
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        if len(block) == 16:  # Only encrypt complete blocks
            out.extend(aes_encrypt_block(block, key, sbox))
    return bytes(out)


def simple_sbox_encrypt(plaintext: bytes, key: bytes, sbox: List[int]) -> bytes:
    """
    Simple stream cipher using S-Box substitution per byte.
    Cocok untuk image encryption tanpa padding.
    
    Enkripsi: c_i = S[p_i XOR k_i]
    Di mana k_i adalah keystream derived dari key.
    """
    key = derive_key_from_input(key) if isinstance(key, str) else key
    keystream = bytearray()
    
    # Generate keystream dengan menggandakan key sesuai panjang plaintext
    plaintext_len = len(plaintext)
    counter = 0
    while len(keystream) < plaintext_len:
        # Hash key dengan counter untuk generate keystream
        counter_bytes = counter.to_bytes(4, 'big')
        keystream.extend(hashlib.sha256(key + counter_bytes).digest())
        counter += 1
    
    keystream = keystream[:plaintext_len]
    
    # Enkripsi: c[i] = sbox[p[i] XOR k[i]]
    ciphertext = bytearray()
    for p_byte, k_byte in zip(plaintext, keystream):
        xor_val = p_byte ^ k_byte
        c_byte = sbox[xor_val]
        ciphertext.append(c_byte)
    
    return bytes(ciphertext)


def simple_sbox_decrypt(ciphertext: bytes, key: bytes, sbox: List[int]) -> bytes:
    """
    Decrypt menggunakan inverse S-Box.
    
    Dekripsi: p_i = (S_inv[c_i]) XOR k_i
    """
    key = derive_key_from_input(key) if isinstance(key, str) else key
    
    # Build inverse S-Box
    inv_sbox = [0] * 256
    for i, val in enumerate(sbox):
        inv_sbox[val] = i
    
    keystream = bytearray()
    ciphertext_len = len(ciphertext)
    counter = 0
    while len(keystream) < ciphertext_len:
        counter_bytes = counter.to_bytes(4, 'big')
        keystream.extend(hashlib.sha256(key + counter_bytes).digest())
        counter += 1
    
    keystream = keystream[:ciphertext_len]
    
    # Dekripsi: p[i] = S_inv[c[i]] XOR k[i]
    plaintext = bytearray()
    for c_byte, k_byte in zip(ciphertext, keystream):
        inv_val = inv_sbox[c_byte]
        p_byte = inv_val ^ k_byte
        plaintext.append(p_byte)
    
    return bytes(plaintext)


def encrypt_text_to_hex(
    plaintext: str,
    key_input: str,
    sbox: List[int] | None = None
) -> str:
    if sbox is None:
        sbox = AES_STANDARD_SBOX

    if not validate_sbox(sbox):
        raise ValueError("S-Box tidak valid (harus permutasi 0..255)")

    key = derive_key_from_input(key_input)

    pt_bytes = plaintext.encode("utf-8")
    ct_bytes = aes_encrypt_ecb(pt_bytes, key, sbox)
    return ct_bytes.hex()


def gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= 0x1B
        b >>= 1
    return p


def inv_shift_rows(state: List[List[int]]) -> List[List[int]]:
    new_state = [row[:] for row in state]
    for r in range(4):
        new_state[r] = state[r][-r:] + state[r][:-r]
    return new_state


def inv_sub_bytes(state: List[List[int]], inv_sbox: List[int]) -> List[List[int]]:
    return [[inv_sbox[byte] for byte in row] for row in state]


def inv_mix_single_column(col: List[int]) -> List[int]:
    s0, s1, s2, s3 = col
    r0 = gmul(s0, 0x0E) ^ gmul(s1, 0x0B) ^ gmul(s2, 0x0D) ^ gmul(s3, 0x09)
    r1 = gmul(s0, 0x09) ^ gmul(s1, 0x0E) ^ gmul(s2, 0x0B) ^ gmul(s3, 0x0D)
    r2 = gmul(s0, 0x0D) ^ gmul(s1, 0x09) ^ gmul(s2, 0x0E) ^ gmul(s3, 0x0B)
    r3 = gmul(s0, 0x0B) ^ gmul(s1, 0x0D) ^ gmul(s2, 0x09) ^ gmul(s3, 0x0E)
    return [r0, r1, r2, r3]


def inv_mix_columns(state: List[List[int]]) -> List[List[int]]:
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        col = inv_mix_single_column(col)
        for r in range(4):
            new_state[r][c] = col[r]
    return new_state


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Data ciphertext tidak kelipatan blok, tidak valid.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Padding tidak valid.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding bytes tidak konsisten.")
    return data[:-pad_len]


def aes_decrypt_block(block: bytes, key: bytes, sbox: List[int], inv_sbox: List[int]) -> bytes:
    assert len(block) == 16
    state = bytes_to_state(block)
    round_keys = key_expansion(key, sbox)

    state = add_round_key(state, round_keys[NR])

    for rnd in range(NR - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state, inv_sbox)
        state = add_round_key(state, round_keys[rnd])
        state = inv_mix_columns(state)

    state = inv_shift_rows(state)
    state = inv_sub_bytes(state, inv_sbox)
    state = add_round_key(state, round_keys[0])

    return state_to_bytes(state)


def aes_decrypt_ecb(ciphertext: bytes, key: bytes, sbox: List[int], inv_sbox: List[int], use_padding: bool = True) -> bytes:
    """
    AES ECB decryption.
    use_padding=True untuk text decryption (default)
    use_padding=False untuk image decryption (no padding)
    """
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext harus kelipatan 16 byte (blok AES).")
    
    out = bytearray()
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        out.extend(aes_decrypt_block(block, key, sbox, inv_sbox))
    
    if use_padding:
        return pkcs7_unpad(bytes(out))
    else:
        return bytes(out)


def build_inv_sbox(sbox: List[int]) -> List[int]:
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return inv


def decrypt_hex_to_text(
    ciphertext_hex: str,
    key_input: str,
    sbox: List[int] | None = None
) -> str:
    if sbox is None:
        sbox = AES_STANDARD_SBOX

    if not validate_sbox(sbox):
        raise ValueError("S-Box tidak valid (harus permutasi 0..255)")

    key = derive_key_from_input(key_input)

    try:
        ct_bytes = bytes.fromhex(ciphertext_hex)
    except ValueError:
        raise ValueError("ciphertext_hex bukan hex yang valid")

    inv_sbox = build_inv_sbox(sbox)
    pt_bytes = aes_decrypt_ecb(ct_bytes, key, sbox, inv_sbox)
    return pt_bytes.decode("utf-8", errors="replace")