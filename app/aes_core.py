from typing import List

# AES standard S-Box (boleh dipakai default)
AES_STANDARD_SBOX: List[int] = [
    # baris ini kamu isi full nanti; sementara placeholder sedikit dulu
    # Biar struktur jalan, bisa diisi nanti dari referensi standar AES.
    # Contoh awal (HARUS 256 elemen total):
    0x63, 0x7c, 0x77, 0x7b,  # ...
] + [0] * (256 - 4)  # placeholder biar panjangnya 256, nanti diganti


NB = 4  # blok AES = 4 kolom (16 byte)
NK = 4  # key length (4 words = 16 byte)
NR = 10 # 10 round untuk AES-128


def validate_sbox(sbox: List[int]) -> bool:
    if len(sbox) != 256:
        return False
    if any(not (0 <= x <= 255) for x in sbox):
        return False
    if sorted(sbox) != list(range(256)):
        return False
    return True


def bytes_to_state(block: bytes) -> List[List[int]]:
    """
    Ubah 16 byte -> matriks 4x4 (state) kolom-major.
    """
    assert len(block) == 16
    return [[block[row + 4 * col] for col in range(4)] for row in range(4)]


def state_to_bytes(state: List[List[int]]) -> bytes:
    """
    Ubah state 4x4 -> 16 byte.
    """
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
        a ^= 0x11B  # polinomial AES
    return a & 0xFF


def mix_single_column(col: List[int]) -> List[int]:
    # implementasi standard MixColumns
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
    # round_key panjang 16 byte
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
    w: List[int] = list(key)  # mulai dari key asli (4 word pertama)

    # kita butuh (NB * (NR + 1)) * 4 byte = 176 byte
    for i in range(NK, NB * (NR + 1)):
        temp = w[4*(i-1):4*i]
        if i % NK == 0:
            temp = rot_word(temp)
            temp = sub_word(temp, sbox)
            temp[0] ^= RCON[i // NK]
        for j in range(4):
            temp[j] ^= w[4*(i-NK) + j]
        w.extend(temp)

    # pecah jadi round keys, masing2 16 byte
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

    # final round tanpa mix_columns
    state = sub_bytes(state, sbox)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[NR])

    return state_to_bytes(state)


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)


def aes_encrypt_ecb(plaintext: bytes, key: bytes, sbox: List[int]) -> bytes:
    plaintext = pkcs7_pad(plaintext, 16)
    out = bytearray()
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        out.extend(aes_encrypt_block(block, key, sbox))
    return bytes(out)


def encrypt_text_to_hex(
    plaintext: str,
    key_hex: str,
    sbox: List[int] | None = None
) -> str:
    if sbox is None:
        sbox = AES_STANDARD_SBOX

    if not validate_sbox(sbox):
        raise ValueError("S-Box tidak valid (harus permutasi 0..255)")

    key = bytes.fromhex(key_hex)
    if len(key) != 16:
        raise ValueError("Key harus 128-bit (16 byte, 32 hex char)")

    pt_bytes = plaintext.encode("utf-8")
    ct_bytes = aes_encrypt_ecb(pt_bytes, key, sbox)
    return ct_bytes.hex()
