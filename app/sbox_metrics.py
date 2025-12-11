from __future__ import annotations

from typing import Dict, List

from .aes_core import validate_sbox


def _int_to_bits(x: int, width: int = 8) -> List[int]:
    return [(x >> i) & 1 for i in range(width)]


def _precompute_bits(sbox: List[int]) -> List[List[int]]:
    return [_int_to_bits(v) for v in sbox]


def _walsh_hadamard_transform(vec: List[int]) -> List[int]:
    """In-place fast Walsh-Hadamard transform (copy is returned)."""
    n = len(vec)
    h = vec[:]
    step = 1
    while step < n:
        jump = step * 2
        for i in range(0, n, jump):
            for j in range(i, i + step):
                x = h[j]
                y = h[j + step]
                h[j] = x + y
                h[j + step] = x - y
        step = jump
    return h


def boolean_walsh(truth_table: List[int]) -> List[int]:
    """Walsh spectrum for a Boolean function truth table (0/1 values)."""
    spectrum_input = [1 if bit == 0 else -1 for bit in truth_table]
    return _walsh_hadamard_transform(spectrum_input)


def boolean_nonlinearity(truth_table: List[int]) -> int:
    walsh = boolean_walsh(truth_table)
    max_w = max(abs(w) for w in walsh)
    return (len(truth_table) // 2) - (max_w // 2)


def boolean_algebraic_degree(truth_table: List[int]) -> int:
    """Algebraic degree via Mobius transform of ANF."""
    n = len(truth_table).bit_length() - 1
    anf = truth_table[:]
    for i in range(n):
        step = 1 << i
        for mask in range(len(anf)):
            if mask & step:
                anf[mask] ^= anf[mask ^ step]
    deg = 0
    for mask, coeff in enumerate(anf):
        if coeff:
            wt = mask.bit_count()
            if wt > deg:
                deg = wt
    return deg


def boolean_correlation_immunity(truth_table: List[int]) -> int:
    n = len(truth_table).bit_length() - 1
    walsh = boolean_walsh(truth_table)
    ci = 0
    for order in range(1, n + 1):
        if any(
            walsh[mask] != 0
            for mask in range(1, 1 << n)
            if 1 <= mask.bit_count() <= order
        ):
            break
        ci = order
    return ci


def _truth_table_for_bit(sbox_bits: List[List[int]], bit_index: int) -> List[int]:
    return [bits[bit_index] for bits in sbox_bits]


def _truth_table_for_bit_pair_xor(sbox_bits: List[List[int]], i: int, j: int) -> List[int]:
    return [bits[i] ^ bits[j] for bits in sbox_bits]


def sac_average(sbox: List[int]) -> float:
    """Strict Avalanche Criterion average score across all input/output bits."""
    total_changes = 0
    comparisons = 256 * 8 * 8  # inputs * input_bits * output_bits
    for in_bit in range(8):
        delta = 1 << in_bit
        for x in range(256):
            y1 = sbox[x]
            y2 = sbox[x ^ delta]
            total_changes += (y1 ^ y2).bit_count()
    return total_changes / comparisons


def bic_sac_score(sbox_bits: List[List[int]]) -> float:
    """
    Avalanche score for XOR pair outputs (Bit Independence Criterion).
    Nilai mendekati 0.5 lebih baik.
    """
    total_changes = 0.0
    pair_count = 0
    comparisons_per_pair = 256 * 8
    for i in range(8):
        for j in range(i + 1, 8):
            pair_count += 1
            changes = 0
            for in_bit in range(8):
                delta = 1 << in_bit
                for x in range(256):
                    b1 = sbox_bits[x][i] ^ sbox_bits[x][j]
                    b2 = sbox_bits[x ^ delta][i] ^ sbox_bits[x ^ delta][j]
                    changes += (b1 ^ b2)
            total_changes += changes / comparisons_per_pair
    if pair_count == 0:
        return 0.0
    return total_changes / pair_count


def bic_nonlinearity_min(sbox_bits: List[List[int]]) -> int:
    """Nonlinearity minimum untuk XOR setiap pasangan bit output (BIC-NL)."""
    min_nl = None
    for i in range(8):
        for j in range(i + 1, 8):
            tt = _truth_table_for_bit_pair_xor(sbox_bits, i, j)
            nl = boolean_nonlinearity(tt)
            min_nl = nl if min_nl is None or nl < min_nl else min_nl
    return min_nl or 0


def du_max(sbox: List[int]) -> int:
    """Differential uniformity: maksimum count untuk semua input diff != 0."""
    du_val = 0
    for a in range(1, 256):
        counts = [0] * 256
        for x in range(256):
            b = sbox[x] ^ sbox[x ^ a]
            counts[b] += 1
        du_val = max(du_val, max(counts))
    return du_val


def lap_max_bias(sbox: List[int]) -> float:
    """Linear Approximation Probability: maksimum bias |C|/256 untuk mask input/output."""
    max_bias = 0.0
    precomp_out = [
        [((val & b).bit_count() & 1) for val in sbox]
        for b in range(256)
    ]
    for a in range(1, 256):
        in_parity = [((x & a).bit_count() & 1) for x in range(256)]
        for b in range(1, 256):
            out_parity = precomp_out[b]
            corr = 0
            for x in range(256):
                corr += 1 if in_parity[x] == out_parity[x] else -1
            bias = abs(corr) / 256.0
            if bias > max_bias:
                max_bias = bias
    return max_bias


def analyze_sbox(sbox: List[int]) -> Dict[str, float | int]:
    """Hitung metrik utama untuk S-Box 8x8."""
    if not validate_sbox(sbox):
        raise ValueError("S-Box tidak valid (harus permutasi 0..255).")

    sbox_bits = _precompute_bits(sbox)
    truth_tables = [_truth_table_for_bit(sbox_bits, i) for i in range(8)]

    # Nonlinearity & algebraic degree per output bit
    nls = [boolean_nonlinearity(tt) for tt in truth_tables]
    ads = [boolean_algebraic_degree(tt) for tt in truth_tables]
    cis = [boolean_correlation_immunity(tt) for tt in truth_tables]

    nl_min = min(nls)
    ad_min = min(ads)
    ci_min = min(cis)

    sac_avg_val = sac_average(sbox)
    bic_nl_min_val = bic_nonlinearity_min(sbox_bits)
    bic_sac_val = bic_sac_score(sbox_bits)
    lap_bias = lap_max_bias(sbox)
    du_val = du_max(sbox)
    dap_max = du_val / 256.0

    # Transparansi orde placeholder
    to_value = 0.0  # TODO: implement transparency order

    return {
        "nl_min": float(nl_min),
        "sac_avg": sac_avg_val,
        "bic_nl_min": float(bic_nl_min_val),
        "bic_sac_score": bic_sac_val,
        "lap_max_bias": lap_bias,
        "du": du_val,
        "dap_max": dap_max,
        "ad_min": ad_min,
        "to_value": to_value,
        "ci_min": ci_min,
    }
