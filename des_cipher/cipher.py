"""Core DES cipher logic with ECB and CFB modes."""

import os
from typing import List, Optional, Tuple

# Initial Permutation (IP)
IP_TABLE = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

# Expansion (E) from 32 bits to 48 bits
E_SELECTION_TABLE = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]

# S-boxes S1..S8
S_BOXES = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
]

# Permutation P inside the f-function
P_PERMUTATION = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25,
]

# Permuted Choice 1 (PC-1) for key schedule
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]

# Left rotations for each round
LEFT_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# Permuted Choice 2 (PC-2) to generate round keys
PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32,
]

# Final Permutation (IP^-1)
IP_INV_TABLE = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

from .helper import (
    bits_to_bytes,
    bytes_to_bits,
    chunk_blocks,
    left_rotate,
    normalize_des_key,
    permute,
    pkcs7_pad,
    pkcs7_unpad,
    utf8_to_bytes,
    xor_bits,
)


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte sequences of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


def _generate_round_keys(key_bytes: bytes) -> List[List[int]]:
    """Generate 16 round keys (48-bit) from 8-byte key with parity already set."""
    key_bits = bytes_to_bits(key_bytes)
    permuted = permute(key_bits, PC1)  # 56 bits
    c, d = permuted[:28], permuted[28:]
    round_keys = []
    for shift in LEFT_SHIFTS:
        c = left_rotate(c, shift)
        d = left_rotate(d, shift)
        cd = c + d
        round_keys.append(permute(cd, PC2))
    return round_keys


def _sbox_substitution(bits48: List[int]) -> List[int]:
    """Apply 8 S-boxes to 48-bit input -> 32-bit output."""
    out = []
    for i in range(8):
        block = bits48[i * 6:(i + 1) * 6]
        row = (block[0] << 1) | block[5]
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        val = S_BOXES[i][row * 16 + col]
        out.extend([(val >> shift) & 1 for shift in (3, 2, 1, 0)])
    return out


def _feistel(right: List[int], round_key: List[int]) -> List[int]:
    """DES f-function: expand, XOR with key, S-boxes, permutation P."""
    expanded = permute(right, E_SELECTION_TABLE)  # 48 bits
    xored = xor_bits(expanded, round_key)
    sboxed = _sbox_substitution(xored)  # 32 bits
    return permute(sboxed, P_PERMUTATION)


def _des_block(block: bytes, round_keys: List[List[int]], encrypt: bool = True) -> bytes:
    """Encrypt/decrypt a single 8-byte block with provided round keys."""
    bits = bytes_to_bits(block)
    permuted = permute(bits, IP_TABLE)
    left, right = permuted[:32], permuted[32:]

    keys = round_keys if encrypt else list(reversed(round_keys))
    for k in keys:
        f_out = _feistel(right, k)
        new_left = right
        new_right = xor_bits(left, f_out)
        left, right = new_left, new_right

    preoutput = right + left  # swap halves
    final_bits = permute(preoutput, IP_INV_TABLE)
    return bits_to_bytes(final_bits)


def _parse_iv(iv: str) -> bytes:
    """Parse IV from hex (16 chars) or UTF-8, enforcing 8 bytes length."""
    stripped = iv.strip()
    if len(stripped) == 16:
        try:
            iv_bytes = bytes.fromhex(stripped)
        except ValueError:
            iv_bytes = utf8_to_bytes(iv)
    else:
        iv_bytes = utf8_to_bytes(iv)
    if len(iv_bytes) != 8:
        raise ValueError("IV must be exactly 8 bytes for DES.")
    return iv_bytes


def des_encrypt(plaintext: str, key: str, mode: str = "ecb", iv: Optional[str] = None) -> Tuple[str, Optional[str]]:
    """
    Encrypt plaintext with DES.

    Args:
        plaintext: Text to encrypt (UTF-8).
        key: User key (16-hex or 8-char), parity adjusted to DES requirements.
        mode: "ecb" (PKCS#7 padded) or "cfb" (no padding).
        iv: Required for CFB; 16-hex or 8-char string.

    Returns:
        (cipher_hex, iv_hex) where iv_hex is None for ECB.
    """
    mode = mode.lower()
    key_bytes = normalize_des_key(key)
    round_keys = _generate_round_keys(key_bytes)

    if mode == "ecb":
        data = pkcs7_pad(utf8_to_bytes(plaintext), 8)
        out = bytearray()
        for block in chunk_blocks(data, 8):
            out.extend(_des_block(block, round_keys, encrypt=True))
        return out.hex(), None

    if mode == "cfb":
        iv_bytes = _parse_iv(iv) if iv is not None else os.urandom(8)
        data = utf8_to_bytes(plaintext)
        out = bytearray()
        prev = iv_bytes
        # process full 8-byte blocks
        full_len = len(data) - (len(data) % 8)
        for i in range(0, full_len, 8):
            block = data[i:i + 8]
            keystream = _des_block(prev, round_keys, encrypt=True)
            cipher_block = _xor_bytes(block, keystream)
            out.extend(cipher_block)
            prev = cipher_block
        # process tail (if any) without padding
        if len(data) % 8:
            tail = data[full_len:]
            keystream = _des_block(prev, round_keys, encrypt=True)
            cipher_tail = _xor_bytes(tail, keystream[: len(tail)])
            out.extend(cipher_tail)
            prev = prev  # prev not used further
        return out.hex(), iv_bytes.hex()

    raise ValueError("Unsupported mode. Use 'ecb' or 'cfb'.")


def des_decrypt(ciphertext: str, key: str, mode: str = "ecb", iv: Optional[str] = None) -> str:
    """
    Decrypt ciphertext with DES.

    Args:
        ciphertext: Hex-encoded ciphertext.
        key: User key (16-hex or 8-char), parity adjusted to DES requirements.
        mode: "ecb" (expects PKCS#7 padding) or "cfb".
        iv: Required for CFB; 16-hex or 8-char string.

    Returns:
        Decrypted plaintext as UTF-8 string.
    """
    mode = mode.lower()
    key_bytes = normalize_des_key(key)
    round_keys = _generate_round_keys(key_bytes)
    try:
        data = bytes.fromhex(ciphertext.strip())
    except ValueError:
        raise ValueError("Ciphertext must be a valid hex string.")

    if mode == "ecb":
        out = bytearray()
        for block in chunk_blocks(data, 8):
            out.extend(_des_block(block, round_keys, encrypt=False))
        unpadded = pkcs7_unpad(bytes(out), 8)
        return unpadded.decode("utf-8")

    if mode == "cfb":
        if iv is None:
            raise ValueError("IV is required for CFB mode.")
        iv_bytes = _parse_iv(iv)
        out = bytearray()
        prev = iv_bytes
        full_len = len(data) - (len(data) % 8)
        for i in range(0, full_len, 8):
            block = data[i:i + 8]
            keystream = _des_block(prev, round_keys, encrypt=True)
            plain_block = _xor_bytes(block, keystream)
            out.extend(plain_block)
            prev = block
        if len(data) % 8:
            tail = data[full_len:]
            keystream = _des_block(prev, round_keys, encrypt=True)
            plain_tail = _xor_bytes(tail, keystream[: len(tail)])
            out.extend(plain_tail)
        return bytes(out).decode("utf-8")

    raise ValueError("Unsupported mode. Use 'ecb' or 'cfb'.")
