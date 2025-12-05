"""Helper utilities for DES bit-level operations."""

from typing import Iterable, List


def left_rotate(bits: List[int], shift: int) -> List[int]:
    """Circular left rotation for a list of bits."""
    if not bits:
        return bits
    shift %= len(bits)
    return bits[shift:] + bits[:shift]


def permute(bits: List[int], table: Iterable[int]) -> List[int]:
    """Reorder/select bits according to a permutation table (1-based indices)."""
    return [bits[i - 1] for i in table]


def xor_bits(a: List[int], b: List[int]) -> List[int]:
    """Bitwise XOR between two equal-length bit lists."""
    return [(x ^ y) for x, y in zip(a, b)]


def bytes_to_bits(data: bytes) -> List[int]:
    """Convert bytes to a list of bits (big-endian within each byte)."""
    out = []
    for byte in data:
        for i in range(7, -1, -1): # Iterate i in range 7 to 0
            out.append((byte >> i) & 1) # right shift i steps and mask - to get bit at MSB --> LSB (left --> right)
    return out


def bits_to_bytes(bits: List[int]) -> bytes:
    """Convert a list of bits (len multiple of 8) back to bytes."""
    if len(bits) % 8 != 0:
        raise ValueError("Number of bits must be a multiple of 8.")
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | (b & 1) # left shift and add current bit
        out.append(byte)
    return bytes(out)


def utf8_to_bytes(text: str) -> bytes:
    """Encode text to UTF-8 bytes (strict)."""
    return text.encode("utf-8")


def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    """
    Apply PKCS#7 padding to reach a multiple of block_size.
    Note: block_size must fit in one byte (1..255) because padding value is stored in a single byte.
    """
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size must be in range 1..255")
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _force_odd_parity(byte: int) -> int:
    """Set LSB parity bit to make total set bits odd."""
    ones = bin(byte >> 1).count("1")  # ignore current "parity bit"
    lsb = byte & 1
    if (ones + lsb) % 2 == 0:  # if parity even, flip lsb to make odd
        return byte ^ 1
    return byte


def normalize_des_key(key_str: str) -> bytes:
    """
    Normalize user key string into 8-byte DES key with odd parity.
    - Accepts 16 hex chars (case-insensitive), else raw UTF-8 bytes.
    - Enforces length 8 bytes; raises ValueError otherwise.
    - Adjusts each byte to odd parity (LSB parity bit).
    """
    key_bytes: bytes
    stripped = key_str.strip()
    if len(stripped) == 16:
        try:
            key_bytes = bytes.fromhex(stripped)
        except ValueError:
            key_bytes = utf8_to_bytes(key_str)
    else:
        key_bytes = utf8_to_bytes(key_str)

    if len(key_bytes) != 8:
        raise ValueError("DES key must be exactly 8 bytes (64 bits).")

    return bytes(_force_odd_parity(b) for b in key_bytes)


def pkcs7_unpad(data: bytes, block_size: int = 8) -> bytes:
    """Remove PKCS#7 padding; raises ValueError on bad padding."""
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length.")
    pad_len = data[-1] # get value of last byte
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("Invalid padding byte.")
    if data[-pad_len:] != bytes([pad_len] * pad_len): # check padding content (last pad_len bytes)
        raise ValueError("Invalid padding content.")
    return data[:-pad_len]


def chunk_blocks(data: bytes, block_size: int = 8):
    """Yield successive blocks of size block_size from data; length must be multiple of block_size."""
    if len(data) % block_size != 0:
        raise ValueError("Data length must be a multiple of block size.")
    for i in range(0, len(data), block_size):
        yield data[i:i + block_size]
