"""Cipher blok Feistel 64-bit / 8 ronde dengan key 128 bit, tanpa library kriptografi.

Detail algoritma dijelaskan di README.md.
"""

BLOCK_SIZE = 8
KEY_SIZE = 16
NUM_ROUNDS = 8
MASK32 = 0xFFFFFFFF
GOLDEN_RATIO = 0x9E3779B9

SBOX = [
    0x6, 0xB, 0x3, 0xE,
    0x0, 0x9, 0xD, 0x5,
    0xA, 0x2, 0xF, 0x7,
    0x4, 0x8, 0x1, 0xC,
]


def rotl(x: int, n: int) -> int:
    n %= 32
    return ((x << n) | (x >> (32 - n))) & MASK32


def make_round_keys(key: bytes) -> list:
    if len(key) != KEY_SIZE:
        raise ValueError(f"key harus {KEY_SIZE} byte")
    words = [int.from_bytes(key[i:i + 4], "big") for i in range(0, KEY_SIZE, 4)]
    round_keys = []
    for i in range(NUM_ROUNDS):
        k = words[i % 4] ^ (((i + 1) * GOLDEN_RATIO) & MASK32)
        round_keys.append(rotl(k, 3 * i + 1))
    return round_keys


def _substitute(t: int) -> int:
    out = 0
    for shift in range(0, 32, 4):
        out |= SBOX[(t >> shift) & 0xF] << shift
    return out


def f(r: int, k: int) -> int:
    t = (r + k) & MASK32
    t = rotl(t, 5)
    t = _substitute(t)
    t = t ^ rotl(t, 9) ^ rotl(t, 21)
    return rotl(t, 11)


def encrypt_block(block: bytes, round_keys: list) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"blok harus {BLOCK_SIZE} byte")
    left = int.from_bytes(block[0:4], "big")
    right = int.from_bytes(block[4:8], "big")
    for i in range(NUM_ROUNDS):
        left, right = right, left ^ f(right, round_keys[i])
    return right.to_bytes(4, "big") + left.to_bytes(4, "big")


def decrypt_block(block: bytes, round_keys: list) -> bytes:
    return encrypt_block(block, list(reversed(round_keys)))