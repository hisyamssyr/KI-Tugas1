"""Cipher blok Feistel rancangan sendiri: 64 bit blok, 8 ronde, key 128 bit.

Semua operasi aritmetika dibatasi 32 bit. Konversi byte <-> integer big-endian.
Tidak menggunakan library kriptografi.
"""

BLOCK_SIZE = 8
KEY_SIZE = 16
NUM_ROUNDS = 8
MASK32 = 0xFFFFFFFF

GOLDEN_RATIO = 0x9E3779B9

# S-box 4 bit (permutasi 0..15), rancangan sendiri.
SBOX = [
    0x6, 0xB, 0x3, 0xE,
    0x0, 0x9, 0xD, 0x5,
    0xA, 0x2, 0xF, 0x7,
    0x4, 0x8, 0x1, 0xC,
]


def rotl(x: int, n: int) -> int:
    """Rotasi kiri sirkular pada 32 bit."""
    n %= 32
    return ((x << n) | (x >> (32 - n))) & MASK32


def make_round_keys(key: bytes) -> list:
    """Buat 8 round key (masing-masing 32 bit) dari key 16 byte."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"key harus {KEY_SIZE} byte")
    words = [
        int.from_bytes(key[i:i + 4], "big")
        for i in range(0, KEY_SIZE, 4)
    ]
    round_keys = []
    for i in range(NUM_ROUNDS):
        k = words[i % 4] ^ (((i + 1) * GOLDEN_RATIO) & MASK32)
        round_keys.append(rotl(k, 3 * i + 1))
    return round_keys


def _substitute(t: int) -> int:
    """Ganti tiap nibble lewat S-box, posisi tetap."""
    out = 0
    for shift in range(0, 32, 4):
        nibble = (t >> shift) & 0xF
        out |= SBOX[nibble] << shift
    return out


def f(r: int, k: int) -> int:
    """Fungsi ronde F(R, k)."""
    t = (r + k) & MASK32
    t = rotl(t, 5)
    t = _substitute(t)
    t = t ^ rotl(t, 9) ^ rotl(t, 21)
    t = rotl(t, 11)
    return t


def encrypt_block(block: bytes, round_keys: list) -> bytes:
    """Enkripsi satu blok 8 byte."""
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"blok harus {BLOCK_SIZE} byte")
    left = int.from_bytes(block[0:4], "big")
    right = int.from_bytes(block[4:8], "big")
    for i in range(NUM_ROUNDS):
        left, right = right, left ^ f(right, round_keys[i])
    # Tukar posisi di akhir, lalu gabungkan.
    return right.to_bytes(4, "big") + left.to_bytes(4, "big")


def decrypt_block(block: bytes, round_keys: list) -> bytes:
    """Dekripsi satu blok 8 byte (round key dibalik)."""
    return encrypt_block(block, list(reversed(round_keys)))
