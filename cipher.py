"""Mode CBC + padding PKCS#7 di atas cipher blok Feistel.

encrypt() menghasilkan IV acak 8 byte diikuti ciphertext.
decrypt() membaca IV dari awal data, lalu menolak padding yang rusak.
"""

import os

from feistel import BLOCK_SIZE, make_round_keys, encrypt_block, decrypt_block


def _pad(data: bytes) -> bytes:
    n = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([n]) * n


def _unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("padding rusak: data kosong")
    n = data[-1]
    if not (1 <= n <= BLOCK_SIZE):
        raise ValueError("padding rusak: byte pad tidak valid")
    if data[-n:] != bytes([n]) * n:
        raise ValueError("padding rusak: nilai pad tidak konsisten")
    return data[:-n]


def _encrypt_cbc(blocks: list, round_keys: list, iv: bytes) -> bytes:
    out = b""
    prev = iv
    for block in blocks:
        xored = bytes(a ^ b for a, b in zip(block, prev))
        enc = encrypt_block(xored, round_keys)
        out += enc
        prev = enc
    return out


def _decrypt_cbc(data: bytes, round_keys: list, iv: bytes) -> bytes:
    out = b""
    prev = iv
    for i in range(0, len(data), BLOCK_SIZE):
        enc = data[i:i + BLOCK_SIZE]
        dec = decrypt_block(enc, round_keys)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = enc
    return out


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Pad PKCS#7 lalu enkripsi CBC. Kembali: IV + ciphertext."""
    round_keys = make_round_keys(key)
    iv = os.urandom(BLOCK_SIZE)
    padded = _pad(plaintext)
    blocks = [padded[i:i + BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    return iv + _encrypt_cbc(blocks, round_keys, iv)


def decrypt(data: bytes, key: bytes) -> bytes:
    """Pisahkan IV, dekripsi CBC, lalu buang padding. Tolak padding rusak."""
    if len(data) < 2 * BLOCK_SIZE or len(data) % BLOCK_SIZE != 0:
        raise ValueError("data tidak valid: bukan kelipatan blok")
    round_keys = make_round_keys(key)
    iv, ciphertext = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
    padded = _decrypt_cbc(ciphertext, round_keys, iv)
    return _unpad(padded)