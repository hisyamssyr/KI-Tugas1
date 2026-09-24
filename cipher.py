"""Mode CBC + padding PKCS#7 di atas cipher blok Feistel.

encrypt() mengembalikan IV acak 8 byte diikuti ciphertext.
decrypt() memisahkan IV lalu menolak padding yang rusak.
"""

import os

from feistel import BLOCK_SIZE, make_round_keys, encrypt_block, decrypt_block


def _pad(data: bytes) -> bytes:
    n = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([n]) * n


def _unpad(data: bytes) -> bytes:
    n = data[-1]
    if not (1 <= n <= BLOCK_SIZE) or data[-n:] != bytes([n]) * n:
        raise ValueError("padding rusak")
    return data[:-n]


def _encrypt_cbc(blocks: list, round_keys: list, iv: bytes) -> bytes:
    out = b""
    prev = iv
    for block in blocks:
        prev = encrypt_block(bytes(a ^ b for a, b in zip(block, prev)), round_keys)
        out += prev
    return out


def _decrypt_cbc(data: bytes, round_keys: list, iv: bytes) -> bytes:
    out = b""
    prev = iv
    for i in range(0, len(data), BLOCK_SIZE):
        enc = data[i:i + BLOCK_SIZE]
        out += bytes(a ^ b for a, b in zip(decrypt_block(enc, round_keys), prev))
        prev = enc
    return out


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    round_keys = make_round_keys(key)
    iv = os.urandom(BLOCK_SIZE)
    padded = _pad(plaintext)
    blocks = [padded[i:i + BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    return iv + _encrypt_cbc(blocks, round_keys, iv)


def decrypt(data: bytes, key: bytes) -> bytes:
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("data bukan kelipatan blok")
    round_keys = make_round_keys(key)
    iv, ciphertext = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
    return _unpad(_decrypt_cbc(ciphertext, round_keys, iv))