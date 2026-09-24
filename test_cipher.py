"""Test test-vector dan round-trip untuk cipher Feistel-CBC.

Menjalankan:  python3 test_cipher.py
Key uji 000102030405060708090a0b0c0d0e0f hanya untuk tes, bukan config.py.
Semua nilai acuan diambil dari README.md.
"""

import os
import sys

from feistel import make_round_keys, encrypt_block, decrypt_block
from cipher import encrypt, decrypt

TEST_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

EXPECTED_ROUND_KEYS = [
    0x3C6CF775, 0x86BF5753, 0x57B39069, 0x43A3ADD3,
    0x8C53C2E2, 0xDC51B149, 0xF022DC6A, 0xF1FF6DB0,
]
EXPECTED_BLOCK_CT = bytes.fromhex("3d5cfedd8cbf57f2")
IV_FIXED = bytes.fromhex("0001020304050607")
EXPECTED_CBC = bytes.fromhex(
    "0001020304050607aaeb086afc3645f93d60e216f8ad4a6b9913126a6608faa0"
)

PASS = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASS
    status = "ok" if ok else "GAGAL"
    print(f"[{status}] {name}" + (f"  {detail}" if detail else ""))
    PASS += 1 if ok else 0


def test_round_keys() -> None:
    rk = make_round_keys(TEST_KEY)
    check("round key cocok dengan test vector", rk == EXPECTED_ROUND_KEYS,
          " ".join(f"{x:08x}" for x in rk))


def test_single_block() -> None:
    rk = make_round_keys(TEST_KEY)
    ct = encrypt_block(bytes.fromhex("0123456789abcdef"), rk)
    check("encrypt_block cocok dengan test vector", ct == EXPECTED_BLOCK_CT, ct.hex())
    check("decrypt_block kembali ke plaintext",
          decrypt_block(ct, rk) == bytes.fromhex("0123456789abcdef"))


def test_cbc_fixed_iv() -> None:
    from cipher import _encrypt_cbc, _pad
    rk = make_round_keys(TEST_KEY)
    padded = _pad(b"Halo, ini pesan uji KI")
    blocks = [padded[i:i + 8] for i in range(0, len(padded), 8)]
    ct = IV_FIXED + _encrypt_cbc(blocks, rk, IV_FIXED)
    check("CBC + IV tetap cocok dengan test vector", ct == EXPECTED_CBC, ct.hex())


def test_roundtrip_lengths() -> None:
    ok = True
    for n in (0, 1, 7, 8, 9, 1000):
        data = os.urandom(n)
        if decrypt(encrypt(data, TEST_KEY), TEST_KEY) != data:
            ok = False
            print(f"    mismatch pada panjang {n}")
    check("round-trip untuk panjang 0,1,7,8,9,1000", ok)


def test_random_iv() -> None:
    msg = b"pesan yang sama dikirim dua kali"
    a, b = encrypt(msg, TEST_KEY), encrypt(msg, TEST_KEY)
    check("ciphertext berbeda untuk pesan sama (efek IV)", a != b)
    check("keduanya tetap terdekripsi benar",
          decrypt(a, TEST_KEY) == msg and decrypt(b, TEST_KEY) == msg)


def test_bad_padding_rejected() -> None:
    encrypted = bytearray(encrypt(b"data penting", TEST_KEY))
    encrypted[-1] ^= 0xFF
    try:
        decrypt(bytes(encrypted), TEST_KEY)
        ok = False
    except ValueError:
        ok = True
    check("padding rusak ditolak", ok)


def test_wrong_key() -> None:
    msg = b"rahasia uji"
    encrypted = encrypt(msg, TEST_KEY)
    wrong = bytearray(TEST_KEY)
    wrong[0] ^= 0x01
    try:
        ok = decrypt(encrypted, bytes(wrong)) != msg
    except ValueError:
        ok = True
    check("key salah tidak menghasilkan plaintext asli", ok)


def main() -> None:
    test_round_keys()
    test_single_block()
    test_cbc_fixed_iv()
    test_roundtrip_lengths()
    test_random_iv()
    test_bad_padding_rejected()
    test_wrong_key()
    global PASS
    total = 9
    print(f"\n{PASS}/{total} tes lulus")
    sys.exit(0 if PASS == total else 1)


if __name__ == "__main__":
    main()