"""Test test-vector, struktur tabel, dan round-trip untuk DES-CBC.

Menjalankan:  python3 test_cipher.py
Key uji 0123456789ABCDEF hanya untuk tes, bukan config.py.
Semua nilai acuan block diambil dari test vector FIPS/NIST DES.
"""

import os
import sys
from collections import Counter

import des
import config
from des import make_subkeys, encrypt_block, decrypt_block
from cipher import encrypt, decrypt, _encrypt_cbc, _pad, BLOCK_SIZE

TEST_KEY = bytes.fromhex("0123456789ABCDEF")
IV_FIXED = bytes.fromhex("0001020304050607")

BLOCK_VECTORS = [
    ("0123456789ABCDEF", "4E6F772069732074", "3FA40E8A984D4815"),
    ("0000000000000000", "0000000000000000", "8CA64DE9C1B123A7"),
    ("FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "7359B2163E4EDC58"),
    ("0101010101010101", "8000000000000000", "95F8A5E5DD31D900"),
    ("0123456789ABCDEF", "0000000000000000", "D5D44FF720683D0D"),
]

CBC_VECTORS = [
    (b"Halo, ini pesan uji KI",
     "159feb4380548a62d066461d2a15af741f80f70575453b76"),
    (b"Now is t", "6772b06bbc2200096a0727ca7f8da2fc"),
    (b"A", "da794a39d765cfa8"),
    (b"0123456789abcdef",
     "f3939f9c3037e8a5458d5a18c266d6a9ae60aac91ce15d2b"),
]

PASS = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASS
    status = "ok" if ok else "GAGAL"
    print(f"[{status}] {name}" + (f"  {detail}" if detail else ""))
    PASS += 1 if ok else 0


def _is_permutation(table, size: int) -> bool:
    return sorted(table) == list(range(1, size + 1))


def _selects(table, count: int, in_bits: int) -> bool:
    return (len(table) == count and len(set(table)) == count
            and all(1 <= v <= in_bits for v in table))


def test_tables() -> None:
    samples = (0, 1, 0x0123456789ABCDEF, 0xFFFFFFFFFFFFFFFF, 0xDEADBEEFCAFEBABE)
    check("IP adalah permutasi 64 bit", _is_permutation(des.IP, 64))
    check("FP membatalkan IP (IP lalu FP = identitas)",
          all(des._permute(des._permute(x, des.IP, 64), des.FP, 64) == x
              for x in samples))
    check("PC1 memilih 56 bit unik dari 64 bit", _selects(des.PC1, 56, 64))
    check("PC2 memilih 48 bit unik dari 56 bit", _selects(des.PC2, 48, 56))
    e_count = Counter(des.E)
    check("E mengembang 32 bit ke 48 bit (16 bit diulang)",
          len(des.E) == 48 and set(des.E) == set(range(1, 33))
          and max(e_count.values()) == 2
          and sum(1 for v in e_count.values() if v == 2) == 16)
    check("P adalah permutasi 32 bit", _is_permutation(des.P, 32))
    s_ok = (len(des.SBOXES) == 8
            and all(len(box) == 4 and all(len(r) == 16 for r in box)
                    and all(0 <= v <= 15 for r in box for v in r)
                    for box in des.SBOXES))
    check("8 S-box, masing-masing 4 x 16 nilai 0-15", s_ok)


def test_subkeys() -> None:
    sk = make_subkeys(TEST_KEY)
    check("16 subkey, semuanya berbeda",
          len(sk) == 16 and len(set(sk)) == 16
          and all(0 <= k < 1 << 48 for k in sk),
          f"K1={sk[0]:012x} K16={sk[15]:012x}")


def test_key_validation() -> None:
    check("key di config.py 8 byte dengan paritas ganjil",
          len(config.KEY) == des.KEY_SIZE and des.has_valid_parity(config.KEY),
          config.KEY.hex())
    try:
        make_subkeys(bytes(16))
        ok = False
    except ValueError:
        ok = True
    check("key dengan panjang salah ditolak", ok)
    check("key dengan paritas genap ditolak",
          not des.has_valid_parity(bytes.fromhex("0000000000000000")))


def test_block_vectors() -> None:
    for kh, ph, ch in BLOCK_VECTORS:
        key, pt, expect = (bytes.fromhex(h) for h in (kh, ph, ch))
        sk = make_subkeys(key)
        ct = encrypt_block(pt, sk)
        ok = ct == expect and decrypt_block(expect, sk) == pt
        check(f"block {kh} + {ph}", ok, ct.hex().upper())


def test_cbc_vectors() -> None:
    sk = make_subkeys(TEST_KEY)
    for pt, expect in CBC_VECTORS:
        padded = _pad(pt)
        blocks = [padded[i:i + BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
        ct = IV_FIXED + _encrypt_cbc(blocks, sk, IV_FIXED)
        check(f"CBC + IV tetap: {pt!r}", ct[BLOCK_SIZE:].hex() == expect, ct.hex())


def test_roundtrip_lengths() -> None:
    ok = True
    for n in (0, 1, 7, 8, 9, 1000):
        data = os.urandom(n)
        if decrypt(encrypt(data, TEST_KEY), TEST_KEY) != data:
            ok = False
            print(f"    mismatch pada panjang {n}")
    check("round-trip untuk panjang 0,1,7,8,9,1000", ok)


def test_cbc_length() -> None:
    for n in (0, 1, 8, 1000):
        if len(encrypt(b"x" * n, TEST_KEY)) % BLOCK_SIZE != 0:
            check("ciphertext selalu kelipatan blok", False, f"panjang {n}")
            return
    check("ciphertext selalu kelipatan blok (termasuk IV)", True)


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
    wrong[0] ^= 0x02
    try:
        ok = decrypt(encrypted, bytes(wrong)) != msg
    except ValueError:
        ok = True
    check("key salah tidak menghasilkan plaintext asli", ok)


def test_parity_bits_ignored() -> None:
    wrong = bytearray(TEST_KEY)
    wrong[0] ^= 0x01
    check("bit paritas diabaikan DES (selisih hanya paritas tidak terlihat)",
          make_subkeys(bytes(wrong)) == make_subkeys(TEST_KEY))


def main() -> None:
    test_tables()
    test_subkeys()
    test_key_validation()
    test_block_vectors()
    test_cbc_vectors()
    test_roundtrip_lengths()
    test_cbc_length()
    test_random_iv()
    test_bad_padding_rejected()
    test_wrong_key()
    test_parity_bits_ignored()
    total = 27
    print(f"\n{PASS}/{total} tes lulus")
    sys.exit(0 if PASS == total else 1)


if __name__ == "__main__":
    main()
