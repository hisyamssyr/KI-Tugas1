"""Konfigurasi bersama kedua peer.

KEY: 64 bit pre-shared DES (56 bit efektif + 8 bit paritas ganjil), sama di
kedua sisi dan tidak pernah dikirim lewat jaringan. HOST/PORT: alamat untuk
mode listen.
"""

KEY = bytes.fromhex("2c67464f2915c852")

HOST = "127.0.0.1"
PORT = 9000