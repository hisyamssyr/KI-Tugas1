"""Konfigurasi bersama kedua peer.

KEY: 128 bit pre-shared, sama di kedua sisi dan tidak pernah dikirim
lewat jaringan. HOST/PORT: alamat untuk mode listen.
"""

KEY = bytes.fromhex("f8a1c53a304eb1c37546f864b598d0c1")

HOST = "127.0.0.1"
PORT = 9000