"""Konfigurasi bersama kedua peer.

KEY: 128 bit (16 byte) pre-shared, dibuat sekali lalu disalin ke kedua sisi.
     Tidak pernah dikirim lewat jaringan.
HOST / PORT: alamat listener (Peer A / mode listen).
"""

KEY = bytes.fromhex("f8a1c53a304eb1c37546f864b598d0c1")

HOST = "127.0.0.1"
PORT = 9000