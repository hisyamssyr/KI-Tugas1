"""Peer dua arah: Feistel-CBC di atas TCP socket.

Pemakaian:
    python3 peer.py listen
    python3 peer.py connect <host>

Tiap peer punya dua thread: satu membaca input -> encrypt -> kirim, satu
menerima -> decrypt -> tampilkan. Key dibaca dari config.py (pre-shared dan
tidak ikut dikirim). Framing dijelaskan di README.md.
"""

import socket
import sys
import threading

from cipher import encrypt, decrypt
from config import KEY, HOST, PORT

HEADER = 4
MAX_PAYLOAD = 1 << 20


def _send_frame(sock: socket.socket, data: bytes) -> None:
    sock.sendall(len(data).to_bytes(HEADER, "big") + data)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = b""
    while len(chunks) < n:
        chunk = sock.recv(n - len(chunks))
        if not chunk:
            raise ConnectionResetError("koneksi ditutup lawan bicara")
        chunks += chunk
    return chunks


def _recv_frame(sock: socket.socket) -> bytes:
    length = int.from_bytes(_recv_exact(sock, HEADER), "big")
    if length <= 0 or length > MAX_PAYLOAD:
        raise ValueError(f"panjang payload tidak valid: {length}")
    return _recv_exact(sock, length)


def send_loop(sock: socket.socket) -> None:
    while True:
        line = input()
        if line.strip() == "quit":
            print("[kirim] keluar, menutup koneksi")
            sock.close()
            return
        payload = encrypt(line.encode("utf-8"), KEY)
        print(f"[kirim] ciphertext ({len(payload[8:])} byte): {payload[8:].hex()}")
        _send_frame(sock, payload)


def recv_loop(sock: socket.socket) -> None:
    while True:
        try:
            payload = _recv_frame(sock)
        except (ConnectionResetError, EOFError, OSError):
            print("[terima] koneksi ditutup")
            return
        iv, ct = payload[:8], payload[8:]
        print(f"[terima] ciphertext ({len(ct)} byte): {ct.hex()}  (IV: {iv.hex()})")
        try:
            print(f"[terima] plaintext: {decrypt(payload, KEY).decode('utf-8')}")
        except ValueError as exc:
            print(f"[terima] gagal dekripsi: {exc}")


def run(conn: socket.socket) -> None:
    print("Terhubung. Ketik pesan lalu Enter untuk mengirim, 'quit' untuk menutup.")
    threading.Thread(target=recv_loop, args=(conn,), daemon=True).start()
    send_loop(conn)


def listen() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"[listener] menunggu koneksi di {HOST}:{PORT} ...")
        conn, addr = server.accept()
    print(f"[listener] tersambung dari {addr}")
    run(conn)


def connect(host: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, PORT))
        print(f"[connector] tersambung ke {host}:{PORT}")
        run(sock)


def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] not in ("listen", "connect"):
        sys.exit("pemakaian: python3 peer.py listen | python3 peer.py connect <host>")
    if args[0] == "listen":
        listen()
    else:
        connect(args[1])


if __name__ == "__main__":
    main()