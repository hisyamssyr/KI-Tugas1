"""Peer dua arah: enkripsi/dekripsi Feistel-CBC di atas TCP socket.

Pemakaian:
    python3 peer.py listen
    python3 peer.py connect <host>

Setelah tersambung, tiap peer punya dua thread:
  - kirim : baca input -> encrypt -> kirim [4B panjang][IV+ct]
  - terima: baca header -> baca payload -> decrypt -> tampilkan
Key diambil dari config.py (pre-shared), tidak ikut dikirim.
"""

import socket
import sys
import threading

from cipher import encrypt, decrypt
from config import KEY, HOST, PORT

HEADER = 4
MAX_PAYLOAD = 1 << 20  # batas keamanan: 1 MiB per pesan


def _send_frame(sock: socket.socket, data: bytes) -> None:
    sock.sendall(len(data).to_bytes(HEADER, "big") + data)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = b""
    remaining = n
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionResetError("koneksi ditutup lawan bicara")
        chunks += chunk
        remaining -= len(chunk)
    return chunks


def _recv_frame(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, HEADER)
    length = int.from_bytes(header, "big")
    if length <= 0 or length > MAX_PAYLOAD:
        raise ValueError(f"panjang payload tidak valid: {length}")
    return _recv_exact(sock, length)


def send_loop(sock: socket.socket) -> None:
    while True:
        try:
            line = input()
        except EOFError:
            return
        if line.strip() == "quit":
            print("[kirim] keluar, menutup koneksi")
            sock.close()
            return
        try:
            payload = encrypt(line.encode("utf-8"), KEY)
        except Exception as exc:
            print(f"[kirim] gagal enkripsi: {exc}")
            continue
        ct = payload[8:]
        print(f"[kirim] ciphertext ({len(ct)} byte): {ct.hex()}")
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
            plaintext = decrypt(payload, KEY).decode("utf-8")
        except Exception as exc:
            print(f"[terima] gagal dekripsi: {exc}")
            continue
        print(f"[terima] plaintext: {plaintext}")


def run(conn: socket.socket) -> None:
    print("Terhubung. Ketik pesan lalu Enter untuk mengirim, 'quit' untuk menutup.")
    receiver = threading.Thread(target=recv_loop, args=(conn,), daemon=True)
    receiver.start()
    send_loop(conn)
    receiver.join(timeout=1)


def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] not in ("listen", "connect"):
        sys.exit('pemakaian: peer.py listen | peer.py connect <host>')

    if args[0] == "listen":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((HOST, PORT))
            server.listen(1)
            print(f"[listener] menunggu koneksi di {HOST}:{PORT} ...")
            conn, addr = server.accept()
        print(f"[listener] tersambung dari {addr}")
        run(conn)
    else:
        host = args[1]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, PORT))
            print(f"[connector] tersambung ke {host}:{PORT}")
            run(sock)


if __name__ == "__main__":
    main()