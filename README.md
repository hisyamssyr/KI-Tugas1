# KI-Tugas1 — Simulasi Transmisi Ciphertext Dua Arah

Simulasi komunikasi dua arah antara dua peer yang bertukar **ciphertext** lewat
TCP socket. Algoritma **Feistel rancangan sendiri** (blok 64 bit, 8 ronde, key
128 bit) + mode **CBC** + padding **PKCS#7**, diimplementasikan manual tanpa
library kriptografi.

> Cipher ini untuk pembelajaran — tidak ada analisis keamanan formal. Jangan
> dipakai untuk melindungi data nyata. Blok 64 bit relatif kecil dibanding
> cipher modern, dan CBC tanpa MAC tidak memberi integritas pesan.

## Struktur file

```
feistel.py      cipher blok: round key, fungsi F, S-box, encrypt/decrypt block
cipher.py       mode CBC + padding PKCS#7: encrypt() / decrypt()
config.py       KEY (16 byte pre-shared), HOST, PORT
peer.py         komunikasi dua arah (mode listen / connect)
test_cipher.py  test vector + tes round-trip
README.md
```

`feistel.py` dan `cipher.py` dipakai bersama oleh kedua peer. Key **tidak**
dikirim lewat jaringan — pre-shared, dibaca dari `config.py` di kedua sisi.

## Menjalankan

Tes dulu:

```bash
python3 test_cipher.py
```

Terminal 1 (peer A, listener):

```bash
python3 peer.py listen
```

Terminal 2 (peer B, connector):

```bash
python3 peer.py connect 127.0.0.1        # atau IP VM/device lawan
```

Setelah tersambung, ketik pesan lalu Enter untuk mengirim, `quit` untuk
menutup. Setiap pesan menampilkan **ciphertext (hex)** di sisi kirim dan terima,
sehingga terlihat bahwa yang lewat jaringan adalah ciphertext.

Alur demo:
1. Jalankan `listen` di terminal 1 dan `connect` di terminal 2.
2. A kirim pesan → B, tunjukkan ciphertext hex dan plaintext hasil dekripsi di B.
3. B balas → A (membuktikan dua arah).
4. Kirim pesan yang sama dua kali → ciphertext-nya berbeda (efek IV acak CBC).

---

## Algoritma

### Parameter

| Komponen | Nilai |
|----------|-------|
| Ukuran blok | 64 bit (8 byte), dibagi L (32 bit) dan R (32 bit) |
| Ukuran key | 128 bit (16 byte), dipecah menjadi 4 word 32 bit: K₀..K₃ |
| Jumlah ronde | 8 |
| Round key | 8 buah, masing-masing 32 bit |
| Urutan byte | Big-endian untuk semua konversi byte ↔ integer |
| Aritmetika | Semua operasi 32 bit (`& 0xFFFFFFFF`) |

Fungsi bantu `rotl(x, n)` adalah rotasi kiri sirkular pada 32 bit, dengan `n`
diambil mod 32:

```
rotl(x, n) = ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
```

### Key schedule

Key 128 bit dipecah menjadi 4 word K₀..K₃. Untuk tiap ronde `i = 0..7`:

```
k     = K[i mod 4]  XOR  (((i + 1) * 0x9E3779B9) & 0xFFFFFFFF)
RK[i] = rotl(k, 3*i + 1)
```

Konstanta `0x9E3779B9` (proporsi emas, 2³²/φ) dipakai agar tiap ronde punya
round key yang berbeda walaupun word key hanya empat.

### Fungsi ronde F(R, k)

Masukan: `R` (32 bit) dan round key `k`. Langkah:

1. **Tambah key:** `t = (R + k) mod 2³²`
2. **Rotasi:** `t = rotl(t, 5)`
3. **Substitusi:** pecah `t` menjadi 8 nibble, ganti tiap nibble lewat S-box
   4 bit di bawah, lalu gabungkan pada posisi yang sama
4. **Difusi:** `t = t XOR rotl(t, 9) XOR rotl(t, 21)`
5. **Rotasi akhir:** `t = rotl(t, 11)`, hasil `F = t`

Langkah 4 penting: tanpa difusi, perubahan satu bit pada masukan F tidak akan
menyebar ke banyak bit walau sudah 8 ronde.

**S-box 4 bit** (permutasi 0..15):

| Masukan | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | A | B | C | D | E | F |
|---------|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Keluaran | 6 | B | 3 | E | 0 | 9 | D | 5 | A | 2 | F | 7 | 4 | 8 | 1 | C |

### Enkripsi satu blok

```
L, R = blok[0:4], blok[4:8]              # dibaca sebagai integer big-endian
untuk i = 0..7:
    L, R = R, L XOR F(R, RK[i])
output = R || L                          # tukar posisi di akhir
```

### Dekripsi satu blok

Sama persis dengan enkripsi, hanya urutan round key **dibalik**
(`RK[7], RK[6], ..., RK[0]`). Tidak perlu fungsi invers untuk F, S-box, maupun
rotasi — inilah keuntungan struktur Feistel. Bukti singkat: sejak ronde
terakhir, `L_top = R_bottom` dan `R_top = L_bottom XOR F(R_bottom, RK[7])`;
menjalankan ronde ke-7 lagi dengan round key yang sama mengembalikan
`(L_bottom, R_bottom)`, dan seterusnya mundur sampai ronde 0.

### Mode CBC (blok 8 byte)

- Tiap pesan memakai **IV acak 8 byte** baru (`os.urandom`).
- Enkripsi: `C₀ = IV`, `Cᵢ = Enc(Pᵢ XOR Cᵢ₋₁)`
- Dekripsi: `Pᵢ = Dec(Cᵢ) XOR Cᵢ₋₁`
- IV tidak rahasia, dikirim bersama ciphertext. Karena tiap pesan memakai IV
  baru, pesan yang sama dienkripsi dua kali menghasilkan ciphertext berbeda.

### Padding PKCS#7 (blok 8 byte)

- Tambahkan `n` byte dengan nilai `n`, di mana `n = 8 − (panjang mod 8)`. Bila
  panjang sudah kelipatan 8, tetap ditambah 8 byte padding agar bisa dibedakan.
- Saat dekripsi: baca byte terakhir `n`, validasi `1 ≤ n ≤ 8` dan bahwa `n` byte
  terakhir semuanya bernilai `n`, lalu buang. Padding yang rusak **ditolak**
  dengan `ValueError`.

## Format transmisi

TCP adalah stream, jadi batas pesan didefinisikan lewat framing:

```
[ 4 byte: panjang payload (big-endian) ][ 8 byte IV ][ ciphertext (kelipatan 8) ]
```

Penerima membaca 4 byte header, lalu membaca tepat sejumlah byte payload
tersebut. Key **tidak** ikut dikirim.

---

## Penjelasan Kode Per File

Semua kode ditulis sejelas mungkin untuk pembelajaran, tanpa library
kriptografi. Berikut penjelasannya satu per satu.

### `feistel.py` — Cipher Blok (Inti Algoritma)

Bagian ini berisi "mesin" kripto: S-box, fungsi ronde, key schedule, dan
enkripsi/dekripsi satu blok 8 byte.

**Konstanta global**

```python
BLOCK_SIZE = 8      # satu blok = 8 byte = 64 bit
KEY_SIZE = 16        # key = 16 byte = 128 bit
NUM_ROUNDS = 8       # jumlah ronde
MASK32 = 0xFFFFFFFF  # penutup untuk memotong hasil jadi 32 bit
GOLDEN_RATIO = 0x9E3779B9  # konstanta ala TEA, 2^32 / φ
```

- `MASK32` dipakai tiap kali kita ingin memastikan angka tetap 32 bit. Intinya:
  ambil bit paling kanan sebanyak 32 (operasi `& 0xFFFFFFFF`).
- `GOLDEN_RATIO` adalah konstanta hasil pembagian 2^32 dengan rasio emas.
  Konstanta ini adalah "bumbu" agar tiap ronde dihasilkan round key yang
  berbeda-beda.

**S-box**

```python
SBOX = [0x6, 0xB, 0x3, 0xE, 0x0, 0x9, 0xD, 0x5,
        0xA, 0x2, 0xF, 0x7, 0x4, 0x8, 0x1, 0xC]
```

S-box bekerja seperti "kamus rahasia": setiap 4 bit (~angka 0–15) diganti
dengan angka lain sesuai tabel. Misal masukan `0` menjadi `6`, masukan
`0xF` menjadi `0xC`. Tujuannya membuat hubungan masukan→keluaran tidak
linear, sehingga menyulitkan penyerang menebak pola. Tabel ini adalah
permutasi 0..15 (semua angka muncul tepat satu kali).

**`rotl(x, n)` — rotasi kiri sirkular 32 bit**

```python
def rotl(x: int, n: int) -> int:
    n %= 32                       # amankan nilai n agar tidak lebih dari 32
    return ((x << n) | (x >> (32 - n))) & MASK32
```

Rotasi kiri artinya bit yang keluar di sisi kiri masuk kembali dari sisi
kanan. Contoh kecil (8 bit): `10110000` digeser kiri 1 jadi `01100001`, bukan
`01100000`. Rumusnya: geser kiri `n` bit lalu "tambal" bit yang hilang di
kanan lewat `x >> (32 - n)`. Akhirnya dipotong `& MASK32` supaya tetap 32 bit.
`n %= 32` berjaga-jaga bila `n` dipanggil dengan nilai ≥ 32 (rotasi 33 kali
sama dengan 1 kali).

**`make_round_keys(key)` — key schedule**

```python
def make_round_keys(key: bytes) -> list:
    if len(key) != KEY_SIZE:
        raise ValueError(f"key harus {KEY_SIZE} byte")
    words = [int.from_bytes(key[i:i + 4], "big") for i in range(0, KEY_SIZE, 4)]
    round_keys = []
    for i in range(NUM_ROUNDS):
        k = words[i % 4] ^ (((i + 1) * GOLDEN_RATIO) & MASK32)
        round_keys.append(rotl(k, 3 * i + 1))
    return round_keys
```

- Key 16 byte dipecah jadi 4 word masing-masing 4 byte (K₀..K₃), dibaca
  big-endian (`int.from_bytes(..., "big")`).
- Untuk ronde `i` ke-0 sampai 7: ambil word `i % 4` (jadi berputar
  K₀,K₁,K₂,K₃ lalu K₀ lagi), XOR dengan `(i+1) * GOLDEN_RATIO`, lalu rotasi
  kiri `3*i + 1` bit. Hasilnya: 8 round key yang semuanya berbeda walaupun
  hanya ada 4 word.

**`_substitute(t)` — substitusi 8 nibble**

```python
def _substitute(t: int) -> int:
    out = 0
    for shift in range(0, 32, 4):        # shift 0,4,8,...,28
        out |= SBOX[(t >> shift) & 0xF] << shift
    return out
```

- 32 bit `t` dipecah menjadi 8 potongan 4 bit (nibble).
- Tiap nibble diganti lewat S-box, lalu disusun kembali di posisi yang sama.
- `(t >> shift) & 0xF` mengambil nibble ke-`shift`, `SBOX[...]` menggantinya,
  `<< shift` mengembalikannya ke posisi semula, `|=` menyatukan hasilnya.

**`f(r, k)` — fungsi ronde**

```python
def f(r: int, k: int) -> int:
    t = (r + k) & MASK32          # 1. tambahkan round key
    t = rotl(t, 5)                # 2. rotasi 5 bit
    t = _substitute(t)            # 3. substitusi S-box
    t = t ^ rotl(t, 9) ^ rotl(t, 21)  # 4. difusi: campur bit ke seluruh 32 bit
    return rotl(t, 11)            # 5. rotasi akhir
```

Urutan langkahnya: **tambah key → rotasi → substitusi → difusi → rotasi**.
Langkah 4 inilah yang membuat perubahan satu bit pada masukan menyebar menjadi
banyak bit yang berubah pada keluaran. Tanpa difusi, 8 ronde saja tidak cukup
untuk mengacak data dengan baik.

**`encrypt_block(block, round_keys)` — enkripsi satu blok**

```python
def encrypt_block(block: bytes, round_keys: list) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"blok harus {BLOCK_SIZE} byte")
    left = int.from_bytes(block[0:4], "big")   # L = 4 byte pertama
    right = int.from_bytes(block[4:8], "big")  # R = 4 byte terakhir
    for i in range(NUM_ROUNDS):
        left, right = right, left ^ f(right, round_keys[i])
    return right.to_bytes(4, "big") + left.to_bytes(4, "big")
```

Ini inti struktur Feistel. Tiap ronde hanya melakukan satu operasi pada sisi
kiri:

```
L, R = R,  L XOR f(R, key)
```

Artinya: sisi kanan lama `R` menjadi sisi kiri baru (dipindah apa adanya),
sedangkan sisi kiri lama `L` di-XOR dengan hasil `f(R, key)`. Karena perubahan
baru muncul lewat `f` di XOR, bila `f`-nya bagus maka seluruh blok akan ikut
teracak.

Di akhir, hasilnya ditulis **terbalik** (`R || L`, bukan `L || R`). Ini
bukan kesalahan — justru ini trik yang membuat enkripsi dan dekripsi
menggunakan kode yang sama.

**`decrypt_block(block, round_keys)` — dekripsi satu blok**

```python
def decrypt_block(block: bytes, round_keys: list) -> bytes:
    return encrypt_block(block, list(reversed(round_keys)))
```

Cukup panggil `encrypt_block` dengan round key yang dibalik urutannya. Inilah
keunggulan utama struktur Feistel: **tidak perlu membalik fungsi `f`, S-box,
maupun rotasi**. Dekripsi = enkripsi berjalan mundur.

---

### `cipher.py` — Mode CBC + Padding PKCS#7

Cipher blok hanya bisa mengenkripsi 8 byte sekaligus. File ini bertugas
menangani pesan panjang: memecah jadi blok-blok (CBC), dan merapikan ukuran
agar selalu kelipatan 8 (padding).

**`_pad(data)` — menambah padding PKCS#7**

```python
def _pad(data: bytes) -> bytes:
    n = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([n]) * n
```

- Hitung berapa byte tambahan `n` agar panjang jadi kelipatan 8.
- Tambahkan `n` buah byte yang semuanya bernilai `n`. Contoh: data 5 byte →
  tambah 3 byte `\x03\x03\x03`.
- Bila panjang sudah kelipatan 8, `n = 8` → ditambah 8 byte `\x08`. Penambahan
  full-block ini wajib agar saat dekripsi kita selalu bisa membedakan padding
  dari isi pesan (khususnya bila pesan asli berakhiran byte `\x08`).

**`_unpad(data)` — membuang padding**

```python
def _unpad(data: bytes) -> bytes:
    n = data[-1]
    if not (1 <= n <= BLOCK_SIZE) or data[-n:] != bytes([n]) * n:
        raise ValueError("padding rusak")
    return data[:-n]
```

- Baca byte terakhir `n`, artinya "ada `n` byte padding".
- Periksa `n` antara 1 dan 8, **dan** `n` byte terakhir memang semuanya `n`.
- Jika valid, potong `n` byte terakhir. Jika tidak (misal ciphertext diubah
  orang), lempar `ValueError` — ini pendeteksi kerusakan/problem integritas
  sederhana.

**`_encrypt_cbc(blocks, round_keys, iv)` — rantai blok saat enkripsi**

```python
def _encrypt_cbc(blocks: list, round_keys: list, iv: bytes) -> bytes:
    out = b""
    prev = iv
    for block in blocks:
        prev = encrypt_block(bytes(a ^ b for a, b in zip(block, prev)), round_keys)
        out += prev
    return out
```

- `prev` adalah "blok sebelumnya" (dimulai dari `iv`).
- Untuk tiap blok: **XOR blok dengan blok sebelumnya, baru dienkripsi**, dan
  hasilnya menjadi `prev` untuk blok berikutnya. Rantai `Cᵢ = Enc(Pᵢ XOR Cᵢ₋₁)`
  inilah kenapa mode-nya disebut CBC (Cipher Block Chaining).
- `bytes(a ^ b for a, b in zip(block, prev))` adalah cara singkat melakukan
  XOR byte-per-byte dua deretan byte.

**`_decrypt_cbc(data, round_keys, iv)` — membuka rantai saat dekripsi**

```python
def _decrypt_cbc(data: bytes, round_keys: list, iv: bytes) -> bytes:
    out = b""
    prev = iv
    for i in range(0, len(data), BLOCK_SIZE):
        enc = data[i:i + BLOCK_SIZE]
        out += bytes(a ^ b for a, b in zip(decrypt_block(enc, round_keys), prev))
        prev = enc
    return out
```

Kebalikan dari atas: **dekripsi dulu bloknya, baru XOR dengan blok
sebelumnya** (`Pᵢ = Dec(Cᵢ) XOR Cᵢ₋₁`). `prev` di-update ke blok terenkripsi
(`enc`), bukan blok hasil dekripsi.

**`encrypt(plaintext, key)` — API enkripsi publik**

```python
def encrypt(plaintext: bytes, key: bytes) -> bytes:
    round_keys = make_round_keys(key)
    iv = os.urandom(BLOCK_SIZE)     # IV acak 8 byte baru tiap panggilan
    padded = _pad(plaintext)
    blocks = [padded[i:i + BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    return iv + _encrypt_cbc(blocks, round_keys, iv)
```

- Buat round key dari key.
- Bangkitkan IV acak 8 byte dengan `os.urandom` (sumber acak dari sistem —
  bagus untuk kriptografi). IV acak tiap pesan inilah yang membuat pesan sama
  dikirim dua kali menghasilkan ciphertext berbeda.
- Padding, pecah jadi blok-blok 8 byte, jalankan CBC, lalu kembalikan
  `IV + ciphertext` dalam satu deretan byte. IV tidak rahasia dan boleh
  dikirim apa adanya.

**`decrypt(data, key)` — API dekripsi publik**

```python
def decrypt(data: bytes, key: bytes) -> bytes:
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("data bukan kelipatan blok")
    round_keys = make_round_keys(key)
    iv, ciphertext = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
    return _unpad(_decrypt_cbc(ciphertext, round_keys, iv))
```

- Pastikan total data kelipatan 8 (selalu begitu bila berasal dari `encrypt`).
- Ambil 8 byte pertama sebagai IV, sisanya ciphertext.
- Buka CBC lalu buang padding. Bila padding rusak → `ValueError` menyebar ke
  pemanggil.

---

### `config.py` — Pengaturan Bersama

```python
KEY = bytes.fromhex("f8a1c53a304eb1c37546f864b598d0c1")
HOST = "127.0.0.1"
PORT = 9000
```

- `KEY` — kunci rahasia bersama (pre-shared) 16 byte. Harus **sama persis** di
  kedua peer dan tidak pernah dikirim lewat jaringan. `bytes.fromhex(...)`
  mengubah teks hex jadi deretan byte aktual.
- `HOST` — alamat tempat mode `listen` "menyandarkan" server (loopback = mesin
  sendiri).
- `PORT` — nomor port tempat menunggu koneksi.

  Ketika dijalankan demo, key dari file ini wajib disetujui/diatur sama di
  kedua sisi peer agar cocok. Key untuk file ini sengaja **berbeda** dari key
  uji di `test_cipher.py`.

---

### `peer.py` — Komunikasi Dua Arah

File ini tidak berhubungan dengan kripto, melainkan networking: dua thread
(satu kirim, satu terima) di atas TCP socket, plus framing supaya penerima tahu
di mana batas tiap pesan (karena TCP adalah aliran byte tanpa batas).

```python
HEADER = 4            # panjang field panjang, dalam byte
MAX_PAYLOAD = 1 << 20  # batas panjang pesan: 1 MB, agar aman dari serangan yang
                       # memaksa server menerima data raksasa
```

**`_send_frame(sock, data)` — mengirim satu frame**

```python
def _send_frame(sock: socket.socket, data: bytes) -> None:
    sock.sendall(len(data).to_bytes(HEADER, "big") + data)
```

Tulis panjang data (4 byte, big-endian) lalu data itu sendiri. Satu frame di
jaringan jadi `[4 byte panjang][data]`.

**`_recv_exact(sock, n)` — membaca persis n byte**

```python
def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = b""
    while len(chunks) < n:
        chunk = sock.recv(n - len(chunks))
        if not chunk:
            raise ConnectionResetError("koneksi ditutup lawan bicara")
        chunks += chunk
    return chunks
```

Satu panggilan `recv` tidak menjamin data langsung lengkap; data bisa datang
berpindah-pindah. Fungsi ini memanggil `recv` berulang sampai terkumpul persis
`n` byte. Bila lawan menutup koneksi lebih dulu (`recv` mengembalikan `b""`),
lempar `ConnectionResetError`.

**`_recv_frame(sock)` — membaca satu frame utuh**

```python
def _recv_frame(sock: socket.socket) -> bytes:
    length = int.from_bytes(_recv_exact(sock, HEADER), "big")
    if length <= 0 or length > MAX_PAYLOAD:
        raise ValueError(f"panjang payload tidak valid: {length}")
    return _recv_exact(sock, length)
```

Baca 4 byte header → dapatkan `length`, periksa nilainya wajar (positif dan
≤ 1 MB) untuk menghindari frame nakal, lalu baca persis `length` byte isi.

**`send_loop(sock)` — thread pengirim**

```python
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
```

- Ulang terus: baca satu baris dari keyboard.
- `quit` → tutup socket, selesai.
- Kalau tidak: ubah teks ke `utf-8`, enkripsi, tampilkan ciphertext sebagai
  hex (dipotong 8 byte di depan = IV, jadi yang ditampilkan murni ciphertext),
  lalu kirim satu frame. Terlihat bahwa yang benar-benar lewat jaringan adalah
  ciphertext, bukan plaintext.

**`recv_loop(sock)` — thread penerima**

```python
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
```

- Terima satu frame; bila koneksi putus, laporkan dan berhenti.
- Tampilkan IV dan ciphertext (hex) yang baru saja tiba.
- Dekripsi dengan key bersama; hasil byte di-decode jadi teks UTF-8 dan
  ditampilkan. Bila dekripsi gagal (mis. padding rusak), tampilkan pesan
  errornya tanpa mematikan thread.

**`run(conn)` — menghubungkan dua thread**

```python
def run(conn: socket.socket) -> None:
    print("Terhubung. Ketik pesan lalu Enter untuk mengirim, 'quit' untuk menutup.")
    threading.Thread(target=recv_loop, args=(conn,), daemon=True).start()
    send_loop(conn)
```

- Mulai thread penerima (`daemon=True` agar ikut mati saat program selesai).
- Jalankan loop pengirim di thread utama. Jadi kita bisa mengetik sambil tetap
  mendengarkan jawaban lawan.

**`listen()` — mode server**

```python
def listen() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"[listener] menunggu koneksi di {HOST}:{PORT} ...")
        conn, addr = server.accept()
    print(f"[listener] tersambung dari {addr}")
    run(conn)
```

- AF_INET = jaringan TCP/IP, SOCK_STREAM = TCP.
- `SO_REUSEADDR` mengizinkan port langsung dipakai lagi setelah program tutup
  (menghindari error "Address already in use").
- `bind` mengikat server ke `HOST:PORT`, `listen(1)` menyiapkan antrean,
  `accept` menunggu hingga ada yang tersambung, lalu menyerahkan koneksinya ke
  `run`.

**`connect(host)` — mode client**

```python
def connect(host: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, PORT))
        print(f"[connector] tersambung ke {host}:{PORT}")
        run(sock)
```

Pasang socket dan `connect` ke `host:PORT` lawan, lalu `run`. Sisi ini yang
berperan sebagai penginisialisasi koneksi (berlawanan dengan mode `listen`
yang menunggu).

**`main()` — titik masuk program**

```python
def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] not in ("listen", "connect"):
        sys.exit("pemakaian: python3 peer.py listen | python3 peer.py connect <host>")
    if args[0] == "listen":
        listen()
    else:
        connect(args[1])
```

Pilih mode berdasarkan argumen baris perintah: `listen` → jadi server,
`connect <host>` → jadi client. Salah pemakaian → tampilkan petunjuk lalu
keluar.

---

### `test_cipher.py` — Pengujian Otomatis

Bukan kode produksi, melainkan pembukti bahwa cipher perilaku sesuai
spesifikasi di README. Tiap fungsi tes memanggil fungsi tertentu cipher dan
membandingkan dengan nilai yang diharapkan:

- `test_round_keys()` — 8 round key harus cocok dengan test vector
  `3c6cf775 ... f1ff6db0`.
- `test_single_block()` — `encrypt_block` blok `0123456789abcdef` harus
  menjadi `3d5cfedd8cbf57f2`, dan `decrypt_block` harus mengembalikannya lagi.
- `test_cbc_fixed_iv()` — CBC dengan IV tetap harus menghasilkan ciphertext
  spesifik, membuktikan enkripsi deterministik bila IV-nya tetap.
- `test_roundtrip_lengths()` — `decrypt(encrypt(x)) == x` untuk berbagai
  panjang (0, 1, 7, 8, 9, 1000 byte), termasuk kasus batas padding.
- `test_random_iv()` — pesan sama dua kali menghasilkan ciphertext berbeda
  (karena IV acak), tetapi keduanya tetap terdekripsi dengan benar.
- `test_bad_padding_rejected()` — ciphertext yang salah satu byte paddingnya
  diubah harus ditolak (`ValueError`).
- `test_wrong_key()` — dekripsi dengan key yang salah tidak boleh
  menghasilkan plaintext asli.

Fungsi `check()` cukup mencetak `[ok]` atau `[GAGAL]` dan menghitung jumlah
yang lulus. `main()` menjalankan semua tes dan keluar dengan kode 0 hanya bila
semuanya lulus (9/9). Konstanta `TEST_KEY` (`000102...0e0f`) hanyalah untuk
tes dan tidak dipakai di komunikasi nyata.

## Pengujian

`python3 test_cipher.py` memverifikasi:
- round key cocok dengan test vector,
- `encrypt_block` / `decrypt_block` cocok dengan test vector,
- CBC dengan IV tetap cocok dengan test vector,
- round-trip `decrypt(encrypt(x)) == x` untuk panjang 0, 1, 7, 8, 9, 1000 byte,
- pesan sama dua kali → ciphertext berbeda (efek IV),
- padding rusak ditolak,
- key salah tidak menghasilkan plaintext asli.

Key uji `000102030405060708090a0b0c0d0e0f` hanya untuk `test_cipher.py`; key di
`config.py` dibuat sendiri (16 byte acak via `os.urandom`).