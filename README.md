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

Jalankan tes terlebih dahulu:

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
sehingga dapat diamati bahwa data yang melewati jaringan adalah ciphertext.

Alur demo:
1. Jalankan `listen` di terminal 1 dan `connect` di terminal 2.
2. A mengirim pesan ke B; perhatikan ciphertext heksadesimal di sisi pengirim
   dan plaintext hasil dekripsi di B.
3. B membalas ke A untuk membuktikan komunikasi dua arah.
4. Kirim pesan yang sama dua kali; ciphertext yang dihasilkan akan berbeda
   (efek IV acak pada CBC).

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

Fungsi pembantu `rotl(x, n)` merupakan rotasi kiri sirkular pada 32 bit,
dengan `n` diambil mod 32:

```
rotl(x, n) = ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
```

### Key schedule

Key 128 bit dipecah menjadi 4 word K₀..K₃. Untuk tiap ronde `i = 0..7`:

```
k     = K[i mod 4]  XOR  (((i + 1) * 0x9E3779B9) & 0xFFFFFFFF)
RK[i] = rotl(k, 3*i + 1)
```

Konstanta `0x9E3779B9` (proporsi emas, 2³²/φ) digunakan agar setiap ronde
memiliki round key yang berbeda walaupun word key hanya empat.

### Fungsi ronde F(R, k)

Masukan: `R` (32 bit) dan round key `k`. Langkah:

1. **Tambah key:** `t = (R + k) mod 2³²`
2. **Rotasi:** `t = rotl(t, 5)`
3. **Substitusi:** pecah `t` menjadi 8 nibble, ganti tiap nibble lewat S-box
   4 bit di bawah, lalu gabungkan pada posisi yang sama
4. **Difusi:** `t = t XOR rotl(t, 9) XOR rotl(t, 21)`
5. **Rotasi akhir:** `t = rotl(t, 11)`, hasil `F = t`

Langkah 4 penting: tanpa difusi, perubahan satu bit pada masukan F tidak akan
menyebar ke banyak bit meskipun telah melalui 8 ronde.

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
kriptografi. Berikut penjelasan untuk setiap file.

### `feistel.py` — Cipher Blok (Inti Algoritma)

Bagian ini berisi inti operasi kripto: S-box, fungsi ronde, key schedule, dan
enkripsi/dekripsi satu blok 8 byte.

**Konstanta global**

```python
BLOCK_SIZE = 8      # satu blok = 8 byte = 64 bit
KEY_SIZE = 16        # key = 16 byte = 128 bit
NUM_ROUNDS = 8       # jumlah ronde
MASK32 = 0xFFFFFFFF  # penutup agar hasil tetap 32 bit
GOLDEN_RATIO = 0x9E3779B9  # konstanta yang diadopsi dari TEA, 2^32 / φ
```

- `MASK32` digunakan setiap kali perlu dipastikan bahwa sebuah nilai tetap
  berada dalam rentang 32 bit, yaitu dengan operasi AND `& 0xFFFFFFFF`.
- `GOLDEN_RATIO` adalah konstanta hasil pembagian 2^32 dengan rasio emas.
  Konstanta ini memastikan setiap ronde memperoleh round key yang berbeda.

**S-box**

```python
SBOX = [0x6, 0xB, 0x3, 0xE, 0x0, 0x9, 0xD, 0x5,
        0xA, 0x2, 0xF, 0x7, 0x4, 0x8, 0x1, 0xC]
```

S-box merupakan fungsi substitusi: setiap 4 bit (nilai 0–15) diganti dengan
nilai lain sesuai tabel. Misalnya masukan `0` menjadi `6` dan masukan `0xF`
menjadi `0xC`. Tujuannya untuk membuat hubungan masukan–keluaran tidak linear
sehingga menyulitkan analisis pola oleh pihak penyerang. Tabel ini merupakan
permutasi 0..15 (seluruh nilai muncul tepat satu kali).

**`rotl(x, n)` — rotasi kiri sirkular 32 bit**

```python
def rotl(x: int, n: int) -> int:
    n %= 32                       # amankan nilai n agar tidak lebih dari 32
    return ((x << n) | (x >> (32 - n))) & MASK32
```

Rotasi kiri sirkular berarti bit yang keluar melalui sisi kiri akan kembali
masuk melalui sisi kanan. Contoh pada 8 bit: `10110000` digeser kiri 1 bit
menjadi `01100001`, bukan `01100000`. Implementasinya: nilai digeser kiri
sebanyak `n` bit, kemudian bit yang hilang di sisi kanan dipulihkan melalui
`x >> (32 - n)`. Hasil akhir dipotong dengan `& MASK32` agar tetap 32 bit.
Baris `n %= 32` mengantisipasi pemanggilan dengan `n ≥ 32` (rotasi 33 kali
ekuivalen dengan rotasi 1 kali).

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

- Key 16 byte dipecah menjadi 4 word masing-masing 4 byte (K₀..K₃), dibaca
  sebagai big-endian (`int.from_bytes(..., "big")`).
- Untuk ronde `i` dari 0 sampai 7: diambil word `i % 4` (sehingga berulang
  K₀, K₁, K₂, K₃, K₀, ...), di-XOR dengan `(i+1) * GOLDEN_RATIO`, kemudian
  dirotasikan kiri sebanyak `3*i + 1` bit. Hasilnya berupa 8 round key yang
  berbeda satu sama lain meskipun hanya terdapat 4 word.

**`_substitute(t)` — substitusi 8 nibble**

```python
def _substitute(t: int) -> int:
    out = 0
    for shift in range(0, 32, 4):        # shift 0,4,8,...,28
        out |= SBOX[(t >> shift) & 0xF] << shift
    return out
```

- Nilai 32 bit `t` dipecah menjadi 8 bagian berukuran 4 bit (nibble).
- Setiap nibble diganti melalui S-box, kemudian disusun kembali pada posisi
  semula.
- `(t >> shift) & 0xF` mengambil nibble ke-`shift`, `SBOX[...]` mengganti
  nilainya, `<< shift` mengembalikannya ke posisi semula, dan `|=`
  menggabungkan seluruh hasilnya.

**`f(r, k)` — fungsi ronde**

```python
def f(r: int, k: int) -> int:
    t = (r + k) & MASK32          # 1. tambahkan round key
    t = rotl(t, 5)                # 2. rotasi 5 bit
    t = _substitute(t)            # 3. substitusi S-box
    t = t ^ rotl(t, 9) ^ rotl(t, 21)  # 4. difusi: campur bit ke seluruh 32 bit
    return rotl(t, 11)            # 5. rotasi akhir
```

Urutan kelima langkah tersebut adalah **penambahan key → rotasi →
substitusi → difusi → rotasi**. Langkah 4 menyebabkan perubahan satu bit pada
masukan tersebar menjadi banyak bit yang berubah pada keluaran. Tanpa difusi,
delapan ronde tidak cukup untuk menghasilkan pengacakan data yang memadai.

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

Ini merupakan inti dari struktur Feistel. Setiap ronde hanya melakukan satu
operasi pada sisi kiri:

```
L, R = R,  L XOR f(R, key)
```

Artinya, sisi kanan lama `R` menjadi sisi kiri baru (dipindahkan tanpa
perubahan), sedangkan sisi kiri lama `L` di-XOR kan dengan hasil `f(R, key)`.
Karena modifikasi hanya muncul melalui `f` pada operasi XOR, dengan fungsi `f`
yang berkualitas maka seluruh blok ikut teracak.

Pada akhirnya, hasil ditulis **terbalik** (`R || L`, bukan `L || R`). Ini
bukanlah kesalahan, melainkan teknik yang memungkinkan enkripsi dan dekripsi
menggunakan kode yang sama.

**`decrypt_block(block, round_keys)` — dekripsi satu blok**

```python
def decrypt_block(block: bytes, round_keys: list) -> bytes:
    return encrypt_block(block, list(reversed(round_keys)))
```

Dekripsi cukup memanggil `encrypt_block` dengan urutan round key yang
dibalik. Inilah keunggulan utama struktur Feistel: **tidak diperlukan invers
dari fungsi `f`, S-box, maupun rotasi**. Dekripsi merupakan enkripsi yang
berjalan mundur.

---

### `cipher.py` — Mode CBC + Padding PKCS#7

Cipher blok hanya mampu mengenkripsi 8 byte dalam satu operasi. File ini
bertugas menangani pesan dengan panjang berapa pun, dengan memecahnya menjadi
blok-blok (CBC) serta menyesuaikan panjang data agar selalu kelipatan 8
(padding).

**`_pad(data)` — menambah padding PKCS#7**

```python
def _pad(data: bytes) -> bytes:
    n = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([n]) * n
```

- Menentukan jumlah byte tambahan `n` agar panjang menjadi kelipatan 8.
- Menambahkan `n` byte yang seluruhnya bernilai `n`. Contoh: data sepanjang 5
  byte ditambah 3 byte `\x03\x03\x03`.
- Bila panjang sudah merupakan kelipatan 8, maka `n = 8` sehingga ditambahkan
  8 byte `\x08`. Penambahan satu blok penuh ini perlu dilakukan agar saat
  dekripsi padding dapat dibedakan dari isi pesan (khususnya bila pesan asli
  berakhiran byte `\x08`).

**`_unpad(data)` — membuang padding**

```python
def _unpad(data: bytes) -> bytes:
    n = data[-1]
    if not (1 <= n <= BLOCK_SIZE) or data[-n:] != bytes([n]) * n:
        raise ValueError("padding rusak")
    return data[:-n]
```

- Membaca byte terakhir `n` yang menyatakan jumlah byte padding.
- Memvalidasi bahwa `n` berada pada rentang 1–8 **dan** bahwa `n` byte
  terakhir seluruhnya bernilai `n`.
- Bila valid, `n` byte terakhir dibuang. Bila tidak valid (misalnya akibat
  pengubahan ciphertext oleh pihak ketiga), dilempar `ValueError` — sebuah
  mekanisme deteksi kerusakan dan pengaman integritas yang sederhana.

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

- `prev` merepresentasikan "blok sebelumnya", yang diinisialisasi dengan `iv`.
- Untuk tiap blok: **blok di-XOR kan dengan blok sebelumnya, kemudian
  dienkripsi**, dan hasilnya menjadi `prev` untuk blok berikutnya. Rantai
  `Cᵢ = Enc(Pᵢ XOR Cᵢ₋₁)` inilah yang menjadi dasar penamaan CBC (Cipher Block
  Chaining).
- `bytes(a ^ b for a, b in zip(block, prev))` adalah cara ringkas melakukan XOR
  byte-per-byte pada dua deretan byte.

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

Prosesnya merupakan kebalikan dari enkripsi: **blok didekripsi terlebih
dahulu, kemudian di-XOR kan dengan blok sebelumnya** (`Pᵢ = Dec(Cᵢ) XOR
Cᵢ₋₁`). `prev` diperbarui ke blok terenkripsi (`enc`), bukan ke blok hasil
dekripsi.

**`encrypt(plaintext, key)` — API enkripsi publik**

```python
def encrypt(plaintext: bytes, key: bytes) -> bytes:
    round_keys = make_round_keys(key)
    iv = os.urandom(BLOCK_SIZE)     # IV acak 8 byte baru tiap panggilan
    padded = _pad(plaintext)
    blocks = [padded[i:i + BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    return iv + _encrypt_cbc(blocks, round_keys, iv)
```

- Membuat round key dari key.
- Membangkitkan IV acak 8 byte melalui `os.urandom` (sumber acak kriptografi
  dari sistem). Penggunaan IV acak pada setiap pesan menyebabkan pesan yang
  sama menjadi ciphertext berbeda ketika dienkripsi dua kali.
- Melakukan padding, memecah data menjadi blok-blok 8 byte, menjalankan CBC,
  lalu mengembalikan `IV + ciphertext` dalam satu deretan byte. IV bersifat
  publik dan boleh dikirim secara polos.

**`decrypt(data, key)` — API dekripsi publik**

```python
def decrypt(data: bytes, key: bytes) -> bytes:
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("data bukan kelipatan blok")
    round_keys = make_round_keys(key)
    iv, ciphertext = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
    return _unpad(_decrypt_cbc(ciphertext, round_keys, iv))
```

- Memastikan total panjang data merupakan kelipatan 8 (selalu berlaku untuk
  keluaran `encrypt`).
- Mengambil 8 byte pertama sebagai IV dan sisanya sebagai ciphertext.
- Membuka CBC lalu membuang padding. Bila padding rusak, `ValueError` akan
  menjalar ke pemanggil.

---

### `config.py` — Pengaturan Bersama

```python
KEY = bytes.fromhex("f8a1c53a304eb1c37546f864b598d0c1")
HOST = "127.0.0.1"
PORT = 9000
```

- `KEY` — kunci rahasia bersama (pre-shared key) 16 byte. Nilainya harus
  **identik** pada kedua peer dan tidak pernah dikirim melalui jaringan.
  `bytes.fromhex(...)` mengonversi representasi teks heksadesimal menjadi
  deretan byte.
- `HOST` — alamat yang digunakan mode `listen` untuk mengikat server (loopback
  berarti mesin lokal).
- `PORT` — nomor port yang digunakan untuk menunggu koneksi.

  Sebelum menjalankan demo, key pada file ini harus disetel serupa pada kedua
  sisi peer agar sesuai. Key pada file ini sengaja **berbeda** dari key uji di
  `test_cipher.py`.

---

### `peer.py` — Komunikasi Dua Arah

File ini menangani aspek networking, bukan kriptografi: dua thread (satu
pengirim, satu penerima) di atas TCP socket, serta framing agar penerima dapat
mengetahui batas setiap pesan (TCP merupakan aliran byte tanpa batas).

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

Tulis panjang data (4 byte, big-endian) lalu data itu sendiri, sehingga
struktur satu frame adalah `[4 byte panjang][data]`.

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

Satu pemanggilan `recv` tidak menjamin seluruh data langsung diterima; data
dapat tiba dalam beberapa fragmen. Fungsi ini memanggil `recv` secara berulang
hingga terkumpul tepat `n` byte. Bila lawan bicara menutup koneksi lebih dahulu
(`recv` mengembalikan `b""`), dilempar `ConnectionResetError`.

**`_recv_frame(sock)` — membaca satu frame utuh**

```python
def _recv_frame(sock: socket.socket) -> bytes:
    length = int.from_bytes(_recv_exact(sock, HEADER), "big")
    if length <= 0 or length > MAX_PAYLOAD:
        raise ValueError(f"panjang payload tidak valid: {length}")
    return _recv_exact(sock, length)
```

Membaca 4 byte header untuk mendapatkan `length`, memvalidasi nilainya (positif
dan tidak melebihi 1 MB) sebagai upaya menolak panjang payload yang tidak sah,
lalu membaca tepat `length` byte isi.

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

- Secara berulang, membaca satu baris masukan dari keyboard.
- Bila baris tersebut adalah `quit`, socket ditutup dan loop berakhir.
- Selain itu, teks dikonversi ke `utf-8`, dienkripsi, ciphertext ditampilkan
  dalam bentuk heksadesimal (8 byte awal dibuang karena merupakan IV, sehingga
  yang ditampilkan murni ciphertext), lalu dikirim sebagai satu frame. Tampilan
  ini memperlihatkan bahwa data yang benar-benar melewati jaringan adalah
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

- Menerima satu frame; bila koneksi terputus, situasi tersebut dilaporkan lalu
  thread berakhir.
- Menampilkan IV dan ciphertext (heksadesimal) yang baru saja diterima.
- Mendekripsi dengan key bersama, kemudian hasil byte didekode menjadi teks
  UTF-8 dan ditampilkan. Bila dekripsi gagal (misalnya padding rusak), pesan
  kesalahan ditampilkan tanpa menghentikan thread.

**`run(conn)` — menghubungkan dua thread**

```python
def run(conn: socket.socket) -> None:
    print("Terhubung. Ketik pesan lalu Enter untuk mengirim, 'quit' untuk menutup.")
    threading.Thread(target=recv_loop, args=(conn,), daemon=True).start()
    send_loop(conn)
```

- Memulai thread penerima (`daemon=True` agar thread berakhir bersamaan dengan
  berhentinya program).
- Menjalankan loop pengirim pada thread utama. Dengan demikian, pengguna dapat
  mengetik sekaligus tetap menerima balasan dari lawan bicara.

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

- `AF_INET` menandakan jaringan TCP/IP dan `SOCK_STREAM` menandakan protokol
  TCP.
- `SO_REUSEADDR` mengizinkan port digunakan kembali segera setelah program
  berhenti (menghindari galat "Address already in use").
- `bind` mengikat server ke `HOST:PORT`, `listen(1)` menyiapkan antrean
  koneksi, dan `accept` menunggu hingga ada koneksi masuk, lalu menyerahkan
  koneksi tersebut ke `run`.

**`connect(host)` — mode client**

```python
def connect(host: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, PORT))
        print(f"[connector] tersambung ke {host}:{PORT}")
        run(sock)
```

Membuat socket dan menghubungkannya ke `host:PORT` lawan, kemudian memanggil
`run`. Sisi ini berperan sebagai penginisialisasi koneksi (kebalikan dari mode
`listen` yang menunggu).

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

Menentukan mode berdasarkan argumen baris perintah: `listen` menjadikan
program berperan sebagai server, sedangkan `connect <host>` sebagai client.
Pemakaian yang salah menyebabkan program menampilkan petunjuk penggunaan lalu
keluar.

---

### `test_cipher.py` — Pengujian Otomatis

File ini bukan kode produksi, melainkan alat verifikasi untuk memastikan
cipher berperilaku sesuai spesifikasi pada README. Setiap fungsi tes memanggil
fungsi tertentu pada cipher dan membandingkan hasilnya dengan nilai yang
diharapkan:

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

Fungsi `check()` mencetak `[ok]` atau `[GAGAL]` serta menghitung jumlah tes
yang lulus. `main()` menjalankan seluruh tes dan keluar dengan kode 0 hanya
bila semuanya lulus (9/9). Konstanta `TEST_KEY` (`000102...0e0f`) semata-mata
digunakan untuk pengujian dan tidak dipakai pada komunikasi nyata.

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