# KI-Tugas1 — Simulasi Transmisi Ciphertext Dua Arah (DES)

Simulasi komunikasi dua arah antara dua peer yang bertukar **ciphertext** lewat
TCP socket. Algoritma **DES** (Data Encryption Standard, FIPS 46-3) + mode
**CBC** + padding **PKCS#7**, diimplementasikan **manual dari nol** tanpa library
kriptografi apa pun.

> **Cipher ini hanya untuk pembelajaran — jangan dipakai untuk melindungi data
> nyata.** DES sudah resmi ditarik NIST pada tahun 2005 karena hanya 56 bit
> kunci efektif, sehingga dapat dipecah dengan brute force. Mode CBC tanpa MAC
> juga tidak memberi integritas pesan. Lihat [Catatan Keamanan](#catatan-keamanan).

## Struktur file

```
des.py          cipher blok DES: IP/FP, PC-1/PC-2, S-box, fungsi F, encrypt/decrypt
cipher.py       mode CBC + padding PKCS#7: encrypt() / decrypt()
config.py       KEY (8 byte pre-shared), HOST, PORT
peer.py         komunikasi dua arah (mode listen / connect)
test_cipher.py  test vector + tes round-trip
README.md
```

`des.py` dan `cipher.py` dipakai bersama oleh kedua peer. Key **tidak** dikirim
lewat jaringan — bersifat pre-shared, dibaca dari `config.py` di kedua sisi.

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
| Ukuran key | 64 bit (8 byte) = 56 bit kunci + 8 bit paritas |
| Jumlah ronde | 16 |
| Subkey (round key) | 16 buah, masing-masing 48 bit |
| Ukuran paruh C dan D | 28 bit masing-masing |
| Urutan byte | Big-endian untuk semua konversi byte dan integer |
| Standar | FIPS 46-3 |

### Permutasi bit: satu fungsi untuk semua tabel

Seluruh transformasi DES — Initial Permutation, Final Permutation, PC-1, PC-2,
E, dan P — sebenarnya adalah operasi yang sama: **mengambil bit dari posisi
tertentu lalu menyusunnya di posisi baru**. Kode cukup satu fungsi:

```python
def _permute(value: int, table: tuple, in_bits: int) -> int:
    out = 0
    for i, pos in enumerate(table):
        out |= ((value >> (in_bits - pos)) & 1) << (len(table) - 1 - i)
    return out
```

Cara membacanya: untuk setiap entri `table[i] = pos`, bit ke-`pos` dari masukan
diambil melalui `(value >> (in_bits - pos)) & 1` (posisi `pos = 1` berarti bit
paling kiri), lalu diletakkan sebagai bit ke-`i` dari keluaran melalui
`<< (len(table) - 1 - i)`. Karena itu satu fungsi ini melayani IP, FP, PC-1,
PC-2, E, dan P.

### Initial Permutation (IP) dan Final Permutation (FP)

IP diterapkan lebih dulu pada blok 64 bit, memecahnya menjadi L dan R 32 bit:

```
58 50 42 34 26 18 10  2    40  8 48 16 56 24 64 32
60 52 44 36 28 20 12  4    39  7 47 15 55 23 63 31
62 54 46 38 30 22 14  6    38  6 46 14 54 22 62 30
64 56 48 40 32 24 16  8    37  5 45 13 53 21 61 29
57 49 41 33 25 17  9  1    36  4 44 12 52 20 60 28
59 51 43 35 27 19 11  3    35  3 43 11 51 19 59 27
61 53 45 37 29 21 13  5    34  2 42 10 50 18 58 26
63 55 47 39 31 23 15  7    33  1 41  9 49 17 57 25
   IP (kiri)                     FP (kanan)
```

FP adalah **invers** dari IP, sehingga `FP(IP(x)) == x`. Keduanya sudah
diverifikasi secara programatis di `test_cipher.py`.

### Key schedule (PC-1 dan PC-2)

```
PC-1  57 49 41 33 25 17  9     PC-2  14 17 11 24  1  5
       1 58 50 42 34 26 18            3 28 15  6 21 10
      10  2 59 51 43 35 27           23 19 12  4 26  8
      19 11  3 60 52 44 36           16  7 27 20 13  2
      63 55 47 39 31 23 15           41 52 31 37 47 55
       7 62 54 46 38 30 22           30 40 51 45 33 48
      14  6 61 53 45 37 29           44 49 39 56 34 53
      21 13  5 28 20 12  4           46 42 50 36 29 32
```

Langkah-langkahnya:

1. **PC-1** memilih 56 dari 64 bit key, membuang 8 bit paritas. Hasilnya dipecah
   menjadi paruh kiri `C` dan paruh kanan `D`, masing-masing 28 bit.
2. Untuk tiap ronde, `C` dan `D` dirotasi ke kiri dengan jumlah berbeda sesuai
   tabel di bawah.
3. Hasil rotasi `C` dan `D` digabung menjadi 56 bit, lalu diteruskan ke
   **PC-2** yang mengambil 48 bit menjadi subkey ronde ke-`i`.

Jumlah pergeseran per ronde:

| Ronde | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 |
|-------|---|---|---|---|---|---|---|---|----|----|----|----|----|----|----|----|
| Geser | 1 | 1 | 2 | 2 | 2 | 2 | 2 | 2 | 1 | 2  | 2  | 2  | 2  | 2  | 2  | 1  |

Jumlah seluruh pergeseran adalah 28, sehingga setelah 16 ronde `C` dan `D`
kembali ke posisi awal.

> **Catatan penting tentang bit paritas.** PC-1 membuang posisi
> 8, 16, 24, …, 64 — yaitu **bit paling kanan (LSB) dari tiap byte**, dan itu
> persis letak bit paritas. Konsekuensinya: dua key yang berbeda **hanya pada
> bit paritasnya menghasilkan subkey yang identik**. `test_cipher.py` menguji
> fakta ini secara eksplisit. DES benar-benar hanya memiliki 56 bit keamanan.

Rotasi kiri sirkular 28 bit:

```python
c = ((c << shift) | (c >> (28 - shift))) & MASK28
```

### Fungsi ronde F(R, k)

```
E   32  1  2  3  4  5     P   16  7 20 21 29 12 28 17
     4  5  6  7  8  9          1 15 23 26  5 18 31 10
     8  9 10 11 12 13          2  8 24 14 32 27  3  9
    12 13 14 15 16 17         19 13 30  6 22 11  4 25
    16 17 18 19 20 21
    20 21 22 23 24 25
    24 25 26 27 28 29
    28 29 30 31 32  1
```

1. **Ekspansi (E):** `R` 32 bit di-expand menjadi 48 bit. Tabel ini **bukan
   permutasi** — 16 bit terpilih diduplikasi (bit 1, 4, 5, 8, 9, …, 32 muncul
   dua kali) agar ukurannya sama dengan subkey.
2. **XOR dengan subkey:** 48 bit tersebut di-XOR dengan subkey ronde.
3. **Substitusi S-box:** 48 bit dipecah menjadi **8 grup @ 6 bit**, tiap grup
   dimasukkan ke S-box yang berbeda, hasilnya 4 bit, jadi total 32 bit.
4. **Permutasi (P):** 32 bit hasil S-box diacak dengan tabel P.

> **Dua bit terluar, empat bit tengah.** Untuk grup 6-bit `b1 b2 b3 b4 b5 b6`
> (b1 = bit paling kiri), **baris** diambil dari `b1` dan `b6` (dua bit
> terluar), sedangkan **kolom** diambil dari `b2 b3 b4 b5` (empat bit tengah).
> Dalam bentuk kode:
>
> ```python
> row = ((six >> 5) << 1) | (six & 0x01)   # b1 dan b6
> col = (six >> 1) & 0x0F                  # b2 b3 b4 b5
> ```
>
> Menukar dua bit ini adalah kesalahan yang sangat mudah terjadi, dan membuat
> seluruh hasil enkripsi salah tanpa memunculkan error apa pun.

Delapan S-box (4 baris x 16 kolom), `S1` sampai `S8` sesuai urutan ronde:

```
S1   14  4 13  1  2 15 11  8  3 10  6 12  5  9  0  7
      0 15  7  4 14  2 13  1 10  6 12 11  9  5  3  8
      4  1 14  8 13  6  2 11 15 12  9  7  3 10  5  0
     15 12  8  2  4  9  1  7  5 11  3 14 10  0  6 13

S2   15  1  8 14  6 11  3  4  9  7  2 13 12  0  5 10
      3 13  4  7 15  2  8 14 12  0  1 10  6  9 11  5
      0 14  7 11 10  4 13  1  5  8 12  6  9  3  2 15
     13  8 10  1  3 15  4  2 11  6  7 12  0  5 14  9

S3   10  0  9 14  6  3 15  5  1 13 12  7 11  4  2  8
     13  7  0  9  3  4  6 10  2  8  5 14 12 11 15  1
     13  6  4  9  8 15  3  0 11  1  2 12  5 10 14  7
      1 10 13  0  6  9  8  7  4 15 14  3 11  5  2 12

S4    7 13 14  3  0  6  9 10  1  2  8  5 11 12  4 15
     13  8 11  5  6 15  0  3  4  7  2 12  1 10 14  9
     10  6  9  0 12 11  7 13 15  1  3 14  5  2  8  4
      3 15  0  6 10  1 13  8  9  4  5 11 12  7  2 14

S5    2 12  4  1  7 10 11  6  8  5  3 15 13  0 14  9
     14 11  2 12  4  7 13  1  5  0 15 10  3  9  8  6
      4  2  1 11 10 13  7  8 15  9 12  5  6  3  0 14
     11  8 12  7  1 14  2 13  6 15  0  9 10  4  5  3

S6   12  1 10 15  9  2  6  8  0 13  3  4 14  7  5 11
     10 15  4  2  7 12  9  5  6  1 13 14  0 11  3  8
      9 14 15  5  2  8 12  3  7  0  4 10  1 13 11  6
      4  3  2 12  9  5 15 10 11 14  1  7  6  0  8 13

S7    4 11  2 14 15  0  8 13  3 12  9  7  5 10  6  1
     13  0 11  7  4  9  1 10 14  3  5 12  2 15  8  6
      1  4 11 13 12  3  7 14 10 15  6  8  0  5  9  2
      6 11 13  8  1  4 10  7  9  5  0 15 14  2  3 12

S8   13  2  8  4  6 15 11  1 10  9  3 14  5  0 12  7
      1 15 13  8 10  3  7  4 12  5  6 11  0 14  9  2
      7 11  4  1  9 12 14  2  0  6 10 13 15  3  5  8
      2  1 14  7  4 10  8 13 15 12  9  0  3  5  6 11
```

S-box adalah satu-satunya bagian DES yang **tidak linear**. Tabelnya dirancang
khusus untuk menahan serangan diferensial.

### Enkripsi satu blok

```
v     = IP(blok)
L, R  = v >> 32, v & 0xFFFFFFFF
untuk i = 0..15:
    L, R = R, L XOR f(R, K[i])
output = FP(R || L)                       # tukar posisi di akhir
```

### Dekripsi satu blok

Sama persis dengan enkripsi, hanya urutan subkey **dibalik**
(`K[15], K[14], ..., K[0]`). Tidak diperlukan fungsi invers untuk E, S-box,
maupun P — inilah keunggulan struktur Feistel yang dipakai DES.

### Mode CBC (blok 8 byte)

- Tiap pesan memakai **IV acak 8 byte** baru (`os.urandom`).
- Enkripsi: `C0 = IV`, `Ci = Enc(Pi XOR C(i-1))`
- Dekripsi: `Pi = Dec(Ci) XOR C(i-1)`
- IV tidak rahasia dan dikirim bersama ciphertext. Karena tiap pesan memakai IV
  baru, pesan yang sama dienkripsi dua kali menghasilkan ciphertext berbeda.

### Padding PKCS#7 (blok 8 byte)

- Tambahkan `n` byte dengan nilai `n`, di mana `n = 8 - (panjang mod 8)`. Bila
  panjang sudah kelipatan 8, tetap ditambah 8 byte padding agar bisa dibedakan.
- Saat dekripsi: baca byte terakhir `n`, validasi `1 <= n <= 8` dan bahwa `n`
  byte terakhir semuanya bernilai `n`, lalu buang. Padding yang rusak **ditolak**
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

### `des.py` — Cipher Blok DES (Inti Algoritma)

Berisi inti operasi kripto: seluruh tabel FIPS, key schedule, fungsi ronde, serta
enkripsi dan dekripsi satu blok 8 byte.

**Konstanta global**

```python
BLOCK_SIZE = 8      # satu blok = 8 byte = 64 bit
KEY_SIZE = 8        # key = 8 byte = 64 bit (56 bit kunci + 8 bit paritas)
NUM_ROUNDS = 16     # jumlah ronde
MASK32 = 0xFFFFFFFF # penutup agar hasil tetap 32 bit
MASK28 = 0x0FFFFFFF # penutup agar hasil tetap 28 bit
```

- `MASK32` dipakai agar nilai tetap berada dalam rentang 32 bit saat dipisah
  menjadi L dan R dan saat digabung kembali.
- `MASK28` dipakai untuk menjaga C dan D tetap 28 bit setelah rotasi.

**Tabel**

| Tabel | Isi | Ukuran |
|-------|-----|--------|
| `IP` | Initial Permutation | 64 |
| `FP` | Final Permutation (invers IP) | 64 |
| `PC1` | Permuted Choice 1 | 56 dari 64 |
| `PC2` | Permuted Choice 2 | 48 dari 56 |
| `E` | Ekspansi | 48 dari 32 (dengan duplikasi) |
| `P` | Permutasi keluaran S-box | 32 |
| `SBOXES` | 8 S-box @ 4 baris x 16 kolom | 6-bit jadi 4-bit |
| `SHIFTS` | Pergeseran rotasi per ronde | 16 |

**`_permute(value, table, in_bits)` — permutasi bit generik**

Satu fungsi melayani semua tabel, dijelaskan pada bagian
[Permutasi bit](#permutasi-bit-satu-fungsi-untuk-semua-tabel).

**`make_subkeys(key)` — key schedule**

```python
def make_subkeys(key: bytes) -> list:
    if len(key) != KEY_SIZE:
        raise ValueError(f"key harus {KEY_SIZE} byte")
    cd = _permute(int.from_bytes(key, "big"), PC1, 64)
    c, d = cd >> 28, cd & MASK28
    subkeys = []
    for shift in SHIFTS:
        c = ((c << shift) | (c >> (28 - shift))) & MASK28
        d = ((d << shift) | (d >> (28 - shift))) & MASK28
        subkeys.append(_permute((c << 28) | d, PC2, 56))
    return subkeys
```

- Key 8 byte dibaca sebagai integer big-endian, lalu PC-1 membuang 8 bit paritas
  dan menyisakan 56 bit.
- `cd >> 28` mengambil paruh kiri C (28 bit teratas) dan `cd & MASK28` mengambil
  paruh kanan D (28 bit terbawah).
- Tiap ronde, C dan D dirotasi ke kiri sebanyak `shift`, lalu digabung sebagai
  `(c << 28) | d` untuk diteruskan ke PC-2.
- PC-2 mengambil 48 bit dari 56 bit tersebut menjadi subkey ronde itu.
- Mengembalikan list berisi 16 subkey, masing-masing 48 bit.

**`_f(right, subkey)` — fungsi ronde**

```python
def _f(right: int, subkey: int) -> int:
    expanded = _permute(right, E, 32) ^ subkey
    out = 0
    for i in range(8):
        six = (expanded >> (42 - 6 * i)) & 0x3F
        row = ((six >> 5) << 1) | (six & 0x01)
        col = (six >> 1) & 0x0F
        out |= SBOXES[i][row][col] << (28 - 4 * i)
    return _permute(out, P, 32)
```

- `_permute(right, E, 32)` melakukan ekspansi 32 bit jadi 48 bit, lalu di-XOR
  dengan subkey (keduanya 48 bit).
- `(expanded >> (42 - 6 * i)) & 0x3F` mengambil grup ke-`i`: untuk `i = 0` geser
  42 bit (6 bit teratas), untuk `i = 7` geser 0 bit (6 bit terbawah).
- `row` dan `col` dihitung dari dua bit terluar dan empat bit tengah, lalu
  `SBOXES[i][row][col]` memberikan 4 bit.
- `<< (28 - 4 * i)` menaruh 4 bit hasil S-box ke-`i` pada posisi yang benar
  (`i = 0` geser 28, `i = 7` geser 0).
- Terakhir, P mengacak 32 bit tersebut.

**`encrypt_block(block, subkeys)` — enkripsi satu blok**

```python
def encrypt_block(block: bytes, subkeys: list) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"blok harus {BLOCK_SIZE} byte")
    value = _permute(int.from_bytes(block, "big"), IP, 64)
    left, right = value >> 32, value & MASK32
    for subkey in subkeys:
        left, right = right, left ^ _f(right, subkey)
    return _permute((right << 32) | left, FP, 64).to_bytes(BLOCK_SIZE, "big")
```

- Validasi panjang blok harus tepat 8 byte.
- `IP` diterapkan, lalu `value >> 32` adalah L dan `value & MASK32` adalah R.
- Struktur Feistel: `L, R = R, L XOR f(R, K[i])`. Sisi kanan lama `R` menjadi
  sisi kiri baru, sedangkan sisi kiri lama di-XOR dengan hasil `f`.
- Setelah 16 ronde, R dan L digabung **terbalik** (`R || L`) lalu `FP`
  diterapkan. Penukaran ini bukan kesalahan, melainkan bagian dari spesifikasi
  DES.
- Hasil dikembalikan sebagai 8 byte.

**`decrypt_block(block, subkeys)` — dekripsi satu blok**

```python
def decrypt_block(block: bytes, subkeys: list) -> bytes:
    return encrypt_block(block, list(reversed(subkeys)))
```

Dekripsi cukup memanggil `encrypt_block` dengan urutan subkey dibalik. Tidak
diperlukan invers dari E, S-box, maupun P.

**`has_valid_parity(key)` — validasi bit paritas**

```python
def has_valid_parity(key: bytes) -> bool:
    if len(key) != KEY_SIZE:
        raise ValueError(f"key harus {KEY_SIZE} byte")
    return all(bin(byte).count("1") % 2 == 1 for byte in key)
```

Setiap byte key harus berisi jumlah bit 1 yang ganjil. Fungsi ini bersifat
**informatif** — `make_subkeys` tidak menegakkan paritas, karena PC-1 membuang
bit paritas sehingga paritas tidak memengaruhi hasil enkripsi sama sekali.

---

### `cipher.py` — Mode CBC + Padding PKCS#7

Cipher blok hanya mampu mengenkripsi 8 byte dalam satu operasi. File ini
bertugas menangani pesan dengan panjang berapa pun, dengan memecahnya menjadi
blok-blok (CBC) serta menyesuaikan panjang data agar selalu kelipatan 8.

**`_pad(data)` — menambah padding PKCS#7**

```python
def _pad(data: bytes) -> bytes:
    n = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([n]) * n
```

- Menentukan jumlah byte tambahan `n` agar panjang menjadi kelipatan 8.
- Menambahkan `n` byte yang seluruhnya bernilai `n`. Contoh: data sepanjang 5
  byte ditambah 3 byte `\x03\x03\x03`.
- Bila panjang sudah kelipatan 8, maka `n = 8` sehingga ditambahkan 8 byte
  `\x08`. Penambahan satu blok penuh ini perlu agar padding saat dekripsi dapat
  dibedakan dari isi pesan.

**`_unpad(data)` — membuang padding**

```python
def _unpad(data: bytes) -> bytes:
    n = data[-1]
    if not (1 <= n <= BLOCK_SIZE) or data[-n:] != bytes([n]) * n:
        raise ValueError("padding rusak")
    return data[:-n]
```

- Membaca byte terakhir `n` yang menyatakan jumlah byte padding.
- Memvalidasi `n` pada rentang 1 sampai 8 **dan** bahwa `n` byte terakhir
  semuanya bernilai `n`.
- Bila valid, `n` byte terakhir dibuang. Bila tidak, dilempar `ValueError`.

**`_encrypt_cbc(blocks, subkeys, iv)` — rantai blok saat enkripsi**

```python
def _encrypt_cbc(blocks: list, subkeys: list, iv: bytes) -> bytes:
    out = b""
    prev = iv
    for block in blocks:
        prev = encrypt_block(bytes(a ^ b for a, b in zip(block, prev)), subkeys)
        out += prev
    return out
```

- `prev` adalah "blok sebelumnya", diinisialisasi dengan `iv`.
- Tiap blok di-XOR dengan blok sebelumnya, lalu dienkripsi; hasilnya menjadi
  `prev` untuk blok berikutnya. Inilah rantai `Ci = Enc(Pi XOR C(i-1))`.
- `bytes(a ^ b for a, b in zip(block, prev))` melakukan XOR byte-per-byte.

**`_decrypt_cbc(data, subkeys, iv)` — membuka rantai saat dekripsi**

```python
def _decrypt_cbc(data: bytes, subkeys: list, iv: bytes) -> bytes:
    out = b""
    prev = iv
    for i in range(0, len(data), BLOCK_SIZE):
        enc = data[i:i + BLOCK_SIZE]
        out += bytes(a ^ b for a, b in zip(decrypt_block(enc, subkeys), prev))
        prev = enc
    return out
```

Kebalikan dari enkripsi: blok didekripsi dahulu, baru di-XOR dengan blok
sebelumnya. `prev` diperbarui ke blok **terenkripsi** (`enc`), bukan ke hasil
dekripsi.

**`encrypt(plaintext, key)` — API enkripsi publik**

```python
def encrypt(plaintext: bytes, key: bytes) -> bytes:
    subkeys = make_subkeys(key)
    iv = os.urandom(BLOCK_SIZE)
    padded = _pad(plaintext)
    blocks = [padded[i:i + BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    return iv + _encrypt_cbc(blocks, subkeys, iv)
```

- Membangkitkan IV acak 8 byte tiap panggilan, sehingga pesan yang sama
  menghasilkan ciphertext berbeda.
- Melakukan padding, memecah data, menjalankan CBC, lalu mengembalikan
  `IV + ciphertext` dalam satu deretan byte. IV bersifat publik.

**`decrypt(data, key)` — API dekripsi publik**

```python
def decrypt(data: bytes, key: bytes) -> bytes:
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("data bukan kelipatan blok")
    subkeys = make_subkeys(key)
    iv, ciphertext = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
    return _unpad(_decrypt_cbc(ciphertext, subkeys, iv))
```

Memastikan panjang kelipatan 8, mengambil 8 byte pertama sebagai IV, membuka
CBC, lalu membuang padding.

---

### `config.py` — Pengaturan Bersama

```python
KEY = bytes.fromhex("2c67464f2915c852")
HOST = "127.0.0.1"
PORT = 9000
```

- `KEY` — kunci rahasia bersama (pre-shared key) **8 byte**. Harus **identik**
  pada kedua peer dan tidak pernah dikirim melalui jaringan. Nilai ini
  menggunakan paritas ganjil pada setiap byte.
- `HOST` — alamat untuk mode `listen` (loopback berarti mesin lokal).
- `PORT` — nomor port untuk menunggu koneksi.

  Sebelum menjalankan demo, key pada file ini harus disetel serupa pada kedua
  sisi peer. Key di sini sengaja **berbeda** dari key uji di `test_cipher.py`.

---

### `peer.py` — Komunikasi Dua Arah

File ini menangani aspek networking, bukan kriptografi: dua thread (satu
pengirim, satu penerima) di atas TCP socket, serta framing agar penerima dapat
mengetahui batas setiap pesan (TCP merupakan aliran byte tanpa batas).

```python
HEADER = 4            # panjang field panjang, dalam byte
MAX_PAYLOAD = 1 << 20  # batas panjang pesan 1 MB, agar aman dari serangan yang
                       # memaksa server menerima data raksasa
```

**`_send_frame(sock, data)` — mengirim satu frame**

```python
def _send_frame(sock: socket.socket, data: bytes) -> None:
    sock.sendall(len(data).to_bytes(HEADER, "big") + data)
```

Struktur satu frame adalah `[4 byte panjang][data]`.

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

Satu pemanggilan `recv` tidak menjamin seluruh data langsung diterima. Fungsi ini
memanggil `recv` berulang hingga terkumpul tepat `n` byte. Bila lawan bicara
menutup koneksi lebih dulu, dilempar `ConnectionResetError`.

**`_recv_frame(sock)` — membaca satu frame utuh**

```python
def _recv_frame(sock: socket.socket) -> bytes:
    length = int.from_bytes(_recv_exact(sock, HEADER), "big")
    if length <= 0 or length > MAX_PAYLOAD:
        raise ValueError(f"panjang payload tidak valid: {length}")
    return _recv_exact(sock, length)
```

Membaca 4 byte header, memvalidasi nilainya (positif dan tidak melebihi 1 MB),
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
        print(f"[kirim] ciphertext ({len(payload[BLOCK_SIZE:])} byte): "
              f"{payload[BLOCK_SIZE:].hex()}")
        _send_frame(sock, payload)
```

- Membaca satu baris masukan; bila `quit`, socket ditutup dan loop berakhir.
- Teks dikonversi ke UTF-8, dienkripsi, ciphertext ditampilkan dalam heksadesimal
  (8 byte awal dibuang karena merupakan IV), lalu dikirim sebagai satu frame.
  Tampilan ini memperlihatkan bahwa yang benar-benar melewati jaringan adalah
  ciphertext.

**`recv_loop(sock)` — thread penerima**

```python
def recv_loop(sock: socket.socket) -> None:
    while True:
        try:
            payload = _recv_frame(sock)
        except (ConnectionResetError, EOFError, OSError):
            print("[terima] koneksi ditutup")
            return
        iv, ct = payload[:BLOCK_SIZE], payload[BLOCK_SIZE:]
        print(f"[terima] ciphertext ({len(ct)} byte): {ct.hex()}  (IV: {iv.hex()})")
        try:
            print(f"[terima] plaintext: {decrypt(payload, KEY).decode('utf-8')}")
        except ValueError as exc:
            print(f"[terima] gagal dekripsi: {exc}")
```

Menerima satu frame, menampilkan IV dan ciphertext, lalu mendekripsi dan
menampilkan plaintext. Bila dekripsi gagal, pesan kesalahan ditampilkan tanpa
menghentikan thread.

**`run(conn)` — menghubungkan dua thread**

```python
def run(conn: socket.socket) -> None:
    print("Terhubung. Ketik pesan lalu Enter untuk mengirim, 'quit' untuk menutup.")
    threading.Thread(target=recv_loop, args=(conn,), daemon=True).start()
    send_loop(conn)
```

Thread penerima dijalankan sebagai daemon; loop pengirim berjalan di thread
utama, sehingga pengguna dapat mengetik sekaligus tetap menerima balasan.

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

`AF_INET` menandakan TCP/IP dan `SOCK_STREAM` protokol TCP. `SO_REUSEADDR`
mengizinkan port dipakai kembali segera setelah program berhenti. `bind`
mengikat server ke `HOST:PORT`, `listen(1)` menyiapkan antrean, dan `accept`
menunggu koneksi masuk.

**`connect(host)` — mode client**

```python
def connect(host: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, PORT))
        print(f"[connector] tersambung ke {host}:{PORT}")
        run(sock)
```

Membuat socket dan menghubungkannya ke `host:PORT` lawan.

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

---

### `test_cipher.py` — Pengujian Otomatis

File ini bukan kode produksi, melainkan alat verifikasi. Setiap fungsi tes
memanggil fungsi tertentu dan membandingkan hasilnya dengan nilai yang diharapkan.

- `test_tables()` — memverifikasi struktur semua tabel: `IP` dan `P` adalah
  permutasi penuh, `FP` benar-benar membatalkan `IP`, `PC1` dan `PC2` memilih
  bit-bit unik dalam rentang yang benar, `E` mengembang 32 bit jadi 48 bit dengan
  tepat 16 bit terduplikasi, dan 8 S-box masing-masing berukuran 4 x 16 nilai 0-15.
- `test_subkeys()` — menghasilkan tepat 16 subkey, semuanya berbeda.
- `test_key_validation()` — key di `config.py` berukuran 8 byte dengan paritas
  ganjil; key dengan panjang salah ditolak; key berparitas genap dikenali.
- `test_block_vectors()` — 5 test vector blok DES resmi.
- `test_cbc_vectors()` — 4 test vector CBC dengan IV tetap.
- `test_roundtrip_lengths()` — `decrypt(encrypt(x)) == x` untuk panjang
  0, 1, 7, 8, 9, dan 1000 byte.
- `test_cbc_length()` — panjang ciphertext selalu kelipatan 8 termasuk IV.
- `test_random_iv()` — pesan sama dua kali menghasilkan ciphertext berbeda.
- `test_bad_padding_rejected()` — padding yang diubah harus ditolak (`ValueError`).
- `test_wrong_key()` — dekripsi dengan key salah tidak menghasilkan plaintext asli.
- `test_parity_bits_ignored()` — key yang berbeda hanya pada bit paritas
  menghasilkan subkey identik (konsekuensi PC-1 yang membuang 8 bit LSB).

Fungsi `check()` mencetak `[ok]` atau `[GAGAL]` serta menghitung jumlah tes yang
lulus. `main()` keluar dengan kode 0 hanya bila semuanya lulus (27 dari 27).
`TEST_KEY` (`0123456789ABCDEF`) semata-mata untuk pengujian.

## Pengujian

### Test vector blok DES

| Key | Plaintext | Ciphertext |
|-----|-----------|------------|
| `0123456789ABCDEF` | `4E6F772069732074` | `3FA40E8A984D4815` |
| `0000000000000000` | `0000000000000000` | `8CA64DE9C1B123A7` |
| `FFFFFFFFFFFFFFFF` | `FFFFFFFFFFFFFFFF` | `7359B2163E4EDC58` |
| `0101010101010101` | `8000000000000000` | `95F8A5E5DD31D900` |
| `0123456789ABCDEF` | `0000000000000000` | `D5D44FF720683D0D` |

Key `0101010101010101` adalah *weak key* DES, sengaja diuji agar kelemahan
algoritma ini ikut tercakup.

### Test vector CBC

Key `0123456789ABCDEF`, IV tetap `0001020304050607`:

| Plaintext | Ciphertext |
|-----------|------------|
| `Halo, ini pesan uji KI` | `159feb4380548a62d066461d2a15af741f80f70575453b76` |
| `Now is t` | `6772b06bbc2200096a0727ca7f8da2fc` |
| `A` | `da794a39d765cfa8` |
| `0123456789abcdef` | `f3939f9c3037e8a5458d5a18c266d6a9ae60aac91ce15d2b` |

### Ringkasan

`python3 test_cipher.py` memverifikasi struktur tabel, test vector blok, test
vector CBC, round-trip berbagai panjang, efek IV acak, penolakan padding rusak,
penolakan key salah, dan sifat bit paritas. Semua **27 tes lulus**.

Key uji `0123456789ABCDEF` hanya untuk `test_cipher.py`; key di `config.py` dibuat
terpisah.

## Catatan Keamanan

DES **bukan** pilihan yang tepat untuk sistem nyata:

1. **Hanya 56 bit kunci efektif.** Brute force 2^56 masih dianggap layak, dan
   inilah alasan utama NIST menarik DES pada tahun 2005.
2. **Blok 64 bit rentan Sweet32.** Setelah sekitar 2^32 blok dengan key yang
   sama, pola birthday pada blok 64 bit memunculkan tabrakan yang dapat
   membocorkan plaintext. Untuk CBC, ini berarti jangan pernah memakai satu key
   untuk data dalam jumlah besar.
3. **CBC tanpa autentikasi (MAC).** Protokol ini tidak mendeteksi perubahan
   ciphertext. Penyerang dapat memanipulasi ciphertext, dan karena dekripsi
   melempar `ValueError` saat padding rusak, hal tersebut membuka celah
   **padding oracle** — serangan yang dapat mendekripsi pesan tanpa mengetahui
   key.
4. **IV acak dengan key tetap.** Untuk pesan deterministik di bawah key yang
   sama, IV acak menyembunyikan pola, tetapi tidak menambah keamanan substantif
   terhadap penyerang yang mengetahui plaintext.
5. **Weak key dan key komplementer.** Tersedia key lemah yang membuat enkripsi
   dan dekripsi identik (`0101010101010101` termasuk di antaranya), serta pasangan
   key komplementer yang saling meniadakan.

Untuk aplikasi nyata gunakan **AES-256** dengan mode yang menyediakan
kerahasiaan sekaligus integritas, seperti AES-GCM atau ChaCha20-Poly1305.
Implementasi dalam repository ini bernilai murni untuk keperluan pembelajaran.
