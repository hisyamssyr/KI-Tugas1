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