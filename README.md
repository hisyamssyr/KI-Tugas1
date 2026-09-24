# KI-Tugas1 — Simulasi Transmisi Ciphertext Dua Arah

Cipher **Feistel rancangan sendiri** (blok 64 bit, 8 ronde, key 128 bit) + mode
**CBC** + padding **PKCS#7**. Dua proses terpisah (`peer.py`) bertukar
ciphertext lewat TCP socket. Tanpa library kriptografi: semua algoritma ditulis
manual.

> Cipher ini untuk pembelajaran — tidak ada analisis keamanan formal. Jangan
> dipakai melindungi data nyata. Blok 64 bit relatif kecil, dan CBC tanpa MAC
> tidak memberi integritas pesan.

## Struktur

```
feistel.py      cipher blok: round key, fungsi F, S-box, encrypt/decrypt block
cipher.py       mode CBC + padding PKCS#7: encrypt() / decrypt()
config.py       KEY (16 byte pre-shared), HOST, PORT
peer.py         komunikasi dua arah (mode listen / connect)
test_cipher.py  test vector + tes round-trip
README.md
```

`feistel.py` dan `cipher.py` dipakai bersama kedua peer. Key **tidak** ikut
dikirim lewat jaringan — dibaca dari `config.py` di kedua sisi.

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

Setelah tersambung, ketik pesan lalu Enter. `quit` untuk menutup koneksi.
Setiap pesan menampilkan ciphertext (hex) di sisi kirim **dan** terima, sehingga
terlihat bahwa yang lewat jaringan adalah ciphertext.

Untuk membuktikan dua arah: A kirim pesan, B balas, dst. Kirim pesan yang sama
dua kali — ciphertext-nya berbeda (efek IV acak pada CBC).

## Format transmisi

```
[ 4 byte: panjang payload big-endian ][ 8 byte IV ][ ciphertext (kelipatan 8) ]
```

TCP adalah stream, jadi batas pesan didefinisikan lewat header: 4 byte pertama
menyebutkan berapa byte payload menyusul, lalu dibaca tepat sejumlah itu.

## Ringkasan algoritma

- **Key schedule**: 128 bit dipecah jadi 4 word K0..K3. Untuk ronde ke-i:
  `k = K[i mod 4] XOR ((i+1) * 0x9E3779B9)`, lalu `RK[i] = rotl(k, 3i+1)`.
- **Fungsi F(R,k)**: tambah key mod 2^32 → rotl 5 → substitusi 8 nibble lewat
  S-box 4 bit → `t XOR rotl(t,9) XOR rotl(t,21)` → rotl 11.
- **Enkripsi blok**: 8 ronde `L,R = R, L XOR F(R,RK[i])`, output `R || L`.
- **Dekripsi blok**: jalankan enkripsi dengan urutan round key **dibalik**.
  Struktur Feistel membuat F tidak perlu dibalik.
- **CBC**: `Ci = Enc(Pi XOR C(i-1))`, IV acak 8 byte, IV dikirim mendahului ct.
- **PKCS#7**: selalu tambah 1..8 byte, divalidasi saat unpad.

## Uji

`python3 test_cipher.py` memverifikasi: round key, satu blok, CBC dengan IV
tetap (10a–10c di brief), round-trip panjang 0/1/7/8/9/1000, efek IV, padding
rusak ditolak, dan key salah tidak menghasilkan plaintext asli.

Key uji `000102030405060708090a0b0c0d0e0f` hanya di `test_cipher.py`; key di
`config.py` dibuat sendiri (16 byte acak).