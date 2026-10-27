# Diffie-Hellman dan ElGamal (Tanpa Library)

Tugas Kriptografi: implementasi **Diffie-Hellman** dan **ElGamal** tanpa library atau framework jadi, dengan seluruh tahapan didemonstrasikan dalam **satu studi kasus**.

## Kelompok 6

| No | Nama | NIM |
|----|--------|------------|
| 1 | Rahmad | 5027241068 |
| 2 | Nanda | 5027241057 |
| 3 | Naruna | 5027241105 |

## Studi Kasus

**Pengiriman data nilai rahasia dari Dosen ke Bagian Akademik.**
Alice (Dosen) mengirim data nilai ke Bob (Bagian Akademik) lewat jaringan kampus yang bisa disadap Eve.

1. **Tahap 0**: parameter publik `p` (prima aman) dan `g` (akar primitif) dibangkitkan.
2. **Bagian A, Diffie-Hellman**: Alice dan Bob menyepakati kunci sesi tanpa mengirimkannya, lalu kunci itu dipakai mengenkripsi kode verifikasi.
3. **Bagian B, ElGamal**: Alice mengenkripsi data nilai dengan kunci publik Bob; hanya Bob yang bisa mendekripsinya.
4. **Bagian C, Analisis**: sifat probabilistik ElGamal dan simulasi serangan Eve (brute force pada `p` kecil vs besar).

### Pemetaan tahap

| Tahap | Fungsi dalam studi kasus | Fungsi pada kode |
|-------|--------------------------|------------------|
| 0 | Menetapkan `p` dan `g` yang publik | `gen_safe_prime`, `find_generator` |
| DH-1/2 | Alice dan Bob membuat kunci privat dan publik | `dh_buat_kunci_privat`, `dh_hitung_kunci_publik` |
| DH-3/4 | Tukar kunci publik, hitung kunci bersama `K` | `dh_hitung_kunci_bersama` |
| DH-5 | `K` dipakai sebagai kunci cipher simetris | `xor_keystream` |
| EG-1 | Bob membuat kunci privat `x` dan publik `y = g^x` | `eg_bangkitkan_kunci` |
| EG-2 | Alice mengenkripsi: `c1 = g^k`, `c2 = m * y^k` | `eg_enkripsi_angka`, `eg_enkripsi_teks` |
| EG-3 | Bob mendekripsi: `m = c2 * (c1^x)^-1` | `eg_dekripsi_angka`, `eg_dekripsi_teks` |
| C-1 | Enkripsi probabilistik | `eg_enkripsi_teks` (dua kali) |
| C-2/C-3 | Serangan brute force logaritma diskrit | `studi_kasus` |

## Struktur Repo

```
.
├── src/
│   └── dh_elgamal.py        # versi konsol (Python 3, tanpa import)
├── docs/
│   └── index.html           # aplikasi interaktif (HTML/CSS/JS murni)
├── laporan/
│   └── Laporan_DH_ElGamal.docx
├── examples/
│   └── output_contoh.txt    # contoh keluaran satu kali eksekusi
├── LICENSE
└── README.md
```

## Cara Menjalankan

**Versi konsol** (butuh Python 3, tanpa instalasi paket apa pun):

```bash
python3 src/dh_elgamal.py
```

Tekan Enter untuk memakai pesan bawaan, atau ketik pesan sendiri.

**Aplikasi interaktif**: buka `docs/index.html` di peramban mana pun, tanpa server dan tanpa internet. Tiap tahap punya tombol sendiri, ada juga tombol "Jalankan semua tahap".

**GitHub Pages** (opsional): di *Settings > Pages*, pilih *Deploy from a branch*, branch `main`, folder `/docs`. Aplikasi lalu tersedia di `https://<username>.github.io/<nama-repo>/`.

## Apa yang Ditulis Sendiri

PRNG (SplitMix64), perpangkatan modular (square-and-multiply), Euclid diperluas dan invers modular, uji keprimaan Miller-Rabin, pembangkit prima aman `p = 2q + 1`, pencari akar primitif, serta seluruh tahap Diffie-Hellman dan ElGamal. Versi web memakai tipe `BigInt` bawaan JavaScript untuk bilangan besar.

## Batasan

Proyek ini untuk pembelajaran. PRNG yang dipakai bukan CSPRNG dan ukuran kunci (64 bit secara bawaan) sengaja kecil agar cepat dijalankan. Pada penggunaan nyata, `p` minimal 2048 bit, memakai sumber acak yang aman, dan Diffie-Hellman perlu autentikasi agar tidak rentan terhadap serangan man-in-the-middle.

## Referensi

- Diffie, W. dan Hellman, M. E. (1976). *New Directions in Cryptography*. IEEE Transactions on Information Theory, 22(6).
- ElGamal, T. (1985). *A Public Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms*. IEEE Transactions on Information Theory, 31(4).
- Menezes, A., van Oorschot, P., Vanstone, S. (1996). *Handbook of Applied Cryptography*. CRC Press.

## Lisensi

[MIT](LICENSE)
