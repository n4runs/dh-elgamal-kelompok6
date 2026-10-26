# -*- coding: utf-8 -*-
"""
TUGAS DIFFIE-HELLMAN DAN ELGAMAL
Program TANPA library / framework (tidak ada satu pun `import`).
Semua primitif ditulis sendiri: PRNG, perpangkatan modular, Euclid
yang diperluas, invers modular, uji keprimaan Miller-Rabin,
pembangkit bilangan prima aman, pencari akar primitif.

STUDI KASUS
    "Pengiriman Data Nilai Rahasia dari Dosen ke Bagian Akademik"
    Alice = Dosen            Bob = Bagian Akademik
    Eve   = penyadap di jaringan kampus (kanal publik)

    BAGIAN A  Diffie-Hellman : Alice & Bob menyepakati KUNCI SESI
                               tanpa pernah mengirim kunci itu.
              Kunci sesi dipakai untuk mengenkripsi kode verifikasi.
    BAGIAN B  ElGamal        : Alice mengenkripsi DATA NILAI dengan
                               kunci publik Bob; hanya Bob (kunci
                               privat) yang dapat membukanya.
    BAGIAN C  Analisis       : mengapa Eve gagal (masalah logaritma
                               diskrit) dan sifat probabilistik ElGamal.

PERINGATAN: program ini untuk PEMBELAJARAN. PRNG di bawah bukan
CSPRNG dan ukuran kunci dibuat kecil agar cepat dijalankan.
"""

# ====================== IDENTITAS KELOMPOK (ISI!) ======================
KELOMPOK = "Kelompok 6"
ANGGOTA = [
    "Rahmad - 5027241068",
    "Nanda - 5027241057",
    "Naruna - 5027241105",
]

# ============================ KONFIGURASI ==============================
BIT_P = 64            # panjang bit bilangan prima p (studi kasus utama)
BIT_P_KECIL = 20      # panjang bit p untuk demo serangan brute force
SEED = 20261025       # seed PRNG (ubah agar hasil berbeda)
PESAN_DEFAULT = "NIM 2024001 NILAI UAS KRIPTOGRAFI = A"
KODE_VERIFIKASI = "AKADEMIK-2026"


# ======================================================================
# 1. PRIMITIF MATEMATIKA (ditulis sendiri)
# ======================================================================
MASK64 = (1 << 64) - 1


class PRNG:
    """Pembangkit angka acak SplitMix64 (cukup untuk simulasi)."""

    def __init__(self, seed):
        self.state = seed & MASK64

    def next64(self):
        self.state = (self.state + 0x9E3779B97F4A7C15) & MASK64
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
        return z ^ (z >> 31)

    def bits(self, n, top=False):
        """Bilangan acak n-bit. top=True -> bit tertinggi dipaksa 1."""
        r = 0
        got = 0
        while got < n:
            r = (r << 64) | self.next64()
            got += 64
        r &= (1 << n) - 1
        if top:
            r |= 1 << (n - 1)
        return r

    def rand_range(self, lo, hi):
        """Bilangan acak pada [lo, hi)."""
        span = hi - lo
        n = span.bit_length()
        while True:
            r = self.bits(n)
            if r < span:
                return lo + r


def mod_pow(base, exp, mod):
    """Perpangkatan modular (square-and-multiply): base^exp mod mod."""
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result


def egcd(a, b):
    """Euclid diperluas: kembalikan (g, x, y) dengan a*x + b*y = g."""
    x0, y0, x1, y1 = 1, 0, 0, 1
    while b != 0:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def mod_inverse(a, mod):
    """Invers modular a^-1 mod mod (ada jika gcd(a, mod) = 1)."""
    g, x, _ = egcd(a % mod, mod)
    if g != 1:
        raise ValueError("invers modular tidak ada")
    return x % mod


PRIMA_KECIL = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def is_prime(n):
    """Uji keprimaan Miller-Rabin dengan basis tetap."""
    if n < 2:
        return False
    for p in PRIMA_KECIL:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in PRIMA_KECIL:
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_safe_prime(bits, rng):
    """Bangkitkan prima aman p = 2q + 1 (q juga prima). Kembalikan (p, q)."""
    while True:
        q = rng.bits(bits - 1, top=True) | 1
        if is_prime(q):
            p = 2 * q + 1
            if is_prime(p):
                return p, q


def find_generator(p, q):
    """Akar primitif g mod p untuk p = 2q + 1.
    Karena p-1 = 2*q, g adalah akar primitif jika g^2 != 1 dan g^q != 1."""
    g = 2
    while True:
        if mod_pow(g, 2, p) != 1 and mod_pow(g, q, p) != 1:
            return g
        g += 1


# ======================================================================
# 2. DIFFIE-HELLMAN  (tiap tahap = satu fungsi)
# ======================================================================
def dh_buat_kunci_privat(p, rng):
    """Tahap DH-2/3: pilih rahasia acak a (atau b) pada [2, p-2]."""
    return rng.rand_range(2, p - 1)


def dh_hitung_kunci_publik(g, privat, p):
    """Tahap DH-2/3: A = g^a mod p (atau B = g^b mod p)."""
    return mod_pow(g, privat, p)


def dh_hitung_kunci_bersama(publik_lawan, privat_sendiri, p):
    """Tahap DH-5: K = (kunci publik lawan)^(privat sendiri) mod p."""
    return mod_pow(publik_lawan, privat_sendiri, p)


# ======================================================================
# 3. ELGAMAL  (tiap tahap = satu fungsi)
# ======================================================================
def eg_bangkitkan_kunci(p, g, rng):
    """Tahap EG-1: privat x acak, publik y = g^x mod p."""
    x = rng.rand_range(2, p - 1)
    y = mod_pow(g, x, p)
    return x, y


def eg_enkripsi_angka(m, p, g, y, rng):
    """Tahap EG-2: pilih k acak; c1 = g^k, c2 = m * y^k (mod p)."""
    k = rng.rand_range(2, p - 1)
    c1 = mod_pow(g, k, p)
    c2 = (m * mod_pow(y, k, p)) % p
    return k, c1, c2


def eg_dekripsi_angka(c1, c2, x, p):
    """Tahap EG-3: s = c1^x; m = c2 * s^-1 (mod p)."""
    s = mod_pow(c1, x, p)
    s_inv = mod_inverse(s, p)
    return s, s_inv, (c2 * s_inv) % p


def eg_enkripsi_teks(teks, p, g, y, rng):
    """Enkripsi tiap karakter (kode Unicode < p) -> daftar (c1, c2)."""
    hasil = []
    for ch in teks:
        _, c1, c2 = eg_enkripsi_angka(ord(ch), p, g, y, rng)
        hasil.append((c1, c2))
    return hasil


def eg_dekripsi_teks(cipher, x, p):
    return "".join(chr(eg_dekripsi_angka(c1, c2, x, p)[2]) for c1, c2 in cipher)


# ======================================================================
# 4. PENGAMAN SESI SEDERHANA (memakai kunci hasil Diffie-Hellman)
# ======================================================================
def xor_keystream(data_bytes, kunci_sesi):
    """Kunci sesi K dijadikan seed PRNG -> keystream -> XOR.
    Operasi yang sama untuk enkripsi dan dekripsi."""
    ks = PRNG(kunci_sesi)
    return [b ^ (ks.next64() & 0xFF) for b in data_bytes]


def ke_hex(daftar_byte):
    return "".join(format(b, "02x") for b in daftar_byte)


# ======================================================================
# 5. TAMPILAN
# ======================================================================
def judul(teks):
    print()
    print("=" * 72)
    print(teks)
    print("=" * 72)


def langkah(teks):
    print("\n--- " + teks)


def pendek(n, maks=26):
    s = str(n)
    return s if len(s) <= maks else s[:12] + "..." + s[-10:]


# ======================================================================
# 6. DEMO ANGKA KECIL (bisa diverifikasi dengan kalkulator)
# ======================================================================
def demo_angka_kecil():
    judul("DEMO ANGKA KECIL  (p = 23, g = 5)  - untuk verifikasi manual")
    p, g = 23, 5
    print("Parameter publik : p =", p, ", g =", g)

    langkah("Diffie-Hellman")
    a, b = 6, 15
    A = dh_hitung_kunci_publik(g, a, p)
    B = dh_hitung_kunci_publik(g, b, p)
    print("Alice: a =", a, " A = g^a mod p = 5^6 mod 23 =", A)
    print("Bob  : b =", b, " B = g^b mod p = 5^15 mod 23 =", B)
    ka = dh_hitung_kunci_bersama(B, a, p)
    kb = dh_hitung_kunci_bersama(A, b, p)
    print("Alice: K = B^a mod p = 19^6 mod 23 =", ka)
    print("Bob  : K = A^b mod p = 8^15 mod 23 =", kb)
    print("Kunci sama?", ka == kb)

    langkah("ElGamal")
    x = 6
    y = mod_pow(g, x, p)
    print("Bob  : privat x =", x, " publik y = g^x mod p =", y)
    m, k = 10, 3
    c1 = mod_pow(g, k, p)
    c2 = (m * mod_pow(y, k, p)) % p
    print("Alice: m =", m, " k =", k)
    print("       c1 = g^k mod p =", c1, " c2 = m*y^k mod p =", c2)
    s, s_inv, m2 = eg_dekripsi_angka(c1, c2, x, p)
    print("Bob  : s = c1^x mod p =", s, " s^-1 =", s_inv)
    print("       m = c2 * s^-1 mod p =", m2, "-> sama dengan m asli?", m2 == m)


# ======================================================================
# 7. STUDI KASUS UTAMA
# ======================================================================
def studi_kasus(pesan, rng):
    judul("TAHAP 0 - PARAMETER PUBLIK (disepakati terbuka)")
    p, q = gen_safe_prime(BIT_P, rng)
    g = find_generator(p, q)
    print("Fungsi: p dan g boleh diketahui siapa saja (termasuk Eve).")
    print("        Semua perhitungan berlangsung di grup perkalian mod p.")
    print("p (prima aman, %d bit) = %d" % (p.bit_length(), p))
    print("q = (p-1)/2            = %d  (prima)" % q)
    print("g (akar primitif)      = %d" % g)

    # ------------------------------------------------------------------
    judul("BAGIAN A - DIFFIE-HELLMAN : MENYEPAKATI KUNCI SESI")
    langkah("DH-1  Alice (Dosen) membuat pasangan kunci")
    a = dh_buat_kunci_privat(p, rng)
    A = dh_hitung_kunci_publik(g, a, p)
    print("Fungsi: a RAHASIA Alice; A = g^a mod p boleh dikirim terbuka.")
    print("a (privat) =", a)
    print("A (publik) =", A)

    langkah("DH-2  Bob (Bagian Akademik) membuat pasangan kunci")
    b = dh_buat_kunci_privat(p, rng)
    B = dh_hitung_kunci_publik(g, b, p)
    print("Fungsi: b RAHASIA Bob; B = g^b mod p boleh dikirim terbuka.")
    print("b (privat) =", b)
    print("B (publik) =", B)

    langkah("DH-3  Pertukaran kunci publik lewat kanal TERBUKA")
    print("Alice --> Bob : A =", pendek(A))
    print("Bob --> Alice : B =", pendek(B))
    print("Eve menyadap  : p, g, A, B  (tidak cukup untuk menghitung K)")

    langkah("DH-4  Masing-masing menghitung kunci bersama")
    K_alice = dh_hitung_kunci_bersama(B, a, p)
    K_bob = dh_hitung_kunci_bersama(A, b, p)
    print("Alice: K = B^a mod p =", K_alice)
    print("Bob  : K = A^b mod p =", K_bob)
    print("Kedua kunci identik?", K_alice == K_bob,
          " (karena (g^b)^a = (g^a)^b = g^(ab) mod p)")
    if K_alice != K_bob:
        raise SystemExit("Diffie-Hellman gagal")
    K = K_alice

    langkah("DH-5  Kunci sesi dipakai untuk mengamankan kode verifikasi")
    print("Fungsi: DH hanya SEPAKAT KUNCI; kunci itu lalu dipakai oleh")
    print("        cipher simetris (di sini XOR keystream sederhana).")
    data = list(KODE_VERIFIKASI.encode("utf-8"))
    sandi = xor_keystream(data, K)
    print("Kode asli (Alice)      :", KODE_VERIFIKASI)
    print("Dikirim (hex, publik)  :", ke_hex(sandi))
    terbuka = bytes(xor_keystream(sandi, K)).decode("utf-8")
    print("Dibuka Bob dengan K    :", terbuka, "->",
          "COCOK" if terbuka == KODE_VERIFIKASI else "GAGAL")

    # ------------------------------------------------------------------
    judul("BAGIAN B - ELGAMAL : MENGIRIM DATA NILAI RAHASIA")
    langkah("EG-1  Bob membangkitkan kunci ElGamal (memakai p, g yang sama)")
    x, y = eg_bangkitkan_kunci(p, g, rng)
    print("Fungsi: x = kunci PRIVAT Bob (disimpan); y = g^x mod p = kunci")
    print("        PUBLIK (dibagikan ke Alice).")
    print("x (privat) =", x)
    print("y (publik) =", y)
    print("Kunci publik Bob = (p, g, y)")

    langkah("EG-2  Alice mengenkripsi pesan dengan kunci publik Bob")
    print("Pesan asli :", pesan)
    print("Fungsi: tiap karakter m = kode Unicode; pilih k acak BARU;")
    print("        c1 = g^k mod p ; c2 = m * y^k mod p.")
    rinci = []
    cipher = []
    for ch in pesan:
        m = ord(ch)
        k, c1, c2 = eg_enkripsi_angka(m, p, g, y, rng)
        cipher.append((c1, c2))
        rinci.append((ch, m, k, c1, c2))
    print("\n  Kar  m    k                     c1                        c2")
    for ch, m, k, c1, c2 in rinci[:6]:
        print("  %-3s  %-3d  %-20s  %-24s  %-24s" %
              (repr(ch), m, pendek(k, 20), pendek(c1, 24), pendek(c2, 24)))
    if len(rinci) > 6:
        print("  ... (%d karakter lainnya disingkat)" % (len(rinci) - 6))
    print("Total ciphertext: %d pasang (c1, c2)" % len(cipher))

    langkah("EG-3  Bob mendekripsi dengan kunci privat x")
    print("Fungsi: s = c1^x mod p ; m = c2 * s^-1 mod p (butuh x!).")
    for i in range(3):
        c1, c2 = cipher[i]
        s, s_inv, m = eg_dekripsi_angka(c1, c2, x, p)
        print("  blok %d: s = %s, s^-1 = %s, m = %d -> %r" %
              (i + 1, pendek(s, 18), pendek(s_inv, 18), m, chr(m)))
    hasil = eg_dekripsi_teks(cipher, x, p)
    print("\nPlaintext hasil dekripsi Bob :", hasil)
    print("Sama dengan pesan asli?      :", hasil == pesan)

    # ------------------------------------------------------------------
    judul("BAGIAN C - ANALISIS KEAMANAN")
    langkah("C-1  ElGamal bersifat probabilistik (k berbeda tiap enkripsi)")
    ulang = eg_enkripsi_teks(pesan, p, g, y, rng)
    print("Pesan yang sama dienkripsi dua kali:")
    print("  c1 pertama : ", pendek(cipher[0][0]))
    print("  c1 kedua   : ", pendek(ulang[0][0]))
    print("Ciphertext berbeda?", cipher != ulang,
          "| keduanya terdekripsi sama?",
          eg_dekripsi_teks(ulang, x, p) == pesan)
    print("Fungsi: pola pesan tidak bocor (huruf yang sama != sandi sama).")

    langkah("C-2  Eve menyerang Diffie-Hellman pada parameter KECIL")
    pk, qk = gen_safe_prime(BIT_P_KECIL, rng)
    gk = find_generator(pk, qk)
    ak = dh_buat_kunci_privat(pk, rng)
    bk = dh_buat_kunci_privat(pk, rng)
    Ak = dh_hitung_kunci_publik(gk, ak, pk)
    Bk = dh_hitung_kunci_publik(gk, bk, pk)
    print("p kecil (%d bit) = %d, g = %d" % (pk.bit_length(), pk, gk))
    print("Eve tahu A =", Ak, ", B =", Bk, "-> mencoba semua a = 1,2,3,...")
    cur, tebakan, langkah_eve = 1, None, 0
    for e in range(1, pk):
        cur = (cur * gk) % pk
        langkah_eve += 1
        if cur == Ak:
            tebakan = e
            break
    K_eve = dh_hitung_kunci_bersama(Bk, tebakan, pk)
    K_asli = dh_hitung_kunci_bersama(Bk, ak, pk)
    print("Eve menemukan a =", tebakan, "setelah", langkah_eve, "langkah")
    print("Kunci sesi hasil curian Eve =", K_eve,
          "| kunci asli =", K_asli, "| JEBOL?", K_eve == K_asli)

    langkah("C-3  Serangan yang sama pada parameter studi kasus (%d bit)" % BIT_P)
    kecepatan = 10 ** 7
    detik = p // kecepatan
    tahun = detik // 31536000
    print("Perkiraan langkah brute force   : sekitar %d" % p)
    print("Dengan 10 juta percobaan/detik  : sekitar %d tahun" % tahun)
    print("Kesimpulan: keamanan DH dan ElGamal bertumpu pada sulitnya")
    print("            logaritma diskrit; p harus SANGAT besar (>= 2048 bit")
    print("            pada praktik nyata).")


# ======================================================================
def main():
    print("#" * 72)
    print("TUGAS DIFFIE-HELLMAN DAN ELGAMAL")
    print(KELOMPOK)
    for i, nama in enumerate(ANGGOTA, 1):
        print("  %d. %s" % (i, nama))
    print("#" * 72)

    rng = PRNG(SEED)
    demo_angka_kecil()

    print("\nMasukkan pesan nilai rahasia (kosongkan untuk contoh bawaan):")
    pesan = input("> ").strip()
    if pesan == "":
        pesan = PESAN_DEFAULT
    studi_kasus(pesan, rng)
    print("\nSelesai.")


if __name__ == "__main__":
    main()
