# 🇮🇩 Terjemahan README: sphinx-core/go

## 🧬 Tentang Proyek Ini

Repositori ini adalah implementasi **Go (Golang)** dari protokol **Sphinx**, yang dirancang sebagai **protokol blockchain post-kuantum** berbasis SPHINCS+ (skema tanda tangan digital tahan kuantum).

Tujuan dari repositori ini adalah untuk menciptakan **inti sistem** dari protokol Sphinx, termasuk:
- Struktur blok dasar (block structure)
- Pembuatan dan verifikasi transaksi
- Proses konsensus (consensus process)
- Wallet (dompet) dan sistem address

## 🔍 Fitur Utama

- 📦 **Transaksi**: pembuatan, penandatanganan, dan verifikasi transaksi.
- ⛓️ **Blockchain**: struktur dasar dari blok dan rantai blok.
- 🔐 **Kriptografi Post-Quantum**: menggunakan SPHINCS+ untuk tanda tangan digital.
- 👛 **Dompet**: pembuatan alamat dan manajemen kunci.

## 📂 Struktur Direktori

. ├── core            # Komponen utama sistem Sphinx │   ├── block       # Struktur blok │   ├── chain       # Manajemen rantai blok │   ├── crypto      # Fungsi-fungsi kriptografi │   ├── transaction # Modul transaksi │   └── wallet      # Modul dompet dan address └── main.go         # Entry point (program utama)

## 🚀 Cara Menjalankan

1. **Klon repositori**
```bash
git clone https://github.com/sphinx-core/go.git

2. Masuk ke direktori



cd go

3. Jalankan aplikasi



go run main.go

🏗️ Status Pengembangan

🚧 Proyek ini masih sangat awal dan sedang dalam pengembangan aktif.

Partisipasi sangat diharapkan — silakan buat issue, pull request, atau diskusi jika ingin membantu.

📄 Lisensi

Lisensi: MIT
Artinya lo bebas:

Menggunakan

Memodifikasi

Menyebarkan ulang


Dengan syarat mencantumkan lisensinya.
