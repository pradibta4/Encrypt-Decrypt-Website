# Image Encryption Lab — AES + Modified S-Box (Affine Matrix)

Implementasi enkripsi–dekripsi gambar berbasis substitusi byte menggunakan S-Box dari AES serta S-Box hasil modifikasi berbasis eksplorasi matriks afin (affine matrices). Proyek ini mengacu pada dua paper berikut dan menyediakan metrik evaluasi citra serta analisis histogram kanal RGB:

- AES S-box modification uses affine matrices exploration for increased S-box strength — Nonlinear Dynamics (2025). DOI: https://doi.org/10.1007/s11071-024-10414-3
- S-box Construction on AES Algorithm using Affine Matrix Modification to Improve Image Encryption — Scientific Journal of Informatics (2023). DOI: 10.15294/sji.v10i2.42305

Mode yang didukung:
- AES Standard S-Box
- S-Box 44 (sesuai paper, metrik superior)
- Custom S-Box (JSON)

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Jalankan Server

```bash
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Server akan berjalan di `http://127.0.0.1:8000`

### 3. Akses API Documentation

Buka browser dan kunjungi:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### 4. Gunakan Frontend (GUI)

- Buka `frontend/index.html` di browser (atau via Live Server).
- Lakukan Encrypt: pilih mode S-Box, masukkan kunci, upload gambar asli (PNG/JPG). Hasil enkripsi otomatis diunduh sebagai PNG.
- Lakukan Decrypt: upload file PNG hasil encrypt (bukan JPG). Output dekripsi akan identik dengan gambar asli.

## 📊 Testing dengan Script Python (opsional)

### Test Enkripsi Gambar

```bash
# Test dengan S-Box 44
python test_image_encryption.py --image test_image.png --mode sbox44

# Test dengan AES Standard
python test_image_encryption.py --image test_image.png --mode standard

# Test keduanya sekaligus
python test_image_encryption.py --image test_image.png
```

### Bandingkan Metrik S-Box

```bash
python test_image_encryption.py --compare
```

Output akan menampilkan:
- Entropy (H)
- NPCR (Number of Pixels Change Rate)
- UACI (Unified Average Changing Intensity)
- NPR (Number of Pixel Rate)
- Histogram data
- Evaluasi kualitas enkripsi

## 🧠 Cara Kerja Singkat

- Derivasi kunci: input `key_hex` diproses menjadi keystream byte via SHA-256 (loop sesuai ukuran citra).
- Enkripsi per piksel: untuk setiap byte `p` di gambar: `c = S[p ⊕ k]`, dengan `S` adalah S-Box terpilih.
- Dekripsi per piksel: `p = S⁻¹[c] ⊕ k` dengan `S⁻¹` inverse dari S-Box.
- Analisis: hitung Entropy, NPCR, UACI, NPR, dan histogram terpisah per kanal R, G, B untuk citra asli dan terenkripsi.

Catatan penting: Hasil enkripsi disimpan sebagai PNG (lossless). JPEG bersifat lossy dan akan merusak nilai piksel sehingga dekripsi tidak lagi persis sama dengan citra asli.

## 🔬 Metrik Pengujian

### Nilai Ideal:

| Metrik | Nilai Ideal | Deskripsi |
|--------|-------------|-----------|
| Entropy | 7.9 - 8.0 | Distribusi pixel acak sempurna |
| NPCR | 99.5% - 99.7% | Hampir semua pixel berubah |
| UACI | 33.0% - 34.0% | Intensitas perubahan merata |
| NPR | 99.5% - 99.7% | Persentase pixel berubah |

Definisi singkat:
- Entropy: tingkat keacakan distribusi intensitas piksel.
- NPCR: proporsi piksel yang berubah antara citra asli dan terenkripsi.
- UACI: rata-rata intensitas perubahan antar piksel (skala 0–255) dalam persen.
- NPR: variasi jumlah piksel yang berubah (digunakan dalam project ini sebagai pelengkap).

## 📁 Struktur Project

```
Encrypt-Decrypt-Website/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application & image encryption
│   ├── aes_core.py          # AES encryption core functions
│   ├── sbox_metrics.py      # S-Box cryptographic metrics
│   └── schemas.py           # Pydantic models
├── frontend/
│   ├── index.html           # Web interface
│   ├── main.js              # Frontend logic
│   └── styles.css           # Styling
├── requirements.txt         # Python dependencies
├── test_image_encryption.py # Testing script
├── IMPLEMENTASI_IMAGE_ENCRYPTION.md # Detailed documentation
└── README.md               # This file
```

## 🔐 API Endpoints

### Image Encryption

```http
POST /image/encrypt
Content-Type: multipart/form-data

Parameters:
- `mode`: `standard` | `sbox44` | `custom`
- `key_hex`: kunci (string hex/teks; diproses jadi keystream)
- `file`: gambar input (PNG/JPG). Output terenkripsi selalu PNG.
- `sbox_json` (opsional): array 256 elemen untuk Custom S-Box
```

### Image Decryption

```http
POST /image/decrypt
Content-Type: multipart/form-data

Parameters:
- `mode`: `standard` | `sbox44` | `custom`
- `key_hex`: kunci yang sama dengan saat enkripsi
- `file`: file PNG terenkripsi (hasil dari endpoint encrypt)
- `sbox_json` (opsional): harus cocok dengan saat enkripsi (jika custom)
```

### Get S-Box Info

```http
GET /sbox/standard   # AES Standard S-Box
GET /sbox/paper44    # S-Box 44 dari paper
```

## 📖 Referensi Paper

1) AES S-box modification uses affine matrices exploration for increased S-box strength — Nonlinear Dynamics (2025)
- DOI: https://doi.org/10.1007/s11071-024-10414-3

2) S-box Construction on AES Algorithm using Affine Matrix Modification to Improve Image Encryption — Scientific Journal of Informatics (2023)
- DOI: 10.15294/sji.v10i2.42305

## 🛠️ Troubleshooting

### Server tidak bisa start

```bash
# Pastikan port 8000 tidak digunakan
netstat -ano | findstr :8000

# Kill process jika ada
taskkill /PID <PID> /F
```

### Import error

```bash
# Pastikan di direktori project
cd d:\kriptograf\Encrypt-Decrypt-Website

# Install ulang dependencies
pip install -r requirements.txt
```

### CORS error di frontend

Server sudah dikonfigurasi dengan `allow_origins=["*"]`. Pastikan server berjalan di `localhost:8000`.

### Dekripsi tidak identik dengan citra asli
- Pastikan file yang didekripsi adalah PNG hasil dari fitur Encrypt pada aplikasi ini.
- Jangan konversi terenkripsi PNG ke JPG; JPEG bersifat lossy dan akan merusak byte sehingga dekripsi tidak presisi.

## 📝 Contoh Penggunaan Python

```python
import requests
import base64

# Encrypt
with open('test.png', 'rb') as f:
    response = requests.post('http://127.0.0.1:8000/image/encrypt',
                           files={'file': f},
                           data={'mode': 'sbox44', 'key_hex': 'mykey'})
    result = response.json()
    
print(f"Entropy (original): {result['original_entropy']}")
print(f"Entropy (encrypted): {result['encrypted_entropy']}")
print(f"NPCR: {result['npcr']}% | UACI: {result['uaci']}% | NPR: {result['npr']}%")

# Decrypt (gunakan file PNG terenkripsi dari GUI atau simpan base64 ke file PNG dahulu)
import base64
enc_png = base64.b64decode(result['encrypted_image_base64'])
with open('encrypted_output.png', 'wb') as f:
    f.write(enc_png)

with open('encrypted_output.png', 'rb') as f:
    response = requests.post('http://127.0.0.1:8000/image/decrypt',
                             files={'file': f},
                             data={'mode': 'sbox44', 'key_hex': 'mykey'})
print(response.status_code, response.ok)
```

## ⚙️ Konfigurasi

Server configuration di `app/main.py`:
- FastAPI dengan CORS middleware
- Host: 0.0.0.0 (semua interface)
- Port: 8000 (default)
- Reload: enabled (development mode)

## 🤝 Kontribusi

Untuk development:

1. Clone repository
2. Install dependencies: `pip install -r requirements.txt`
3. Jalankan server dengan `--reload`: `python -m uvicorn app.main:app --reload`
4. Edit code dan test

## 📄 Lisensi & Catatan

Proyek edukasi untuk Image Encryption Lab. Mohon sitasi kedua paper jika menggunakan S-Box 44/varian affine dalam publikasi.
