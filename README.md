# Image Encryption Lab - AES dengan S-Box Custom

Sistem enkripsi dan dekripsi gambar menggunakan AES-128 ECB dengan dukungan:
- AES Standard S-Box
- S-Box 44 (dari paper dengan metrik superior)
- Custom S-Box

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Jalankan Server

```bash
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Server akan berjalan di `http://localhost:8000`

### 3. Akses API Documentation

Buka browser dan kunjungi:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### 4. Gunakan Frontend

Buka file `frontend/index.html` di browser untuk interface GUI.

## 📊 Testing dengan Script Python

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

## 📚 Dokumentasi

Lihat [IMPLEMENTASI_IMAGE_ENCRYPTION.md](IMPLEMENTASI_IMAGE_ENCRYPTION.md) untuk:
- Penjelasan detail implementasi
- Formula metrik pengujian
- Perbandingan S-Box
- API endpoints
- Expected results

## 🔬 Metrik Pengujian

### Nilai Ideal:

| Metrik | Nilai Ideal | Deskripsi |
|--------|-------------|-----------|
| Entropy | 7.9 - 8.0 | Distribusi pixel acak sempurna |
| NPCR | 99.5% - 99.7% | Hampir semua pixel berubah |
| UACI | 33.0% - 34.0% | Intensitas perubahan merata |
| NPR | 99.5% - 99.7% | Persentase pixel berubah |

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
- mode: "standard" atau "sbox44"
- key_hex: kunci enkripsi
- file: gambar (PNG, JPG, dll)
```

### Image Decryption

```http
POST /image/decrypt
Content-Type: multipart/form-data

Parameters:
- mode: "standard" atau "sbox44"
- key_hex: kunci enkripsi (harus sama dengan saat enkripsi)
- encrypted_image_base64: gambar terenkripsi
```

### Get S-Box Info

```http
GET /sbox/standard   # AES Standard S-Box
GET /sbox/paper44    # S-Box 44 dari paper
```

## 📖 Referensi Paper

**Judul:** ANALISIS KUALITAS CITRA HASIL ENKRIPSI MENGGUNAKAN S-BOX KRIPTOGRAFI RIVEST CODE 4 (RC4) DAN ADVANCED ENCRYPTION STANDARD (AES)

**S-Box 44:**
- NL (Nonlinearity): 112
- SAC: 0.50073
- BIC-SAC: 0.50237
- Superior metrics dibanding AES Standard

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

## 📝 Contoh Penggunaan Python

```python
import requests
import base64

# Encrypt
with open('test.png', 'rb') as f:
    response = requests.post('http://localhost:8000/image/encrypt',
                           files={'file': f},
                           data={'mode': 'sbox44', 'key_hex': 'mykey'})
    result = response.json()
    
print(f"Entropy: {result['entropy']}")
print(f"NPCR: {result['npcr']}%")

# Decrypt
response = requests.post('http://localhost:8000/image/decrypt',
                        data={
                            'mode': 'sbox44',
                            'key_hex': 'mykey',
                            'encrypted_image_base64': result['encrypted_image_base64']
                        })
```

## ⚙️ Configuration

Server configuration di `app/main.py`:
- FastAPI dengan CORS middleware
- Host: 0.0.0.0 (semua interface)
- Port: 8000 (default)
- Reload: enabled (development mode)

## 🤝 Contributing

Untuk development:

1. Clone repository
2. Install dependencies: `pip install -r requirements.txt`
3. Jalankan server dengan `--reload`: `python -m uvicorn app.main:app --reload`
4. Edit code dan test

## 📄 License

Educational project untuk Image Encryption Lab.
