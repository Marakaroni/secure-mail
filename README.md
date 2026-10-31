# 🔐 Bezpieczna Poczta

Szyfrowana aplikacja e-mail z dwuetapową autentykacją (2FA), hybrydowym szyfrowaniem (RSA-4096 + AES-256-GCM) i podpisami cyfrowymi.

### Wymagania
- Docker & Docker Compose
- HTTPS (certyfikat samopodpisany)

## Uruchomienie

```bash
cd secure-mail
cp .env.example .env              # uzupełnij SECRET_KEY i JWT_SECRET
# wygeneruj certyfikat TLS (sekcja „Certyfikat SSL”)
docker compose up --build
```

## Architektura

```
┌─────────────────┐
│   Frontend      │ (Vue.js, HTML/CSS/JS)
├─────────────────┤
│   nginx         │ (Port 443 TLS, reverse proxy)
├─────────────────┤
│   FastAPI       │ (Backend, port 8000)
├─────────────────┤
│   SQLite DB     │ (db_data volume)
└─────────────────┘
```

## Bezpieczeństwo

- **Hasła:** Argon2id hashing (3 iteracje, 64 MiB RAM)
- **Szyfrowanie wiadomości:** AES-256-GCM (32-byte key, 12-byte nonce)
- **Hybrydowe klucze:** RSA-4096-OAEP dla każdego odbiorcy
- **Podpisy:** Ed25519 dla autentyczności
- **Sesja kluczy:** Envelope encryption + 5 min TTL
- **CSRF:** Token-based protection
- **Rate Limiting:** Ochrona przed brute force
- **2FA:** TOTP (Time-based One-Time Password)

## Struktura Projektu

```
secure-mail/
├── backend/                 # Python FastAPI
│   ├── app/
│   │   ├── api/routes/      # /auth, /messages endpoints
│   │   ├── models/          # User, Message, Attachment
│   │   ├── crypto/          # AES, RSA, Ed25519, KDF
│   │   ├── security/        # Session keys, CSRF, rate limit
│   │   └── schemas/         # Request/response validators
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/                # Static HTML/CSS/JS
│   ├── index.html           # Landing page
│   ├── login.html           # Login form
│   ├── register.html        # Registration form
│   ├── 2fa-setup.html       # 2FA QR code setup
│   ├── 2fa-verify.html      # 2FA code verification
│   ├── inbox.html           # Mail inbox
│   ├── api.js               # API client
│   └── styles.css           # Global styles
├── nginx/
│   ├── nginx.conf           # Worker config
│   └── conf.d/
│       └── secure-mail.conf # TLS + reverse proxy
└── docker-compose.yml       # Orchestration
```

## Certyfikat SSL

Klucze TLS nie są przechowywane w repozytorium. Przed pierwszym uruchomieniem wygeneruj certyfikat samopodpisany:

```bash
mkdir -p nginx/certs
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout nginx/certs/privkey.pem -out nginx/certs/fullchain.pem -subj "/CN=localhost"
```

## Wymagania Hasła

- Minimum 12 znaków
- Co najmniej 1 wielka litera
- Co najmniej 1 mała litera
- Co najmniej 1 cyfra
- Co najmniej 1 znak specjalny: !@#$%^&*()-_=+

## Zatrzymanie

```bash
docker compose down
```

Aby usunąć bazę danych:
```bash
docker compose down -v
```

## Technologie

- **Backend:** Python 3.11, FastAPI, SQLAlchemy
- **Kryptografia:** cryptography, libsodium
- **Frontend:** HTML5, CSS3, Vanilla JavaScript
- **Reverse Proxy:** nginx
- **Orkiestracja:** Docker Compose
- **Baza Danych:** SQLite
