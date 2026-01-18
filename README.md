# Secure Mail

## Cel projektu
Aplikacja webowa umożliwiająca wymianę zaszyfrowanych wiadomości wraz z weryfikacją autentyczności (podpis cyfrowy nadawcy). System wspiera rejestrację, logowanie z 2FA (TOTP) oraz operacje na wiadomościach i załącznikach.

## Zakres minimalny
- rejestracja konta użytkownika
- logowanie użytkownika
- dwuetapowa autentykacja (TOTP)
- wysyłanie zaszyfrowanej wiadomości do co najmniej jednego użytkownika wraz z załącznikami
- podgląd wiadomości oraz pobieranie załączników
- oznaczanie wiadomości jako odczytanej
- usuwanie otrzymanej wiadomości
- weryfikacja podpisu cyfrowego nadawcy

## Architektura
Client → HTTPS → NGINX (reverse proxy, TLS) → FastAPI (API) → SQLite (dane)

Backend nie jest wystawiany bezpośrednio na świat (brak publikacji portu), dostęp odbywa się wyłącznie przez NGINX.

## Technologie
- Python + FastAPI
- SQLite
- Docker + Docker Compose
- NGINX (TLS termination, reverse proxy)
- cryptography (AEAD + podpisy)
- argon2-cffi (Argon2id)
- pyotp (TOTP)

## Uruchomienie (Etap 0)
1. Skopiuj konfigurację:
   - `cp .env.example .env`
2. Uruchom:
   - `docker-compose up --build`
3. Test:
   - `GET https://localhost/health` (cert self-signed może wymagać zaakceptowania w przeglądarce)
