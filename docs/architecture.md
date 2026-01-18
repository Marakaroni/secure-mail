# Architektura systemu

## Warstwy
- Client: przeglądarka/użytkownik
- NGINX: reverse proxy + terminacja TLS (HTTPS)
- Backend: FastAPI (REST)
- DB: SQLite (wolumen Dockera)

## Przepływ ruchu
1. Klient wysyła żądanie HTTPS do NGINX.
2. NGINX przekazuje żądanie do backendu (HTTP w sieci wewnętrznej Dockera).
3. Backend wykonuje logikę aplikacji i operacje na DB.
4. Odpowiedź wraca przez NGINX do klienta.

## Założenia bezpieczeństwa
- Backend nie jest wystawiony bezpośrednio na świat (brak publikacji portu).
- TLS kończy się na NGINX.
- Operacje kryptograficzne są izolowane w module `app/crypto`.
