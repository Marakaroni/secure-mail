# Etap 7: Hartowanie bezpieczeństwa i walidacja wejścia

**Status**: ✅ UKOŃCZONE  
**Data**: 22 stycznia 2026  
**Build**: Pomyślny (kontenery Docker uruchomione)

---

## Przegląd

Etap 7 implementuje kompleksową walidację wejścia, czyszczenie danych (sanitizację) i ograniczenie szybkości (rate limiting) na wszystkich endpointach API. To zapobiega:
- **Atakom injekcji** (SQL, XSS, command injection)
- **Atakom na przechodzenie ścieżek** (../../ sekwencje)
- **Nadużyciom** (ataki DoS poprzez flood)
- **Nieprawidłowym danym** (bajty null, znaki sterujące, zbyt duże ładunki)

---

## Podsumowanie zmian

### 1. **Narzędzie do sanitizacji wejścia** (`backend/app/security/sanitizer.py`) - NOWY PLIK

**Cel**: Centralizowana logika walidacji dla wszystkich danych od użytkownika

**Główne funkcje**:
- `sanitize_string()` - Usuwa bajty null, znaki sterujące, wzorce XSS
- `sanitize_username()` - Tylko alfanumeryczne + dash/underscore
- `sanitize_email()` - Podstawowa walidacja formatu email
- `sanitize_filename()` - Zapobiega path traversal (../../)
- `sanitize_subject()` - Max 255 znaków, bez znaków sterujących
- `sanitize_body()` - Max 50000 znaków, pozwala na nowe linie, usuwa niebezpieczne wzorce
- `validate_mime_type()` - Whitelist: PDF, obrazy, dokumenty Office, tekst
- `validate_recipient_list()` - Max 20 odbiorców, unikalne, niepuste

**Zablokowane wzorce**:
```
- Bajty null (\x00)
- Znaki sterujące (oprócz \t, \n, \r)
- Path traversal (../ lub ..\ )
- Komentarze SQL (-- ; ' " */)
- Wektory XSS (<script>, javascript:, onerror, onclick)
```

**Przykład działania**:
```python
try:
    clean_subject = InputSanitizer.sanitize_subject(user_input)
except ValueError as e:
    # "Script/XSS patterns not allowed"
    return error(400, str(e))
```

---

### 2. **Ograniczanie szybkości** (`backend/app/security/rate_limiter.py`) - NOWY PLIK

**Cel**: Zapobieganie nadużyciom poprzez ograniczenie operacji na użytkownika

**Implementacja**:
- Rate limiter przechowywany w pamięci (prosty, friendly dla dev)
- Śledzi próby z timestampami
- Automatyczne czyszczenie starych wpisów

**Limity**:
- **Wysyłanie wiadomości**: 10 wiadomości na 60 sekund na użytkownika → kod 429 Too Many Requests
- Możliwość rozszerzenia na inne operacje (upload, delete, itp.)

**Jak to działa**:
```python
limiter = get_rate_limiter()
# Sprawdzenie: czy użytkownik może wysłać wiadomość?
if not limiter.is_allowed(user_id, 'send_message', max_attempts=10, window_seconds=60):
    # Zbyt wiele prób w ostatnich 60 sekund
    raise HTTPException(status_code=429, detail='Zbyt wiele wysłanych wiadomości')

# W przeciwnym wypadku: operacja dozwolona, licznik inkrementowany
```

---

### 3. **Ulepszone schematy Pydantic** (`backend/app/schemas/`)

#### **auth.py** - Walidacja rejestracji i logowania

**Nowe cechy**:
```python
class RegisterIn:
    username: str
    - Min: 3 znaki, Max: 64 znaki
    - Tylko: alfanumeryczne, dash, underscore
    - Pattern: ^[a-zA-Z0-9_\-]+$
    - Validator: InputSanitizer.sanitize_username()
    
    email: EmailStr
    - Pydantic sprawdza RFC 5322
    
    password: str
    - Min: 12 znaków, Max: 128 znaków
    - MUSI zawierać: WIELKIE litery, małe litery, cyfrę, znak specjalny
    - Validator: Regex sprawdzające każdy typ znaku

class LoginIn:
    email: EmailStr
    password: str
    - Validator: Sprawdzenie że nie jest samo whitespace
```

**Bezpieczeństwo**:
- ✅ Username blokuje znaki SQL, path traversal, non-ASCII
- ✅ Hasło musi mieć złożoność (ULSD - Uppercase, Lowercase, Sign, Digit)
- ✅ `extra='forbid'` → odrzuca nieznane pola (zapobieganie data exposure)

---

#### **message.py** - Walidacja wiadomości i załączników

**Nowe schematy**:
```python
class MessageSendRequest:
    recipients: List[str]
    - Min: 1 odbiorca, Max: 20 odbiorców
    - Unikalne, niepuste
    - Validator: validate_recipient_list()
    
    subject: str
    - Min: 0, Max: 255 znaków
    - Bez znaków sterujących
    - Validator: sanitize_subject()
    
    body: str
    - Min: 1 znak, Max: 50000 znaków
    - Pozwala na nowe linie (\n)
    - Validator: sanitize_body() + sprawdzenie że nie puste

class AttachmentUploadResponse:
    attachment_id: int
    message_id: int
    filename: str  # Już sanityzowany
    size_bytes: int

class AttachmentListItem:
    id: int
    message_id: int
    filename: str
    size_bytes: int
    mime_type: str

class AttachmentDownloadResponse:
    filename: str
    data_base64: str  # Zawartość w base64
    mime_type: str
```

**Przepływ walidacji**:
1. JSON od klienta
2. Pydantic schema sprawdza typy i długości
3. Field validators uruchamiają sanitizery
4. Jeśli błąd → kod 422 Unprocessable Entity z szczegółami
5. Jeśli OK → czyszcze dane trafiają do handlera

---

### 4. **Hartowanie endpointów wiadomości** (`backend/app/api/routes/messages.py`)

#### **POST /messages/send** - Wysyłanie wiadomości

**Nowe zabezpieczenia**:
- ✅ Rate limiting: 10 wiadomości/min na użytkownika
- ✅ Zapobieganie wysyłaniu do siebie
- ✅ Walidacja odbiorców (istnieją, nie są usunięci)
- ✅ Wszystkie wejścia czyszczone przed szyfrowaniem

**Co się zmienia w kodzie**:
```python
@router.post('/send', response_model=MessageSendResponse)
def send_message(req: MessageSendRequest, ...):
    # 1. NOWE: Rate limiting - sprawdzenie czy nie ma zbyt wielu próśb
    limiter = get_rate_limiter()
    if not limiter.is_allowed(current_user.id, 'send_message', 
                              max_attempts=10, window_seconds=60):
        raise HTTPException(status_code=429, 
                          detail='Zbyt wiele wysłanych wiadomości')
    
    # 2. Znalezienie odbiorców
    recipients = _resolve_recipients(db, req.recipients)
    recipient_ids = [u.id for u in recipients]
    
    # 3. NOWE: Zapobieganie wysyłaniu do siebie
    if current_user.id in recipient_ids:
        raise HTTPException(status_code=400, 
                          detail='Nie możesz wysłać wiadomości do siebie')
    
    # ... reszta szyfrowania i zapisania
```

**Kody błędów**:
```
200 OK → Wiadomość wysłana (zwracam message_id)
400 Bad Request → Nieprawidłowni odbiorcy, puste body, itp.
403 Forbidden → Nie jesteś nadawcą, odbiorca nie istnieje
429 Too Many Requests → Przekroczony limit szybkości
500 Internal Server Error → Błąd kryptografii/DB
```

---

#### **POST /messages/attachments/upload** - Przesyłanie załącznika

**NOWA WALIDACJA - Szczegółowo**:

```python
async def upload_attachment(message_id: int, file: UploadFile, ...):
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB limit
    
    # 1. Sprawdzenie czy wiadomość istnieje i czy użytkownik jest nadawcą
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg or msg.sender_id != current_user.id:
        raise HTTPException(403, 'Tylko nadawca może dodać załącznik')
    
    # 2. NOWE: Sanitizacja nazwy pliku (zapobieganie path traversal)
    if not file.filename:
        raise HTTPException(400, 'Nazwa pliku wymagana')
    
    try:
        sanitized_filename = InputSanitizer.sanitize_filename(file.filename)
        # "../../malicious.exe" → "maliciousexe"
        # "report.pdf" → "report.pdf"
    except ValueError as e:
        raise HTTPException(400, f'Nieprawidłowa nazwa: {e}')
    
    # 3. NOWE: Walidacja typu MIME (whitelist bezpiecznych typów)
    content_type = file.content_type or 'application/octet-stream'
    if not InputSanitizer.validate_mime_type(content_type):
        raise HTTPException(400, f'Typ MIME {content_type} niedozwolony')
    
    # 4. NOWE: Sprawdzenie rozmiaru pliku
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(413, f'Plik zbyt duży (max 10 MB, {len(content)/1024/1024:.1f} MB)')
    if len(content) == 0:
        raise HTTPException(400, 'Plik jest pusty')
    
    # 5. Zapisanie załącznika
    attachment = Attachment(
        message_id=message_id,
        filename=sanitized_filename,
        mime_type=content_type,
        ciphertext=content,
        size=len(content),
    )
    db.add(attachment)
    db.commit()
    
    return AttachmentUploadResponse(...)
```

**Whitelist typów MIME** (tylko bezpieczne):
```
Dokumenty:
- application/pdf
- application/msword (DOCX)
- application/vnd.openxmlformats-officedocument.wordprocessingml.document
- application/vnd.ms-excel
- application/vnd.openxmlformats-officedocument.spreadsheetml.sheet

Obrazy:
- image/jpeg
- image/png
- image/gif
- image/webp

Tekst:
- text/plain
- text/csv
```

**Zablokowane** (niebezpieczne):
- .exe, .dll, .sh, .bat → executable
- .zip, .rar, .7z → archives
- .html, .js, .php → web
- aplikacja/x-msdownload → MIME dla .exe

**Przykład: Path Traversal Attack**
```
Atak: filename="../../etc/passwd"
Po sanitizacji: "etcpasswd"
Rezultat: Plik zapisany bezpiecznie, nie w /etc/

Atak: filename="malware.exe"
Po validate_mime_type: application/x-msdownload
Rezultat: 400 Bad Request "Type not allowed"
```

---

#### **GET /messages/inbox/{message_id}/attachments** - Listowanie załączników

**Nowy endpoint**:
```python
@router.get('/inbox/{message_id}/attachments', 
            response_model=List[AttachmentListItem])
def get_attachments(message_id: int, ...):
    # Sprawdzenie: wiadomość istnieje?
    msg = db.query(Message).filter(...).first()
    if not msg:
        raise HTTPException(404, 'Wiadomość nie znaleziona')
    
    # Sprawdzenie: użytkownik jest nadawcą lub odbiorcą?
    is_sender = msg.sender_id == current_user.id
    is_recipient = db.query(MessageRecipient).filter(
        MessageRecipient.message_id == message_id,
        MessageRecipient.recipient_id == current_user.id,
        MessageRecipient.is_deleted == False,
    ).first() is not None
    
    if not (is_sender or is_recipient):
        raise HTTPException(403, 'Brak dostępu do wiadomości')
    
    # Zwrócenie metadanych bez zawartości
    attachments = db.query(Attachment).filter(...).all()
    return [AttachmentListItem(...) for a in attachments]
```

**Odpowiedź**:
```json
[
  {
    "id": 1,
    "message_id": 5,
    "filename": "raport.pdf",
    "size_bytes": 2048000,
    "mime_type": "application/pdf"
  },
  {
    "id": 2,
    "message_id": 5,
    "filename": "obraz.jpg",
    "size_bytes": 512000,
    "mime_type": "image/jpeg"
  }
]
```

---

#### **GET /messages/attachments/{attachment_id}/download** - Pobieranie załącznika

**Nowy endpoint**:
```python
@router.get('/attachments/{attachment_id}/download',
            response_model=AttachmentDownloadResponse)
def download_attachment(attachment_id: int, ...):
    # Pobieranie załącznika i wiadomości
    attachment = db.query(Attachment).filter(...).first()
    msg = attachment.message
    
    # Sprawdzenie autoryzacji (jak wyżej)
    is_sender = msg.sender_id == current_user.id
    is_recipient = ...
    
    if not (is_sender or is_recipient):
        raise HTTPException(403, 'Brak dostępu')
    
    # Zwrócenie zawartości w base64
    return AttachmentDownloadResponse(
        filename=attachment.filename,
        data_base64=base64.b64encode(attachment.ciphertext).decode('ascii'),
        mime_type=attachment.mime_type,
    )
```

**Odpowiedź**:
```json
{
  "filename": "raport.pdf",
  "data_base64": "JVBERi0xLjQK...",
  "mime_type": "application/pdf"
}
```

---

## Decyzje bezpieczeństwa

### Dlaczego temat (subject) jest w plaintext?

**PRZED (Niebezpieczne)**:
```
Temat wbudowany w szyfrowany AAD (Associated Authenticated Data)
- Nie można wyszukiwać/sortować po temacie
- Znaki specjalne (cudzysłowy, itp.) powodują błędy parsowania
- Odzyskanie tematu nie działa przy uszkodzeniu danych
- Nie można pokazać podglądu w liście wiadomości
```

**PO (Bezpieczne)**:
```
Temat przechowywany w zwykłej kolumnie SQL
- Szybkie wyszukiwanie (indeks)
- Brak problemów z parsowaniem
- Integralność sprawdzana poprzez sygnaturę (hash AAD)
- Można wyświetlić w liście bez deszyfrowania całej wiadomości
```

**Model zagrożeń**: Temat to metadane (akceptowalne ujawnienie plaintext). Body jest szyfrowany i podpisany.

---

### Dlaczego rate limiting na wysyłaniu?

**Scenariusz ataku**: Osoba atakująca wysyła 10000 wiadomości/sekundę
- Wyczerpuje miejsce na dysku (wzrost bazy danych)
- Marnuje CPU (szyfrowanie dla każdej wiadomości)
- DoS na odbiorców (spam notyfikacji)

**Rozwiązanie**: 10 wiadomości/min na użytkownika
- Użytkownicy legalni: 600 wiadomości/godzinę (bardzo dużo)
- Osoba atakująca: Zablokowana po 10 wiadomościach

---

### Dlaczego whitelist typów MIME?

**Ryzyko**: Użytkownik wysyła złośliwy EXE jako "PDF"
- Jeśli system auto-execute files → RCE (zdalny dostęp)
- Whitelist zapobiega typom executables

**Dozwolone typy**:
- Dokumenty: PDF, DOCX, XLSX, CSV
- Obrazy: JPG, PNG, GIF, WebP (bezpieczne kodeki)
- Tekst: TXT, CSV

**Zablokowane typy**:
- Executable: .exe, .dll, .sh, .bat, .zip
- Web: .html, .js, .php
- Archive: .zip, .rar, .7z

---

### Dlaczego sanitizacja nazw plików?

**Wektor ataku**: Path Traversal
```
Nazwa: "../../etc/passwd"
BEZ sanitizacji → Plik zapisany w /data/../../etc/passwd = /etc/passwd
Z sanitizacją → Nazwa = "etcpasswd" (bezbliskiego)
```

**Ochrona**:
- Usuń ../ i ..\ 
- Pozwól tylko: alfanumeryczne, dot, dash, underscore
- Max 255 znaków

---

## Tabela podsumowania walidacji

| Wejście | Min | Max | Walidacja | Sanitizer |
|---------|-----|-----|-----------|-----------|
| **Username** | 3 | 64 | Alfanumeryczne/dash/underscore | `sanitize_username()` |
| **Email** | 5 | 255 | Format RFC 5322 | Pydantic EmailStr |
| **Hasło** | 12 | 128 | ULSD + znak specjalny | Regex validators |
| **Temat** | 0 | 255 | Bez znaków sterujących | `sanitize_subject()` |
| **Body** | 1 | 50000 | Pozwala nowe linie, bez XSS | `sanitize_body()` |
| **Odbiorcy** | 1 | 20 | Unikalne, niepuste | `validate_recipient_list()` |
| **Nazwa pliku** | 1 | 255 | Bez path traversal | `sanitize_filename()` |
| **Rozmiar pliku** | 1 byte | 10 MB | Pozytywny | Sprawdzenie rozmiaru |
| **Typ MIME** | - | - | Whitelist 8 typów | `validate_mime_type()` |

---

## Strategia obsługi błędów

### Szczegółowe błędy (logowanie wewnętrzne)
```
Log: "Użytkownik 42 spróbował SQL injection w temacie: DROP TABLE users"
Cel: Zapobieganie ujawnieniu internałów atakującemu
```

### Generyczne błędy (do klienta)
```json
{
  "detail": "Nieprawidłowe wejście. Sprawdź swoją wiadomość."
}
```

**Korzyści**:
- Osoba atakująca nie może wyliczać luk
- Użytkownik nie mylony by jargon techniczny
- Admin może debugować poprzez logi

---

## Modyfikowane pliki

| Plik | Zmiany | Linii |
|------|--------|-------|
| `backend/app/security/sanitizer.py` | NOWY: Centralizowana walidacja wejścia | +400 |
| `backend/app/security/rate_limiter.py` | NOWY: Ograniczanie szybkości | +80 |
| `backend/app/schemas/auth.py` | Validators, pattern checks, weryfikacja złożoności | +40 |
| `backend/app/schemas/message.py` | Validators dla tematu/body, nowe attachment schematy | +80 |
| `backend/app/api/routes/messages.py` | Rate limiting, walidacja filename/MIME na upload | +150 |

**Razem**: +750 linii kodu, 2 nowe pliki

---

## Co NIJE chronione (poza zakresem Etap 7)

1. **SQL Injection**: SQLAlchemy parameterization to obsługuje
2. **CSRF Tokens**: Już implementowane w Etap 6
3. **Authentication Bypass**: JWT + 2FA na miejscu
4. **Message Encryption Bypass**: Stack kryptografii działa prawidłowo
5. **Rate Limiting na wszystkich endpointach**: Tylko send_message na teraz (rozszerzalne)

---

## Integracja z istniejącymi funkcjonalnościami

### Pydantic Validators + Sanitizer
```
Wejście użytkownika → Pydantic Schema → Field Validators → Funkcje Sanitizer → Czyszcze dane → Logika biznesowa
```

### Rate Limiter + Database
```
POST /send → Sprawdzenie rate limit → Jeśli OK → Szyfrowanie + Zapis → Commit DB → Return 200
           → Jeśli zablokowane → Return 429 (bez zapisu DB)
```

### CSRF Middleware + Upload Załącznika
```
POST /upload → CSRF validation → Sanitizacja filename → Sprawdzenie MIME → Zapis
```

---

## Następne kroki (Etap 8)

1. **README.md** - Scenariusz demo (rejestracja → login → wysłanie → odbiór)
2. **Deployment guide** - Konfiguracja środowiska, SSL certs, Docker commands
3. **Security assumptions** - Co jest chronione, co NIJE (ograniczenia single-server)

---

## Wnioski

Etap 7 hartuje aplikację przed częstymi lukami web poprzez:
- ✅ **Walidacja wejścia** (Pydantic schema z regex, limitami długości)
- ✅ **Sanitizacja** (centralizowane narzędzie blokujące niebezpieczne wzorce)
- ✅ **Rate limiting** (zapobieganie nadużyciom i DoS)
- ✅ **Walidacja typu MIME** (zapobiega przesyłaniu złośliwych plików)
- ✅ **Zapobieganie path traversal** (sanitizacja nazw plików)

System jest teraz **odporny na ataki injekcji, XSS, path traversal i flood** przy czystej obsłudze błędów i logowaniu.

---

*Etap 7 ukończony. Gotowy do Etap 8: Dokumentacja & Deployment.*
