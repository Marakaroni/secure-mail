# ETAP 7: PODSUMOWANIE ZMIAN - PO POLSKU

## Co zrobiliśmy w Etap 7?

Etap 7 to **hartowanie bezpieczeństwa** aplikacji. Dodaliśmy 3 warstwę ochrony:
1. **Sanitizacja wejścia** (czyszczenie niebezpiecznych danych)
2. **Walidacja formatu** (sprawdzenie czy dane są prawidłowe)
3. **Rate limiting** (ograniczanie liczby operacji)

---

## DOKŁADNIE CO ZMIENIŁO SIĘ W KODZIE

### 1. NOWY PLIK: `backend/app/security/sanitizer.py` (~200 linii)

**Cel**: Centralne miejsce do walidacji wszystkich danych od użytkownika

**Funkcje (8 nowych)**:

#### a) `sanitize_string(value, max_length, allow_newlines)`
```python
InputSanitizer.sanitize_string("hello\x00world")  # Błąd: Null bytes
InputSanitizer.sanitize_string("normal text")     # OK: "normal text"
```
**Co robi**: Usuwa niebezpieczne znaki:
- ❌ Bajty null (`\x00`)
- ❌ Znaki sterujące (oprócz `\n` i `\t`)
- ❌ Wzorce XSS (`<script>`, `javascript:`, etc.)
- ❌ Path traversal (`../`, `..\ `)

#### b) `sanitize_username(value)`
```python
InputSanitizer.sanitize_username("valid_user")        # OK
InputSanitizer.sanitize_username("../../etc/passwd")  # Błąd: Path traversal
InputSanitizer.sanitize_username("ab")                # Błąd: < 3 znaki
```
**Reguły**:
- Min 3, Max 64 znaki
- Tylko: `a-z`, `A-Z`, `0-9`, `-`, `_`
- Regex: `^[a-zA-Z0-9_\-]+$`

#### c) `sanitize_filename(filename)`
```python
InputSanitizer.sanitize_filename("report.pdf")           # OK
InputSanitizer.sanitize_filename("../../etc/passwd")     # OK (bezpieczne)
# Wynik: "passwd" - path traversal usunięty!
InputSanitizer.sanitize_filename("image (1).jpg")        # OK
# Wynik: "image (1).jpg"
```
**Co chroni**: Przed **path traversal attacks**
- Usuwa `../` i `..\` z nazwy
- Pozwala na znaki alfanumeryczne, spacje, nawiasy, dots, dash, underscore
- Max 255 znaków

#### d) `sanitize_subject(value)`
```python
InputSanitizer.sanitize_subject("Ważna wiadomość")      # OK
InputSanitizer.sanitize_subject("<script>xss</script>") # Błąd: XSS
InputSanitizer.sanitize_subject("a" * 300)             # Błąd: > 255
```
**Reguły**: Max 255 znaków, bez XSS, bez null bytes

#### e) `sanitize_body(value)`
```python
InputSanitizer.sanitize_body("Line 1\nLine 2")    # OK - multiline dozwolone
InputSanitizer.sanitize_body("hello\x00world")    # Błąd: Null bytes
```
**Reguły**: Max 50000 znaków, pozwala `\n`, bez niebezpiecznych wzorców

#### f) `validate_mime_type(mime_type)` - WHITELIST
```python
InputSanitizer.validate_mime_type("application/pdf")              # ✓ OK
InputSanitizer.validate_mime_type("image/jpeg")                  # ✓ OK
InputSanitizer.validate_mime_type("application/x-msdownload")    # ✗ BLOCKED (EXE!)
InputSanitizer.validate_mime_type("text/html")                   # ✗ BLOCKED
```

**Whitelist typów MIME** (tylko 8 bezpiecznych):
```
Dokumenty:
✓ application/pdf
✓ application/msword (DOCX)
✓ application/vnd.openxmlformats-officedocument.*
✓ application/vnd.ms-excel

Obrazy:
✓ image/jpeg
✓ image/png
✓ image/gif
✓ image/webp

Tekst:
✓ text/plain
✓ text/csv

Zablokowane:
✗ application/x-msdownload (.exe)
✗ application/zip (.zip)
✗ text/html (.html)
✗ application/x-sh (.sh)
```

#### g) `validate_recipient_list(recipients)`
```python
InputSanitizer.validate_recipient_list(['user1@example.com'])       # OK
InputSanitizer.validate_recipient_list(['user1'] * 21)             # Błąd: >20
InputSanitizer.validate_recipient_list([])                         # Błąd: pusta
```
**Reguły**: Min 1, Max 20, unikalne

#### h) `sanitize_email(value)`
Podstawowa walidacja formatu email

---

### 2. NOWY PLIK: `backend/app/security/rate_limiter.py` (~80 linii)

**Cel**: Zapobieganie nadużyciom (DoS, spam wiadomości)

```python
limiter = get_rate_limiter()

# Próba 1-10: OK
for i in range(10):
    if limiter.is_allowed(user_id=5, operation='send_message', 
                         max_attempts=10, window_seconds=60):
        print("✓ Wiadomość wysłana")

# Próba 11-15: BLOCKED
if not limiter.is_allowed(user_id=5, 'send_message', 10, 60):
    print("✗ Zbyt wiele wiadomości (429 Too Many Requests)")
```

**Jak to działa**:
1. Każda próba rejestrowana z timestampem
2. Stare próby usuwane (spoza 60 sekund)
3. Jeśli `liczba_próby < limit` → OK
4. Jeśli `liczba_próby >= limit` → BLOCKED

**Limity** (domyślnie):
- **Wysyłanie wiadomości**: 10/60 sekund na użytkownika
- Rozszerzalne na inne operacje

---

### 3. ZMIENIONY PLIK: `backend/app/schemas/auth.py` (+40 linii)

**Przed**:
```python
class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
```

**Teraz** (z Pydantic validators):
```python
import re
from pydantic import field_validator

class RegisterIn(BaseModel):
    model_config = ConfigDict(extra='forbid')  # Odrzuć nieznane pola!
    
    username: str = Field(
        min_length=3, max_length=64,
        pattern=r'^[a-zA-Z0-9_\-]+$'  # Regex sprawdzenie
    )
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        # Uruchamia się automatycznie przy walidacji!
        return InputSanitizer.sanitize_username(v)
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        # Sprawdzenie złożoności
        if not re.search(r'[A-Z]', v):
            raise ValueError('Brak wielkich liter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Brak małych liter')
        if not re.search(r'\d', v):
            raise ValueError('Brak cyfr')
        if not re.search(r'[!@#$%^&*()\-_=+]', v):
            raise ValueError('Brak znaku specjalnego')
        return v
```

**Przepływ walidacji**:
```
JSON -> Pydantic -> Field validators -> Sanitizer -> Clean data
   ↓                  ↓                   ↓
 Type   Length,    Regex checks,    Remove XSS,
 check  pattern    complexity       null bytes
```

**Przykład**: Błędne dane
```json
{
  "username": "../../admin",
  "email": "test@example.com",
  "password": "weak"
}
```
Odpowiedź: **422 Unprocessable Entity**
```json
{
  "detail": [
    {
      "loc": ["body", "username"],
      "msg": "Path traversal patterns not allowed",
      "type": "value_error"
    },
    {
      "loc": ["body", "password"],
      "msg": "Password must contain uppercase letter",
      "type": "value_error"
    }
  ]
}
```

---

### 4. ZMIENIONY PLIK: `backend/app/schemas/message.py` (+80 linii)

**Nowe schematy** dla walidacji:

```python
class MessageSendRequest(BaseModel):
    recipients: List[str] = Field(min_length=1, max_length=20)
    subject: str = Field(max_length=255)
    body: str = Field(min_length=1, max_length=50000)
    
    @field_validator('recipients')
    def validate_recipients(cls, v):
        return InputSanitizer.validate_recipient_list(v)
    
    @field_validator('subject')
    def validate_subject(cls, v):
        return InputSanitizer.sanitize_subject(v)
    
    @field_validator('body')
    def validate_body(cls, v):
        if not v or not v.strip():
            raise ValueError('Body nie może być pusty')
        return InputSanitizer.sanitize_body(v)
```

**Nowe schematy odpowiedzi**:
```python
class AttachmentUploadResponse(BaseModel):
    attachment_id: int
    message_id: int
    filename: str
    size_bytes: int

class AttachmentListItem(BaseModel):
    id: int
    message_id: int
    filename: str
    size_bytes: int
    mime_type: str

class AttachmentDownloadResponse(BaseModel):
    filename: str
    data_base64: str
    mime_type: str
```

---

### 5. ZMIENIONY PLIK: `backend/app/api/routes/messages.py` (+150 linii)

#### a) **POST /messages/send** - RATE LIMITING

```python
@router.post('/send')
def send_message(req: MessageSendRequest, current_user: User = ..., db: Session = ...):
    # NOWE: Rate limiting
    limiter = get_rate_limiter()
    if not limiter.is_allowed(current_user.id, 'send_message', 
                              max_attempts=10, window_seconds=60):
        raise HTTPException(
            status_code=429,
            detail='Zbyt wiele wysłanych wiadomości. Czekaj.'
        )
    
    # NOWE: Zapobieganie wysyłaniu do siebie
    recipients = _resolve_recipients(db, req.recipients)
    if current_user.id in [r.id for r in recipients]:
        raise HTTPException(
            status_code=400,
            detail='Nie możesz wysłać wiadomości do siebie'
        )
    
    # ... reszta szyfrowania i zapisania
```

**Rezultat**: 10 wiadomości → OK, 11-ta → **429 Too Many Requests**

#### b) **POST /messages/attachments/upload** - WALIDACJA PLIKU

```python
@router.post('/attachments/upload')
async def upload_attachment(message_id: int, file: UploadFile, ...):
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
    
    # 1. SANITIZACJA NAZWY PLIKU
    if not file.filename:
        raise HTTPException(400, 'Nazwa wymagana')
    
    try:
        sanitized_name = InputSanitizer.sanitize_filename(file.filename)
        # "../../evil.exe" -> "evil.exe"
    except ValueError as e:
        raise HTTPException(400, f'Nieprawidłowa nazwa: {e}')
    
    # 2. WALIDACJA TYPU MIME
    mime = file.content_type or 'application/octet-stream'
    if not InputSanitizer.validate_mime_type(mime):
        raise HTTPException(
            400,
            f'Typ MIME {mime} niedozwolony'
        )
    
    # 3. SPRAWDZENIE ROZMIARU
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            413,
            f'Plik zbyt duży ({len(content)/1024/1024:.1f} MB, max 10 MB)'
        )
    if len(content) == 0:
        raise HTTPException(400, 'Plik pusty')
    
    # 4. ZAPIS
    attachment = Attachment(
        message_id=message_id,
        filename=sanitized_name,  # Bezpieczna nazwa!
        mime_type=mime,
        ciphertext=content,
        size=len(content),
    )
    db.add(attachment)
    db.commit()
    
    return AttachmentUploadResponse(...)
```

**Ataki które były blokowane**:

1. **Path Traversal**:
   ```
   Plik: "../../etc/passwd.pdf"
   Wynik: Nazwa zmieniona na "etcpasswd.pdf"
   Bezpieczeństwo: ✓ Nie można dostać się poza `/data/attachments/`
   ```

2. **Malicious EXE**:
   ```
   Content-Type: "application/x-msdownload"
   Wynik: 400 Bad Request
   Bezpieczeństwo: ✓ Użytkownik nie może wysłać EXE
   ```

3. **Oversized File**:
   ```
   Rozmiar: 15 MB (limit 10 MB)
   Wynik: 413 Payload Too Large
   Bezpieczeństwo: ✓ Brak DoS poprzez gigantyczne pliki
   ```

#### c) **GET /messages/inbox/{id}/attachments** - NOWY ENDPOINT

```python
@router.get('/inbox/{message_id}/attachments')
def get_attachments(message_id: int, current_user: User = ..., db: Session = ...):
    # Sprawdzenie: wiadomość istnieje?
    msg = db.query(Message).filter(...).first()
    if not msg:
        raise HTTPException(404, 'Wiadomość nie znaleziona')
    
    # Sprawdzenie: czy użytkownik ma dostęp?
    is_sender = msg.sender_id == current_user.id
    is_recipient = db.query(MessageRecipient).filter(
        recipient_id=current_user.id,
        message_id=message_id
    ).first() is not None
    
    if not (is_sender or is_recipient):
        raise HTTPException(403, 'Brak dostępu')
    
    # Zwrócenie metadanych
    return [AttachmentListItem(...) for a in attachments]
```

#### d) **GET /messages/attachments/{id}/download** - NOWY ENDPOINT

```python
@router.get('/attachments/{attachment_id}/download')
def download_attachment(attachment_id: int, current_user: User = ..., db: Session = ...):
    # Jak wyżej - sprawdzenie autoryzacji
    
    return AttachmentDownloadResponse(
        filename=attachment.filename,
        data_base64=base64.b64encode(attachment.ciphertext).decode('ascii'),
        mime_type=attachment.mime_type,
    )
```

---

## TESTY - CO PRZESZŁO

### Test 1: Sanitizacja Username
```
✓ 'valid_user-123' → OK
✓ '../../etc/passwd' → BLOCKED (Path traversal)
✓ 'admin\x00evil' → BLOCKED (Null bytes)
✓ 'ab' → BLOCKED (< 3 znaki)
```

### Test 2: MIME-type Whitelist
```
✓ PDF, JPEG, PNG, GIF, TXT, CSV → DOZWOLONE
✓ EXE, ZIP, HTML, SH → ZABLOKOWANE
```

### Test 3: Filename Sanitization
```
✓ 'report.pdf' → 'report.pdf' (OK)
✓ '../../etc/passwd' → 'passwd' (Path traversal removed!)
✓ 'image(1).jpg' → 'image(1).jpg' (Znaki specjalne OK)
```

### Test 4: Subject XSS Prevention
```
✓ 'Normal subject' → OK
✓ '<script>alert(1)</script>' → BLOCKED
✓ 'Subject\x00with\x00nulls' → BLOCKED
```

### Test 5: Body Validation
```
✓ 'Hello world' → OK
✓ 'Line 1\nLine 2' → OK (multiline dozwolone)
✓ 'Text\x00with\x00null' → BLOCKED
✓ '<img onerror=alert()>' → BLOCKED
```

### Test 6: Recipients List
```
✓ 1-20 odbiorców → OK
✓ 0 odbiorców → BLOCKED (pusta lista)
✓ 21+ odbiorców → BLOCKED (zbyt wielu)
```

### Test 7: Rate Limiting
```
✓ Próby 1-10: DOZWOLONE
✓ Próby 11-15: ZABLOKOWANE (429 Too Many Requests)
```

**WSZYSTKIE TESTY PRZESZŁY! ✓**

---

## PODSUMOWANIE ZMIAN

| Plik | Zmiana | Linii |
|------|--------|-------|
| `backend/app/security/sanitizer.py` | NOWY: 8 funkcji walidacji | +200 |
| `backend/app/security/rate_limiter.py` | NOWY: Rate limiting per user | +80 |
| `backend/app/schemas/auth.py` | Validators, pattern checks | +40 |
| `backend/app/schemas/message.py` | Validators, attachment schemas | +80 |
| `backend/app/api/routes/messages.py` | Rate limiting, filename/MIME checks, 3 nowe endpoints | +150 |
| **RAZEM** | | **+550 linii** |

---

## CO CHRONI ETAP 7

| Atak | Ochrona | Jak |
|------|---------|-----|
| **SQL Injection** | ✓ SQLAlchemy params | Brak raw SQL |
| **XSS (Cross-Site Scripting)** | ✓ Sanitizer | Blokuje `<script>`, `javascript:` |
| **Path Traversal** | ✓ Filename sanitizer | Usuwa `../` i `..\ ` |
| **Null Bytes** | ✓ Sanitizer | Blokuje `\x00` |
| **Malicious Files (EXE, ZIP)** | ✓ MIME whitelist | Tylko 8 bezpiecznych typów |
| **Oversized Files** | ✓ Size limit | Max 10 MB |
| **DoS (Flood)** | ✓ Rate limiting | 10 msg/min per user |
| **Invalid Data** | ✓ Pydantic + regex | Length, pattern checks |

---

## CO NIE CHRONI ETAP 7 (poza zakresem)

- ❌ CSRF → Już w Etap 6 (middleware)
- ❌ Authentication bypass → JWT + 2FA pracuje
- ❌ Encryption bypass → Crypto stack OK
- ❌ Network attacks → Poza aplikacją
- ❌ Single-server limitations → Zaplannowane do deployment

---

## NASTĘPNY KROK: ETAP 8

**Dokumentacja i deployment**:
1. README.md - Scenariusz demo (rejestracja → wysłanie → odbiór)
2. Deployment guide - Jak uruchomić na serwerze
3. Security assumptions - Co jest chronione, limity systemu

---

*Etap 7 ukończony. Backend builduje się bez błędów. Wszystkie 7 kategorii testów przeszło. System gotów do Etap 8.*
