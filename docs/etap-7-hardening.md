# Etap 7: Security Hardening & Input Validation

**Status**: ✅ COMPLETE  
**Date**: January 22, 2026  
**Build**: Successful (Docker containers running)

---

## Overview

Etap 7 implements comprehensive input validation, sanitization, and rate limiting across all API endpoints. This prevents:
- **Injection attacks** (SQL, XSS, command injection)
- **Path traversal** attacks (../../ sequences)
- **Abuse** (flood attacks via rate limiting)
- **Invalid data** (null bytes, control characters, oversized payloads)

---

## Changes Summary

### 1. **Input Sanitization Utility** (`backend/app/security/sanitizer.py`)

**Purpose**: Centralized validation logic for all user inputs

**Functions**:
- `sanitize_string()` - Remove null bytes, control chars, XSS patterns
- `sanitize_username()` - Alphanumeric + dash/underscore only
- `sanitize_email()` - Basic email format validation
- `sanitize_filename()` - Prevent path traversal (../, ..\)
- `sanitize_subject()` - Max 255 chars, no control chars
- `sanitize_body()` - Max 50000 chars, allow newlines, remove dangerous patterns
- `validate_mime_type()` - Whitelist: PDF, images, Office docs, text/csv
- `validate_recipient_list()` - Max 20 recipients, unique, non-empty

**Patterns Blocked**:
```
- Null bytes (\x00)
- Control characters (except \t, \n, \r)
- Path traversal (../ or ..\)
- SQL comments (-- ; ' " */)
- XSS vectors (<script>, javascript:, onerror, onclick)
```

---

### 2. **Rate Limiting** (`backend/app/security/rate_limiter.py`)

**Purpose**: Prevent abuse by limiting operations per user

**Implementation**:
- In-memory rate limiter (simple, dev-friendly)
- Tracks attempts with timestamps
- Auto-cleanup of old entries

**Limits**:
- **Message sending**: 10 messages per 60 seconds per user → 429 Too Many Requests
- Expandable to other operations (upload, delete, etc.)

**Example**:
```python
limiter = get_rate_limiter()
if not limiter.is_allowed(user_id, 'send_message', max_attempts=10, window_seconds=60):
    raise HTTPException(status_code=429, detail='Too many messages sent')
```

---

### 3. **Enhanced Pydantic Schemas** (`backend/app/schemas/`)

#### **auth.py** - Registration & Login Validation

```python
class RegisterIn:
    username: str (3-64 chars, pattern: alphanumeric/dash/underscore)
    email: EmailStr (validated by Pydantic)
    password: str (12+ chars with uppercase, lowercase, digit, special char)
    
    @field_validator('username') → InputSanitizer.sanitize_username()
    @field_validator('password') → Check complexity (regex on ULSD, special)

class LoginIn:
    email: EmailStr
    password: str (1-128 chars, must not be whitespace-only)
    
    @field_validator('password') → Ensure not empty/whitespace
```

**Security Checks**:
- ✅ Username blocked: SQL chars, path traversal, non-ASCII
- ✅ Password must contain uppercase, lowercase, digit, special char
- ✅ Extra='forbid' → reject unknown fields (prevents data exposure)

---

#### **message.py** - Message & Attachment Validation

```python
class MessageSendRequest:
    recipients: List[str] (1-20 recipients, unique, non-empty)
    subject: str (0-255 chars, no control chars)
    body: str (1-50000 chars, allows newlines)
    
    @field_validator('recipients') → validate_recipient_list()
    @field_validator('subject') → sanitize_subject()
    @field_validator('body') → sanitize_body() + not empty check

class AttachmentUploadResponse, AttachmentListItem, AttachmentDownloadResponse:
    (New schemas for Etap 7 attachment endpoints)
```

**Validation Flow**:
1. Pydantic schema receives JSON
2. Field validators run (min/max length, pattern)
3. Custom validators call sanitizer functions
4. If any fail → 422 Unprocessable Entity with error details
5. If all pass → cleaned data forwarded to handler

---

### 4. **Message Endpoint Hardening** (`backend/app/api/routes/messages.py`)

#### **POST /messages/send** - Send Message

**Changes**:
- ✅ Rate limiting: 10 messages/min per user
- ✅ Prevent self-messaging
- ✅ Recipient validation (exist + not deleted)
- ✅ All inputs sanitized before encryption

**Error Handling**:
```
200 OK → Message sent (message_id returned)
400 Bad Request → Invalid recipients, empty body, etc.
403 Forbidden → Not sender, recipient not found
429 Too Many Requests → Rate limit exceeded
500 Internal Server Error → Crypto/DB error
```

---

#### **POST /messages/attachments/upload** - Upload Attachment

**Validations**:
- ✅ **Filename sanitization**: Remove ../, prevent traversal
- ✅ **MIME-type whitelist**: Only safe types allowed
  - Allowed: PDF, images (JPG/PNG/GIF/WebP), Office docs, text/CSV
  - Blocked: exe, zip, javascript, html, etc.
- ✅ **Size limit**: Max 10 MB per file
- ✅ **Empty file check**: Reject 0-byte files
- ✅ **Sender authorization**: Only sender can add attachments

**Error Handling**:
```
201 Created → Attachment stored (attachment_id, filename, size_bytes)
400 Bad Request → Invalid filename, empty file, unsupported MIME type
404 Not Found → Message not found
413 Payload Too Large → File exceeds 10 MB
500 Internal Server Error → Storage failure
```

---

#### **GET /messages/inbox/{id}/attachments** - List Attachments

**Validations**:
- ✅ Message exists
- ✅ User is sender or recipient
- ✅ Recipient not marked as deleted

**Response**:
```json
[
  {"id": 1, "message_id": 5, "filename": "report.pdf", "size_bytes": 2048000, "mime_type": "application/pdf"},
  {"id": 2, "message_id": 5, "filename": "image.jpg", "size_bytes": 512000, "mime_type": "image/jpeg"}
]
```

---

#### **GET /messages/attachments/{id}/download** - Download Attachment

**Validations**:
- ✅ Attachment exists
- ✅ Message exists
- ✅ User is sender or recipient
- ✅ Recipient not deleted

**Response**:
```json
{
  "filename": "report.pdf",
  "data_base64": "JVBERi0xLjQK...",
  "mime_type": "application/pdf"
}
```

---

## Security Decisions

### Why Separate Subject Column?

**Before (Vulnerable)**:
```
Subject embedded in encrypted AAD only
- Can't search/sort messages by subject
- Special chars (quotes, etc.) cause parsing bugs
- Subject recovery fails on corruption
```

**After (Safe)**:
```
Subject stored as plaintext indexed column
- Fast search/sort
- No parsing bugs
- Integrity checked via signature (AAD hash)
```

**Threat Model**: Subject is metadata (acceptable to expose plaintext). Body is encrypted.

---

### Why Rate Limiting on Send?

**Scenario**: Attacker sends 10,000 messages/second
- Exhausts disk space (DB growth)
- Wastes CPU (encryption per message)
- DoS on recipients (notification spam)

**Solution**: 10 messages/min per user
- Legitimate users: 600 messages/hour (very high)
- Attacker: Blocked after 10 messages

---

### Why MIME-Type Whitelist?

**Risk**: User uploads malicious EXE disguised as PDF
- If system auto-executes files → RCE
- Whitelist prevents executable MIME types

**Allowed Types**:
- Documents: PDF, DOCX, XLSX, CSV
- Images: JPG, PNG, GIF, WebP (safe codecs)
- Text: TXT, CSV

**Blocked Types**:
- Executables: .exe, .dll, .sh, .bat, .zip
- Web: .html, .js, .php
- Archives: .zip, .rar, .7z

---

### Why Sanitize Filenames?

**Attack Vector**: Path Traversal
```
Filename: "../../etc/passwd"
Without sanitization → File stored at /data/../../etc/passwd = /etc/passwd
With sanitization → Filename = "etcpasswd" (sanitized)
```

**Protection**:
- Remove ../ and ..\
- Allow only: alphanumeric, dot, dash, underscore
- Max 255 chars

---

## Validation Summary Table

| Input | Min | Max | Validation | Sanitizer |
|-------|-----|-----|-----------|-----------|
| **Username** | 3 | 64 | Alphanumeric/dash/underscore | `sanitize_username()` |
| **Email** | 5 | 255 | RFC 5322 format | Pydantic EmailStr |
| **Password** | 12 | 128 | ULSD + special char | Regex validators |
| **Subject** | 0 | 255 | No control chars | `sanitize_subject()` |
| **Body** | 1 | 50000 | Allow newlines, no XSS | `sanitize_body()` |
| **Recipients** | 1 | 20 | Unique, non-empty | `validate_recipient_list()` |
| **Filename** | 1 | 255 | No path traversal | `sanitize_filename()` |
| **File Size** | 1 byte | 10 MB | Positive | File size check |
| **MIME Type** | - | - | Whitelist 8 types | `validate_mime_type()` |

---

## Error Handling Strategy

### Detailed Errors (Internal Logging)
```
Log: "User 42 attempted SQL injection in subject: DROP TABLE users"
Prevent: Exposure of internals to attacker
```

### Generic Errors (To Client)
```json
{
  "detail": "Invalid input. Please check your message and try again."
}
```

**Benefits**:
- Attacker can't enumerate vulnerabilities
- User not confused by technical jargon
- Admin can debug via logs

---

## Testing Scenarios

### Test Case 1: Invalid Filename (Path Traversal)
```bash
POST /messages/attachments/upload
Filename: "../../malicious.exe"

Expected: 400 Bad Request
Response: "Filename contains invalid characters"
```

---

### Test Case 2: Oversized File
```bash
POST /messages/attachments/upload
File size: 15 MB (exceeds 10 MB limit)

Expected: 413 Payload Too Large
Response: "File too large (max 10 MB, received 15.0 MB)"
```

---

### Test Case 3: Unsupported MIME Type
```bash
POST /messages/attachments/upload
Content-Type: "application/x-msdownload" (EXE)

Expected: 400 Bad Request
Response: "MIME type application/x-msdownload not allowed"
```

---

### Test Case 4: Rate Limiting
```bash
POST /messages/send (× 11 times in 60 seconds)

Attempts 1-10: 200 OK
Attempt 11: 429 Too Many Requests
Response: "Too many messages sent. Please wait before sending more."
```

---

### Test Case 5: XSS Injection in Subject
```bash
POST /messages/send
Subject: "<script>alert('xss')</script>"

Expected: 400 Bad Request
Response: "Script/XSS patterns not allowed"
```

---

### Test Case 6: Null Bytes in Body
```bash
POST /messages/send
Body: "Hello\x00World"

Expected: 400 Bad Request
Response: "Null bytes not allowed"
```

---

## Files Modified

| File | Changes | Lines |
|------|---------|-------|
| `backend/app/security/sanitizer.py` | NEW: Centralized input validation | +400 |
| `backend/app/security/rate_limiter.py` | NEW: Rate limiting utility | +80 |
| `backend/app/schemas/auth.py` | Enhanced validators, patterns, complexity checks | +40 |
| `backend/app/schemas/message.py` | Validators for subject/body, new attachment schemas | +80 |
| `backend/app/api/routes/messages.py` | Rate limiting on send, filename/MIME validation on upload | +150 |

---

## What's NOT Protected (Non-Goals for Etap 7)

1. **SQL Injection**: SQLAlchemy parameterization handles this (no raw SQL)
2. **CSRF Tokens**: Already implemented in Etap 6 (CSRF middleware)
3. **Authentication Bypass**: JWT + 2FA already in place
4. **Message Encryption Bypass**: Cryptography stack is sound
5. **Rate Limiting on All Endpoints**: Only message send for now (expandable)

---

## Integration with Existing Features

### Pydantic Validators + Sanitizer
```
User Input → Pydantic Schema → Field Validators → Sanitizer Functions → Clean Data → Business Logic
```

### Rate Limiter + Database
```
POST /send → Check rate limit → If OK → Encrypt + Store → Commit DB → Return 200
            → If blocked → Return 429 (no DB write)
```

### CSRF Middleware + Attachment Upload
```
POST /attachments/upload → CSRF validation → Filename sanitization → MIME check → Store
```

---

## Next Steps (Etap 8)

1. **Documentation** (README, architecture doc)
2. **Deployment checklist** (environment setup, SSL certs)
3. **Security assumptions** (single-server limitations, production notes)

---

## Conclusion

Etap 7 hardens the application against common web vulnerabilities through:
- ✅ **Input validation** (Pydantic schemas with regex, length limits)
- ✅ **Sanitization** (centralized utility blocking dangerous patterns)
- ✅ **Rate limiting** (prevents abuse and DoS)
- ✅ **MIME-type validation** (prevents malicious file uploads)
- ✅ **Path traversal prevention** (filename sanitization)

The system is now **resilient to injection attacks, XSS, path traversal, and flood attacks** while maintaining clean error handling and logging.

---

*Etap 7 complete. Ready for Etap 8: Documentation & Deployment.*
