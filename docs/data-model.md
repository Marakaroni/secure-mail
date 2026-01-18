# Model danych (zarys)

## users
- id (PK)
- username/login (unikalny)
- password_hash (Argon2id)
- totp_secret
- public_key
- created_at

## messages
- id (PK)
- sender_id (FK -> users.id)
- created_at
- ciphertext (wiadomość + załączniki jako ładunek logiczny)
- signature (podpis nadawcy)

## message_recipients
- message_id (FK -> messages.id)
- recipient_id (FK -> users.id)
- encrypted_key (K_msg zaszyfrowany dla odbiorcy)
- is_read (bool)
- is_deleted (bool)

## attachments
- id (PK)
- message_id (FK -> messages.id)
- filename
- mime_type
- size
- ciphertext (zaszyfrowane dane pliku)
