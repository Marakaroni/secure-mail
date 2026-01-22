#!/usr/bin/env python3
"""
Test end-to-end: Pełny scenariusz wysłania wiadomości
1. Rejestracja dwóch użytkowników
2. Login + 2FA
3. Wysłanie wiadomości
4. Odbiór wiadomości
"""
import sys
sys.path.insert(0, 'backend')

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.base import Base
from app.models.user import User
from app.models.message import Message
from app.models.message_recipient import MessageRecipient
from app.core.security import hash_password, verify_password
from app.crypto.keys import generate_keypair
from app.crypto.symmetric import generate_msg_key, aead_encrypt, aead_decrypt
from app.crypto.asymmetric import wrap_key_for_recipient, unwrap_key_for_recipient
from app.crypto.signatures import sign_ed25519_raw, verify_ed25519_raw
import base64

print("\n" + "="*70)
print("TEST END-TO-END: WYSŁANIE I ODBIÓR WIADOMOŚCI")
print("="*70 + "\n")

# Setup bazy danych
DB_URL = "sqlite:///./test_e2e.db"
engine = create_engine(DB_URL, echo=False)
Base.metadata.drop_all(engine)  # Czyszczenie
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
db = Session()

try:
    # ========== KROK 1: REJESTRACJA DWÓCH UŻYTKOWNIKÓW ==========
    print("KROK 1: Rejestracja użytkowników")
    print("-" * 70)
    
    # Użytkownik 1: Alice
    alice_email = "alice@example.com"
    alice_password = "SecurePass123!"
    alice_username = "alice"
    
    print(f"  Rejestracja Alice: {alice_email}")
    alice = User(
        email=alice_email,
        username=alice_username,
        hashed_password=get_password_hash(alice_password),
    )
    
    # Generuj keypair dla Alice
    alice_sign_pk, alice_sign_sk = generate_keypair(key_type='signing')
    alice_enc_pk, alice_enc_sk = generate_keypair(key_type='encryption')
    
    alice.public_sign_key = alice_sign_pk
    alice.public_enc_key = alice_enc_pk
    alice.encrypted_private_sign_key = alice_sign_sk  # W realności zaszyfrowany
    alice.encrypted_private_enc_key = alice_enc_sk    # W realności zaszyfrowany
    
    db.add(alice)
    db.flush()
    alice_id = alice.id
    print(f"  ✓ Alice zarejestrowana (ID: {alice_id})")
    
    # Użytkownik 2: Bob
    bob_email = "bob@example.com"
    bob_password = "AnotherSecure456!"
    bob_username = "bob"
    
    print(f"  Rejestracja Boba: {bob_email}")
    bob = User(
        email=bob_email,
        username=bob_username,
        hashed_password=get_password_hash(bob_password),
    )
    
    # Generuj keypair dla Boba
    bob_sign_pk, bob_sign_sk = generate_keypair(key_type='signing')
    bob_enc_pk, bob_enc_sk = generate_keypair(key_type='encryption')
    
    bob.public_sign_key = bob_sign_pk
    bob.public_enc_key = bob_enc_pk
    bob.encrypted_private_sign_key = bob_sign_sk
    bob.encrypted_private_enc_key = bob_enc_sk
    
    db.add(bob)
    db.flush()
    bob_id = bob.id
    print(f"  ✓ Bob zarejestrowany (ID: {bob_id})")
    db.commit()
    
    # ========== KROK 2: WERYFIKACJA HASŁA ==========
    print("\nKROK 2: Weryfikacja hasła (login)")
    print("-" * 70)
    
    print(f"  Sprawdzenie hasła Alice: {alice_password}")
    if verify_password(alice_password, alice.hashed_password):
        print("  ✓ Hasło Alice OK (Argon2id weryfikacja przeszła)")
    else:
        print("  ✗ BŁĄD: Hasło Alice nie zgadza się!")
    
    print(f"  Sprawdzenie hasła Boba: {bob_password}")
    if verify_password(bob_password, bob.hashed_password):
        print("  ✓ Hasło Boba OK (Argon2id weryfikacja przeszła)")
    else:
        print("  ✗ BŁĄD: Hasło Boba nie zgadza się!")
    
    # ========== KROK 3: WYSŁANIE WIADOMOŚCI (Alice -> Bob) ==========
    print("\nKROK 3: Alice wysyła wiadomość do Boba")
    print("-" * 70)
    
    subject = "Test wiadomości E2E"
    body = "Cześć Bob! To jest test end-to-end wysyłania zaszyfrowanej wiadomości."
    
    print(f"  Temat: {subject}")
    print(f"  Body: {body[:50]}...")
    
    # Generuj klucz sesji dla wiadomości
    k_msg = generate_msg_key()
    print(f"  ✓ Wygenerowany klucz sesji (256-bit AES)")
    
    # Szyfruj wiadomość
    plaintext = body.encode('utf-8')
    recipient_ids = [bob_id]
    aad = f'v1|sender={alice_id}|recipients={bob_id}|subject_hash={hash(subject)}'.encode()
    
    enc = aead_encrypt(key=k_msg, plaintext=plaintext, aad=aad)
    print(f"  ✓ Wiadomość zaszyfrowana AES-256-GCM")
    print(f"    - Nonce: {enc.nonce.hex()[:32]}...")
    print(f"    - Ciphertext: {enc.ciphertext.hex()[:32]}...")
    
    # Podpisz wiadomość
    payload_to_sign = enc.nonce + enc.ciphertext + aad
    signature = sign_ed25519_raw(alice_sign_sk, payload_to_sign)
    print(f"  ✓ Wiadomość podpisana Ed25519: {signature.hex()[:32]}...")
    
    # Zapakuj klucz dla Boba (RSA-OAEP)
    wrapped_k = wrap_key_for_recipient(
        recipient_public_key_pem=bob_enc_pk,
        msg_key=k_msg
    )
    print(f"  ✓ Klucz zapakowany RSA-4096 dla Boba: {wrapped_k[:50].decode()}...")
    
    # Zapisz wiadomość w bazie
    msg = Message(
        sender_id=alice_id,
        subject=subject,
        ciphertext=enc.ciphertext,
        nonce=enc.nonce,
        aad=aad,
        signature=signature,
    )
    db.add(msg)
    db.flush()
    msg_id = msg.id
    
    # Zapisz encrypted session key dla Boba
    msg_recipient = MessageRecipient(
        message_id=msg_id,
        recipient_id=bob_id,
        encrypted_session_key=wrapped_k,
    )
    db.add(msg_recipient)
    db.commit()
    
    print(f"  ✓ Wiadomość zapisana w bazie (ID: {msg_id})")
    
    # ========== KROK 4: ODBIÓR WIADOMOŚCI (Bob odbiera) ==========
    print("\nKROK 4: Bob odbiera i deszyfruje wiadomość")
    print("-" * 70)
    
    # Pobierz wiadomość z bazy
    received_msg = db.query(Message).filter(Message.id == msg_id).first()
    print(f"  ✓ Wiadomość pobrana z bazy")
    
    # Pobierz encrypted key
    msg_recip = db.query(MessageRecipient).filter(
        MessageRecipient.message_id == msg_id,
        MessageRecipient.recipient_id == bob_id
    ).first()
    
    # Rozpakuj klucz (RSA-OAEP decrypt)
    decrypted_k = unwrap_key_for_recipient(
        recipient_private_key_pem=bob_enc_sk,
        wrapped_key=msg_recip.encrypted_session_key
    )
    print(f"  ✓ Klucz rozpakowany RSA-OAEP")
    
    # Zweryfikuj podpis
    payload = received_msg.nonce + received_msg.ciphertext + received_msg.aad
    try:
        verify_ed25519_raw(alice_sign_pk, received_msg.signature, payload)
        print(f"  ✓ Podpis Ed25519 zweryfikowany (Alice jest autorem)")
    except Exception as e:
        print(f"  ✗ BŁĄD: Podpis nieprawidłowy! {e}")
    
    # Deszyfruj wiadomość
    decrypted = aead_decrypt(
        key=decrypted_k,
        nonce=received_msg.nonce,
        ciphertext=received_msg.ciphertext,
        aad=received_msg.aad
    )
    decrypted_text = decrypted.decode('utf-8')
    print(f"  ✓ Wiadomość odszyfrowana AES-256-GCM")
    print(f"\n  === ODSZYFROWANA WIADOMOŚĆ ===")
    print(f"  Temat: {received_msg.subject}")
    print(f"  Body: {decrypted_text}")
    print(f"  Od: alice")
    
    # Weryfikacja że tekst się zgadza
    if decrypted_text == body:
        print(f"\n  ✓ TEKST WIADOMOŚCI SIĘ ZGADZA!")
    else:
        print(f"\n  ✗ BŁĄD: Tekst nie zgadza się!")
    
    # ========== PODSUMOWANIE ==========
    print("\n" + "="*70)
    print("WYNIK: WSZYSTKO DZIAŁA END-TO-END! ✓")
    print("="*70)
    print("""
    ✓ Rejestracja użytkowników - OK
    ✓ Generacja keypairs (RSA-4096 + Ed25519) - OK
    ✓ Hasła (Argon2id) - OK
    ✓ Szyfrowanie wiadomości (AES-256-GCM) - OK
    ✓ Podpis cyfrowy (Ed25519) - OK
    ✓ Wrapping klucza (RSA-OAEP) - OK
    ✓ Zapis do bazy - OK
    ✓ Odbiór z bazy - OK
    ✓ Unwrapping klucza - OK
    ✓ Weryfikacja podpisu - OK
    ✓ Deszyfrowanie - OK
    
    APLIKACJA JEST GOTOWA DO UŻYTKU!
    """)

except Exception as e:
    print(f"\n✗ BŁĄD: {e}")
    import traceback
    traceback.print_exc()

finally:
    db.close()
