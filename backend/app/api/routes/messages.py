from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.models.message import Message
from app.models.message_recipient import MessageRecipient

from app.schemas.message import MessageSendRequest, MessageSendResponse, MessageListItem, MessageReceiveResponse, MessageUpdateResponse

from app.core.security import get_current_user

from app.crypto.symmetric import generate_msg_key, aead_encrypt
from app.crypto.asymmetric import wrap_key_for_recipient
from app.crypto.signatures import sign_ed25519_raw
from app.security.session_keys import get_session_private_sign_key


router = APIRouter(prefix='/messages', tags=['messages'])


def _resolve_recipients(db: Session, tokens: List[str]) -> List[User]:
    """
    tokens: lista 'recipients' z requestu (u Ciebie stringi).
    Wyszukujemy po email ALBO username (bo logowanie masz po emailu, a username wyświetlasz).
    """
    uniq = [t.strip() for t in tokens if t and t.strip()]
    if not uniq:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid recipients')

    # email match
    by_email = db.query(User).filter(User.email.in_(uniq)).all()

    # username match (jeśli masz kolumnę username)
    by_username = []
    if hasattr(User, 'username'):
        by_username = db.query(User).filter(User.username.in_(uniq)).all()

    # połącz, bez duplikatów
    found_map = {}
    for u in (by_email + by_username):
        found_map[u.id] = u

    recipients = list(found_map.values())
    if not recipients:
        # nie zdradzamy czy użytkownicy istnieją; komunikat ogólny
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid recipients')

    return recipients


def _build_aad(sender_id: int, recipient_ids: List[int], subject: str) -> bytes:
    """
    AAD (Associated Authenticated Data) - nie jest tajne, ale jest uwierzytelnione w AES-GCM.
    To będzie też częścią payloadu do podpisu.
    """
    ids = ','.join(str(i) for i in sorted(recipient_ids))
    subj = subject or ''
    return f'v1|sender={sender_id}|recipients={ids}|subject={subj}'.encode('utf-8')


@router.post('/send', response_model=MessageSendResponse)
def send_message(
    req: MessageSendRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MessageSendResponse:
    # 1) Find recipients
    recipients = _resolve_recipients(db, req.recipients)
    recipient_ids = [u.id for u in recipients]

    # 2) Generate session key for this message
    k_msg = generate_msg_key()

    # 3) Build AAD (Associated Authenticated Data) and encrypt message body
    aad = _build_aad(current_user.id, recipient_ids, req.subject)
    plaintext = req.body.encode('utf-8')

    enc = aead_encrypt(key=k_msg, plaintext=plaintext, aad=aad)
    nonce = enc.nonce
    ciphertext = enc.ciphertext

    # 4) Create signature over (nonce + ciphertext + aad)
    payload_to_sign = nonce + ciphertext + aad

    # Get sender's Ed25519 private key from session cache
    sender_sign_sk_raw = get_session_private_sign_key(current_user.id)
    
    if not sender_sign_sk_raw:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Sender signing key not available in session'
        )
    
    signature = sign_ed25519_raw(sender_sign_sk_raw, payload_to_sign)

    # 5) Save message and recipients in transaction
    try:
        msg = Message(
            sender_id=current_user.id,
            ciphertext=ciphertext,
            nonce=nonce,
            aad=aad,
            signature=signature,
        )

        db.add(msg)
        db.flush()  # Get msg.id

        for r in recipients:
            # Recipient's RSA public key (PEM encoded)
            if not r.public_enc_key:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail='Recipient encryption key missing'
                )

            wrapped_k = wrap_key_for_recipient(
                recipient_public_key_pem=r.public_enc_key,
                msg_key=k_msg
            )

            mr = MessageRecipient(
                message_id=msg.id,
                recipient_id=r.id,
                encrypted_session_key=wrapped_k,
            )
            db.add(mr)

        db.commit()
        return MessageSendResponse(message_id=msg.id)

    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Failed to send message'
        )


@router.get('/inbox', response_model=List[MessageListItem])
def list_inbox(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List received messages (inbox)"""
    from sqlalchemy import and_
    
    # Get all message recipients for this user (where is_deleted=False)
    recipients = db.query(MessageRecipient).filter(
        and_(
            MessageRecipient.recipient_id == current_user.id,
            MessageRecipient.is_deleted == False,
        )
    ).all()
    
    items = []
    for mr in recipients:
        msg = mr.message
        items.append(MessageListItem(
            id=msg.id,
            sender_id=msg.sender_id,
            created_at=msg.created_at,
            is_read=mr.is_read,
            is_deleted=mr.is_deleted,
            subject=msg.aad.decode('utf-8').split('|')[3].replace('subject=', '') if msg.aad else '',
        ))
    
    return items


@router.get('/inbox/{message_id}', response_model=MessageReceiveResponse)
def get_message(
    message_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get decrypted message from inbox.
    Verifies sender signature and decrypts content.
    """
    from app.crypto.asymmetric import unwrap_key_for_recipient
    from app.crypto.symmetric import aead_decrypt
    from app.crypto.signatures import verify_ed25519_raw
    from app.security.session_keys import get_session_private_enc_key
    
    # Find message recipient record
    mr = db.query(MessageRecipient).filter(
        MessageRecipient.message_id == message_id,
        MessageRecipient.recipient_id == current_user.id,
    ).first()
    
    if not mr or mr.is_deleted:
        raise HTTPException(status_code=404, detail='Message not found')
    
    msg = mr.message
    sender = msg.sender
    
    # Get recipient's private encryption key from session
    private_enc_key_pem = get_session_private_enc_key(current_user.id)
    if not private_enc_key_pem:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Private key not available (login again)'
        )
    
    # Decrypt session key
    try:
        k_msg = unwrap_key_for_recipient(
            recipient_private_key_pem=private_enc_key_pem,
            wrapped_key=mr.encrypted_session_key,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Failed to decrypt message key'
        )
    
    # Decrypt message content
    try:
        plaintext = aead_decrypt(
            key=k_msg,
            nonce=msg.nonce,
            ciphertext=msg.ciphertext,
            aad=msg.aad,
        )
        body = plaintext.decode('utf-8')
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Failed to decrypt message'
        )
    
    # Verify signature
    payload_to_verify = msg.nonce + msg.ciphertext + msg.aad
    signature_valid = verify_ed25519_raw(
        public_sign_key_raw=sender.public_sign_key,
        signature=msg.signature,
        payload=payload_to_verify,
    )
    
    # Extract subject from AAD
    aad_str = msg.aad.decode('utf-8')
    subject = ''
    for part in aad_str.split('|'):
        if part.startswith('subject='):
            subject = part.replace('subject=', '')
            break
    
    return MessageReceiveResponse(
        id=msg.id,
        sender_username=sender.username,
        sender_email=sender.email,
        subject=subject,
        body=body,
        created_at=msg.created_at,
        is_read=mr.is_read,
        is_deleted=mr.is_deleted,
        signature_valid=signature_valid,
    )


@router.put('/inbox/{message_id}/read')
def mark_as_read(
    message_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Mark message as read"""
    mr = db.query(MessageRecipient).filter(
        MessageRecipient.message_id == message_id,
        MessageRecipient.recipient_id == current_user.id,
    ).first()
    
    if not mr:
        raise HTTPException(status_code=404, detail='Message not found')
    
    mr.is_read = True
    db.add(mr)
    db.commit()
    
    return MessageUpdateResponse(status='ok')


@router.delete('/inbox/{message_id}')
def delete_message(
    message_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete message (mark as deleted for user)"""
    mr = db.query(MessageRecipient).filter(
        MessageRecipient.message_id == message_id,
        MessageRecipient.recipient_id == current_user.id,
    ).first()
    
    if not mr:
        raise HTTPException(status_code=404, detail='Message not found')
    
    mr.is_deleted = True
    db.add(mr)
    db.commit()
    
    return MessageUpdateResponse(status='ok')
