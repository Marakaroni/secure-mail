# Model kryptograficzny (opis)

## Hasła
- Hasła nie są przechowywane jawnie.
- Stosowany jest Argon2id z losową solą i parametrami kosztu.

## 2FA
- Użytkownik ma przypisany sekret TOTP.
- Podczas logowania wymagane jest: hasło + kod TOTP.

## Szyfrowanie wiadomości i załączników
- Dla każdej wiadomości generowany jest losowy klucz sesyjny K_msg oraz nonce/IV.
- Treść i załączniki stanowią spójny ładunek (integralność i poufność dla całości).
- Stosowany jest algorytm AEAD: AES-256-GCM.

## Dystrybucja klucza (hybrydowo)
- K_msg jest szyfrowany kluczem publicznym odbiorcy.
- Dla każdego odbiorcy przechowywany jest osobny zaszyfrowany K_msg.

## Autentyczność (podpis cyfrowy)
- Nadawca podpisuje ciphertext wiadomości oraz istotne metadane.
- Odbiorca weryfikuje podpis kluczem publicznym nadawcy.
