import re
from typing import Tuple


def validate_password_strength(password: str) -> Tuple[bool, str]:
    if len(password) < 12:
        return False, "Hasło musi mieć co najmniej 12 znaków"
    
    if not re.search(r'[A-Z]', password):
        return False, "Hasło musi zawierać wielką literę"
    
    if not re.search(r'[a-z]', password):
        return False, "Hasło musi zawierać małą literę"
    
    if not re.search(r'[0-9]', password):
        return False, "Hasło musi zawierać cyfrę"
    
    if not re.search(r'[!@#$%^&*\-+=]', password):
        return False, "Hasło musi zawierać znak specjalny (!@#$%^&*-+="
    
    return True, ""


def get_password_strength_feedback(password: str) -> str:
    is_valid, error = validate_password_strength(password)
    
    if is_valid:
        return "Siła hasła: Silne ✓"
    
    return f"Siła hasła: {error}"
