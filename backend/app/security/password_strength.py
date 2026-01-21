"""
Password strength validation.
Ensures users create secure passwords.
"""
import re
from typing import Tuple


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password strength according to NIST guidelines.
    
    Requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character (!@#$%^&*-+=)
    
    Args:
        password: Password to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r'[!@#$%^&*\-+=]', password):
        return False, "Password must contain at least one special character (!@#$%^&*-+=)"
    
    return True, ""


def get_password_strength_feedback(password: str) -> str:
    """
    Get detailed feedback about password strength for user.
    """
    is_valid, error = validate_password_strength(password)
    
    if is_valid:
        return "Password strength: Strong ✓"
    
    return f"Password strength: {error}"
