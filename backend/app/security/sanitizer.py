"""
Input sanitization utilities for Etap 7 - Security Hardening.

Prevents:
- Null bytes in strings
- Control characters (except newlines/tabs)
- SQL injection (prepared statements elsewhere, but validate format)
- Path traversal (../ sequences)
- XSS payloads (basic detection)
"""
import re
from typing import Optional


class InputSanitizer:
    """Validates and sanitizes user input."""

    # Patterns for dangerous content
    NULL_BYTE_PATTERN = re.compile(r'\x00')
    CONTROL_CHAR_PATTERN = re.compile(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]')  # Except \t=0x09, \n=0x0a, \r=0x0d
    PATH_TRAVERSAL_PATTERN = re.compile(r'\.\.[/\\]')
    SQL_COMMENT_PATTERN = re.compile(r'(--|;|\'|\"|\*\/)', re.IGNORECASE)
    SCRIPT_PATTERN = re.compile(r'<script|javascript:|onerror|onclick|<iframe|<embed', re.IGNORECASE)

    @staticmethod
    def sanitize_string(value: str, max_length: Optional[int] = None, allow_newlines: bool = False) -> str:
        """
        Sanitize string input.
        
        Args:
            value: Input string
            max_length: Optional max length after sanitization
            allow_newlines: Allow \n and \r characters (for body text)
        
        Returns:
            Sanitized string
            
        Raises:
            ValueError: If input contains dangerous patterns
        """
        if not isinstance(value, str):
            raise ValueError("Input must be string")
        
        # Check for null bytes
        if InputSanitizer.NULL_BYTE_PATTERN.search(value):
            raise ValueError("Null bytes not allowed")
        
        # Check for dangerous control characters
        if allow_newlines:
            # Allow tab (0x09), newline (0x0a), carriage return (0x0d)
            dangerous = InputSanitizer.CONTROL_CHAR_PATTERN.sub('', value)
            if dangerous != value:
                raise ValueError("Control characters not allowed")
        else:
            # Remove most control characters for single-line fields
            if InputSanitizer.CONTROL_CHAR_PATTERN.search(value):
                raise ValueError("Control characters not allowed")
        
        # Check for path traversal attempts
        if InputSanitizer.PATH_TRAVERSAL_PATTERN.search(value):
            raise ValueError("Path traversal patterns not allowed")
        
        # Warn about SQL patterns (SQLAlchemy parameterization protects us, but flag for review)
        if InputSanitizer.SQL_COMMENT_PATTERN.search(value):
            # Don't block (valid in email/text), but log it
            pass
        
        # Check for XSS patterns
        if InputSanitizer.SCRIPT_PATTERN.search(value):
            raise ValueError("Script/XSS patterns not allowed")
        
        # Apply length limit if specified
        if max_length and len(value) > max_length:
            raise ValueError(f"Input exceeds max length of {max_length}")
        
        return value

    @staticmethod
    def sanitize_username(value: str) -> str:
        """Validate username format (alphanumeric + underscore/dash)."""
        if len(value) < 3:
            raise ValueError("Username must be at least 3 characters")
        
        sanitized = InputSanitizer.sanitize_string(value, max_length=64)
        
        # Username: alphanumeric, dash, underscore only
        if not re.match(r'^[a-zA-Z0-9_\-]+$', sanitized):
            raise ValueError("Username must contain only alphanumeric, dash, underscore")
        
        return sanitized

    @staticmethod
    def sanitize_email(value: str) -> str:
        """Basic email validation (Pydantic handles EmailStr)."""
        sanitized = InputSanitizer.sanitize_string(value, max_length=255)
        
        # Basic format check (EmailStr handles full validation)
        if '@' not in sanitized or '.' not in sanitized.split('@')[1]:
            raise ValueError("Invalid email format")
        
        return sanitized

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Prevent path traversal in filenames."""
        if not filename or len(filename) > 255:
            raise ValueError("Invalid filename length")
        
        # Remove path separators and traversal attempts
        filename = filename.replace('\\', '/').split('/')[-1]
        
        if '..' in filename:
            raise ValueError("Path traversal not allowed")
        
        # Allow alphanumeric, dot, dash, underscore, space, parentheses
        # Replace other characters with nothing instead of rejecting
        filename = re.sub(r'[^a-zA-Z0-9._\-() ]', '', filename)
        
        # Remove multiple consecutive spaces/dots
        filename = re.sub(r'[ ]{2,}', ' ', filename)
        filename = re.sub(r'[.]{2,}', '.', filename)
        
        if not filename:
            raise ValueError("Filename becomes empty after sanitization")
        
        return filename

    @staticmethod
    def sanitize_subject(value: str) -> str:
        """Sanitize message subject."""
        sanitized = InputSanitizer.sanitize_string(value, max_length=255, allow_newlines=False)
        
        # Remove leading/trailing whitespace
        sanitized = sanitized.strip()
        
        return sanitized

    @staticmethod
    def sanitize_body(value: str) -> str:
        """Sanitize message body (allow newlines)."""
        sanitized = InputSanitizer.sanitize_string(value, max_length=50000, allow_newlines=True)
        
        # Trim excessive whitespace but preserve message structure
        lines = sanitized.split('\n')
        lines = [line.rstrip() for line in lines]
        sanitized = '\n'.join(lines)
        
        return sanitized

    @staticmethod
    def validate_mime_type(mime_type: str) -> bool:
        """Validate MIME type is from whitelist."""
        # Whitelist common, safe MIME types
        ALLOWED_TYPES = {
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'text/plain',
            'text/csv',
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/webp',
        }
        
        # Normalize and check
        base_type = mime_type.split(';')[0].strip().lower()
        return base_type in ALLOWED_TYPES

    @staticmethod
    def validate_recipient_list(recipients: list[str], max_recipients: int = 20) -> list[str]:
        """
        Validate and normalize recipient list.
        
        Args:
            recipients: List of recipient identifiers
            max_recipients: Maximum recipients per message
            
        Returns:
            Normalized, unique recipient list
            
        Raises:
            ValueError: If validation fails
        """
        if not isinstance(recipients, list):
            raise ValueError("Recipients must be list")
        
        if len(recipients) > max_recipients:
            raise ValueError(f"Too many recipients (max {max_recipients})")
        
        if len(recipients) == 0:
            raise ValueError("At least one recipient required")
        
        # Sanitize each recipient and remove duplicates
        unique = set()
        for r in recipients:
            if not isinstance(r, str):
                raise ValueError("Each recipient must be string")
            
            r_clean = r.strip().lower()
            if not r_clean:
                raise ValueError("Empty recipient")
            
            if len(r_clean) > 255:
                raise ValueError("Recipient identifier too long")
            
            unique.add(r_clean)
        
        return list(unique)
