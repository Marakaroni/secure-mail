import re
from typing import Optional


class InputSanitizer:
    NULL_BYTE_PATTERN = re.compile(r'\x00')
    CONTROL_CHAR_PATTERN = re.compile(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]') 
    PATH_TRAVERSAL_PATTERN = re.compile(r'\.\.[/\\]')
    SQL_COMMENT_PATTERN = re.compile(r'(--|;|\'|\"|\*\/)', re.IGNORECASE)
    SCRIPT_PATTERN = re.compile(r'<script|javascript:|onerror|onclick|<iframe|<embed', re.IGNORECASE)

    @staticmethod
    def sanitize_string(value: str, max_length: Optional[int] = None, allow_newlines: bool = False) -> str:
        if not isinstance(value, str):
            raise ValueError("Wejście musi być tekstem")
        
        if InputSanitizer.NULL_BYTE_PATTERN.search(value):
            raise ValueError("Bajty null są niedozwolone")

        if allow_newlines:
            dangerous = InputSanitizer.CONTROL_CHAR_PATTERN.sub('', value)
            if dangerous != value:
                raise ValueError("Znaki kontrolne są niedozwolone")
        else:
            if InputSanitizer.CONTROL_CHAR_PATTERN.search(value):
                raise ValueError("Znaki kontrolne są niedozwolone")
        
        if InputSanitizer.PATH_TRAVERSAL_PATTERN.search(value):
            raise ValueError("Wzorce path traversal są niedozwolone")
        
        if InputSanitizer.SQL_COMMENT_PATTERN.search(value):
            pass
        
        if InputSanitizer.SCRIPT_PATTERN.search(value):
            raise ValueError("Wzorce skryptów/XSS są niedozwolone")
        
        if max_length and len(value) > max_length:
            raise ValueError(f"Wejście przekracza maksymalną długość {max_length}")
        
        return value

    @staticmethod
    def sanitize_username(value: str) -> str:
        if len(value) < 3:
            raise ValueError("Nazwa użytkownika musi mieć co najmniej 3 znaki")
        
        sanitized = InputSanitizer.sanitize_string(value, max_length=64)
        
        if not re.match(r'^[a-zA-Z0-9_\-]+$', sanitized):
            raise ValueError("Nazwa użytkownika może zawierać tylko litery, cyfry, dash, underscore")
        
        return sanitized

    @staticmethod
    def sanitize_email(value: str) -> str:
        sanitized = InputSanitizer.sanitize_string(value, max_length=255)
        
        if '@' not in sanitized or '.' not in sanitized.split('@')[1]:
            raise ValueError("Nieprawidłowy format emaila")
        
        return sanitized

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        if not filename or len(filename) > 255:
            raise ValueError("Nieprawidłowa długość nazwy pliku")
        
        filename = filename.replace('\\', '/').split('/')[-1]
        
        if '..' in filename:
            raise ValueError("Path traversal jest niedozwolony")
        
        filename = re.sub(r'[^a-zA-Z0-9._\-() ]', '', filename)
        
        filename = re.sub(r'[ ]{2,}', ' ', filename)
        filename = re.sub(r'[.]{2,}', '.', filename)
        
        if not filename:
            raise ValueError("Nazwa pliku jest pusta po sanityzacji")
        
        return filename

    @staticmethod
    def sanitize_subject(value: str) -> str:
        sanitized = InputSanitizer.sanitize_string(value, max_length=255, allow_newlines=False)
        
        sanitized = sanitized.strip()
        
        return sanitized

    @staticmethod
    def sanitize_body(value: str) -> str:
        sanitized = InputSanitizer.sanitize_string(value, max_length=50000, allow_newlines=True)
        
        lines = sanitized.split('\n')
        lines = [line.rstrip() for line in lines]
        sanitized = '\n'.join(lines)
        
        return sanitized

    @staticmethod
    def validate_mime_type(mime_type: str) -> bool:
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
        
        base_type = mime_type.split(';')[0].strip().lower()
        return base_type in ALLOWED_TYPES

    @staticmethod
    def validate_recipient_list(recipients: list[str], max_recipients: int = 20) -> list[str]:
        if not isinstance(recipients, list):
            raise ValueError("Odbiorcy muszą być listą")
        
        if len(recipients) > max_recipients:
            raise ValueError(f"Za dużo odbiorców (max {max_recipients})")
        
        if len(recipients) == 0:
            raise ValueError("Wymagany co najmniej jeden odbiorca")
        
        unique = set()
        for r in recipients:
            if not isinstance(r, str):
                raise ValueError("Każdy odbiorca musi być tekstem")
            
            r_clean = r.strip().lower()
            if not r_clean:
                raise ValueError("Pusty odbiorca")
            
            if len(r_clean) > 255:
                raise ValueError("Identyfikator odbiorcy jest za długi")
            
            unique.add(r_clean)
        
        return list(unique)
