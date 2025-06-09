"""
Encryption utilities for the password manager.
Provides secure password hashing using SHA-256 and encryption using AES-256.
"""

import os
import base64
import hashlib
from typing import Dict
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class PasswordEncryption:
    """Handles password hashing and encryption operations."""
    
    def __init__(self):
        self.iterations = 100000  # Number of iterations for additional security
    
    def generate_salt(self) -> bytes:
        """Generate a random salt."""
        return os.urandom(32)
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def hash_and_encrypt_password(self, password: str, master_password: str) -> Dict[str, str]:
        """
        Hash password with SHA-256 and encrypt it with AES.
        
        Args:
            password: The password to process
            master_password: Master password for encryption
            
        Returns:
            Dict containing password hash, encrypted password, and salt
        """
        # Generate salt
        salt = self.generate_salt()
        
        # Create hash
        salted_password = password.encode('utf-8') + salt
        password_hash = hashlib.sha256(salted_password).hexdigest()
        
        # Encrypt original password
        key = self._derive_key(master_password, salt)
        f = Fernet(key)
        encrypted_password = f.encrypt(password.encode())
        
        return {
            'password_hash': password_hash,
            'encrypted_password': base64.b64encode(encrypted_password).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8')
        }
    
    def decrypt_password(self, encrypted_password: str, master_password: str, salt: str) -> str:
        """
        Decrypt a password using the master password.
        
        Args:
            encrypted_password: Base64 encoded encrypted password
            master_password: Master password for decryption
            salt: Base64 encoded salt
            
        Returns:
            Decrypted password string
        """
        try:
            # Decode salt
            salt_bytes = base64.b64decode(salt.encode('utf-8'))
            
            # Derive key
            key = self._derive_key(master_password, salt_bytes)
            f = Fernet(key)
            
            # Decrypt password
            encrypted_bytes = base64.b64decode(encrypted_password.encode('utf-8'))
            decrypted = f.decrypt(encrypted_bytes).decode()
            
            return decrypted
            
        except Exception as e:
            raise Exception(f"Failed to decrypt password: {str(e)}")
    
    def verify_and_decrypt_password(self, password: str, stored_hash: str, 
                                  encrypted_password: str, salt: str, 
                                  master_password: str) -> tuple[bool, str]:
        """
        Verify password against hash and decrypt stored password.
        
        Args:
            password: Password to verify
            stored_hash: Stored password hash
            encrypted_password: Encrypted original password
            salt: Base64 encoded salt
            master_password: Master password for decryption
            
        Returns:
            Tuple of (is_valid, decrypted_password)
        """
        try:
            # Decode salt
            salt_bytes = base64.b64decode(salt.encode('utf-8'))
            
            # Verify hash
            salted_password = password.encode('utf-8') + salt_bytes
            test_hash = hashlib.sha256(salted_password).hexdigest()
            is_valid = (test_hash == stored_hash)
            
            # Decrypt original password
            key = self._derive_key(master_password, salt_bytes)
            f = Fernet(key)
            encrypted_bytes = base64.b64decode(encrypted_password.encode('utf-8'))
            decrypted_password = f.decrypt(encrypted_bytes).decode()
            
            return is_valid, decrypted_password
            
        except Exception:
            return False, ""
    
    def verify_master_password(self, password: str, stored_hash: str, salt: str) -> bool:
        """
        Verify master password against stored hash.
        
        Args:
            password: The password to verify
            stored_hash: The stored password hash
            salt: Base64 encoded salt
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            # Decode salt
            salt_bytes = base64.b64decode(salt.encode('utf-8'))
            
            # Create hash with same salt
            salted_password = password.encode('utf-8') + salt_bytes
            test_hash = hashlib.sha256(salted_password).hexdigest()
            
            # Compare hashes
            return test_hash == stored_hash
        
        except Exception:
            return False
    
    def hash_master_password(self, password: str) -> Dict[str, str]:
        """
        Hash master password for storage.
        
        Args:
            password: The master password
            
        Returns:
            Dict containing password hash and salt
        """
        # Generate salt
        salt = self.generate_salt()
        
        # Create hash
        salted_password = password.encode('utf-8') + salt
        password_hash = hashlib.sha256(salted_password).hexdigest()
        
        return {
            'password_hash': password_hash,
            'salt': base64.b64encode(salt).decode('utf-8')
        }
    
    def generate_password(self, length: int = 16, use_uppercase: bool = True, 
                         use_lowercase: bool = True, use_numbers: bool = True, 
                         use_symbols: bool = True, exclude_similar: bool = False) -> str:
        """Generate a secure random password."""
        if length < 8 or length > 128:
            raise ValueError("Password length must be between 8 and 128 characters")
        
        characters = ""
        
        if use_lowercase:
            chars = "abcdefghijklmnopqrstuvwxyz"
            if exclude_similar:
                chars = chars.replace('l', '').replace('o', '')
            characters += chars
        
        if use_uppercase:
            chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            if exclude_similar:
                chars = chars.replace('I', '').replace('O', '')
            characters += chars
        
        if use_numbers:
            chars = "0123456789"
            if exclude_similar:
                chars = chars.replace('0', '').replace('1', '')
            characters += chars
        
        if use_symbols:
            chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            characters += chars
        
        if not characters:
            raise ValueError("At least one character type must be selected")
        
        # Generate password using cryptographically secure random
        password = ""
        for _ in range(length):
            password += characters[int.from_bytes(os.urandom(1), 'big') % len(characters)]
        
        return password
    
    def check_password_strength(self, password: str) -> dict:
        """
        Check password strength and return score with feedback.
        
        Args:
            password: Password to check
            
        Returns:
            Dict with strength score (0-100) and feedback list
        """
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 8:
            score += 25
        else:
            feedback.append("Password should be at least 8 characters long")
        
        if len(password) >= 12:
            score += 10
        
        # Character diversity checks
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)
        
        if has_lower:
            score += 15
        else:
            feedback.append("Include lowercase letters")
        
        if has_upper:
            score += 15
        else:
            feedback.append("Include uppercase letters")
        
        if has_digit:
            score += 15
        else:
            feedback.append("Include numbers")
        
        if has_symbol:
            score += 20
        else:
            feedback.append("Include symbols (!@#$%^&*, etc.)")
        
        # Bonus for length
        if len(password) >= 16:
            score += min(10, (len(password) - 16) * 2)
        
        # Ensure score doesn't exceed 100
        score = min(score, 100)
        
        return {
            'score': score,
            'feedback': feedback,
            'strength': self._get_strength_text(score)
        }
    
    def _get_strength_text(self, score: int) -> str:
        """Convert numeric score to descriptive strength text."""
        if score < 30:
            return "Very Weak"
        elif score < 50:
            return "Weak"
        elif score < 70:
            return "Fair"
        elif score < 90:
            return "Strong"
        else:
            return "Very Strong" 