import base64
from cryptography.fernet import Fernet

class AESCipher:
    def __init__(self, key_hex):
        """
        Initializes the AES-128-CBC cipher (via Fernet) with the 256-bit hex session key.
        Fernet requires a 32-byte URL-safe base64 encoded key.
        """
        # Our session_key is a 64-character SHA-256 hex string (exactly 32 bytes)
        key_bytes = bytes.fromhex(key_hex)
        self.key = base64.urlsafe_b64encode(key_bytes)
        self.fernet = Fernet(self.key)

    def encrypt(self, plaintext_str):
        """Encrypts a string and returns a base64 encoded string safe for JSON."""
        ciphertext_bytes = self.fernet.encrypt(plaintext_str.encode('utf-8'))
        return ciphertext_bytes.decode('utf-8')

    def decrypt(self, encrypted_str):
        """Decrypts a base64 string back into plaintext."""
        plaintext_bytes = self.fernet.decrypt(encrypted_str.encode('utf-8'))
        return plaintext_bytes.decode('utf-8')
