# COMP SCI 3307: Group 42 Implementation
# Members: a1850028 Kanwartej Singh, a1853790 Christian Mignone, a1851275 Seung Lee, a1849563 Matthew Fuhlbohm

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class AES:
    def __init__(self, n = 128) -> None:
        # The same key can be used provided the initialisation vector is different
        self.key = AESGCM.generate_key(bit_length = n)

    def encrypt(self, plaintext: bytes) -> tuple[bytes, bytes]:
        # Randomly generate 16 byte initialisation vector
        iv = os.urandom(16)

        ciphertext = AESGCM(self.key).encrypt(
            iv,
            plaintext,
            associated_data = None
        )

        return iv, ciphertext
    
    def decrypt(self, iv: bytes, ciphertext: bytes, key: bytes = None) -> bytes:
        if key is None:
            key = self.key

        if len(iv) != 16:
            raise ValueError("Invalid initialisation vector length: 16 byte length is required")

        plaintext = AESGCM(key).decrypt(iv, ciphertext, associated_data = None)

        return plaintext
    
    def export_key(self) -> bytes:
        return self.key
