from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
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
    
# def main():
#     aes = AES_cryptography()
#     message = b"penis"

#     iv, encrypted = aes.encrypt(message)
#     print(encrypted)

#     decrypted = aes.decrypt(iv, encrypted)
#     print(decrypted)

#     key = aes.export_key()
#     print(key)

# if __name__ == "__main__":
#     main()
