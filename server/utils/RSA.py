# COMP SCI 3307: Group 42 Implementation
# Members: a1850028 Kanwartej Singh, a1853790 Christian Mignone, a1851275 Seung Lee, a1849563 Matthew Fuhlbohm

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

class RSA:
    def __init__(self, private_key = None, e = 65537, n = 2048) -> None:
        # If no keys are passed generate them
        if private_key is None:
            self.private_key = rsa.generate_private_key(
                public_exponent = e,
                key_size = n,
                backend = default_backend()
            )

            self.public_key = self.private_key.public_key()

        else:
            self.private_key = private_key
            self.public_key = self.private_key.public_key()

    def encrypt(self, plaintext: bytes, public_key = None) -> bytes:
        # If there is no public key provided then use the internal generated one
        # This is needed to encrypt with an external public key
        if public_key is None:
            public_key = self.public_key

        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf = padding.MGF1(algorithm = hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label = None
            )
        )

        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf = padding.MGF1(algorithm = hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label = None
            )
        )

        return plaintext
    
    def sign(self, message: bytes) -> bytes:
        signiture = self.private_key.sign(
            message,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = 32
            ),
            hashes.SHA256()
        )

        return signiture
    
    def verify(self, public_key, message: bytes, signiture: bytes) -> bool:
        try:
            public_key.verify(
                signiture,
                message,
                padding.PSS(
                    mgf = padding.MGF1(hashes.SHA256()),
                    salt_length = 32
                ),
                hashes.SHA256()
            )

            return True
        
        except Exception:
            return False

    def export_private_key(self) -> bytes:
        # Serialise the private key to PEM format
        return self.private_key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.NoEncryption()
        )
    
    def export_public_key(self) -> bytes:
        # Serialise the public key to PEM format
        return self.public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        )

# def main():
#     rsa = RSA_cryptography()
#     message = b"penis"

#     # encryption/decryption

#     encrypted = rsa.encrypt(message)
#     print(encrypted)

#     decrypted = rsa.decrypt(encrypted)
#     print(decrypted)

#     # signing/verifying

#     signature = rsa.sign(message)
#     print(signature)

#     valid = rsa.verify(message, signature)
#     print(valid)

#     # exporting

#     public_key_pem = rsa.export_public_key()
#     private_key_pem = rsa.export_private_key()

#     print(public_key_pem.decode())
#     print(private_key_pem.decode())

# if __name__ == "__main__":
#     main()
