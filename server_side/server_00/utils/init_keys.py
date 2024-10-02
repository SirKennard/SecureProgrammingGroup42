from cryptography.hazmat.primitives import serialization
from utils.RSA import RSA
import os

class init_keys:
    def __init__(self, logger, private_key_file, public_key_file):
        self.logger = logger
        self.private_key_file = private_key_file
        self.public_key_file = public_key_file

    def manage(self):
        # Load keys from file
        # If the keys don't exist call rsa = RSA() and generate the key pair and export
        try:
            if os.path.exists(self.private_key_file) and os.stat(self.private_key_file).st_size > 0:
                self.logger.info(f"[+] Found public and private RSA keys")

                with open(self.private_key_file, 'rb') as file:
                    private_key = serialization.load_pem_private_key(
                        file.read(),
                        password=None
                    )   

                with open(self.public_key_file, 'rb') as file:
                    public_key = serialization.load_pem_public_key(file.read())

                rsa = RSA(private_key)
                
            else:
                self.logger.warning(f"[-] RSA key pair not found")
                self.logger.info(f"[*] Generating new RSA key pair")

                rsa = RSA()
                private_key = rsa.export_private_key()
                public_key = rsa.export_public_key()

                with open(self.private_key_file, 'wb') as file:
                    file.write(private_key)

                with open(self.public_key_file, 'wb') as file:
                    file.write(public_key)

        except OSError as e:
            self.logger.error(f"[#] Error validating RSA key pair: {e}")

        return rsa