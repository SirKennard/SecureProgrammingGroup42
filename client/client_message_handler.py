from RSA import RSA
from AES import AES
from cryptography.hazmat.primitives import hashes, serialization
import json
import base64

# See https://github.com/xvk-64/2024-secure-programming-protocol

class client_message_handler:
    def __init__(self, rsa_handler, aes_handler) -> None:
        self.counter = 0
        self.rsa_handler = rsa_handler
        self.aes_handler = aes_handler

    def client_message(self, data: json) -> json:
        self.counter += 1
        signature = self.rsa_handler.sign((json.dumps(data) + str(self.counter)).encode())

        message = {
            "type": "signed_data",
            "data": data,
            "counter": self.counter,
            "signature": base64.b64encode(signature).decode('utf-8')
        }

        return message

    def hello(self) -> json:
        public_key = self.rsa_handler.export_public_key()

        data = {
            "type": "hello",
            "public_key": public_key.decode('utf-8')
        }

        return self.client_message(data)
    
    # complete changing sender_fingerprint to encoded str
    # participant_fingerprints and recipient_rsa_pub_keys are lists of bytes
    
    def chat(self, sender_fingerprint: bytes, participant_fingerprints: list, message: str, destination_servers: list, recipient_rsa_pub_keys: list) -> json:
            fingerprints = [sender_fingerprint] + participant_fingerprints
            encoded_fingerprints = [base64.b64encode(fp).decode('utf-8') for fp in fingerprints]

            chat = {
                "participants": encoded_fingerprints,
                "message": message
            }

            # Encrypt the chat message with the AES symetric key and export the key
            iv, encrypted_chat = self.aes_handler.encrypt(json.dumps(chat).encode())
            key = self.aes_handler.export_key()

            # Encrypt the AES symetric key with each recipients RSA public key
            symm_keys = {}
            for pub_key in recipient_rsa_pub_keys:
                public_key = serialization.load_pem_public_key(pub_key)
                encrypted_key = self.rsa_handler.encrypt(key, public_key)
                # print(f"encrypted key:{encrypted_key}")
                encoded_key = base64.b64encode(encrypted_key).decode('utf-8')
                pub_key_str = base64.b64encode(pub_key).decode('utf-8')
                symm_keys[pub_key_str] = encoded_key
            
            # symm_keys: list of base64 encrypted strings

            data = {
                "type": "chat",
                "destination_servers": destination_servers,
                "iv": base64.b64encode(iv).decode('utf-8'),
                "symm_keys": symm_keys,
                "chat": base64.b64encode(encrypted_chat).decode('utf-8')
            }

            return self.client_message(data)
        

    def public_chat(self, sender_fingerprint: str, message: str) -> json:
        # sender_fingerprint is passed in as base64 encoded string
        data = {
            "type": "public_chat",
            "sender": sender_fingerprint,
            "message": message
        }

        return self.client_message(data)
    

            
    