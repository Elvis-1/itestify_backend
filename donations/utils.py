import base64
import secrets
import string
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AESEncryptor:
    def __init__(self, encryption_key: str):
        # self.aes_key = base64.b64encode(encryption_key.encode('utf-8')).decode('utf-8')
        self.aes_key = base64.b64decode(encryption_key)

    @staticmethod
    def generate_nonce(length: int = 12) -> str:
        characters = string.ascii_letters + string.digits
        return "".join(secrets.choice(characters) for _ in range(length))

    def encrypt(self, plain_text: str, nonce: str) -> str:
        if not plain_text or not nonce:
            raise ValueError("Both plain_text and nonce are required for encryption.")

        nonce_bytes = nonce.encode()
        aes_gcm = AESGCM(self.aes_key)
        cipher_text = aes_gcm.encrypt(nonce_bytes, plain_text.encode(), None)

        return base64.b64encode(cipher_text).decode()

    def encrypt_dict(self, data: dict) -> dict:
        if not isinstance(data, dict):
            raise ValueError("Data must be a dictionary.")

        nonce = self.generate_nonce()
        encrypted_data = {"nonce": nonce}

        for key, value in data.items():
            encrypted_data[key] = self.encrypt(str(value), nonce)

        return encrypted_data

