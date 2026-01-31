from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

class KeyManager:
    def __init__(self, base_dir):
        self.keys_dir = os.path.join(base_dir, "keys")
        self.private_path = os.path.join(self.keys_dir, "private.pem")
        self.public_path = os.path.join(self.keys_dir, "public.pem")

        self.private_key = None
        self.public_key = None

        self._init_keys()

    def _init_keys(self):
        os.makedirs(self.keys_dir, exist_ok=True)

        if os.path.exists(self.private_path) and os.path.exists(self.public_path):
            self._load_keys()
        else:
            self._generate_keys()

    def _generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

        with open(self.private_path, "wb") as f:
            f.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        with open(self.public_path, "wb") as f:
            f.write(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        print(f"[KEYS] Chaves RSA geradas em {self.keys_dir}")

    def _load_keys(self):
        with open(self.private_path, "rb") as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )

        with open(self.public_path, "rb") as f:
            self.public_key = serialization.load_pem_public_key(f.read())

        print(f"[KEYS] Chaves RSA carregadas de {self.keys_dir}")
