from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
import os

class CryptoUtils:
    def __init__(self, key_dir="keys"):
        """Initialize the CryptoUtils with a directory for storing keys."""
        self.key_dir = key_dir
        if not os.path.exists(key_dir):
            os.makedirs(key_dir)

    def generate_key_pair(self, username=None):
        """
        Generate a private/public key pair.
        :param username: Optional username for logging purposes.
        :return: A tuple containing the private key object and the public key in PEM format (string).
        """
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        if username:
            print(f"[INFO] Key pair generated for user: {username}")

        # Convert the public key to PEM format
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')

        return private_key, public_key_pem

    def save_keys(self, username, private_key, public_key):
        """Save the private and public keys to files."""
        # Save private key
        private_key_path = os.path.join(self.key_dir, f"{username}_private_key.pem")
        with open(private_key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Save public key
        public_key_path = os.path.join(self.key_dir, f"{username}_public_key.pem")
        with open(public_key_path, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

    def load_private_key(self, username):
        """Load the private key from file."""
        private_key_path = os.path.join(self.key_dir, f"{username}_private_key.pem")
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
        return private_key

    def load_public_key(self, username):
        """Load the public key from file."""
        public_key_path = os.path.join(self.key_dir, f"{username}_public_key.pem")
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return public_key

    def sign_message(self, private_key, message):
        """Sign a message using a provided private key."""
        signature = private_key.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return signature.hex()

    def verify_signature(self, public_key, message, signature):
        """Verify a message signature using the provided public key."""
        try:
            r, s = decode_dss_signature(bytes.fromhex(signature))
            public_key.verify(
                encode_dss_signature(r, s),
                message.encode(),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception as e:
            print(f"Error verifying signature: {e}")
            return False

    def sign_message_with_key(self, private_key, message):
        """
        Sign a message using an in-memory private key.
        :param private_key: The private key object.
        :param message: The message to sign.
        :return: The signature in hexadecimal format.
        """
        signature = private_key.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return signature.hex()

