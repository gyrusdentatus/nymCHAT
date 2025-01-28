from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
import os

class CryptoUtils:
    def __init__(self, storage_dir="storage"):
        """Initialize the CryptoUtils with a base storage directory."""
        self.storage_dir = storage_dir
        if not os.path.exists(storage_dir):
            os.makedirs(storage_dir)

    def generate_key_pair(self, username):
        """
        Generate a private/public key pair.
        :param username: The username for which to generate keys.
        :return: A tuple containing the private key object and the public key in PEM format (string).
        """
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        # Convert the public key to PEM format
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return private_key, public_key_pem

    def save_keys(self, username, private_key, public_key_pem):
        """
        Save the private and public keys to files.
        :param username: The username associated with the keys.
        :param private_key: The private key object.
        :param public_key_pem: The public key in PEM format as a string.
        """
        user_dir = os.path.join(self.storage_dir, username)
        if not os.path.exists(user_dir):
            os.makedirs(user_dir)

        # Save private key
        private_key_path = os.path.join(user_dir, f"{username}_private_key.pem")
        with open(private_key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Save public key
        public_key_path = os.path.join(user_dir, f"{username}_public_key.pem")
        with open(public_key_path, "wb") as f:
            f.write(public_key_pem.encode())

    def load_private_key(self, username):
        """
        Load the private key from the user's folder.
        :param username: The username associated with the key.
        :return: The private key object.
        """
        private_key_path = os.path.join(self.storage_dir, username, f"{username}_private_key.pem")
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
        return private_key

    def load_public_key(self, username):
        """
        Load the public key from the user's folder.
        :param username: The username associated with the key.
        :return: The public key object.
        """
        public_key_path = os.path.join(self.storage_dir, username, f"{username}_public_key.pem")
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return public_key

    def sign_message(self, private_key, message):
        """
        Sign a message using a provided private key.
        :param private_key: The private key object.
        :param message: The message to sign.
        :return: The signature in hexadecimal format.
        """
        signature = private_key.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return signature.hex()

    def verify_signature(self, public_key, message, signature):
        """
        Verify a message signature using the provided public key.
        :param public_key: The public key object.
        :param message: The original message that was signed.
        :param signature: The signature to verify (in hexadecimal format).
        :return: True if the signature is valid, False otherwise.
        """
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
