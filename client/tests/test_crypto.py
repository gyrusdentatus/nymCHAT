import unittest
import os
from cryptographyUtils import CryptoUtils

class TestCryptoUtils(unittest.TestCase):
    def setUp(self):
        self.crypto = CryptoUtils(storage_dir="test_storage")
        self.username = "test_user"
        self.recipient = "recipient"
        
        # Generate and save keys for both sender and recipient
        self.private_key, self.public_key_pem = self.crypto.generate_key_pair(self.username)
        self.recipient_private_key, self.recipient_public_key_pem = self.crypto.generate_key_pair(self.recipient)
        
        self.crypto.save_keys(self.username, self.private_key, self.public_key_pem)
        self.crypto.save_keys(self.recipient, self.recipient_private_key, self.recipient_public_key_pem)
    
    def tearDown(self):
        # Cleanup test storage directory
        if os.path.exists("test_storage"):
            for root, dirs, files in os.walk("test_storage", topdown=False):
                for file in files:
                    os.remove(os.path.join(root, file))
                for dir in dirs:
                    os.rmdir(os.path.join(root, dir))
            os.rmdir("test_storage")

    def test_generate_key_pair(self):
        private_key, public_key_pem = self.crypto.generate_key_pair("new_user")
        self.assertIsNotNone(private_key)
        self.assertTrue(public_key_pem.startswith("-----BEGIN PUBLIC KEY-----"))

    def test_save_key_pair(self):
        self.assertTrue(os.path.exists(f"test_storage/{self.username}/{self.username}_private_key.pem"))
        self.assertTrue(os.path.exists(f"test_storage/{self.username}/{self.username}_public_key.pem"))

    def test_load_public_key(self):
        loaded_public_key = self.crypto.load_public_key(self.username)
        self.assertIsNotNone(loaded_public_key)

    def test_load_private_key(self):
        loaded_private_key = self.crypto.load_private_key(self.username)
        self.assertIsNotNone(loaded_private_key)

    def test_sign_and_verify_message(self):
        message = "Hello, World!"
        signature = self.crypto.sign_message(self.private_key, message)
        public_key = self.crypto.load_public_key(self.username)
        self.assertTrue(self.crypto.verify_signature(public_key, message, signature))

    def test_invalid_signature(self):
        message = "Hello, World!"
        # Create a valid signature using the recipient's private key
        invalid_signature = self.crypto.sign_message(self.recipient_private_key, message)
        public_key = self.crypto.load_public_key(self.username)  # Load test_user's public key
        
        # Verify the signature with the wrong public key
        self.assertFalse(self.crypto.verify_signature(public_key, message, invalid_signature))

    def test_encrypt_and_decrypt_message(self):
        recipient_public_key = self.crypto.load_public_key(self.recipient)
        
        enc_dict = self.crypto.encrypt_message("Secret Message", self.private_key, recipient_public_key)
        decrypted_message = self.crypto.decrypt_message(enc_dict, self.recipient_private_key, self.crypto.load_public_key(self.username))
        self.assertEqual(decrypted_message, "Secret Message")

if __name__ == "__main__":
    unittest.main()
