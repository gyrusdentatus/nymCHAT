import json
import asyncio
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from nicegui import ui
from mixnetMessages import MixnetMessage
from cryptographyUtils import CryptoUtils
from connectionUtils import WebSocketClient
from dbUtils import SQLiteManager

class MessageHandler:
    def __init__(self, crypto_utils: CryptoUtils, websocket_client: WebSocketClient):
        self.crypto_utils = crypto_utils
        self.websocket_client = websocket_client
        self.current_user = {"username": None}
        self.temporary_keys = {"private_key": None, "public_key": None}
        self.registration_complete = asyncio.Event()  # Event to track registration status
        self.login_complete = asyncio.Event()  # Event to track login status

    async def register_user(self, username, first_name="", last_name=""):
        """Register a new user with the handshake protocol."""
        try:
            self.current_user["username"] = username
            self.registration_complete.clear()  # Reset the event

            private_key, public_key = self.crypto_utils.generate_key_pair(username)
            self.temporary_keys["private_key"] = private_key
            self.temporary_keys["public_key"] = public_key
            print(f"[INFO] Keypair generated for user: {username}")

            register_message = MixnetMessage.register(usernym=username, publicKey=public_key)
            await self.websocket_client.send_message(register_message)
            print(f"[INFO] Registration message sent for username: {username}")
            print("[INFO] Waiting for server challenge...")

            await self.registration_complete.wait()  # Wait for completion before returning

        except Exception as e:
            print(f"[ERROR] An error occurred during registration: {e}")

    async def login_user(self, username):
        """Login an existing user with the handshake protocol."""
        try:
            self.current_user["username"] = username
            self.login_complete.clear()  # Reset login event

            private_key = self.crypto_utils.load_private_key(username)
            if not private_key:
                print(f"[ERROR] Could not find private key for username: {username}")
                return

            self.temporary_keys["private_key"] = private_key
            print(f"[INFO] Private key loaded for user: {username}")

            login_message = MixnetMessage.login(username)
            await self.websocket_client.send_message(login_message)
            print(f"[INFO] Login message sent for username: {username}")
            print("[INFO] Waiting for server challenge...")

            await self.login_complete.wait()  # Wait for completion before returning

        except Exception as e:
            print(f"[ERROR] An error occurred during login: {e}")

    async def handle_registration_challenge(self, content):
        """Handle the registration challenge."""
        nonce = content.get("nonce")
        if not nonce:
            print("[ERROR] Received registration challenge without a nonce.")
            return

        print(f"[INFO] Received registration challenge with nonce: {nonce}")

        private_key = self.temporary_keys.get("private_key")
        if private_key is None:
            print("[ERROR] Private key not found in memory during registration.")
            return

        try:
            signature = self.crypto_utils.sign_message_with_key(private_key, nonce)
            print(f"[INFO] Successfully signed the nonce.")
        except Exception as e:
            print(f"[ERROR] Failed to sign the nonce: {e}")
            return

        try:
            response = MixnetMessage.registrationResponse(self.current_user["username"], signature)
            await self.websocket_client.send_message(response)
            print("[INFO] Challenge response sent to the server.")
        except Exception as e:
            print(f"[ERROR] Failed to send the challenge response: {e}")

    async def handle_login_challenge(self, content):
        """Handle the login challenge."""
        nonce = content.get("nonce")
        if not nonce:
            print("[ERROR] Received login challenge without a nonce.")
            return

        print(f"[INFO] Received login challenge with nonce: {nonce}")

        private_key = self.temporary_keys.get("private_key")
        if private_key is None:
            print("[ERROR] Private key not found in memory during login.")
            return

        try:
            signature = self.crypto_utils.sign_message_with_key(private_key, nonce)
            print(f"[INFO] Successfully signed the nonce.")
        except Exception as e:
            print(f"[ERROR] Failed to sign the nonce: {e}")
            return

        try:
            response = MixnetMessage.loginResponse(self.current_user["username"], signature)
            await self.websocket_client.send_message(response)
            print("[INFO] Login response sent to the server.")
        except Exception as e:
            print(f"[ERROR] Failed to send the login response: {e}")

    async def handle_registration_response(self, content):
        """Handle the server's registration response."""
        if content == "success":
            print("[INFO] Registration successful!")
            username = self.current_user["username"]
            private_key = self.temporary_keys["private_key"]
            public_key_pem = self.temporary_keys["public_key"]

            try:
                self.crypto_utils.save_keys(username, private_key, public_key_pem)
                print(f"[INFO] Keys saved for user: {username}")
            except Exception as e:
                print(f"[ERROR] Failed to save keys: {e}")
                return

            try:
                SQLiteManager(username)
                print(f"[INFO] Database initialized for user: {username}")
            except Exception as e:
                print(f"[ERROR] Failed to initialize database: {e}")
                return

            self.registration_complete.set()  # Signal that registration is complete
        else:
            print(f"[ERROR] Registration failed: {content}")

    async def handle_login_response(self, content):
        """Handle the server's login response."""
        if content == "success":
            print("[INFO] Login successful!")
            self.login_complete.set()  # Signal that login is complete
        else:
            print(f"[ERROR] Login failed: {content}")

    async def handle_incoming_message(self, data):
        """
        Generalized message handler to process different types of incoming messages.
        """
        message_type = data.get("type")
        sender_tag = data.get("senderTag")
        encapsulated_message = data.get("message")  # Extract the encapsulated message

        if message_type == "received":
            try:
                encapsulated_data = json.loads(encapsulated_message)
                action = encapsulated_data.get("action")
                context = encapsulated_data.get("context")  # Extract the context
                content = encapsulated_data.get("content")

                if isinstance(content, str):
                    try:
                        content = json.loads(content)
                    except json.JSONDecodeError:
                        pass

                if action == "challenge":
                    if context == "registration":
                        await self.handle_registration_challenge(content)
                    elif context == "login":
                        await self.handle_login_challenge(content)
                    else:
                        print(f"[WARNING] Unhandled context in challenge: {context}")
                elif action == "challengeResponse":
                    if context == "registration":
                        await self.handle_registration_response(content)
                    elif context == "login":
                        await self.handle_login_response(content)
                    else:
                        print(f"[WARNING] Unhandled context in challengeResponse: {context}")
                else:
                    print(f"[WARNING] Unknown action in received message: {action}")
            except json.JSONDecodeError:
                print(f"[ERROR] Failed to decode encapsulated message: {encapsulated_message}")
        else:
            print(f"[WARNING] Unknown message type: {message_type}")
