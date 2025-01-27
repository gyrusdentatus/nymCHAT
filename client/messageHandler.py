import json
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from nicegui import ui
from mixnetMessages import MixnetMessage
from cryptographyUtils import CryptoUtils
from connectionUtils import WebSocketClient

class MessageHandler:
    def __init__(self, crypto_utils: CryptoUtils, websocket_client: WebSocketClient):
        self.crypto_utils = crypto_utils
        self.websocket_client = websocket_client
        self.current_user = {"username": None}
        self.temporary_keys = {"private_key": None, "public_key": None}

    async def register_user(self, username, first_name="", last_name=""):
        """Register a new user with the handshake protocol."""
        try:
            # Set the current user immediately
            self.current_user["username"] = username

            # Step 1: Generate key pair and temporarily store it
            private_key, public_key = self.crypto_utils.generate_key_pair(username)
            self.temporary_keys["private_key"] = private_key
            self.temporary_keys["public_key"] = public_key
            print(f"[INFO] Keypair generated for user: {username}")

            # Step 2: Create and send the register message
            register_message = MixnetMessage.register(usernym=username, publicKey=public_key)
            await self.websocket_client.send_message(register_message)
            print(f"[INFO] Registration message sent for username: {username}")
            print("[INFO] Waiting for server challenge...")

        except Exception as e:
            print(f"[ERROR] An error occurred during registration: {e}")
            ui.notify(f"An error occurred: {e}")

    async def login_user(self, username):
        """Login an existing user with the handshake protocol."""
        try:
            # Load the private key for the username
            private_key = self.crypto_utils.load_private_key(username)
            if not private_key:
                print(f"[ERROR] Could not find private key for username: {username}")
                return

            # Set the current user and private key
            self.current_user["username"] = username
            self.temporary_keys["private_key"] = private_key
            print(f"[INFO] Private key loaded for user: {username}")

            # Send a login request to the server
            login_message = MixnetMessage.login(username)
            await self.websocket_client.send_message(login_message)
            print(f"[INFO] Login message sent for username: {username}")
            print("[INFO] Waiting for server challenge...")

        except Exception as e:
            print(f"[ERROR] An error occurred during login: {e}")
            ui.notify(f"An error occurred: {e}")

    async def handle_registration_challenge(self, content):
        """Handle the registration challenge."""
        nonce = content.get("nonce")
        print(f"[INFO] Received registration challenge with nonce: {nonce}")

        # Use the private key to sign the nonce
        private_key = self.temporary_keys.get("private_key")
        if private_key is None:
            print("[ERROR] Private key not found in memory during registration.")
            return

        signature = self.crypto_utils.sign_message_with_key(private_key, nonce)
        response = MixnetMessage.registrationResponse(self.current_user["username"], signature)
        await self.websocket_client.send_message(response)
        print("[INFO] Challenge response sent.")

    async def handle_login_challenge(self, content):
        """Handle the login challenge."""
        nonce = content.get("nonce")
        print(f"[INFO] Received login challenge with nonce: {nonce}")

        # Use the private key to sign the nonce
        private_key = self.temporary_keys.get("private_key")
        if private_key is None:
            print("[ERROR] Private key not found in memory during login.")
            return

        signature = self.crypto_utils.sign_message_with_key(private_key, nonce)
        response = MixnetMessage.loginResponse(self.current_user["username"], signature)
        await self.websocket_client.send_message(response)
        print("[INFO] Login response sent.")

    async def handle_registration_response(self, content):
        """Handle the server's registration response."""
        if content == "success":
            print("[INFO] Registration successful!")
            # Convert the public key PEM string back to an object
            public_key_pem = self.temporary_keys["public_key"]
            public_key = load_pem_public_key(public_key_pem.encode())

            # Save the keys since registration succeeded
            username = self.current_user["username"]
            self.crypto_utils.save_keys(username, self.temporary_keys["private_key"], public_key)
        else:
            print(f"[ERROR] Registration failed: {content}")
            ui.notify(f"Registration failed: {content}")

    async def handle_login_response(self, content):
        """Handle the server's login response."""
        if content == "success":
            print("[INFO] Login successful!")
            ui.notify(f"Welcome back, {self.current_user['username']}!")
            ui.navigate.to("/app")
        else:
            print(f"[ERROR] Login failed: {content}")
            ui.notify(f"Login failed: {content}")

    async def handle_incoming_message(self, data):
        """
        Generalized message handler to process different types of incoming messages.
        :param data: The incoming message data.
        """
        message_type = data.get("type")
        sender_tag = data.get("senderTag")
        encapsulated_message = data.get("message")  # Extract the encapsulated message

        if message_type == "received":
            try:
                # Parse the encapsulated message
                encapsulated_data = json.loads(encapsulated_message)
                action = encapsulated_data.get("action")
                context = encapsulated_data.get("context")  # Extract the context
                content = encapsulated_data.get("content")

                # Check if content is a JSON string or plain string
                if isinstance(content, str):
                    try:
                        # Try parsing content as JSON (if applicable)
                        content = json.loads(content)
                    except json.JSONDecodeError:
                        # Content is already a plain string (e.g., "success")
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
