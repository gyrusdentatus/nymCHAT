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
        self.db_manager = None  # Will hold the SQLiteManager instance after registration/login

        # Events for registration/login completion
        self.registration_complete = asyncio.Event()
        self.login_complete = asyncio.Event()

        # For user query results
        self.query_result_event = asyncio.Event()
        self.query_result = None  # Will hold the latest query result from the server

    # --------------------------------------------------------------------------
    # Registration & Login
    # --------------------------------------------------------------------------
    async def register_user(self, username, first_name="", last_name=""):
        """Register a new user with the handshake protocol."""
        try:
            self.current_user["username"] = username
            self.registration_complete.clear()  # Reset the event

            private_key, public_key = self.crypto_utils.generate_key_pair(username)
            self.temporary_keys["private_key"] = private_key
            self.temporary_keys["public_key"] = public_key
            print(f"[INFO] Keypair generated for user: {username}")

            # Send a 'register' message to the server
            register_message = MixnetMessage.register(usernym=username, publicKey=public_key)
            await self.websocket_client.send_message(register_message)
            print(f"[INFO] Registration message sent for username: {username}")
            print("[INFO] Waiting for server challenge...")

            # Wait for the server's final registration response
            await self.registration_complete.wait()

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

            # Send a 'login' message to the server
            login_message = MixnetMessage.login(username)
            await self.websocket_client.send_message(login_message)
            print(f"[INFO] Login message sent for username: {username}")
            print("[INFO] Waiting for server challenge...")

            # Wait for the server's final login response
            await self.login_complete.wait()

        except Exception as e:
            print(f"[ERROR] An error occurred during login: {e}")

    # --------------------------------------------------------------------------
    # Registration / Login Challenge Handlers
    # --------------------------------------------------------------------------
    async def handle_registration_challenge(self, content):
        """Handle the server's registration challenge by signing the provided nonce."""
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
        """Handle the server's login challenge by signing the provided nonce."""
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

    # --------------------------------------------------------------------------
    # Registration / Login Response Handlers
    # --------------------------------------------------------------------------
    async def handle_registration_response(self, content):
        """Handle the final server response for registration."""
        if content == "success":
            print("[INFO] Registration successful!")
            username = self.current_user["username"]
            private_key = self.temporary_keys["private_key"]
            public_key_pem = self.temporary_keys["public_key"]

            # Save the keys locally
            try:
                self.crypto_utils.save_keys(username, private_key, public_key_pem)
                print(f"[INFO] Keys saved for user: {username}")
            except Exception as e:
                print(f"[ERROR] Failed to save keys: {e}")
                return

            # Initialize the user database
            try:
                self.db_manager = SQLiteManager(username)
                print(f"[INFO] Database initialized for user: {username}")
            except Exception as e:
                print(f"[ERROR] Failed to initialize database: {e}")
                return

            # Signal that registration is complete
            self.registration_complete.set()
        else:
            print(f"[ERROR] Registration failed: {content}")

    async def handle_login_response(self, content):
        """Handle the final server response for login."""
        if content == "success":
            print("[INFO] Login successful!")
            username = self.current_user["username"]

            # Initialize the user database
            try:
                self.db_manager = SQLiteManager(username)
                print(f"[INFO] Database initialized for user: {username}")
                self.db_manager.create_user_tables(username)

            except Exception as e:
                print(f"[ERROR] Failed to initialize database: {e}")

            # Signal that login is complete
            self.login_complete.set()
        else:
            print(f"[ERROR] Login failed: {content}")

    # --------------------------------------------------------------------------
    # Sending Direct Messages
    # --------------------------------------------------------------------------
    async def send_direct_message(self, recipient_username: str, message_content: str):
        """
        Encapsulate and send a direct message to 'recipient_username',
        then store the outgoing message in the DB.
        """
        if not recipient_username or not message_content.strip():
            return

        payload = {
            "sender": self.current_user["username"],
            "recipient": recipient_username,
            "body": message_content
        }
        payload_str = json.dumps(payload)

        private_key = self.temporary_keys.get("private_key")
        if not private_key:
            print("[ERROR] No private key in memory. Cannot send message.")
            return

        # Sign the message payload
        signature = self.crypto_utils.sign_message_with_key(private_key, payload_str)

        # Construct the final mixnet message
        mixnet_msg = MixnetMessage.send(
            usernym=recipient_username,
            content=payload_str,
            signature=signature
        )
        # Send through the WebSocket
        await self.websocket_client.send_message(mixnet_msg)
        print(f"[INFO] Sent direct message to {recipient_username} via mixnet.")

        # Store outgoing message in the DB
        if self.db_manager:
            self.db_manager.save_message(
                self.current_user["username"],
                contact_username=recipient_username,
                msg_type='to',
                message=message_content
            )
        else:
            print("[WARNING] DB manager not initialized; outgoing message not saved.")

    # --------------------------------------------------------------------------
    # Query (User Search) Methods
    # --------------------------------------------------------------------------
    async def query_user(self, target_username: str):
        """
        Send a query to the server to see if 'target_username' exists.
        Wait for the server's 'queryResponse' to populate self.query_result.
        Returns either a dict with user data or "No user found" or None (on error).
        """
        try:
            self.query_result_event.clear()
            self.query_result = None

            query_msg = MixnetMessage.query(usernym=target_username)
            await self.websocket_client.send_message(query_msg)
            print(f"[INFO] Sent query for username: {target_username}")

            # Wait until the server response arrives
            await self.query_result_event.wait()
            return self.query_result
        except Exception as e:
            print(f"[ERROR] query_user exception: {e}")
            return None

    async def handle_query_response(self, content):
        """
        Handle the server's query response. 'content' might be a user info dict
        or a string like 'No user found'.
        """
        self.query_result = content
        self.query_result_event.set()
        print(f"[INFO] Received queryResponse: {content}")

    # --------------------------------------------------------------------------
    # Handling Incoming Messages
    # --------------------------------------------------------------------------
    async def handle_incoming_message(self, data):
        """
        Main entry point for all inbound messages from the WebSocket.
        """
        message_type = data.get("type")
        encapsulated_message = data.get("message")

        if message_type == "received":
            try:
                encapsulated_data = json.loads(encapsulated_message)
                action = encapsulated_data.get("action")
                context = encapsulated_data.get("context")
                content = encapsulated_data.get("content")

                # Attempt to parse 'content' if it's a JSON string
                if isinstance(content, str):
                    try:
                        content = json.loads(content)
                    except json.JSONDecodeError:
                        pass

                # --------------------- Challenge flow ----------------------
                if action == "challenge":
                    if context == "registration":
                        await self.handle_registration_challenge(content)
                    elif context == "login":
                        await self.handle_login_challenge(content)
                    else:
                        print(f"[WARNING] Unhandled challenge context: {context}")

                # --------------------- Challenge Response -------------------
                elif action == "challengeResponse":
                    if context == "registration":
                        await self.handle_registration_response(content)
                    elif context == "login":
                        await self.handle_login_response(content)
                    else:
                        print(f"[WARNING] Unhandled challengeResponse context: {context}")

                # --------------------- Direct Message -----------------------
                elif action == "send":
                    # Incoming direct chat message
                    if isinstance(content, dict):
                        from_user = content.get("sender")
                        msg_body = content.get("body")
                        if from_user and msg_body and self.db_manager:
                            self.db_manager.save_message(
                                self.current_user["username"],
                                contact_username=from_user,
                                msg_type='from',
                                message=msg_body
                            )
                            print(f"[INFO] Stored incoming message from {from_user} in DB.")
                        else:
                            print("[WARNING] Missing fields or DB manager not initialized for 'send' action.")
                    else:
                        print("[WARNING] 'content' is not a dict in 'send' action.")

                # --------------------- Query Response -----------------------
                elif action == "queryResponse" and context == "query":
                    await self.handle_query_response(content)

                # --------------------- Unknown -----------------------------
                else:
                    print(f"[WARNING] Unknown or unhandled action '{action}', context='{context}'")

            except json.JSONDecodeError:
                print(f"[ERROR] Failed to decode encapsulated message: {encapsulated_message}")

        else:
            print(f"[WARNING] Unknown message type: {message_type}")
