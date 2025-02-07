import json
import asyncio
from nicegui import ui
from datetime import datetime
from cryptography.hazmat.primitives import serialization
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
        self.db_manager = None  # Will be set after login/registration

        # Wait-for-completion events
        self.registration_complete = asyncio.Event()
        self.login_complete = asyncio.Event()
        
        # Registration / login status (success or failure)
        self.registration_successful = None
        self.login_successful = None

        # Query flow
        self.query_result_event = asyncio.Event()
        self.query_result = None

        # [OPTIONAL] references to UI or chat state
        self.chat_messages = None
        self.chat_list = None
        self.active_chat = None
        self.render_chat_fn = None
        self.chat_list_sidebar_fn = None  # For refreshing the chat list sidebar
        self.chat_container = None
        self.new_message_callback = None  # To notify UI of new messages



    def set_ui_state(self, messages, chat_list, get_active_chat, render_chat, chat_container, chat_list_sidebar_fn=None):
        """
        Optionally call this from runClient.py if you want to update UI state
        directly from handle_incoming_message.
        'get_active_chat' can be a function or a reference to the global variable.
        """
        self.chat_messages = messages
        self.chat_list = chat_list
        self._get_active_chat = get_active_chat
        self.render_chat_fn = render_chat
        self.chat_container = chat_container
        self.chat_list_sidebar_fn = chat_list_sidebar_fn  # Store reference for sidebar refresh

    # --------------------------------------------------------------------------
    # Registration & Login
    # --------------------------------------------------------------------------

    async def register_user(self, username, first_name="", last_name=""):
        try:
            self.current_user["username"] = username
            self.registration_complete.clear()

            private_key, public_key = self.crypto_utils.generate_key_pair(username)
            self.temporary_keys["private_key"] = private_key
            self.temporary_keys["public_key"] = public_key
            print(f"[INFO] Keypair generated for user: {username}")

            # Send a 'register' message (only username and public key are used)
            register_msg = MixnetMessage.register(usernym=username, publicKey=public_key)
            await self.websocket_client.send_message(register_msg)
            print("[INFO] Registration message sent; waiting for challenge...")

            await self.registration_complete.wait()

        except Exception as e:
            print(f"[ERROR] Registration error: {e}")

    async def login_user(self, username):
        try:
            self.current_user["username"] = username
            self.login_complete.clear()

            private_key = self.crypto_utils.load_private_key(username)
            if not private_key:
                print(f"[ERROR] No private key for {username}")
                return

            self.temporary_keys["private_key"] = private_key
            print(f"[INFO] Loaded private key for {username}")

            msg = MixnetMessage.login(username)
            await self.websocket_client.send_message(msg)
            print("[INFO] Login message sent; waiting for challenge...")

            await self.login_complete.wait()

        except Exception as e:
            print(f"[ERROR] Login error: {e}")

    async def handle_registration_challenge(self, content):
        nonce = content.get("nonce")
        if not nonce:
            print("[ERROR] No nonce in registration challenge.")
            return
        private_key = self.temporary_keys.get("private_key")
        if not private_key:
            print("[ERROR] No private key for registration.")
            return

        try:
            signature = self.crypto_utils.sign_message_with_key(private_key, nonce)
            resp = MixnetMessage.registrationResponse(self.current_user["username"], signature)
            await self.websocket_client.send_message(resp)
            print("[INFO] Registration challenge response sent.")
        except Exception as e:
            print(f"[ERROR] Signing registration nonce: {e}")

    async def handle_login_challenge(self, content):
        nonce = content.get("nonce")
        if not nonce:
            print("[ERROR] No nonce in login challenge.")
            return
        private_key = self.temporary_keys.get("private_key")
        if not private_key:
            print("[ERROR] No private key for login.")
            return

        try:
            signature = self.crypto_utils.sign_message_with_key(private_key, nonce)
            resp = MixnetMessage.loginResponse(self.current_user["username"], signature)
            await self.websocket_client.send_message(resp)
            print("[INFO] Login challenge response sent.")
        except Exception as e:
            print(f"[ERROR] Signing login nonce: {e}")

    async def handle_registration_response(self, content):
        """
        Handles the response after the registration challenge has been completed.
        """
        if content == "success":
            print("[INFO] Registration successful!")
            username = self.current_user["username"]
            priv_k = self.temporary_keys["private_key"]
            pub_k = self.temporary_keys["public_key"]

            try:
                self.crypto_utils.save_keys(username, priv_k, pub_k)
                print("[INFO] Keys saved.")
            except Exception as e:
                print(f"[ERROR] Saving keys: {e}")
                self.registration_successful = False
                self.registration_complete.set()  # Ensure the event is set
                return

            try:
                self.db_manager = SQLiteManager(username)
                print("[INFO] DB initialized for user:", username)
            except Exception as e:
                print(f"[ERROR] DB init: {e}")
                self.registration_successful = False
                self.registration_complete.set()  # Ensure the event is set
                return

            self.registration_successful = True  # Registration is successful
            self.registration_complete.set()  # Signal that registration is complete

        else:
            # Handle registration failure (e.g., username already in use)
            print(f"[ERROR] Registration failed: {content}")
            self.registration_successful = False
            self.registration_complete.set()  # Ensure the event is set

    async def handle_login_response(self, content):
        """
        Handles the response after the login challenge has been completed.
        """
        if content == "success":
            print("[INFO] Login successful!")
            username = self.current_user["username"]
            try:
                self.db_manager = SQLiteManager(username)
                print("[INFO] DB manager created.")
                self.db_manager.create_user_tables(username)
            except Exception as e:
                print(f"[ERROR] DB init: {e}")
                self.login_successful = False
                self.login_complete.set()  # Ensure the event is set
                return

            self.login_successful = True  # Login is successful
            self.login_complete.set()  # Signal that login is complete

        else:
            print(f"[ERROR] Login failed: {content}")
            self.login_successful = False
            self.login_complete.set()  # Signal that login is complete even if it failed

    # --------------------------------------------------------------------------
    # Sending Direct Messages (All messages encrypted)
    # --------------------------------------------------------------------------

    async def send_direct_message(self, recipient_username, message_content):
        if not recipient_username or not message_content.strip():
            return

        sender_private_key = self.crypto_utils.load_private_key(self.current_user["username"])
        if not sender_private_key:
            print("[ERROR] No private key to send message.")
            return

        if not self.db_manager:
            print("[ERROR] DB manager not initialized.")
            return

        # Retrieve recipient's details from the DB; they must exist.
        contact = self.db_manager.get_contact(self.current_user["username"], recipient_username)
        if not contact:
            print(f"[ERROR] No contact record found for {recipient_username}. Cannot send message.")
            return

        # Determine if there is any prior message history.
        existing_msgs = self.db_manager.get_messages_by_contact(self.current_user["username"], recipient_username)
        initial_message = not existing_msgs

        # Always encrypt the message using the recipient's public key.
        recipient_public_key_pem = contact[1]
        recipient_public_key = serialization.load_pem_public_key(recipient_public_key_pem.encode())
        enc_result = self.crypto_utils.encrypt_message(message_content, sender_private_key, recipient_public_key)

        # Build payload.
        payload = {
            "sender": self.current_user["username"],
            "recipient": recipient_username,
            "body": enc_result,  # A dict with iv, ciphertext, and tag.
            "encrypted": True
        }
        # Only attach our public key on the initial message.
        if initial_message:
            sender_public_key_obj = self.crypto_utils.load_public_key(self.current_user["username"])
            sender_public_key_pem = sender_public_key_obj.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            payload["senderPublicKey"] = sender_public_key_pem

        payload_str = json.dumps(payload)
        signature = self.crypto_utils.sign_message_with_key(sender_private_key, payload_str)
        msg = MixnetMessage.send(content=payload_str, signature=signature)
        await self.websocket_client.send_message(msg)
        print(f"[INFO] Sent direct message to {recipient_username}")

        self.db_manager.save_message(
            self.current_user["username"],
            contact_username=recipient_username,
            msg_type='to',
            message=message_content
        )

    async def handle_send_response(self, content):
        # Optional: display a UI notification if desired.
        pass

    # --------------------------------------------------------------------------
    # Query
    # --------------------------------------------------------------------------

    async def query_user(self, target_username):
        try:
            self.query_result_event.clear()
            self.query_result = None

            msg = MixnetMessage.query(target_username)
            await self.websocket_client.send_message(msg)
            print(f"[INFO] Sent query for user: {target_username}")

            await self.query_result_event.wait()
            return self.query_result
        except Exception as e:
            print(f"[ERROR] query_user: {e}")
            return None

    async def handle_query_response(self, content):
        self.query_result = content
        self.query_result_event.set()
        print(f"[INFO] queryResponse: {content}")
        # Store the public key along with the username if provided.
        if self.db_manager and isinstance(content, dict):
            username = content.get("username")
            public_key = content.get("publicKey")
            if username and public_key:
                self.db_manager.add_contact(self.current_user["username"], username, public_key)

    # --------------------------------------------------------------------------
    # Handling Incoming Messages (SINGLE CALLBACK)
    # --------------------------------------------------------------------------

    async def handle_incoming_message(self, data):
        """
        Handles incoming messages, updating the UI and local database.
        """
        message_type = data.get("type")
        if message_type != "received":
            print(f"[WARNING] Unknown message type: {message_type}")
            return

        try:
            encapsulated_data = json.loads(data.get("message", "{}"))
            action = encapsulated_data.get("action")
            context = encapsulated_data.get("context")
            content = encapsulated_data.get("content")

            # If 'content' is a JSON string, try decoding it.
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
                    print(f"[WARNING] Unhandled challenge context: {context}")

            elif action == "challengeResponse":
                if context == "registration":
                    await self.handle_registration_response(content)
                elif context == "login":
                    await self.handle_login_response(content)
                else:
                    print(f"[WARNING] Unhandled challengeResponse context: {context}")

            elif action == "incomingMessage":
                if isinstance(content, dict):
                    from_user = content.get("sender")
                    # Determine if the message is encrypted.
                    # Here we assume that if "body" is a dict, it's encrypted.
                    if isinstance(content.get("body"), dict):
                        is_encrypted = True
                    else:
                        is_encrypted = content.get("encrypted", False)

                    if is_encrypted:
                        # For encrypted messages, try to get the sender's public key.
                        sender_pub_from_msg = content.get("senderPublicKey")
                        if self.db_manager and not self.db_manager.get_contact(self.current_user["username"], from_user) and sender_pub_from_msg:
                            self.db_manager.add_contact(self.current_user["username"], from_user, sender_pub_from_msg)
                        # Retrieve sender's public key from DB if available; otherwise, use the one from the message.
                        contact = self.db_manager.get_contact(self.current_user["username"], from_user) if self.db_manager else None
                        if contact:
                            sender_public_key_pem = contact[1]
                        else:
                            sender_public_key_pem = sender_pub_from_msg
                        if not sender_public_key_pem:
                            print(f"[ERROR] No sender public key available for {from_user}.")
                            decrypted_msg = content.get("body")
                        else:
                            sender_public_key = serialization.load_pem_public_key(sender_public_key_pem.encode())
                            recipient_private_key = self.crypto_utils.load_private_key(self.current_user["username"])
                            try:
                                decrypted_msg = self.crypto_utils.decrypt_message(content.get("body"), recipient_private_key, sender_public_key)
                            except Exception as e:
                                print(f"[ERROR] Decryption failed: {e}")
                                decrypted_msg = content.get("body")
                    else:
                        decrypted_msg = content.get("body")
                        if self.db_manager and not self.db_manager.get_contact(self.current_user["username"], from_user):
                            sender_pub = content.get("senderPublicKey")
                            if sender_pub:
                                self.db_manager.add_contact(self.current_user["username"], from_user, sender_pub)

                    # Ensure decrypted_msg is a string.
                    if isinstance(decrypted_msg, dict):
                        decrypted_msg = json.dumps(decrypted_msg)

                    if from_user and decrypted_msg and self.db_manager:
                        self.db_manager.save_message(
                            self.current_user["username"],
                            from_user,
                            'from',
                            decrypted_msg
                        )
                        print(f"[INFO] Stored incoming message from {from_user} in DB.")

                        if self.chat_messages is not None:
                            if from_user not in self.chat_messages:
                                self.chat_messages[from_user] = []
                            stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            self.chat_messages[from_user].append((from_user, decrypted_msg, stamp))

                            if not any(chat["id"] == from_user for chat in self.chat_list):
                                self.chat_list.append({"id": from_user, "name": from_user})
                                if self.chat_list_sidebar_fn:
                                    self.chat_list_sidebar_fn.refresh()
                                print(f"[INFO] Added {from_user} to chat list.")

                            currently_active_chat = self._get_active_chat()
                            if from_user == currently_active_chat:
                                if self.render_chat_fn:
                                    try:
                                        self.render_chat_fn.refresh(
                                            self.current_user["username"],
                                            currently_active_chat,
                                            self.chat_messages
                                        )
                                        print("[INFO] Chat UI refreshed successfully.")
                                    except Exception as e:
                                        print(f"[ERROR] Failed to refresh chat UI: {e}")
                            else:
                                if self.new_message_callback:
                                    self.new_message_callback(from_user, decrypted_msg)
                        else:
                            print("[WARNING] chat_messages is None; UI might not be initialized.")
                    else:
                        print("[WARNING] Missing fields or DB manager not ready.")
                else:
                    print("[WARNING] 'content' not a dict in 'incomingMessage' action.")

            elif action == "queryResponse" and context == "query":
                await self.handle_query_response(content)

            elif action == "sendResponse" and context == "chat":
                await self.handle_send_response(content)

            else:
                print(f"[WARNING] Unknown or unhandled action '{action}', context='{context}'")

        except json.JSONDecodeError:
            print("[ERROR] Could not decode the message content.")
