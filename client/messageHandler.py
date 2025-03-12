import json
import asyncio
from nicegui import ui
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from mixnetMessages import MixnetMessage
from cryptographyUtils import CryptoUtils
from connectionUtils import MixnetConnectionClient
from dbUtils import SQLiteManager
from logUtils import logger

class MessageHandler:
    def __init__(self, crypto_utils: CryptoUtils, connection_client: MixnetConnectionClient):
        self.crypto_utils = crypto_utils
        self.connection_client = connection_client
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

        # Ephemeral mapping of usernames to nym addresses for p2p routing
        self.nym_addresses = {}  # {username: nym_address}

        # Store our own nym address (to be set externally after mixnet initialization)
        self.nym_address = None

    def update_nym_address(self, nym_address):
        """Update the client's own nym address in MessageHandler."""
        self.nym_address = nym_address
        logger.info(f"Updated own nym address in MessageHandler: {nym_address}")

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
            logger.info(f"Keypair generated for user: {username}")

            # Send a 'register' message (only username and public key are used)
            register_msg = MixnetMessage.register(usernym=username, publicKey=public_key)
            await self.connection_client.send_message(register_msg)
            logger.info("Registration message sent; waiting for challenge...")

            await self.registration_complete.wait()

        except Exception as e:
            logger.error(f"Registration error: {e}")

    async def login_user(self, username):
        try:
            self.current_user["username"] = username
            self.login_complete.clear()

            private_key = self.crypto_utils.load_private_key(username)
            if not private_key:
                logger.error(f"No private key for {username}")
                return

            self.temporary_keys["private_key"] = private_key
            logger.info(f"Loaded private key for {username}")

            msg = MixnetMessage.login(username)
            await self.connection_client.send_message(msg)
            logger.info("Login message sent; waiting for challenge...")

            await self.login_complete.wait()

        except Exception as e:
            logger.error(f"Login error: {e}")

    async def handle_registration_challenge(self, content):
        nonce = content.get("nonce")
        if not nonce:
            logger.error("No nonce in registration challenge.")
            return
        private_key = self.temporary_keys.get("private_key")
        if not private_key:
            logger.error("No private key for registration.")
            return

        try:
            signature = self.crypto_utils.sign_message(private_key, nonce)
            resp = MixnetMessage.registrationResponse(self.current_user["username"], signature)
            await self.connection_client.send_message(resp)
            logger.info("Registration challenge response sent.")
        except Exception as e:
            logger.error(f"Signing registration nonce: {e}")

    async def handle_login_challenge(self, content):
        nonce = content.get("nonce")
        if not nonce:
            logger.error("No nonce in login challenge.")
            return
        private_key = self.temporary_keys.get("private_key")
        if not private_key:
            logger.error("No private key for login.")
            return

        try:
            signature = self.crypto_utils.sign_message(private_key, nonce)
            resp = MixnetMessage.loginResponse(self.current_user["username"], signature)
            await self.connection_client.send_message(resp)
            logger.info("Login challenge response sent.")
        except Exception as e:
            logger.error(f"Signing login nonce: {e}")

    async def handle_registration_response(self, content):
        """
        Handles the response after the registration challenge has been completed.
        """
        if content == "success":
            logger.info("Registration successful!")
            username = self.current_user["username"]
            priv_k = self.temporary_keys["private_key"]
            pub_k = self.temporary_keys["public_key"]

            try:
                self.crypto_utils.save_keys(username, priv_k, pub_k)
                logger.info("Keys saved.")
            except Exception as e:
                logger.error(f"Saving keys: {e}")
                self.registration_successful = False
                self.registration_complete.set()  # Ensure the event is set
                return

            try:
                self.db_manager = SQLiteManager(username)
                logger.info("DB initialized for user:", username)
            except Exception as e:
                logger.error(f"DB init: {e}")
                self.registration_successful = False
                self.registration_complete.set()  # Ensure the event is set
                return

            self.registration_successful = True  # Registration is successful
            self.registration_complete.set()  # Signal that registration is complete

        else:
            logger.error(f"Registration failed: {content}")
            self.registration_successful = False
            self.registration_complete.set()

    async def handle_login_response(self, content):
        """
        Handles the response after the login challenge has been completed.
        """
        if content == "success":
            logger.info("Login successful!")
            username = self.current_user["username"]
            try:
                self.db_manager = SQLiteManager(username)
                logger.info("DB manager created.")
                self.db_manager.create_user_tables(username)
            except Exception as e:
                logger.error(f"DB init: {e}")
                self.login_successful = False
                self.login_complete.set()
                return

            self.login_successful = True
            self.login_complete.set()

        else:
            logger.error(f"Login failed: {content}")
            self.login_successful = False
            self.login_complete.set()

    # --------------------------------------------------------------------------
    # Sending Direct Messages (All messages encrypted)
    # --------------------------------------------------------------------------
    async def send_direct_message(self, recipient_username, message_content):
        if not recipient_username or not message_content.strip():
            return

        sender_private_key = self.crypto_utils.load_private_key(self.current_user["username"])
        if not sender_private_key:
            logger.error("No private key to send message.")
            return

        if not self.db_manager:
            logger.error("DB manager not initialized.")
            return

        contact = self.db_manager.get_contact(self.current_user["username"], recipient_username)
        if not contact:
            logger.error(f"No contact record found for {recipient_username}. Cannot send message.")
            return

        existing_msgs = self.db_manager.get_messages_by_contact(self.current_user["username"], recipient_username)
        initial_message = not existing_msgs

        recipient_public_key_pem = contact[1]
        recipient_public_key = serialization.load_pem_public_key(recipient_public_key_pem.encode())

        wrapped_message = json.dumps({"type": 0, "message": message_content})
        enc_result = self.crypto_utils.encrypt_message(wrapped_message, sender_private_key, recipient_public_key)

        payload = {
            "sender": self.current_user["username"],
            "recipient": recipient_username,
            "body": enc_result,
            "encrypted": True
        }
        if initial_message:
            sender_public_key_obj = self.crypto_utils.load_public_key(self.current_user["username"])
            sender_public_key_pem = sender_public_key_obj.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            payload["senderPublicKey"] = sender_public_key_pem

        payload_str = json.dumps(payload)
        signature = self.crypto_utils.sign_message(sender_private_key, payload_str)
        # If a p2p nym address exists for this recipient, encapsulate as a directMessage.
        if recipient_username in self.nym_addresses:
            msg = MixnetMessage.directMessage(content=payload_str, signature=signature)
            msg["recipient"] = self.nym_addresses[recipient_username]
        else:
            msg = MixnetMessage.send(content=payload_str, signature=signature)
        await self.connection_client.send_message(msg)
        logger.info(f"Sent direct message to {recipient_username}")

        self.db_manager.save_message(
            self.current_user["username"],
            contact_username=recipient_username,
            msg_type='to',
            message=message_content
        )

    async def send_handshake(self, recipient_username):
        """
        Sends a handshake (type 1 message) containing this client's nym address.
        """
        if self.nym_address is None:
            logger.error("Nym address not set in MessageHandler.")
            return

        sender_private_key = self.crypto_utils.load_private_key(self.current_user["username"])
        if not sender_private_key:
            logger.error("No private key available for handshake.")
            return

        if not self.db_manager:
            logger.error("DB manager not initialized.")
            return

        contact = self.db_manager.get_contact(self.current_user["username"], recipient_username)
        if not contact:
            logger.error(f"No contact record found for {recipient_username}. Cannot send handshake.")
            return

        recipient_public_key_pem = contact[1]
        recipient_public_key = serialization.load_pem_public_key(recipient_public_key_pem.encode())

        handshake_payload = json.dumps({"type": 1, "message": self.nym_address})
        enc_result = self.crypto_utils.encrypt_message(handshake_payload, sender_private_key, recipient_public_key)

        payload = {
            "sender": self.current_user["username"],
            "recipient": recipient_username,
            "body": enc_result,
            "encrypted": True
        }
        payload_str = json.dumps(payload)
        signature = self.crypto_utils.sign_message(sender_private_key, payload_str)

        if recipient_username in self.nym_addresses:
            msg = MixnetMessage.directMessage(content=payload_str, signature=signature)
            msg["recipient"] = self.nym_addresses[recipient_username]
        else:
            msg = MixnetMessage.send(content=payload_str, signature=signature)
        await self.connection_client.send_message(msg)

        logger.info(f"Sent handshake (nym address) to {recipient_username}")

    async def handle_send_response(self, content):
        pass

    # --------------------------------------------------------------------------
    # Query
    # --------------------------------------------------------------------------
    async def query_user(self, target_username):
        try:
            self.query_result_event.clear()
            self.query_result = None

            msg = MixnetMessage.query(target_username)
            await self.connection_client.send_message(msg)
            logger.info(f"Sent query for user: {target_username}")

            await self.query_result_event.wait()
            return self.query_result
        except Exception as e:
            logger.error(f"query_user: {e}")
            return None

    async def handle_query_response(self, content):
        self.query_result = content
        self.query_result_event.set()
        logger.info(f"queryResponse: {content}")
        if self.db_manager and isinstance(content, dict):
            username = content.get("username")
            public_key = content.get("publicKey")
            if username and public_key:
                self.db_manager.add_contact(self.current_user["username"], username, public_key)

    # --------------------------------------------------------------------------
    # Handling Incoming Messages (SINGLE CALLBACK)
    # --------------------------------------------------------------------------
    async def handle_incoming_message(self, message):
        """ Main dispatcher for handling messages """
        try:
            encapsulated_data = json.loads(message)
            action = encapsulated_data.get("action")
            context = encapsulated_data.get("context")
            content = self._parse_content(encapsulated_data.get("content"))

            handler = self.get_handler(action, context)
            if handler:
                await handler(content)
            else:
                logger.warning(f"Unknown or unhandled action '{action}', context='{context}'")
        except json.JSONDecodeError:
            logger.error("Could not decode the message content.")

    def _parse_content(self, content):
        """ Ensure content is a dictionary, converting if necessary """
        if isinstance(content, str):
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                pass
        return content

    def get_handler(self, action, context):
        """ Returns the appropriate handler function based on action and context """
        handlers = {
            ("challenge", "registration"): self.handle_registration_challenge,
            ("challenge", "login"): self.handle_login_challenge,
            ("challengeResponse", "registration"): self.handle_registration_response,
            ("challengeResponse", "login"): self.handle_login_response,
            ("incomingMessage", None): self.handle_incoming_message_content,
            ("queryResponse", "query"): self.handle_query_response,
            ("sendResponse", "chat"): self.handle_send_response,
        }
        return handlers.get((action, context)) or handlers.get((action, None))

    async def handle_incoming_message_content(self, content):
        """ Handles incoming messages, including decryption and storage """
        if not isinstance(content, dict):
            logger.warning("'content' not a dict in 'incomingMessage' action.")
            return

        from_user = content.get("sender")
        is_encrypted = isinstance(content.get("body"), dict) or content.get("encrypted", False)
        decrypted_msg = self._decrypt_message(content, from_user) if is_encrypted else content.get("body")

        message_obj = self._parse_message(decrypted_msg)
        if message_obj.get("type") == 1:
            self._handle_handshake(from_user, message_obj)
            return

        actual_message = message_obj.get("message")
        if from_user and actual_message and self.db_manager:
            self._store_message(from_user, actual_message)
            self._update_chat_ui(from_user, actual_message)

    def _decrypt_message(self, content, from_user):
        """ Handles message decryption """
        sender_pub_from_msg = content.get("senderPublicKey")
        contact = self.db_manager.get_contact(self.current_user["username"], from_user) if self.db_manager else None
        sender_public_key_pem = contact[1] if contact else sender_pub_from_msg

        if not sender_public_key_pem:
            logger.error(f"No sender public key available for {from_user}.")
            return content.get("body")

        sender_public_key = serialization.load_pem_public_key(sender_public_key_pem.encode())
        recipient_private_key = self.crypto_utils.load_private_key(self.current_user["username"])
        
        try:
            return self.crypto_utils.decrypt_message(content.get("body"), recipient_private_key, sender_public_key)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return content.get("body")

    def _parse_message(self, decrypted_msg):
        """ Ensures the message content is in the correct format """
        try:
            return json.loads(decrypted_msg)
        except json.JSONDecodeError:
            return {"type": 0, "message": decrypted_msg}

    def _handle_handshake(self, from_user, message_obj):
        """ Handles handshake messages and updates contact list """
        nym_addr = message_obj.get("message")
        if nym_addr:
            self.nym_addresses[from_user] = nym_addr
            logger.info(f"Received handshake from {from_user}. Updated nym address: {nym_addr}")
        else:
            logger.warning(f"Handshake message from {from_user} missing nym address.")

    def _store_message(self, from_user, actual_message):
        """ Stores message in the database """
        self.db_manager.save_message(self.current_user["username"], from_user, 'from', actual_message)
        logger.info(f"Stored incoming message from {from_user} in DB.")

    def _update_chat_ui(self, from_user, actual_message):
        """ Updates chat messages and UI elements """
        if self.chat_messages is None:
            logger.warning("chat_messages is None; UI might not be initialized.")
            return

        if from_user not in self.chat_messages:
            self.chat_messages[from_user] = []

        stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.chat_messages[from_user].append((from_user, actual_message, stamp))

        if not any(chat["id"] == from_user for chat in self.chat_list):
            self.chat_list.append({"id": from_user, "name": from_user})
            if self.chat_list_sidebar_fn:
                self.chat_list_sidebar_fn.refresh()
            logger.info(f"Added {from_user} to chat list.")

        currently_active_chat = self._get_active_chat()
        if from_user == currently_active_chat and self.render_chat_fn:
            try:
                self.render_chat_fn.refresh(self.current_user["username"], currently_active_chat, self.chat_messages)
                logger.info("Chat UI refreshed successfully.")
            except Exception as e:
                logger.error(f"Failed to refresh chat UI: {e}")
        elif self.new_message_callback:
            self.new_message_callback(from_user, actual_message)