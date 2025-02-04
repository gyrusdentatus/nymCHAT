# messageHandler.py

import json
import asyncio

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

        # Query flow
        self.query_result_event = asyncio.Event()
        self.query_result = None

        # [OPTIONAL] references to UI or chat state
        self.chat_messages = None
        self.chat_list = None
        self.active_chat = None
        self.render_chat_fn = None
        self.chat_container = None

    def set_ui_state(self, messages, chat_list, get_active_chat, render_chat, chat_container):
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

            # Send a 'register' message
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
                return

            try:
                self.db_manager = SQLiteManager(username)
                print("[INFO] DB initialized for user:", username)
            except Exception as e:
                print(f"[ERROR] DB init: {e}")
                return

            self.registration_complete.set()
        else:
            print(f"[ERROR] Registration failed: {content}")

    async def handle_login_response(self, content):
        if content == "success":
            print("[INFO] Login successful!")
            username = self.current_user["username"]
            try:
                self.db_manager = SQLiteManager(username)
                print("[INFO] DB manager created.")
                self.db_manager.create_user_tables(username)
            except Exception as e:
                print(f"[ERROR] DB init: {e}")

            self.login_complete.set()
        else:
            print(f"[ERROR] Login failed: {content}")

    # --------------------------------------------------------------------------
    # Sending Direct Messages
    # --------------------------------------------------------------------------
    async def send_direct_message(self, recipient_username, message_content):
        if not recipient_username or not message_content.strip():
            return

        payload = {
            "sender": self.current_user["username"],
            "recipient": recipient_username,
            "body": message_content
        }
        payload_str = json.dumps(payload)

        private_key = self.crypto_utils.load_private_key(self.current_user["username"])
        if not private_key:
            print("[ERROR] No private key to send message.")
            return

        signature = self.crypto_utils.sign_message_with_key(private_key, payload_str)
        msg = MixnetMessage.send(content=payload_str, signature=signature)
        await self.websocket_client.send_message(msg)
        print(f"[INFO] Sent direct message to {recipient_username}")

        if self.db_manager:
            self.db_manager.save_message(
                self.current_user["username"],
                contact_username=recipient_username,
                msg_type='to',
                message=message_content
            )
        else:
            print("[WARNING] DB manager not init; outgoing message not saved.")

    async def handle_send_response(self, content):
        # Could display a UI notification if desired
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

    # --------------------------------------------------------------------------
    # Handling Incoming Messages (SINGLE CALLBACK)
    # --------------------------------------------------------------------------
    async def handle_incoming_message(self, data):
        """
        The single callback from `connectionUtils.WebSocketClient`.
        Does:
        1) Check if challenge or direct message
        2) DB logic
        3) UI updates (if you have set_ui_state references)
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

            # If 'content' is a JSON string, try decoding it
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
                    from_user = content.get("from")
                    msg_body = content.get("content")

                    if from_user and msg_body and self.db_manager:
                        # Save message to database
                        self.db_manager.save_message(
                            self.current_user["username"],
                            from_user,
                            'from',
                            msg_body
                        )
                        print(f"[INFO] Stored incoming message from {from_user} in DB.")

                        # Ensure in-memory storage is updated
                        if self.chat_messages is not None:
                            if from_user not in self.chat_messages:
                                self.chat_messages[from_user] = []
                            stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            self.chat_messages[from_user].append((from_user, msg_body, stamp))

                            # Check if the message is for the currently open chat
                            currently_active_chat = self._get_active_chat()
                            if from_user == currently_active_chat:
                                print(f"[INFO] Updating UI for chat with {from_user}")

                                # Ensure UI refresh function is being called properly
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
                                print(f"[INFO] Message stored but {from_user} is not active chat.")
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

