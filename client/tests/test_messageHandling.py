import unittest
import json
import os
import secrets
import asyncio
import logging
from messageHandler import MessageHandler
from cryptographyUtils import CryptoUtils
from dbUtils import SQLiteManager
from connectionUtils import MixnetConnectionClient
from mixnetMessages import MixnetMessage

class MockServer:
    def __init__(self):
        self.users = {}
        self.nonces = {}
        self.pending_users = {}

    async def handle_message(self, message_json):
        """Simulates processing a message from a client and returning a response."""
        try:
            if isinstance(message_json, str):
                message = json.loads(message_json)  # Ensure message is properly parsed
            else:
                message = message_json

            if "message" in message:  # Extract encapsulated message
                message = json.loads(message["message"])

            action = message.get("action")
            senderTag = message.get("senderTag", "mockTag")

            # print(f"[MockServer] Received action: {action}")

            if action == "query":
                return await self.handle_query(message, senderTag)
            elif action == "register":
                return await self.handle_register(message, senderTag)
            elif action == "registrationResponse":
                return await self.handle_registration_response(message, senderTag)
            elif action == "login":
                return await self.handle_login(message, senderTag)
            elif action == "loginResponse":
                return await self.handle_login_response(message, senderTag)
            elif action == "send":
                return await self.handle_send(message, senderTag)
            return json.dumps({"error": f"Unknown action: {action}"})
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid JSON"})

    async def handle_query(self, message, senderTag):
        """Handles user queries."""
        username = message.get("username")
        if username in self.users:
            return json.dumps({
                "action": "queryResponse",
                "content": {"username": username, "publicKey": self.users[username]},
                "context": "query"
            })
        return json.dumps({
            "action": "queryResponse",
            "content": "No user found",
            "context": "query"
        })

    async def handle_register(self, message, senderTag):
        """Handles user registration (returns a nonce)."""
        username = message.get("usernym")
        publicKey = message.get("publicKey")

        if username in self.users:
            return json.dumps({"action": "challengeResponse", "content": "error: username already in use", "context": "registration"})

        nonce = secrets.token_hex(16)
        self.pending_users[senderTag] = (username, publicKey, nonce)
        return json.dumps({"action": "challenge", "content": {"nonce": nonce}, "context": "registration"})

    async def handle_registration_response(self, message, senderTag):
        """Handles user registration challenge response."""
        signature = message.get("signature")
        if senderTag not in self.pending_users:
            return json.dumps({"action": "challengeResponse", "content": "error: no pending registration", "context": "registration"})

        username, publicKey, nonce = self.pending_users[senderTag]

        # Simulate successful signature verification
        if signature == "valid_signature":
            self.users[username] = publicKey
            del self.pending_users[senderTag]
            return json.dumps({"action": "challengeResponse", "content": "success", "context": "registration"})

        return json.dumps({"action": "challengeResponse", "content": "error: invalid signature", "context": "registration"})

    async def handle_login(self, message, senderTag):
        """Handles user login request (returns a nonce)."""
        username = message.get("usernym")

        if username not in self.users:
            return json.dumps({"action": "challengeResponse", "content": "error: user not found", "context": "login"})

        nonce = secrets.token_hex(16)
        self.nonces[senderTag] = (username, self.users[username], nonce)
        return json.dumps({"action": "challenge", "content": {"nonce": nonce}, "context": "login"})

    async def handle_login_response(self, message, senderTag):
        """Handles user login challenge response."""
        signature = message.get("signature")
        if senderTag not in self.nonces:
            return json.dumps({"action": "challengeResponse", "content": "error: no pending login", "context": "login"})

        username, publicKey, nonce = self.nonces[senderTag]

        # Simulate successful signature verification
        if signature == "valid_signature":
            del self.nonces[senderTag]
            return json.dumps({"action": "challengeResponse", "content": "success", "context": "login"})

        return json.dumps({"action": "challengeResponse", "content": "error: invalid signature", "context": "login"})

    async def handle_send(self, message, senderTag):
        """Handles direct message sending."""
        content = message.get("content")
        signature = message.get("signature")

        try:
            content_data = json.loads(content)
        except json.JSONDecodeError:
            return json.dumps({"action": "sendResponse", "content": "error: invalid JSON", "context": "chat"})

        sender = content_data.get("sender")
        recipient = content_data.get("recipient")

        if sender not in self.users or recipient not in self.users:
            return json.dumps({"action": "sendResponse", "content": "error: sender or recipient not found", "context": "chat"})

        # Simulate successful signature verification
        if signature != "valid_signature":
            return json.dumps({"action": "sendResponse", "content": "error: invalid signature", "context": "chat"})

        return json.dumps({"action": "sendResponse", "content": "success", "context": "chat"})


class TestMessageHandler(unittest.TestCase):
    def setUp(self):
        """Setup real dependencies and mock the server."""

        self.logger = logging.getLogger("AppLogger")  # Match the logger name used in the app
        self.logger.setLevel(logging.CRITICAL)  # Suppress all logs except critical

        self.username = "testuser"
        self.storage_dir = "test_storage"
        self.crypto_utils = CryptoUtils()
        self.connection_client = MixnetConnectionClient()
        self.db_manager = SQLiteManager(self.username, self.storage_dir)

        # Populate the database with test data
        self.db_manager.register_user(self.username, "public_key_testuser")
        self.db_manager.create_user_tables(self.username)
        self.db_manager.add_contact(self.username, "alice", "public_key_alice")
        self.db_manager.add_contact(self.username, "bob", "public_key_bob")
        self.db_manager.save_message(self.username, "alice", "to", "Hello Alice!")
        self.db_manager.save_message(self.username, "bob", "from", "Hello Bob!")

        self.mock_server = MockServer()
        self.message_handler = MessageHandler(
            crypto_utils=self.crypto_utils,
            connection_client=self.connection_client
        )

        # Set the active user
        self.message_handler.current_user["username"] = self.username
        self.message_handler.db_manager = self.db_manager  # Ensure DB is set

        self.message_handler.set_ui_state(
            messages={},  # Empty dictionary to prevent 'None' errors
            chat_list=[],
            get_active_chat=lambda: None,  # Placeholder function
            render_chat=lambda u, c, m: None,  # Placeholder function
            chat_container=None,
            chat_list_sidebar_fn=None
        )


    def tearDown(self):
        self.logger.setLevel(logging.NOTSET)
        self.db_manager.close()
        db_path = os.path.join(self.storage_dir, self.username, f"{self.username}_client.db")
        if os.path.exists(db_path):
            os.remove(db_path)
        os.rmdir(os.path.join(self.storage_dir, self.username))
        os.rmdir(self.storage_dir)

    def test_register_user(self):
        asyncio.run(self.async_test_register_user())

    async def async_test_register_user(self):
        username = "testuser"
        private_key, public_key = self.crypto_utils.generate_key_pair(username)
        register_msg = MixnetMessage.register(username, public_key)
        register_msg_json = json.dumps(register_msg)
        server_response = await self.mock_server.handle_message(register_msg_json)
        # print(f"[TEST] Register response: {server_response}")
        self.assertIn("challenge", server_response)

    def test_login_user(self):
        asyncio.run(self.async_test_login_user())

    async def async_test_login_user(self):
        username = "testuser"
        self.mock_server.users[username] = "mock_public_key"
        login_msg = MixnetMessage.login(username)
        login_msg_json = json.dumps(login_msg)
        server_response = await self.mock_server.handle_message(login_msg_json)
        # print(f"[TEST] Login response: {server_response}")
        self.assertIn("challenge", server_response)

    def test_query_user(self):
        asyncio.run(self.async_test_query_user())

    async def async_test_query_user(self):
        username = "friend"
        self.mock_server.users[username] = "mock_public_key"
        query_msg = MixnetMessage.query(username)
        query_msg_json = json.dumps(query_msg)
        server_response = await self.mock_server.handle_message(query_msg_json)
        # print(f"[TEST] Query response: {server_response}")
        self.assertIn("queryResponse", server_response)

    def test_send_message(self):
        asyncio.run(self.async_test_send_message())

    async def async_test_send_message(self):
        sender = "testuser"
        recipient = "friend"
        self.mock_server.users[sender] = "mock_public_key"
        self.mock_server.users[recipient] = "mock_public_key"
        send_msg = MixnetMessage.send(json.dumps({"sender": sender, "recipient": recipient, "body": "Hello"}), "valid_signature")
        send_msg_json = json.dumps(send_msg)
        server_response = await self.mock_server.handle_message(send_msg_json)
        # print(f"[TEST] Send response: {server_response}")
        self.assertIn("success", server_response)

    def test_handle_incoming_message(self):
        asyncio.run(self.async_test_handle_incoming_message())

    async def async_test_handle_incoming_message(self):
        sender = "friend"
        current_user = "testuser"
        message_content = "Hello!"
        self.mock_server.users[sender] = "mock_public_key"
        incoming_message = json.dumps({"action": "incomingMessage", "context": "chat", "content": {"sender": sender, "body": message_content, "encrypted": False}})
        await self.message_handler.handle_incoming_message(incoming_message)
        chat_messages = self.db_manager.get_messages_by_contact(current_user, sender)
        # print(f"[TEST] Messages retrieved: {messages}")
        self.assertGreater(len(chat_messages), 0)

if __name__ == "__main__":
    unittest.main()
