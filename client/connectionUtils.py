import asyncio
import json
import websockets

class WebSocketClient:
    def __init__(self, server_url="ws://127.0.0.1:1977"):
        self.server_url = server_url
        self.websocket = None

    async def connect(self):
        """Establish a WebSocket connection with the Nym client."""
        try:
            self.websocket = await websockets.connect(self.server_url)
            await self.websocket.send(json.dumps({"type": "selfAddress"}))
            response = await self.websocket.recv()
            data = json.loads(response)
            self_address = data.get("address")
            print("Connected to WebSocket. Your Nym Address:", self_address)

            await self.receive_messages()  # Start listening for incoming messages
        except Exception as e:
            print("Connection error:", e)

    async def receive_messages(self):
        """Listen for incoming messages."""
        try:
            while True:
                message = await self.websocket.recv()
                data = json.loads(message)

                # Handle received mixnet messages
                if data["type"] == "received":
                    received_message = data.get("message", "")
                    print(f"Received: {received_message}")
        except websockets.exceptions.ConnectionClosed:
            print("Connection closed by the server.")

    async def send_message(self, message):
        """Send a message through the WebSocket."""
        try:
            if isinstance(message, dict):
                # Convert the dictionary to a JSON string
                message = json.dumps(message)
            await self.websocket.send(message)
            print(f"Message sent: {message}")
        except Exception as e:
            print(f"Error sending message: {e}")


