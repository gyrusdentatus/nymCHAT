import asyncio
import json
import tkinter as tk
from tkinter import Toplevel
from tkinter.scrolledtext import ScrolledText
import websockets


class MixnetMessage:
    @staticmethod
    def createRegistrationMessage(pseudonym, recipientAddress):
        """Create a registration message with properly encapsulated JSON."""
        encapsulatedMessage = json.dumps({"method": "register", "content": pseudonym})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": recipientAddress,
            "replySurbs": 10
        }

    @staticmethod
    def createQueryMessage(pseudonym, content, recipientAddress):
        """Create a query message with properly encapsulated JSON."""
        encapsulatedMessage = json.dumps({"method": "query", "pseudonym": pseudonym, "content": content})
        return {
            "type": "send",
            "message": encapsulatedMessage,
            "recipient": recipientAddress
        }


class AsyncTkApp:
    remailerAddress = "8V1Mtou4BBDJdpPfdt3eqhQdxauSVEqp8BRvU3YZGPPZ.BinUeqBzaHEsvpicBi7GmbZverhXZJBfF68v47c1GccV@69euaLVrZrgqXVge95BPzAanymqYdk6UgubmmGrHw8Sp"

    def __init__(self, root):
        self.root = root
        self.root.title("Nym Messaging Client")

        # Chat display area
        self.chatDisplay = ScrolledText(root, state='disabled', width=50, height=20)
        self.chatDisplay.pack(pady=10)

        # Buttons for registration and query messages
        self.registerButton = tk.Button(root, text="Register", command=self.openRegisterWindow)
        self.registerButton.pack(pady=5)

        self.queryButton = tk.Button(root, text="Send Query", command=self.openQueryWindow)
        self.queryButton.pack(pady=5)

        # WebSocket setup
        self.loop = asyncio.get_event_loop()
        self.websocket = None

        # Schedule the asyncio task to start
        self.root.after(100, self.startAsyncLoop)

    def openRegisterWindow(self):
        """Open a popup window for registering a pseudonym."""
        registerWindow = Toplevel(self.root)
        registerWindow.title("Register Pseudonym")

        tk.Label(registerWindow, text="Enter your pseudonym:").pack(pady=5)
        pseudonymEntry = tk.Entry(registerWindow, width=30)
        pseudonymEntry.pack(pady=5)

        def submitPseudonym():
            pseudonym = pseudonymEntry.get().strip()
            if pseudonym:
                message = MixnetMessage.createRegistrationMessage(pseudonym, self.remailerAddress)
                self.loop.create_task(self.asyncSendMessage(message))
                self.displayMessage(f"Registered pseudonym: {pseudonym}")
                registerWindow.destroy()
            else:
                tk.Label(registerWindow, text="Pseudonym cannot be empty.", fg="red").pack()

        tk.Button(registerWindow, text="Register", command=submitPseudonym).pack(pady=10)

    def openQueryWindow(self):
        """Open a popup window for sending a query message."""
        queryWindow = Toplevel(self.root)
        queryWindow.title("Send Query")

        tk.Label(queryWindow, text="Enter the pseudonym:").pack(pady=5)
        pseudonymEntry = tk.Entry(queryWindow, width=30)
        pseudonymEntry.pack(pady=5)

        tk.Label(queryWindow, text="Enter your message:").pack(pady=5)
        contentEntry = tk.Entry(queryWindow, width=30)
        contentEntry.pack(pady=5)

        def submitQuery():
            pseudonym = pseudonymEntry.get().strip()
            content = contentEntry.get().strip()
            if pseudonym and content:
                message = MixnetMessage.createQueryMessage(pseudonym, content, self.remailerAddress)
                self.loop.create_task(self.asyncSendMessage(message))
                self.displayMessage(f"Sent to {pseudonym}: {content}")
                queryWindow.destroy()
            else:
                tk.Label(queryWindow, text="Both fields are required.", fg="red").pack()

        tk.Button(queryWindow, text="Send", command=submitQuery).pack(pady=10)

    async def asyncSendMessage(self, message):
        """Send a message through the WebSocket."""
        try:
            if isinstance(message, dict):
                # Convert the dictionary to a JSON string
                message = json.dumps(message)
            await self.websocket.send(message)
            print(f"Message sent: {message}")
        except Exception as e:
            print(f"Error sending message: {e}")

    async def connectWebsocket(self):
        """Establish a WebSocket connection with the Nym client."""
        try:
            self.websocket = await websockets.connect("ws://127.0.0.1:1977")
            await self.websocket.send(json.dumps({"type": "selfAddress"}))
            response = await self.websocket.recv()
            data = json.loads(response)
            selfAddress = data.get("address")
            print("Connected to WebSocket. Your Nym Address:", selfAddress)

            await self.receiveMessages()  # Start listening for incoming messages
        except Exception as e:
            print("Connection error:", e)

    async def receiveMessages(self):
        """Listen for incoming messages."""
        try:
            while True:
                message = await self.websocket.recv()
                data = json.loads(message)
                print(data)

                # Handle received mixnet messages
                if data["type"] == "received":
                    receivedMessage = data.get("message", "")
                    self.displayMessage(f"Received: {receivedMessage}")
                if data.get("senderTag"):
                    senderTag = data.get("senderTag")
                    print(f"SenderTag: {senderTag}")
        except websockets.exceptions.ConnectionClosed:
            print("Connection closed by the server.")

    def displayMessage(self, message):
        """Update the chat display with the new message."""
        self.chatDisplay.config(state='normal')
        self.chatDisplay.insert('end', message + "\n")
        self.chatDisplay.config(state='disabled')
        self.chatDisplay.see('end')

    def startAsyncLoop(self):
        """Start the asyncio loop."""
        self.loop.create_task(self.connectWebsocket())
        self.checkAsyncLoop()

    def checkAsyncLoop(self):
        """Run the asyncio loop periodically."""
        self.loop.stop()
        self.loop.run_forever()
        self.root.after(100, self.checkAsyncLoop)


if __name__ == "__main__":
    root = tk.Tk()
    app = AsyncTkApp(root)
    root.mainloop()
