import asyncio
import json
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import websockets

class MixnetMessage:
    def __init__(self, message_bytes, recipient_address, surbs=0):
        self.message_bytes = message_bytes
        self.recipient_address = recipient_address
        self.surbs = surbs

    def to_dict(self):
        # convert the message to a dictionary for json serialization
        return {
            "type": "send",
            "recipient": self.recipient_address,
            "message": self.message_bytes,
            "surbs": self.surbs
        }

    def is_valid(self):
        # validate message before sending
        return bool(self.recipient_address and self.message_bytes)

class AsyncTkApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Nym Messaging Client")

        # tkinter widgets
        self.chatDisplay = ScrolledText(root, state='disabled', width=50, height=20)
        self.chatDisplay.pack(pady=10)

        self.recipientEntry = tk.Entry(root, width=50)
        self.recipientEntry.insert(0, "Recipient Address")
        self.recipientEntry.pack(pady=5)

        self.messageEntry = tk.Entry(root, width=50)
        self.messageEntry.insert(0, "Type your message here")
        self.messageEntry.pack(pady=5)

        self.sendButton = tk.Button(root, text="Send", command=self.sendMessage)
        self.sendButton.pack(pady=5)

        # websocket and asyncio setup
        self.loop = asyncio.get_event_loop()
        self.websocket = None

        # schedule the asyncio task to start
        self.root.after(100, self.startAsyncLoop)

    async def connectWebsocket(self):
        try:
            self.websocket = await websockets.connect("ws://127.0.0.1:1977")
            await self.websocket.send(json.dumps({"type": "selfAddress"}))
            response = await self.websocket.recv()
            print("connected to websocket")
            await self.receiveMessages()  # start listening for incoming messages
        except Exception as e:
            print("connection error:", e)

    async def receiveMessages(self):
        try:
            while True:
                message = await self.websocket.recv()
                data = json.loads(message)
                self.displayMessage(f"Received: {data.get('message', '')}")
        except websockets.exceptions.ConnectionClosed:
            print("connection closed by the server.")

    def displayMessage(self, message):
        # update the chat display in a thread-safe manner
        self.chatDisplay.config(state='normal')
        self.chatDisplay.insert('end', message + "\n")
        self.chatDisplay.config(state='disabled')
        self.chatDisplay.see('end')

    def sendMessage(self):
        recipient = self.recipientEntry.get().strip()
        message_content = self.messageEntry.get().strip()
        if recipient and message_content:
            # create a MixnetMessage instance
            message = MixnetMessage(message_content, recipient)
            if message.is_valid():
                # send the message asynchronously
                self.loop.create_task(self.asyncSendMessage(message))
                self.displayMessage(f"Sent: {message_content}")
                self.messageEntry.delete(0, 'end')
            else:
                print("invalid message or recipient")

    async def asyncSendMessage(self, message):
        if self.websocket:
            # convert the MixnetMessage instance to dictionary for JSON serialization
            await self.websocket.send(json.dumps(message.to_dict()))

    def startAsyncLoop(self):
        self.loop.create_task(self.connectWebsocket())
        self.checkAsyncioLoop()

    def checkAsyncioLoop(self):
        # allow the asyncio loop to run periodically
        self.loop.stop()  # stop loop if already running
        self.loop.run_forever()  # run pending asyncio tasks
        self.root.after(100, self.checkAsyncioLoop)  # check again after 100ms

if __name__ == "__main__":
    root = tk.Tk()
    app = AsyncTkApp(root)
    root.mainloop()

