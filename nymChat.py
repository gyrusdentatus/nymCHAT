import asyncio
import json
import re
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import websockets

class MixnetMessage:
    def __init__(self, messageBytes, recipientAddress, surbs=0):
        # Initialize a Mixnet message with content, recipient, and SURBs
        self.messageBytes = messageBytes
        self.recipientAddress = recipientAddress
        self.surbs = surbs

    def toDict(self):
        # Convert the message to a dictionary format for JSON serialization
        return {
            "type": "send",
            "recipient": self.recipientAddress,
            "message": self.messageBytes,
            "surbs": self.surbs
        }

    def isValid(self):
        # Check if the message and recipient are valid (non-empty)
        return bool(self.recipientAddress and self.messageBytes)

class AsyncTkApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Nym Messaging Client")
        self.root.protocol("WM_DELETE_WINDOW", self.onClose)  # Handle the "X" button

        # Chat display area for received and sent messages
        self.chatDisplay = ScrolledText(root, state='disabled', width=50, height=20)
        self.chatDisplay.pack(pady=10)

        # Entry field for recipient address
        self.recipientEntry = tk.Entry(root, width=50)
        self.recipientEntry.insert(0, "Recipient Address")  # Placeholder text
        self.recipientEntry.bind("<FocusIn>", self.clearPlaceholder)  # Remove placeholder on focus
        self.recipientEntry.bind("<FocusOut>", self.addPlaceholder)  # Restore placeholder if empty
        self.recipientEntry.pack(pady=5)

        # Entry field for message content
        self.messageEntry = tk.Entry(root, width=50)
        self.messageEntry.insert(0, "Type your message here")  # Placeholder text
        self.messageEntry.bind("<FocusIn>", self.clearPlaceholder)
        self.messageEntry.bind("<FocusOut>", self.addPlaceholder)
        self.messageEntry.pack(pady=5)

        # Button to send a message
        self.sendButton = tk.Button(root, text="Send", command=self.sendMessage)
        self.sendButton.pack(pady=5)

        # Frame for displaying and copying the user's own address
        self.addressFrame = tk.Frame(root)
        self.addressFrame.pack(pady=10)

        # Label for the self address
        self.addressLabel = tk.Label(self.addressFrame, text="Your Nym Address:")
        self.addressLabel.grid(row=0, column=0, columnspan=2, pady=(0, 5))  # Added label

        # Entry field for user's address, read-only
        self.selfAddressEntry = tk.Entry(self.addressFrame, width=50, state='readonly')
        self.selfAddressEntry.grid(row=1, column=0, padx=(0, 10))
        self.selfAddressEntry.insert(0, "Fetching address...")  # Placeholder until address is retrieved

        # Button to copy the user's address to the clipboard
        self.copyButton = tk.Button(self.addressFrame, text="Copy to Clipboard", command=self.copyToClipboard)
        self.copyButton.grid(row=1, column=1)

        # Asyncio event loop and WebSocket setup
        self.loop = asyncio.get_event_loop()
        self.websocket = None  # WebSocket connection
        self.running = True  # Flag to indicate the app is running

        # Start the asyncio tasks
        self.startAsyncLoop()

    def clearPlaceholder(self, event):
        # Remove placeholder text when the user focuses on an entry field
        widget = event.widget
        if widget == self.recipientEntry and widget.get() == "Recipient Address":
            widget.delete(0, 'end')
        elif widget == self.messageEntry and widget.get() == "Type your message here":
            widget.delete(0, 'end')

    def addPlaceholder(self, event):
        # Add placeholder text back if the entry field is empty
        widget = event.widget
        if widget == self.recipientEntry and widget.get() == "":
            widget.insert(0, "Recipient Address")
        elif widget == self.messageEntry and widget.get() == "":
            widget.insert(0, "Type your message here")

    def sendMessage(self):
        # Get recipient and message content, validate, and send message
        recipient = self.recipientEntry.get().strip()
        messageContent = self.messageEntry.get().strip()

        # Validate recipient address
        if not self.isValidNymAddress(recipient):
            print("Invalid recipient address.")
            return

        # Create a MixnetMessage and send it
        message = MixnetMessage(messageContent, recipient)
        if message.isValid():
            self.loop.create_task(self.asyncSendMessage(message))
            self.displayMessage(f"Sent: {messageContent}")  # Show the sent message in the chat
            self.messageEntry.delete(0, 'end')  # Clear the message field
        else:
            print("Invalid message or recipient")

    def isValidNymAddress(self, address):
        # Validate the Nym address using a regex for allowed characters
        nymAddressRegex = re.compile("^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz.@]+$")
        return bool(nymAddressRegex.match(address))

    async def asyncSendMessage(self, message):
        # Send the message over the WebSocket connection
        if self.websocket:
            await self.websocket.send(json.dumps(message.toDict()))

    async def connectWebsocket(self):
        # Establish a WebSocket connection and fetch the user's address
        try:
            self.websocket = await websockets.connect("ws://127.0.0.1:1977")
            await self.websocket.send(json.dumps({"type": "selfAddress"}))  # Request the self-address
            response = await self.websocket.recv()
            data = json.loads(response)
            selfAddress = data.get("address")
            print("Connected to WebSocket. Your Nym Address:", selfAddress)

            # Update the GUI with the user's address
            self.selfAddressEntry.config(state='normal')
            self.selfAddressEntry.delete(0, 'end')
            self.selfAddressEntry.insert(0, selfAddress)
            self.selfAddressEntry.config(state='readonly')
            self.selfAddress = selfAddress

            await self.receiveMessages()  # Start listening for incoming messages
        except Exception as e:
            if self.running:
                print(f"Connection error: {e}")
        finally:
            await self.cleanupWebsocket()

    async def receiveMessages(self):
        # Continuously listen for incoming messages
        try:
            while self.running:
                message = await self.websocket.recv()
                data = json.loads(message)
                self.displayMessage(f"Received: {data.get('message', '')}")
        except websockets.exceptions.ConnectionClosedOK:
            print("Connection closed cleanly.")
        except websockets.exceptions.ConnectionClosedError as e:
            if self.running:
                print(f"Connection error: {e}")
        except Exception as e:
            if self.running:
                print(f"Unexpected error: {e}")
        finally:
            print("WebSocket connection terminated.")

    async def cleanupWebsocket(self):
        # Close the WebSocket connection if it exists
        if self.websocket:
            try:
                await self.websocket.close()
            except Exception:
                pass
            finally:
                self.websocket = None

    def displayMessage(self, message):
        # Display a message in the chat area
        self.chatDisplay.config(state='normal')
        self.chatDisplay.insert('end', message + "\n")
        self.chatDisplay.config(state='disabled')
        self.chatDisplay.see('end')

    def copyToClipboard(self):
        # Copy the user's address to the clipboard
        self.root.clipboard_clear()
        self.root.clipboard_append(self.selfAddress)

    def startAsyncLoop(self):
        # Start the asyncio tasks in the background
        self.loop.create_task(self.connectWebsocket())
        self.runAsyncTasks()

    def runAsyncTasks(self):
        # Keep the asyncio loop running periodically
        try:
            self.loop.stop()
            self.loop.run_forever()
        except RuntimeError:
            pass
        finally:
            self.root.after(100, self.runAsyncTasks)

    def onClose(self):
        # Handle the app closure by cleaning up and exiting
        print("Closing the app...")
        self.running = False
        self.loop.run_until_complete(self.cleanupWebsocket())
        self.loop.stop()
        self.loop.close()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = AsyncTkApp(root)
    root.mainloop()
