import asyncio
import websockets
import json

class MixnetMessage:
    def __init__(self, messageBytes, recipientAddress, surbs=0):
        self.messageBytes = messageBytes
        self.recipientAddress = recipientAddress
        self.surbs = surbs

    def toDict(self):
        return {
            "type": "send",
            "recipient": self.recipientAddress,
            "message": self.messageBytes,
            "surbs": self.surbs
        }

async def asyncInput(prompt=""):
    # asynchronous input to avoid blocking the main event loop
    print(prompt, end="", flush=True)
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, input)

async def sendMessages(websocket, recipientAddress):
    # function to handle sending messages asynchronously
    while True:
        messageContent = await asyncInput("Enter your message (or type 'exit' to quit): ")
        if messageContent.lower() == "exit":
            print("exiting message sending loop.")
            await websocket.close()
            break
        
        message = MixnetMessage(messageContent, recipientAddress)
        await websocket.send(json.dumps(message.toDict()))
        print("message sent!")

async def receiveMessages(websocket):
    # function to handle receiving messages asynchronously
    print("waiting for incoming messages...")
    try:
        while True:
            incomingMessage = await websocket.recv()
            messageData = json.loads(incomingMessage)
            print("\nincoming message:", messageData.get("message"))
    except websockets.exceptions.ConnectionClosed:
        print("connection closed by the server.")

async def main():
    uri = "ws://127.0.0.1:1977"
    try:
        async with websockets.connect(uri) as websocket:
            print("connected to the nym client websocket")

            # get self address
            await websocket.send(json.dumps({"type": "selfAddress"}))
            response = await websocket.recv()
            selfAddress = json.loads(response).get("address")
            print("your nym address:", selfAddress)

            recipientAddress = input("Enter the recipient's nym address: ").strip()

            # run send and receive tasks concurrently
            sendTask = asyncio.create_task(sendMessages(websocket, recipientAddress))
            receiveTask = asyncio.create_task(receiveMessages(websocket))

            # wait for both tasks to complete
            await asyncio.gather(sendTask, receiveTask)
            
    except ConnectionRefusedError:
        print("could not connect to websocket server. ensure the server is running and accessible.")
    except Exception as e:
        print("an unexpected error occurred:", e)

if __name__ == "__main__":
    asyncio.run(main())
