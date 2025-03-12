import json
import os
from dotenv import load_dotenv

load_dotenv()

# def read_server_address():
#     try:
#         # Direct path to storage/config.txt
#         config_path = os.path.join('storage', 'config.txt')
        
#         with open(config_path, 'r') as file:
#             line = file.readline().strip()
#             if line.startswith("SERVER_ADDRESS="):
#                 return line.split('=')[1].strip()
#             else:
#                 raise ValueError("SERVER_ADDRESS not found in config file")
#     except FileNotFoundError:
#         raise FileNotFoundError("Config file not found.")
#     except Exception as e:
#         raise e

# Global variable for the server address
SERVER_ADDRESS = os.getenv("SERVER_ADDRESS")

class MixnetMessage:
    @staticmethod
    def query(usernym):
        encapsulatedMessage = json.dumps({"action": "query", "username": usernym})
        return {
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
        }

    @staticmethod
    def register(usernym, publicKey):
        encapsulatedMessage = json.dumps({"action": "register", "usernym": usernym, "publicKey": publicKey})
        return {
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
        }

    @staticmethod
    def login(usernym):
        encapsulatedMessage = json.dumps({"action": "login", "usernym": usernym})
        return {
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
        }

    @staticmethod
    def update(field, value, signature):
        encapsulatedMessage = json.dumps({"action": "update", "field": field, "value": value, "signature": signature})
        return {
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
        }

    @staticmethod
    def send(content, signature):
        """
        Encapsulates a message for sending via the centralized server.
        This is used for handshake messages (to hide it from the server) and is not appropriate for p2p direct messaging.
        """
        encapsulatedMessage = json.dumps({"action": "send", "content": content, "signature": signature})
        return {
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
        }

    @staticmethod
    def directMessage(content, signature):
        """
        Encapsulates a p2p direct message in the format expected by the receiving client.
        The resulting JSON has an action of 'incomingMessage' and a context of 'chat'.
        """
        encapsulatedMessage = json.dumps({
            "action": "incomingMessage",
            "content": content,
            "context": "chat",
            "signature": signature
        })
        # The recipient field can be overridden if a direct p2p address is available.
        return {
            "message": encapsulatedMessage,
            "recipient": ""  # This field can be set externally
        }

    @staticmethod
    def sendGroup(groupID, content, signature):
        encapsulatedMessage = json.dumps({"action": "sendGroup", "target": groupID, "content": content, "signature": signature})
        return {
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
        }

    @staticmethod
    def createGroup(signature):
        encapsulatedMessage = json.dumps({"action": "createGroup", "signature": signature})
        return {
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
        }

    @staticmethod
    def inviteGroup(usernym, groupID, signature):
        encapsulatedMessage = json.dumps({"action": "inviteGroup", "target": usernym, "groupID": groupID, "signature": signature})
        return {
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
        }

    @staticmethod
    def registrationResponse(username, signature):
        encapsulatedMessage = json.dumps({
            "action": "registrationResponse",
            "username": username,
            "signature": signature,
        })
        return {
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
        }

    @staticmethod
    def loginResponse(username, signature):
        encapsulatedMessage = json.dumps({
            "action": "loginResponse",
            "username": username,
            "signature": signature,
        })
        return {
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
        }

