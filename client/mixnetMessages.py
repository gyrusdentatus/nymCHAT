import json
import os

# Read the server address from the config file
def read_server_address():
    try:
        # Direct path to storage/config.txt
        config_path = os.path.join('storage', 'config.txt')
        
        with open(config_path, 'r') as file:
            line = file.readline().strip()
            if line.startswith("SERVER_ADDRESS="):
                return line.split('=')[1].strip()
            else:
                raise ValueError("SERVER_ADDRESS not found in config file")
    except FileNotFoundError:
        raise FileNotFoundError("Config file not found.")
    except Exception as e:
        raise e

# Global variable for the server address
SERVER_ADDRESS = read_server_address()

class MixnetMessage:
    @staticmethod
    def query(usernym):
        """
        Prepare the message to query user existence (or initiate login).
        """
        encapsulatedMessage = json.dumps({"action": "query", "username": usernym})
        return {
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
        }

    @staticmethod
    def register(usernym, publicKey):
        """
        Prepare the message for user registration.
        """
        encapsulatedMessage = json.dumps({"action": "register", "usernym": usernym, "publicKey": publicKey})
        return {
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
        }

    @staticmethod
    def login(usernym):
        """
        Prepare the message for user login.
        """
        encapsulatedMessage = json.dumps({"action": "login", "usernym": usernym})
        return {
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
        }

    @staticmethod
    def update(field, value, signature):
        """
        Prepare the message for updating user information.
        """
        encapsulatedMessage = json.dumps({"action": "update", "field": field, "value": value, "signature": signature})
        return {
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
        }

    @staticmethod
    def send(content, signature):
        """
        Prepare the message for sending a direct message.
        """
        encapsulatedMessage = json.dumps({"action": "send", "content": content, "signature": signature})
        return {
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
        }

    @staticmethod
    def sendGroup(groupID, content, signature):
        """
        Prepare the message for sending a group message.
        """
        encapsulatedMessage = json.dumps({"action": "sendGroup", "target": groupID, "content": content, "signature": signature})
        return {
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
        }

    @staticmethod
    def createGroup(signature):
        """
        Prepare the message for creating a group.
        """
        encapsulatedMessage = json.dumps({"action": "createGroup", "signature": signature})
        return {
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
        }

    @staticmethod
    def inviteGroup(usernym, groupID, signature):
        """
        Prepare the message for inviting a user to a group.
        """
        encapsulatedMessage = json.dumps({"action": "inviteGroup", "target": usernym, "groupID": groupID, "signature": signature})
        return {
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
        }

    @staticmethod
    def registrationResponse(username, signature):
        """
        Prepare the response message for a server-issued registration challenge.
        """
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
        """
        Prepare the response message for a server-issued login challenge.
        """
        encapsulatedMessage = json.dumps({
            "action": "loginResponse",
            "username": username,
            "signature": signature,
        })
        return {
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
        }
