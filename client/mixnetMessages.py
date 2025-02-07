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
        :param usernym: The username to query.
        :return: A dictionary formatted as a query message.
        """
        encapsulatedMessage = json.dumps({"action": "query", "username": usernym})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
            "replySurbs": 10,
        }

    @staticmethod
    def register(usernym, publicKey):
        """
        Prepare the message for user registration.
        :param usernym: The username to register.
        :param publicKey: The public key of the user.
        :return: A dictionary formatted as a registration message.
        """
        encapsulatedMessage = json.dumps({"action": "register", "usernym": usernym, "publicKey": publicKey})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
            "replySurbs": 10,
        }

    @staticmethod
    def login(usernym):
        """
        Prepare the message for user login.
        :param usernym: The username to log in.
        :return: A dictionary formatted as a login message.
        """
        encapsulatedMessage = json.dumps({"action": "login", "usernym": usernym})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
            "replySurbs": 10,
        }


    @staticmethod
    def update(field, value, signature):
        """
        Prepare the message for updating user information.
        :param field: The field to update.
        :param value: The new value for the field.
        :param signature: The signature for the update operation.
        :return: A dictionary formatted as an update message.
        """
        encapsulatedMessage = json.dumps({"action": "update", "field": field, "value": value, "signature": signature})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
            "replySurbs": 10,
        }

    @staticmethod
    def send(content, signature):
        """
        Prepare the message for sending a direct message.
        :param usernym: The recipient's username.
        :param content: The message content.
        :param signature: The signature of the message.
        :return: A dictionary formatted as a send message.
        """
        encapsulatedMessage = json.dumps({"action": "send", "content": content, "signature": signature})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
            "replySurbs": 10,
        }

    @staticmethod
    def sendGroup(groupID, content, signature):
        """
        Prepare the message for sending a group message.
        :param groupID: The group ID to send the message to.
        :param content: The message content.
        :param signature: The signature of the message.
        :return: A dictionary formatted as a group message.
        """
        encapsulatedMessage = json.dumps({"action": "sendGroup", "target": groupID, "content": content, "signature": signature})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
            "replySurbs": 10,
        }

    @staticmethod
    def createGroup(signature):
        """
        Prepare the message for creating a group.
        :param signature: The signature of the group creation request.
        :return: A dictionary formatted as a create group message.
        """
        encapsulatedMessage = json.dumps({"action": "createGroup", "signature": signature})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
            "replySurbs": 10,
        }

    @staticmethod
    def inviteGroup(usernym, groupID, signature):
        """
        Prepare the message for inviting a user to a group.
        :param usernym: The username of the user to invite.
        :param groupID: The group ID to invite the user to.
        :param signature: The signature of the invite request.
        :return: A dictionary formatted as a group invite message.
        """
        encapsulatedMessage = json.dumps({"action": "inviteGroup", "target": usernym, "groupID": groupID, "signature": signature})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
            "replySurbs": 10,
        }

    @staticmethod
    def registrationResponse(username, signature):
        """
        Prepare the response message for a server-issued registration challenge.
        :param username: The client's username.
        :param signature: The signed nonce by the client's private key.
        :return: A dictionary formatted as a registration response message.
        """
        encapsulatedMessage = json.dumps({
            "action": "registrationResponse",
            "username": username,
            "signature": signature,
        })
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
            "replySurbs": 10,
        }

    @staticmethod
    def loginResponse(username, signature):
        """
        Prepare the response message for a server-issued login challenge.
        :param username: The client's username.
        :param signature: The signed nonce by the client's private key.
        :return: A dictionary formatted as a login response message.
        """
        encapsulatedMessage = json.dumps({
            "action": "loginResponse",
            "username": username,
            "signature": signature,
        })
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
            "replySurbs": 10,
        }
