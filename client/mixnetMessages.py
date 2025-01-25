import json

# Global variable for the server address
SERVER_ADDRESS = "8V1Mtou4BBDJdpPfdt3eqhQdxauSVEqp8BRvU3YZGPPZ.BinUeqBzaHEsvpicBi7GmbZverhXZJBfF68v47c1GccV@69euaLVrZrgqXVge95BPzAanymqYdk6UgubmmGrHw8Sp"

class MixnetMessage:

    @staticmethod
    def query(usernym):
        # query to determine if a user exists
        encapsulatedMessage = json.dumps({"action": "query", "target": usernym})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
            "replySurbs": 10
        }

    @staticmethod
    def register(usernym, publicKey):
        # register a new user
        encapsulatedMessage = json.dumps({"action": "register", "usernym": usernym, "publicKey": publicKey})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
            "replySurbs": 10
        }

    @staticmethod
    def update(field, value, signature):
        # update any given field
        encapsulatedMessage = json.dumps({"action": "update", "field": field, "value": value, "signature": signature})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
            "replySurbs": 10
        }

    @staticmethod
    def send(usernym, content, signature):
        # send a message to a user
        encapsulatedMessage = json.dumps({"action": "send", "target": usernym, "content": content, "signature": signature})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
            "replySurbs": 10
        }

    @staticmethod
    def sendGroup(groupID, content, signature):
        # send a message to a group
        encapsulatedMessage = json.dumps({"action": "sendGroup", "target": groupID, "content": content, "signature": signature})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
            "replySurbs": 10
        }

    @staticmethod
    def createGroup(signature):
        # create a group
        encapsulatedMessage = json.dumps({"action": "createGroup", "signature": signature})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
            "replySurbs": 10
        }

    @staticmethod
    def inviteGroup(usernym, groupID, signature):
        # invite a user to a group
        encapsulatedMessage = json.dumps({"action": "inviteGroup", "target": usernym, "groupID": groupID, "signature": signature})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": SERVER_ADDRESS,
            "replySurbs": 10
        }
