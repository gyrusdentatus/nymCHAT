import json

class MixnetMessage:

    @staticmethod
    def query(usernym, serverAddress):
        # query to determine if a user exists
        encapsulatedMessage = json.dumps({"action": "query", "target": usernym})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": serverAddress,
            "replySurbs": 10
        }

    @staticmethod
    def register(usernym, publicKey, serverAddress):
        # register a new user
        encapsulatedMessage = json.dumps({"action": "register", "publicKey": publicKey})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": serverAddress,
            "replySurbs": 10
        }

    @staticmethod
    def update(field, value, signature, serverAddress):
        # update any given field
        encapsulatedMessage = json.dumps({"action": "update", "field": field, "value": value, "signature": signature})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": serverAddress,
            "replySurbs": 10
        }

    @staticmethod
    def send(usernym, content, signature, serverAddress):
        # send a message to a user
        encapsulatedMessage = json.dumps({"action": "send", "target": usernym, "content": content, "signature": signature})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": serverAddress,
            "replySurbs": 10
        }

    @staticmethod
    def sendGroup(groupID, content, signature, serverAddress):
        # send a message to a group
        encapsulatedMessage = json.dumps({"action": "sendGroup", "target": groupID, "content": content, "signature": signature})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": serverAddress,
            "replySurbs": 10
        }

    @staticmethod
    def createGroup(signature, serverAddress):
        # create a group
        encapsulatedMessage = json.dumps({"action": "createGroup", "signature": signature})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": serverAddress,
            "replySurbs": 10
        }

    @staticmethod
    def inviteGroup(usernym, groupID, signature, serverAddress):
        # invite a user to a group
        encapsulatedMessage = json.dumps({"action": "inviteGroup", "target": usernym, "groupID": groupID, "signature": signature})
        return {
            "type": "sendAnonymous",
            "message": encapsulatedMessage,
            "recipient": serverAddress,
            "replySurbs": 10
        }

