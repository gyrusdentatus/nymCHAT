# NymCHAT

NymCHAT is a messaging client that routes all traffic through the Nym Mixnet. It sends messages to the NymServer, which acts as a remailer / directory and is designed to only store a username, public key, and SURB. A **SURB** (Short Unlinkable Reply Block) is a cryptographic token that allows the server to send a reply to a client without revealing or linking the client's identity. 

---
## Features

- **Network-Level Privacy**: By routing all messages through the mixnet, network traffic metadata is obfuscated using layered encryption, independent message routing, and cover traffic, making it resistant to global adversaries and advanced traffic analysis techniques​​.
- **User Registration**: No Information Required. 
- **End-to-End Encryption**: All messages are encrypted using AES-GCM, with secure key exchange via ECDH, ensuring privacy and integrity of communication between users.

---
## Prerequisites

- **nym-client**: Download from [Nym Client Release Page](https://github.com/nymtech/nym/releases/tag/nym-binaries-v2025.2-hu)
---
## Setting up the nym-client

1. **Download and make executable:**
- Once you've downloaded the `nym-client` file, navigate (`cd`) to its location in the terminal.
- Make it executable by running: `sudo chmod +x nym-client`

2. **Initialize the client**:
- Initialize the client with a unique ID by running:  `./nym-client init --id name` 
- Replace `name` with any identifier you'd like to use for your client.

3. **Run the client**:
- Start the client by running: `./nym-client run --id name`
- Replace `name` with the identifier you used during initialization.

> Once you see the message `> Client startup finished!`, you’ll know the Nym client is ready. Keep this terminal running, and open a new terminal for the next steps.

---
## Running the App

1. **Set up your Python environment**:
- Clone this repository and navigate to the directory:
```
git clone https://github.com/code-zm/nymCHAT.git
cd nymChat
```

2. **Create Virutal Environment**
- Run these commands to create and activate a virtual environment:
```
python3 -m venv venv
source venv/bin/activate
```

3. **Install Dependencies**:
- Install required dependencies by running: `pip install -r requirements.txt`

4. **Run the Script**:
- In a new terminal, run the Python script `python client/runClient.py`

--- 
## Usage

 **Register a new user**:
    - Open the application in your browser.
    - Navigate to the **Register** page, enter your username, and click **Register**.
    - The system will generate a key pair and send a registration request to the NymDirectory server.

**Login**:
    - After registration, log in using your username to access the messaging features.
    - You will be presented with a list of existing users and can start a conversation with them.

**Search**
	- To start a chat with a new user, click the search button in the top right. 
	- Enter the username and click search. *Note: Usernames are CASE SENSITIVE*

**Send Messages**:
    - Once logged in, you can select a contact and send secure, encrypted messages.

**Database Storage**:
    - All messages are stored locally in a SQLite database. The app loads your messages upon login and stores new ones after each communication.

--- 
## Script Overview

- `connectionUtils.py`: Manages WebSocket connection to `nym-client`.
- `cryptographyUtils.py`: Handles cryptographic operations like key generation, signing, encryption, and decryption.
- `dbUtils.py`: Manages the local SQLite database for contacts and messages.
- `messageHandler.py`: Handles the logic for registering, logging in, and managing messages.
- `mixnetMessages.py`: Constructs messages for communication with `nym-client`.
- `runClient.py`: Runs the user interface using NiceGUI.
- `storage/`: Directory where keys and databases are stored.
- `client/`: Directory where the scripts are stored. 

---
## Plans

I plan on developing this into a full-featured cross platform messaging app. If anyone wants to help out, DM me on X @zm_0x

**TODO:**
- Upgrade cryptography to MLS
- Groupchats and channels

---
## License
This project is licensed under the GPL-3.0 License - see the LICENSE file for details.
