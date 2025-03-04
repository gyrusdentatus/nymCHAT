# NymCHAT

NymCHAT is a messaging client that routes all traffic through the Nym Mixnet for privacy. 

---
## Features

- **Network-Level Privacy**: By routing all messages through the mixnet, network traffic metadata is obfuscated using layered encryption, independent message routing, and cover traffic, making it resistant to global adversaries and advanced traffic analysis techniques​​.
- **User Registration**: No Personal Information Required. 
- **End-to-End Encryption**: All messages are encrypted / decrypted locally using AES-GCM, with secure key exchange via ECDH, ensuring privacy and integrity of communication between users.

---
## Prerequisites
- Python 3.11+
- Rust
---
## Set Up
In order to communicate with the mixnet, we use the Nym Rust SDK with pyo3 bindings If you are on linux, you can install the pre-existing .whl, or build yourself. 

1.  Clone this repository and navigate to the directory:
```
git clone https://github.com/code-zm/nymCHAT.git
cd nymChat
```

2. Create & activate python virtual environment
```
python3 -m venv .venv
source .venv/bin/activate
```

3. Install requirements
```
pip install -r requirements.txt
```

4. Build the python-rust bindings with maturin
```
maturin develop
maturin build
```
*Take note of where the .whl file is built, usually /target/wheels/*

5. Install the FFI library
```
pip install path/to/.whl
```

---
## Running the App

```
python client/runClient.py
```

--- 
## Usage
**Connect to the mixnet**
	- Start the app
	- Connect to the mixnet

 **Register a new user**:
    - Navigate to the **Register** page, enter your username, and click **Register**.
    - The system will generate a key pair and send a registration request to the NymDirectory server.

**Login**:
    - After registration, log in using your username to access the messaging features.

**Search**
	- To start a chat with a new user, click the search button in the top right. 
	- Enter the username and click search. *Note: Usernames are CASE SENSITIVE*

**Send Messages**:
    - Once logged in, you can select a contact and send secure, encrypted messages.

**Database Storage**:
    - All messages are stored locally in a SQLite database. The app loads your messages upon login and stores new ones after each communication.

--- 
## Script Overview

- `connectionUtils.py`: Manages Mixnet operations using Rust-Python FFI library.
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
