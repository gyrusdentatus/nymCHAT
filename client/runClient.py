import os
import asyncio
from nicegui import ui, app
from dbUtils import SQLiteManager
from cryptographyUtils import CryptoUtils
from connectionUtils import WebSocketClient
from messageHandler import MessageHandler
from uuid import uuid4
from datetime import datetime

# Instantiate utilities
crypto_utils = CryptoUtils()
websocket_client = WebSocketClient()
message_handler = MessageHandler(crypto_utils, websocket_client)

# Directory for scanning local user databases
DB_DIR = "./storage"
usernames = []

# In-memory chat state at the module level
chat_list = []  # List of chats: [{"id": <username>, "name": <username>}]
active_chat = None  # Currently active chat ID (username)
active_chat_user = None  # Display name in chat header
messages = {}  # {username: [(sender_id, avatar_url, text, timestamp), ...]}


def scan_for_users():
    """Scan the `storage` folder for user directories and extract usernames."""
    global usernames
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR)
        print("[INFO] No users found. 'storage' directory created.")
        return

    user_dirs = [
        d for d in os.listdir(DB_DIR)
        if os.path.isdir(os.path.join(DB_DIR, d))
    ]
    usernames = user_dirs
    print(f"[INFO] Found users: {usernames}")


def load_chats_from_db():
    """Load the chat list and message history from the user's database."""
    global chat_list, messages
    chat_list.clear()
    messages.clear()

    active_username = message_handler.current_user["username"]
    if not message_handler.db_manager:
        print("[WARNING] No DB manager found, possibly not logged in yet.")
        return

    # Distinct contacts from messages_<username> table
    rows = message_handler.db_manager.conn.execute(
        f"SELECT DISTINCT username FROM messages_{active_username}"
    ).fetchall()

    # Build chat_list
    for (contact_username,) in rows:
        chat_list.append({"id": contact_username, "name": contact_username})

    # For each contact, load message history
    for contact_info in chat_list:
        contact_username = contact_info["id"]
        chat_msgs = message_handler.db_manager.get_messages_by_contact(
            active_username, contact_username
        )

        message_list = []
        for (msg_type, msg_content, stamp) in chat_msgs:
            if msg_type == 'to':
                # Outgoing
                sender_id = active_username
                avatar_url = f'https://robohash.org/{sender_id}?bgset=bg2'
            else:
                # Incoming
                sender_id = contact_username
                avatar_url = f'https://robohash.org/{contact_username}?bgset=bg2'

            message_list.append((sender_id, avatar_url, msg_content, stamp))

        messages[contact_username] = message_list

    print("[INFO] Chat list and messages loaded from DB.")


@ui.page('/')
def main_page():
    """Main page with navigation."""
    ui.label("Welcome to the Nym Client").classes("text-3xl font-bold mb-8")
    ui.button("Login", on_click=lambda: ui.navigate.to("/login")).classes("mb-2")
    ui.button("Register", on_click=lambda: ui.navigate.to("/register"))


@ui.page('/login')
def login_page():
    """Login page with a dropdown for existing users."""
    ui.label("Login").classes("text-2xl font-bold mb-4")

    scan_for_users()

    if usernames:
        selected_user = ui.select(
            usernames, label="Select a User"
        ).props("outlined").classes("mb-2")

        spinner = ui.spinner(size='lg').props('hidden').classes("mt-4")

        async def handle_login():
            if not selected_user.value:
                ui.notify("Please select a user.")
                return

            spinner.props(remove='hidden')
            await message_handler.login_user(selected_user.value)
            await message_handler.login_complete.wait()

            # Load existing chats from DB
            load_chats_from_db()

            spinner.props('hidden')
            ui.navigate.to("/app")

        ui.button("Login", on_click=handle_login).classes("mt-4")
    else:
        ui.label("No users found. Please register first.")

    ui.button("Back to Main Menu", on_click=lambda: ui.navigate.to("/")).classes("mt-4")


@ui.page('/register')
def register_page():
    """Registration page."""
    ui.label("Register a New User").classes("text-2xl font-bold mb-4")
    username_input = ui.input(label="Username").props("outlined").classes("mb-2")
    first_name_input = ui.input(label="First Name (optional)").props("outlined").classes("mb-2")
    last_name_input = ui.input(label="Last Name (optional)").props("outlined").classes("mb-2")

    spinner = ui.spinner(size='lg').props('hidden').classes("mt-4")

    async def register():
        username = username_input.value.strip()
        first_name = first_name_input.value
        last_name = last_name_input.value

        if not username:
            ui.notify("Username is required!")
            return

        spinner.props(remove='hidden')
        await message_handler.register_user(username, first_name, last_name)
        await message_handler.registration_complete.wait()

        spinner.props('hidden')
        ui.notify("Registration completed! Please login.")
        ui.navigate.to("/login")

    ui.button("Register", on_click=register).classes("mt-4")
    ui.button("Back to Main Menu", on_click=lambda: ui.navigate.to("/")).classes("mt-4")


@ui.page('/app')
def chat_page():
    ui.add_css('body { background-color: #121212; color: white; }')
    ui.run_javascript('document.title = "NymCHAT"')
    user_id = message_handler.current_user["username"] or str(uuid4())

    # Sidebar listing of chats
    def chat_list_container():
        with ui.column():
            ui.label('Chats').classes('text-xl font-bold')
            if not chat_list:
                ui.label('No chats yet').classes('text-gray-400')
            for user in chat_list:
                with ui.row().classes('p-2 hover:bg-gray-800 cursor-pointer') \
                        .on('click', lambda u=user: open_chat(u)):
                    ui.label(user["name"]).classes('font-bold text-white')
                    ui.label('Click to open chat').classes('text-gray-400 text-sm')

    # Container for the chat messages
    chat_messages_container = ui.column().classes('w-full max-w-6xl mx-auto items-stretch flex-grow gap-1')

    def render_chat_messages(own_id: str):
        """Draw chat header at the top, followed by the list of messages."""
        chat_messages_container.clear()
        with chat_messages_container:
            # Chat header pinned at the top
            with ui.row().classes('w-full bg-gray-800 text-white p-3 items-center rounded-t-lg'):
                ui.label(f"Chat with {active_chat_user or ''}").classes('text-lg font-bold')

            # Display messages below the header
            if active_chat and active_chat in messages and messages[active_chat]:
                for sender_id, avatar, msg_text, timestamp in messages[active_chat]:
                    ui.chat_message(
                        text=msg_text,
                        stamp=timestamp,
                        avatar=avatar,
                        sent=(own_id == sender_id)
                    ).classes('mx-1')
            else:
                # Minimal message if none exist
                ui.label('No messages yet').classes('mx-auto my-4')

        ui.run_javascript('window.scrollTo(0, document.body.scrollHeight)')
        # Force UI to update in case we're in a background task
        chat_messages_container.update()

    def open_chat(user):
        """Opens a chat with the given user and updates the header."""
        global active_chat, active_chat_user
        active_chat = user["id"]
        active_chat_user = user["name"]
        render_chat_messages(user_id)

    async def send_message():
        """Send the typed message to the current chat partner."""
        if not active_chat or not text.value.strip():
            return
        msg_content = text.value.strip()
        text.value = ''

        # 1) Send message through mixnet & DB
        await message_handler.send_direct_message(active_chat_user, msg_content)

        # 2) Locally append so we see it immediately
        stamp = datetime.now().strftime('%X')
        if active_chat not in messages:
            messages[active_chat] = []
        messages[active_chat].append((
            user_id,
            f'https://robohash.org/{user_id}?bgset=bg2',
            msg_content,
            stamp
        ))

        # 3) Re-render chat UI
        render_chat_messages(user_id)

    ui.add_css(r'a:link, a:visited { color: inherit !important; text-decoration: none; font-weight: 500 }')

    # Top Bar
    with ui.row().classes('w-full bg-gray-900 text-white p-4 items-center justify-between'):
        ui.label('NymCHAT').classes('text-xl font-bold')
        ui.button('Search', on_click=lambda: ui.navigate.to('/search')).classes('bg-blue-500 text-white p-2 rounded')

    # Sidebar Drawer for chat list
    with ui.left_drawer().classes('w-64 bg-gray-900 text-white p-4'):
        chat_list_container()

    # Main Chat Window
    render_chat_messages(user_id)

    # Footer input field
    with ui.footer().classes('w-full bg-gray-900 text-white p-4'):
        with ui.row().classes('w-full items-center'):
            text = ui.input(placeholder='Type a message...') \
                .on('keydown.enter', lambda: asyncio.create_task(send_message())) \
                .props('rounded outlined input-class=mx-3') \
                .classes('flex-grow bg-gray-700 text-white p-2 rounded-lg')
            ui.button('Send', on_click=lambda: asyncio.create_task(send_message())) \
                .classes('bg-blue-500 text-white p-2 rounded')


@ui.page('/search')
def search_page():
    """User Search Page using query messages."""
    ui.add_css('body { background-color: #121212; color: white; }')

    global profile_container
    profile_container = ui.column().classes('mt-4')

    async def search_user():
        username = search_input.value.strip()
        with profile_container:
            profile_container.clear()

            if not username:
                ui.notify("Please enter a username to search.")
                return

            ui.notify(f"Searching for '{username}'...")

        # Send the query to the server (async call)
        result = await message_handler.query_user(username)

        # After the await, we again wrap UI updates in with profile_container:
        with profile_container:
            if result is None:
                ui.notify("Error occurred or no response from server.")
                return

            if isinstance(result, str):
                # "No user found" or some other string
                if result == "No user found":
                    ui.notify("No user found.")
                else:
                    ui.notify(f"Server returned: {result}")

            elif isinstance(result, dict):
                # Show user details from the server
                user_data = result
                with ui.card().classes('p-4 bg-gray-800 text-white rounded-lg shadow-lg w-80'):
                    ui.label(f"Username: {user_data.get('username') or 'N/A'}").classes('text-xl font-bold')
                    ui.label(f"First Name: {user_data.get('firstName') or ''}")
                    ui.label(f"Last Name: {user_data.get('lastName') or ''}")
                    pubkey_short = (user_data.get('publicKey') or '')[:50]
                    ui.label(f"Public Key (partial): {pubkey_short}...")

                    def start_chat():
                        chat_entry = {"id": user_data["username"], "name": user_data["username"]}
                        if chat_entry not in chat_list:
                            chat_list.append(chat_entry)
                        ui.navigate.to('/app')

                    ui.button('Start Chat', on_click=start_chat).classes('bg-green-500 text-white p-2 mt-2 rounded')
            else:
                ui.notify("Unexpected response format from server.")

    with ui.column().classes('w-full h-screen flex justify-center items-center gap-4'):
        with ui.row().classes('w-full bg-gray-900 text-white p-4 items-center justify-between'):
            ui.button('← Back to Chat', on_click=lambda: ui.navigate.to('/')).classes('bg-gray-700 text-white p-2 rounded')

        with ui.row().classes('gap-2 bg-gray-800 p-4 rounded-lg shadow-lg'):
            search_input = ui.input(
                placeholder='Enter username...'
            ).props('rounded outlined input-class=mx-3') \
             .classes('bg-gray-700 text-white p-2 rounded-lg w-64')

            ui.button('Search', on_click=lambda: asyncio.create_task(search_user())) \
                .classes('bg-blue-500 text-white p-2 rounded')


@app.on_startup
async def startup_sequence():
    """Initialize WebSocket and navigate to the main page."""
    scan_for_users()
    try:
        websocket_client.set_message_callback(message_handler.handle_incoming_message)
        await websocket_client.connect()
        print("WebSocket connected successfully.")
    except Exception as e:
        print(f"[ERROR] WebSocket connection failed: {e}")
        ui.notify("WebSocket connection failed.")
    ui.navigate.to("/")


ui.run()
