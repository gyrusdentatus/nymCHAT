# runClient.py

import os
import asyncio
from nicegui import ui, app
from uuid import uuid4
from datetime import datetime

from dbUtils import SQLiteManager
from cryptographyUtils import CryptoUtils
from connectionUtils import WebSocketClient
from messageHandler import MessageHandler

###############################################################################
# GLOBAL / IN-MEMORY STATE
###############################################################################
DB_DIR = "./storage"
usernames = []

chat_list = []        # [{"id": <username>, "name": <username>}]
active_chat = None    # currently active chat user ID
active_chat_user = None
messages = {}         # {username: [(sender_id, msg_text, timestamp), ...]}

chat_messages_container = None  # assigned in chat_page()


def set_active_chat(value):
    global active_chat
    active_chat = value

def get_active_chat():
    """Helper so we can pass this function to messageHandler for checking which chat is active."""
    return active_chat

def set_active_chat_user(value):
    global active_chat_user
    active_chat_user = value


###############################################################################
# CREATE CORE OBJECTS
###############################################################################
crypto_utils = CryptoUtils()
websocket_client = WebSocketClient()
message_handler = MessageHandler(crypto_utils, websocket_client)


###############################################################################
# UTILITY: SCAN FOR USERS, LOAD CHATS FROM DB
###############################################################################
def scan_for_users():
    global usernames
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR)
        print("[INFO] Created 'storage' directory for user data.")
        return

    dirs = [
        d for d in os.listdir(DB_DIR)
        if os.path.isdir(os.path.join(DB_DIR, d))
    ]
    usernames = dirs
    print("[INFO] Found local users:", usernames)

def load_chats_from_db():
    """Load the chat_list and messages from DB for the current user."""
    global chat_list, messages
    chat_list.clear()
    messages.clear()

    active_username = message_handler.current_user["username"]
    if not message_handler.db_manager:
        print("[WARNING] DB manager not found; maybe not logged in yet.")
        return

    rows = message_handler.db_manager.conn.execute(
        f"SELECT DISTINCT username FROM messages_{active_username}"
    ).fetchall()

    # build chat_list
    for (contact_username,) in rows:
        chat_list.append({"id": contact_username, "name": contact_username})

    # load messages
    for info in chat_list:
        contact_username = info["id"]
        chat_msgs = message_handler.db_manager.get_messages_by_contact(
            active_username, contact_username
        )

        msg_list = []
        for (msg_type, msg_content, stamp) in chat_msgs:
            sender_id = active_username if msg_type == 'to' else contact_username
            msg_list.append((sender_id, msg_content, stamp))

        messages[contact_username] = msg_list

    print("[INFO] Chat list and messages loaded from DB.")


###############################################################################
# REFRESHABLE UI FOR CHAT
###############################################################################
@ui.refreshable
def render_chat_messages(current_user, target_chat, msg_dict):
    """
    Refresh the chat area to display messages properly, inside a structured column.
    """
    chat_messages_container.clear()  # Clear old messages before re-rendering
    
    ui.label(f"Chat with {target_chat or ''}").classes('text-lg font-bold')

    if not target_chat or target_chat not in msg_dict or not msg_dict[target_chat]:
        ui.label('No messages yet.').classes('mx-auto my-4')
    else:
        with ui.column().classes('w-full max-w-6xl mx-auto items-stretch flex-grow gap-2'):
            for sender_id, text, stamp in msg_dict[target_chat]:
                is_sent = sender_id == current_user  # Check if the message is sent by the user

                # Handle multi-line messages
                text_content = text.split("\n") if "\n" in text else text

                # Create message inside column
                ui.chat_message(
                    text=text_content,
                    stamp=stamp,
                    sent=is_sent
                ).classes('p-3 rounded-lg')

    ui.run_javascript('window.scrollTo(0, document.body.scrollHeight)')  # Auto-scroll to latest message



###############################################################################
# OUTGOING MESSAGES
###############################################################################
async def send_message(text_input):
    if not active_chat or not text_input.value.strip():
        return

    msg_text = text_input.value.strip()
    text_input.value = ''
    current_user = message_handler.current_user["username"]

    # 1) Send
    await message_handler.send_direct_message(active_chat_user, msg_text)

    # 2) Store in local memory
    stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if active_chat not in messages:
        messages[active_chat] = []
    messages[active_chat].append((current_user, msg_text, stamp))

    # 3) Re-render
    render_chat_messages.refresh(current_user, active_chat, messages)


###############################################################################
# PAGE DEFINITIONS
###############################################################################
@ui.page('/')
def main_page():
    with ui.column().classes('w-full max-w-6xl mx-auto items-stretch flex-grow gap-1 flex justify-center items-center h-screen w-full'):
        ui.label("NymCHAT").classes("text-3xl font-bold mb-8")
        ui.button("Login", color="green-6", on_click=lambda: ui.navigate.to("/login")).classes("mb-2")
        ui.button("Register", color="green-6", on_click=lambda: ui.navigate.to("/register"))


@ui.page('/login')
def login_page():
    with ui.column().classes('w-full max-w-6xl mx-auto items-stretch flex-grow gap-1 flex justify-center items-center h-screen w-full'):
        ui.label("Login").classes("text-2xl font-bold mb-4")
        scan_for_users()

        if usernames:
            user_select = ui.select(usernames, label="Select a User").props("outlined").classes("mb-2")
            with ui.row().classes('justify-center w-full'):
                spin = ui.spinner(size='lg').props('hidden').classes("mt-4")

            async def do_login():
                if not user_select.value:
                    ui.notify("Please select a user.")
                    return
                spin.props(remove='hidden')

                await message_handler.login_user(user_select.value)
                await message_handler.login_complete.wait()

                message_handler.set_ui_state(messages, chat_list, get_active_chat, render_chat_messages, chat_messages_container)

                # Once login is finished, load chat data
                load_chats_from_db()

                spin.props('hidden')
                ui.navigate.to("/app")

            ui.button("Login", color="green-6", on_click=do_login).classes("mt-4")
        else:
            ui.label("No users found. Please register first.")

        ui.button("Back", color="green-6", on_click=lambda: ui.navigate.to("/")).classes("mt-4")

@ui.page('/register')
def register_page():
    with ui.column().classes('w-full max-w-6xl mx-auto items-stretch flex-grow gap-1 flex justify-center items-center h-screen w-full'):
        ui.label("Register a New User").classes("text-2xl font-bold mb-4")
        user_in = ui.input(label="Username").props("outlined").classes("mb-2")
        # Removed first and last name fields

        with ui.row().classes('justify-center w-full'):
            spin = ui.spinner(size='lg').props('hidden').classes("mt-4")
            
        async def do_register():
            username = user_in.value.strip()
            if not username:
                ui.notify("Username is required!")
                return

            spin.props(remove='hidden')
            # Call register_user with only the username
            await message_handler.register_user(username)
            await message_handler.registration_complete.wait()

            spin.props('hidden')
            ui.notify("Registration completed! Please login.")
            ui.navigate.to("/login")

        ui.button("Register", color="green-6", on_click=do_register).classes("mt-4")
        ui.button("Back", color="green-6", on_click=lambda: ui.navigate.to("/"))


@ui.page('/app')
def chat_page():
    """
    Main chat page: toggleable chat list (sidebar), chat container, and message input.
    """
    user_id = message_handler.current_user["username"] or str(uuid4())

    global chat_messages_container  # Ensure it is globally accessible

    # Function to show notifications for messages from inactive chats
    def show_new_message_notification(sender, message):
        """Displays a notification when a message is received from an inactive chat."""
        ui.notify(f"New message from {sender}: {message}")

    # Register the notification callback in messageHandler
    message_handler.new_message_callback = show_new_message_notification

    # Ensure chat_messages_container is initialized
    chat_messages_container = ui.column().classes('flex-grow gap-2 overflow-auto')

    # Function to Render Chat List (Sidebar)
    @ui.refreshable
    def chat_list_sidebar():
        """Refreshable chat list sidebar that updates when new chats are added."""
        with ui.column():
            ui.label('Chats').classes('text-xl font-bold')
            if not chat_list:
                ui.label('No chats yet').classes('text-gray-400')
            for info in chat_list:
                with ui.row().classes('p-2 hover:bg-gray-800 cursor-pointer') \
                        .on('click', lambda _, u=info: open_chat(u)):
                    ui.label(info["name"]).classes('font-bold text-white')
                    ui.label('Click to open chat').classes('text-gray-400 text-sm')

    # Function to Open a Chat
    def open_chat(u):
        """When a chat row is clicked in the sidebar, set the active chat and refresh the UI."""
        set_active_chat(u["id"])
        set_active_chat_user(u["name"])
        chat_drawer.toggle()
        if chat_messages_container:
            render_chat_messages.refresh(user_id, active_chat, messages)

    # Sidebar - Left Drawer (Always Visible by Default)
    with ui.left_drawer().classes('w-64 bg-zinc-700 text-white p-4') as chat_drawer:
        chat_list_sidebar()  # Render the chat list inside the drawer

    # Top Bar (Header) with Sidebar Toggle Button
    with ui.header().classes('w-full bg-zinc-800 text-white p-4 items-center justify-between'):
        with ui.row().classes('items-center gap-2'):
            ui.button('☰', color="green-6", on_click=lambda: chat_drawer.toggle()).props('flat color=white')  # Toggle sidebar
            ui.label('NymCHAT').classes('text-xl font-bold')

        ui.button('Search', color="green-6", on_click=lambda: ui.navigate.to('/search')) \
            .classes('bg-blue-500 text-white p-2 rounded')


    # Pass chat_list_sidebar to messageHandler
    message_handler.set_ui_state(messages, chat_list, get_active_chat, render_chat_messages, chat_messages_container, chat_list_sidebar)

    # Main Chat Display
    render_chat_messages(user_id, active_chat, messages)  # Ensure it is called after initialization

    # Footer (Message Input)
    with ui.footer().classes('w-full bg-zinc-800 text-white p-4'):
        with ui.row().classes('w-full items-center'):
            text_in = ui.input(placeholder='Type a message...') \
                .props('rounded outlined input-class=mx-3') \
                .classes('flex-grow bg-zinc-700 text-white p-2 rounded-lg') \
                .on('keydown.enter', lambda: asyncio.create_task(send_message(text_in)))

            ui.button('Send', color="green-6", on_click=lambda: asyncio.create_task(send_message(text_in))) \
                .classes('text-white p-2 rounded')


@ui.page('/search')
def search_page():
    """User Search Page for queries."""
    with ui.header().classes('w-full bg-zinc-950 text-white p-4 justify-between'):
        ui.button('← Back to Chat', color="green-6", on_click=lambda: ui.navigate.to('/app')).classes('text-white p-2 rounded')
    
    with ui.column().classes('w-full max-w-6xl mx-auto items-stretch flex-grow gap-1 w-full items-start p-4'):
        with ui.row().classes('gap-2 bg-zinc-800 p-4 rounded-lg shadow-lg w-full items-center justify-center'):
            search_in = ui.input(placeholder='Enter username...').props('rounded outlined input-style="border-color: red !important;" input-class="focus:border-green-500"').classes('p-2 rounded-lg w-full')
            ui.button('Search', color="green-6", on_click=lambda: asyncio.create_task(do_search())).classes('text-white p-2 rounded')

        global profile_container
        profile_container = ui.column().classes('mt-4')

        async def do_search():
            username = search_in.value.strip()
            with profile_container:
                profile_container.clear()

                if not username:
                    ui.notify("Enter a username to search.")
                    return

                ui.notify(f"Searching for '{username}'...")

            result = await message_handler.query_user(username)

            with profile_container:
                if result is None:
                    ui.notify("Error or no response from server.")
                    return

                if isinstance(result, str):
                    ui.notify(result)
                elif isinstance(result, dict):
                    user_data = result
                    with ui.card().classes('p-4 bg-zinc-700 text-white rounded-lg shadow-lg w-80'):
                        ui.label(f"Username: {user_data.get('username') or 'N/A'}").classes('text-xl font-bold')
                        partial_key = (user_data.get('publicKey') or '')[:50]
                        ui.label(f"Public Key (partial): {partial_key}...")

                        def start_chat():
                            new_chat = {"id": user_data["username"], "name": user_data["username"]}
                            if new_chat not in chat_list:
                                chat_list.append(new_chat)
                            ui.navigate.to('/app')

                        ui.button('Start Chat', color='green-6', on_click=start_chat).classes('text-white p-2 mt-2 rounded')
                else:
                    ui.notify("Unexpected response format from server.")


###############################################################################
# APP STARTUP
###############################################################################
@app.on_startup
async def startup_sequence():
    """Initialize WebSocket, set single callback, and jump to main page."""
    scan_for_users()

    # The single callback from connectionUtils
    # => all inbound messages go to message_handler.handle_incoming_message
    websocket_client.set_message_callback(message_handler.handle_incoming_message)

    try:
        await websocket_client.connect()
        print("[INFO] WebSocket connected successfully.")
    except Exception as e:
        print(f"[ERROR] WebSocket connection failed: {e}")
        ui.notify("WebSocket connection failed.")

    # Now optionally let messageHandler know how to update local chat + UI
    message_handler.set_ui_state(
        messages,               # in-memory messages dict
        chat_list,             # in-memory chat_list
        get_active_chat,       # function to retrieve 'active_chat'
        render_chat_messages,  # your @ui.refreshable function
        chat_messages_container  # container (if needed)
    )

    ui.navigate.to("/")

ui.run(dark=True, host='127.0.0.1', title="NymCHAT")


