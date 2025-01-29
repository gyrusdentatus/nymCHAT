import os
from asyncio import Queue
from nicegui import app, ui
from dbUtils import SQLiteManager
from cryptographyUtils import CryptoUtils
from connectionUtils import WebSocketClient
from messageHandler import MessageHandler

# Utilities
crypto_utils = CryptoUtils()
websocket_client = WebSocketClient()
message_handler = MessageHandler(crypto_utils, websocket_client)
registration_response_queue = Queue()

# Directory to check for `*_client.db` files
DB_DIR = "./storage"
usernames = []

def scan_for_users():
    """Scan the `storage` folder for user directories and extract usernames."""
    global usernames
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR)  # Ensure the storage directory exists
        print("[INFO] No users found. `storage` directory created.")
        return

    user_dirs = [
        d for d in os.listdir(DB_DIR)
        if os.path.isdir(os.path.join(DB_DIR, d))
    ]
    usernames = user_dirs
    print(f"[INFO] Found users: {usernames}")

@ui.page('/app')
def app_page():
    """Main app page with menu and tabs."""
    if not message_handler.current_user["username"]:
        print("Please log in first!")
        ui.navigate.to("/")
        return

    with ui.header().classes(replace='row items-center'):
        ui.label(f"Welcome, {message_handler.current_user['username']}").classes("text-lg font-bold ml-4")
        ui.button("Logout", on_click=lambda: ui.navigate.to("/")).props("flat color=white").classes("ml-auto")

    with ui.tabs() as tabs:
        ui.tab("Chats")
        ui.tab("Contacts")
        ui.tab("Settings")

    with ui.tab_panels(tabs, value="Chats").classes("w-full"):
        with ui.tab_panel("Chats"):
            ui.label("This is the Chats tab.")
        with ui.tab_panel("Contacts"):
            ui.label("This is the Contacts tab.")
        with ui.tab_panel("Settings"):
            ui.label("This is the Settings tab.")

@ui.page('/')
def main_page():
    """Main page with navigation to login and registration."""
    ui.label("Welcome to the Nym Client").classes("text-3xl font-bold mb-8")
    ui.button("Login", on_click=lambda: ui.navigate.to("/login")).classes("mb-2")
    ui.button("Register", on_click=lambda: ui.navigate.to("/register"))

@ui.page('/login')
def login_page():
    """Login page with dropdown for existing users."""
    ui.label("Login").classes("text-2xl font-bold mb-4")

    scan_for_users()

    if usernames:
        selected_user = ui.select(
            usernames, label="Select a User"
        ).props("outlined").classes("mb-2")

        spinner = ui.spinner(size='lg').props('hidden').classes("mt-4")  # Initially hidden

        async def handle_login():
            spinner.props(remove='hidden')  # Show spinner
            await message_handler.login_user(selected_user.value)

            print("[INFO] Waiting for login handshake to complete...")
            await message_handler.login_complete.wait()  # Wait for confirmation before redirecting

            spinner.props('hidden')  # Hide spinner
            print("[INFO] Login fully completed. Redirecting to /app...")
            ui.navigate.to("/app")  # Redirect only when done

        ui.button("Login", on_click=handle_login).classes("mt-4")
    else:
        ui.label("No users found. Please register first.")
    
    ui.button("Back to Main Menu", on_click=lambda: ui.navigate.to("/")).classes("mt-4")

@ui.page('/register')
def register_page():
    """Registration page with a form for new users."""
    ui.label("Register a New User").classes("text-2xl font-bold mb-4")
    username_input = ui.input(label="Username").props("outlined").classes("mb-2")
    first_name_input = ui.input(label="First Name (optional)").props("outlined").classes("mb-2")
    last_name_input = ui.input(label="Last Name (optional)").props("outlined").classes("mb-2")

    spinner = ui.spinner(size='lg').props('hidden').classes("mt-4")  # Initially hidden

    async def register():
        username = username_input.value
        first_name = first_name_input.value
        last_name = last_name_input.value

        if not username:
            print("Username is required!")
            ui.notify("Username is required!")
            return

        spinner.props(remove='hidden')  # Show spinner while waiting
        await message_handler.register_user(username, first_name, last_name)

        print("[INFO] Waiting for registration handshake to complete...")
        await message_handler.registration_complete.wait()  # Wait for confirmation before redirecting

        spinner.props('hidden')  # Hide spinner after registration
        print("[INFO] Registration fully completed. Redirecting to login page...")
        ui.navigate.to("/login")  # Redirect only when done

    ui.button("Register", on_click=register).classes("mt-4")
    ui.button("Back to Main Menu", on_click=lambda: ui.navigate.to("/")).classes("mt-4")

@app.on_startup
async def startup_sequence():
    """Handle startup actions."""
    scan_for_users()
    try:
        websocket_client.set_message_callback(message_handler.handle_incoming_message)  # Set the general message handler
        await websocket_client.connect()
        print("WebSocket connected successfully.")
    except Exception as e:
        print(f"WebSocket connection failed: {e}")
        ui.notify("WebSocket connection failed.")

ui.run()
