#!/usr/bin/env python3
import os
from nicegui import app, ui
from dbUtils import SQLiteManager
from cryptographyUtils import CryptoUtils
from connectionUtils import WebSocketClient

# Utilities
crypto_utils = CryptoUtils()
websocket_client = WebSocketClient()

# Directory to check for `*_client.db` files
DB_DIR = "./"
usernames = []
current_user = {"username": None}  # Track the currently logged-in user


def scan_for_users():
    """Scan for `*_client.db` files and extract usernames."""
    global usernames
    db_files = [f for f in os.listdir(DB_DIR) if f.endswith("_client.db")]
    usernames = [os.path.splitext(f)[0].replace("_client", "") for f in db_files]


async def register_user(username, first_name="", last_name=""):
    """Register a new user."""
    private_key, public_key = crypto_utils.generate_key_pair(username)
    db_manager = SQLiteManager(f"{username}_client.db")
    db_manager.register_user(username, first_name, last_name)
    await websocket_client.send_message({
        "type": "register",
        "username": username,
        "public_key": public_key,
    })

    # Print success message to the terminal
    print(f"User {username} registered successfully!")

    # Refresh the username list
    scan_for_users()

    # Navigate back to the main page
    ui.navigate.to("/")


async def login_user(username):
    """Log in a user."""
    current_user["username"] = username
    await websocket_client.send_message({
        "type": "update",
        "username": username,
    })

    # Print success message to the terminal
    print(f"Welcome back, {username}!")
    ui.navigate.to("/app")


# App Tabs
def chats_tab():
    with ui.column().classes("items-center"):
        ui.label("Chats").classes("text-2xl font-bold mb-4")
        ui.label("This is the Chats tab. Here you can display and manage chats.")


def contacts_tab():
    with ui.column().classes("items-center"):
        ui.label("Contacts").classes("text-2xl font-bold mb-4")
        ui.label("This is the Contacts tab. Here you can display and manage contacts.")


def settings_tab():
    with ui.column().classes("items-center"):
        ui.label("Settings").classes("text-2xl font-bold mb-4")
        ui.label("This is the Settings tab. Adjust your preferences here.")


@ui.page('/app')
def app_page():
    """Main app page with menu and tabs."""
    if not current_user["username"]:
        print("Please log in first!")
        ui.navigate.to("/")
        return

    with ui.header().classes(replace='row items-center'):
        ui.label(f"Welcome, {current_user['username']}").classes("text-lg font-bold ml-4")
        ui.button("Logout", on_click=lambda: ui.navigate.to("/")).props("flat color=white").classes("ml-auto")

    with ui.tabs() as tabs:
        ui.tab("Chats")
        ui.tab("Contacts")
        ui.tab("Settings")

    with ui.tab_panels(tabs, value="Chats").classes("w-full"):
        with ui.tab_panel("Chats"):
            chats_tab()
        with ui.tab_panel("Contacts"):
            contacts_tab()
        with ui.tab_panel("Settings"):
            settings_tab()


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
    if usernames:
        selected_user = ui.select(usernames, label="Select a User").props("outlined").classes("mb-2")

        async def handle_login():
            await login_user(selected_user.value)

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

    async def register():
        username = username_input.value
        first_name = first_name_input.value
        last_name = last_name_input.value

        if not username:
            print("Username is required!")
            return

        await register_user(username, first_name, last_name)

    ui.button("Register", on_click=register).classes("mt-4")
    ui.button("Back to Main Menu", on_click=lambda: ui.navigate.to("/")).classes("mt-4")


@app.on_startup
async def startup_sequence():
    """Handle startup actions."""
    scan_for_users()
    try:
        await websocket_client.connect()
        print("WebSocket connected successfully.")
    except Exception as e:
        print(f"WebSocket connection failed: {e}")


ui.run(host="127.0.0.1", port=8080)

