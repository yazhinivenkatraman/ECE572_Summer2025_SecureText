#!/usr/bin/env python3
"""
Author: Ardeshir S.
Course: ECE 572; Summer 2025
SecureText Console Messenger (Insecure Genesis Version)
A basic console-based messenger application with intentional security vulnerabilities.

Features:
- Account creation with plaintext password storage
- User login
- Send/receive messages via TCP sockets
- Basic password reset functionality
"""

import socket
import threading
import json
import os
import sys
import time
from datetime import datetime
import hashlib
import bcrypt
import time
import base64
import hmac
import pyotp
import qrcode
import io
import requests
import webbrowser
from oauth_callback_server import app, get_auth_code
import threading
import secrets
import hashlib
import base64


GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")

if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
    print("Missing GitHub OAuth credentials. Please set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET.")
    sys.exit(1)

# Pre-shared key
SHARED_KEY = b'secretkey123'

# Helper function for flawed MAC
def generate_flawed_mac(message: str) -> str:
    if isinstance(message, str):
        message = message.encode('latin1')
    return hashlib.md5(SHARED_KEY + message).hexdigest()

def generate_secure_mac(message: str) -> str:
    if isinstance(message, str):
        message = message.encode('utf-8')
    return hmac.new(SHARED_KEY, message, hashlib.sha256).hexdigest()

class SecureTextServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.users_file = 'users.json'
        self.users = self.load_users()
        self.active_connections = {}  # username -> connection
        self.server_socket = None
        # test_hashing_time()
        
    def load_users(self):
        """Load users from JSON file or create empty dict if file doesn't exist"""
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                print(f"Warning: Could not load {self.users_file}, starting with empty user database")
        return {}
    
    def save_users(self):
        """Save users to JSON file with plaintext passwords (INSECURE!)"""
        try:
            with open(self.users_file, 'w') as f:
                json.dump(self.users, f, indent=2)
        except IOError as e:
            print(f"Error saving users: {e}")
    
    def create_account(self, username, password):
        """Create new user account - stores password in PLAINTEXT!"""
        if username in self.users:
            return False, "Username already exists"

        # Updating password hashing to generate 128-bit (16-byte) and store salt manually.
        salt = base64.b64encode(os.urandom(16)).decode()
    
        # Initially combining salt and password, then hashing using bcrypt
        salted_password = password + salt
        password_hash = bcrypt.hashpw(salted_password.encode(), bcrypt.gensalt()).decode()

        # Generate TOTP secret
        totp_secret = pyotp.random_base32()
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="SecureText")

        # Generate ASCII QR code
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        buf = io.StringIO()
        qr.print_ascii(out=buf)
        print("\nScan the following QR code in your authenticator app:\n")
        print(buf.getvalue())

        # SECURITY VULNERABILITY: Storing password in plaintext!
        self.users[username] = {
            'password': password_hash,  # PLAINTEXT PASSWORD!
            'salt': salt,
            'totp_secret': totp_secret,
            'created_at': datetime.now().isoformat(),
            'reset_question': 'What is your favorite color?',
            'reset_answer': 'blue'  # Default for simplicity
        }
        self.save_users()
        return True, "Account created successfully"
    
    def authenticate(self, username, password, totp_code=None):
        """Authenticate user with plaintext password comparison"""
        if username not in self.users:
            return False, "Username not found"

        user = self.users[username]
        stored_hash = user['password']
        stored_salt = user.get('salt')

        if not stored_salt:
            return False, "Salt missing for user. Migration required."
            
        # Recreate hash using stored salt
        salted_password = password + stored_salt

        # Modern user - verify hashed password using bcrypt
        salted_password = password + stored_salt
        if not bcrypt.checkpw(salted_password.encode(), stored_hash.encode()):
            return False, "Invalid password"

        # TOTP check
        if 'totp_secret' in user:
            if not totp_code:
                return False, "Missing TOTP code"
            totp = pyotp.TOTP(user['totp_secret'])
            if not totp.verify(totp_code):
                return False, "Invalid TOTP code"

        return True, "Authentication successful"
    
    def reset_password(self, username, new_password):
        """Basic password reset - just requires existing username"""
        if username not in self.users:
            return False, "Username not found"
        
        # SECURITY VULNERABILITY: No proper verification for password reset!
        #self.users[username]['password'] = new_password

        # While resetting the password, storing it as bcrypt hashed password
        new_password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        self.users[username]['password'] = new_password_hash

        self.save_users()
        return True, "Password reset successful"
    
    def handle_client(self, conn, addr):
        """Handle individual client connection"""
        print(f"New connection from {addr}")
        current_user = None
        
        try:
            while True:
                data = conn.recv(1024).decode('utf-8')
                if not data:
                    break
                
                try:
                    message = json.loads(data)
                    command = message.get('command')
                    
                    if command == 'CREATE_ACCOUNT':
                        username = message.get('username')
                        password = message.get('password')
                        success, msg = self.create_account(username, password)
                        response = {'status': 'success' if success else 'error', 'message': msg}
                        
                    elif command == 'LOGIN':
                        username = message.get('username')
                        password = message.get('password')
                        totp = message.get('totp')
                        success, msg = self.authenticate(username, password, totp)

                        if success:
                            current_user = username
                            self.active_connections[username] = conn
                        response = {'status': 'success' if success else 'error', 'message': msg}
                        
                    elif command == 'SEND_MESSAGE':
                        if not current_user:
                            current_user = message.get('from', 'forged_attacker')
                            print(f"[DEBUG] Forged sender accepted as: {current_user}")
                            response = {'status': 'error', 'message': 'Not logged in'}
                        #else:
                            recipient = message.get('recipient')
                            msg_content = message.get('content')
                            mac = message.get('mac')
                            
                            # Send message to recipient if they're online
                            expected_mac = generate_secure_mac(msg_content)
                            if mac != expected_mac:
                                response = {'status': 'error', 'message': 'MAC verification failed'}
                            elif recipient in self.active_connections:
                                msg_data = {
                                    'type': 'MESSAGE',
                                    'from': current_user,
                                    'content': msg_content,
                                    'timestamp': datetime.now().isoformat(),
                                    'mac': mac
                                }
                                try:
                                    self.active_connections[recipient].send(
                                        json.dumps(msg_data).encode('utf-8')
                                    )
                                    response = {'status': 'success', 'message': 'Message sent'}
                                except:
                                    # Remove inactive connection
                                    del self.active_connections[recipient]
                                    response = {'status': 'error', 'message': 'Recipient is offline'}
                            else:
                                response = {'status': 'error', 'message': 'Recipient is offline'}
                    
                    elif command == 'RESET_PASSWORD':
                        username = message.get('username')
                        new_password = message.get('new_password')
                        success, msg = self.reset_password(username, new_password)
                        response = {'status': 'success' if success else 'error', 'message': msg}
                        
                    elif command == 'LIST_USERS':
                        if not current_user:
                            response = {'status': 'error', 'message': 'Not logged in'}
                        else:
                            online_users = list(self.active_connections.keys())
                            all_users = list(self.users.keys())
                            response = {
                                'status': 'success', 
                                'online_users': online_users,
                                'all_users': all_users
                            }
                    elif command == 'GITHUB_LOGIN':
                        github_id = message.get('github_id')
                        github_username = message.get('github_username')
                        github_email = message.get('github_email')

                        # Try to find matching user by GitHub ID or email
                        matched_user = None
                        for username, data in self.users.items():
                            if data.get('github_id') == github_id or data.get('github_email') == github_email:
                                matched_user = username
                                break

                        if matched_user:
                            # Link if not already linked
                            self.users[matched_user]['github_id'] = github_id
                            self.users[matched_user]['github_username'] = github_username
                            self.users[matched_user]['github_email'] = github_email
                            self.save_users()
                            self.active_connections[matched_user] = conn
                            current_user = matched_user
                            response = {'status': 'success', 'message': f"Logged in as {matched_user} (GitHub linked)"}
                        elif github_username in self.users:
                            existing_user = self.users[github_username]
                            if "github_id" not in existing_user:
                                # Safe to link GitHub account to existing local user
                                existing_user["github_id"] = github_id
                                existing_user["github_username"] = github_username
                                existing_user["github_email"] = github_email
                                self.save_users()
                                self.active_connections[github_username] = conn
                                current_user = github_username
                                response = {'status': 'success', 'message': f"GitHub linked to existing user '{github_username}'"}
                            else:
                                response = {'status': 'error', 'message': f"Username '{github_username}' exists and is already linked. Please contact admin."}
                        else:
                            # Create a new user linked with GitHub
                            self.users[github_username] = {
                            'github_id': github_id,
                            'github_username': github_username,
                            'github_email': github_email,
                            'created_at': datetime.now().isoformat()
                            }
                            self.save_users()
                            self.active_connections[github_username] = conn
                            current_user = github_username
                            response = {'status': 'success', 'message': f"New user '{github_username}' created and logged in via GitHub"}
                    else:
                        response = {'status': 'error', 'message': 'Unknown command'}
                    
                    conn.send(json.dumps(response).encode('utf-8'))
                    
                except json.JSONDecodeError:
                    error_response = {'status': 'error', 'message': 'Invalid JSON'}
                    conn.send(json.dumps(error_response).encode('utf-8'))
                    
        except ConnectionResetError:
            pass
        finally:
            # Clean up connection
            if current_user and current_user in self.active_connections:
                del self.active_connections[current_user]
            conn.close()
            print(f"Connection from {addr} closed")
    
    def start_server(self):
        """Start the TCP server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"SecureText Server started on {self.host}:{self.port}")
            print("Waiting for connections...")
            
            while True:
                conn, addr = self.server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\nServer shutting down...")
        finally:
            if self.server_socket:
                self.server_socket.close()

class SecureTextClient:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.socket = None
        self.logged_in = False
        self.username = None
        self.running = False
        
    def connect(self):
        """Connect to the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            return True
        except ConnectionRefusedError:
            print("Error: Could not connect to server. Make sure the server is running.")
            return False
        except Exception as e:
            print(f"Connection error: {e}")
            return False
    
    def send_command(self, command_data):
        """Send command to server and get response"""
        try:
            self.socket.send(json.dumps(command_data).encode('utf-8'))
            response = self.socket.recv(1024).decode('utf-8')
            return json.loads(response)
        except Exception as e:
            print(f"Communication error: {e}")
            return {'status': 'error', 'message': 'Communication failed'}
    
    def listen_for_messages(self):
        """Listen for incoming messages in a separate thread"""
        while self.running:
            try:
                data = self.socket.recv(1024).decode('utf-8')
                if data:
                    message = json.loads(data)
                    if message.get('type') == 'MESSAGE':
                        # Added MAC verification in Client
                        expected_mac = generate_secure_mac(message['content'])
                        if message.get('mac') == expected_mac:
                            print(f"\n[{message['timestamp']}] {message['from']}: {message['content']} (MAC verified)")
                        else:
                            print(f"\n[{message['timestamp']}] {message['from']}: {message['content']} (MAC failed)")

                        print(">> ", end="", flush=True)
            except:
                break
    
    def create_account(self):
        """Create a new account"""
        print("\n=== Create Account ===")
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        
        if not username or not password:
            print("Username and password cannot be empty!")
            return
        
        command = {
            'command': 'CREATE_ACCOUNT',
            'username': username,
            'password': password
        }
        
        response = self.send_command(command)
        print(f"{response['message']}")
    
    def login(self):
        """Login to the system"""
        print("\n=== Login ===")
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        totp_code = input("Enter TOTP code: ").strip()
        
        command = {
            'command': 'LOGIN',
            'username': username,
            'password': password,
            'totp': totp_code
        }
        
        response = self.send_command(command)
        print(f"{response['message']}")
        
        if response['status'] == 'success':
            self.logged_in = True
            self.username = username
            self.running = True
            
            # Start listening for messages
            listen_thread = threading.Thread(target=self.listen_for_messages)
            listen_thread.daemon = True
            listen_thread.start()
    
    def send_message(self):
        """Send a message to another user"""
        if not self.logged_in:
            print("You must be logged in to send messages!")
            return
        
        print("\n=== Send Message ===")
        recipient = input("Enter recipient username: ").strip()
        msg_type = input("Is this a command message? (y/n): ").strip().lower()

        if msg_type == 'y':
            # Command message
            content = input("Enter command (e.g., CMD=SET_QUOTA&USER=bob&LIMIT=100): ").strip()
        else:
            content = input("Enter regular message: ").strip()
        
        if not recipient or not content:
            print("Recipient and message cannot be empty!")
            return
        
        # Add MAC for message authentication
        mac = generate_secure_mac(content)
        
        command = {
            'command': 'SEND_MESSAGE',
            'recipient': recipient,
            'content': content,
            'mac': mac
        }
        
        response = self.send_command(command)
        print(f"{response['message']}")
    
    def list_users(self):
        """List all users and show who's online"""
        if not self.logged_in:
            print("You must be logged in to list users!")
            return
        
        command = {'command': 'LIST_USERS'}
        response = self.send_command(command)
        
        if response['status'] == 'success':
            print(f"\nOnline users: {', '.join(response['online_users'])}")
            print(f"All users: {', '.join(response['all_users'])}")
        else:
            print(f"Error: {response['message']}")
    
    def reset_password(self):
        """Reset password (basic implementation)"""
        print("\n=== Reset Password ===")
        username = input("Enter username: ").strip()
        new_password = input("Enter new password: ").strip()
        
        command = {
            'command': 'RESET_PASSWORD',
            'username': username,
            'new_password': new_password
        }
        
        response = self.send_command(command)
        print(f"{response['message']}")

    def login_with_github(self):
        code_verifier = secrets.token_urlsafe(64)
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b'=').decode('ascii')     

        # Step 1: Start Flask server in background
        threading.Thread(target=lambda: app.run(port=8080, debug=False)).start()

        # Step 2: Build GitHub OAuth URL
        auth_url = (
            f"https://github.com/login/oauth/authorize"
            f"?client_id={GITHUB_CLIENT_ID}"
            f"&scope=user:email"
            f"&code_challenge={code_challenge}"
            f"&code_challenge_method=S256"
        )

        webbrowser.open(auth_url)

        print("Please complete login in the browser. Waiting for redirect...")

        # Step 3: Wait for the code to be set
        while not get_auth_code():
            time.sleep(1)

        code = get_auth_code()

        # Step 4: Exchange code for token
        token_url = "https://github.com/login/oauth/access_token"
        headers = {'Accept': 'application/json'}
        payload = {
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code
        }
        response = requests.post(token_url, json=payload, headers=headers).json()
        token = response.get("access_token")

        # Step 5: Fetch user info
        user_data = requests.get("https://api.github.com/user", headers={
            "Authorization": f"token {token}"
        }).json()

        email_data = requests.get("https://api.github.com/user/emails", headers={
            "Authorization": f"token {token}"
        }).json()

        github_email = None
        for item in email_data:
            if item.get("primary") and item.get("verified"):
                github_email = item["email"]
                break

        # Fallback if none found
        if not github_email:
            github_email = user_data.get("email", "")

        # Check if GitHub user is already linked to a local user
        github_id = user_data["id"]
        github_username = user_data["login"]

        # Request the full user list from server
        command = {
            'command': 'GITHUB_LOGIN',
            'github_id': github_id,
            'github_username': github_username,
            'github_email': github_email
        }
        response = self.send_command(command)

        if response["status"] == "success":
            self.logged_in = True
            self.username = github_username
            self.running = True

            # Start listening for messages
            listen_thread = threading.Thread(target=self.listen_for_messages)
            listen_thread.daemon = True
            listen_thread.start()
            print(response["message"])
        else:
            print(f"Login error: {response['message']}")


    def run(self):
        """Main client loop"""
        if not self.connect():
            return
        
        print("=== SecureText Messenger (Insecure Version) ===")
        print("WARNING: This is an intentionally insecure implementation for educational purposes!")
        
        while True:
            if not self.logged_in:
                print("\n1. Create Account")
                print("2. Login")
                print("3. Reset Password")
                print("4. Exit")
                print("5. Login with GitHub (OAuth)")
                choice = input("Choose an option: ").strip()
                
                if choice == '1':
                    self.create_account()
                elif choice == '2':
                    self.login()
                elif choice == '3':
                    self.reset_password()
                elif choice == '4':
                    break
                elif choice == '5':
                    self.login_with_github()
                else:
                    print("Invalid choice!")
            else:
                print(f"\nLogged in as: {self.username}")
                print("1. Send Message")
                print("2. List Users")
                print("3. Logout")
                choice = input("Choose an option (or just press Enter to wait for messages): ").strip()
                
                if choice == '1':
                    self.send_message()
                elif choice == '2':
                    self.list_users()
                elif choice == '3':
                    self.logged_in = False
                    self.running = False
                    self.username = None
                    print("Logged out successfully")
                elif choice == '':
                    # Just wait for messages
                    print("Waiting for messages... (press Enter to show menu)")
                    input()
                else:
                    print("Invalid choice!")
        
        if self.socket:
            self.socket.close()
        print("Goodbye!")

# Utility function for testing the hashing speed in SHA-256 and bcrypt methods
def test_hashing_time():
    check_hash_time = input("Enter 1 to test SHA-256 & bcrypt hashing time orelse enter 0: ")
    if check_hash_time == "1":
        # Using sample password to check the timing difference
        password = "TestP@$$word123"

        # Time taken for SHA-256 hashing technique
        start = time.time()
        password_hash = hashlib.sha256(password.encode()).hexdigest() 
        end = time.time()
        print("SHA-256 hashing took " + str(float(end - start)) + " seconds")

        # Time taken for Bcrypt hashing technique
        start = time.time()
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        end = time.time()
        print("Bcrypt hashing took " + str(float(end - start)) + " seconds")
    else:
        pass

def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'server':
        # Run as server
        server = SecureTextServer()
        server.start_server()
    else:
        # Run as client
        client = SecureTextClient()
        client.run()

if __name__ == "__main__":
    main()