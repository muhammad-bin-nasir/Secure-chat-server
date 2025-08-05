# main.py - Complete Railway-Compatible Secure Chat Server
import socket
import threading
import json
import hashlib
import time
import os
from datetime import datetime, timedelta

# Railway configuration
PORT = int(os.environ.get("PORT", 5000))
HOST = '0.0.0.0'

MAX_CLIENTS = 50
BUFFER_SIZE = 16384

# Client storage
clients = {}
client_usernames = {}
username_to_socket = {}

# User authentication
user_database = {}

# Rate limiting
connection_attempts = {}
MAX_ATTEMPTS_PER_IP = 10
RATE_LIMIT_WINDOW = timedelta(minutes=15)

def hash_password(password):
    """Simple password hashing"""
    return hashlib.sha256(password.encode()).hexdigest()

def check_rate_limit(client_ip):
    """Check if IP is rate limited"""
    now = datetime.now()
    
    if client_ip in connection_attempts:
        attempt_info = connection_attempts[client_ip]
        
        if now - attempt_info["last_attempt"] > RATE_LIMIT_WINDOW:
            connection_attempts[client_ip] = {"count": 1, "last_attempt": now}
            return True
        
        if attempt_info["count"] >= MAX_ATTEMPTS_PER_IP:
            return False
        
        connection_attempts[client_ip]["count"] += 1
        connection_attempts[client_ip]["last_attempt"] = now
        return True
    else:
        connection_attempts[client_ip] = {"count": 1, "last_attempt": now}
        return True

def authenticate_user(username, password, public_key):
    """Authenticate user or create new account"""
    if not username or not password or not public_key:
        return {"status": "fail", "message": "Missing credentials"}
    
    if len(username) > 50 or not username.replace('_', '').replace('-', '').isalnum():
        return {"status": "fail", "message": "Invalid username format"}
    
    if len(password) > 128:
        return {"status": "fail", "message": "Password too long"}
    
    password_hash = hash_password(password)
    
    if username in user_database:
        if user_database[username]["password_hash"] == password_hash:
            user_database[username]["public_key"] = public_key
            user_database[username]["last_login"] = datetime.now()
            return {"status": "success", "message": "Welcome back!"}
        else:
            return {"status": "fail", "message": "Invalid password"}
    else:
        user_database[username] = {
            "password_hash": password_hash,
            "public_key": public_key,
            "last_login": datetime.now()
        }
        return {"status": "new_user", "message": "Account created successfully!"}

def broadcast_peer_list():
    """Send updated peer list to all authenticated clients"""
    peer_list = []
    for sock, username in client_usernames.items():
        if username in user_database:
            peer_list.append({
                "username": username,
                "public_key": user_database[username]["public_key"]
            })
    
    peer_message = {
        "type": "peer_list",
        "peers": peer_list
    }
    
    message_data = json.dumps(peer_message).encode()
    
    disconnected_clients = []
    for client_socket in client_usernames.keys():
        try:
            client_socket.sendall(message_data)
        except:
            disconnected_clients.append(client_socket)
    
    for client_socket in disconnected_clients:
        remove_client(client_socket)

def remove_client(client_socket):
    """Remove client from all tracking structures"""
    try:
        if client_socket in client_usernames:
            username = client_usernames[client_socket]
            del client_usernames[client_socket]
            
            if username in username_to_socket:
                del username_to_socket[username]
            
            print(f"[-] User {username} disconnected")
        
        if client_socket in clients:
            del clients[client_socket]
        
        try:
            client_socket.close()
        except:
            pass
        
        if client_usernames:
            broadcast_peer_list()
            
    except Exception as e:
        print(f"[!] Error removing client: {e}")

def is_http_request(data):
    """Check if incoming data is an HTTP request"""
    try:
        decoded = data.decode('utf-8', errors='ignore')
        http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
        first_line = decoded.split('\n')[0].strip()
        return any(first_line.startswith(method + ' ') for method in http_methods)
    except:
        return False

def send_http_response(client_socket):
    """Send HTTP response for web browsers accessing the server"""
    response = """HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Connection: close

<!DOCTYPE html>
<html>
<head>
    <title>🔐 Secure Chat Server</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .status { color: green; font-weight: bold; }
        .info { background: #f0f0f0; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .warning { color: orange; }
    </style>
</head>
<body>
    <h1>🔐 Secure Chat Server</h1>
    <p class="status">✅ Server is running and accepting connections!</p>
    
    <div class="info">
        <h3>Connection Details:</h3>
        <p><strong>For Desktop Clients:</strong></p>
        <ul>
            <li>This server accepts <strong>TCP socket connections</strong> only</li>
            <li>Use your PyQt5 desktop client to connect</li>
            <li>Not accessible via web browser directly</li>
        </ul>
    </div>
    
    <div class="info">
        <h3>Server Statistics:</h3>
        <p>Connected Users: <span id="users">""" + str(len(client_usernames)) + """</span></p>
        <p>Total Registered: <span id="total">""" + str(len(user_database)) + """</span></p>
        <p>Server Uptime: Online</p>
    </div>
    
    <div class="warning">
        <p><strong>Note:</strong> This is a secure chat server. Use the desktop client application to connect and chat securely.</p>
    </div>
</body>
</html>"""
    
    try:
        client_socket.sendall(response.encode())
        client_socket.close()
    except:
        pass

def handle_client(client_socket, client_address):
    """Handle individual client connection"""
    print(f"[+] New connection from {client_address}")
    
    client_ip = client_address[0]
    if not check_rate_limit(client_ip):
        print(f"[!] Rate limit exceeded for {client_ip}")
        try:
            error_msg = json.dumps({
                "type": "auth_result",
                "status": "error",
                "message": "Too many connection attempts. Please try again later."
            }).encode()
            client_socket.sendall(error_msg)
            client_socket.close()
        except:
            pass
        return
    
    clients[client_socket] = {
        "address": client_address,
        "authenticated": False,
        "username": None
    }
    
    try:
        # Set timeout for initial data
        client_socket.settimeout(30)
        initial_data = client_socket.recv(BUFFER_SIZE)
        
        if not initial_data:
            print(f"[!] No initial data received from {client_address}")
            return
        
        # Check if this is an HTTP request (browser accessing the server)
        if is_http_request(initial_data):
            print(f"[i] HTTP request detected from {client_address}, sending web response")
            send_http_response(client_socket)
            return
        
        # Try to parse as JSON (desktop client authentication)
        try:
            auth_payload = json.loads(initial_data.decode())
            
            # Validate expected authentication fields
            if not all(key in auth_payload for key in ["username", "auth", "public_key"]):
                print(f"[!] Missing auth fields from {client_address}")
                error_response = json.dumps({
                    "type": "auth_result",
                    "status": "error",
                    "message": "Missing authentication fields"
                }).encode()
                client_socket.sendall(error_response)
                return
            
            username = auth_payload.get("username", "").strip()
            password = auth_payload.get("auth", "")
            public_key = auth_payload.get("public_key", "")
            
            # Authenticate user
            auth_result = authenticate_user(username, password, public_key)
            
            # Send authentication result
            response = json.dumps({
                "type": "auth_result",
                **auth_result
            }).encode()
            client_socket.sendall(response)
            
            if auth_result["status"] in ["success", "new_user"]:
                # Authentication successful
                clients[client_socket]["authenticated"] = True
                clients[client_socket]["username"] = username
                client_usernames[client_socket] = username
                username_to_socket[username] = client_socket
                
                print(f"[+] User {username} authenticated from {client_address}")
                
                # Remove authentication timeout
                client_socket.settimeout(None)
                
                # Send updated peer list to all clients
                broadcast_peer_list()
                
                # Handle messages from this authenticated client
                handle_authenticated_client(client_socket, username)
            else:
                print(f"[!] Authentication failed for {username} from {client_address}: {auth_result['message']}")
                return
                
        except json.JSONDecodeError as e:
            print(f"[!] Invalid JSON format from {client_address}: {e}")
            print(f"[DEBUG] Received data (first 200 chars): {initial_data[:200]}")
            
            # Send error response
            error_msg = json.dumps({
                "type": "auth_result",
                "status": "error",
                "message": "Invalid authentication data format"
            }).encode()
            try:
                client_socket.sendall(error_msg)
            except:
                pass
            return
        except Exception as e:
            print(f"[!] Auth processing error for {client_address}: {e}")
            error_msg = json.dumps({
                "type": "auth_result",
                "status": "error",
                "message": "Authentication processing error"
            }).encode()
            try:
                client_socket.sendall(error_msg)
            except:
                pass
            return
            
    except socket.timeout:
        print(f"[!] Authentication timeout for {client_address}")
    except Exception as e:
        print(f"[!] Client handling error for {client_address}: {e}")
    finally:
        remove_client(client_socket)

def handle_authenticated_client(client_socket, username):
    """Handle messages from authenticated client"""
    try:
        while True:
            data = client_socket.recv(BUFFER_SIZE)
            if not data:
                print(f"[i] {username} disconnected (no data)")
                break
            
            try:
                message = json.loads(data.decode())
                route_message(client_socket, username, message)
            except json.JSONDecodeError:
                print(f"[!] Invalid message format from {username}")
                continue
            except Exception as e:
                print(f"[!] Message processing error from {username}: {e}")
                continue
                
    except Exception as e:
        print(f"[!] Connection error with {username}: {e}")

def route_message(sender_socket, sender_username, message):
    """Route message to appropriate recipient"""
    msg_type = message.get("type")
    recipient = message.get("to")
    
    if not recipient:
        print(f"[!] No recipient specified in message from {sender_username}")
        return
    
    # Find recipient socket
    recipient_socket = username_to_socket.get(recipient)
    if not recipient_socket:
        print(f"[!] Recipient {recipient} not found for message from {sender_username}")
        return
    
    try:
        # Forward the message to recipient
        message_data = json.dumps(message).encode()
        recipient_socket.sendall(message_data)
        
        # Log message types
        if msg_type == "message":
            print(f"[MSG] {sender_username} -> {recipient}: [encrypted]")
        elif msg_type == "key_exchange":
            print(f"[KEY] {sender_username} -> {recipient}: Key exchange")
        elif msg_type == "file_header":
            filename = message.get("filename", "unknown")
            filesize = message.get("filesize", 0)
            print(f"[FILE] {sender_username} -> {recipient}: Starting '{filename}' ({filesize} bytes)")
        elif msg_type == "file_chunk":
            print(f"[FILE] {sender_username} -> {recipient}: File chunk")
        elif msg_type == "file_end":
            filename = message.get("filename", "unknown")  
            print(f"[FILE] {sender_username} -> {recipient}: Completed '{filename}'")
        else:
            print(f"[MSG] {sender_username} -> {recipient}: {msg_type}")
            
    except Exception as e:
        print(f"[!] Failed to forward message from {sender_username} to {recipient}: {e}")
        # Remove disconnected recipient
        if recipient_socket in client_usernames:
            remove_client(recipient_socket)

def cleanup_old_rate_limits():
    """Clean up old rate limit entries periodically"""
    while True:
        try:
            now = datetime.now()
            expired_ips = [
                ip for ip, info in connection_attempts.items()
                if now - info["last_attempt"] > RATE_LIMIT_WINDOW
            ]
            
            for ip in expired_ips:
                del connection_attempts[ip]
            
            if expired_ips:
                print(f"[CLEANUP] Removed {len(expired_ips)} expired rate limit entries")
            
            # Clean up every 5 minutes
            time.sleep(300)
        except Exception as e:
            print(f"[!] Cleanup error: {e}")
            time.sleep(60)

def print_server_stats():
    """Print server statistics periodically"""
    while True:
        try:
            # Print stats every 5 minutes
            time.sleep(300)
            connected_users = len(client_usernames)
            total_users = len(user_database)
            rate_limited_ips = len(connection_attempts)
            
            print(f"[STATS] Connected: {connected_users}, Total users: {total_users}, Rate-limited IPs: {rate_limited_ips}")
            
            if connected_users > 0:
                usernames = list(client_usernames.values())
                print(f"[STATS] Online: {', '.join(usernames)}")
                
        except Exception as e:
            print(f"[!] Stats error: {e}")

def start_server():
    """Start the secure chat server"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(MAX_CLIENTS)
        
        print("=" * 60)
        print("🔐 SECURE CHAT SERVER - RAILWAY DEPLOYMENT")
        print(f"🌐 Host: {HOST}")
        print(f"🔌 Port: {PORT}")
        print(f"👥 Max clients: {MAX_CLIENTS}")
        print(f"📦 Buffer size: {BUFFER_SIZE} bytes")
        print(f"🕐 Started: {datetime.now()}")
        print("=" * 60)
        print("✅ Server ready for connections...")
        print("🌍 Desktop clients can connect from anywhere!")
        print("🌐 HTTP requests will receive a status page")
        print("-" * 60)
        
        # Start background threads
        threading.Thread(target=cleanup_old_rate_limits, daemon=True).start()
        threading.Thread(target=print_server_stats, daemon=True).start()
        
        # Main server loop
        while True:
            try:
                client_socket, client_address = server_socket.accept()
                
                # Check server capacity
                if len(clients) >= MAX_CLIENTS:
                    print(f"[!] Server at capacity ({MAX_CLIENTS}), rejecting {client_address}")
                    try:
                        error_msg = json.dumps({
                            "type": "auth_result",
                            "status": "error",
                            "message": f"Server at capacity ({MAX_CLIENTS} users). Please try again later."
                        }).encode()
                        client_socket.sendall(error_msg)
                        client_socket.close()
                    except:
                        pass
                    continue
                
                # Start client handler thread
                client_thread = threading.Thread(
                    target=handle_client, 
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()
                
            except Exception as e:
                print(f"[!] Error accepting connection: {e}")
                continue
                
    except KeyboardInterrupt:
        print("\n[*] Server shutdown requested")
    except Exception as e:
        print(f"[!] Server error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("[*] Shutting down server...")
        
        # Close all client connections
        for client_socket in list(clients.keys()):
            try:
                client_socket.close()
            except:
                pass
        
        try:
            server_socket.close()
        except:
            pass
            
        print("[*] Server shutdown complete")

# Entry point
if __name__ == "__main__":
    try:
        start_server()
    except Exception as e:
        print(f"[!] Fatal server error: {e}")
        import traceback
        traceback.print_exc()
