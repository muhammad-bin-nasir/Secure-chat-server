# main.py - Railway-Compatible Secure Chat Server (Fixed)
import socket
import threading
import json
import hashlib
import time
import os
import logging
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Railway configuration
PORT = int(os.environ.get("PORT", 5000))
HOST = '0.0.0.0'

# Railway specific settings
RAILWAY_STATIC_URL = os.environ.get("RAILWAY_STATIC_URL", "")
RAILWAY_PUBLIC_DOMAIN = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "")

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
    for client_socket in list(client_usernames.keys()):
        try:
            client_socket.sendall(message_data)
        except Exception as e:
            logger.warning(f"Failed to send peer list to client: {e}")
            disconnected_clients.append(client_socket)
    
    for client_socket in disconnected_clients:
        remove_client(client_socket)

def remove_client(client_socket):
    """Remove client from all tracking structures"""
    try:
        username = None
        if client_socket in client_usernames:
            username = client_usernames[client_socket]
            del client_usernames[client_socket]
            
            if username in username_to_socket:
                del username_to_socket[username]
            
            logger.info(f"User {username} disconnected")
        
        if client_socket in clients:
            del clients[client_socket]
        
        try:
            client_socket.close()
        except:
            pass
        
        # Only broadcast if there are still clients
        if client_usernames:
            broadcast_peer_list()
            
    except Exception as e:
        logger.error(f"Error removing client: {e}")

def is_http_request(data):
    """Check if incoming data is an HTTP request"""
    try:
        if len(data) == 0:
            return False
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
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type

<!DOCTYPE html>
<html>
<head>
    <title>🔐 Secure Chat Server</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            max-width: 600px; 
            margin: 50px auto; 
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .status { color: #28a745; font-weight: bold; font-size: 18px; }
        .info { 
            background: #e9ecef; 
            padding: 15px; 
            border-radius: 5px; 
            margin: 20px 0;
            border-left: 4px solid #007bff;
        }
        .warning { 
            color: #fd7e14; 
            background: #fff3cd;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #ffc107;
        }
        .stats {
            display: flex;
            justify-content: space-between;
            margin: 20px 0;
        }
        .stat-item {
            text-align: center;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
            flex: 1;
            margin: 0 5px;
        }
        .stat-number {
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
        }
        h1 { color: #343a40; text-align: center; }
        h3 { color: #495057; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Secure Chat Server</h1>
        <p class="status">✅ Server is running and accepting connections!</p>
        
        <div class="stats">
            <div class="stat-item">
                <div class="stat-number">""" + str(len(client_usernames)) + """</div>
                <div>Connected Users</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">""" + str(len(user_database)) + """</div>
                <div>Total Registered</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">""" + str(PORT) + """</div>
                <div>Server Port</div>
            </div>
        </div>
        
        <div class="info">
            <h3>📱 For Desktop Clients:</h3>
            <ul>
                <li><strong>Connection Type:</strong> TCP Socket</li>
                <li><strong>Protocol:</strong> JSON over TCP</li>
                <li><strong>Use your PyQt5 desktop client to connect</strong></li>
                <li><strong>Server URL:</strong> This Railway domain</li>
                <li><strong>Port:</strong> """ + str(PORT) + """</li>
            </ul>
        </div>
        
        <div class="info">
            <h3>🔧 Technical Details:</h3>
            <ul>
                <li><strong>Max Clients:</strong> """ + str(MAX_CLIENTS) + """</li>
                <li><strong>Buffer Size:</strong> """ + str(BUFFER_SIZE) + """ bytes</li>
                <li><strong>Rate Limiting:</strong> """ + str(MAX_ATTEMPTS_PER_IP) + """ attempts per 15 minutes</li>
                <li><strong>Deployment:</strong> Railway Cloud Platform</li>
            </ul>
        </div>
        
        <div class="warning">
            <h3>⚠️ Important Notes:</h3>
            <ul>
                <li>This server accepts <strong>desktop client connections only</strong></li>
                <li>Web browsers cannot directly connect to the chat functionality</li>
                <li>All messages are end-to-end encrypted using RSA + AES</li>
                <li>Use the provided PyQt5 client application</li>
            </ul>
        </div>
        
        <div class="info">
            <h3>📊 Server Status:</h3>
            <p><strong>Uptime:</strong> Online since """ + str(datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")) + """</p>
            <p><strong>Health:</strong> ✅ All systems operational</p>
        </div>
    </div>
</body>
</html>"""
    
    try:
        client_socket.sendall(response.encode())
        time.sleep(0.1)  # Small delay to ensure data is sent
        client_socket.close()
    except Exception as e:
        logger.warning(f"Failed to send HTTP response: {e}")

def send_safe_json_response(client_socket, response_data):
    """Safely send JSON response to client"""
    try:
        response_json = json.dumps(response_data)
        response_bytes = response_json.encode('utf-8')
        client_socket.sendall(response_bytes)
        return True
    except Exception as e:
        logger.error(f"Failed to send JSON response: {e}")
        return False

def handle_client(client_socket, client_address):
    """Handle individual client connection"""
    logger.info(f"New connection from {client_address}")
    
    client_ip = client_address[0]
    if not check_rate_limit(client_ip):
        logger.warning(f"Rate limit exceeded for {client_ip}")
        error_response = {
            "type": "auth_result",
            "status": "error",
            "message": "Too many connection attempts. Please try again later."
        }
        send_safe_json_response(client_socket, error_response)
        try:
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
        # Set longer timeout for initial data
        client_socket.settimeout(60)
        initial_data = client_socket.recv(BUFFER_SIZE)
        
        if not initial_data:
            logger.warning(f"No initial data received from {client_address}")
            return
        
        logger.info(f"Received {len(initial_data)} bytes from {client_address}")
        
        # Check if this is an HTTP request (browser accessing the server)
        if is_http_request(initial_data):
            logger.info(f"HTTP request detected from {client_address}, sending web response")
            send_http_response(client_socket)
            return
        
        # Try to parse as JSON (desktop client authentication)
        try:
            # Handle potentially multiple JSON messages in one packet
            data_str = initial_data.decode('utf-8')
            
            # Try to find complete JSON object
            brace_count = 0
            json_end = -1
            for i, char in enumerate(data_str):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        json_end = i + 1
                        break
            
            if json_end > 0:
                json_str = data_str[:json_end]
                auth_payload = json.loads(json_str)
            else:
                auth_payload = json.loads(data_str)
            
            logger.info(f"Parsed auth payload from {client_address}: {list(auth_payload.keys())}")
            
            # Validate expected authentication fields
            required_fields = ["username", "auth", "public_key"]
            missing_fields = [field for field in required_fields if field not in auth_payload]
            
            if missing_fields:
                logger.warning(f"Missing auth fields from {client_address}: {missing_fields}")
                error_response = {
                    "type": "auth_result",
                    "status": "error",
                    "message": f"Missing authentication fields: {', '.join(missing_fields)}"
                }
                send_safe_json_response(client_socket, error_response)
                return
            
            username = auth_payload.get("username", "").strip()
            password = auth_payload.get("auth", "")
            public_key = auth_payload.get("public_key", "")
            
            logger.info(f"Authentication attempt from {client_address} for user: {username}")
            
            # Authenticate user
            auth_result = authenticate_user(username, password, public_key)
            
            # Send authentication result
            response = {
                "type": "auth_result",
                **auth_result
            }
            
            if not send_safe_json_response(client_socket, response):
                logger.error(f"Failed to send auth response to {client_address}")
                return
            
            logger.info(f"Auth result sent to {client_address}: {auth_result['status']}")
            
            if auth_result["status"] in ["success", "new_user"]:
                # Authentication successful
                clients[client_socket]["authenticated"] = True
                clients[client_socket]["username"] = username
                client_usernames[client_socket] = username
                username_to_socket[username] = client_socket
                
                logger.info(f"User {username} authenticated from {client_address}")
                
                # Remove authentication timeout
                client_socket.settimeout(None)
                
                # Send updated peer list to all clients
                broadcast_peer_list()
                
                # Handle messages from this authenticated client
                handle_authenticated_client(client_socket, username)
            else:
                logger.warning(f"Authentication failed for {username} from {client_address}: {auth_result['message']}")
                time.sleep(1)  # Prevent rapid auth attempts
                return
                
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON format from {client_address}: {e}")
            logger.debug(f"Received data (first 500 chars): {initial_data[:500]}")
            
            error_response = {
                "type": "auth_result",
                "status": "error",
                "message": "Invalid authentication data format. Please ensure you're using the desktop client."
            }
            send_safe_json_response(client_socket, error_response)
            return
            
        except UnicodeDecodeError as e:
            logger.error(f"Unicode decode error from {client_address}: {e}")
            error_response = {
                "type": "auth_result",
                "status": "error",
                "message": "Invalid character encoding in request"
            }
            send_safe_json_response(client_socket, error_response)
            return
            
        except Exception as e:
            logger.error(f"Auth processing error for {client_address}: {e}")
            error_response = {
                "type": "auth_result",
                "status": "error",
                "message": "Authentication processing error. Please try again."
            }
            send_safe_json_response(client_socket, error_response)
            return
            
    except socket.timeout:
        logger.warning(f"Authentication timeout for {client_address}")
    except ConnectionResetError:
        logger.info(f"Connection reset by {client_address}")
    except Exception as e:
        logger.error(f"Client handling error for {client_address}: {e}")
    finally:
        remove_client(client_socket)

def handle_authenticated_client(client_socket, username):
    """Handle messages from authenticated client"""
    logger.info(f"Starting message handler for user: {username}")
    
    try:
        while True:
            try:
                # Set a reasonable timeout for receiving messages
                client_socket.settimeout(300)  # 5 minutes timeout
                data = client_socket.recv(BUFFER_SIZE)
                
                if not data:
                    logger.info(f"{username} disconnected (no data)")
                    break
                
                # Remove timeout for processing
                client_socket.settimeout(None)
                
                try:
                    message = json.loads(data.decode('utf-8'))
                    route_message(client_socket, username, message)
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid message format from {username}: {e}")
                    continue
                except UnicodeDecodeError as e:
                    logger.warning(f"Unicode decode error from {username}: {e}")
                    continue
                    
            except socket.timeout:
                logger.info(f"Timeout waiting for message from {username}")
                # Send a ping to check if client is still alive
                try:
                    ping_message = json.dumps({"type": "ping"})
                    client_socket.sendall(ping_message.encode())
                except:
                    logger.info(f"Failed to ping {username}, disconnecting")
                    break
                continue
            except ConnectionResetError:
                logger.info(f"Connection reset by {username}")
                break
            except Exception as e:
                logger.error(f"Message receiving error from {username}: {e}")
                break
                
    except Exception as e:
        logger.error(f"Connection error with {username}: {e}")

def route_message(sender_socket, sender_username, message):
    """Route message to appropriate recipient"""
    try:
        msg_type = message.get("type")
        recipient = message.get("to")
        
        if not recipient:
            logger.warning(f"No recipient specified in message from {sender_username}")
            return
        
        # Find recipient socket
        recipient_socket = username_to_socket.get(recipient)
        if not recipient_socket:
            logger.warning(f"Recipient {recipient} not found for message from {sender_username}")
            # Send error back to sender
            error_msg = {
                "type": "error",
                "message": f"User {recipient} is not online"
            }
            try:
                sender_socket.sendall(json.dumps(error_msg).encode())
            except:
                pass
            return
        
        try:
            # Forward the message to recipient
            message_data = json.dumps(message).encode()
            recipient_socket.sendall(message_data)
            
            # Log message types (but not content for privacy)
            if msg_type == "message":
                logger.info(f"Message: {sender_username} -> {recipient}")
            elif msg_type == "key_exchange":
                logger.info(f"Key exchange: {sender_username} -> {recipient}")
            elif msg_type == "file_header":
                filename = message.get("filename", "unknown")
                filesize = message.get("filesize", 0)
                logger.info(f"File start: {sender_username} -> {recipient}: '{filename}' ({filesize} bytes)")
            elif msg_type == "file_chunk":
                logger.debug(f"File chunk: {sender_username} -> {recipient}")
            elif msg_type == "file_end":
                filename = message.get("filename", "unknown")  
                logger.info(f"File completed: {sender_username} -> {recipient}: '{filename}'")
            else:
                logger.info(f"Message type '{msg_type}': {sender_username} -> {recipient}")
                
        except Exception as e:
            logger.error(f"Failed to forward message from {sender_username} to {recipient}: {e}")
            # Remove disconnected recipient
            if recipient_socket in client_usernames:
                remove_client(recipient_socket)
                
    except Exception as e:
        logger.error(f"Error routing message from {sender_username}: {e}")

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
                logger.info(f"Cleaned up {len(expired_ips)} expired rate limit entries")
            
            # Clean up every 10 minutes
            time.sleep(600)
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
            time.sleep(60)

def print_server_stats():
    """Print server statistics periodically"""
    while True:
        try:
            # Print stats every 10 minutes
            time.sleep(600)
            connected_users = len(client_usernames)
            total_users = len(user_database)
            rate_limited_ips = len(connection_attempts)
            
            logger.info(f"Server Stats - Connected: {connected_users}, Total users: {total_users}, Rate-limited IPs: {rate_limited_ips}")
            
            if connected_users > 0:
                usernames = list(client_usernames.values())
                logger.info(f"Online users: {', '.join(usernames)}")
                
        except Exception as e:
            logger.error(f"Stats error: {e}")

def start_server():
    """Start the secure chat server"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Set socket options for better compatibility
    try:
        server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except:
        pass  # Not critical if this fails
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(MAX_CLIENTS)
        
        logger.info("=" * 60)
        logger.info("🔐 SECURE CHAT SERVER - RAILWAY DEPLOYMENT")
        logger.info(f"🌐 Host: {HOST}")
        logger.info(f"🔌 Port: {PORT}")
        logger.info(f"👥 Max clients: {MAX_CLIENTS}")
        logger.info(f"📦 Buffer size: {BUFFER_SIZE} bytes")
        logger.info(f"🕐 Started: {datetime.now()}")
        logger.info("=" * 60)
        logger.info("✅ Server ready for connections...")
        logger.info("🌍 Desktop clients can connect from anywhere!")
        logger.info("🌐 HTTP requests will receive a status page")
        logger.info("-" * 60)
        
        # Start background threads
        cleanup_thread = threading.Thread(target=cleanup_old_rate_limits, daemon=True)
        cleanup_thread.start()
        
        stats_thread = threading.Thread(target=print_server_stats, daemon=True)
        stats_thread.start()
        
        logger.info("Background threads started")
        
        # Main server loop
        connection_count = 0
        while True:
            try:
                client_socket, client_address = server_socket.accept()
                connection_count += 1
                
                logger.info(f"Connection #{connection_count} from {client_address}")
                
                # Check server capacity
                if len(clients) >= MAX_CLIENTS:
                    logger.warning(f"Server at capacity ({MAX_CLIENTS}), rejecting {client_address}")
                    error_response = {
                        "type": "auth_result",
                        "status": "error",
                        "message": f"Server at capacity ({MAX_CLIENTS} users). Please try again later."
                    }
                    send_safe_json_response(client_socket, error_response)
                    try:
                        client_socket.close()
                    except:
                        pass
                    continue
                
                # Set socket options for the client connection
                try:
                    client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                except:
                    pass  # Not critical if these fail
                
                # Start client handler thread
                client_thread = threading.Thread(
                    target=handle_client, 
                    args=(client_socket, client_address),
                    daemon=True,
                    name=f"Client-{client_address[0]}-{client_address[1]}"
                )
                client_thread.start()
                
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")
                time.sleep(1)  # Prevent rapid error loops
                continue
                
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {e}")
        import traceback
        logger.error(traceback.format_exc())
    finally:
        logger.info("Shutting down server...")
        
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
            
        logger.info("Server shutdown complete")

# Entry point
if __name__ == "__main__":
    try:
        start_server()
    except Exception as e:
        logger.error(f"Fatal server error: {e}")
        import traceback
        logger.error(traceback.format_exc())
