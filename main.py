# main.py - Fixed Railway TCP Server with Proper HTTP Healthcheck
import socket
import threading
import json
import hashlib
import time
import os
import logging
from datetime import datetime, timedelta
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import traceback
import sys
import http.server
import socketserver
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)

# Railway configuration
PORT = int(os.environ.get("PORT", 42721))
HOST = '0.0.0.0'

# HTTP Server for Railway healthcheck
HTTP_PORT = PORT  # Use same port for both HTTP and TCP

# MongoDB configuration
MONGODB_URL = os.environ.get("MONGO_URL")
MONGODB_HOST = os.environ.get("MONGODB_HOST", "localhost")
MONGODB_PORT = int(os.environ.get("MONGODB_PORT", "27017"))
MONGODB_DB = os.environ.get("MONGODB_DB", "secure_chat")
MONGODB_USERNAME = os.environ.get("MONGODB_USERNAME", "")
MONGODB_PASSWORD = os.environ.get("MONGODB_PASSWORD", "")

MAX_CLIENTS = 50
BUFFER_SIZE = 16384

# Client storage
clients = {}
client_usernames = {}
username_to_socket = {}

# MongoDB collections
db = None
users_collection = None
messages_collection = None
sessions_collection = None

# Rate limiting
connection_attempts = {}
MAX_ATTEMPTS_PER_IP = 10
RATE_LIMIT_WINDOW = timedelta(minutes=15)

def init_database():
    """Initialize MongoDB connection"""
    global db, users_collection, messages_collection, sessions_collection
    
    logger.info("🔄 Starting database initialization...")
    
    try:
        if MONGODB_URL:
            logger.info(f"🔐 Connecting to Railway MongoDB via URL")
            client = MongoClient(
                MONGODB_URL,
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=15000,
                socketTimeoutMS=30000
            )
        elif MONGODB_USERNAME and MONGODB_PASSWORD:
            connection_string = f"mongodb://{MONGODB_USERNAME}:{MONGODB_PASSWORD}@{MONGODB_HOST}:{MONGODB_PORT}/"
            logger.info(f"🔐 Connecting to MongoDB with authentication")
            client = MongoClient(
                connection_string,
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=15000,
                socketTimeoutMS=30000
            )
        else:
            connection_string = f"mongodb://{MONGODB_HOST}:{MONGODB_PORT}/"
            logger.info(f"🔓 Connecting to MongoDB without authentication")
            client = MongoClient(
                connection_string,
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=15000,
                socketTimeoutMS=30000
            )
        
        # Test the connection
        client.admin.command('ping')
        logger.info("✅ MongoDB connection successful")
        
        # Get database and collections
        db = client[MONGODB_DB]
        users_collection = db.users
        messages_collection = db.messages
        sessions_collection = db.sessions
        
        # Create indexes
        try:
            users_collection.create_index("username", unique=True)
            messages_collection.create_index([("timestamp", -1)])
            sessions_collection.create_index([("last_activity", 1)], expireAfterSeconds=3600)
            logger.info("📊 Database indexes created successfully")
        except Exception as index_error:
            logger.warning(f"⚠️ Index creation warning: {index_error}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ MongoDB connection failed: {e}")
        logger.warning("🔄 Falling back to in-memory storage")
        return False

def hash_password(password):
    """Simple password hashing with salt"""
    salt = "secure_chat_2024"
    return hashlib.sha256((password + salt).encode()).hexdigest()

def authenticate_user(username, password, public_key):
    """Authenticate user or create new account"""
    logger.debug(f"🔍 Authentication attempt for: {username}")
    
    if not username or not password or not public_key:
        return {"status": "fail", "message": "Missing credentials"}
    
    if len(username) > 50:
        return {"status": "fail", "message": "Username too long"}
        
    if not username.replace('_', '').replace('-', '').isalnum():
        return {"status": "fail", "message": "Invalid username format"}
    
    if len(password) > 128:
        return {"status": "fail", "message": "Password too long"}
    
    password_hash = hash_password(password)
    
    try:
        if users_collection is not None:
            existing_user = users_collection.find_one({"username": username})
            
            if existing_user:
                if existing_user["password_hash"] == password_hash:
                    users_collection.update_one(
                        {"username": username},
                        {
                            "$set": {
                                "public_key": public_key,
                                "last_login": datetime.utcnow()
                            }
                        }
                    )
                    logger.info(f"🔐 User {username} authenticated successfully")
                    return {"status": "success", "message": "Welcome back!"}
                else:
                    return {"status": "fail", "message": "Invalid password"}
            else:
                user_data = {
                    "username": username,
                    "password_hash": password_hash,
                    "public_key": public_key,
                    "created_at": datetime.utcnow(),
                    "last_login": datetime.utcnow()
                }
                users_collection.insert_one(user_data)
                logger.info(f"👤 New user {username} created successfully")
                return {"status": "new_user", "message": "Account created successfully!"}
        else:
            # In-memory fallback
            user_database = getattr(authenticate_user, 'user_database', {})
            
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
                authenticate_user.user_database = user_database
                return {"status": "new_user", "message": "Account created successfully!"}
                
    except Exception as e:
        logger.error(f"❌ Authentication error: {e}")
        return {"status": "fail", "message": "Authentication error"}

def get_user_public_key(username):
    """Get user's public key"""
    try:
        if users_collection is not None:
            user = users_collection.find_one({"username": username})
            return user["public_key"] if user else None
        else:
            user_database = getattr(authenticate_user, 'user_database', {})
            return user_database.get(username, {}).get("public_key")
    except Exception as e:
        logger.error(f"❌ Error getting public key: {e}")
        return None

def broadcast_peer_list():
    """Send updated peer list to all clients"""
    peer_list = []
    
    try:
        if users_collection is not None:
            for sock, username in client_usernames.items():
                public_key = get_user_public_key(username)
                if public_key:
                    peer_list.append({
                        "username": username,
                        "public_key": public_key
                    })
        else:
            user_database = getattr(authenticate_user, 'user_database', {})
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
                disconnected_clients.append(client_socket)
        
        for client_socket in disconnected_clients:
            remove_client(client_socket)
            
    except Exception as e:
        logger.error(f"❌ Error broadcasting peer list: {e}")

def remove_client(client_socket):
    """Remove client from tracking"""
    try:
        username = None
        if client_socket in client_usernames:
            username = client_usernames[client_socket]
            del client_usernames[client_socket]
            
            if username in username_to_socket:
                del username_to_socket[username]
            
            logger.info(f"👋 User {username} disconnected")
        
        if client_socket in clients:
            del clients[client_socket]
        
        try:
            client_socket.close()
        except:
            pass
        
        if client_usernames:
            broadcast_peer_list()
            
    except Exception as e:
        logger.error(f"Error removing client: {e}")

def is_http_request(data):
    """Check if data is HTTP request"""
    try:
        if len(data) == 0:
            return False
        decoded = data.decode('utf-8', errors='ignore')
        http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
        first_line = decoded.split('\n')[0].strip()
        return any(first_line.startswith(method + ' ') for method in http_methods)
    except:
        return False

def send_http_response(client_socket, request_path="/"):
    """Send HTTP response - FIXED FOR RAILWAY HEALTHCHECK"""
    try:
        # Get stats
        total_users = 0
        if users_collection is not None:
            try:
                total_users = users_collection.count_documents({})
            except:
                pass
        else:
            user_database = getattr(authenticate_user, 'user_database', {})
            total_users = len(user_database)
        
        connected_users = len(client_usernames)
        db_status = "✅ MongoDB Connected" if db else "⚠️ In-Memory Storage"
        
        # Simple health check response for Railway
        if request_path == "/" or request_path == "/health":
            health_response = f"""HTTP/1.1 200 OK
Content-Type: application/json
Connection: close
Access-Control-Allow-Origin: *

{{
    "status": "healthy",
    "service": "Secure Chat TCP Server",
    "connected_users": {connected_users},
    "total_users": {total_users},
    "database": "{db_status}",
    "port": {PORT},
    "timestamp": "{datetime.utcnow().isoformat()}"
}}"""
        else:
            # Full web page for other requests
            health_response = f"""HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Connection: close
Access-Control-Allow-Origin: *

<!DOCTYPE html>
<html>
<head>
    <title>🔐 Secure Chat Server - Railway</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, sans-serif; 
            max-width: 800px; 
            margin: 50px auto; 
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
        }}
        .container {{
            background: rgba(255, 255, 255, 0.95);
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
        }}
        .status {{ color: #28a745; font-weight: bold; font-size: 20px; text-align: center; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-item {{
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 15px;
        }}
        .stat-number {{
            font-size: 32px;
            font-weight: bold;
            color: #2196f3;
        }}
        h1 {{ color: #2c3e50; text-align: center; font-size: 2.5em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Secure Chat Server</h1>
        <p class="status">✅ Server is healthy and accepting connections!</p>
        
        <div class="stats">
            <div class="stat-item">
                <div class="stat-number">{connected_users}</div>
                <div>Connected Users</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">{total_users}</div>
                <div>Total Registered</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">{PORT}</div>
                <div>Server Port</div>
            </div>
        </div>
        
        <div style="background: #e3f2fd; padding: 20px; border-radius: 15px; margin: 25px 0;">
            <h3>🚀 Railway Deployment Status</h3>
            <p><strong>Health Check:</strong> ✅ Passing</p>
            <p><strong>Database:</strong> {db_status}</p>
            <p><strong>TCP Server:</strong> ✅ Running on port {PORT}</p>
            <p><strong>Protocol:</strong> JSON over TCP with End-to-End Encryption</p>
        </div>
        
        <div style="background: #fff3e0; padding: 20px; border-radius: 15px;">
            <h3>📱 For Mobile Apps</h3>
            <p>This server requires TCP socket connections. Mobile apps need WebSocket support.</p>
            <p><strong>Server Address:</strong> tramway.proxy.rlwy.net:{PORT}</p>
        </div>
    </div>
</body>
</html>"""
    
        client_socket.sendall(health_response.encode())
        time.sleep(0.1)
        client_socket.close()
        
    except Exception as e:
        logger.warning(f"Failed to send HTTP response: {e}")

def handle_client(client_socket, client_address):
    """Handle client connection - FIXED FOR RAILWAY"""
    logger.info(f"New connection from {client_address}")
    
    clients[client_socket] = {
        "address": client_address,
        "authenticated": False,
        "username": None
    }
    
    try:
        client_socket.settimeout(60)
        initial_data = client_socket.recv(BUFFER_SIZE)
        
        if not initial_data:
            logger.warning(f"No data from {client_address}")
            return
        
        logger.info(f"Received {len(initial_data)} bytes from {client_address}")
        
        # Handle HTTP requests (including Railway healthcheck)
        if is_http_request(initial_data):
            logger.info(f"HTTP request from {client_address}")
            
            # Parse the HTTP request to get the path
            try:
                request_line = initial_data.decode('utf-8').split('\n')[0]
                method, path, version = request_line.split()
                logger.info(f"HTTP {method} {path} from {client_address}")
                send_http_response(client_socket, path)
            except:
                # Default to root path if parsing fails
                send_http_response(client_socket, "/")
            return
        
        # Handle TCP JSON authentication
        try:
            data_str = initial_data.decode('utf-8')
            auth_payload = json.loads(data_str)
            
            logger.info(f"TCP auth from {client_address}: {auth_payload.get('username', 'unknown')}")
            
            username = auth_payload.get("username", "").strip()
            password = auth_payload.get("auth", "")
            public_key = auth_payload.get("public_key", "")
            
            auth_result = authenticate_user(username, password, public_key)
            
            response = {
                "type": "auth_result",
                **auth_result
            }
            
            client_socket.sendall(json.dumps(response).encode())
            
            if auth_result["status"] in ["success", "new_user"]:
                clients[client_socket]["authenticated"] = True
                clients[client_socket]["username"] = username
                client_usernames[client_socket] = username
                username_to_socket[username] = client_socket
                
                logger.info(f"User {username} authenticated from {client_address}")
                
                client_socket.settimeout(None)
                broadcast_peer_list()
                handle_authenticated_client(client_socket, username)
            else:
                logger.warning(f"Auth failed for {username}")
                return
                
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON from {client_address}: {e}")
            return
        except Exception as e:
            logger.error(f"Auth error from {client_address}: {e}")
            return
            
    except socket.timeout:
        logger.warning(f"Timeout from {client_address}")
    except Exception as e:
        logger.error(f"Client error from {client_address}: {e}")
    finally:
        remove_client(client_socket)

def handle_authenticated_client(client_socket, username):
    """Handle messages from authenticated client"""
    logger.info(f"Message handler started for: {username}")
    
    try:
        while True:
            try:
                client_socket.settimeout(300)
                data = client_socket.recv(BUFFER_SIZE)
                
                if not data:
                    logger.info(f"{username} disconnected")
                    break
                
                client_socket.settimeout(None)
                
                try:
                    message = json.loads(data.decode('utf-8'))
                    route_message(client_socket, username, message)
                except json.JSONDecodeError:
                    logger.warning(f"Invalid message from {username}")
                    continue
                    
            except socket.timeout:
                try:
                    ping = json.dumps({"type": "ping"})
                    client_socket.sendall(ping.encode())
                except:
                    break
                continue
            except Exception as e:
                logger.error(f"Message error from {username}: {e}")
                break
                
    except Exception as e:
        logger.error(f"Connection error with {username}: {e}")

def route_message(sender_socket, sender_username, message):
    """Route message to recipient"""
    try:
        recipient = message.get("to")
        if not recipient:
            return
        
        recipient_socket = username_to_socket.get(recipient)
        if not recipient_socket:
            error_msg = {"type": "error", "message": f"User {recipient} not online"}
            try:
                sender_socket.sendall(json.dumps(error_msg).encode())
            except:
                pass
            return
        
        try:
            message_data = json.dumps(message).encode()
            recipient_socket.sendall(message_data)
            
            msg_type = message.get("type")
            if msg_type == "message":
                logger.info(f"💬 {sender_username} -> {recipient}")
            elif msg_type == "file_header":
                filename = message.get("filename", "unknown")
                logger.info(f"📁 File: {sender_username} -> {recipient}: {filename}")
                
        except Exception as e:
            logger.error(f"Failed to route message: {e}")
            if recipient_socket in client_usernames:
                remove_client(recipient_socket)
                
    except Exception as e:
        logger.error(f"Route error: {e}")

def start_server():
    """Start the server - FIXED FOR RAILWAY HEALTHCHECK"""
    # Initialize database
    db_connected = init_database()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(MAX_CLIENTS)
        
        logger.info("=" * 70)
        logger.info("🔐 SECURE CHAT SERVER - RAILWAY DEPLOYMENT (HEALTHCHECK FIXED)")
        logger.info(f"🌐 Host: {HOST}")
        logger.info(f"🔌 Port: {PORT}")
        logger.info(f"👥 Max clients: {MAX_CLIENTS}")
        logger.info(f"💾 Database: {'MongoDB' if db_connected else 'In-Memory'}")
        logger.info("=" * 70)
        logger.info("✅ Server ready - Railway healthcheck will pass!")
        logger.info("🌐 HTTP requests on / return healthcheck JSON")
        logger.info("📱 TCP connections handle chat authentication")
        logger.info("-" * 70)
        
        # Main server loop
        while True:
            try:
                client_socket, client_address = server_socket.accept()
                
                if len(clients) >= MAX_CLIENTS:
                    logger.warning(f"Server at capacity, rejecting {client_address}")
                    try:
                        client_socket.close()
                    except:
                        pass
                    continue
                
                # Handle client in separate thread
                client_thread = threading.Thread(
                    target=handle_client, 
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()
                
            except Exception as e:
                logger.error(f"Accept error: {e}")
                continue
                
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        logger.info("🔄 Shutting down...")
        
        # Close all connections
        for client_socket in list(clients.keys()):
            try:
                client_socket.close()
            except:
                pass
        
        try:
            server_socket.close()
        except:
            pass
            
        logger.info("✅ Server shutdown complete")

if __name__ == "__main__":
    try:
        start_server()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        logger.error(traceback.format_exc())
