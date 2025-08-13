# main.py - Enhanced Secure Chat Server
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
import base64
from typing import Dict, Optional, List, Any
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

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

# Server configuration
PORT = int(os.environ.get("PORT", 42721))
HOST = '0.0.0.0'
HEALTH_CHECK_PORT = PORT  # Railway health check on same port

# MongoDB configuration
MONGODB_URL = os.environ.get("MONGO_URL")
MONGODB_HOST = os.environ.get("MONGODB_HOST", "localhost")
MONGODB_PORT = int(os.environ.get("MONGODB_PORT", "27017"))
MONGODB_DB = os.environ.get("MONGODB_DB", "secure_chat")
MONGODB_USERNAME = os.environ.get("MONGODB_USERNAME", "")
MONGODB_PASSWORD = os.environ.get("MONGODB_PASSWORD", "")

# Server limits
MAX_CLIENTS = 100
BUFFER_SIZE = 16384
MAX_MESSAGE_SIZE = 50 * 1024 * 1024  # 50MB for file transfers
MAX_USERNAME_LENGTH = 50
MAX_PASSWORD_LENGTH = 128

# Client storage
clients: Dict[socket.socket, Dict[str, Any]] = {}
client_usernames: Dict[socket.socket, str] = {}
username_to_socket: Dict[str, socket.socket] = {}
active_channels: Dict[str, List[str]] = {}  # channel_name -> [usernames]

# MongoDB collections
db = None
users_collection = None
messages_collection = None
sessions_collection = None
channels_collection = None

# Rate limiting
connection_attempts: Dict[str, List[datetime]] = {}
MAX_ATTEMPTS_PER_IP = 10
RATE_LIMIT_WINDOW = timedelta(minutes=15)

class MessageTypes:
    """Message type constants"""
    AUTH_REQUEST = "auth_request"
    AUTH_RESPONSE = "auth_response"
    MESSAGE = "message"
    FILE_HEADER = "file_header"
    FILE_CHUNK = "file_chunk"
    FILE_COMPLETE = "file_complete"
    PEER_LIST = "peer_list"
    USER_STATUS = "user_status"
    CHANNEL_CREATE = "channel_create"
    CHANNEL_JOIN = "channel_join"
    CHANNEL_LEAVE = "channel_leave"
    CHANNEL_MESSAGE = "channel_message"
    CHANNEL_LIST = "channel_list"
    TYPING_INDICATOR = "typing_indicator"
    PING = "ping"
    PONG = "pong"
    ERROR = "error"
    SUCCESS = "success"

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTP server for health checks"""
    daemon_threads = True
    allow_reuse_address = True

class HealthCheckHandler(BaseHTTPRequestHandler):
    """HTTP handler for Railway health checks"""
    
    def do_GET(self):
        """Handle GET requests for health checks"""
        try:
            # Get server statistics
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
            db_status = "MongoDB Connected" if db else "In-Memory Storage"
            
            # Health check response
            if self.path in ['/', '/health', '/status']:
                response_data = {
                    "status": "healthy",
                    "service": "Enhanced Secure Chat Server",
                    "version": "2.0",
                    "connected_users": connected_users,
                    "total_registered_users": total_users,
                    "database_status": db_status,
                    "server_port": PORT,
                    "max_clients": MAX_CLIENTS,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "uptime_check": "passing"
                }
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Cache-Control', 'no-cache')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                self.wfile.write(json.dumps(response_data, indent=2).encode())
            else:
                # Send simple OK for other paths
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'OK')
                
        except Exception as e:
            logger.error(f"Health check error: {e}")
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            error_response = {"status": "error", "message": str(e)}
            self.wfile.write(json.dumps(error_response).encode())
    
    def do_HEAD(self):
        """Handle HEAD requests"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
    
    def log_message(self, format, *args):
        """Override to use our logger"""
        logger.debug(f"HTTP: {format % args}")

def start_health_check_server():
    """Start dedicated HTTP server for Railway health checks"""
    try:
        # Try to start on the main port first
        try:
            httpd = ThreadedHTTPServer((HOST, HEALTH_CHECK_PORT), HealthCheckHandler)
            logger.info(f"🌐 Health check server started on {HOST}:{HEALTH_CHECK_PORT}")
            httpd.serve_forever()
        except OSError as e:
            if "Address already in use" in str(e):
                # Port is busy, try alternative approach
                logger.warning(f"Port {HEALTH_CHECK_PORT} busy for HTTP, using fallback")
                # We'll handle HTTP in the main TCP server
                return
            else:
                raise e
    except Exception as e:
        logger.error(f"Failed to start health check server: {e}")

# Global server reference for health checks
tcp_server_socket = None

def init_database() -> bool:
    """Initialize MongoDB connection with enhanced error handling"""
    global db, users_collection, messages_collection, sessions_collection, channels_collection
    
    logger.info("🔄 Starting database initialization...")
    
    try:
        if MONGODB_URL:
            logger.info("🔐 Connecting to Railway MongoDB via URL")
            client = MongoClient(
                MONGODB_URL,
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=15000,
                socketTimeoutMS=30000,
                maxPoolSize=50
            )
        elif MONGODB_USERNAME and MONGODB_PASSWORD:
            connection_string = f"mongodb://{MONGODB_USERNAME}:{MONGODB_PASSWORD}@{MONGODB_HOST}:{MONGODB_PORT}/"
            logger.info("🔐 Connecting to MongoDB with authentication")
            client = MongoClient(
                connection_string,
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=15000,
                socketTimeoutMS=30000,
                maxPoolSize=50
            )
        else:
            connection_string = f"mongodb://{MONGODB_HOST}:{MONGODB_PORT}/"
            logger.info("🔓 Connecting to MongoDB without authentication")
            client = MongoClient(
                connection_string,
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=15000,
                socketTimeoutMS=30000,
                maxPoolSize=50
            )
        
        # Test the connection
        client.admin.command('ping')
        logger.info("✅ MongoDB connection successful")
        
        # Get database and collections
        db = client[MONGODB_DB]
        users_collection = db.users
        messages_collection = db.messages
        sessions_collection = db.sessions
        channels_collection = db.channels
        
        # Create indexes for better performance
        try:
            users_collection.create_index("username", unique=True)
            users_collection.create_index("email", unique=True, sparse=True)
            messages_collection.create_index([("timestamp", -1)])
            messages_collection.create_index([("sender", 1), ("recipient", 1)])
            sessions_collection.create_index([("last_activity", 1)], expireAfterSeconds=3600)
            channels_collection.create_index("name", unique=True)
            channels_collection.create_index("created_by")
            logger.info("📊 Database indexes created successfully")
        except Exception as index_error:
            logger.warning(f"⚠️ Index creation warning: {index_error}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ MongoDB connection failed: {e}")
        logger.warning("🔄 Falling back to in-memory storage")
        return False

def hash_password(password: str) -> str:
    """Enhanced password hashing with salt and multiple rounds"""
    salt = "secure_chat_2024_enhanced_salt"
    # Use multiple rounds for better security
    hashed = password + salt
    for _ in range(10000):  # 10k rounds
        hashed = hashlib.sha256(hashed.encode()).hexdigest()
    return hashed

def validate_credentials(username: str, password: str, public_key: str = None) -> Dict[str, str]:
    """Validate user credentials with enhanced checks"""
    errors = []
    
    if not username or not username.strip():
        errors.append("Username is required")
    elif len(username) > MAX_USERNAME_LENGTH:
        errors.append(f"Username must be {MAX_USERNAME_LENGTH} characters or less")
    elif not username.replace('_', '').replace('-', '').replace('.', '').isalnum():
        errors.append("Username can only contain letters, numbers, dots, hyphens, and underscores")
    
    if not password:
        errors.append("Password is required")
    elif len(password) > MAX_PASSWORD_LENGTH:
        errors.append(f"Password must be {MAX_PASSWORD_LENGTH} characters or less")
    elif len(password) < 6:
        errors.append("Password must be at least 6 characters long")
    
    if public_key and len(public_key) > 4096:  # Reasonable limit for RSA keys
        errors.append("Public key is too long")
    
    return {"valid": len(errors) == 0, "errors": errors}

def authenticate_user(username: str, password: str, public_key: str = None, email: str = None) -> Dict[str, Any]:
    """Enhanced user authentication with email support"""
    logger.debug(f"🔍 Authentication attempt for: {username}")
    
    # Validate input
    validation = validate_credentials(username, password, public_key)
    if not validation["valid"]:
        return {"status": "fail", "message": "; ".join(validation["errors"])}
    
    password_hash = hash_password(password)
    
    try:
        if users_collection is not None:
            existing_user = users_collection.find_one({"username": username})
            
            if existing_user:
                # Existing user login
                if existing_user["password_hash"] == password_hash:
                    # Update user info
                    update_data = {
                        "last_login": datetime.utcnow(),
                        "login_count": existing_user.get("login_count", 0) + 1
                    }
                    if public_key:
                        update_data["public_key"] = public_key
                    if email:
                        update_data["email"] = email
                    
                    users_collection.update_one(
                        {"username": username},
                        {"$set": update_data}
                    )
                    
                    logger.info(f"🔐 User {username} authenticated successfully")
                    return {
                        "status": "success", 
                        "message": "Welcome back!",
                        "user_data": {
                            "username": username,
                            "email": existing_user.get("email"),
                            "created_at": existing_user.get("created_at"),
                            "login_count": update_data["login_count"]
                        }
                    }
                else:
                    logger.warning(f"🚫 Invalid password for {username}")
                    return {"status": "fail", "message": "Invalid password"}
            else:
                # New user registration
                user_data = {
                    "username": username,
                    "password_hash": password_hash,
                    "email": email,
                    "public_key": public_key,
                    "created_at": datetime.utcnow(),
                    "last_login": datetime.utcnow(),
                    "login_count": 1,
                    "status": "active"
                }
                
                try:
                    users_collection.insert_one(user_data)
                    logger.info(f"👤 New user {username} created successfully")
                    return {
                        "status": "new_user", 
                        "message": "Account created successfully!",
                        "user_data": {
                            "username": username,
                            "email": email,
                            "created_at": user_data["created_at"],
                            "login_count": 1
                        }
                    }
                except Exception as e:
                    if "duplicate key" in str(e).lower():
                        if "username" in str(e):
                            return {"status": "fail", "message": "Username already exists"}
                        elif "email" in str(e):
                            return {"status": "fail", "message": "Email already registered"}
                    raise e
        else:
            # In-memory fallback
            user_database = getattr(authenticate_user, 'user_database', {})
            
            if username in user_database:
                if user_database[username]["password_hash"] == password_hash:
                    user_database[username].update({
                        "public_key": public_key,
                        "last_login": datetime.now(),
                        "login_count": user_database[username].get("login_count", 0) + 1
                    })
                    return {"status": "success", "message": "Welcome back!"}
                else:
                    return {"status": "fail", "message": "Invalid password"}
            else:
                user_database[username] = {
                    "password_hash": password_hash,
                    "public_key": public_key,
                    "email": email,
                    "created_at": datetime.now(),
                    "last_login": datetime.now(),
                    "login_count": 1
                }
                authenticate_user.user_database = user_database
                return {"status": "new_user", "message": "Account created successfully!"}
                
    except Exception as e:
        logger.error(f"❌ Authentication error: {e}")
        return {"status": "fail", "message": "Authentication error occurred"}

def get_user_public_key(username: str) -> Optional[str]:
    """Get user's public key"""
    try:
        if users_collection is not None:
            user = users_collection.find_one({"username": username}, {"public_key": 1})
            return user["public_key"] if user and "public_key" in user else None
        else:
            user_database = getattr(authenticate_user, 'user_database', {})
            return user_database.get(username, {}).get("public_key")
    except Exception as e:
        logger.error(f"❌ Error getting public key for {username}: {e}")
        return None

def get_online_users() -> List[Dict[str, Any]]:
    """Get list of currently online users with their public keys"""
    online_users = []
    
    try:
        for sock, username in client_usernames.items():
            public_key = get_user_public_key(username)
            user_info = {
                "username": username,
                "status": "online",
                "public_key": public_key
            }
            online_users.append(user_info)
        
        return online_users
        
    except Exception as e:
        logger.error(f"❌ Error getting online users: {e}")
        return []

def broadcast_peer_list():
    """Send updated peer list to all authenticated clients"""
    try:
        online_users = get_online_users()
        
        peer_message = {
            "type": MessageTypes.PEER_LIST,
            "peers": online_users,
            "total_online": len(online_users),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        broadcast_to_authenticated(peer_message)
        logger.debug(f"📋 Broadcasted peer list to {len(client_usernames)} users")
        
    except Exception as e:
        logger.error(f"❌ Error broadcasting peer list: {e}")

def broadcast_user_status(username: str, status: str, exclude_socket: socket.socket = None):
    """Broadcast user status change to all clients"""
    try:
        status_message = {
            "type": MessageTypes.USER_STATUS,
            "username": username,
            "status": status,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        broadcast_to_authenticated(status_message, exclude_socket)
        
    except Exception as e:
        logger.error(f"❌ Error broadcasting user status: {e}")

def broadcast_to_authenticated(message: Dict[str, Any], exclude_socket: socket.socket = None):
    """Broadcast message to all authenticated clients"""
    message_data = json.dumps(message).encode()
    disconnected_clients = []
    
    for client_socket, username in client_usernames.items():
        if client_socket == exclude_socket:
            continue
            
        try:
            client_socket.sendall(message_data)
        except Exception as e:
            logger.warning(f"Failed to send to {username}: {e}")
            disconnected_clients.append(client_socket)
    
    # Clean up disconnected clients
    for client_socket in disconnected_clients:
        remove_client(client_socket)

def remove_client(client_socket: socket.socket):
    """Remove client from all tracking structures"""
    try:
        username = client_usernames.get(client_socket)
        
        if username:
            logger.info(f"👋 User {username} disconnected")
            
            # Remove from tracking
            if client_socket in client_usernames:
                del client_usernames[client_socket]
            
            if username in username_to_socket:
                del username_to_socket[username]
            
            # Remove from channels
            for channel_name, members in active_channels.items():
                if username in members:
                    members.remove(username)
            
            # Broadcast status change
            broadcast_user_status(username, "offline", exclude_socket=client_socket)
        
        # Remove from clients dict
        if client_socket in clients:
            del clients[client_socket]
        
        # Close socket
        try:
            client_socket.close()
        except:
            pass
        
        # Update peer list if there are still connected users
        if client_usernames:
            broadcast_peer_list()
            
    except Exception as e:
        logger.error(f"❌ Error removing client: {e}")

def is_http_request(data: bytes) -> bool:
    """Check if incoming data is an HTTP request"""
    try:
        if not data:
            return False
        
        decoded = data.decode('utf-8', errors='ignore')
        http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
        first_line = decoded.split('\n')[0].strip()
        
        return any(first_line.startswith(method + ' ') for method in http_methods)
    except:
        return False

def send_http_response(client_socket: socket.socket, request_path: str = "/"):
    """Send HTTP response for health checks and web interface"""
    try:
        # Get server statistics
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
        
        # Health check endpoint for Railway
        if request_path in ["/", "/health", "/status"]:
            health_response = f"""HTTP/1.1 200 OK
Content-Type: application/json
Connection: close
Access-Control-Allow-Origin: *
Cache-Control: no-cache

{{
    "status": "healthy",
    "service": "Enhanced Secure Chat Server",
    "version": "2.0",
    "connected_users": {connected_users},
    "total_registered_users": {total_users},
    "database_status": "{db_status}",
    "server_port": {PORT},
    "max_clients": {MAX_CLIENTS},
    "features": [
        "End-to-End Encryption",
        "File Transfer",
        "Channel Support",
        "Real-time Messaging",
        "User Authentication",
        "MongoDB Integration"
    ],
    "timestamp": "{datetime.utcnow().isoformat()}Z",
    "uptime_check": "passing"
}}"""
        else:
            # Full web interface
            health_response = f"""HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Connection: close
Access-Control-Allow-Origin: *
Cache-Control: no-cache

<!DOCTYPE html>
<html lang="en">
<head>
    <title>🔐 Enhanced Secure Chat Server</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta charset="utf-8">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.95);
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.15);
        }}
        .header {{ text-align: center; margin-bottom: 40px; }}
        h1 {{ color: #2c3e50; font-size: 2.5em; margin-bottom: 10px; }}
        .version {{ color: #7f8c8d; font-size: 1.1em; }}
        .status {{ 
            color: #27ae60; 
            font-weight: bold; 
            font-size: 1.3em; 
            text-align: center;
            margin: 20px 0;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-item {{
            text-align: center;
            padding: 25px;
            background: #f8f9fa;
            border-radius: 15px;
            border: 1px solid #e9ecef;
        }}
        .stat-number {{
            font-size: 36px;
            font-weight: bold;
            color: #3498db;
            margin-bottom: 5px;
        }}
        .stat-label {{ color: #6c757d; font-weight: 500; }}
        .features {{
            background: #e8f5e8;
            padding: 25px;
            border-radius: 15px;
            margin: 25px 0;
        }}
        .features h3 {{ color: #2c3e50; margin-bottom: 15px; }}
        .feature-list {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 10px;
        }}
        .feature-item {{ 
            padding: 8px 0; 
            color: #27ae60;
            font-weight: 500;
        }}
        .technical-info {{
            background: #e3f2fd;
            padding: 25px;
            border-radius: 15px;
            margin: 25px 0;
        }}
        .tech-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .tech-item {{
            display: flex;
            justify-content: space-between;
            padding: 8px 12px;
            background: rgba(255,255,255,0.7);
            border-radius: 8px;
            font-size: 0.9em;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #e9ecef;
            color: #6c757d;
        }}
        @media (max-width: 768px) {{
            .container {{ padding: 20px; }}
            h1 {{ font-size: 2em; }}
            .stats {{ grid-template-columns: 1fr 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Enhanced Secure Chat Server</h1>
            <div class="version">Version 2.0 - Production Ready</div>
            <div class="status">✅ Server is healthy and accepting connections!</div>
        </div>
        
        <div class="stats">
            <div class="stat-item">
                <div class="stat-number">{connected_users}</div>
                <div class="stat-label">Connected Users</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">{total_users}</div>
                <div class="stat-label">Total Registered</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">{PORT}</div>
                <div class="stat-label">Server Port</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">{MAX_CLIENTS}</div>
                <div class="stat-label">Max Capacity</div>
            </div>
        </div>
        
        <div class="features">
            <h3>🚀 Server Features</h3>
            <div class="feature-list">
                <div class="feature-item">✨ End-to-End Encryption</div>
                <div class="feature-item">📁 File Transfer Support</div>
                <div class="feature-item">💬 Real-time Messaging</div>
                <div class="feature-item">👥 Channel Support</div>
                <div class="feature-item">🔐 User Authentication</div>
                <div class="feature-item">📊 MongoDB Integration</div>
                <div class="feature-item">⚡ High Performance</div>
                <div class="feature-item">🌐 Railway Deployment</div>
            </div>
        </div>
        
        <div class="technical-info">
            <h3>🔧 Technical Information</h3>
            <div class="tech-grid">
                <div class="tech-item">
                    <span>Database:</span>
                    <span>{db_status}</span>
                </div>
                <div class="tech-item">
                    <span>Protocol:</span>
                    <span>JSON over TCP</span>
                </div>
                <div class="tech-item">
                    <span>Encryption:</span>
                    <span>Client-side E2E</span>
                </div>
                <div class="tech-item">
                    <span>Buffer Size:</span>
                    <span>{BUFFER_SIZE // 1024}KB</span>
                </div>
                <div class="tech-item">
                    <span>Max File Size:</span>
                    <span>{MAX_MESSAGE_SIZE // (1024*1024)}MB</span>
                </div>
                <div class="tech-item">
                    <span>Server Time:</span>
                    <span>{datetime.utcnow().strftime('%H:%M:%S UTC')}</span>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>🌐 For client connections, use TCP socket on <strong>{PORT}</strong></p>
            <p>Last updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
    </div>
</body>
</html>"""
        
        client_socket.sendall(health_response.encode())
        time.sleep(0.1)  # Give time for data to send
        
    except Exception as e:
        logger.warning(f"⚠️ Failed to send HTTP response: {e}")
    finally:
        try:
            client_socket.close()
        except:
            pass

def handle_client_connection(client_socket: socket.socket, client_address: tuple):
    """Handle new client connection with immediate HTTP detection"""
    logger.info(f"🔗 New connection from {client_address}")
    
    try:
        # Set very short timeout for initial detection
        client_socket.settimeout(1.0)
        
        # Peek at the first few bytes to detect HTTP quickly
        try:
            first_bytes = client_socket.recv(16, socket.MSG_PEEK)
            
            if not first_bytes:
                logger.warning(f"⚠️ No data from {client_address}")
                return
            
            # Quick HTTP detection
            if first_bytes.startswith(b'GET ') or first_bytes.startswith(b'HEAD ') or first_bytes.startswith(b'POST '):
                logger.info(f"🌐 HTTP request detected from {client_address}")
                handle_http_request(client_socket, client_address)
                return
                
        except socket.timeout:
            # No immediate data, treat as potential TCP client
            pass
        except Exception as e:
            logger.warning(f"Detection error for {client_address}: {e}")
            return
        
        # Now handle as TCP client
        handle_tcp_client(client_socket, client_address)
        
    except Exception as e:
        logger.error(f"❌ Client connection error from {client_address}: {e}")
    finally:
        try:
            client_socket.close()
        except:
            pass

def handle_http_request(client_socket: socket.socket, client_address: tuple):
    """Handle HTTP request immediately for Railway health checks"""
    try:
        # Read the full HTTP request
        client_socket.settimeout(5.0)
        request_data = b""
        
        while True:
            try:
                chunk = client_socket.recv(1024)
                if not chunk:
                    break
                request_data += chunk
                
                # Check if we have complete HTTP headers
                if b'\r\n\r\n' in request_data:
                    break
                    
            except socket.timeout:
                break
        
        # Parse request
        request_lines = request_data.decode('utf-8', errors='ignore').split('\n')
        if request_lines:
            first_line = request_lines[0].strip()
            try:
                method, path, version = first_line.split(' ', 2)
                logger.info(f"📡 {method} {path} from {client_address}")
            except:
                path = "/"
        else:
            path = "/"
        
        # Send immediate health check response
        send_health_response(client_socket, path)
        
    except Exception as e:
        logger.warning(f"HTTP handling error: {e}")
        send_health_response(client_socket, "/")

def send_health_response(client_socket: socket.socket, path: str = "/"):
    """Send immediate health check response for Railway"""
    try:
        # Get quick stats
        connected_users = len(client_usernames)
        db_status = "Connected" if db else "In-Memory"
        
        # Always send JSON health response for Railway
        health_data = {
            "status": "healthy",
            "service": "Enhanced Secure Chat Server",
            "connected_users": connected_users,
            "database": db_status,
            "port": PORT,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        response = f"""HTTP/1.1 200 OK\r
Content-Type: application/json\r
Connection: close\r
Cache-Control: no-cache\r
Access-Control-Allow-Origin: *\r
\r
{json.dumps(health_data)}"""
        
        client_socket.sendall(response.encode())
        
    except Exception as e:
        logger.warning(f"Failed to send health response: {e}")

def handle_tcp_client(client_socket: socket.socket, client_address: tuple):
    """Handle TCP client connection and authentication"""
    # Add to clients tracking
    clients[client_socket] = {
        "address": client_address,
        "authenticated": False,
        "username": None,
        "connected_at": datetime.utcnow()
    }
    
    try:
        # Set timeout for authentication
        client_socket.settimeout(30)
        
        # Read authentication data
        auth_data = client_socket.recv(BUFFER_SIZE)
        
        if not auth_data:
            logger.warning(f"⚠️ No auth data from {client_address}")
            return
        
        # Handle TCP authentication
        try:
            auth_payload = json.loads(auth_data.decode('utf-8'))
            
            logger.info(f"🔐 TCP auth attempt from {client_address}: {auth_payload.get('username', 'unknown')}")
            
            # Extract authentication data
            username = auth_payload.get("username", "").strip()
            password = auth_payload.get("password", "") or auth_payload.get("auth", "")
            public_key = auth_payload.get("public_key", "")
            email = auth_payload.get("email", "")
            
            # Authenticate user
            auth_result = authenticate_user(username, password, public_key, email)
            
            # Send authentication response
            response = {
                "type": MessageTypes.AUTH_RESPONSE,
                "timestamp": datetime.utcnow().isoformat(),
                **auth_result
            }
            
            client_socket.sendall(json.dumps(response).encode())
            
            # Handle successful authentication
            if auth_result["status"] in ["success", "new_user"]:
                clients[client_socket].update({
                    "authenticated": True,
                    "username": username
                })
                client_usernames[client_socket] = username
                username_to_socket[username] = client_socket
                
                logger.info(f"✅ User {username} authenticated from {client_address}")
                
                # Remove authentication timeout
                client_socket.settimeout(None)
                
                # Broadcast user online status
                broadcast_user_status(username, "online", exclude_socket=client_socket)
                
                # Send updated peer list
                broadcast_peer_list()
                
                # Handle authenticated client messages
                handle_authenticated_client(client_socket, username)
            else:
                logger.warning(f"❌ Authentication failed for {username}: {auth_result['message']}")
                time.sleep(1)  # Brief delay before closing
                
        except json.JSONDecodeError as e:
            logger.error(f"❌ Invalid JSON from {client_address}: {e}")
            error_response = {
                "type": MessageTypes.ERROR,
                "message": "Invalid JSON format",
                "timestamp": datetime.utcnow().isoformat()
            }
            try:
                client_socket.sendall(json.dumps(error_response).encode())
            except:
                pass
        except Exception as e:
            logger.error(f"❌ Authentication error from {client_address}: {e}")
            
    except socket.timeout:
        logger.warning(f"⏰ Authentication timeout from {client_address}")
    except Exception as e:
        logger.error(f"❌ TCP client error from {client_address}: {e}")
    finally:
        remove_client(client_socket)

def handle_authenticated_client(client_socket: socket.socket, username: str):
    """Handle messages from authenticated client with enhanced message routing"""
    logger.info(f"💬 Message handler started for: {username}")
    
    try:
        while True:
            try:
                # Set timeout for activity
                client_socket.settimeout(300)  # 5 minutes
                data = client_socket.recv(BUFFER_SIZE)
                
                if not data:
                    logger.info(f"📴 {username} disconnected")
                    break
                
                # Remove timeout after receiving data
                client_socket.settimeout(None)
                
                try:
                    message = json.loads(data.decode('utf-8'))
                    message["timestamp"] = datetime.utcnow().isoformat()
                    
                    # Route message based on type
                    handle_message(client_socket, username, message)
                    
                except json.JSONDecodeError as e:
                    logger.warning(f"⚠️ Invalid JSON from {username}: {e}")
                    send_error_response(client_socket, "Invalid JSON format")
                    continue
                    
            except socket.timeout:
                # Send ping to check if client is still alive
                try:
                    ping_message = {"type": MessageTypes.PING, "timestamp": datetime.utcnow().isoformat()}
                    client_socket.sendall(json.dumps(ping_message).encode())
                except:
                    logger.info(f"⏰ Ping failed for {username}, disconnecting")
                    break
                continue
            except Exception as e:
                logger.error(f"❌ Message handling error for {username}: {e}")
                break
                
    except Exception as e:
        logger.error(f"❌ Connection error with {username}: {e}")
    finally:
        logger.info(f"🔌 Closing connection for {username}")

def handle_message(client_socket: socket.socket, sender_username: str, message: Dict[str, Any]):
    """Enhanced message handling with support for different message types"""
    try:
        message_type = message.get("type")
        
        if message_type == MessageTypes.MESSAGE:
            handle_direct_message(client_socket, sender_username, message)
        elif message_type == MessageTypes.FILE_HEADER:
            handle_file_transfer_start(client_socket, sender_username, message)
        elif message_type == MessageTypes.FILE_CHUNK:
            handle_file_chunk(client_socket, sender_username, message)
        elif message_type == MessageTypes.FILE_COMPLETE:
            handle_file_transfer_complete(client_socket, sender_username, message)
        elif message_type == MessageTypes.CHANNEL_CREATE:
            handle_channel_create(client_socket, sender_username, message)
        elif message_type == MessageTypes.CHANNEL_JOIN:
            handle_channel_join(client_socket, sender_username, message)
        elif message_type == MessageTypes.CHANNEL_LEAVE:
            handle_channel_leave(client_socket, sender_username, message)
        elif message_type == MessageTypes.CHANNEL_MESSAGE:
            handle_channel_message(client_socket, sender_username, message)
        elif message_type == MessageTypes.CHANNEL_LIST:
            handle_channel_list_request(client_socket, sender_username)
        elif message_type == MessageTypes.TYPING_INDICATOR:
            handle_typing_indicator(client_socket, sender_username, message)
        elif message_type == MessageTypes.PONG:
            logger.debug(f"🏓 Pong received from {sender_username}")
        else:
            logger.warning(f"⚠️ Unknown message type '{message_type}' from {sender_username}")
            send_error_response(client_socket, f"Unknown message type: {message_type}")
            
    except Exception as e:
        logger.error(f"❌ Error handling message from {sender_username}: {e}")
        send_error_response(client_socket, "Message processing error")

def handle_direct_message(client_socket: socket.socket, sender_username: str, message: Dict[str, Any]):
    """Handle direct messages between users"""
    try:
        recipient = message.get("to")
        if not recipient:
            send_error_response(client_socket, "Recipient not specified")
            return
        
        recipient_socket = username_to_socket.get(recipient)
        if not recipient_socket:
            send_error_response(client_socket, f"User {recipient} is not online")
            return
        
        # Add sender information
        message["from"] = sender_username
        message["message_id"] = f"{sender_username}_{recipient}_{int(time.time() * 1000)}"
        
        try:
            message_data = json.dumps(message).encode()
            recipient_socket.sendall(message_data)
            
            # Send delivery confirmation
            confirmation = {
                "type": MessageTypes.SUCCESS,
                "message": "Message delivered",
                "message_id": message["message_id"],
                "timestamp": datetime.utcnow().isoformat()
            }
            client_socket.sendall(json.dumps(confirmation).encode())
            
            # Log the message
            content_preview = message.get("content", "")[:50]
            logger.info(f"💬 {sender_username} -> {recipient}: {content_preview}...")
            
            # Store message in database if available
            store_message(sender_username, recipient, message)
            
        except Exception as e:
            logger.error(f"❌ Failed to deliver message: {e}")
            if recipient_socket in client_usernames:
                remove_client(recipient_socket)
            send_error_response(client_socket, "Failed to deliver message")
            
    except Exception as e:
        logger.error(f"❌ Direct message error: {e}")
        send_error_response(client_socket, "Message processing error")

def handle_file_transfer_start(client_socket: socket.socket, sender_username: str, message: Dict[str, Any]):
    """Handle file transfer initiation"""
    try:
        recipient = message.get("to")
        filename = message.get("filename")
        file_size = message.get("file_size", 0)
        
        if not recipient or not filename:
            send_error_response(client_socket, "Missing file transfer parameters")
            return
        
        if file_size > MAX_MESSAGE_SIZE:
            send_error_response(client_socket, f"File too large. Max size: {MAX_MESSAGE_SIZE // (1024*1024)}MB")
            return
        
        recipient_socket = username_to_socket.get(recipient)
        if not recipient_socket:
            send_error_response(client_socket, f"User {recipient} is not online")
            return
        
        # Forward file header to recipient
        message["from"] = sender_username
        message["transfer_id"] = f"file_{sender_username}_{recipient}_{int(time.time() * 1000)}"
        
        try:
            message_data = json.dumps(message).encode()
            recipient_socket.sendall(message_data)
            
            logger.info(f"📁 File transfer started: {sender_username} -> {recipient}: {filename} ({file_size} bytes)")
            
        except Exception as e:
            logger.error(f"❌ Failed to initiate file transfer: {e}")
            send_error_response(client_socket, "Failed to initiate file transfer")
            
    except Exception as e:
        logger.error(f"❌ File transfer start error: {e}")
        send_error_response(client_socket, "File transfer error")

def handle_file_chunk(client_socket: socket.socket, sender_username: str, message: Dict[str, Any]):
    """Handle file chunk transfer"""
    try:
        recipient = message.get("to")
        transfer_id = message.get("transfer_id")
        
        if not recipient or not transfer_id:
            send_error_response(client_socket, "Missing file chunk parameters")
            return
        
        recipient_socket = username_to_socket.get(recipient)
        if not recipient_socket:
            send_error_response(client_socket, f"User {recipient} is not online")
            return
        
        # Forward chunk to recipient
        message["from"] = sender_username
        
        try:
            message_data = json.dumps(message).encode()
            recipient_socket.sendall(message_data)
            
        except Exception as e:
            logger.error(f"❌ Failed to transfer file chunk: {e}")
            send_error_response(client_socket, "Failed to transfer file chunk")
            
    except Exception as e:
        logger.error(f"❌ File chunk error: {e}")

def handle_file_transfer_complete(client_socket: socket.socket, sender_username: str, message: Dict[str, Any]):
    """Handle file transfer completion"""
    try:
        recipient = message.get("to")
        transfer_id = message.get("transfer_id")
        
        if not recipient or not transfer_id:
            send_error_response(client_socket, "Missing file completion parameters")
            return
        
        recipient_socket = username_to_socket.get(recipient)
        if recipient_socket:
            message["from"] = sender_username
            message_data = json.dumps(message).encode()
            recipient_socket.sendall(message_data)
        
        logger.info(f"📁 File transfer completed: {sender_username} -> {recipient} (ID: {transfer_id})")
        
    except Exception as e:
        logger.error(f"❌ File completion error: {e}")

def handle_channel_create(client_socket: socket.socket, creator_username: str, message: Dict[str, Any]):
    """Handle channel creation"""
    try:
        channel_name = message.get("channel_name", "").strip()
        channel_description = message.get("description", "")
        
        if not channel_name:
            send_error_response(client_socket, "Channel name is required")
            return
        
        if len(channel_name) > 50:
            send_error_response(client_socket, "Channel name too long (max 50 characters)")
            return
        
        if not channel_name.replace('_', '').replace('-', '').isalnum():
            send_error_response(client_socket, "Channel name can only contain letters, numbers, hyphens, and underscores")
            return
        
        # Check if channel already exists
        if channel_name in active_channels:
            send_error_response(client_socket, f"Channel '{channel_name}' already exists")
            return
        
        # Create channel
        active_channels[channel_name] = [creator_username]
        
        # Store in database if available
        if channels_collection is not None:
            try:
                channel_data = {
                    "name": channel_name,
                    "description": channel_description,
                    "created_by": creator_username,
                    "created_at": datetime.utcnow(),
                    "members": [creator_username]
                }
                channels_collection.insert_one(channel_data)
            except Exception as e:
                logger.error(f"❌ Failed to store channel in database: {e}")
        
        # Send success response
        response = {
            "type": MessageTypes.SUCCESS,
            "message": f"Channel '{channel_name}' created successfully",
            "channel_name": channel_name,
            "timestamp": datetime.utcnow().isoformat()
        }
        client_socket.sendall(json.dumps(response).encode())
        
        logger.info(f"📢 Channel '{channel_name}' created by {creator_username}")
        
    except Exception as e:
        logger.error(f"❌ Channel creation error: {e}")
        send_error_response(client_socket, "Channel creation error")

def handle_channel_join(client_socket: socket.socket, username: str, message: Dict[str, Any]):
    """Handle channel join request"""
    try:
        channel_name = message.get("channel_name", "").strip()
        
        if not channel_name:
            send_error_response(client_socket, "Channel name is required")
            return
        
        if channel_name not in active_channels:
            send_error_response(client_socket, f"Channel '{channel_name}' does not exist")
            return
        
        if username not in active_channels[channel_name]:
            active_channels[channel_name].append(username)
        
        # Send success response
        response = {
            "type": MessageTypes.SUCCESS,
            "message": f"Joined channel '{channel_name}'",
            "channel_name": channel_name,
            "members": active_channels[channel_name],
            "timestamp": datetime.utcnow().isoformat()
        }
        client_socket.sendall(json.dumps(response).encode())
        
        # Notify other channel members
        join_notification = {
            "type": MessageTypes.USER_STATUS,
            "username": username,
            "status": "joined_channel",
            "channel_name": channel_name,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        for member_username in active_channels[channel_name]:
            if member_username != username:
                member_socket = username_to_socket.get(member_username)
                if member_socket:
                    try:
                        member_socket.sendall(json.dumps(join_notification).encode())
                    except:
                        pass
        
        logger.info(f"📢 {username} joined channel '{channel_name}'")
        
    except Exception as e:
        logger.error(f"❌ Channel join error: {e}")
        send_error_response(client_socket, "Channel join error")

def handle_channel_leave(client_socket: socket.socket, username: str, message: Dict[str, Any]):
    """Handle channel leave request"""
    try:
        channel_name = message.get("channel_name", "").strip()
        
        if not channel_name:
            send_error_response(client_socket, "Channel name is required")
            return
        
        if channel_name not in active_channels:
            send_error_response(client_socket, f"Channel '{channel_name}' does not exist")
            return
        
        if username in active_channels[channel_name]:
            active_channels[channel_name].remove(username)
            
            # If channel is empty, remove it
            if not active_channels[channel_name]:
                del active_channels[channel_name]
        
        # Send success response
        response = {
            "type": MessageTypes.SUCCESS,
            "message": f"Left channel '{channel_name}'",
            "channel_name": channel_name,
            "timestamp": datetime.utcnow().isoformat()
        }
        client_socket.sendall(json.dumps(response).encode())
        
        logger.info(f"📢 {username} left channel '{channel_name}'")
        
    except Exception as e:
        logger.error(f"❌ Channel leave error: {e}")
        send_error_response(client_socket, "Channel leave error")

def handle_channel_message(client_socket: socket.socket, sender_username: str, message: Dict[str, Any]):
    """Handle channel message broadcast"""
    try:
        channel_name = message.get("channel_name")
        content = message.get("content")
        
        if not channel_name or not content:
            send_error_response(client_socket, "Channel name and content are required")
            return
        
        if channel_name not in active_channels:
            send_error_response(client_socket, f"Channel '{channel_name}' does not exist")
            return
        
        if sender_username not in active_channels[channel_name]:
            send_error_response(client_socket, f"You are not a member of channel '{channel_name}'")
            return
        
        # Prepare message for broadcast
        channel_message = {
            "type": MessageTypes.CHANNEL_MESSAGE,
            "channel_name": channel_name,
            "from": sender_username,
            "content": content,
            "message_id": f"ch_{channel_name}_{sender_username}_{int(time.time() * 1000)}",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Broadcast to all channel members
        message_data = json.dumps(channel_message).encode()
        delivered_count = 0
        
        for member_username in active_channels[channel_name]:
            if member_username != sender_username:  # Don't echo back to sender
                member_socket = username_to_socket.get(member_username)
                if member_socket:
                    try:
                        member_socket.sendall(message_data)
                        delivered_count += 1
                    except Exception as e:
                        logger.warning(f"Failed to send channel message to {member_username}: {e}")
        
        # Send delivery confirmation to sender
        confirmation = {
            "type": MessageTypes.SUCCESS,
            "message": f"Message sent to {delivered_count} members",
            "channel_name": channel_name,
            "delivered_count": delivered_count,
            "timestamp": datetime.utcnow().isoformat()
        }
        client_socket.sendall(json.dumps(confirmation).encode())
        
        logger.info(f"📢 Channel message in '{channel_name}' from {sender_username} -> {delivered_count} members")
        
    except Exception as e:
        logger.error(f"❌ Channel message error: {e}")
        send_error_response(client_socket, "Channel message error")

def handle_channel_list_request(client_socket: socket.socket, username: str):
    """Handle request for channel list"""
    try:
        channel_list = []
        
        for channel_name, members in active_channels.items():
            channel_info = {
                "name": channel_name,
                "member_count": len(members),
                "is_member": username in members,
                "members": members if username in members else []
            }
            channel_list.append(channel_info)
        
        response = {
            "type": MessageTypes.CHANNEL_LIST,
            "channels": channel_list,
            "total_channels": len(channel_list),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        client_socket.sendall(json.dumps(response).encode())
        
    except Exception as e:
        logger.error(f"❌ Channel list error: {e}")
        send_error_response(client_socket, "Failed to get channel list")

def handle_typing_indicator(client_socket: socket.socket, sender_username: str, message: Dict[str, Any]):
    """Handle typing indicator forwarding"""
    try:
        recipient = message.get("to")
        is_typing = message.get("is_typing", False)
        
        if not recipient:
            return  # Silently ignore invalid typing indicators
        
        recipient_socket = username_to_socket.get(recipient)
        if recipient_socket:
            typing_message = {
                "type": MessageTypes.TYPING_INDICATOR,
                "from": sender_username,
                "is_typing": is_typing,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            try:
                recipient_socket.sendall(json.dumps(typing_message).encode())
            except:
                pass  # Silently ignore delivery failures for typing indicators
        
    except Exception as e:
        logger.debug(f"Typing indicator error: {e}")  # Use debug level for non-critical errors

def send_error_response(client_socket: socket.socket, error_message: str):
    """Send error response to client"""
    try:
        error_response = {
            "type": MessageTypes.ERROR,
            "message": error_message,
            "timestamp": datetime.utcnow().isoformat()
        }
        client_socket.sendall(json.dumps(error_response).encode())
    except Exception as e:
        logger.error(f"❌ Failed to send error response: {e}")

def store_message(sender: str, recipient: str, message: Dict[str, Any]):
    """Store message in database for history"""
    try:
        if messages_collection is not None:
            message_doc = {
                "sender": sender,
                "recipient": recipient,
                "content": message.get("content", ""),
                "message_type": message.get("type"),
                "timestamp": datetime.utcnow(),
                "message_id": message.get("message_id")
            }
            messages_collection.insert_one(message_doc)
    except Exception as e:
        logger.debug(f"Failed to store message: {e}")

def check_rate_limit(client_ip: str) -> bool:
    """Check if client IP is rate limited"""
    try:
        now = datetime.utcnow()
        
        # Clean old attempts
        if client_ip in connection_attempts:
            connection_attempts[client_ip] = [
                attempt_time for attempt_time in connection_attempts[client_ip]
                if now - attempt_time < RATE_LIMIT_WINDOW
            ]
        else:
            connection_attempts[client_ip] = []
        
        # Check if over limit
        if len(connection_attempts[client_ip]) >= MAX_ATTEMPTS_PER_IP:
            return False
        
        # Add current attempt
        connection_attempts[client_ip].append(now)
        return True
        
    except Exception as e:
        logger.error(f"Rate limit check error: {e}")
        return True  # Allow on error

def start_server():
    """Start the enhanced secure chat server with Railway health check support"""
    global tcp_server_socket
    
    logger.info("🚀 Starting Enhanced Secure Chat Server...")
    
    # Initialize database
    db_connected = init_database()
    
    # Create server socket
    tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        tcp_server_socket.bind((HOST, PORT))
        tcp_server_socket.listen(MAX_CLIENTS)
        
        # Display startup information
        logger.info("=" * 80)
        logger.info("🔐 ENHANCED SECURE CHAT SERVER v2.0 - RAILWAY OPTIMIZED")
        logger.info("=" * 80)
        logger.info(f"🌐 Host: {HOST}")
        logger.info(f"🔌 Port: {PORT}")
        logger.info(f"👥 Max clients: {MAX_CLIENTS}")
        logger.info(f"📦 Buffer size: {BUFFER_SIZE // 1024}KB")
        logger.info(f"📁 Max file size: {MAX_MESSAGE_SIZE // (1024*1024)}MB")
        logger.info(f"💾 Database: {'✅ MongoDB Connected' if db_connected else '⚠️ In-Memory Storage'}")
        logger.info(f"⚡ Rate limiting: {MAX_ATTEMPTS_PER_IP} attempts per {RATE_LIMIT_WINDOW}")
        logger.info("=" * 80)
        logger.info("✨ FEATURES ENABLED:")
        logger.info("   📧 User Authentication & Registration")
        logger.info("   🔒 End-to-End Encryption Support")
        logger.info("   💬 Direct Messaging")
        logger.info("   📁 File Transfer")
        logger.info("   📢 Channel Support")
        logger.info("   🌐 HTTP Health Check (Same Port)")
        logger.info("   📊 Real-time User Status")
        logger.info("   ⌨️ Typing Indicators")
        logger.info("=" * 80)
        logger.info("🚀 Server ready and accepting connections!")
        logger.info("🌐 Railway health checks: HTTP requests on same port")
        logger.info("📱 TCP clients: JSON authentication protocol")
        logger.info("-" * 80)
        
        # Main server loop with immediate HTTP detection
        while True:
            try:
                client_socket, client_address = tcp_server_socket.accept()
                client_ip = client_address[0]
                
                # Check rate limiting
                if not check_rate_limit(client_ip):
                    logger.warning(f"🚫 Rate limit exceeded for {client_ip}")
                    try:
                        client_socket.close()
                    except:
                        pass
                    continue
                
                # Check capacity
                if len(clients) >= MAX_CLIENTS:
                    logger.warning(f"🏠 Server at capacity ({MAX_CLIENTS}), rejecting {client_address}")
                    try:
                        # Send capacity error if possible
                        error_msg = {
                            "type": MessageTypes.ERROR,
                            "message": "Server at maximum capacity",
                            "timestamp": datetime.utcnow().isoformat()
                        }
                        client_socket.sendall(json.dumps(error_msg).encode())
                        time.sleep(0.1)
                        client_socket.close()
                    except:
                        pass
                    continue
                
                # Handle client in separate thread with immediate processing
                client_thread = threading.Thread(
                    target=handle_client_connection,
                    args=(client_socket, client_address),
                    daemon=True,
                    name=f"Client-{client_address[0]}:{client_address[1]}"
                )
                client_thread.start()
                
            except KeyboardInterrupt:
                logger.info("\n🛑 Shutdown signal received")
                break
            except Exception as e:
                logger.error(f"❌ Accept error: {e}")
                time.sleep(0.1)  # Very brief pause
                continue
                
    except KeyboardInterrupt:
        logger.info("🛑 Server shutdown requested")
    except Exception as e:
        logger.error(f"❌ Server startup error: {e}")
        raise  # Re-raise for Railway to detect the failure
    finally:
        logger.info("🔄 Shutting down server...")
        
        # Notify all connected clients
        shutdown_message = {
            "type": MessageTypes.ERROR,
            "message": "Server is shutting down",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        for client_socket in list(clients.keys()):
            try:
                client_socket.sendall(json.dumps(shutdown_message).encode())
                time.sleep(0.1)
                client_socket.close()
            except:
                pass
        
        try:
            tcp_server_socket.close()
        except:
            pass
            
        logger.info("✅ Server shutdown complete")
        logger.info("👋 Thank you for using Enhanced Secure Chat Server!")

if __name__ == "__main__":
    try:
        start_server()
    except Exception as e:
        logger.error(f"💥 Fatal error: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)
