# main.py - Railway-Compatible Secure Chat Server with MongoDB and Enhanced Debugging
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

# Configure logging with more detail
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG for more detail
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)

# Railway configuration - MODIFIED FOR RAILWAY
PORT = int(os.environ.get("PORT", 5000))
HOST = '0.0.0.0'  # Railway requires 0.0.0.0

# MongoDB configuration - UPDATED FOR RAILWAY MONGODB
MONGODB_URL = os.environ.get("MONGO_URL")  # Railway MongoDB addon provides this
MONGODB_HOST = os.environ.get("MONGODB_HOST", "localhost")
MONGODB_PORT = int(os.environ.get("MONGODB_PORT", "27017"))
MONGODB_DB = os.environ.get("MONGODB_DB", "secure_chat")
MONGODB_USERNAME = os.environ.get("MONGODB_USERNAME", "")
MONGODB_PASSWORD = os.environ.get("MONGODB_PASSWORD", "")

# Railway specific settings
RAILWAY_STATIC_URL = os.environ.get("RAILWAY_STATIC_URL", "")
RAILWAY_PUBLIC_DOMAIN = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "")

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
    """Initialize MongoDB connection and collections - UPDATED FOR RAILWAY"""
    global db, users_collection, messages_collection, sessions_collection
    
    logger.info("🔄 Starting database initialization...")
    logger.info(f"MONGODB_URL exists: {bool(MONGODB_URL)}")
    logger.info(f"MONGODB_HOST: {MONGODB_HOST}")
    logger.info(f"MONGODB_PORT: {MONGODB_PORT}")
    logger.info(f"MONGODB_DB: {MONGODB_DB}")
    logger.info(f"MONGODB_USERNAME exists: {bool(MONGODB_USERNAME)}")
    logger.info(f"MONGODB_PASSWORD exists: {bool(MONGODB_PASSWORD)}")
    
    try:
        # Try Railway MongoDB URL first (preferred)
        if MONGODB_URL:
            logger.info(f"🔐 Connecting to Railway MongoDB via URL")
            client = MongoClient(
                MONGODB_URL,
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=15000,
                socketTimeoutMS=30000
            )
        elif MONGODB_USERNAME and MONGODB_PASSWORD:
            # With authentication
            connection_string = f"mongodb://{MONGODB_USERNAME}:{MONGODB_PASSWORD}@{MONGODB_HOST}:{MONGODB_PORT}/"
            logger.info(f"🔐 Connecting to MongoDB with authentication at {MONGODB_HOST}:{MONGODB_PORT}")
            client = MongoClient(
                connection_string,
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=15000,
                socketTimeoutMS=30000
            )
        else:
            # Without authentication (local development)
            connection_string = f"mongodb://{MONGODB_HOST}:{MONGODB_PORT}/"
            logger.info(f"🔓 Connecting to MongoDB without authentication at {MONGODB_HOST}:{MONGODB_PORT}")
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
        
        # Create indexes for better performance
        try:
            users_collection.create_index("username", unique=True)
            messages_collection.create_index([("timestamp", -1)])
            sessions_collection.create_index([("last_activity", 1)], expireAfterSeconds=3600)
            logger.info("📊 Database indexes created successfully")
        except Exception as index_error:
            logger.warning(f"⚠️ Index creation warning: {index_error}")
        
        # Test basic operations
        test_result = db.command("dbStats")
        logger.info(f"📁 Database '{MONGODB_DB}' initialized - Collections: {len(db.list_collection_names())}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ MongoDB connection failed: {e}")
        logger.error(f"Full error: {traceback.format_exc()}")
        logger.warning("🔄 Falling back to in-memory storage")
        logger.info("💡 For MongoDB setup on Railway: Add MongoDB addon or set MONGODB_URL")
        return False

def hash_password(password):
    """Simple password hashing with salt"""
    salt = "secure_chat_2024"  # In production, use random salt per user
    return hashlib.sha256((password + salt).encode()).hexdigest()

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
    """Authenticate user or create new account with MongoDB - ENHANCED DEBUGGING"""
    logger.debug(f"🔍 Starting authentication for user: {username}")
    logger.debug(f"   Username length: {len(username) if username else 0}")
    logger.debug(f"   Password length: {len(password) if password else 0}")
    logger.debug(f"   Public key length: {len(public_key) if public_key else 0}")
    logger.debug(f"   MongoDB available: {users_collection is not None}")
    
    # Basic validation
    if not username or not password or not public_key:
        missing = []
        if not username: missing.append("username")
        if not password: missing.append("password") 
        if not public_key: missing.append("public_key")
        logger.warning(f"❌ Missing credentials: {missing}")
        return {"status": "fail", "message": f"Missing credentials: {', '.join(missing)}"}
    
    # Username validation
    if len(username) > 50:
        logger.warning(f"❌ Username too long: {len(username)} chars")
        return {"status": "fail", "message": "Username too long (max 50 characters)"}
        
    if not username.replace('_', '').replace('-', '').isalnum():
        logger.warning(f"❌ Invalid username format: {username}")
        return {"status": "fail", "message": "Invalid username format"}
    
    # Password validation
    if len(password) > 128:
        logger.warning(f"❌ Password too long: {len(password)} chars")
        return {"status": "fail", "message": "Password too long (max 128 characters)"}
    
    logger.debug("✅ Basic validation passed")
    
    # Hash password
    try:
        password_hash = hash_password(password)
        logger.debug(f"✅ Password hashed successfully")
    except Exception as e:
        logger.error(f"❌ Password hashing failed: {e}")
        return {"status": "fail", "message": "Password processing error"}
    
    try:
        if users_collection is not None:
            logger.debug("🔍 Using MongoDB storage")
            try:
                # MongoDB storage
                existing_user = users_collection.find_one({"username": username})
                logger.debug(f"✅ Database query completed, user exists: {bool(existing_user)}")
                
                if existing_user:
                    logger.debug("🔍 Existing user found, checking password")
                    if existing_user["password_hash"] == password_hash:
                        logger.debug("✅ Password matches")
                        # Update user info
                        try:
                            users_collection.update_one(
                                {"username": username},
                                {
                                    "$set": {
                                        "public_key": public_key,
                                        "last_login": datetime.utcnow()
                                    }
                                }
                            )
                            logger.debug("✅ User info updated")
                            logger.info(f"🔐 User {username} authenticated successfully")
                            return {"status": "success", "message": "Welcome back!"}
                        except Exception as update_error:
                            logger.error(f"❌ Failed to update user: {update_error}")
                            return {"status": "fail", "message": "Database update error"}
                    else:
                        logger.warning(f"❌ Invalid password for user {username}")
                        return {"status": "fail", "message": "Invalid password"}
                else:
                    logger.debug("🆕 Creating new user")
                    # Create new user
                    try:
                        user_data = {
                            "username": username,
                            "password_hash": password_hash,
                            "public_key": public_key,
                            "created_at": datetime.utcnow(),
                            "last_login": datetime.utcnow()
                        }
                        result = users_collection.insert_one(user_data)
                        logger.debug(f"✅ User created with ID: {result.inserted_id}")
                        logger.info(f"👤 New user {username} created successfully")
                        return {"status": "new_user", "message": "Account created successfully!"}
                    except Exception as create_error:
                        logger.error(f"❌ Failed to create user: {create_error}")
                        return {"status": "fail", "message": "Account creation error"}
                        
            except Exception as db_error:
                logger.error(f"❌ Database operation failed: {db_error}")
                logger.error(f"Full database error: {traceback.format_exc()}")
                return {"status": "fail", "message": "Database error"}
        
        else:
            logger.debug("💾 Using in-memory storage")
            # Fallback to in-memory storage (original code)
            user_database = getattr(authenticate_user, 'user_database', {})
            logger.debug(f"In-memory database has {len(user_database)} users")
            
            if username in user_database:
                logger.debug("🔍 Existing user found in memory")
                if user_database[username]["password_hash"] == password_hash:
                    user_database[username]["public_key"] = public_key
                    user_database[username]["last_login"] = datetime.now()
                    logger.info(f"🔐 User {username} authenticated successfully (in-memory)")
                    return {"status": "success", "message": "Welcome back!"}
                else:
                    logger.warning(f"❌ Invalid password for user {username} (in-memory)")
                    return {"status": "fail", "message": "Invalid password"}
            else:
                logger.debug("🆕 Creating new user in memory")
                user_database[username] = {
                    "password_hash": password_hash,
                    "public_key": public_key,
                    "last_login": datetime.now()
                }
                authenticate_user.user_database = user_database
                logger.info(f"👤 New user {username} created successfully (in-memory)")
                return {"status": "new_user", "message": "Account created successfully!"}
                
    except Exception as e:
        logger.error(f"❌ Authentication error for {username}: {str(e)}")
        logger.error(f"Full authentication error: {traceback.format_exc()}")
        return {"status": "fail", "message": f"Authentication error: {str(e)}"}

def get_user_public_key(username):
    """Get user's public key from database"""
    try:
        if users_collection is not None:
            user = users_collection.find_one({"username": username})
            return user["public_key"] if user else None
        else:
            # Fallback to in-memory
            user_database = getattr(authenticate_user, 'user_database', {})
            return user_database.get(username, {}).get("public_key")
    except Exception as e:
        logger.error(f"❌ Error getting public key for {username}: {e}")
        return None

def log_message(sender, recipient, message_type, metadata=None):
    """Log message to database for audit purposes"""
    try:
        if messages_collection is not None:
            message_log = {
                "sender": sender,
                "recipient": recipient,
                "message_type": message_type,
                "timestamp": datetime.utcnow(),
                "metadata": metadata or {}
            }
            messages_collection.insert_one(message_log)
    except Exception as e:
        logger.error(f"❌ Error logging message: {e}")

def update_user_session(username, status="online"):
    """Update user session status"""
    try:
        if sessions_collection is not None:
            sessions_collection.update_one(
                {"username": username},
                {
                    "$set": {
                        "status": status,
                        "last_activity": datetime.utcnow()
                    }
                },
                upsert=True
            )
    except Exception as e:
        logger.error(f"❌ Error updating session for {username}: {e}")

def broadcast_peer_list():
    """Send updated peer list to all authenticated clients"""
    peer_list = []
    
    try:
        if users_collection is not None:
            # Get public keys from database for active users
            for sock, username in client_usernames.items():
                public_key = get_user_public_key(username)
                if public_key:
                    peer_list.append({
                        "username": username,
                        "public_key": public_key
                    })
        else:
            # Fallback to in-memory
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
                logger.warning(f"Failed to send peer list to client: {e}")
                disconnected_clients.append(client_socket)
        
        for client_socket in disconnected_clients:
            remove_client(client_socket)
            
    except Exception as e:
        logger.error(f"❌ Error broadcasting peer list: {e}")

def remove_client(client_socket):
    """Remove client from all tracking structures"""
    try:
        username = None
        if client_socket in client_usernames:
            username = client_usernames[client_socket]
            del client_usernames[client_socket]
            
            if username in username_to_socket:
                del username_to_socket[username]
            
            # Update session status
            update_user_session(username, "offline")
            
            logger.info(f"👋 User {username} disconnected")
        
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
    """Send HTTP response for web browsers accessing the server - UPDATED FOR RAILWAY"""
    try:
        # Get stats from database if available
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
        
        # Database status
        db_status = "✅ MongoDB Connected" if db else "⚠️ In-Memory Storage"
        
        # Railway domain info
        railway_domain = RAILWAY_PUBLIC_DOMAIN or f"your-app.railway.app"
        
    except:
        total_users = 0
        connected_users = 0
        db_status = "❌ Database Error"
        railway_domain = "your-app.railway.app"
    
    response = f"""HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Connection: close
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type

<!DOCTYPE html>
<html>
<head>
    <title>🔐 Secure Chat Server - Railway Deployment</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
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
            backdrop-filter: blur(10px);
        }}
        .status {{ color: #28a745; font-weight: bold; font-size: 20px; text-align: center; }}
        .info {{ 
            background: linear-gradient(135deg, #e3f2fd 0%, #f8f9ff 100%);
            padding: 20px; 
            border-radius: 15px; 
            margin: 25px 0;
            border-left: 5px solid #2196f3;
            box-shadow: 0 4px 15px rgba(0,0,0,0.05);
        }}
        .warning {{ 
            color: #e65100; 
            background: linear-gradient(135deg, #fff3e0 0%, #fff8e1 100%);
            padding: 20px;
            border-radius: 15px;
            border-left: 5px solid #ff9800;
            box-shadow: 0 4px 15px rgba(0,0,0,0.05);
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-item {{
            text-align: center;
            padding: 20px;
            background: linear-gradient(135deg, #f8f9fa 0%, #ffffff 100%);
            border-radius: 15px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.05);
            transition: transform 0.3s ease;
        }}
        .stat-item:hover {{
            transform: translateY(-5px);
        }}
        .stat-number {{
            font-size: 32px;
            font-weight: bold;
            color: #2196f3;
            margin-bottom: 5px;
        }}
        .stat-label {{
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        h1 {{ 
            color: #2c3e50; 
            text-align: center; 
            font-size: 2.5em;
            margin-bottom: 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        h3 {{ 
            color: #34495e; 
            margin-bottom: 15px;
            font-size: 1.3em;
        }}
        ul {{ 
            line-height: 1.8; 
            margin-left: 20px;
        }}
        li {{ 
            margin: 8px 0; 
        }}
        .database-status {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 12px;
            background: #e8f5e8;
            color: #2e7d2e;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #666;
            font-size: 14px;
        }}
        @keyframes pulse {{
            0% {{ opacity: 1; }}
            50% {{ opacity: 0.7; }}
            100% {{ opacity: 1; }}
        }}
        .online {{ animation: pulse 2s infinite; }}
        .railway-info {{
            background: linear-gradient(135deg, #f3e5f5 0%, #e8eaf6 100%);
            padding: 20px;
            border-radius: 15px;
            border-left: 5px solid #9c27b0;
            margin: 25px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Secure Chat Server</h1>
        <p class="status online">✅ Server is running on Railway and accepting connections!</p>
        
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
        
        <div class="railway-info">
            <h3>🚀 Railway Deployment Info</h3>
            <p><strong>Public Domain:</strong> {railway_domain}</p>
            <p><strong>Environment:</strong> Railway Cloud Platform</p>
            <p><strong>Database:</strong> <span class="database-status">{db_status}</span></p>
            <p>Your chat server is deployed on Railway with automatic HTTPS, global CDN, and persistent storage.</p>
        </div>
        
        <div class="info">
            <h3>📱 For Desktop Clients:</h3>
            <ul>
                <li><strong>Server Address:</strong> {railway_domain}</li>
                <li><strong>Port:</strong> {PORT}</li>
                <li><strong>Connection Type:</strong> TCP Socket Connection</li>
                <li><strong>Protocol:</strong> JSON over TCP with End-to-End Encryption</li>
                <li><strong>Security:</strong> RSA + AES-256 hybrid encryption</li>
            </ul>
        </div>
        
        <div class="info">
            <h3>🔧 Technical Specifications:</h3>
            <ul>
                <li><strong>Platform:</strong> Railway Cloud with MongoDB</li>
                <li><strong>Runtime:</strong> Python 3.11+ with PyMongo</li>
                <li><strong>Maximum Clients:</strong> {MAX_CLIENTS} simultaneous connections</li>
                <li><strong>Buffer Size:</strong> {BUFFER_SIZE:,} bytes per message</li>
                <li><strong>Rate Limiting:</strong> {MAX_ATTEMPTS_PER_IP} attempts per 15 minutes</li>
                <li><strong>Features:</strong> File transfer, Group messaging, User authentication</li>
            </ul>
        </div>
        
        <div class="warning">
            <h3>⚠️ Important Information:</h3>
            <ul>
                <li><strong>Desktop Only:</strong> This server requires the desktop client application</li>
                <li><strong>Web Incompatible:</strong> Browsers cannot connect to TCP socket servers</li>
                <li><strong>End-to-End Encrypted:</strong> All messages use RSA + AES-256 encryption</li>
                <li><strong>Persistent Storage:</strong> User accounts and sessions are saved in MongoDB</li>
                <li><strong>File Support:</strong> Secure file transfer with integrity verification</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>🚀 Deployed on Railway | 🔐 Secured by RSA-2048 + AES-256</p>
            <p>© 2024 Secure Chat Server - End-to-End Encrypted Messaging</p>
        </div>
    </div>
</body>
</html>"""
    
    try:
        client_socket.sendall(response.encode())
        time.sleep(0.1)
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
        client_socket.settimeout(60)
        initial_data = client_socket.recv(BUFFER_SIZE)
        
        if not initial_data:
            logger.warning(f"No initial data received from {client_address}")
            return
        
        logger.info(f"Received {len(initial_data)} bytes from {client_address}")
        logger.debug(f"Raw data preview: {initial_data[:200]}...")
        
        if is_http_request(initial_data):
            logger.info(f"HTTP request detected from {client_address}, sending web response")
            send_http_response(client_socket)
            return
        
        try:
            data_str = initial_data.decode('utf-8')
            logger.debug(f"Decoded data: {data_str[:200]}...")
            
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
            logger.debug(f"Auth payload contents: {auth_payload}")
            
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
            logger.debug(f"   Username: '{username}' (len: {len(username)})")
            logger.debug(f"   Password: {len(password)} chars")
            logger.debug(f"   Public key: {len(public_key)} chars")
            
            auth_result = authenticate_user(username, password, public_key)
            
            response = {
                "type": "auth_result",
                **auth_result
            }
            
            logger.debug(f"Sending auth response: {response}")
            
            if not send_safe_json_response(client_socket, response):
                logger.error(f"Failed to send auth response to {client_address}")
                return
            
            logger.info(f"Auth result sent to {client_address}: {auth_result['status']}")
            
            if auth_result["status"] in ["success", "new_user"]:
                clients[client_socket]["authenticated"] = True
                clients[client_socket]["username"] = username
                client_usernames[client_socket] = username
                username_to_socket[username] = client_socket
                
                update_user_session(username, "online")
                
                logger.info(f"User {username} authenticated from {client_address}")
                
                client_socket.settimeout(None)
                
                broadcast_peer_list()
                
                handle_authenticated_client(client_socket, username)
            else:
                logger.warning(f"Authentication failed for {username} from {client_address}: {auth_result['message']}")
                time.sleep(1)
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
            logger.error(f"Full auth processing error: {traceback.format_exc()}")
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
        logger.error(f"Full client handling error: {traceback.format_exc()}")
    finally:
        remove_client(client_socket)

def handle_authenticated_client(client_socket, username):
    """Handle messages from authenticated client"""
    logger.info(f"Starting message handler for user: {username}")
    
    try:
        while True:
            try:
                client_socket.settimeout(300)
                data = client_socket.recv(BUFFER_SIZE)
                
                if not data:
                    logger.info(f"{username} disconnected (no data)")
                    break
                
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
            
            # Log message to database
            metadata = {}
            if msg_type == "message":
                logger.info(f"💬 Message: {sender_username} -> {recipient}")
                metadata = {"encrypted": True}
            elif msg_type == "key_exchange":
                logger.info(f"🔑 Key exchange: {sender_username} -> {recipient}")
                metadata = {"key_type": "public_key"}
            elif msg_type == "file_header":
                filename = message.get("filename", "unknown")
                filesize = message.get("filesize", 0)
                logger.info(f"📁 File start: {sender_username} -> {recipient}: '{filename}' ({filesize} bytes)")
                metadata = {"filename": filename, "filesize": filesize, "transfer_status": "started"}
            elif msg_type == "file_chunk":
                logger.debug(f"📦 File chunk: {sender_username} -> {recipient}")
                metadata = {"chunk_transfer": True}
            elif msg_type == "file_end":
                filename = message.get("filename", "unknown")  
                logger.info(f"✅ File completed: {sender_username} -> {recipient}: '{filename}'")
                metadata = {"filename": filename, "transfer_status": "completed"}
            else:
                logger.info(f"📨 Message type '{msg_type}': {sender_username} -> {recipient}")
                metadata = {"message_type": msg_type}
            
            # Log to database (non-blocking)
            try:
                log_message(sender_username, recipient, msg_type, metadata)
            except Exception as log_error:
                logger.warning(f"Failed to log message: {log_error}")
                
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
                logger.info(f"🧹 Cleaned up {len(expired_ips)} expired rate limit entries")
            
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
            
            # Get total users from database
            total_users = 0
            if users_collection is not None:
                try:
                    total_users = users_collection.count_documents({})
                except:
                    pass
            else:
                user_database = getattr(authenticate_user, 'user_database', {})
                total_users = len(user_database)
            
            rate_limited_ips = len(connection_attempts)
            
            logger.info(f"📊 Server Stats - Connected: {connected_users}, Total users: {total_users}, Rate-limited IPs: {rate_limited_ips}")
            
            if connected_users > 0:
                usernames = list(client_usernames.values())
                logger.info(f"👥 Online users: {', '.join(usernames)}")
            
            # Log database status
            if db:
                try:
                    # Get recent message count
                    if messages_collection is not None:
                        recent_messages = messages_collection.count_documents({
                            "timestamp": {"$gte": datetime.utcnow() - timedelta(hours=24)}
                        })
                        logger.info(f"📨 Messages in last 24h: {recent_messages}")
                except Exception as e:
                    logger.warning(f"Failed to get message stats: {e}")
                
        except Exception as e:
            logger.error(f"Stats error: {e}")

def health_check():
    """Perform periodic health checks"""
    while True:
        try:
            time.sleep(300)  # Check every 5 minutes
            
            # Check database connection
            if db:
                try:
                    db.command('ping')
                    logger.debug("🔍 Database health check: OK")
                except Exception as e:
                    logger.error(f"❌ Database health check failed: {e}")
            
        except Exception as e:
            logger.error(f"Health check error: {e}")

def start_server():
    """Start the secure chat server"""
    # Initialize database first
    db_connected = init_database()
    
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
        
        logger.info("=" * 70)
        logger.info("🔐 SECURE CHAT SERVER - RAILWAY DEPLOYMENT WITH ENHANCED DEBUGGING")
        logger.info(f"🌐 Host: {HOST}")
        logger.info(f"🔌 Port: {PORT}")
        logger.info(f"👥 Max clients: {MAX_CLIENTS}")
        logger.info(f"📦 Buffer size: {BUFFER_SIZE:,} bytes")
        logger.info(f"💾 Database: {'MongoDB Connected' if db_connected else 'In-Memory Fallback'}")
        if db_connected:
            if MONGODB_URL:
                logger.info(f"🏠 MongoDB: Railway MongoDB Service")
            else:
                logger.info(f"🏠 MongoDB: {MONGODB_HOST}:{MONGODB_PORT}/{MONGODB_DB}")
        logger.info(f"🕐 Started: {datetime.now()}")
        logger.info("=" * 70)
        logger.info("✅ Server ready for connections...")
        logger.info("🚀 Running on Railway - clients can connect globally!")
        logger.info("🌐 HTTP requests will receive a status page")
        logger.info("📊 All activities are logged to database")
        logger.info("🐛 Enhanced debugging enabled")
        logger.info("-" * 70)
        
        # Start background threads
        cleanup_thread = threading.Thread(target=cleanup_old_rate_limits, daemon=True, name="Cleanup")
        cleanup_thread.start()
        
        stats_thread = threading.Thread(target=print_server_stats, daemon=True, name="Stats")
        stats_thread.start()
        
        health_thread = threading.Thread(target=health_check, daemon=True, name="HealthCheck")
        health_thread.start()
        
        logger.info("🔄 Background threads started (Cleanup, Stats, HealthCheck)")
        
        # Main server loop
        connection_count = 0
        while True:
            try:
                client_socket, client_address = server_socket.accept()
                connection_count += 1
                
                logger.info(f"🔌 Connection #{connection_count} from {client_address}")
                
                # Check server capacity
                if len(clients) >= MAX_CLIENTS:
                    logger.warning(f"🚫 Server at capacity ({MAX_CLIENTS}), rejecting {client_address}")
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
        logger.error(traceback.format_exc())
    finally:
        logger.info("🔄 Shutting down server...")
        
        # Close all client connections
        for client_socket in list(clients.keys()):
            try:
                client_socket.close()
            except:
                pass
        
        # Close database connection
        if db:
            try:
                # Update all sessions to offline
                if sessions_collection is not None:
                    sessions_collection.update_many(
                        {"status": "online"},
                        {"$set": {"status": "offline", "last_activity": datetime.utcnow()}}
                    )
                logger.info("💾 Database cleanup completed")
            except Exception as e:
                logger.warning(f"Database cleanup error: {e}")
        
        try:
            server_socket.close()
        except:
            pass
            
        logger.info("✅ Server shutdown complete")

# Entry point
if __name__ == "__main__":
    try:
        start_server()
    except Exception as e:
        logger.error(f"Fatal server error: {e}")
        logger.error(traceback.format_exc())
