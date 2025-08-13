# main.py - Railway-Optimized Secure Chat Server
import socket
import threading
import json
import hashlib
import time
import os
import logging
import sys
from datetime import datetime, timedelta
from pymongo import MongoClient
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Configuration
PORT = int(os.environ.get("PORT", 5000))
HOST = '0.0.0.0'
HEALTH_PORT = PORT + 1 if PORT != 5000 else 5001

# MongoDB config
MONGODB_URL = os.environ.get("MONGO_URL")
MONGODB_HOST = os.environ.get("MONGODB_HOST", "localhost")
MONGODB_PORT = int(os.environ.get("MONGODB_PORT", "27017"))
MONGODB_DB = os.environ.get("MONGODB_DB", "secure_chat")
MONGODB_USERNAME = os.environ.get("MONGODB_USERNAME", "")
MONGODB_PASSWORD = os.environ.get("MONGODB_PASSWORD", "")

# Server settings
MAX_CLIENTS = 100
BUFFER_SIZE = 16384

# Global state
clients = {}
client_usernames = {}
username_to_socket = {}
active_channels = {}
db = None
users_collection = None
messages_collection = None
server_stats = {"start_time": datetime.utcnow(), "messages_sent": 0}

class MessageTypes:
    AUTH = "auth"
    AUTH_RESPONSE = "auth_response"
    MESSAGE = "message"
    FILE_HEADER = "file_header"
    FILE_CHUNK = "file_chunk"
    FILE_COMPLETE = "file_complete"
    CHANNEL_CREATE = "channel_create"
    CHANNEL_JOIN = "channel_join"
    CHANNEL_LEAVE = "channel_leave"
    CHANNEL_MESSAGE = "channel_message"
    CHANNEL_LIST = "channel_list"
    PEER_LIST = "peer_list"
    USER_STATUS = "user_status"
    TYPING = "typing"
    PING = "ping"
    PONG = "pong"
    ERROR = "error"
    SUCCESS = "success"

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle health check requests"""
        try:
            # Simple, safe health response
            health_data = {
                "status": "healthy",
                "service": "Secure Chat Server",
                "version": "1.0",
                "port": PORT,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Add safe stats
            try:
                health_data["connected_users"] = len(client_usernames)
                health_data["active_channels"] = len(active_channels)
                health_data["uptime_seconds"] = int((datetime.utcnow() - server_stats["start_time"]).total_seconds())
                health_data["messages_sent"] = server_stats["messages_sent"]
                
                # Safe database check
                if db is not None:
                    health_data["database"] = "connected"
                    try:
                        health_data["total_users"] = users_collection.count_documents({})
                    except:
                        health_data["total_users"] = 0
                else:
                    health_data["database"] = "in-memory"
                    health_data["total_users"] = len(getattr(authenticate_user, 'user_db', {}))
                    
            except Exception as e:
                logger.debug(f"Stats error in health check: {e}")
                # Continue with basic health data
            
            response = json.dumps(health_data, indent=2)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            self.wfile.write(response.encode())
            
        except Exception as e:
            logger.error(f"Health check error: {e}")
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            error_response = json.dumps({"status": "error", "message": str(e)})
            self.wfile.write(error_response.encode())
    
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
    
    def log_message(self, format, *args):
        # Suppress HTTP server logs
        pass

def get_total_users():
    """Get total registered users"""
    try:
        if users_collection is not None:
            return users_collection.count_documents({})
        else:
            return len(getattr(authenticate_user, 'user_db', {}))
    except Exception as e:
        logger.debug(f"Error getting user count: {e}")
        return 0

def start_health_server():
    """Start health check server"""
    try:
        # Try main port first (Railway health check)
        try:
            health_server = ThreadedHTTPServer((HOST, PORT), HealthHandler)
            logger.info(f"🌐 Health server started on {HOST}:{PORT}")
            health_server.serve_forever()
        except OSError:
            # Port busy, try alternative
            health_server = ThreadedHTTPServer((HOST, HEALTH_PORT), HealthHandler)
            logger.info(f"🌐 Health server started on {HOST}:{HEALTH_PORT}")
            health_server.serve_forever()
    except Exception as e:
        logger.error(f"Failed to start health server: {e}")

def init_database():
    """Initialize MongoDB"""
    global db, users_collection, messages_collection
    
    try:
        if MONGODB_URL:
            client = MongoClient(MONGODB_URL, serverSelectionTimeoutMS=5000)
        elif MONGODB_USERNAME and MONGODB_PASSWORD:
            uri = f"mongodb://{MONGODB_USERNAME}:{MONGODB_PASSWORD}@{MONGODB_HOST}:{MONGODB_PORT}/"
            client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        else:
            uri = f"mongodb://{MONGODB_HOST}:{MONGODB_PORT}/"
            client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        
        client.admin.command('ping')
        db = client[MONGODB_DB]
        users_collection = db.users
        messages_collection = db.messages
        
        # Create indexes
        users_collection.create_index("username", unique=True)
        messages_collection.create_index([("timestamp", -1)])
        
        logger.info("✅ MongoDB connected successfully")
        return True
        
    except Exception as e:
        logger.warning(f"⚠️ MongoDB connection failed: {e}")
        logger.info("📝 Using in-memory storage")
        return False

def hash_password(password):
    """Hash password with salt"""
    salt = "secure_chat_2024"
    return hashlib.sha256((password + salt).encode()).hexdigest()

def authenticate_user(username, password, public_key="", email=""):
    """Authenticate or register user"""
    if not username or not password:
        return {"status": "fail", "message": "Username and password required"}
    
    if len(username) > 50 or not username.replace('_', '').replace('-', '').isalnum():
        return {"status": "fail", "message": "Invalid username"}
    
    password_hash = hash_password(password)
    
    try:
        if users_collection is not None:
            # MongoDB storage
            user = users_collection.find_one({"username": username})
            if user:
                if user["password_hash"] == password_hash:
                    users_collection.update_one(
                        {"username": username},
                        {"$set": {"public_key": public_key, "last_login": datetime.utcnow()}}
                    )
                    return {"status": "success", "message": "Welcome back!"}
                else:
                    return {"status": "fail", "message": "Invalid password"}
            else:
                # Create new user
                user_data = {
                    "username": username,
                    "password_hash": password_hash,
                    "public_key": public_key,
                    "email": email,
                    "created_at": datetime.utcnow(),
                    "last_login": datetime.utcnow()
                }
                users_collection.insert_one(user_data)
                return {"status": "new_user", "message": "Account created successfully!"}
        else:
            # In-memory storage
            user_db = getattr(authenticate_user, 'user_db', {})
            if username in user_db:
                if user_db[username]["password_hash"] == password_hash:
                    user_db[username]["public_key"] = public_key
                    user_db[username]["last_login"] = datetime.now()
                    return {"status": "success", "message": "Welcome back!"}
                else:
                    return {"status": "fail", "message": "Invalid password"}
            else:
                user_db[username] = {
                    "password_hash": password_hash,
                    "public_key": public_key,
                    "email": email,
                    "created_at": datetime.now(),
                    "last_login": datetime.now()
                }
                authenticate_user.user_db = user_db
                return {"status": "new_user", "message": "Account created successfully!"}
                
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return {"status": "fail", "message": "Authentication failed"}

def get_user_public_key(username):
    """Get user's public key"""
    try:
        if users_collection is not None:
            user = users_collection.find_one({"username": username})
            return user.get("public_key", "") if user else ""
        else:
            user_db = getattr(authenticate_user, 'user_db', {})
            return user_db.get(username, {}).get("public_key", "")
    except Exception as e:
        logger.debug(f"Error getting public key: {e}")
        return ""

def broadcast_peer_list():
    """Send peer list to all clients"""
    try:
        peers = []
        for socket_obj, username in client_usernames.items():
            public_key = get_user_public_key(username)
            peers.append({
                "username": username,
                "public_key": public_key,
                "status": "online"
            })
        
        message = {
            "type": MessageTypes.PEER_LIST,
            "peers": peers,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        broadcast_message(message)
        
    except Exception as e:
        logger.error(f"Error broadcasting peer list: {e}")

def broadcast_user_status(username, status, exclude_socket=None):
    """Broadcast user status change"""
    try:
        message = {
            "type": MessageTypes.USER_STATUS,
            "username": username,
            "status": status,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        broadcast_message(message, exclude_socket)
        
    except Exception as e:
        logger.error(f"Error broadcasting user status: {e}")

def broadcast_message(message, exclude_socket=None):
    """Broadcast message to all connected clients"""
    message_data = json.dumps(message).encode()
    disconnected = []
    
    for client_socket in list(client_usernames.keys()):
        if client_socket == exclude_socket:
            continue
        try:
            client_socket.sendall(message_data)
        except:
            disconnected.append(client_socket)
    
    # Clean up disconnected clients
    for client_socket in disconnected:
        remove_client(client_socket)

def remove_client(client_socket):
    """Remove client and cleanup"""
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
            
            # Notify others
            broadcast_user_status(username, "offline", exclude_socket=client_socket)
        
        if client_socket in clients:
            del clients[client_socket]
        
        try:
            client_socket.close()
        except:
            pass
        
        # Update peer list
        if client_usernames:
            broadcast_peer_list()
            
    except Exception as e:
        logger.error(f"Error removing client: {e}")

def handle_client(client_socket, client_address):
    """Handle client connection"""
    logger.info(f"🔗 New connection from {client_address}")
    
    clients[client_socket] = {
        "address": client_address,
        "authenticated": False,
        "username": None
    }
    
    try:
        # Wait for authentication
        client_socket.settimeout(30)
        data = client_socket.recv(BUFFER_SIZE)
        
        if not data:
            return
        
        try:
            auth_data = json.loads(data.decode('utf-8'))
            username = auth_data.get("username", "").strip()
            password = auth_data.get("password", "") or auth_data.get("auth", "")
            public_key = auth_data.get("public_key", "")
            email = auth_data.get("email", "")
            
            # Authenticate
            auth_result = authenticate_user(username, password, public_key, email)
            
            # Send response
            response = {
                "type": MessageTypes.AUTH_RESPONSE,
                "timestamp": datetime.utcnow().isoformat(),
                **auth_result
            }
            client_socket.sendall(json.dumps(response).encode())
            
            if auth_result["status"] in ["success", "new_user"]:
                # Authentication successful
                clients[client_socket]["authenticated"] = True
                clients[client_socket]["username"] = username
                client_usernames[client_socket] = username
                username_to_socket[username] = client_socket
                
                logger.info(f"✅ User {username} authenticated")
                
                # Remove timeout
                client_socket.settimeout(None)
                
                # Notify others and send peer list
                broadcast_user_status(username, "online", exclude_socket=client_socket)
                broadcast_peer_list()
                
                # Handle messages
                handle_authenticated_client(client_socket, username)
            else:
                logger.warning(f"❌ Authentication failed for {username}")
                
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON from {client_address}")
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            
    except socket.timeout:
        logger.warning(f"Authentication timeout from {client_address}")
    except Exception as e:
        logger.error(f"Client handling error: {e}")
    finally:
        remove_client(client_socket)

def handle_authenticated_client(client_socket, username):
    """Handle messages from authenticated client"""
    logger.info(f"💬 Message handler started for {username}")
    
    try:
        while True:
            try:
                client_socket.settimeout(300)  # 5 minute timeout
                data = client_socket.recv(BUFFER_SIZE)
                
                if not data:
                    break
                
                client_socket.settimeout(None)
                
                try:
                    message = json.loads(data.decode('utf-8'))
                    handle_message(client_socket, username, message)
                except json.JSONDecodeError:
                    send_error(client_socket, "Invalid JSON")
                    
            except socket.timeout:
                # Send ping
                try:
                    ping = {"type": MessageTypes.PING, "timestamp": datetime.utcnow().isoformat()}
                    client_socket.sendall(json.dumps(ping).encode())
                except:
                    break
            except Exception as e:
                logger.error(f"Message error for {username}: {e}")
                break
                
    except Exception as e:
        logger.error(f"Client handler error for {username}: {e}")

def handle_message(client_socket, sender_username, message):
    """Route and handle different message types"""
    try:
        msg_type = message.get("type")
        
        if msg_type == MessageTypes.MESSAGE:
            handle_direct_message(client_socket, sender_username, message)
        elif msg_type == MessageTypes.CHANNEL_CREATE:
            handle_channel_create(client_socket, sender_username, message)
        elif msg_type == MessageTypes.CHANNEL_JOIN:
            handle_channel_join(client_socket, sender_username, message)
        elif msg_type == MessageTypes.CHANNEL_LEAVE:
            handle_channel_leave(client_socket, sender_username, message)
        elif msg_type == MessageTypes.CHANNEL_MESSAGE:
            handle_channel_message(client_socket, sender_username, message)
        elif msg_type == MessageTypes.CHANNEL_LIST:
            handle_channel_list(client_socket, sender_username)
        elif msg_type == MessageTypes.FILE_HEADER:
            handle_file_header(client_socket, sender_username, message)
        elif msg_type == MessageTypes.FILE_CHUNK:
            handle_file_chunk(client_socket, sender_username, message)
        elif msg_type == MessageTypes.FILE_COMPLETE:
            handle_file_complete(client_socket, sender_username, message)
        elif msg_type == MessageTypes.TYPING:
            handle_typing(client_socket, sender_username, message)
        elif msg_type == MessageTypes.PONG:
            logger.debug(f"Pong from {sender_username}")
        else:
            send_error(client_socket, f"Unknown message type: {msg_type}")
            
    except Exception as e:
        logger.error(f"Message handling error: {e}")
        send_error(client_socket, "Message processing error")

def handle_direct_message(client_socket, sender_username, message):
    """Handle direct messages"""
    try:
        recipient = message.get("to")
        content = message.get("content")
        
        if not recipient or not content:
            send_error(client_socket, "Missing recipient or content")
            return
        
        recipient_socket = username_to_socket.get(recipient)
        if not recipient_socket:
            send_error(client_socket, f"User {recipient} is not online")
            return
        
        # Forward message
        forward_msg = {
            "type": MessageTypes.MESSAGE,
            "from": sender_username,
            "content": content,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        try:
            recipient_socket.sendall(json.dumps(forward_msg).encode())
            
            # Send confirmation
            send_success(client_socket, "Message delivered")
            
            # Update stats
            server_stats["messages_sent"] += 1
            
            logger.info(f"💬 {sender_username} -> {recipient}")
            
        except Exception as e:
            logger.error(f"Failed to deliver message: {e}")
            send_error(client_socket, "Failed to deliver message")
            
    except Exception as e:
        logger.error(f"Direct message error: {e}")

def handle_channel_create(client_socket, creator_username, message):
    """Handle channel creation"""
    try:
        channel_name = message.get("channel_name", "").strip()
        
        if not channel_name:
            send_error(client_socket, "Channel name required")
            return
        
        if channel_name in active_channels:
            send_error(client_socket, f"Channel {channel_name} already exists")
            return
        
        # Create channel
        active_channels[channel_name] = [creator_username]
        
        send_success(client_socket, f"Channel {channel_name} created")
        logger.info(f"📢 Channel {channel_name} created by {creator_username}")
        
    except Exception as e:
        logger.error(f"Channel creation error: {e}")
        send_error(client_socket, "Channel creation failed")

def handle_channel_join(client_socket, username, message):
    """Handle channel join"""
    try:
        channel_name = message.get("channel_name", "").strip()
        
        if not channel_name:
            send_error(client_socket, "Channel name required")
            return
        
        if channel_name not in active_channels:
            send_error(client_socket, f"Channel {channel_name} does not exist")
            return
        
        if username not in active_channels[channel_name]:
            active_channels[channel_name].append(username)
        
        response = {
            "type": MessageTypes.SUCCESS,
            "message": f"Joined channel {channel_name}",
            "channel_name": channel_name,
            "members": active_channels[channel_name]
        }
        client_socket.sendall(json.dumps(response).encode())
        
        logger.info(f"📢 {username} joined channel {channel_name}")
        
    except Exception as e:
        logger.error(f"Channel join error: {e}")
        send_error(client_socket, "Failed to join channel")

def handle_channel_leave(client_socket, username, message):
    """Handle channel leave"""
    try:
        channel_name = message.get("channel_name", "").strip()
        
        if channel_name in active_channels and username in active_channels[channel_name]:
            active_channels[channel_name].remove(username)
            
            # Remove empty channels
            if not active_channels[channel_name]:
                del active_channels[channel_name]
        
        send_success(client_socket, f"Left channel {channel_name}")
        logger.info(f"📢 {username} left channel {channel_name}")
        
    except Exception as e:
        logger.error(f"Channel leave error: {e}")

def handle_channel_message(client_socket, sender_username, message):
    """Handle channel messages"""
    try:
        channel_name = message.get("channel_name")
        content = message.get("content")
        
        if not channel_name or not content:
            send_error(client_socket, "Missing channel name or content")
            return
        
        if channel_name not in active_channels:
            send_error(client_socket, f"Channel {channel_name} does not exist")
            return
        
        if sender_username not in active_channels[channel_name]:
            send_error(client_socket, f"You are not in channel {channel_name}")
            return
        
        # Broadcast to channel members
        channel_msg = {
            "type": MessageTypes.CHANNEL_MESSAGE,
            "channel_name": channel_name,
            "from": sender_username,
            "content": content,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        delivered = 0
        for member_username in active_channels[channel_name]:
            if member_username != sender_username:
                member_socket = username_to_socket.get(member_username)
                if member_socket:
                    try:
                        member_socket.sendall(json.dumps(channel_msg).encode())
                        delivered += 1
                    except:
                        pass
        
        send_success(client_socket, f"Message sent to {delivered} members")
        server_stats["messages_sent"] += 1
        
        logger.info(f"📢 Channel {channel_name}: {sender_username} -> {delivered} members")
        
    except Exception as e:
        logger.error(f"Channel message error: {e}")
        send_error(client_socket, "Channel message failed")

def handle_channel_list(client_socket, username):
    """Send channel list"""
    try:
        channels = []
        for name, members in active_channels.items():
            channels.append({
                "name": name,
                "member_count": len(members),
                "is_member": username in members
            })
        
        response = {
            "type": MessageTypes.CHANNEL_LIST,
            "channels": channels
        }
        client_socket.sendall(json.dumps(response).encode())
        
    except Exception as e:
        logger.error(f"Channel list error: {e}")

def handle_file_header(client_socket, sender_username, message):
    """Handle file transfer start"""
    try:
        recipient = message.get("to")
        filename = message.get("filename")
        file_size = message.get("file_size", 0)
        
        if not recipient or not filename:
            send_error(client_socket, "Missing file transfer parameters")
            return
        
        recipient_socket = username_to_socket.get(recipient)
        if not recipient_socket:
            send_error(client_socket, f"User {recipient} is not online")
            return
        
        # Forward file header
        forward_msg = {
            "type": MessageTypes.FILE_HEADER,
            "from": sender_username,
            "filename": filename,
            "file_size": file_size,
            "transfer_id": f"file_{sender_username}_{recipient}_{int(time.time())}"
        }
        
        recipient_socket.sendall(json.dumps(forward_msg).encode())
        logger.info(f"📁 File transfer started: {sender_username} -> {recipient}: {filename}")
        
    except Exception as e:
        logger.error(f"File header error: {e}")

def handle_file_chunk(client_socket, sender_username, message):
    """Handle file chunk"""
    try:
        recipient = message.get("to")
        if recipient:
            recipient_socket = username_to_socket.get(recipient)
            if recipient_socket:
                forward_msg = message.copy()
                forward_msg["from"] = sender_username
                recipient_socket.sendall(json.dumps(forward_msg).encode())
    except Exception as e:
        logger.error(f"File chunk error: {e}")

def handle_file_complete(client_socket, sender_username, message):
    """Handle file transfer completion"""
    try:
        recipient = message.get("to")
        if recipient:
            recipient_socket = username_to_socket.get(recipient)
            if recipient_socket:
                forward_msg = message.copy()
                forward_msg["from"] = sender_username
                recipient_socket.sendall(json.dumps(forward_msg).encode())
                logger.info(f"📁 File transfer completed: {sender_username} -> {recipient}")
    except Exception as e:
        logger.error(f"File complete error: {e}")

def handle_typing(client_socket, sender_username, message):
    """Handle typing indicators"""
    try:
        recipient = message.get("to")
        if recipient:
            recipient_socket = username_to_socket.get(recipient)
            if recipient_socket:
                forward_msg = {
                    "type": MessageTypes.TYPING,
                    "from": sender_username,
                    "is_typing": message.get("is_typing", False)
                }
                try:
                    recipient_socket.sendall(json.dumps(forward_msg).encode())
                except:
                    pass
    except:
        pass  # Ignore typing errors

def send_error(client_socket, error_message):
    """Send error response"""
    try:
        response = {
            "type": MessageTypes.ERROR,
            "message": error_message,
            "timestamp": datetime.utcnow().isoformat()
        }
        client_socket.sendall(json.dumps(response).encode())
    except:
        pass

def send_success(client_socket, success_message):
    """Send success response"""
    try:
        response = {
            "type": MessageTypes.SUCCESS,
            "message": success_message,
            "timestamp": datetime.utcnow().isoformat()
        }
        client_socket.sendall(json.dumps(response).encode())
    except:
        pass

def start_tcp_server():
    """Start TCP chat server"""
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        # Try to bind to PORT + 1000 for TCP
        tcp_port = PORT + 1000
        tcp_socket.bind((HOST, tcp_port))
        tcp_socket.listen(MAX_CLIENTS)
        
        logger.info(f"🔌 TCP server listening on {HOST}:{tcp_port}")
        
        while True:
            try:
                client_socket, client_address = tcp_socket.accept()
                
                if len(clients) >= MAX_CLIENTS:
                    logger.warning(f"Server full, rejecting {client_address}")
                    client_socket.close()
                    continue
                
                # Handle client in thread
                client_thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()
                
            except Exception as e:
                logger.error(f"Accept error: {e}")
                time.sleep(0.1)
                
    except Exception as e:
        logger.error(f"TCP server error: {e}")
    finally:
        tcp_socket.close()

def main():
    """Main server startup"""
    try:
        logger.info("🚀 Starting Secure Chat Server for Railway")
        logger.info(f"📍 Railway PORT: {PORT}")
        
        # Initialize database
        db_connected = init_database()
        logger.info(f"💾 Database: {'MongoDB' if db_connected else 'In-Memory'}")
        
        # Start health check server first (Railway requirement)
        health_thread = threading.Thread(target=start_health_server, daemon=True)
        health_thread.start()
        logger.info("🏥 Health check server started")
        
        # Give health server time to start
        time.sleep(1)
        
        # Start TCP server
        logger.info("🔌 Starting TCP chat server...")
        start_tcp_server()
        
    except KeyboardInterrupt:
        logger.info("🛑 Server shutdown requested")
    except Exception as e:
        logger.error(f"💥 Server error: {e}")
        traceback.print_exc()
    finally:
        logger.info("✅ Server shutdown complete")

if __name__ == "__main__":
    main()
