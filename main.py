# hybrid_server.py - Use EXACT working minimal server code + chat features
import socket
import json
import threading
import time
import os
import sys
import hashlib
from datetime import datetime
from pymongo import MongoClient

# Railway configuration
PORT = int(os.environ.get("PORT", 42721))
HOST = '0.0.0.0'

# MongoDB configuration
MONGODB_URL = os.environ.get("MONGO_URL")
MONGODB_HOST = os.environ.get("MONGODB_HOST", "localhost")
MONGODB_PORT = int(os.environ.get("MONGODB_PORT", "27017"))
MONGODB_DB = os.environ.get("MONGODB_DB", "secure_chat")
MONGODB_USERNAME = os.environ.get("MONGODB_USERNAME", "")
MONGODB_PASSWORD = os.environ.get("MONGODB_PASSWORD", "")

# Global state
clients = {}
client_usernames = {}
username_to_socket = {}
db = None
users_collection = None

print(f"🚀 Hybrid Chat Server Starting on {HOST}:{PORT}")
print(f"📅 Started at: {datetime.utcnow().isoformat()}")

def init_database():
    """Initialize MongoDB connection"""
    global db, users_collection
    
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
        users_collection.create_index("username", unique=True)
        print("✅ MongoDB connected")
        return True
        
    except Exception as e:
        print(f"⚠️ MongoDB failed, using in-memory: {e}")
        return False

def hash_password(password):
    """Simple password hashing"""
    salt = "secure_chat_2024"
    return hashlib.sha256((password + salt).encode()).hexdigest()

def authenticate_user(username, password, public_key="", email=""):
    """Authenticate user"""
    if not username or not password:
        return {"status": "fail", "message": "Username and password required"}
    
    if len(username) > 50:
        return {"status": "fail", "message": "Username too long"}
    
    password_hash = hash_password(password)
    
    try:
        if users_collection is not None:
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
        print(f"Authentication error: {e}")
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
    except:
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
            "type": "peer_list",
            "peers": peers,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        broadcast_message(message)
        print(f"📋 Broadcasted peer list to {len(client_usernames)} users")
        
    except Exception as e:
        print(f"Error broadcasting peer list: {e}")

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
            print(f"👋 User {username} disconnected")
            
            # Remove from tracking
            if client_socket in client_usernames:
                del client_usernames[client_socket]
            if username in username_to_socket:
                del username_to_socket[username]
        
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
        print(f"Error removing client: {e}")

def handle_authenticated_client(client_socket, username):
    """Handle messages from authenticated client with better buffer handling"""
    print(f"💬 Message handler started for: {username}")
    
    try:
        buffer = b""  # Buffer for incomplete messages
        
        while True:
            try:
                client_socket.settimeout(300)  # 5 minute timeout
                data = client_socket.recv(16384)  # Larger buffer for file transfers
                
                if not data:
                    print(f"📴 {username} disconnected")
                    break
                
                client_socket.settimeout(None)
                
                # Add to buffer
                buffer += data
                
                # Process complete messages from buffer
                while buffer:
                    try:
                        # Try to find a complete JSON message
                        brace_count = 0
                        start_found = False
                        end_pos = -1
                        
                        for i, byte in enumerate(buffer):
                            char = chr(byte)
                            if char == '{':
                                if not start_found:
                                    start_found = True
                                brace_count += 1
                            elif char == '}' and start_found:
                                brace_count -= 1
                                if brace_count == 0:
                                    end_pos = i
                                    break
                        
                        if end_pos == -1:
                            # No complete message yet, wait for more data
                            break
                        
                        # Extract complete message
                        message_data = buffer[:end_pos + 1]
                        buffer = buffer[end_pos + 1:]
                        
                        # Process the message
                        try:
                            message_str = message_data.decode('utf-8')
                            message = json.loads(message_str)
                            handle_message(client_socket, username, message)
                        except (json.JSONDecodeError, UnicodeDecodeError) as e:
                            print(f"❌ Message decode error from {username}: {e}")
                            print(f"📄 Problematic data: {message_data[:100]}...")
                            continue
                        
                    except Exception as e:
                        print(f"❌ Buffer processing error for {username}: {e}")
                        buffer = b""  # Clear buffer on error
                        break
                    
            except socket.timeout:
                # Send ping
                try:
                    ping = {"type": "ping", "timestamp": datetime.utcnow().isoformat()}
                    client_socket.sendall(json.dumps(ping).encode())
                except:
                    break
            except Exception as e:
                print(f"❌ Message receive error for {username}: {e}")
                break
                
    except Exception as e:
        print(f"❌ Client handler error for {username}: {e}")
    finally:
        remove_client(client_socket)

def handle_message(client_socket, sender_username, message):
    """Handle different message types with complete support"""
    try:
        msg_type = message.get("type")
        print(f"📨 Processing {msg_type} from {sender_username}")
        
        if msg_type == "message":
            # Direct message
            recipient = message.get("to")
            if recipient and recipient in username_to_socket:
                recipient_socket = username_to_socket[recipient]
                try:
                    forward_msg = message.copy()
                    forward_msg["from"] = sender_username
                    forward_msg["timestamp"] = datetime.utcnow().isoformat()
                    recipient_socket.sendall(json.dumps(forward_msg).encode())
                    print(f"💬 {sender_username} -> {recipient}")
                    
                    # Send delivery confirmation
                    confirm = {
                        "type": "success",
                        "message": "Message delivered",
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    client_socket.sendall(json.dumps(confirm).encode())
                except Exception as e:
                    print(f"❌ Failed to deliver message: {e}")
                    send_error(client_socket, "Failed to deliver message")
            else:
                send_error(client_socket, f"User {recipient} is not online")
        
        elif msg_type == "key_exchange":
            # Key exchange
            recipient = message.get("to")
            if recipient and recipient in username_to_socket:
                recipient_socket = username_to_socket[recipient]
                try:
                    forward_msg = message.copy()
                    forward_msg["from"] = sender_username
                    forward_msg["timestamp"] = datetime.utcnow().isoformat()
                    recipient_socket.sendall(json.dumps(forward_msg).encode())
                    print(f"🔑 Key exchange: {sender_username} -> {recipient}")
                except:
                    send_error(client_socket, "Failed to send key")
            else:
                send_error(client_socket, f"User {recipient} is not online")
        
        elif msg_type == "file_header":
            # File transfer start
            recipient = message.get("to")
            filename = message.get("filename", "unknown")
            filesize = message.get("filesize", 0)
            
            if recipient and recipient in username_to_socket:
                recipient_socket = username_to_socket[recipient]
                try:
                    forward_msg = message.copy()
                    forward_msg["from"] = sender_username
                    forward_msg["timestamp"] = datetime.utcnow().isoformat()
                    recipient_socket.sendall(json.dumps(forward_msg).encode())
                    print(f"📁 File transfer started: {sender_username} -> {recipient}: {filename} ({filesize} bytes)")
                except:
                    send_error(client_socket, "Failed to start file transfer")
            else:
                send_error(client_socket, f"User {recipient} is not online")
        
        elif msg_type == "file_chunk":
            # File chunk
            recipient = message.get("to")
            if recipient and recipient in username_to_socket:
                recipient_socket = username_to_socket[recipient]
                try:
                    forward_msg = message.copy()
                    forward_msg["from"] = sender_username
                    recipient_socket.sendall(json.dumps(forward_msg).encode())
                    # Don't log every chunk to avoid spam
                except:
                    send_error(client_socket, "Failed to send file chunk")
            else:
                send_error(client_socket, f"User {recipient} is not online")
        
        elif msg_type == "file_end":
            # File transfer complete
            recipient = message.get("to")
            filename = message.get("filename", "unknown")
            
            if recipient and recipient in username_to_socket:
                recipient_socket = username_to_socket[recipient]
                try:
                    forward_msg = message.copy()
                    forward_msg["from"] = sender_username
                    forward_msg["timestamp"] = datetime.utcnow().isoformat()
                    recipient_socket.sendall(json.dumps(forward_msg).encode())
                    print(f"📁 File transfer completed: {sender_username} -> {recipient}: {filename}")
                except:
                    send_error(client_socket, "Failed to complete file transfer")
            else:
                send_error(client_socket, f"User {recipient} is not online")
        
        elif msg_type == "ping":
            # Respond to ping with pong
            try:
                pong = {
                    "type": "pong", 
                    "timestamp": datetime.utcnow().isoformat()
                }
                client_socket.sendall(json.dumps(pong).encode())
                print(f"🏓 Ping-pong with {sender_username}")
            except:
                pass
        
        elif msg_type == "pong":
            # Acknowledge pong
            print(f"🏓 Pong from {sender_username}")
        
        elif msg_type == "typing_indicator":
            # Forward typing indicator
            recipient = message.get("to")
            if recipient and recipient in username_to_socket:
                recipient_socket = username_to_socket[recipient]
                try:
                    forward_msg = message.copy()
                    forward_msg["from"] = sender_username
                    recipient_socket.sendall(json.dumps(forward_msg).encode())
                except:
                    pass  # Ignore typing indicator failures
        
        else:
            print(f"❓ Unknown message type: {msg_type}")
            send_error(client_socket, f"Unknown message type: {msg_type}")
            
    except Exception as e:
        print(f"❌ Message handling error: {e}")
        send_error(client_socket, "Message processing error")

def send_error(client_socket, error_message):
    """Send error response to client"""
    try:
        error_response = {
            "type": "error",
            "message": error_message,
            "timestamp": datetime.utcnow().isoformat()
        }
        client_socket.sendall(json.dumps(error_response).encode())
    except Exception as e:
        print(f"❌ Failed to send error: {e}")

def send_success(client_socket, success_message):
    """Send success response to client"""
    try:
        success_response = {
            "type": "success",
            "message": success_message,
            "timestamp": datetime.utcnow().isoformat()
        }
        client_socket.sendall(json.dumps(success_response).encode())
    except Exception as e:
        print(f"❌ Failed to send success: {e}")

def handle_client(client_socket, client_address):
    """Handle any client connection - EXACT COPY of working minimal server"""
    print(f"\n🔗 NEW CONNECTION: {client_address}")
    
    try:
        # Set timeout
        client_socket.settimeout(10)
        
        # Read ALL data - EXACT SAME as working minimal server
        all_data = b""
        try:
            while True:
                chunk = client_socket.recv(1024)
                if not chunk:
                    break
                all_data += chunk
                print(f"📥 Received chunk: {len(chunk)} bytes")
                
                # Check if we have complete data - EXACT SAME logic
                try:
                    decoded = all_data.decode('utf-8')
                    if decoded.strip().endswith('}'):  # Complete JSON
                        break
                    elif '\r\n\r\n' in decoded:  # Complete HTTP
                        break
                except:
                    pass
                    
        except socket.timeout:
            print(f"⏰ Timeout reading from {client_address}")
        
        if not all_data:
            print(f"❌ No data from {client_address}")
            return
        
        print(f"📊 Total received: {len(all_data)} bytes")
        
        try:
            decoded_data = all_data.decode('utf-8')
            print(f"📄 Decoded data:\n{decoded_data}")
            
            # Check what type of request this is - EXACT SAME logic
            if decoded_data.startswith('GET ') or decoded_data.startswith('POST '):
                print("🌐 HTTP REQUEST detected")
                
                # Send HTTP response - EXACT SAME as working server
                http_response = """HTTP/1.1 200 OK\r
Content-Type: application/json\r
Connection: close\r
\r
{"status": "ok", "message": "Hybrid chat server running", "timestamp": "%s"}""" % datetime.utcnow().isoformat()
                
                client_socket.sendall(http_response.encode())
                print("📤 HTTP response sent")
                
            elif decoded_data.strip().startswith('{'):
                print("💬 JSON REQUEST detected")
                
                try:
                    json_data = json.loads(decoded_data.strip())
                    print(f"✅ JSON parsed: {json_data}")
                    
                    # Check if it's authentication - EXACT SAME logic
                    if 'username' in json_data:
                        username = json_data.get('username')
                        password = json_data.get('password')
                        public_key = json_data.get('public_key', '')
                        email = json_data.get('email', '')
                        
                        print(f"🔐 Authentication request for: {username}")
                        
                        # Authenticate user
                        auth_result = authenticate_user(username, password, public_key, email)
                        
                        # Send JSON response - EXACT SAME format as working server
                        response = {
                            "type": "auth_response",
                            "status": auth_result["status"],
                            "message": auth_result["message"],
                            "timestamp": datetime.utcnow().isoformat()
                        }
                        
                        response_json = json.dumps(response)
                        print(f"📤 Sending JSON response: {response_json}")
                        
                        client_socket.sendall(response_json.encode('utf-8'))
                        print("✅ JSON response sent successfully")
                        
                        # If authentication successful, continue with chat functionality
                        if auth_result["status"] in ["success", "new_user"]:
                            print(f"✅ Authentication successful for {username}")
                            
                            # Add to tracking
                            clients[client_socket] = {
                                "address": client_address,
                                "authenticated": True,
                                "username": username,
                                "connected_at": datetime.utcnow()
                            }
                            client_usernames[client_socket] = username
                            username_to_socket[username] = client_socket
                            
                            # Remove timeout
                            client_socket.settimeout(None)
                            
                            # Send peer list
                            broadcast_peer_list()
                            
                            # Handle authenticated client
                            print(f"🎯 Starting message handler for {username}")
                            handle_authenticated_client(client_socket, username)
                        else:
                            print(f"❌ Authentication failed for {username}")
                            time.sleep(1)
                        
                    else:
                        print("❓ Unknown JSON format")
                        
                except json.JSONDecodeError as e:
                    print(f"❌ JSON parse error: {e}")
                    
            else:
                print(f"❓ Unknown protocol: {decoded_data[:100]}")
                
        except UnicodeDecodeError:
            print(f"❌ Cannot decode as UTF-8: {all_data[:100]}")
        
    except Exception as e:
        print(f"❌ Error handling {client_address}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            client_socket.close()
        except:
            pass
        print(f"🔌 Connection closed: {client_address}")

def main():
    """Main server loop"""
    # Initialize database
    init_database()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(10)
        
        print(f"✅ Server listening on {HOST}:{PORT}")
        print(f"🌐 Health check: http://your-app.railway.app/")
        print(f"💬 TCP test: connect to port {PORT}")
        print("=" * 50)
        
        connection_count = 0
        
        while True:
            try:
                client_socket, client_address = server_socket.accept()
                connection_count += 1
                
                print(f"\n📞 Connection #{connection_count} from {client_address}")
                
                # Handle in thread
                client_thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()
                
            except KeyboardInterrupt:
                print("\n🛑 Server shutdown requested")
                break
            except Exception as e:
                print(f"❌ Accept error: {e}")
                
    except Exception as e:
        print(f"❌ Server startup error: {e}")
    finally:
        server_socket.close()
        print("✅ Server shutdown complete")

if __name__ == "__main__":
    main()
