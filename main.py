# minimal_test_server.py - Debug Railway Connection Issues
import socket
import json
import threading
import time
import os
import sys
from datetime import datetime

# Railway configuration
PORT = int(os.environ.get("PORT", 42721))
HOST = '0.0.0.0'

print(f"🚀 Minimal Test Server Starting on {HOST}:{PORT}")
print(f"📅 Started at: {datetime.utcnow().isoformat()}")

def handle_client(client_socket, client_address):
    """Handle any client connection"""
    print(f"\n🔗 NEW CONNECTION: {client_address}")
    
    try:
        # Set timeout
        client_socket.settimeout(10)
        
        # Read ALL data
        all_data = b""
        try:
            while True:
                chunk = client_socket.recv(1024)
                if not chunk:
                    break
                all_data += chunk
                print(f"📥 Received chunk: {len(chunk)} bytes")
                
                # Check if we have complete data
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
            
            # Check what type of request this is
            if decoded_data.startswith('GET ') or decoded_data.startswith('POST '):
                print("🌐 HTTP REQUEST detected")
                
                # Send HTTP response
                http_response = """HTTP/1.1 200 OK\r
Content-Type: application/json\r
Connection: close\r
\r
{"status": "ok", "message": "Minimal test server running", "timestamp": "%s"}""" % datetime.utcnow().isoformat()
                
                client_socket.sendall(http_response.encode())
                print("📤 HTTP response sent")
                
            elif decoded_data.strip().startswith('{'):
                print("💬 JSON REQUEST detected")
                
                try:
                    json_data = json.loads(decoded_data.strip())
                    print(f"✅ JSON parsed: {json_data}")
                    
                    # Check if it's authentication
                    if 'username' in json_data:
                        username = json_data.get('username')
                        print(f"🔐 Authentication request for: {username}")
                        
                        # Send JSON response
                        response = {
                            "type": "auth_response",
                            "status": "success",
                            "message": f"Hello {username}! Test server responding.",
                            "timestamp": datetime.utcnow().isoformat()
                        }
                        
                        response_json = json.dumps(response)
                        print(f"📤 Sending JSON response: {response_json}")
                        
                        client_socket.sendall(response_json.encode('utf-8'))
                        print("✅ JSON response sent successfully")
                        
                        # Keep connection alive for a bit
                        time.sleep(2)
                        
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
