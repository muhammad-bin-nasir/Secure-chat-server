#!/usr/bin/env python3
"""
Simple Chat Client for Railway Server - No Encryption Version
Compatible with the Railway secure chat server for testing purposes
"""

import sys
import json
import socket
import threading
import time
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QLineEdit, QPushButton, QLabel, QListWidget, QMessageBox, 
    QInputDialog, QSplitter, QTabWidget, QProgressBar, QFrame
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QThread
from PyQt5.QtGui import QFont, QPalette, QColor

class MessageSignal(QObject):
    """Signal handler for thread-safe GUI updates"""
    message_received = pyqtSignal(str, str)  # sender, message
    peer_list_updated = pyqtSignal(list)     # list of peers
    system_message = pyqtSignal(str)         # system messages
    status_changed = pyqtSignal(str, str)    # status, color

class SimpleChatClient(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔗 Simple Chat Client - Railway Compatible")
        self.resize(1000, 700)
        
        # Connection variables
        self.socket = None
        self.username = ""
        self.connected = False
        self.peers = []
        
        # Signal handler
        self.signals = MessageSignal()
        self.signals.message_received.connect(self.display_message)
        self.signals.peer_list_updated.connect(self.update_peer_list)
        self.signals.system_message.connect(self.display_system_message)
        self.signals.status_changed.connect(self.update_status)
        
        self.init_ui()
        self.apply_styles()

    def init_ui(self):
        """Initialize the user interface"""
        main_layout = QVBoxLayout()
        
        # Title
        title_label = QLabel("🔗 Simple Chat Client")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        main_layout.addWidget(title_label)
        
        # Connection section
        conn_frame = QFrame()
        conn_frame.setFrameStyle(QFrame.Box)
        conn_layout = QHBoxLayout()
        
        # Connection inputs
        conn_layout.addWidget(QLabel("Username:"))
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username")
        conn_layout.addWidget(self.username_input)
        
        conn_layout.addWidget(QLabel("Server:"))
        self.server_input = QLineEdit("secure-chat-server-production.up.railway.app")
        conn_layout.addWidget(self.server_input)
        
        conn_layout.addWidget(QLabel("Port:"))
        self.port_input = QLineEdit("5000")
        self.port_input.setFixedWidth(80)
        conn_layout.addWidget(self.port_input)
        
        # Connect button
        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self.connect_to_server)
        conn_layout.addWidget(self.connect_btn)
        
        # Disconnect button
        self.disconnect_btn = QPushButton("Disconnect")
        self.disconnect_btn.clicked.connect(self.disconnect_from_server)
        self.disconnect_btn.setEnabled(False)
        conn_layout.addWidget(self.disconnect_btn)
        
        conn_frame.setLayout(conn_layout)
        main_layout.addWidget(conn_frame)
        
        # Status bar
        self.status_label = QLabel("🔴 Not connected")
        self.status_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.status_label)
        
        # Main content area
        content_splitter = QSplitter(Qt.Horizontal)
        
        # Chat area
        chat_widget = QWidget()
        chat_layout = QVBoxLayout()
        
        # Chat display
        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_display.setFont(QFont("Consolas", 10))
        chat_layout.addWidget(QLabel("💬 Chat Messages:"))
        chat_layout.addWidget(self.chat_display)
        
        # Message input area
        msg_frame = QFrame()
        msg_frame.setFrameStyle(QFrame.Box)
        msg_layout = QHBoxLayout()
        
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message here...")
        self.message_input.returnPressed.connect(self.send_message)
        msg_layout.addWidget(self.message_input)
        
        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self.send_message)
        self.send_btn.setEnabled(False)
        msg_layout.addWidget(self.send_btn)
        
        msg_frame.setLayout(msg_layout)
        chat_layout.addWidget(msg_frame)
        
        chat_widget.setLayout(chat_layout)
        content_splitter.addWidget(chat_widget)
        
        # Peers panel
        peers_widget = QWidget()
        peers_layout = QVBoxLayout()
        
        peers_layout.addWidget(QLabel("👥 Connected Peers:"))
        self.peers_list = QListWidget()
        self.peers_list.setFixedWidth(250)
        peers_layout.addWidget(self.peers_list)
        
        # Connection info
        self.info_display = QTextEdit()
        self.info_display.setReadOnly(True)
        self.info_display.setMaximumHeight(150)
        self.info_display.setFont(QFont("Consolas", 9))
        peers_layout.addWidget(QLabel("ℹ️ Connection Info:"))
        peers_layout.addWidget(self.info_display)
        
        peers_widget.setLayout(peers_layout)
        content_splitter.addWidget(peers_widget)
        
        content_splitter.setSizes([750, 250])
        main_layout.addWidget(content_splitter)
        
        self.setLayout(main_layout)

    def apply_styles(self):
        """Apply modern styling to the application"""
        self.setStyleSheet("""
            QWidget {
                background-color: #f0f0f0;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            
            QFrame {
                background-color: white;
                border: 1px solid #d0d0d0;
                border-radius: 5px;
                padding: 5px;
                margin: 2px;
            }
            
            QLineEdit {
                padding: 8px;
                border: 2px solid #d0d0d0;
                border-radius: 5px;
                background-color: white;
                font-size: 12px;
            }
            
            QLineEdit:focus {
                border-color: #4CAF50;
            }
            
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 12px;
            }
            
            QPushButton:hover {
                background-color: #45a049;
            }
            
            QPushButton:pressed {
                background-color: #3d8b40;
            }
            
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
            
            QTextEdit {
                border: 1px solid #d0d0d0;
                border-radius: 5px;
                background-color: white;
                padding: 8px;
            }
            
            QListWidget {
                border: 1px solid #d0d0d0;
                border-radius: 5px;
                background-color: white;
                padding: 5px;
            }
            
            QListWidget::item {
                padding: 5px;
                border-bottom: 1px solid #e0e0e0;
            }
            
            QListWidget::item:selected {
                background-color: #4CAF50;
                color: white;
            }
            
            QLabel {
                font-weight: bold;
                color: #333333;
                margin: 5px 0px;
            }
        """)

    def connect_to_server(self):
        """Connect to the chat server"""
        username = self.username_input.text().strip()
        server = self.server_input.text().strip()
        
        if not username:
            QMessageBox.warning(self, "Input Error", "Please enter a username!")
            return
            
        if not server:
            QMessageBox.warning(self, "Input Error", "Please enter a server address!")
            return
        
        try:
            port = int(self.port_input.text())
        except ValueError:
            QMessageBox.warning(self, "Input Error", "Please enter a valid port number!")
            return
        
        # Validate username
        if len(username) > 50:
            QMessageBox.warning(self, "Input Error", "Username too long (max 50 characters)!")
            return
            
        if not username.replace('_', '').replace('-', '').isalnum():
            QMessageBox.warning(self, "Input Error", 
                              "Username can only contain letters, numbers, underscores, and hyphens!")
            return
        
        # Get password
        password, ok = QInputDialog.getText(
            self, 
            "Authentication", 
            f"Enter password for user '{username}':\n(New users: create any password)",
            QLineEdit.Password
        )
        
        if not ok or not password:
            return
            
        if len(password) > 128:
            QMessageBox.warning(self, "Input Error", "Password too long (max 128 characters)!")
            return
        
        self.username = username
        
        # Disable connection controls
        self.connect_btn.setEnabled(False)
        self.username_input.setEnabled(False)
        self.server_input.setEnabled(False)
        self.port_input.setEnabled(False)
        
        self.signals.status_changed.emit("Connecting...", "orange")
        self.add_info_message(f"Attempting to connect to {server}:{port}...")
        
        # Start connection in separate thread
        connection_thread = threading.Thread(
            target=self._connect_worker, 
            args=(server, port, username, password),
            daemon=True
        )
        connection_thread.start()

    def _connect_worker(self, server, port, username, password):
        """Worker thread for connection"""
        try:
            # Create socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(15)
            
            # Connect
            self.socket.connect((server, port))
            self.signals.system_message.emit(f"Connected to {server}:{port}")
            
            # Create dummy public key for compatibility
            dummy_public_key = f"-----BEGIN PUBLIC KEY-----\nDUMMY_KEY_FOR_TESTING_{username}\n-----END PUBLIC KEY-----"
            
            # Send authentication
            auth_data = {
                "username": username,
                "public_key": dummy_public_key,
                "auth": password
            }
            
            auth_json = json.dumps(auth_data)
            self.socket.sendall(auth_json.encode('utf-8'))
            
            self.signals.status_changed.emit("Authenticating...", "orange")
            self.signals.system_message.emit("Authentication data sent, waiting for response...")
            
            # Start message listener
            self.connected = True
            listener_thread = threading.Thread(target=self._message_listener, daemon=True)
            listener_thread.start()
            
        except socket.timeout:
            self.signals.system_message.emit("❌ Connection timeout!")
            self._connection_failed()
        except ConnectionRefusedError:
            self.signals.system_message.emit("❌ Connection refused by server!")
            self._connection_failed()
        except Exception as e:
            self.signals.system_message.emit(f"❌ Connection error: {e}")
            self._connection_failed()

    def _connection_failed(self):
        """Handle connection failure"""
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        
        self.signals.status_changed.emit("Connection Failed", "red")
        
        # Re-enable connection controls
        self.connect_btn.setEnabled(True)
        self.username_input.setEnabled(True)
        self.server_input.setEnabled(True)
        self.port_input.setEnabled(True)

    def _message_listener(self):
        """Listen for messages from server"""
        try:
            while self.connected and self.socket:
                try:
                    # Set timeout for regular checks
                    self.socket.settimeout(30)
                    data = self.socket.recv(16384)
                    
                    if not data:
                        self.signals.system_message.emit("Server disconnected")
                        break
                    
                    # Process received data
                    try:
                        data_str = data.decode('utf-8')
                        
                        # Handle single JSON message
                        try:
                            message = json.loads(data_str)
                            self._process_message(message)
                        except json.JSONDecodeError:
                            # Try to handle multiple JSON objects
                            lines = data_str.strip().split('\n')
                            for line in lines:
                                if line.strip():
                                    try:
                                        message = json.loads(line.strip())
                                        self._process_message(message)
                                    except json.JSONDecodeError:
                                        continue
                                        
                    except UnicodeDecodeError as e:
                        self.signals.system_message.emit(f"Unicode decode error: {e}")
                        continue
                        
                except socket.timeout:
                    # Send keepalive
                    try:
                        ping = json.dumps({"type": "ping"})
                        self.socket.sendall(ping.encode())
                    except:
                        break
                    continue
                except Exception as e:
                    self.signals.system_message.emit(f"Message receive error: {e}")
                    break
                    
        except Exception as e:
            self.signals.system_message.emit(f"Listener error: {e}")
        finally:
            self._handle_disconnection()

    def _process_message(self, message):
        """Process incoming messages"""
        msg_type = message.get("type")
        
        if msg_type == "auth_result":
            status = message.get("status")
            msg_text = message.get("message", "")
            
            if status == "success":
                self.signals.system_message.emit(f"✅ Login successful! {msg_text}")
                self.signals.status_changed.emit("Connected & Authenticated", "green")
                self._enable_chat()
            elif status == "new_user":
                self.signals.system_message.emit(f"🆕 Account created! {msg_text}")
                self.signals.status_changed.emit("Connected & Authenticated", "green")
                self._enable_chat()
            elif status in ["fail", "error"]:
                self.signals.system_message.emit(f"❌ Authentication failed: {msg_text}")
                self.signals.status_changed.emit("Authentication Failed", "red")
                self.disconnect_from_server()
        
        elif msg_type == "peer_list":
            peers = message.get("peers", [])
            peer_names = []
            for peer in peers:
                if isinstance(peer, dict):
                    peer_names.append(peer.get("username", "Unknown"))
                else:
                    peer_names.append(str(peer))
            
            # Remove self from peer list
            if self.username in peer_names:
                peer_names.remove(self.username)
                
            self.signals.peer_list_updated.emit(peer_names)
            self.signals.system_message.emit(f"Peer list updated: {len(peer_names)} peers online")
        
        elif msg_type == "message":
            sender = message.get("from", "Unknown")
            # Since we're not using encryption, we'll display a placeholder
            msg_text = "[Encrypted message - encryption not supported in test client]"
            self.signals.message_received.emit(sender, msg_text)
        
        elif msg_type == "ping":
            # Respond to server ping
            try:
                pong = json.dumps({"type": "pong"})
                self.socket.sendall(pong.encode())
            except:
                pass
        
        elif msg_type == "error":
            error_msg = message.get("message", "Unknown error")
            self.signals.system_message.emit(f"Server error: {error_msg}")
        
        else:
            self.signals.system_message.emit(f"Unknown message type: {msg_type}")

    def _enable_chat(self):
        """Enable chat functionality after successful authentication"""
        self.send_btn.setEnabled(True)
        self.message_input.setEnabled(True)
        self.disconnect_btn.setEnabled(True)
        self.add_info_message("✅ Chat enabled - you can now send messages")

    def _handle_disconnection(self):
        """Handle disconnection cleanup"""
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        
        self.signals.status_changed.emit("Disconnected", "red")
        self.signals.peer_list_updated.emit([])
        
        # Reset UI state
        self.connect_btn.setEnabled(True)
        self.disconnect_btn.setEnabled(False)
        self.send_btn.setEnabled(False)
        self.message_input.setEnabled(False)
        self.username_input.setEnabled(True)
        self.server_input.setEnabled(True)
        self.port_input.setEnabled(True)

    def disconnect_from_server(self):
        """Disconnect from server"""
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        
        self.signals.system_message.emit("Disconnected from server")
        self._handle_disconnection()

    def send_message(self):
        """Send a message to selected peer"""
        message_text = self.message_input.text().strip()
        if not message_text:
            return
        
        selected_items = self.peers_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Peer Selected", "Please select a peer to send the message to!")
            return
        
        recipient = selected_items[0].text()
        
        if not self.connected or not self.socket:
            QMessageBox.warning(self, "Not Connected", "Not connected to server!")
            return
        
        # Note: Since this is a test client without encryption,
        # we'll send a simple unencrypted message with a warning
        simple_message = {
            "type": "test_message",
            "to": recipient,
            "from": self.username,
            "message": f"[UNENCRYPTED TEST] {message_text}"
        }
        
        try:
            message_json = json.dumps(simple_message)
            self.socket.sendall(message_json.encode('utf-8'))
            
            # Display in chat
            timestamp = time.strftime("%H:%M:%S")
            self.chat_display.append(f"[{timestamp}] You to {recipient}: {message_text}")
            self.message_input.clear()
            
        except Exception as e:
            self.signals.system_message.emit(f"Failed to send message: {e}")

    def display_message(self, sender, message):
        """Display received message"""
        timestamp = time.strftime("%H:%M:%S")
        self.chat_display.append(f"[{timestamp}] {sender}: {message}")

    def display_system_message(self, message):
        """Display system message"""
        timestamp = time.strftime("%H:%M:%S")
        self.chat_display.append(f"[{timestamp}] SYSTEM: {message}")

    def update_peer_list(self, peers):
        """Update the peers list"""
        self.peers = peers
        self.peers_list.clear()
        for peer in peers:
            self.peers_list.addItem(peer)
        
        self.add_info_message(f"Online peers: {len(peers)}")

    def update_status(self, status, color):
        """Update status label"""
        color_symbols = {
            "red": "🔴",
            "green": "🟢", 
            "orange": "🟡"
        }
        symbol = color_symbols.get(color, "🔴")
        self.status_label.setText(f"{symbol} {status}")
        
        # Apply color styling
        color_codes = {
            "red": "#ff4444",
            "green": "#44ff44",
            "orange": "#ffaa44"
        }
        color_code = color_codes.get(color, "#ff4444")
        self.status_label.setStyleSheet(f"color: {color_code}; font-weight: bold; padding: 5px;")

    def add_info_message(self, message):
        """Add message to info display"""
        timestamp = time.strftime("%H:%M:%S")
        self.info_display.append(f"[{timestamp}] {message}")

    def closeEvent(self, event):
        """Handle application close"""
        if self.connected:
            self.disconnect_from_server()
        event.accept()

def main():
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Simple Chat Client")
    app.setApplicationVersion("1.0")
    app.setOrganizationName("Railway Chat Test")
    
    # Create and show the main window
    window = SimpleChatClient()
    window.show()
    
        # Add welcome message with correct TCP endpoint
        window.display_system_message("Welcome to Simple Chat Client!")
        window.display_system_message("This is a test client without encryption for Railway server testing.")
        window.display_system_message("Server: tramway.proxy.rlwy.net:42721 (Railway TCP Proxy)")
        window.display_system_message("Enter your credentials and click Connect to get started.")
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
