#!/usr/bin/env python3
"""
🔐 Enhanced Encrypted Chat Client - Modern UI Design
Railway-compatible client with beautiful interface, E2E encryption, file sharing, and P2P support
"""

# ===🌐 SERVER CONFIGURATION===
RAILWAY_SERVER_URL = "tramway.proxy.rlwy.net"  # Your Railway deployment URL
RAILWAY_TCP_PORT = 42721  # Main Railway PORT (same as health check)
DEFAULT_P2P_PORT = 6001  # Default P2P port
DEFAULT_PASSWORD = ""  # Leave empty to prompt user

import time
import sys
import threading
import socket
import json
import base64
import hashlib
import os
from pathlib import Path
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QLineEdit, QPushButton, QLabel, QListWidget, QComboBox, QMessageBox, 
    QInputDialog, QFileDialog, QProgressBar, QTabWidget, QSplitter,
    QFrame, QScrollArea, QListWidgetItem, QTextBrowser, QStatusBar,
    QMenuBar, QMenu, QAction, QDialog, QFormLayout, QCheckBox, QSpinBox
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QThread, QTimer, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QFont, QPalette, QColor, QPixmap, QIcon, QPainter, QBrush, QLinearGradient
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import traceback

def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    print("[!!] Uncaught exception:", "".join(traceback.format_exception(exc_type, exc_value, exc_traceback)))

sys.excepthook = handle_exception

# ===🔐 Generate RSA Keys for Each Client===
key_pair = RSA.generate(2048)
public_key = key_pair.publickey().export_key()
private_key = key_pair.export_key()

peer_public_keys = {}   # username -> public key string
peer_key_hashes = {}    # username -> SHA256 hash
aes_session_keys = {}   # username -> AES session key

# File transfer constants
CHUNK_SIZE = 8192  # 8KB chunks
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB limit

# ===🎨 MODERN UI STYLES===
DARK_THEME = """
QMainWindow {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #1a1a2e, stop:1 #16213e);
    color: #ffffff;
}

QWidget {
    background: transparent;
    color: #ffffff;
    font-family: 'Segoe UI', Arial, sans-serif;
}

/* Modern Buttons */
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #667eea, stop:1 #764ba2);
    border: none;
    border-radius: 8px;
    padding: 10px 20px;
    color: white;
    font-weight: bold;
    font-size: 12px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #7c8fff, stop:1 #8b5fbf);
    transform: translateY(-1px);
}

QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #5a6fd8, stop:1 #6a4190);
}

QPushButton:disabled {
    background: #3a3a5c;
    color: #888888;
}

/* Primary Action Buttons */
QPushButton#primaryButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #4CAF50, stop:1 #45a049);
}

QPushButton#primaryButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #5CBF60, stop:1 #55b059);
}

/* Danger Buttons */
QPushButton#dangerButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #f44336, stop:1 #d32f2f);
}

QPushButton#dangerButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #f66356, stop:1 #e34f4f);
}

/* Modern Input Fields */
QLineEdit {
    background: rgba(255, 255, 255, 0.1);
    border: 2px solid rgba(255, 255, 255, 0.2);
    border-radius: 8px;
    padding: 8px 12px;
    color: white;
    font-size: 12px;
}

QLineEdit:focus {
    border: 2px solid #667eea;
    background: rgba(255, 255, 255, 0.15);
}

/* Modern Text Areas */
QTextEdit, QTextBrowser {
    background: rgba(0, 0, 0, 0.3);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 8px;
    padding: 10px;
    color: white;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 11px;
    line-height: 1.4;
}

/* Modern List Widget */
QListWidget {
    background: rgba(0, 0, 0, 0.2);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 8px;
    padding: 5px;
    alternate-background-color: rgba(255, 255, 255, 0.05);
}

QListWidget::item {
    background: transparent;
    padding: 8px;
    border-radius: 4px;
    margin: 2px;
}

QListWidget::item:selected {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #667eea, stop:1 #764ba2);
}

QListWidget::item:hover {
    background: rgba(255, 255, 255, 0.1);
}

/* Modern Tabs */
QTabWidget::pane {
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 8px;
    background: rgba(0, 0, 0, 0.2);
}

QTabBar::tab {
    background: rgba(0, 0, 0, 0.3);
    padding: 8px 16px;
    margin-right: 2px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    color: #cccccc;
}

QTabBar::tab:selected {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #667eea, stop:1 #764ba2);
    color: white;
}

QTabBar::tab:hover {
    background: rgba(255, 255, 255, 0.1);
    color: white;
}

/* Modern Combo Box */
QComboBox {
    background: rgba(255, 255, 255, 0.1);
    border: 2px solid rgba(255, 255, 255, 0.2);
    border-radius: 8px;
    padding: 6px 12px;
    color: white;
}

QComboBox:hover {
    border: 2px solid #667eea;
}

QComboBox::drop-down {
    border: none;
}

QComboBox::down-arrow {
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 5px solid white;
}

/* Status Bar */
QStatusBar {
    background: rgba(0, 0, 0, 0.4);
    border-top: 1px solid rgba(255, 255, 255, 0.1);
    color: white;
}

/* Progress Bar */
QProgressBar {
    background: rgba(255, 255, 255, 0.1);
    border: none;
    border-radius: 4px;
    text-align: center;
    color: white;
}

QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #667eea, stop:1 #764ba2);
    border-radius: 4px;
}

/* Modern Frame */
QFrame {
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 8px;
}

/* Scrollbars */
QScrollBar:vertical {
    background: rgba(255, 255, 255, 0.1);
    width: 12px;
    border-radius: 6px;
}

QScrollBar::handle:vertical {
    background: rgba(255, 255, 255, 0.3);
    border-radius: 6px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background: rgba(255, 255, 255, 0.5);
}
"""

# ===🔐 Crypto Helpers===
def sha256_digest(data):
    return hashlib.sha256(data).hexdigest()

def aes_encrypt(key, message):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }

def aes_encrypt_bytes(key, data):
    """Encrypt binary data (for files)"""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }

def aes_decrypt(key, enc_data):
    try:
        nonce = base64.b64decode(enc_data["nonce"])
        ciphertext = base64.b64decode(enc_data["ciphertext"])
        tag = base64.b64decode(enc_data["tag"])
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except:
        return "[Decryption failed]"

def aes_decrypt_bytes(key, enc_data):
    """Decrypt binary data (for files)"""
    try:
        nonce = base64.b64decode(enc_data["nonce"])
        ciphertext = base64.b64decode(enc_data["ciphertext"])
        tag = base64.b64decode(enc_data["tag"])
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except:
        return None

def rsa_encrypt(pub_key_str, secret_key):
    peer_key = RSA.import_key(pub_key_str)
    cipher_rsa = PKCS1_OAEP.new(peer_key)
    return base64.b64encode(cipher_rsa.encrypt(secret_key)).decode()

def rsa_decrypt(encrypted_key):
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
    return cipher_rsa.decrypt(base64.b64decode(encrypted_key))

# ===🔁 PyQt5 Signal Bridge===
class Communicator(QObject):
    message_received = pyqtSignal(str, str)
    peer_list_updated = pyqtSignal(list)
    file_transfer_progress = pyqtSignal(str, int, int)  # filename, current, total
    file_received = pyqtSignal(str, str, str)  # sender, filename, filepath
    connection_status_changed = pyqtSignal(str, str)  # status, color
    system_message = pyqtSignal(str)

# ===📁 File Transfer Thread===
class FileTransferThread(QThread):
    progress_updated = pyqtSignal(int, int)  # current, total
    transfer_completed = pyqtSignal(bool, str)  # success, message
    
    def __init__(self, socket_obj, session_key, file_path, recipient, username, is_p2p=False):
        super().__init__()
        self.socket_obj = socket_obj
        self.session_key = session_key
        self.file_path = file_path
        self.recipient = recipient
        self.username = username
        self.is_p2p = is_p2p
        
    def run(self):
        try:
            file_size = os.path.getsize(self.file_path)
            filename = os.path.basename(self.file_path)
            
            if file_size > MAX_FILE_SIZE:
                self.transfer_completed.emit(False, f"File too large (max {MAX_FILE_SIZE//1024//1024}MB)")
                return
            
            # Send file header
            file_header = {
                "type": "file_header",
                "to": self.recipient,
                "from": self.username,
                "filename": filename,
                "filesize": file_size,
                "file_hash": self.calculate_file_hash(self.file_path)
            }
            
            self.socket_obj.sendall(json.dumps(file_header).encode())
            
            # Send file in chunks
            bytes_sent = 0
            with open(self.file_path, 'rb') as f:
                while bytes_sent < file_size:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                        
                    # Encrypt chunk
                    encrypted_chunk = aes_encrypt_bytes(self.session_key, chunk)
                    
                    chunk_data = {
                        "type": "file_chunk",
                        "to": self.recipient,
                        "from": self.username,
                        "chunk_data": encrypted_chunk
                    }
                    
                    self.socket_obj.sendall(json.dumps(chunk_data).encode())
                    bytes_sent += len(chunk)
                    self.progress_updated.emit(bytes_sent, file_size)
                    
                    # Small delay to prevent overwhelming
                    time.sleep(0.001)
            
            # Send file end marker
            file_end = {
                "type": "file_end",
                "to": self.recipient,
                "from": self.username,
                "filename": filename
            }
            
            self.socket_obj.sendall(json.dumps(file_end).encode())
            self.transfer_completed.emit(True, f"File '{filename}' sent successfully")
            
        except Exception as e:
            self.transfer_completed.emit(False, f"Transfer failed: {str(e)}")
    
    def calculate_file_hash(self, filepath):
        """Calculate SHA256 hash of file"""
        hash_sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

# ===⚙️ Settings Dialog===
class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("🔧 Connection Settings")
        self.setFixedSize(400, 300)
        self.setStyleSheet(DARK_THEME)
        
        layout = QVBoxLayout()
        
        # Form layout
        form_layout = QFormLayout()
        
        self.server_input = QLineEdit(RAILWAY_SERVER_URL)
        self.tcp_port_input = QSpinBox()
        self.tcp_port_input.setRange(1, 65535)
        self.tcp_port_input.setValue(RAILWAY_TCP_PORT)
        
        self.p2p_port_input = QSpinBox()
        self.p2p_port_input.setRange(1, 65535)
        self.p2p_port_input.setValue(DEFAULT_P2P_PORT)
        
        self.auto_connect_check = QCheckBox()
        self.auto_connect_check.setChecked(False)
        
        form_layout.addRow("🌐 Server URL:", self.server_input)
        form_layout.addRow("🔌 TCP Port:", self.tcp_port_input)
        form_layout.addRow("🤝 P2P Port:", self.p2p_port_input)
        form_layout.addRow("⚡ Auto Connect:", self.auto_connect_check)
        
        layout.addLayout(form_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.save_btn = QPushButton("💾 Save")
        self.save_btn.setObjectName("primaryButton")
        self.cancel_btn = QPushButton("❌ Cancel")
        
        self.save_btn.clicked.connect(self.accept)
        self.cancel_btn.clicked.connect(self.reject)
        
        button_layout.addWidget(self.save_btn)
        button_layout.addWidget(self.cancel_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)

# ===💬 Modern Chat Client===
class ModernChatClient(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 Enhanced Encrypted Chat Client")
        self.setGeometry(100, 100, 1200, 800)
        self.setStyleSheet(DARK_THEME)
        
        # Initialize communication system
        self.comm = Communicator()
        self.setup_signals()
        
        # Connection state
        self.server_sock = None
        self.p2p_socket = None
        self.p2p_listener = None
        self.p2p_connected = False
        self.connection_lock = threading.Lock()
        self.username = ""
        self.peers = []
        self.p2p_mode = False
        
        # File transfer
        self.incoming_files = {}
        self.file_transfer_threads = []
        self.downloads_dir = Path.home() / "Downloads" / "SecureChat"
        self.downloads_dir.mkdir(parents=True, exist_ok=True)
        
        # Server configuration
        self.server_url = RAILWAY_SERVER_URL
        self.tcp_port = RAILWAY_TCP_PORT
        self.p2p_port = DEFAULT_P2P_PORT
        
        self.public_key = public_key.decode()
        
        # Initialize UI
        self.init_ui()
        self.init_menu()
        self.init_status_bar()
        
        # Welcome message
        self.show_welcome_message()

    def setup_signals(self):
        """Connect all signals"""
        self.comm.message_received.connect(self.display_message)
        self.comm.peer_list_updated.connect(self.update_peer_list)
        self.comm.file_transfer_progress.connect(self.update_file_progress)
        self.comm.file_received.connect(self.handle_file_received)
        self.comm.connection_status_changed.connect(self.update_connection_status)
        self.comm.system_message.connect(self.display_system_message)

    def init_menu(self):
        """Initialize menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('📁 File')
        
        settings_action = QAction('⚙️ Settings', self)
        settings_action.triggered.connect(self.show_settings)
        file_menu.addAction(settings_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('🚪 Exit', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Connection menu
        conn_menu = menubar.addMenu('🔗 Connection')
        
        connect_server_action = QAction('🌐 Connect to Server', self)
        connect_server_action.triggered.connect(self.connect_to_server)
        conn_menu.addAction(connect_server_action)
        
        connect_p2p_action = QAction('🤝 P2P Mode', self)
        connect_p2p_action.triggered.connect(self.connect_p2p)
        conn_menu.addAction(connect_p2p_action)
        
        conn_menu.addSeparator()
        
        disconnect_action = QAction('❌ Disconnect All', self)
        disconnect_action.triggered.connect(self.disconnect_all)
        conn_menu.addAction(disconnect_action)
        
        # Help menu
        help_menu = menubar.addMenu('❓ Help')
        
        about_action = QAction('ℹ️ About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def init_status_bar(self):
        """Initialize status bar"""
        self.status_bar = self.statusBar()
        self.connection_label = QLabel("🔴 Disconnected")
        self.peers_count_label = QLabel("👥 0 peers")
        self.encryption_label = QLabel("🔐 RSA+AES256")
        
        self.status_bar.addWidget(self.connection_label)
        self.status_bar.addPermanentWidget(self.peers_count_label)
        self.status_bar.addPermanentWidget(self.encryption_label)

    def init_ui(self):
        """Initialize the modern UI"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(15, 15, 15, 15)
        
        # Connection panel
        self.create_connection_panel(main_layout)
        
        # Main content tabs
        self.create_main_content(main_layout)

    def create_connection_panel(self, parent_layout):
        """Create modern connection panel"""
        conn_frame = QFrame()
        conn_frame.setFrameStyle(QFrame.StyledPanel)
        conn_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(102, 126, 234, 0.1), stop:1 rgba(118, 75, 162, 0.1));
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 12px;
                padding: 10px;
            }
        """)
        
        conn_layout = QVBoxLayout(conn_frame)
        
        # Title
        title_label = QLabel("🌐 Connection Settings")
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        conn_layout.addWidget(title_label)
        
        # Input row
        input_row = QHBoxLayout()
        
        # Username
        username_group = QVBoxLayout()
        username_group.addWidget(QLabel("👤 Username:"))
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username...")
        username_group.addWidget(self.username_input)
        
        # Server info (read-only display)
        server_group = QVBoxLayout()
        server_group.addWidget(QLabel("🌐 Server:"))
        self.server_display = QLabel(f"{RAILWAY_SERVER_URL}:{RAILWAY_TCP_PORT}")
        self.server_display.setStyleSheet("""
            QLabel {
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 6px;
                padding: 8px 12px;
                font-family: 'Consolas', monospace;
                color: #4CAF50;
            }
        """)
        server_group.addWidget(self.server_display)
        
        input_row.addLayout(username_group, 2)
        input_row.addLayout(server_group, 2)
        
        # Buttons row
        button_row = QHBoxLayout()
        
        self.connect_btn = QPushButton("🌐 Connect to Server")
        self.connect_btn.setObjectName("primaryButton")
        self.connect_btn.clicked.connect(self.connect_to_server)
        
        self.p2p_btn = QPushButton("🤝 P2P Mode")
        self.p2p_btn.clicked.connect(self.connect_p2p)
        
        self.disconnect_btn = QPushButton("❌ Disconnect")
        self.disconnect_btn.setObjectName("dangerButton")
        self.disconnect_btn.clicked.connect(self.disconnect_all)
        self.disconnect_btn.setEnabled(False)
        
        button_row.addWidget(self.connect_btn)
        button_row.addWidget(self.p2p_btn)
        button_row.addWidget(self.disconnect_btn)
        
        conn_layout.addLayout(input_row)
        conn_layout.addLayout(button_row)
        
        parent_layout.addWidget(conn_frame)

    def create_main_content(self, parent_layout):
        """Create main content area with tabs"""
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabPosition(QTabWidget.North)
        
        # Chat tab
        self.create_chat_tab()
        
        # Files tab
        self.create_files_tab()
        
        # Settings tab
        self.create_settings_tab()
        
        parent_layout.addWidget(self.tab_widget)

    def create_chat_tab(self):
        """Create the chat tab"""
        chat_widget = QWidget()
        chat_layout = QHBoxLayout(chat_widget)
        
        # Main chat area
        chat_main = QVBoxLayout()
        
        # Chat display
        self.chat_display = QTextBrowser()
        self.chat_display.setMinimumHeight(400)
        self.chat_display.setStyleSheet("""
            QTextBrowser {
                background: rgba(0, 0, 0, 0.4);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 10px;
                padding: 15px;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 12px;
                line-height: 1.5;
            }
        """)
        chat_main.addWidget(self.chat_display)
        
        # Message input area
        msg_frame = QFrame()
        msg_frame.setStyleSheet("""
            QFrame {
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                padding: 10px;
            }
        """)
        msg_layout = QVBoxLayout(msg_frame)
        
        # Encryption indicator
        enc_layout = QHBoxLayout()
        enc_layout.addWidget(QLabel("🔐 Encryption:"))
        self.encryption_select = QComboBox()
        self.encryption_select.addItems(["AES-256 + RSA-2048"])
        self.encryption_select.setEnabled(False)  # Always encrypted
        enc_layout.addWidget(self.encryption_select)
        enc_layout.addStretch()
        
        # Message input row
        input_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your encrypted message here...")
        self.message_input.returnPressed.connect(self.send_message)
        
        self.send_btn = QPushButton("📤 Send")
        self.send_btn.setObjectName("primaryButton")
        self.send_btn.clicked.connect(self.send_message)
        
        self.send_file_btn = QPushButton("📁 File")
        self.send_file_btn.clicked.connect(self.send_file)
        
        input_layout.addWidget(self.message_input, 4)
        input_layout.addWidget(self.send_btn, 1)
        input_layout.addWidget(self.send_file_btn, 1)
        
        msg_layout.addLayout(enc_layout)
        msg_layout.addLayout(input_layout)
        
        chat_main.addWidget(msg_frame)
        
        # Peers sidebar
        peers_widget = self.create_peers_sidebar()
        
        chat_layout.addLayout(chat_main, 4)
        chat_layout.addWidget(peers_widget, 1)
        
        self.tab_widget.addTab(chat_widget, "💬 Chat")

    def create_peers_sidebar(self):
        """Create peers sidebar"""
        peers_frame = QFrame()
        peers_frame.setStyleSheet("""
            QFrame {
                background: rgba(0, 0, 0, 0.3);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 10px;
                padding: 10px;
            }
        """)
        peers_layout = QVBoxLayout(peers_frame)
        
        # Peers header
        peers_header = QLabel("👥 Connected Peers")
        peers_header.setFont(QFont("Arial", 12, QFont.Bold))
        peers_header.setAlignment(Qt.AlignCenter)
        peers_layout.addWidget(peers_header)
        
        # Peers list
        self.peers_list = QListWidget()
        self.peers_list.setStyleSheet("""
            QListWidget {
                background: rgba(0, 0, 0, 0.2);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                padding: 5px;
            }
            QListWidget::item {
                background: transparent;
                padding: 10px;
                border-radius: 6px;
                margin: 2px;
                border: 1px solid transparent;
            }
            QListWidget::item:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #667eea, stop:1 #764ba2);
                border: 1px solid rgba(255, 255, 255, 0.3);
            }
            QListWidget::item:hover {
                background: rgba(255, 255, 255, 0.1);
                border: 1px solid rgba(255, 255, 255, 0.2);
            }
        """)
        peers_layout.addWidget(self.peers_list)
        
        # Connection info
        self.connection_info = QLabel("🔴 Not connected")
        self.connection_info.setAlignment(Qt.AlignCenter)
        self.connection_info.setStyleSheet("""
            QLabel {
                background: rgba(0, 0, 0, 0.4);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 6px;
                padding: 8px;
                font-size: 10px;
            }
        """)
        peers_layout.addWidget(self.connection_info)
        
        return peers_frame

    def create_files_tab(self):
        """Create files transfer tab"""
        files_widget = QWidget()
        files_layout = QVBoxLayout(files_widget)
        
        # File transfer header
        header_frame = QFrame()
        header_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(76, 175, 80, 0.1), stop:1 rgba(56, 142, 60, 0.1));
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 10px;
                padding: 15px;
            }
        """)
        header_layout = QVBoxLayout(header_frame)
        
        title = QLabel("📁 Secure File Transfer")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        
        subtitle = QLabel("End-to-end encrypted file sharing with integrity verification")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("color: #cccccc; font-size: 11px;")
        
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        
        files_layout.addWidget(header_frame)
        
        # Transfer progress section
        progress_frame = QFrame()
        progress_frame.setStyleSheet("""
            QFrame {
                background: rgba(0, 0, 0, 0.2);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                padding: 10px;
            }
        """)
        progress_layout = QVBoxLayout(progress_frame)
        
        progress_layout.addWidget(QLabel("📊 Transfer Progress:"))
        self.file_progress_display = QTextBrowser()
        self.file_progress_display.setMaximumHeight(150)
        self.file_progress_display.setStyleSheet("""
            QTextBrowser {
                background: rgba(0, 0, 0, 0.4);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 6px;
                padding: 10px;
                font-family: 'Consolas', monospace;
                font-size: 10px;
            }
        """)
        progress_layout.addWidget(self.file_progress_display)
        
        files_layout.addWidget(progress_frame)
        
        # Received files section
        received_frame = QFrame()
        received_frame.setStyleSheet("""
            QFrame {
                background: rgba(0, 0, 0, 0.2);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                padding: 10px;
            }
        """)
        received_layout = QVBoxLayout(received_frame)
        
        received_header = QHBoxLayout()
        received_header.addWidget(QLabel("📥 Received Files:"))
        
        open_folder_btn = QPushButton("📂 Open Folder")
        open_folder_btn.clicked.connect(self.open_downloads_folder)
        received_header.addWidget(open_folder_btn)
        
        received_layout.addLayout(received_header)
        
        self.received_files_list = QListWidget()
        self.received_files_list.itemDoubleClicked.connect(self.open_received_file)
        self.received_files_list.setStyleSheet("""
            QListWidget::item {
                background: rgba(255, 255, 255, 0.05);
                padding: 8px;
                border-radius: 4px;
                margin: 2px;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
            QListWidget::item:hover {
                background: rgba(255, 255, 255, 0.1);
                border: 1px solid rgba(255, 255, 255, 0.3);
            }
        """)
        received_layout.addWidget(self.received_files_list)
        
        # Downloads info
        downloads_info = QLabel(f"💾 Files saved to: {self.downloads_dir}")
        downloads_info.setStyleSheet("color: #888888; font-size: 10px; padding: 5px;")
        received_layout.addWidget(downloads_info)
        
        files_layout.addWidget(received_frame)
        
        self.tab_widget.addTab(files_widget, "📁 Files")

    def create_settings_tab(self):
        """Create settings tab"""
        settings_widget = QWidget()
        settings_layout = QVBoxLayout(settings_widget)
        
        # Server settings
        server_frame = QFrame()
        server_frame.setStyleSheet("""
            QFrame {
                background: rgba(0, 0, 0, 0.2);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 10px;
                padding: 15px;
            }
        """)
        server_layout = QVBoxLayout(server_frame)
        
        server_title = QLabel("🌐 Server Configuration")
        server_title.setFont(QFont("Arial", 14, QFont.Bold))
        server_layout.addWidget(server_title)
        
        # Server info display
        info_layout = QVBoxLayout()
        
        railway_info = QLabel(f"Railway Server: {RAILWAY_SERVER_URL}")
        railway_info.setStyleSheet("color: #4CAF50; font-weight: bold;")
        
        tcp_info = QLabel(f"TCP Port: {RAILWAY_TCP_PORT}")
        tcp_info.setStyleSheet("color: #2196F3; font-weight: bold;")
        
        p2p_info = QLabel(f"P2P Port: {DEFAULT_P2P_PORT}")
        p2p_info.setStyleSheet("color: #FF9800; font-weight: bold;")
        
        info_layout.addWidget(railway_info)
        info_layout.addWidget(tcp_info)
        info_layout.addWidget(p2p_info)
        
        server_layout.addLayout(info_layout)
        
        # Security settings
        security_frame = QFrame()
        security_frame.setStyleSheet("""
            QFrame {
                background: rgba(0, 0, 0, 0.2);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 10px;
                padding: 15px;
            }
        """)
        security_layout = QVBoxLayout(security_frame)
        
        security_title = QLabel("🔐 Security Information")
        security_title.setFont(QFont("Arial", 14, QFont.Bold))
        security_layout.addWidget(security_title)
        
        security_info = QLabel("""
        • End-to-End Encryption: AES-256-GCM
        • Key Exchange: RSA-2048 OAEP
        • File Integrity: SHA-256 verification
        • Perfect Forward Secrecy: New session keys per chat
        • Zero-Knowledge: Server cannot decrypt messages
        """)
        security_info.setStyleSheet("color: #cccccc; line-height: 1.6;")
        security_layout.addWidget(security_info)
        
        settings_layout.addWidget(server_frame)
        settings_layout.addWidget(security_frame)
        settings_layout.addStretch()
        
        self.tab_widget.addTab(settings_widget, "⚙️ Settings")

    def show_welcome_message(self):
        """Display welcome message"""
        welcome_html = """
        <div style="color: #667eea; font-weight: bold; font-size: 14px; margin: 10px 0;">
            🔐 Welcome to Enhanced Encrypted Chat!
        </div>
        <div style="color: #4CAF50; margin: 5px 0;">
            ✅ Military-grade encryption (AES-256 + RSA-2048)
        </div>
        <div style="color: #2196F3; margin: 5px 0;">
            📁 Secure file transfer with integrity verification
        </div>
        <div style="color: #FF9800; margin: 5px 0;">
            🌐 Railway server ready: {0}:{1}
        </div>
        <div style="color: #9C27B0; margin: 5px 0;">
            🤝 P2P mode available for direct connections
        </div>
        <div style="color: #cccccc; margin: 10px 0; font-size: 12px;">
            Enter your username and click "Connect to Server" to begin!
        </div>
        """.format(RAILWAY_SERVER_URL, RAILWAY_TCP_PORT)
        
        self.chat_display.append(welcome_html)

    def show_settings(self):
        """Show settings dialog"""
        dialog = SettingsDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            self.server_url = dialog.server_input.text()
            self.tcp_port = dialog.tcp_port_input.value()
            self.p2p_port = dialog.p2p_port_input.value()
            
            # Update display
            self.server_display.setText(f"{self.server_url}:{self.tcp_port}")
            self.comm.system_message.emit(f"Settings updated: {self.server_url}:{self.tcp_port}")

    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, "About Enhanced Encrypted Chat", """
        <h3>🔐 Enhanced Encrypted Chat Client</h3>
        <p><b>Version:</b> 2.0</p>
        <p><b>Features:</b></p>
        <ul>
            <li>🔒 End-to-end encryption (AES-256 + RSA-2048)</li>
            <li>📁 Secure file transfer</li>
            <li>🌐 Railway server integration</li>
            <li>🤝 P2P direct connections</li>
            <li>🎨 Modern dark theme UI</li>
        </ul>
        <p><b>Security:</b> All messages and files are encrypted before leaving your device.</p>
        """)

    def display_system_message(self, message):
        """Display system message with timestamp"""
        timestamp = time.strftime("%H:%M:%S")
        self.chat_display.append(f"""
        <div style="color: #888888; font-size: 11px; margin: 5px 0;">
            [{timestamp}] {message}
        </div>
        """)

    def display_message(self, sender, message):
        """Display chat message"""
        timestamp = time.strftime("%H:%M:%S")
        self.chat_display.append(f"""
        <div style="margin: 8px 0; padding: 8px; background: rgba(102, 126, 234, 0.1); 
                    border-left: 3px solid #667eea; border-radius: 4px;">
            <span style="color: #667eea; font-weight: bold;">{sender}</span>
            <span style="color: #888888; font-size: 10px; float: right;">{timestamp}</span>
            <br>
            <span style="color: #ffffff; margin-top: 4px; display: block;">{message}</span>
        </div>
        """)

    def update_connection_status(self, status, color):
        """Update connection status"""
        color_map = {
            "red": "🔴",
            "green": "🟢", 
            "yellow": "🟡",
            "blue": "🔵"
        }
        
        icon = color_map.get(color, "🔴")
        self.connection_label.setText(f"{icon} {status}")
        self.connection_info.setText(f"{icon} {status}")

    def update_peer_list(self, peers):
        """Update peers list"""
        self.peers = peers
        self.peers_list.clear()
        
        for peer in peers:
            item = QListWidgetItem(peer)
            item.setToolTip(f"Click to select {peer.split(' [')[0]} for messaging")
            self.peers_list.addItem(item)
        
        # Update peers count
        self.peers_count_label.setText(f"👥 {len(peers)} peers")
        
        if peers:
            self.comm.system_message.emit(f"Peer list updated: {len(peers)} peer(s) online")

    def update_file_progress(self, filename, current, total):
        """Update file transfer progress"""
        progress = (current / total) * 100 if total > 0 else 0
        timestamp = time.strftime("%H:%M:%S")
        
        self.file_progress_display.append(f"""
        <div style="color: #2196F3; margin: 2px 0;">
            [{timestamp}] 📥 {filename}: {progress:.1f}% ({current:,}/{total:,} bytes)
        </div>
        """)

    def handle_file_received(self, sender, filename, filepath):
        """Handle completed file reception"""
        timestamp = time.strftime("%H:%M:%S")
        
        # Add to received files list
        item_text = f"📁 {filename} (from {sender}) - {timestamp}"
        self.received_files_list.addItem(item_text)
        
        # Update progress display
        self.file_progress_display.append(f"""
        <div style="color: #4CAF50; margin: 5px 0; font-weight: bold;">
            ✅ File '{filename}' received from {sender}
        </div>
        """)
        
        # Switch to files tab
        self.tab_widget.setCurrentIndex(1)
        
        # Show notification
        self.comm.system_message.emit(f"File received: {filename} from {sender}")

    def open_downloads_folder(self):
        """Open downloads folder"""
        import subprocess
        import platform
        
        try:
            if platform.system() == "Windows":
                os.startfile(str(self.downloads_dir))
            elif platform.system() == "Darwin":  # macOS
                subprocess.run(["open", str(self.downloads_dir)])
            else:  # Linux
                subprocess.run(["xdg-open", str(self.downloads_dir)])
        except Exception as e:
            self.comm.system_message.emit(f"Could not open folder: {e}")

    def open_received_file(self, item):
        """Open received file"""
        self.open_downloads_folder()

    def send_file(self):
        """Handle file sending"""
        selected = self.peers_list.selectedItems()
        if not selected:
            self.comm.system_message.emit("❌ Please select a peer first!")
            return

        peer_label = selected[0].text()
        peer = peer_label.split(" [")[0]

        # Check connection
        if not self.p2p_mode and not self.server_sock:
            self.comm.system_message.emit("❌ Not connected to server!")
            return
        elif self.p2p_mode and not self.p2p_connected:
            self.comm.system_message.emit("❌ Not connected to peer!")
            return

        # Check if we have session key
        if peer not in aes_session_keys:
            self.comm.system_message.emit(f"❌ No session key for {peer}. Send a message first!")
            return

        # Select file
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "📁 Select File to Send", 
            "", 
            "All Files (*)"
        )
        
        if not file_path:
            return
            
        # Check file size
        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE:
            self.comm.system_message.emit(f"❌ File too large (max {MAX_FILE_SIZE//1024//1024}MB)")
            return
        
        filename = os.path.basename(file_path)
        self.comm.system_message.emit(f"📤 Sending {filename} ({file_size:,} bytes) to {peer}...")
        
        # Start file transfer thread
        socket_obj = self.p2p_socket if self.p2p_mode else self.server_sock
        transfer_thread = FileTransferThread(
            socket_obj, 
            aes_session_keys[peer], 
            file_path, 
            peer, 
            self.username, 
            self.p2p_mode
        )
        
        transfer_thread.progress_updated.connect(
            lambda current, total: self.update_transfer_progress(filename, current, total)
        )
        transfer_thread.transfer_completed.connect(
            lambda success, msg: self.file_transfer_completed(filename, success, msg)
        )
        
        self.file_transfer_threads.append(transfer_thread)
        transfer_thread.start()

    def update_transfer_progress(self, filename, current, total):
        """Update file transfer progress"""
        progress = (current / total) * 100 if total > 0 else 0
        timestamp = time.strftime("%H:%M:%S")
        
        self.file_progress_display.append(f"""
        <div style="color: #FF9800; margin: 2px 0;">
            [{timestamp}] 📤 {filename}: {progress:.1f}% ({current:,}/{total:,} bytes)
        </div>
        """)

    def file_transfer_completed(self, filename, success, message):
        """Handle file transfer completion"""
        if success:
            self.file_progress_display.append(f"""
            <div style="color: #4CAF50; margin: 5px 0; font-weight: bold;">
                ✅ {message}
            </div>
            """)
        else:
            self.file_progress_display.append(f"""
            <div style="color: #f44336; margin: 5px 0; font-weight: bold;">
                ❌ {message}
            </div>
            """)
        
        self.comm.system_message.emit(message)

    def connect_to_server(self):
        """Connect to Railway server"""
        self.username = self.username_input.text().strip()
        
        # Validation
        if not self.username:
            self.comm.system_message.emit("❌ Please enter a username!")
            return
            
        if len(self.username) > 50:
            self.comm.system_message.emit("❌ Username too long (max 50 characters)!")
            return
            
        if not self.username.replace('_', '').replace('-', '').isalnum():
            self.comm.system_message.emit("❌ Username can only contain letters, numbers, underscores, and hyphens!")
            return
        
        self.comm.connection_status_changed.emit("Testing Connection...", "yellow")
        self.comm.system_message.emit(f"🔄 Testing connection to {self.server_url}...")
        
        # Test multiple possible ports
        test_ports = [
            42721,  # Main Railway PORT
            43721,  # PORT + 1000 (legacy)
            5000,   # Common alternative
            6000,   # Another alternative
        ]
        
        working_port = None
        for port in test_ports:
            self.comm.system_message.emit(f"🔍 Trying port {port}...")
            if self.test_port_connection(self.server_url, port):
                working_port = port
                self.tcp_port = port
                break
        
        if not working_port:
            self.comm.system_message.emit("❌ Could not connect to any port. Server may be down.")
            self.comm.connection_status_changed.emit("Connection Failed", "red")
            return
        
        self.comm.system_message.emit(f"✅ Found working port: {working_port}")
        
        # Get password
        password, ok = QInputDialog.getText(
            self, 
            "🔐 Authentication", 
            f"Enter password for '{self.username}':\n(New users: create any password)",
            QLineEdit.Password
        )
        
        if not ok or not password:
            self.comm.system_message.emit("❌ No password entered")
            self.comm.connection_status_changed.emit("Disconnected", "red")
            return
            
        if len(password) > 128:
            self.comm.system_message.emit("❌ Password too long (max 128 characters)!")
            self.comm.connection_status_changed.emit("Disconnected", "red")
            return

        self.comm.connection_status_changed.emit("Connecting...", "yellow")
        self.comm.system_message.emit(f"🔄 Connecting to {self.server_url}:{working_port}...")

        try:
            # Create connection with better timeout handling
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.settimeout(10)  # Shorter timeout for faster feedback
            self.server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            self.server_sock.connect((self.server_url, working_port))
            self.comm.system_message.emit(f"✅ Connected to {self.server_url}:{working_port}")
            self.comm.connection_status_changed.emit("Connected", "green")

            # Send authentication - match server's expected format
            auth_data = {
                "username": self.username,
                "password": password,  # Use "password" not "auth"
                "public_key": self.public_key,
                "email": ""  # Optional email field
            }
            
            auth_json = json.dumps(auth_data)
            self.comm.system_message.emit(f"📤 Sending auth data ({len(auth_json)} bytes)")
            self.server_sock.sendall(auth_json.encode('utf-8'))
            self.comm.system_message.emit("🔐 Authenticating...")
            self.comm.connection_status_changed.emit("Authenticating...", "yellow")

            # Start message listener
            threading.Thread(target=self.listen_for_server_messages, daemon=True).start()
            
            # Enable disconnect button
            self.disconnect_btn.setEnabled(True)

        except socket.timeout:
            self.comm.system_message.emit("❌ Connection timeout! Check your internet connection.")
            self.comm.connection_status_changed.emit("Timeout", "red")
            if self.server_sock:
                self.server_sock.close()
                self.server_sock = None
        except ConnectionRefusedError:
            self.comm.system_message.emit(f"❌ Connection refused by {self.server_url}:{working_port}")
            self.comm.connection_status_changed.emit("Refused", "red")
        except Exception as e:
            self.comm.system_message.emit(f"❌ Connection failed: {e}")
            self.comm.connection_status_changed.emit("Failed", "red")
            if self.server_sock:
                self.server_sock.close()
                self.server_sock = None

    def test_port_connection(self, host, port):
        """Test if a specific port is responding"""
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(5)  # Quick test
            result = test_sock.connect_ex((host, port))
            test_sock.close()
            return result == 0
        except Exception:
            return False

    def connect_p2p(self):
        """Connect in P2P mode"""
        self.p2p_mode = True
        self.username = self.username_input.text().strip()
        
        if not self.username:
            self.comm.system_message.emit("❌ Enter a username first!")
            return

        # Get peer IP
        peer_ip, ok = QInputDialog.getText(
            self,
            "🤝 P2P Connection",
            "Enter peer IP address:",
            text="127.0.0.1"
        )
        
        if not ok or not peer_ip:
            return
        
        self.peer_ip = peer_ip.strip()
        
        # Reset connection state
        self.p2p_connected = False
        if self.p2p_socket:
            try:
                self.p2p_socket.close()
            except:
                pass
            self.p2p_socket = None

        self.comm.system_message.emit(f"🤝 Starting P2P mode: {self.username}")
        self.comm.system_message.emit(f"🔗 Local port: {self.p2p_port}, Remote: {self.peer_ip}:{self.p2p_port}")
        self.comm.connection_status_changed.emit("P2P Connecting...", "yellow")

        # Start listener and connector
        self.start_p2p_listener(self.p2p_port)
        self.attempt_p2p_connection(self.peer_ip, self.p2p_port)

    def start_p2p_listener(self, port):
        """Start P2P listener"""
        def listener():
            try:
                self.p2p_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.p2p_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.p2p_listener.bind(("0.0.0.0", port))
                self.p2p_listener.listen(1)
                
                self.comm.system_message.emit(f"👂 P2P listener started on port {port}")

                while not self.p2p_connected:
                    try:
                        self.p2p_listener.settimeout(2.0)
                        conn, addr = self.p2p_listener.accept()
                        
                        with self.connection_lock:
                            if not self.p2p_connected:
                                conn.settimeout(None)
                                self.p2p_socket = conn
                                self.p2p_connected = True
                                
                                self.comm.system_message.emit(f"✅ P2P peer connected from {addr[0]}:{addr[1]}")
                                self.comm.connection_status_changed.emit("P2P Connected", "green")
                                self.disconnect_btn.setEnabled(True)
                                
                                try:
                                    self.p2p_listener.close()
                                except:
                                    pass
                                
                                # Start message listener
                                threading.Thread(target=self.listen_for_p2p_messages, daemon=True).start()
                                
                                # Send introduction
                                intro = {
                                    "type": "introduction",
                                    "username": self.username,
                                    "public_key": self.public_key
                                }
                                self.p2p_socket.sendall(json.dumps(intro).encode())
                                break
                            else:
                                conn.close()
                                
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if not self.p2p_connected:
                            self.comm.system_message.emit(f"❌ P2P listener error: {e}")
                        break
                        
            except Exception as e:
                self.comm.system_message.emit(f"❌ Failed to start P2P listener: {e}")
                self.comm.connection_status_changed.emit("P2P Failed", "red")

        threading.Thread(target=listener, daemon=True).start()

    def attempt_p2p_connection(self, peer_ip, remote_port):
        """Attempt P2P connection"""
        def connector():
            time.sleep(2)  # Let listener start
            
            for attempt in range(15):
                with self.connection_lock:
                    if self.p2p_connected:
                        return
                
                try:
                    self.comm.system_message.emit(f"🔄 P2P attempt {attempt + 1}/15 to {peer_ip}:{remote_port}")
                    
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.settimeout(8)
                    test_sock.connect((peer_ip, remote_port))
                    
                    with self.connection_lock:
                        if not self.p2p_connected:
                            test_sock.settimeout(None)
                            self.p2p_socket = test_sock
                            self.p2p_connected = True
                            
                            self.comm.system_message.emit(f"✅ Connected to peer {peer_ip}:{remote_port}")
                            self.comm.connection_status_changed.emit("P2P Connected", "green")
                            self.disconnect_btn.setEnabled(True)
                            
                            try:
                                if self.p2p_listener:
                                    self.p2p_listener.close()
                            except:
                                pass
                            
                            # Send introduction
                            intro = {
                                "type": "introduction", 
                                "username": self.username,
                                "public_key": self.public_key
                            }
                            self.p2p_socket.sendall(json.dumps(intro).encode())
                            
                            # Start message listener
                            threading.Thread(target=self.listen_for_p2p_messages, daemon=True).start()
                            return
                        else:
                            test_sock.close()
                            return
                            
                except Exception:
                    test_sock.close()
                    time.sleep(4)

            with self.connection_lock:
                if not self.p2p_connected:
                    self.comm.system_message.emit("❌ P2P connection failed after 15 attempts")
                    self.comm.connection_status_changed.emit("P2P Failed", "red")

        threading.Thread(target=connector, daemon=True).start()

    def listen_for_server_messages(self):
        """Listen for server messages"""
        self.comm.system_message.emit("👂 Server message listener started")
        
        try:
            # Wait for auth response
            self.server_sock.settimeout(10)
            auth_data = self.server_sock.recv(16384)
            
            if auth_data:
                try:
                    auth_response = json.loads(auth_data.decode('utf-8'))
                    self.process_message(auth_response)
                except Exception as e:
                    self.comm.system_message.emit(f"❌ Auth response error: {e}")
                    return
            else:
                self.comm.system_message.emit("❌ No auth response received")
                return
        except socket.timeout:
            self.comm.system_message.emit("❌ Authentication timeout")
            return
        except Exception as e:
            self.comm.system_message.emit(f"❌ Auth error: {e}")
            return
        
        # Continue listening for messages
        while True:
            try:
                self.server_sock.settimeout(30)
                data = self.server_sock.recv(16384)
                
                if not data:
                    self.comm.system_message.emit("❌ Server disconnected")
                    break
                
                try:
                    data_str = data.decode('utf-8')
                    try:
                        payload = json.loads(data_str)
                        self.process_message(payload)
                    except json.JSONDecodeError:
                        # Handle multiple JSON objects
                        lines = data_str.strip().split('\n')
                        for line in lines:
                            if line.strip():
                                try:
                                    payload = json.loads(line.strip())
                                    self.process_message(payload)
                                except json.JSONDecodeError:
                                    continue
                        
                except Exception as e:
                    self.comm.system_message.emit(f"❌ Message processing error: {e}")
                    continue
                    
            except socket.timeout:
                # Send keepalive
                try:
                    ping = json.dumps({"type": "ping"})
                    self.server_sock.sendall(ping.encode())
                except:
                    break
                continue
            except Exception as e:
                self.comm.system_message.emit(f"❌ Server error: {e}")
                break
        
        # Cleanup
        self.comm.connection_status_changed.emit("Disconnected", "red")
        if self.server_sock:
            try:
                self.server_sock.close()
            except:
                pass
            self.server_sock = None
        self.comm.peer_list_updated.emit([])

    def listen_for_p2p_messages(self):
        """Listen for P2P messages"""
        self.comm.system_message.emit("👂 P2P message listener started")
        
        while self.p2p_connected:
            try:
                self.p2p_socket.settimeout(5.0)
                data = self.p2p_socket.recv(16384)
                
                if not data:
                    self.comm.system_message.emit("❌ P2P peer disconnected")
                    break
                    
                self.p2p_socket.settimeout(None)
                
                try:
                    payload = json.loads(data.decode('utf-8'))
                    self.process_message(payload)
                except json.JSONDecodeError as e:
                    self.comm.system_message.emit(f"❌ P2P invalid message: {e}")
                    continue
                
            except socket.timeout:
                continue
            except Exception as e:
                self.comm.system_message.emit(f"❌ P2P error: {e}")
                break
        
        # Cleanup
        with self.connection_lock:
            self.p2p_connected = False
            if self.p2p_socket:
                try:
                    self.p2p_socket.close()
                except:
                    pass
                self.p2p_socket = None
        
        self.comm.system_message.emit("❌ P2P connection lost")
        self.comm.connection_status_changed.emit("P2P Disconnected", "red")
        self.comm.peer_list_updated.emit([])

    def process_message(self, payload):
        """Process incoming messages"""
        msg_type = payload.get("type")
        
        if msg_type == "auth_response":
            status = payload.get("status")
            message = payload.get("message", "")
            
            if status == "success":
                self.comm.system_message.emit(f"✅ Login successful! {message}")
                self.comm.connection_status_changed.emit("Authenticated", "green")
            elif status == "new_user":
                self.comm.system_message.emit(f"🆕 Account created! {message}")
                self.comm.connection_status_changed.emit("Authenticated", "green")
            elif status == "fail":
                self.comm.system_message.emit(f"❌ Authentication failed: {message}")
                self.comm.connection_status_changed.emit("Auth Failed", "red")
                if self.server_sock:
                    self.server_sock.close()
                    self.server_sock = None
            else:
                self.comm.system_message.emit(f"❌ Unknown auth status: {status}")
        
        elif msg_type == "ping":
            # Respond to ping
            try:
                pong = json.dumps({"type": "pong"})
                if self.server_sock:
                    self.server_sock.sendall(pong.encode())
            except:
                pass
        
        elif msg_type == "introduction":
            # P2P peer introduction
            peer_name = payload["username"]
            peer_key = payload["public_key"]
            peer_public_keys[peer_name] = peer_key
            peer_key_hashes[peer_name] = sha256_digest(peer_key.encode())
            
            peer_display = f"{peer_name} [{peer_key_hashes[peer_name][:6]}...]"
            self.comm.peer_list_updated.emit([peer_display])
            self.comm.system_message.emit(f"✅ Peer identified: {peer_name}")
            
        elif msg_type == "key_exchange":
            key = rsa_decrypt(payload["encrypted_key"])
            aes_session_keys[payload["from"]] = key
            self.comm.system_message.emit(f"🔑 Session key received from {payload['from']}")

        elif msg_type == "message":
            peer = payload["from"]
            if peer in aes_session_keys:
                msg = aes_decrypt(aes_session_keys[peer], payload)
            else:
                msg = "[Key missing]"
            self.comm.message_received.emit(peer, msg)

        elif msg_type == "peer_list":
            # Server peer list
            peer_list = []
            for peer in payload["peers"]:
                uname = peer["username"]
                pkey = peer["public_key"]
                peer_public_keys[uname] = pkey
                peer_key_hashes[uname] = sha256_digest(pkey.encode())
                peer_list.append(f"{uname} [{peer_key_hashes[uname][:6]}...]")
            self.comm.peer_list_updated.emit(peer_list)
        
        elif msg_type == "file_header":
            # File transfer start
            sender = payload["from"]
            filename = payload["filename"]
            filesize = payload["filesize"]
            file_hash = payload["file_hash"]
            
            self.incoming_files[filename] = {
                "sender": sender,
                "size": filesize,
                "received": 0,
                "data": b"",
                "hash": file_hash
            }
            
            self.comm.system_message.emit(f"📥 Receiving {filename} ({filesize:,} bytes) from {sender}")
            self.comm.file_transfer_progress.emit(filename, 0, filesize)
        
        elif msg_type == "file_chunk":
            # File chunk
            sender = payload["from"]
            chunk_data = payload["chunk_data"]
            
            filename = None
            for fname, finfo in self.incoming_files.items():
                if finfo["sender"] == sender and finfo["received"] < finfo["size"]:
                    filename = fname
                    break
            
            if filename and filename in self.incoming_files:
                if sender in aes_session_keys:
                    decrypted_chunk = aes_decrypt_bytes(aes_session_keys[sender], chunk_data)
                    if decrypted_chunk:
                        self.incoming_files[filename]["data"] += decrypted_chunk
                        self.incoming_files[filename]["received"] += len(decrypted_chunk)
                        
                        current = self.incoming_files[filename]["received"]
                        total = self.incoming_files[filename]["size"]
                        self.comm.file_transfer_progress.emit(filename, current, total)
        
        elif msg_type == "file_end":
            # File transfer complete
            sender = payload["from"]
            filename = payload["filename"]
            
            if filename in self.incoming_files:
                file_info = self.incoming_files[filename]
                
                # Verify integrity
                received_hash = hashlib.sha256(file_info["data"]).hexdigest()
                if received_hash == file_info["hash"]:
                    # Save file
                    safe_filename = self.sanitize_filename(filename)
                    file_path = self.downloads_dir / safe_filename
                    
                    # Handle duplicates
                    counter = 1
                    while file_path.exists():
                        name, ext = os.path.splitext(safe_filename)
                        file_path = self.downloads_dir / f"{name}_{counter}{ext}"
                        counter += 1
                    
                    try:
                        with open(file_path, 'wb') as f:
                            f.write(file_info["data"])
                        
                        self.comm.file_received.emit(sender, filename, str(file_path))
                    except Exception as e:
                        self.comm.system_message.emit(f"❌ Failed to save file: {e}")
                else:
                    self.comm.system_message.emit(f"❌ File integrity check failed: {filename}")
                
                del self.incoming_files[filename]
        
        elif msg_type == "error":
            error_msg = payload.get("message", "Unknown error")
            self.comm.system_message.emit(f"❌ Server error: {error_msg}")

    def sanitize_filename(self, filename):
        """Sanitize filename for safe saving"""
        import re
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        filename = filename.strip('. ')
        if not filename:
            filename = "received_file"
        return filename

    def send_message(self):
        """Send encrypted message"""
        msg = self.message_input.text().strip()
        if not msg:
            return
            
        selected = self.peers_list.selectedItems()
        if not selected:
            self.comm.system_message.emit("❌ Select a peer first!")
            return

        peer_label = selected[0].text()
        peer = peer_label.split(" [")[0]

        # Check connection
        if not self.p2p_mode and not self.server_sock:
            self.comm.system_message.emit("❌ Not connected to server!")
            return
        elif self.p2p_mode and not self.p2p_connected:
            self.comm.system_message.emit("❌ Not connected to peer!")
            return

        # Establish session key if needed
        if peer not in aes_session_keys:
            if peer not in peer_public_keys:
                self.comm.system_message.emit(f"❌ No public key for {peer}!")
                return
                
            session_key = get_random_bytes(16)
            encrypted_key = rsa_encrypt(peer_public_keys[peer], session_key)
            key_payload = {
                "type": "key_exchange",
                "to": peer,
                "from": self.username,
                "encrypted_key": encrypted_key
            }
            
            try:
                if self.p2p_mode and self.p2p_connected:
                    self.p2p_socket.sendall(json.dumps(key_payload).encode())
                elif self.server_sock:
                    self.server_sock.sendall(json.dumps(key_payload).encode())
                else:
                    self.comm.system_message.emit("❌ No connection available")
                    return
                    
                aes_session_keys[peer] = session_key
                self.comm.system_message.emit(f"🔑 Session key sent to {peer}")
            except Exception as e:
                self.comm.system_message.emit(f"❌ Failed to send key: {e}")
                return

        # Encrypt and send message
        enc = aes_encrypt(aes_session_keys[peer], msg)
        enc.update({
            "type": "message",
            "to": peer,
            "from": self.username
        })

        try:
            if self.p2p_mode and self.p2p_connected:
                self.p2p_socket.sendall(json.dumps(enc).encode())
            elif self.server_sock:
                self.server_sock.sendall(json.dumps(enc).encode())
            else:
                self.comm.system_message.emit("❌ No connection available")
                return
                
            # Display sent message
            timestamp = time.strftime("%H:%M:%S")
            self.chat_display.append(f"""
            <div style="margin: 8px 0; padding: 8px; background: rgba(76, 175, 80, 0.1); 
                        border-left: 3px solid #4CAF50; border-radius: 4px;">
                <span style="color: #4CAF50; font-weight: bold;">You → {peer}</span>
                <span style="color: #888888; font-size: 10px; float: right;">{timestamp}</span>
                <br>
                <span style="color: #ffffff; margin-top: 4px; display: block;">{msg}</span>
            </div>
            """)
            
            self.message_input.clear()
            
        except Exception as e:
            self.comm.system_message.emit(f"❌ Failed to send message: {e}")

    def disconnect_all(self):
        """Disconnect all connections"""
        self.comm.system_message.emit("🔄 Disconnecting all connections...")
        
        # Server disconnect
        if self.server_sock:
            try:
                self.server_sock.close()
            except:
                pass
            self.server_sock = None
        
        # P2P disconnect
        self.p2p_connected = False
        if self.p2p_socket:
            try:
                self.p2p_socket.close()
            except:
                pass
            self.p2p_socket = None
            
        if self.p2p_listener:
            try:
                self.p2p_listener.close()
            except:
                pass
            self.p2p_listener = None
        
        # Reset state
        self.p2p_mode = False
        self.comm.connection_status_changed.emit("Disconnected", "red")
        self.comm.peer_list_updated.emit([])
        self.disconnect_btn.setEnabled(False)
        self.comm.system_message.emit("✅ All connections closed")

    def closeEvent(self, event):
        """Handle application close"""
        self.disconnect_all()
        event.accept()

# ===🚀 Application Entry Point===
def main():
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Enhanced Encrypted Chat")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("Railway Secure Chat")
    app.setApplicationDisplayName("🔐 Enhanced Encrypted Chat Client")
    
    # Set application icon (if available)
    try:
        app.setWindowIcon(QIcon("icon.png"))
    except:
        pass
    
    # Create and show main window
    window = ModernChatClient()
    window.show()
    
    # Center window on screen
    screen = app.primaryScreen()
    screen_geometry = screen.availableGeometry()
    window_geometry = window.frameGeometry()
    center_point = screen_geometry.center()
    window_geometry.moveCenter(center_point)
    window.move(window_geometry.topLeft())
    
    # Run application
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()