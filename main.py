# client.py - Enhanced Secure Chat Client
import socket
import json
import threading
import time
import base64
import hashlib
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Callable
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MessageTypes:
    """Message type constants - must match server"""
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

class SecureChatClient:
    """Enhanced Secure Chat Client with full feature support"""
    
    def __init__(self):
        self.socket = None
        self.connected = False
        self.authenticated = False
        self.username = None
        self.server_host = None
        self.server_port = None
        
        # Callback functions for handling different events
        self.message_callbacks: Dict[str, List[Callable]] = {
            MessageTypes.MESSAGE: [],
            MessageTypes.PEER_LIST: [],
            MessageTypes.USER_STATUS: [],
            MessageTypes.CHANNEL_MESSAGE: [],
            MessageTypes.CHANNEL_LIST: [],
            MessageTypes.FILE_HEADER: [],
            MessageTypes.FILE_CHUNK: [],
            MessageTypes.FILE_COMPLETE: [],
            MessageTypes.TYPING_INDICATOR: [],
            MessageTypes.ERROR: [],
            MessageTypes.SUCCESS: [],
            MessageTypes.PING: []
        }
        
        # Client state
        self.online_users = {}
        self.channels = {}
        self.active_file_transfers = {}
        
        # Threading
        self.receive_thread = None
        self.running = False
        
    def add_message_callback(self, message_type: str, callback: Callable):
        """Add callback function for specific message types"""
        if message_type in self.message_callbacks:
            self.message_callbacks[message_type].append(callback)
        else:
            logger.warning(f"Unknown message type for callback: {message_type}")
    
    def remove_message_callback(self, message_type: str, callback: Callable):
        """Remove callback function"""
        if message_type in self.message_callbacks and callback in self.message_callbacks[message_type]:
            self.message_callbacks[message_type].remove(callback)
    
    def connect(self, host: str, port: int, timeout: int = 10) -> bool:
        """Connect to the chat server"""
        try:
            logger.info(f"🔗 Connecting to {host}:{port}...")
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(timeout)
            self.socket.connect((host, port))
            
            self.server_host = host
            self.server_port = port
            self.connected = True
            
            logger.info(f"✅
