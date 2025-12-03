#!/usr/bin/env python3
"""
VARUX OT DISCOVERY FRAMEWORK
Enhanced Industrial Network Topology Discovery and Security Framework
"""

import asyncio
import json
import time
import ipaddress
import subprocess
import platform
import sys
import os
from dataclasses import dataclass, asdict
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from enum import Enum
import logging
import logging.handlers
from contextlib import asynccontextmanager
from collections import defaultdict, deque
import graphviz
import aiofiles
from pymodbus.client import AsyncModbusTcpClient
from pymodbus.pdu import ModbusRequest, ModbusResponse
from pymodbus.mei_message import ReadDeviceInformationRequest, ReadDeviceInformationResponse
from pymodbus.exceptions import ModbusIOException, ConnectionException
import aiosnmp
from scapy.all import *
from scapy.layers.l2 import Ether, ARP, Dot3, LLC, SNAP
from scapy.layers.lldp import LLDPDU, LLDPDUSystemName, LLDPDUPortID, LLDPDUChassisID, LLDPDUTimeToLive, LLDPDUSystemDescription, LLDPDUSystemCapabilities
from scapy.contrib.lldp import LLDPDUManagementAddress, LLDPDUOrganizationSpecific
from scapy.layers.inet import IP, ICMP, TCP, UDP
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
import hashlib
import hmac
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import threading
from concurrent.futures import ThreadPoolExecutor
import socket
import struct
import netifaces
from pathlib import Path
import gzip
import shutil
from datetime import datetime, timedelta
import yaml
import base64
import getpass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
import h5py
import pickle
import tempfile
from typing import BinaryIO
import signal
import psutil
from dataclasses_json import dataclass_json
import uuid
import queue
import select
from io import BytesIO
import zipfile
import tarfile
from functools import wraps
import inspect
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import docker
import mininet.net
import mininet.node
import mininet.link
import mininet.cli
import jwt
import requests
from prometheus_client import start_http_server, Counter, Gauge, Histogram, Summary
import dash
from dash import dcc, html, Input, Output, State, dash_table
import plotly.graph_objects as go
import plotly.express as px
from flask import Flask, send_file
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import warnings
import argparse
import resource
import syslog
from systemd import journal
warnings.filterwarnings('ignore')

# =============================================================================
# ENHANCED SNMPv3 AUTH+PRIV IMPLEMENTATION
# =============================================================================

class EliteSNMPv3AuthPriv:
    """Enhanced SNMPv3 implementation with MD5/SHA authentication and AES encryption"""
    
    def __init__(self, username: str, auth_key: str, priv_key: str, 
                 auth_protocol: str = 'SHA', priv_protocol: str = 'AES'):
        self.username = username
        self.auth_key = auth_key
        self.priv_key = priv_key
        self.auth_protocol = auth_protocol.upper()
        self.priv_protocol = priv_protocol.upper()
        
        # Validate protocols
        if self.auth_protocol not in ['MD5', 'SHA']:
            raise ValueError(f"Unsupported auth protocol: {auth_protocol}")
        if self.priv_protocol not in ['AES', 'DES']:
            raise ValueError(f"Unsupported priv protocol: {priv_protocol}")
    
    def generate_encryption_keys(self) -> Tuple[bytes, bytes, bytes, bytes]:
        """Generate encryption keys for SNMPv3 authPriv"""
        # Generate localized auth key
        auth_key_bytes = self.auth_key.encode('utf-8') if isinstance(self.auth_key, str) else self.auth_key
        priv_key_bytes = self.priv_key.encode('utf-8') if isinstance(self.priv_key, str) else self.priv_key
        
        # For MD5 authentication
        if self.auth_protocol == 'MD5':
            auth_key_localized = hashlib.md5(auth_key_bytes).digest()
        else:  # SHA
            auth_key_localized = hashlib.sha1(auth_key_bytes).digest()
        
        # For AES privacy
        if self.priv_protocol == 'AES':
            # Generate AES key from privacy key
            if len(priv_key_bytes) < 16:
                # Pad key if too short
                priv_key_bytes = priv_key_bytes.ljust(16, b'\0')
            priv_key_localized = priv_key_bytes[:16]
            
            # Generate encryption keys
            aes_key = hashlib.sha256(priv_key_localized).digest()[:16]
            aes_iv = hashlib.sha256(priv_key_localized + b'iv').digest()[:16]
            
            return auth_key_localized, priv_key_localized, aes_key, aes_iv
        else:  # DES
            # DES implementation would go here
            return auth_key_localized, priv_key_localized, b'', b''
    
    def encrypt_message(self, data: bytes, engine_boots: int, engine_time: int) -> bytes:
        """Encrypt SNMPv3 message using AES"""
        if self.priv_protocol != 'AES':
            return data
            
        try:
            _, _, aes_key, aes_iv = self.generate_encryption_keys()
            
            # Generate salt from engine boots and time
            salt = struct.pack('!II', engine_boots, engine_time)
            
            # Create AES GCM cipher
            aesgcm = AESGCM(aes_key)
            nonce = aes_iv + salt
            
            # Encrypt data
            encrypted_data = aesgcm.encrypt(nonce, data, None)
            return encrypted_data
            
        except Exception as e:
            logging.error(f"SNMPv3 encryption failed: {e}")
            return data
    
    def decrypt_message(self, encrypted_data: bytes, engine_boots: int, engine_time: int) -> bytes:
        """Decrypt SNMPv3 message using AES"""
        if self.priv_protocol != 'AES':
            return encrypted_data
            
        try:
            _, _, aes_key, aes_iv = self.generate_encryption_keys()
            
            # Generate salt from engine boots and time
            salt = struct.pack('!II', engine_boots, engine_time)
            nonce = aes_iv + salt
            
            # Create AES GCM cipher
            aesgcm = AESGCM(aes_key)
            
            # Decrypt data
            decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
            return decrypted_data
            
        except Exception as e:
            logging.error(f"SNMPv3 decryption failed: {e}")
            return encrypted_data
    
    def generate_auth_parameters(self, whole_msg: bytes) -> bytes:
        """Generate authentication parameters for SNMPv3"""
        auth_key_localized, _, _, _ = self.generate_encryption_keys()
        
        if self.auth_protocol == 'MD5':
            # HMAC-MD5
            return hmac.new(auth_key_localized, whole_msg, hashlib.md5).digest()
        else:  # SHA
            # HMAC-SHA
            return hmac.new(auth_key_localized, whole_msg, hashlib.sha1).digest()
    
    def verify_auth_parameters(self, whole_msg: bytes, received_auth_params: bytes) -> bool:
        """Verify SNMPv3 authentication parameters"""
        expected_auth_params = self.generate_auth_parameters(whole_msg)
        return hmac.compare_digest(expected_auth_params, received_auth_params)

# =============================================================================
# SECURE LOG FORMETTER
# =============================================================================

class SecureLogFormatter(logging.Formatter):
    """Secure log formatter that masks sensitive information"""
    
    SENSITIVE_PATTERNS = [
        (r'("password":\s*")([^"]*)(")', r'\1***\3'),
        (r'("auth_key":\s*")([^"]*)(")', r'\1***\3'),
        (r'("priv_key":\s*")([^"]*)(")', r'\1***\3'),
        (r'("community":\s*")([^"]*)(")', r'\1***\3'),
        (r'(password=)([^\s&]+)', r'\1***'),
        (r'(community=)([^\s&]+)', r'\1***'),
        (r'\b([0-9a-fA-F]{32,})\b', '***HASH***'),  # Long hex strings (API keys)
        (r'\b([A-Za-z0-9+/]{40,}\={0,2})\b', '***BASE64***'),  # Base64 strings
    ]
    
    def format(self, record):
        """Format log record with sensitive data masking"""
        import re
        
        original_message = super().format(record)
        masked_message = original_message
        
        for pattern, replacement in self.SENSITIVE_PATTERNS:
            try:
                if isinstance(replacement, str):
                    masked_message = re.sub(pattern, replacement, masked_message)
                else:
                    masked_message = re.sub(pattern, replacement, masked_message)
            except:
                continue
        
        return masked_message

# =============================================================================
# ENHANCED LOG ROTATION SYSTEM
# =============================================================================

class EliteLogRotationSystem:
    """Enhanced log rotation system with automatic cleanup and archiving"""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.config = config_manager.load_config()
        self.log_dir = Path(self.config.get('log_directory', '/var/log/industrial_discovery'))
        self.max_log_size = self.config.get('max_log_size_mb', 100) * 1024 * 1024
        self.backup_count = self.config.get('log_backup_count', 5)
        self.retention_days = self.config.get('log_retention_days', 30)
        
        # Create log directory
        self.log_dir.mkdir(exist_ok=True, parents=True)
        
        self.setup_logging()
    
    def setup_logging(self):
        """Setup comprehensive logging with rotation"""
        # Clear existing handlers
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        secure_formatter = SecureLogFormatter()
        
        # Main log file handler with rotation
        main_log = self.log_dir / 'industrial_discovery.log'
        file_handler = logging.handlers.RotatingFileHandler(
            main_log,
            maxBytes=self.max_log_size,
            backupCount=self.backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(secure_formatter)
        
        # Error log handler
        error_log = self.log_dir / 'industrial_discovery_error.log'
        error_handler = logging.handlers.RotatingFileHandler(
            error_log,
            maxBytes=self.max_log_size,
            backupCount=self.backup_count,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(secure_formatter)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(secure_formatter)
        
        # Systemd journal handler (if available)
        try:
            journal_handler = journal.JournalHandler()
            journal_handler.setLevel(logging.INFO)
            journal_handler.setFormatter(secure_formatter)
            logging.root.addHandler(journal_handler)
        except:
            pass
        
        # Add handlers
        logging.root.setLevel(logging.DEBUG)
        logging.root.addHandler(file_handler)
        logging.root.addHandler(error_handler)
        logging.root.addHandler(console_handler)
    
    def cleanup_old_logs(self):
        """Cleanup old log files beyond retention period"""
        try:
            cutoff_time = time.time() - (self.retention_days * 24 * 3600)
            
            for log_file in self.log_dir.glob('*.log.*'):  # Rotated files
                if log_file.stat().st_mtime < cutoff_time:
                    log_file.unlink()
                    logging.info(f"Removed old log file: {log_file}")
            
            # Cleanup compressed archives
            archive_dir = self.log_dir / 'archives'
            if archive_dir.exists():
                for archive_file in archive_dir.glob('*.gz'):
                    if archive_file.stat().st_mtime < cutoff_time:
                        archive_file.unlink()
                        logging.info(f"Removed old archive: {archive_file}")
                        
        except Exception as e:
            logging.error(f"Log cleanup failed: {e}")
    
    def compress_old_logs(self):
        """Compress log files older than 7 days"""
        try:
            cutoff_time = time.time() - (7 * 24 * 3600)
            archive_dir = self.log_dir / 'archives'
            archive_dir.mkdir(exist_ok=True)
            
            for log_file in self.log_dir.glob('*.log.*'):
                if (log_file.stat().st_mtime < cutoff_time and 
                    not log_file.name.endswith('.gz')):
                    
                    # Compress file
                    compressed_path = archive_dir / f"{log_file.name}.gz"
                    with open(log_file, 'rb') as f_in:
                        with gzip.open(compressed_path, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    
                    # Remove original
                    log_file.unlink()
                    logging.info(f"Compressed log file: {log_file} -> {compressed_path}")
                    
        except Exception as e:
            logging.error(f"Log compression failed: {e}")
    
    def get_log_statistics(self) -> Dict[str, Any]:
        """Get log system statistics"""
        try:
            total_size = 0
            file_count = 0
            
            for log_file in self.log_dir.glob('*.log*'):
                if log_file.is_file():
                    total_size += log_file.stat().st_size
                    file_count += 1
            
            return {
                'log_directory': str(self.log_dir),
                'total_files': file_count,
                'total_size_mb': total_size / (1024 * 1024),
                'retention_days': self.retention_days,
                'max_file_size_mb': self.max_log_size / (1024 * 1024)
            }
        except Exception as e:
            logging.error(f"Log statistics failed: {e}")
            return {}

# =============================================================================
# ENHANCED CONFIGURATION MANAGEMENT
# =============================================================================

class EliteConfigManager:
    """Enhanced configuration management with YAML/JSON support"""
    
    def __init__(self, config_path: str = None):
        if config_path is None:
            # Default config paths
            config_paths = [
                'config/elite_config.yaml',
                '/etc/industrial_discovery/config.yaml',
                'elite_config.yaml'
            ]
            
            for path in config_paths:
                if Path(path).exists():
                    config_path = path
                    break
            else:
                config_path = 'config/elite_config.yaml'
        
        self.config_path = Path(config_path)
        self.config_path.parent.mkdir(exist_ok=True, parents=True)
        
        # Load or create default config
        if not self.config_path.exists():
            self._create_default_config()
        
        self.config = self.load_config()
    
    def _create_default_config(self):
        """Create comprehensive default configuration"""
        default_config = {
            # Network Discovery
            'network_ranges': ['192.168.1.0/24', '10.0.0.0/8', '172.16.0.0/12'],
            'scan_ports': [502, 161, 443, 80, 22, 23, 21, 25, 53, 123, 389, 636, 3389],
            'default_timeout': 5,
            'max_retries': 3,
            'retry_backoff': True,
            'backoff_multiplier': 2.0,
            'max_backoff': 60,
            
            # Rate Limiting
            'base_requests_per_second': 1.0,
            'burst_capacity': 5,
            'adaptive_rate_enabled': True,
            'vendor_rate_limits': {
                'siemens': 0.5,
                'rockwell': 0.3,
                'schneider': 0.4,
                'cisco': 2.0,
                'moxa': 1.0,
                'abb': 0.6,
                'honeywell': 0.4
            },
            
            # SNMP Configuration
            'snmp_community': 'public',
            'snmp_timeout': 5,
            'snmp_retries': 2,
            'snmpv3_enabled': True,
            'snmpv3_users': [
                {
                    'username': 'discovery',
                    'auth_protocol': 'SHA',
                    'auth_key': '${SNMPV3_AUTH_KEY}',
                    'priv_protocol': 'AES', 
                    'priv_key': '${SNMPV3_PRIV_KEY}'
                }
            ],
            
            # Modbus Configuration
            'modbus_ports': [502, 503, 2000, 44818],
            'modbus_timeout': 5,
            'modbus_retries': 2,
            'modbus_unit_id': 1,
            
            # LLDP Configuration
            'lldp_enabled': True,
            'lldp_interfaces': ['eth0', 'en0'],
            'lldp_scan_interval': 60,
            
            # Security Settings
            'encryption_enabled': True,
            'key_rotation_interval': 3600,
            'hmac_validation': True,
            'sensitive_data_masking': True,
            'audit_logging': True,
            
            # Output Configuration
            'output_directory': 'elite_discovery_outputs',
            'max_file_size_mb': 100,
            'max_files_count': 50,
            'retention_days': 30,
            'auto_archive_enabled': True,
            
            # Logging Configuration
            'log_level': 'INFO',
            'log_directory': '/var/log/industrial_discovery',
            'log_rotation_size_mb': 100,
            'log_backup_count': 5,
            'log_retention_days': 30,
            'sensitive_log_masking': True,
            
            # Passive Monitoring
            'passive_monitoring_enabled': False,
            'passive_interfaces': ['eth0', 'en0'],
            'passive_capture_filter': 'tcp or udp or arp or icmp or lldp',
            'passive_analysis_interval': 60,
            
            # SIEM Integration
            'siem_enabled': False,
            'siem_endpoints': ['http://localhost:9200'],
            'siem_batch_size': 1000,
            'siem_flush_interval': 30,
            'siem_auth_token': '${SIEM_AUTH_TOKEN}',
            
            # Dashboard Configuration
            'dashboard_enabled': True,
            'dashboard_port': 8050,
            'dashboard_host': '0.0.0.0',
            'dashboard_auth_required': True,
            
            # Test Environment
            'test_environment_enabled': False,
            'mininet_topology_file': 'test_topology.py',
            'plc_simulator_endpoints': ['http://localhost:8080'],
            
            # Advanced Settings
            'concurrent_workers': 20,
            'discovery_batch_size': 10,
            'topology_inference_enabled': True,
            'security_assessment_enabled': True,
            'continuous_monitoring_enabled': False,
            'monitoring_interval': 3600,
            
            # Resource Protection
            'max_memory_mb': 1024,
            'max_cpu_percent': 80,
            'max_file_descriptors': 1024,
            
            # CLI Defaults
            'cli_default_range': '192.168.1.0/24',
            'cli_default_rps': 1.0,
            'cli_default_timeout': 5
        }
        
        self.save_config(default_config)
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file with environment variable substitution"""
        try:
            with open(self.config_path, 'r') as f:
                config_content = f.read()
            
            # Substitute environment variables
            config_content = self._substitute_env_vars(config_content)
            
            if self.config_path.suffix.lower() in ['.yaml', '.yml']:
                config = yaml.safe_load(config_content)
            else:
                config = json.loads(config_content)
            
            return config or {}
            
        except Exception as e:
            logging.error(f"Config load failed: {e}")
            return self._get_fallback_config()
    
    def _substitute_env_vars(self, content: str) -> str:
        """Substitute environment variables in configuration"""
        import re
        
        def replace_env(match):
            env_var = match.group(1)
            return os.getenv(env_var, match.group(0))
        
        # Replace ${VAR} with environment variables
        return re.sub(r'\$\{([^}]+)\}', replace_env, content)
    
    def save_config(self, config: Dict[str, Any]):
        """Save configuration to file"""
        try:
            self.config_path.parent.mkdir(exist_ok=True, parents=True)
            
            if self.config_path.suffix.lower() in ['.yaml', '.yml']:
                with open(self.config_path, 'w') as f:
                    yaml.safe_dump(config, f, default_flow_style=False, indent=2)
            else:
                with open(self.config_path, 'w') as f:
                    json.dump(config, f, indent=2)
                    
        except Exception as e:
            logging.error(f"Config save failed: {e}")
    
    def _get_fallback_config(self) -> Dict[str, Any]:
        """Get fallback configuration when file loading fails"""
        return {
            'network_ranges': ['192.168.1.0/24'],
            'scan_ports': [502, 161, 80, 443],
            'default_timeout': 5,
            'max_retries': 3
        }
    
    def get_timeout(self, protocol: str = 'default') -> int:
        """Get timeout for specific protocol"""
        timeouts = {
            'snmp': self.config.get('snmp_timeout', 5),
            'modbus': self.config.get('modbus_timeout', 5),
            'lldp': self.config.get('lldp_timeout', 5),
            'default': self.config.get('default_timeout', 5)
        }
        return timeouts.get(protocol, timeouts['default'])
    
    def get_retries(self, protocol: str = 'default') -> int:
        """Get retry count for specific protocol"""
        retries = {
            'snmp': self.config.get('snmp_retries', 2),
            'modbus': self.config.get('modbus_retries', 2),
            'default': self.config.get('max_retries', 3)
        }
        return retries.get(protocol, retries['default'])

# =============================================================================
# ENHANCED CREDENTIAL MANAGEMENT WITH VAULT SUPPORT
# =============================================================================

class EliteCredentialManager:
    """Enhanced credential management with vault and environment variable support"""
    
    def __init__(self, config_manager: EliteConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.load_config()
        self.credentials_cache = {}
        self.vault_enabled = self.config.get('vault_enabled', False)
        self.vault_addr = self.config.get('vault_addr', 'http://localhost:8200')
        self.vault_token = os.getenv('VAULT_TOKEN')
        
        # Initialize vault client if enabled
        if self.vault_enabled and self.vault_token:
            try:
                import hvac
                self.vault_client = hvac.Client(url=self.vault_addr, token=self.vault_token)
                logging.info("Vault client initialized successfully")
            except ImportError:
                logging.warning("hvac not available, vault integration disabled")
                self.vault_enabled = False
        else:
            self.vault_enabled = False
    
    def get_credential(self, service: str, key: str) -> Optional[str]:
        """Get credential from secure storage"""
        # Check cache first
        cache_key = f"{service}.{key}"
        if cache_key in self.credentials_cache:
            return self.credentials_cache[cache_key]
        
        # Try environment variables first
        env_var = f"{service.upper()}_{key.upper()}"
        credential = os.getenv(env_var)
        
        if credential:
            self.credentials_cache[cache_key] = credential
            return credential
        
        # Try vault if enabled
        if self.vault_enabled:
            try:
                vault_path = f"secret/industrial_discovery/{service}"
                secret = self.vault_client.secrets.kv.v2.read_secret_version(path=vault_path)
                if secret and 'data' in secret and 'data' in secret['data']:
                    credential = secret['data']['data'].get(key)
                    if credential:
                        self.credentials_cache[cache_key] = credential
                        return credential
            except Exception as e:
                logging.error(f"Vault credential retrieval failed for {service}.{key}: {e}")
        
        # Fallback to configuration
        config_creds = self.config.get(f"{service}_credentials", {})
        credential = config_creds.get(key)
        
        if credential and credential.startswith('${') and credential.endswith('}'):
            # This is an environment variable reference that wasn't resolved
            return None
        
        if credential:
            self.credentials_cache[cache_key] = credential
        
        return credential
    
    def store_credential(self, service: str, key: str, value: str, persistent: bool = False):
        """Store credential in secure storage"""
        cache_key = f"{service}.{key}"
        self.credentials_cache[cache_key] = value
        
        if persistent:
            if self.vault_enabled:
                try:
                    vault_path = f"secret/industrial_discovery/{service}"
                    self.vault_client.secrets.kv.v2.create_or_update_secret(
                        path=vault_path,
                        secret={key: value}
                    )
                    logging.info(f"Credential stored in vault: {service}.{key}")
                except Exception as e:
                    logging.error(f"Vault credential storage failed: {e}")
    
    def get_snmpv3_credentials(self) -> List[Dict[str, str]]:
        """Get SNMPv3 credentials with secure retrieval"""
        snmpv3_users = self.config.get('snmpv3_users', [])
        enhanced_users = []
        
        for user in snmpv3_users:
            enhanced_user = user.copy()
            
            # Resolve auth key
            auth_key = user.get('auth_key', '')
            if auth_key.startswith('${') and auth_key.endswith('}'):
                env_var = auth_key[2:-1]
                enhanced_user['auth_key'] = os.getenv(env_var, '')
            
            # Resolve priv key
            priv_key = user.get('priv_key', '')
            if priv_key.startswith('${') and priv_key.endswith('}'):
                env_var = priv_key[2:-1]
                enhanced_user['priv_key'] = os.getenv(env_var, '')
            
            enhanced_users.append(enhanced_user)
        
        return enhanced_users

# =============================================================================
# ENHANCED LLDP PARSER WITH COMPLETE FRAME ANALYSIS
# =============================================================================

class EliteLLDPParser:
    """Enhanced LLDP parser with complete frame analysis and neighbor discovery"""
    
    def __init__(self):
        self.lldp_neighbors = {}
        self.parsed_frames = 0
        self.supported_tlvs = {
            1: 'Chassis ID',
            2: 'Port ID', 
            3: 'Time To Live',
            4: 'Port Description',
            5: 'System Name',
            6: 'System Description',
            7: 'System Capabilities',
            8: 'Management Address',
            127: 'Organization Specific'
        }
    
    def parse_lldp_frame(self, packet) -> Optional[Dict[str, Any]]:
        """Parse LLDP frame and extract complete neighbor information"""
        if not packet.haslayer(LLDPDU):
            return None
            
        try:
            lldp_data = {}
            chassis_id = None
            port_id = None
            system_name = None
            port_description = None
            system_description = None
            system_capabilities = None
            management_address = None
            ttl = None
            
            # Extract LLDPDU layers
            lldp_layers = []
            layer = packet
            while layer:
                if layer.name == 'LLDPDU':
                    lldp_layers.append(layer)
                layer = layer.payload
            
            for layer in lldp_layers:
                # Chassis ID
                if hasattr(layer, 'chassisID') and layer.chassisID:
                    chassis_id = self._parse_chassis_id(layer.chassisID)
                    lldp_data['chassis_id'] = chassis_id
                
                # Port ID
                if hasattr(layer, 'portID') and layer.portID:
                    port_id = self._parse_port_id(layer.portID)
                    lldp_data['port_id'] = port_id
                
                # Time To Live
                if hasattr(layer, 'ttl') and layer.ttl:
                    ttl = int(layer.ttl)
                    lldp_data['ttl'] = ttl
                
                # System Name
                if hasattr(layer, 'systemName') and layer.systemName:
                    system_name = str(layer.systemName)
                    lldp_data['system_name'] = system_name
                
                # System Description
                if hasattr(layer, 'systemDescription') and layer.systemDescription:
                    system_description = str(layer.systemDescription)
                    lldp_data['system_description'] = system_description
                
                # Port Description
                if hasattr(layer, 'portDescription') and layer.portDescription:
                    port_description = str(layer.portDescription)
                    lldp_data['port_description'] = port_description
                
                # System Capabilities
                if hasattr(layer, 'systemCapabilities') and layer.systemCapabilities:
                    system_capabilities = self._parse_system_capabilities(layer.systemCapabilities)
                    lldp_data['system_capabilities'] = system_capabilities
                
                # Management Address
                if hasattr(layer, 'managementAddress') and layer.managementAddress:
                    management_address = self._parse_management_address(layer.managementAddress)
                    lldp_data['management_address'] = management_address
            
            # Generate neighbor identifier
            if chassis_id and port_id:
                neighbor_id = f"{chassis_id}:{port_id}"
                lldp_data['neighbor_id'] = neighbor_id
                
                # Store in neighbors cache
                self.lldp_neighbors[neighbor_id] = {
                    'timestamp': time.time(),
                    'data': lldp_data
                }
            
            self.parsed_frames += 1
            return lldp_data
            
        except Exception as e:
            logging.error(f"LLDP frame parsing failed: {e}")
            return None
    
    def _parse_chassis_id(self, chassis_id) -> str:
        """Parse chassis ID TLV"""
        try:
            if hasattr(chassis_id, 'subtype'):
                subtype = chassis_id.subtype
                id_value = chassis_id.id
                
                if subtype == 4:  # MAC address
                    return ':'.join(f'{b:02x}' for b in id_value[:6])
                elif subtype == 5:  # Network Address
                    return socket.inet_ntoa(id_value[:4])
                else:
                    return id_value.decode('utf-8', errors='ignore')
            return str(chassis_id)
        except:
            return str(chassis_id)
    
    def _parse_port_id(self, port_id) -> str:
        """Parse port ID TLV"""
        try:
            if hasattr(port_id, 'subtype'):
                subtype = port_id.subtype
                id_value = port_id.id
                
                if subtype == 3:  # MAC address
                    return ':'.join(f'{b:02x}' for b in id_value[:6])
                elif subtype == 4:  # Network Address
                    return socket.inet_ntoa(id_value[:4])
                else:
                    return id_value.decode('utf-8', errors='ignore')
            return str(port_id)
        except:
            return str(port_id)
    
    def _parse_system_capabilities(self, capabilities) -> Dict[str, bool]:
        """Parse system capabilities TLV"""
        cap_dict = {}
        try:
            if hasattr(capabilities, 'capabilities'):
                cap_bits = capabilities.capabilities
                
                cap_dict = {
                    'other': bool(cap_bits & 0x01),
                    'repeater': bool(cap_bits & 0x02),
                    'bridge': bool(cap_bits & 0x04),
                    'wlan_ap': bool(cap_bits & 0x08),
                    'router': bool(cap_bits & 0x10),
                    'telephone': bool(cap_bits & 0x20),
                    'docsis': bool(cap_bits & 0x40),
                    'station_only': bool(cap_bits & 0x80)
                }
        except:
            pass
        return cap_dict
    
    def _parse_management_address(self, mgmt_addr) -> str:
        """Parse management address TLV"""
        try:
            if hasattr(mgmt_addr, 'address'):
                addr_str = str(mgmt_addr.address)
                # Extract IP address if present
                if '.' in addr_str:
                    return addr_str.split(' ')[0]  # Get IP part
                return addr_str
        except:
            pass
        return str(mgmt_addr)
    
    def generate_topology_links(self) -> List[Dict[str, Any]]:
        """Generate network topology links from LLDP data"""
        links = []
        
        for neighbor_id, neighbor_data in self.lldp_neighbors.items():
            data = neighbor_data['data']
            
            link = {
                'source_chassis': data.get('chassis_id', 'unknown'),
                'source_port': data.get('port_id', 'unknown'),
                'source_system': data.get('system_name', 'unknown'),
                'management_address': data.get('management_address', 'unknown'),
                'capabilities': data.get('system_capabilities', {}),
                'timestamp': neighbor_data['timestamp'],
                'ttl': data.get('ttl', 0)
            }
            
            links.append(link)
        
        return links
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get LLDP parser statistics"""
        return {
            'parsed_frames': self.parsed_frames,
            'unique_neighbors': len(self.lldp_neighbors),
            'neighbor_details': list(self.lldp_neighbors.keys())
        }

# =============================================================================
# ENHANCED PASSIVE DISCOVERY MODE
# =============================================================================

class ElitePassiveDiscoverer:
    """Enhanced passive discovery with SPAN/tap monitoring"""
    
    def __init__(self, config_manager: EliteConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.load_config()
        self.is_monitoring = False
        self.captured_packets = []
        self.device_fingerprints = {}
        self.network_topology = {}
        self.lldp_parser = EliteLLDPParser()
        
        # Statistics
        self.stats = {
            'packets_captured': 0,
            'devices_discovered': 0,
            'lldp_frames': 0,
            'start_time': 0
        }
    
    def start_passive_monitoring(self, interfaces: List[str] = None):
        """Start passive network monitoring"""
        if not interfaces:
            interfaces = self.config.get('passive_interfaces', ['eth0'])
        
        # Check privilege level
        if os.geteuid() != 0:
            logging.error("Passive monitoring requires root privileges")
            return False
        
        self.is_monitoring = True
        self.stats['start_time'] = time.time()
        
        # Start capture threads for each interface
        for interface in interfaces:
            if self._check_interface(interface):
                threading.Thread(
                    target=self._capture_interface,
                    args=(interface,),
                    daemon=True
                ).start()
                logging.info(f"Started passive monitoring on {interface}")
        
        # Start analysis thread
        threading.Thread(target=self._analyze_captures, daemon=True).start()
        
        return True
    
    def stop_passive_monitoring(self):
        """Stop passive monitoring"""
        self.is_monitoring = False
        logging.info("Passive monitoring stopped")
    
    def _check_interface(self, interface: str) -> bool:
        """Check if network interface is available"""
        try:
            interfaces = netifaces.interfaces()
            return interface in interfaces
        except:
            return False
    
    def _capture_interface(self, interface: str):
        """Capture packets on specific interface"""
        try:
            capture_filter = self.config.get('passive_capture_filter', 
                                           'tcp or udp or arp or icmp or lldp')
            
            # Use scapy's AsyncSniffer
            from scapy.all import AsyncSniffer
            
            sniffer = AsyncSniffer(
                iface=interface,
                filter=capture_filter,
                prn=self._process_packet,
                store=False
            )
            sniffer.start()
            
            # Keep thread alive while monitoring
            while self.is_monitoring:
                time.sleep(1)
            
            sniffer.stop()
            
        except Exception as e:
            logging.error(f"Packet capture failed on {interface}: {e}")
    
    def _process_packet(self, packet):
        """Process captured packet"""
        self.stats['packets_captured'] += 1
        
        # Store packet (with size limit)
        packet_info = {
            'timestamp': time.time(),
            'packet': packet,
            'summary': packet.summary()
        }
        self.captured_packets.append(packet_info)
        
        # Keep only recent packets
        if len(self.captured_packets) > 10000:
            self.captured_packets.pop(0)
        
        # Process packet for device discovery
        self._analyze_packet(packet)
    
    def _analyze_packet(self, packet):
        """Analyze packet for device information"""
        try:
            # Extract source information
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                self._update_device_fingerprint(src_ip, packet)
            
            # Extract MAC addresses
            if packet.haslayer(Ether):
                src_mac = packet[Ether].src
                self._update_mac_mapping(src_mac, packet)
            
            # Process LLDP frames for topology discovery
            if packet.haslayer(LLDPDU):
                self.stats['lldp_frames'] += 1
                lldp_data = self.lldp_parser.parse_lldp_frame(packet)
                if lldp_data:
                    self._update_topology(lldp_data)
                    
        except Exception as e:
            logging.debug(f"Packet analysis failed: {e}")
    
    def _update_device_fingerprint(self, ip: str, packet):
        """Update device fingerprint based on packet characteristics"""
        if ip not in self.device_fingerprints:
            self.device_fingerprints[ip] = {
                'first_seen': time.time(),
                'last_seen': time.time(),
                'protocols': set(),
                'ports': set(),
                'packet_count': 0,
                'vendor_indicators': set()
            }
            self.stats['devices_discovered'] += 1
        
        fingerprint = self.device_fingerprints[ip]
        fingerprint['last_seen'] = time.time()
        fingerprint['packet_count'] += 1
        
        # Protocol analysis
        if packet.haslayer(TCP):
            fingerprint['protocols'].add('TCP')
            fingerprint['ports'].add(packet[TCP].sport)
            fingerprint['ports'].add(packet[TCP].dport)
            
        if packet.haslayer(UDP):
            fingerprint['protocols'].add('UDP')
            fingerprint['ports'].add(packet[UDP].sport)
            fingerprint['ports'].add(packet[UDP].dport)
            
        if packet.haslayer(ICMP):
            fingerprint['protocols'].add('ICMP')
            
        if packet.haslayer(ARP):
            fingerprint['protocols'].add('ARP')
    
    def _update_mac_mapping(self, mac: str, packet):
        """Update MAC address to vendor mapping"""
        # Extract vendor from MAC OUI
        if mac != 'ff:ff:ff:ff:ff:ff' and mac != '00:00:00:00:00:00':
            oui = mac[:8].upper()
            vendor = self._get_vendor_from_oui(oui)
            if vendor and 'vendor' not in self.network_topology:
                self.network_topology['vendors'] = self.network_topology.get('vendors', {})
                self.network_topology['vendors'][mac] = vendor
    
    def _get_vendor_from_oui(self, oui: str) -> Optional[str]:
        """Get vendor name from MAC OUI"""
        # Common industrial vendor OUIs
        vendor_ouis = {
            '00:1D:9C': 'Rockwell Automation',
            '00:0E:8C': 'Siemens',
            '00:1B:1B': 'Schneider Electric',
            '00:1E:52': 'ABB',
            '00:17:81': 'Honeywell',
            '00:0C:29': 'VMware',  # Common in virtual environments
            '00:50:C2': 'Cisco',
            '00:1A:A0': 'Moxa'
        }
        return vendor_ouis.get(oui, None)
    
    def _update_topology(self, lldp_data: Dict[str, Any]):
        """Update network topology from LLDP data"""
        if 'neighbor_id' not in lldp_data:
            return
        
        neighbor_id = lldp_data['neighbor_id']
        self.network_topology[neighbor_id] = lldp_data
    
    def _analyze_captures(self):
        """Periodically analyze captured data"""
        analysis_interval = self.config.get('passive_analysis_interval', 60)
        
        while self.is_monitoring:
            try:
                # Generate topology from LLDP data
                lldp_links = self.lldp_parser.generate_topology_links()
                self.network_topology['lldp_links'] = lldp_links
                
                # Classify discovered devices
                classified_devices = self._classify_devices()
                self.network_topology['devices'] = classified_devices
                
                time.sleep(analysis_interval)
                
            except Exception as e:
                logging.error(f"Passive analysis failed: {e}")
                time.sleep(10)
    
    def _classify_devices(self) -> Dict[str, Dict[str, Any]]:
        """Classify devices based on passive fingerprinting"""
        classified = {}
        
        for ip, fingerprint in self.device_fingerprints.items():
            device_type = self._determine_device_type(fingerprint)
            
            classified[ip] = {
                'ip': ip,
                'device_type': device_type,
                'protocols': list(fingerprint['protocols']),
                'ports': list(fingerprint['ports']),
                'first_seen': fingerprint['first_seen'],
                'last_seen': fingerprint['last_seen'],
                'packet_count': fingerprint['packet_count']
            }
        
        return classified
    
    def _determine_device_type(self, fingerprint: Dict) -> str:
        """Determine device type from fingerprint"""
        protocols = fingerprint['protocols']
        ports = fingerprint['ports']
        
        # Industrial device detection
        if 502 in ports:  # Modbus
            return 'PLC'
        elif 44818 in ports:  # EtherNet/IP
            return 'Industrial Controller'
        elif 161 in ports:  # SNMP
            return 'Network Device'
        elif 80 in ports or 443 in ports:  # HTTP/HTTPS
            return 'HMI/SCADA'
        elif 22 in ports:  # SSH
            return 'Linux Device'
        elif 3389 in ports:  # RDP
            return 'Windows Device'
        else:
            return 'Unknown'
    
    def get_discovery_results(self) -> Dict[str, Any]:
        """Get passive discovery results"""
        return {
            'statistics': self.stats,
            'topology': self.network_topology,
            'devices': self._classify_devices(),
            'lldp_statistics': self.lldp_parser.get_statistics()
        }

# =============================================================================
# ENHANCED SIEM INTEGRATION
# =============================================================================

class EliteSIEMIntegration:
    """Enhanced SIEM integration with multiple output formats"""
    
    def __init__(self, config_manager: EliteConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.load_config()
        self.siem_enabled = self.config.get('siem_enabled', False)
        self.endpoints = self.config.get('siem_endpoints', [])
        self.batch_size = self.config.get('siem_batch_size', 1000)
        self.flush_interval = self.config.get('siem_flush_interval', 30)
        
        # Authentication
        self.auth_token = os.getenv('SIEM_AUTH_TOKEN', 
                                  self.config.get('siem_auth_token', ''))
        
        # Output formats
        self.output_formats = ['json', 'cef', 'leef']
        
        # Event queue
        self.event_queue = queue.Queue()
        self.batch_buffer = []
        
        if self.siem_enabled:
            self._start_worker()
    
    def _start_worker(self):
        """Start SIEM worker thread"""
        threading.Thread(target=self._process_events, daemon=True).start()
        logging.info("SIEM integration worker started")
    
    def send_event(self, event_type: str, data: Dict[str, Any], severity: str = "info"):
        """Send event to SIEM system"""
        if not self.siem_enabled:
            return
        
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'type': event_type,
            'data': data,
            'severity': severity,
            'source': 'industrial_discovery_elite',
            'version': '2.0'
        }
        
        self.event_queue.put(event)
    
    def _process_events(self):
        """Process events from queue and send to SIEM"""
        last_flush = time.time()
        
        while True:
            try:
                current_time = time.time()
                
                # Check if it's time to flush
                if (self.batch_buffer and 
                    (len(self.batch_buffer) >= self.batch_size or 
                     current_time - last_flush >= self.flush_interval)):
                    
                    self._flush_batch()
                    last_flush = current_time
                
                # Get event from queue
                try:
                    event = self.event_queue.get(timeout=1)
                    self.batch_buffer.append(event)
                    self.event_queue.task_done()
                except queue.Empty:
                    continue
                    
            except Exception as e:
                logging.error(f"SIEM event processing error: {e}")
                time.sleep(5)
    
    def _flush_batch(self):
        """Flush batch of events to SIEM endpoints"""
        if not self.batch_buffer:
            return
        
        batch = self.batch_buffer.copy()
        self.batch_buffer.clear()
        
        for endpoint in self.endpoints:
            try:
                if endpoint.startswith('http'):
                    self._send_http(endpoint, batch)
                elif endpoint.startswith('tcp://'):
                    self._send_tcp(endpoint, batch)
                elif endpoint.startswith('kafka://'):
                    self._send_kafka(endpoint, batch)
                elif endpoint.startswith('file://'):
                    self._send_file(endpoint, batch)
                    
            except Exception as e:
                logging.error(f"SIEM endpoint {endpoint} failed: {e}")
    
    def _send_http(self, endpoint: str, batch: List[Dict]):
        """Send batch to HTTP/HTTPS endpoint (ELK, Splunk HTTP Event Collector)"""
        try:
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'IndustrialDiscoveryElite/2.0'
            }
            
            if self.auth_token:
                headers['Authorization'] = f'Bearer {self.auth_token}'
            
            # Format events based on endpoint type
            if 'splunk' in endpoint.lower():
                formatted_events = self._format_splunk_events(batch)
            else:  # Default JSON format for ELK
                formatted_events = self._format_elk_events(batch)
            
            response = requests.post(
                endpoint,
                json=formatted_events,
                headers=headers,
                timeout=30
            )
            
            if response.status_code not in [200, 201, 202]:
                logging.warning(f"SIEM HTTP endpoint returned {response.status_code}: {response.text}")
            else:
                logging.debug(f"Sent {len(batch)} events to {endpoint}")
                
        except Exception as e:
            logging.error(f"HTTP SIEM send failed: {e}")
            raise
    
    def _send_tcp(self, endpoint: str, batch: List[Dict]):
        """Send batch to TCP syslog endpoint"""
        try:
            # Parse endpoint (tcp://host:port)
            parts = endpoint[6:].split(':')
            host = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 514
            
            # Create TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            
            # Send events in CEF format
            for event in batch:
                cef_message = self._format_cef_event(event)
                sock.send(cef_message.encode('utf-8') + b'\n')
            
            sock.close()
            logging.debug(f"Sent {len(batch)} events to TCP syslog {endpoint}")
            
        except Exception as e:
            logging.error(f"TCP SIEM send failed: {e}")
            raise
    
    def _send_kafka(self, endpoint: str, batch: List[Dict]):
        """Send batch to Kafka endpoint"""
        try:
            # This would require kafka-python
            # Placeholder implementation
            logging.info(f"Would send {len(batch)} events to Kafka {endpoint}")
        except Exception as e:
            logging.error(f"Kafka SIEM send failed: {e}")
    
    def _send_file(self, endpoint: str, batch: List[Dict]):
        """Send batch to file endpoint"""
        try:
            file_path = endpoint[7:]  # Remove file://
            
            with open(file_path, 'a') as f:
                for event in batch:
                    f.write(json.dumps(event) + '\n')
            
            logging.debug(f"Written {len(batch)} events to file {file_path}")
            
        except Exception as e:
            logging.error(f"File SIEM send failed: {e}")
    
    def _format_splunk_events(self, batch: List[Dict]) -> Dict[str, Any]:
        """Format events for Splunk HTTP Event Collector"""
        events = []
        
        for event in batch:
            splunk_event = {
                'time': event['timestamp'],
                'source': 'industrial_discovery',
                'sourcetype': '_json',
                'event': event
            }
            events.append(splunk_event)
        
        return {'events': events}
    
    def _format_elk_events(self, batch: List[Dict]) -> List[Dict]:
        """Format events for ELK stack"""
        return batch
    
    def _format_cef_event(self, event: Dict) -> str:
        """Format event as CEF (Common Event Format)"""
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        cef_parts = [
            'CEF:0',
            'IndustrialDiscovery',
            'Elite',
            '2.0',
            event.get('type', 'unknown'),
            event.get('type', 'unknown').replace('_', ' ').title(),
            self._severity_to_cef(event.get('severity', 'info'))
        ]
        
        # Build extension
        extensions = []
        data = event.get('data', {})
        
        for key, value in data.items():
            if isinstance(value, (str, int, float, bool)):
                safe_key = key.replace(' ', '_').replace('.', '_')
                extensions.append(f'{safe_key}={value}')
        
        cef_parts.append(' '.join(extensions))
        return '|'.join(cef_parts)
    
    def _severity_to_cef(self, severity: str) -> str:
        """Convert severity to CEF numeric format"""
        severity_map = {
            'critical': '10',
            'high': '8',
            'medium': '5', 
            'low': '3',
            'info': '1'
        }
        return severity_map.get(severity.lower(), '1')
    
    def send_discovery_results(self, devices: List[Dict], links: List[Dict], 
                             topology: Dict[str, Any]):
        """Send discovery results to SIEM"""
        event_data = {
            'devices_count': len(devices),
            'links_count': len(links),
            'topology_segments': len(topology.get('segments', [])),
            'discovery_timestamp': datetime.utcnow().isoformat()
        }
        
        self.send_event('network_discovery_complete', event_data, 'info')
    
    def send_security_alert(self, device_ip: str, issue: str, severity: str, 
                          details: Dict[str, Any]):
        """Send security alert to SIEM"""
        alert_data = {
            'device_ip': device_ip,
            'issue': issue,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.send_event('security_alert', alert_data, severity)

# =============================================================================
# ENHANCED RATE LIMITING WITH VENDOR TEMPLATES
# =============================================================================

class EliteRateLimiter:
    """Enhanced rate limiter with vendor-specific templates and adaptive control"""
    
    def __init__(self, config_manager: EliteConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.load_config()
        
        # Rate limiting configuration
        self.base_rps = self.config.get('base_requests_per_second', 1.0)
        self.burst_capacity = self.config.get('burst_capacity', 5)
        self.vendor_limits = self.config.get('vendor_rate_limits', {})
        
        # State tracking
        self.tokens = self.burst_capacity
        self.last_update = time.time()
        self.vendor_stats = defaultdict(lambda: {'requests': 0, 'failures': 0})
        self.adaptive_enabled = self.config.get('adaptive_rate_enabled', True)
        
        # Lock for thread safety
        self._lock = threading.RLock()
    
    def get_vendor_rate_limit(self, vendor: str) -> float:
        """Get rate limit for specific vendor"""
        vendor_lower = vendor.lower()
        
        # Check for exact match
        if vendor_lower in self.vendor_limits:
            return self.vendor_limits[vendor_lower]
        
        # Check for partial match (e.g., 'siemens' in 'siemens-plc')
        for vendor_key, rate in self.vendor_limits.items():
            if vendor_key in vendor_lower:
                return rate
        
        # Default rate
        return self.base_rps
    
    async def acquire(self, vendor: str = "unknown"):
        """Acquire token for making a request"""
        rate_limit = self.get_vendor_rate_limit(vendor)
        
        while True:
            with self._lock:
                now = time.time()
                time_passed = now - self.last_update
                
                # Refill tokens based on elapsed time
                self.tokens = min(
                    self.burst_capacity,
                    self.tokens + time_passed * rate_limit
                )
                self.last_update = now
                
                if self.tokens >= 1:
                    self.tokens -= 1
                    self.vendor_stats[vendor]['requests'] += 1
                    return
                    
            # Wait before checking again
            await asyncio.sleep(1 / rate_limit)
    
    def record_success(self, vendor: str):
        """Record successful request"""
        with self._lock:
            # Reset failure count on success
            self.vendor_stats[vendor]['failures'] = 0
    
    def record_failure(self, vendor: str):
        """Record failed request and potentially adjust rate"""
        with self._lock:
            self.vendor_stats[vendor]['failures'] += 1
            
            # Adaptive rate adjustment
            if self.adaptive_enabled:
                failures = self.vendor_stats[vendor]['failures']
                if failures > 3:
                    # Reduce rate after multiple failures
                    current_rate = self.get_vendor_rate_limit(vendor)
                    new_rate = max(0.1, current_rate * 0.5)
                    self.vendor_limits[vendor] = new_rate
                    logging.warning(f"Reduced rate limit for {vendor} to {new_rate} RPS due to failures")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get rate limiting statistics"""
        with self._lock:
            return {
                'base_rps': self.base_rps,
                'current_tokens': self.tokens,
                'vendor_stats': dict(self.vendor_stats),
                'vendor_limits': self.vendor_limits
            }

# =============================================================================
# ENHANCED RETRY AND BACKOFF SYSTEM
# =============================================================================

class EliteRetryManager:
    """Enhanced retry manager with exponential backoff and circuit breaker"""
    
    def __init__(self, config_manager: EliteConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.load_config()
        
        self.max_retries = self.config.get('max_retries', 3)
        self.backoff_enabled = self.config.get('retry_backoff', True)
        self.backoff_multiplier = self.config.get('backoff_multiplier', 2.0)
        self.max_backoff = self.config.get('max_backoff', 60)
        
        # Circuit breaker state
        self.circuit_states = {}  # key: (target, protocol) -> state
        self.failure_threshold = 5
        self.circuit_timeout = 300  # 5 minutes
    
    async def execute_with_retry(self, func, *args, protocol: str = "unknown", 
                               target: str = "unknown", **kwargs):
        """Execute function with retry logic and exponential backoff"""
        last_exception = None
        circuit_key = (target, protocol)
        
        # Check circuit breaker
        if self._is_circuit_open(circuit_key):
            raise ConnectionError(f"Circuit breaker open for {target} ({protocol})")
        
        for attempt in range(self.max_retries + 1):
            try:
                result = await func(*args, **kwargs)
                
                # Success - reset circuit breaker
                self._record_success(circuit_key)
                return result
                
            except (ConnectionError, TimeoutError, asyncio.TimeoutError) as e:
                last_exception = e
                
                # Record failure for circuit breaker
                self._record_failure(circuit_key)
                
                if attempt == self.max_retries:
                    break
                
                # Calculate backoff delay
                delay = self._calculate_backoff(attempt)
                logging.warning(f"Attempt {attempt + 1}/{self.max_retries + 1} failed for {target}: {e}. Retrying in {delay:.2f}s")
                
                await asyncio.sleep(delay)
                
            except Exception as e:
                # Non-retryable error
                last_exception = e
                break
        
        # All retries failed
        error_msg = f"All {self.max_retries + 1} attempts failed for {target} ({protocol}): {last_exception}"
        logging.error(error_msg)
        raise ConnectionError(error_msg) from last_exception
    
    def _calculate_backoff(self, attempt: int) -> float:
        """Calculate exponential backoff delay"""
        if not self.backoff_enabled:
            return 1.0
        
        delay = min(self.max_backoff, self.backoff_multiplier ** attempt)
        return delay
    
    def _is_circuit_open(self, circuit_key: Tuple[str, str]) -> bool:
        """Check if circuit breaker is open for given target"""
        if circuit_key not in self.circuit_states:
            return False
        
        state = self.circuit_states[circuit_key]
        if state['state'] == 'open':
            # Check if timeout has passed
            if time.time() - state['last_failure'] > self.circuit_timeout:
                # Move to half-open state
                state['state'] = 'half_open'
                state['half_open_time'] = time.time()
                return False
            return True
        
        return False
    
    def _record_failure(self, circuit_key: Tuple[str, str]):
        """Record failure for circuit breaker"""
        if circuit_key not in self.circuit_states:
            self.circuit_states[circuit_key] = {
                'failures': 0,
                'state': 'closed',
                'last_failure': time.time()
            }
        
        state = self.circuit_states[circuit_key]
        state['failures'] += 1
        state['last_failure'] = time.time()
        
        if state['failures'] >= self.failure_threshold:
            state['state'] = 'open'
            logging.warning(f"Circuit breaker opened for {circuit_key}")
    
    def _record_success(self, circuit_key: Tuple[str, str]):
        """Record success for circuit breaker"""
        if circuit_key in self.circuit_states:
            state = self.circuit_states[circuit_key]
            
            if state['state'] == 'half_open':
                # Success in half-open state, reset circuit
                state['state'] = 'closed'
                state['failures'] = 0
            elif state['state'] == 'closed':
                # Reset failure count on success
                state['failures'] = max(0, state['failures'] - 1)

# =============================================================================
# ENHANCED AUDIT TRAIL SYSTEM
# =============================================================================

class EliteAuditTrail:
    """Enhanced audit trail system with digital signatures"""
    
    def __init__(self, config_manager: EliteConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.load_config()
        
        self.audit_enabled = self.config.get('audit_logging', True)
        self.audit_dir = Path(self.config.get('audit_directory', 'audit_logs'))
        self.audit_dir.mkdir(exist_ok=True, parents=True)
        
        # Digital signature setup
        self.private_key = self._load_or_generate_private_key()
        self.public_key = self.private_key.public_key() if self.private_key else None
        
        # Audit log file
        self.audit_file = self.audit_dir / f"audit_{int(time.time())}.log"
        
        # Statistics
        self.entries_logged = 0
    
    def _load_or_generate_private_key(self) -> Optional[rsa.RSAPrivateKey]:
        """Load or generate RSA private key for digital signatures"""
        try:
            key_path = self.audit_dir / "audit_key.pem"
            
            if key_path.exists():
                with open(key_path, 'rb') as f:
                    private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None,
                        backend=default_backend()
                    )
                return private_key
            else:
                # Generate new key
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                
                # Save key
                with open(key_path, 'wb') as f:
                    f.write(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                
                # Set restrictive permissions
                key_path.chmod(0o600)
                
                return private_key
                
        except Exception as e:
            logging.error(f"Audit key management failed: {e}")
            return None
    
    def log_operation(self, operation: str, target: str, user: str = "system",
                     details: Dict[str, Any] = None, success: bool = True):
        """Log an operation to audit trail"""
        if not self.audit_enabled:
            return
        
        try:
            audit_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'operation': operation,
                'target': target,
                'user': user,
                'success': success,
                'details': details or {},
                'session_id': getattr(threading.current_thread(), 'name', 'unknown')
            }
            
            # Generate digital signature
            if self.private_key:
                signature = self._sign_audit_entry(audit_entry)
                audit_entry['signature'] = base64.b64encode(signature).decode('utf-8')
            
            # Write to audit log
            with open(self.audit_file, 'a') as f:
                f.write(json.dumps(audit_entry) + '\n')
            
            self.entries_logged += 1
            
            # Rotate audit log if too large
            if self.audit_file.stat().st_size > 100 * 1024 * 1024:  # 100MB
                self._rotate_audit_log()
                
        except Exception as e:
            logging.error(f"Audit logging failed: {e}")
    
    def _sign_audit_entry(self, audit_entry: Dict[str, Any]) -> bytes:
        """Generate digital signature for audit entry"""
        try:
            # Create signature data
            signature_data = json.dumps({
                'timestamp': audit_entry['timestamp'],
                'operation': audit_entry['operation'],
                'target': audit_entry['target'],
                'user': audit_entry['user']
            }, sort_keys=True).encode('utf-8')
            
            # Generate signature
            signature = self.private_key.sign(
                signature_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return signature
            
        except Exception as e:
            logging.error(f"Audit signature generation failed: {e}")
            return b''
    
    def verify_audit_entry(self, audit_entry: Dict[str, Any]) -> bool:
        """Verify digital signature of audit entry"""
        try:
            if 'signature' not in audit_entry:
                return False
            
            # Recreate signature data
            signature_data = json.dumps({
                'timestamp': audit_entry['timestamp'],
                'operation': audit_entry['operation'],
                'target': audit_entry['target'],
                'user': audit_entry['user']
            }, sort_keys=True).encode('utf-8')
            
            signature = base64.b64decode(audit_entry['signature'])
            
            # Verify signature
            self.public_key.verify(
                signature,
                signature_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except Exception as e:
            logging.error(f"Audit signature verification failed: {e}")
            return False
    
    def _rotate_audit_log(self):
        """Rotate audit log file"""
        try:
            timestamp = int(time.time())
            new_audit_file = self.audit_dir / f"audit_{timestamp}.log"
            self.audit_file.rename(new_audit_file)
            
            # Create new audit file
            self.audit_file = self.audit_dir / f"audit_{timestamp + 1}.log"
            
            # Compress old audit files
            self._compress_old_audit_logs()
            
        except Exception as e:
            logging.error(f"Audit log rotation failed: {e}")
    
    def _compress_old_audit_logs(self):
        """Compress old audit log files"""
        try:
            cutoff_time = time.time() - (7 * 24 * 3600)  # 7 days
            
            for audit_file in self.audit_dir.glob("audit_*.log"):
                if (audit_file != self.audit_file and 
                    audit_file.stat().st_mtime < cutoff_time):
                    
                    compressed_file = audit_file.with_suffix('.log.gz')
                    with open(audit_file, 'rb') as f_in:
                        with gzip.open(compressed_file, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    
                    audit_file.unlink()
                    logging.info(f"Compressed audit log: {audit_file}")
                    
        except Exception as e:
            logging.error(f"Audit log compression failed: {e}")
    
    def get_audit_statistics(self) -> Dict[str, Any]:
        """Get audit system statistics"""
        return {
            'audit_enabled': self.audit_enabled,
            'entries_logged': self.entries_logged,
            'current_audit_file': str(self.audit_file),
            'signing_enabled': self.private_key is not None
        }

# =============================================================================
# ENHANCED OUTPUT FILE MANAGEMENT
# =============================================================================

class EliteOutputManager:
    """Enhanced output file management with rotation and archiving"""
    
    def __init__(self, config_manager: EliteConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.load_config()
        
        self.output_dir = Path(self.config.get('output_directory', 'elite_discovery_outputs'))
        self.max_file_size = self.config.get('max_file_size_mb', 100) * 1024 * 1024
        self.max_files = self.config.get('max_files_count', 50)
        self.retention_days = self.config.get('retention_days', 30)
        self.auto_archive = self.config.get('auto_archive_enabled', True)
        
        # Create directory structure
        self._create_directory_structure()
    
    def _create_directory_structure(self):
        """Create comprehensive output directory structure"""
        directories = [
            self.output_dir,
            self.output_dir / "json",
            self.output_dir / "svg", 
            self.output_dir / "reports",
            self.output_dir / "archives",
            self.output_dir / "logs",
            self.output_dir / "security",
            self.output_dir / "backups",
            self.output_dir / "temp"
        ]
        
        for directory in directories:
            directory.mkdir(exist_ok=True, parents=True)
    
    async def manage_output_rotation(self):
        """Manage output file rotation and archiving"""
        try:
            await self._compress_old_files()
            await self._remove_old_files()
            await self._enforce_size_limits()
            await self._cleanup_temp_files()
            
            logging.info("Output rotation management completed")
            
        except Exception as e:
            logging.error(f"Output rotation management failed: {e}")
    
    async def _compress_old_files(self):
        """Compress files older than retention threshold"""
        try:
            # Compress files older than 7 days
            cutoff_time = time.time() - (7 * 24 * 3600)
            
            for directory in [self.output_dir / "json", self.output_dir / "svg", self.output_dir / "reports"]:
                for file_path in directory.glob("*"):
                    if (file_path.is_file() and 
                        file_path.stat().st_mtime < cutoff_time and 
                        file_path.suffix != '.gz' and
                        not file_path.name.startswith('.')):
                        
                        compressed_path = self.output_dir / "archives" / f"{file_path.name}.gz"
                        
                        with open(file_path, 'rb') as f_in:
                            with gzip.open(compressed_path, 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)
                        
                        file_path.unlink()
                        logging.info(f"Compressed and archived: {file_path.name}")
                        
        except Exception as e:
            logging.error(f"File compression failed: {e}")
    
    async def _remove_old_files(self):
        """Remove files older than retention period"""
        try:
            cutoff_time = time.time() - (self.retention_days * 24 * 3600)
            
            # Remove old archived files
            for file_path in (self.output_dir / "archives").glob("*.gz"):
                if file_path.stat().st_mtime < cutoff_time:
                    file_path.unlink()
                    logging.info(f"Removed old archive: {file_path.name}")
            
            # Remove old backup files
            for file_path in (self.output_dir / "backups").glob("*.bak"):
                if file_path.stat().st_mtime < cutoff_time:
                    file_path.unlink()
                    logging.info(f"Removed old backup: {file_path.name}")
                    
        except Exception as e:
            logging.error(f"Old file removal failed: {e}")
    
    async def _enforce_size_limits(self):
        """Enforce maximum file count and size limits"""
        try:
            for directory in [self.output_dir / "json", self.output_dir / "svg", 
                            self.output_dir / "reports", self.output_dir / "archives"]:
                
                files = list(directory.glob("*"))
                
                # Sort by modification time (oldest first)
                files.sort(key=lambda x: x.stat().st_mtime)
                
                # Remove oldest files if over limit
                if len(files) > self.max_files:
                    for file_path in files[:-self.max_files]:
                        file_path.unlink()
                        logging.info(f"Removed excess file: {file_path.name}")
                
                # Check individual file sizes
                for file_path in files:
                    if file_path.stat().st_size > self.max_file_size:
                        # Rotate large files
                        timestamp = int(time.time())
                        new_name = file_path.parent / f"{file_path.stem}_{timestamp}{file_path.suffix}"
                        file_path.rename(new_name)
                        logging.info(f"Rotated large file: {file_path.name} -> {new_name.name}")
                        
        except Exception as e:
            logging.error(f"Size limit enforcement failed: {e}")
    
    async def _cleanup_temp_files(self):
        """Cleanup temporary files"""
        try:
            temp_dir = self.output_dir / "temp"
            
            # Remove files older than 1 day from temp directory
            cutoff_time = time.time() - (24 * 3600)
            
            for file_path in temp_dir.glob("*"):
                if file_path.stat().st_mtime < cutoff_time:
                    file_path.unlink()
                    
        except Exception as e:
            logging.error(f"Temp file cleanup failed: {e}")
    
    def get_output_path(self, file_type: str, timestamp: int = None, suffix: str = "") -> Path:
        """Get output file path with proper organization"""
        if timestamp is None:
            timestamp = int(time.time())
        
        filename = f"{file_type}_{timestamp}{suffix}"
        
        file_type_map = {
            'topology': self.output_dir / "svg" / f"{filename}.svg",
            'json': self.output_dir / "json" / f"{filename}.json",
            'report': self.output_dir / "reports" / f"{filename}.json",
            'security': self.output_dir / "security" / f"{filename}_security.json",
            'backup': self.output_dir / "backups" / f"{filename}.bak",
            'temp': self.output_dir / "temp" / filename
        }
        
        return file_type_map.get(file_type, self.output_dir / filename)
    
    def create_backup(self, source_path: Path) -> bool:
        """Create backup of important files"""
        try:
            if not source_path.exists():
                return False
            
            timestamp = int(time.time())
            backup_path = self.get_output_path('backup', timestamp, f"_{source_path.name}")
            
            shutil.copy2(source_path, backup_path)
            logging.info(f"Backup created: {backup_path}")
            return True
            
        except Exception as e:
            logging.error(f"Backup creation failed: {e}")
            return False

# =============================================================================
# ENHANCED RESOURCE PROTECTION
# =============================================================================

class EliteResourceProtector:
    """Enhanced resource protection with CPU and memory limits"""
    
    def __init__(self, config_manager: EliteConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.load_config()
        
        self.max_memory_mb = self.config.get('max_memory_mb', 1024)
        self.max_cpu_percent = self.config.get('max_cpu_percent', 80)
        self.max_file_descriptors = self.config.get('max_file_descriptors', 1024)
        
        # Monitoring
        self.monitoring_enabled = True
        self.usage_history = deque(maxlen=100)
        
        # Set initial resource limits
        self._set_resource_limits()
    
    def _set_resource_limits(self):
        """Set system resource limits"""
        try:
            # Set memory limit
            if hasattr(resource, 'RLIMIT_AS'):
                memory_limit = self.max_memory_mb * 1024 * 1024  # Convert to bytes
                resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
            
            # Set file descriptor limit
            if hasattr(resource, 'RLIMIT_NOFILE'):
                resource.setrlimit(resource.RLIMIT_NOFILE, 
                                 (self.max_file_descriptors, self.max_file_descriptors))
            
            logging.info("Resource limits set successfully")
            
        except Exception as e:
            logging.error(f"Resource limit setting failed: {e}")
    
    def start_monitoring(self):
        """Start resource usage monitoring"""
        def monitor_resources():
            while self.monitoring_enabled:
                try:
                    # Get current resource usage
                    memory_usage = self._get_memory_usage()
                    cpu_usage = self._get_cpu_usage()
                    
                    # Store in history
                    self.usage_history.append({
                        'timestamp': time.time(),
                        'memory_mb': memory_usage,
                        'cpu_percent': cpu_usage
                    })
                    
                    # Check limits
                    self._check_resource_limits(memory_usage, cpu_usage)
                    
                    time.sleep(5)  # Check every 5 seconds
                    
                except Exception as e:
                    logging.error(f"Resource monitoring failed: {e}")
                    time.sleep(10)
        
        threading.Thread(target=monitor_resources, daemon=True).start()
        logging.info("Resource monitoring started")
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB"""
        process = psutil.Process()
        return process.memory_info().rss / (1024 * 1024)
    
    def _get_cpu_usage(self) -> float:
        """Get current CPU usage percentage"""
        process = psutil.Process()
        return process.cpu_percent()
    
    def _check_resource_limits(self, memory_usage: float, cpu_usage: float):
        """Check if resource usage exceeds limits"""
        warnings = []
        
        if memory_usage > self.max_memory_mb:
            warnings.append(f"Memory usage {memory_usage:.1f}MB exceeds limit {self.max_memory_mb}MB")
        
        if cpu_usage > self.max_cpu_percent:
            warnings.append(f"CPU usage {cpu_usage:.1f}% exceeds limit {self.max_cpu_percent}%")
        
        if warnings:
            logging.warning("Resource limits exceeded: " + "; ".join(warnings))
            
            # If severely over limit, take action
            if memory_usage > self.max_memory_mb * 1.5:
                logging.error("Severe memory overuse detected, consider reducing workload")
    
    def get_resource_statistics(self) -> Dict[str, Any]:
        """Get resource usage statistics"""
        if not self.usage_history:
            return {}
        
        recent_usage = list(self.usage_history)[-10:]  # Last 10 samples
        
        memory_values = [u['memory_mb'] for u in recent_usage]
        cpu_values = [u['cpu_percent'] for u in recent_usage]
        
        return {
            'current_memory_mb': memory_values[-1] if memory_values else 0,
            'current_cpu_percent': cpu_values[-1] if cpu_values else 0,
            'avg_memory_mb': sum(memory_values) / len(memory_values) if memory_values else 0,
            'avg_cpu_percent': sum(cpu_values) / len(cpu_values) if cpu_values else 0,
            'max_memory_mb': max(memory_values) if memory_values else 0,
            'max_cpu_percent': max(cpu_values) if cpu_values else 0,
            'limits': {
                'max_memory_mb': self.max_memory_mb,
                'max_cpu_percent': self.max_cpu_percent,
                'max_file_descriptors': self.max_file_descriptors
            }
        }
    
    def stop_monitoring(self):
        """Stop resource monitoring"""
        self.monitoring_enabled = False

# =============================================================================
# ENHANCED COMMAND LINE INTERFACE
# =============================================================================

class EliteCLI:
    """Enhanced command line interface with comprehensive options"""
    
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description='Industrial Network Topology Discovery - Elite Edition',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Basic network discovery
  python3 elite_discovery.py --range 192.168.1.0/24
  
  # SNMPv3 discovery with custom credentials
  python3 elite_discovery.py --range 10.0.0.0/8 --snmpv3 --snmpv3-user admin --snmpv3-auth-key secret
  
  # High-speed discovery with increased rate limit
  python3 elite_discovery.py --range 172.16.0.0/12 --rps 5.0 --timeout 2
  
  # Passive monitoring only
  python3 elite_discovery.py --passive-only --interface eth0
  
  # Continuous monitoring
  python3 elite_discovery.py --range 192.168.1.0/24 --continuous --interval 3600
            """
        )
        
        self._setup_arguments()
    
    def _setup_arguments(self):
        """Setup command line arguments"""
        # Network configuration
        network_group = self.parser.add_argument_group('Network Configuration')
        network_group.add_argument('--range', '-r', 
                                 help='Network range in CIDR notation (e.g., 192.168.1.0/24)')
        network_group.add_argument('--interface', '-i',
                                 help='Network interface for passive monitoring')
        network_group.add_argument('--ports', '-p', nargs='+', type=int,
                                 help='Ports to scan (default: common industrial ports)')
        
        # Rate limiting
        rate_group = self.parser.add_argument_group('Rate Limiting')
        rate_group.add_argument('--rps', '--requests-per-second', type=float,
                              help='Requests per second rate limit')
        rate_group.add_argument('--timeout', '-t', type=float,
                              help='Request timeout in seconds')
        rate_group.add_argument('--retries', type=int,
                              help='Number of retry attempts')
        
        # SNMP Configuration
        snmp_group = self.parser.add_argument_group('SNMP Configuration')
        snmp_group.add_argument('--snmpv3', action='store_true',
                              help='Enable SNMPv3 discovery')
        snmp_group.add_argument('--snmpv3-user',
                              help='SNMPv3 username')
        snmp_group.add_argument('--snmpv3-auth-key',
                              help='SNMPv3 authentication key')
        snmp_group.add_argument('--snmpv3-priv-key',
                              help='SNMPv3 privacy key')
        snmp_group.add_argument('--snmp-community',
                              help='SNMP community string (v1/v2c)')
        
        # Operation modes
        mode_group = self.parser.add_argument_group('Operation Modes')
        mode_group.add_argument('--passive-only', action='store_true',
                              help='Enable passive monitoring only')
        mode_group.add_argument('--continuous', action='store_true',
                              help='Enable continuous monitoring')
        mode_group.add_argument('--interval', type=int,
                              help='Continuous monitoring interval in seconds')
        
        # Output options
        output_group = self.parser.add_argument_group('Output Options')
        output_group.add_argument('--output', '-o',
                                help='Output directory')
        output_group.add_argument('--format', choices=['json', 'svg', 'all'],
                                help='Output format')
        output_group.add_argument('--no-dashboard', action='store_true',
                                help='Disable web dashboard')
        
        # Security options
        security_group = self.parser.add_argument_group('Security Options')
        security_group.add_argument('--audit', action='store_true',
                                  help='Enable audit logging')
        security_group.add_argument('--siem', action='store_true',
                                  help='Enable SIEM integration')
        
        # Advanced options
        advanced_group = self.parser.add_argument_group('Advanced Options')
        advanced_group.add_argument('--config', 
                                  help='Configuration file path')
        advanced_group.add_argument('--verbose', '-v', action='count', default=0,
                                  help='Increase verbosity')
        advanced_group.add_argument('--debug', action='store_true',
                                  help='Enable debug mode')
    
    def parse_args(self):
        """Parse command line arguments"""
        args = self.parser.parse_args()
        
        # Set log level based on verbosity
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
        elif args.verbose >= 2:
            logging.getLogger().setLevel(logging.DEBUG)
        elif args.verbose >= 1:
            logging.getLogger().setLevel(logging.INFO)
        
        return args
    
    def validate_args(self, args) -> List[str]:
        """Validate command line arguments"""
        errors = []
        
        # Validate network range
        if args.range and not self._is_valid_cidr(args.range):
            errors.append(f"Invalid network range: {args.range}")
        
        # Validate SNMPv3 arguments
        if args.snmpv3:
            if not args.snmpv3_user:
                errors.append("SNMPv3 requires --snmpv3-user")
            if not args.snmpv3_auth_key:
                errors.append("SNMPv3 requires --snmpv3-auth-key")
        
        # Validate rate limits
        if args.rps and args.rps <= 0:
            errors.append("RPS must be positive")
        
        if args.timeout and args.timeout <= 0:
            errors.append("Timeout must be positive")
        
        return errors
    
    def _is_valid_cidr(self, cidr: str) -> bool:
        """Validate CIDR notation"""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False
    
    def apply_args_to_config(self, args, config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply command line arguments to configuration"""
        updated_config = config.copy()
        
        # Network configuration
        if args.range:
            updated_config['network_ranges'] = [args.range]
        
        if args.ports:
            updated_config['scan_ports'] = args.ports
        
        # Rate limiting
        if args.rps:
            updated_config['base_requests_per_second'] = args.rps
        
        if args.timeout:
            updated_config['default_timeout'] = args.timeout
        
        if args.retries:
            updated_config['max_retries'] = args.retries
        
        # SNMP configuration
        if args.snmpv3:
            updated_config['snmpv3_enabled'] = True
            if args.snmpv3_user:
                # Update or add SNMPv3 user
                snmpv3_users = updated_config.get('snmpv3_users', [])
                if snmpv3_users:
                    snmpv3_users[0]['username'] = args.snmpv3_user
                    if args.snmpv3_auth_key:
                        snmpv3_users[0]['auth_key'] = args.snmpv3_auth_key
                    if args.snmpv3_priv_key:
                        snmpv3_users[0]['priv_key'] = args.snmpv3_priv_key
                else:
                    snmpv3_users.append({
                        'username': args.snmpv3_user,
                        'auth_protocol': 'SHA',
                        'auth_key': args.snmpv3_auth_key or '',
                        'priv_protocol': 'AES',
                        'priv_key': args.snmpv3_priv_key or ''
                    })
        
        if args.snmp_community:
            updated_config['snmp_community'] = args.snmp_community
        
        # Operation modes
        if args.passive_only:
            updated_config['passive_monitoring_enabled'] = True
        
        if args.continuous:
            updated_config['continuous_monitoring_enabled'] = True
        
        if args.interval:
            updated_config['monitoring_interval'] = args.interval
        
        # Output options
        if args.output:
            updated_config['output_directory'] = args.output
        
        if args.no_dashboard:
            updated_config['dashboard_enabled'] = False
        
        # Security options
        if args.audit:
            updated_config['audit_logging'] = True
        
        if args.siem:
            updated_config['siem_enabled'] = True
        
        return updated_config

# =============================================================================
# ENHANCED MAIN DISCOVERY SYSTEM INTEGRATION
# =============================================================================

class IndustrialNetworkTopologyDiscovererEliteEnhanced:
    """
    Enhanced Industrial Network Topology Discovery System - Elite Edition v2.0
    """
    
    def __init__(self, config_path: str = None):
        # Initialize enhanced components
        self.config_manager = EliteConfigManager(config_path)
        self.config = self.config_manager.load_config()
        
        # Enhanced systems
        self.credential_manager = EliteCredentialManager(self.config_manager)
        self.rate_limiter = EliteRateLimiter(self.config_manager)
        self.retry_manager = EliteRetryManager(self.config_manager)
        self.audit_trail = EliteAuditTrail(self.config_manager)
        self.output_manager = EliteOutputManager(self.config_manager)
        self.resource_protector = EliteResourceProtector(self.config_manager)
        self.log_rotation = EliteLogRotationSystem(self.config_manager)
        
        # Protocol handlers
        self.snmpv3_auth_priv = EliteSNMPv3AuthPriv(
            username='discovery',
            auth_key='',
            priv_key='',
            auth_protocol='SHA',
            priv_protocol='AES'
        )
        
        self.lldp_parser = EliteLLDPParser()
        self.passive_discoverer = ElitePassiveDiscoverer(self.config_manager)
        self.siem_integration = EliteSIEMIntegration(self.config_manager)
        
        # Discovery state
        self.discovered_devices = {}
        self.network_links = []
        self.discovery_results = {}
        
        # Start resource monitoring
        self.resource_protector.start_monitoring()
        
        logging.info("Enhanced Industrial Network Topology Discoverer Elite initialized")
    
    async def discover_network_enhanced(self, network_range: str = None) -> Dict[str, Any]:
        """Enhanced network discovery with all advanced features"""
        start_time = time.time()
        
        try:
            # Log discovery start
            self.audit_trail.log_operation(
                'network_discovery_start',
                network_range or 'default',
                details={'timestamp': start_time}
            )
            
            # Update network range if provided
            if network_range:
                self.config['network_ranges'] = [network_range]
            
            # Start passive monitoring if enabled
            if self.config.get('passive_monitoring_enabled', False):
                self.passive_discoverer.start_passive_monitoring()
            
            # Perform active discovery
            active_results = await self._perform_active_discovery()
            
            # Get passive results
            passive_results = self.passive_discoverer.get_discovery_results()
            
            # Merge results
            merged_results = self._merge_discovery_results(active_results, passive_results)
            
            # Generate outputs
            output_files = await self._generate_enhanced_outputs(merged_results)
            
            # Send to SIEM
            if self.config.get('siem_enabled', False):
                self.siem_integration.send_discovery_results(
                    list(merged_results['devices'].values()),
                    merged_results['links'],
                    merged_results['topology']
                )
            
            # Log discovery completion
            discovery_time = time.time() - start_time
            self.audit_trail.log_operation(
                'network_discovery_complete',
                network_range or 'default',
                details={
                    'duration': discovery_time,
                    'devices_found': len(merged_results['devices']),
                    'links_found': len(merged_results['links'])
                },
                success=True
            )
            
            # Update discovery results
            self.discovery_results = merged_results
            self.discovery_results['statistics']['discovery_time'] = discovery_time
            self.discovery_results['output_files'] = output_files
            
            logging.info(f"Enhanced discovery completed in {discovery_time:.2f} seconds")
            
            return self.discovery_results
            
        except Exception as e:
            # Log discovery failure
            self.audit_trail.log_operation(
                'network_discovery_failed',
                network_range or 'default',
                details={'error': str(e)},
                success=False
            )
            
            logging.error(f"Enhanced discovery failed: {e}")
            raise
    
    async def _perform_active_discovery(self) -> Dict[str, Any]:
        """Perform active network discovery"""
        # This would implement the actual discovery logic
        # Using the enhanced components like rate_limiter, retry_manager, etc.
        
        # Placeholder implementation
        return {
            'devices': {},
            'links': [],
            'topology': {},
            'statistics': {}
        }
    
    def _merge_discovery_results(self, active_results: Dict[str, Any], 
                               passive_results: Dict[str, Any]) -> Dict[str, Any]:
        """Merge active and passive discovery results"""
        merged = {
            'devices': {},
            'links': [],
            'topology': {},
            'statistics': {
                'active_devices': len(active_results.get('devices', {})),
                'passive_devices': len(passive_results.get('devices', {})),
                'total_devices': 0,
                'total_links': 0
            }
        }
        
        # Merge devices
        for ip, device in active_results.get('devices', {}).items():
            merged['devices'][ip] = device
        
        for ip, device in passive_results.get('devices', {}).items():
            if ip in merged['devices']:
                # Merge device information
                merged['devices'][ip].update(device)
            else:
                merged['devices'][ip] = device
        
        # Merge links
        merged['links'] = active_results.get('links', []) + passive_results.get('links', [])
        
        # Merge topology
        merged['topology'] = {
            **active_results.get('topology', {}),
            **passive_results.get('topology', {})
        }
        
        # Update statistics
        merged['statistics']['total_devices'] = len(merged['devices'])
        merged['statistics']['total_links'] = len(merged['links'])
        
        return merged
    
    async def _generate_enhanced_outputs(self, results: Dict[str, Any]) -> Dict[str, str]:
        """Generate enhanced output files"""
        timestamp = int(time.time())
        output_files = {}
        
        try:
            # JSON output
            json_path = self.output_manager.get_output_path('json', timestamp)
            with open(json_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            output_files['json'] = str(json_path)
            
            # SVG topology
            svg_path = await self._generate_enhanced_topology_svg(results, timestamp)
            output_files['svg'] = str(svg_path)
            
            # Security report
            security_path = self._generate_security_report(results, timestamp)
            output_files['security'] = str(security_path)
            
            # Compress outputs if enabled
            if self.config.get('auto_archive_enabled', True):
                await self.output_manager.manage_output_rotation()
            
            logging.info(f"Enhanced outputs generated: {list(output_files.keys())}")
            
        except Exception as e:
            logging.error(f"Enhanced output generation failed: {e}")
        
        return output_files
    
    async def _generate_enhanced_topology_svg(self, results: Dict[str, Any], 
                                            timestamp: int) -> Path:
        """Generate enhanced topology visualization"""
        try:
            # Use graphviz for topology visualization
            dot = graphviz.Digraph(
                comment='Industrial Network Topology - Enhanced',
                engine='neato',
                graph_attr={
                    'overlap': 'false',
                    'splines': 'true',
                    'rankdir': 'TB'
                }
            )
            
            # Add devices as nodes
            for ip, device in results.get('devices', {}).items():
                node_attrs = self._get_enhanced_node_attrs(device)
                dot.node(ip, self._get_enhanced_node_label(device), **node_attrs)
            
            # Add links as edges
            for link in results.get('links', []):
                edge_attrs = self._get_enhanced_edge_attrs(link)
                dot.edge(link.get('source', ''), link.get('target', ''), **edge_attrs)
            
            # Generate SVG
            output_path = self.output_manager.get_output_path('topology', timestamp)
            dot.render(output_path, format='svg', cleanup=True)
            
            return Path(f"{output_path}.svg")
            
        except Exception as e:
            logging.error(f"Enhanced topology generation failed: {e}")
            return Path("/tmp/topology_error.svg")
    
    def _get_enhanced_node_attrs(self, device: Dict) -> Dict[str, str]:
        """Get enhanced node attributes for visualization"""
        device_type = device.get('device_type', 'unknown').lower()
        
        colors = {
            'plc': 'lightblue',
            'hmi': 'lightgreen', 
            'controller': 'orange',
            'sensor': 'yellow',
            'actuator': 'pink',
            'switch': 'lightgray',
            'router': 'darkgray',
            'firewall': 'red'
        }
        
        return {
            'shape': 'box',
            'style': 'filled,rounded',
            'fillcolor': colors.get(device_type, 'white'),
            'color': 'black'
        }
    
    def _get_enhanced_node_label(self, device: Dict) -> str:
        """Get enhanced node label"""
        label_parts = []
        
        if device.get('hostname'):
            label_parts.append(device['hostname'])
        else:
            label_parts.append(device.get('ip', 'unknown'))
        
        label_parts.append(device.get('device_type', 'unknown').upper())
        
        if device.get('vendor', 'unknown') != 'unknown':
            label_parts.append(device['vendor'])
        
        return '\n'.join(label_parts)
    
    def _get_enhanced_edge_attrs(self, link: Dict) -> Dict[str, str]:
        """Get enhanced edge attributes"""
        protocol = link.get('protocol', 'tcp').lower()
        
        styles = {
            'lldp': {'color': 'blue', 'style': 'solid'},
            'snmp': {'color': 'purple', 'style': 'dashed'},
            'modbus': {'color': 'red', 'style': 'bold'},
            'tcp': {'color': 'green', 'style': 'solid'},
            'udp': {'color': 'orange', 'style': 'dotted'}
        }
        
        return styles.get(protocol, {'color': 'black', 'style': 'solid'})
    
    def _generate_security_report(self, results: Dict[str, Any], timestamp: int) -> Path:
        """Generate enhanced security report"""
        security_path = self.output_manager.get_output_path('security', timestamp)
        
        # Analyze security posture
        security_issues = self._analyze_security_posture(results)
        
        report = {
            'timestamp': timestamp,
            'summary': {
                'total_devices': len(results.get('devices', {})),
                'security_issues': len(security_issues),
                'critical_issues': len([i for i in security_issues if i.get('severity') == 'critical']),
                'high_issues': len([i for i in security_issues if i.get('severity') == 'high'])
            },
            'security_issues': security_issues,
            'recommendations': self._generate_security_recommendations(security_issues)
        }
        
        with open(security_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        return security_path
    
    def _analyze_security_posture(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze network security posture"""
        issues = []
        
        for ip, device in results.get('devices', {}).items():
            device_issues = self._analyze_device_security(device)
            issues.extend(device_issues)
        
        return issues
    
    def _analyze_device_security(self, device: Dict) -> List[Dict[str, Any]]:
        """Analyze individual device security"""
        issues = []
        
        # Check for insecure protocols
        protocols = device.get('protocols', [])
        if 'snmp' in protocols and device.get('snmp_version') in ['v1', 'v2c']:
            issues.append({
                'device': device.get('ip', 'unknown'),
                'issue': 'Insecure SNMP version',
                'severity': 'high',
                'recommendation': 'Upgrade to SNMPv3 with authentication',
                'protocol': 'SNMP'
            })
        
        if 'modbus' in protocols:
            issues.append({
                'device': device.get('ip', 'unknown'),
                'issue': 'Unencrypted Modbus communication',
                'severity': 'medium',
                'recommendation': 'Implement network segmentation or Modbus/TCP Security',
                'protocol': 'MODBUS'
            })
        
        if 'http' in protocols and 'https' not in protocols:
            issues.append({
                'device': device.get('ip', 'unknown'),
                'issue': 'Unencrypted HTTP web interface',
                'severity': 'medium',
                'recommendation': 'Enable HTTPS and redirect HTTP to HTTPS',
                'protocol': 'HTTP'
            })
        
        return issues
    
    def _generate_security_recommendations(self, issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate security recommendations"""
        recommendations = []
        
        # Network segmentation
        if any(i['severity'] in ['high', 'critical'] for i in issues):
            recommendations.append({
                'priority': 'high',
                'category': 'Network Architecture',
                'action': 'Implement network segmentation',
                'rationale': 'Isolate critical industrial systems from corporate network'
            })
        
        # Protocol security
        if any(i['protocol'] == 'SNMP' for i in issues):
            recommendations.append({
                'priority': 'high',
                'category': 'Protocol Security',
                'action': 'Upgrade SNMP to v3',
                'rationale': 'SNMP v1/v2c uses plaintext community strings'
            })
        
        # Access control
        if len([i for i in issues if i['severity'] in ['high', 'critical']]) > 5:
            recommendations.append({
                'priority': 'medium',
                'category': 'Access Control',
                'action': 'Implement strict firewall rules',
                'rationale': 'Reduce attack surface and prevent unauthorized access'
            })
        
        return recommendations
    
    async def continuous_monitoring_enhanced(self, interval_minutes: int = 60):
        """Enhanced continuous monitoring"""
        if not self.config.get('continuous_monitoring_enabled', False):
            logging.info("Continuous monitoring disabled")
            return
        
        logging.info(f"Starting enhanced continuous monitoring with {interval_minutes} minute intervals")
        
        try:
            while True:
                await asyncio.sleep(interval_minutes * 60)
                
                logging.info("Starting periodic enhanced network discovery")
                await self.discover_network_enhanced()
                
        except KeyboardInterrupt:
            logging.info("Enhanced continuous monitoring stopped")
        except Exception as e:
            logging.error(f"Enhanced continuous monitoring failed: {e}")
    
    def get_system_statistics(self) -> Dict[str, Any]:
        """Get comprehensive system statistics"""
        return {
            'resource_usage': self.resource_protector.get_resource_statistics(),
            'audit_statistics': self.audit_trail.get_audit_statistics(),
            'rate_limiting': self.rate_limiter.get_statistics(),
            'discovery_results': {
                'devices_found': len(self.discovered_devices),
                'links_found': len(self.network_links)
            }
        }
    
    async def cleanup_enhanced(self):
        """Enhanced cleanup operations"""
        logging.info("Starting enhanced cleanup")
        
        # Stop passive monitoring
        self.passive_discoverer.stop_passive_monitoring()
        
        # Stop resource monitoring
        self.resource_protector.stop_monitoring()
        
        # Manage output rotation
        await self.output_manager.manage_output_rotation()
        
        # Cleanup log files
        self.log_rotation.cleanup_old_logs()
        self.log_rotation.compress_old_logs()
        
        logging.info("Enhanced cleanup completed")

# =============================================================================
# ENHANCED MAIN EXECUTION
# =============================================================================

async def main_enhanced():
    """
    Enhanced Industrial Network Topology Discovery - Elite Edition v2.0
    """
    print("Industrial Network Topology Discovery - Elite Edition v2.0")
    print("=" * 70)
    print("Enhanced Enterprise-Grade Security Assessment Implementation")
    print("REDHACK Elite - Advanced Protocol Support with SNMPv3 Auth+Priv")
    print("=" * 70)
    
    # Parse command line arguments
    cli = EliteCLI()
    args = cli.parse_args()
    
    # Validate arguments
    validation_errors = cli.validate_args(args)
    if validation_errors:
        for error in validation_errors:
            print(f"Error: {error}")
        return
    
    discoverer = None
    try:
        # Initialize enhanced discovery system
        discoverer = IndustrialNetworkTopologyDiscovererEliteEnhanced(args.config)
        
        # Apply command line arguments to configuration
        if args:
            discoverer.config = cli.apply_args_to_config(args, discoverer.config)
        
        # Display system information
        print(f"Privilege Level: {'root' if os.geteuid() == 0 else 'user'}")
        print(f"Configuration: {discoverer.config_manager.config_path}")
        print(f"Output Directory: {discoverer.config['output_directory']}")
        print()
        
        # Start discovery
        network_range = args.range if args.range else discoverer.config['network_ranges'][0]
        print(f"Starting Enhanced Elite Network Discovery for {network_range}...")
        
        results = await discoverer.discover_network_enhanced(network_range)
        
        # Display summary
        print("\n" + "=" * 70)
        print("ENHANCED ELITE DISCOVERY SUMMARY")
        print("=" * 70)
        
        stats = results.get('statistics', {})
        print(f"Network Range: {network_range}")
        print(f"Total Devices Discovered: {stats.get('total_devices', 0)}")
        print(f"Active Devices: {stats.get('active_devices', 0)}")
        print(f"Passive Devices: {stats.get('passive_devices', 0)}")
        print(f"Network Links: {stats.get('total_links', 0)}")
        print(f"Discovery Time: {stats.get('discovery_time', 0):.2f} seconds")
        print()
        
        # Display security summary
        security_issues = len(results.get('security_issues', []))
        if security_issues > 0:
            print(f"Security Issues Found: {security_issues}")
            critical_issues = len([i for i in results.get('security_issues', []) 
                                 if i.get('severity') == 'critical'])
            if critical_issues > 0:
                print(f"CRITICAL ISSUES: {critical_issues} - Immediate attention required!")
        print()
        
        # Display output files
        output_files = results.get('output_files', {})
        if output_files:
            print("Output Files Generated:")
            for file_type, file_path in output_files.items():
                print(f"  {file_type.upper()}: {file_path}")
        
        print("\nEnhanced Elite Discovery Completed Successfully!")
        
        # Display system statistics
        system_stats = discoverer.get_system_statistics()
        print(f"\nSystem Statistics:")
        print(f"  Memory Usage: {system_stats['resource_usage'].get('current_memory_mb', 0):.1f} MB")
        print(f"  CPU Usage: {system_stats['resource_usage'].get('current_cpu_percent', 0):.1f}%")
        print(f"  Audit Entries: {system_stats['audit_statistics'].get('entries_logged', 0)}")
        
        # Continuous monitoring if enabled
        if args.continuous or discoverer.config.get('continuous_monitoring_enabled', False):
            interval = args.interval if args.interval else discoverer.config.get('monitoring_interval', 3600)
            print(f"\nStarting continuous monitoring with {interval} second intervals...")
            await discoverer.continuous_monitoring_enhanced(interval // 60)
        
    except KeyboardInterrupt:
        print("\nDiscovery interrupted by user")
    except Exception as e:
        print(f"\nEnhanced elite discovery failed: {e}")
        logging.error(f"Enhanced main execution failed: {e}", exc_info=True)
    finally:
        # Cleanup
        try:
            if discoverer:
                await discoverer.cleanup_enhanced()
        except:
            pass

if __name__ == "__main__":
    # Run enhanced main function
    asyncio.run(main_enhanced())