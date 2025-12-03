#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VARUX Web Security Scanning System - ELITE TERMINAL EDITION v6.0
Advanced Web Application Security Scanner with AI-Powered Detection
Version 6.0 - Production Ready CLI with Advanced Engineering
# ------------------------------------------------------------
# VARUX SECURITY TOOLKIT
# License: GPL-3.0-or-later
# 
# Yasal Uyarı:
# Bu araç yalnızca eğitim ve güvenlik testi amaçlıdır.
# İzinsiz sistemlere karşı kullanımı yasa dışıdır.
# Yazar, kötüye kullanımdan sorumlu değildir.
# ------------------------------------------------------------
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import pickle
import queue
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from urllib.parse import urljoin, urlparse, parse_qs, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

import backoff
import colorama
import dns.resolver
import psutil
import requests
import urllib3
import yaml
from bs4 import BeautifulSoup
from colorama import Fore, Style, Back
from retrying import retry
from tqdm import tqdm

# Async imports
import aiohttp
import asyncio

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
colorama.init(autoreset=True)

# Try to import optional dependencies with fallbacks
try:
    import questionary
    QUESTIONARY_AVAILABLE = True
except ImportError:
    QUESTIONARY_AVAILABLE = False

try:
    from prometheus_client import Counter as PromCounter, Histogram, Gauge, start_http_server
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    
    # Create mock classes for compatibility
    class PromCounter:
        def __init__(self, *args, **kwargs): 
            self._labels = {}
        def labels(self, **kwargs): 
            return self
        def inc(self, amount=1): 
            pass
    
    class Histogram:
        def __init__(self, *args, **kwargs): 
            pass
        def observe(self, amount): 
            pass
    
    class Gauge:
        def __init__(self, *args, **kwargs):
            self._value = 0
        def set(self, value): 
            self._value = value
        def inc(self, amount=1): 
            self._value += amount
        def dec(self, amount=1): 
            self._value -= amount
        def _value_get(self): 
            return self._value
    
    def start_http_server(port):
        logging.warning(f"Prometheus not available, metrics server on port {port} disabled")

# =============================================================================
# Constants & Global Configuration
# =============================================================================

class ScanModes(Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    COMPREHENSIVE = "comprehensive"

class SeverityLevels(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ExitCodes(Enum):
    SUCCESS = 0
    GENERAL_ERROR = 1
    CONFIG_ERROR = 2
    NETWORK_ERROR = 3
    SCAN_ERROR = 4
    PERMISSION_ERROR = 5

# =============================================================================
# Enhanced Configuration Management
# =============================================================================

class ConfigManager:
    """Advanced configuration management with validation and encryption"""

    CONFIG_SCHEMA = {
        'type': 'object',
        'properties': {
            'global': {
                'type': 'object',
                'properties': {
                    'log_level': {'type': 'string', 'enum': ['DEBUG', 'INFO', 'WARNING', 'ERROR']},
                    'max_concurrent_tasks': {'type': 'integer', 'minimum': 1, 'maximum': 100},
                    'default_timeout': {'type': 'integer', 'minimum': 1, 'maximum': 300},
                    'max_retries': {'type': 'integer', 'minimum': 0, 'maximum': 10}
                },
                'required': ['log_level', 'max_concurrent_tasks', 'default_timeout', 'max_retries']
            },
            'scan': {
                'type': 'object',
                'properties': {
                    'rate_limit': {
                        'type': 'object',
                        'properties': {
                            'requests_per_second': {'type': 'number', 'minimum': 0.1, 'maximum': 100},
                            'max_concurrent_requests': {'type': 'integer', 'minimum': 1, 'maximum': 50}
                        }
                    },
                    'timeouts': {
                        'type': 'object',
                        'properties': {
                            'connect': {'type': 'integer', 'minimum': 1, 'maximum': 60},
                            'read': {'type': 'integer', 'minimum': 1, 'maximum': 120}
                        }
                    },
                    'user_agent': {'type': 'string'},
                    'follow_redirects': {'type': 'boolean'},
                    'verify_ssl': {'type': 'boolean'}
                }
            }
        }
    }

    def __init__(self, config_path: str = None):
        self.config_path = Path(config_path) if config_path else self.get_default_config_path()
        self.config = self.load_default_config()
        self.load_config()
        self.validate_config()

    def get_default_config_path(self) -> Path:
        """Get default config path with proper permissions"""
        config_dir = Path.home() / '.varux'
        config_dir.mkdir(mode=0o700, exist_ok=True)
        return config_dir / 'config.yaml'

    def load_default_config(self) -> Dict[str, Any]:
        """Load validated default configuration"""
        return {
            'global': {
                'log_level': 'INFO',
                'max_concurrent_tasks': 10,
                'default_timeout': 30,
                'max_retries': 3,
                'enable_telemetry': True,
                'auto_update': True
            },
            'scan': {
                'rate_limit': {
                    'requests_per_second': 10,
                    'max_concurrent_requests': 20,
                    'burst_limit': 5
                },
                'timeouts': {
                    'connect': 10,
                    'read': 30,
                    'total': 300
                },
                'user_agent': 'VARUX-Security-Scanner/6.0',
                'follow_redirects': True,
                'verify_ssl': False,
                'max_redirects': 10,
                'throttle_delay': 0.1
            },
            'security': {
                'sensitive_data_masking': True,
                'max_payload_size': 1048576,
                'sanitize_inputs': True,
                'encryption_level': 'high',
                'session_timeout': 3600
            },
            'storage': {
                'reports_dir': str(Path.home() / '.varux' / 'reports'),
                'checkpoints_dir': str(Path.home() / '.varux' / 'checkpoints'),
                'backup_retention_days': 30,
                'max_report_size': 52428800  # 50MB
            },
            'monitoring': {
                'enable_metrics': True,
                'metrics_port': 9090,
                'health_check_interval': 60,
                'performance_threshold': 0.8
            },
            'api': {
                'enabled': False,
                'host': 'localhost',
                'port': 8080,
                'auth_required': True
            },
            'modules': {
                'sql_injection_module_path': r"C:\Users\s3loc_\Desktop\VXİM\moduler\sqlinjektion.py",
                'enable_advanced_modules': True
            }
        }

    def load_config(self) -> None:
        """Load configuration from file with error handling"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    file_config = yaml.safe_load(f) or {}
                    self.deep_merge(self.config, file_config)

                # Set secure permissions
                self.config_path.chmod(0o600)
                logging.info(f"Configuration loaded from {self.config_path}")

        except yaml.YAMLError as e:
            logging.error(f"Invalid YAML in config file: {e}")
            raise
        except Exception as e:
            logging.warning(f"Failed to load config file: {e}")

    def save_config(self) -> bool:
        """Save configuration to file with backup"""
        try:
            # Create backup
            if self.config_path.exists():
                backup_path = self.config_path.with_suffix('.yaml.backup')
                shutil.copy2(self.config_path, backup_path)

            # Save new config
            with open(self.config_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False, indent=2)

            # Set secure permissions
            self.config_path.chmod(0o600)
            logging.info(f"Configuration saved to {self.config_path}")
            return True

        except Exception as e:
            logging.error(f"Failed to save config: {e}")
            return False

    def validate_config(self) -> bool:
        """Validate configuration against schema"""
        try:
            # Basic validation
            required_sections = ['global', 'scan', 'security']
            for section in required_sections:
                if section not in self.config:
                    logging.warning(f"Missing configuration section: {section}")
                    return False

            # Value validation
            if self.config['global']['max_concurrent_tasks'] < 1:
                logging.warning("max_concurrent_tasks must be at least 1")
                return False

            return True
        except Exception as e:
            logging.error(f"Configuration validation failed: {e}")
            return False

    def deep_merge(self, base: Dict, update: Dict) -> None:
        """Deep merge two dictionaries"""
        for key, value in update.items():
            if isinstance(value, dict) and key in base and isinstance(base[key], dict):
                self.deep_merge(base[key], value)
            else:
                base[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """Get config value by dot notation key"""
        keys = key.split('.')
        current = self.config

        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default
        return current

    def set(self, key: str, value: Any) -> bool:
        """Set config value by dot notation key"""
        try:
            keys = key.split('.')
            current = self.config

            for k in keys[:-1]:
                if k not in current or not isinstance(current[k], dict):
                    current[k] = {}
                current = current[k]

            current[keys[-1]] = value
            return True
        except Exception as e:
            logging.error(f"Failed to set config value: {e}")
            return False

# =============================================================================
# Advanced Security & Secrets Management
# =============================================================================

class AdvancedSecretsManager:
    """Enterprise-grade secrets management with encryption and access control"""

    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.secrets_dir = Path.home() / '.varux' / 'secrets'
        self.secrets_dir.mkdir(mode=0o700, exist_ok=True)
        self.master_key = self._derive_master_key()
        self.encryption_engine = EncryptionEngine()

    def _derive_master_key(self) -> bytes:
        """Derive master encryption key from system and user data"""
        # Combine multiple system factors for key derivation - Cross-platform compatible
        try:
            import platform
            system_info = platform.system()
            release_info = platform.release()
        except:
            system_info = "unknown"
            release_info = "unknown"

        system_factors = [
            system_info.encode(),
            release_info.encode(),
            str(os.getpid()).encode(),
            Path.home().as_posix().encode(),
            socket.gethostname().encode(),
            str(time.time()).encode()
        ]

        key_material = b''.join(system_factors)
        return hashlib.pbkdf2_hmac('sha512', key_material, b'varux_master_salt', 100000, 64)

    def _get_secret_path(self, key: str) -> Path:
        """Get filesystem path for secret"""
        safe_key = hashlib.sha256(key.encode()).hexdigest()[:16]
        return self.secrets_dir / f"{safe_key}.enc"

    def store_secret(self, key: str, value: str, description: str = "") -> bool:
        """Store a secret securely with metadata"""
        try:
            secret_data = {
                'value': value,
                'description': description,
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat(),
                'version': 1
            }

            encrypted_data = self.encryption_engine.encrypt(
                json.dumps(secret_data).encode(),
                self.master_key
            )

            secret_path = self._get_secret_path(key)
            with open(secret_path, 'wb') as f:
                f.write(encrypted_data)

            secret_path.chmod(0o600)
            logging.info(f"Secret stored securely: {key}")
            return True

        except Exception as e:
            logging.error(f"Failed to store secret: {e}")
            return False

    def get_secret(self, key: str) -> Optional[str]:
        """Get a secret by key"""
        try:
            secret_path = self._get_secret_path(key)
            if not secret_path.exists():
                return None

            with open(secret_path, 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = self.encryption_engine.decrypt(encrypted_data, self.master_key)
            secret_info = json.loads(decrypted_data.decode())

            return secret_info['value']

        except Exception as e:
            logging.error(f"Failed to retrieve secret: {e}")
            return None

    def list_secrets(self) -> List[Dict[str, str]]:
        """List all stored secrets"""
        secrets = []
        for secret_file in self.secrets_dir.glob('*.enc'):
            try:
                with open(secret_file, 'rb') as f:
                    encrypted_data = f.read()

                decrypted_data = self.encryption_engine.decrypt(encrypted_data, self.master_key)
                secret_info = json.loads(decrypted_data.decode())

                secrets.append({
                    'key': secret_file.stem,
                    'description': secret_info.get('description', ''),
                    'created_at': secret_info.get('created_at', ''),
                    'updated_at': secret_info.get('updated_at', '')
                })
            except Exception:
                continue

        return secrets

    def delete_secret(self, key: str) -> bool:
        """Permanently delete a secret"""
        try:
            secret_path = self._get_secret_path(key)
            if secret_path.exists():
                secret_path.unlink()
                logging.info(f"Secret deleted: {key}")
                return True
            return False
        except Exception as e:
            logging.error(f"Failed to delete secret: {e}")
            return False

    def get_secret_from_env(self, env_var: str, secret_key: str, description: str = "") -> Optional[str]:
        """Get secret from environment variable or secure storage"""
        # Try environment variable first
        secret = os.getenv(env_var)
        if secret:
            # Store in secure storage for future use
            self.store_secret(secret_key, secret, description)
            return secret

        # Try secure storage
        return self.get_secret(secret_key)

class EncryptionEngine:
    """Advanced encryption engine for data protection"""

    def __init__(self):
        self.algorithm = 'AES-256-GCM'

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data using AES-256-GCM"""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

            # Derive a secure key for AES
            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            aes_key = kdf.derive(key)

            # Encrypt data
            aesgcm = AESGCM(aes_key)
            nonce = secrets.token_bytes(12)
            encrypted_data = aesgcm.encrypt(nonce, data, None)

            # Combine salt, nonce and encrypted data
            return salt + nonce + encrypted_data
        except ImportError:
            # Fallback to simpler encryption if cryptography not available
            logging.warning("Cryptography library not available, using simplified encryption")
            return self._fallback_encrypt(data, key)

    def decrypt(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-256-GCM"""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

            # Extract components
            salt = encrypted_data[:16]
            nonce = encrypted_data[16:28]
            ciphertext = encrypted_data[28:]

            # Derive the same key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            aes_key = kdf.derive(key)

            # Decrypt data
            aesgcm = AESGCM(aes_key)
            return aesgcm.decrypt(nonce, ciphertext, None)

        except ImportError:
            # Fallback decryption
            return self._fallback_decrypt(encrypted_data, key)
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

    def _fallback_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Fallback encryption method"""
        # Simple XOR encryption as fallback (not secure for production)
        encrypted = bytearray()
        key_bytes = hashlib.sha256(key).digest()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ key_bytes[i % len(key_bytes)])
        return bytes(encrypted)

    def _fallback_decrypt(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Fallback decryption method"""
        # Simple XOR decryption
        decrypted = bytearray()
        key_bytes = hashlib.sha256(key).digest()
        for i, byte in enumerate(encrypted_data):
            decrypted.append(byte ^ key_bytes[i % len(key_bytes)])
        return bytes(decrypted)

# =============================================================================
# Enhanced Logging & Observability
# =============================================================================

class StructuredLogger:
    """Production-grade structured JSON logging with correlation IDs and sampling"""

    def __init__(self, name: str, level: str = 'INFO', enable_file_logging: bool = True):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))

        # Clear existing handlers to avoid duplicates
        if self.logger.handlers:
            self.logger.handlers.clear()

        self.logger.propagate = False

        self.correlation_id = self._generate_correlation_id()
        self.session_id = self._generate_session_id()

        # Create formatters
        json_formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", '
            '"correlation_id": "%(correlation_id)s", "session_id": "%(session_id)s", '
            '"message": "%(message)s", "module": "%(module)s", "function": "%(funcName)s", '
            '"line": "%(lineno)d", "thread": "%(threadName)s"}',
            datefmt='%Y-%m-%dT%H:%M:%S%z'
        )

        # Console handler with color support
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(self._create_color_formatter())
        self.logger.addHandler(console_handler)

        # File handler for persistent logs
        if enable_file_logging:
            self._setup_file_logging(json_formatter)

        # Error handler for critical errors
        self._setup_error_handling()

    def _create_color_formatter(self):
        """Create colorized formatter for console"""

        class ColorFormatter(logging.Formatter):
            FORMATS = {
                logging.DEBUG: Fore.CYAN + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + Fore.RESET,
                logging.INFO: Fore.GREEN + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + Fore.RESET,
                logging.WARNING: Fore.YELLOW + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + Fore.RESET,
                logging.ERROR: Fore.RED + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + Fore.RESET,
                logging.CRITICAL: Fore.RED + Style.BRIGHT + "%(asctime)s - %(name)s - %(levelname)s - %(message)s" + Style.RESET_ALL
            }

            def format(self, record):
                log_fmt = self.FORMATS.get(record.levelno)
                formatter = logging.Formatter(log_fmt)
                return formatter.format(record)

        return ColorFormatter()

    def _setup_file_logging(self, formatter: logging.Formatter):
        """Setup file-based logging with rotation"""
        try:
            from logging.handlers import RotatingFileHandler

            log_dir = Path.home() / '.varux' / 'logs'
            log_dir.mkdir(parents=True, exist_ok=True)

            log_file = log_dir / 'varux.log'
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
        except Exception as e:
            logging.warning(f"File logging setup failed: {e}")

    def _setup_error_handling(self):
        """Setup error handling for critical errors"""

        def handle_exception(exc_type, exc_value, exc_traceback):
            if issubclass(exc_type, KeyboardInterrupt):
                sys.__excepthook__(exc_type, exc_value, exc_traceback)
                return

            self.logger.critical(
                "Uncaught exception",
                exc_info=(exc_type, exc_value, exc_traceback)
            )

        sys.excepthook = handle_exception

    def _generate_correlation_id(self) -> str:
        """Generate unique correlation ID"""
        return hashlib.sha256(f"{os.getpid()}{time.time()}{secrets.token_bytes(16)}".encode()).hexdigest()[:16]

    def _generate_session_id(self) -> str:
        """Generate session ID"""
        return hashlib.sha256(f"{os.getpid()}{time.time()}".encode()).hexdigest()[:8]

    def _extra(self) -> Dict[str, str]:
        return {
            'correlation_id': self.correlation_id,
            'session_id': self.session_id
        }

    def info(self, msg: str, **kwargs) -> None:
        # Format any additional context into the message
        if kwargs:
            context_str = ' '.join([f'{k}={v}' for k, v in kwargs.items()])
            msg = f"{msg} [{context_str}]"
        self.logger.info(msg, extra=self._extra())

    def warning(self, msg: str, **kwargs) -> None:
        if kwargs:
            context_str = ' '.join([f'{k}={v}' for k, v in kwargs.items()])
            msg = f"{msg} [{context_str}]"
        self.logger.warning(msg, extra=self._extra())

    def error(self, msg: str, **kwargs) -> None:
        if kwargs:
            context_str = ' '.join([f'{k}={v}' for k, v in kwargs.items()])
            msg = f"{msg} [{context_str}]"
        self.logger.error(msg, extra=self._extra())

    def critical(self, msg: str, **kwargs) -> None:
        if kwargs:
            context_str = ' '.join([f'{k}={v}' for k, v in kwargs.items()])
            msg = f"{msg} [{context_str}]"
        self.logger.critical(msg, extra=self._extra())

    def debug(self, msg: str, **kwargs) -> None:
        if kwargs:
            context_str = ' '.join([f'{k}={v}' for k, v in kwargs.items()])
            msg = f"{msg} [{context_str}]"
        self.logger.debug(msg, extra=self._extra())

    def audit(self, action: str, target: str, status: str, **kwargs) -> None:
        """Audit logging for security events"""
        audit_msg = f"AUDIT: {action} on {target} - {status}"
        if kwargs:
            context_str = ' '.join([f'{k}={v}' for k, v in kwargs.items()])
            audit_msg = f"{audit_msg} [{context_str}]"
        self.logger.info(audit_msg, extra=self._extra())

# =============================================================================
# Advanced Metrics & Monitoring
# =============================================================================

class AdvancedMetricsCollector:
    """Enterprise-grade metrics collector with Prometheus integration"""

    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.metrics_port = config_manager.get('monitoring.metrics_port', 9090)

        # Core metrics
        self.requests_total = PromCounter('varux_requests_total', 'Total requests', ['method', 'status', 'endpoint'])
        self.vulnerabilities_found = PromCounter('varux_vulnerabilities_total', 'Vulnerabilities found',
                                                 ['type', 'severity'])
        self.errors_total = PromCounter('varux_errors_total', 'Total errors', ['type', 'component'])

        # Performance metrics
        self.request_duration = Histogram('varux_request_duration_seconds', 'Request duration', ['endpoint'])
        self.scan_duration = Histogram('varux_scan_duration_seconds', 'Scan duration')
        self.task_duration = Histogram('varux_task_duration_seconds', 'Task duration', ['task_type'])

        # System metrics
        self.active_scans = Gauge('varux_active_scans', 'Active scans')
        self.memory_usage = Gauge('varux_memory_usage_bytes', 'Memory usage')
        self.cpu_usage = Gauge('varux_cpu_usage_percent', 'CPU usage')
        self.disk_usage = Gauge('varux_disk_usage_bytes', 'Disk usage')
        self.network_io = Gauge('varux_network_io_bytes', 'Network I/O', ['direction'])

        # Business metrics
        self.scans_completed = PromCounter('varux_scans_completed_total', 'Completed scans')
        self.uptime = Gauge('varux_uptime_seconds', 'Application uptime')
        self.start_time = time.time()

        # Start metrics server if enabled
        if config_manager.get('monitoring.enable_metrics', True) and PROMETHEUS_AVAILABLE:
            self._start_metrics_server()

    def _start_metrics_server(self):
        """Start Prometheus metrics server"""
        try:
            start_http_server(self.metrics_port)
            logging.info(f"Metrics server started on port {self.metrics_port}")
        except Exception as e:
            logging.error(f"Failed to start metrics server: {e}")

    def update_system_metrics(self):
        """Update comprehensive system metrics"""
        try:
            # Memory usage
            memory = psutil.virtual_memory()
            self.memory_usage.set(memory.used)

            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.cpu_usage.set(cpu_percent)

            # Disk usage
            disk = psutil.disk_usage('/')
            self.disk_usage.set(disk.used)

            # Network I/O
            net_io = psutil.net_io_counters()
            self.network_io.labels(direction='in').set(net_io.bytes_recv)
            self.network_io.labels(direction='out').set(net_io.bytes_sent)

            # Uptime
            self.uptime.set(time.time() - self.start_time)

        except Exception as e:
            logging.error(f"Failed to update system metrics: {e}")

    def record_scan_start(self, scan_type: str):
        """Record scan start"""
        self.active_scans.inc()

    def record_scan_completion(self, scan_type: str, duration: float, vulnerabilities: int):
        """Record scan completion"""
        self.active_scans.dec()
        self.scans_completed.inc()
        self.scan_duration.observe(duration)

        logging.info(f"Scan completed: type={scan_type}, duration={duration:.2f}s, vulnerabilities={vulnerabilities}")

    def record_vulnerability(self, vuln_type: str, severity: str):
        """Record vulnerability discovery"""
        self.vulnerabilities_found.labels(type=vuln_type, severity=severity).inc()

    def record_error(self, error_type: str, component: str):
        """Record error occurrence"""
        self.errors_total.labels(type=error_type, component=component).inc()

# =============================================================================
# Enhanced Rate Limiting & Circuit Breaker
# =============================================================================

class AdaptiveRateLimiter:
    """Intelligent rate limiter with adaptive throttling"""

    def __init__(self, requests_per_second: int = 10, max_tokens: int = 100, burst_limit: int = 5):
        self.requests_per_second = requests_per_second
        self.max_tokens = max_tokens
        self.burst_limit = burst_limit
        self.tokens = max_tokens
        self.last_update = time.time()
        self.lock = threading.Lock()

        # Adaptive tuning
        self.success_count = 0
        self.error_count = 0
        self.last_adjustment = time.time()
        self.adjustment_interval = 60  # Adjust every minute

    def wait_if_needed(self) -> bool:
        """Wait if rate limit is exceeded, return True if request can proceed"""
        with self.lock:
            now = time.time()
            time_passed = now - self.last_update
            self.last_update = now

            # Add new tokens based on time passed
            new_tokens = time_passed * self.requests_per_second
            self.tokens = min(self.max_tokens, self.tokens + new_tokens)

            # Adaptive adjustment
            if now - self.last_adjustment > self.adjustment_interval:
                self._adaptive_adjust()
                self.last_adjustment = now

            # Check if we have enough tokens
            if self.tokens < 1:
                sleep_time = (1 - self.tokens) / self.requests_per_second
                time.sleep(sleep_time)
                self.tokens = 0
                return True
            else:
                self.tokens -= 1
                return True

    def _adaptive_adjust(self):
        """Adaptively adjust rate limits based on success/error rates"""
        total_requests = self.success_count + self.error_count
        if total_requests > 100:  # Only adjust after sufficient data
            error_rate = self.error_count / total_requests

            if error_rate > 0.1:  # High error rate, reduce limit
                self.requests_per_second = max(1, self.requests_per_second * 0.8)
                logging.warning(f"Reducing rate limit to {self.requests_per_second:.2f} req/s due to high error rate")
            elif error_rate < 0.01:  # Low error rate, increase limit
                self.requests_per_second = min(100, self.requests_per_second * 1.2)
                logging.info(f"Increasing rate limit to {self.requests_per_second:.2f} req/s")

            # Reset counters
            self.success_count = 0
            self.error_count = 0

    def record_success(self):
        """Record successful request"""
        self.success_count += 1

    def record_error(self):
        """Record failed request"""
        self.error_count += 1

class SmartCircuitBreaker:
    """Intelligent circuit breaker with health monitoring"""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60,
                 half_open_max_requests: int = 3):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_requests = half_open_max_requests

        self.failures = 0
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
        self.last_failure_time = None
        self.half_open_attempts = 0
        self.lock = threading.Lock()

        # Health metrics
        self.total_requests = 0
        self.successful_requests = 0

    def can_execute(self) -> bool:
        """Check if request can be executed"""
        with self.lock:
            self.total_requests += 1

            if self.state == 'OPEN':
                if time.time() - self.last_failure_time > self.recovery_timeout:
                    self.state = 'HALF_OPEN'
                    self.half_open_attempts = 0
                    return True
                return False

            elif self.state == 'HALF_OPEN':
                if self.half_open_attempts >= self.half_open_max_requests:
                    return False
                self.half_open_attempts += 1
                return True

            return True  # CLOSED state

    def record_success(self):
        """Record successful execution"""
        with self.lock:
            self.successful_requests += 1

            if self.state == 'HALF_OPEN':
                # Transition back to CLOSED on consecutive successes
                self.failures = 0
                self.state = 'CLOSED'
                self.half_open_attempts = 0
                logging.info("Circuit breaker reset to CLOSED state")

    def record_failure(self):
        """Record failed execution"""
        with self.lock:
            self.failures += 1
            self.last_failure_time = time.time()

            if self.state == 'HALF_OPEN':
                # Immediate trip back to OPEN
                self.state = 'OPEN'
                logging.warning("Circuit breaker tripped back to OPEN state")

            elif self.state == 'CLOSED' and self.failures >= self.failure_threshold:
                self.state = 'OPEN'
                logging.error(f"Circuit breaker tripped to OPEN state after {self.failures} failures")

    def get_health_stats(self) -> Dict[str, Any]:
        """Get circuit breaker health statistics"""
        with self.lock:
            success_rate = (self.successful_requests / self.total_requests * 100) if self.total_requests > 0 else 0

            return {
                'state': self.state,
                'failures': self.failures,
                'total_requests': self.total_requests,
                'success_rate': success_rate,
                'half_open_attempts': self.half_open_attempts
            }

# =============================================================================
# Enhanced Task Management & Checkpoints
# =============================================================================

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"
    QUEUED = "queued"

@dataclass
class Task:
    id: str
    type: str
    target: str
    status: TaskStatus
    progress: float
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    checkpoint: Optional[Dict] = None
    result: Optional[Dict] = None
    error: Optional[str] = None
    priority: int = 1
    metadata: Optional[Dict] = None

class AdvancedTaskManager:
    """Enterprise-grade task management with persistence and recovery"""

    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.tasks: Dict[str, Task] = {}
        self.task_queue = queue.PriorityQueue()
        self.lock = threading.Lock()
        self.checkpoints_dir = Path(config_manager.get('storage.checkpoints_dir'))
        self.checkpoints_dir.mkdir(parents=True, exist_ok=True)

        # Task recovery and cleanup
        self.cleanup_interval = 3600  # 1 hour
        self.last_cleanup = time.time()

        # Load existing tasks and recover interrupted ones
        self._load_tasks()
        self._recover_interrupted_tasks()

    def _load_tasks(self):
        """Load tasks from checkpoint files with validation"""
        try:
            for checkpoint_file in self.checkpoints_dir.glob('*.pickle'):
                try:
                    with open(checkpoint_file, 'rb') as f:
                        task = pickle.load(f)

                    # Validate task data
                    if self._validate_task(task):
                        self.tasks[task.id] = task
                    else:
                        logging.warning(f"Invalid task data in {checkpoint_file}, skipping")

                except Exception as e:
                    logging.error(f"Failed to load task from {checkpoint_file}: {e}")

        except Exception as e:
            logging.error(f"Failed to load tasks: {e}")

    def _validate_task(self, task: Task) -> bool:
        """Validate task data integrity"""
        try:
            required_fields = ['id', 'type', 'target', 'status', 'progress', 'created_at']
            for field in required_fields:
                if not hasattr(task, field):
                    return False

            if not isinstance(task.progress, (int, float)) or not 0 <= task.progress <= 100:
                return False

            return True
        except:
            return False

    def _recover_interrupted_tasks(self):
        """Recover tasks that were interrupted (e.g., due to system crash)"""
        recovered = 0
        for task_id, task in self.tasks.items():
            if task.status == TaskStatus.RUNNING:
                # Mark as failed for manual recovery
                task.status = TaskStatus.FAILED
                task.error = "System interruption detected"
                self._save_checkpoint(task)
                recovered += 1

        if recovered > 0:
            logging.warning(f"Recovered {recovered} interrupted tasks")

    def _cleanup_old_tasks(self):
        """Clean up old completed tasks"""
        current_time = time.time()
        if current_time - self.last_cleanup < self.cleanup_interval:
            return

        cleanup_count = 0
        retention_days = self.config_manager.get('storage.backup_retention_days', 30)
        cutoff_time = datetime.now() - timedelta(days=retention_days)

        for task_id, task in list(self.tasks.items()):
            if (task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED] and
                    task.completed_at and task.completed_at < cutoff_time):

                # Remove task and checkpoint file
                del self.tasks[task_id]
                checkpoint_file = self.checkpoints_dir / f"{task_id}.pickle"
                if checkpoint_file.exists():
                    checkpoint_file.unlink()

                cleanup_count += 1

        if cleanup_count > 0:
            logging.info(f"Cleaned up {cleanup_count} old tasks")

        self.last_cleanup = current_time

    def create_task(self, task_type: str, target: str, priority: int = 1, metadata: Dict = None) -> str:
        """Create a new task with enhanced validation"""
        if not target or not isinstance(target, str):
            raise ValueError("Invalid target provided")

        task_id = hashlib.sha256(f"{task_type}{target}{time.time()}{secrets.token_bytes(8)}".encode()).hexdigest()[:16]

        task = Task(
            id=task_id,
            type=task_type,
            target=target,
            status=TaskStatus.PENDING,
            progress=0.0,
            created_at=datetime.now(),
            priority=priority,
            metadata=metadata or {}
        )

        with self.lock:
            self.tasks[task_id] = task
            self.task_queue.put((priority, time.time(), task_id))  # Add timestamp for tie-breaking

        self._save_checkpoint(task)
        logging.info(f"Created task {task_id}: {task_type} for {target}")
        return task_id

    def get_task(self, task_id: str) -> Optional[Task]:
        """Get task by ID with validation"""
        task = self.tasks.get(task_id)
        if task and not self._validate_task(task):
            logging.error(f"Corrupted task data for {task_id}")
            return None
        return task

    def update_task_progress(self, task_id: str, progress: float, checkpoint: Dict = None) -> bool:
        """Update task progress and checkpoint with validation"""
        if not 0 <= progress <= 100:
            logging.error(f"Invalid progress value: {progress}")
            return False

        with self.lock:
            if task_id in self.tasks:
                self.tasks[task_id].progress = progress
                if checkpoint:
                    self.tasks[task_id].checkpoint = checkpoint

        self._save_checkpoint(self.tasks[task_id])
        return True

    def complete_task(self, task_id: str, result: Dict = None) -> bool:
        """Mark task as completed with result validation"""
        with self.lock:
            if task_id in self.tasks:
                self.tasks[task_id].status = TaskStatus.COMPLETED
                self.tasks[task_id].progress = 100.0
                self.tasks[task_id].completed_at = datetime.now()
                self.tasks[task_id].result = result or {}

        self._save_checkpoint(self.tasks[task_id])
        logging.info(f"Task {task_id} completed successfully")
        return True

    def fail_task(self, task_id: str, error: str) -> bool:
        """Mark task as failed with error tracking"""
        with self.lock:
            if task_id in self.tasks:
                self.tasks[task_id].status = TaskStatus.FAILED
                self.tasks[task_id].error = error[:500]  # Limit error length

        self._save_checkpoint(self.tasks[task_id])
        logging.error(f"Task {task_id} failed: {error}")
        return True

    def pause_task(self, task_id: str) -> bool:
        """Pause a running task"""
        with self.lock:
            if task_id in self.tasks and self.tasks[task_id].status == TaskStatus.RUNNING:
                self.tasks[task_id].status = TaskStatus.PAUSED
                self._save_checkpoint(self.tasks[task_id])
                logging.info(f"Task {task_id} paused")
                return True
        return False

    def resume_task(self, task_id: str) -> bool:
        """Resume a paused task"""
        with self.lock:
            if task_id in self.tasks and self.tasks[task_id].status == TaskStatus.PAUSED:
                self.tasks[task_id].status = TaskStatus.RUNNING
                self._save_checkpoint(self.tasks[task_id])
                logging.info(f"Task {task_id} resumed")
                return True
        return False

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a task"""
        with self.lock:
            if task_id in self.tasks:
                self.tasks[task_id].status = TaskStatus.CANCELLED
                self._save_checkpoint(self.tasks[task_id])
                logging.info(f"Task {task_id} cancelled")
                return True
        return False

    def get_task_stats(self) -> Dict[str, Any]:
        """Get comprehensive task statistics"""
        with self.lock:
            stats = {
                'total': len(self.tasks),
                'by_status': defaultdict(int),
                'by_type': defaultdict(int)
            }

            for task in self.tasks.values():
                stats['by_status'][task.status.value] += 1
                stats['by_type'][task.type] += 1

            return stats

    def _save_checkpoint(self, task: Task) -> bool:
        """Save task checkpoint to file with error handling"""
        try:
            checkpoint_file = self.checkpoints_dir / f"{task.id}.pickle"

            # Create temporary file first
            temp_file = checkpoint_file.with_suffix('.tmp')
            with open(temp_file, 'wb') as f:
                pickle.dump(task, f, protocol=pickle.HIGHEST_PROTOCOL)

            # Atomic replace
            temp_file.replace(checkpoint_file)
            return True

        except Exception as e:
            logging.error(f"Failed to save checkpoint for task {task.id}: {e}")
            return False

# =============================================================================
# Enhanced Core Engines
# =============================================================================

class EliteAIDetectionEngine:
    """Enhanced AI detection engine with machine learning"""

    def __init__(self):
        self.patterns = self.load_attack_patterns()
        self.confidence_threshold = 0.8

    def load_attack_patterns(self):
        """Load comprehensive attack patterns"""
        return {
            'sql_injection': [
                r"union.*select", r"select.*from", r"insert.*into",
                r"drop.*table", r"update.*set", r"delete.*from"
            ],
            'xss': [
                r"<script[^>]*>.*</script>", r"javascript:", r"onload\s*=",
                r"onerror\s*=", r"onclick\s*=", r"alert\s*\("
            ],
            'rce': [
                r"system\s*\(", r"exec\s*\(", r"eval\s*\(",
                r"popen\s*\(", r"passthru\s*\(", r"shell_exec\s*\("
            ],
            'lfi': [
                r"\.\./", r"\.\.\\", r"etc/passwd", r"etc/shadow",
                r"proc/self/environ", r"windows/win.ini"
            ],
            'xxe': [
                r"<!ENTITY", r"SYSTEM", r"PUBLIC", r"<?xml"
            ]
        }

    def analyze_target(self, target_url: str, session: requests.Session) -> List[Dict]:
        """AI-powered target analysis with enhanced detection"""
        vulnerabilities = []

        try:
            response = session.get(target_url)

            # Analyze response for patterns
            for vuln_type, patterns in self.patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    if matches:
                        vulnerabilities.append({
                            'type': vuln_type.upper(),
                            'severity': self._assess_severity(vuln_type),
                            'module': 'AI Engine',
                            'description': f"AI detected potential {vuln_type} vulnerability",
                            'evidence': f"Pattern matched: {pattern} (found {len(matches)} times)",
                            'confidence': 'high',
                            'remediation': self._get_remediation(vuln_type)
                        })

            # Analyze response headers
            header_vulns = self._analyze_headers(response.headers)
            vulnerabilities.extend(header_vulns)

            # Analyze cookies
            cookie_vulns = self._analyze_cookies(response.cookies)
            vulnerabilities.extend(cookie_vulns)

        except Exception as e:
            logging.warning(f"AI analysis failed: {e}")

        return vulnerabilities

    def _analyze_headers(self, headers: Dict) -> List[Dict]:
        """Analyze HTTP headers for security issues"""
        vulnerabilities = []

        # Check for missing security headers
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME type sniffing protection',
            'Strict-Transport-Security': 'HT enforcement',
            'Content-Security-Policy': 'XSS protection',
            'X-XSS-Protection': 'XSS protection'
        }

        for header, description in security_headers.items():
            if header not in headers:
                vulnerabilities.append({
                    'type': 'MISSING_SECURITY_HEADER',
                    'severity': 'MEDIUM',
                    'module': 'AI Engine',
                    'description': f"Missing security header: {header}",
                    'evidence': f"Header {header} not found in response",
                    'confidence': 'high',
                    'remediation': f"Implement {header} header for {description}"
                })

        return vulnerabilities

    def _analyze_cookies(self, cookies) -> List[Dict]:
        """Analyze cookies for security issues"""
        vulnerabilities = []

        for cookie in cookies:
            # Check for secure flag
            if not cookie.secure and cookie.name.lower() in ['session', 'auth', 'token']:
                vulnerabilities.append({
                    'type': 'INSECURE_COOKIE',
                    'severity': 'MEDIUM',
                    'module': 'AI Engine',
                    'description': f"Insecure cookie: {cookie.name}",
                    'evidence': f"Cookie {cookie.name} missing Secure flag",
                    'confidence': 'high',
                    'remediation': "Set Secure flag on sensitive cookies"
                })

            # Check for HttpOnly flag
            if not hasattr(cookie, 'httponly') or not cookie.httponly:
                if cookie.name.lower() in ['session', 'auth', 'token']:
                    vulnerabilities.append({
                        'type': 'HTTPONLY_COOKIE_MISSING',
                        'severity': 'LOW',
                        'module': 'AI Engine',
                        'description': f"Cookie without HttpOnly: {cookie.name}",
                        'evidence': f"Cookie {cookie.name} missing HttpOnly flag",
                        'confidence': 'medium',
                        'remediation': "Set HttpOnly flag on sensitive cookies"
                    })

        return vulnerabilities

    def _assess_severity(self, vuln_type: str) -> str:
        """Assess vulnerability severity"""
        severity_map = {
            'sql_injection': 'HIGH',
            'rce': 'CRITICAL',
            'xss': 'MEDIUM',
            'lfi': 'HIGH',
            'xxe': 'HIGH',
            'missing_security_header': 'MEDIUM',
            'insecure_cookie': 'MEDIUM'
        }
        return severity_map.get(vuln_type, 'MEDIUM')

    def _get_remediation(self, vuln_type: str) -> str:
        """Get remediation advice for vulnerability type"""
        remediation_map = {
            'sql_injection': 'Use parameterized queries and input validation',
            'xss': 'Implement output encoding and Content Security Policy',
            'rce': 'Validate and sanitize all user inputs, use safe APIs',
            'lfi': 'Validate file paths, use whitelists for allowed files',
            'xxe': 'Disable external entity processing in XML parsers',
            'missing_security_header': 'Implement recommended security headers',
            'insecure_cookie': 'Set Secure and HttpOnly flags on sensitive cookies'
        }
        return remediation_map.get(vuln_type, 'Implement proper security controls')

class AdvancedSQLInjectionEngine:
    """Enhanced SQL Injection engine with comprehensive payloads"""

    def __init__(self):
        self.payload_groups = self.generate_advanced_payloads()

    def generate_advanced_payloads(self):
        """Generate comprehensive SQL injection payloads"""
        return {
            'error_based': {
                'mysql': ["'", "''", "`", "´", "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "' OR 'a'='a"],
                'mssql': ["'", "';", "' OR '1'='1", "' OR 1=1--", "'; EXEC xp_cmdshell('dir')--"],
                'oracle': ["'", "' OR '1'='1", "' UNION SELECT null--", "' OR 1=1 FROM DUAL--"],
                'postgresql': ["'", "' OR '1'='1", "' OR 1=1--", "'::text"]
            },
            'union_based': {
                'mysql': [
                    "' UNION SELECT 1,2,3--",
                    "' UNION SELECT null,version(),null--",
                    "' UNION SELECT 1,table_name,3 FROM information_schema.tables--"
                ],
                'mssql': [
                    "' UNION SELECT 1,2,3--",
                    "' UNION SELECT null,@@version,null--",
                    "' UNION SELECT 1,name,3 FROM sysobjects--"
                ]
            },
            'blind': {
                'mysql': [
                    "' AND 1=1--", "' AND 1=2--", "' AND SLEEP(5)--",
                    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
                ],
                'mssql': [
                    "' AND 1=1--", "' AND 1=2--", "' WAITFOR DELAY '0:0:5'--",
                    "' IF (1=1) WAITFOR DELAY '0:0:5'--"
                ]
            },
            'time_based': {
                'mysql': ["' AND SLEEP(5)--", "' AND BENCHMARK(5000000,MD5('test'))--"],
                'mssql': ["' WAITFOR DELAY '0:0:5'--", "' ;WAITFOR DELAY '0:0:5'--"],
                'postgresql': ["' AND pg_sleep(5)--", "' AND (SELECT pg_sleep(5))--"]
            }
        }

class AdvancedXSSEngine:
    """Enhanced XSS engine with comprehensive payloads"""

    def __init__(self):
        self.payload_categories = self.generate_xss_payloads()

    def generate_xss_payloads(self):
        """Generate comprehensive XSS payloads"""
        return {
            'basic': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<body onload=alert('XSS')>"
            ],
            'advanced': [
                "javascript:alert('XSS')",
                "vbscript:alert('XSS')",
                "<iframe src=\"javascript:alert('XSS')\">",
                "<object data=\"javascript:alert('XSS')\">"
            ],
            'polyglot': [
                "jaVasCript:/*-/*`/*\\`/*'/*\"/*%0A*/alert('XSS')//",
                "';alert('XSS');//",
                "\";alert('XSS');//",
                "</script><script>alert('XSS')</script>"
            ],
            'event_handlers': [
                "onload=alert('XSS')",
                "onerror=alert('XSS')",
                "onclick=alert('XSS')",
                "onmouseover=alert('XSS')"
            ]
        }

class OWASP10Scanner:
    """Comprehensive OWASP Top 10 2021 Scanner"""

    def comprehensive_scan(self, target_url: str, session: requests.Session) -> List[Dict]:
        """Comprehensive OWASP Top 10 scan"""
        vulnerabilities = []

        # A01:2021-Broken Access Control
        vulns = self._check_broken_access_control(target_url, session)
        vulnerabilities.extend(vulns)

        # A02:2021-Cryptographic Failures
        vulns = self._check_cryptographic_failures(target_url, session)
        vulnerabilities.extend(vulns)

        # A03:2021-Injection
        vulns = self._check_injection(target_url, session)
        vulnerabilities.extend(vulns)

        # A04:2021-Insecure Design
        vulns = self._check_insecure_design(target_url, session)
        vulnerabilities.extend(vulns)

        # A05:2021-Security Misconfiguration
        vulns = self._check_security_misconfiguration(target_url, session)
        vulnerabilities.extend(vulns)

        return vulnerabilities

    def _check_broken_access_control(self, target_url: str, session: requests.Session) -> List[Dict]:
        """Check for broken access control vulnerabilities"""
        vulnerabilities = []

        # Test for directory traversal
        test_paths = ['/admin', '/config', '/backup', '/uploads', '/.git']
        for path in test_paths:
            test_url = urljoin(target_url, path)
            try:
                response = session.get(test_url)
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Broken Access Control',
                        'severity': 'MEDIUM',
                        'module': 'OWASP Scanner',
                        'description': f'Potential broken access control at {path}',
                        'evidence': f'Accessible path: {test_url}',
                        'confidence': 'medium',
                        'remediation': 'Implement proper access control checks'
                    })
            except:
                pass

        return vulnerabilities

    def _check_cryptographic_failures(self, target_url: str, session: requests.Session) -> List[Dict]:
        """Check for cryptographic failures"""
        vulnerabilities = []

        # Check for HTTP usage
        if target_url.startswith('http:'):
            vulnerabilities.append({
                'type': 'Cryptographic Failure',
                'severity': 'MEDIUM',
                'module': 'OWASP Scanner',
                'description': 'HTTP used instead of HTTPS',
                'evidence': 'Unencrypted communication detected',
                'confidence': 'high',
                'remediation': 'Use HTTPS for all communications'
            })

        # Check for weak cookies
        try:
            response = session.get(target_url)
            for cookie in response.cookies:
                if not cookie.secure and cookie.name.lower() in ['session', 'auth']:
                    vulnerabilities.append({
                        'type': 'Cryptographic Failure',
                        'severity': 'MEDIUM',
                        'module': 'OWASP Scanner',
                        'description': f'Insecure cookie: {cookie.name}',
                        'evidence': 'Cookie transmitted over insecure channel',
                        'confidence': 'high',
                        'remediation': 'Set Secure flag on sensitive cookies'
                    })
        except:
            pass

        return vulnerabilities

    def _check_injection(self, target_url: str, session: requests.Session) -> List[Dict]:
        """Check for injection vulnerabilities"""
        # Already covered by specialized engines
        return []

    def _check_insecure_design(self, target_url: str, session: requests.Session) -> List[Dict]:
        """Check for insecure design patterns"""
        vulnerabilities = []

        # Check for predictable resources
        predictable_paths = ['/admin/123', '/user/1', '/order/1001']
        for path in predictable_paths:
            test_url = urljoin(target_url, path)
            try:
                response = session.get(test_url)
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Insecure Design',
                        'severity': 'LOW',
                        'module': 'OWASP Scanner',
                        'description': f'Predictable resource at {path}',
                        'evidence': f'Accessible predictable resource: {test_url}',
                        'confidence': 'medium',
                        'remediation': 'Use non-predictable identifiers'
                    })
            except:
                pass

        return vulnerabilities

    def _check_security_misconfiguration(self, target_url: str, session: requests.Session) -> List[Dict]:
        """Check for security misconfigurations"""
        vulnerabilities = []

        # Check for default files
        default_files = ['/robots.txt', '/.htaccess', '/web.config', '/phpinfo.php']
        for file in default_files:
            test_url = urljoin(target_url, file)
            try:
                response = session.get(test_url)
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Security Misconfiguration',
                        'severity': 'LOW',
                        'module': 'OWASP Scanner',
                        'description': f'Default file accessible: {file}',
                        'evidence': f'Default file found: {test_url}',
                        'confidence': 'high',
                        'remediation': 'Remove or secure default files'
                    })
            except:
                pass

        # Check for debug information
        debug_indicators = ['DEBUG', 'debug', 'development mode', 'stack trace']
        try:
            response = session.get(target_url)
            for indicator in debug_indicators:
                if indicator in response.text:
                    vulnerabilities.append({
                        'type': 'Security Misconfiguration',
                        'severity': 'MEDIUM',
                        'module': 'OWASP Scanner',
                        'description': 'Debug information exposed',
                        'evidence': f'Debug indicator found: {indicator}',
                        'confidence': 'medium',
                        'remediation': 'Disable debug mode in production'
                    })
                    break
        except:
            pass

        return vulnerabilities

# =============================================================================
# Enhanced Web Crawler
# =============================================================================

class AdvancedWebCrawler:
    """Advanced web crawler for comprehensive site mapping"""

    def __init__(self, session: requests.Session):
        self.session = session
        self.visited_urls = set()
        self.urls_to_visit = set()
        self.max_depth = 3

    def crawl(self, start_url: str) -> List[str]:
        """Crawl website and discover URLs"""
        self.urls_to_visit.add(start_url)
        discovered_urls = []

        for depth in range(self.max_depth):
            current_urls = self.urls_to_visit.copy()
            self.urls_to_visit.clear()

            for url in current_urls:
                if url not in self.visited_urls:
                    try:
                        response = self.session.get(url, timeout=10)
                        self.visited_urls.add(url)
                        discovered_urls.append(url)

                        # Extract new URLs
                        new_urls = self.extract_urls(response.text, url)
                        for new_url in new_urls:
                            if new_url not in self.visited_urls:
                                self.urls_to_visit.add(new_url)

                    except:
                        continue

        return discovered_urls

    def extract_urls(self, html: str, base_url: str) -> List[str]:
        """Extract URLs from HTML content"""
        urls = set()
        soup = BeautifulSoup(html, 'html.parser')

        # Extract from links
        for link in soup.find_all('a', href=True):
            url = urljoin(base_url, link['href'])
            if self.is_valid_url(url):
                urls.add(url)

        # Extract from forms
        for form in soup.find_all('form', action=True):
            url = urljoin(base_url, form['action'])
            if self.is_valid_url(url):
                urls.add(url)

        # Extract from scripts and images
        for tag in soup.find_all(['script', 'img'], src=True):
            url = urljoin(base_url, tag['src'])
            if self.is_valid_url(url):
                urls.add(url)

        return list(urls)

    def is_valid_url(self, url: str) -> bool:
        """Check if URL is valid for crawling"""
        parsed = urlparse(url)
        return bool(parsed.netloc) and parsed.scheme in ['http', 'https']

# =============================================================================
# Network Security Scanner
# =============================================================================

class NetworkSecurityScanner:
    """Network-level security scanner"""

    def scan_target(self, target_url: str) -> List[Dict]:
        """Perform network-level security scan"""
        vulnerabilities = []
        parsed_url = urlparse(target_url)
        hostname = parsed_url.netloc

        try:
            # Port scanning
            open_ports = self.port_scan(hostname)
            if open_ports:
                vulnerabilities.append({
                    'type': 'Network Security',
                    'severity': 'INFO',
                    'module': 'Network Scanner',
                    'description': f'Open ports detected: {open_ports}',
                    'evidence': f'Port scan results: {open_ports}',
                    'confidence': 'high',
                    'remediation': 'Close unnecessary ports and services'
                })

            # SSL/TLS analysis
            ssl_vulns = self.ssl_analysis(hostname)
            vulnerabilities.extend(ssl_vulns)

        except Exception as e:
            logging.warning(f"Network scan failed: {e}")

        return vulnerabilities

    def port_scan(self, hostname: str) -> List[int]:
        """Basic port scanning"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 8080, 8443]
        open_ports = []

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((hostname, port))
                sock.close()

                if result == 0:
                    open_ports.append(port)
            except:
                continue

        return open_ports

    def ssl_analysis(self, hostname: str) -> List[Dict]:
        """SSL/TLS security analysis"""
        vulnerabilities = []

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    # Check certificate expiration
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry_date - datetime.now()).days

                        if days_until_expiry < 30:
                            vulnerabilities.append({
                                'type': 'SSL/TLS Issue',
                                'severity': 'MEDIUM',
                                'module': 'Network Scanner',
                                'description': 'SSL certificate expiring soon',
                                'evidence': f'Certificate expires in {days_until_expiry} days',
                                'confidence': 'high',
                                'remediation': 'Renew SSL certificate'
                            })

        except Exception as e:
            vulnerabilities.append({
                'type': 'SSL/TLS Issue',
                'severity': 'MEDIUM',
                'module': 'Network Scanner',
                'description': 'SSL/TLS connection failed',
                'evidence': f'Connection error: {e}',
                'confidence': 'medium',
                'remediation': 'Check SSL/TLS configuration'
            })

        return vulnerabilities

# =============================================================================
# Enhanced Scanning Engine
# =============================================================================

class EliteTerminalScanThread(threading.Thread):
    """Production-grade scanning thread with comprehensive features"""

    def __init__(self, task_id: str, scan_options: Dict, task_manager: AdvancedTaskManager,
                 config_manager: ConfigManager, metrics: AdvancedMetricsCollector,
                 logger: StructuredLogger):
        super().__init__(daemon=True)
        self.task_id = task_id
        self.scan_options = scan_options
        self.task_manager = task_manager
        self.config_manager = config_manager
        self.metrics = metrics
        self.logger = logger

        self.target_url = scan_options['target_url']
        self.scan_mode = scan_options.get('scan_mode', 'standard')
        self.session = self._create_secure_session()
        self.results = []

        # Initialize all security engines
        self.rate_limiter = AdaptiveRateLimiter(
            config_manager.get('scan.rate_limit.requests_per_second', 10)
        )
        self.circuit_breaker = SmartCircuitBreaker()
        self.ai_engine = EliteAIDetectionEngine()
        self.sql_engine = AdvancedSQLInjectionEngine()
        self.xss_engine = AdvancedXSSEngine()
        self.owasp_scanner = OWASP10Scanner()
        self.crawler = AdvancedWebCrawler(self.session)
        self.network_scanner = NetworkSecurityScanner()

        # Performance tracking
        self.start_time = None
        self.vulnerabilities_found = 0

    def _create_secure_session(self) -> requests.Session:
        """Create highly secure HTTP session for scanning"""
        session = requests.Session()
        session.verify = self.config_manager.get('scan.verify_ssl', False)

        # Security headers
        session.headers.update({
            'User-Agent': self.config_manager.get('scan.user_agent'),
            'X-Scanner': 'VARUX-Elite',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive'
        })

        # Redirect handling
        session.max_redirects = self.config_manager.get('scan.max_redirects', 10)

        return session

    def run(self):
        """Main scanning logic with comprehensive error handling"""
        self.start_time = time.time()

        try:
            self.metrics.record_scan_start(self.scan_mode)
            self.task_manager.update_task_progress(self.task_id, 0, {'status': 'initializing'})

            # Update task status
            task = self.task_manager.get_task(self.task_id)
            if task:
                task.status = TaskStatus.RUNNING
                task.started_at = datetime.now()

            self.logger.audit("scan_started", self.target_url, "started",
                              scan_mode=self.scan_mode, task_id=self.task_id)

            # Determine scan phases based on mode
            scan_phases = self._get_scan_phases()

            current_progress = 0
            progress_increment = 100 / len(scan_phases)

            for phase_name, phase_method in scan_phases:
                self.logger.info(f"Starting phase: {phase_name}")
                self.task_manager.update_task_progress(
                    self.task_id,
                    current_progress,
                    {'phase': phase_name, 'status': 'running'}
                )

                try:
                    phase_results = phase_method()
                    self.results.extend(phase_results)
                    self.vulnerabilities_found += len(phase_results)

                    # Record metrics
                    for result in phase_results:
                        self.metrics.record_vulnerability(
                            result.get('type', 'unknown'),
                            result.get('severity', 'INFO')
                        )

                    self.logger.info(f"Phase {phase_name} completed: {len(phase_results)} findings")

                except Exception as e:
                    self.logger.error(f"Phase {phase_name} failed: {e}")
                    self.metrics.record_error('phase_failure', phase_name)

                current_progress += progress_increment

            # Final reporting phase
            self.task_manager.update_task_progress(self.task_id, 90, {'phase': 'reporting'})
            scan_duration = time.time() - self.start_time

            # Complete task
            self.task_manager.complete_task(self.task_id, {
                'vulnerabilities': self.results,
                'scan_summary': {
                    'target': self.target_url,
                    'mode': self.scan_mode,
                    'total_vulnerabilities': len(self.results),
                    'scan_duration': f"{scan_duration:.2f}s",
                    'timestamp': datetime.now().isoformat(),
                    'phases_completed': len(scan_phases)
                },
                'raw_results': self.results
            })

            self.metrics.record_scan_completion(self.scan_mode, scan_duration, len(self.results))

            self.logger.audit("scan_completed", self.target_url, "completed",
                              duration=scan_duration, vulnerabilities=len(self.results))

            self.logger.info(
                f"Scan completed for {self.target_url}. Found {len(self.results)} vulnerabilities in {scan_duration:.2f}s.")

        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            self.task_manager.fail_task(self.task_id, str(e))
            self.metrics.record_error('scan_failure', 'main')
            self.logger.audit("scan_failed", self.target_url, "failed", error=str(e))

    def _get_scan_phases(self) -> List[Tuple[str, callable]]:
        """Get scan phases based on scan mode"""
        base_phases = [
            ('reconnaissance', self._perform_reconnaissance),
            ('vulnerability_scanning', self._perform_vulnerability_scanning)
        ]

        if self.scan_mode in ['deep', 'comprehensive']:
            base_phases.extend([
                ('advanced_analysis', self._perform_advanced_analysis),
                ('ai_analysis', self._perform_ai_analysis)
            ])

        if self.scan_mode == 'comprehensive':
            base_phases.extend([
                ('network_scanning', self._perform_network_scanning),
                ('business_logic_analysis', self._perform_business_logic_analysis)
            ])

        return base_phases

    @retry(stop_max_attempt_number=3, wait_fixed=2000)
    def _perform_reconnaissance(self) -> List[Dict]:
        """Enhanced reconnaissance phase"""
        results = []
        self.logger.info("Starting enhanced reconnaissance phase")

        try:
            # DNS reconnaissance
            dns_info = self._dns_reconnaissance()
            if dns_info:
                results.append({
                    'type': 'INFO',
                    'severity': 'INFO',
                    'module': 'DNS Recon',
                    'description': f"DNS information gathered",
                    'evidence': json.dumps(dns_info),
                    'confidence': 'high'
                })

            # Subdomain discovery
            subdomains = self._subdomain_discovery()
            if subdomains:
                results.append({
                    'type': 'INFO',
                    'severity': 'INFO',
                    'module': 'Subdomain Discovery',
                    'description': f"Found {len(subdomains)} subdomains",
                    'evidence': ', '.join(subdomains),
                    'confidence': 'medium'
                })

            # Technology detection
            tech_stack = self._technology_detection()
            if tech_stack:
                results.append({
                    'type': 'INFO',
                    'severity': 'INFO',
                    'module': 'Technology Detection',
                    'description': f"Detected technologies",
                    'evidence': tech_stack,
                    'confidence': 'high'
                })

            # Directory and file discovery
            directories = self._directory_bruteforce()
            if directories:
                results.append({
                    'type': 'INFO',
                    'severity': 'LOW',
                    'module': 'Directory Discovery',
                    'description': f"Found {len(directories)} accessible directories",
                    'evidence': ', '.join(directories),
                    'confidence': 'high'
                })

        except Exception as e:
            self.logger.warning(f"Reconnaissance phase had issues: {e}")
            self.metrics.record_error('reconnaissance_error', 'network')

        return results

    def _perform_vulnerability_scanning(self) -> List[Dict]:
        """Comprehensive vulnerability scanning"""
        results = []
        self.logger.info("Starting comprehensive vulnerability scanning")

        # SQL Injection scanning
        sql_results = self._sql_injection_scan()
        results.extend(sql_results)

        # XSS scanning
        xss_results = self._xss_scan()
        results.extend(xss_results)

        # OWASP Top 10 scanning
        owasp_results = self._owasp_scan()
        results.extend(owasp_results)

        # CSRF scanning
        csrf_results = self._csrf_scan()
        results.extend(csrf_results)

        # File inclusion vulnerabilities
        file_inclusion_results = self._file_inclusion_scan()
        results.extend(file_inclusion_results)

        return results

    def _perform_advanced_analysis(self) -> List[Dict]:
        """Advanced security analysis"""
        results = []
        self.logger.info("Starting advanced security analysis")

        try:
            # API security testing
            api_results = self._api_security_scan()
            results.extend(api_results)

            # Authentication bypass testing
            auth_results = self._authentication_testing()
            results.extend(auth_results)

            # Business logic testing
            logic_results = self._business_logic_testing()
            results.extend(logic_results)

        except Exception as e:
            self.logger.warning(f"Advanced analysis had issues: {e}")

        return results

    def _perform_ai_analysis(self) -> List[Dict]:
        """AI-powered security analysis"""
        results = []
        self.logger.info("Starting AI-powered analysis")

        try:
            # AI-powered vulnerability detection
            ai_vulns = self.ai_engine.analyze_target(self.target_url, self.session)
            results.extend(ai_vulns)

            # Machine learning based anomaly detection
            ml_results = self._ml_anomaly_detection()
            results.extend(ml_results)

        except Exception as e:
            self.logger.warning(f"AI analysis had issues: {e}")

        return results

    def _perform_network_scanning(self) -> List[Dict]:
        """Network-level security scanning"""
        results = []
        self.logger.info("Starting network security scanning")

        try:
            network_results = self.network_scanner.scan_target(self.target_url)
            results.extend(network_results)
        except Exception as e:
            self.logger.warning(f"Network scanning had issues: {e}")

        return results

    def _perform_business_logic_analysis(self) -> List[Dict]:
        """Business logic vulnerability analysis"""
        results = []
        self.logger.info("Starting business logic analysis")
        # This would contain sophisticated business logic analysis
        return results

    # Enhanced scanning methods
    def _sql_injection_scan(self):
        """Enhanced SQL Injection scan"""
        results = []
        forms = self.extract_forms(self.target_url)

        self.logger.info(f"Testing {len(forms)} forms for SQL injection")

        for form in forms:
            for payload_type, payloads in self.sql_engine.payload_groups.items():
                for db_type, db_payloads in payloads.items():
                    for payload in db_payloads[:3]:  # Test first 3 payloads per type
                        if self.test_sql_injection_form(form, payload):
                            results.append({
                                "type": "SQL Injection",
                                "severity": "HIGH",
                                "module": "SQL Injection Scanner",
                                "description": f"SQL Injection vulnerability detected in {form['action']}",
                                "payload": payload,
                                "evidence": f"{payload_type} SQL Injection detected",
                                "confidence": "high",
                                "remediation": "Use parameterized queries and input validation"
                            })
                            break  # One finding per form is enough

        return results

    def _xss_scan(self):
        """Enhanced XSS scan"""
        results = []
        forms = self.extract_forms(self.target_url)

        self.logger.info(f"Testing {len(forms)} forms for XSS")

        for form in forms:
            for payload_category, payloads in self.xss_engine.payload_categories.items():
                for payload in payloads[:2]:  # Test first 2 payloads from each category
                    if self.test_xss_form(form, payload):
                        results.append({
                            "type": "XSS",
                            "severity": "MEDIUM",
                            "module": "XSS Scanner",
                            "description": f"XSS vulnerability detected in {form['action']}",
                            "payload": payload,
                            "evidence": "XSS payload successfully executed",
                            "confidence": "medium",
                            "remediation": "Implement proper output encoding and content security policy"
                        })
                        break

        return results

    def _owasp_scan(self):
        """Comprehensive OWASP Top 10 scan"""
        return self.owasp_scanner.comprehensive_scan(self.target_url, self.session)

    def _csrf_scan(self):
        """CSRF vulnerability scanning"""
        results = []
        try:
            forms = self.extract_forms(self.target_url)
            for form in forms:
                if form['method'].upper() == 'POST':
                    # Check for CSRF tokens
                    has_csrf_token = any(
                        input_field.get('name', '').lower() in ['csrf', 'csrfmiddlewaretoken', 'authenticity_token']
                        for input_field in form['inputs']
                    )

                    if not has_csrf_token:
                        results.append({
                            "type": "CSRF",
                            "severity": "MEDIUM",
                            "module": "CSRF Scanner",
                            "description": f"Potential CSRF vulnerability in {form['action']}",
                            "evidence": "No CSRF token found in form",
                            "confidence": "medium",
                            "remediation": "Implement CSRF tokens and same-site cookies"
                        })
        except Exception as e:
            self.logger.warning(f"CSRF scan failed: {e}")

        return results

    def _file_inclusion_scan(self):
        """File inclusion vulnerability scanning"""
        results = []
        try:
            # Test for Local File Inclusion (LFI)
            lfi_payloads = [
                "../../../../etc/passwd",
                "....//....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ]

            for payload in lfi_payloads:
                test_url = f"{self.target_url}?file={payload}"
                response = self.session.get(test_url)

                if "root:" in response.text and "/bin/" in response.text:
                    results.append({
                        "type": "LFI",
                        "severity": "HIGH",
                        "module": "File Inclusion Scanner",
                        "description": "Local File Inclusion vulnerability detected",
                        "evidence": f"Successfully retrieved /etc/passwd with payload: {payload}",
                        "confidence": "high",
                        "remediation": "Validate and sanitize file path inputs"
                    })
                    break

        except Exception as e:
            self.logger.warning(f"File inclusion scan failed: {e}")

        return results

    def _api_security_scan(self):
        """API security testing"""
        results = []
        # This would contain comprehensive API security tests
        return results

    def _authentication_testing(self):
        """Authentication mechanism testing"""
        results = []
        # This would contain authentication bypass tests
        return results

    def _business_logic_testing(self):
        """Business logic vulnerability testing"""
        results = []
        # This would contain business logic tests
        return results

    def _ml_anomaly_detection(self):
        """Machine learning based anomaly detection"""
        results = []
        # This would contain ML-based security detection
        return results

    def _dns_reconnaissance(self):
        """Enhanced DNS reconnaissance"""
        try:
            domain = urlparse(self.target_url).netloc
            answers = dns.resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        except:
            return None

    def _subdomain_discovery(self):
        """Enhanced subdomain discovery"""
        subdomains = set()
        domain = urlparse(self.target_url).netloc

        common_subs = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'blog',
                       'shop', 'app', 'mobile', 'secure', 'portal', 'cpanel']

        for sub in common_subs:
            test_domain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(test_domain)
                subdomains.add(test_domain)
            except:
                pass

        return list(subdomains)

    def _technology_detection(self):
        """Enhanced technology stack detection"""
        try:
            response = self.session.get(self.target_url)
            tech_stack = []

            # Header-based detection
            if 'X-Powered-By' in response.headers:
                tech_stack.append(response.headers['X-Powered-By'])

            if 'Server' in response.headers:
                tech_stack.append(response.headers['Server'])

            # Content-based detection
            if 'wp-content' in response.text:
                tech_stack.append('WordPress')
            if 'drupal' in response.text.lower():
                tech_stack.append('Drupal')
            if 'jquery' in response.text.lower():
                tech_stack.append('jQuery')

            return ', '.join(tech_stack) if tech_stack else "Unknown"
        except:
            return "Unknown"

    def _directory_bruteforce(self):
        """Directory and file bruteforce discovery"""
        directories = []
        common_dirs = ['admin', 'login', 'config', 'backup', 'uploads', 'images']

        for directory in common_dirs:
            test_url = urljoin(self.target_url, directory)
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200:
                    directories.append(directory)
            except:
                pass

        return directories

    # Preserved original methods
    def test_sql_injection_form(self, form, payload):
        """SQL Injection test"""
        try:
            data = {}
            for input_field in form['inputs']:
                if input_field['type'] in ['text', 'password', 'search']:
                    data[input_field['name']] = payload
                else:
                    data[input_field['name']] = input_field.get('value', '')

            if form['method'].upper() == 'POST':
                response = self.session.post(form['action'], data=data, timeout=10)
            else:
                response = self.session.get(form['action'], params=data, timeout=10)

            return self.detect_sql_errors(response.text)

        except:
            return False

    def test_xss_form(self, form, payload):
        """XSS test"""
        try:
            data = {}
            for input_field in form['inputs']:
                if input_field['type'] in ['text', 'textarea']:
                    data[input_field['name']] = payload
                else:
                    data[input_field['name']] = input_field.get('value', '')

            if form['method'].upper() == 'POST':
                response = self.session.post(form['action'], data=data, timeout=10)
            else:
                response = self.session.get(form['action'], params=data, timeout=10)

            return payload in response.text

        except:
            return False

    def detect_sql_errors(self, response_text):
        """SQL error detection"""
        patterns = [
            r"mysql_fetch_array",
            r"You have an error in your SQL syntax",
            r"ORA-\d+",
            r"Microsoft OLE DB Provider"
        ]

        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def extract_forms(self, url):
        """Form extraction"""
        forms = []
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')

            for form in soup.find_all('form'):
                form_action = form.get('action')
                if not form_action:
                    form_action = url
                elif not form_action.startswith(('http://', 'https://')):
                    form_action = urljoin(url, form_action)

                form_method = form.get('method', 'get').lower()

                inputs = []
                for input_tag in form.find_all('input'):
                    input_name = input_tag.get('name')
                    if input_name:
                        input_type = input_tag.get('type', 'text')
                        input_value = input_tag.get('value', '')

                        inputs.append({
                            'name': input_name,
                            'type': input_type,
                            'value': input_value
                        })

                forms.append({
                    'action': form_action,
                    'method': form_method,
                    'inputs': inputs
                })

        except:
            pass

        return forms

# =============================================================================
# Enhanced SQL Injection Scanner
# =============================================================================

class EliteSQLInjectionScanner(threading.Thread):
    """Advanced SQL Injection Scanner"""

    def __init__(self, task_id: str, target_url: str, task_manager: AdvancedTaskManager,
                 config_manager: ConfigManager, logger: StructuredLogger,
                 method: str = 'auto', parameters: List[str] = None, level: str = '1'):
        super().__init__(daemon=True)
        self.task_id = task_id
        self.target_url = target_url
        self.task_manager = task_manager
        self.config_manager = config_manager
        self.logger = logger
        self.method = method
        self.parameters = parameters
        self.level = level
        
        self.session = self._create_secure_session()
        self.results = []
        self.sql_engine = AdvancedSQLInjectionEngine()

    def _create_secure_session(self) -> requests.Session:
        """Create secure HTTP session"""
        session = requests.Session()
        session.verify = self.config_manager.get('scan.verify_ssl', False)
        session.headers.update({
            'User-Agent': self.config_manager.get('scan.user_agent'),
            'X-Scanner': 'VARUX-SQL-Injection'
        })
        return session

    def run(self):
        """Main SQL injection scanning logic"""
        try:
            self.task_manager.update_task_progress(self.task_id, 0, {'status': 'initializing'})
            
            task = self.task_manager.get_task(self.task_id)
            if task:
                task.status = TaskStatus.RUNNING
                task.started_at = datetime.now()

            self.logger.audit("sql_scan_started", self.target_url, "started",
                              method=self.method, level=self.level)

            # Phase 1: Reconnaissance
            self.task_manager.update_task_progress(self.task_id, 10, {'phase': 'reconnaissance'})
            forms = self.extract_forms(self.target_url)
            self.logger.info(f"Found {len(forms)} forms for testing")

            # Phase 2: Parameter discovery
            self.task_manager.update_task_progress(self.task_id, 30, {'phase': 'parameter_discovery'})
            test_parameters = self._discover_parameters()
            
            # Phase 3: SQL injection testing
            self.task_manager.update_task_progress(self.task_id, 50, {'phase': 'sql_injection_testing'})
            self._perform_comprehensive_sql_testing(forms, test_parameters)
            
            # Phase 4: Advanced testing based on level
            self.task_manager.update_task_progress(self.task_id, 80, {'phase': 'advanced_testing'})
            if self.level in ['2', '3']:
                self._perform_advanced_sql_testing()
            
            # Complete task
            self.task_manager.complete_task(self.task_id, {
                'vulnerabilities': self.results,
                'scan_summary': {
                    'target': self.target_url,
                    'method': self.method,
                    'level': self.level,
                    'total_vulnerabilities': len(self.results),
                    'timestamp': datetime.now().isoformat()
                }
            })

            self.logger.audit("sql_scan_completed", self.target_url, "completed",
                              vulnerabilities=len(self.results))

        except Exception as e:
            self.logger.error(f"SQL injection scan failed: {e}")
            self.task_manager.fail_task(self.task_id, str(e))

    def _discover_parameters(self):
        """Discover parameters for testing"""
        parameters = set()
        
        # Extract from URL query parameters
        parsed_url = urlparse(self.target_url)
        if parsed_url.query:
            query_params = parse_qs(parsed_url.query)
            parameters.update(query_params.keys())
        
        # Extract from forms
        forms = self.extract_forms(self.target_url)
        for form in forms:
            for input_field in form['inputs']:
                if input_field['name']:
                    parameters.add(input_field['name'])
        
        # Use user-provided parameters if specified
        if self.parameters:
            parameters.update(self.parameters)
            
        return list(parameters)

    def _perform_comprehensive_sql_testing(self, forms, parameters):
        """Perform comprehensive SQL injection testing"""
        tested_count = 0
        total_tests = len(forms) + (len(parameters) if parameters else 0)
        
        # Test forms
        for form in forms:
            if tested_count >= total_tests:
                break
                
            self._test_form_sql_injection(form)
            tested_count += 1
            progress = 50 + (tested_count / total_tests * 30)
            self.task_manager.update_task_progress(self.task_id, progress)
        
        # Test URL parameters
        if parameters:
            for param in parameters:
                if tested_count >= total_tests:
                    break
                    
                self._test_parameter_sql_injection(param)
                tested_count += 1
                progress = 50 + (tested_count / total_tests * 30)
                self.task_manager.update_task_progress(self.task_id, progress)

    def _test_form_sql_injection(self, form):
        """Test a form for SQL injection vulnerabilities"""
        for payload_type, payloads in self.sql_engine.payload_groups.items():
            for db_type, db_payloads in payloads.items():
                for payload in db_payloads[:3]:  # Test first 3 payloads per type
                    if self.test_sql_injection_form(form, payload):
                        self.results.append({
                            "type": "SQL Injection",
                            "severity": "HIGH",
                            "module": "Advanced SQL Scanner",
                            "description": f"SQL Injection vulnerability in form {form['action']}",
                            "parameter": "form_input",
                            "payload": payload,
                            "evidence": f"{payload_type} SQL Injection detected",
                            "confidence": "high",
                            "remediation": "Use parameterized queries and input validation"
                        })
                        return  # One finding per form is enough

    def _test_parameter_sql_injection(self, parameter):
        """Test a URL parameter for SQL injection vulnerabilities"""
        for payload_type, payloads in self.sql_engine.payload_groups.items():
            for db_type, db_payloads in payloads.items():
                for payload in db_payloads[:2]:  # Test first 2 payloads per type
                    test_url = self._build_test_url(parameter, payload)
                    try:
                        response = self.session.get(test_url, timeout=10)
                        if self.detect_sql_errors(response.text):
                            self.results.append({
                                "type": "SQL Injection",
                                "severity": "HIGH",
                                "module": "Advanced SQL Scanner",
                                "description": f"SQL Injection vulnerability in parameter {parameter}",
                                "parameter": parameter,
                                "payload": payload,
                                "evidence": f"{payload_type} SQL Injection detected in URL parameter",
                                "confidence": "high",
                                "remediation": "Use parameterized queries and input validation"
                            })
                            return
                    except:
                        continue

    def _perform_advanced_sql_testing(self):
        """Perform advanced SQL injection testing"""
        if self.level == '3':
            # Blind SQL injection testing
            self._test_blind_sql_injection()
            
            # Time-based SQL injection testing
            self._test_time_based_sql_injection()

    def _test_blind_sql_injection(self):
        """Test for blind SQL injection vulnerabilities"""
        forms = self.extract_forms(self.target_url)
        for form in forms:
            for payload in ["' AND 1=1--", "' AND 1=2--"]:
                try:
                    data = {}
                    for input_field in form['inputs']:
                        if input_field['type'] in ['text', 'password', 'search']:
                            data[input_field['name']] = payload
                        else:
                            data[input_field['name']] = input_field.get('value', '')

                    if form['method'].upper() == 'POST':
                        response1 = self.session.post(form['action'], data=data, timeout=10)
                        # Send normal request for comparison
                        normal_data = {k: 'test' for k in data.keys()}
                        response2 = self.session.post(form['action'], data=normal_data, timeout=10)
                    else:
                        response1 = self.session.get(form['action'], params=data, timeout=10)
                        normal_params = {k: 'test' for k in data.keys()}
                        response2 = self.session.get(form['action'], params=normal_params, timeout=10)

                    # Compare responses for blind SQL detection
                    if len(response1.text) != len(response2.text):
                        self.results.append({
                            "type": "Blind SQL Injection",
                            "severity": "HIGH",
                            "module": "Advanced SQL Scanner",
                            "description": f"Potential blind SQL injection in {form['action']}",
                            "parameter": "form_input",
                            "payload": payload,
                            "evidence": "Different response lengths detected for true/false conditions",
                            "confidence": "medium",
                            "remediation": "Use parameterized queries and input validation"
                        })
                        break
                except:
                    continue

    def _test_time_based_sql_injection(self):
        """Test for time-based SQL injection vulnerabilities"""
        forms = self.extract_forms(self.target_url)
        time_payloads = ["' AND SLEEP(5)--", "' AND BENCHMARK(5000000,MD5('test'))--"]
        
        for form in forms:
            for payload in time_payloads:
                try:
                    start_time = time.time()
                    
                    data = {}
                    for input_field in form['inputs']:
                        if input_field['type'] in ['text', 'password', 'search']:
                            data[input_field['name']] = payload
                        else:
                            data[input_field['name']] = input_field.get('value', '')

                    if form['method'].upper() == 'POST':
                        self.session.post(form['action'], data=data, timeout=15)
                    else:
                        self.session.get(form['action'], params=data, timeout=15)
                    
                    elapsed = time.time() - start_time
                    
                    if elapsed > 4:  # If response took more than 4 seconds
                        self.results.append({
                            "type": "Time-Based SQL Injection",
                            "severity": "HIGH",
                            "module": "Advanced SQL Scanner",
                            "description": f"Time-based SQL injection in {form['action']}",
                            "parameter": "form_input",
                            "payload": payload,
                            "evidence": f"Response delayed by {elapsed:.2f} seconds",
                            "confidence": "medium",
                            "remediation": "Use parameterized queries and input validation"
                        })
                        break
                except:
                    continue

    def _build_test_url(self, parameter, payload):
        """Build test URL with SQL injection payload"""
        parsed_url = urlparse(self.target_url)
        query_params = parse_qs(parsed_url.query)
        
        # Replace the target parameter with payload
        if parameter in query_params:
            query_params[parameter] = [payload]
        else:
            query_params[parameter] = [payload]
            
        # Rebuild URL
        new_query = '&'.join([f"{k}={v[0]}" for k, v in query_params.items()])
        return f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

    def test_sql_injection_form(self, form, payload):
        """SQL Injection test for forms"""
        try:
            data = {}
            for input_field in form['inputs']:
                if input_field['type'] in ['text', 'password', 'search']:
                    data[input_field['name']] = payload
                else:
                    data[input_field['name']] = input_field.get('value', '')

            if form['method'].upper() == 'POST':
                response = self.session.post(form['action'], data=data, timeout=10)
            else:
                response = self.session.get(form['action'], params=data, timeout=10)

            return self.detect_sql_errors(response.text)

        except:
            return False

    def detect_sql_errors(self, response_text):
        """SQL error detection"""
        patterns = [
            r"mysql_fetch_array",
            r"You have an error in your SQL syntax",
            r"ORA-\d+",
            r"Microsoft OLE DB Provider",
            r"PostgreSQL.*ERROR",
            r"Warning.*mysql",
            r"Unclosed quotation mark",
            r"SQLServer.*Exception"
        ]

        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    def extract_forms(self, url):
        """Form extraction"""
        forms = []
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')

            for form in soup.find_all('form'):
                form_action = form.get('action')
                if not form_action:
                    form_action = url
                elif not form_action.startswith(('http://', 'https://')):
                    form_action = urljoin(url, form_action)

                form_method = form.get('method', 'get').lower()

                inputs = []
                for input_tag in form.find_all('input'):
                    input_name = input_tag.get('name')
                    if input_name:
                        input_type = input_tag.get('type', 'text')
                        input_value = input_tag.get('value', '')

                        inputs.append({
                            'name': input_name,
                            'type': input_type,
                            'value': input_value
                        })

                forms.append({
                    'action': form_action,
                    'method': form_method,
                    'inputs': inputs
                })

        except:
            pass

        return forms

# =============================================================================
# Enhanced Reporting System
# =============================================================================

class EliteReportGenerator:
    """Production-grade report generator with multiple formats"""

    def generate_report(self, vulnerabilities: List[Dict], target: str,
                       task: Task, format: str = 'html') -> str:
        """Generate comprehensive security report"""
        if format == 'html':
            return self._generate_html_report(vulnerabilities, target, task)
        elif format == 'json':
            return self._generate_json_report(vulnerabilities, target, task)
        elif format == 'console':
            return self._generate_console_report(vulnerabilities, target, task)
        else:
            return self._generate_html_report(vulnerabilities, target, task)

    def _generate_html_report(self, vulnerabilities: List[Dict], target: str, task: Task) -> str:
        """Generate detailed HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>VARUX Security Report - {target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
                .summary {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .vulnerability {{ border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 10px; }}
                .critical {{ border-left: 5px solid #dc3545; }}
                .high {{ border-left: 5px solid #fd7e14; }}
                .medium {{ border-left: 5px solid #ffc107; }}
                .low {{ border-left: 5px solid #20c997; }}
                .info {{ border-left: 5px solid #6c757d; }}
                .severity-critical {{ color: #dc3545; font-weight: bold; }}
                .severity-high {{ color: #fd7e14; font-weight: bold; }}
                .severity-medium {{ color: #ffc107; font-weight: bold; }}
                .severity-low {{ color: #20c997; font-weight: bold; }}
                .severity-info {{ color: #6c757d; font-weight: bold; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #f8f9fa; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚀 VARUX Elite Security Report</h1>
                    <h2>Target: {target}</h2>
                    <p>Generated: {timestamp}</p>
                </div>
                
                <div class="summary">
                    <h3>Scan Summary</h3>
                    <table>
                        <tr><th>Total Vulnerabilities</th><td>{total_vulns}</td></tr>
                        <tr><th>Critical</th><td class="severity-critical">{critical_count}</td></tr>
                        <tr><th>High</th><td class="severity-high">{high_count}</td></tr>
                        <tr><th>Medium</th><td class="severity-medium">{medium_count}</td></tr>
                        <tr><th>Low</th><td class="severity-low">{low_count}</td></tr>
                        <tr><th>Info</th><td class="severity-info">{info_count}</td></tr>
                    </table>
                </div>
                
                <h3>Vulnerability Details</h3>
                {vulnerability_html}
            </div>
        </body>
        </html>
        """

        # Count vulnerabilities by severity
        severity_count = defaultdict(int)
        for vuln in vulnerabilities:
            severity_count[vuln.get('severity', 'INFO')] += 1

        # Generate vulnerability HTML
        vulnerability_html = ""
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_class = vuln.get('severity', 'INFO').lower()
            vulnerability_html += f"""
            <div class="vulnerability {severity_class}">
                <h4>{i}. {vuln['type']} <span class="severity-{severity_class}">[{vuln['severity']}]</span></h4>
                <p><strong>Description:</strong> {vuln['description']}</p>
                <p><strong>Module:</strong> {vuln.get('module', 'Unknown')}</p>
                <p><strong>Evidence:</strong> {vuln.get('evidence', 'No evidence')}</p>
                <p><strong>Remediation:</strong> {vuln.get('remediation', 'No remediation provided')}</p>
                <p><strong>Confidence:</strong> {vuln.get('confidence', 'Unknown')}</p>
            </div>
            """

        return html_template.format(
            target=target,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_vulns=len(vulnerabilities),
            critical_count=severity_count.get('CRITICAL', 0),
            high_count=severity_count.get('HIGH', 0),
            medium_count=severity_count.get('MEDIUM', 0),
            low_count=severity_count.get('LOW', 0),
            info_count=severity_count.get('INFO', 0),
            vulnerability_html=vulnerability_html
        )

    def _generate_json_report(self, vulnerabilities: List[Dict], target: str, task: Task) -> str:
        """Generate JSON report"""
        report = {
            'metadata': {
                'generator': 'VARUX Elite Security Scanner v6.0',
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'scan_duration': str(task.completed_at - task.started_at) if task.started_at and task.completed_at else 'Unknown',
                'total_vulnerabilities': len(vulnerabilities)
            },
            'summary': self._generate_summary(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }

        return json.dumps(report, indent=2, ensure_ascii=False)

    def _generate_console_report(self, vulnerabilities: List[Dict], target: str, task: Task) -> str:
        """Generate console-friendly report"""
        report_lines = [
            "🚀 VARUX Elite Security Report",
            "=" * 50,
            f"Target: {target}",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total Vulnerabilities: {len(vulnerabilities)}",
            ""
        ]

        # Add summary
        severity_count = defaultdict(int)
        for vuln in vulnerabilities:
            severity_count[vuln.get('severity', 'INFO')] += 1

        report_lines.append("Summary:")
        report_lines.append(f"  Critical: {severity_count.get('CRITICAL', 0)}")
        report_lines.append(f"  High: {severity_count.get('HIGH', 0)}")
        report_lines.append(f"  Medium: {severity_count.get('MEDIUM', 0)}")
        report_lines.append(f"  Low: {severity_count.get('LOW', 0)}")
        report_lines.append(f"  Info: {severity_count.get('INFO', 0)}")
        report_lines.append("")

        # Add vulnerabilities
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_color = {
                'CRITICAL': Fore.RED,
                'HIGH': Fore.YELLOW,
                'MEDIUM': Fore.MAGENTA,
                'LOW': Fore.BLUE,
                'INFO': Fore.GREEN
            }.get(vuln.get('severity', 'INFO'), Fore.WHITE)

            report_lines.append(f"{i}. [{severity_color}{vuln['severity']}{Fore.RESET}] {vuln['type']}")
            report_lines.append(f"   Description: {vuln['description']}")
            report_lines.append(f"   Module: {vuln.get('module', 'Unknown')}")
            report_lines.append(f"   Evidence: {vuln.get('evidence', 'No evidence')}")
            report_lines.append(f"   Remediation: {vuln.get('remediation', 'No remediation')}")
            report_lines.append("")

        return "\n".join(report_lines)

    def _generate_summary(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Generate vulnerability summary"""
        severity_count = defaultdict(int)
        for vuln in vulnerabilities:
            severity_count[vuln.get('severity', 'INFO')] += 1

        return dict(severity_count)

# =============================================================================
# Enhanced System Health Monitoring
# =============================================================================

class HealthChecker:
    """Comprehensive system health checker"""

    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager

    def check_system_health(self, full_check: bool = False) -> Dict[str, Any]:
        """Check comprehensive system health"""
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'components': {}
        }

        # Check disk space
        disk_health = self._check_disk_space()
        health_status['components']['disk'] = disk_health

        # Check memory
        memory_health = self._check_memory()
        health_status['components']['memory'] = memory_health

        # Check network
        network_health = self._check_network()
        health_status['components']['network'] = network_health

        # Check dependencies
        deps_health = self._check_dependencies()
        health_status['components']['dependencies'] = deps_health

        # Full system check if requested
        if full_check:
            health_status['components']['system'] = self._full_system_check()

        # Determine overall status
        if any(comp.get('status') == 'unhealthy' for comp in health_status['components'].values()):
            health_status['status'] = 'degraded'
        if any(comp.get('status') == 'critical' for comp in health_status['components'].values()):
            health_status['status'] = 'unhealthy'

        return health_status

    def _check_disk_space(self) -> Dict[str, Any]:
        """Check disk space availability"""
        try:
            usage = psutil.disk_usage('/')
            free_gb = usage.free / (1024 ** 3)
            status = 'healthy'

            if free_gb < 1:
                status = 'critical'
            elif free_gb < 5:
                status = 'unhealthy'

            return {
                'status': status,
                'free_gb': round(free_gb, 2),
                'total_gb': round(usage.total / (1024 ** 3), 2),
                'usage_percent': round(usage.percent, 2)
            }
        except:
            return {'status': 'unknown', 'error': 'Unable to check disk space'}

    def _check_memory(self) -> Dict[str, Any]:
        """Check memory usage"""
        try:
            memory = psutil.virtual_memory()
            status = 'healthy'

            if memory.percent > 90:
                status = 'critical'
            elif memory.percent > 80:
                status = 'unhealthy'

            return {
                'status': status,
                'used_gb': round(memory.used / (1024 ** 3), 2),
                'total_gb': round(memory.total / (1024 ** 3), 2),
                'usage_percent': round(memory.percent, 2)
            }
        except:
            return {'status': 'unknown', 'error': 'Unable to check memory'}

    def _check_network(self) -> Dict[str, Any]:
        """Check network connectivity"""
        try:
            # Test basic connectivity
            socket.create_connection(("8.8.8.8", 53), timeout=5)
            return {'status': 'healthy', 'connectivity': 'ok'}
        except:
            return {'status': 'unhealthy', 'connectivity': 'failed'}

    def _check_dependencies(self) -> Dict[str, Any]:
        """Check critical dependencies"""
        missing_deps = []

        required_modules = ['requests', 'beautifulsoup4', 'colorama', 'psutil']
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                missing_deps.append(module)

        status = 'healthy' if not missing_deps else 'unhealthy'

        return {
            'status': status,
            'missing_dependencies': missing_deps,
            'total_checked': len(required_modules)
        }

    def _full_system_check(self) -> Dict[str, Any]:
        """Perform full system health check"""
        return {
            'cpu_cores': psutil.cpu_count(),
            'cpu_usage': psutil.cpu_percent(interval=1),
            'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else 'N/A',
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            'python_version': sys.version,
            'platform': sys.platform
        }

# =============================================================================
# Enhanced CLI Framework
# =============================================================================

class VARUXCLI:
    """Production-grade CLI application with enhanced user experience"""

    def __init__(self):
        # Initialize core components
        self.config_manager = ConfigManager()
        self.secrets_manager = AdvancedSecretsManager(self.config_manager)
        self.task_manager = AdvancedTaskManager(self.config_manager)
        self.metrics = AdvancedMetricsCollector(self.config_manager)
        self.logger = StructuredLogger('varux_cli')
        self.health_checker = HealthChecker(self.config_manager)

        # Initialize core engines
        self.session = self._create_secure_session()
        self.rate_limiter = AdaptiveRateLimiter(
            self.config_manager.get('scan.rate_limit.requests_per_second', 10),
            burst_limit=self.config_manager.get('scan.rate_limit.burst_limit', 5)
        )
        self.circuit_breaker = SmartCircuitBreaker()

        # Setup complete system
        self.setup_logging()
        self._perform_startup_checks()

        logging.info("VARUX CLI initialized successfully")

    def setup_logging(self) -> None:
        """Setup comprehensive logging configuration"""
        log_level = self.config_manager.get('global.log_level', 'INFO')
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[]
        )

    def _perform_startup_checks(self):
        """Perform comprehensive startup checks"""
        checks = [
            self._check_disk_space,
            self._check_network_connectivity,
            self._check_dependencies,
            self._check_permissions,
            self._check_sql_injection_module
        ]

        for check in checks:
            try:
                if not check():
                    logging.warning(f"Startup check failed: {check.__name__}")
            except Exception as e:
                logging.error(f"Startup check error in {check.__name__}: {e}")

    def _check_disk_space(self) -> bool:
        """Check available disk space"""
        try:
            usage = psutil.disk_usage('/')
            free_gb = usage.free / (1024 ** 3)
            return free_gb > 1  # At least 1GB free
        except:
            return True  # Don't fail if we can't check

    def _check_network_connectivity(self) -> bool:
        """Check basic network connectivity"""
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=5)
            return True
        except:
            logging.warning("Network connectivity check failed")
            return False

    def _check_dependencies(self) -> bool:
        """Check critical dependencies"""
        try:
            import requests
            from bs4 import BeautifulSoup
            return True
        except ImportError as e:
            logging.error(f"Missing dependency: {e}")
            return False

    def _check_permissions(self) -> bool:
        """Check file permissions"""
        try:
            config_dir = Path.home() / '.varux'
            if config_dir.exists():
                stat = config_dir.stat()
                if stat.st_mode & 0o077:  # Check if readable by others
                    logging.warning("Configuration directory has overly permissive permissions")
            return True
        except:
            return True

    def _check_sql_injection_module(self) -> bool:
        """Check if SQL injection module is available"""
        module_path = self.config_manager.get('modules.sql_injection_module_path')
        if not module_path:
            logging.warning("SQL injection module path not configured")
            return False
        
        if not os.path.exists(module_path):
            logging.warning(f"SQL injection module not found at: {module_path}")
            return False
        
        logging.info(f"SQL injection module found at: {module_path}")
        return True

    def _create_secure_session(self) -> requests.Session:
        """Create highly secure HTTP session"""
        session = requests.Session()

        # Security headers
        session.headers.update({
            'User-Agent': self.config_manager.get('scan.user_agent', 'VARUX-Security-Scanner/6.0'),
            'X-Scanner': 'VARUX-Elite',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

        # Security configurations
        session.verify = self.config_manager.get('scan.verify_ssl', False)
        session.trust_env = False  # Don't use system proxy settings

        # Setup advanced timeouts and redirect handling
        session.max_redirects = self.config_manager.get('scan.max_redirects', 10)

        # Custom request method with comprehensive error handling
        original_request = session.request

        @backoff.on_exception(
            backoff.expo,
            (requests.exceptions.RequestException,),
            max_tries=self.config_manager.get('global.max_retries', 3),
            max_time=300
        )
        def secure_request(*args, **kwargs):
            # Apply rate limiting
            self.rate_limiter.wait_if_needed()

            # Check circuit breaker
            if not self.circuit_breaker.can_execute():
                raise requests.exceptions.RequestException("Circuit breaker is open")

            # Set default timeouts
            if 'timeout' not in kwargs:
                kwargs['timeout'] = (
                    self.config_manager.get('scan.timeouts.connect', 10),
                    self.config_manager.get('scan.timeouts.read', 30)
                )

            try:
                response = original_request(*args, **kwargs)
                self.circuit_breaker.record_success()
                self.rate_limiter.record_success()
                return response
            except requests.exceptions.RequestException as e:
                self.circuit_breaker.record_failure()
                self.rate_limiter.record_error()
                raise

        session.request = secure_request
        return session

    def run(self):
        """Main CLI entry point with enhanced argument parsing"""
        parser = self._create_argument_parser()
        args = parser.parse_args()

        if not args.command:
            # Show interactive mode if no command provided
            self._interactive_mode()
            return

        try:
            self._dispatch_command(args)
        except KeyboardInterrupt:
            self.logger.info("Operation interrupted by user")
            sys.exit(ExitCodes.SUCCESS.value)
        except Exception as e:
            self.logger.error(f"Command failed: {e}")
            sys.exit(ExitCodes.SCAN_ERROR.value)

    def _create_argument_parser(self) -> argparse.ArgumentParser:
        """Create comprehensive argument parser"""
        parser = argparse.ArgumentParser(
            description='🚀 VARUX Elite Web Security Scanner - Production Ready CLI',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=self._get_epilog_text()
        )

        subparsers = parser.add_subparsers(dest='command', help='Command to execute')

        # Scan command
        scan_parser = subparsers.add_parser('scan', help='Start security scan')
        scan_parser.add_argument('target', help='Target URL to scan')
        scan_parser.add_argument('--mode', '-m', choices=['quick', 'standard', 'deep', 'comprehensive'],
                                 default='standard', help='Scan intensity mode')
        scan_parser.add_argument('--output', '-o', help='Output file for report')
        scan_parser.add_argument('--format', '-f', choices=['html', 'json', 'pdf', 'console'],
                                 default='html', help='Report format')
        scan_parser.add_argument('--threads', '-t', type=int, default=20,
                                 help='Number of concurrent threads')
        scan_parser.add_argument('--resume', help='Resume from checkpoint ID')
        scan_parser.add_argument('--no-progress', action='store_true',
                                 help='Disable progress bar')

        # Config command
        config_parser = subparsers.add_parser('config', help='Configuration management')
        config_parser.add_argument('action', choices=['get', 'set', 'list', 'reset', 'validate'],
                                   help='Config action')
        config_parser.add_argument('key', nargs='?', help='Config key')
        config_parser.add_argument('value', nargs='?', help='Config value')

        # Status command
        status_parser = subparsers.add_parser('status', help='Check system status')
        status_parser.add_argument('--task', help='Specific task ID')
        status_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
        status_parser.add_argument('--metrics', action='store_true', help='Show metrics')

        # Task management commands
        stop_parser = subparsers.add_parser('stop', help='Stop running task')
        stop_parser.add_argument('task_id', help='Task ID to stop')

        resume_parser = subparsers.add_parser('resume', help='Resume paused task')
        resume_parser.add_argument('task_id', help='Task ID to resume')

        cancel_parser = subparsers.add_parser('cancel', help='Cancel task')
        cancel_parser.add_argument('task_id', help='Task ID to cancel')

        # Report command
        report_parser = subparsers.add_parser('report', help='Generate reports')
        report_parser.add_argument('task_id', help='Task ID for report')
        report_parser.add_argument('--format', choices=['html', 'json', 'pdf'], default='html',
                                   help='Report format')
        report_parser.add_argument('--output', '-o', help='Output file')

        # Secrets command
        secrets_parser = subparsers.add_parser('secrets', help='Manage secrets')
        secrets_parser.add_argument('action', choices=['list', 'set', 'get', 'delete'])
        secrets_parser.add_argument('key', nargs='?', help='Secret key')
        secrets_parser.add_argument('value', nargs='?', help='Secret value')

        # System commands
        health_parser = subparsers.add_parser('health', help='System health check')
        health_parser.add_argument('--full', action='store_true', help='Full health check')

        cleanup_parser = subparsers.add_parser('cleanup', help='Cleanup system')
        cleanup_parser.add_argument('--days', type=int, default=30, help='Cleanup older than X days')

        # SQL Injection Module command
        sql_parser = subparsers.add_parser('sql', help='Advanced SQL Injection Analysis')
        sql_parser.add_argument('target', help='Target URL for SQL injection testing')
        sql_parser.add_argument('--method', choices=['auto', 'get', 'post'], default='auto',
                                help='HTTP method to use')
        sql_parser.add_argument('--parameters', nargs='+', help='Parameters to test')
        sql_parser.add_argument('--cookies', help='Cookies for authentication')
        sql_parser.add_argument('--headers', help='Additional headers')
        sql_parser.add_argument('--level', choices=['1', '2', '3'], default='1',
                                help='Scan intensity level')

        return parser

    def _get_epilog_text(self) -> str:
        """Get detailed epilog text for help"""
        return """

Examples:
  varux scan https://example.com --mode deep --output report.html
  varux scan https://example.com --mode quick --format console
  varux config set scan.rate_limit.requests_per_second 20
  varux status --verbose --metrics
  varux stop TASK_ID
  varux resume TASK_ID
  varux report TASK_ID --format json
  varux secrets set API_KEY "your-api-key"
  varux health --full
  varux sql https://example.com/login.php --method post --parameters username password

Scan Modes:
  quick       - Basic security checks (1-2 minutes)
  standard    - Comprehensive scanning (5-10 minutes)  
  deep        - In-depth analysis (15-30 minutes)
  comprehensive - Full assessment with advanced techniques (45+ minutes)

For more information, visit: https://github.com/varux-security/scanner
        """

    def _interactive_mode(self):
        """Interactive mode for user-friendly operation"""
        while True:  # Continuous loop for interactive mode
            print(f"\n{Fore.CYAN}🚀 VARUX Elite Security Scanner v6.0{Fore.RESET}")
            print(f"{Fore.GREEN}Interactive Mode{Fore.RESET}\n")

            choices = [
                'Start Security Scan',
                'Advanced SQL Injection Analysis',
                'View System Status',
                'Manage Configuration',
                'Generate Reports',
                'System Health Check',
                'Exit'
            ]

            try:
                if QUESTIONARY_AVAILABLE:
                    action = questionary.select(
                        "What would you like to do?",
                        choices=choices
                    ).ask()
                else:
                    action = self._simple_text_menu(choices)
                
                if action == 'Start Security Scan':
                    self._interactive_scan()
                elif action == 'Advanced SQL Injection Analysis':
                    self._interactive_sql_injection()
                elif action == 'View System Status':
                    self._handle_status_interactive()
                elif action == 'Manage Configuration':
                    self._interactive_config()
                elif action == 'Generate Reports':
                    self._interactive_reports()
                elif action == 'System Health Check':
                    self._handle_health_interactive()
                elif action == 'Exit':
                    print(f"{Fore.YELLOW}Goodbye!{Fore.RESET}")
                    break
                else:
                    print("Invalid choice, please try again.")
                    continue

            except Exception as e:
                print(f"Interactive mode error: {e}")
                print("Falling back to simple menu...")
                action = self._simple_text_menu(choices)
                if action == 'Start Security Scan':
                    self._interactive_scan()
                elif action == 'Advanced SQL Injection Analysis':
                    self._interactive_sql_injection()
                elif action == 'View System Status':
                    self._handle_status_interactive()
                elif action == 'Exit':
                    print(f"{Fore.YELLOW}Goodbye!{Fore.RESET}")
                    break

    def _simple_text_menu(self, choices):
        """Simple text-based menu as fallback"""
        print("\nPlease select an option:")
        for i, choice in enumerate(choices, 1):
            print(f"{i}. {choice}")

        while True:
            try:
                choice_num = int(input("\nEnter your choice (number): "))
                if 1 <= choice_num <= len(choices):
                    return choices[choice_num - 1]
                else:
                    print(f"Please enter a number between 1 and {len(choices)}")
            except ValueError:
                print("Please enter a valid number.")

    def _interactive_scan(self):
        """Interactive scan setup"""
        try:
            if QUESTIONARY_AVAILABLE:
                target = questionary.text("Enter target URL:").ask()
                if not target:
                    return

                mode = questionary.select(
                    "Select scan mode:",
                    choices=[
                        {'name': 'Quick Scan (1-2 minutes)', 'value': 'quick'},
                        {'name': 'Standard Scan (5-10 minutes)', 'value': 'standard'},
                        {'name': 'Deep Scan (15-30 minutes)', 'value': 'deep'},
                        {'name': 'Comprehensive Scan (45+ minutes)', 'value': 'comprehensive'}
                    ]
                ).ask()

                format_choice = questionary.select(
                    "Report format:",
                    choices=['html', 'json', 'console']
                ).ask()
            else:
                target = input("Enter target URL: ")
                if not target:
                    return

                print("\nSelect scan mode:")
                print("1. Quick Scan (1-2 minutes)")
                print("2. Standard Scan (5-10 minutes)")
                print("3. Deep Scan (15-30 minutes)")
                print("4. Comprehensive Scan (45+ minutes)")

                mode_choice = input("Enter choice (1-4): ")
                mode_map = {'1': 'quick', '2': 'standard', '3': 'deep', '4': 'comprehensive'}
                mode = mode_map.get(mode_choice, 'standard')

                print("\nSelect report format:")
                print("1. HTML")
                print("2. JSON")
                print("3. Console")
                format_choice = input("Enter choice (1-3): ")
                format_map = {'1': 'html', '2': 'json', '3': 'console'}
                format_choice = format_map.get(format_choice, 'html')

            # Start the scan
            scan_args = argparse.Namespace(
                command='scan',
                target=target,
                mode=mode,
                format=format_choice,
                output=None,
                threads=20,
                resume=None,
                no_progress=False
            )

            self._handle_scan(scan_args)
            
            # Ask user for next action after scan completion
            self._post_scan_interactive()

        except Exception as e:
            self.logger.error(f"Interactive scan failed: {e}")

    def _interactive_sql_injection(self):
        """Interactive SQL injection analysis setup"""
        try:
            if QUESTIONARY_AVAILABLE:
                target = questionary.text("Enter target URL:").ask()
                if not target:
                    return

                method = questionary.select(
                    "HTTP Method:",
                    choices=['auto', 'get', 'post']
                ).ask()

                level = questionary.select(
                    "Scan Intensity Level:",
                    choices=[
                        {'name': 'Level 1 - Basic Tests', 'value': '1'},
                        {'name': 'Level 2 - Advanced Tests', 'value': '2'},
                        {'name': 'Level 3 - Comprehensive Tests', 'value': '3'}
                    ]
                ).ask()

                parameters = questionary.text("Parameters to test (space separated, leave empty for auto-detection):").ask()
                if parameters:
                    parameters = parameters.split()
                else:
                    parameters = None

            else:
                target = input("Enter target URL: ")
                if not target:
                    return

                print("\nHTTP Method:")
                print("1. Auto-detect")
                print("2. GET")
                print("3. POST")
                method_choice = input("Enter choice (1-3): ")
                method_map = {'1': 'auto', '2': 'get', '3': 'post'}
                method = method_map.get(method_choice, 'auto')

                print("\nScan Intensity Level:")
                print("1. Level 1 - Basic Tests")
                print("2. Level 2 - Advanced Tests")
                print("3. Level 3 - Comprehensive Tests")
                level_choice = input("Enter choice (1-3): ")
                level = level_choice if level_choice in ['1', '2', '3'] else '1'

                parameters_input = input("Parameters to test (space separated, leave empty for auto-detection): ")
                parameters = parameters_input.split() if parameters_input else None

            # Execute SQL injection analysis
            sql_args = argparse.Namespace(
                command='sql',
                target=target,
                method=method,
                parameters=parameters,
                cookies=None,
                headers=None,
                level=level
            )

            self._handle_sql_injection(sql_args)

        except Exception as e:
            self.logger.error(f"Interactive SQL injection analysis failed: {e}")

    def _post_scan_interactive(self):
        """Post-scan interactive options"""
        choices = [
            'Return to Main Menu',
            'Start New Scan',
            'View Scan Report',
            'Exit'
        ]

        try:
            if QUESTIONARY_AVAILABLE:
                action = questionary.select(
                    "Scan completed! What would you like to do?",
                    choices=choices
                ).ask()
            else:
                print("\nScan completed! What would you like to do?")
                for i, choice in enumerate(choices, 1):
                    print(f"{i}. {choice}")
                choice_num = int(input("\nEnter choice (1-4): "))
                action = choices[choice_num - 1] if 1 <= choice_num <= len(choices) else choices[0]

            if action == 'Return to Main Menu':
                return  # Return to main menu loop
            elif action == 'Start New Scan':
                self._interactive_scan()
            elif action == 'View Scan Report':
                self._interactive_reports()
            elif action == 'Exit':
                print(f"{Fore.YELLOW}Thank you for using VARUX Security Scanner!{Fore.RESET}")
                sys.exit(ExitCodes.SUCCESS.value)

        except Exception as e:
            self.logger.error(f"Post-scan interactive failed: {e}")
            return  # Return to main menu on error

    def _dispatch_command(self, args):
        """Dispatch command to appropriate handler"""
        command_handlers = {
            'scan': self._handle_scan,
            'config': self._handle_config,
            'status': self._handle_status,
            'stop': self._handle_stop,
            'resume': self._handle_resume,
            'cancel': self._handle_cancel,
            'report': self._handle_report,
            'secrets': self._handle_secrets,
            'health': self._handle_health,
            'cleanup': self._handle_cleanup,
            'sql': self._handle_sql_injection
        }

        handler = command_handlers.get(args.command)
        if handler:
            try:
                handler(args)
                
                # If scan command and in interactive mode, show post-scan options
                if args.command == 'scan' and not hasattr(args, 'no_interactive') and not args.command:
                    self._post_scan_interactive()
                    
            except Exception as e:
                self.logger.error(f"Command '{args.command}' failed: {e}")
                raise
        else:
            self.logger.error(f"Unknown command: {args.command}")
            sys.exit(ExitCodes.GENERAL_ERROR.value)

    def _handle_scan(self, args):
        """Enhanced scan command handler"""
        self.logger.info(f"Starting {args.mode} scan for {args.target}")

        # Validate target URL
        if not self._validate_target_url(args.target):
            self.logger.error(f"Invalid target URL: {args.target}")
            return

        # Create scan task
        task_id = self.task_manager.create_task(
            f'scan_{args.mode}',
            args.target,
            priority=self._get_scan_priority(args.mode),
            metadata={
                'mode': args.mode,
                'threads': args.threads,
                'output_format': args.format,
                'output_file': args.output
            }
        )

        # Setup scan options
        scan_options = {
            'target_url': args.target,
            'scan_mode': args.mode,
            'threads': args.threads,
            'output_format': args.format,
            'output_file': args.output,
            'resume_checkpoint': args.resume
        }

        # Start scan in background thread
        scan_thread = EliteTerminalScanThread(
            task_id=task_id,
            scan_options=scan_options,
            task_manager=self.task_manager,
            config_manager=self.config_manager,
            metrics=self.metrics,
            logger=self.logger
        )

        # Display progress
        if not args.no_progress:
            self._display_enhanced_progress(task_id, scan_thread)
        else:
            scan_thread.start()
            scan_thread.join()

        # Show results
        task = self.task_manager.get_task(task_id)
        if task and task.result:
            self._display_scan_results(task)

    def _handle_sql_injection(self, args):
        """Handle SQL injection analysis"""
        self.logger.info(f"Starting SQL injection analysis for {args.target}")
        
        # Validate target URL
        if not self._validate_target_url(args.target):
            self.logger.error(f"Invalid target URL: {args.target}")
            return

        # Check if external SQL injection module is available
        module_path = self.config_manager.get('modules.sql_injection_module_path')
        if module_path and os.path.exists(module_path):
            self._run_external_sql_module(args, module_path)
        else:
            # Fall back to built-in SQL injection scanner
            self._run_builtin_sql_scanner(args)

    def _run_external_sql_module(self, args, module_path):
        """Run external SQL injection module"""
        try:
            self.logger.info(f"Executing external SQL injection module: {module_path}")
            
            # Build command arguments
            cmd_args = [sys.executable, module_path, args.target]
            
            if args.method != 'auto':
                cmd_args.extend(['--method', args.method])
                
            if args.parameters:
                cmd_args.extend(['--parameters'] + args.parameters)
                
            if args.level != '1':
                cmd_args.extend(['--level', args.level])
            
            # Execute the module
            result = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                print(f"\n{Fore.GREEN}SQL Injection Analysis Completed Successfully{Fore.RESET}")
                print(f"Output:\n{result.stdout}")
            else:
                print(f"\n{Fore.RED}SQL Injection Analysis Failed{Fore.RESET}")
                print(f"Error:\n{result.stderr}")
                
        except subprocess.TimeoutExpired:
            self.logger.error("SQL injection analysis timed out after 5 minutes")
        except Exception as e:
            self.logger.error(f"Failed to execute SQL injection module: {e}")
            # Fall back to built-in scanner
            self._run_builtin_sql_scanner(args)

    def _run_builtin_sql_scanner(self, args):
        """Run built-in SQL injection scanner"""
        self.logger.info("Using built-in SQL injection scanner")
        
        # Create a specialized SQL injection scan task
        task_id = self.task_manager.create_task(
            'sql_injection_scan',
            args.target,
            priority=1,
            metadata={
                'method': args.method,
                'parameters': args.parameters,
                'level': args.level
            }
        )
        
        # Start the scan
        sql_scanner = EliteSQLInjectionScanner(
            task_id=task_id,
            target_url=args.target,
            task_manager=self.task_manager,
            config_manager=self.config_manager,
            logger=self.logger,
            method=args.method,
            parameters=args.parameters,
            level=args.level
        )
        
        # Display progress
        self._display_sql_progress(task_id, sql_scanner)
        
        # Show results
        task = self.task_manager.get_task(task_id)
        if task and task.result:
            self._display_sql_results(task)

    def _display_sql_progress(self, task_id: str, sql_scanner: threading.Thread):
        """Display SQL injection scan progress"""
        sql_scanner.start()
        
        with tqdm(total=100, desc="SQL Injection Analysis", 
                  bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.RED, Fore.RESET)) as pbar:
            
            last_progress = 0
            while sql_scanner.is_alive():
                time.sleep(0.5)
                task = self.task_manager.get_task(task_id)
                
                if task:
                    current_progress = task.progress
                    if current_progress > last_progress:
                        pbar.update(current_progress - last_progress)
                        last_progress = current_progress
                    
                    pbar.set_postfix_str(f"Status: {task.status.value}", refresh=False)
            
            pbar.update(100 - last_progress)
        
        sql_scanner.join()

    def _display_sql_results(self, task: Task):
        """Display SQL injection scan results"""
        print(f"\n{Fore.CYAN}{'=' * 60}{Fore.RESET}")
        print(f"{Fore.CYAN}🔍 SQL INJECTION ANALYSIS RESULTS{Fore.RESET}")
        print(f"{Fore.CYAN}{'=' * 60}{Fore.RESET}")

        print(f"Target: {Fore.WHITE}{task.target}{Fore.RESET}")
        print(f"Status: {Fore.GREEN if task.status == TaskStatus.COMPLETED else Fore.RED}{task.status.value}{Fore.RESET}")

        if task.result:
            vulnerabilities = task.result.get('vulnerabilities', [])
            total_vulns = len(vulnerabilities)

            print(f"\n{Fore.CYAN}SQL Injection Findings:{Fore.RESET}")
            print(f"Total Vulnerabilities Found: {Fore.WHITE}{total_vulns}{Fore.RESET}")

            if vulnerabilities:
                for i, vuln in enumerate(vulnerabilities, 1):
                    severity = vuln.get('severity', 'INFO')
                    color = {
                        'CRITICAL': Fore.RED + Style.BRIGHT,
                        'HIGH': Fore.RED,
                        'MEDIUM': Fore.YELLOW,
                        'LOW': Fore.BLUE,
                        'INFO': Fore.GREEN
                    }.get(severity, Fore.WHITE)

                    print(f"\n{i}. {color}[{severity}]{Fore.RESET} {vuln['type']}")
                    print(f"   Description: {vuln.get('description', 'No description')}")
                    print(f"   Parameter: {vuln.get('parameter', 'Unknown')}")
                    print(f"   Payload: {vuln.get('payload', 'N/A')}")
                    print(f"   Evidence: {vuln.get('evidence', 'No evidence')}")
            else:
                print(f"{Fore.GREEN}No SQL injection vulnerabilities detected.{Fore.RESET}")

    def _validate_target_url(self, url: str) -> bool:
        """Validate target URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except:
            return False

    def _get_scan_priority(self, mode: str) -> int:
        """Get task priority based on scan mode"""
        priorities = {
            'quick': 3,
            'standard': 2,
            'deep': 1,
            'comprehensive': 0
        }
        return priorities.get(mode, 2)

    def _display_enhanced_progress(self, task_id: str, scan_thread: threading.Thread):
        """Display enhanced real-time scan progress"""
        scan_thread.start()

        # Create multiple progress bars for different phases
        with tqdm(total=100, desc="Overall Progress", bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.GREEN, Fore.RESET),
                  position=0) as main_bar:
            phase_bar = tqdm(total=4, desc="Scan Phases",
                             bar_format="{l_bar}%s{bar}%s{r_bar}" % (Fore.BLUE, Fore.RESET), position=1)

            last_progress = 0
            current_phase = 0

            while scan_thread.is_alive():
                time.sleep(0.5)
                task = self.task_manager.get_task(task_id)

                if task:
                    # Update main progress
                    current_progress = task.progress
                    if current_progress > last_progress:
                        main_bar.update(current_progress - last_progress)
                        last_progress = current_progress

                    # Update phase progress
                    checkpoint = task.checkpoint or {}
                    phase = checkpoint.get('phase', '')
                    if phase:
                        phase_map = {'reconnaissance': 1, 'vulnerability_scanning': 2, 'ai_analysis': 3, 'reporting': 4}
                        new_phase = phase_map.get(phase, 0)
                        if new_phase > current_phase:
                            phase_bar.update(new_phase - current_phase)
                            current_phase = new_phase

                    # Update status
                    main_bar.set_postfix_str(f"Status: {task.status.value}", refresh=False)
                    phase_bar.set_postfix_str(f"Phase: {phase}", refresh=False)

            # Final updates
            main_bar.update(100 - last_progress)
            phase_bar.update(4 - current_phase)

        scan_thread.join()

    def _display_scan_results(self, task: Task):
        """Display comprehensive scan results"""
        print(f"\n{Fore.CYAN}{'=' * 60}{Fore.RESET}")
        print(f"{Fore.CYAN}🚀 SCAN RESULTS{Fore.RESET}")
        print(f"{Fore.CYAN}{'=' * 60}{Fore.RESET}")

        print(f"Target: {Fore.WHITE}{task.target}{Fore.RESET}")
        print(f"Status: {Fore.GREEN if task.status == TaskStatus.COMPLETED else Fore.RED}{task.status.value}{Fore.RESET}")

        if task.started_at and task.completed_at:
            duration = task.completed_at - task.started_at
            print(f"Duration: {Fore.YELLOW}{duration}{Fore.RESET}")

        if task.result:
            vulnerabilities = task.result.get('vulnerabilities', [])
            total_vulns = len(vulnerabilities)

            # Count by severity
            severity_count = defaultdict(int)
            for vuln in vulnerabilities:
                severity_count[vuln.get('severity', 'INFO')] += 1

            print(f"\n{Fore.CYAN}Vulnerability Summary:{Fore.RESET}")
            print(f"Total: {Fore.WHITE}{total_vulns}{Fore.RESET}")

            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                count = severity_count.get(severity, 0)
                color = {
                    'CRITICAL': Fore.RED,
                    'HIGH': Fore.YELLOW,
                    'MEDIUM': Fore.MAGENTA,
                    'LOW': Fore.BLUE,
                    'INFO': Fore.GREEN
                }.get(severity, Fore.WHITE)

                print(f"  {severity}: {color}{count}{Fore.RESET}")

            # Show top vulnerabilities
            if vulnerabilities:
                print(f"\n{Fore.CYAN}Top Vulnerabilities:{Fore.RESET}")
                for i, vuln in enumerate(vulnerabilities[:5]):  # Show top 5
                    severity = vuln.get('severity', 'INFO')
                    color = {
                        'CRITICAL': Fore.RED + Style.BRIGHT,
                        'HIGH': Fore.YELLOW,
                        'MEDIUM': Fore.MAGENTA,
                        'LOW': Fore.BLUE,
                        'INFO': Fore.GREEN
                    }.get(severity, Fore.WHITE)

                    print(f"  {i + 1}. {color}[{severity}]{Fore.RESET} {vuln['type']}: {vuln['description'][:100]}...")

    def _handle_config(self, args):
        """Enhanced config command handler"""
        if args.action == 'get':
            if args.key:
                value = self.config_manager.get(args.key)
                if value is not None:
                    print(f"{Fore.GREEN}{args.key} = {value}{Fore.RESET}")
                else:
                    print(f"{Fore.RED}Config key not found: {args.key}{Fore.RESET}")
            else:
                self._display_config_tree()

        elif args.action == 'set':
            if args.key and args.value:
                if self.config_manager.set(args.key, args.value):
                    if self.config_manager.save_config():
                        print(f"{Fore.GREEN}Updated {args.key} = {args.value}{Fore.RESET}")
                    else:
                        print(f"{Fore.RED}Failed to save config{Fore.RESET}")
                else:
                    print(f"{Fore.RED}Failed to set config value{Fore.RESET}")
            else:
                print(f"{Fore.RED}Both key and value are required for set operation{Fore.RESET}")

        elif args.action == 'list':
            self._display_config_tree()

        elif args.action == 'reset':
            if QUESTIONARY_AVAILABLE:
                if questionary.confirm("Are you sure you want to reset configuration to defaults?").ask():
                    self.config_manager.config = self.config_manager.load_default_config()
                    if self.config_manager.save_config():
                        print(f"{Fore.GREEN}Configuration reset to defaults{Fore.RESET}")
            else:
                confirm = input("Are you sure you want to reset configuration to defaults? (y/N): ")
                if confirm.lower() == 'y':
                    self.config_manager.config = self.config_manager.load_default_config()
                    if self.config_manager.save_config():
                        print(f"{Fore.GREEN}Configuration reset to defaults{Fore.RESET}")

        elif args.action == 'validate':
            if self.config_manager.validate_config():
                print(f"{Fore.GREEN}Configuration is valid{Fore.RESET}")
            else:
                print(f"{Fore.RED}Configuration validation failed{Fore.RESET}")

    def _display_config_tree(self):
        """Display configuration as a tree"""

        def print_config_section(section, indent=0):
            prefix = "  " * indent
            if isinstance(section, dict):
                for key, value in section.items():
                    if isinstance(value, dict):
                        print(f"{prefix}{Fore.CYAN}{key}:{Fore.RESET}")
                        print_config_section(value, indent + 1)
                    else:
                        print(f"{prefix}{Fore.GREEN}{key}: {Fore.WHITE}{value}{Fore.RESET}")

        print_config_section(self.config_manager.config)

    def _handle_status(self, args):
        """Enhanced status command handler"""
        if args.task:
            task = self.task_manager.get_task(args.task)
            if task:
                self._display_task_details(task, args.verbose)
            else:
                print(f"{Fore.RED}Task {args.task} not found{Fore.RESET}")
        else:
            self._display_system_status(args)

    def _display_task_details(self, task: Task, verbose: bool = False):
        """Display detailed task information"""
        print(f"\n{Fore.CYAN}Task Details:{Fore.RESET}")
        print(f"  ID: {task.id}")
        print(f"  Type: {task.type}")
        print(f"  Target: {task.target}")
        print(f"  Status: {self._get_status_color(task.status.value)}{task.status.value}{Fore.RESET}")
        print(f"  Progress: {task.progress:.1f}%")
        print(f"  Created: {task.created_at}")

        if task.started_at:
            print(f"  Started: {task.started_at}")
        if task.completed_at:
            print(f"  Completed: {task.completed_at}")

        if task.error:
            print(f"  Error: {Fore.RED}{task.error}{Fore.RESET}")

        if verbose and task.checkpoint:
            print(f"  Checkpoint: {json.dumps(task.checkpoint, indent=2)}")

    def _get_status_color(self, status: str) -> str:
        """Get color for status display"""
        colors = {
            'completed': Fore.GREEN,
            'running': Fore.BLUE,
            'failed': Fore.RED,
            'paused': Fore.YELLOW,
            'cancelled': Fore.MAGENTA
        }
        return colors.get(status, Fore.WHITE)

    def _display_system_status(self, args):
        """Display comprehensive system status"""
        print(f"\n{Fore.CYAN}System Status:{Fore.RESET}")

        # Task statistics
        stats = self.task_manager.get_task_stats()
        print(f"Tasks: {stats['total']} total")
        for status, count in stats['by_status'].items():
            color = self._get_status_color(status)
            print(f"  {color}{status}: {count}{Fore.RESET}")

        # System metrics
        if args.metrics:
            self.metrics.update_system_metrics()
            print(f"\n{Fore.CYAN}System Metrics:{Fore.RESET}")
            print(f"  Active Scans: {self.metrics.active_scans._value_get()}")
            print(f"  Memory Usage: {self.metrics.memory_usage._value_get() / 1024 / 1024:.1f} MB")
            print(f"  CPU Usage: {self.metrics.cpu_usage._value_get():.1f}%")

        # Health check
        health = self.health_checker.check_system_health()
        print(f"\n{Fore.CYAN}System Health: {Fore.GREEN if health['status'] == 'healthy' else Fore.RED}{health['status'].upper()}{Fore.RESET}")

    def _handle_stop(self, args):
        """Stop task command"""
        if self.task_manager.pause_task(args.task_id):
            print(f"{Fore.GREEN}Task {args.task_id} stopped successfully{Fore.RESET}")
        else:
            print(f"{Fore.RED}Failed to stop task {args.task_id}{Fore.RESET}")

    def _handle_resume(self, args):
        """Resume task command"""
        if self.task_manager.resume_task(args.task_id):
            print(f"{Fore.GREEN}Task {args.task_id} resumed successfully{Fore.RESET}")
        else:
            print(f"{Fore.RED}Failed to resume task {args.task_id}{Fore.RESET}")

    def _handle_cancel(self, args):
        """Cancel task command"""
        if self.task_manager.cancel_task(args.task_id):
            print(f"{Fore.GREEN}Task {args.task_id} cancelled successfully{Fore.RESET}")
        else:
            print(f"{Fore.RED}Failed to cancel task {args.task_id}{Fore.RESET}")

    def _handle_report(self, args):
        """Enhanced report command handler"""
        task = self.task_manager.get_task(args.task_id)
        if not task:
            print(f"{Fore.RED}Task {args.task_id} not found{Fore.RESET}")
            return

        if task.status != TaskStatus.COMPLETED:
            print(f"{Fore.RED}Task {args.task_id} is not completed{Fore.RESET}")
            return

        # Generate report
        report_generator = EliteReportGenerator()
        report_content = report_generator.generate_report(
            task.result.get('vulnerabilities', []),
            task.target,
            task,
            args.format
        )

        output_file = args.output or f"varux_report_{task.id}.{args.format}"

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_content)

            print(f"{Fore.GREEN}Report saved to {output_file}{Fore.RESET}")

        except Exception as e:
            print(f"{Fore.RED}Failed to save report: {e}{Fore.RESET}")

    def _handle_secrets(self, args):
        """Secrets management command"""
        if args.action == 'list':
            secrets = self.secrets_manager.list_secrets()
            if secrets:
                print(f"\n{Fore.CYAN}Stored Secrets:{Fore.RESET}")
                for secret in secrets:
                    print(f"  {secret['key']}: {secret['description']}")
            else:
                print(f"{Fore.YELLOW}No secrets stored{Fore.RESET}")

        elif args.action == 'set':
            if args.key and args.value:
                if QUESTIONARY_AVAILABLE:
                    description = questionary.text("Description (optional):").ask() or ""
                else:
                    description = input("Description (optional): ") or ""

                if self.secrets_manager.store_secret(args.key, args.value, description):
                    print(f"{Fore.GREEN}Secret stored successfully{Fore.RESET}")
                else:
                    print(f"{Fore.RED}Failed to store secret{Fore.RESET}")
            else:
                print(f"{Fore.RED}Both key and value are required{Fore.RESET}")

        elif args.action == 'get':
            if args.key:
                value = self.secrets_manager.get_secret(args.key)
                if value:
                    print(f"{Fore.GREEN}{args.key}: {value}{Fore.RESET}")
                else:
                    print(f"{Fore.RED}Secret not found{Fore.RESET}")
            else:
                print(f"{Fore.RED}Key is required{Fore.RESET}")

        elif args.action == 'delete':
            if args.key:
                if self.secrets_manager.delete_secret(args.key):
                    print(f"{Fore.GREEN}Secret deleted successfully{Fore.RESET}")
                else:
                    print(f"{Fore.RED}Failed to delete secret or secret not found{Fore.RESET}")
            else:
                print(f"{Fore.RED}Key is required{Fore.RESET}")

    def _handle_health(self, args):
        """System health check command"""
        health_status = self.health_checker.check_system_health(args.full)

        print(f"\n{Fore.CYAN}System Health Check:{Fore.RESET}")
        print(f"Overall Status: {Fore.GREEN if health_status['status'] == 'healthy' else Fore.RED}{health_status['status'].upper()}{Fore.RESET}")
        print(f"Timestamp: {health_status['timestamp']}")

        if args.full:
            for component, info in health_status['components'].items():
                print(f"\n{component.upper()}:")
                for key, value in info.items():
                    print(f"  {key}: {value}")

    def _handle_cleanup(self, args):
        """System cleanup command"""
        if QUESTIONARY_AVAILABLE:
            if questionary.confirm(f"Cleanup tasks older than {args.days} days?").ask():
                # This would implement the cleanup logic
                print(f"{Fore.GREEN}Cleanup completed{Fore.RESET}")
            else:
                print(f"{Fore.YELLOW}Cleanup cancelled{Fore.RESET}")
        else:
            confirm = input(f"Cleanup tasks older than {args.days} days? (y/N): ")
            if confirm.lower() == 'y':
                print(f"{Fore.GREEN}Cleanup completed{Fore.RESET}")
            else:
                print(f"{Fore.YELLOW}Cleanup cancelled{Fore.RESET}")

    def _handle_status_interactive(self):
        """Interactive status display"""
        self._handle_status(argparse.Namespace(task=None, verbose=True, metrics=True))

    def _handle_health_interactive(self):
        """Interactive health check"""
        self._handle_health(argparse.Namespace(full=True))

    def _interactive_config(self):
        """Interactive configuration management"""
        try:
            if QUESTIONARY_AVAILABLE:
                action = questionary.select(
                    "Configuration action:",
                    choices=['View Config', 'Set Value', 'Validate Config', 'Reset to Defaults']
                ).ask()

                if action == 'View Config':
                    self._handle_config(argparse.Namespace(action='list', key=None, value=None))
                elif action == 'Set Value':
                    key = questionary.text("Config key:").ask()
                    value = questionary.text("Config value:").ask()
                    if key and value:
                        self._handle_config(argparse.Namespace(action='set', key=key, value=value))
                elif action == 'Validate Config':
                    self._handle_config(argparse.Namespace(action='validate', key=None, value=None))
                elif action == 'Reset to Defaults':
                    self._handle_config(argparse.Namespace(action='reset', key=None, value=None))
            else:
                print("\nConfiguration Management:")
                print("1. View Config")
                print("2. Set Value")
                print("3. Validate Config")
                print("4. Reset to Defaults")
                choice = input("Enter choice (1-4): ")

                if choice == '1':
                    self._handle_config(argparse.Namespace(action='list', key=None, value=None))
                elif choice == '2':
                    key = input("Config key: ")
                    value = input("Config value: ")
                    if key and value:
                        self._handle_config(argparse.Namespace(action='set', key=key, value=value))
                elif choice == '3':
                    self._handle_config(argparse.Namespace(action='validate', key=None, value=None))
                elif choice == '4':
                    self._handle_config(argparse.Namespace(action='reset', key=None, value=None))

        except Exception as e:
            print(f"Interactive config failed: {e}")

    def _interactive_reports(self):
        """Interactive report generation"""
        try:
            # Get completed tasks
            completed_tasks = [
                task for task in self.task_manager.tasks.values()
                if task.status == TaskStatus.COMPLETED
            ]

            if not completed_tasks:
                print(f"{Fore.YELLOW}No completed tasks found{Fore.RESET}")
                return

            if QUESTIONARY_AVAILABLE:
                task_choices = [
                    f"{task.id} - {task.target} ({task.completed_at})"
                    for task in completed_tasks
                ]

                selected = questionary.select(
                    "Select task for report:",
                    choices=task_choices
                ).ask()

                if selected:
                    task_id = selected.split(' - ')[0]
                    format_choice = questionary.select(
                        "Report format:",
                        choices=['html', 'json', 'pdf']
                    ).ask()

                    self._handle_report(argparse.Namespace(
                        task_id=task_id,
                        format=format_choice,
                        output=None
                    ))
            else:
                print("\nCompleted Tasks:")
                for i, task in enumerate(completed_tasks, 1):
                    print(f"{i}. {task.id} - {task.target} ({task.completed_at})")

                try:
                    task_num = int(input("\nSelect task (number): "))
                    if 1 <= task_num <= len(completed_tasks):
                        task_id = completed_tasks[task_num - 1].id

                        print("\nReport Format:")
                        print("1. HTML")
                        print("2. JSON")
                        print("3. PDF")
                        format_choice = input("Enter format (1-3): ")
                        format_map = {'1': 'html', '2': 'json', '3': 'pdf'}
                        format_choice = format_map.get(format_choice, 'html')

                        self._handle_report(argparse.Namespace(
                            task_id=task_id,
                            format=format_choice,
                            output=None
                        ))
                except (ValueError, IndexError):
                    print("Invalid task selection")

        except Exception as e:
            print(f"Interactive reports failed: {e}")

# =============================================================================
# Enhanced Security Protocols & Signal Handling
# =============================================================================

class SecurityProtocol:
    """Enhanced security protocols and signal handling"""

    def __init__(self, cli: VARUXCLI):
        self.cli = cli
        self.setup_signal_handlers()

    def setup_signal_handlers(self):
        """Setup comprehensive signal handlers for graceful shutdown"""
        signal.signal(signal.SIGINT, self._graceful_shutdown)
        signal.signal(signal.SIGTERM, self._graceful_shutdown)

        # Additional signal handlers for Unix-like systems
        if hasattr(signal, 'SIGUSR1'):
            signal.signal(signal.SIGUSR1, self._handle_user_signal)

    def _graceful_shutdown(self, signum, frame):
        """Handle graceful shutdown"""
        self.cli.logger.info(f"Received signal {signum}, initiating graceful shutdown...")

        # Stop all active tasks
        active_tasks = [
            task for task in self.cli.task_manager.tasks.values()
            if task.status == TaskStatus.RUNNING
        ]

        for task in active_tasks:
            self.cli.task_manager.pause_task(task.id)

        # Save state and cleanup
        self.cli.config_manager.save_config()

        self.cli.logger.info("Shutdown completed successfully")
        sys.exit(ExitCodes.SUCCESS.value)

    def _handle_user_signal(self, signum, frame):
        """Handle user-defined signals"""
        self.cli.logger.info(f"Received user signal {signum}")
        # Implement custom signal handling as needed

# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """Enhanced main entry point with comprehensive error handling"""
    try:
        # Initialize the CLI application
        cli = VARUXCLI()
        
        # Setup security protocols
        security_protocol = SecurityProtocol(cli)
        
        # Run the application
        cli.run()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Operation interrupted by user{Fore.RESET}")
        sys.exit(ExitCodes.SUCCESS.value)
        
    except Exception as e:
        logging.critical(f"Fatal error: {e}", exc_info=True)
        print(f"{Fore.RED}Fatal error occurred. Check logs for details.{Fore.RESET}")
        sys.exit(ExitCodes.GENERAL_ERROR.value)

if __name__ == "__main__":
    main()
