"""
HoneyManager Configuration Module
Loads settings from .env file
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / '.env')

class Config:
    """Application configuration"""
    
    # Flask
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key')
    HOST = os.getenv('FLASK_HOST', '0.0.0.0')
    PORT = int(os.getenv('FLASK_PORT', 80))
    DEBUG = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'

    # Admin
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')
    
    # Telegram
    TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '')
    TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID', '')
    
    # Google Gemini API
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')

    # DeepSeek API (fallback classifier)
    DEEPSEEK_API_KEY = os.getenv('DEEPSEEK_API_KEY', '')

    # VirusTotal API
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')

    # Dionaea binary capture directory (mounted from container)
    DIONAEA_BINARIES_PATH = Path(os.getenv('DIONAEA_BINARIES_PATH', str(BASE_DIR / 'data/dionaea-binaries')))
    
    # Network
    MACVLAN_NETWORK = os.getenv('MACVLAN_NETWORK', 'macvlan_honeynet')
    SUBNET = os.getenv('SUBNET', '192.168.1.0/24')
    GATEWAY = os.getenv('GATEWAY', '192.168.1.1')
    
    # Paths
    BASE_DIR = BASE_DIR
    LOG_PATH = Path(os.getenv('LOG_PATH', BASE_DIR / 'data/logs'))
    DB_PATH = Path(os.getenv('DB_PATH', str(BASE_DIR / 'data/db/alerts.db')))
    
    # Retention
    LOG_RETENTION_DAYS = int(os.getenv('LOG_RETENTION_DAYS', 30))
    
    # Default IPs
    DEFAULT_IPS = {
        'cowrie': os.getenv('COWRIE_IP', '192.168.1.215'),
        'web-camera': os.getenv('WEBCAM_IP', '192.168.1.216'),
        'dionaea': os.getenv('DIONAEA_IP', '192.168.1.217'),
        'custom-iot': os.getenv('CUSTOM_IOT_IP', '192.168.1.218'),
    }
    
    # Whitelist IPs (trusted devices that won't trigger HIGH alerts)
    _whitelist_str = os.getenv('WHITELIST_IPS', '')
    WHITELIST_IPS = [ip.strip() for ip in _whitelist_str.split(',') if ip.strip()]
    
    # Honeypot profiles
    HONEYPOT_PROFILES = {
        'cowrie': {
            'name': 'Cowrie SSH/Telnet',
            'image': 'honeymanager/cowrie:latest',
            'build_path': str(BASE_DIR / 'honeypots/cowrie'),
            'role': 'router',
            'ports': '22, 23',
            'description': 'SSH/Telnet honeypot - Router emulation'
        },
        'web-camera': {
            'name': 'Web Camera',
            'image': 'honeymanager/web-camera:latest',
            'build_path': str(BASE_DIR / 'honeypots/web-camera'),
            'role': 'camera',
            'ports': '80',
            'description': 'Hikvision IP Camera clone'
        },
        'dionaea': {
            'name': 'Dionaea SMB/FTP',
            'image': 'dinotools/dionaea:latest',
            'role': 'nas',
            'ports': '21, 445',
            'description': 'SMB/FTP honeypot - NAS/Printer emulation'
        },
        'custom-iot': {
            'name': 'Custom IoT',
            'image': 'onurmaden/iothoneypot:latest',
            'role': 'iot',
            'ports': '22, 21, 23',
            'description': 'Custom IoT device honeypot'
        }
    }


config = Config()
