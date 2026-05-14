"""
Log Parser - Parse honeypot logs from various formats
"""
import json
import re
import requests
from datetime import datetime
from typing import Dict, Any, Optional, Generator
import logging
from google import genai
from google.genai import types
from config import config

logger = logging.getLogger(__name__)

# Gemini API Config:   
client = None
if config.GEMINI_API_KEY:
    try:
        client = genai.Client(api_key=config.GEMINI_API_KEY)
    except Exception as e:
        logger.error(f"Gemini Client başlatılamadı: {e}")
else:
    logger.warning("GEMINI_API_KEY could not be found in .env file. Classification will use fallback ID.")
 
# In-memory caching for repetitive instructions (Performance and quota optimization)
_COMMAND_CACHE = {}

# Maps MITRE technique IDs to alert severity for command_execution events
_MITRE_SEVERITY = {
    'T1105': 'critical',   # Ingress Tool Transfer (wget/curl malware)
    'T1496': 'critical',   # Resource Hijacking (xmrig, crypto miner)
    'T1485': 'critical',   # Data Destruction (rm -rf /, dd)
    'T1489': 'critical',   # Service Stop (systemctl stop firewalld)
    'T1059.004': 'high',   # Unix Shell
    'T1548.003': 'high',   # Sudo abuse (sudo su, sudo bash)
    'T1053.003': 'high',   # Scheduled Task (crontab)
    'T1070.003': 'high',   # Clear History (history -c)
    'T1082': 'medium',     # System Info Discovery (uname, lscpu)
    'T1033': 'medium',     # User/Owner Discovery (id, whoami)
    'T1057': 'medium',     # Process Discovery (ps aux, top)
    'T1083': 'medium',     # File and Directory Discovery (ls, find)
}

# User-Agent substrings that identify known vulnerability scanning tools (T1595.002)
_SCANNER_UA_PATTERNS = [
    'nmap', 'nikto', 'masscan', 'nuclei', 'sqlmap', 'zgrab',
    'gobuster', 'dirbuster', 'wfuzz', 'hydra', 'metasploit',
    'openvas', 'acunetix', 'nessus', 'burp', 'zap',
]

_MITRE_ID_RE = re.compile(r'^T\d{4}(\.\d{3})?$')
_SYSTEM_PROMPT = (
    "You are a cybersecurity expert analyzing honeypot logs. "
    "Map the provided shell command to a single most specific MITRE ATT&CK Technique ID. "
    "Prioritize specific Discovery, Credential Access, and Defense Evasion techniques over generic Execution techniques. "
    "Respond ONLY with the ID (e.g., T1082, T1105). If totally unknown, return T1059.004."
)


def _classify_with_gemini(cmd: str) -> Optional[str]:
    """Try Gemini API. Returns MITRE ID string or None on any failure."""
    if not client:
        return None
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash-lite',
            contents=cmd,
            config=types.GenerateContentConfig(
                system_instruction=_SYSTEM_PROMPT,
                temperature=0.0,
                max_output_tokens=15,
                safety_settings=[
                    types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE"),
                    types.SafetySetting(category="HARM_CATEGORY_HARASSMENT", threshold="BLOCK_NONE"),
                    types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH", threshold="BLOCK_NONE"),
                    types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="BLOCK_NONE"),
                ]
            )
        )
        if not response.text:
            logger.warning(f"Gemini returned empty response for: {cmd}")
            return None
        result_id = response.text.strip()
        if _MITRE_ID_RE.match(result_id):
            return result_id
        logger.warning(f"Gemini unexpected format: '{result_id}'")
        return None
    except Exception as e:
        logger.error(f"Gemini API error: {e}")
        return None


def _classify_with_deepseek(cmd: str) -> Optional[str]:
    """Try DeepSeek API. Returns MITRE ID string or None on any failure."""
    if not config.DEEPSEEK_API_KEY:
        return None
    try:
        response = requests.post(
            'https://api.deepseek.com/chat/completions',
            headers={
                'Authorization': f'Bearer {config.DEEPSEEK_API_KEY}',
                'Content-Type': 'application/json',
            },
            json={
                'model': 'deepseek-chat',
                'messages': [
                    {'role': 'system', 'content': _SYSTEM_PROMPT},
                    {'role': 'user', 'content': cmd},
                ],
                'temperature': 0.0,
                'max_tokens': 15,
            },
            timeout=15,
        )
        if response.status_code != 200:
            logger.error(f"DeepSeek API error {response.status_code}: {response.text[:200]}")
            return None
        result_id = response.json()['choices'][0]['message']['content'].strip()
        if _MITRE_ID_RE.match(result_id):
            return result_id
        logger.warning(f"DeepSeek unexpected format: '{result_id}'")
        return None
    except Exception as e:
        logger.error(f"DeepSeek API error: {e}")
        return None


def classify_command(cmd: str) -> str:
    """Classify a shell command to a MITRE ATT&CK ID.

    Priority: Gemini → DeepSeek → T1059.004 (no API configured).
    """
    if not cmd:
        return 'T1059.004'

    cmd_lower = cmd.strip().lower()
    if cmd_lower in _COMMAND_CACHE:
        return _COMMAND_CACHE[cmd_lower]

    result_id = _classify_with_gemini(cmd) or _classify_with_deepseek(cmd)

    if result_id is None:
        if not client and not config.DEEPSEEK_API_KEY:
            logger.warning("No AI classifier configured. Defaulting to T1059.004.")
        return 'T1059.004'

    _COMMAND_CACHE[cmd_lower] = result_id
    return result_id
class LogParser:
    """Parse logs from different honeypot types"""
    
    @staticmethod
    def _get_time():
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    @staticmethod
    def parse_cowrie_json(log_line: str) -> Optional[Dict[str, Any]]:
        """Parse Cowrie JSON log entry with MITRE ATT&CK"""
        try:
            data = json.loads(log_line)
            event_id = data.get('eventid', '')
            src_ip = data.get('src_ip', 'unknown')
            timestamp = data.get('timestamp', LogParser._get_time())
            
            event_type, severity, description, mitre_id = 'unknown', 'low', None, None
            
            username = data.get('username', '')

            if 'cowrie.login' in event_id:
                if 'success' in event_id:
                    event_type, severity, mitre_id = 'successful_login', 'critical', 'T1078'
                    description = f"Successful SSH/Telnet login as '{username}'"
                elif 'failed' in event_id:
                    event_type, severity, mitre_id = 'failed_login', 'high', 'T1110.001'
                    description = f"Failed login attempt: {username}/{data.get('password', '')}"

            elif 'cowrie.command.input' in event_id:
                event_type = 'command_execution'
                cmd_input = data.get('input', '')
                mitre_id = classify_command(cmd_input)
                severity = _MITRE_SEVERITY.get(mitre_id, 'high')
                description = f"Command executed: {cmd_input}"

            elif 'cowrie.session.connect' in event_id:
                event_type, severity, mitre_id = 'connection', 'low', 'T1021.004'
                description = f"New connection to port {data.get('dst_port', '')}"

            elif 'cowrie.client.version' in event_id:
                event_type, severity, mitre_id = 'client_info', 'low', 'T1592.004'
                description = f"Client version: {data.get('version', '')}"

            if event_type != 'unknown':
                return {
                    'timestamp': timestamp,
                    'source_ip': src_ip,
                    'event_type': event_type,
                    'severity': severity,
                    'mitre_id': mitre_id,
                    'description': description,
                    'raw_data': log_line,
                    'honeypot_type': 'cowrie',
                    'username': username
                }
        except json.JSONDecodeError: pass
        return None
    
    @staticmethod
    def parse_nginx_json(log_line: str) -> Optional[Dict[str, Any]]:
        """Parse Nginx/Web-Camera JSON log entry with MITRE ATT&CK"""
        try:
            data = json.loads(log_line)

            if 'username' in data and 'password' in data:
                return {
                    'timestamp': LogParser._get_time(),
                    'source_ip': data.get('source_ip', 'unknown'),
                    'event_type': 'credential_capture',
                    'severity': 'critical',
                    'mitre_id': 'T1056.003',
                    'description': f"Captured credentials: {data.get('username')}/[MASKED]",
                    'raw_data': log_line,
                    'honeypot_type': 'web-camera'
                }

            request_uri = data.get('request_uri', '')
            request_method = data.get('request_method', '')
            status = data.get('status', '')
            src_ip = data.get('remote_addr', 'unknown')
            user_agent = data.get('http_user_agent', '')

            event_type, severity, mitre_id = 'web_access', 'low', 'T1190'
            description = f"HTTP {request_method} {request_uri} ({status})"

            ua_lower = user_agent.lower()
            if any(s in ua_lower for s in _SCANNER_UA_PATTERNS):
                # Known vulnerability scanner tool identified by User-Agent
                event_type, severity, mitre_id = 'scanner_detected', 'high', 'T1595.002'
                description = f"Vulnerability scanner: [{user_agent}] {request_method} {request_uri}"
            elif '/login' in request_uri and request_method == 'POST':
                event_type, severity, mitre_id = 'login_attempt', 'high', 'T1110.003'
            elif any(x in request_uri for x in ['/.env', '/config', '/.git']):
                event_type, severity, mitre_id = 'scanner_detected', 'high', 'T1552.001'
            elif any(x in request_uri for x in ['/wp-admin', '/phpmyadmin', '/admin']):
                event_type, severity, mitre_id = 'scanner_detected', 'medium', 'T1595.003'
            elif '/robots.txt' in request_uri:
                event_type, severity, mitre_id = 'scanner_detected', 'low', 'T1083'

            return {
                'timestamp': LogParser._get_time(),
                'source_ip': src_ip,
                'event_type': event_type,
                'severity': severity,
                'mitre_id': mitre_id,
                'description': description,
                'raw_data': log_line,
                'honeypot_type': 'web-camera'
            }
        except json.JSONDecodeError: pass
        return None
    
    @staticmethod
    def parse_dionaea(log_line: str) -> Optional[Dict[str, Any]]:
        try:
            src_ip, dst_port = 'unknown', None
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log_line)
            if ip_match: src_ip = ip_match.group(1)
                
            if log_line.strip().startswith('{'):
                data = json.loads(log_line)
                dst_port = data.get('local', {}).get('port') or data.get('dst_port')
                src_ip = data.get('remote', {}).get('host') or src_ip
            else:
                port_match = re.search(r'(?:port|dst_port|dpt)[:\s]*(\d+)', log_line.lower())
                if port_match: dst_port = int(port_match.group(1))

            if src_ip == 'unknown': return None

            event_type, severity, mitre_id = 'connection', 'medium', 'T1190'
            description = "Connection to Dionaea honeypot"

            if dst_port == 445:
                mitre_id, severity = 'T1210', 'high'
                description = "SMB exploit attempt — EternalBlue/Ransomware (T1210 / T1021.002)"
            elif dst_port == 21:
                mitre_id = 'T1048.003'
                description = "FTP connection attempt"
            elif dst_port == 80:
                mitre_id = 'T1190'
                description = "HTTP exploit attempt on Dionaea"
            elif dst_port == 3306:
                description = "MySQL remote brute force attempt"

            return {
                'timestamp': LogParser._get_time(),
                'source_ip': src_ip,
                'event_type': event_type,
                'severity': severity,
                'mitre_id': mitre_id,
                'description': description,
                'raw_data': log_line,
                'honeypot_type': 'dionaea'
            }
        except Exception: pass
        return None
    
    @staticmethod
    def parse_syslog(log_line: str) -> Optional[Dict[str, Any]]:
        try:
            if not log_line.strip(): return None
            
            ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', log_line)
            src_ip = ip_match.group(1) if ip_match else 'unknown'
            
            event_type, severity, description, mitre_id = 'unknown', 'low', None, None
            
            username = 'unknown'

            if 'Failed password' in log_line or 'authentication failure' in log_line.lower():
                event_type, severity, mitre_id = 'failed_login', 'high', 'T1110.001'
                user_match = re.search(r'(?:invalid user|user)\s+(\w+)', log_line, re.IGNORECASE)
                username = user_match.group(1) if user_match else 'unknown'
                description = f"SSH failed login: {username} from {src_ip}"

            elif 'Invalid user' in log_line or 'invalid password' in log_line:
                event_type, severity, mitre_id = 'invalid_user', 'high', 'T1110.001'
                user_match = re.search(r'(?:Invalid user|for)\s+[\'"]?(\w+)[\'"]?', log_line)
                username = user_match.group(1) if user_match else 'unknown'
                description = f"Invalid user/password attempt: {username} from {src_ip}"

            elif 'Accepted password' in log_line or 'Accepted publickey' in log_line:
                event_type, severity, mitre_id = 'successful_login', 'critical', 'T1133'
                description = f"SSH successful login from {src_ip}"

            elif any(x in log_line for x in ['Connection closed', 'Server listening', 'syslogd started']):
                return None
            else:
                return None

            return {
                'timestamp': LogParser._get_time(),
                'source_ip': src_ip,
                'event_type': event_type,
                'severity': severity,
                'mitre_id': mitre_id,
                'description': description,
                'honeypot_type': 'custom-iot',
                'raw_data': log_line,
                'username': username
            }
        except Exception: return None

    @staticmethod
    def parse_vsftpd(log_line: str) -> Optional[Dict[str, Any]]:
        try:
            if not log_line.strip(): return None
            
            ip_match = re.search(r'Client "(\d+\.\d+\.\d+\.\d+)"', log_line)
            src_ip = ip_match.group(1) if ip_match else 'unknown'
            
            event_type, severity, mitre_id = 'unknown', 'low', None
            description = log_line.strip()
            
            if 'CONNECT:' in log_line:
                event_type, severity, mitre_id = 'connection', 'high', 'T1071.002' # EKLENDİ
                description = f"FTP connection from {src_ip}"
            elif 'FAIL LOGIN' in log_line:
                event_type, severity, mitre_id = 'failed_login', 'high', 'T1110.001' # EKLENDİ
                description = f"FTP failed login from {src_ip}"
            elif 'OK LOGIN' in log_line:
                event_type, severity, mitre_id = 'successful_login', 'critical', 'T1078.003' # EKLENDİ
                description = f"FTP successful login from {src_ip}"
            else: return None
                
            return {
                'timestamp': LogParser._get_time(),
                'source_ip': src_ip,
                'event_type': event_type,
                'severity': severity,
                'mitre_id': mitre_id,
                'description': description,
                'honeypot_type': 'custom-iot',
                'raw_data': log_line
            }
        except Exception: return None


LOG_PATTERNS = {
    'cowrie': {
        'files': ['cowrie.json'],
        'parser': LogParser.parse_cowrie_json
    },
    'web-camera': {
        'files': ['access.json', 'credentials.json'],
        'parser': LogParser.parse_nginx_json
    },
    'dionaea': {
        'files': ['dionaea.log'],
        'parser': LogParser.parse_dionaea
    },
    'custom-iot': {
        'files': ['messages', 'auth.log', 'vsftpd.log'],
        'parser': LogParser.parse_syslog # Note: watcher.py overrides this for vsftpd.log
    }
}
