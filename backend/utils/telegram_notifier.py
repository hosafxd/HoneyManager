"""
Telegram Notifier - Send alerts via Telegram Bot
"""
import requests
import logging
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class TelegramNotifier:
    """Send honeypot alerts via Telegram Bot API"""
    
    SEVERITY_EMOJI = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🔵'
    }
    
    HONEYPOT_EMOJI = {
        'cowrie': '🔒',
        'web-camera': '📷',
        'dionaea': '🖨️',
        'custom-iot': '📡',
        'router': '🔒',
        'camera': '📷',
        'nas': '🖨️',
        'iot': '📡'
    }
    
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{bot_token}"
        self.enabled = bool(bot_token and chat_id)
    
    def send_message(self, text: str, parse_mode: str = 'HTML') -> bool:
        """Send a text message to Telegram"""
        if not self.enabled:
            logger.warning("Telegram not configured, skipping notification")
            return False
        
        try:
            response = requests.post(
                f"{self.base_url}/sendMessage",
                json={
                    'chat_id': self.chat_id,
                    'text': text,
                    'parse_mode': parse_mode
                },
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info("Telegram notification sent successfully")
                return True
            else:
                logger.error(f"Telegram API error: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send Telegram message: {e}")
            return False
    
    def send_alert(
        self,
        severity: str,
        honeypot_name: str,
        source_ip: str,
        event_type: str,
        honeypot_type: str = None,
        description: str = None,
        timestamp: datetime = None,
        destination_ip: str = None,
        destination_port: str = None
    ) -> bool:
        """Send formatted honeypot alert"""
        
        if timestamp is None:
            timestamp = datetime.now()
        
        severity_emoji = self.SEVERITY_EMOJI.get(severity, '⚪')
        honeypot_emoji = self.HONEYPOT_EMOJI.get(honeypot_type or honeypot_name, '🍯')
        
        # Format alert message
        message = f"""
{severity_emoji} <b>HONEYPOT ALERT</b> {severity_emoji}

<b>Severity:</b> {severity.upper()}
<b>Time:</b> {timestamp.strftime('%Y-%m-%d %H:%M:%S')}

{honeypot_emoji} <b>Honeypot:</b> {honeypot_name}
<b>Type:</b> {honeypot_type or 'Unknown'}

🎯 <b>Event:</b> {event_type}
🌐 <b>Source IP:</b> <code>{source_ip}</code>
{f'📍 <b>Destination:</b> <code>{destination_ip}:{destination_port}</code>' if destination_ip else ''}

{f'📝 <b>Details:</b> {description}' if description else ''}

━━━━━━━━━━━━━━━━━━━━━━
🔗 <i>HoneyManager Alert System</i>
"""
        
        return self.send_message(message.strip())
    
    def send_test_message(self) -> Dict[str, Any]:
        """Send a test message to verify configuration"""
        message = """
🧪 <b>HoneyManager Test Alert</b>

This is a test notification from your HoneyManager honeypot system.

✅ Telegram integration is working correctly!

━━━━━━━━━━━━━━━━━━━━━━
🕐 Sent at: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        success = self.send_message(message.strip())
        return {
            'success': success,
            'message': 'Test message sent!' if success else 'Failed to send test message'
        }
    
    def send_startup_message(self) -> bool:
        """Send notification when HoneyManager starts"""
        message = """
🚀 <b>HoneyManager Started</b>

Your honeypot monitoring system is now active.

🍯 Honeypots are being monitored
📊 Dashboard is available
🔔 Alerts are enabled

━━━━━━━━━━━━━━━━━━━━━━
🕐 Started at: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        return self.send_message(message.strip())


# Factory function
def create_notifier(bot_token: str = None, chat_id: str = None) -> TelegramNotifier:
    """Create TelegramNotifier from config or parameters"""
    if bot_token is None or chat_id is None:
        from config import config
        bot_token = config.TELEGRAM_BOT_TOKEN
        chat_id = config.TELEGRAM_CHAT_ID
    
    return TelegramNotifier(bot_token, chat_id)
