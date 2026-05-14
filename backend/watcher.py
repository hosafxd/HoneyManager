"""
HoneyManager Log Watcher
"""
import os
import sys
import time
import threading
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
import logging
import schedule

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from config import config
from models import Alert, init_db
from utils.log_parser import LogParser, LOG_PATTERNS
from utils.telegram_notifier import create_notifier

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
telegram = create_notifier()


class LogWatcher:
    """Watch honeypot log files and trigger alerts"""
    
    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.file_positions = {}
        self.ip_events = defaultdict(list)  # Track events per IP 
        self.running = False
        
    def get_log_files(self):
        files = []
        for honeypot_type, pattern_info in LOG_PATTERNS.items():
            honeypot_dir = self.log_path / honeypot_type
            if not honeypot_dir.exists(): continue
            for pattern in pattern_info['files']:
                if '*' in pattern:
                    files.extend(honeypot_dir.glob(pattern))
                else:
                    log_file = honeypot_dir / pattern
                    if log_file.exists(): files.append(log_file)
                    
                    
       # Also check dynamically created honeypot directories 
        for subdir in self.log_path.iterdir():
            if subdir.is_dir() and subdir.name not in LOG_PATTERNS:
                all_files = list(subdir.rglob('*'))
                for file_path in all_files:
                    if not file_path.is_file(): continue
                    if file_path.name == 'access.json' or file_path.suffix == '.json':
                        files.append(file_path)
                    elif file_path.name in ['messages', 'auth.log', 'dionaea.log', 'vsftpd.log']:
                        files.append(file_path)
        return list(set(files))
    
    def get_parser_for_file(self, file_path: Path):
        """Get appropriate parser for log file"""
        parent_name = file_path.parent.name
        file_name = file_path.name
        
        if file_name == 'access.json': return LogParser.parse_nginx_json
        if file_name == 'credentials.json': return LogParser.parse_nginx_json
        if file_name == 'dionaea.log': return LogParser.parse_dionaea
        if file_name == 'vsftpd.log': return LogParser.parse_vsftpd
        if file_name in ['messages', 'auth.log', 'syslog']: return LogParser.parse_syslog
        
        if parent_name in LOG_PATTERNS: return LOG_PATTERNS[parent_name]['parser']
      
        # Default to syslog parser for unknown text files, Cowrie for JSON
        if file_path.suffix == '.json': return LogParser.parse_cowrie_json
        return LogParser.parse_syslog
    
    def read_new_lines(self, file_path: Path):
        """Read new lines from log file since last check"""
        try:
            file_key = str(file_path)
            with open(file_path, 'r') as f:
                f.seek(0, 2)
                file_size = f.tell()

                if file_key not in self.file_positions:
                    # First encounter: skip all existing content, only watch from now on
                    self.file_positions[file_key] = file_size
                    return []

                current_pos = self.file_positions[file_key]
                if file_size < current_pos:
                    current_pos = 0  # File was truncated/rotated
                f.seek(current_pos)
                lines = f.readlines()
                self.file_positions[file_key] = f.tell()
            return lines
        except Exception as e:
            return []
    
    def should_alert(self, source_ip: str, severity: str) -> bool:
        """Rate limiting: avoid duplicate alerts for same IP"""
        now = datetime.now()
        
         # Clean old events
        self.ip_events[source_ip] = [
            event for event in self.ip_events[source_ip]
            if now - event['time'] < timedelta(minutes=5)
        ]
         # Always alert for critical
        if severity == 'critical': return True
        
        # Rate limit: max 10 alerts per IP per 5 minutes
        recent_alerts = len(self.ip_events[source_ip])
        return recent_alerts < 10
    
    def process_event(self, event: dict, honeypot_name: str):
        """Process parsed event and create alert"""
        try:
            severity = event.get('severity', 'low')
            source_ip = event.get('source_ip', 'unknown')
            event_type = event.get('event_type', 'unknown')
            mitre_id = event.get('mitre_id')
            description = event.get('description', '')
            honeypot_type = event.get('honeypot_type', honeypot_name)
            
             # Check whitelist - downgrade severity for trusted IPs
            if source_ip in config.WHITELIST_IPS:
                severity = 'low'
                description = f"[WHITELISTED] {description}"
            
            # Record event memory for Cross-Honeypot Analysis
            self.ip_events[source_ip].append({
                'time': datetime.now(),
                'severity': severity,
                'event_type': event_type,
                'honeypot_name': honeypot_name,
                'username': event.get('username', '')
            })
            
             # Create database alert
            alert_id = Alert.create(
                severity=severity,
                honeypot_name=honeypot_name,
                honeypot_type=honeypot_type,
                source_ip=source_ip,
                event_type=event_type,
                mitre_id=mitre_id,
                description=description,
                raw_data=event.get('raw_data', '')
            )
            
            logger.info(f"Alert #{alert_id}: [{severity.upper()}] {honeypot_name} - {event_type} ({mitre_id}) from {source_ip}")
            
             # Send Telegram notification for HIGH and CRITICAL (not whitelisted)
            if self.should_alert(source_ip, severity) and severity in ['critical', 'high']:
                telegram.send_alert(
                    severity=severity,
                    honeypot_name=honeypot_name,
                    source_ip=source_ip,
                    event_type=event_type,
                    honeypot_type=honeypot_type,
                    description=f"[{mitre_id}] {description}" if mitre_id else description,
                    destination_ip=event.get('destination_ip'),
                    destination_port=event.get('destination_port')
                )
                if alert_id: Alert.mark_notified(alert_id)
            
        except Exception as e:
            logger.error(f"Error processing event: {e}")
    
    def check_attack_patterns(self):
        """Check for brute force, port scan, and cross-honeypot reconnaissance"""
        _BRUTE_FORCE_TYPES = {'failed_login', 'invalid_user', 'login_attempt'}

        for ip, events in list(self.ip_events.items()):
            detected = False

            # 1. BRUTE FORCE CHECK (T1110 / T1110.003)
            failed_logins = [e for e in events if e.get('event_type') in _BRUTE_FORCE_TYPES]
            if len(failed_logins) >= 5:
                usernames = {e.get('username') for e in failed_logins if e.get('username')}
                is_spraying = len(usernames) > 1
                mitre = 'T1110.003' if is_spraying else 'T1110'
                desc = (
                    f"Password spraying: {len(failed_logins)} attempts across {len(usernames)} usernames"
                    if is_spraying else
                    f"Brute force attack: {len(failed_logins)} failed attempts in 5 mins"
                )
                Alert.create(
                    severity='high', honeypot_name='system', honeypot_type='detector',
                    source_ip=ip, event_type='brute_force_detected', mitre_id=mitre,
                    description=desc
                )
                telegram.send_alert(
                    severity='high', honeypot_name='Network Level', source_ip=ip,
                    event_type='brute_force_detected', honeypot_type='detector',
                    description=f"🚨 {'Password Spraying (T1110.003)' if is_spraying else 'Brute Force (T1110)'}: {desc}"
                )
                detected = True

            # 2. PORT SCAN CHECK (T1046)
            connections = [e for e in events if e.get('event_type') == 'connection']
            if len(connections) >= 10:
                Alert.create(
                    severity='medium', honeypot_name='system', honeypot_type='detector',
                    source_ip=ip, event_type='port_scan_detected', mitre_id='T1046',
                    description=f"Port Scanning: {len(connections)} rapid connections detected"
                )
                detected = True

            # 3. CROSS-HONEYPOT RECONNAISSANCE (T1595.001)
            unique_honeypots = {e.get('honeypot_name') for e in events if e.get('honeypot_name')}
            if len(unique_honeypots) >= 3:
                Alert.create(
                    severity='high', honeypot_name='system', honeypot_type='detector',
                    source_ip=ip, event_type='active_scanning_detected', mitre_id='T1595.001',
                    description=f"Network Reconnaissance: IP touched {len(unique_honeypots)} different honeypots ({', '.join(unique_honeypots)})"
                )
                telegram.send_alert(
                    severity='high', honeypot_name='Network Level', source_ip=ip,
                    event_type='recon_detected', honeypot_type='detector',
                    description=f"🚨 Lateral Movement / Scan: Source is probing multiple sensors ({len(unique_honeypots)} nodes)."
                )
                detected = True

            # 4. CONNECTION FLOOD / DoS (T1499)
            # 100+ total events in the 5-minute window = sustained flood from single source
            if len(events) >= 100:
                Alert.create(
                    severity='high', honeypot_name='system', honeypot_type='detector',
                    source_ip=ip, event_type='connection_flood_detected', mitre_id='T1499',
                    description=f"Endpoint DoS: {len(events)} events in 5 minutes from single source"
                )
                telegram.send_alert(
                    severity='high', honeypot_name='Network Level', source_ip=ip,
                    event_type='connection_flood_detected', honeypot_type='detector',
                    description=f"🚨 Connection Flood (T1499): {len(events)} events in 5 minutes."
                )
                detected = True

            if detected:
                self.ip_events[ip] = []

    def _watch_dionaea_binaries(self):
        """Poll Dionaea binary capture directory for new payloads and query VirusTotal."""
        from utils.virustotal import hash_file, query_virustotal, classify_binary

        binaries_path = config.DIONAEA_BINARIES_PATH
        if not binaries_path.exists():
            logger.info(f"Dionaea binaries path not found ({binaries_path}), binary watcher inactive.")
            return

        known_files = {f for f in binaries_path.glob('*') if f.is_file()}
        logger.info(f"Dionaea binary watcher started ({len(known_files)} existing files tracked).")

        while self.running:
            time.sleep(30)
            try:
                current_files = {f for f in binaries_path.glob('*') if f.is_file()}
                new_files = current_files - known_files
                for file_path in sorted(new_files):
                    self._process_dionaea_binary(file_path)
                known_files = current_files
            except Exception as e:
                logger.error(f"Dionaea binary watcher error: {e}")

    def _process_dionaea_binary(self, file_path: Path):
        from utils.virustotal import hash_file, query_virustotal, classify_binary
        try:
            sha256 = hash_file(file_path)

            if config.VIRUSTOTAL_API_KEY:
                vt_result = query_virustotal(sha256, config.VIRUSTOTAL_API_KEY)
                mitre_id, severity, description = classify_binary(vt_result, file_path)
                if mitre_id is None:
                    logger.info(f"Binary clean: {file_path.name}")
                    return
            else:
                # No VT key — still alert about the capture, just can't classify it
                mitre_id = 'T1203'
                severity = 'medium'
                description = f"Binary captured by Dionaea: {file_path.name} [SHA256: {sha256[:16]}…]"

            alert_id = Alert.create(
                severity=severity,
                honeypot_name='honey_dionaea',
                honeypot_type='dionaea',
                source_ip='unknown',
                event_type='binary_captured',
                mitre_id=mitre_id,
                description=f"[SHA256: {sha256[:16]}…] {description}",
                raw_data=str(file_path)
            )

            logger.info(f"Binary alert #{alert_id}: {file_path.name} → {mitre_id} ({severity})")

            if severity in ('critical', 'high'):
                telegram.send_alert(
                    severity=severity,
                    honeypot_name='honey_dionaea',
                    source_ip='unknown',
                    event_type='binary_captured',
                    honeypot_type='dionaea',
                    description=f"[{mitre_id}] {description}\nSHA256: {sha256}"
                )
                if alert_id:
                    Alert.mark_notified(alert_id)
        except Exception as e:
            logger.error(f"Error processing binary {file_path.name}: {e}")

    def watch_cycle(self):
        log_files = self.get_log_files()
        for log_file in log_files:
            parser = self.get_parser_for_file(log_file)
            try:
                relative_path = log_file.relative_to(self.log_path)
                honeypot_name = relative_path.parts[0]
                if not honeypot_name.startswith('honey_'):
                    honeypot_name = f"honey_{honeypot_name}"
            except ValueError:
                honeypot_name = log_file.parent.name
            
            new_lines = self.read_new_lines(log_file)
            for line in new_lines:
                line = line.strip()
                if not line: continue
                event = parser(line)
                if event: self.process_event(event, honeypot_name)
        
        # Check patterns after parsing logs
        self.check_attack_patterns()
    
    def run(self, interval: int = 2):
        self.running = True
        logger.info(f"Starting log watcher, monitoring: {self.log_path}")

        for log_file in self.get_log_files():
            try:
                with open(log_file, 'r') as f:
                    f.seek(0, 2)
                    self.file_positions[str(log_file)] = f.tell()
            except: pass

        binary_thread = threading.Thread(target=self._watch_dionaea_binaries, daemon=True)
        binary_thread.start()

        while self.running:
            try: self.watch_cycle()
            except Exception as e: logger.error(f"Watcher cycle error: {e}")
            time.sleep(interval)
    
    def stop(self): self.running = False


def cleanup_job():
    try: Alert.cleanup_old()
    except Exception as e: logger.error(f"Cleanup error: {e}")

def run_scheduler():
    schedule.every().day.at("03:00").do(cleanup_job)
    while True:
        schedule.run_pending()
        time.sleep(60)

def main():
    init_db()
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    
    watcher = LogWatcher(config.LOG_PATH)
    try: watcher.run()
    except KeyboardInterrupt:
        logger.info("Stopping watcher...")
        watcher.stop()

if __name__ == '__main__':
    main()
