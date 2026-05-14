"""
HoneyManager Database Models
SQLite models for alerts and honeypot tracking
"""
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any
from config import config
from werkzeug.security import generate_password_hash, check_password_hash

def get_db_connection():
    """Get SQLite database connection"""
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(config.DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database tables"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Alerts table 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            severity TEXT NOT NULL,
            honeypot_name TEXT NOT NULL,
            honeypot_type TEXT,
            source_ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            mitre_id TEXT,
            description TEXT,
            raw_data TEXT,
            notified BOOLEAN DEFAULT FALSE
        )
    ''')
    
    # Critical alerts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS critical_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            alert_id INTEGER,
            honeypot_name TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            mitre_id TEXT,
            description TEXT,
            raw_data TEXT,
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        )
    ''')
    
    # Honeypot nodes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS honeypot_nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            container_id TEXT UNIQUE,
            name TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            honeypot_type TEXT NOT NULL,
            status TEXT DEFAULT 'running',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)')
    
    # Users table (for RBAC)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    
    # Settings table (for Telegram API etc. settings)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')

    # if there are no users, create admin account
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        default_password = getattr(config, 'ADMIN_PASSWORD', 'admin123')
        default_hash = generate_password_hash(default_password)
        cursor.execute(
            'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
            ('admin', default_hash, 'admin')
        )
        print(f"Default admin user created. Username: admin")
    
    conn.commit()
    conn.close()


class Alert:
    SEVERITY_CRITICAL = 'critical'
    SEVERITY_HIGH = 'high'
    SEVERITY_MEDIUM = 'medium'
    SEVERITY_LOW = 'low'
    
    @staticmethod
    def create(
        severity: str,
        honeypot_name: str,
        source_ip: str,
        event_type: str,
        honeypot_type: str = None,
        mitre_id: str = None,
        description: str = None,
        raw_data: str = None
    ) -> int:
        """Create new alert and return ID"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        try:
            cursor.execute('''
                INSERT INTO alerts (timestamp, severity, honeypot_name, honeypot_type, source_ip, event_type, mitre_id, description, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (current_time, severity, honeypot_name, honeypot_type, source_ip, event_type, mitre_id, description, raw_data))
            
            alert_id = cursor.lastrowid
            
            if severity == Alert.SEVERITY_CRITICAL:
                cursor.execute('''
                    INSERT INTO critical_alerts (timestamp, alert_id, honeypot_name, source_ip, event_type, mitre_id, description, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (current_time, alert_id, honeypot_name, source_ip, event_type, mitre_id, description, raw_data))
            
            conn.commit()
            return alert_id
        except Exception as e:
            print(f"Database error: {e}")
            return None
        finally:
            conn.close()
    
    @staticmethod
    def get_recent(hours: int = 24, limit: int = 100, severity: str = None) -> List[Dict]:
        """Get recent alerts, optionally filtered by severity tier."""
        conn = get_db_connection()
        cursor = conn.cursor()

        since = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')

        if severity == 'critical':
            cursor.execute('''
                SELECT * FROM alerts
                WHERE timestamp > ? AND severity = 'critical'
                ORDER BY id DESC LIMIT ?
            ''', (since, limit))
        elif severity == 'high':
            cursor.execute('''
                SELECT * FROM alerts
                WHERE timestamp > ? AND severity IN ('critical', 'high')
                ORDER BY id DESC LIMIT ?
            ''', (since, limit))
        else:
            cursor.execute('''
                SELECT * FROM alerts
                WHERE timestamp > ?
                ORDER BY id DESC LIMIT ?
            ''', (since, limit))

        alerts = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return alerts
    
    @staticmethod
    def get_stats() -> Dict[str, Any]:
        """Get alert statistics for dashboard"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        now = datetime.now()
        last_24h = (now - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        last_7d = (now - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute('SELECT COUNT(*) FROM alerts WHERE timestamp > ?', (last_24h,))
        total_24h = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM alerts WHERE timestamp > ?', (last_7d,))
        total_7d = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT severity, COUNT(*) as count 
            FROM alerts 
            WHERE timestamp > ? 
            GROUP BY severity
        ''', (last_24h,))
        by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}
        
        cursor.execute('''
            SELECT honeypot_name, COUNT(*) as count 
            FROM alerts 
            WHERE timestamp > ? 
            GROUP BY honeypot_name
        ''', (last_24h,))
        by_honeypot = {row['honeypot_name']: row['count'] for row in cursor.fetchall()}
        
        cursor.execute('''
            SELECT COUNT(DISTINCT source_ip) FROM alerts WHERE timestamp > ?
        ''', (last_24h,))
        unique_ips = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_24h': total_24h,
            'total_7d': total_7d,
            'by_severity': by_severity,
            'by_honeypot': by_honeypot,
            'unique_ips_24h': unique_ips,
            'critical': by_severity.get('critical', 0),
            'high': by_severity.get('high', 0),
            'medium': by_severity.get('medium', 0),
            'low': by_severity.get('low', 0)
        }
    
    @staticmethod
    def get_timeline(hours: int = 24) -> Dict:
        """Get per-15-minute alert counts for the last N hours, grouped by severity."""
        conn = get_db_connection()
        cursor = conn.cursor()

        now = datetime.now()
        since = now - timedelta(hours=hours)

        cursor.execute('''
            SELECT
                strftime('%Y-%m-%d %H', timestamp) || ':' ||
                printf('%02d', (CAST(strftime('%M', timestamp) AS INTEGER) / 15) * 15) AS bucket,
                severity,
                COUNT(*) AS count
            FROM alerts
            WHERE timestamp > ?
            GROUP BY bucket, severity
        ''', (since.strftime('%Y-%m-%d %H:%M:%S'),))

        rows = cursor.fetchall()
        conn.close()

        bucket_data = {}
        for row in rows:
            b = row['bucket']
            if b not in bucket_data:
                bucket_data[b] = {}
            bucket_data[b][row['severity']] = row['count']

        # Snap since down to the nearest 15-minute boundary so buckets align with SQL grouping
        snap = since - timedelta(
            minutes=since.minute % 15,
            seconds=since.second,
            microseconds=since.microsecond
        )

        labels = []
        datasets = {'critical': [], 'high': [], 'medium': [], 'low': []}

        for i in range(hours * 4):  # 96 buckets for 24 h
            t = snap + timedelta(minutes=i * 15)
            bucket_key = t.strftime('%Y-%m-%d %H:') + f'{t.minute:02d}'
            labels.append(t.strftime('%H:%M'))
            h = bucket_data.get(bucket_key, {})
            for sev in ['critical', 'high', 'medium', 'low']:
                datasets[sev].append(h.get(sev, 0))

        return {'labels': labels, 'datasets': datasets}

    @staticmethod
    def cleanup_old(days: int = None):
        """Delete alerts older than retention period"""
        if days is None:
            days = config.LOG_RETENTION_DAYS
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cutoff = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('DELETE FROM alerts WHERE timestamp < ?', (cutoff,))
        deleted = cursor.rowcount
        
        cursor.execute('VACUUM')
        conn.commit()
        conn.close()
        return deleted
    
    @staticmethod
    def mark_notified(alert_id: int):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE alerts SET notified = TRUE WHERE id = ?', (alert_id,))
        conn.commit()
        conn.close()

class User:
    ROLE_ADMIN = 'admin'
    ROLE_OPERATOR = 'operator'
    ROLE_VIEWER = 'viewer'

    @staticmethod
    def authenticate(username, password):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            return dict(user)
        return None

    @staticmethod
    def create(username, password, role):
        conn = get_db_connection()
        cursor = conn.cursor()
        password_hash = generate_password_hash(password)
        try:
            cursor.execute(
                'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                (username, password_hash, role)
            )
            conn.commit()
            return True, "User created successfully"
        except sqlite3.IntegrityError:
            return False, "Username already exists"
        except Exception as e:
            return False, str(e)
        finally:
            conn.close()

    @staticmethod
    def get_all():
        conn = get_db_connection()
        cursor = conn.cursor()
        # Şifre hash'lerini frontende göndermemek için seçmiyoruz
        cursor.execute('SELECT id, username, role FROM users')
        users = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return users

    @staticmethod
    def delete(user_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted > 0

class Setting:
    @staticmethod
    def get(key, default=None):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
        row = cursor.fetchone()
        conn.close()
        return row['value'] if row else default

    @staticmethod
    def set(key, value):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO settings (key, value) 
            VALUES (?, ?) 
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        ''', (key, value))
        conn.commit()
        conn.close()
        
# Initialize database on import
init_db()
