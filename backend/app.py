"""
HoneyManager - Flask API Backend
Honeypot orchestration and monitoring API
"""
import os
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from flask import Flask, jsonify, request, send_from_directory, session,  make_response
from functools import wraps
from flask_cors import CORS
from datetime import datetime
import logging

from config import config
from models import Alert, Alert, User, Setting, init_db
from utils.docker_manager import docker_manager
from utils.telegram_notifier import create_notifier
from utils import network_utils



# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, static_folder='../frontend', static_url_path='')
app.secret_key = config.SECRET_KEY
CORS(app)

# Initialize Telegram notifier
telegram = create_notifier()

# Authentication & Role Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    """
    It checks whether the user has one of the roles.
    Example: @role_required(['admin', 'operator'])
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_role = session.get('role')
            if user_role not in roles:
                return jsonify({'success': False, 'error': 'Forbidden: Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Static Files
@app.route('/')
def index():
    """Serve frontend dashboard"""
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/<path:path>')
def static_files(path):
    """Serve static files"""
    return send_from_directory(app.static_folder, path)


# API: Authentication
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    client_ip = request.remote_addr
    
    user = User.authenticate(username, password)
    
    if user:
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        session['logged_in'] = True
        
        logger.info(f"User login successful: {username} from {client_ip}")
        return jsonify({
            'success': True, 
            'user': {
                'username': user['username'],
                'role': user['role']
            }
        })
    
    if telegram.enabled:
        message = f"🚨 <b>UNAUTHORIZED LOGIN ATTEMPT!</b>\n\nIP: {client_ip}\nUser: {username}\nTime: {datetime.now().strftime('%H:%M:%S')}"
        telegram.send_message(message)

    return jsonify({'success': False, 'error': 'Invalid username or password'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    session.permanent = False
    
    response = make_response(jsonify({'success': True}))
    response.set_cookie('session', '', expires=0) 
    return response

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    """Oturum durumunu kontrol eder ve önbelleğe alınmasını engeller"""
    response_data = {'authenticated': False}
    status_code = 401

    if session.get('user_id'):
        response_data = {
            'authenticated': True,
            'user': {
                'username': session.get('username'),
                'role': session.get('role')
            }
        }
        status_code = 200

    response = make_response(jsonify(response_data), status_code)
    # Önbelleği tamamen kapat (Özellikle Chrome için kritik)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response
    
# Admin can add and delete users:
@app.route('/api/users', methods=['GET'])
@login_required
@role_required(['admin'])
def list_users():
    users = User.get_all()
    return jsonify({'success': True, 'users': users})

@app.route('/api/users', methods=['POST'])
@login_required
@role_required(['admin'])
def add_user():
    data = request.get_json()
    success, message = User.create(data.get('username'), data.get('password'), data.get('role'))
    return jsonify({'success': success, 'message': message if success else None, 'error': message if not success else None})

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
@role_required(['admin'])
def delete_user(user_id):
    if session.get('user_id') == user_id:
        return jsonify({'success': False, 'error': 'You cannot delete yourself'}), 400
    success = User.delete(user_id)
    return jsonify({'success': success})

# API: Health & Status
@app.route('/api/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })


# API: Network Verification
@app.route('/api/verify-ip/<ip>', methods=['GET'])
@login_required
@role_required(['admin', 'operator'])
def verify_ip(ip):
    """Verify if IP is available"""
    try:
        # Check matching format
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'available': False, 'message': 'Invalid IP format'}), 400
            
        # Check Docker used IPs
        used_ips = network_utils.get_used_ips()
        if ip in used_ips:
             from config import config
             if ip == config.GATEWAY:
                 return jsonify({'available': False, 'message': 'IP is the Network Gateway (Reserved)'}), 200
             return jsonify({'available': False, 'message': 'IP already assigned to a container'}), 200
             
        # Check reachability
        reachable = network_utils.is_ip_reachable(ip)
        if reachable:
            return jsonify({'available': False, 'message': 'IP is responding to ping (In Use)'}), 200
            
        return jsonify({'available': True, 'message': 'IP appears free'}), 200
        
    except Exception as e:
        logger.error(f"Error verifying IP: {e}")
        return jsonify({'available': False, 'message': str(e)}), 500


@app.route('/api/stats')
@login_required
@role_required(['admin', 'operator', 'viewer'])
def get_stats():
    """Get dashboard statistics"""
    try:
        stats = Alert.get_stats()
        honeypots = docker_manager.list_honeypots()

        return jsonify({
            'success': True,
            'alerts': stats,
            'honeypots': {
                'total': len(honeypots),
                'running': len([h for h in honeypots if h['status'] == 'running']),
                'stopped': len([h for h in honeypots if h['status'] != 'running'])
            }
        })
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/stats/timeline')
@login_required
@role_required(['admin', 'operator', 'viewer'])
def get_timeline():
    """Get hourly alert counts for the last 24 hours, used for dashboard charts"""
    try:
        timeline = Alert.get_timeline()
        return jsonify({'success': True, 'timeline': timeline})
    except Exception as e:
        logger.error(f"Error getting timeline: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# API: Honeypot Nodes
@app.route('/api/nodes', methods=['GET'])
@login_required
@role_required(['admin', 'operator', 'viewer'])
def list_nodes():
    """List all honeypot containers"""
    try:
        honeypots = docker_manager.list_honeypots()
        return jsonify({
            'success': True,
            'nodes': honeypots,
            'count': len(honeypots)
        })
    except Exception as e:
        logger.error(f"Error listing nodes: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/nodes', methods=['POST'])
@login_required
@role_required(['admin', 'operator'])
def create_node():
    """Launch a new honeypot container"""
    try:
        data = request.get_json()
        logger.info(f"Create Node Request Data: {data}")
        
        # Validate required fields
        name = data.get('name')
        ip_address = data.get('ip_address')
        honeypot_type = data.get('honeypot_type') or data.get('type')
        
        if not name or not honeypot_type:
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
            
        profile = config.HONEYPOT_PROFILES.get(honeypot_type)
        if not profile:
            return jsonify({'success': False, 'error': 'Invalid honeypot type'}), 400

        # Dynamic IP Assignment
        if not ip_address:
            try:
                ip_address = network_utils.find_free_ip()
                logger.info(f"Assigned dynamic IP: {ip_address}")
            except Exception as e:
                return jsonify({'success': False, 'error': f'Failed to assign dynamic IP: {e}'}), 500
        else:
            # Validate manually provided IP
            # Check if used by Docker
            used_ips = network_utils.get_used_ips()
            if ip_address in used_ips:
                return jsonify({'success': False, 'error': f'IP {ip_address} is already assigned to another honeypot'}), 400
                
            # Check if reachable on network (Ping)
            if network_utils.is_ip_reachable(ip_address):
                return jsonify({'success': False, 'error': f'IP {ip_address} is in use on the network (Ping response)'}), 400
        
        # Create log directory
        log_dir = config.LOG_PATH / name
        log_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(log_dir, 0o777)
        except Exception:
            pass 
        
        entrypoint = None
        log_path = '/var/log/honeypot'  # Default log path
        
        if honeypot_type == 'custom-iot':
            entrypoint = ['/bin/sh', '-c', '/start.sh']
            log_path = '/var/log'  # Custom IoT uses syslog in /var/log/messages
        elif honeypot_type == 'cowrie':
            log_path = '/cowrie/var/log/cowrie'  # Cowrie's log directory
        elif honeypot_type == 'dionaea':
            log_path = '/opt/dionaea/var/log'  # Dionaea log directory
            
        # Prepare extra volumes
        extra_volumes = {}
        if honeypot_type == 'dionaea':
            config_path = config.BASE_DIR / 'data/configs/dionaea.cfg'
            if config_path.exists():
                extra_volumes[str(config_path)] = {
                    'bind': '/opt/dionaea/etc/dionaea/dionaea.cfg',
                    'mode': 'ro'
                }
        
        # Create container
        result = docker_manager.create_honeypot(
            name=name,
            ip_address=ip_address,
            honeypot_type=honeypot_type,
            image=profile['image'],
            role=profile['role'],
            ports=profile['ports'],
            log_path=log_path,
            host_log_path=str(log_dir),
            extra_volumes=extra_volumes,
            entrypoint=entrypoint,
            build_path=profile.get('build_path')
        )
        
        if result['success']:
            logger.info(f"Created honeypot: {name} ({ip_address})")
        
        return jsonify(result), 201 if result['success'] else 400
        
    except Exception as e:
        logger.error(f"Error creating node: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/nodes/<container_id>', methods=['DELETE'])
@login_required
@role_required(['admin'])
def delete_node(container_id):
    """Delete a honeypot container"""
    try:
        result = docker_manager.delete_honeypot(container_id)
        return jsonify(result), 200 if result['success'] else 404
    except Exception as e:
        logger.error(f"Error deleting node: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/nodes/<container_id>/start', methods=['POST'])
@login_required
@role_required(['admin', 'operator'])
def start_node(container_id):
    """Start a stopped honeypot"""
    try:
        result = docker_manager.start_honeypot(container_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/nodes/<container_id>/stop', methods=['POST'])
@login_required
@role_required(['admin', 'operator'])
def stop_node(container_id):
    """Stop a running honeypot"""
    try:
        result = docker_manager.stop_honeypot(container_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/nodes/<container_id>/logs', methods=['GET'])
@login_required
@role_required(['admin', 'operator', 'viewer'])
def get_node_logs(container_id):
    """Get container logs"""
    try:
        tail = request.args.get('tail', 100, type=int)
        logs = docker_manager.get_container_logs(container_id, tail=tail)
        return jsonify({'success': True, 'logs': logs})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# API: Profiles
@app.route('/api/profiles', methods=['GET'])
@login_required
@role_required(['admin', 'operator', 'viewer'])
def get_profiles():
    """Get available honeypot profiles"""
    return jsonify({
        'success': True,
        'profiles': config.HONEYPOT_PROFILES
    })


# API: Alerts & Logs
@app.route('/api/logs', methods=['GET'])
@login_required
@role_required(['admin', 'operator', 'viewer'])
def get_logs():
    """Get recent alerts"""
    try:
        hours = request.args.get('hours', 24, type=int)
        limit = request.args.get('limit', 100, type=int)
        severity = request.args.get('severity', None)

        alerts = Alert.get_recent(hours=hours, limit=limit, severity=severity)
        
        return jsonify({
            'success': True,
            'alerts': alerts,
            'count': len(alerts)
        })
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/logs/cleanup', methods=['POST'])
@login_required
@role_required(['admin'])
def cleanup_logs():
    """Manually trigger log cleanup"""
    try:
        days = request.json.get('days', config.LOG_RETENTION_DAYS) if request.json else config.LOG_RETENTION_DAYS
        deleted = Alert.cleanup_old(days)
        return jsonify({
            'success': True,
            'deleted': deleted,
            'message': f'Deleted {deleted} alerts older than {days} days'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# API: Telegram
@app.route('/api/test-telegram', methods=['POST'])
@login_required
@role_required(['admin'])
def test_telegram():
    """Send a test Telegram notification"""
    try:
        result = telegram.send_test_message()
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
        

# Retrieve and update Telegram information from the database.
@app.route('/api/settings/telegram', methods=['GET'])
@login_required
@role_required(['admin'])
def get_telegram_settings():
    config_data = {
        'bot_token': Setting.get('telegram_bot_token', config.TELEGRAM_BOT_TOKEN),
        'chat_id': Setting.get('telegram_chat_id', config.TELEGRAM_CHAT_ID)
    }
    return jsonify({'success': True, 'config': config_data})

@app.route('/api/settings/telegram', methods=['POST'])
@login_required
@role_required(['admin'])
def update_telegram_settings():
    data = request.get_json()
    Setting.set('telegram_bot_token', data.get('bot_token'))
    Setting.set('telegram_chat_id', data.get('chat_id'))
    
    telegram.bot_token = data.get('bot_token')
    telegram.chat_id = data.get('chat_id')
    telegram.enabled = bool(telegram.bot_token and telegram.chat_id)
    
    return jsonify({'success': True})

# API: Configuration
@app.route('/api/config', methods=['GET'])
@login_required
@role_required(['admin', 'operator', 'viewer'])
def get_config():
    """Get current configuration (non-sensitive)"""
    return jsonify({
        'success': True,
        'config': {
            'network': config.MACVLAN_NETWORK,
            'subnet': config.SUBNET,
            'gateway': config.GATEWAY,
            'log_retention_days': config.LOG_RETENTION_DAYS,
            'default_ips': config.DEFAULT_IPS,
            'telegram_configured': bool(config.TELEGRAM_BOT_TOKEN)
        }
    })

# the session is automatically deleted when the browser is closed.
app.config.update(
    SESSION_PERMANENT=False, 
)

# Error Handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({'success': False, 'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({'success': False, 'error': 'Internal server error'}), 500


# Main
if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Send startup notification
    #if telegram.enabled:
        #telegram.send_startup_message()
    
   # logger.info(f"Starting HoneyManager API on {config.HOST}:{config.PORT}")
    
    app.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG
    )
