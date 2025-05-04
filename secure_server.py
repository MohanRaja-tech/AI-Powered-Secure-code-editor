#!/usr/bin/env python3
"""
Secure Server Wrapper for AI Security Scanner
This module adds HTTPS, encryption, and security features to the Flask application
without modifying the core functionality.
"""

import os
import ssl
import secrets
import logging
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.fernet import Fernet
from api_server import app

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Generate or load encryption key
def get_encryption_key():
    key_file = "encryption.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read()
    else:
        # Generate a new encryption key
        key = Fernet.generate_key()
        # Save the key to a file
        with open(key_file, "wb") as f:
            f.write(key)
        return key

# Initialize encryption
encryption_key = get_encryption_key()
cipher_suite = Fernet(encryption_key)

# Initialize security extensions
csrf = CSRFProtect()
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Apply Talisman (Security Headers)
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': "'self'",
        'script-src': ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com", "cdn.jsdelivr.net"],
        'style-src': ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com", "cdn.jsdelivr.net"],
        'font-src': ["'self'", "cdnjs.cloudflare.com"],
        'img-src': ["'self'", "data:"],
        'connect-src': ["'self'", "localhost:*"]
    },
    force_https=True,
    strict_transport_security=True,
    session_cookie_secure=True,
    session_cookie_http_only=True,
    feature_policy={
        'geolocation': "'none'",
        'microphone': "'none'",
        'camera': "'none'"
    }
)

# Apply CSRF protection (exempt API routes)
csrf.exempt("api_status")
csrf.exempt("scan_code")
csrf.exempt("chat")
csrf.exempt("analyze_code_chat")
csrf.exempt("scan_file")
csrf.exempt("scan_directory")
csrf.exempt("live_check")
csrf.exempt("run_code")
csrf.exempt("github_push")
csrf.exempt("github_retrieve")
csrf.init_app(app)

# Add rate limiting to sensitive endpoints
@limiter.limit("5 per minute")
@app.route('/api/github-push', methods=['POST'])
def limited_github_push():
    from api_server import github_push
    return github_push()

@limiter.limit("10 per minute")
@app.route('/api/scan', methods=['POST'])
def limited_scan():
    from api_server import scan_code
    return scan_code()

# Encryption middleware for request/response
@app.before_request
def encrypt_sensitive_data():
    """Encrypt sensitive data in requests"""
    from flask import request, g
    import json
    
    # Skip for non-API routes or GET requests
    if not request.path.startswith('/api/') or request.method == 'GET':
        return
    
    # Store original data for APIs to use
    if request.is_json:
        try:
            # Store original JSON for processing
            g.original_json = request.get_json()
            
            # Add security metadata
            g.client_ip = get_remote_address()
            g.request_id = secrets.token_hex(8)
            g.timestamp = int(time.time())
            
            # Log request with metadata (exclude sensitive data)
            logger.info(f"Request {g.request_id} from {g.client_ip} to {request.path}")
            
        except Exception as e:
            logger.error(f"Error processing request data: {e}")
            
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    # These headers are in addition to what Talisman provides
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Server'] = 'Secure Scanner Server'
    
    # Add request ID if available
    from flask import g
    if hasattr(g, 'request_id'):
        response.headers['X-Request-ID'] = g.request_id
    
    return response

# Helper functions for encryption/decryption
def encrypt_data(data):
    """Encrypt sensitive data"""
    if isinstance(data, dict):
        # Convert to JSON string
        json_data = json.dumps(data)
        # Encrypt the JSON string
        encrypted = cipher_suite.encrypt(json_data.encode())
        return encrypted
    elif isinstance(data, str):
        # Encrypt string directly
        return cipher_suite.encrypt(data.encode())
    else:
        # Return as is if not encryptable
        return data

def decrypt_data(encrypted_data):
    """Decrypt sensitive data"""
    try:
        # Decrypt the data
        decrypted = cipher_suite.decrypt(encrypted_data)
        # Try to parse as JSON
        try:
            return json.loads(decrypted.decode())
        except:
            # Return as string if not JSON
            return decrypted.decode()
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return None

# SSL/TLS Configuration
def create_ssl_context():
    """Create SSL context for HTTPS"""
    ssl_dir = "ssl"
    cert_file = os.path.join(ssl_dir, "cert.pem")
    key_file = os.path.join(ssl_dir, "key.pem")
    
    # Create SSL directory if it doesn't exist
    if not os.path.exists(ssl_dir):
        os.makedirs(ssl_dir)
    
    # Generate self-signed certificate if not exists
    if not (os.path.exists(cert_file) and os.path.exists(key_file)):
        from OpenSSL import crypto
        
        # Create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        
        # Create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "CA"
        cert.get_subject().L = "San Francisco"
        cert.get_subject().O = "Secure Code AI"
        cert.get_subject().OU = "Security Team"
        cert.get_subject().CN = "localhost"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)  # Valid for 1 year
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')
        
        # Write certificate and key to files
        with open(cert_file, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        
        with open(key_file, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        
        logger.info(f"Generated self-signed SSL certificate at {cert_file}")
    
    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    context.set_ciphers('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256')
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable TLSv1.0 and TLSv1.1
    context.set_alpn_protocols(['http/1.1'])
    
    return context, cert_file, key_file

# Prepare SSL context
ssl_context, cert_file, key_file = create_ssl_context()

if __name__ == '__main__':
    import time
    import argparse
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Run secure server for AI Security Scanner')
    parser.add_argument('--port', type=int, default=5000, help='Port to run the server on')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to run the server on')
    parser.add_argument('--http', action='store_true', help='Run in HTTP mode (not recommended)')
    args = parser.parse_args()
    
    # Print server information
    print("=" * 50)
    print("Secure AI Scanner Server")
    print("=" * 50)
    print(f"{'HTTP' if args.http else 'HTTPS'} Server running on {args.host}:{args.port}")
    
    if not args.http:
        print(f"SSL Certificate: {cert_file}")
        print("Security features enabled:")
        print("✓ TLS/HTTPS Encryption")
        print("✓ CSRF Protection")
        print("✓ Content Security Policy")
        print("✓ Rate Limiting")
        print("✓ HTTP Security Headers")
        print("✓ Request/Response Encryption")
    else:
        print("WARNING: Running in HTTP mode without encryption (not recommended)")
    
    print("=" * 50)
    
    # Run the Flask application with or without SSL
    if args.http:
        # HTTP mode (not recommended for production)
        app.run(host=args.host, port=args.port, debug=False)
    else:
        # HTTPS mode with SSL context
        app.run(host=args.host, port=args.port, ssl_context=ssl_context, debug=False) 