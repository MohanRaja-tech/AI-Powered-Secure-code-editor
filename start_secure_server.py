#!/usr/bin/env python3
"""
Secure Startup Script for AI Security Scanner
This script starts the secure server with proper configurations and security settings.
"""

import os
import sys
import argparse
import logging
import subprocess
import time
import atexit
import ssl
import signal
from typing import List, Optional, Callable

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('secure_server.log')
    ]
)
logger = logging.getLogger(__name__)

# Constants
DEFAULT_PORT = 5000
DEFAULT_HOST = "0.0.0.0"
SSL_DIR = "ssl"
CERT_FILE = os.path.join(SSL_DIR, "cert.pem")
KEY_FILE = os.path.join(SSL_DIR, "key.pem")
PID_FILE = "secure_server.pid"

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Start the Secure AI Security Scanner Server')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Port to run the server on')
    parser.add_argument('--host', type=str, default=DEFAULT_HOST, help='Host to run the server on')
    parser.add_argument('--http', action='store_true', help='Run in HTTP mode (not recommended)')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode (not recommended for production)')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon (background process)')
    parser.add_argument('--stop', action='store_true', help='Stop a running daemon instance')
    parser.add_argument('--restart', action='store_true', help='Restart a running daemon instance')
    parser.add_argument('--status', action='store_true', help='Check if daemon is running')
    
    return parser.parse_args()

def is_server_running() -> bool:
    """Check if server is already running as daemon"""
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                pid = int(f.read().strip())
            
            # Check if process with this PID exists
            os.kill(pid, 0)  # This will raise an exception if process doesn't exist
            return True
        except (OSError, ValueError):
            # Process not running or PID file is invalid
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)
            return False
    return False

def stop_server() -> bool:
    """Stop running server daemon"""
    if not os.path.exists(PID_FILE):
        logger.error("No PID file found. Server may not be running as daemon.")
        return False
    
    try:
        with open(PID_FILE, 'r') as f:
            pid = int(f.read().strip())
        
        # First try SIGTERM for graceful shutdown
        logger.info(f"Stopping server with PID {pid}...")
        os.kill(pid, signal.SIGTERM)
        
        # Wait up to 5 seconds for process to exit
        for _ in range(10):
            try:
                os.kill(pid, 0)  # Check if process still exists
                time.sleep(0.5)
            except OSError:
                # Process is gone
                if os.path.exists(PID_FILE):
                    os.remove(PID_FILE)
                logger.info("Server stopped successfully")
                return True
        
        # If still running, send SIGKILL
        logger.warning("Server didn't stop gracefully, using SIGKILL")
        os.kill(pid, signal.SIGKILL)
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        return True
        
    except (OSError, ValueError) as e:
        logger.error(f"Error stopping server: {e}")
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
        return False

def daemonize() -> None:
    """Daemonize the current process"""
    try:
        # First fork
        pid = os.fork()
        if pid > 0:
            # Exit first parent
            sys.exit(0)
    except OSError as e:
        logger.error(f"Fork #1 failed: {e}")
        sys.exit(1)
    
    # Decouple from parent environment
    os.chdir('/')
    os.setsid()
    os.umask(0)
    
    try:
        # Second fork
        pid = os.fork()
        if pid > 0:
            # Exit from second parent
            sys.exit(0)
    except OSError as e:
        logger.error(f"Fork #2 failed: {e}")
        sys.exit(1)
    
    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    
    si = open(os.devnull, 'r')
    so = open('secure_server.log', 'a+')
    se = open('secure_server.err', 'a+')
    
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())
    
    # Write PID file
    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))
    
    # Register cleanup function
    atexit.register(lambda: os.path.exists(PID_FILE) and os.remove(PID_FILE))

def check_dependencies() -> bool:
    """Check if all required dependencies are installed"""
    try:
        # Import required modules
        import flask
        import flask_cors
        import flask_talisman
        import flask_wtf
        import flask_limiter
        from cryptography.fernet import Fernet
        import ssl
        
        # Check for custom modules
        import secure_server
        import data_security
        import api_security
        
        return True
    except ImportError as e:
        logger.error(f"Missing dependency: {e}")
        logger.error("Please install all required dependencies: pip install -r requirements_secure.txt")
        return False

def main():
    """Main function to start the secure server"""
    args = parse_arguments()
    
    # Handle daemon control commands
    if args.stop:
        if stop_server():
            logger.info("Server stopped successfully")
        else:
            logger.error("Failed to stop server or server was not running")
        return
    
    if args.status:
        if is_server_running():
            with open(PID_FILE, 'r') as f:
                pid = f.read().strip()
            logger.info(f"Server is running with PID {pid}")
        else:
            logger.info("Server is not running")
        return
    
    if args.restart:
        if is_server_running():
            stop_server()
            time.sleep(1)  # Allow time for shutdown
        # Continue to start server
    else:
        # Check if server is already running
        if is_server_running():
            logger.error("Server is already running. Use --restart to restart or --stop to stop it.")
            return
    
    # Check dependencies
    if not check_dependencies():
        logger.error("Missing dependencies. Please install all required packages.")
        return
    
    # Prepare command and arguments
    cmd = [
        sys.executable,
        "secure_server.py",
        "--port", str(args.port),
        "--host", args.host
    ]
    
    if args.http:
        cmd.append("--http")
    
    if args.debug:
        cmd.append("--debug")
    
    # Run as daemon if requested
    if args.daemon:
        logger.info("Starting server as daemon...")
        daemonize()
    
    # Print server information
    logger.info("=" * 50)
    logger.info("Secure AI Scanner Server")
    logger.info("=" * 50)
    logger.info(f"{'HTTP' if args.http else 'HTTPS'} Server starting on {args.host}:{args.port}")
    
    if not args.http:
        logger.info(f"SSL Certificate: {CERT_FILE}")
        logger.info("Security features enabled:")
        logger.info("✓ TLS/HTTPS Encryption")
        logger.info("✓ CSRF Protection")
        logger.info("✓ Content Security Policy")
        logger.info("✓ Rate Limiting")
        logger.info("✓ HTTP Security Headers")
        logger.info("✓ Request/Response Encryption")
    else:
        logger.warning("Running in HTTP mode without encryption (not recommended)")
    
    logger.info("=" * 50)
    
    if args.daemon:
        # If running as daemon, execute directly
        import secure_server
    else:
        # Otherwise, run as subprocess (allows Ctrl+C to work properly)
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
        except Exception as e:
            logger.error(f"Server error: {e}")

if __name__ == "__main__":
    main() 