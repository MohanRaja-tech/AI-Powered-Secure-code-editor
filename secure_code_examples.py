"""Secure implementations of common code patterns to avoid vulnerabilities."""

import os
import subprocess
import sqlite3
from typing import Any, Optional
import html
from pathlib import Path
from urllib.parse import quote
import secrets
import hashlib
import bcrypt
import logging
from contextlib import contextmanager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database operations
@contextmanager
def get_db_connection(db_path: str):
    """Secure database connection context manager."""
    conn = sqlite3.connect(db_path)
    try:
        yield conn
    finally:
        conn.close()

def secure_query(username: str, password: str) -> Optional[Any]:
    """Secure SQL query using parameterized statements."""
    with get_db_connection('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        )
        return cursor.fetchone()

def secure_update(user_id: int, data: dict) -> None:
    """Secure database update using parameterized queries."""
    with get_db_connection('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET name = ? WHERE id = ?",
            (data['name'], user_id)
        )
        conn.commit()

# File operations
def secure_file_read(filename: str, base_dir: str) -> str:
    """Secure file reading with path validation."""
    try:
        base_path = Path(base_dir).resolve()
        file_path = (base_path / filename).resolve()
        
        if not str(file_path).startswith(str(base_path)):
            raise ValueError("Access to file outside base directory denied")
            
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {filename}")
            
        return file_path.read_text()
    except Exception as e:
        logging.error(f"File read error: {e}")
        return ""

# Command execution
def secure_command_execution(command: list) -> bool:
    """Secure command execution using subprocess."""
    try:
        result = subprocess.run(
            command,
            shell=False,
            check=True,
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except subprocess.SubprocessError as e:
        logging.error(f"Command execution error: {e}")
        return False

# HTML output
def secure_html_render(user_data: dict) -> str:
    """Secure HTML rendering with proper escaping."""
    return f"<div>Name: {html.escape(user_data['name'])}</div>"

# Credential handling
def secure_credentials() -> dict:
    """Secure credential handling using environment variables."""
    return {
        'api_key': os.environ.get('API_KEY'),
        'password': os.environ.get('PASSWORD')
    }

# Password hashing
def secure_password_hash(password: str) -> str:
    """Secure password hashing using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

# Token generation
def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure token."""
    return secrets.token_urlsafe(length)

def main() -> None:
    """Example usage of secure functions."""
    try:
        # Example of secure SQL query
        user_data = secure_query("username", "password")
        
        # Example of secure file reading
        content = secure_file_read("config.txt", "/app/data")
        
        # Example of secure command execution
        success = secure_command_execution(["ls", "-l"])
        
        # Example of secure password handling
        hashed_password = secure_password_hash("user_password")
        
        # Example of secure token generation
        token = generate_secure_token()
        
        logger.info("All security operations completed successfully")
        
    except Exception as e:
        logger.error(f"Security operation failed: {e}")

if __name__ == "__main__":
    main()
