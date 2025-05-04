import os
import sys
import time
from typing import List, Dict, Any
from check_model import VulnerabilityScanner
import logging

# Configure logging to show in terminal
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',  # Only show the message, not the log level
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

class ModelTrainer:
    def __init__(self, model_path: str = None):
        """Initialize the model trainer.
        
        Args:
            model_path: Path to save/load the trained model
        """
        self.model_path = model_path or os.path.join(os.path.dirname(os.path.realpath(__file__)), "vulnerability_model.codex")
        self.scanner = VulnerabilityScanner()
        
    def train_with_default_examples(self) -> bool:
        """Train the model with default examples.
        
        Returns:
            bool: True if training was successful
        """
        try:
            print("\n=== Model Training Progress ===")
            print("1. Preparing training data...")
            time.sleep(0.5)  # Small delay to make progress visible
            
            # Example vulnerable code snippets
            vulnerable_examples = [
                # SQL Injection
                """def login(username, password):
                    conn = sqlite3.connect('users.db')
                    cursor = conn.cursor()
                    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
                    cursor.execute(query)
                    return cursor.fetchone()""",
                
                # Command Injection
                """def get_logs(date):
                    os.system("cat /var/log/app.log | grep " + date)""",
                
                # XSS
                """def render_profile(user_data):
                    template = "<div>Name: " + user_data['name'] + "</div>"
                    return template""",
                
                # Path Traversal
                """def read_file(filename):
                    with open(user_input + ".txt", "r") as f:
                        return f.read()""",
                
                # Hard-coded Credentials
                """def store_secret():
                    api_key = "12345secret_key_here"
                    password = "admin123"
                    return encrypt(api_key)""",
                
                # Insecure Deserialization
                """def insecure_deserialize(data):
                    return pickle.loads(data)""",
                
                # Weak Cryptography
                """def hash_password(password):
                    import hashlib
                    return hashlib.md5(password.encode()).hexdigest()"""
            ]
            
            print("2. Loading safe code examples...")
            time.sleep(0.5)
            
            # Example safe code snippets
            safe_examples = [
                # Safe SQL
                """def login(username, password):
                    conn = sqlite3.connect('users.db')
                    cursor = conn.cursor()
                    query = "SELECT * FROM users WHERE username = ? AND password = ?"
                    cursor.execute(query, (username, password))
                    return cursor.fetchone()""",
                
                # Safe Command Execution
                """def get_logs(date):
                    import subprocess
                    result = subprocess.run(['grep', date, '/var/log/app.log'], 
                                         capture_output=True, text=True, shell=False)
                    return result.stdout""",
                
                # Safe XSS Prevention
                """def render_profile(user_data):
                    from html import escape
                    template = f"<div>Name: {escape(user_data['name'])}</div>"
                    return template""",
                
                # Safe File Handling
                """def read_file(filename):
                    import os
                    safe_path = os.path.normpath(os.path.join('/safe/dir', filename))
                    if not safe_path.startswith('/safe/dir'):
                        raise ValueError("Invalid file path")
                    with open(safe_path, "r") as f:
                        return f.read()""",
                
                # Safe Credential Handling
                """def store_secret():
                    import os
                    api_key = os.getenv('API_KEY')
                    password = os.getenv('PASSWORD')
                    return encrypt(api_key)""",
                
                # Safe Deserialization
                """def secure_deserialize(data):
                    import json
                    return json.loads(data)""",
                
                # Strong Cryptography
                """def hash_password(password):
                    from hashlib import sha256
                    import os
                    salt = os.urandom(32)
                    return sha256(password.encode() + salt).hexdigest()"""
            ]
            
            print("3. Training model with examples...")
            time.sleep(0.5)
            
            # Train the model
            self.scanner.train(vulnerable_examples + safe_examples, 
                             [1] * len(vulnerable_examples) + [0] * len(safe_examples))
            
            print("4. Saving trained model...")
            time.sleep(0.5)
            
            # Save the model
            self.scanner.save_model(self.model_path)
            
            print("\n✓ Model training completed successfully!")
            print(f"Model saved to: {self.model_path}")
            return True
            
        except Exception as e:
            print(f"\n✗ Error during model training: {str(e)}")
            return False

def train_model_in_background():
    """Train the model in the background before starting the GUI."""
    trainer = ModelTrainer()
    return trainer.train_with_default_examples() 