#!/usr/bin/env python3
"""
Data Security Module for AI Security Scanner
This module provides data encryption, protection, and security features
for sensitive data handled by the application.
"""

import os
import base64
import json
import time
import secrets
import hashlib
from typing import Any, Dict, Union, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Constants
AES_BLOCK_SIZE = 16
DEFAULT_KEY_DIR = "security_keys"
RSA_KEY_SIZE = 2048
PBKDF2_ITERATIONS = 100000

class SecurityLayer:
    """
    Security layer implementing the OSI model layers 5-7 (Session, Presentation, Application)
    for data protection in the AI Security Scanner.
    """
    
    def __init__(self, key_dir: str = DEFAULT_KEY_DIR):
        """Initialize the security layer with keys"""
        self.key_dir = key_dir
        self._ensure_key_dir()
        
        # Initialize encryption keys
        self.symmetric_key = self._load_or_generate_symmetric_key()
        self.fernet = Fernet(self.symmetric_key)
        self.rsa_private_key, self.rsa_public_key = self._load_or_generate_rsa_keys()
        
        # Initialize security features
        self.request_registry = {}  # Tracks requests to prevent replay attacks
        self.nonce_registry = set()  # Tracks used nonces
    
    def _ensure_key_dir(self) -> None:
        """Ensure the key directory exists"""
        if not os.path.exists(self.key_dir):
            os.makedirs(self.key_dir)
    
    def _load_or_generate_symmetric_key(self) -> bytes:
        """Load or generate a symmetric encryption key for Fernet"""
        key_path = os.path.join(self.key_dir, "symmetric.key")
        
        if os.path.exists(key_path):
            # Load existing key
            with open(key_path, "rb") as f:
                return f.read()
        else:
            # Generate a new key
            key = Fernet.generate_key()
            with open(key_path, "wb") as f:
                f.write(key)
            return key
    
    def _load_or_generate_rsa_keys(self) -> tuple:
        """Load or generate RSA key pair for asymmetric encryption"""
        private_key_path = os.path.join(self.key_dir, "rsa_private.pem")
        public_key_path = os.path.join(self.key_dir, "rsa_public.pem")
        
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            # Load existing keys
            from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
            
            with open(private_key_path, "rb") as f:
                private_key = load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            
            with open(public_key_path, "rb") as f:
                public_key = load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            
            return private_key, public_key
        else:
            # Generate new keys
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                PrivateFormat,
                PublicFormat,
                NoEncryption
            )
            
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=RSA_KEY_SIZE,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            
            # Save private key
            with open(private_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=Encoding.PEM,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=NoEncryption()
                ))
            
            # Save public key
            with open(public_key_path, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=Encoding.PEM,
                    format=PublicFormat.SubjectPublicKeyInfo
                ))
            
            return private_key, public_key
    
    def encrypt_data(self, data: Any) -> str:
        """
        Encrypt data using symmetric encryption with Fernet
        
        Args:
            data: The data to encrypt (can be dict, list, or string)
            
        Returns:
            Base64-encoded encrypted data as string
        """
        # Serialize the data to JSON if it's a complex type
        if isinstance(data, (dict, list)):
            data_str = json.dumps(data)
        else:
            data_str = str(data)
        
        # Generate a nonce for this encryption
        nonce = secrets.token_bytes(16)
        
        # Encrypt the data
        encrypted_data = self.fernet.encrypt(data_str.encode())
        
        # Combine nonce and encrypted data
        result = {
            "nonce": base64.b64encode(nonce).decode(),
            "data": base64.b64encode(encrypted_data).decode(),
            "timestamp": int(time.time())
        }
        
        return base64.b64encode(json.dumps(result).encode()).decode()
    
    def decrypt_data(self, encrypted_str: str) -> Any:
        """
        Decrypt data that was encrypted with encrypt_data
        
        Args:
            encrypted_str: The base64-encoded encrypted data
            
        Returns:
            The decrypted data, parsed from JSON if possible
        """
        try:
            # Decode the base64 string
            decoded = base64.b64decode(encrypted_str)
            
            # Parse the JSON
            encrypted_package = json.loads(decoded)
            
            # Extract components
            nonce = base64.b64decode(encrypted_package["nonce"])
            encrypted_data = base64.b64decode(encrypted_package["data"])
            timestamp = encrypted_package["timestamp"]
            
            # Check for replay attacks (nonce should not have been used before)
            if nonce in self.nonce_registry:
                raise ValueError("Potential replay attack detected: Nonce has been used before")
            
            # Add nonce to registry to prevent reuse
            self.nonce_registry.add(nonce)
            
            # Check timestamp (prevent old messages from being reused)
            current_time = int(time.time())
            if current_time - timestamp > 300:  # 5 minute validity
                raise ValueError("Message expired: Timestamp too old")
            
            # Decrypt the data
            decrypted_data = self.fernet.decrypt(encrypted_data).decode()
            
            # Try to parse as JSON, return as string if not JSON
            try:
                return json.loads(decrypted_data)
            except json.JSONDecodeError:
                return decrypted_data
                
        except Exception as e:
            raise ValueError(f"Failed to decrypt data: {str(e)}")
    
    def asymmetric_encrypt(self, data: str) -> str:
        """
        Encrypt data using asymmetric RSA encryption
        Useful for very sensitive data or key exchange
        
        Args:
            data: String data to encrypt
            
        Returns:
            Base64-encoded encrypted data
        """
        # Convert data to bytes
        data_bytes = data.encode()
        
        # Encrypt with public key
        encrypted = self.rsa_public_key.encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Return base64 encoded string
        return base64.b64encode(encrypted).decode()
    
    def asymmetric_decrypt(self, encrypted_str: str) -> str:
        """
        Decrypt data that was encrypted with asymmetric_encrypt
        
        Args:
            encrypted_str: Base64-encoded encrypted data
            
        Returns:
            Decrypted string
        """
        # Decode the base64 string
        encrypted = base64.b64decode(encrypted_str)
        
        # Decrypt with private key
        decrypted = self.rsa_private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Return as string
        return decrypted.decode()
    
    def generate_api_key(self, user_id: str, expires_in_days: int = 30) -> str:
        """
        Generate a secure API key for a user
        
        Args:
            user_id: User identifier
            expires_in_days: Key validity in days
            
        Returns:
            Secure API key
        """
        # Generate random token
        token = secrets.token_hex(16)
        
        # Calculate expiry timestamp
        expiry = int(time.time()) + (expires_in_days * 24 * 60 * 60)
        
        # Create key data
        key_data = {
            "uid": user_id,
            "exp": expiry,
            "tok": token
        }
        
        # Convert to JSON and encrypt
        json_data = json.dumps(key_data)
        encrypted = self.fernet.encrypt(json_data.encode()).decode()
        
        # Create API key with format: prefix_base64data
        api_key = f"scai_{base64.urlsafe_b64encode(encrypted.encode()).decode()}"
        
        return api_key
    
    def verify_api_key(self, api_key: str) -> Dict[str, Any]:
        """
        Verify an API key and return user data
        
        Args:
            api_key: The API key to verify
            
        Returns:
            Dictionary with user data if valid
            
        Raises:
            ValueError: If key is invalid or expired
        """
        # Check prefix
        if not api_key.startswith("scai_"):
            raise ValueError("Invalid API key format")
        
        # Extract data portion
        data_part = api_key[5:]
        
        try:
            # Decode and decrypt
            decoded = base64.urlsafe_b64decode(data_part).decode()
            decrypted = self.fernet.decrypt(decoded.encode()).decode()
            key_data = json.loads(decrypted)
            
            # Check expiry
            if key_data["exp"] < int(time.time()):
                raise ValueError("API key has expired")
            
            return key_data
        except Exception as e:
            raise ValueError(f"Invalid API key: {str(e)}")
    
    def secure_hash(self, data: str) -> str:
        """
        Create a secure hash of data (for integrity verification)
        
        Args:
            data: String to hash
            
        Returns:
            Secure hash string
        """
        # Use SHA-256 for secure hashing
        hash_obj = hashlib.sha256(data.encode())
        return hash_obj.hexdigest()
    
    def encrypt_file(self, file_path: str, output_path: Optional[str] = None) -> str:
        """
        Encrypt a file using symmetric encryption
        
        Args:
            file_path: Path to file to encrypt
            output_path: Optional output path (if not provided, uses file_path + .enc)
            
        Returns:
            Path to the encrypted file
        """
        if output_path is None:
            output_path = file_path + ".enc"
        
        # Read file
        with open(file_path, "rb") as f:
            file_data = f.read()
        
        # Encrypt
        encrypted_data = self.fernet.encrypt(file_data)
        
        # Write encrypted data
        with open(output_path, "wb") as f:
            f.write(encrypted_data)
        
        return output_path
    
    def decrypt_file(self, encrypted_path: str, output_path: Optional[str] = None) -> str:
        """
        Decrypt a file that was encrypted with encrypt_file
        
        Args:
            encrypted_path: Path to encrypted file
            output_path: Optional output path (if not provided, removes .enc extension)
            
        Returns:
            Path to the decrypted file
        """
        if output_path is None:
            if encrypted_path.endswith(".enc"):
                output_path = encrypted_path[:-4]
            else:
                output_path = encrypted_path + ".dec"
        
        # Read encrypted file
        with open(encrypted_path, "rb") as f:
            encrypted_data = f.read()
        
        # Decrypt
        decrypted_data = self.fernet.decrypt(encrypted_data)
        
        # Write decrypted data
        with open(output_path, "wb") as f:
            f.write(decrypted_data)
        
        return output_path
    
    def secure_request(self, data: Dict[str, Any], endpoint: str) -> Dict[str, Any]:
        """
        Prepare a secure request package
        
        Args:
            data: Request data
            endpoint: API endpoint
            
        Returns:
            Secured request package
        """
        # Create a request ID
        request_id = secrets.token_hex(8)
        
        # Generate a nonce
        nonce = base64.b64encode(secrets.token_bytes(16)).decode()
        
        # Create timestamp
        timestamp = int(time.time())
        
        # Create the secure request package
        secure_package = {
            "payload": self.encrypt_data(data),
            "metadata": {
                "request_id": request_id,
                "nonce": nonce,
                "timestamp": timestamp,
                "endpoint": endpoint
            }
        }
        
        # Add signature for integrity verification
        signature_base = f"{request_id}:{nonce}:{timestamp}:{endpoint}"
        secure_package["signature"] = self.secure_hash(signature_base)
        
        # Register request to prevent replay attacks
        self.request_registry[request_id] = {
            "nonce": nonce,
            "timestamp": timestamp,
            "endpoint": endpoint
        }
        
        return secure_package
    
    def verify_secure_request(self, secure_package: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify and decrypt a secure request package
        
        Args:
            secure_package: The secure request package
            
        Returns:
            Decrypted request data
            
        Raises:
            ValueError: If request is invalid, tampered, or replay
        """
        # Extract components
        try:
            payload = secure_package["payload"]
            metadata = secure_package["metadata"]
            signature = secure_package["signature"]
            
            request_id = metadata["request_id"]
            nonce = metadata["nonce"]
            timestamp = metadata["timestamp"]
            endpoint = metadata["endpoint"]
        except KeyError as e:
            raise ValueError(f"Invalid secure package: Missing {e}")
        
        # Verify timestamp (5 minute window)
        current_time = int(time.time())
        if current_time - timestamp > 300:
            raise ValueError("Request expired: Timestamp too old")
        
        # Verify signature
        signature_base = f"{request_id}:{nonce}:{timestamp}:{endpoint}"
        expected_signature = self.secure_hash(signature_base)
        if signature != expected_signature:
            raise ValueError("Invalid signature: Request may have been tampered with")
        
        # Check for replay attacks
        if request_id in self.request_registry:
            stored_request = self.request_registry[request_id]
            if stored_request["nonce"] == nonce and stored_request["timestamp"] == timestamp:
                raise ValueError("Potential replay attack: Duplicate request detected")
        
        # Register request to prevent future replay attacks
        self.request_registry[request_id] = {
            "nonce": nonce,
            "timestamp": timestamp,
            "endpoint": endpoint
        }
        
        # Clean up old requests from registry (keep only last 5 minutes)
        self._clean_request_registry(current_time - 300)
        
        # Decrypt the payload
        try:
            return self.decrypt_data(payload)
        except Exception as e:
            raise ValueError(f"Failed to decrypt payload: {str(e)}")
    
    def _clean_request_registry(self, older_than_timestamp: int) -> None:
        """Remove old requests from registry to prevent memory leaks"""
        to_remove = []
        for request_id, request_data in self.request_registry.items():
            if request_data["timestamp"] < older_than_timestamp:
                to_remove.append(request_id)
        
        for request_id in to_remove:
            del self.request_registry[request_id]
    
    def serialize_for_network(self, data: Dict[str, Any]) -> bytes:
        """
        Serialize data for network transmission with security measures
        
        Args:
            data: Data to serialize
            
        Returns:
            Serialized and encrypted bytes ready for transmission
        """
        # Convert to JSON and encrypt
        json_data = json.dumps(data)
        encrypted = self.fernet.encrypt(json_data.encode())
        
        # Add length prefix for safer transport protocols
        length = len(encrypted)
        length_bytes = length.to_bytes(4, byteorder='big')
        
        return length_bytes + encrypted
    
    def deserialize_from_network(self, data_bytes: bytes) -> Dict[str, Any]:
        """
        Deserialize data received from network
        
        Args:
            data_bytes: Received bytes
            
        Returns:
            Deserialized data
        """
        # Extract length
        length = int.from_bytes(data_bytes[:4], byteorder='big')
        
        # Ensure we have the right amount of data
        if len(data_bytes) - 4 != length:
            raise ValueError("Data length mismatch - potential tampering detected")
        
        # Extract and decrypt the data
        encrypted = data_bytes[4:]
        decrypted = self.fernet.decrypt(encrypted).decode()
        
        # Parse JSON
        return json.loads(decrypted)


class DataProtection:
    """
    Data protection for sensitive information stored by the application.
    """
    
    def __init__(self, key_dir: str = DEFAULT_KEY_DIR):
        """Initialize with encryption keys"""
        self.security = SecurityLayer(key_dir)
    
    def protect_data(self, data: Dict[str, Any], sensitivity_level: str = "medium") -> Dict[str, Any]:
        """
        Protect data based on sensitivity level.
        
        Args:
            data: Data to protect
            sensitivity_level: 'low', 'medium', or 'high'
            
        Returns:
            Protected data
        """
        # Make a copy to avoid modifying the original
        protected = data.copy()
        
        # Define sensitive fields based on level
        sensitive_fields = {
            "low": ["password", "secret", "token", "key"],
            "medium": ["password", "secret", "token", "key", "credit_card", "ssn", "dob", "address"],
            "high": ["password", "secret", "token", "key", "credit_card", "ssn", "dob", 
                     "address", "name", "email", "phone", "ip", "location"]
        }
        
        fields = sensitive_fields.get(sensitivity_level, sensitive_fields["medium"])
        
        # Process each field
        self._protect_fields_recursive(protected, fields)
        
        return protected
    
    def _protect_fields_recursive(self, data: Any, sensitive_fields: list) -> None:
        """Recursively protect sensitive fields in data structure"""
        if isinstance(data, dict):
            for key, value in data.items():
                # If this is a sensitive field, encrypt it
                if any(field in key.lower() for field in sensitive_fields):
                    if isinstance(value, (str, int, float, bool)):
                        data[key] = self.security.encrypt_data(value)
                # Recursively process nested structures
                elif isinstance(value, (dict, list)):
                    self._protect_fields_recursive(value, sensitive_fields)
        
        elif isinstance(data, list):
            # Process each item in the list
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    self._protect_fields_recursive(item, sensitive_fields)
    
    def unprotect_data(self, protected_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Unprotect data that was protected with protect_data
        
        Args:
            protected_data: Data to unprotect
            
        Returns:
            Unprotected data
        """
        if not protected_data:
            return protected_data
            
        # Make a copy to avoid modifying the original
        unprotected = protected_data.copy()
        
        # Recursively decrypt any encrypted values
        self._unprotect_fields_recursive(unprotected)
        
        return unprotected
    
    def _unprotect_fields_recursive(self, data: Any) -> None:
        """Recursively unprotect fields in data structure"""
        if isinstance(data, dict):
            for key, value in list(data.items()):  # Use list() to create a copy of items
                # If value is a string and looks like encrypted data, try to decrypt
                if isinstance(value, str) and value.startswith("eyJ"):
                    try:
                        data[key] = self.security.decrypt_data(value)
                    except:
                        # If decryption fails, leave as is
                        pass
                # Recursively process nested structures
                elif isinstance(value, (dict, list)):
                    self._unprotect_fields_recursive(value)
        
        elif isinstance(data, list):
            # Process each item in the list
            for i, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    self._unprotect_fields_recursive(item)
    
    def protect_file(self, file_path: str, output_path: Optional[str] = None) -> str:
        """
        Protect a file with encryption
        
        Args:
            file_path: Path to file to protect
            output_path: Optional output path
            
        Returns:
            Path to protected file
        """
        return self.security.encrypt_file(file_path, output_path)
    
    def unprotect_file(self, protected_path: str, output_path: Optional[str] = None) -> str:
        """
        Unprotect a file that was protected with protect_file
        
        Args:
            protected_path: Path to protected file
            output_path: Optional output path
            
        Returns:
            Path to unprotected file
        """
        return self.security.decrypt_file(protected_path, output_path)


# Singleton instances for easy import and use
security_layer = SecurityLayer()
data_protection = DataProtection()


if __name__ == "__main__":
    # Self-test
    security = SecurityLayer()
    
    # Test data encryption/decryption
    test_data = {
        "user_id": 123,
        "username": "test_user",
        "sensitive_info": {
            "password": "secret_password",
            "api_key": "abcd1234"
        }
    }
    
    print("Testing symmetric encryption...")
    encrypted = security.encrypt_data(test_data)
    print(f"Encrypted: {encrypted[:30]}...")
    
    decrypted = security.decrypt_data(encrypted)
    print(f"Decrypted: {decrypted}")
    
    print("\nTesting asymmetric encryption...")
    secret = "This is a secret message"
    encrypted_secret = security.asymmetric_encrypt(secret)
    print(f"Encrypted: {encrypted_secret[:30]}...")
    
    decrypted_secret = security.asymmetric_decrypt(encrypted_secret)
    print(f"Decrypted: {decrypted_secret}")
    
    print("\nTesting data protection...")
    protection = DataProtection()
    protected = protection.protect_data(test_data, "high")
    print(f"Protected: {protected}")
    
    unprotected = protection.unprotect_data(protected)
    print(f"Unprotected: {unprotected}")
    
    print("\nAll tests completed successfully!") 