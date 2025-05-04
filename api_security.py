#!/usr/bin/env python3
"""
API Security Module for Secure Code AI
This module provides security enhancements for API endpoints
implementing OSI Layer 7 (Application) security.
"""

import time
import json
import logging
import functools
from flask import request, g, jsonify, Response
from typing import Callable, Dict, Any, Optional, Union

from data_security import security_layer, data_protection

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Common security headers for all responses
SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com;",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store, max-age=0',
    'Pragma': 'no-cache'
}

class APISecurityManager:
    """Manages API security features"""
    
    def __init__(self):
        """Initialize API security manager"""
        self.security = security_layer
        self.protection = data_protection
        
        # Track rate limits per IP
        self.rate_limits = {}
        
        # Configure security levels for different endpoints
        self.endpoint_security_levels = {
            # High security endpoints (authentication, user data, etc.)
            '/api/github-push': 'high',
            '/api/github-retrieve': 'high',
            '/api/scan/file': 'medium',
            '/api/scan/directory': 'medium',
            
            # Medium security endpoints (most API endpoints)
            '/api/scan': 'medium',
            '/api/analyze-code': 'medium',
            '/api/chat': 'medium',
            '/api/live-check': 'medium',
            
            # Lower security endpoints (public info, demos)
            '/api/status': 'low',
            '/api/demo': 'low',
            '/api/template': 'low'
        }
    
    def get_security_level(self, endpoint: str) -> str:
        """Get the security level for an endpoint"""
        # Check exact matches
        if endpoint in self.endpoint_security_levels:
            return self.endpoint_security_levels[endpoint]
        
        # Check for partial matches
        for path, level in self.endpoint_security_levels.items():
            if endpoint.startswith(path):
                return level
        
        # Default to medium security
        return 'medium'
    
    def secure_endpoint(self, f: Callable) -> Callable:
        """
        Decorator to secure API endpoints
        Applies appropriate security measures based on endpoint sensitivity
        """
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client IP
            client_ip = request.remote_addr
            
            # Store in Flask g object for logging
            g.client_ip = client_ip
            g.request_time = time.time()
            g.endpoint = request.path
            
            # Check rate limits
            if not self._check_rate_limit(client_ip, request.path):
                logger.warning(f"Rate limit exceeded for {client_ip} on {request.path}")
                return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429
            
            # Get security level for this endpoint
            security_level = self.get_security_level(request.path)
            
            # For requests with JSON data, decrypt and validate
            if request.is_json:
                try:
                    # Store original JSON
                    original_json = request.get_json()
                    
                    # If the request has a "secure_payload" field, it's encrypted
                    if original_json and "secure_payload" in original_json:
                        try:
                            # Decrypt the secure payload
                            encrypted_payload = original_json["secure_payload"]
                            decrypted_data = self.security.decrypt_data(encrypted_payload)
                            
                            # Store decrypted data in Flask g object for the endpoint to use
                            g.json_data = decrypted_data
                        except Exception as e:
                            logger.error(f"Failed to decrypt payload: {e}")
                            return jsonify({"error": "Invalid encrypted payload"}), 400
                    else:
                        # Non-encrypted payload - Store in g
                        g.json_data = original_json
                except Exception as e:
                    logger.error(f"Failed to process request JSON: {e}")
                    return jsonify({"error": "Invalid JSON payload"}), 400
            
            # Call the original function
            response = f(*args, **kwargs)
            
            # Process the response
            return self._secure_response(response, security_level)
        
        return decorated_function
    
    def _check_rate_limit(self, client_ip: str, endpoint: str) -> bool:
        """
        Check if the request exceeds rate limits
        
        Args:
            client_ip: Client IP address
            endpoint: API endpoint
            
        Returns:
            True if request is allowed, False if it exceeds limits
        """
        current_time = time.time()
        
        # Get security level for rate limit determination
        security_level = self.get_security_level(endpoint)
        
        # Define rate limits (requests per minute) based on security level
        rate_limits = {
            'high': 5,       # 5 requests per minute for high security endpoints
            'medium': 30,    # 30 requests per minute for medium security endpoints
            'low': 60        # 60 requests per minute for low security endpoints
        }
        
        rate_limit = rate_limits.get(security_level, 30)
        
        # Initialize rate limit tracking for this IP if not exists
        if client_ip not in self.rate_limits:
            self.rate_limits[client_ip] = {}
        
        if endpoint not in self.rate_limits[client_ip]:
            self.rate_limits[client_ip][endpoint] = {'count': 0, 'reset_time': current_time + 60}
        
        # Reset count if the minute has passed
        if current_time > self.rate_limits[client_ip][endpoint]['reset_time']:
            self.rate_limits[client_ip][endpoint] = {'count': 0, 'reset_time': current_time + 60}
        
        # Increment count and check against limit
        self.rate_limits[client_ip][endpoint]['count'] += 1
        
        # Clean up old rate limit data periodically
        if current_time % 10 < 0.1:  # Approximately every 10 seconds
            self._clean_rate_limits(current_time)
        
        return self.rate_limits[client_ip][endpoint]['count'] <= rate_limit
    
    def _clean_rate_limits(self, current_time: float) -> None:
        """Clean up expired rate limit data"""
        ips_to_remove = []
        
        # Find expired entries
        for ip, endpoints in self.rate_limits.items():
            endpoints_to_remove = []
            
            for endpoint, data in endpoints.items():
                if current_time > data['reset_time']:
                    endpoints_to_remove.append(endpoint)
            
            # Remove expired endpoints
            for endpoint in endpoints_to_remove:
                del endpoints[endpoint]
            
            # If no endpoints left for this IP, mark IP for removal
            if not endpoints:
                ips_to_remove.append(ip)
        
        # Remove empty IP entries
        for ip in ips_to_remove:
            del self.rate_limits[ip]
    
    def _secure_response(self, response: Union[Response, tuple, Dict[str, Any]], security_level: str) -> Response:
        """
        Process and secure the response based on security level
        
        Args:
            response: Original response from endpoint
            security_level: Security level ('high', 'medium', 'low')
            
        Returns:
            Secured response
        """
        # Extract response and status code
        if isinstance(response, tuple):
            # Response is (json_response, status_code)
            data, status_code = response
        else:
            # Response is just data
            data = response
            status_code = 200
        
        # Convert dictionary to Response if needed
        if isinstance(data, dict):
            # For high security endpoints, encrypt sensitive data
            if security_level == 'high':
                # Protect the data
                protected_data = self.protection.protect_data(data, security_level)
                
                # Create a secure response package
                secure_response = {
                    "secure_payload": self.security.encrypt_data(protected_data),
                    "metadata": {
                        "encrypted": True,
                        "timestamp": int(time.time())
                    }
                }
                
                # Convert to Response
                response = jsonify(secure_response)
            else:
                # For medium/low security, just return the data with headers
                response = jsonify(data)
        
        # If we already have a Response object, keep using it
        if not isinstance(response, Response):
            response = jsonify(response)
        
        # Set status code
        response.status_code = status_code
        
        # Add security headers
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        
        # Add request processing time
        if hasattr(g, 'request_time'):
            processing_time = time.time() - g.request_time
            response.headers['X-Processing-Time'] = f"{processing_time:.4f}s"
        
        # Log the response (excluding sensitive data)
        client_ip = getattr(g, 'client_ip', 'unknown')
        endpoint = getattr(g, 'endpoint', request.path)
        logger.info(f"Response to {client_ip} for {endpoint}: status={status_code}")
        
        return response


# Create a singleton instance for easy import
api_security = APISecurityManager()

# Decorator for securing API endpoints
secure_endpoint = api_security.secure_endpoint


def encrypt_response_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Utility function to encrypt response data for sensitive APIs"""
    return {
        "secure_payload": security_layer.encrypt_data(data),
        "metadata": {
            "encrypted": True,
            "timestamp": int(time.time())
        }
    }


def create_secure_api_key(user_id: str, expires_in_days: int = 30) -> str:
    """Create a secure API key for a user"""
    return security_layer.generate_api_key(user_id, expires_in_days)


def verify_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """Verify an API key and return user data if valid"""
    try:
        return security_layer.verify_api_key(api_key)
    except ValueError:
        return None


if __name__ == "__main__":
    # Test the API security functions
    print("API Security Module Self-Test")
    print("-" * 50)
    
    # Test API key generation and verification
    user_id = "test_user_123"
    api_key = create_secure_api_key(user_id, expires_in_days=1)
    print(f"Generated API key: {api_key}")
    
    verified = verify_api_key(api_key)
    print(f"Verified API key: {verified}")
    
    # Test data encryption
    test_data = {
        "user_id": user_id,
        "results": [
            {"id": 1, "score": 95},
            {"id": 2, "score": 87}
        ],
        "metadata": {
            "timestamp": int(time.time()),
            "source": "api_security_test"
        }
    }
    
    encrypted = encrypt_response_data(test_data)
    print(f"\nEncrypted response data: {json.dumps(encrypted, indent=2)[:100]}...")
    
    # Decrypt the data
    decrypted = security_layer.decrypt_data(encrypted["secure_payload"])
    print(f"\nDecrypted data matches original: {decrypted == test_data}")
    
    print("\nSelf-test completed successfully!") 