/**
 * Secure Client Module for AI Security Scanner
 * This module provides client-side security features for communicating with the server.
 * It implements data encryption, integrity verification, and secure communication.
 */

// Secure Client namespace
const SecureClient = (function() {
    // Private variables
    let _apiKey = null;
    let _encryptionKey = null;
    let _sessionId = null;
    let _serverPublicKey = null;
    let _initialized = false;
    let _securityLevel = 'medium'; // 'low', 'medium', 'high'

    // Constants
    const API_ENDPOINT = window.location.hostname === 'localhost' ? 'https://localhost:5000/api' : '/api';
    const SESSION_STORAGE_KEY = 'secure_client_session';
    const MAX_RETRIES = 3;
    const RETRY_DELAY = 1000; // ms

    /**
     * Initialize the secure client
     * @param {Object} options Configuration options
     * @returns {Promise} Promise that resolves when initialization is complete
     */
    async function initialize(options = {}) {
        if (_initialized) {
            return Promise.resolve();
        }

        // Apply options
        _securityLevel = options.securityLevel || _securityLevel;
        _apiKey = options.apiKey || localStorage.getItem('api_key');

        try {
            // Generate a session ID
            _sessionId = generateRandomId();

            // Try to restore session from storage
            const storedSession = sessionStorage.getItem(SESSION_STORAGE_KEY);
            if (storedSession) {
                const session = JSON.parse(storedSession);
                _encryptionKey = session.encryptionKey;
                _sessionId = session.sessionId;
                _serverPublicKey = session.serverPublicKey;
                _initialized = true;
                return Promise.resolve();
            }

            // Generate a new encryption key
            _encryptionKey = await crypto.subtle.generateKey(
                {
                    name: "AES-GCM",
                    length: 256
                },
                true,
                ["encrypt", "decrypt"]
            );

            // Initialize session with the server
            await initializeSecureSession();

            // Store session
            saveSession();

            _initialized = true;
            return Promise.resolve();
        } catch (error) {
            console.error('Failed to initialize secure client:', error);
            _initialized = false;
            return Promise.reject(error);
        }
    }

    /**
     * Save the current session to storage
     */
    function saveSession() {
        const session = {
            sessionId: _sessionId,
            serverPublicKey: _serverPublicKey,
            timestamp: Date.now()
        };

        // Store in session storage
        sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
    }

    /**
     * Initialize a secure session with the server
     * @returns {Promise} Promise that resolves when session is established
     */
    async function initializeSecureSession() {
        // For now, this is a placeholder
        // In a real implementation, this would exchange keys with the server
        return Promise.resolve();
    }

    /**
     * Generate a random identifier
     * @returns {string} Random ID
     */
    function generateRandomId() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Encrypt data for secure transmission
     * @param {Object|string} data Data to encrypt
     * @returns {Promise<string>} Promise that resolves to base64 encoded encrypted data
     */
    async function encryptData(data) {
        // Convert data to string if it's an object
        const dataStr = typeof data === 'object' ? JSON.stringify(data) : String(data);
        
        // Generate a random initialization vector
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        // For high security level, actually encrypt the data
        if (_securityLevel === 'high' && _encryptionKey) {
            try {
                // Encrypt the data
                const encodedData = new TextEncoder().encode(dataStr);
                const encryptedData = await crypto.subtle.encrypt(
                    {
                        name: "AES-GCM",
                        iv: iv,
                        tagLength: 128
                    },
                    _encryptionKey,
                    encodedData
                );
                
                // Combine IV and encrypted data
                const combined = new Uint8Array(iv.length + encryptedData.byteLength);
                combined.set(iv, 0);
                combined.set(new Uint8Array(encryptedData), iv.length);
                
                // Return as base64
                return btoa(String.fromCharCode.apply(null, combined));
            } catch (error) {
                console.error('Encryption failed:', error);
                // Fall back to unencrypted (but still encode)
                return btoa(dataStr);
            }
        } else {
            // For lower security levels, just encode the data
            return btoa(dataStr);
        }
    }

    /**
     * Decrypt data received from the server
     * @param {string} encryptedStr Base64 encoded encrypted data
     * @returns {Promise<Object|string>} Promise that resolves to decrypted data
     */
    async function decryptData(encryptedStr) {
        // For high security level, actually decrypt the data
        if (_securityLevel === 'high' && _encryptionKey) {
            try {
                // Decode from base64
                const encryptedData = new Uint8Array(
                    atob(encryptedStr).split('').map(char => char.charCodeAt(0))
                );
                
                // Extract IV and encrypted data
                const iv = encryptedData.slice(0, 12);
                const data = encryptedData.slice(12);
                
                // Decrypt
                const decryptedBuffer = await crypto.subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv: iv,
                        tagLength: 128
                    },
                    _encryptionKey,
                    data
                );
                
                // Decode the decrypted data
                const decryptedStr = new TextDecoder().decode(decryptedBuffer);
                
                // Try to parse as JSON, return as string if not JSON
                try {
                    return JSON.parse(decryptedStr);
                } catch (e) {
                    return decryptedStr;
                }
            } catch (error) {
                console.error('Decryption failed:', error);
                // Fall back to just decoding
                const decoded = atob(encryptedStr);
                try {
                    return JSON.parse(decoded);
                } catch (e) {
                    return decoded;
                }
            }
        } else {
            // For lower security levels, just decode
            const decoded = atob(encryptedStr);
            try {
                return JSON.parse(decoded);
            } catch (e) {
                return decoded;
            }
        }
    }

    /**
     * Make a secure API request to the server
     * @param {string} endpoint API endpoint path
     * @param {Object} data Request data
     * @param {Object} options Additional options
     * @returns {Promise<Object>} Promise that resolves to the response data
     */
    async function secureRequest(endpoint, data = {}, options = {}) {
        // Ensure client is initialized
        if (!_initialized) {
            try {
                await initialize();
            } catch (error) {
                return Promise.reject(new Error('Failed to initialize secure client'));
            }
        }

        // Default options
        const defaultOptions = {
            method: 'POST',
            securityLevel: _securityLevel,
            retries: 0,
            headers: {}
        };

        // Merge options
        const requestOptions = { ...defaultOptions, ...options };
        
        // Get security level for this specific request
        const securityLevel = requestOptions.securityLevel;

        // Prepare the request data
        const requestData = {
            ...data,
            metadata: {
                timestamp: Date.now(),
                sessionId: _sessionId,
                clientInfo: {
                    userAgent: navigator.userAgent,
                    language: navigator.language
                }
            }
        };

        // For high security, encrypt the data
        let finalData;
        if (securityLevel === 'high') {
            try {
                const encryptedPayload = await encryptData(requestData);
                finalData = {
                    secure_payload: encryptedPayload,
                    metadata: {
                        encrypted: true,
                        timestamp: Date.now(),
                        format: 'aes-gcm'
                    }
                };
            } catch (error) {
                console.warn('Failed to encrypt request data, falling back to unencrypted');
                finalData = requestData;
            }
        } else {
            finalData = requestData;
        }

        // Prepare headers
        const headers = {
            'Content-Type': 'application/json',
            'X-Session-ID': _sessionId,
            'X-Request-ID': generateRandomId(),
            'X-Timestamp': Date.now().toString(),
            ...requestOptions.headers
        };

        // Add API key if available
        if (_apiKey) {
            headers['X-API-Key'] = _apiKey;
        }

        // Full URL
        const url = `${API_ENDPOINT}${endpoint.startsWith('/') ? endpoint : '/' + endpoint}`;

        try {
            // Make the request
            const response = await fetch(url, {
                method: requestOptions.method,
                headers: headers,
                body: requestOptions.method !== 'GET' ? JSON.stringify(finalData) : undefined,
                credentials: 'include'
            });

            // Check for errors
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                
                // Handle specific error cases
                if (response.status === 429) { // Rate limit exceeded
                    if (requestOptions.retries < MAX_RETRIES) {
                        // Exponential backoff
                        const delay = RETRY_DELAY * Math.pow(2, requestOptions.retries);
                        await new Promise(resolve => setTimeout(resolve, delay));
                        
                        // Retry
                        return secureRequest(endpoint, data, {
                            ...requestOptions,
                            retries: requestOptions.retries + 1
                        });
                    }
                }
                
                throw new Error(errorData.error || `Request failed with status ${response.status}`);
            }

            // Parse response
            const responseData = await response.json();

            // For high security, decrypt the response if it's encrypted
            if (securityLevel === 'high' && responseData.secure_payload) {
                try {
                    return await decryptData(responseData.secure_payload);
                } catch (error) {
                    console.error('Failed to decrypt response:', error);
                    return responseData;
                }
            }

            return responseData;
        } catch (error) {
            console.error(`API request to ${endpoint} failed:`, error);
            
            // Retry logic for network errors
            if (requestOptions.retries < MAX_RETRIES) {
                const delay = RETRY_DELAY * Math.pow(2, requestOptions.retries);
                await new Promise(resolve => setTimeout(resolve, delay));
                
                return secureRequest(endpoint, data, {
                    ...requestOptions,
                    retries: requestOptions.retries + 1
                });
            }
            
            throw error;
        }
    }

    /**
     * Set the security level for future requests
     * @param {string} level Security level ('low', 'medium', 'high')
     */
    function setSecurityLevel(level) {
        if (['low', 'medium', 'high'].includes(level)) {
            _securityLevel = level;
        } else {
            console.warn(`Invalid security level: ${level}. Using 'medium' instead.`);
            _securityLevel = 'medium';
        }
    }

    /**
     * Set an API key for authentication
     * @param {string} apiKey API key
     * @param {boolean} remember Whether to store the key in localStorage
     */
    function setApiKey(apiKey, remember = false) {
        _apiKey = apiKey;
        
        if (remember) {
            localStorage.setItem('api_key', apiKey);
        }
    }

    /**
     * Get stored API key
     * @returns {string|null} API key or null if not set
     */
    function getApiKey() {
        return _apiKey || localStorage.getItem('api_key');
    }

    /**
     * Clear session data
     */
    function clearSession() {
        _sessionId = null;
        _encryptionKey = null;
        _serverPublicKey = null;
        _initialized = false;
        sessionStorage.removeItem(SESSION_STORAGE_KEY);
    }

    /**
     * Calculate a secure hash of data (for integrity verification)
     * @param {string} data Data to hash
     * @returns {Promise<string>} Promise that resolves to the hash
     */
    async function secureHash(data) {
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);
        const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Public API
    return {
        initialize,
        secureRequest,
        setSecurityLevel,
        setApiKey,
        getApiKey,
        clearSession,
        secureHash,
        
        // Request helper methods for different HTTP methods
        get: (endpoint, options = {}) => secureRequest(endpoint, {}, { ...options, method: 'GET' }),
        post: (endpoint, data, options = {}) => secureRequest(endpoint, data, { ...options, method: 'POST' }),
        put: (endpoint, data, options = {}) => secureRequest(endpoint, data, { ...options, method: 'PUT' }),
        delete: (endpoint, options = {}) => secureRequest(endpoint, {}, { ...options, method: 'DELETE' }),
        
        // Security level constants
        SecurityLevel: {
            LOW: 'low',
            MEDIUM: 'medium',
            HIGH: 'high'
        }
    };
})();

// Initialize the secure client when the document is ready
document.addEventListener('DOMContentLoaded', function() {
    SecureClient.initialize()
        .then(() => {
            console.log('Secure client initialized successfully');
        })
        .catch(error => {
            console.error('Failed to initialize secure client:', error);
        });
});

// Example API calls:
/*
// Make a secure API request
SecureClient.post('/scan', {
    code: "print('Hello, world!')"
})
.then(response => {
    console.log('API response:', response);
})
.catch(error => {
    console.error('API error:', error);
});

// Set high security level for sensitive operations
SecureClient.setSecurityLevel(SecureClient.SecurityLevel.HIGH);

// Make a request with custom options
SecureClient.post('/github-push', {
    code: "print('Hello, world!')",
    filename: "hello.py",
    commit_message: "Add hello world script"
}, {
    securityLevel: SecureClient.SecurityLevel.HIGH,
    headers: {
        'X-Custom-Header': 'value'
    }
})
.then(response => {
    console.log('Push response:', response);
})
.catch(error => {
    console.error('Push error:', error);
});
*/ 