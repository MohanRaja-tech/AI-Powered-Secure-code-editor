import os
import json
import logging
from typing import List, Dict, Any
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import tempfile
import re
import subprocess
import datetime
import requests
import openai
import os.path
import sys
import time
import groq
from dotenv import load_dotenv
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Define a 16-byte AES key (128-bit)



# Import the vulnerability scanner from check_model.py
from check_model import VulnerabilityScanner

# Import GroqChat for AI chat
from groq_integration import GroqChat

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, static_folder='web')
CORS(app)  # Enable Cross-Origin Resource Sharing

# Initialize the vulnerability scanner
scanner = VulnerabilityScanner()

# Initialize GroqChat with API key
GROQ_API_KEY = "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"
try:
    groq_chat = GroqChat(api_key=GROQ_API_KEY)
    # Test the API connection with a simple prompt
    test_response = groq_chat.get_response("Hello, are you working correctly?")
    if "Error getting response from GROQ" in test_response:
        logger.error(f"GROQ API test failed: {test_response}")
        groq_chat = None
    else:
        logger.info("GROQ Chat initialized successfully and API connection verified")
        # Make sure we're using llama3 model
        groq_chat.model = groq_chat.models["llama3"]
        logger.info(f"Using GROQ model: {groq_chat.model}")
except Exception as e:
    logger.error(f"Failed to initialize GROQ Chat: {e}")
    groq_chat = None

# Try to import OpenAI for the live code checking
try:
    import openai
    from openai import OpenAI
    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
    if OPENAI_API_KEY:
        openai_client = OpenAI(api_key=OPENAI_API_KEY)
        logger.info("OpenAI initialized successfully")
    else:
        logger.warning("OpenAI API key not found, falling back to scanner")
        openai_client = None
except ImportError:
    logger.warning("OpenAI package not installed, falling back to scanner")
    openai_client = None

# Load environment variables
load_dotenv()

# Get API keys from environment variables
openai_api_key = os.getenv("OPENAI_API_KEY")
groq_api_key = os.getenv("GROQ_API_KEY")

# Initialize OpenAI if key is available
if openai_api_key:
    openai.api_key = openai_api_key

# Initialize GROQ if key is available
if groq_api_key:
    groq_client = groq.Groq(api_key=groq_api_key)

@app.route('/')
def index():
    """Serve the main web UI"""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve static files from the web directory"""
    return send_from_directory(app.static_folder, path)

@app.route('/api/status', methods=['GET'])
def api_status():
    """
    API endpoint to check status of services
    
    Returns:
        {
            "scanner": true/false,
            "groq_chat": true/false
        }
    """
    return jsonify({
        'scanner': True,
        'groq_chat': groq_chat is not None
    })

@app.route('/api/scan', methods=['POST'])
def scan_code():
    """
    API endpoint to scan code for vulnerabilities
    
    Request body:
        {
            "code": "source code to scan"
        }
    
    Returns:
        {
            "vulnerabilities": [...],
            "secure_code": "fixed version of the code"
        }
    """
    try:
        data = request.get_json()
        if not data or 'code' not in data:
            return jsonify({'error': 'No code provided in request body'}), 400
        
        code = data['code']
        print("-------- Original code -------- ")
        print(code)
        print("-------- Original code --------")
        
        # Scan the code for vulnerabilities
        logger.info("Scanning code for vulnerabilities")
        vulnerabilities = scanner.analyze_code(code)
        
        # Generate secure code
        logger.info("Generating secure code recommendations")
        secure_code = scanner.generate_secure_code(code, vulnerabilities)
        
        # Generate detailed report
        report = scanner.generate_detailed_report({"submitted_code.py": vulnerabilities})

        return jsonify({
            'vulnerabilities': vulnerabilities,
            'secure_code': secure_code,
            'report': report
        })
    
    except Exception as e:
        logger.error(f"Error scanning code: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat', methods=['POST'])
def chat():
    """
    API endpoint for AI chat using GROQ API
    
    Request body:
        {
            "message": "user message",
            "system_prompt": "optional system prompt" (optional)
        }
    
    Returns:
        {
            "response": "AI response"
        }
    """
    try:
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({'error': 'No message provided in request body'}), 400
        
        message = data['message']
        system_prompt = data.get('system_prompt')
        
        # If message appears to be about code, prepare a security-focused system prompt
        default_system_prompt = """You are an AI security assistant specialized in helping developers write secure code.
        Focus on providing best practices, identifying security vulnerabilities, and suggesting secure coding techniques.
        Be concise but thorough, and include code examples where appropriate."""
        
        # Use the provided system prompt or the default one
        system_prompt = system_prompt or default_system_prompt
        
        if groq_chat:
            logger.info("Sending message to GROQ Chat")
            response = groq_chat.get_response(message, system_prompt)
            
            # Check if there was an error
            if "Error getting response from GROQ" in response:
                logger.error(f"GROQ API error: {response}")
                return jsonify({
                    'response': "I encountered an error while connecting to the AI service. Please try again later.",
                    'error': response
                }), 503
            
            return jsonify({'response': response})
        else:
            logger.warning("GROQ Chat not available, using fallback response")
            return jsonify({
                'response': "I'm sorry, but the AI chat service is currently unavailable. Please check your GROQ API key configuration.",
                'error': 'GROQ service unavailable'
            }), 503
    
    except Exception as e:
        logger.error(f"Error in chat API: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze-code', methods=['POST'])
def analyze_code_chat():
    """
    API endpoint to analyze code specifically using the GROQ API
    
    Request body:
        {
            "code": "source code to analyze"
        }
    
    Returns:
        {
            "analysis": "AI analysis of the code"
        }
    """
    try:
        data = request.get_json()
        if not data or 'code' not in data:
            return jsonify({'error': 'No code provided in request body'}), 400
        
        code = data['code']
        
        if groq_chat:
            logger.info("Sending code to GROQ Chat for analysis")
            analysis = groq_chat.analyze_code(code)
            
            # Check if there was an error
            if "Error getting response from GROQ" in analysis.get('analysis', ''):
                logger.error(f"GROQ API error: {analysis['analysis']}")
                return jsonify({
                    'analysis': "I encountered an error while connecting to the AI service. Please try again later.",
                    'error': analysis['analysis']
                }), 503
                
            return jsonify(analysis)
        else:
            logger.warning("GROQ Chat not available, using fallback response")
            return jsonify({
                'analysis': "I'm sorry, but the AI code analysis service is currently unavailable. Please check your GROQ API key configuration.",
                'error': 'GROQ service unavailable'
            }), 503
    
    except Exception as e:
        logger.error(f"Error in code analysis API: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    """
    API endpoint to scan an uploaded file for vulnerabilities
    
    Request:
        Multipart form with 'file' field containing the file to scan
    
    Returns:
        {
            "vulnerabilities": [...],
            "secure_code": "fixed version of the code"
        }
    """
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Create a temporary file to store the uploaded content
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            file_path = temp.name
            file.save(file_path)
        
        try:
            # Read the file content
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            
            # Scan the code for vulnerabilities
            vulnerabilities = scanner.analyze_code(code, file.filename)
            
            # Generate secure code
            secure_code = scanner.generate_secure_code(code, vulnerabilities)
            
            # Generate detailed report
            report = scanner.generate_detailed_report({file.filename: vulnerabilities})
            
            return jsonify({
                'vulnerabilities': vulnerabilities,
                'secure_code': secure_code,
                'report': report
            })
        finally:
            # Clean up the temporary file
            try:
                os.unlink(file_path)
            except Exception as e:
                logger.error(f"Error deleting temporary file: {e}")
    
    except Exception as e:
        logger.error(f"Error scanning file: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/directory', methods=['POST'])
def scan_directory():
    """
    API endpoint to scan a directory for vulnerabilities
    
    Request body:
        {
            "path": "directory path to scan",
            "extensions": [".py", ".js", ".php"] (optional)
        }
    
    Returns:
        {
            "vulnerabilities": {
                "file1.py": [...],
                "file2.js": [...]
            },
            "report": "detailed vulnerability report"
        }
    """
    try:
        data = request.get_json()
        if not data or 'path' not in data:
            return jsonify({'error': 'No path provided in request body'}), 400
        
        path = data['path']
        extensions = data.get('extensions', ['.py', '.js', '.php', '.java'])
        
        # Validate the path exists and is a directory
        if not os.path.exists(path):
            return jsonify({'error': f"Directory '{path}' does not exist"}), 400
        
        if not os.path.isdir(path):
            return jsonify({'error': f"'{path}' is not a directory"}), 400
        
        # Scan the directory
        logger.info(f"Scanning directory: {path}")
        results = scanner.scan_directory(path, extensions)
        
        # Generate detailed report
        report = scanner.generate_detailed_report(results)
        
        return jsonify({
            'vulnerabilities': results,
            'report': report
        })
    
    except Exception as e:
        logger.error(f"Error scanning directory: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/demo', methods=['GET'])
def get_demo_data():
    """
    API endpoint to get demo vulnerability data
    
    Returns:
        {
            "vulnerabilities": [...],
            "secure_code": "secure version of code",
            "original_code": "original vulnerable code"
        }
    """
    vulnerable_code = """
import sqlite3
from flask import request, Flask

app = Flask(__name__)

@app.route('/login')
def login():
    username = request.args.get('username')
    password = request.args.get('password')
    
    # Vulnerable to SQL Injection
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    # Vulnerable to XSS
    if not user:
        return f"<p>Login failed for username: {username}</p>"
    
    # Vulnerable to command injection
    import os
    os.system("echo " + username + " logged in")
    
    return f"<p>Welcome, {username}!</p>"
"""
    
    secure_code = """
import sqlite3
from flask import request, Flask, escape

app = Flask(__name__)

@app.route('/login')
def login():
    username = request.args.get('username')
    password = request.args.get('password')
    
    # Fixed SQL Injection by using parameterized query
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    user = cursor.fetchone()
    
    # Fixed XSS by escaping output
    if not user:
        return f"<p>Login failed for username: {escape(username)}</p>"
    
    # Fixed command injection by using a safer alternative
    import subprocess
    subprocess.run(["echo", f"{username} logged in"], shell=False)
    
    return f"<p>Welcome, {escape(username)}!</p>"
"""
    
    # Demo vulnerabilities
    vulnerabilities = [
        {
            "file": "app.py",
            "line": 12,
            "type": "sql_injection",
            "severity": "high",
            "message": "SQL Injection vulnerability detected. User input is directly concatenated into SQL query.",
            "code": "query = \"SELECT * FROM users WHERE username = '\" + username + \"' AND password = '\" + password + \"'\"",
            "fix": "Use parameterized queries instead of string concatenation"
        },
        {
            "file": "app.py",
            "line": 18,
            "type": "xss",
            "severity": "medium",
            "message": "Cross-Site Scripting (XSS) vulnerability detected. User input is directly rendered in HTML response.",
            "code": "return f\"<p>Login failed for username: {username}</p>\"",
            "fix": "Use template escaping or escape the user input before rendering"
        },
        {
            "file": "app.py",
            "line": 22,
            "type": "command_injection",
            "severity": "critical",
            "message": "Command Injection vulnerability detected. User input is directly used in system command.",
            "code": "os.system(\"echo \" + username + \" logged in\")",
            "fix": "Use subprocess module with shell=False instead of os.system"
        }
    ]
    
    return jsonify({
        'vulnerabilities': vulnerabilities,
        'secure_code': secure_code,
        'original_code': vulnerable_code
    })

@app.route('/api/live-check', methods=['POST'])
def live_check():
    """
    API endpoint to check code for security vulnerabilities in real-time
    
    JSON body parameters:
        code: The code to check
        language: Programming language of the code
        
    Returns:
        {
            "vulnerabilities": List of detected vulnerabilities,
            "totalCount": Count of vulnerabilities,
            "status": "success" or "error",
            "language": Language detected
        }
    """
    try:
        # Get code from request
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No JSON data provided"}), 400
            
        code = data.get('code', '')
        language = data.get('language', '')
        
        if not code:
            return jsonify({"status": "error", "message": "No code provided"}), 400
            
        if not language:
            # Detect language from code if not provided
            language = detect_language(code)
            
        print("\n========== RECEIVED CODE FOR LIVE CHECK ==========")
        print(code[:200] + "..." if len(code) > 200 else code)
        print("=================================================\n")
        
        # Check if code might be harmful before processing
        if is_potentially_harmful(code, language):
            return jsonify({
                "status": "error",
                "message": "Code contains potentially harmful operations that cannot be analyzed",
                "vulnerabilities": [],
                "totalCount": 0,
                "language": language
            }), 400
        
        # Initialize scanner
        scanner = VulnerabilityScanner()
        
        # Encrypt the code before sending to the analysis function
        try:
            encrypted_code = encrypt(code, key)
            print("\n========== CODE ENCRYPTED FOR TRANSMISSION ==========")
            print(f"Original length: {len(code)}, Encrypted length: {len(encrypted_code)}")
            print("====================================================\n")
        except Exception as e:
            print(f"Encryption error: {e}")
            # If encryption fails, use the original code
            encrypted_code = code
        
        # Analyze code for vulnerabilities
        vulnerabilities = scanner.analyze_code(encrypted_code, f"live_check.{language}")
        
        return jsonify({
            "status": "success",
            "vulnerabilities": vulnerabilities,
            "totalCount": len(vulnerabilities),
            "language": language
        })
        
    except Exception as e:
        # Log the error but don't expose details to client
        error_message = str(e)
        logger.error(f"Error in live-check: {error_message}")
        
        return jsonify({
            "status": "error",
            "message": "An error occurred during code analysis",
            "vulnerabilities": [],
            "totalCount": 0,
            "language": language if 'language' in locals() else "unknown"
        }), 500

@app.route('/api/template/<language>', methods=['GET'])
def get_language_template(language):
    """
    API endpoint to get starter code templates for different languages
    
    URL parameter:
        language: The programming language for the template
    
    Returns:
        {
            "template": "starter code template",
            "language": "language name"
        }
    """
    templates = {
        'python': """#!/usr/bin/env python3
# Python Template with common imports

import sys
import os
import json
import math
import random
from datetime import datetime

def main():
    print("Hello, Python World!")
    # Your code here
    
    # Working with lists
    my_list = [1, 2, 3, 4, 5]
    print(f"List: {my_list}")
    
    # Working with dictionaries
    my_dict = {"name": "Python", "type": "Language", "level": "Advanced"}
    print(f"Dictionary: {my_dict}")
    
    # Current date and time
    now = datetime.now()
    print(f"Current time: {now.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Random number
    rand_num = random.randint(1, 100)
    print(f"Random number: {rand_num}")
    
    # Command line arguments
    print(f"Command line arguments: {sys.argv}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
""",
        'javascript': """// JavaScript Template with common patterns

// Importing modules (Node.js)
// const fs = require('fs');
// const path = require('path');

// Main function
function main() {
    console.log("Hello, JavaScript World!");
    
    // Working with arrays
    const myArray = [1, 2, 3, 4, 5];
    console.log("Array:", myArray);
    
    // Array methods
    const doubled = myArray.map(num => num * 2);
    console.log("Doubled array:", doubled);
    
    // Working with objects
    const myObject = {
        name: "JavaScript",
        type: "Language",
        level: "Advanced",
        features: ["Functional", "OOP", "Event-driven"]
    };
    console.log("Object:", myObject);
    
    // JSON operations
    const jsonString = JSON.stringify(myObject, null, 2);
    console.log("JSON string:", jsonString);
    
    // Date and time
    const now = new Date();
    console.log("Current time:", now.toISOString());
    
    // Random number
    const randomNum = Math.floor(Math.random() * 100) + 1;
    console.log("Random number:", randomNum);
    
    // Promise example
    const myPromise = new Promise((resolve, reject) => {
        setTimeout(() => {
            resolve("Promise resolved after 1 second");
        }, 1000);
    });
    
    myPromise.then(result => {
        console.log(result);
    }).catch(error => {
        console.error("Error:", error);
    });
    
    // Async/await example (uncomment to use)
    /*
    async function asyncFunction() {
        try {
            const result = await myPromise;
            console.log("Async result:", result);
        } catch (error) {
            console.error("Async error:", error);
        }
    }
    asyncFunction();
    */
}

// Run the main function
main();
""",
        'java': """// Java Template with common utilities

import java.util.*;
import java.time.*;
import java.io.*;
import java.text.SimpleDateFormat;

public class Main {
    public static void main(String[] args) {
        System.out.println("Hello, Java World!");

        // Working with arrays
        int[] numbers = {1, 2, 3, 4, 5};
        System.out.println("Array: " + Arrays.toString(numbers));
        
        // Working with ArrayList
        List<String> stringList = new ArrayList<>();
        stringList.add("Java");
        stringList.add("Programming");
        stringList.add("Language");
        System.out.println("ArrayList: " + stringList);
        
        // Working with HashMap
        Map<String, Object> map = new HashMap<>();
        map.put("name", "Java");
        map.put("type", "Language");
        map.put("version", 17);
        System.out.println("HashMap: " + map);
        
        // Date and time
        LocalDateTime now = LocalDateTime.now();
        System.out.println("Current time: " + now);
        
        // Random number
        Random random = new Random();
        int randomNumber = random.nextInt(100) + 1;
        System.out.println("Random number: " + randomNumber);
        
        // Command line arguments
        System.out.println("Command line arguments: " + Arrays.toString(args));
        
        // Exception handling example
        try {
            // Some code that might throw exceptions
            File file = new File("example.txt");
            if (!file.exists()) {
                System.out.println("File doesn't exist, but we caught this condition");
            }
        } catch (Exception e) {
            System.err.println("Exception caught: " + e.getMessage());
        } finally {
            System.out.println("Finally block executed");
        }
    }
}
""",
        'htmlmixed': """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HTML Template</title>
    <style>
        /* CSS styles */
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 800px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        header {
            text-align: center;
            margin-bottom: 20px;
        }
        
        h1 {
            color: #333;
        }
        
        .content {
            margin-bottom: 20px;
        }
        
        .btn {
            display: inline-block;
            background-color: #4CAF50;
            color: white;
            padding: 10px 15px;
            text-decoration: none;
            border-radius: 4px;
            cursor: pointer;
        }
        
        .btn:hover {
            background-color: #45a049;
        }
        
        footer {
            margin-top: 20px;
            text-align: center;
            color: #777;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>HTML Template</h1>
        </header>
        
        <div class="content">
            <h2>Welcome to Your HTML Template</h2>
            <p>This is a starter HTML template with CSS and JavaScript included.</p>
            
            <!-- Example list -->
            <h3>Features:</h3>
            <ul>
                <li>Clean, responsive design</li>
                <li>Interactive elements with JavaScript</li>
                <li>CSS styling included</li>
                <li>DOM manipulation example</li>
            </ul>
            
            <!-- Example form -->
            <h3>Example Form:</h3>
            <form id="sample-form">
                <div style="margin-bottom: 10px;">
                    <label for="name">Name:</label>
                    <input type="text" id="name" name="name" style="width: 100%; padding: 8px;">
                </div>
                
                <div style="margin-bottom: 10px;">
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" style="width: 100%; padding: 8px;">
                </div>
                
                <button type="button" id="submit-btn" class="btn">Submit</button>
            </form>
            
            <!-- Element to be manipulated by JavaScript -->
            <div id="result" style="margin-top: 20px; padding: 10px; border: 1px solid #ddd; display: none;"></div>
        </div>
        
        <footer>
            &copy; <span id="current-year"></span> HTML Template. All rights reserved.
        </footer>
    </div>
    
    <script>
        // JavaScript code
        document.addEventListener('DOMContentLoaded', function() {
            // Set current year in footer
            document.getElementById('current-year').textContent = new Date().getFullYear();
            
            // Handle form submission
            document.getElementById('submit-btn').addEventListener('click', function() {
                const name = document.getElementById('name').value;
                const email = document.getElementById('email').value;
                
                if (name && email) {
                    const resultDiv = document.getElementById('result');
                    resultDiv.innerHTML = `<strong>Form Data:</strong><br>Name: ${name}<br>Email: ${email}`;
                    resultDiv.style.display = 'block';
                } else {
                    alert('Please fill in all fields');
                }
            });
            
            // Example of creating elements dynamically
            const newParagraph = document.createElement('p');
            newParagraph.textContent = 'This paragraph was created with JavaScript!';
            newParagraph.style.color = '#4CAF50';
            document.querySelector('.content').appendChild(newParagraph);
            
            // Console log for developers
            console.log('HTML template loaded successfully');
        });
    </script>
</body>
</html>
""",
        'cpp': """// C++ Template with common libraries and functions

#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <ctime>
#include <random>
#include <chrono>
#include <memory>

// Function prototypes
void printVector(const std::vector<int>& vec);
void workWithStrings();
void workWithContainers();
void demonstrateModernCpp();

int main(int argc, char* argv[]) {
    std::cout << "Hello, C++ World!" << std::endl;
    
    // Print command line arguments
    std::cout << "Command line arguments: ";
    for (int i = 0; i < argc; ++i) {
        std::cout << argv[i] << " ";
    }
    std::cout << std::endl;
    
    // Working with vectors
    std::vector<int> numbers = {1, 2, 3, 4, 5};
    std::cout << "Vector: ";
    printVector(numbers);
    
    // String operations
    workWithStrings();
    
    // Container operations
    workWithContainers();
    
    // Modern C++ features
    demonstrateModernCpp();
    
    // Get current time
    auto now = std::chrono::system_clock::now();
    std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
    std::cout << "Current time: " << std::ctime(&currentTime);
    
    // Generate random number
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(1, 100);
    int randomNumber = distrib(gen);
    std::cout << "Random number: " << randomNumber << std::endl;
    
    return 0;
}

// Function to print a vector
void printVector(const std::vector<int>& vec) {
    for (const auto& element : vec) {
        std::cout << element << " ";
    }
    std::cout << std::endl;
}

// Function demonstrating string operations
void workWithStrings() {
    std::cout << "\\nString operations:" << std::endl;
    
    std::string text = "C++ Programming Language";
    
    // String info
    std::cout << "Original text: " << text << std::endl;
    std::cout << "Length: " << text.length() << std::endl;
    
    // Substring
    std::string sub = text.substr(5, 11);
    std::cout << "Substring: " << sub << std::endl;
    
    // Find
    size_t pos = text.find("Language");
    if (pos != std::string::npos) {
        std::cout << "Found 'Language' at position: " << pos << std::endl;
    }
    
    // Replace
    std::string modified = text;
    modified.replace(0, 3, "Modern C++");
    std::cout << "Modified: " << modified << std::endl;
}

// Function demonstrating containers
void workWithContainers() {
    std::cout << "\\nContainer operations:" << std::endl;
    
    // Map
    std::map<std::string, std::string> languageInfo = {
        {"name", "C++"},
        {"paradigm", "Multi-paradigm"},
        {"designed", "1985"}
    };
    
    std::cout << "Map contents:" << std::endl;
    for (const auto& entry : languageInfo) {
        std::cout << "  " << entry.first << ": " << entry.second << std::endl;
    }
    
    // Vector algorithms
    std::vector<int> numbers = {5, 2, 8, 1, 9, 3, 7, 4, 6};
    
    // Sort
    std::sort(numbers.begin(), numbers.end());
    std::cout << "Sorted vector: ";
    printVector(numbers);
    
    // Find
    auto it = std::find(numbers.begin(), numbers.end(), 7);
    if (it != numbers.end()) {
        std::cout << "Found 7 at position: " << (it - numbers.begin()) << std::endl;
    }
    
    // Transform
    std::vector<int> doubled(numbers.size());
    std::transform(numbers.begin(), numbers.end(), doubled.begin(),
                  [](int x) { return x * 2; });
    std::cout << "Doubled vector: ";
    printVector(doubled);
}

// Function demonstrating modern C++ features
void demonstrateModernCpp() {
    std::cout << "\\nModern C++ features:" << std::endl;
    
    // Auto type deduction
    auto value = 42;
    auto text = "C++17";
    std::cout << "Auto variables: " << value << ", " << text << std::endl;
    
    // Lambda function
    auto add = [](int a, int b) { return a + b; };
    std::cout << "Lambda result: 3 + 4 = " << add(3, 4) << std::endl;
    
    // Smart pointers
    std::shared_ptr<std::vector<int>> shared = std::make_shared<std::vector<int>>();
    shared->push_back(10);
    shared->push_back(20);
    std::cout << "Shared pointer vector size: " << shared->size() << std::endl;
    
    // Structured binding (C++17)
    std::pair<std::string, int> person = {"C++", 2020};
    auto [name, year] = person;
    std::cout << "Structured binding: " << name << " " << year << std::endl;
}
"""
    }
    
    if language not in templates:
        return jsonify({
            "error": f"No template available for '{language}'"
        }), 404
    
    return jsonify({
        "template": templates.get(language, ""),
        "language": language
    })

# Run code endpoint
@app.route('/api/run-code', methods=['POST'])
def run_code():
    data = request.json
    if not data or 'code' not in data or 'language' not in data:
        return jsonify({"error": "Invalid request. Provide code and language."}), 400
    
    code = data['code']
    language = data['language']
    
    if not code.strip():
        return jsonify({"error": "No code provided"}), 400
    
    # Quick security check for potentially harmful code
    if is_potentially_harmful(code, language):
        return jsonify({
            "error": "Code execution blocked due to security concerns. The code appears to contain potentially harmful operations.",
            "details": "For security reasons, certain operations like file system access, network operations, and system command execution are restricted."
        }), 403
    
    # Map of languages to file extensions and execution commands
    language_configs = {
        'python': {
            'extension': '.py',
            'command': lambda file_path: ['python', file_path],
            'timeout': 20  # Increased timeout for complex Python scripts
        },
        'javascript': {
            'extension': '.js',
            'command': lambda file_path: ['node', file_path],
            'timeout': 20  # Increased timeout for JavaScript with dependencies
        },
        'java': {
            'extension': '.java',
            'command': lambda file_path: compile_and_run_java(file_path),
            'timeout': 30  # Increased timeout for Java compilation and execution
        },
        'htmlmixed': {
            'extension': '.html',
            # For HTML, we don't execute but return a "rendered successfully" message
            'command': lambda file_path: ['echo', 'HTML file processed successfully. This would normally be viewed in a browser.'],
            'timeout': 5
        },
        'cpp': {
            'extension': '.cpp',
            'command': lambda file_path: compile_and_run_cpp(file_path),
            'timeout': 30  # Increased timeout for C++ compilation and execution
        }
    }
    
    # Check if language is supported
    if language not in language_configs:
        return jsonify({"error": f"Unsupported language: {language}"}), 400
    
    try:
        # Create temporary directory and file
        with tempfile.TemporaryDirectory() as temp_dir:
            # Get file extension and create temporary file
            file_extension = language_configs[language]['extension']
            file_name = f"temp_code{file_extension}"
            file_path = os.path.join(temp_dir, file_name)
            
            # Write code to file
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(code)
            
            # Get command to execute the code
            command = language_configs[language]['command'](file_path)
            timeout = language_configs[language]['timeout']
            
            # Run the command
            try:
                result = subprocess.run(
                    command,
                    cwd=temp_dir,
                    capture_output=True,
                    text=True,
                    timeout=timeout  # Set timeout to prevent long-running code
                )
                
                # Format output
                output = ""
                if result.stdout:
                    output += result.stdout
                
                if result.stderr:
                    if output:
                        output += "\n\nErrors/Warnings:\n"
                    output += result.stderr
                
                if not output:
                    output = "Program executed successfully with no output."
                
                return jsonify({
                    "output": output,
                    "exit_code": result.returncode
                })
                
            except subprocess.TimeoutExpired:
                return jsonify({"error": f"Code execution timed out after {timeout} seconds."}), 408
            
            except Exception as e:
                return jsonify({"error": f"Error executing code: {str(e)}"}), 500
    
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# Helper functions for language compilation and execution
def compile_and_run_java(file_path):
    """
    Enhanced Java compilation function that handles dependencies.
    The server should have JDK installed with common libraries.
    """
    temp_dir = os.path.dirname(file_path)
    file_name = os.path.basename(file_path)
    class_name = get_java_class_name(file_path)
    
    try:
        # Create a lib directory for any JAR dependencies if it doesn't exist
        lib_dir = os.path.join(temp_dir, "lib")
        if not os.path.exists(lib_dir):
            os.makedirs(lib_dir)
            
        # Set up classpath - include the current directory and lib directory
        classpath = f"{temp_dir}{os.pathsep}{lib_dir}{os.pathsep}."
            
        # Compile Java file with classpath
        compile_result = subprocess.run(
            ['javac', '-cp', classpath, file_name], 
            cwd=temp_dir, 
            capture_output=True,
            text=True,
            check=False
        )
        
        if compile_result.returncode != 0:
            return ['echo', f"Compilation Error: {compile_result.stderr}"]
        
        # Run Java program with classpath
        return ['java', '-cp', classpath, class_name]
    except Exception as e:
        return ['echo', f"Error setting up Java environment: {str(e)}"]

def get_java_class_name(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    
    # Extract class name using regex
    match = re.search(r'public\s+class\s+(\w+)', content)
    if match:
        return match.group(1)
    return "Main"  # Fallback class name

def compile_and_run_csharp(file_path):
    temp_dir = os.path.dirname(file_path)
    file_name = os.path.basename(file_path)
    executable = os.path.join(temp_dir, 'program.exe')
    
    # Compile C# file
    subprocess.run(['csc', file_name, '-out:program.exe'], cwd=temp_dir, check=True)
    
    # Run C# program
    if os.name == 'nt':  # Windows
        return [executable]
    else:  # Unix/Linux/Mac
        return ['mono', executable]

def compile_and_run_go(file_path):
    temp_dir = os.path.dirname(file_path)
    file_name = os.path.basename(file_path)
    executable = os.path.join(temp_dir, 'program')
    
    # Compile Go file
    subprocess.run(['go', 'build', '-o', 'program', file_name], cwd=temp_dir, check=True)
    
    # Run Go program
    return [executable]

def compile_and_run_c(file_path):
    temp_dir = os.path.dirname(file_path)
    file_name = os.path.basename(file_path)
    executable = os.path.join(temp_dir, 'program')
    
    # Compile C file
    subprocess.run(['gcc', file_name, '-o', 'program'], cwd=temp_dir, check=True)
    
    # Run C program
    return [executable]

def compile_and_run_cpp(file_path):
    """
    Enhanced C++ compilation function that handles complex dependencies.
    The server should have g++ installed with common libraries.
    """
    temp_dir = os.path.dirname(file_path)
    file_name = os.path.basename(file_path)
    executable = os.path.join(temp_dir, 'program')
    
    try:
        # Compile C++ file with standard libraries and C++17 support
        compile_result = subprocess.run(
            ['g++', file_name, '-o', 'program', '-std=c++17', '-pthread'], 
            cwd=temp_dir, 
            capture_output=True,
            text=True,
            check=False
        )
        
        if compile_result.returncode != 0:
            return ['echo', f"Compilation Error: {compile_result.stderr}"]
        
        # Run C++ program
        return [executable]
    except Exception as e:
        return ['echo', f"Error setting up C++ environment: {str(e)}"]

# GitHub push endpoint
@app.route('/api/github-push', methods=['POST'])
def github_push():
    data = request.json
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    # Extract data
    code = data.get('code')
    filename = data.get('filename')
    commit_message = data.get('commit_message')
    repo_url = data.get('repo_url')

    # Validate inputs
    if not code:
        return jsonify({"success": False, "error": "No code provided"}), 400
    if not filename:
        return jsonify({"success": False, "error": "No filename provided"}), 400
    if not commit_message:
        return jsonify({"success": False, "error": "No commit message provided"}), 400
    if not repo_url:
        return jsonify({"success": False, "error": "No repository URL provided"}), 400

    try:
        # Create a temporary directory for the operation
        with tempfile.TemporaryDirectory() as temp_dir:
            logger.info(f"Created temp directory: {temp_dir} for GitHub push")
            
            # Clone the repository with a timeout
            try:
                logger.info(f"Cloning repository: {repo_url}")
                clone_result = subprocess.run(
                    ['git', 'clone', repo_url, temp_dir],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=60  # Set a reasonable timeout
                )
                
                if clone_result.returncode != 0:
                    error_message = f"Failed to clone repository: {clone_result.stderr}"
                    logger.error(error_message)
                    return jsonify({
                        "success": False,
                        "error": "Failed to clone repository",
                        "details": error_message
                    }), 500
            except subprocess.TimeoutExpired:
                logger.error("Timeout while cloning repository")
                return jsonify({
                    "success": False,
                    "error": "Timeout while cloning repository",
                    "details": "The operation took too long and was terminated"
                }), 500
            except Exception as e:
                logger.error(f"Exception during repository clone: {str(e)}")
                return jsonify({
                    "success": False,
                    "error": "Failed to clone repository",
                    "details": str(e)
                }), 500
            
            # Write the code to the file
            file_path = os.path.join(temp_dir, filename)
            
            # Ensure directory exists if filename includes subdirectories
            os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
            
            # Check if the file already exists and compare contents
            try:
                if os.path.exists(file_path):
                    logger.info(f"File exists, checking for content changes: {file_path}")
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            existing_content = f.read()
                        
                        # If content is identical, no need to update
                        if existing_content == code:
                            logger.info(f"File content unchanged: {filename}")
                            return jsonify({
                                "success": True,
                                "message": "No changes detected - file content is identical",
                                "filename": filename,
                                "timestamp": datetime.datetime.now().isoformat()
                            })
                    except UnicodeDecodeError:
                        # Try with a different encoding if UTF-8 fails
                        with open(file_path, 'r', encoding='latin-1') as f:
                            existing_content = f.read()
                        
                        # Compare with latin-1 encoding
                        if existing_content == code:
                            logger.info(f"File content unchanged (latin-1 encoding): {filename}")
                            return jsonify({
                                "success": True,
                                "message": "No changes detected - file content is identical",
                                "filename": filename,
                                "timestamp": datetime.datetime.now().isoformat()
                            })
            except Exception as e:
                logger.warning(f"Error comparing file contents: {str(e)}")
                # Continue with the process even if comparison fails
            
            try:
                logger.info(f"Writing code to file: {file_path}")
                # Safely write the code to the file with proper encoding
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(code)
            except Exception as e:
                logger.error(f"Error writing file: {str(e)}")
                return jsonify({
                    "success": False,
                    "error": "Failed to write file",
                    "details": str(e)
                }), 500
            
            # Configure Git user
            try:
                logger.info("Configuring Git user")
                subprocess.run(['git', 'config', 'user.name', 'Secure Code AI'], cwd=temp_dir, check=True)
                subprocess.run(['git', 'config', 'user.email', 'secureai@example.com'], cwd=temp_dir, check=True)
            except Exception as e:
                logger.error(f"Error configuring Git user: {str(e)}")
                return jsonify({
                    "success": False,
                    "error": "Failed to configure Git user",
                    "details": str(e)
                }), 500
            
            # Check if there are any changes to commit
            try:
                logger.info("Checking for file changes")
                status_result = subprocess.run(
                    ['git', 'status', '--porcelain', filename],
                    cwd=temp_dir,
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                # If status is empty, there are no changes to commit
                if not status_result.stdout.strip():
                    logger.info(f"No changes detected for file: {filename}")
                    return jsonify({
                        "success": True,
                        "message": "No changes detected - file is already up to date",
                        "filename": filename,
                        "timestamp": datetime.datetime.now().isoformat()
                    })
            except Exception as e:
                logger.error(f"Error checking file status: {str(e)}")
                # Continue with the process even if status check fails
            
            # Add file to Git
            try:
                logger.info(f"Adding file to Git: {filename}")
                add_result = subprocess.run(
                    ['git', 'add', filename],
                    cwd=temp_dir,
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                if add_result.returncode != 0:
                    error_message = f"Failed to add file: {add_result.stderr}"
                    logger.error(error_message)
                    return jsonify({
                        "success": False,
                        "error": "Failed to add file to Git",
                        "details": error_message
                    }), 500
            except Exception as e:
                logger.error(f"Exception during git add: {str(e)}")
                return jsonify({
                    "success": False,
                    "error": "Failed to add file to Git",
                    "details": str(e)
                }), 500
            
            # Commit the changes
            try:
                logger.info(f"Committing changes with message: {commit_message}")
                commit_result = subprocess.run(
                    ['git', 'commit', '-m', commit_message],
                    cwd=temp_dir,
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                # Log the full commit output for better debugging
                logger.info(f"Git commit stdout: {commit_result.stdout}")
                logger.info(f"Git commit stderr: {commit_result.stderr}")
                
                # Check for various "nothing to commit" messages in both stdout and stderr
                nothing_to_commit_patterns = [
                    'nothing to commit',
                    'no changes added to commit',
                    'nothing added to commit',
                    'working tree clean',
                    'branch is up to date',
                    'no changes',
                    'already up-to-date'
                ]
                
                # Check both stdout and stderr for any of these patterns
                stdout_lower = commit_result.stdout.lower()
                stderr_lower = commit_result.stderr.lower()
                
                nothing_to_commit = any(pattern in stdout_lower or pattern in stderr_lower 
                                      for pattern in nothing_to_commit_patterns)
                
                if commit_result.returncode != 0:
                    if nothing_to_commit:
                        # This is not a failure case, just means file is unchanged
                        logger.info("Nothing to commit - file unchanged or already up to date")
                        return jsonify({
                            "success": True,
                            "message": "No changes detected - file is already up to date",
                            "filename": filename,
                            "timestamp": datetime.datetime.now().isoformat()
                        })
                    else:
                        error_message = f"Failed to commit changes: {commit_result.stderr}"
                        logger.error(error_message)
                        return jsonify({
                            "success": False,
                            "error": "Failed to commit changes",
                            "details": error_message
                        }), 500
            except Exception as e:
                logger.error(f"Exception during git commit: {str(e)}")
                return jsonify({
                    "success": False,
                    "error": "Failed to commit changes",
                    "details": str(e)
                }), 500
            
            # Push the changes
            try:
                logger.info("Pushing changes to remote repository")
                push_result = subprocess.run(
                    ['git', 'push'],
                    cwd=temp_dir,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=60  # Set a reasonable timeout
                )
                
                # Check for common harmless push messages
                nothing_to_push = (
                    'Everything up-to-date' in push_result.stdout or
                    'Everything up-to-date' in push_result.stderr or
                    'up to date' in push_result.stdout.lower() or
                    'up to date' in push_result.stderr.lower()
                )
                
                if push_result.returncode != 0:
                    if nothing_to_push:
                        # This is not a failure case
                        logger.info("Repository already up-to-date, nothing to push")
                        return jsonify({
                            "success": True,
                            "message": "Repository already up-to-date",
                            "filename": filename,
                            "timestamp": datetime.datetime.now().isoformat()
                        })
                    else:
                        error_message = f"Failed to push changes: {push_result.stderr}"
                        logger.error(error_message)
                        return jsonify({
                            "success": False,
                            "error": "Failed to push changes to GitHub",
                            "details": error_message
                        }), 500
            except subprocess.TimeoutExpired:
                logger.error("Timeout while pushing to repository")
                return jsonify({
                    "success": False,
                    "error": "Timeout while pushing to repository",
                    "details": "The operation took too long and was terminated"
                }), 500
            except Exception as e:
                logger.error(f"Exception during git push: {str(e)}")
                return jsonify({
                    "success": False,
                    "error": "Failed to push changes to GitHub",
                    "details": str(e)
                }), 500
            
        # Return success if everything worked
        logger.info(f"Successfully pushed code to GitHub: {filename}")
        return jsonify({
            "success": True,
            "message": "Code successfully pushed to GitHub",
            "filename": filename,
            "timestamp": datetime.datetime.now().isoformat()
        })
    
    except Exception as e:
        logger.error(f"Unexpected error pushing to GitHub: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Error pushing to GitHub",
            "details": str(e)
        }), 500

# GitHub retrieve endpoint
@app.route('/api/github-retrieve', methods=['POST'])
def github_retrieve():
    data = request.json
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    # Extract data
    filename = data.get('filename')
    repo_url = data.get('repo_url')

    # Validate inputs
    if not filename:
        return jsonify({"success": False, "error": "No filename provided"}), 400
    if not repo_url:
        return jsonify({"success": False, "error": "No repository URL provided"}), 400

    try:
        # Create a temporary directory for the operation
        with tempfile.TemporaryDirectory() as temp_dir:
            logger.info(f"Created temp directory: {temp_dir} for GitHub retrieve")
            
            # Clone the repository with a timeout
            try:
                logger.info(f"Cloning repository: {repo_url}")
                clone_result = subprocess.run(
                    ['git', 'clone', repo_url, temp_dir],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=60  # Set a reasonable timeout
                )
                
                if clone_result.returncode != 0:
                    error_message = f"Failed to clone repository: {clone_result.stderr}"
                    logger.error(error_message)
                    return jsonify({
                        "success": False,
                        "error": "Failed to clone repository",
                        "details": error_message
                    }), 500
            except subprocess.TimeoutExpired:
                logger.error("Timeout while cloning repository")
                return jsonify({
                    "success": False,
                    "error": "Timeout while cloning repository",
                    "details": "The operation took too long and was terminated"
                }), 500
            except Exception as e:
                logger.error(f"Exception during repository clone: {str(e)}")
                return jsonify({
                    "success": False,
                    "error": "Failed to clone repository",
                    "details": str(e)
                }), 500
            
            # Read the code from the file
            file_path = os.path.join(temp_dir, filename)
            
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return jsonify({
                    "success": False,
                    "error": "File not found in repository",
                    "details": f"The file '{filename}' does not exist in the repository."
                }), 404
            
            # Check if the file is empty
            if os.path.getsize(file_path) == 0:
                logger.warning(f"File is empty: {file_path}")
                return jsonify({
                    "success": True,
                    "code": "",
                    "language": "plaintext",
                    "filename": filename,
                    "message": "The file exists but is empty",
                    "timestamp": datetime.datetime.now().isoformat()
                })
            
            try:
                logger.info(f"Reading file content: {file_path}")
                # Safely read the file with proper encoding detection
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        code = f.read()
                except UnicodeDecodeError:
                    # Try with a different encoding if UTF-8 fails
                    with open(file_path, 'r', encoding='latin-1') as f:
                        code = f.read()
                
                # Determine file extension for language detection
                _, ext = os.path.splitext(filename)
                language = detect_language_from_extension(ext)
                
                logger.info(f"Successfully retrieved file from GitHub: {filename}")
                return jsonify({
                    "success": True,
                    "code": code,
                    "language": language,
                    "filename": filename,
                    "timestamp": datetime.datetime.now().isoformat()
                })
            except Exception as e:
                logger.error(f"Error reading file: {str(e)}")
                return jsonify({
                    "success": False,
                    "error": "Failed to read file",
                    "details": str(e)
                }), 500
            
    except Exception as e:
        logger.error(f"Unexpected error retrieving from GitHub: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Error retrieving from GitHub",
            "details": str(e)
        }), 500

# Helper function to detect language from file extension
def detect_language_from_extension(ext):
    ext = ext.lower()
    language_map = {
        '.py': 'python',
        '.js': 'javascript',
        '.html': 'html',
        '.java': 'java',
        '.cpp': 'cpp',
        '.c': 'c',
        '.h': 'cpp',
        '.hpp': 'cpp'
    }
    return language_map.get(ext, 'plaintext')

key = b'ThisIsASecretKey'  # Must be 16, 24, or 32 bytes

def encrypt(plaintext: str, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(plaintext.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode('utf-8')  # Output as string

def decrypt(ciphertext_b64: str, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = base64.b64decode(ciphertext_b64.encode('utf-8'))
    decrypted = cipher.decrypt(encrypted)
    return unpad(decrypted, AES.block_size).decode('utf-8')



# Function to check if code contains potentially harmful operations
def is_potentially_harmful(code, language):
    # Allow more functionality for our selected languages while maintaining security
    # Common dangerous patterns across languages - we're more permissive but still check highly risky operations
    dangerous_patterns = [
        # Most dangerous system command execution patterns
        r'os\.system\(\s*[\'"]rm\s+-rf', r'exec\(\s*[\'"]rm', 
        r'Runtime\.getRuntime\(\)\.exec\(\s*[\'"]rm',
        r'process\.exec\(\s*[\'"]rm',
        
        # Network operations to suspicious domains
        r'\.connect\(\s*[\'"]evil\.com', r'urllib\.request\.urlopen\(\s*[\'"]http://malicious',
    ]
    
    # Language-specific patterns - more permissive for legitimate use cases
    if language == 'python':
        dangerous_patterns.extend([
            r'importlib\.reload\(os\)\.system', r'__import__\([\'"]os[\'"]\)\.system\([\'"]rm\s+-rf'
        ])
    elif language == 'javascript':
        dangerous_patterns.extend([
            r'child_process.*exec\(\s*[\'"]rm\s+-rf', r'require\([\'"]child_process[\'"]\).*exec\(\s*[\'"]rm'
        ])
    elif language == 'java':
        dangerous_patterns.extend([
            r'ProcessBuilder\([\'"]rm[\'"],\s*[\'"]-rf' 
        ])
    elif language == 'cpp':
        dangerous_patterns.extend([
            r'system\([\'"]rm\s+-rf' 
        ])
    
    # Check if code contains any dangerous patterns
    for pattern in dangerous_patterns:
        if re.search(pattern, code):
            return True
    
    return False

if __name__ == '__main__':
    app.run(debug=True, port=5000) 