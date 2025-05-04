import os
import re
import ast
import argparse
import logging
from typing import List, Dict, Any, Tuple, Optional
import numpy as np
import pickle
import hashlib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import openai_codex
import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ReportManager:
    """Manages report generation and updates"""
    def __init__(self, base_dir: str):
        self.reports_dir = os.path.join(base_dir, 'security_reports')
        os.makedirs(self.reports_dir, exist_ok=True)
        self.report_file = os.path.join(self.reports_dir, 'vulnerability_report.txt')
        self.fixes_file = os.path.join(self.reports_dir, 'secure_code.txt')
        self.clear_reports()
    
    def clear_reports(self) -> None:
        """Clear all existing reports"""
        os.makedirs(self.reports_dir, exist_ok=True)
        for file_path in [self.report_file, self.fixes_file]:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("")
                logger.info(f"Cleared report file: {file_path}")
            except Exception as e:
                logger.error(f"Error clearing report {file_path}: {e}")
    
    def update_reports(self, report: str, secure_code: str) -> None:
        """Update both reports atomically"""
        # Check if reports directory exists (create if not)
        os.makedirs(self.reports_dir, exist_ok=True)
        
        # Define temporary file paths
        temp_report = f"{self.report_file}.tmp"
        temp_fixes = f"{self.fixes_file}.tmp"
        
        try:
            # Write to temporary files first
            with open(temp_report, 'w', encoding='utf-8') as f:
                f.write(report)
            with open(temp_fixes, 'w', encoding='utf-8') as f:
                f.write(secure_code)
            
            # Then atomically replace the old files
            os.replace(temp_report, self.report_file)
            os.replace(temp_fixes, self.fixes_file)
            
            logger.info(f"Reports updated successfully. Report: {self.report_file}, Fixes: {self.fixes_file}")
        except Exception as e:
            logger.error(f"Error updating reports: {e}")
            # Try direct write as fallback if atomic replace fails
            try:
                with open(self.report_file, 'w', encoding='utf-8') as f:
                    f.write(report)
                with open(self.fixes_file, 'w', encoding='utf-8') as f:
                    f.write(secure_code)
                logger.info("Reports updated via direct write (fallback method)")
            except Exception as e2:
                logger.error(f"Error in fallback report update: {e2}")
            
            # Clean up temp files if they exist
            for temp_file in [temp_report, temp_fixes]:
                if os.path.exists(temp_file):
                    try:
                        os.remove(temp_file)
                    except Exception:
                        pass

class VulnerabilityScanner:
    """
    AI-powered tool to scan code for security vulnerabilities and suggest fixes.
    """
    
    # Common vulnerability patterns
    VULNERABILITY_PATTERNS = {
        'sql_injection': [
            r'execute\s*\(\s*[\'"`].*?\bSELECT\b.*?\+.*?[\'"`]',
            r'execute\s*\(\s*[\'"`].*?\bINSERT\b.*?\+.*?[\'"`]',
            r'execute\s*\(\s*[\'"`].*?\bUPDATE\b.*?\+.*?[\'"`]',
            r'execute\s*\(\s*[\'"`].*?\bDELETE\b.*?\+.*?[\'"`]',
            r'cursor\.execute\s*\([^,]*?%s',
            r'cursor\.execute\s*\(.*?\+.*?\)',
            r'\.execute\s*\(.*?\+.*?\)',
            r'sqlite3.*?execute\s*\(.*?\+.*?\)',
            r'cursor\.executemany\s*\(.*?\+.*?\)',
            r'cursor\.executescript\s*\(.*?\)'
        ],
        'xss': [
            r'render\s*\([^,]*?\+.*?\)',
            r'innerHTML\s*=.*?\+.*?',
            r'document\.write\s*\(.*?\+.*?\)',
            r'\.html\s*\(.*?\+.*?\)'
        ],
        'path_traversal': [
            r'open\s*\([^,]*?\+.*?\)',
            r'os\.path\.join\s*\([^,]*?\.\..*?\)',
            r'file_get_contents\s*\([^,]*?\+.*?\)'
        ],
        'command_injection': [
            r'os\.system\s*\([^,]*?\+.*?\)',
            r'subprocess\.call\s*\([^,]*?\+.*?\)',
            r'subprocess\.Popen\s*\([^,]*?\+.*?\)',
            r'exec\s*\([^,]*?\+.*?\)',
            r'eval\s*\([^,]*?\+.*?\)'
        ],
        'insecure_deserialization': [
            r'pickle\.loads\s*\(',
            r'yaml\.load\s*\([^,]*?Loader=None',
            r'yaml\.load\s*\([^,]*?Loader=yaml\.Loader',
            r'marshal\.loads\s*\('
        ],
        'weak_cryptography': [
            r'md5\s*\(',
            r'hashlib\.md5\s*\(',
            r'hashlib\.sha1\s*\(',
            r'random\.'
        ],
        'hard_coded_credentials': [
            r'password\s*=\s*[\'"`][^\'"]+[\'"`]',
            r'api_key\s*=\s*[\'"`][^\'"]+[\'"`]',
            r'secret\s*=\s*[\'"`][^\'"]+[\'"`]',
            r'token\s*=\s*[\'"`][^\'"]+[\'"`]'
        ],
        'csrf': [
            r'@csrf_exempt',
            r'csrf_token.*?=.*?none',
            r'csrf_protection\s*=\s*false'
        ],
        'xxe_injection': [
            r'xml\.etree\.ElementTree\.parse\(',
            r'minidom\.parse\(',
            r'xmlrpclib\.loads\(',
            r'parseString\('
        ],
        'ldap_injection': [
            r'ldap\.search\s*\(.*?\+.*?\)',
            r'ldap\.bind\s*\(.*?\+.*?\)'
        ],
        'buffer_overflow': [
            r'strcpy\(',
            r'strcat\(',
            r'gets\(',
            r'sprintf\('
        ],
        'session_management': [
            r'session\.id\s*=',
            r'sessionid\s*=.*?[\'"`][^\'"]+[\'"`]',
            r'session\.cookie_secure\s*=\s*false'
        ],
        'sensitive_data_exposure': [
            r'\.log\(.*?(password|secret|key|token)',
            r'print.*?(password|secret|key|token)',
            r'debug.*?(password|secret|key|token)'
        ],
        'broken_authentication': [
            r'auth_token\s*=\s*[\'"`][^\'"]+[\'"`]',
            r'basic_auth\s*=\s*[\'"`][^\'"]+[\'"`]',
            r'bearer_token\s*=\s*[\'"`][^\'"]+[\'"`]'
        ],
        'cors_misconfiguration': [
            r'Access-Control-Allow-Origin\s*:\s*\*',
            r'response\.headers\[.*?origin.*?\]\s*=\s*\*'
        ],
        'insecure_file_upload': [
            r'upload.*?\.exe',
            r'upload.*?\.php',
            r'content_type.*?=.*?application/.*'
        ],
        'api_security': [
            r'api_key\s*=\s*[\'"`][^\'"]+[\'"`]',
            r'auth_token\s*=\s*[\'"`][^\'"]+[\'"`]',
            r'rate_limit.*?=.*?none'
        ],
        'insecure_dependencies': [
            r'package\.json',
            r'requirements\.txt',
            r'setup\.py'
        ],
        'debug_exposure': [
            r'DEBUG\s*=\s*True',
            r'DEVELOPMENT_MODE\s*=\s*True',
            r'show_errors\s*=\s*true'
        ],
        'dom_xss': [
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'document\.write\(',
            r'eval\('
        ]
    }
    
    # Fix suggestions for each vulnerability type
    FIX_SUGGESTIONS = {
        'sql_injection': [
            "Use parameterized queries with placeholders instead of string concatenation",
            "Example: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            "Consider using an ORM like SQLAlchemy to help prevent SQL injection"
        ],
        'xss': [
            "Sanitize user input before rendering in HTML",
            "Use templating engines with automatic escaping",
            "Consider using Content Security Policy (CSP)"
        ],
        'path_traversal': [
            "Validate and sanitize file paths",
            "Use os.path.abspath() and os.path.normpath() to resolve paths",
            "Consider using path libraries like pathlib that handle path manipulation securely"
        ],
        'command_injection': [
            "Avoid passing user input directly to shell commands",
            "Use subprocess with shell=False and a list of arguments",
            "Example: subprocess.run(['ls', directory], shell=False)"
        ],
        'insecure_deserialization': [
            "Avoid deserializing untrusted data",
            "Use safer alternatives like JSON for data serialization",
            "If using YAML, use yaml.safe_load() instead of yaml.load()"
        ],
        'weak_cryptography': [
            "Use strong hashing algorithms like SHA-256 or SHA-3",
            "For passwords, use specialized algorithms like bcrypt or Argon2",
            "Use cryptographically secure random number generators from secrets module"
        ],
        'hard_coded_credentials': [
            "Store credentials in environment variables",
            "Use a secure secrets management system",
            "Consider using tools like AWS Secrets Manager or HashiCorp Vault"
        ],
        'csrf': [
            "Enable CSRF protection middleware",
            "Use anti-CSRF tokens in forms",
            "Implement SameSite cookie attribute"
        ],
        'xxe_injection': [
            "Disable XXE processing in XML parsers",
            "Use safe XML parsing libraries",
            "Implement XML parsing security controls"
        ],
        'ldap_injection': [
            "Use LDAP escape functions",
            "Implement input validation for LDAP queries",
            "Use parameterized LDAP queries"
        ],
        'buffer_overflow': [
            "Use safe string functions (strncpy, strncat)",
            "Implement proper buffer size checks",
            "Use modern string handling libraries"
        ],
        'session_management': [
            "Use secure session configuration",
            "Implement session timeout",
            "Use secure session storage"
        ],
        'sensitive_data_exposure': [
            "Remove sensitive data from logs",
            "Implement proper log sanitization",
            "Use secure logging practices"
        ],
        'broken_authentication': [
            "Implement proper authentication mechanisms",
            "Use secure token storage",
            "Implement OAuth or JWT properly"
        ],
        'cors_misconfiguration': [
            "Specify allowed origins explicitly",
            "Implement proper CORS policies",
            "Use secure CORS configuration"
        ],
        'insecure_file_upload': [
            "Validate file types and content",
            "Implement file size limits",
            "Use secure file storage"
        ],
        'api_security': [
            "Implement proper API authentication",
            "Use rate limiting",
            "Implement API versioning"
        ],
        'insecure_dependencies': [
            "Regular dependency updates",
            "Use dependency scanning tools",
            "Implement lockfile mechanism"
        ],
        'debug_exposure': [
            "Disable debug mode in production",
            "Remove debug endpoints",
            "Implement proper error handling"
        ],
        'dom_xss': [
            "Use safe DOM manipulation methods",
            "Sanitize user input for DOM operations",
            "Implement CSP headers"
        ]
    }

    # Add vulnerability descriptions dictionary
    VULNERABILITY_DESCRIPTIONS = {
        'sql_injection': """SQL Injection vulnerabilities occur when untrusted data is used to construct SQL queries. 
        This can allow attackers to manipulate your database queries and potentially access, modify or delete data.""",
        
        'command_injection': """Command Injection vulnerabilities happen when user input is passed directly to system commands.
        Attackers can inject malicious commands that will be executed on your system.""",
        
        'path_traversal': """Path Traversal vulnerabilities allow attackers to access files outside the intended directory
        by manipulating file paths, potentially exposing sensitive system files.""",
        
        'xss': """Cross-Site Scripting (XSS) vulnerabilities occur when user input is displayed without proper sanitization.
        Attackers can inject malicious scripts that execute in users' browsers.""",
        
        'potential_vulnerability': """Potential security weakness detected in code structure or patterns.
        This requires manual review to confirm and assess the actual risk.""",
        
        'insecure_deserialization': """Insecure Deserialization vulnerabilities occur when untrusted data is deserialized.
        Attackers can craft malicious serialized objects to execute code.""",
        
        'weak_cryptography': """Weak Cryptography refers to the use of outdated or insecure cryptographic methods.
        This can lead to data exposure or system compromise.""",
        
        'hard_coded_credentials': """Hard-coded Credentials in source code pose a security risk as they can be
        discovered through code access or decompilation."""
    }


    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the scanner with an optional pre-trained model or create a basic model.
        
        Args:
            model_path: Path to a pre-trained model file
        """
        self.vectorizer = TfidfVectorizer(max_features=1000)
        self.model = RandomForestClassifier(n_estimators=100)
        
        # Try to load existing model
        if (model_path and os.path.exists(model_path)):
            try:
                self._load_model(model_path)
                logger.info(f"Model loaded from {model_path}")
            except Exception as e:
                logger.warning(f"Failed to load model: {e}")
                logger.info("Using default model")
                self._create_basic_model()
        else:
            logger.info("Creating basic model...")
            self._create_basic_model()
        
        self.report_manager = ReportManager(os.path.dirname(os.path.realpath(__file__)))
    
    def _create_basic_model(self):
        """Create a basic model with sample vulnerable and non-vulnerable code."""
        # Sample vulnerable code snippets
        vulnerable_samples = [
            """def login(username, password):
                conn = sqlite3.connect('users.db')
                cursor = conn.cursor()
                query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
                cursor.execute(query)
                return cursor.fetchone()""",
            
            """def get_user(user_id):
                conn = sqlite3.connect('users.db')
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE id = " + user_id)
                return cursor.fetchone()""",
            
            """def update_profile(user_id, data):
                conn = sqlite3.connect('users.db')
                cursor = conn.cursor()
                query = f"UPDATE users SET name = '{data['name']}' WHERE id = {user_id}"
                cursor.execute(query)
                conn.commit()""",
            
            """def get_logs(date):
                os.system("cat /var/log/app.log | grep " + date)""",
            
            """def render_profile(user_data):
                template = "<div>Name: " + user_data['name'] + "</div>"
                return template""",
            
            """def read_file(filename):
                with open(user_input + ".txt", "r") as f:
                    return f.read()""",
                    
            """def store_secret():
                api_key = "12345secret_key_here"
                password = "admin123"
                return encrypt(api_key)"""
        ]
        
        # Sample safe code snippets
        safe_samples = [
            """def login(username, password):
                conn = sqlite3.connect('users.db')
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
                return cursor.fetchone()""",
            
            """def get_user(user_id):
                conn = sqlite3.connect('users.db')
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
                return cursor.fetchone()""",
            
            """def update_profile(user_id, data):
                conn = sqlite3.connect('users.db')
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET name = ? WHERE id = ?", (data['name'], user_id))
                conn.commit()""",
            
            """def get_logs(date):
                subprocess.run(["cat", "/var/log/app.log"], shell=False)
                subprocess.run(["grep", date], shell=False)""",
            
            """def render_profile(user_data):
                import html
                template = f"<div>Name: {html.escape(user_data['name'])}</div>"
                return template""",
            
            """def read_file(filename):
                import os.path
                safe_path = os.path.normpath(os.path.join(safe_dir, filename))
                if not safe_path.startswith(safe_dir):
                    return "Access denied"
                with open(safe_path, "r") as f:
                    return f.read()""",
                    
            """def store_secret():
                import os
                api_key = os.environ.get("API_KEY")
                password = os.environ.get("PASSWORD")
                return encrypt(api_key)"""
        ]
        
        # Combine samples
        all_samples = vulnerable_samples + safe_samples
        labels = [1] * len(vulnerable_samples) + [0] * len(safe_samples)
        
        # Train basic model
        self.vectorizer.fit(all_samples)
        X = self.vectorizer.transform(all_samples)
        self.model.fit(X, labels)
        logger.info("Basic model trained with sample data")
    
    def _load_model(self, model_path: str) -> None:
        """
        Load a pre-trained model.
        
        Args:
            model_path: Path to the model file
        """
        model_data = openai_codex.load(model_path)
        self.vectorizer = model_data['vectorizer']
        self.model = model_data['model']
    
    def save_model(self, model_path: str) -> None:
        """
        Save the trained model.
        
        Args:
            model_path: Path to save the model file
        """
        model_data = {
            'vectorizer': self.vectorizer,
            'model': self.model
        }
        openai_codex.dump(model_data, model_path)
        logger.info(f"Model saved to {model_path}")
    
    def train(self, code_samples: List[str], labels: List[int]) -> None:
        """
        Train the model with labeled code samples.
        
        Args:
            code_samples: List of code snippets
            labels: List of labels (1 for vulnerable, 0 for safe)
        """
        logger.info("Training model...")
        self.vectorizer.fit(code_samples)
        X = self.vectorizer.transform(code_samples)
        self.model.fit(X, labels)
        logger.info("Model training completed")
    
    def clear_previous_reports(self) -> None:
        """Clear any existing vulnerability reports."""
        reports_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'security_reports')
        if os.path.exists(reports_dir):
            try:
                for file in os.listdir(reports_dir):
                    file_path = os.path.join(reports_dir, file)
                    if file.endswith('.txt'):
                        open(file_path, 'w').close()  # Clear file contents
                logger.info("Previous reports cleared successfully")
            except Exception as e:
                logger.error(f"Error clearing previous reports: {e}")

    def clear_active_reports(self) -> None:
        """Clear and prepare reports for live updating."""
        reports_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'security_reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        # Create or clear live report files
        live_report = os.path.join(reports_dir, 'live_vulnerability_report.txt')
        live_fixes = os.path.join(reports_dir, 'live_secure_code.txt')
        
        # Clear existing live reports
        for file_path in [live_report, live_fixes]:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("")
            except Exception as e:
                logger.error(f"Error clearing live report {file_path}: {e}")
        
        return live_report, live_fixes

    def update_live_report(self, report_content: str, fixes_content: str, report_file: str, fixes_file: str) -> None:
        """Update live reports with new content."""
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
            with open(fixes_file, 'w', encoding='utf-8') as f:
                f.write(fixes_content)
        except Exception as e:
            logger.error(f"Error updating live reports: {e}")

    def analyze_code(self, code: str, file_name: str = "analyzed_file.py") -> List[Dict[str, Any]]:
        """
        Analyze code for security vulnerabilities.
        
        Args:
            code: The code to analyze
            file_name: Name of the file being analyzed
            
        Returns:
            List of detected vulnerabilities
        """
        # Clear previous reports before starting new analysis
        self.report_manager.clear_reports()
        
        # Get live report files
        live_report, live_fixes = self.clear_active_reports()
        vulnerabilities = []
        lines = code.split('\n')
        
        try:
            # First pass: Rule-based detection
            for vuln_type, patterns in self.VULNERABILITY_PATTERNS.items():
                for pattern in patterns:
                    for i, line in enumerate(lines):
                        if re.search(pattern, line):
                            context = self._get_context(lines, i)
                            vuln_type_confirmed = self._determine_vulnerability_type(context)
                            if vuln_type_confirmed != "potential_vulnerability":
                                vuln = {
                                    'type': vuln_type_confirmed,
                                    'line_number': i + 1,
                                    'line_content': line.strip(),
                                    'context': context,
                                    'confidence': 'High',
                                    'detection_method': 'pattern',
                                    'description': self.VULNERABILITY_DESCRIPTIONS.get(vuln_type_confirmed, ""),
                                    'fixes': self.FIX_SUGGESTIONS.get(vuln_type_confirmed, ["No specific fix available"])
                                }
                                vulnerabilities.append(vuln)
                                
                                # Generate and write reports
                                current_report = self.generate_detailed_report({file_name: vulnerabilities})
                                current_fixes = self.generate_secure_code(code, vulnerabilities)
                                
                                # Update final reports directly
                                self.report_manager.update_reports(current_report, current_fixes)
            
            # Second pass: ML-based detection
            code_blocks = self._extract_code_blocks(code)
            for block in code_blocks:
                # Skip if block already contains known vulnerabilities
                if not any(vuln['context'] in block for vuln in vulnerabilities):
                    X = self.vectorizer.transform([block])
                    prediction = self.model.predict_proba(X)[0]
                    
                    if prediction[1] > 0.8:  # Increased confidence threshold
                        vuln_type = self._determine_vulnerability_type(block)
                        if vuln_type != "potential_vulnerability":
                            vuln = {
                                'type': vuln_type,
                                'line_number': self._find_block_start_line(block, lines),
                                'line_content': block.split('\n')[0].strip(),
                                'context': block,
                                'confidence': f'{prediction[1]:.2f}',
                                'detection_method': 'ml',
                                'description': self.VULNERABILITY_DESCRIPTIONS.get(vuln_type, ""),
                                'fixes': self.FIX_SUGGESTIONS.get(vuln_type, ["Review this code block for potential security issues"])
                            }
                            vulnerabilities.append(vuln)
                            
                            # Update final reports directly
                            current_report = self.generate_detailed_report({file_name: vulnerabilities})
                            current_fixes = self.generate_secure_code(code, vulnerabilities)
                            self.report_manager.update_reports(current_report, current_fixes)
                            
        except Exception as e:
            logger.error(f"Error during code analysis: {e}")
            
        # Ensure a final update happens even if no vulnerabilities were found
        if not vulnerabilities:
            self.report_manager.update_reports(
                "No vulnerabilities detected in the analyzed code.",
                "# No code fixes required. The analyzed code appears to be secure."
            )
            
        return vulnerabilities

    def _determine_vulnerability_type(self, code_block: str) -> str:
        """
        Determine the most likely vulnerability type in a code block.
        
        Args:
            code_block: The code block to analyze
            
        Returns:
            The most likely vulnerability type
        """
        # Check against each vulnerability pattern first
        pattern_matches = {}
        for vuln_type, patterns in self.VULNERABILITY_PATTERNS.items():
            for pattern in patterns:
                matches = len(re.findall(pattern, code_block))
                if matches > 0:
                    pattern_matches[vuln_type] = pattern_matches.get(vuln_type, 0) + matches

        if pattern_matches:
            # Return the vulnerability type with the most matches
            return max(pattern_matches.items(), key=lambda x: x[1])[0]

        # If no patterns match, perform additional checks
        if re.search(r'input\s*\(.*?\)|raw_input\s*\(.*?\)', code_block):
            if re.search(r'execute|cursor', code_block):
                return 'sql_injection'
            elif re.search(r'system|popen|exec', code_block):
                return 'command_injection'
            elif re.search(r'open|read|write', code_block):
                return 'path_traversal'
            elif re.search(r'render|html', code_block):
                return 'xss'

        # Check for specific vulnerability indicators
        if re.search(r'password|secret|key|token', code_block):
            return 'hard_coded_credentials'
        elif re.search(r'md5|sha1', code_block):
            return 'weak_cryptography'
        elif re.search(r'pickle\.loads|yaml\.load', code_block):
            return 'insecure_deserialization'
        elif re.search(r'debug\s*=\s*true|DEBUG\s*=\s*True', code_block):
            return 'debug_exposure'
        elif re.search(r'csrf|csrf_exempt', code_block):
            return 'csrf'
        elif re.search(r'CORS|Access-Control-Allow', code_block):
            return 'cors_misconfiguration'

        # Only return potential_vulnerability if no specific type is detected
        return "potential_vulnerability"

    def _get_context(self, lines: List[str], index: int, context_size: int = 3) -> str:
        """Get surrounding context for a line of code."""
        start = max(0, index - context_size)
        end = min(len(lines), index + context_size + 1)
        return '\n'.join(lines[start:end])

    def _find_block_start_line(self, block: str, lines: List[str]) -> int:
        """Find the starting line number of a code block."""
        first_line = block.split('\n')[0].strip()
        for i, line in enumerate(lines):
            if line.strip() == first_line:
                return i + 1
        return 1
    
    def _extract_code_blocks(self, code: str) -> List[str]:
        """
        Extract meaningful code blocks for ML analysis.
        
        Args:
            code: The code to analyze
            
        Returns:
            List of code blocks
        """
        blocks = []
        
        # First try to extract function/method blocks
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_code = ast.get_source_segment(code, node)
                    if func_code:
                        blocks.append(func_code)
        except SyntaxError:
            # If AST parsing fails, fall back to simple line grouping
            pass
        
        # If no blocks found or parsing failed, use simpler approach
        if not blocks:
            current_block = []
            for line in code.split('\n'):
                if line.strip():
                    current_block.append(line)
                elif current_block:
                    blocks.append('\n'.join(current_block))
                    current_block = []
            if current_block:
                blocks.append('\n'.join(current_block))
        
        return blocks
    
    def suggest_fixes(self, vulnerability: Dict[str, Any]) -> List[str]:
        """
        Suggest fixes for a specific vulnerability.
        
        Args:
            vulnerability: The detected vulnerability
            
        Returns:
            List of fix suggestions
        """
        vuln_type = vulnerability['type']
        if vuln_type in self.FIX_SUGGESTIONS:
            return self.FIX_SUGGESTIONS[vuln_type]
        return ["No specific fix available"]
    
    def generate_report(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """
        Generate a detailed security analysis report.
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            
        Returns:
            Formatted report string
        """
        if not vulnerabilities:
            return "No vulnerabilities detected."
        
        report = "# Security Analysis Report\n\n"
        report += f"Total vulnerabilities detected: {len(vulnerabilities)}\n\n"
        
        # Group by vulnerability type
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln['type']
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        # Generate detailed report sections
        for vuln_type, vulns in vuln_types.items():
            report += f"## {vuln_type.replace('_', ' ').title()} ({len(vulns)})\n\n"
            
            for vuln in vulns:
                report += f"### Vulnerability Details\n"
                report += f"- Location: Line {vuln['line_number']}\n"
                report += f"- Vulnerable Code:\n```\n{vuln['line_content']}\n```\n"
                report += f"- Confidence Score: {vuln['confidence']}\n"
                report += f"- Detection Method: {vuln['detection_method']}\n"
                report += f"- Risk Level: {'High' if float(str(vuln['confidence'])) > 0.7 else 'Medium'}\n"
                report += "\n### Recommended Fixes:\n"
                for idx, fix in enumerate(vuln['fixes'], 1):
                    report += f"{idx}. {fix}\n"
                
                if vuln_type in self.FIX_SUGGESTIONS:
                    report += "\n### Code Example:\n"
                    if vuln_type == 'sql_injection':
                        report += "```python\n# Use parameterized queries\ncursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n```\n"
                    elif vuln_type == 'command_injection':
                        report += "```python\n# Use subprocess with arguments list\nsubprocess.run(['ls', directory], shell=False, check=True)\n```\n"
                    elif vuln_type == 'path_traversal':
                        report += "```python\nimport os\nsafe_path = os.path.normpath(os.path.join(safe_dir, filename))\nif not safe_path.startswith(safe_dir):\n    raise ValueError('Invalid path')\n```\n"
                
                report += "\n---\n\n"
        
        return report

    def generate_detailed_report(self, results: Dict[str, List[Dict[str, Any]]]) -> str:
        """Generate an enhanced detailed vulnerability report with explanations."""
        report = "=============== COMPREHENSIVE SECURITY ANALYSIS REPORT ===============\n\n"
        total_vulns = sum(len(vulns) for vulns in results.values())
        
        # Add severity levels
        severity_levels = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        
        # Calculate severity statistics
        for file_vulns in results.values():
            for vuln in file_vulns:
                confidence = float(str(vuln['confidence']))
                if confidence > 0.9:
                    severity_levels['Critical'] += 1
                elif confidence > 0.7:
                    severity_levels['High'] += 1
                elif confidence > 0.5:
                    severity_levels['Medium'] += 1
                else:
                    severity_levels['Low'] += 1
        
        report += "SUMMARY\n"
        report += f"Total files scanned: {len(results)}\n"
        report += f"Total vulnerabilities: {total_vulns}\n\n"
        
        report += "SEVERITY DISTRIBUTION\n"
        for level, count in severity_levels.items():
            report += f"{level}: {count}\n"
        
        report += "DETAILED FINDINGS BY FILE\n"
        report += "=========================\n\n"
        
        for file_path, file_vulns in results.items():
            report += f"File: {file_path}\n"
            report += "=" * 80 + "\n\n"
            
            # Group vulnerabilities by type for this file
            vuln_types = {}
            for vuln in file_vulns:
                vuln_type = vuln['type']
                if vuln_type not in vuln_types:
                    vuln_types[vuln_type] = []
                vuln_types[vuln_type].append(vuln)
            
            for vuln_type, vulns in vuln_types.items():
                report += f"## {vuln_type.replace('_', ' ').title()}\n\n"
                
                # Add vulnerability description
                if vuln_type in self.VULNERABILITY_DESCRIPTIONS:
                    report += "What is this vulnerability?\n"
                    report += "-" * 25 + "\n"
                    report += f"{self.VULNERABILITY_DESCRIPTIONS[vuln_type]}\n\n"
                
                report += "Found Instances:\n"
                report += "-" * 15 + "\n"
                
                for vuln in vulns:
                    report += f"\n### Instance at Line {vuln['line_number']}\n"
                    report += f"Vulnerable Code:\n```python\n{vuln['line_content']}\n```\n"
                    report += f"\nRisk Analysis:\n"
                    report += f"- Confidence: {vuln['confidence']}\n"
                    report += f"- Detection Method: {vuln['detection_method']}\n"
                    report += f"- Risk Level: {'Critical' if float(str(vuln['confidence'])) > 0.9 else 'High' if float(str(vuln['confidence'])) > 0.7 else 'Medium'}\n"
                    
                    report += "\nWhy is this vulnerable?\n"
                    if vuln_type == 'command_injection':
                        report += "This code directly uses user input in system commands without proper validation or sanitization.\n"
                    elif vuln_type == 'path_traversal':
                        report += "This code handles file paths without proper validation, allowing potential access outside intended directories.\n"
                    elif vuln_type == 'potential_vulnerability':
                        report += "This code contains patterns that might indicate security weaknesses and requires review.\n"
                    
                    report += "\nHow to Fix:\n"
                    for idx, fix in enumerate(vuln['fixes'], 1):
                        report += f"{idx}. {fix}\n"
                    
                    report += "\nSecure Code Example:\n"
                    if vuln_type in self.FIX_SUGGESTIONS:
                        if vuln_type == 'command_injection':
                            report += "```python\n# Use subprocess with arguments list\ncommand_args = ['/bin/grep', user_input]\nresult = subprocess.run(command_args, shell=False, check=True, capture_output=True)\n```\n"
                        elif vuln_type == 'path_traversal':
                            report += "```python\n# Use secure path handling\nfrom pathlib import Path\nsafe_path = Path(base_dir) / filename\nif not safe_path.is_relative_to(base_dir):\n    raise ValueError('Invalid path')\n```\n"
                    
                    report += "\n" + "-" * 50 + "\n"
                
                report += "\n"
            
            report += "\n" + "=" * 80 + "\n\n"
        
        return report

    def generate_secure_code(self, code: str, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate secure version of the code by fixing vulnerabilities."""
        lines = code.split('\n')
        secure_lines = lines.copy()
        fixes_applied = []
        
        for vuln in vulnerabilities:
            line_num = vuln['line_number'] - 1  # Convert to 0-based index
            vuln_type = vuln['type']
            
            if vuln_type == 'sql_injection':
                if 'execute' in lines[line_num]:
                    # Fix SQL injection by using parameterized queries
                    secure_lines[line_num] = secure_lines[line_num].replace(
                        'execute("', 'execute("SELECT * FROM users WHERE id = ?", ('
                    ).replace(' + ', ', ') + ')'
                    fixes_applied.append(f"Line {vuln['line_number']}: Fixed SQL injection using parameterized query")
            
            elif vuln_type == 'command_injection':
                if 'os.system' in lines[line_num]:
                    # Fix command injection using subprocess
                    cmd = lines[line_num].split('os.system')[1].strip('( )"\'')
                    secure_lines[line_num] = f"    subprocess.run([{cmd}], shell=False, check=True)"
                    fixes_applied.append(f"Line {vuln['line_number']}: Fixed command injection using subprocess")
            
            elif vuln_type == 'path_traversal':
                if 'open' in lines[line_num]:
                    # Fix path traversal
                    secure_lines[line_num] = (
                        "    safe_path = os.path.normpath(os.path.join(safe_dir, filename))\n"
                        "    if not safe_path.startswith(safe_dir):\n"
                        "        raise ValueError('Invalid path')\n"
                        "    with open(safe_path, 'r') as f:"
                    )
                    fixes_applied.append(f"Line {vuln['line_number']}: Fixed path traversal with path validation")
            
            elif vuln_type == 'hard_coded_credentials':
                # Fix hardcoded credentials using environment variables
                secure_lines[line_num] = secure_lines[line_num].replace(
                    '= "', '= os.environ.get("'
                ) + '")'
                fixes_applied.append(f"Line {vuln['line_number']}: Replaced hardcoded credentials with environment variables")
        
        secure_code = "\n".join(secure_lines)
        secure_code = "import os\nimport subprocess\n" + secure_code
        
        # Add summary of fixes
        secure_code = "# Secure version with applied fixes:\n#\n" + \
                     "\n".join(f"# {fix}" for fix in fixes_applied) + \
                     "\n\n" + secure_code
        
        return secure_code

    def save_report_and_fixes(self, report: str, secure_code: str, base_dir: str) -> Tuple[str, str]:
        """Save vulnerability report and secure code to files."""
        try:
            # Ensure the reports directory exists
            reports_dir = os.path.join(base_dir, 'security_reports')
            os.makedirs(reports_dir, exist_ok=True)
            
            # Define file paths
            report_file = os.path.join(reports_dir, 'vulnerability_report.txt')
            fixes_file = os.path.join(reports_dir, 'secure_code.txt')
            
            # Create default content for empty reports
            if not report or report.strip() == "":
                report = "No vulnerabilities detected in the analyzed code."
            
            if not secure_code or secure_code.strip() == "":
                secure_code = "# No code fixes required. The analyzed code appears to be secure."
            
            # Write files with proper encoding and error handling
            try:
                with open(report_file, 'w', encoding='utf-8') as f:
                    f.write(report)
                logger.info(f"Vulnerability report saved to: {report_file}")
            except Exception as e:
                logger.error(f"Error writing vulnerability report: {e}")
                # Try with a different encoding as fallback
                with open(report_file, 'w', encoding='latin-1') as f:
                    f.write(report)
            
            try:
                with open(fixes_file, 'w', encoding='utf-8') as f:
                    f.write(secure_code)
                logger.info(f"Secure code saved to: {fixes_file}")
            except Exception as e:
                logger.error(f"Error writing secure code: {e}")
                # Try with a different encoding as fallback
                with open(fixes_file, 'w', encoding='latin-1') as f:
                    f.write(secure_code)
                
            # Copy files to the report manager's files for consistency
            if hasattr(self, 'report_manager'):
                self.report_manager.update_reports(report, secure_code)
                
            return report_file, fixes_file
            
        except Exception as e:
            logger.error(f"Error saving reports: {e}")
            # Try to save to the current directory as a fallback
            try:
                fallback_report = os.path.join(os.getcwd(), 'vulnerability_report.txt')
                fallback_fixes = os.path.join(os.getcwd(), 'secure_code.txt')
                
                with open(fallback_report, 'w', encoding='utf-8') as f:
                    f.write(report if report else "No vulnerabilities detected.")
                
                with open(fallback_fixes, 'w', encoding='utf-8') as f:
                    f.write(secure_code if secure_code else "No code fixes required.")
                
                logger.info(f"Reports saved to fallback location: {os.getcwd()}")
                return fallback_report, fallback_fixes
            except Exception as e2:
                logger.error(f"Failed to save to fallback location: {e2}")
                return "", ""

def scan_file(scanner: VulnerabilityScanner, file_path: str) -> List[Dict[str, Any]]:
    """
    Scan a single file for vulnerabilities.
    
    Args:
        scanner: The vulnerability scanner instance
        file_path: Path to the file to scan
        
    Returns:
        List of detected vulnerabilities
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
        file_name = os.path.basename(file_path)
        return scanner.analyze_code(code, file_name)
    except Exception as e:
        logger.error(f"Error scanning {file_path}: {e}")
        return []

def scan_directory(scanner: VulnerabilityScanner, directory: str, extensions: List[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    """
    Recursively scan a directory for vulnerabilities.
    
    Args:
        scanner: The vulnerability scanner instance
        directory: Directory path to scan
        extensions: List of file extensions to scan
        
    Returns:
        Dictionary mapping file paths to vulnerabilities
    """
    if extensions is None:
        extensions = ['.py', '.js', '.php', '.java', '.rb']
    
    results = {}
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        code = f.read()
                    file_name = os.path.basename(file_path)
                    vulnerabilities = scanner.analyze_code(code, file_name)
                    if vulnerabilities:
                        results[file_path] = vulnerabilities
                except Exception as e:
                    logger.error(f"Error scanning {file_path}: {e}")
    
    # If no vulnerabilities found in any file, create a default report
    if not results:
        scanner.report_manager.update_reports(
            "No vulnerabilities detected in any of the scanned files.",
            "# All scanned files appear to be secure."
        )
    
    return results

def generate_test_vulnerabilities() -> str:
    """Generate a code sample with various vulnerabilities for testing."""
    return """
import os
import sqlite3
import subprocess

def login(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()

def get_logs(date):
    # Command injection vulnerability
    os.system("cat /var/log/app.log | grep " + date)

def render_profile(user_data):
    # XSS vulnerability
    template = "<div>Name: " + user_data['name'] + "</div>"
    return template

def read_file(filename):
    # Path traversal vulnerability
    with open(user_input + ".txt", "r") as f:
        return f.read()
        
def store_secret():
    # Hard-coded credentials vulnerability
    api_key = "12345secret_key_here"
    password = "admin123"
    return encrypt(api_key)
    
def insecure_deserialize(data):
    # Insecure deserialization vulnerability
    import pickle
    return pickle.loads(data)
    
def hash_password(password):
    # Weak cryptography vulnerability
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()
"""

def interactive_mode():
    """Run the scanner in interactive mode for a single file."""
    # Create a model path
    default_model_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "vulnerability_model.codex")
    
    # Initialize scanner with default model or create one
    print("\nInitializing scanner with basic model...")
    scanner = VulnerabilityScanner()
    
    # Save the default model if it doesn't exist
    if not os.path.exists(default_model_path):
        scanner.save_model(default_model_path)
        print(f"Created and saved basic model to {default_model_path}")
    
    while True:
        print("\n===== AI Security Vulnerability Scanner =====")
        print("1. Scan a single file")
        print("2. Scan a directory")
        print("3. Train model with additional examples")
        print("4. Run demo scan with test vulnerabilities")
        print("5. Exit")
        
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == '1':
            # Scan a single file
            file_path = input("Enter the path to the file you want to scan: ").strip()
            
            if not os.path.isfile(file_path):
                print(f"Error: '{file_path}' is not a valid file.")
                continue
                
            print(f"\nScanning {file_path}...")
            vulnerabilities = scan_file(scanner, file_path)
            
            # Read original code
            with open(file_path, 'r') as f:
                original_code = f.read()
            
            # Generate reports and secure code
            report = scanner.generate_detailed_report({file_path: vulnerabilities})
            secure_code = scanner.generate_secure_code(original_code, vulnerabilities)
            
            # Save reports
            report_file, fixes_file = scanner.save_report_and_fixes(
                report, secure_code, os.path.dirname(file_path)
            )
            
            print("\nScan completed!")
            print(f"Vulnerability report saved to: {report_file}")
            print(f"Secure code saved to: {fixes_file}")
                
        elif choice == '2':
            # Scan a directory
            dir_path = input("Enter the path to the directory you want to scan: ").strip()
            
            if not os.path.isdir(dir_path):
                print(f"Error: '{dir_path}' is not a valid directory.")
                continue
                
            extensions_input = input("Enter file extensions to scan (comma-separated, e.g., .py,.js,.php) or press Enter for defaults: ").strip()
            extensions = [ext.strip() for ext in extensions_input.split(',')] if extensions_input else ['.py', '.js', '.php', '.java', '.rb']
            
            print(f"\nScanning directory {dir_path} for files with extensions: {', '.join(extensions)}...")
            results = scan_directory(scanner, dir_path, extensions)
            
            if results:
                # Generate consolidated report
                report = scanner.generate_detailed_report(results)
                
                # Generate secure code for each file
                all_secure_code = ""
                for file_path, vulnerabilities in results.items():
                    with open(file_path, 'r') as f:
                        original_code = f.read()
                    secure_code = scanner.generate_secure_code(original_code, vulnerabilities)
                    all_secure_code += f"\n\n# File: {file_path}\n{secure_code}"
                
                # Save reports
                report_file, fixes_file = scanner.save_report_and_fixes(
                    report, all_secure_code, dir_path
                )
                
                print("\nScan completed!")
                print(f"Vulnerability report saved to: {report_file}")
                print(f"Secure code saved to: {fixes_file}")
            else:
                print("No vulnerabilities detected.")
                
        elif choice == '3':
            # Train model with additional examples
            print("\n===== Train Model with Additional Examples =====")
            print("This will improve the scanner's ability to detect vulnerabilities.")
            print("You can provide examples of vulnerable and non-vulnerable code.")
            
            # Get examples
            vulnerable_examples = []
            safe_examples = []
            
            # Collect vulnerable examples
            print("\nProvide examples of vulnerable code (enter 'done' when finished):")
            while True:
                example = input("Enter vulnerable code snippet (or 'done' to finish): ").strip()
                if example.lower() == 'done':
                    break
                vulnerable_examples.append(example)
            
            # Collect safe examples
            print("\nProvide examples of safe code (enter 'done' when finished):")
            while True:
                example = input("Enter safe code snippet (or 'done' to finish): ").strip()
                if example.lower() == 'done':
                    break
                safe_examples.append(example)
            
            # Train if examples provided
            if vulnerable_examples or safe_examples:
                all_examples = vulnerable_examples + safe_examples
                labels = [1] * len(vulnerable_examples) + [0] * len(safe_examples)
                
                scanner.train(all_examples, labels)
                print("Model training completed.")
                
                # Save the updated model
                model_path = input("Enter path to save the trained model (or press Enter for default): ").strip()
                if not model_path:
                    model_path = default_model_path
                
                scanner.save_model(model_path)
                print(f"Model saved to {model_path}")
            else:
                print("No examples provided. Model not updated.")
        
        elif choice == '4':
            # Run demo scan with test vulnerabilities
            print("\n===== Running Demo Scan with Test Vulnerabilities =====")
            test_code = generate_test_vulnerabilities()
            
            # Create a temporary file for the test code
            import tempfile
            temp_dir = tempfile.gettempdir()
            test_file = os.path.join(temp_dir, "test_vulnerabilities.py")
            
            try:
                with open(test_file, 'w', encoding='utf-8') as f:
                    f.write(test_code)
                
                print(f"Created test file at: {test_file}")
                print("Scanning for vulnerabilities...")
                
                vulnerabilities = scan_file(scanner, test_file)
                
                # Generate reports and secure code
                report = scanner.generate_detailed_report({test_file: vulnerabilities})
                secure_code = scanner.generate_secure_code(test_code, vulnerabilities)
                
                # Save reports to the current directory for easy access
                current_dir = os.getcwd()
                report_file, fixes_file = scanner.save_report_and_fixes(
                    report, secure_code, current_dir
                )
                
                print("\nDemo scan completed!")
                print(f"Vulnerability report saved to: {report_file}")
                print(f"Secure code saved to: {fixes_file}")
                
            except Exception as e:
                print(f"Error during demo scan: {e}")
            finally:
                # Clean up temporary file
                try:
                    if os.path.exists(test_file):
                        os.remove(test_file)
                except:
                    pass
                
        elif choice == '5':
            print("Exiting Security Vulnerability Scanner. Goodbye!")
            break
            
        else:
            print("Invalid choice! Please enter 1, 2, 3, 4, or 5.")

def main():
    """Main function to run the scanner."""
    parser = argparse.ArgumentParser(description='AI-powered security vulnerability scanner')
    parser.add_argument('--cli', action='store_true', help='Run in CLI mode (non-interactive)')
    parser.add_argument('--path', help='File or directory to scan (for CLI mode)')
    parser.add_argument('--model', help='Path to pre-trained model')
    parser.add_argument('--report', help='Path to save the report')
    parser.add_argument('--extensions', nargs='+', default=['.py', '.js', '.php', '.java', '.rb'],
                        help='File extensions to scan')
    parser.add_argument('--demo', action='store_true', help='Run a demo scan with test vulnerabilities')
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = VulnerabilityScanner(args.model)
    
    if args.demo:
        # Run demo scan with test vulnerabilities
        print("\n===== Running Demo Scan with Test Vulnerabilities =====")
        test_code = generate_test_vulnerabilities()
        
        # Create a temporary file for the test code
        import tempfile
        temp_dir = tempfile.gettempdir()
        test_file = os.path.join(temp_dir, "test_vulnerabilities.py")
        
        try:
            with open(test_file, 'w', encoding='utf-8') as f:
                f.write(test_code)
            
            print(f"Created test file at: {test_file}")
            print("Scanning for vulnerabilities...")
            
            vulnerabilities = scan_file(scanner, test_file)
            
            # Generate reports and secure code
            report = scanner.generate_detailed_report({test_file: vulnerabilities})
            secure_code = scanner.generate_secure_code(test_code, vulnerabilities)
            
            # Save reports to the current directory for easy access
            current_dir = os.getcwd()
            report_file, fixes_file = scanner.save_report_and_fixes(
                report, secure_code, current_dir
            )
            
            print("\nDemo scan completed!")
            print(f"Found {len(vulnerabilities)} vulnerabilities.")
            print(f"Vulnerability report saved to: {report_file}")
            print(f"Secure code saved to: {fixes_file}")
            
        except Exception as e:
            print(f"Error during demo scan: {e}")
            return 1
        finally:
            # Clean up temporary file
            try:
                if os.path.exists(test_file):
                    os.remove(test_file)
            except:
                pass
        
        return 0
    
    elif args.cli and args.path:
        # CLI mode
        # Scan file or directory
        if os.path.isfile(args.path):
            vulnerabilities = scan_file(scanner, args.path)
            
            # Read original code
            with open(args.path, 'r', encoding='utf-8') as f:
                original_code = f.read()
            
            # Generate reports and secure code
            report = scanner.generate_detailed_report({args.path: vulnerabilities})
            secure_code = scanner.generate_secure_code(original_code, vulnerabilities)
            
            # Determine where to save reports
            report_dir = os.path.dirname(args.report) if args.report else os.path.dirname(args.path)
            
            # Save reports
            report_file, fixes_file = scanner.save_report_and_fixes(
                report, secure_code, report_dir
            )
            
            print("\nScan completed!")
            print(f"Found {len(vulnerabilities)} vulnerabilities.")
            print(f"Vulnerability report saved to: {report_file}")
            print(f"Secure code saved to: {fixes_file}")
            
        elif os.path.isdir(args.path):
            results = scan_directory(scanner, args.path, args.extensions)
            
            if not results:
                print("No vulnerabilities detected.")
                return 0
                
            # Count total vulnerabilities
            total_vulns = sum(len(vulns) for vulns in results.values())
            
            # Generate consolidated report
            report = scanner.generate_detailed_report(results)
            
            # Generate secure code for each file
            all_secure_code = ""
            for file_path, vulnerabilities in results.items():
                with open(file_path, 'r', encoding='utf-8') as f:
                    original_code = f.read()
                secure_code = scanner.generate_secure_code(original_code, vulnerabilities)
                all_secure_code += f"\n\n# File: {file_path}\n{secure_code}"
            
            # Determine where to save reports
            report_dir = os.path.dirname(args.report) if args.report else args.path
            
            # Save reports
            report_file, fixes_file = scanner.save_report_and_fixes(
                report, all_secure_code, report_dir
            )
            
            print("\nScan completed!")
            print(f"Found {total_vulns} vulnerabilities in {len(results)} files.")
            print(f"Vulnerability report saved to: {report_file}")
            print(f"Secure code saved to: {fixes_file}")
        else:
            print(f"Error: {args.path} is not a valid file or directory")
            return 1
    else:
        # Interactive mode
        interactive_mode()
    
    return 0

if __name__ == "__main__":
    exit(main())