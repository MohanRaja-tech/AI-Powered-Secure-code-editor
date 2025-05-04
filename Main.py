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
        ]
    }
    
    # Fix suggestions for each vulnerability type
    FIX_SUGGESTIONS = {
        'sql_injection': [
            "Use parameterized queries with placeholders instead of string concatenation",
            "Example: cursor.execute('SELECT * FROM users WHERE username = ?', (username,))",
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
        ]
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
        if model_path and os.path.exists(model_path):
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
    
    def analyze_code(self, code: str) -> List[Dict[str, Any]]:
        """
        Analyze code for security vulnerabilities.
        
        Args:
            code: The code to analyze
            
        Returns:
            List of detected vulnerabilities with details
        """
        vulnerabilities = []
        lines = code.split('\n')
        
        # Rule-based detection
        for vuln_type, patterns in self.VULNERABILITY_PATTERNS.items():
            for pattern in patterns:
                for i, line in enumerate(lines):
                    if re.search(pattern, line):
                        vulnerabilities.append({
                            'type': vuln_type,
                            'line_number': i + 1,
                            'line_content': line.strip(),
                            'confidence': 'High',
                            'detection_method': 'pattern',
                            'fixes': self.FIX_SUGGESTIONS.get(vuln_type, ["No specific fix available"])
                        })
        
        # ML-based detection
        try:
            # Extract code blocks
            code_blocks = self._extract_code_blocks(code)
            if code_blocks:
                # Predict vulnerabilities using ML
                for i, block in enumerate(code_blocks):
                    X = self.vectorizer.transform([block])
                    prediction = self.model.predict_proba(X)[0]
                    
                    # Only report if probability is high enough
                    if len(prediction) >= 2 and prediction[1] > 0.6:
                        # Find the starting line number for this block
                        start_line = 1
                        for j, line in enumerate(lines):
                            if block.startswith(line.strip()):
                                start_line = j + 1
                                break
                        
                        # Determine vulnerability type
                        vuln_type = self._determine_vulnerability_type(block)
                        
                        vulnerabilities.append({
                            'type': vuln_type,
                            'line_number': start_line,
                            'line_content': block.split('\n')[0].strip() + '...',
                            'confidence': f'{prediction[1]:.2f}',
                            'detection_method': 'ml',
                            'fixes': self.FIX_SUGGESTIONS.get(vuln_type, ["Review this code block for potential security issues"])
                        })
        except Exception as e:
            logger.warning(f"ML-based detection failed: {e}")
        
        return vulnerabilities
    
    def _determine_vulnerability_type(self, code_block: str) -> str:
        """
        Determine the most likely vulnerability type in a code block.
        
        Args:
            code_block: The code block to analyze
            
        Returns:
            The most likely vulnerability type
        """
        # Check for each vulnerability pattern
        for vuln_type, patterns in self.VULNERABILITY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, code_block):
                    return vuln_type
        
        # If no specific pattern matches, return a generic type
        return "potential_vulnerability"
    
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
        Generate a report from detected vulnerabilities.
        
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
        
        # Generate report sections
        for vuln_type, vulns in vuln_types.items():
            report += f"## {vuln_type.replace('_', ' ').title()} ({len(vulns)})\n\n"
            
            for vuln in vulns:
                report += f"- Line {vuln['line_number']}: `{vuln['line_content']}`\n"
                report += f"  - Confidence: {vuln['confidence']}\n"
                report += f"  - Detection Method: {vuln['detection_method']}\n"
                report += "  - Suggested fixes:\n"
                for fix in vuln['fixes']:
                    report += f"    - {fix}\n"
                report += "\n"
        
        return report

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
        return scanner.analyze_code(code)
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
                vulnerabilities = scan_file(scanner, file_path)
                if vulnerabilities:
                    results[file_path] = vulnerabilities
    
    return results

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
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == '1':
            # Scan a single file
            file_path = input("Enter the path to the file you want to scan: ").strip()
            
            if not os.path.isfile(file_path):
                print(f"Error: '{file_path}' is not a valid file.")
                continue
                
            print(f"\nScanning {file_path}...")
            vulnerabilities = scan_file(scanner, file_path)
            
            # Generate and display report
            report = scanner.generate_report(vulnerabilities)
            print("\n" + report)
            
            # Ask to save report
            save_report = input("Would you like to save this report? (y/n): ").strip().lower()
            if save_report == 'y':
                report_path = input("Enter the path to save the report: ").strip()
                with open(report_path, 'w') as f:
                    f.write(report)
                print(f"Report saved to {report_path}")
                
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
            
            # Display results
            if not results:
                print("No vulnerabilities detected.")
            else:
                print(f"Vulnerabilities detected in {len(results)} files:")
                for file_path, vulnerabilities in results.items():
                    print(f"\n{file_path}:")
                    print(scanner.generate_report(vulnerabilities))
            
            # Ask to save report
            save_report = input("Would you like to save this report? (y/n): ").strip().lower()
            if save_report == 'y':
                report_path = input("Enter the path to save the report: ").strip()
                with open(report_path, 'w') as f:
                    if not results:
                        f.write("No vulnerabilities detected.")
                    else:
                        for file_path, vulnerabilities in results.items():
                            f.write(f"\n{file_path}:\n")
                            f.write(scanner.generate_report(vulnerabilities))
                print(f"Report saved to {report_path}")
        
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
            print("Exiting Security Vulnerability Scanner. Goodbye!")
            break
            
        else:
            print("Invalid choice! Please enter 1, 2, 3, or 4.")

def main():
    """Main function to run the scanner."""
    parser = argparse.ArgumentParser(description='AI-powered security vulnerability scanner')
    parser.add_argument('--cli', action='store_true', help='Run in CLI mode (non-interactive)')
    parser.add_argument('--path', help='File or directory to scan (for CLI mode)')
    parser.add_argument('--model', help='Path to pre-trained model')
    parser.add_argument('--report', help='Path to save the report')
    parser.add_argument('--extensions', nargs='+', default=['.py', '.js', '.php', '.java', '.rb'],
                        help='File extensions to scan')
    args = parser.parse_args()
    
    if args.cli and args.path:
        # CLI mode
        scanner = VulnerabilityScanner(args.model)
        
        # Scan file or directory
        if os.path.isfile(args.path):
            vulnerabilities = scan_file(scanner, args.path)
            report = scanner.generate_report(vulnerabilities)
            print(report)
        elif os.path.isdir(args.path):
            results = scan_directory(scanner, args.path, args.extensions)
            
            # Generate consolidated report
            if not results:
                print("No vulnerabilities detected.")
            else:
                print(f"Vulnerabilities detected in {len(results)} files:")
                for file_path, vulnerabilities in results.items():
                    print(f"\n{file_path}:")
                    print(scanner.generate_report(vulnerabilities))
        else:
            print(f"Error: {args.path} is not a valid file or directory")
            return 1
        
        # Save report if requested
        if args.report and (results or vulnerabilities):
            with open(args.report, 'w') as f:
                if os.path.isfile(args.path):
                    f.write(scanner.generate_report(vulnerabilities))
                else:
                    for file_path, vulnerabilities in results.items():
                        f.write(f"\n{file_path}:\n")
                        f.write(scanner.generate_report(vulnerabilities))
            print(f"Report saved to {args.report}")
    else:
        # Interactive mode
        interactive_mode()
    
    return 0

if __name__ == "__main__":
    exit(main())