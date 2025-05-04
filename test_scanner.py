#!/usr/bin/env python3
"""
Test script for the enhanced Vulnerability Scanner that can detect all vulnerabilities from vul.txt.
This script demonstrates how to use the scanner to analyze code for security issues and generate reports.
"""

import os
import sys
import argparse
from check_model import VulnerabilityScanner, generate_test_vulnerabilities

def main():
    parser = argparse.ArgumentParser(description='Test the enhanced vulnerability scanner')
    parser.add_argument('--save-dir', default='./security_reports', 
                        help='Directory to save the security reports')
    parser.add_argument('--file', help='Specify a file to scan instead of using the test vulnerabilities')
    args = parser.parse_args()
    
    # Create the save directory if it doesn't exist
    os.makedirs(args.save_dir, exist_ok=True)
    
    # Initialize the scanner
    print("Initializing enhanced vulnerability scanner...")
    scanner = VulnerabilityScanner()
    
    # Generate test code or use the specified file
    if args.file:
        print(f"Scanning file: {args.file}")
        with open(args.file, 'r', encoding='utf-8') as f:
            code = f.read()
        file_name = os.path.basename(args.file)
    else:
        print("Generating test code with various vulnerabilities...")
        code = generate_test_vulnerabilities()
        file_name = "test_vulnerabilities.py"
        
        # Save the test code for reference
        test_file_path = os.path.join(args.save_dir, file_name)
        with open(test_file_path, 'w', encoding='utf-8') as f:
            f.write(code)
        print(f"Test code saved to: {test_file_path}")
    
    # Analyze the code for vulnerabilities
    print("\nScanning code for security vulnerabilities...")
    vulnerabilities = scanner.analyze_code(code, file_name)
    
    # Print summary of detected vulnerabilities
    vuln_types = {}
    for vuln in vulnerabilities:
        vuln_type = vuln['type']
        if vuln_type not in vuln_types:
            vuln_types[vuln_type] = 0
        vuln_types[vuln_type] += 1
    
    print(f"\nDetected {len(vulnerabilities)} potential security issues across {len(vuln_types)} vulnerability types:")
    for vuln_type, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
        print(f"- {vuln_type.replace('_', ' ').title()}: {count} issues")
    
    # Generate detailed report
    print("\nGenerating detailed vulnerability report...")
    report = scanner.generate_detailed_report({file_name: vulnerabilities})
    report_path = os.path.join(args.save_dir, "vulnerability_report.txt")
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"Detailed report saved to: {report_path}")
    
    # Generate secure code
    print("\nGenerating secure version of the code...")
    secure_code = scanner.generate_secure_code(code, vulnerabilities)
    secure_code_path = os.path.join(args.save_dir, "secure_code.py")
    with open(secure_code_path, 'w', encoding='utf-8') as f:
        f.write(secure_code)
    print(f"Secure code saved to: {secure_code_path}")
    
    print("\nSuggestions to fix the vulnerabilities:")
    for vuln_type in vuln_types:
        suggestions = scanner.FIX_SUGGESTIONS.get(vuln_type, ["No specific suggestions available"])
        print(f"\n{vuln_type.replace('_', ' ').title()}:")
        for suggestion in suggestions[:2]:  # Show just the first two suggestions
            print(f"  - {suggestion}")
    
    print("\nScan completed successfully! Check the generated reports for details.")
    return 0

if __name__ == "__main__":
    sys.exit(main()) 