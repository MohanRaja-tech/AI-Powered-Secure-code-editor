#!/usr/bin/env python3
"""
Check if all required compilers and interpreters are installed
"""

import subprocess
import shutil
import sys
import os

def check_command(command, name):
    """Check if a command is available in PATH"""
    print(f"Checking for {name}...", end="")
    is_available = shutil.which(command) is not None
    
    if is_available:
        print(f"\033[92m Found\033[0m")
    else:
        print(f"\033[91m Not found\033[0m")
    
    return is_available

def run_command(command):
    """Run a command and return its output"""
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

def main():
    print("Checking for required compilers and interpreters...")
    print("-" * 50)
    
    all_available = True
    
    # Check Python
    if check_command("python", "Python"):
        version = run_command(["python", "--version"])
        print(f"  Python version: {version}")
    else:
        all_available = False
        print("  Python is required for all operations.")
    
    # Check Node.js (for JavaScript)
    if check_command("node", "Node.js"):
        version = run_command(["node", "--version"])
        print(f"  Node.js version: {version}")
    else:
        all_available = False
        print("  Node.js is required for JavaScript compilation.")
        print("  Install from: https://nodejs.org/")
    
    # Check Java
    if check_command("java", "Java Runtime"):
        version = run_command(["java", "--version"])
        if version:
            print(f"  Java version: {version.splitlines()[0]}")
        else:
            version = run_command(["java", "-version"])
            print(f"  Java version: Available (could not determine version)")
    else:
        all_available = False
        print("  Java is required for Java compilation.")
        print("  Install from: https://www.oracle.com/java/technologies/downloads/")
    
    # Check javac (Java compiler)
    if check_command("javac", "Java Compiler"):
        version = run_command(["javac", "--version"])
        print(f"  Java compiler version: {version}")
    else:
        all_available = False
        print("  Java compiler (javac) is required for Java compilation.")
        print("  Install JDK from: https://www.oracle.com/java/technologies/downloads/")
    
    # Check g++ (C++ compiler)
    if check_command("g++", "C++ Compiler"):
        version = run_command(["g++", "--version"])
        if version:
            print(f"  G++ version: {version.splitlines()[0]}")
    else:
        all_available = False
        print("  G++ is required for C++ compilation.")
        print("  Install GCC from: https://gcc.gnu.org/install/")
    
    # Check .NET (for C#)
    if check_command("dotnet", ".NET"):
        version = run_command(["dotnet", "--version"])
        print(f"  .NET version: {version}")
        
        # Check if dotnet-script is installed
        script_version = run_command(["dotnet", "tool", "list", "--global"])
        if script_version and "dotnet-script" in script_version:
            print("  dotnet-script: Installed")
        else:
            all_available = False
            print("  dotnet-script is not installed.")
            print("  Install with: dotnet tool install -g dotnet-script")
    else:
        all_available = False
        print("  .NET is required for C# compilation.")
        print("  Install from: https://dotnet.microsoft.com/download")
    
    # Check PHP
    if check_command("php", "PHP"):
        version = run_command(["php", "--version"])
        if version:
            print(f"  PHP version: {version.splitlines()[0]}")
    else:
        all_available = False
        print("  PHP is required for PHP execution.")
        print("  Install from: https://www.php.net/downloads")
    
    print("-" * 50)
    if all_available:
        print("\033[92mAll required compilers and interpreters are installed!\033[0m")
        return 0
    else:
        print("\033[91mSome required compilers or interpreters are missing.\033[0m")
        print("Please install the missing components to enable all language support.")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 