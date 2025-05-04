import sqlite3
import os
import subprocess

def insecure_db_query(user_input):
    # Vulnerable to SQL injection
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    cursor.execute(query)
    return cursor.fetchall()

def insecure_command(user_input):
    # Vulnerable to command injection
    cmd = "echo " + user_input
    os.system(cmd)

def insecure_file_read(filename):
    # Vulnerable to path traversal
    with open(filename, 'r') as file:
        return file.read()

def main():
    # Example usage
    user_input = input("Enter username to search: ")
    print(insecure_db_query(user_input))

    command_input = input("Enter message to echo: ")
    insecure_command(command_input)

    file_input = input("Enter filename to read: ")
    print(insecure_file_read(file_input))

if __name__ == "__main__":
    main()