#!/usr/bin/env python3
import os
import sys
from groq_integration import GroqChat

def test_groq():
    """Test the GROQ API connection"""
    api_key = "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"
    
    try:
        print("Initializing GroqChat...")
        chat = GroqChat(api_key=api_key)
        
        print(f"Default model: {chat.model}")
        print("Available models:", chat.models)
        
        # Try using a different model
        chat.model = "llama3-8b-8192"
        print(f"Using model: {chat.model}")
        
        print("Testing API connection...")
        response = chat.get_response("Hello, is this working?")
        
        print(f"Response received:\n{response}")
        
        if "Error getting response from GROQ" in response:
            print("Error detected in response!", file=sys.stderr)
            print("Full error:", response)
            return False
        else:
            print("Success! GROQ API connection is working.")
            return True
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return False

if __name__ == "__main__":
    print("GROQ API Test")
    print("-" * 40)
    success = test_groq()
    
    if not success:
        sys.exit(1) 