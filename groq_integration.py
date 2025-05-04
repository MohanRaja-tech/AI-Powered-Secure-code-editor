import os
from typing import Optional, Dict, Any
import groq
from groq import Groq

class GroqChat:
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the GROQ chat client.
        
        Args:
            api_key: Optional GROQ API key. If not provided, will try to get from environment.
        """
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        if not self.api_key:
            raise ValueError("GROQ_API_KEY environment variable not set and no API key provided")
        
        # Create the Groq client with the correct base URL
        self.client = Groq(api_key=self.api_key)
        
        # Available GROQ models - updated to currently supported models
        self.models = {
            "mixtral": "mixtral-8x7b-32768",
            "llama3": "llama3-8b-8192",
            "llama3-70b": "llama3-70b-8192",
            "gemma": "gemma-7b-it"
        }
        
        # Default model - using LLama3 as default since Mixtral was decommissioned
        self.model = self.models["llama3"]
        
    def get_response(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Get a response from GROQ LLM.
        
        Args:
            prompt: The user's input prompt
            system_prompt: Optional system prompt to guide the model's behavior
            
        Returns:
            The model's response as a string
        """
        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})
            
            # Make the API call with the correct endpoint structure
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.7,
                max_tokens=2048,
                top_p=0.9
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            return f"Error getting response from GROQ: {str(e)}"
    
    def analyze_code(self, code: str) -> Dict[str, Any]:
        """Analyze code for security vulnerabilities using GROQ.
        
        Args:
            code: The code to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        system_prompt = """You are an expert security code reviewer. Analyze the provided code for security vulnerabilities.
        Focus on common issues like:
        - SQL Injection
        - Command Injection
        - Path Traversal
        - XSS
        - Insecure Deserialization
        - Weak Cryptography
        - Hard-coded Credentials
        
        Provide detailed explanations and specific remediation steps."""
        
        prompt = f"""Please analyze this code for security vulnerabilities and provide:
        1. List of vulnerabilities found
        2. Line numbers where vulnerabilities occur
        3. Detailed explanation of each vulnerability
        4. Specific remediation steps
        
        Code to analyze:
        {code}
        """
        
        response = self.get_response(prompt, system_prompt)
        
        return {
            "analysis": response,
            "raw_response": response
        }
    
    def suggest_fixes(self, code: str, vulnerability: str) -> Dict[str, Any]:
        """Get specific fix suggestions for a vulnerability.
        
        Args:
            code: The original code
            vulnerability: Description of the vulnerability
            
        Returns:
            Dictionary containing fix suggestions
        """
        system_prompt = """You are an expert security developer. Provide specific, actionable fixes for security vulnerabilities.
        Include code examples and best practices."""
        
        prompt = f"""Please provide specific fixes for this vulnerability:
        {vulnerability}
        
        In this code:
        {code}
        
        Provide:
        1. Specific code changes needed
        2. Explanation of why the fix works
        3. Best practices to prevent similar issues
        4. Code example of the fixed version"""
        
        response = self.get_response(prompt, system_prompt)
        
        return {
            "fixes": response,
            "raw_response": response
        } 