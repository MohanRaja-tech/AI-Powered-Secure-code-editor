# Secure Code AI - Security Vulnerability Scanner

A powerful AI-powered tool to scan code for security vulnerabilities and suggest fixes, available through both a web interface and command-line. The AI chat feature is powered by GROQ's language models for intelligent security advice.

## Features

- **Comprehensive Vulnerability Detection**: Identifies over 50 types of security vulnerabilities including SQL injection, XSS, path traversal, and more
- **Detailed Reports**: Generates comprehensive vulnerability reports with explanations and fix suggestions
- **Secure Code Generation**: Automatically creates fixed versions of vulnerable code
- **Live Code Checking**: Real-time vulnerability detection while you type with the new Live Checker feature
- **Web Interface**: Modern, responsive web UI for easy code scanning
- **Command-Line Tool**: Powerful CLI for integration into development workflows
- **AI Chat Assistant**: Ask questions about security best practices and get responses powered by GROQ AI

## Requirements

- Python 3.7+
- Flask
- scikit-learn
- OpenAI API access (optional, for enhanced live checking)
- GROQ API access for AI chat
- Additional Python packages (see requirements.txt)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/your-repo/secure-code-ai.git
   cd secure-code-ai
   ```

2. Install required packages:
   ```
   pip install -r requirements.txt
   ```

3. Configure your API keys in `config.py` or set them as environment variables:
   - `GROQ_API_KEY` for AI chat functionality
   - `OPENAI_API_KEY` for enhanced live code checking (optional)

## Running the Web Interface

The web interface consists of a Flask API server that handles the backend functionality and a web UI. To run the integrated system:

1. Start the API server:
   ```
   python api_server.py
   ```
   This will start the Flask server on http://localhost:5000

2. The web UI will be automatically served by the API server. Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

## Using the Web Interface

1. **Code Scanning**: Paste your code in the left panel and click "Scan Code" to analyze for vulnerabilities
2. **AI Chat**: Click the "AI Chat" button to switch to chat mode, then ask security-related questions
3. **Live Checker**: Use the Live Checker for real-time vulnerability detection while you type
4. **View Results**: See vulnerability reports, secure code suggestions, and AI chat responses in the right panel

## Using the Live Checker

The Live Checker provides real-time vulnerability detection while you write code:

1. Access the Live Checker via the left sidebar menu or at http://localhost:5000/live-checker.html
2. Begin typing or paste your code into the editor
3. The system will automatically check for vulnerabilities as you type
4. Security issues will be highlighted in the editor with explanations in the right panel
5. Click "Apply This Fix" to automatically implement security fixes for specific vulnerabilities
6. Click "Secure All" to apply all recommended fixes at once

## Using the Command-Line Interface

For command-line usage, the scanner can be run directly:

```
# Interactive mode
python Main.py

# CLI mode to scan a single file
python Main.py --cli --path /path/to/file.py

# CLI mode to scan a directory
python Main.py --cli --path /path/to/directory --extensions .py .js .php

# Save report to a file
python Main.py --cli --path /path/to/file.py --report report.txt
```

## Enhanced Scanner (check_model.py)

The enhanced scanner in `check_model.py` provides additional capabilities:

```
# Run demo scan
python check_model.py --test

# Interactive mode
python check_model.py
```

## API Endpoints

The Flask API server (`api_server.py`) provides the following endpoints:

- `POST /api/scan`: Scan code provided in the request body
- `POST /api/scan/file`: Scan an uploaded file
- `POST /api/scan/directory`: Scan a directory
- `POST /api/live-check`: Real-time code checking for Live Checker
- `GET /api/demo`: Get demo vulnerability data
- `POST /api/chat`: Send a message to the GROQ AI assistant
- `POST /api/analyze-code`: Send code to be analyzed by the GROQ AI assistant
- `GET /api/status`: Check the status of system components

## AI Integration

The application uses AI for several key features:

### GROQ Chat Integration

The AI chat feature uses the GROQ API to provide intelligent responses to security-related questions. The integration:

1. Sends user messages to GROQ's LLM (Language Model)
2. Uses a security-focused system prompt to guide the model
3. Formats and displays the responses with proper code highlighting
4. Provides fallback responses if the API is unavailable

### OpenAI Integration (Live Checker)

The Live Checker feature can use OpenAI's models for enhanced vulnerability detection:

1. Analyzes code line-by-line as you type
2. Provides specific security recommendations for each vulnerable line
3. Suggests secure code alternatives that can be applied with one click
4. Falls back to the built-in scanner if OpenAI API is not available

### GROQ Model Support

This application uses GROQ's language models for AI chat capabilities. Currently, the application supports:

- Llama3 (8B) - Default model for chat functionality
- Llama3 (70B) - Higher capacity model for complex tasks (can be configured)
- Mixtral (8x7B) - Advanced model with wide capabilities
- Gemma (7B) - Google's instruction-tuned model

To change the GROQ model, modify the `groq_integration.py` file:

```python
# In the class constructor:
self.model = self.models["llama3"]  # Change to other model keys as needed
```

## Configuration

API keys for AI services can be configured in one of the following ways:

1. Directly in `api_server.py`:
   ```python
   GROQ_API_KEY = "your-groq-api-key"
   OPENAI_API_KEY = "your-openai-api-key"
   ```

2. Using environment variables:
   ```
   export GROQ_API_KEY="your-groq-api-key"
   export OPENAI_API_KEY="your-openai-api-key"
   ```

3. In a `config.py` file:
   ```python
   # GROQ API for AI chat
   GROQ_API_KEY = "your-groq-api-key"

   # OpenAI API for Live Checker
   OPENAI_API_KEY = "your-openai-api-key"
   
   # Claude API for enhanced responses (if implemented)
   CLAUDE_API_KEY = "your-claude-api-key"
   ```

## Advanced Configuration

You can customize how the scanner works by modifying the vulnerability patterns in `check_model.py`. The `VULNERABILITY_PATTERNS` dictionary contains regex patterns for detecting different types of vulnerabilities.

## Troubleshooting

- **API Connection Issues**: Make sure the Flask server is running and accessible at http://localhost:5000
- **Missing Dependencies**: Ensure all packages in requirements.txt are installed
- **Large File Scanning**: For very large files, the scanner may take longer to process
- **AI Chat Not Working**: Verify your GROQ API key is valid and properly configured
- **Live Checker AI Suggestions**: If the OpenAI integration is not working, verify your OpenAI API key
- **GROQ Model Errors**: Some models may be deprecated over time. If you encounter an error about a decommissioned model, update the model in `groq_integration.py` to one of the currently supported models.

## Security Notes

This tool is designed to help identify potential security vulnerabilities in code, but it is not a substitute for a thorough security review by experienced professionals. Always verify findings and consider additional security testing methods.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 