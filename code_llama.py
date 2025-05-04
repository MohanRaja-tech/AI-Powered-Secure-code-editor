import os
import pickle
import tempfile
from typing import Any, Dict
import logging
from huggingface_hub import hf_hub_download
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Default model settings
DEFAULT_MODEL_ID = "codellama/CodeLlama-7b-Python-hf"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# Global variables to cache model and tokenizer
_model = None
_tokenizer = None

def _initialize_model(model_id=DEFAULT_MODEL_ID):
    """Initialize the Code Llama model and tokenizer."""
    global _model, _tokenizer
    
    if _model is None or _tokenizer is None:
        logger.info(f"Initializing Code Llama model: {model_id}")
        try:
            _tokenizer = AutoTokenizer.from_pretrained(model_id)
            _model = AutoModelForCausalLM.from_pretrained(model_id, torch_dtype=torch.float16, device_map=DEVICE)
            logger.info("Model initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing model: {e}")
            raise

def load(model_path: str) -> Dict[str, Any]:
    """
    Load model data from a file.
    
    Args:
        model_path: Path to the model file
        
    Returns:
        Dictionary containing the loaded model data
    """
    logger.info(f"Loading model data from {model_path}")
    try:
        # Initialize Code Llama
        _initialize_model()
        
        # Load the saved model data using pickle
        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)
        
        return model_data
    except Exception as e:
        logger.error(f"Error loading model data: {e}")
        raise

def dump(model_data: Dict[str, Any], model_path: str) -> None:
    """
    Save model data to a file.
    
    Args:
        model_data: Dictionary containing the model data
        model_path: Path to save the model file
    """
    logger.info(f"Saving model data to {model_path}")
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(os.path.abspath(model_path)), exist_ok=True)
        
        # Save the model data using pickle
        with open(model_path, 'wb') as f:
            pickle.dump(model_data, f)
        
        logger.info(f"Model data saved successfully to {model_path}")
    except Exception as e:
        logger.error(f"Error saving model data: {e}")
        raise

def analyze_vulnerability(code: str) -> Dict[str, Any]:
    """
    Use Code Llama to analyze code for vulnerabilities.
    
    Args:
        code: The code to analyze
        
    Returns:
        Dictionary with vulnerability analysis
    """
    _initialize_model()
    
    prompt = f"""
    Analyze the following code for security vulnerabilities:
    
    ```
    {code}
    ```
    
    List any security vulnerabilities found, their severity, and how to fix them.
    """
    
    inputs = _tokenizer(prompt, return_tensors="pt").to(DEVICE)
    
    # Generate with limited length to avoid very long responses
    with torch.no_grad():
        outputs = _model.generate(
            inputs["input_ids"],
            max_length=2048,
            temperature=0.2,
            top_p=0.95,
            do_sample=True
        )
    
    response = _tokenizer.decode(outputs[0], skip_special_tokens=True)
    
    # Extract the analysis part of the response (after the prompt)
    analysis = response.split("```")[-1].strip()
    
    return {
        "analysis": analysis,
        "vulnerabilities_found": "vulnerability" in analysis.lower() or "vulnerable" in analysis.lower(),
        "raw_response": response
    }

def suggest_fixes(code: str, vulnerabilities: list) -> str:
    """
    Use Code Llama to suggest security fixes for the code.
    
    Args:
        code: The code to fix
        vulnerabilities: List of detected vulnerabilities
        
    Returns:
        Fixed version of the code
    """
    _initialize_model()
    
    # Prepare vulnerability descriptions
    vuln_descriptions = "\n".join([f"- {v['type']} at line {v['line_number']}: {v['line_content']}" 
                                  for v in vulnerabilities])
    
    prompt = f"""
    The following code has security vulnerabilities:
    
    ```
    {code}
    ```
    
    Detected vulnerabilities:
    {vuln_descriptions}
    
    Rewrite the code to fix these security issues. Return only the fixed code without explanations.
    """
    
    inputs = _tokenizer(prompt, return_tensors="pt").to(DEVICE)
    
    with torch.no_grad():
        outputs = _model.generate(
            inputs["input_ids"],
            max_length=4096,  # Longer to accommodate the entire fixed code
            temperature=0.1,  # Lower temperature for more deterministic output
            top_p=0.95,
            do_sample=False  # Deterministic generation for code
        )
    
    response = _tokenizer.decode(outputs[0], skip_special_tokens=True)
    
    # Extract the fixed code part (after the prompt)
    try:
        # Try to find code section indicated by triple backticks
        if "```" in response:
            # Extract everything between the first set of triple backticks
            fixed_code = response.split("```")[1]
            # If the extracted section starts with a language specifier (like 'python'), remove it
            if fixed_code.startswith(("python", "py")):
                fixed_code = fixed_code.split("\n", 1)[1]
        else:
            # If no backticks, just return everything after the prompt
            fixed_code = response.split("Return only the fixed code without explanations.")[-1].strip()
        
        return fixed_code
    except Exception as e:
        logger.error(f"Error extracting fixed code: {e}")
        # Fallback: return everything after the prompt
        return response.split(code)[-1].strip() 