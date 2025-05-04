#!/usr/bin/env python
import os
import re
import glob
import argparse
import logging
import pickle
import numpy as np
from typing import List, Dict, Any, Tuple, Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Common vulnerability patterns (from check_model.py)
VULNERABILITY_PATTERNS = {
    'sql_injection': [
        r'execute\s*\(\s*[\'"`].*?\bSELECT\b.*?\+.*?[\'"`]',
        r'execute\s*\(\s*[\'"`].*?\bINSERT\b.*?\+.*?[\'"`]',
        r'execute\s*\(\s*[\'"`].*?\bUPDATE\b.*?\+.*?[\'"`]',
        r'execute\s*\(\s*[\'"`].*?\bDELETE\b.*?\+.*?[\'"`]',
        r'cursor\.execute\s*\([^,]*?%s',
        r'cursor\.execute\s*\(.*?\+.*?\)',
        r'\.execute\s*\(.*?\+.*?\)',
    ],
    'command_injection': [
        r'os\.system\s*\([^,]*?\+.*?\)',
        r'os\.system\s*\(.*?input.*?\)',
        r'subprocess\.call\s*\([^,]*?\+.*?\)',
        r'subprocess\.Popen\s*\([^,]*?\+.*?\)',
        r'exec\s*\([^,]*?\+.*?\)',
        r'eval\s*\([^,]*?\+.*?\)',
    ],
    'xss': [
        r'render\s*\([^,]*?\+.*?\)',
        r'innerHTML\s*=.*?\+.*?',
        r'document\.write\s*\(.*?\+.*?\)',
        r'\.html\s*\(.*?\+.*?\)',
        r'template\s*=.*?<.*>\s*\+.*?\+',
    ],
    'path_traversal': [
        r'open\s*\([^,]*?\+.*?\)',
        r'open\s*\(.*?input.*?\)',
        r'os\.path\.join\s*\([^,]*?\.\..*?\)',
        r'file_get_contents\s*\([^,]*?\+.*?\)',
    ],
    'insecure_deserialization': [
        r'pickle\.loads\s*\(',
        r'yaml\.load\s*\([^,]*?Loader=None',
        r'yaml\.load\s*\([^,]*?Loader=yaml\.Loader',
        r'marshal\.loads\s*\(',
    ],
    'buffer_overflow': [
        r'strcpy\s*\(',
        r'strcat\s*\(',
        r'memcpy\s*\(.*?,.*?,\s*sizeof\(',
        r'gets\s*\(',
    ],
    'hard_coded_credentials': [
        r'password\s*=\s*[\'"`][^\'"]+[\'"`]',
        r'api_key\s*=\s*[\'"`][^\'"]+[\'"`]',
        r'secret\s*=\s*[\'"`][^\'"]+[\'"`]',
        r'token\s*=\s*[\'"`][^\'"]+[\'"`]',
    ],
    'weak_cryptography': [
        r'md5\s*\(',
        r'hashlib\.md5\s*\(',
        r'hashlib\.sha1\s*\(',
        r'random\.',
        r'Math\.random\s*\(',
    ]
}

def extract_features(code_snippet: str) -> List[float]:
    """
    Extract features from code snippet that might indicate security vulnerabilities.
    
    Args:
        code_snippet: String containing code
        
    Returns:
        List of features (0 or 1 values) indicating presence of vulnerability patterns
    """
    features = []
    
    # Check for each vulnerability pattern
    for vuln_type, patterns in VULNERABILITY_PATTERNS.items():
        # For each type, check if any pattern matches
        vuln_found = 0
        for pattern in patterns:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                vuln_found = 1
                break
        features.append(vuln_found)
    
    # Additional features
    
    # Count strings being concatenated
    string_concat_count = len(re.findall(r'[\'"]\s*\+', code_snippet))
    features.append(min(1.0, string_concat_count / 5.0))  # Normalize
    
    # Count user input usage
    user_input_count = len(re.findall(r'(?:input|param|request|stdin|argv|getParameter|POST|GET)', code_snippet))
    features.append(min(1.0, user_input_count / 5.0))  # Normalize
    
    # Count of potentially dangerous functions
    dangerous_funcs = [
        'eval', 'exec', 'system', 'popen', 'subprocess', 
        'execute', 'fromstring', 'deserialize', 'pickle', 
        'yaml', 'shell', 'command', 'innerHTML', 'document.write'
    ]
    
    danger_count = 0
    for func in dangerous_funcs:
        danger_count += len(re.findall(r'\b' + func + r'\b', code_snippet))
    features.append(min(1.0, danger_count / 3.0))  # Normalize
    
    return features

def load_dataset(path: str, is_security_dataset: bool) -> Tuple[List[str], List[int]]:
    """
    Load code snippets from a directory
    
    Args:
        path: Path to directory containing code samples
        is_security_dataset: True if this contains security vulnerabilities
        
    Returns:
        Tuple of (code_samples, labels)
    """
    code_samples = []
    labels = []
    
    # Get all text files in the directory
    file_pattern = os.path.join(path, '*.txt')
    files = glob.glob(file_pattern)
    
    logger.info(f"Found {len(files)} files in {path}")
    
    for file_path in files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # Skip very short snippets
                if len(content) < 50:
                    continue
                
                code_samples.append(content)
                labels.append(1 if is_security_dataset else 0)
        except Exception as e:
            logger.warning(f"Error reading {file_path}: {e}")
    
    logger.info(f"Successfully loaded {len(code_samples)} samples with label {1 if is_security_dataset else 0}")
    return code_samples, labels

def preprocess_code(code: str) -> str:
    """
    Preprocess code to make it more suitable for feature extraction
    
    Args:
        code: Raw code string
        
    Returns:
        Processed code
    """
    # Remove comments (simplified)
    code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)  # Remove C++ style comments
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)  # Remove C style comments
    code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)    # Remove Python/bash style comments
    
    # Keep only relevant parts of git diff output (find actual code changes)
    if code.startswith('diff --git') or code.startswith('commit '):
        # Extract only the code changes from git diff format
        # Look for code after the "+++" line
        code_changes = []
        in_change_block = False
        for line in code.split('\n'):
            if line.startswith('+++') or line.startswith('---'):
                continue
            if line.startswith('@@'):
                in_change_block = True
                continue
            if in_change_block:
                if line.startswith('+'):
                    code_changes.append(line[1:])  # Remove the '+' prefix
        
        if code_changes:
            code = '\n'.join(code_changes)
    
    return code

def extract_code_blocks(code: str) -> List[str]:
    """
    Extract meaningful code blocks for analysis
    
    Args:
        code: The code to analyze
        
    Returns:
        List of code blocks
    """
    blocks = []
    lines = code.split('\n')
    
    current_block = []
    indentation_stack = []
    
    for line in lines:
        stripped = line.strip()
        
        # Skip empty lines and comments
        if not stripped or stripped.startswith(('#', '//', '/*')):
            continue
        
        # Start a new block for function definitions
        if re.match(r'^(def|function|void|int|char|public|private|class)\s+\w+', stripped):
            if current_block:
                blocks.append('\n'.join(current_block))
            current_block = [line]
            indentation_level = len(line) - len(line.lstrip())
            indentation_stack = [indentation_level]
        elif current_block:
            # Check indentation level for existing block
            indentation_level = len(line) - len(line.lstrip())
            
            # If we're back to original indentation, end the block
            if indentation_stack and indentation_level <= indentation_stack[0]:
                blocks.append('\n'.join(current_block))
                current_block = []
                indentation_stack = []
            
            # Add to the current block
            if current_block:
                current_block.append(line)
    
    # Add the last block if any
    if current_block:
        blocks.append('\n'.join(current_block))
    
    # If no blocks found, treat the whole code as one block
    if not blocks and code.strip():
        blocks = [code]
    
    return blocks

def train_model(security_dataset_path: str, non_security_dataset_path: str, output_model_path: str):
    """
    Train a security vulnerability detection model
    
    Args:
        security_dataset_path: Path to the security dataset
        non_security_dataset_path: Path to the non-security dataset
        output_model_path: Path to save the trained model
    """
    logger.info("Loading security dataset...")
    security_samples, security_labels = load_dataset(security_dataset_path, True)
    
    logger.info("Loading non-security dataset...")
    non_security_samples, non_security_labels = load_dataset(non_security_dataset_path, False)
    
    # Combine datasets
    all_samples = security_samples + non_security_samples
    all_labels = security_labels + non_security_labels
    
    logger.info(f"Total dataset size: {len(all_samples)} samples")
    logger.info(f"Security samples: {len(security_samples)}")
    logger.info(f"Non-security samples: {len(non_security_samples)}")
    
    # Preprocess code samples
    logger.info("Preprocessing code samples...")
    preprocessed_samples = [preprocess_code(sample) for sample in all_samples]
    
    # First, train a model using TF-IDF features
    logger.info("Creating TF-IDF features...")
    vectorizer = TfidfVectorizer(
        max_features=1000,
        ngram_range=(1, 2),
        analyzer='word',
        token_pattern=r'(?u)\b\w+\b|->|\.|::|<<|>>|<=|>=|==|!=|&&|\|\||\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<='
    )
    
    X_tfidf = vectorizer.fit_transform(preprocessed_samples)
    
    # Now extract custom security features
    logger.info("Extracting security features...")
    X_security_features = np.array([extract_features(sample) for sample in preprocessed_samples])
    
    # Combine all features
    X_combined = np.hstack((X_tfidf.toarray(), X_security_features))
    
    # Split the dataset
    X_train, X_test, y_train, y_test = train_test_split(
        X_combined, all_labels, test_size=0.2, random_state=42
    )
    
    # Train model
    logger.info("Training model...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate model
    logger.info("Evaluating model...")
    train_score = model.score(X_train, y_train)
    test_score = model.score(X_test, y_test)
    
    logger.info(f"Training accuracy: {train_score:.4f}")
    logger.info(f"Testing accuracy: {test_score:.4f}")
    
    # Detailed evaluation
    y_pred = model.predict(X_test)
    
    logger.info("Classification Report:")
    logger.info("\n" + classification_report(y_test, y_pred))
    
    logger.info("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    logger.info("\n" + str(cm))
    
    # Cross-validation
    cv_scores = cross_val_score(model, X_combined, all_labels, cv=5)
    logger.info(f"Cross-validation scores: {cv_scores}")
    logger.info(f"Mean CV score: {cv_scores.mean():.4f}")
    
    # Feature importance
    feature_names = vectorizer.get_feature_names_out().tolist() + [
        f"vuln_{v_type}" for v_type in VULNERABILITY_PATTERNS.keys()
    ] + ["string_concat", "user_input", "dangerous_functions"]
    
    top_features_idx = model.feature_importances_.argsort()[-20:]
    top_features = [(feature_names[i], model.feature_importances_[i]) 
                   for i in top_features_idx]
    
    logger.info("Top 20 features:")
    for feature, importance in reversed(top_features):
        logger.info(f"{feature}: {importance:.4f}")
    
    # Save the model with vectorizer
    logger.info(f"Saving model to {output_model_path}")
    model_data = {
        'vectorizer': vectorizer,
        'model': model,
        'feature_names': feature_names,
        'training_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'evaluation': {
            'train_score': train_score,
            'test_score': test_score,
            'classification_report': classification_report(y_test, y_pred),
            'confusion_matrix': cm.tolist(),
            'cv_scores': cv_scores.tolist()
        }
    }
    
    with open(output_model_path, 'wb') as f:
        pickle.dump(model_data, f)
    
    logger.info("Model training completed successfully!")
    
    # Plot feature importance
    plt.figure(figsize=(12, 8))
    plt.barh(range(20), [imp for _, imp in reversed(top_features)])
    plt.yticks(range(20), [name for name, _ in reversed(top_features)])
    plt.xlabel('Importance')
    plt.title('Top 20 Feature Importance')
    plt.tight_layout()
    
    # Save the plot
    plot_path = os.path.splitext(output_model_path)[0] + '_feature_importance.png'
    plt.savefig(plot_path)
    logger.info(f"Feature importance plot saved to {plot_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Train a security vulnerability detection model')
    parser.add_argument('--security-dataset', 
                        default='Dev forge Hackathon IT dept/Secure Code AI/SecurityDataset/cleaned',
                        help='Path to the security dataset directory')
    parser.add_argument('--non-security-dataset', 
                        default='Dev forge Hackathon IT dept/Secure Code AI/NonSecurityDataset/nonSecurityDataset',
                        help='Path to the non-security dataset directory')
    parser.add_argument('--output-model', 
                        default='Dev forge Hackathon IT dept/Secure Code AI/vulnerability_model.pkl',
                        help='Path to save the trained model')
    
    args = parser.parse_args()
    
    train_model(args.security_dataset, args.non_security_dataset, args.output_model) 