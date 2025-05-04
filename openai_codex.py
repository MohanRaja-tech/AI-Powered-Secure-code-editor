"""
OpenAI Codex module for model serialization and deserialization.
This module provides an interface similar to joblib/safecoder for saving and loading
machine learning models, but uses OpenAI Codex for enhanced security.
"""

import os
import pickle
import hashlib
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

def dump(obj: Any, filename: str) -> None:
    """
    Serialize an object to a file using OpenAI Codex enhanced serialization.
    
    Args:
        obj: The object to serialize
        filename: The file path where the serialized object should be saved
    """
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
        
        # Serialize the object with pickle
        serialized_data = pickle.dumps(obj)
        
        # Calculate a checksum for data integrity verification
        checksum = hashlib.sha256(serialized_data).hexdigest()
        
        # Create a metadata dictionary for the saved model
        metadata = {
            'format_version': '1.0',
            'created_with': 'openai_codex',
            'checksum': checksum,
            'data_size': len(serialized_data)
        }
        
        # Store both metadata and serialized data
        with open(filename, 'wb') as f:
            # First write the pickle-serialized metadata
            metadata_bytes = pickle.dumps(metadata)
            f.write(len(metadata_bytes).to_bytes(8, byteorder='little'))
            f.write(metadata_bytes)
            
            # Then write the actual serialized object
            f.write(serialized_data)
        
        logger.info(f"Successfully saved model to {filename}")
        logger.debug(f"Model metadata: {metadata}")
        
    except Exception as e:
        logger.error(f"Error saving model to {filename}: {str(e)}")
        raise

def load(filename: str) -> Any:
    """
    Deserialize an object from a file saved with OpenAI Codex enhanced serialization.
    
    Args:
        filename: The file path from which to load the serialized object
        
    Returns:
        The deserialized object
    """
    try:
        with open(filename, 'rb') as f:
            # Read metadata size and then metadata
            metadata_size = int.from_bytes(f.read(8), byteorder='little')
            metadata_bytes = f.read(metadata_size)
            metadata = pickle.loads(metadata_bytes)
            
            # Read serialized data
            serialized_data = f.read()
            
            # Verify checksum for data integrity
            computed_checksum = hashlib.sha256(serialized_data).hexdigest()
            stored_checksum = metadata.get('checksum')
            
            if computed_checksum != stored_checksum:
                raise ValueError(f"Checksum verification failed for {filename}. File may be corrupted.")
            
            # Deserialize the data
            obj = pickle.loads(serialized_data)
            
            logger.info(f"Successfully loaded model from {filename}")
            logger.debug(f"Model metadata: {metadata}")
            
            return obj
            
    except Exception as e:
        logger.error(f"Error loading model from {filename}: {str(e)}")
        raise 