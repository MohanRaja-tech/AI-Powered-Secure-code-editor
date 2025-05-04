import os
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

def test_codellama():
    """Test if Code Llama is installed and working correctly."""
    print("Testing Code Llama installation...")
    
    try:
        # Check if model exists locally
        model_path = "models/CodeLlama-7b-Python-hf"
        if os.path.exists(model_path):
            print(f"Loading model from local directory: {model_path}")
        else:
            model_path = "codellama/CodeLlama-7b-Python-hf"
            print(f"Local model not found, loading from Hugging Face: {model_path}")
        
        # Check if CUDA is available
        device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"Using device: {device}")
        
        # Load tokenizer
        print("Loading tokenizer...")
        tokenizer = AutoTokenizer.from_pretrained(model_path)
        
        # Load model
        print("Loading model (this may take a while)...")
        model = AutoModelForCausalLM.from_pretrained(
            model_path,
            torch_dtype=torch.float16 if device == "cuda" else torch.float32,
            device_map=device
        )
        
        # Test a simple code generation
        prompt = "def fibonacci(n):"
        print(f"\nGenerating code for prompt: '{prompt}'")
        
        inputs = tokenizer(prompt, return_tensors="pt").to(device)
        
        with torch.no_grad():
            outputs = model.generate(
                inputs["input_ids"],
                max_length=100,
                temperature=0.2,
                top_p=0.95,
                do_sample=True
            )
        
        generated_code = tokenizer.decode(outputs[0], skip_special_tokens=True)
        print(f"\nGenerated code:\n{generated_code}")
        
        # Test our code_llama module
        print("\nTesting code_llama module...")
        import code_llama
        
        # Create a sample model data structure to test the dump/load functions
        model_data = {
            'vectorizer': 'dummy_vectorizer',
            'model': 'dummy_model'
        }
        
        # Test dump
        print("Testing dump function...")
        test_path = "models/test_model.codellama"
        code_llama.dump(model_data, test_path)
        
        # Test load
        print("Testing load function...")
        loaded_data = code_llama.load(test_path)
        
        # Clean up
        if os.path.exists(test_path):
            os.remove(test_path)
        
        print("\nCode Llama installation test completed successfully!")
        return True
        
    except Exception as e:
        print(f"\nError testing Code Llama: {e}")
        return False

if __name__ == "__main__":
    test_codellama() 