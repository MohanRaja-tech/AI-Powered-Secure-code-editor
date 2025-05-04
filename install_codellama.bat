@echo off
echo Installing Code Llama...

:: Create models directory
mkdir models 2>nul

:: Install required packages
echo Installing required packages...
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
pip install transformers huggingface_hub

:: Download the model
echo Downloading Code Llama model...
python -c "from huggingface_hub import snapshot_download; snapshot_download(repo_id='codellama/CodeLlama-7b-Python-hf', local_dir='models/CodeLlama-7b-Python-hf', local_dir_use_symlinks=False)"

echo.
echo Code Llama installation completed!
echo.
echo You can now use code_llama.py module in your application.
echo. 