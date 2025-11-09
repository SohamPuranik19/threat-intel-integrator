#!/usr/bin/env python3
"""
Startup script for Render deployment
"""
import os
import sys

# Add the current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

print(f"Current directory: {os.getcwd()}")
print(f"Script directory: {current_dir}")
print(f"Python path: {sys.path}")
print(f"Contents of current dir: {os.listdir(current_dir)}")

if os.path.exists('infosecwriteups'):
    print(f"infosecwriteups directory found!")
    print(f"Contents: {os.listdir('infosecwriteups')}")
else:
    print("ERROR: infosecwriteups directory not found!")
    sys.exit(1)

# Import and run uvicorn
import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(
        "infosecwriteups.api_server_enhanced:app",
        host="127.0.0.1",
        port=port,
        log_level="info"
    )
