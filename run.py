"""
Single-command runner for Protocol Archaeology Tool.
Automatically checks dependencies, launches the server, and opens your browser.
"""

import sys
import subprocess
import webbrowser
import threading
import time
import os

def check_and_install_dependencies():
    required = ["fastapi", "uvicorn", "scapy", "python-multipart", "jinja2", "pydantic"]
    missing = []
    
    for package in required:
        try:
            __import__(package.replace("-", "_"))
        except ImportError:
            missing.append(package)
            
    if missing:
        print(f"[*] Installing required dependencies: {', '.join(missing)}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])
        print("[+] All dependencies installed successfully!\n")

def open_browser():
    time.sleep(1.2)
    webbrowser.open("http://localhost:8000")

def main():
    print("=" * 60)
    print("   PROTOCOL ARCHAEOLOGY TOOL - EASY LAUNCHER")
    print("=" * 60)
    
    check_and_install_dependencies()
    
    import uvicorn
    
    print("[*] Starting backend server at http://localhost:8000 ...")
    print("[*] Opening your web browser automatically...")
    print("[*] Press Ctrl+C at any time in this window to stop the server.\n")
    
    # Open browser in a background thread
    threading.Thread(target=open_browser, daemon=True).start()
    
    # Run uvicorn
    uvicorn.run("backend.app:app", host="127.0.0.1", port=8000, reload=False)

if __name__ == "__main__":
    main()
