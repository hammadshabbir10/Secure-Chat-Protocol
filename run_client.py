#!/usr/bin/env python3
"""
Secure Chat Client Runner with Virtual Environment Support
"""

import sys
import os

# Add virtual environment to path
venv_path = os.path.join(os.path.dirname(__file__), 'securechat-env')
if os.path.exists(venv_path):
    # Add virtual environment's site-packages to Python path
    site_packages = os.path.join(venv_path, 'lib', 'python3.*', 'site-packages')
    import glob
    site_packages_dirs = glob.glob(site_packages)
    if site_packages_dirs:
        sys.path.insert(0, site_packages_dirs[0])

# Add src to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Check if we're in virtual environment, if not, warn
if not hasattr(sys, 'real_prefix') and not (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
    print("⚠️  Warning: Not running in virtual environment. Run 'source securechat-env/bin/activate' first.")

from client import SecureChatClient

if __name__ == "__main__":
    print("🚀 Starting Secure Chat Client...")
    print("📍 Connecting to localhost:8080")
    print("💡 Type 'exit' to quit the chat")
    print("-" * 50)
    
    client = SecureChatClient(host='localhost', port=8080)
    try:
        client.start()
    except KeyboardInterrupt:
        print("\n🛑 Client stopped by user")
    except Exception as e:
        print(f"❌ Client error: {e}")
