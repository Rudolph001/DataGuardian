
#!/usr/bin/env python3
"""
ExfilEye DLP - Windows Python Launcher
Cross-platform Python launcher for Windows systems
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def check_python():
    """Check if Python is available and compatible"""
    try:
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 8):
            print("❌ ERROR: Python 3.8 or higher is required")
            print(f"   Current version: {version.major}.{version.minor}.{version.micro}")
            print("   Please install Python 3.8+ from https://python.org/downloads/")
            return False
        
        print(f"✅ Python {version.major}.{version.minor}.{version.micro} detected")
        return True
    except Exception as e:
        print(f"❌ ERROR: Unable to check Python version: {e}")
        return False

def run_command(cmd, description=""):
    """Run a command with error handling"""
    try:
        print(f"🔧 {description}...")
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ ERROR: {description} failed")
        print(f"   Command: {cmd}")
        print(f"   Error: {e.stderr}")
        return False
    except Exception as e:
        print(f"❌ ERROR: Unexpected error during {description}: {e}")
        return False

def create_venv():
    """Create virtual environment"""
    venv_path = Path("venv")
    
    if venv_path.exists():
        print("📁 Virtual environment already exists")
        return True
    
    return run_command(f"{sys.executable} -m venv venv", "Creating virtual environment")

def activate_venv():
    """Get the path to the virtual environment Python"""
    if platform.system() == "Windows":
        venv_python = Path("venv") / "Scripts" / "python.exe"
    else:
        venv_python = Path("venv") / "bin" / "python"
    
    if venv_python.exists():
        return str(venv_python)
    else:
        print("⚠️  Virtual environment not found, using system Python")
        return sys.executable

def install_requirements():
    """Install required packages"""
    requirements_file = Path("local_requirements.txt")
    
    if not requirements_file.exists():
        print("❌ ERROR: local_requirements.txt not found")
        return False
    
    venv_python = activate_venv()
    return run_command(f'"{venv_python}" -m pip install -r local_requirements.txt', "Installing required packages")

def create_streamlit_config():
    """Create Streamlit configuration"""
    streamlit_dir = Path(".streamlit")
    config_file = streamlit_dir / "config.toml"
    
    streamlit_dir.mkdir(exist_ok=True)
    
    if not config_file.exists():
        print("🔧 Creating Streamlit configuration...")
        
        config_content = '''[server]
headless = true
address = "0.0.0.0"
port = 8501

[theme]
primaryColor = "#FF6B6B"
backgroundColor = "#FFFFFF"
secondaryBackgroundColor = "#F0F2F6"
textColor = "#262730"

[browser]
gatherUsageStats = false
'''
        
        try:
            with open(config_file, 'w') as f:
                f.write(config_content)
            print("✅ Streamlit configuration created")
            return True
        except Exception as e:
            print(f"❌ ERROR: Failed to create Streamlit config: {e}")
            return False
    else:
        print("📁 Streamlit configuration already exists")
        return True

def check_openai_key():
    """Check for OpenAI API key"""
    api_key = os.environ.get("OPENAI_API_KEY", "")
    
    if not api_key:
        print("\n⚠️  WARNING: OPENAI_API_KEY environment variable is not set")
        print("   AI features will not work without this key")
        print("   To set it:")
        print("   Windows: set OPENAI_API_KEY=your_api_key_here")
        print("   Or create a .env file with: OPENAI_API_KEY=your_api_key_here")
        print("   Get your API key from: https://platform.openai.com/api-keys")
        print()
    else:
        print("✅ OpenAI API key found")

def start_application():
    """Start the ExfilEye application"""
    app_file = Path("app_fixed.py")
    
    if not app_file.exists():
        print("❌ ERROR: app_fixed.py not found")
        print("   Please ensure all files are in the same directory")
        return False
    
    venv_python = activate_venv()
    
    print("\n🚀 Starting ExfilEye DLP System...")
    print("=" * 60)
    print("🌐 Application will be available at: http://localhost:8501")
    print("🔧 Press Ctrl+C to stop the application")
    print("=" * 60)
    print()
    
    try:
        # Start Streamlit
        cmd = f'"{venv_python}" -m streamlit run app_fixed.py --server.port 8501'
        subprocess.run(cmd, shell=True)
    except KeyboardInterrupt:
        print("\n\n🛑 Application stopped by user")
        print("Thank you for using ExfilEye DLP!")
    except Exception as e:
        print(f"\n❌ ERROR: Failed to start application: {e}")
        return False

def main():
    """Main launcher function"""
    print("🛡️  ExfilEye DLP - Local Setup (Windows)")
    print("=" * 50)
    print()
    
    # Check Python version
    if not check_python():
        input("Press Enter to exit...")
        return False
    
    # Create virtual environment
    if not create_venv():
        input("Press Enter to exit...")
        return False
    
    # Install requirements
    if not install_requirements():
        input("Press Enter to exit...")
        return False
    
    # Create Streamlit config
    if not create_streamlit_config():
        input("Press Enter to exit...")
        return False
    
    # Check OpenAI API key
    check_openai_key()
    
    # Start application
    start_application()
    
    return True

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n🛑 Setup interrupted by user")
    except Exception as e:
        print(f"\n❌ CRITICAL ERROR: {e}")
        input("Press Enter to exit...")
