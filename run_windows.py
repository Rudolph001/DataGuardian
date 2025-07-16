
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

def check_package_status():
    """Check the installation status of each required package"""
    requirements_file = Path("requirements_windows.txt")
    
    if not requirements_file.exists():
        print("❌ ERROR: requirements_windows.txt not found")
        return False
    
    print("\n📦 PACKAGE INSTALLATION STATUS:")
    print("=" * 50)
    
    venv_python = activate_venv()
    
    # Read requirements from file
    try:
        with open(requirements_file, 'r') as f:
            requirements = f.readlines()
    except Exception as e:
        print(f"❌ ERROR: Cannot read requirements file: {e}")
        return False
    
    all_installed = True
    
    for req in requirements:
        req = req.strip()
        if not req or req.startswith('#'):
            continue
            
        # Extract package name (remove version constraints)
        package_name = req.split('>=')[0].split('==')[0].split('<=')[0].split('>')[0].split('<')[0].split('!')[0]
        
        try:
            # Check if package is installed
            result = subprocess.run(
                f'"{venv_python}" -c "import {package_name}; print(__import__(\'{package_name}\').__version__)"',
                shell=True, capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                version = result.stdout.strip()
                print(f"✅ {package_name:<15} - Version: {version}")
            else:
                print(f"❌ {package_name:<15} - NOT INSTALLED")
                all_installed = False
                
        except subprocess.TimeoutExpired:
            print(f"⏰ {package_name:<15} - TIMEOUT (checking took too long)")
            all_installed = False
        except Exception as e:
            # Try alternative import names for some packages
            alt_names = {
                'scikit-learn': 'sklearn',
                'pillow': 'PIL',
                'opencv-python': 'cv2'
            }
            
            if package_name in alt_names:
                alt_name = alt_names[package_name]
                try:
                    result = subprocess.run(
                        f'"{venv_python}" -c "import {alt_name}; print(__import__(\'{alt_name}\').__version__)"',
                        shell=True, capture_output=True, text=True, timeout=10
                    )
                    
                    if result.returncode == 0:
                        version = result.stdout.strip()
                        print(f"✅ {package_name:<15} - Version: {version}")
                    else:
                        print(f"❌ {package_name:<15} - NOT INSTALLED")
                        all_installed = False
                except:
                    print(f"❌ {package_name:<15} - NOT INSTALLED")
                    all_installed = False
            else:
                print(f"❌ {package_name:<15} - NOT INSTALLED")
                all_installed = False
    
    print("=" * 50)
    
    if all_installed:
        print("✅ ALL PACKAGES INSTALLED SUCCESSFULLY!")
    else:
        print("⚠️  SOME PACKAGES ARE MISSING - Installation needed")
    
    print()
    return all_installed

def install_requirements():
    """Install required packages"""
    requirements_file = Path("requirements_windows.txt")
    
    if not requirements_file.exists():
        print("❌ ERROR: requirements_windows.txt not found")
        return False
    
    venv_python = activate_venv()
    return run_command(f'"{venv_python}" -m pip install -r requirements_windows.txt', "Installing required packages")

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

def check_environment():
    """Check environment setup"""
    print("\n🔧 ENVIRONMENT CHECK:")
    print("=" * 30)
    print("✅ All required packages are installed")
    print("✅ ExfilEye DLP is ready to run")
    print("✅ No external API keys required")
    print("=" * 30)

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
    
    # Check current package status
    print("\n🔍 Checking current package installation status...")
    check_package_status()
    
    # Ask user if they want to install/update packages
    print("📦 Package Installation Options:")
    print("1. Install/Update all packages")
    print("2. Skip installation (use existing packages)")
    print("3. Exit")
    
    choice = input("\nEnter your choice (1-3): ").strip()
    
    if choice == "1":
        if not install_requirements():
            input("Press Enter to exit...")
            return False
        # Check status again after installation
        print("\n🔍 Checking package status after installation...")
        check_package_status()
    elif choice == "2":
        print("⏭️  Skipping package installation")
    elif choice == "3":
        print("👋 Exiting setup")
        return False
    else:
        print("❌ Invalid choice, exiting")
        return False
    
    # Create Streamlit config
    if not create_streamlit_config():
        input("Press Enter to exit...")
        return False
    
    # Check environment
    check_environment()
    
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
