#!/usr/bin/env python3
"""
Create a download package for ExfilEye DLP local installation
"""

import os
import zipfile
import shutil
from datetime import datetime

def create_download_package():
    """Create a ZIP file with all necessary files for local installation"""
    
    # Files to include in the package
    files_to_include = [
        'app_fixed.py',
        'auth.py',
        'domain_classifier.py',
        'security_config.py',
        'local_requirements.txt',
        'run_windows.py',
        'run_mac.py',
        'run_windows.bat',
        'run_mac.sh',
        'local_config.toml',
        'LOCAL_SETUP.md',
        'DOWNLOAD_PACKAGE.md'
    ]
    
    # Create package directory
    package_dir = 'ExfilEye_Local_Package'
    if os.path.exists(package_dir):
        shutil.rmtree(package_dir)
    os.makedirs(package_dir)
    
    # Copy files to package directory
    for file_name in files_to_include:
        if os.path.exists(file_name):
            shutil.copy2(file_name, package_dir)
            print(f"✓ Added {file_name}")
        else:
            print(f"⚠ Missing {file_name}")
    
    # Create .streamlit directory and config
    streamlit_dir = os.path.join(package_dir, '.streamlit')
    os.makedirs(streamlit_dir, exist_ok=True)
    shutil.copy2('local_config.toml', os.path.join(streamlit_dir, 'config.toml'))
    
    # Create ZIP file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_name = f'ExfilEye_DLP_Local_{timestamp}.zip'
    
    with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(package_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, package_dir)
                zipf.write(file_path, arcname)
    
    # Clean up temporary directory
    shutil.rmtree(package_dir)
    
    print(f"\n✅ Package created: {zip_name}")
    print(f"📁 Package size: {os.path.getsize(zip_name) / 1024:.1f} KB")
    print("\nThe ZIP file contains everything needed to run ExfilEye locally!")
    print("Extract it anywhere and run the appropriate script for your OS.")

if __name__ == "__main__":
    create_download_package()