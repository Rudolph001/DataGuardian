# ExfilEye DLP - Download Package

## What You Need to Download

To run ExfilEye on your local Windows or Mac computer, download these files:

### Core Application Files (Required)
- `app_fixed.py` - Main application
- `auth.py` - Authentication system  
- `domain_classifier.py` - Domain classification
- `security_config.py` - Security configuration

### Setup Files (Required)
- `local_requirements.txt` - Python dependencies
- `run_windows.bat` - Windows startup script
- `run_mac.sh` - Mac startup script (already executable)
- `local_config.toml` - Streamlit configuration
- `LOCAL_SETUP.md` - Complete setup instructions

## Quick Start

### For Windows:
1. Download all files to a folder
2. Double-click `run_windows.bat`
3. Go to `http://localhost:8501` in your browser

### For Mac:
1. Download all files to a folder
2. Open Terminal, navigate to the folder
3. Run: `./run_mac.sh`
4. Go to `http://localhost:8501` in your browser

## Requirements
- Python 3.8 or higher
- Internet connection (for initial setup)
- OpenAI API key (optional, for AI features)

The setup scripts will automatically:
- Create a virtual environment
- Install all required packages
- Configure Streamlit
- Start the application

## Full Documentation
See `LOCAL_SETUP.md` for complete instructions and troubleshooting.