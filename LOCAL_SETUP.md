# ExfilEye DLP - Local Setup Guide

## Quick Start

### Windows Users
**Option 1: Python Launcher (Recommended)**
1. Download all files to a folder on your computer
2. Double-click `run_windows.py`
3. The app will automatically install dependencies and start
4. Open your browser to `http://localhost:8501`

**Option 2: Batch Script**
1. Download all files to a folder on your computer
2. Double-click `run_windows.bat`
3. The app will automatically install dependencies and start
4. Open your browser to `http://localhost:8501`

### Mac Users
**Option 1: Python Launcher (Recommended)**
1. Download all files to a folder on your computer
2. Open Terminal and navigate to the folder
3. Run: `python3 run_mac.py`
4. The app will automatically install dependencies and start
5. Open your browser to `http://localhost:8501`

**Option 2: Shell Script**
1. Download all files to a folder on your computer
2. Open Terminal and navigate to the folder
3. Run: `chmod +x run_mac.sh && ./run_mac.sh`
4. The app will automatically install dependencies and start
5. Open your browser to `http://localhost:8501`

## Prerequisites

### Windows
- Python 3.8 or higher (download from https://python.org/downloads/)
- Make sure to check "Add Python to PATH" during installation

### Mac
- Python 3.8 or higher (pre-installed on most Macs or install via Homebrew)
- If needed: `brew install python3`

## Files You Need

Download these files to the same folder:
- `app_fixed.py` - Main application
- `auth.py` - Authentication system
- `domain_classifier.py` - Domain classification
- `security_config.py` - Security configuration
- `local_requirements.txt` - Python dependencies
- `run_windows.bat` - Windows startup script
- `run_mac.sh` - Mac startup script

## AI Features Setup

To use AI-powered insights:
1. Get an OpenAI API key from https://platform.openai.com/api-keys
2. Set the environment variable:
   - **Windows**: `set OPENAI_API_KEY=your_api_key_here`
   - **Mac**: `export OPENAI_API_KEY=your_api_key_here`
3. Or create a `.env` file with: `OPENAI_API_KEY=your_api_key_here`

## Manual Installation (Alternative)

If the automated scripts don't work:

1. Install Python dependencies:
   ```bash
   pip install streamlit networkx numpy openai pandas plotly reportlab scikit-learn scipy weasyprint
   ```

2. Create `.streamlit/config.toml`:
   ```toml
   [server]
   headless = true
   address = "0.0.0.0"
   port = 8501
   ```

3. Run the application:
   ```bash
   streamlit run app_fixed.py --server.port 8501
   ```

## Features Available Locally

✅ **All Core Features:**
- Data upload and processing
- Security operations dashboard
- Network analysis and visualization
- Domain classification
- Follow-up center
- PDF report generation

✅ **AI Features (with API key):**
- Anomaly detection
- Intelligent email analysis
- Risk assessment insights

## Troubleshooting

### Common Issues

**"Python not found"**
- Install Python from https://python.org/downloads/
- Ensure Python is added to PATH

**"Permission denied" (Mac)**
- Run: `chmod +x run_mac.sh`

**"Module not found"**
- Delete the `venv` folder and run the script again
- Check your internet connection for package downloads

**AI features not working**
- Verify your OpenAI API key is set correctly
- Check your OpenAI account has credits available

### Getting Help

If you encounter issues:
1. Check that Python 3.8+ is installed
2. Ensure you have an internet connection for package installation
3. Try running the manual installation commands
4. Check the console output for specific error messages

## Security Notes

- The application runs locally on your computer
- No data is sent to external servers (except OpenAI for AI features)
- All configuration files are stored locally
- You can use the app completely offline (except AI features)

## Stopping the Application

- Press `Ctrl+C` in the terminal/command prompt
- Or close the terminal window
- The application will stop and free up the port

## Data Storage

- Configuration files are stored in the application folder
- Uploaded data is processed in memory only
- Export files are saved to your Downloads folder or selected location