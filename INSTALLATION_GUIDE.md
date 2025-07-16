# ExfilEye DLP - Local Installation Guide

## Quick Start

### Windows
1. Run `run_windows.bat` (double-click)
2. Or manually: `python run_windows.py`

### macOS
1. Run `run_mac.sh` (double-click or `chmod +x run_mac.sh && ./run_mac.sh`)
2. Or manually: `python run_mac.py`

### Linux
1. Use `python app_fixed.py` after installing dependencies
2. Or adapt the macOS script for your distribution

## Manual Installation

### Prerequisites
- Python 3.11 or higher
- pip package manager

### Step 1: Create Virtual Environment (Recommended)
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 2: Install Dependencies

Choose the requirements file for your operating system:

#### Windows
```bash
pip install -r requirements_windows.txt
```

#### macOS
```bash
pip install -r requirements_mac.txt
```

#### Linux
```bash
pip install -r requirements_linux.txt
```

#### Generic/Cross-platform
```bash
pip install -r local_requirements.txt
```

### Step 3: System Dependencies

Some packages may require additional system dependencies:

#### Windows
- Visual C++ Build Tools (if not already installed)
- Download from Microsoft's official website

#### macOS
- Xcode Command Line Tools:
  ```bash
  xcode-select --install
  ```
- For WeasyPrint (PDF generation):
  ```bash
  brew install cairo pango gdk-pixbuf libffi
  ```

#### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install python3-dev gcc g++ libcairo2-dev libpango1.0-dev libgdk-pixbuf2.0-dev libffi-dev
```

#### Linux (CentOS/RHEL)
```bash
sudo yum install python3-devel gcc gcc-c++ cairo-devel pango-devel gdk-pixbuf2-devel libffi-devel
```

### Step 4: Configure Application
Create a `.streamlit/config.toml` file:
```toml
[server]
headless = true
address = "0.0.0.0"
port = 5000

[browser]
gatherUsageStats = false
```

### Step 5: Run Application
```bash
streamlit run app_fixed.py --server.port 5000
```

## Optional: AI Features Setup

For advanced AI-powered insights, set up OpenAI API:

1. Get API key from OpenAI
2. Set environment variable:
   ```bash
   # Windows
   set OPENAI_API_KEY=your_api_key_here
   
   # macOS/Linux
   export OPENAI_API_KEY=your_api_key_here
   ```

## Troubleshooting

### Common Issues

1. **Import Errors**
   - Ensure all dependencies are installed
   - Check Python version (3.11+ required)
   - Verify virtual environment activation

2. **WeasyPrint Issues**
   - Install system dependencies as listed above
   - On Windows, may need Visual C++ Build Tools

3. **Port Already in Use**
   - Change port in command: `streamlit run app_fixed.py --server.port 5001`
   - Or kill existing process on port 5000

4. **Memory Issues with Large Files**
   - Increase system memory allocation
   - Process smaller file chunks
   - Monitor system resources

### Performance Tips

- Use SSD storage for better file processing
- Allocate sufficient RAM (8GB+ recommended)
- Close unnecessary applications during analysis
- Use virtual environment to avoid package conflicts

## File Structure

```
ExfilEye/
├── app_fixed.py              # Main application
├── auth.py                   # Authentication (optional)
├── data_persistence.py       # Data storage
├── domain_classifier.py      # Domain classification
├── security_config.py        # Security settings
├── local_requirements.txt    # Cross-platform requirements
├── requirements_windows.txt  # Windows-specific
├── requirements_mac.txt      # macOS-specific
├── requirements_linux.txt    # Linux-specific
├── run_windows.py           # Windows launcher
├── run_mac.py               # macOS launcher
├── domains.json             # Domain classifications
├── daily_data/              # Data storage
├── work_states/             # Work state persistence
└── data_backups/            # Backup files
```

## Support

For issues or questions:
1. Check this installation guide
2. Review system requirements
3. Ensure all dependencies are correctly installed
4. Verify file permissions and paths