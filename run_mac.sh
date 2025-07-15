#!/bin/bash

echo "Starting ExfilEye DLP System..."
echo

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed or not in PATH"
    echo "Please install Python from https://python.org/downloads/"
    echo "Or use: brew install python3"
    exit 1
fi

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    echo "ERROR: pip3 is not available"
    echo "Please ensure pip is installed with Python"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to create virtual environment"
        exit 1
    fi
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to activate virtual environment"
    exit 1
fi

# Install requirements
echo "Installing required packages..."
pip install -r local_requirements.txt
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install requirements"
    exit 1
fi

# Create .streamlit directory if it doesn't exist
mkdir -p .streamlit

# Create config.toml if it doesn't exist
if [ ! -f ".streamlit/config.toml" ]; then
    echo "Creating Streamlit configuration..."
    cat > .streamlit/config.toml << EOF
[server]
headless = true
address = "0.0.0.0"
port = 8501

[theme]
primaryColor = "#FF6B6B"
backgroundColor = "#FFFFFF"
EOF
fi

# Check for OpenAI API key
if [ -z "$OPENAI_API_KEY" ]; then
    echo
    echo "WARNING: OPENAI_API_KEY environment variable is not set"
    echo "AI features will not work without this key"
    echo "To set it, run: export OPENAI_API_KEY=your_api_key_here"
    echo "Or create a .env file with: OPENAI_API_KEY=your_api_key_here"
    echo
fi

# Start the application
echo
echo "Starting ExfilEye DLP System..."
echo "Application will be available at: http://localhost:8501"
echo "Press Ctrl+C to stop the application"
echo

streamlit run app_fixed.py --server.port 8501