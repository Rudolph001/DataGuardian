@echo off
echo Starting ExfilEye DLP System...
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python from https://python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

:: Check if pip is available
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: pip is not available
    echo Please ensure pip is installed with Python
    pause
    exit /b 1
)

:: Create virtual environment if it doesn't exist
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
)

:: Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat
if %errorlevel% neq 0 (
    echo ERROR: Failed to activate virtual environment
    pause
    exit /b 1
)

:: Install requirements
echo Installing required packages...
pip install -r local_requirements.txt
if %errorlevel% neq 0 (
    echo ERROR: Failed to install requirements
    pause
    exit /b 1
)

:: Create .streamlit directory if it doesn't exist
if not exist ".streamlit" mkdir .streamlit

:: Create config.toml if it doesn't exist
if not exist ".streamlit\config.toml" (
    echo Creating Streamlit configuration...
    echo [server] > .streamlit\config.toml
    echo headless = true >> .streamlit\config.toml
    echo address = "0.0.0.0" >> .streamlit\config.toml
    echo port = 8501 >> .streamlit\config.toml
    echo. >> .streamlit\config.toml
    echo [theme] >> .streamlit\config.toml
    echo primaryColor = "#FF6B6B" >> .streamlit\config.toml
    echo backgroundColor = "#FFFFFF" >> .streamlit\config.toml
)

:: Check for OpenAI API key
if "%OPENAI_API_KEY%"=="" (
    echo.
    echo WARNING: OPENAI_API_KEY environment variable is not set
    echo AI features will not work without this key
    echo To set it, run: set OPENAI_API_KEY=your_api_key_here
    echo Or create a .env file with: OPENAI_API_KEY=your_api_key_here
    echo.
)

:: Start the application
echo.
echo Starting ExfilEye DLP System...
echo Application will be available at: http://localhost:8501
echo Press Ctrl+C to stop the application
echo.

streamlit run app_fixed.py --server.port 8501
pause