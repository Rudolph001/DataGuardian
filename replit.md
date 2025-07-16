# ExfilEye - Data Loss Prevention Email Monitoring System

## Overview

ExfilEye is a comprehensive Streamlit-based Data Loss Prevention (DLP) email monitoring system that provides AI-powered insights, network analysis, and security operations management for email communications. The application focuses on anomaly detection and domain classification to identify potential data exfiltration attempts through email.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: Streamlit (>=1.46.0) - Single-page application with sidebar navigation
- **Visualization**: Plotly (>=6.1.2) for interactive charts and graphs
- **Layout**: Wide layout with expandable sidebar for navigation
- **Navigation**: Multi-page structure using Streamlit's built-in page system
- **Deployment**: Configured for Replit environment with proper server settings

### Backend Architecture
- **Main Application**: Single-file architecture in `app_fixed.py`
- **Modular Components**: Separate modules for domain classification, security configuration, and authentication
- **Data Processing**: Custom CSV parser without pandas dependency for handling large files (up to 2GB)
- **Session Management**: Streamlit's session state for maintaining user data across interactions
- **Data Persistence**: JSON-based daily data storage with DataPersistence class

### Data Storage Solutions
- **Configuration Storage**: JSON files for persistent configuration
  - `domains.json` - Domain classification data
  - `security_config.json` - Security policies and thresholds
  - `users.json` - User authentication data (disabled by default)
- **Runtime Data**: In-memory storage using Streamlit session state
- **Daily Data Storage**: JSON files for filtered email data with date-based organization
- **Export Capabilities**: PDF and CSV export for reports and data

### Authentication and Authorization
- **Authentication**: Optional authentication system (disabled by default)
- **User Roles**: Admin and analyst roles with different permission levels
- **Security**: SHA-256 password hashing for credential storage

## Key Components

### 1. Data Upload & Preprocessing
- **Purpose**: Handle large CSV file uploads and validate email metadata
- **Features**: Progress tracking, custom parser, field validation, risk distribution analysis
- **Required Fields**: 20+ fields including _time, sender, subject, recipients, etc.
- **Data Flow**: Processes data for filtering - save functionality moved to Data Filtering & Review

### 2. Security Operations Dashboard
- **Purpose**: Main interface for reviewing and managing email security events
- **Features**: Risk indicators, timeline views, decision tracking (Clear/Escalate)
- **Visual Elements**: Color-coded risk levels (🔴🟠🟡🟢), modal pop-ups for details

### 3. Machine Learning Event Insights
- **Purpose**: Generate statistical analysis of email patterns and anomalies
- **Technology**: Scikit-learn machine learning algorithms for pattern detection
- **ML Components**: Isolation Forest for anomaly detection, DBSCAN for clustering

### 3a. Suspicious Email Analysis (New)
- **Purpose**: Specialized ML system for identifying suspicious patterns in Medium Low and unclassified emails
- **Technology**: Custom ML pipeline with multiple detection methods
- **Features**: Keyword analysis, pattern clustering, timing analysis, domain verification, suspicion scoring
- **Output**: Ranked list of suspicious emails with explanations and actionable recommendations

### 4. Network Analysis
- **Purpose**: Visualize email communication patterns and relationships
- **Technology**: NetworkX for graph analysis, multiple layout algorithms
- **Features**: Community detection, centrality calculations, interactive visualization

### 5. Domain Classification System
- **Purpose**: Categorize recipient domains for security assessment
- **Categories**: Suspicious, Free Email, Business, Government, Financial, Cloud Providers, Social Media, News Media, Educational, Healthcare, Legal, Technology, Non-Profit, Personal, Unknown, Blocked, Whitelisted
- **Features**: Auto-classification, manual overrides, bulk operations
- **Whitelist Feature**: Automatically filters out ALL emails to whitelisted domains during data upload, with persistent storage and management interface

### 6. Data Filtering & Review (Enhanced)
- **Purpose**: Filter and refine email data before security operations
- **Features**: Enhanced UI with professional styling, attachment filtering, wordlist filtering, policy filtering, time period selection
- **Save Functionality**: Moved from Data Upload - users can now save filtered data to JSON after applying filters
- **Workflow**: Filter → Review → Save → Send to Security Operations
- **Whitelist Filtering**: All emails to whitelisted domains are automatically filtered out during upload

### 7. Follow-up Center
- **Purpose**: Track escalated records and manage follow-up actions
- **Integration**: Outlook email template generation
- **Features**: Action tracking, automated email creation

## Data Flow

1. **Data Ingestion**: CSV files uploaded through Streamlit file uploader
2. **Preprocessing**: Custom parser validates and structures email metadata
3. **Data Filtering**: Enhanced filtering interface with improved UI for refining data
4. **Data Persistence**: Filtered data saved to JSON with date-based organization
5. **Risk Assessment**: Status field determines risk levels for each email
6. **Analysis**: AI and ML algorithms analyze patterns and detect anomalies
7. **Classification**: Domains are automatically categorized based on security policies
8. **Review Process**: Security operations dashboard facilitates manual review
9. **Decision Tracking**: Clear/Escalate decisions are recorded and managed
10. **Reporting**: Export capabilities for compliance and documentation

## Recent Changes (2025-07-16)

### Migration to Replit Environment
- **Server Configuration**: Added proper Streamlit configuration for Replit deployment
- **Package Installation**: Installed all required dependencies via Replit package manager
- **Workflow Setup**: Configured ExfilEye DLP Server workflow for automatic startup
- **Navigation Fix**: Improved sidebar navigation reliability with better state management and auto-rerun functionality

### Security Operations Dashboard Architecture Changes
- **Critical/High Only**: Security Operations Dashboard now exclusively handles Critical and High priority emails
- **Medium/Low/Unclassified Redirect**: Medium, Low, and Unclassified emails are now properly routed to Suspicious Email Analysis section
- **UI Cleanup**: Removed Medium/Low/Unclassified cards from Security Review Queue, replaced with navigation to Suspicious Email Analysis
- **Clear Separation**: Enforced proper separation of concerns between high-priority security operations and suspicious email analysis

### Data Filtering & Review Enhancements
- **Improved UI**: Enhanced Email Content Preferences section with better styling and organization
- **Visual Separators**: Added clear visual separators between filter sections
- **Policy Layout**: Improved policy checkbox layout with responsive columns
- **Professional Styling**: Added background styling and better section headers

### Data Save Workflow Changes
- **Moved Save Functionality**: Relocated data save from Data Upload to Data Filtering & Review
- **Filtered Data Focus**: Users now save filtered data instead of raw uploaded data
- **Improved Workflow**: Better user experience - filter first, then save processed data

### Whitelist Filtering Enhancement
- **Complete Whitelist Filtering**: Updated to filter out ALL emails to whitelisted domains during upload (not just Critical/High)
- **Simplified UI**: Removed redundant whitelist checkbox from filter dashboard
- **Improved Data Handling**: Enhanced filtering logic to properly handle empty/null values including "-", "null", "none", "false"

## External Dependencies

### ML Services
- **Scikit-learn**: Machine learning algorithms for anomaly detection
- **NetworkX**: Graph analysis and network visualization

### Visualization and Reporting
- **Plotly**: Interactive charts and network graphs
- **ReportLab**: PDF report generation
- **WeasyPrint**: Additional report formatting capabilities

### Core Libraries
- **Streamlit**: Web application framework
- **NumPy**: Numerical operations
- **SciPy**: Statistical analysis

## Deployment Strategy

### Environment Requirements
- **Python Version**: 3.11+
- **Memory**: Sufficient for processing 2GB CSV files
- **Storage**: File system access for JSON configuration files

### Local Development Setup
For running ExfilEye locally, use the appropriate requirements file for your system:

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

#### Cross-platform
```bash
pip install -r local_requirements.txt
```

#### Core Dependencies
- streamlit>=1.46.0 (Web framework)
- matplotlib>=3.7.0 (Chart generation)
- networkx>=3.1 (Network analysis)
- numpy>=1.24.0 (Numerical computing)
- pandas>=2.0.0 (Data processing)
- plotly>=5.15.0 (Interactive visualization)
- reportlab>=4.0.0 (PDF generation)
- scikit-learn>=1.3.0 (Machine learning)
- scipy>=1.11.0 (Scientific computing)
- seaborn>=0.12.0 (Statistical visualization)
- weasyprint>=60.0 (PDF rendering)
- openai>=1.0.0 (AI features - optional)

#### Installation Scripts
- `run_windows.py` / `run_windows.bat` - Windows launcher
- `run_mac.py` / `run_mac.sh` - macOS launcher
- `INSTALLATION_GUIDE.md` - Complete setup instructions

### Configuration Management
- **Default Settings**: Preconfigured domain classifications and security policies
- **Persistence**: JSON files for maintaining configuration across sessions

### Security Considerations
- **Authentication**: Optional system (disabled by default for ease of use)
- **File Handling**: Secure upload processing with size limits

### Scalability
- **Single-user Design**: Optimized for individual analyst workflows
- **Memory Management**: Efficient processing of large datasets
- **Session Isolation**: Each user session maintains separate data state