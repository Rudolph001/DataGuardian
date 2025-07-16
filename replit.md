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

### Backend Architecture
- **Main Application**: Single-file architecture in `app_fixed.py`
- **Modular Components**: Separate modules for domain classification, security configuration, and authentication
- **Data Processing**: Custom CSV parser without pandas dependency for handling large files (up to 2GB)
- **Session Management**: Streamlit's session state for maintaining user data across interactions

### Data Storage Solutions
- **Configuration Storage**: JSON files for persistent configuration
  - `domains.json` - Domain classification data
  - `security_config.json` - Security policies and thresholds
  - `users.json` - User authentication data (disabled by default)
- **Runtime Data**: In-memory storage using Streamlit session state
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
- **Categories**: Suspicious, Free Email, Business, Government, Financial, Cloud Providers, Social Media, News Media, Educational, Healthcare, Legal, Technology, Non-Profit, Personal, Unknown, Blocked
- **Features**: Auto-classification, manual overrides, bulk operations

### 6. Follow-up Center
- **Purpose**: Track escalated records and manage follow-up actions
- **Integration**: Outlook email template generation
- **Features**: Action tracking, automated email creation

## Data Flow

1. **Data Ingestion**: CSV files uploaded through Streamlit file uploader
2. **Preprocessing**: Custom parser validates and structures email metadata
3. **Risk Assessment**: Status field determines risk levels for each email
4. **Analysis**: AI and ML algorithms analyze patterns and detect anomalies
5. **Classification**: Domains are automatically categorized based on security policies
6. **Review Process**: Security operations dashboard facilitates manual review
7. **Decision Tracking**: Clear/Escalate decisions are recorded and managed
8. **Reporting**: Export capabilities for compliance and documentation

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