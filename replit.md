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

### 3. AI-Powered Event Insights
- **Purpose**: Generate intelligent analysis of email patterns and anomalies
- **Technology**: OpenAI GPT-4o integration for contextual analysis
- **ML Components**: Isolation Forest for anomaly detection, DBSCAN for clustering

### 4. Network Analysis
- **Purpose**: Visualize email communication patterns and relationships
- **Technology**: NetworkX for graph analysis, multiple layout algorithms
- **Features**: Community detection, centrality calculations, interactive visualization

### 5. Domain Classification System
- **Purpose**: Categorize recipient domains for security assessment
- **Categories**: Suspicious, Free Email, Business, Government, Financial, Cloud Providers
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

### AI/ML Services
- **OpenAI API**: GPT-4o model for intelligent analysis and insights
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

### Configuration Management
- **Environment Variables**: OPENAI_API_KEY for AI functionality
- **Default Settings**: Preconfigured domain classifications and security policies
- **Persistence**: JSON files for maintaining configuration across sessions

### Security Considerations
- **Authentication**: Optional system (disabled by default for ease of use)
- **File Handling**: Secure upload processing with size limits
- **API Security**: OpenAI API key management through environment variables

### Scalability
- **Single-user Design**: Optimized for individual analyst workflows
- **Memory Management**: Efficient processing of large datasets
- **Session Isolation**: Each user session maintains separate data state