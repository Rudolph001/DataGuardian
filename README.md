# ExfilEye - Data Loss Prevention Email Monitoring System

ExfilEye is a comprehensive Streamlit-based Data Loss Prevention (DLP) email monitoring system that provides AI-powered insights, network analysis, and security operations management for email communications.

## Features

### 📁 Data Upload & Preprocessing
- Upload CSV files up to 2GB with progress tracking
- Custom email metadata parser (no pandas dependency)
- Validate required fields and data quality metrics
- Risk distribution analysis and sample data preview

### 🛡️ Security Operations Dashboard
- Track review status with visual risk indicators (🔴🟠🟡🟢)
- Timeline views grouped by sender, domain, time, or subject
- Decision tracking: Clear → Email Check Completed, Escalate → Follow-up Center
- Interactive email details with modal pop-ups

### 🤖 AI-Powered Event Insights
- Select fields for ML analysis and AI-powered insights
- Generate contextual analysis using OpenAI GPT-4o
- Anomaly detection and pattern recognition
- Risk assessment and security recommendations

### 🔗 Network Analysis
- Interactive email communication graphs using NetworkX
- Multiple layout algorithms (spring, circular, hierarchical, Fruchterman-Reingold)
- Community detection and cluster analysis
- Node metrics and centrality calculations

### 🌐 Domain Classification
- Auto-classify recipient domains into categories:
  - Suspicious
  - Free Email (Gmail, Yahoo, etc.)
  - Business
  - Government
  - Financial
  - Cloud Providers
- Detailed domain lists with search and filtering
- Bulk domain operations and manual overrides

### ✅ Email Check Completed
- Overview of completed security reviews
- Summary statistics and review metrics
- PDF and CSV export capabilities
- Filterable review history

### 📨 Follow-up Center
- Track escalated records and follow-up actions
- Generate email templates for Outlook integration
- Status tracking: Pending → In Progress → Completed
- Follow-up notes and documentation

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd exfileye
