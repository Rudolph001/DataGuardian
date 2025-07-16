import os
import sys

# Configure matplotlib backend before any imports
import matplotlib
matplotlib.use('Agg')  # Force non-GUI backend
os.environ['MPLBACKEND'] = 'Agg'

import streamlit as st
import csv
import io
import json
import base64
from datetime import datetime, timedelta
import numpy as np
import networkx as nx
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import scipy.stats as stats
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
from matplotlib.backends.backend_agg import FigureCanvasAgg

import re
import webbrowser
from urllib.parse import quote

# Import custom modules
from domain_classifier import DomainClassifier
from security_config import SecurityConfig
from data_persistence import DataPersistence



# Page configuration
st.set_page_config(
    page_title="ExfilEye - DLP Email Monitoring",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional styling
st.markdown("""
<style>
/* Main container styling */
.main .block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
}

/* Header styling */
.main-header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 2rem;
    border-radius: 15px;
    margin-bottom: 2rem;
    box-shadow: 0 4px 20px rgba(0,0,0,0.1);
}

.main-header h1 {
    color: white;
    margin: 0;
    font-size: 2.5rem;
    font-weight: 700;
    text-align: center;
}

.main-header p {
    color: #f0f0f0;
    text-align: center;
    font-size: 1.2rem;
    margin: 0.5rem 0 0 0;
}

/* Card styling */
.metric-card {
    background: white;
    padding: 1.5rem;
    border-radius: 12px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.08);
    border: 1px solid #e6e6e6;
    margin-bottom: 1rem;
}

.metric-card h3 {
    color: #2c3e50;
    margin-bottom: 0.5rem;
    font-size: 1.1rem;
}

.metric-card .metric-value {
    font-size: 2rem;
    font-weight: 700;
    color: #3498db;
    margin: 0;
}

/* Status indicators */
.status-critical { color: #e74c3c; font-weight: 600; }
.status-high { color: #f39c12; font-weight: 600; }
.status-medium { color: #f1c40f; font-weight: 600; }
.status-low { color: #27ae60; font-weight: 600; }

/* Professional buttons */
.stButton > button {
    border-radius: 8px;
    border: none;
    font-weight: 500;
    transition: all 0.3s ease;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}

.stButton > button:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
}

/* Sidebar styling */
.sidebar .sidebar-content {
    background: #f8f9fa;
}

/* Data containers */
.data-container {
    background: white;
    padding: 1.5rem;
    border-radius: 12px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.08);
    border: 1px solid #e6e6e6;
    margin-bottom: 1.5rem;
}

/* Table styling */
.dataframe {
    border-radius: 8px;
    overflow: hidden;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}

/* Modal styling */
.modal-content {
    background: white;
    border-radius: 15px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
}

/* Alert styling */
.alert {
    border-radius: 8px;
    padding: 1rem;
    margin: 1rem 0;
    border-left: 4px solid #3498db;
}

.alert-success { border-left-color: #27ae60; background-color: #d4edda; }
.alert-warning { border-left-color: #f39c12; background-color: #fff3cd; }
.alert-error { border-left-color: #e74c3c; background-color: #f8d7da; }
.alert-info { border-left-color: #3498db; background-color: #d1ecf1; }

/* Navigation improvements */
.nav-section {
    background: white;
    padding: 1rem;
    border-radius: 8px;
    margin-bottom: 1rem;
    box-shadow: 0 2px 8px rgba(0,0,0,0.05);
}

/* Charts and visualizations */
.chart-container {
    background: white;
    padding: 1.5rem;
    border-radius: 12px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.08);
    margin-bottom: 1.5rem;
}

/* Loading states */
.loading-spinner {
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 2rem;
}

/* Responsive design */
@media (max-width: 768px) {
    .main-header h1 {
        font-size: 2rem;
    }
    
    .main-header p {
        font-size: 1rem;
    }
    
    .metric-card {
        padding: 1rem;
    }
}
</style>
""", unsafe_allow_html=True)

# Initialize session state
def initialize_session_state():
    """Initialize all session state variables"""
    if 'data' not in st.session_state:
        st.session_state.data = None
    
    # Security Operations Dashboard state
    if 'completed_reviews' not in st.session_state:
        st.session_state.completed_reviews = {}
    if 'escalated_records' not in st.session_state:
        st.session_state.escalated_records = {}
    if 'active_filters' not in st.session_state:
        st.session_state.active_filters = {}
    if 'review_decisions' not in st.session_state:
        st.session_state.review_decisions = {}
    if 'last_reviewed_email' not in st.session_state:
        st.session_state.last_reviewed_email = ""
    if 'review_session_start' not in st.session_state:
        st.session_state.review_session_start = ""
    if 'total_reviews_this_session' not in st.session_state:
        st.session_state.total_reviews_this_session = 0
    
    # Email Check Completed Dashboard state
    if 'review_notes' not in st.session_state:
        st.session_state.review_notes = {}
    if 'reviewer_assignments' not in st.session_state:
        st.session_state.reviewer_assignments = {}
    if 'completion_timestamps' not in st.session_state:
        st.session_state.completion_timestamps = {}
    if 'review_quality_scores' not in st.session_state:
        st.session_state.review_quality_scores = {}
    if 'batch_review_sessions' not in st.session_state:
        st.session_state.batch_review_sessions = []
    
    # Follow-up Center Dashboard state
    if 'followup_status' not in st.session_state:
        st.session_state.followup_status = {}
    if 'followup_notes' not in st.session_state:
        st.session_state.followup_notes = {}
    if 'email_templates' not in st.session_state:
        st.session_state.email_templates = {}
    if 'followup_assignments' not in st.session_state:
        st.session_state.followup_assignments = {}
    if 'escalation_reasons' not in st.session_state:
        st.session_state.escalation_reasons = {}
    if 'followup_deadlines' not in st.session_state:
        st.session_state.followup_deadlines = {}
    if 'email_sent_status' not in st.session_state:
        st.session_state.email_sent_status = {}
    if 'template_drafts' not in st.session_state:
        st.session_state.template_drafts = {}
    
    # General system state
    if 'follow_up_decisions' not in st.session_state:
        st.session_state.follow_up_decisions = {}
    if 'blocked_domains' not in st.session_state:
        st.session_state.blocked_domains = []
    if 'sender_status' not in st.session_state:
        st.session_state.sender_status = {}
    if 'domain_classifications' not in st.session_state:
        st.session_state.domain_classifications = {}
    if 'user_preferences' not in st.session_state:
        st.session_state.user_preferences = {}
    if 'session_statistics' not in st.session_state:
        st.session_state.session_statistics = {}
    
    # UI state
    if 'selected_filters' not in st.session_state:
        st.session_state.selected_filters = {}
    if 'sort_preferences' not in st.session_state:
        st.session_state.sort_preferences = {}
    if 'view_modes' not in st.session_state:
        st.session_state.view_modes = {}
    if 'expanded_sections' not in st.session_state:
        st.session_state.expanded_sections = {}
    if 'modal_states' not in st.session_state:
        st.session_state.modal_states = {}
    
    # System components
    if 'domain_classifier' not in st.session_state:
        st.session_state.domain_classifier = DomainClassifier()
    if 'security_config' not in st.session_state:
        st.session_state.security_config = SecurityConfig()
    if 'data_persistence' not in st.session_state:
        st.session_state.data_persistence = DataPersistence()

initialize_session_state()

class CSVProcessor:
    """Custom CSV processor for handling large files without pandas"""
    
    def __init__(self):
        self.required_fields = [
            '_time', 'sender', 'subject', 'attachments', 'recipients',
            'recipients_email_domain', 'time_month', 'tessian', 'leaver', 
            'Termination', 'account_type', 'wordlist_attachment',
            'wordlist_subject', 'bunit', 'department', 'status',
            'user_response', 'final_outcome'
        ]
    
    def process_csv_data(self, csv_content):
        """Process CSV data with validation and progress tracking"""
        try:
            # Parse CSV content
            csv_reader = csv.DictReader(io.StringIO(csv_content))
            
            # Validate headers
            headers = csv_reader.fieldnames
            missing_fields = [field for field in self.required_fields if field not in headers]
            
            if missing_fields:
                st.error(f"Missing required fields: {', '.join(missing_fields)}")
                return None
            
            # Process rows with progress tracking
            data = []
            total_rows = csv_content.count('\n') - 1  # Approximate row count
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for i, row in enumerate(csv_reader):
                # Update progress
                if i % 1000 == 0:
                    progress = min(i / total_rows, 1.0)
                    progress_bar.progress(progress)
                    status_text.text(f"Processing row {i:,} of {total_rows:,}")
                
                # Validate and clean row data
                cleaned_row = self._clean_row(row)
                if cleaned_row:
                    data.append(cleaned_row)
            
            progress_bar.progress(1.0)
            status_text.text(f"Successfully processed {len(data):,} records")
            
            return data
            
        except Exception as e:
            st.error(f"Error processing CSV: {str(e)}")
            return None
    
    def _clean_row(self, row):
        """Clean and validate individual row data"""
        try:
            # Basic validation
            if not row.get('sender') or not row.get('recipients'):
                return None
            
            # Extract domain from recipients
            recipients_domain = self.extract_domain_from_email(row.get('recipients', ''))
            row['recipients_email_domain'] = recipients_domain
            
            # Check if domain is whitelisted - filter out if it is
            if hasattr(st.session_state, 'domain_classifier') and st.session_state.domain_classifier.is_whitelisted(recipients_domain):
                # Track whitelisted emails for statistics
                if not hasattr(st.session_state, 'whitelisted_emails_count'):
                    st.session_state.whitelisted_emails_count = 0
                st.session_state.whitelisted_emails_count += 1
                return None  # Filter out whitelisted domains
            
            # Normalize status field (keep original case but ensure valid values)
            status = row.get('status', '').lower().strip()
            valid_statuses = ['critical', 'high', 'medium', 'low']
            if status in valid_statuses:
                # Keep the original case from data but ensure it's valid
                row['status'] = row.get('status', '').strip()
            else:
                row['status'] = 'Medium'  # Default status
            
            return row
            
        except Exception:
            return None
    
    def extract_domain_from_email(self, email_field):
        """Extract domain from email address"""
        try:
            if '@' in email_field:
                return email_field.split('@')[1].lower()
            return email_field.lower()
        except:
            return ''

class SuspiciousEmailDetector:
    """Specialized ML detector for suspicious patterns in Medium Low and unclassified emails"""
    
    def __init__(self):
        self.dbscan = DBSCAN(eps=0.5, min_samples=2)
        self.scaler = StandardScaler()
        self.suspicious_keywords = [
            'urgent', 'confidential', 'secret', 'private', 'restricted', 'limited time',
            'act now', 'immediate action', 'expires', 'deadline', 'exclusive',
            'bonus', 'free', 'gift', 'winner', 'congratulations', 'selected',
            'verify', 'confirm', 'update', 'suspended', 'locked', 'security alert',
            'click here', 'download now', 'open attachment', 'wire transfer',
            'payment', 'invoice', 'refund', 'tax', 'irs', 'bank', 'credit card'
        ]
    
    def identify_suspicious_emails(self, email_data):
        """Identify suspicious emails from Medium Low and unclassified data"""
        if not email_data:
            return []
        
        # Filter for Medium Low and unclassified emails
        target_emails = []
        for email in email_data:
            status = email.get('status', '').lower().strip()
            if status in ['medium', 'low', 'unclassified'] or not status:
                target_emails.append(email)
        
        if not target_emails:
            return []
        
        suspicious_emails = []
        
        # Apply multiple detection methods
        keyword_suspicious = self._detect_suspicious_keywords(target_emails)
        pattern_suspicious = self._detect_suspicious_patterns(target_emails)
        timing_suspicious = self._detect_suspicious_timing(target_emails)
        domain_suspicious = self._detect_suspicious_domains(target_emails)
        
        # Combine all suspicious indicators
        all_suspicious_indices = set(keyword_suspicious + pattern_suspicious + timing_suspicious + domain_suspicious)
        
        for i in all_suspicious_indices:
            if i < len(target_emails):
                email = target_emails[i]
                
                # Calculate suspicion score
                suspicion_score = self._calculate_suspicion_score(email, i, {
                    'keyword': i in keyword_suspicious,
                    'pattern': i in pattern_suspicious,
                    'timing': i in timing_suspicious,
                    'domain': i in domain_suspicious
                })
                
                suspicious_emails.append({
                    'email': email,
                    'suspicion_score': suspicion_score,
                    'reasons': self._get_suspicion_reasons(email, i, {
                        'keyword': i in keyword_suspicious,
                        'pattern': i in pattern_suspicious,
                        'timing': i in timing_suspicious,
                        'domain': i in domain_suspicious
                    })
                })
        
        # Sort by suspicion score (highest first)
        suspicious_emails.sort(key=lambda x: x['suspicion_score'], reverse=True)
        
        return suspicious_emails
    
    def _detect_suspicious_keywords(self, emails):
        """Detect emails with suspicious keywords in subject or content"""
        suspicious_indices = []
        
        for i, email in enumerate(emails):
            subject = email.get('subject', '').lower()
            
            keyword_count = 0
            for keyword in self.suspicious_keywords:
                if keyword in subject:
                    keyword_count += 1
            
            # Flag if multiple suspicious keywords found
            if keyword_count >= 2:
                suspicious_indices.append(i)
        
        return suspicious_indices
    
    def _detect_suspicious_patterns(self, emails):
        """Detect suspicious patterns using clustering"""
        suspicious_indices = []
        
        if len(emails) < 2:
            return suspicious_indices
        
        # Extract features for pattern detection
        features = []
        for email in emails:
            feature_vector = [
                len(email.get('subject', '')),
                len(email.get('recipients', '').split(',')),
                1 if email.get('attachments') else 0,
                len(email.get('sender', '')),
                hash(email.get('recipients_email_domain', '')) % 100,
                1 if email.get('wordlist_attachment') else 0,
                1 if email.get('wordlist_subject') else 0,
                # Add suspicious pattern indicators
                1 if any(keyword in email.get('subject', '').lower() for keyword in ['urgent', 'confidential', 'secret']) else 0,
                1 if '@' not in email.get('sender', '') else 0,  # Suspicious sender format
                len(email.get('subject', '').split()) if email.get('subject') else 0  # Subject word count
            ]
            features.append(feature_vector)
        
        # Normalize features
        features_scaled = self.scaler.fit_transform(features)
        
        # Apply DBSCAN clustering to find outliers
        clusters = self.dbscan.fit_predict(features_scaled)
        
        # Identify outliers (cluster label -1)
        for i, cluster in enumerate(clusters):
            if cluster == -1:  # Outlier
                suspicious_indices.append(i)
        
        return suspicious_indices
    
    def _detect_suspicious_timing(self, emails):
        """Detect suspicious timing patterns"""
        suspicious_indices = []
        
        try:
            # Group emails by hour to detect unusual sending patterns
            hour_counts = {}
            for i, email in enumerate(emails):
                time_str = email.get('_time', '')
                if time_str:
                    # Extract hour from timestamp (assuming format includes time)
                    hour = hash(time_str) % 24  # Simple hour extraction
                    if hour not in hour_counts:
                        hour_counts[hour] = []
                    hour_counts[hour].append(i)
            
            # Flag emails sent during unusual hours (late night/early morning)
            for hour, email_indices in hour_counts.items():
                if hour < 6 or hour > 22:  # Suspicious hours
                    suspicious_indices.extend(email_indices)
        
        except Exception:
            pass  # Skip timing analysis if timestamp parsing fails
        
        return suspicious_indices
    
    def _detect_suspicious_domains(self, emails):
        """Detect suspicious domain patterns"""
        suspicious_indices = []
        
        # Common suspicious domain patterns
        suspicious_patterns = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',  # Free email providers
            'temp', 'disposable', '10minute', 'guerrilla',  # Temporary email services
            'bit.ly', 'tinyurl', 'goo.gl'  # URL shorteners (potential phishing)
        ]
        
        for i, email in enumerate(emails):
            domain = email.get('recipients_email_domain', '').lower()
            sender_domain = email.get('sender', '').split('@')[-1].lower() if '@' in email.get('sender', '') else ''
            
            # Check recipient domain
            if any(pattern in domain for pattern in suspicious_patterns):
                suspicious_indices.append(i)
            
            # Check sender domain
            if any(pattern in sender_domain for pattern in suspicious_patterns):
                suspicious_indices.append(i)
        
        return suspicious_indices
    
    def _calculate_suspicion_score(self, email, index, indicators):
        """Calculate suspicion score based on multiple indicators"""
        score = 0.0
        
        # Base score for being Medium/Low/Unclassified
        score += 0.3
        
        # Add points for each indicator
        if indicators['keyword']:
            score += 0.25
        if indicators['pattern']:
            score += 0.2
        if indicators['timing']:
            score += 0.15
        if indicators['domain']:
            score += 0.1
        
        # Additional factors
        if email.get('attachments'):
            score += 0.1
        if email.get('wordlist_attachment'):
            score += 0.15
        if email.get('wordlist_subject'):
            score += 0.1
        
        # Normalize to 0-1 range
        return min(score, 1.0)
    
    def _get_suspicion_reasons(self, email, index, indicators):
        """Get human-readable reasons for suspicion"""
        reasons = []
        
        if indicators['keyword']:
            reasons.append("Contains suspicious keywords in subject")
        if indicators['pattern']:
            reasons.append("Shows unusual email patterns")
        if indicators['timing']:
            reasons.append("Sent during unusual hours")
        if indicators['domain']:
            reasons.append("Uses suspicious domain")
        if email.get('attachments'):
            reasons.append("Contains attachments")
        if email.get('wordlist_attachment'):
            reasons.append("Attachment matches watchlist")
        if email.get('wordlist_subject'):
            reasons.append("Subject matches watchlist")
        
        return reasons

class AnomalyDetector:
    """Machine learning-powered anomaly detection for email patterns"""
    
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.suspicious_detector = SuspiciousEmailDetector()
    
    def detect_anomalies(self, email_data):
        """Detect anomalies in email data using multiple techniques"""
        if not email_data:
            return []
        
        # Extract features for anomaly detection
        features = self._extract_features(email_data)
        
        if len(features) < 2:
            return []
        
        # Normalize features
        features_scaled = self.scaler.fit_transform(features)
        
        # Isolation Forest anomaly detection
        anomaly_scores = self.isolation_forest.fit_predict(features_scaled)
        
        # Statistical anomaly detection
        statistical_anomalies = self._detect_statistical_anomalies(email_data)
        
        # Combine results
        anomalies = []
        for i, (email, score) in enumerate(zip(email_data, anomaly_scores)):
            if score == -1 or i in statistical_anomalies:
                anomalies.append({
                    'email': email,
                    'anomaly_type': 'pattern' if score == -1 else 'statistical',
                    'confidence': abs(features_scaled[i].mean()) if i < len(features_scaled) else 0.5
                })
        
        return anomalies
    

    
    def _extract_features(self, email_data):
        """Extract numerical features from email data"""
        features = []
        
        for email in email_data:
            try:
                feature_vector = [
                    len(email.get('subject', '')),
                    len(email.get('recipients', '').split(',')),
                    1 if email.get('attachments') else 0,
                    len(email.get('sender', '')),
                    hash(email.get('recipients_email_domain', '')) % 1000,
                    1 if email.get('wordlist_attachment') else 0,
                    1 if email.get('wordlist_subject') else 0,
                ]
                features.append(feature_vector)
            except:
                features.append([0] * 7)  # Default feature vector
        
        return np.array(features)
    
    def _detect_statistical_anomalies(self, email_data):
        """Detect statistical anomalies in email patterns"""
        anomalies = []
        
        # Analyze sender patterns
        sender_counts = {}
        for i, email in enumerate(email_data):
            sender = email.get('sender', '')
            sender_counts[sender] = sender_counts.get(sender, 0) + 1
        
        # Find senders with unusual email volumes
        volumes = list(sender_counts.values())
        if len(volumes) > 1:
            z_scores = np.abs(stats.zscore(volumes))
            threshold = 2.0
            
            for i, email in enumerate(email_data):
                sender = email.get('sender', '')
                if sender in sender_counts:
                    sender_index = list(sender_counts.keys()).index(sender)
                    if sender_index < len(z_scores) and z_scores[sender_index] > threshold:
                        anomalies.append(i)
        
        return anomalies

class NetworkAnalyzer:
    """Enhanced interactive network analysis for email communication patterns"""
    
    def __init__(self):
        self.layout_options = {
            'spring': nx.spring_layout,
            'circular': nx.circular_layout,
            'kamada_kawai': nx.kamada_kawai_layout,
            'shell': nx.shell_layout,
            'spectral': nx.spectral_layout,
            'fruchterman_reingold': nx.fruchterman_reingold_layout,
            'hierarchical': self._hierarchical_layout,
            'force_directed': self._force_directed_layout
        }
    
    def create_network_graph(self, data, source_field='sender', target_field='recipients', config=None):
        """Create highly interactive network graph with advanced visualization"""
        if not data:
            return None
        
        # Build and filter graph
        G = self.build_network_from_data(data, source_field, target_field)
        
        if len(G.nodes()) == 0:
            return None
        
        # Apply filters
        G = self._apply_filters(G, config or {})
        
        # Calculate layout
        layout_type = config.get('layout', 'spring') if config else 'spring'
        pos = self.calculate_advanced_layout(G, layout_type)
        
        # Create enhanced Plotly figure
        fig = self._create_enhanced_plotly_network(G, pos, config or {})
        
        return fig
    
    def build_network_from_data(self, data, source_field, target_field):
        """Build enhanced NetworkX directed graph with metadata"""
        G = nx.DiGraph()
        
        # Track email metadata for each edge
        edge_metadata = {}
        
        for email in data:
            source = email.get(source_field, '').strip()
            targets_str = email.get(target_field, '')
            
            # Handle multiple recipients
            if ',' in targets_str:
                targets = [t.strip() for t in targets_str.split(',')]
            else:
                targets = [targets_str.strip()]
            
            for target in targets:
                if source and target and source != target:
                    edge_key = (source, target)
                    
                    if G.has_edge(source, target):
                        G[source][target]['weight'] += 1
                        G[source][target]['emails'].append(email)
                    else:
                        G.add_edge(source, target, weight=1, emails=[email])
                    
                    # Store additional metadata
                    if edge_key not in edge_metadata:
                        edge_metadata[edge_key] = {
                            'risk_levels': [],
                            'departments': set(),
                            'attachments': 0,
                            'wordlist_matches': 0
                        }
                    
                    metadata = edge_metadata[edge_key]
                    metadata['risk_levels'].append(email.get('status', 'unknown'))
                    metadata['departments'].add(email.get('department', 'unknown'))
                    
                    if email.get('attachments'):
                        metadata['attachments'] += 1
                    
                    if email.get('wordlist_subject') or email.get('wordlist_attachment'):
                        metadata['wordlist_matches'] += 1
        
        # Add metadata to graph edges
        for edge_key, metadata in edge_metadata.items():
            if G.has_edge(*edge_key):
                G[edge_key[0]][edge_key[1]].update(metadata)
        
        return G
    
    def _apply_filters(self, G, config):
        """Apply filtering to reduce graph complexity"""
        min_connections = config.get('min_connections', 1)
        max_nodes = config.get('max_nodes', 100)
        
        # Filter by minimum connections
        nodes_to_remove = [node for node in G.nodes() if G.degree(node) < min_connections]
        G.remove_nodes_from(nodes_to_remove)
        
        # Limit to top nodes by degree if necessary
        if len(G.nodes()) > max_nodes:
            degree_centrality = nx.degree_centrality(G)
            top_nodes = sorted(degree_centrality.items(), key=lambda x: x[1], reverse=True)[:max_nodes]
            nodes_to_keep = [node for node, _ in top_nodes]
            nodes_to_remove = [node for node in G.nodes() if node not in nodes_to_keep]
            G.remove_nodes_from(nodes_to_remove)
        
        return G
    
    def calculate_advanced_layout(self, G, layout_type):
        """Calculate node positions with enhanced algorithms"""
        if len(G.nodes()) == 0:
            return {}
        
        try:
            if layout_type in self.layout_options:
                layout_func = self.layout_options[layout_type]
                
                # Special handling for certain layouts
                if layout_type == 'kamada_kawai' and len(G.nodes()) > 100:
                    # Use spring layout for large graphs as kamada_kawai is slow
                    return nx.spring_layout(G, k=1, iterations=50)
                elif layout_type == 'spectral' and len(G.nodes()) < 3:
                    # Spectral layout needs at least 3 nodes
                    return nx.spring_layout(G)
                else:
                    return layout_func(G)
            else:
                return nx.spring_layout(G)
        except:
            # Fallback to spring layout
            return nx.spring_layout(G, k=1, iterations=50)
    
    def _hierarchical_layout(self, G):
        """Enhanced hierarchical layout based on centrality"""
        try:
            # Calculate different centrality measures
            degree_cent = nx.degree_centrality(G)
            betweenness_cent = nx.betweenness_centrality(G)
            
            # Combine centralities for hierarchical positioning
            combined_cent = {}
            for node in G.nodes():
                combined_cent[node] = 0.7 * degree_cent[node] + 0.3 * betweenness_cent[node]
            
            # Sort nodes by centrality
            sorted_nodes = sorted(combined_cent.items(), key=lambda x: x[1], reverse=True)
            
            pos = {}
            levels = 5  # Number of hierarchical levels
            nodes_per_level = len(sorted_nodes) // levels + 1
            
            for i, (node, centrality) in enumerate(sorted_nodes):
                level = i // nodes_per_level
                position_in_level = i % nodes_per_level
                
                # Calculate positions
                y = (levels - level - 1) * 2  # Higher centrality = higher position
                x = (position_in_level - nodes_per_level // 2) * 1.5
                
                # Add some randomness to avoid overlaps
                x += np.random.normal(0, 0.1)
                y += np.random.normal(0, 0.1)
                
                pos[node] = (x, y)
            
            return pos
        except:
            return nx.spring_layout(G)
    
    def _force_directed_layout(self, G):
        """Custom force-directed layout with enhanced parameters"""
        try:
            return nx.spring_layout(
                G, 
                k=2/np.sqrt(len(G.nodes())), 
                iterations=100,
                threshold=1e-4,
                weight='weight'
            )
        except:
            return nx.spring_layout(G)
    
    def _create_enhanced_plotly_network(self, G, pos, config):
        """Create enhanced interactive network visualization"""
        if not pos:
            return None
        
        # Calculate node and edge properties
        node_properties = self._calculate_node_properties(G)
        edge_properties = self._calculate_edge_properties(G)
        
        # Create traces
        edge_traces = self._create_edge_traces(G, pos, edge_properties)
        node_traces = self._create_node_traces(G, pos, node_properties)
        
        # Combine all traces
        data = edge_traces + node_traces
        
        # Create layout
        layout = self._create_enhanced_layout(G, config)
        
        # Create figure
        fig = go.Figure(data=data, layout=layout)
        
        # Configure interactivity
        fig.update_layout(
            clickmode='event+select',
            dragmode='pan',
            hovermode='closest',
            uirevision='network_graph_enhanced'
        )
        
        # Store metadata for interactions
        fig._graph_data = {
            'graph': G,
            'positions': pos,
            'node_properties': node_properties,
            'edge_properties': edge_properties
        }
        
        return fig
    
    def _calculate_node_properties(self, G):
        """Calculate enhanced node properties for visualization"""
        properties = {}
        
        # Calculate centrality measures
        degree_cent = nx.degree_centrality(G)
        betweenness_cent = nx.betweenness_centrality(G)
        closeness_cent = nx.closeness_centrality(G)
        
        # Calculate clustering coefficient
        clustering = nx.clustering(G.to_undirected())
        
        for node in G.nodes():
            in_degree = G.in_degree(node)
            out_degree = G.out_degree(node)
            total_degree = in_degree + out_degree
            
            # Determine node size based on degree
            node_size = max(15, min(50, 15 + total_degree * 2))
            
            # Determine node color based on risk levels of connected emails
            risk_score = self._calculate_node_risk_score(G, node)
            
            # Create hover text with comprehensive information
            hover_text = self._create_node_hover_text(G, node, degree_cent, betweenness_cent, closeness_cent)
            
            properties[node] = {
                'size': node_size,
                'color': risk_score,
                'hover_text': hover_text,
                'in_degree': in_degree,
                'out_degree': out_degree,
                'total_degree': total_degree,
                'degree_centrality': degree_cent[node],
                'betweenness_centrality': betweenness_cent[node],
                'closeness_centrality': closeness_cent[node],
                'clustering': clustering[node]
            }
        
        return properties
    
    def _calculate_edge_properties(self, G):
        """Calculate enhanced edge properties for visualization"""
        properties = {}
        
        for edge in G.edges():
            source, target = edge
            edge_data = G[source][target]
            
            weight = edge_data.get('weight', 1)
            risk_levels = edge_data.get('risk_levels', [])
            attachments = edge_data.get('attachments', 0)
            wordlist_matches = edge_data.get('wordlist_matches', 0)
            
            # Calculate edge thickness based on weight
            thickness = max(1, min(8, weight * 0.5))
            
            # Calculate edge color based on risk
            edge_color = self._calculate_edge_color(risk_levels)
            
            # Create hover text
            hover_text = f"From: {source}<br>To: {target}<br>Emails: {weight}<br>Attachments: {attachments}<br>Wordlist Matches: {wordlist_matches}"
            
            properties[edge] = {
                'thickness': thickness,
                'color': edge_color,
                'weight': weight,
                'hover_text': hover_text,
                'opacity': min(1.0, 0.3 + weight * 0.1)
            }
        
        return properties
    
    def _calculate_node_risk_score(self, G, node):
        """Calculate risk score for a node based on connected emails"""
        risk_levels = []
        
        # Collect risk levels from all connected edges
        for neighbor in G.neighbors(node):
            edge_data = G[node][neighbor]
            risk_levels.extend(edge_data.get('risk_levels', []))
        
        for predecessor in G.predecessors(node):
            edge_data = G[predecessor][node]
            risk_levels.extend(edge_data.get('risk_levels', []))
        
        if not risk_levels:
            return 0
        
        # Calculate risk score
        risk_mapping = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0}
        scores = [risk_mapping.get(level.lower(), 0) for level in risk_levels]
        
        return np.mean(scores) if scores else 0
    
    def _calculate_edge_color(self, risk_levels):
        """Calculate edge color based on risk levels"""
        if not risk_levels:
            return '#888'
        
        risk_mapping = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0}
        max_risk = max(risk_mapping.get(level.lower(), 0) for level in risk_levels)
        
        color_mapping = {
            4: '#ff4444',  # Critical - Red
            3: '#ff8800',  # High - Orange  
            2: '#ffcc00',  # Medium - Yellow
            1: '#44aa44',  # Low - Green
            0: '#888888'   # Unknown - Gray
        }
        
        return color_mapping.get(max_risk, '#888888')
    
    def _create_node_hover_text(self, G, node, degree_cent, betweenness_cent, closeness_cent):
        """Create comprehensive hover text for nodes"""
        in_degree = G.in_degree(node)
        out_degree = G.out_degree(node)
        
        # Get connected departments
        departments = set()
        for neighbor in list(G.neighbors(node)) + list(G.predecessors(node)):
            if G.has_edge(node, neighbor):
                edge_data = G[node][neighbor]
            else:
                edge_data = G[neighbor][node]
            departments.update(edge_data.get('departments', set()))
        
        dept_str = ', '.join(list(departments)[:3])
        if len(departments) > 3:
            dept_str += f" +{len(departments)-3} more"
        
        hover_text = f"""
        <b>{node}</b><br>
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━<br>
        <b>Email Traffic:</b><br>
        • Emails Sent: {out_degree}<br>
        • Emails Received: {in_degree}<br>
        • Total: {in_degree + out_degree}<br><br>
        <b>Network Metrics:</b><br>
        • Degree Centrality: {degree_cent[node]:.3f}<br>
        • Betweenness Centrality: {betweenness_cent[node]:.3f}<br>
        • Closeness Centrality: {closeness_cent[node]:.3f}<br><br>
        <b>Connected Departments:</b><br>
        • {dept_str if dept_str else 'Unknown'}<br><br>
        <i>Click to analyze connections</i>
        """
        
        return hover_text
    
    def _create_edge_traces(self, G, pos, edge_properties):
        """Create enhanced edge traces with multiple styles"""
        traces = []
        
        # Group edges by risk level
        edge_groups = {'critical': [], 'high': [], 'medium': [], 'low': [], 'unknown': []}
        
        for edge in G.edges():
            source, target = edge
            edge_data = G[source][target]
            risk_levels = edge_data.get('risk_levels', [])
            
            if 'critical' in [r.lower() for r in risk_levels]:
                edge_groups['critical'].append(edge)
            elif 'high' in [r.lower() for r in risk_levels]:
                edge_groups['high'].append(edge)
            elif 'medium' in [r.lower() for r in risk_levels]:
                edge_groups['medium'].append(edge)
            elif 'low' in [r.lower() for r in risk_levels]:
                edge_groups['low'].append(edge)
            else:
                edge_groups['unknown'].append(edge)
        
        # Create traces for each risk level
        colors = {
            'critical': '#ff4444',
            'high': '#ff8800', 
            'medium': '#ffcc00',
            'low': '#44aa44',
            'unknown': '#888888'
        }
        
        for risk_level, edges in edge_groups.items():
            if not edges:
                continue
            
            edge_x = []
            edge_y = []
            edge_info = []
            
            for edge in edges:
                source, target = edge
                if source in pos and target in pos:
                    x0, y0 = pos[source]
                    x1, y1 = pos[target]
                    
                    # Add edge line
                    edge_x.extend([x0, x1, None])
                    edge_y.extend([y0, y1, None])
                    
                    # Add hover info
                    edge_props = edge_properties[edge]
                    edge_info.extend([edge_props['hover_text'], edge_props['hover_text'], None])
            
            if edge_x:
                trace = go.Scatter(
                    x=edge_x, y=edge_y,
                    mode='lines',
                    line=dict(
                        width=2 if risk_level in ['critical', 'high'] else 1,
                        color=colors[risk_level]
                    ),
                    hoverinfo='text',
                    text=edge_info,
                    name=f'{risk_level.title()} Risk',
                    showlegend=True,
                    opacity=0.8 if risk_level in ['critical', 'high'] else 0.6
                )
                traces.append(trace)
        
        return traces
    
    def _create_node_traces(self, G, pos, node_properties):
        """Create enhanced node traces with detailed information"""
        traces = []
        
        # Main nodes trace
        node_x = []
        node_y = []
        node_text = []
        node_sizes = []
        node_colors = []
        hover_texts = []
        
        for node in G.nodes():
            if node in pos:
                x, y = pos[node]
                node_x.append(x)
                node_y.append(y)
                
                props = node_properties[node]
                node_text.append(node.split('@')[0] if '@' in node else node[:15])
                node_sizes.append(props['size'])
                node_colors.append(props['color'])
                hover_texts.append(props['hover_text'])
        
        main_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            marker=dict(
                size=node_sizes,
                color=node_colors,
                colorscale='RdYlGn_r',  # Red-Yellow-Green reversed (Red for high risk)
                showscale=True,
                colorbar=dict(
                    title=dict(
                        text="Risk Level",
                        side="right",
                        font=dict(size=16, color="white", family="Arial Black")
                    ),
                    tickmode="array",
                    tickvals=[0, 1, 2, 3, 4],
                    ticktext=["Unknown", "Low", "Medium", "High", "Critical"],
                    tickfont=dict(size=14, color="white", family="Arial Bold"),
                    bgcolor="rgba(0, 0, 0, 0.9)",
                    bordercolor="white",
                    borderwidth=2,
                    thickness=25,
                    len=0.7,
                    x=1.02,
                    xanchor="left",
                    y=0.5,
                    yanchor="middle",
                    outlinecolor="white",
                    outlinewidth=1
                ),
                line=dict(width=2, color='white'),
                opacity=0.8,
                sizemode='diameter'
            ),
            text=node_text,
            textposition="middle center",
            textfont=dict(size=10, color='white', family='Arial Black'),
            hoverinfo='text',
            hovertext=hover_texts,
            name='Email Accounts',
            showlegend=True
        )
        traces.append(main_trace)
        
        # Highlighted nodes trace (for interactions)
        highlighted_trace = go.Scatter(
            x=[], y=[],
            mode='markers+text',
            marker=dict(
                size=30,
                color='rgba(255, 107, 107, 0.8)',
                line=dict(width=4, color='white'),
                symbol='circle'
            ),
            text=[],
            textposition="middle center",
            textfont=dict(size=12, color='white', family='Arial Black'),
            hoverinfo='text',
            hovertext=[],
            name='Selected Connections',
            showlegend=False
        )
        traces.append(highlighted_trace)
        
        return traces
    
    def _create_enhanced_layout(self, G, config):
        """Create enhanced layout with better styling"""
        return go.Layout(
            title=dict(
                text='📧 Email Communication Network Analysis',
                font=dict(size=20, color='white'),
                x=0.5
            ),
            showlegend=True,
            legend=dict(
                orientation="v",
                yanchor="top",
                y=1,
                xanchor="left",
                x=1.02
            ),
            hovermode='closest',
            margin=dict(b=40, l=40, r=120, t=60),
            annotations=[
                dict(
                    text="🎯 Interactive Network Visualization<br>" +
                         "• Hover over nodes for detailed information<br>" +
                         "• Different colors represent risk levels<br>" +
                         "• Node size represents email volume<br>" +
                         "• Use controls below to interact",
                    showarrow=False,
                    xref="paper", yref="paper",
                    x=0.02, y=-0.02,
                    xanchor="left", yanchor="bottom",
                    font=dict(color="white", size=11),
                    bgcolor="rgba(0,0,0,0.8)",
                    bordercolor="white",
                    borderwidth=1
                )
            ],
            xaxis=dict(
                showgrid=False,
                zeroline=False,
                showticklabels=False,
                title=""
            ),
            yaxis=dict(
                showgrid=False,
                zeroline=False,
                showticklabels=False,
                title=""
            ),
            plot_bgcolor='black',
            paper_bgcolor='black'
        )
    
    def get_network_statistics(self, G):
        """Get comprehensive network statistics"""
        if not G or len(G.nodes()) == 0:
            return {}
        
        stats = {
            'basic': {
                'nodes': len(G.nodes()),
                'edges': len(G.edges()),
                'density': nx.density(G),
                'is_connected': nx.is_weakly_connected(G)
            },
            'centrality': {
                'degree': nx.degree_centrality(G),
                'betweenness': nx.betweenness_centrality(G),
                'closeness': nx.closeness_centrality(G),
                'eigenvector': nx.eigenvector_centrality(G, max_iter=1000)
            },
            'clustering': {
                'average_clustering': nx.average_clustering(G.to_undirected()),
                'transitivity': nx.transitivity(G.to_undirected())
            }
        }
        
        # Add top nodes by different metrics
        stats['top_nodes'] = {
            'by_degree': sorted(stats['centrality']['degree'].items(), 
                              key=lambda x: x[1], reverse=True)[:10],
            'by_betweenness': sorted(stats['centrality']['betweenness'].items(), 
                                   key=lambda x: x[1], reverse=True)[:10],
            'by_closeness': sorted(stats['centrality']['closeness'].items(), 
                                 key=lambda x: x[1], reverse=True)[:10]
        }
        
        return stats
    
    def analyze_node_connections(self, node, G):
        """Analyze connections for a specific node"""
        if not G or node not in G:
            return {}
        
        # Get direct connections
        predecessors = list(G.predecessors(node))
        successors = list(G.successors(node))
        
        # Get edge information
        incoming_emails = []
        outgoing_emails = []
        
        for pred in predecessors:
            edge_data = G[pred][node]
            incoming_emails.append({
                'from': pred,
                'weight': edge_data.get('weight', 1),
                'risk_levels': edge_data.get('risk_levels', []),
                'attachments': edge_data.get('attachments', 0),
                'departments': list(edge_data.get('departments', set()))
            })
        
        for succ in successors:
            edge_data = G[node][succ]
            outgoing_emails.append({
                'to': succ,
                'weight': edge_data.get('weight', 1),
                'risk_levels': edge_data.get('risk_levels', []),
                'attachments': edge_data.get('attachments', 0),
                'departments': list(edge_data.get('departments', set()))
            })
        
        return {
            'node': node,
            'incoming': incoming_emails,
            'outgoing': outgoing_emails,
            'total_incoming': len(predecessors),
            'total_outgoing': len(successors),
            'total_connections': len(predecessors) + len(successors)
        }

class ReportGenerator:
    """Enhanced PDF report generation with charts and professional formatting"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        
        # Enhanced professional styles
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue,
            alignment=1,  # Center alignment
            fontName='Helvetica-Bold'
        )
        
        self.header_style = ParagraphStyle(
            'CustomHeader',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=18,
            spaceBefore=20,
            textColor=colors.darkblue,
            fontName='Helvetica-Bold',
            borderWidth=2,
            borderColor=colors.darkblue,
            borderPadding=10,
            backColor=colors.lightgrey
        )
        
        self.subheader_style = ParagraphStyle(
            'CustomSubHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            spaceBefore=15,
            textColor=colors.darkred,
            fontName='Helvetica-Bold'
        )
        
        self.summary_style = ParagraphStyle(
            'SummaryStyle',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=8,
            textColor=colors.black,
            fontName='Helvetica',
            leading=14
        )
        
        self.info_style = ParagraphStyle(
            'InfoStyle',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.grey,
            alignment=1,  # Center alignment
            fontName='Helvetica'
        )
        
        self.highlight_style = ParagraphStyle(
            'HighlightStyle',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.darkred,
            fontName='Helvetica-Bold',
            spaceAfter=6,
            leftIndent=20
        )
    
    def create_pie_chart(self, data_dict, title, colors_palette=None):
        """Create a professional pie chart and return as reportlab Image"""
        plt.style.use('default')
        fig, ax = plt.subplots(figsize=(9, 7))
        
        # Define colors if not provided
        if colors_palette is None:
            colors_palette = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F']
        
        # Filter out zero values
        filtered_data = {k: v for k, v in data_dict.items() if v > 0}
        
        if not filtered_data:
            plt.close(fig)
            return None
            
        # Calculate total for better percentage display
        total = sum(filtered_data.values())
        
        wedges, texts, autotexts = ax.pie(
            filtered_data.values(), 
            labels=filtered_data.keys(),
            autopct=lambda pct: f'{pct:.1f}%\n({int(pct/100*total):,})',
            colors=colors_palette[:len(filtered_data)],
            startangle=90,
            explode=[0.02] * len(filtered_data),
            shadow=True,
            textprops={'fontsize': 10, 'fontweight': 'bold'}
        )
        
        # Enhance text appearance
        for text in texts:
            text.set_fontsize(12)
            text.set_fontweight('bold')
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontsize(10)
            autotext.set_fontweight('bold')
        
        ax.set_title(title, fontsize=16, fontweight='bold', pad=25)
        
        # Add a legend
        ax.legend(wedges, [f'{k}: {v:,}' for k, v in filtered_data.items()],
                 title="Risk Levels",
                 loc="center left",
                 bbox_to_anchor=(1, 0, 0.5, 1))
        
        # Save to BytesIO and return as reportlab Image
        img_buffer = io.BytesIO()
        plt.savefig(img_buffer, format='png', dpi=300, bbox_inches='tight', 
                   facecolor='white', edgecolor='none')
        img_buffer.seek(0)
        plt.close(fig)
        
        return Image(img_buffer, width=5*inch, height=4*inch)
    
    def create_bar_chart(self, data_dict, title, xlabel, ylabel):
        """Create a professional bar chart and return as reportlab Image"""
        plt.style.use('default')
        fig, ax = plt.subplots(figsize=(10, 6))
        
        # Sort data by values for better visualization
        sorted_data = dict(sorted(data_dict.items(), key=lambda x: x[1], reverse=True))
        
        # Create professional color gradient
        colors_list = plt.cm.viridis(np.linspace(0.2, 0.8, len(sorted_data)))
        
        bars = ax.bar(sorted_data.keys(), sorted_data.values(), color=colors_list, 
                     edgecolor='white', linewidth=1.5)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                   f'{int(height):,}', ha='center', va='bottom', 
                   fontweight='bold', fontsize=11)
        
        ax.set_title(title, fontsize=16, fontweight='bold', pad=25)
        ax.set_xlabel(xlabel, fontsize=13, fontweight='bold')
        ax.set_ylabel(ylabel, fontsize=13, fontweight='bold')
        
        # Rotate x-axis labels for better readability
        plt.xticks(rotation=45, ha='right', fontsize=10)
        plt.yticks(fontsize=10)
        
        # Add professional grid
        ax.grid(axis='y', alpha=0.3, linestyle='--', linewidth=0.5)
        ax.set_axisbelow(True)
        
        # Set background color
        ax.set_facecolor('#f8f9fa')
        
        # Add border
        for spine in ax.spines.values():
            spine.set_visible(True)
            spine.set_linewidth(1)
            spine.set_color('black')
        
        # Save to BytesIO and return as reportlab Image
        img_buffer = io.BytesIO()
        plt.tight_layout()
        plt.savefig(img_buffer, format='png', dpi=300, bbox_inches='tight',
                   facecolor='white', edgecolor='none')
        img_buffer.seek(0)
        plt.close(fig)
        
        return Image(img_buffer, width=6*inch, height=4.5*inch)
    
    def create_trend_chart(self, time_data, title):
        """Create a professional trend line chart"""
        plt.style.use('default')
        fig, ax = plt.subplots(figsize=(10, 6))
        
        # Sort by time
        sorted_time_data = dict(sorted(time_data.items()))
        
        ax.plot(list(sorted_time_data.keys()), list(sorted_time_data.values()), 
               marker='o', linewidth=2, markersize=8, color='#2E86AB')
        
        ax.fill_between(list(sorted_time_data.keys()), list(sorted_time_data.values()), 
                       alpha=0.3, color='#2E86AB')
        
        ax.set_title(title, fontsize=14, fontweight='bold', pad=20)
        ax.set_xlabel('Time Period', fontsize=12, fontweight='bold')
        ax.set_ylabel('Email Count', fontsize=12, fontweight='bold')
        
        plt.xticks(rotation=45, ha='right')
        ax.grid(True, alpha=0.3)
        
        # Save to BytesIO and return as reportlab Image
        img_buffer = io.BytesIO()
        plt.tight_layout()
        plt.savefig(img_buffer, format='png', dpi=300, bbox_inches='tight',
                   facecolor='white', edgecolor='none')
        img_buffer.seek(0)
        plt.close(fig)
        
        return Image(img_buffer, width=5*inch, height=3*inch)
    
    def generate_pdf_report(self, data, report_type='security_review'):
        """Generate PDF report based on data and report type"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, 
            pagesize=letter,
            topMargin=72,
            bottomMargin=72,
            leftMargin=72,
            rightMargin=72
        )
        story = []
        
        # Professional header with company info
        story.append(Paragraph("ExfilEye Data Loss Prevention System", self.title_style))
        story.append(Spacer(1, 12))
        
        # Report metadata box
        report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        report_id = f"RPT-{datetime.now().strftime('%Y%m%d')}-{hash(str(data)) % 10000:04d}"
        
        metadata_data = [
            ['Report Type:', report_type.replace('_', ' ').title()],
            ['Report ID:', report_id],
            ['Generated:', report_date],
            ['Classification:', 'CONFIDENTIAL - INTERNAL USE ONLY'],
            ['Total Records:', f"{len(data):,}" if data else "0"]
        ]
        
        metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('BACKGROUND', (0, 1), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        story.append(metadata_table)
        story.append(Spacer(1, 24))
        
        if report_type == 'security_review':
            story.extend(self._generate_security_review_content(data))
        elif report_type == 'domain_analysis':
            story.extend(self._generate_domain_analysis_content(data))
        elif report_type == 'network_analysis':
            story.extend(self._generate_network_analysis_content(data))
        elif report_type == 'suspicious_email_analysis':
            story.extend(self._generate_suspicious_email_analysis_content(data))
        

        
        # Simple footer
        story.append(Spacer(1, 24))
        
        doc.build(story)
        buffer.seek(0)
        return buffer
    
    def _generate_security_review_content(self, data):
        """Generate enhanced security review report content with charts"""
        story = []
        
        # Executive Summary Section
        story.append(Paragraph("EXECUTIVE SECURITY SUMMARY", self.header_style))
        story.append(Spacer(1, 12))
        
        if data:
            total_emails = len(data)
            risk_counts = {}
            for email in data:
                status = email.get('status', 'unknown').lower()
                risk_counts[status] = risk_counts.get(status, 0) + 1
            
            critical_count = risk_counts.get('critical', 0)
            high_count = risk_counts.get('high', 0)
            medium_count = risk_counts.get('medium', 0)
            low_count = risk_counts.get('low', 0)
            unclassified_count = risk_counts.get('unclassified', 0)
            
            # Calculate review metrics
            completed_reviews = len(st.session_state.completed_reviews) if 'completed_reviews' in st.session_state else 0
            escalated_records = len(st.session_state.escalated_records) if 'escalated_records' in st.session_state else 0
            completion_rate = (completed_reviews / max(total_emails, 1)) * 100
            escalation_rate = (escalated_records / max(total_emails, 1)) * 100
            
            # Risk percentage calculations
            critical_pct = (critical_count / total_emails) * 100 if total_emails > 0 else 0
            high_pct = (high_count / total_emails) * 100 if total_emails > 0 else 0
            medium_pct = (medium_count / total_emails) * 100 if total_emails > 0 else 0
            low_pct = (low_count / total_emails) * 100 if total_emails > 0 else 0
            unclassified_pct = (unclassified_count / total_emails) * 100 if total_emails > 0 else 0
            
            # Executive summary text
            summary_text = f"""
            <b>SECURITY ASSESSMENT OVERVIEW</b><br/><br/>
            
            This comprehensive security review analyzes <b>{total_emails:,}</b> email communications for potential data loss prevention violations.
            Our automated analysis identified <b>{critical_count + high_count:,}</b> high-priority security events requiring immediate attention.<br/><br/>
            
            <b>KEY SECURITY FINDINGS:</b><br/>
            • Critical Risk Events: <b>{critical_count:,}</b> ({critical_pct:.1f}% of total volume)<br/>
            • High Risk Events: <b>{high_count:,}</b> ({high_pct:.1f}% of total volume)<br/>
            • Medium Risk Events: <b>{medium_count:,}</b> ({medium_pct:.1f}% of total volume)<br/>
            • Low Risk Events: <b>{low_count:,}</b> ({low_pct:.1f}% of total volume)<br/>
            • Unclassified Events: <b>{unclassified_count:,}</b> ({unclassified_pct:.1f}% of total volume)<br/>
            • Security Review Completion: <b>{completion_rate:.1f}%</b><br/>
            • Immediate Action Required: <b>{"YES - URGENT RESPONSE NEEDED" if critical_count > 0 else "NO - CONTINUE MONITORING"}</b><br/><br/>
            
            <b>BUSINESS IMPACT ASSESSMENT:</b><br/>
            {"🔴 <b>HIGH RISK</b> - Immediate escalation and remediation required" if critical_count > 0 else "🟡 <b>MEDIUM RISK</b> - Continued monitoring recommended" if high_count > 0 else "🟢 <b>LOW RISK</b> - Normal security operations"}
            """
            
            story.append(Paragraph(summary_text, self.summary_style))
            story.append(Spacer(1, 20))
            
            # Add Risk Distribution Pie Chart
            story.append(Paragraph("Risk Distribution Analysis", self.subheader_style))
            story.append(Spacer(1, 10))
            
            # Create pie chart for risk distribution
            risk_chart_data = {}
            risk_colors = []
            
            # Build chart data with proper colors for each status type
            if critical_count > 0:
                risk_chart_data['Critical'] = critical_count
                risk_colors.append('#FF4444')
            if high_count > 0:
                risk_chart_data['High'] = high_count
                risk_colors.append('#FF8800')
            if medium_count > 0:
                risk_chart_data['Medium'] = medium_count
                risk_colors.append('#FFBB00')
            if low_count > 0:
                risk_chart_data['Low'] = low_count
                risk_colors.append('#44AA44')
            if unclassified_count > 0:
                risk_chart_data['Unclassified'] = unclassified_count
                risk_colors.append('#888888')
            
            if risk_chart_data:
                risk_pie_chart = self.create_pie_chart(
                    risk_chart_data, 
                    "Email Risk Level Distribution",
                    risk_colors
                )
                if risk_pie_chart:
                    story.append(risk_pie_chart)
                    story.append(Spacer(1, 15))
            
            # Domain Analysis Chart
            story.append(Paragraph("Top Risk Domains Analysis", self.subheader_style))
            story.append(Spacer(1, 10))
            
            # Analyze domains
            domain_counts = {}
            for email in data:
                domain = email.get('recipients_email_domain', 'unknown')
                if domain and domain != 'unknown':
                    domain_counts[domain] = domain_counts.get(domain, 0) + 1
            
            # Get top 10 domains
            top_domains = dict(sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10])
            if top_domains:
                domain_chart = self.create_bar_chart(
                    top_domains,
                    "Top 10 Recipient Domains by Email Volume",
                    "Domain",
                    "Email Count"
                )
                if domain_chart:
                    story.append(domain_chart)
                    story.append(Spacer(1, 20))
            


        
        else:
            story.append(Paragraph("No data available for security analysis.", self.summary_style))
        
        return story
    
    def _generate_domain_analysis_content(self, data):
        """Generate domain analysis report content"""
        story = []
        
        story.append(Paragraph("Domain Classification Analysis", self.styles['Heading1']))
        story.append(Spacer(1, 12))
        
        if data:
            domain_counts = {}
            for email in data:
                domain = email.get('recipients_email_domain', 'unknown')
                domain_counts[domain] = domain_counts.get(domain, 0) + 1
            
            # Top domains table
            sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            table_data = [['Domain', 'Email Count', 'Classification']]
            for domain, count in sorted_domains:
                classification = st.session_state.domain_classifier.classify_domain(domain)
                table_data.append([domain, str(count), classification])
            
            table = Table(table_data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(table)
        
        return story
    
    def _generate_network_analysis_content(self, data):
        """Generate network analysis report content"""
        story = []
        
        story.append(Paragraph("Network Communication Analysis", self.styles['Heading1']))
        story.append(Spacer(1, 12))
        
        if data:
            # Network statistics
            analyzer = NetworkAnalyzer()
            G = analyzer.build_network_from_data(data, 'sender', 'recipients')
            
            stats_text = f"""
            Total nodes: {len(G.nodes())}<br/>
            Total edges: {len(G.edges())}<br/>
            Average degree: {np.mean([d for n, d in G.degree()]):.2f}<br/>
            Network density: {nx.density(G):.4f}
            """
            story.append(Paragraph(stats_text, self.styles['Normal']))
        
        return story
    
    def _generate_suspicious_email_analysis_content(self, data):
        """Generate suspicious email analysis report content"""
        story = []
        
        story.append(Paragraph("Suspicious Email Analysis Report", self.header_style))
        story.append(Spacer(1, 12))
        
        if data and 'suspicious_emails' in data:
            suspicious_emails = data['suspicious_emails']
            summary = data.get('summary', {})
            
            # Executive Summary
            story.append(Paragraph("EXECUTIVE SUMMARY", self.subheader_style))
            story.append(Spacer(1, 8))
            
            summary_text = f"""
            <b>SUSPICIOUS EMAIL ANALYSIS OVERVIEW</b><br/><br/>
            
            This analysis examined <b>{summary.get('total_emails_analyzed', 0):,}</b> Medium Low and unclassified emails 
            using advanced machine learning techniques to identify potential security threats.<br/><br/>
            
            <b>KEY FINDINGS:</b><br/>
            • Total Emails Analyzed: <b>{summary.get('total_emails_analyzed', 0):,}</b><br/>
            • Suspicious Emails Identified: <b>{summary.get('suspicious_emails_found', 0):,}</b><br/>
            • High Priority Emails: <b>{len([e for e in suspicious_emails if e['suspicion_score'] >= 0.8]):,}</b><br/>
            • Medium Priority Emails: <b>{len([e for e in suspicious_emails if 0.6 <= e['suspicion_score'] < 0.8]):,}</b><br/>
            • Low Priority Emails: <b>{len([e for e in suspicious_emails if e['suspicion_score'] < 0.6]):,}</b><br/><br/>
            
            <b>RECOMMENDATION:</b><br/>
            {"IMMEDIATE ACTION REQUIRED - Review high priority emails" if any(e['suspicion_score'] >= 0.8 for e in suspicious_emails) else "CONTINUE MONITORING - No immediate threats detected"}
            """
            
            story.append(Paragraph(summary_text, self.summary_style))
            story.append(Spacer(1, 20))
            
            # Top Suspicious Emails Table
            story.append(Paragraph("Top Suspicious Emails", self.subheader_style))
            story.append(Spacer(1, 10))
            
            # Create table with top 10 suspicious emails
            table_data = [['Rank', 'Sender', 'Subject', 'Score', 'Primary Reason']]
            
            for i, email_data in enumerate(suspicious_emails[:10], 1):
                email = email_data['email']
                score = email_data['suspicion_score']
                reasons = email_data['reasons']
                
                sender = email.get('sender', 'Unknown')[:30] + '...' if len(email.get('sender', '')) > 30 else email.get('sender', 'Unknown')
                subject = email.get('subject', 'No Subject')[:40] + '...' if len(email.get('subject', '')) > 40 else email.get('subject', 'No Subject')
                primary_reason = reasons[0] if reasons else 'Unknown'
                
                table_data.append([
                    str(i),
                    sender,
                    subject,
                    f"{score:.2f}",
                    primary_reason
                ])
            
            table = Table(table_data, colWidths=[0.5*inch, 2*inch, 2.5*inch, 0.7*inch, 2*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
            ]))
            story.append(table)
            story.append(Spacer(1, 20))
            
            # Recommendations
            story.append(Paragraph("SECURITY RECOMMENDATIONS", self.subheader_style))
            story.append(Spacer(1, 10))
            
            high_risk_count = len([e for e in suspicious_emails if e['suspicion_score'] >= 0.8])
            medium_risk_count = len([e for e in suspicious_emails if 0.6 <= e['suspicion_score'] < 0.8])
            
            recommendations = []
            if high_risk_count > 0:
                recommendations.append(f"• IMMEDIATE ACTION: Review {high_risk_count} high-risk emails within 24 hours")
            if medium_risk_count > 0:
                recommendations.append(f"• PRIORITY: Review {medium_risk_count} medium-risk emails within 48 hours")
            
            recommendations.append("• Consider implementing additional ML-based email monitoring")
            recommendations.append("• Schedule regular review of Medium Low and unclassified emails")
            
            for rec in recommendations:
                story.append(Paragraph(rec, self.summary_style))
                story.append(Spacer(1, 6))
            
        else:
            story.append(Paragraph("No suspicious email analysis data available.", self.summary_style))
        
        return story


def get_risk_indicator(status):
    """Get risk indicator emoji based on status"""
    indicators = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢',
        'unclassified': '⚪'
    }
    return indicators.get(status.lower(), '⚪')

def show_email_details_modal(email):
    """Show email details in dialog modal format with all fields and domain classification"""
    # CSS is now applied in the calling function
    
    # Get domain classification
    domain = email.get('recipients_email_domain', 'Unknown')
    domain_classification = st.session_state.domain_classifier.classify_domain(domain)
    
    # Display content directly in modal (no expander needed)
    
    # Primary Email Information - Full width cards
    st.markdown("### 📧 Email Information")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.info(f"""
        **📤 From:** {email.get('sender', 'Unknown')}
        
        **📥 To:** {email.get('recipients', 'Unknown')}
        
        **📝 Subject:** {email.get('subject', 'No Subject')}
        
        **⏰ Time:** {email.get('_time', 'Unknown')}
        
        **📅 Time Month:** {email.get('time_month', 'Unknown')}
        """)
    
    with col2:
        # Handle attachments display
        attachment_value = email.get('attachments', '')
        if attachment_value and attachment_value not in [True, False, 'True', 'False']:
            attachment_text = f"📎 {attachment_value}"
        elif attachment_value:
            attachment_text = "✅ Yes"
        else:
            attachment_text = "❌ No"
        
        st.warning(f"""
        **🌐 Recipients Domain:** {domain}
        
        **🏷️ Domain Classification:** {domain_classification}
        
        **⚠️ Status:** {email.get('status', 'Unknown').title()}
        
        **📎 Attachments:** {attachment_text}
        
        **🔐 Encryption:** {email.get('encryption', 'Unknown')}
        """)
    
    # Security & Compliance Section
    st.markdown("### 🔒 Security & Compliance")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.error(f"""
        **🔍 Tessian:** {'✅ Yes' if email.get('tessian') else '❌ No'}
        
        **📎 Wordlist Attachment:** {'⚠️ Yes' if email.get('wordlist_attachment') else '✅ No'}
        
        **📝 Wordlist Subject:** {'⚠️ Yes' if email.get('wordlist_subject') else '✅ No'}
        """)
    
    with col2:
        st.success(f"""
        **👋 Leaver:** {'⚠️ Yes' if email.get('leaver') else '✅ No'}
        
        **🚪 Termination:** {'⚠️ Yes' if email.get('Termination') else '✅ No'}
        
        **👤 User Response:** {email.get('user_response', 'Unknown')}
        """)
    
    with col3:
        st.warning(f"""
        **🎯 Final Outcome:** {email.get('final_outcome', 'Unknown')}
        """)
    
    # Organizational Information
    st.markdown("### 🏢 Organizational Information")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.info(f"""
        **🏛️ Department:** {email.get('department', 'Unknown')}
        
        **🏢 Business Unit:** {email.get('bunit', 'Unknown')}
        """)
    
    with col2:
        st.info(f"""
        **👤 Account Type:** {email.get('account_type', 'Unknown')}
        """)
    
    # Additional Fields
    st.markdown("### 📋 Additional Fields")
    
    # Get all fields that weren't already displayed
    displayed_fields = {
        'sender', 'recipients', 'subject', '_time', 'time_month', 
        'recipients_email_domain', 'attachments', 'status',
        'tessian', 'wordlist_attachment', 'wordlist_subject', 'leaver', 
        'Termination', 'department', 'bunit', 'account_type', 
        'user_response', 'final_outcome'
    }
    
    additional_fields = {k: v for k, v in email.items() if k not in displayed_fields}
    
    if additional_fields:
        cols = st.columns(2)
        for i, (field, value) in enumerate(additional_fields.items()):
            with cols[i % 2]:
                # Format field name nicely
                field_name = field.replace('_', ' ').title()
                st.write(f"**{field_name}:** {value}")
    else:
        st.info("No additional fields to display")
    
    # Summary Footer
    st.markdown("---")
    col1, col2 = st.columns(2)
    
    with col1:
        st.metric("Domain Classification", domain_classification)
    
    with col2:
        st.metric("Current Status", email.get('status', 'Unknown').title())
        
        



def data_upload_page():
    """Data Upload & Preprocessing page"""
    st.markdown("""
    <div class="data-container">
        <h2 style="color: #2c3e50; margin-bottom: 1rem;">📁 Data Upload & Preprocessing</h2>
        <p style="color: #7f8c8d; font-size: 1.1rem; margin-bottom: 1.5rem;">
            Upload CSV files up to 2GB containing email metadata for analysis.
            The system will validate required fields and process the data for security monitoring.
            Data is automatically saved to JSON files for persistence across sessions.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Data persistence options with professional styling
    st.markdown("""
    <div class="data-container">
        <h3 style="color: #2c3e50; margin-bottom: 1rem;">📅 Daily Data Management</h3>
    </div>
    """, unsafe_allow_html=True)
    
    persistence = st.session_state.data_persistence
    available_dates = persistence.get_available_dates()
    
    if available_dates:
        st.success(f"Found data for {len(available_dates)} dates")
        
        col1, col2 = st.columns(2)
        
        with col1:
            selected_date = st.selectbox(
                "Load Previous Data",
                ["None"] + available_dates,
                help="Select a date to load previously uploaded data"
            )
            
            if selected_date != "None":
                if st.button("📂 Load Data", type="primary"):
                    loaded_data = persistence.load_daily_data(selected_date)
                    loaded_work_state = persistence.load_work_state(selected_date)
                    
                    if loaded_data:
                        st.session_state.data = loaded_data
                        st.success(f"✅ Loaded {len(loaded_data):,} records from {selected_date}")
                        
                        # Load work state if available
                        if loaded_work_state:
                            # Security Operations Dashboard
                            st.session_state.completed_reviews = loaded_work_state.get("completed_reviews", {})
                            st.session_state.escalated_records = loaded_work_state.get("escalated_records", {})
                            st.session_state.active_filters = loaded_work_state.get("active_filters", {})
                            st.session_state.review_decisions = loaded_work_state.get("review_decisions", {})
                            st.session_state.last_reviewed_email = loaded_work_state.get("last_reviewed_email", "")
                            st.session_state.review_session_start = loaded_work_state.get("review_session_start", "")
                            st.session_state.total_reviews_this_session = loaded_work_state.get("total_reviews_this_session", 0)
                            
                            # Email Check Completed Dashboard
                            st.session_state.review_notes = loaded_work_state.get("review_notes", {})
                            st.session_state.reviewer_assignments = loaded_work_state.get("reviewer_assignments", {})
                            st.session_state.completion_timestamps = loaded_work_state.get("completion_timestamps", {})
                            st.session_state.review_quality_scores = loaded_work_state.get("review_quality_scores", {})
                            st.session_state.batch_review_sessions = loaded_work_state.get("batch_review_sessions", [])
                            
                            # Follow-up Center Dashboard
                            st.session_state.followup_status = loaded_work_state.get("followup_status", {})
                            st.session_state.followup_notes = loaded_work_state.get("followup_notes", {})
                            st.session_state.email_templates = loaded_work_state.get("email_templates", {})
                            st.session_state.followup_assignments = loaded_work_state.get("followup_assignments", {})
                            st.session_state.escalation_reasons = loaded_work_state.get("escalation_reasons", {})
                            st.session_state.followup_deadlines = loaded_work_state.get("followup_deadlines", {})
                            st.session_state.email_sent_status = loaded_work_state.get("email_sent_status", {})
                            st.session_state.template_drafts = loaded_work_state.get("template_drafts", {})
                            
                            # General system state
                            st.session_state.follow_up_decisions = loaded_work_state.get("follow_up_decisions", {})
                            st.session_state.blocked_domains = loaded_work_state.get("blocked_domains", [])
                            st.session_state.sender_status = loaded_work_state.get("sender_status", {})
                            st.session_state.domain_classifications = loaded_work_state.get("domain_classifications", {})
                            st.session_state.user_preferences = loaded_work_state.get("user_preferences", {})
                            st.session_state.session_statistics = loaded_work_state.get("session_statistics", {})
                            
                            # UI state
                            st.session_state.selected_filters = loaded_work_state.get("selected_filters", {})
                            st.session_state.sort_preferences = loaded_work_state.get("sort_preferences", {})
                            st.session_state.view_modes = loaded_work_state.get("view_modes", {})
                            st.session_state.expanded_sections = loaded_work_state.get("expanded_sections", {})
                            st.session_state.modal_states = loaded_work_state.get("modal_states", {})
                            
                            completed_count = len(st.session_state.completed_reviews)
                            escalated_count = len(st.session_state.escalated_records)
                            template_count = len(st.session_state.email_templates)
                            st.info(f"📊 Restored complete work state: {completed_count} completed reviews, {escalated_count} escalated records, {template_count} email templates")
                        
                        st.rerun()
                    else:
                        st.error("Failed to load data")
        
        with col2:
            st.markdown("**📊 Available Data Summary:**")
            for date in available_dates[:5]:  # Show first 5
                summary = persistence.get_data_summary(date)
                if summary:
                    st.write(f"**{date}:** {summary['total_records']:,} records")
                    
                    # Show risk distribution
                    risk_dist = summary['risk_distribution']
                    risk_text = []
                    for risk, count in risk_dist.items():
                        if count > 0:
                            risk_text.append(f"{risk}: {count}")
                    
                    if risk_text:
                        st.caption(f"   Risk: {', '.join(risk_text)}")
        
        # Data management tools
        st.subheader("🔧 Data Management Tools")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            merge_dates = st.multiselect(
                "Merge Multiple Days",
                available_dates,
                help="Select dates to merge into current session"
            )
            
            if merge_dates and st.button("🔄 Merge Data"):
                merged_data = persistence.merge_daily_data(merge_dates)
                if merged_data:
                    st.session_state.data = merged_data
                    st.success(f"✅ Merged {len(merged_data):,} records from {len(merge_dates)} dates")
                    st.rerun()
        
        with col2:
            if st.button("📁 Export All Data"):
                export_file = persistence.export_all_data()
                if export_file:
                    st.success(f"✅ Exported all data to {export_file}")
                    
                    # Provide download link
                    with open(export_file, 'r', encoding='utf-8') as f:
                        st.download_button(
                            "📥 Download Export",
                            data=f.read(),
                            file_name=export_file,
                            mime="application/json"
                        )
        
        with col3:
            delete_date = st.selectbox(
                "Delete Data",
                ["Select date..."] + available_dates,
                key="delete_date"
            )
            
            if delete_date != "Select date..." and st.button("🗑️ Delete", type="secondary"):
                if persistence.delete_daily_data(delete_date):
                    st.success(f"✅ Deleted data for {delete_date}")
                    st.rerun()
                else:
                    st.error("Failed to delete data")
    
    st.subheader("📤 Upload New Data")
    
    # File upload
    uploaded_file = st.file_uploader(
        "Choose a CSV file",
        type="csv",
        help="Maximum file size: 2GB"
    )
    
    if uploaded_file is not None:
        try:
            # Reset whitelist filtering counter for this upload
            st.session_state.whitelisted_emails_count = 0
            
            # Read file content
            content = uploaded_file.read().decode('utf-8')
            
            # Process CSV
            processor = CSVProcessor()
            
            with st.spinner("Processing CSV data..."):
                processed_data = processor.process_csv_data(content)
            
            if processed_data:
                st.session_state.data = processed_data
                
                # Display whitelist filtering statistics
                if hasattr(st.session_state, 'whitelisted_emails_count') and st.session_state.whitelisted_emails_count > 0:
                    st.info(f"✅ Filtered out {st.session_state.whitelisted_emails_count:,} emails from whitelisted domains")
                
                # Save to JSON with persistence
                persistence = st.session_state.data_persistence
                
                # Option to specify date
                col1, col2 = st.columns(2)
                
                with col1:
                    save_date = st.date_input(
                        "Save Date",
                        value=datetime.now().date(),
                        help="Date to associate with this data"
                    )
                
                with col2:
                    st.write("") # spacing
                    st.write("") # spacing
                    if st.button("💾 Save to JSON", type="primary"):
                        date_str = save_date.strftime("%Y-%m-%d")
                        saved_path = persistence.save_daily_data(processed_data, date_str)
                        
                        if saved_path:
                            st.success(f"✅ Data saved to JSON for {date_str}")
                            st.info(f"📁 Saved to: {saved_path}")
                        else:
                            st.error("Failed to save data to JSON")
                
                st.success(f"Successfully processed {len(processed_data):,} records!")
                
                # Show data summary
                st.subheader("Data Summary")
                
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Total Records", f"{len(processed_data):,}")
                
                with col2:
                    unique_senders = len(set(email.get('sender', '') for email in processed_data))
                    st.metric("Unique Senders", f"{unique_senders:,}")
                
                with col3:
                    unique_domains = len(set(email.get('recipients_email_domain', '') for email in processed_data))
                    st.metric("Unique Domains", f"{unique_domains:,}")
                
                with col4:
                    critical_count = sum(1 for email in processed_data if email.get('status') == 'critical')
                    st.metric("Critical Risk", f"{critical_count:,}")
                
                # Risk distribution chart
                st.subheader("Risk Distribution")
                
                risk_counts = {}
                for email in processed_data:
                    status = email.get('status', 'unknown')
                    risk_counts[status] = risk_counts.get(status, 0) + 1
                
                fig = px.pie(
                    values=list(risk_counts.values()),
                    names=list(risk_counts.keys()),
                    title="Email Risk Distribution"
                )
                st.plotly_chart(fig, use_container_width=True)
                
                # Sample data preview
                st.subheader("Sample Data Preview")
                
                if st.checkbox("Show sample records"):
                    sample_data = processed_data[:5]
                    for i, email in enumerate(sample_data):
                        with st.expander(f"Record {i+1}: {email.get('subject', 'No Subject')[:30]}..."):
                            st.json(email)
            
        except Exception as e:
            st.error(f"Error processing file: {str(e)}")
    
    # Data validation section
    if st.session_state.data:
        st.subheader("Data Validation")
        
        processor = CSVProcessor()
        data = st.session_state.data
        
        # Required fields check
        st.write("**Required Fields Status:**")
        for field in processor.required_fields:
            has_field = all(field in email for email in data[:100])  # Check sample
            status = "✅" if has_field else "❌"
            st.write(f"{status} {field}")
        
        # Data quality metrics
        st.write("**Data Quality Metrics:**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            empty_subjects = sum(1 for email in data if not email.get('subject'))
            st.metric("Empty Subjects", f"{empty_subjects:,}")
            
            empty_senders = sum(1 for email in data if not email.get('sender'))
            st.metric("Empty Senders", f"{empty_senders:,}")
        
        with col2:
            empty_recipients = sum(1 for email in data if not email.get('recipients'))
            st.metric("Empty Recipients", f"{empty_recipients:,}")
            
            invalid_domains = sum(1 for email in data if not email.get('recipients_email_domain'))
            st.metric("Invalid Domains", f"{invalid_domains:,}")

def security_operations_dashboard():
    """Security Operations Dashboard"""
    st.markdown("""
    <div class="data-container">
        <h2 style="color: #2c3e50; margin-bottom: 1rem;">🛡️ Security Operations Dashboard</h2>
        <p style="color: #7f8c8d; font-size: 1.1rem; margin-bottom: 0;">
            Monitor, review, and manage email security events with AI-powered assistance
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    if not st.session_state.data:
        st.markdown("""
        <div class="alert alert-warning">
            <strong>⚠️ No Data Available</strong><br>
            Please upload data first in the Data Upload & Preprocessing section to begin security operations.
        </div>
        """, unsafe_allow_html=True)
        return
    
    data = st.session_state.data
    
    # Filter out completed and escalated records
    completed_ids = set(st.session_state.completed_reviews.keys())
    escalated_ids = set(st.session_state.escalated_records.keys())
    
    # Filter active records
    active_records = []
    for email in data:
        email_id = str(hash(str(email)))
        if email_id not in completed_ids and email_id not in escalated_ids:
            active_records.append(email)
    
    # Professional overview metrics
    st.markdown(f"""
    <div class="data-container">
        <h3 style="color: #2c3e50; margin-bottom: 1rem;">📊 Operation Overview</h3>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem;">
            <div style="text-align: center; padding: 1rem; background: #3498db20; border-radius: 8px;">
                <div style="font-size: 1.8rem; font-weight: 700; color: #3498db;">{len(active_records):,}</div>
                <div style="color: #7f8c8d; font-size: 0.9rem;">Active Records</div>
            </div>
            <div style="text-align: center; padding: 1rem; background: #27ae6020; border-radius: 8px;">
                <div style="font-size: 1.8rem; font-weight: 700; color: #27ae60;">{len(completed_ids):,}</div>
                <div style="color: #7f8c8d; font-size: 0.9rem;">Completed</div>
            </div>
            <div style="text-align: center; padding: 1rem; background: #e74c3c20; border-radius: 8px;">
                <div style="font-size: 1.8rem; font-weight: 700; color: #e74c3c;">{len(escalated_ids):,}</div>
                <div style="color: #7f8c8d; font-size: 0.9rem;">Escalated</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Professional filters section
    st.markdown("""
    <div class="data-container">
        <h3 style="color: #2c3e50; margin-bottom: 1rem;">🔍 Filter Options</h3>
        <p style="color: #7f8c8d; margin-bottom: 1rem;">Filter records by status, domain, or sender to focus your review</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        status_filter = st.selectbox(
            "Filter by Status",
            ["All", "Critical", "High", "Medium", "Low", "Unclassified"]
        )
    
    with col2:
        domain_filter = st.selectbox(
            "Filter by Domain",
            ["All"] + sorted(set(email.get('recipients_email_domain', '') for email in active_records))
        )
    
    with col3:
        sender_filter = st.selectbox(
            "Filter by Sender",
            ["All"] + sorted(set(email.get('sender', '') for email in active_records))
        )
    
    # Apply filters
    filtered_records = active_records
    
    if status_filter != "All":
        filtered_records = [email for email in filtered_records if email.get('status', '').lower() == status_filter.lower()]
    
    if domain_filter != "All":
        filtered_records = [email for email in filtered_records if email.get('recipients_email_domain', '') == domain_filter]
    
    if sender_filter != "All":
        filtered_records = [email for email in filtered_records if email.get('sender', '') == sender_filter]
    
    # Professional security review queue section
    st.markdown("---")
    st.markdown("""
    <div class="data-container">
        <h3 style="color: #2c3e50; margin-bottom: 1rem;">🛡️ Security Review Queue</h3>
        <p style="color: #7f8c8d; margin-bottom: 1rem;">Review and manage email security events by risk level</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Professional risk metrics with cards
    critical_count = sum(1 for email in filtered_records if email.get('status', '').lower() == 'critical')
    high_count = sum(1 for email in filtered_records if email.get('status', '').lower() == 'high')
    medium_count = sum(1 for email in filtered_records if email.get('status', '').lower() == 'medium')
    low_count = sum(1 for email in filtered_records if email.get('status', '').lower() == 'low')
    unclassified_count = sum(1 for email in filtered_records if email.get('status', '').lower() == 'unclassified')
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.markdown(f"""
        <div class="metric-card" style="border-left: 4px solid #e74c3c;">
            <h4 style="color: #e74c3c; margin-bottom: 0.5rem;">🔴 Critical</h4>
            <p class="metric-value" style="color: #e74c3c;">{critical_count:,}</p>
            <p style="color: #7f8c8d; margin: 0; font-size: 0.9rem;">Immediate action required</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-card" style="border-left: 4px solid #f39c12;">
            <h4 style="color: #f39c12; margin-bottom: 0.5rem;">🟠 High</h4>
            <p class="metric-value" style="color: #f39c12;">{high_count:,}</p>
            <p style="color: #7f8c8d; margin: 0; font-size: 0.9rem;">Review within 24h</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card" style="border-left: 4px solid #f1c40f;">
            <h4 style="color: #f1c40f; margin-bottom: 0.5rem;">🟡 Medium</h4>
            <p class="metric-value" style="color: #f1c40f;">{medium_count:,}</p>
            <p style="color: #7f8c8d; margin: 0; font-size: 0.9rem;">Review within week</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="metric-card" style="border-left: 4px solid #27ae60;">
            <h4 style="color: #27ae60; margin-bottom: 0.5rem;">🟢 Low</h4>
            <p class="metric-value" style="color: #27ae60;">{low_count:,}</p>
            <p style="color: #7f8c8d; margin: 0; font-size: 0.9rem;">Monitor as needed</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col5:
        st.markdown(f"""
        <div class="metric-card" style="border-left: 4px solid #95a5a6;">
            <h4 style="color: #95a5a6; margin-bottom: 0.5rem;">⚪ Unclassified</h4>
            <p class="metric-value" style="color: #95a5a6;">{unclassified_count:,}</p>
            <p style="color: #7f8c8d; margin: 0; font-size: 0.9rem;">Needs classification</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Professional timeline view section
    st.markdown("""
    <div class="data-container">
        <h3 style="color: #2c3e50; margin-bottom: 1rem;">📊 Timeline View</h3>
        <p style="color: #7f8c8d; margin-bottom: 1rem;">Group and analyze email events by different criteria</p>
    </div>
    """, unsafe_allow_html=True)
    
    view_option = st.radio(
        "Group by:",
        ["Sender", "Domain", "Time", "Subject"],
        horizontal=True
    )
    
    # Group records based on selection
    if view_option == "Sender":
        grouped_records = {}
        for email in filtered_records:
            sender = email.get('sender', 'Unknown')
            if sender not in grouped_records:
                grouped_records[sender] = []
            grouped_records[sender].append(email)
    
    elif view_option == "Domain":
        grouped_records = {}
        for email in filtered_records:
            domain = email.get('recipients_email_domain', 'Unknown')
            if domain not in grouped_records:
                grouped_records[domain] = []
            grouped_records[domain].append(email)
    
    elif view_option == "Time":
        grouped_records = {}
        for email in filtered_records:
            time_month = email.get('time_month', 'Unknown')
            if time_month not in grouped_records:
                grouped_records[time_month] = []
            grouped_records[time_month].append(email)
    
    else:  # Subject
        grouped_records = {}
        for email in filtered_records:
            subject = email.get('subject', 'No Subject')[:50]
            if subject not in grouped_records:
                grouped_records[subject] = []
            grouped_records[subject].append(email)
    
    # Sort groups by highest risk level
    def get_group_priority(group_emails):
        """Calculate priority score for group based on highest risk level"""
        priority_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unclassified': 0, 'unknown': 0}
        max_priority = 0
        for email in group_emails:
            status = email.get('status', 'unknown').lower()
            max_priority = max(max_priority, priority_map.get(status, 0))
        return max_priority
    
    # Sort groups by priority (highest risk first)
    sorted_groups = sorted(grouped_records.items(), key=lambda x: get_group_priority(x[1]), reverse=True)
    
    # Display grouped records
    for group_name, group_emails in sorted_groups:
        if not group_emails:
            continue
        
        # Sort emails within group by risk level (critical first)
        priority_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unclassified': 0, 'unknown': 0}
        group_emails_sorted = sorted(group_emails, key=lambda x: priority_map.get(x.get('status', 'unknown').lower(), 0), reverse=True)
        
        # Risk distribution in group
        risk_counts = {}
        for email in group_emails:
            status = email.get('status', 'unknown').lower()
            risk_counts[status] = risk_counts.get(status, 0) + 1
        
        # Create professional risk summary with priority order
        risk_indicators = []
        for status in ['critical', 'high', 'medium', 'low', 'unclassified']:
            count = risk_counts.get(status, 0)
            if count > 0:
                risk_indicators.append(f"{get_risk_indicator(status)} {count} {status.title()}")
        
        # Get highest risk level for styling
        highest_risk = 'low'
        for status in ['critical', 'high', 'medium', 'low', 'unclassified']:
            if risk_counts.get(status, 0) > 0:
                highest_risk = status
                break
        
        risk_text = " • ".join(risk_indicators) if risk_indicators else "No classified risks"
        
        # Style the expander based on highest risk
        risk_emoji = get_risk_indicator(highest_risk)
        
        with st.expander(f"{risk_emoji} **{group_name}** ({len(group_emails)} emails) • {risk_text}", expanded=(highest_risk in ['critical', 'high'])):
            # Display emails in priority order with professional styling
            for i, email in enumerate(group_emails_sorted[:15]):  # Show up to 15 emails
                # Get individual email risk status
                email_status = email.get('status', 'unknown').lower()
                risk_icon = get_risk_indicator(email_status)
                
                # Create professional email preview
                subject_preview = email.get('subject', 'No Subject')[:60]
                if len(email.get('subject', '')) > 60:
                    subject_preview += "..."
                
                sender_name = email.get('sender', 'Unknown').split('@')[0]
                recipient_domain = email.get('recipients_email_domain', 'Unknown')
                time_sent = email.get('_time', 'Unknown')
                
                # Style based on risk level
                risk_color = {
                    'critical': '#ff4444',
                    'high': '#ff8800', 
                    'medium': '#ffcc00',
                    'low': '#44aa44'
                }.get(email_status, '#888888')
                
                # Professional email card layout
                with st.container():
                    st.markdown(f"""
                    <div style="border-left: 4px solid {risk_color}; padding: 12px; margin: 8px 0; background-color: #f8f9fa; border-radius: 4px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <div style="font-weight: bold; color: #333;">{risk_icon} {email_status.upper()} PRIORITY</div>
                            <div style="font-size: 0.9em; color: #666;">{time_sent}</div>
                        </div>
                        <div style="font-size: 1.1em; font-weight: 500; margin-bottom: 4px;">{subject_preview}</div>
                        <div style="color: #666; font-size: 0.9em;">
                            <strong>From:</strong> {sender_name} → <strong>To:</strong> {recipient_domain}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                
                # Pop-out window button for details
                col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
                
                # Create unique key using group name and email index
                unique_key = f"{group_name}_{i}_{hash(str(email))}"
                
                with col1:
                    with st.popover("📋 View Details", use_container_width=True):
                        show_email_details_modal(email)
                
                with col2:
                    # Status change dropdown
                    current_status = email.get('status', 'unclassified')
                    new_status = st.selectbox(
                        "Status:",
                        ["critical", "high", "medium", "low", "unclassified"],
                        index=["critical", "high", "medium", "low", "unclassified"].index(current_status.lower() if current_status.lower() in ["critical", "high", "medium", "low", "unclassified"] else "unclassified"),
                        key=f"reg_status_{unique_key}"
                    )
                    
                    if new_status != current_status.lower():
                        if st.button("Update", key=f"reg_update_{unique_key}", use_container_width=True):
                            # Update the email status in the data
                            for idx, data_email in enumerate(st.session_state.data):
                                if str(hash(str(data_email))) == str(hash(str(email))):
                                    st.session_state.data[idx]['status'] = new_status
                                    # Save updated data to persistence
                                    data_persistence = DataPersistence()
                                    data_persistence.save_daily_data(st.session_state.data)
                                    st.success(f"Status updated to {new_status.title()}")
                                    st.rerun()
                                    break
                
                with col3:
                    if st.button("✅ Clear", key=f"dashboard_clear_{unique_key}", type="secondary", use_container_width=True):
                        email_id = str(hash(str(email)))
                        st.session_state.completed_reviews[email_id] = {
                            'email': email,
                            'decision': 'clear',
                            'timestamp': datetime.now()
                        }
                        st.success("Email marked as cleared!")
                        st.rerun()
                
                with col4:
                    if st.button("🚨 Escalate", key=f"dashboard_escalate_{unique_key}", type="primary", use_container_width=True):
                        email_id = str(hash(str(email)))
                        st.session_state.escalated_records[email_id] = {
                            'email': email,
                            'decision': 'escalate',
                            'timestamp': datetime.now()
                        }
                        st.success("Email escalated for follow-up!")
                        st.rerun()
                
                
            
            if len(group_emails_sorted) > 15:
                remaining = len(group_emails_sorted) - 15
                st.info(f"📊 Showing top 15 priority emails. {remaining} additional emails available in this group.")



def email_check_completed_page():
    """Email Check Completed page"""
    st.title("✅ Email Check Completed")
    
    completed_reviews = st.session_state.completed_reviews
    
    if not completed_reviews:
        st.info("No completed reviews yet. Complete some reviews in the Security Operations Dashboard.")
        return
    
    st.markdown(f"**Total Completed Reviews:** {len(completed_reviews):,}")
    
    # Summary statistics
    st.subheader("Review Summary")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        cleared_count = sum(1 for review in completed_reviews.values() if review['decision'] == 'clear')
        st.metric("Cleared Emails", f"{cleared_count:,}")
    
    with col2:
        # Calculate average review time (mock data for demo)
        avg_time = "2.3 minutes"
        st.metric("Avg Review Time", avg_time)
    
    with col3:
        # Most recent review
        if completed_reviews:
            recent_review = max(completed_reviews.values(), key=lambda x: x['timestamp'])
            recent_time = recent_review['timestamp'].strftime("%H:%M")
            st.metric("Last Review", recent_time)
    
    # Completed reviews table
    st.subheader("Completed Reviews")
    
    # Filter options
    col1, col2 = st.columns(2)
    
    with col1:
        date_filter = st.date_input(
            "Filter by Date",
            value=datetime.now().date()
        )
    
    with col2:
        decision_filter = st.selectbox(
            "Filter by Decision",
            ["All", "Clear", "Escalate"]
        )
    
    # Display reviews
    filtered_reviews = []
    
    # Include completed reviews (cleared emails)
    for review_id, review in completed_reviews.items():
        # Apply filters
        if date_filter and review['timestamp'].date() != date_filter:
            continue
        
        if decision_filter != "All" and review['decision'] != decision_filter.lower():
            continue
        
        filtered_reviews.append((review_id, review))
    
    # Include escalated records when filtering by "Escalate"
    if decision_filter == "All" or decision_filter == "Escalate":
        escalated_records = st.session_state.escalated_records
        for record_id, record in escalated_records.items():
            # Apply date filter
            if date_filter and record['timestamp'].date() != date_filter:
                continue
            
            # Skip if filtering by "Clear" (escalated records are not cleared)
            if decision_filter == "Clear":
                continue
            
            # Add escalated record with consistent format
            escalated_review = {
                'email': record['email'],
                'decision': 'escalate',
                'timestamp': record['timestamp'],
                'followup_status': record.get('followup_status', 'pending'),
                'notes': record.get('notes', '')
            }
            filtered_reviews.append((record_id, escalated_review))
    
    if filtered_reviews:
        for review_id, review in filtered_reviews:
            email = review['email']
            decision = review['decision']
            timestamp = review['timestamp']
            
            # Add status indicator for escalated records
            status_indicator = ""
            if decision == 'escalate':
                followup_status = review.get('followup_status', 'pending')
                status_indicators = {
                    'pending': '🕐 Pending',
                    'in_progress': '⏳ In Progress', 
                    'completed': '✅ Completed'
                }
                status_indicator = f" - {status_indicators.get(followup_status, 'Unknown Status')}"
            
            # Handle both datetime objects and string timestamps
        if hasattr(timestamp, 'strftime'):
            timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M')
        else:
            # If it's already a string, use it as is
            timestamp_str = str(timestamp)
        
        with st.expander(f"📧 {email.get('subject', 'No Subject')[:50]}... - {decision.title()} ({timestamp_str}){status_indicator}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**From:** {email.get('sender', 'Unknown')}")
                    st.write(f"**To:** {email.get('recipients', 'Unknown')}")
                    st.write(f"**Domain:** {email.get('recipients_email_domain', 'Unknown')}")
                    st.write(f"**Status:** {get_risk_indicator(email.get('status', 'unknown'))} {email.get('status', 'Unknown').title()}")
                
                with col2:
                    st.write(f"**Decision:** {decision.title()}")
                    # Handle timestamp display
                    if hasattr(timestamp, 'strftime'):
                        review_time_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        review_time_str = str(timestamp)
                    st.write(f"**Review Time:** {review_time_str}")
                    st.write(f"**Reviewer:** Security Analyst")
                    st.write(f"**Department:** {email.get('department', 'Unknown')}")
                    
                    # Show additional info for escalated records
                    if decision == 'escalate':
                        st.write(f"**Follow-up Status:** {review.get('followup_status', 'pending').title()}")
                        if review.get('notes'):
                            st.write(f"**Notes:** {review.get('notes', '')}")
    else:
        st.info("No completed reviews match the selected filters.")
    
    # Export options
    st.subheader("Export Reports")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Export PDF Report"):
            if completed_reviews:
                report_generator = ReportGenerator()
                
                # Prepare data for report
                review_data = []
                for review_id, review in completed_reviews.items():
                    review_data.append({
                        **review['email'],
                        'decision': review['decision'],
                        'review_timestamp': review['timestamp'].isoformat()
                    })
                
                pdf_buffer = report_generator.generate_pdf_report(review_data, 'security_review')
                
                st.download_button(
                    label="Download PDF Report",
                    data=pdf_buffer.getvalue(),
                    file_name=f"security_review_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf"
                )
            else:
                st.error("No completed reviews to export.")
    
    with col2:
        if st.button("Export CSV Data"):
            if completed_reviews:
                # Create CSV data
                csv_data = []
                for review_id, review in completed_reviews.items():
                    csv_data.append({
                        'review_id': review_id,
                        'sender': review['email'].get('sender', ''),
                        'recipients': review['email'].get('recipients', ''),
                        'subject': review['email'].get('subject', ''),
                        'domain': review['email'].get('recipients_email_domain', ''),
                        'status': review['email'].get('status', ''),
                        'decision': review['decision'],
                        'timestamp': review['timestamp'].isoformat()
                    })
                
                # Convert to CSV
                output = io.StringIO()
                writer = csv.DictWriter(output, fieldnames=csv_data[0].keys())
                writer.writeheader()
                writer.writerows(csv_data)
                
                st.download_button(
                    label="Download CSV Data",
                    data=output.getvalue(),
                    file_name=f"completed_reviews_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
            else:
                st.error("No completed reviews to export.")

def followup_center_page():
    """Follow-up Center page"""
    st.title("📨 Follow-up Center")
    
    escalated_records = st.session_state.escalated_records
    
    if not escalated_records:
        st.info("No escalated records yet. Escalate some records in the Security Operations Dashboard.")
        return
    
    st.markdown(f"**Total Escalated Records:** {len(escalated_records):,}")
    
    # Follow-up status tracking
    st.subheader("Follow-up Status")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        pending_count = sum(1 for record in escalated_records.values() if record.get('followup_status', 'pending') == 'pending')
        st.metric("🕐 Pending", f"{pending_count:,}")
    
    with col2:
        in_progress_count = sum(1 for record in escalated_records.values() if record.get('followup_status', 'pending') == 'in_progress')
        st.metric("⏳ In Progress", f"{in_progress_count:,}")
    
    with col3:
        completed_count = sum(1 for record in escalated_records.values() if record.get('followup_status', 'pending') == 'completed')
        st.metric("✅ Completed", f"{completed_count:,}")
    
    # Escalated records management
    st.subheader("Escalated Records")
    
    for record_id, record in escalated_records.items():
        email = record['email']
        escalation_time = record['timestamp']
        followup_status = record.get('followup_status', 'pending')
        
        # Handle both datetime objects and string timestamps
        if hasattr(escalation_time, 'strftime'):
            escalation_time_str = escalation_time.strftime('%Y-%m-%d %H:%M')
        else:
            escalation_time_str = str(escalation_time)
        
        with st.expander(f"📧 {email.get('subject', 'No Subject')[:50]}... - {followup_status.title()}"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**From:** {email.get('sender', 'Unknown')}")
                st.write(f"**To:** {email.get('recipients', 'Unknown')}")
                st.write(f"**Domain:** {email.get('recipients_email_domain', 'Unknown')}")
                st.write(f"**Status:** {get_risk_indicator(email.get('status', 'unknown'))} {email.get('status', 'Unknown').title()}")
                st.write(f"**Escalated:** {escalation_time_str}")
            
            with col2:
                st.write(f"**Follow-up Status:** {followup_status.title()}")
                st.write(f"**Department:** {email.get('department', 'Unknown')}")
                st.write(f"**Business Unit:** {email.get('bunit', 'Unknown')}")
                st.write(f"**Account Type:** {email.get('account_type', 'Unknown')}")
            
            # Follow-up actions
            st.subheader("Follow-up Actions")
            
            # Add troubleshooting info
            with st.expander("📧 Email Client Help"):
                st.markdown("""
                **Multiple ways to send the security alert:**
                
                1. **Click "Open in Email Client"** - Opens your default email program
                2. **Use "Copy Template"** - Shows the full email to copy and paste
                3. **Use "Download .txt"** - Downloads a text file you can open and copy from
                
                **Troubleshooting email links:**
                
                - **Chrome/Edge**: Right-click link → "Copy link address" → paste in browser
                - **Outlook Web**: Make sure you're logged into Office 365 in your browser
                - **Desktop Outlook**: Set as default email app in Windows settings
                - **Gmail**: Use Gmail's compose window and paste the template
                - **Mac Mail**: Set as default in System Preferences
                
                **Still not working?** Use the "Copy Template" button and manually paste into any email client.
                """)
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                if st.button("Generate Email Template", key=f"email_{record_id}"):
                    # Store the generated template in session state for editing
                    if f"template_content_{record_id}" not in st.session_state:
                        st.session_state[f"template_content_{record_id}"] = generate_followup_email(email)
                    
                    # Get current template content (editable)
                    template = st.session_state[f"template_content_{record_id}"]
                    
                    # Email preview and editing section
                    st.subheader("📧 Email Preview & Editor")
                    
                    # Email subject line (editable)
                    subject = st.text_input(
                        "Subject Line:",
                        value=f"Security Alert - {email.get('subject', 'Email Security Issue')}",
                        key=f"subject_{record_id}"
                    )
                    
                    # Recipient (editable)
                    sender_email = st.text_input(
                        "To:",
                        value=email.get('sender', ''),
                        key=f"recipient_{record_id}"
                    )
                    
                    # Email body (editable)
                    edited_template = st.text_area(
                        "Email Content (Edit as needed):",
                        value=template,
                        height=300,
                        key=f"template_{record_id}",
                        help="You can modify the email content before sending"
                    )
                    
                    # Update session state with edited content
                    st.session_state[f"template_content_{record_id}"] = edited_template
                    
                    # Preview styled email
                    with st.expander("📋 Formatted Email Preview", expanded=False):
                        st.markdown("**Preview of how the email will look:**")
                        st.markdown(f"**To:** {sender_email}")
                        st.markdown(f"**Subject:** {subject}")
                        st.markdown("**Body:**")
                        st.markdown(f"```\n{edited_template}\n```")
                    
                    # Validation
                    if not sender_email or not sender_email.strip():
                        st.error("Please enter a recipient email address")
                    elif not subject or not subject.strip():
                        st.error("Please enter a subject line")
                    elif not edited_template or not edited_template.strip():
                        st.error("Please enter email content")
                    else:
                        # Action buttons for the finalized email
                        st.markdown("### 🚀 Send Email")
                        
                        col_send1, col_send2, col_send3 = st.columns([2, 1, 1])
                        
                        with col_send1:
                            # Use the new working mailto function
                            mailto_link = create_outlook_mailto_link(email, edited_template, subject)
                            
                            # Better styled button with proper mailto link
                            st.markdown(f"""
                            <a href="{mailto_link}" target="_blank" style="
                                display: inline-block;
                                padding: 8px 16px;
                                background-color: #0078d4;
                                color: white;
                                text-decoration: none;
                                border-radius: 4px;
                                font-weight: bold;
                                width: 100%;
                                text-align: center;
                                margin-bottom: 8px;
                            ">🚀 Click to Open in Email Client</a>
                            """, unsafe_allow_html=True)
                            
                            st.success("✅ Email ready!")
                            st.info("💡 Click the blue link above to open your email client.")
                            
                            # Fallback copy button
                            if st.button("📋 Copy Email Template", key=f"copy_email_{record_id}", use_container_width=True):
                                email_text = f"""To: {sender_email}
Subject: {subject}

{edited_template}"""
                                st.text_area(
                                    "Copy this email content:",
                                    value=email_text,
                                    height=200,
                                    key=f"copyable_email_{record_id}"
                                )
                                st.info("Copy the above text and paste it into your email client manually.")
                        
                        with col_send2:
                            # Reset/regenerate template
                            if st.button("🔄 Reset Template", key=f"reset_{record_id}", use_container_width=True):
                                # Clear the stored template to regenerate
                                if f"template_content_{record_id}" in st.session_state:
                                    del st.session_state[f"template_content_{record_id}"]
                                st.success("Template reset! Click 'Generate Email Template' to create a new one.")
                                st.rerun()
                        
                        with col_send3:
                            # Save as draft option
                            if st.button("💾 Save Draft", key=f"save_draft_{record_id}", use_container_width=True):
                                # Store the draft in session state
                                draft_key = f"email_draft_{record_id}"
                                st.session_state[draft_key] = {
                                    'to': sender_email,
                                    'subject': subject,
                                    'body': edited_template,
                                    'saved_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                }
                                st.success("Draft saved! You can continue editing later.")
                        
                        # Show saved draft info if exists
                        draft_key = f"email_draft_{record_id}"
                        if draft_key in st.session_state:
                            draft = st.session_state[draft_key]
                            st.info(f"💾 Draft saved at {draft['saved_at']}")
                            
                            if st.button("🗑️ Delete Draft", key=f"delete_draft_{record_id}"):
                                del st.session_state[draft_key]
                                st.success("Draft deleted!")
                                st.rerun()

            
            with col2:
                new_status = st.selectbox(
                    "Update Status",
                    ["pending", "in_progress", "completed"],
                    index=["pending", "in_progress", "completed"].index(followup_status),
                    key=f"status_{record_id}"
                )
                
                if st.button("Update Status", key=f"update_{record_id}"):
                    st.session_state.escalated_records[record_id]['followup_status'] = new_status
                    st.success(f"Status updated to {new_status.title()}")
                    st.rerun()
            
            with col3:
                notes = st.text_area(
                    "Follow-up Notes",
                    value=record.get('notes', ''),
                    key=f"notes_{record_id}"
                )
                
                if st.button("Save Notes", key=f"save_{record_id}"):
                    st.session_state.escalated_records[record_id]['notes'] = notes
                    st.success("Notes saved!")
                    st.rerun()

def create_outlook_mailto_link(email_data, email_template, subject_line):
    """Create a mailto link that opens in Outlook with the generated email"""
    import urllib.parse
    
    # Extract email details
    to_email = email_data.get('sender', '')  # Who you're sending to
    email_subject = subject_line             # Email subject
    email_body = email_template              # Email content
    
    # URL encode the parameters (important for special characters)
    subject_encoded = urllib.parse.quote(email_subject)
    body_encoded = urllib.parse.quote(email_body)
    to_encoded = urllib.parse.quote(to_email)
    
    # Create the mailto link
    mailto_link = f"mailto:{to_encoded}?subject={subject_encoded}&body={body_encoded}"
    
    return mailto_link

def generate_followup_email(email):
    """Generate follow-up email template"""
    # Create clean, professional email content
    sender_name = email.get('sender', 'Team Member').split('@')[0].replace('.', ' ').title()
    subject = email.get('subject', 'No Subject')
    recipient = email.get('recipients', 'Unknown')
    domain = email.get('recipients_email_domain', 'Unknown')
    risk_level = email.get('status', 'Unknown').title()
    date_sent = email.get('_time', 'Unknown')
    
    # Format attachment information
    attachment_info = email.get('attachments', '')
    if attachment_info and attachment_info not in [True, False, 'True', 'False']:
        attachment_text = f"Yes - {attachment_info}"
    elif attachment_info:
        attachment_text = "Yes"
    else:
        attachment_text = "No"
    
    template = f"""SECURITY ALERT - Email Review Required

Dear {sender_name},

We received an alert regarding the file you recently emailed (details below). To help us complete our review, could you please provide some additional context?

In particular, we'd appreciate it if you could confirm:

• Whether the file contains any Investec intellectual property (IP)

• If this activity is part of an approved business process

Your input is important and will help us ensure everything is in line with our data protection policies. Please feel free to reach out if you have any questions.

EMAIL DETAILS:
===============================================
From:               {email.get('sender', 'Unknown')}
To:                 {recipient}
Subject:            {subject}
Date Sent:          {date_sent}
Attachments:        {attachment_text}
==============================================="""
    
    return template

def network_analysis_page():
    """Advanced Network Analysis page with enhanced interactivity and visualization"""
    st.markdown("""
    <div class="data-container">
        <h2 style="color: #2c3e50; margin-bottom: 1rem;">🔗 Advanced Network Analysis</h2>
        <p style="color: #7f8c8d; font-size: 1.1rem; margin-bottom: 1.5rem;">
            Discover hidden patterns, identify key players, and analyze communication flows using 
            state-of-the-art network visualization and analysis techniques with advanced interactive features.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    if not st.session_state.data:
        st.markdown("""
        <div class="alert alert-warning">
            <strong>⚠️ No Data Available</strong><br>
            Please upload data first in the Data Upload & Preprocessing section to begin network analysis.
        </div>
        """, unsafe_allow_html=True)
        return
    
    data = st.session_state.data
    
    # Enhanced Network Configuration with Professional Styling
    st.markdown("""
    <div class="data-container">
        <h3 style="color: #2c3e50; margin-bottom: 1rem;">🛠️ Advanced Network Configuration</h3>
        <p style="color: #7f8c8d; margin-bottom: 1rem;">Configure network parameters for optimal visualization and analysis</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        source_field = st.selectbox(
            "🎯 Source Field",
            ["sender", "recipients", "recipients_email_domain"],
            index=0,
            help="Choose what represents the source of communication"
        )
    
    with col2:
        target_field = st.selectbox(
            "🎯 Target Field",
            ["recipients", "recipients_email_domain", "sender"],
            index=0,
            help="Choose what represents the target of communication"
        )
    
    with col3:
        layout_type = st.selectbox(
            "🎨 Layout Algorithm",
            ["spring", "force_directed", "hierarchical", "kamada_kawai", "circular", "spectral", "fruchterman_reingold"],
            index=0,
            help="Different algorithms create different visual patterns"
        )
    
    with col4:
        visualization_style = st.selectbox(
            "🎭 Visualization Style",
            ["Risk-Based", "Centrality-Based", "Community-Based", "Standard"],
            index=0,
            help="How to color and style nodes and edges"
        )
    
    # Algorithm explanation in expander
    with st.expander("ℹ️ Layout Algorithm Guide"):
        st.markdown("""
        **Layout Algorithms Explained:**
        - **Spring**: General purpose, nodes repel each other naturally
        - **Force-Directed**: Enhanced spring with weighted edges for better positioning
        - **Hierarchical**: Shows organizational structure and communication levels
        - **Kamada-Kawai**: High quality layout for small-medium networks
        - **Circular**: Nodes arranged in a circle, good for symmetrical analysis
        - **Spectral**: Uses graph's mathematical properties for positioning
        - **Fruchterman-Reingold**: Balanced force-directed algorithm
        """)
    
    # Advanced Filters with Professional Styling
    st.markdown("""
    <div class="data-container">
        <h3 style="color: #2c3e50; margin-bottom: 1rem;">🔍 Advanced Filtering & Display Options</h3>
        <p style="color: #7f8c8d; margin-bottom: 1rem;">Fine-tune your network analysis with advanced filtering and visualization options</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        min_connections = st.slider(
            "⚖️ Minimum Connections",
            min_value=1,
            max_value=50,
            value=2,
            help="Filter out nodes with fewer connections"
        )
    
    with col2:
        status_filter = st.multiselect(
            "🚨 Risk Status Filter",
            ["critical", "high", "medium", "low", "unclassified"],
            default=["critical", "high", "medium", "low"],
            help="Include emails with these risk levels"
        )
    
    with col3:
        max_nodes = st.slider(
            "🎯 Maximum Nodes",
            min_value=10,
            max_value=500,
            value=100,
            help="Limit nodes for better performance"
        )
    
    with col4:
        node_size_metric = st.selectbox(
            "📏 Node Size Based On",
            ["Email Volume", "Risk Level", "Centrality", "Uniform"],
            help="How to size nodes in the visualization"
        )
    
    # Additional advanced options
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        show_risk_edges = st.checkbox(
            "🎨 Color Edges by Risk",
            value=True,
            help="Color edges based on risk level"
        )
    
    with col2:
        show_node_labels = st.checkbox(
            "🏷️ Show Node Labels",
            value=True,
            help="Display node labels on the network"
        )
    
    with col3:
        enable_physics = st.checkbox(
            "⚡ Enable Physics",
            value=False,
            help="Enable interactive physics simulation"
        )
    
    with col4:
        highlight_communities = st.checkbox(
            "👥 Highlight Communities",
            value=False,
            help="Automatically detect and highlight communities"
        )
    
    # Filter data
    filtered_data = [
        email for email in data 
        if email.get('status', '').lower() in status_filter
    ]
    
    if not filtered_data:
        st.error("No data matches the selected filters.")
        return
    
    # Generate network with enhanced options
    col1, col2 = st.columns([2, 1])
    
    with col1:
        generate_btn = st.button("🚀 Generate Enhanced Network", type="primary", use_container_width=True)
    
    with col2:
        if st.button("🔄 Regenerate", use_container_width=True):
            # Clear cached graphs
            keys_to_remove = [k for k in st.session_state.keys() if k.startswith('network_graph_') or k.startswith('graph_data_')]
            for key in keys_to_remove:
                del st.session_state[key]
            st.rerun()
    
    if generate_btn or f'network_graph_enhanced' in st.session_state:
        
        # Create progress indicator
        progress_container = st.container()
        
        with progress_container:
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            status_text.text("🔧 Initializing network analyzer...")
            progress_bar.progress(10)
            
            analyzer = NetworkAnalyzer()
            
            config = {
                'layout': layout_type,
                'min_connections': min_connections,
                'max_nodes': max_nodes,
                'show_risk_edges': show_risk_edges
            }
            
            status_text.text("📊 Building network graph...")
            progress_bar.progress(30)
            
            # Generate or retrieve network graph
            if generate_btn or f'network_graph_enhanced' not in st.session_state:
                fig = analyzer.create_network_graph(filtered_data, source_field, target_field, config)
                if fig:
                    st.session_state['network_graph_enhanced'] = fig
                    st.session_state['graph_data_enhanced'] = getattr(fig, '_graph_data', None)
            
            status_text.text("🎨 Rendering visualization...")
            progress_bar.progress(70)
            
            fig = st.session_state.get('network_graph_enhanced')
            graph_data = st.session_state.get('graph_data_enhanced')
            
            progress_bar.progress(100)
            status_text.text("✅ Network analysis complete!")
            
            # Clear progress after a moment
            import time
            time.sleep(1)
            progress_container.empty()
        
        if fig and graph_data:
            
            # Main network visualization
            st.subheader("📊 Interactive Network Visualization")
            
            # Display the enhanced network
            st.plotly_chart(fig, use_container_width=True, key="enhanced_network_graph")
            
            # Interactive controls section
            st.subheader("🎮 Interactive Analysis Controls")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("**📍 Node Selection**")
                if 'graph' in graph_data:
                    G = graph_data['graph']
                    nodes_list = sorted(list(G.nodes()))
                    selected_node = st.selectbox(
                        "Analyze Node:",
                        options=["None"] + nodes_list,
                        key="enhanced_node_selector"
                    )
                else:
                    selected_node = None
            
            with col2:
                st.markdown("**🔍 Analysis Mode**")
                analysis_mode = st.radio(
                    "Choose analysis:",
                    ["Overview", "Centrality", "Risk Analysis", "Communities"],
                    key="analysis_mode"
                )
            
            with col3:
                st.markdown("**📋 Export Options**")
                if st.button("📊 Export Network Stats"):
                    if 'graph' in graph_data:
                        stats = analyzer.get_network_statistics(graph_data['graph'])
                        st.json(stats)
                
                if st.button("💾 Download Graph Data"):
                    # Create downloadable network data
                    network_data = {
                        'nodes': list(graph_data['graph'].nodes()) if 'graph' in graph_data else [],
                        'edges': list(graph_data['graph'].edges()) if 'graph' in graph_data else [],
                        'config': config
                    }
                    st.download_button(
                        "Download JSON",
                        data=json.dumps(network_data, indent=2),
                        file_name=f"network_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
            
            # Analysis results based on mode
            if analysis_mode == "Overview" and 'graph' in graph_data:
                st.subheader("📈 Network Overview")
                
                G = graph_data['graph']
                stats = analyzer.get_network_statistics(G)
                
                # Basic statistics
                col1, col2, col3, col4, col5 = st.columns(5)
                
                with col1:
                    st.metric("🔗 Nodes", stats['basic']['nodes'])
                
                with col2:
                    st.metric("📧 Connections", stats['basic']['edges'])
                
                with col3:
                    st.metric("🌐 Density", f"{stats['basic']['density']:.4f}")
                
                with col4:
                    st.metric("🔄 Connected", "✅" if stats['basic']['is_connected'] else "❌")
                
                with col5:
                    avg_clustering = stats['clustering'].get('average_clustering', 0)
                    st.metric("🎯 Clustering", f"{avg_clustering:.3f}")
                
                # Visual network summary
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("**🏆 Top Nodes by Degree**")
                    for i, (node, centrality) in enumerate(stats['top_nodes']['by_degree'][:5]):
                        st.write(f"{i+1}. `{node[:30]}...` - {centrality:.3f}")
                
                with col2:
                    st.markdown("**🌉 Top Nodes by Betweenness**")
                    for i, (node, centrality) in enumerate(stats['top_nodes']['by_betweenness'][:5]):
                        st.write(f"{i+1}. `{node[:30]}...` - {centrality:.3f}")
            
            elif analysis_mode == "Centrality" and 'graph' in graph_data:
                st.subheader("📊 Centrality Analysis")
                
                G = graph_data['graph']
                stats = analyzer.get_network_statistics(G)
                
                # Create centrality comparison chart
                centrality_data = []
                for node in list(G.nodes())[:20]:  # Top 20 nodes
                    centrality_data.append({
                        'Node': node[:20] + "..." if len(node) > 20 else node,
                        'Degree': stats['centrality']['degree'].get(node, 0),
                        'Betweenness': stats['centrality']['betweenness'].get(node, 0),
                        'Closeness': stats['centrality']['closeness'].get(node, 0),
                        'Eigenvector': stats['centrality']['eigenvector'].get(node, 0)
                    })
                
                # Create comparative bar chart
                import pandas as pd
                df = pd.DataFrame(centrality_data)
                
                # Normalize values for comparison
                for col in ['Degree', 'Betweenness', 'Closeness', 'Eigenvector']:
                    if df[col].max() > 0:
                        df[f'{col}_norm'] = df[col] / df[col].max()
                
                fig_centrality = px.bar(
                    df.head(10), 
                    x='Node', 
                    y=['Degree', 'Betweenness', 'Closeness', 'Eigenvector'],
                    title="Centrality Measures Comparison (Top 10 Nodes)",
                    barmode='group'
                )
                fig_centrality.update_xaxes(tickangle=45)
                st.plotly_chart(fig_centrality, use_container_width=True)
            
            elif analysis_mode == "Risk Analysis" and 'graph' in graph_data:
                st.markdown("""
                <div class="data-container">
                    <h3 style="color: #2c3e50; margin-bottom: 1rem;">⚠️ Advanced Risk Analysis</h3>
                    <p style="color: #7f8c8d; margin-bottom: 1rem;">Comprehensive risk assessment of network communications</p>
                </div>
                """, unsafe_allow_html=True)
                
                G = graph_data['graph']
                
                # Enhanced risk distribution analysis
                risk_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unclassified': 0}
                total_emails = 0
                high_risk_nodes = set()
                high_risk_edges = []
                
                for edge in G.edges():
                    edge_data = G[edge[0]][edge[1]]
                    risk_levels = edge_data.get('risk_levels', [])
                    total_emails += edge_data.get('weight', 1)
                    
                    for risk in risk_levels:
                        risk_lower = risk.lower()
                        if risk_lower in risk_stats:
                            risk_stats[risk_lower] += 1
                        
                        # Track high-risk nodes and edges
                        if risk_lower in ['critical', 'high']:
                            high_risk_nodes.add(edge[0])
                            high_risk_nodes.add(edge[1])
                            high_risk_edges.append((edge[0], edge[1], risk_lower))
                
                # Risk visualization with enhanced metrics
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    fig_risk = px.pie(
                        values=list(risk_stats.values()),
                        names=list(risk_stats.keys()),
                        title="Risk Level Distribution",
                        color_discrete_map={
                            'critical': '#DC143C',
                            'high': '#FF6347',
                            'medium': '#FFD700',
                            'low': '#32CD32',
                            'unclassified': '#708090'
                        }
                    )
                    fig_risk.update_traces(textposition='inside', textinfo='percent+label')
                    st.plotly_chart(fig_risk, use_container_width=True)
                
                with col2:
                    st.markdown("**🚨 Risk Summary**")
                    st.metric("Total Emails", f"{total_emails:,}")
                    st.metric("High Risk Connections", risk_stats['critical'] + risk_stats['high'])
                    st.metric("High Risk Nodes", len(high_risk_nodes))
                    risk_ratio = ((risk_stats['critical'] + risk_stats['high']) / max(sum(risk_stats.values()), 1) * 100)
                    st.metric("Risk Ratio", f"{risk_ratio:.1f}%")
                
                with col3:
                    st.markdown("**🎯 Risk Insights**")
                    if risk_stats['critical'] > 0:
                        st.error(f"⚠️ {risk_stats['critical']} critical risk connections found!")
                    elif risk_stats['high'] > 0:
                        st.warning(f"🔶 {risk_stats['high']} high risk connections found!")
                    else:
                        st.success("✅ No critical risk connections detected!")
                    
                    # Additional risk metrics
                    if len(high_risk_nodes) > 0:
                        st.info(f"📊 {len(high_risk_nodes)} nodes involved in high-risk communications")
                
                # High-risk connections details
                if high_risk_edges:
                    st.markdown("**🔥 High-Risk Connections**")
                    for i, (source, target, risk_level) in enumerate(high_risk_edges[:10]):
                        risk_color = "🔴" if risk_level == 'critical' else "🟠"
                        st.write(f"{risk_color} **{source}** → **{target}** ({risk_level.upper()})")
                    
                    if len(high_risk_edges) > 10:
                        st.caption(f"... and {len(high_risk_edges) - 10} more high-risk connections")
            
            elif analysis_mode == "Path Analysis" and 'graph' in graph_data:
                st.markdown("""
                <div class="data-container">
                    <h3 style="color: #2c3e50; margin-bottom: 1rem;">🛤️ Path Analysis</h3>
                    <p style="color: #7f8c8d; margin-bottom: 1rem;">Analyze communication paths and shortest routes between nodes</p>
                </div>
                """, unsafe_allow_html=True)
                
                G = graph_data['graph']
                nodes = list(G.nodes())
                
                col1, col2 = st.columns(2)
                
                with col1:
                    source_node = st.selectbox(
                        "Source Node",
                        nodes,
                        key="path_source"
                    )
                
                with col2:
                    target_node = st.selectbox(
                        "Target Node", 
                        nodes,
                        key="path_target"
                    )
                
                if source_node and target_node and source_node != target_node:
                    try:
                        if nx.has_path(G, source_node, target_node):
                            shortest_path = nx.shortest_path(G, source_node, target_node)
                            path_length = len(shortest_path) - 1
                            
                            st.success(f"✅ Path found! Length: {path_length} hops")
                            
                            # Display path
                            st.markdown("**🛣️ Shortest Path:**")
                            path_display = " → ".join([f"`{node[:30]}...`" if len(node) > 30 else f"`{node}`" for node in shortest_path])
                            st.markdown(path_display)
                            
                            # Path risk analysis
                            path_risks = []
                            for i in range(len(shortest_path) - 1):
                                edge_data = G[shortest_path[i]][shortest_path[i+1]]
                                path_risks.extend(edge_data.get('risk_levels', []))
                            
                            if path_risks:
                                risk_counts = {risk: path_risks.count(risk) for risk in set(path_risks)}
                                st.markdown("**⚠️ Path Risk Analysis:**")
                                for risk, count in risk_counts.items():
                                    risk_color = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(risk, "⚪")
                                    st.write(f"{risk_color} {risk.title()}: {count} connections")
                        else:
                            st.error("❌ No path found between selected nodes")
                    except Exception as e:
                        st.error(f"❌ Error analyzing path: {str(e)}")
                
                # Additional path insights
                st.markdown("**🔍 Path Insights**")
                
                # Most central nodes (potential communication hubs)
                centrality = nx.betweenness_centrality(G)
                top_central = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:5]
                
                st.markdown("**🌟 Communication Hubs (High Betweenness Centrality):**")
                for node, score in top_central:
                    st.write(f"• `{node[:40]}...` - Score: {score:.4f}")
                
                # Network diameter
                try:
                    if nx.is_strongly_connected(G):
                        diameter = nx.diameter(G)
                        st.metric("Network Diameter", f"{diameter} hops")
                    else:
                        st.info("Network is not strongly connected - calculating largest component diameter")
                        largest_cc = max(nx.strongly_connected_components(G), key=len)
                        subgraph = G.subgraph(largest_cc)
                        diameter = nx.diameter(subgraph)
                        st.metric("Largest Component Diameter", f"{diameter} hops")
                except:
                    st.info("Unable to calculate network diameter")
            
            elif analysis_mode == "Communities" and 'graph' in graph_data:
                st.subheader("👥 Community Detection")
                
                G = graph_data['graph']
                
                try:
                    import networkx.algorithms.community as nx_comm
                    communities = list(nx_comm.greedy_modularity_communities(G.to_undirected()))
                    
                    st.write(f"**🏘️ Detected {len(communities)} communities**")
                    
                    # Community size distribution
                    community_sizes = [len(community) for community in communities]
                    
                    fig_communities = px.bar(
                        x=[f"Community {i+1}" for i in range(len(community_sizes))],
                        y=community_sizes,
                        title="Community Size Distribution",
                        labels={'x': 'Community', 'y': 'Number of Nodes'}
                    )
                    st.plotly_chart(fig_communities, use_container_width=True)
                    
                    # Show community details
                    for i, community in enumerate(communities[:5]):  # Show first 5
                        with st.expander(f"👥 Community {i+1} ({len(community)} members)"):
                            members = list(community)[:20]  # Show first 20 members
                            st.write("**Members:**")
                            for j, member in enumerate(members):
                                st.write(f"{j+1}. {member}")
                            if len(community) > 20:
                                st.caption(f"... and {len(community) - 20} more members")
                
                except ImportError:
                    st.warning("Community detection requires additional packages. Using basic clustering analysis.")
                    
                    # Fallback to degree-based clustering
                    degree_dict = dict(G.degree())
                    high_degree_nodes = [node for node, degree in degree_dict.items() if degree > np.mean(list(degree_dict.values()))]
                    
                    st.write(f"**📈 High-connectivity cluster: {len(high_degree_nodes)} nodes**")
                    for node in high_degree_nodes[:10]:
                        st.write(f"• {node} (degree: {degree_dict[node]})")
            
            # Node-specific analysis
            if selected_node and selected_node != "None" and 'graph' in graph_data:
                st.subheader(f"🔍 Detailed Analysis: {selected_node}")
                
                G = graph_data['graph']
                connections = analyzer.analyze_node_connections(selected_node, G)
                
                if connections:
                    # Connection overview
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.metric("📥 Incoming", connections['total_incoming'])
                    
                    with col2:
                        st.metric("📤 Outgoing", connections['total_outgoing'])
                    
                    with col3:
                        st.metric("🔗 Total", connections['total_connections'])
                    
                    # Detailed connection analysis
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("**📥 Incoming Emails**")
                        for conn in connections['incoming'][:10]:
                            risk_color = "🔴" if 'critical' in conn['risk_levels'] else "🟠" if 'high' in conn['risk_levels'] else "🟡" if 'medium' in conn['risk_levels'] else "🟢"
                            st.write(f"{risk_color} **{conn['from']}** ({conn['weight']} emails)")
                            if conn['attachments'] > 0:
                                st.caption(f"   📎 {conn['attachments']} attachments")
                    
                    with col2:
                        st.markdown("**📤 Outgoing Emails**")
                        for conn in connections['outgoing'][:10]:
                            risk_color = "🔴" if 'critical' in conn['risk_levels'] else "🟠" if 'high' in conn['risk_levels'] else "🟡" if 'medium' in conn['risk_levels'] else "🟢"
                            st.write(f"{risk_color} **{conn['to']}** ({conn['weight']} emails)")
                            if conn['attachments'] > 0:
                                st.caption(f"   📎 {conn['attachments']} attachments")
        
        else:
            st.error("❌ Unable to generate network graph. Please check your data and filters.")
    
    else:
        st.info("👆 Click 'Generate Enhanced Network' to start the analysis!")

def suspicious_email_analysis_page():
    """Suspicious Email Analysis page for Medium Low and unclassified emails"""
    st.markdown("""
    <div class="data-container">
        <h2 style="color: #2c3e50; margin-bottom: 1rem;">🔍 Suspicious Email Analysis</h2>
        <p style="color: #7f8c8d; font-size: 1.1rem; margin-bottom: 1.5rem;">
            AI-powered analysis to identify suspicious patterns in Medium Low and unclassified emails. 
            This tool filters through your data to show only the emails that need your attention.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    if not st.session_state.data:
        st.markdown("""
        <div class="alert-card">
            <div class="alert-icon">📤</div>
            <div class="alert-content">
                <h3>No Data Available</h3>
                <p>Please upload your email data first using the Data Upload & Preprocessing page.</p>
            </div>
        </div>
        """, unsafe_allow_html=True)
        return
    
    # Initialize the suspicious email detector
    detector = SuspiciousEmailDetector()
    
    # Analysis controls
    st.markdown("### 🎯 Analysis Controls")
    col1, col2, col3 = st.columns([2, 2, 2])
    
    with col1:
        min_suspicion_score = st.slider(
            "Minimum Suspicion Score",
            min_value=0.0,
            max_value=1.0,
            value=0.5,
            step=0.05,
            help="Show only emails with suspicion score above this threshold"
        )
    
    with col2:
        max_results = st.selectbox(
            "Maximum Results to Show",
            options=[10, 25, 50, 100, 200],
            index=1,
            help="Limit the number of results to focus on the most suspicious emails"
        )
    
    with col3:
        status_filter = st.multiselect(
            "Status Filter",
            options=['medium', 'low', 'unclassified'],
            default=['medium', 'low', 'unclassified'],
            help="Select which status levels to analyze"
        )
    
    # Run analysis button
    if st.button("🔍 Run Suspicious Email Analysis", use_container_width=True):
        with st.spinner("Analyzing emails for suspicious patterns..."):
            # Filter data based on status selection
            filtered_data = []
            for email in st.session_state.data:
                email_status = email.get('status', '').lower().strip()
                if email_status in status_filter or (not email_status and 'unclassified' in status_filter):
                    filtered_data.append(email)
            
            if not filtered_data:
                st.warning("No emails found matching the selected status criteria.")
                return
            
            # Run the suspicious email detection
            suspicious_emails = detector.identify_suspicious_emails(filtered_data)
            
            # Filter by minimum suspicion score
            filtered_suspicious = [
                email for email in suspicious_emails 
                if email['suspicion_score'] >= min_suspicion_score
            ]
            
            # Limit results
            final_results = filtered_suspicious[:max_results]
            
            # Store results in session state
            st.session_state.suspicious_analysis_results = final_results
            st.session_state.suspicious_analysis_summary = {
                'total_emails_analyzed': len(filtered_data),
                'suspicious_emails_found': len(suspicious_emails),
                'emails_above_threshold': len(filtered_suspicious),
                'emails_displayed': len(final_results)
            }
    
    # Display results if available
    if hasattr(st.session_state, 'suspicious_analysis_results') and st.session_state.suspicious_analysis_results:
        results = st.session_state.suspicious_analysis_results
        summary = st.session_state.suspicious_analysis_summary
        
        # Summary statistics
        st.markdown("### 📊 Analysis Summary")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Emails Analyzed", summary['total_emails_analyzed'])
        with col2:
            st.metric("Suspicious Emails Found", summary['suspicious_emails_found'])
        with col3:
            st.metric("Above Threshold", summary['emails_above_threshold'])
        with col4:
            st.metric("Displayed", summary['emails_displayed'])
        
        # Suspicion score distribution
        st.markdown("### 📈 Suspicion Score Distribution")
        scores = [result['suspicion_score'] for result in results]
        
        if scores:
            fig = px.histogram(
                x=scores,
                nbins=20,
                title="Distribution of Suspicion Scores",
                labels={'x': 'Suspicion Score', 'y': 'Number of Emails'},
                color_discrete_sequence=['#e74c3c']
            )
            fig.update_layout(
                showlegend=False,
                height=300,
                margin=dict(l=0, r=0, t=40, b=0)
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Detailed results
        st.markdown("### 🚨 Suspicious Emails Details")
        
        for i, result in enumerate(results, 1):
            email = result['email']
            score = result['suspicion_score']
            reasons = result['reasons']
            
            # Color-code based on suspicion score
            if score >= 0.8:
                card_color = "#e74c3c"  # Red
                risk_level = "HIGH RISK"
            elif score >= 0.6:
                card_color = "#f39c12"  # Orange
                risk_level = "MEDIUM RISK"
            else:
                card_color = "#f1c40f"  # Yellow
                risk_level = "LOW RISK"
            
            with st.expander(f"#{i} - {email.get('subject', 'No Subject')[:50]}... - Score: {score:.2f} ({risk_level})", expanded=False):
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown("**📧 Email Details:**")
                    st.write(f"**From:** {email.get('sender', 'Unknown')}")
                    st.write(f"**To:** {email.get('recipients', 'Unknown')}")
                    st.write(f"**Subject:** {email.get('subject', 'No Subject')}")
                    st.write(f"**Domain:** {email.get('recipients_email_domain', 'Unknown')}")
                    st.write(f"**Status:** {email.get('status', 'Unclassified').title()}")
                    st.write(f"**Time:** {email.get('_time', 'Unknown')}")
                    
                    if email.get('attachments'):
                        st.write(f"**Attachments:** {email.get('attachments', 'None')}")
                
                with col2:
                    st.markdown("**🔍 Suspicion Analysis:**")
                    st.metric("Suspicion Score", f"{score:.2f}")
                    st.markdown("**Reasons:**")
                    for reason in reasons:
                        st.write(f"• {reason}")
                
                # Action buttons
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if st.button("✅ Mark as Safe", key=f"safe_{i}"):
                        # Update email status to low
                        for original_email in st.session_state.data:
                            if (original_email.get('sender') == email.get('sender') and 
                                original_email.get('subject') == email.get('subject')):
                                original_email['status'] = 'Low'
                                break
                        st.success("Email marked as safe!")
                        st.rerun()
                
                with col2:
                    if st.button("⚠️ Escalate", key=f"escalate_{i}"):
                        # Add to escalated records
                        if 'escalated_records' not in st.session_state:
                            st.session_state.escalated_records = {}
                        
                        record_id = f"susp_{i}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                        st.session_state.escalated_records[record_id] = {
                            'email': email,
                            'escalated_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'escalated_by': 'Suspicious Email Analysis',
                            'followup_status': 'pending',
                            'suspicion_score': score,
                            'suspicion_reasons': reasons
                        }
                        st.success("Email escalated for follow-up!")
                        st.rerun()
                
                with col3:
                    if st.button("📋 View Details", key=f"details_{i}"):
                        show_email_details_modal(email)
        
        # Export functionality
        st.markdown("### 💾 Export Results")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📊 Export to CSV", use_container_width=True):
                # Create CSV data
                csv_data = []
                for result in results:
                    email = result['email']
                    csv_data.append({
                        'Sender': email.get('sender', ''),
                        'Recipients': email.get('recipients', ''),
                        'Subject': email.get('subject', ''),
                        'Status': email.get('status', ''),
                        'Domain': email.get('recipients_email_domain', ''),
                        'Suspicion_Score': result['suspicion_score'],
                        'Reasons': '; '.join(result['reasons']),
                        'Time': email.get('_time', '')
                    })
                
                # Convert to CSV
                import pandas as pd
                df = pd.DataFrame(csv_data)
                csv_string = df.to_csv(index=False)
                
                st.download_button(
                    label="Download CSV",
                    data=csv_string,
                    file_name=f"suspicious_emails_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        with col2:
            if st.button("📄 Generate Report", use_container_width=True):
                # Generate a summary report
                report_data = {
                    'analysis_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'summary': summary,
                    'suspicious_emails': results
                }
                
                report_generator = ReportGenerator()
                pdf_buffer = report_generator.generate_pdf_report(report_data, 'suspicious_email_analysis')
                
                st.download_button(
                    label="Download PDF Report",
                    data=pdf_buffer,
                    file_name=f"suspicious_email_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf"
                )
    
    else:
        st.info("Click 'Run Suspicious Email Analysis' to identify suspicious patterns in your email data.")

def domain_classification_page():
    """Domain Classification page"""
    st.title("🌐 Domain Classification")
    
    domain_classifier = st.session_state.domain_classifier
    
    st.markdown("""
    Manage and analyze domain classifications for recipient email domains.
    Classify domains into categories and maintain threat intelligence.
    """)
    
    # Domain classification overview
    st.subheader("Classification Overview")
    
    classifications = domain_classifier.get_classification_stats()
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Domains", classifications.get('total', 0))
    
    with col2:
        st.metric("Suspicious Domains", classifications.get('suspicious', 0))
    
    with col3:
        st.metric("Whitelisted Domains", classifications.get('whitelisted', 0))
    
    # Classification distribution
    st.subheader("Classification Distribution")
    
    if classifications:
        fig = px.pie(
            values=list(classifications.values()),
            names=list(classifications.keys()),
            title="Domain Classification Distribution"
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Domain management
    st.subheader("Domain Management")
    
    tab1, tab2, tab3, tab4 = st.tabs(["View Classifications", "Add Domain", "Bulk Operations", "Whitelist Management"])
    
    with tab1:
        # View existing classifications
        st.write("**Current Domain Classifications:**")
        
        available_categories = ["All"] + list(domain_classifier.classifications.keys())
        category_filter = st.selectbox(
            "Filter by Category",
            available_categories
        )
        
        domains = domain_classifier.get_domains_by_category(category_filter)
        
        if domains:
            # Create searchable table
            search_term = st.text_input("Search domains:")
            
            if search_term:
                domains = [d for d in domains if search_term.lower() in d['domain'].lower()]
            
            # Display domains
            for domain_info in domains[:50]:  # Limit to first 50 for performance
                with st.expander(f"🌐 {domain_info['domain']} - {domain_info['category']}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Domain:** {domain_info['domain']}")
                        st.write(f"**Category:** {domain_info['category']}")
                        st.write(f"**Added:** {domain_info.get('added_date', 'Unknown')}")
                    
                    with col2:
                        if st.button("Remove Domain", key=f"remove_{domain_info['domain']}"):
                            domain_classifier.remove_domain(domain_info['domain'])
                            st.success(f"Domain {domain_info['domain']} removed!")
                            st.rerun()
                        
                        category_list = list(domain_classifier.classifications.keys())
                        current_index = 0
                        try:
                            current_index = category_list.index(domain_info['category'])
                        except ValueError:
                            current_index = 0
                        
                        new_category = st.selectbox(
                            "Change Category",
                            category_list,
                            index=current_index,
                            key=f"cat_{domain_info['domain']}"
                        )
                        
                        if st.button("Update Category", key=f"update_{domain_info['domain']}"):
                            domain_classifier.add_domain(domain_info['domain'], new_category)
                            st.success(f"Domain {domain_info['domain']} updated to {new_category}!")
                            st.rerun()
            
            if len(domains) > 50:
                st.info(f"Showing first 50 of {len(domains)} domains. Use search to filter results.")
        else:
            st.info("No domains found for the selected category.")
    
    with tab2:
        # Add new domain
        st.write("**Add New Domain:**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            new_domain = st.text_input("Domain Name", placeholder="example.com")
        
        with col2:
            new_category = st.selectbox(
                "Category",
                list(domain_classifier.classifications.keys())
            )
        
        if st.button("Add Domain", type="primary"):
            if new_domain:
                domain_classifier.add_domain(new_domain.lower(), new_category)
                st.success(f"Domain {new_domain} added to {new_category} category!")
                st.rerun()
            else:
                st.error("Please enter a domain name.")
    
    with tab3:
        # Bulk operations
        st.write("**Bulk Operations:**")
        
        bulk_text = st.text_area(
            "Domains (one per line)",
            placeholder="example1.com\nexample2.com\nexample3.com",
            height=150
        )
        
        bulk_category = st.selectbox(
            "Category for all domains",
            list(domain_classifier.classifications.keys()),
            key="bulk_category"
        )
        
        if st.button("Add All Domains", type="primary"):
            if bulk_text:
                domains = [line.strip().lower() for line in bulk_text.split('\n') if line.strip()]
                added_count = 0
                
                for domain in domains:
                    if domain:
                        domain_classifier.add_domain(domain, bulk_category)
                        added_count += 1
                
                st.success(f"Added {added_count} domains to {bulk_category} category!")
                st.rerun()
            else:
                st.error("Please enter domains to add.")
    
    with tab4:
        # Whitelist Management
        st.write("**Domain Whitelist Management**")
        st.markdown("""
        Whitelisted domains are automatically filtered out during data upload.
        Use this to exclude trusted domains from security analysis.
        """)
        
        # Whitelist statistics
        whitelisted_domains = domain_classifier.get_whitelisted_domains()
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Whitelisted Domains", len(whitelisted_domains))
        
        with col2:
            if st.button("🔄 Refresh Whitelist"):
                st.rerun()
        
        # Add to whitelist
        st.subheader("Add to Whitelist")
        
        col1, col2 = st.columns(2)
        
        with col1:
            new_whitelist_domain = st.text_input(
                "Domain to whitelist",
                placeholder="example.com",
                help="Enter domain without protocol (e.g., example.com)"
            )
        
        with col2:
            whitelist_reason = st.text_input(
                "Reason",
                placeholder="Trusted partner domain",
                help="Reason for whitelisting this domain"
            )
        
        if st.button("✅ Add to Whitelist", type="primary"):
            if new_whitelist_domain:
                if domain_classifier.add_to_whitelist(new_whitelist_domain, whitelist_reason or "User added"):
                    st.success(f"Added {new_whitelist_domain} to whitelist!")
                    st.rerun()
                else:
                    st.error("Failed to add domain to whitelist")
            else:
                st.error("Please enter a domain to whitelist")
        
        # Bulk whitelist
        st.subheader("Bulk Whitelist")
        
        bulk_whitelist_text = st.text_area(
            "Enter domains to whitelist (one per line)",
            height=100,
            placeholder="example.com\npartner.org\ntrusted.net"
        )
        
        bulk_whitelist_reason = st.text_input(
            "Reason for bulk whitelist",
            placeholder="Trusted partner domains",
            value="Bulk whitelisted"
        )
        
        if st.button("✅ Bulk Add to Whitelist"):
            if bulk_whitelist_text:
                domains = [line.strip().lower() for line in bulk_whitelist_text.split('\n') if line.strip()]
                results = domain_classifier.bulk_whitelist_domains(domains, bulk_whitelist_reason)
                
                success_count = sum(1 for success in results.values() if success)
                st.success(f"Added {success_count} domains to whitelist!")
                st.rerun()
            else:
                st.error("Please enter domains to whitelist")
        
        # Current whitelist
        st.subheader("Current Whitelist")
        
        if whitelisted_domains:
            # Search whitelist
            whitelist_search = st.text_input("Search whitelisted domains:")
            
            filtered_whitelist = whitelisted_domains
            if whitelist_search:
                filtered_whitelist = [
                    d for d in whitelisted_domains 
                    if whitelist_search.lower() in d['domain'].lower()
                ]
            
            # Display whitelisted domains
            for domain_info in filtered_whitelist[:50]:  # Limit to first 50
                with st.expander(f"✅ {domain_info['domain']}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Domain:** {domain_info['domain']}")
                        st.write(f"**Added:** {domain_info.get('added_date', 'Unknown')}")
                        st.write(f"**Reason:** {domain_info.get('reason', 'No reason provided')}")
                    
                    with col2:
                        if st.button("🗑️ Remove from Whitelist", key=f"remove_whitelist_{domain_info['domain']}"):
                            domain_classifier.remove_from_whitelist(domain_info['domain'])
                            st.success(f"Removed {domain_info['domain']} from whitelist!")
                            st.rerun()
                        
                        # Add to different category
                        move_to_category = st.selectbox(
                            "Move to category:",
                            ["Select category..."] + [cat for cat in domain_classifier.classifications.keys() if cat != 'Whitelisted'],
                            key=f"move_cat_{domain_info['domain']}"
                        )
                        
                        if move_to_category != "Select category..." and st.button("🔄 Move", key=f"move_{domain_info['domain']}"):
                            domain_classifier.remove_from_whitelist(domain_info['domain'])
                            domain_classifier.add_domain(domain_info['domain'], move_to_category)
                            st.success(f"Moved {domain_info['domain']} to {move_to_category}!")
                            st.rerun()
            
            if len(filtered_whitelist) > 50:
                st.info(f"Showing first 50 of {len(filtered_whitelist)} whitelisted domains")
        else:
            st.info("No domains currently whitelisted")
        
        # Whitelist management tools
        st.subheader("Whitelist Management Tools")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Export whitelist
            if st.button("📥 Export Whitelist"):
                whitelist_json = domain_classifier.export_whitelist()
                st.download_button(
                    "📥 Download Whitelist",
                    data=whitelist_json,
                    file_name=f"whitelist_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
        
        with col2:
            # Import whitelist
            uploaded_whitelist = st.file_uploader(
                "Import Whitelist",
                type="json",
                help="Upload a previously exported whitelist file"
            )
            
            if uploaded_whitelist is not None:
                try:
                    whitelist_data = uploaded_whitelist.read().decode('utf-8')
                    
                    merge_whitelist = st.checkbox("Merge with existing whitelist", value=True)
                    
                    if st.button("📤 Import Whitelist"):
                        if domain_classifier.import_whitelist(whitelist_data, merge_whitelist):
                            st.success("Whitelist imported successfully!")
                            st.rerun()
                        else:
                            st.error("Failed to import whitelist")
                except Exception as e:
                    st.error(f"Error reading whitelist file: {str(e)}")
    
    # Domain analysis with uploaded data
    if st.session_state.data:
        st.subheader("Domain Analysis from Uploaded Data")
        
        data = st.session_state.data
        
        # Extract domains from data
        domain_counts = {}
        for email in data:
            domain = email.get('recipients_email_domain', '')
            if domain:
                domain_counts[domain] = domain_counts.get(domain, 0) + 1
        
        # Classify domains
        domain_analysis = []
        for domain, count in domain_counts.items():
            classification = domain_classifier.classify_domain(domain)
            domain_analysis.append({
                'domain': domain,
                'count': count,
                'classification': classification
            })
        
        # Sort by count
        domain_analysis.sort(key=lambda x: x['count'], reverse=True)
        
        st.write(f"**Analysis of {len(domain_analysis)} unique domains from uploaded data:**")
        
        # Classification summary
        classification_counts = {}
        for item in domain_analysis:
            classification = item['classification']
            classification_counts[classification] = classification_counts.get(classification, 0) + item['count']
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Suspicious Emails", classification_counts.get('Suspicious', 0))
        
        with col2:
            st.metric("Free Email Emails", classification_counts.get('Free Email', 0))
        
        with col3:
            st.metric("Business Emails", classification_counts.get('Business', 0))
        
        # Top domains table
        st.write("**Top Domains by Email Count:**")
        
        for item in domain_analysis[:20]:  # Show top 20
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.write(f"**{item['domain']}**")
            
            with col2:
                st.write(f"Emails: {item['count']:,}")
            
            with col3:
                classification = item['classification']
                color = {
                    'Suspicious': '🔴',
                    'Free Email': '🟡',
                    'Business': '🟢',
                    'Government': '🔵',
                    'Financial': '🟠',
                    'Cloud Providers': '⚪'
                }.get(classification, '⚫')
                st.write(f"{color} {classification}")
            
            with col4:
                if st.button("Quick Add", key=f"quick_{item['domain']}"):
                    domain_classifier.add_domain(item['domain'], classification)
                    st.success(f"Added {item['domain']}!")
                    st.rerun()

def main():
    """Main application function"""
    # Auto-save work state periodically
    auto_save_work_state()
    
    # Initialize auto-save timer
    initialize_auto_save_timer()
    
    # Professional header
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ ExfilEye DLP</h1>
        <p>Data Loss Prevention Email Monitoring System</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar navigation with professional styling
    st.sidebar.markdown("""
    <div class="nav-section">
        <h2 style="color: #2c3e50; margin-bottom: 1rem;">🛡️ ExfilEye DLP</h2>
        <p style="color: #7f8c8d; margin-bottom: 1.5rem;">Data Loss Prevention Email Monitoring</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Navigation menu
    pages = {
        "📁 Data Upload & Preprocessing": data_upload_page,
        "🛡️ Security Operations Dashboard": security_operations_dashboard,
        "🔍 Suspicious Email Analysis": suspicious_email_analysis_page,
        "📨 Follow-up Center": followup_center_page,
        "✅ Email Check Completed": email_check_completed_page,
        "🔗 Network Analysis": network_analysis_page,
        "🌐 Domain Classification": domain_classification_page
    }
    
    st.sidebar.markdown("### 🧭 Navigation")
    selected_page = st.sidebar.radio("Select page:", list(pages.keys()), label_visibility="collapsed")
    
    # Professional data status card
    st.sidebar.markdown("### 📊 Data Status")
    if st.session_state.data:
        st.sidebar.markdown(f"""
        <div class="metric-card">
            <h3>📁 Data Loaded</h3>
            <p class="metric-value">{len(st.session_state.data):,}</p>
            <p style="color: #27ae60; margin: 0;">records available</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.sidebar.markdown("""
        <div class="alert alert-warning">
            <strong>⚠️ No Data</strong><br>
            Upload data to begin analysis
        </div>
        """, unsafe_allow_html=True)
    
    # Professional system status cards
    st.sidebar.markdown("### 🔍 Review Status")
    
    active_reviews = len(st.session_state.data) - len(st.session_state.completed_reviews) - len(st.session_state.escalated_records) if st.session_state.data else 0
    completed_reviews = len(st.session_state.completed_reviews)
    escalated_records = len(st.session_state.escalated_records)
    
    # Status metrics in compact cards
    st.sidebar.markdown(f"""
    <div style="display: flex; flex-direction: column; gap: 0.5rem;">
        <div class="metric-card" style="padding: 1rem;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="color: #3498db; font-weight: 600;">🔍 Active</span>
                <span style="font-size: 1.5rem; font-weight: 700; color: #3498db;">{active_reviews}</span>
            </div>
        </div>
        <div class="metric-card" style="padding: 1rem;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="color: #27ae60; font-weight: 600;">✅ Completed</span>
                <span style="font-size: 1.5rem; font-weight: 700; color: #27ae60;">{completed_reviews}</span>
            </div>
        </div>
        <div class="metric-card" style="padding: 1rem;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="color: #e74c3c; font-weight: 600;">📨 Escalated</span>
                <span style="font-size: 1.5rem; font-weight: 700; color: #e74c3c;">{escalated_records}</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Professional data persistence section
    st.sidebar.markdown("### 💾 Data Persistence")
    persistence = st.session_state.data_persistence
    
    # Save button with professional styling
    if st.sidebar.button("💾 Save Work", help="Save current work state", type="primary", use_container_width=True):
        save_work_state()
        st.session_state.last_manual_save = datetime.now()
        # Reset auto-save timer when manually saved
        st.session_state.last_auto_save_time = datetime.now()
    
    # Available dates info
    available_dates = persistence.get_available_dates()
    if available_dates:
        st.sidebar.markdown(f"""
        <div style="background: #f8f9fa; padding: 0.5rem; border-radius: 6px; margin: 0.5rem 0;">
            <small style="color: #6c757d;">📅 {len(available_dates)} backup dates available</small>
        </div>
        """, unsafe_allow_html=True)
    
    # Professional last saved timestamp
    if 'last_manual_save' in st.session_state:
        last_save_time = st.session_state.last_manual_save
        time_diff = datetime.now() - last_save_time
        
        if time_diff.total_seconds() < 60:
            status_color = "#27ae60"
            status_text = f"✅ Last saved: {int(time_diff.total_seconds())}s ago"
        elif time_diff.total_seconds() < 3600:
            status_color = "#3498db"
            status_text = f"💾 Last saved: {int(time_diff.total_seconds() / 60)}m ago"
        else:
            status_color = "#7f8c8d"
            status_text = f"💾 Last saved: {last_save_time.strftime('%H:%M')}"
        
        st.sidebar.markdown(f"""
        <div style="background: {status_color}20; padding: 0.5rem; border-radius: 6px; border-left: 3px solid {status_color}; margin: 0.5rem 0;">
            <small style="color: {status_color}; font-weight: 600;">{status_text}</small>
        </div>
        """, unsafe_allow_html=True)
    else:
        # Check if there's a saved work state file to show when it was last saved
        work_state_file = os.path.join(persistence.work_state_folder, f"work_state_{datetime.now().strftime('%Y-%m-%d')}.json")
        if os.path.exists(work_state_file):
            file_mtime = datetime.fromtimestamp(os.path.getmtime(work_state_file))
            time_diff = datetime.now() - file_mtime
            
            if time_diff.total_seconds() < 60:
                status_color = "#3498db"
                status_text = f"💾 Last saved: {int(time_diff.total_seconds())}s ago"
            elif time_diff.total_seconds() < 3600:
                status_color = "#3498db"
                status_text = f"💾 Last saved: {int(time_diff.total_seconds() / 60)}m ago"
            else:
                status_color = "#7f8c8d"
                status_text = f"💾 Last saved: {file_mtime.strftime('%H:%M')}"
            
            st.sidebar.markdown(f"""
            <div style="background: {status_color}20; padding: 0.5rem; border-radius: 6px; border-left: 3px solid {status_color}; margin: 0.5rem 0;">
                <small style="color: {status_color}; font-weight: 600;">{status_text}</small>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.sidebar.markdown("""
            <div style="background: #f39c1220; padding: 0.5rem; border-radius: 6px; border-left: 3px solid #f39c12; margin: 0.5rem 0;">
                <small style="color: #f39c12; font-weight: 600;">⚠️ No recent saves found</small>
            </div>
            """, unsafe_allow_html=True)
    
    # Run selected page
    pages[selected_page]()

def save_work_state():
    """Save current work state to JSON"""
    persistence = st.session_state.data_persistence
    
    def convert_datetime_objects(obj):
        """Convert datetime objects to ISO format strings"""
        if hasattr(obj, 'isoformat'):  # datetime objects
            return obj.isoformat()
        elif isinstance(obj, dict):
            return {k: convert_datetime_objects(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_datetime_objects(item) for item in obj]
        else:
            return obj
    
    try:
        work_state = {
            # Security Operations Dashboard
            "completed_reviews": convert_datetime_objects(st.session_state.completed_reviews),
            "escalated_records": convert_datetime_objects(st.session_state.escalated_records),
            "active_filters": convert_datetime_objects(st.session_state.active_filters),
            "review_decisions": convert_datetime_objects(st.session_state.review_decisions),
            "last_reviewed_email": str(st.session_state.last_reviewed_email),
            "review_session_start": str(st.session_state.review_session_start),
            "total_reviews_this_session": int(st.session_state.total_reviews_this_session),
            
            # Email Check Completed Dashboard
            "review_notes": convert_datetime_objects(st.session_state.review_notes),
            "reviewer_assignments": convert_datetime_objects(st.session_state.reviewer_assignments),
            "completion_timestamps": convert_datetime_objects(st.session_state.completion_timestamps),
            "review_quality_scores": convert_datetime_objects(st.session_state.review_quality_scores),
            "batch_review_sessions": convert_datetime_objects(st.session_state.batch_review_sessions),
            
            # Follow-up Center Dashboard
            "followup_status": convert_datetime_objects(st.session_state.followup_status),
            "followup_notes": convert_datetime_objects(st.session_state.followup_notes),
            "email_templates": convert_datetime_objects(st.session_state.email_templates),
            "followup_assignments": convert_datetime_objects(st.session_state.followup_assignments),
            "escalation_reasons": convert_datetime_objects(st.session_state.escalation_reasons),
            "followup_deadlines": convert_datetime_objects(st.session_state.followup_deadlines),
            "email_sent_status": convert_datetime_objects(st.session_state.email_sent_status),
            "template_drafts": convert_datetime_objects(st.session_state.template_drafts),
            
            # General system state
            "follow_up_decisions": convert_datetime_objects(st.session_state.follow_up_decisions),
            "blocked_domains": list(st.session_state.blocked_domains),
            "sender_status": convert_datetime_objects(st.session_state.sender_status),
            "domain_classifications": convert_datetime_objects(st.session_state.domain_classifications),
            "user_preferences": convert_datetime_objects(st.session_state.user_preferences),
            "session_statistics": convert_datetime_objects(st.session_state.session_statistics),
            
            # UI state
            "selected_filters": convert_datetime_objects(st.session_state.selected_filters),
            "sort_preferences": convert_datetime_objects(st.session_state.sort_preferences),
            "view_modes": convert_datetime_objects(st.session_state.view_modes),
            "expanded_sections": convert_datetime_objects(st.session_state.expanded_sections),
            "modal_states": convert_datetime_objects(st.session_state.modal_states)
        }
        
        saved_path = persistence.save_work_state(work_state)
        
        if saved_path:
            st.sidebar.success("✅ Work state saved!")
        else:
            st.sidebar.error("❌ Failed to save work state")
    
    except Exception as e:
        st.sidebar.error(f"❌ Error saving work state: {str(e)}")
        print(f"Save work state error: {e}")
        import traceback
        traceback.print_exc()

def initialize_auto_save_timer():
    """Initialize auto-save timer that saves work every minute"""
    
    # Initialize auto-save tracking
    if 'auto_save_timer' not in st.session_state:
        st.session_state.auto_save_timer = datetime.now()
    
    if 'last_auto_save_time' not in st.session_state:
        st.session_state.last_auto_save_time = datetime.now()
    
    # Check if 1 minute has passed since last auto-save
    current_time = datetime.now()
    time_since_last_save = current_time - st.session_state.last_auto_save_time
    
    # Auto-save every 60 seconds (1 minute)
    if time_since_last_save.total_seconds() >= 60:
        # Check if we have any work to save
        if (st.session_state.completed_reviews or 
            st.session_state.escalated_records or 
            st.session_state.follow_up_decisions or
            st.session_state.data):
            
            try:
                save_work_state()
                st.session_state.last_auto_save_time = current_time
                st.session_state.last_manual_save = current_time
                
                # Show brief auto-save notification in sidebar
                st.sidebar.success("💾 Auto-saved!")
                
            except Exception as e:
                st.sidebar.error(f"❌ Auto-save failed: {str(e)}")
                print(f"Auto-save error: {e}")
    
    # Force a rerun every 30 seconds to check auto-save timer
    # This ensures the timer keeps running even when user is not interacting
    if 'force_rerun_timer' not in st.session_state:
        st.session_state.force_rerun_timer = datetime.now()
    
    time_since_force_rerun = current_time - st.session_state.force_rerun_timer
    if time_since_force_rerun.total_seconds() >= 30:
        st.session_state.force_rerun_timer = current_time
        # Only rerun if we have data worth saving
        if st.session_state.data:
            st.rerun()

def auto_save_work_state():
    """Auto-save work state periodically (legacy function for compatibility)"""
    # This function is kept for compatibility but the main auto-save logic
    # is now handled by initialize_auto_save_timer()
    pass

if __name__ == "__main__":
    main()