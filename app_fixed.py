import streamlit as st
import csv
import io
import json
import os
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
from openai import OpenAI
import re
import webbrowser
from urllib.parse import quote

# Import custom modules
from domain_classifier import DomainClassifier
from security_config import SecurityConfig
from data_persistence import DataPersistence

# Initialize OpenAI client
# the newest OpenAI model is "gpt-4o" which was released May 13, 2024.
# do not change this unless explicitly requested by the user
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
openai_client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

# Page configuration
st.set_page_config(
    page_title="ExfilEye - DLP Email Monitoring",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

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
            'recipients_email_domain', 'minecast', 'tessian', 'leaver', 
            'Termination', 'time_month', 'account_type', 'wordlist_attachment',
            'wordlist_subject', 'bunit', 'department', 'status', 
            'tessian_status_A', 'tessian_status_B'
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

class AnomalyDetector:
    """AI-powered anomaly detection for email patterns"""
    
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.intelligent_filter = IsolationForest(contamination=0.05, random_state=42)
    
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
    
    def intelligent_filter_suspicious_events(self, email_data):
        """Intelligently filter Medium, Low, and Unclassified events to highlight only suspicious ones"""
        if not email_data:
            return []
        
        # Filter only Medium, Low, and Unclassified events
        filtered_events = [
            email for email in email_data 
            if email.get('status', '').lower() in ['medium', 'low', 'unclassified']
        ]
        
        if len(filtered_events) < 2:
            return filtered_events
        
        # Extract advanced features for intelligent filtering
        features = self._extract_advanced_features(filtered_events)
        
        if len(features) < 2:
            return filtered_events[:5]  # Return first 5 if not enough data
        
        # Normalize features
        features_scaled = self.scaler.fit_transform(features)
        
        # Use more strict isolation forest for filtering
        suspicious_scores = self.intelligent_filter.fit_predict(features_scaled)
        
        # Get anomaly scores for ranking
        anomaly_scores = self.intelligent_filter.decision_function(features_scaled)
        
        # Combine events with their suspicion scores
        suspicious_events = []
        for i, (email, score, anomaly_score) in enumerate(zip(filtered_events, suspicious_scores, anomaly_scores)):
            if score == -1:  # Anomaly detected
                suspicious_events.append({
                    'email': email,
                    'suspicion_score': abs(anomaly_score),
                    'reason': self._generate_suspicion_reason(email, features[i])
                })
        
        # Sort by suspicion score and return top 10 most suspicious
        suspicious_events.sort(key=lambda x: x['suspicion_score'], reverse=True)
        return suspicious_events[:10]
    
    def _extract_advanced_features(self, email_data):
        """Extract advanced features for intelligent filtering"""
        features = []
        
        # Calculate baseline statistics
        all_subject_lengths = [len(email.get('subject', '')) for email in email_data]
        all_recipient_counts = [len(email.get('recipients', '').split(',')) for email in email_data]
        
        avg_subject_length = np.mean(all_subject_lengths) if all_subject_lengths else 0
        avg_recipient_count = np.mean(all_recipient_counts) if all_recipient_counts else 0
        
        for email in email_data:
            try:
                subject = email.get('subject', '')
                recipients = email.get('recipients', '')
                sender = email.get('sender', '')
                domain = email.get('recipients_email_domain', '')
                
                # Time-based features
                time_str = email.get('_time', '')
                hour_of_day = 12  # Default
                try:
                    if time_str:
                        hour_of_day = int(time_str.split('T')[1].split(':')[0]) if 'T' in time_str else 12
                except:
                    hour_of_day = 12
                
                # Advanced feature vector
                feature_vector = [
                    # Basic features
                    len(subject),
                    len(recipients.split(',')),
                    1 if email.get('attachments') else 0,
                    len(sender),
                    
                    # Deviation from normal patterns
                    abs(len(subject) - avg_subject_length),
                    abs(len(recipients.split(',')) - avg_recipient_count),
                    
                    # Time-based features
                    hour_of_day,
                    1 if hour_of_day < 6 or hour_of_day > 22 else 0,  # Off-hours indicator
                    
                    # Content-based features
                    1 if email.get('wordlist_attachment') else 0,
                    1 if email.get('wordlist_subject') else 0,
                    
                    # Domain-based features
                    hash(domain) % 1000,
                    1 if domain.endswith('.com') else 0,
                    1 if any(word in domain.lower() for word in ['temp', 'disposable', 'fake']) else 0,
                    
                    # Recipient pattern analysis
                    1 if len(recipients.split(',')) > 5 else 0,
                    1 if '@' in recipients and recipients.count('@') > 3 else 0,
                    
                    # Subject pattern analysis
                    1 if any(word in subject.lower() for word in ['urgent', 'confidential', 'secret', 'private']) else 0,
                    1 if subject.isupper() else 0,
                    len([c for c in subject if c.isdigit()]) / max(len(subject), 1),
                    
                    # Sender pattern analysis
                    1 if sender.count('.') > 2 else 0,
                    1 if '@' in sender and any(char.isdigit() for char in sender.split('@')[0]) else 0,
                ]
                
                features.append(feature_vector)
            except:
                features.append([0] * 20)  # Default feature vector
        
        return np.array(features)
    
    def _generate_suspicion_reason(self, email, features):
        """Generate a human-readable reason for why this email is suspicious"""
        reasons = []
        
        subject = email.get('subject', '')
        recipients = email.get('recipients', '')
        sender = email.get('sender', '')
        domain = email.get('recipients_email_domain', '')
        
        # Check various suspicious patterns
        if email.get('wordlist_attachment'):
            reasons.append("Contains suspicious attachment keywords")
        if email.get('wordlist_subject'):
            reasons.append("Subject contains flagged keywords")
        if len(recipients.split(',')) > 5:
            reasons.append("Large number of recipients")
        if any(word in subject.lower() for word in ['urgent', 'confidential', 'secret']):
            reasons.append("Urgent/confidential language in subject")
        if subject.isupper():
            reasons.append("Subject in ALL CAPS")
        if any(word in domain.lower() for word in ['temp', 'disposable', 'fake']):
            reasons.append("Suspicious recipient domain")
        if sender.count('.') > 2:
            reasons.append("Complex sender email pattern")
        
        # Time-based reasons
        try:
            time_str = email.get('_time', '')
            if time_str:
                hour_of_day = int(time_str.split('T')[1].split(':')[0]) if 'T' in time_str else 12
                if hour_of_day < 6 or hour_of_day > 22:
                    reasons.append("Sent during off-hours")
        except:
            pass
        
        if not reasons:
            reasons.append("Unusual email pattern detected")
        
        return "; ".join(reasons[:3])  # Return top 3 reasons
    
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

class AIInsights:
    """AI-powered insights for selected email fields"""
    
    def __init__(self):
        self.client = openai_client
    
    def run_ai_on_selected_fields(self, selected_fields, data):
        """Run AI analysis on user-selected fields"""
        if not self.client:
            return "OpenAI API key not configured. Please set OPENAI_API_KEY environment variable."
        
        if not selected_fields or not data:
            return "No fields selected or no data available for analysis."
        
        # Prepare data for analysis
        field_data = self._extract_field_data(selected_fields, data)
        
        # Generate insights using OpenAI
        try:
            prompt = self._create_analysis_prompt(selected_fields, field_data)
            
            response = self.client.chat.completions.create(
                model="gpt-4o",  # the newest OpenAI model is "gpt-4o"
                messages=[
                    {"role": "system", "content": "You are a cybersecurity analyst expert in data loss prevention and email security. Provide detailed, actionable insights based on the email data provided."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                max_tokens=2000
            )
            
            result = json.loads(response.choices[0].message.content)
            return self._format_ai_insights(result)
            
        except Exception as e:
            return f"Error generating AI insights: {str(e)}"
    
    def _extract_field_data(self, selected_fields, data):
        """Extract data for selected fields"""
        field_data = {}
        
        for field in selected_fields:
            field_values = []
            for email in data[:1000]:  # Limit to first 1000 records for performance
                value = email.get(field, '')
                if value:
                    field_values.append(str(value))
            
            field_data[field] = field_values
        
        return field_data
    
    def _create_analysis_prompt(self, selected_fields, field_data):
        """Create analysis prompt for OpenAI"""
        prompt = f"""
        Analyze the following email security data for potential data loss prevention insights:

        Selected Fields: {', '.join(selected_fields)}

        Data Summary:
        """
        
        for field, values in field_data.items():
            unique_values = len(set(values))
            total_values = len(values)
            
            prompt += f"\n{field}:"
            prompt += f"\n  - Total entries: {total_values}"
            prompt += f"\n  - Unique values: {unique_values}"
            
            if values:
                sample_values = list(set(values))[:10]  # Show sample values
                prompt += f"\n  - Sample values: {', '.join(sample_values)}"
        
        prompt += """

        Please provide a JSON response with the following structure:
        {
            "summary": "Brief overview of the analysis",
            "anomalies": ["List of potential anomalies or concerns"],
            "patterns": ["List of notable patterns identified"],
            "recommendations": ["List of actionable security recommendations"],
            "risk_assessment": "Overall risk assessment (Low/Medium/High/Critical)"
        }
        """
        
        return prompt
    
    def _format_ai_insights(self, result):
        """Format AI insights for display"""
        formatted = f"## AI Analysis Results\n\n"
        
        if 'summary' in result:
            formatted += f"### Summary\n{result['summary']}\n\n"
        
        if 'anomalies' in result and result['anomalies']:
            formatted += "### Potential Anomalies\n"
            for anomaly in result['anomalies']:
                formatted += f"- {anomaly}\n"
            formatted += "\n"
        
        if 'patterns' in result and result['patterns']:
            formatted += "### Notable Patterns\n"
            for pattern in result['patterns']:
                formatted += f"- {pattern}\n"
            formatted += "\n"
        
        if 'recommendations' in result and result['recommendations']:
            formatted += "### Recommendations\n"
            for rec in result['recommendations']:
                formatted += f"- {rec}\n"
            formatted += "\n"
        
        if 'risk_assessment' in result:
            risk_color = {
                'Low': '🟢',
                'Medium': '🟡',
                'High': '🟠',
                'Critical': '🔴'
            }.get(result['risk_assessment'], '⚪')
            formatted += f"### Risk Assessment: {risk_color} {result['risk_assessment']}\n"
        
        return formatted

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
    """Show email details in pop-out window format with all fields and domain classification"""
    # Create a clean title for the modal
    subject_preview = email.get('subject', 'No Subject')[:50]
    if len(email.get('subject', '')) > 50:
        subject_preview += "..."
    
    # Get domain classification
    domain = email.get('recipients_email_domain', 'Unknown')
    domain_classification = st.session_state.domain_classifier.classify_domain(domain)
    
    # Classification color mapping
    classification_colors = {
        'Suspicious': '#ff4444',
        'Free Email': '#ffaa00',
        'Business': '#44aa44',
        'Government': '#4444ff',
        'Financial': '#ff8800',
        'Cloud Providers': '#8844ff',
        'Unknown': '#888888'
    }
    
    classification_color = classification_colors.get(domain_classification, '#888888')
    
    # Create pop-out window with prominent styling
    with st.container():
        # Header with prominent styling
        st.markdown(f"""
        <div style="
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            border-radius: 15px;
            margin: 10px 0;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.2);
        ">
            <h2 style="color: white; margin: 0; text-align: center; font-size: 24px;">
                📧 Email Analysis Details
            </h2>
            <p style="color: #e0e0e0; text-align: center; margin: 5px 0 0 0; font-size: 16px;">
                {subject_preview}
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # Main content in a styled container
        st.markdown(f"""
        <div style="
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            margin: 15px 0;
            border: 1px solid rgba(255,255,255,0.1);
            box-shadow: 0 4px 16px rgba(0,0,0,0.2);
        ">
        """, unsafe_allow_html=True)
        
        # Primary Email Information with enhanced styling
        st.markdown("### 📧 Email Information")
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown(f"""
            <div style="background: rgba(100,149,237,0.1); padding: 15px; border-radius: 10px; margin: 10px 0;">
                <p><strong>📤 From:</strong> {email.get('sender', 'Unknown')}</p>
                <p><strong>📥 To:</strong> {email.get('recipients', 'Unknown')}</p>
                <p><strong>📝 Subject:</strong> {email.get('subject', 'No Subject')}</p>
                <p><strong>⏰ Time:</strong> {email.get('_time', 'Unknown')}</p>
                <p><strong>📅 Time Month:</strong> {email.get('time_month', 'Unknown')}</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            attachment_value = email.get('attachments', '')
            if attachment_value and attachment_value not in [True, False, 'True', 'False']:
                attachment_text = f"📎 {attachment_value}"
            elif attachment_value:
                attachment_text = "✅ Yes"
            else:
                attachment_text = "❌ No"
            
            risk_status = email.get('status', 'Unknown')
            termination_value = email.get('Termination', '')
            termination_text = f"⚠️ {termination_value}" if termination_value else "✅ No"
            
            st.markdown(f"""
            <div style="background: rgba(255,140,0,0.1); padding: 15px; border-radius: 10px; margin: 10px 0;">
                <p><strong>🌐 Recipients Domain:</strong> {domain}</p>
                <p><strong>🏷️ Domain Classification:</strong> 
                    <span style="background: {classification_color}; color: white; padding: 4px 8px; border-radius: 15px; font-weight: bold;">
                        {domain_classification}
                    </span>
                </p>
                <p><strong>📎 Attachments:</strong> {attachment_text}</p>
                <p><strong>⚠️ Risk Status:</strong> {get_risk_indicator(risk_status)} {risk_status.title()}</p>
                <p><strong>🚪 Termination:</strong> {termination_text}</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Security & Compliance Section with enhanced styling
        st.markdown("### 🔒 Security & Compliance")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown(f"""
            <div style="background: rgba(255,69,0,0.1); padding: 15px; border-radius: 10px; margin: 10px 0;">
                <p><strong>🛡️ Minecast:</strong> {'✅ Yes' if email.get('minecast') else '❌ No'}</p>
                <p><strong>🔍 Tessian:</strong> {'✅ Yes' if email.get('tessian') else '❌ No'}</p>
                <p><strong>📊 Tessian Status A:</strong> {email.get('tessian_status_A', 'Unknown')}</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div style="background: rgba(50,205,50,0.1); padding: 15px; border-radius: 10px; margin: 10px 0;">
                <p><strong>📊 Tessian Status B:</strong> {email.get('tessian_status_B', 'Unknown')}</p>
                <p><strong>📎 Wordlist Attachment:</strong> {'⚠️ Yes' if email.get('wordlist_attachment') else '✅ No'}</p>
                <p><strong>📝 Wordlist Subject:</strong> {'⚠️ Yes' if email.get('wordlist_subject') else '✅ No'}</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown(f"""
            <div style="background: rgba(255,20,147,0.1); padding: 15px; border-radius: 10px; margin: 10px 0;">
                <p><strong>👋 Leaver:</strong> {'⚠️ Yes' if email.get('leaver') else '✅ No'}</p>
                <p><strong>🚪 Termination:</strong> {'⚠️ Yes' if email.get('Termination') else '✅ No'}</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Organizational Information with enhanced styling
        st.markdown("### 🏢 Organizational Information")
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown(f"""
            <div style="background: rgba(70,130,180,0.1); padding: 15px; border-radius: 10px; margin: 10px 0;">
                <p><strong>🏛️ Department:</strong> {email.get('department', 'Unknown')}</p>
                <p><strong>🏢 Business Unit:</strong> {email.get('bunit', 'Unknown')}</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div style="background: rgba(147,112,219,0.1); padding: 15px; border-radius: 10px; margin: 10px 0;">
                <p><strong>👤 Account Type:</strong> {email.get('account_type', 'Unknown')}</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Domain Classification Details Section
        st.markdown("### 🌐 Domain Classification Details")
        st.markdown(f"""
        <div style="
            background: linear-gradient(135deg, {classification_color}20, {classification_color}10);
            border-left: 5px solid {classification_color};
            padding: 20px;
            border-radius: 10px;
            margin: 15px 0;
        ">
            <h4 style="color: {classification_color}; margin-top: 0;">
                🏷️ Classification: {domain_classification}
            </h4>
            <p><strong>🌐 Domain:</strong> {domain}</p>
            <p><strong>📊 Classification Confidence:</strong> Auto-detected</p>
            <p><strong>🔍 Last Updated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Additional Fields (for any extra fields not explicitly handled)
        st.markdown("### 📋 Additional Fields")
        
        # Get all fields that weren't already displayed
        displayed_fields = {
            'sender', 'recipients', 'subject', '_time', 'time_month', 
            'recipients_email_domain', 'attachments', 'status', 'minecast', 
            'tessian', 'tessian_status_A', 'tessian_status_B', 'wordlist_attachment', 
            'wordlist_subject', 'leaver', 'Termination', 'department', 'bunit', 
            'account_type'
        }
        
        additional_fields = {k: v for k, v in email.items() if k not in displayed_fields}
        
        if additional_fields:
            st.markdown(f"""
            <div style="background: rgba(128,128,128,0.1); padding: 15px; border-radius: 10px; margin: 10px 0;">
            """, unsafe_allow_html=True)
            
            cols = st.columns(2)
            for i, (field, value) in enumerate(additional_fields.items()):
                with cols[i % 2]:
                    # Format field name nicely
                    field_name = field.replace('_', ' ').title()
                    st.markdown(f"**{field_name}:** {value}")
            
            st.markdown("</div>", unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="background: rgba(128,128,128,0.1); padding: 15px; border-radius: 10px; margin: 10px 0; text-align: center; color: #888;">
                <em>No additional fields</em>
            </div>
            """, unsafe_allow_html=True)
        
        # Action buttons with enhanced styling
        st.markdown("### 🔧 Actions")
        col1, col2, col3 = st.columns([1, 1, 1])
        
        with col1:
            if st.button("✅ Clear", key=f"modal_clear_{hash(str(email))}", type="secondary", use_container_width=True):
                email_id = str(hash(str(email)))
                st.session_state.completed_reviews[email_id] = {
                    'email': email,
                    'decision': 'clear',
                    'timestamp': datetime.now()
                }
                st.success("Email marked as cleared!")
                st.rerun()
        
        with col2:
            if st.button("🚨 Escalate", key=f"modal_escalate_{hash(str(email))}", type="primary", use_container_width=True):
                email_id = str(hash(str(email)))
                st.session_state.escalated_records[email_id] = {
                    'email': email,
                    'decision': 'escalate',
                    'timestamp': datetime.now()
                }
                st.success("Email escalated for follow-up!")
                st.rerun()
        
        with col3:
            if st.button("🌐 Update Domain", key=f"modal_domain_{hash(str(email))}", use_container_width=True):
                st.info("Domain classification update feature - coming soon!")
        
        # Close the main container
        st.markdown("</div>", unsafe_allow_html=True)
        
        



def data_upload_page():
    """Data Upload & Preprocessing page"""
    st.title("📁 Data Upload & Preprocessing")
    
    st.markdown("""
    Upload CSV files up to 2GB containing email metadata for analysis.
    The system will validate required fields and process the data for security monitoring.
    Data is automatically saved to JSON files for persistence across sessions.
    """)
    
    # Data persistence options
    st.subheader("📅 Daily Data Management")
    
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
            # Read file content
            content = uploaded_file.read().decode('utf-8')
            
            # Process CSV
            processor = CSVProcessor()
            
            with st.spinner("Processing CSV data..."):
                processed_data = processor.process_csv_data(content)
            
            if processed_data:
                st.session_state.data = processed_data
                
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
    st.title("🛡️ Security Operations Dashboard")
    
    if not st.session_state.data:
        st.warning("Please upload data first in the Data Upload & Preprocessing section.")
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
    
    st.markdown(f"""
    **Active Records:** {len(active_records):,} | 
    **Completed:** {len(completed_ids):,} | 
    **Escalated:** {len(escalated_ids):,}
    """)
    
    # Filters
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
    
    # Add intelligent filtering toggle
    st.markdown("---")
    col1, col2 = st.columns([3, 1])
    with col1:
        st.subheader("🤖 Intelligent ML-Powered Review Assistant")
    with col2:
        use_intelligent_filter = st.toggle("Enable Smart Filtering", value=False, help="Use AI to filter and show only the most suspicious Medium, Low, and Unclassified events")
    
    # Apply intelligent filtering if enabled
    if use_intelligent_filter:
        anomaly_detector = AnomalyDetector()
        suspicious_events = anomaly_detector.intelligent_filter_suspicious_events(filtered_records)
        
        if suspicious_events:
            st.info(f"🎯 AI identified {len(suspicious_events)} suspicious events from {len(filtered_records)} records that need your attention")
            
            # Show smart filtered results
            st.subheader("🔍 AI-Recommended Events to Review")
            for i, event in enumerate(suspicious_events):
                email = event['email']
                email_id = str(hash(str(email)))
                
                with st.expander(f"🚨 Suspicious Event #{i+1} - {email.get('subject', 'No Subject')[:50]}...", expanded=False):
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.write(f"**Sender:** {email.get('sender', 'N/A')}")
                        st.write(f"**Recipients:** {email.get('recipients', 'N/A')}")
                        st.write(f"**Current Status:** {get_risk_indicator(email.get('status', 'unknown'))} {email.get('status', 'Unknown').title()}")
                        st.write(f"**Suspicion Score:** {event['suspicion_score']:.2f}")
                        st.write(f"**AI Reasoning:** {event['reason']}")
                    
                    with col2:
                        # Status change functionality
                        current_status = email.get('status', 'unclassified')
                        new_status = st.selectbox(
                            "Change Status:",
                            ["critical", "high", "medium", "low", "unclassified"],
                            index=["critical", "high", "medium", "low", "unclassified"].index(current_status.lower() if current_status.lower() in ["critical", "high", "medium", "low", "unclassified"] else "unclassified"),
                            key=f"status_{email_id}"
                        )
                        
                        if st.button(f"Update Status", key=f"update_{email_id}"):
                            # Update the email status in the data
                            for i, data_email in enumerate(st.session_state.data):
                                if str(hash(str(data_email))) == email_id:
                                    st.session_state.data[i]['status'] = new_status
                                    # Save updated data to persistence
                                    data_persistence = DataPersistence()
                                    data_persistence.save_daily_data(st.session_state.data)
                                    st.success(f"Status updated to {new_status.title()}")
                                    st.rerun()
                                    break
                        
                        if st.button(f"View Details", key=f"details_{email_id}"):
                            show_email_details_modal(email)
            
            st.markdown("---")
        else:
            st.info("🎉 No suspicious events detected in the current filtered data!")
    
    st.subheader(f"Security Review Queue ({len(filtered_records):,} records)")
    
    # Risk metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        critical_count = sum(1 for email in filtered_records if email.get('status', '').lower() == 'critical')
        st.metric("🔴 Critical", f"{critical_count:,}")
    
    with col2:
        high_count = sum(1 for email in filtered_records if email.get('status', '').lower() == 'high')
        st.metric("🟠 High", f"{high_count:,}")
    
    with col3:
        medium_count = sum(1 for email in filtered_records if email.get('status', '').lower() == 'medium')
        st.metric("🟡 Medium", f"{medium_count:,}")
    
    with col4:
        low_count = sum(1 for email in filtered_records if email.get('status', '').lower() == 'low')
        st.metric("🟢 Low", f"{low_count:,}")
    
    with col5:
        unclassified_count = sum(1 for email in filtered_records if email.get('status', '').lower() == 'unclassified')
        st.metric("⚪ Unclassified", f"{unclassified_count:,}")
    
    # Timeline view options
    st.subheader("Timeline View")
    
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
                    if st.button(f"📋 View Details - {subject_preview}", key=f"details_{unique_key}", use_container_width=True):
                        # Set session state to show modal
                        st.session_state[f'show_modal_{unique_key}'] = True
                        st.rerun()
                
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
                
                # Show modal if triggered
                if st.session_state.get(f'show_modal_{unique_key}', False):
                    # Create modal overlay
                    with st.container():
                        # Close button
                        if st.button("❌ Close Details", key=f"close_{unique_key}", type="secondary"):
                            st.session_state[f'show_modal_{unique_key}'] = False
                            st.rerun()
                        
                        # Show email details in modal format
                        show_email_details_modal(email)
            
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
    """Enhanced Network Analysis page with advanced interactivity"""
    st.title("🔗 Advanced Network Analysis")
    
    if not st.session_state.data:
        st.warning("Please upload data first in the Data Upload & Preprocessing section.")
        return
    
    st.markdown("""
    🎯 **Advanced Email Communication Network Analysis**
    
    Discover hidden patterns, identify key players, and analyze communication flows using 
    state-of-the-art network visualization and analysis techniques.
    """)
    
    data = st.session_state.data
    
    # Enhanced Network Configuration
    st.subheader("🛠️ Network Configuration")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        source_field = st.selectbox(
            "Source Field",
            ["sender", "recipients", "recipients_email_domain"],
            index=0,
            help="Choose what represents the source of communication"
        )
    
    with col2:
        target_field = st.selectbox(
            "Target Field",
            ["recipients", "recipients_email_domain", "sender"],
            index=0,
            help="Choose what represents the target of communication"
        )
    
    with col3:
        layout_type = st.selectbox(
            "Layout Algorithm",
            ["spring", "kamada_kawai", "circular", "hierarchical", "force_directed", "spectral", "fruchterman_reingold"],
            index=0,
            help="Different algorithms create different visual patterns"
        )
    
    with col4:
        if st.button("ℹ️ Layout Help", help="Learn about layout algorithms"):
            st.info("""
            **Layout Algorithms:**
            - **Spring**: Good general purpose, nodes repel each other
            - **Kamada-Kawai**: High quality for small-medium networks
            - **Hierarchical**: Shows organizational structure
            - **Force-Directed**: Enhanced spring with weighted edges
            - **Circular**: Nodes arranged in a circle
            - **Spectral**: Uses graph's eigenvalues for positioning
            """)
    
    # Advanced Filters
    st.subheader("🔍 Advanced Filters")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        min_connections = st.slider(
            "Minimum Connections",
            min_value=1,
            max_value=50,
            value=2,
            help="Filter out nodes with fewer connections"
        )
    
    with col2:
        status_filter = st.multiselect(
            "Risk Status",
            ["critical", "high", "medium", "low"],
            default=["critical", "high", "medium", "low"],
            help="Include emails with these risk levels"
        )
    
    with col3:
        max_nodes = st.slider(
            "Maximum Nodes",
            min_value=10,
            max_value=500,
            value=100,
            help="Limit nodes for better performance"
        )
    
    with col4:
        show_risk_edges = st.checkbox(
            "Highlight Risk Edges",
            value=True,
            help="Color edges by risk level"
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
                st.subheader("⚠️ Risk Analysis")
                
                G = graph_data['graph']
                
                # Risk distribution analysis
                risk_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0}
                total_emails = 0
                
                for edge in G.edges():
                    edge_data = G[edge[0]][edge[1]]
                    risk_levels = edge_data.get('risk_levels', [])
                    total_emails += edge_data.get('weight', 1)
                    
                    for risk in risk_levels:
                        risk_lower = risk.lower()
                        if risk_lower in risk_stats:
                            risk_stats[risk_lower] += 1
                
                # Risk visualization
                col1, col2 = st.columns(2)
                
                with col1:
                    fig_risk = px.pie(
                        values=list(risk_stats.values()),
                        names=list(risk_stats.keys()),
                        title="Risk Level Distribution",
                        color_discrete_map={
                            'critical': '#ff4444',
                            'high': '#ff8800',
                            'medium': '#ffcc00',
                            'low': '#44aa44',
                            'unknown': '#888888'
                        }
                    )
                    st.plotly_chart(fig_risk, use_container_width=True)
                
                with col2:
                    st.markdown("**🚨 Risk Summary**")
                    st.metric("Total Emails", total_emails)
                    st.metric("High Risk Connections", risk_stats['critical'] + risk_stats['high'])
                    st.metric("Risk Ratio", f"{((risk_stats['critical'] + risk_stats['high']) / max(sum(risk_stats.values()), 1) * 100):.1f}%")
                    
                    if risk_stats['critical'] > 0:
                        st.error(f"⚠️ {risk_stats['critical']} critical risk connections found!")
                    elif risk_stats['high'] > 0:
                        st.warning(f"🔶 {risk_stats['high']} high risk connections found!")
                    else:
                        st.success("✅ No critical risk connections detected!")
            
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
        st.metric("Business Domains", classifications.get('business', 0))
    
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
    
    tab1, tab2, tab3 = st.tabs(["View Classifications", "Add Domain", "Bulk Operations"])
    
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
    
    # Sidebar navigation
    st.sidebar.title("🛡️ ExfilEye DLP")
    st.sidebar.markdown("Data Loss Prevention Email Monitoring")
    
    # Navigation menu
    pages = {
        "📁 Data Upload & Preprocessing": data_upload_page,
        "🛡️ Security Operations Dashboard": security_operations_dashboard,
        "📨 Follow-up Center": followup_center_page,
        "✅ Email Check Completed": email_check_completed_page,
        "🔗 Network Analysis": network_analysis_page,
        "🌐 Domain Classification": domain_classification_page
    }
    
    selected_page = st.sidebar.radio("Navigate to:", list(pages.keys()))
    
    # Display current data status
    if st.session_state.data:
        st.sidebar.success(f"✅ Data loaded: {len(st.session_state.data):,} records")
    else:
        st.sidebar.warning("⚠️ No data loaded")
    
    # System status
    st.sidebar.subheader("System Status")
    st.sidebar.write(f"🔍 Active Reviews: {len(st.session_state.data) - len(st.session_state.completed_reviews) - len(st.session_state.escalated_records) if st.session_state.data else 0}")
    st.sidebar.write(f"✅ Completed: {len(st.session_state.completed_reviews)}")
    st.sidebar.write(f"📨 Escalated: {len(st.session_state.escalated_records)}")
    
    # Data persistence controls
    st.sidebar.subheader("💾 Data Persistence")
    persistence = st.session_state.data_persistence
    
    col1, col2 = st.sidebar.columns(2)
    
    with col1:
        if st.button("💾 Save Work", help="Save current work state"):
            save_work_state()
            st.session_state.last_manual_save = datetime.now()
    
    with col2:
        available_dates = persistence.get_available_dates()
        if available_dates:
            st.caption(f"📅 {len(available_dates)} dates available")
    
    # Show last saved timestamp
    if 'last_manual_save' in st.session_state:
        last_save_time = st.session_state.last_manual_save
        time_diff = datetime.now() - last_save_time
        
        if time_diff.total_seconds() < 60:
            st.sidebar.success(f"✅ Last saved: {int(time_diff.total_seconds())}s ago")
        elif time_diff.total_seconds() < 3600:
            st.sidebar.info(f"💾 Last saved: {int(time_diff.total_seconds() / 60)}m ago")
        else:
            st.sidebar.info(f"💾 Last saved: {last_save_time.strftime('%H:%M')}")
    else:
        # Check if there's a saved work state file to show when it was last saved
        work_state_file = os.path.join(persistence.work_state_folder, f"work_state_{datetime.now().strftime('%Y-%m-%d')}.json")
        if os.path.exists(work_state_file):
            file_mtime = datetime.fromtimestamp(os.path.getmtime(work_state_file))
            time_diff = datetime.now() - file_mtime
            
            if time_diff.total_seconds() < 60:
                st.sidebar.info(f"💾 Last saved: {int(time_diff.total_seconds())}s ago")
            elif time_diff.total_seconds() < 3600:
                st.sidebar.info(f"💾 Last saved: {int(time_diff.total_seconds() / 60)}m ago")
            else:
                st.sidebar.info(f"💾 Last saved: {file_mtime.strftime('%H:%M')}")
        else:
            st.sidebar.warning("⚠️ No recent saves found")
    
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

def auto_save_work_state():
    """Auto-save work state periodically"""
    # Check if we have any work to save
    if (st.session_state.completed_reviews or 
        st.session_state.escalated_records or 
        st.session_state.follow_up_decisions):
        
        # Save every few interactions (simple approach)
        if 'last_auto_save' not in st.session_state:
            st.session_state.last_auto_save = 0
        
        current_count = (len(st.session_state.completed_reviews) + 
                        len(st.session_state.escalated_records))
        
        # Auto-save every 5 actions
        if current_count > 0 and current_count % 5 == 0 and current_count != st.session_state.last_auto_save:
            save_work_state()
            st.session_state.last_auto_save = current_count
            st.session_state.last_manual_save = datetime.now()  # Track auto-save time too

if __name__ == "__main__":
    main()