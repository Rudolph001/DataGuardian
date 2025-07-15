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
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from openai import OpenAI
import re
import webbrowser
from urllib.parse import quote

# Import custom modules
from domain_classifier import DomainClassifier
from security_config import SecurityConfig

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
    if 'follow_up_decisions' not in st.session_state:
        st.session_state.follow_up_decisions = {}
    if 'blocked_domains' not in st.session_state:
        st.session_state.blocked_domains = []
    if 'sender_status' not in st.session_state:
        st.session_state.sender_status = {}
    if 'completed_reviews' not in st.session_state:
        st.session_state.completed_reviews = {}
    if 'escalated_records' not in st.session_state:
        st.session_state.escalated_records = {}
    if 'domain_classifier' not in st.session_state:
        st.session_state.domain_classifier = DomainClassifier()
    if 'security_config' not in st.session_state:
        st.session_state.security_config = SecurityConfig()

initialize_session_state()

class CSVProcessor:
    """Custom CSV processor for handling large files without pandas"""
    
    def __init__(self):
        self.required_fields = [
            '_time', 'sender', 'subject', 'attachment', 'recipients',
            'recipients_email_domain', 'minecast', 'tessian', 'leaver', 
            'Termination', '_time_month', 'account_type', 'wordlist_attachment',
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
                    1 if email.get('attachment') else 0,
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
    """Network analysis for email communication patterns"""
    
    def __init__(self):
        self.layout_options = {
            'spring': nx.spring_layout,
            'circular': nx.circular_layout,
            'hierarchical': self._hierarchical_layout,
            'fruchterman_reingold': nx.fruchterman_reingold_layout
        }
    
    def create_network_graph(self, data, source_field='sender', target_field='recipients', config=None):
        """Create interactive network graph using NetworkX and Plotly"""
        if not data:
            return None
        
        # Build graph
        G = self.build_network_from_data(data, source_field, target_field)
        
        if len(G.nodes()) == 0:
            return None
        
        # Calculate layout
        layout_type = config.get('layout', 'spring') if config else 'spring'
        pos = self.calculate_advanced_layout(G, layout_type)
        
        # Create Plotly figure
        fig = self._create_plotly_network(G, pos, config)
        
        return fig
    
    def build_network_from_data(self, data, source_field, target_field):
        """Build NetworkX graph from email data"""
        G = nx.Graph()
        
        for email in data:
            source = email.get(source_field, '')
            targets = email.get(target_field, '').split(',')
            
            for target in targets:
                target = target.strip()
                if source and target and source != target:
                    if G.has_edge(source, target):
                        G[source][target]['weight'] += 1
                    else:
                        G.add_edge(source, target, weight=1)
        
        return G
    
    def calculate_advanced_layout(self, G, layout_type):
        """Calculate node positions using specified layout algorithm"""
        if layout_type in self.layout_options:
            layout_func = self.layout_options[layout_type]
            try:
                return layout_func(G)
            except:
                return nx.spring_layout(G)
        else:
            return nx.spring_layout(G)
    
    def _hierarchical_layout(self, G):
        """Custom hierarchical layout"""
        try:
            # Simple hierarchical layout based on degree
            pos = {}
            degrees = dict(G.degree())
            sorted_nodes = sorted(degrees.items(), key=lambda x: x[1], reverse=True)
            
            levels = {}
            for i, (node, degree) in enumerate(sorted_nodes):
                level = min(i // 10, 5)  # Max 5 levels
                levels[node] = level
            
            for node, level in levels.items():
                angle = hash(node) % 360
                radius = level * 0.3
                pos[node] = (radius * np.cos(angle), radius * np.sin(angle))
            
            return pos
        except:
            return nx.spring_layout(G)
    
    def _create_plotly_network(self, G, pos, config):
        """Create Plotly network visualization"""
        # Extract node and edge information
        edge_x = []
        edge_y = []
        
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
        
        # Create edge trace
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='#888'),
            hoverinfo='none',
            mode='lines'
        )
        
        # Create node trace
        node_x = []
        node_y = []
        node_text = []
        node_info = []
        
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            
            # Node information
            adjacencies = list(G.neighbors(node))
            node_text.append(f'{node}<br>Connections: {len(adjacencies)}')
            node_info.append(f'Node: {node}<br>Degree: {G.degree(node)}')
        
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            text=node_text,
            hovertext=node_info,
            marker=dict(
                size=10,
                color=[G.degree(node) for node in G.nodes()],
                colorscale='Viridis',
                showscale=True,
                colorbar=dict(title="Node Connections")
            )
        )
        
        # Create figure
        fig = go.Figure(data=[edge_trace, node_trace],
                       layout=go.Layout(
                           title='Email Communication Network',
                           titlefont_size=16,
                           showlegend=False,
                           hovermode='closest',
                           margin=dict(b=20,l=5,r=5,t=40),
                           annotations=[dict(
                               text="Click on nodes to see details",
                               showarrow=False,
                               xref="paper", yref="paper",
                               x=0.005, y=-0.002,
                               xanchor="left", yanchor="bottom",
                               font=dict(color="#888", size=12)
                           )],
                           xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                       ))
        
        return fig

class ReportGenerator:
    """PDF report generation for security reviews"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Title'],
            fontSize=18,
            spaceAfter=30,
        )
    
    def generate_pdf_report(self, data, report_type='security_review'):
        """Generate PDF report based on data and report type"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []
        
        # Title
        title = f"ExfilEye Security Report - {report_type.replace('_', ' ').title()}"
        story.append(Paragraph(title, self.title_style))
        story.append(Spacer(1, 12))
        
        # Report date
        report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        story.append(Paragraph(f"Generated: {report_date}", self.styles['Normal']))
        story.append(Spacer(1, 12))
        
        if report_type == 'security_review':
            story.extend(self._generate_security_review_content(data))
        elif report_type == 'domain_analysis':
            story.extend(self._generate_domain_analysis_content(data))
        elif report_type == 'network_analysis':
            story.extend(self._generate_network_analysis_content(data))
        
        doc.build(story)
        buffer.seek(0)
        return buffer
    
    def _generate_security_review_content(self, data):
        """Generate security review report content"""
        story = []
        
        # Summary section
        story.append(Paragraph("Executive Summary", self.styles['Heading1']))
        story.append(Spacer(1, 12))
        
        if data:
            total_emails = len(data)
            critical_count = sum(1 for email in data if email.get('status') == 'critical')
            high_count = sum(1 for email in data if email.get('status') == 'high')
            
            summary_text = f"""
            Total emails analyzed: {total_emails:,}<br/>
            Critical risk emails: {critical_count:,}<br/>
            High risk emails: {high_count:,}<br/>
            Review completion rate: {len(st.session_state.completed_reviews) / max(total_emails, 1) * 100:.1f}%
            """
            story.append(Paragraph(summary_text, self.styles['Normal']))
        else:
            story.append(Paragraph("No data available for analysis.", self.styles['Normal']))
        
        story.append(Spacer(1, 12))
        
        # Risk distribution table
        if data:
            story.append(Paragraph("Risk Distribution", self.styles['Heading2']))
            story.append(Spacer(1, 12))
            
            risk_counts = {}
            for email in data:
                status = email.get('status', 'unknown')
                risk_counts[status] = risk_counts.get(status, 0) + 1
            
            table_data = [['Risk Level', 'Count', 'Percentage']]
            for risk, count in sorted(risk_counts.items()):
                percentage = (count / len(data)) * 100
                table_data.append([risk.title(), str(count), f"{percentage:.1f}%"])
            
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
        'low': '🟢'
    }
    return indicators.get(status.lower(), '⚪')

def show_email_details_modal(email):
    """Show email details in expandable section with all fields"""
    # Create a clean title for the expander
    subject_preview = email.get('subject', 'No Subject')[:50]
    if len(email.get('subject', '')) > 50:
        subject_preview += "..."
    
    with st.expander(f"📧 Email Details - {subject_preview}"):
        # Create organized sections for better readability
        
        # Primary Email Information
        st.markdown("### 📧 Email Information")
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown(f"**From:** {email.get('sender', 'Unknown')}")
            st.markdown(f"**To:** {email.get('recipients', 'Unknown')}")
            st.markdown(f"**Subject:** {email.get('subject', 'No Subject')}")
            st.markdown(f"**Time:** {email.get('_time', 'Unknown')}")
            st.markdown(f"**Time Month:** {email.get('_time_month', 'Unknown')}")
        
        with col2:
            st.markdown(f"**Recipients Domain:** {email.get('recipients_email_domain', 'Unknown')}")
            attachment_value = email.get('attachment', '')
            if attachment_value and attachment_value not in [True, False, 'True', 'False']:
                st.markdown(f"**Attachment:** 📎 {attachment_value}")
            elif attachment_value:
                st.markdown(f"**Attachment:** ✅ Yes")
            else:
                st.markdown(f"**Attachment:** ❌ No")
            risk_status = email.get('status', 'Unknown')
            st.markdown(f"**Risk Status:** {get_risk_indicator(risk_status)} {risk_status.title()}")
            termination_value = email.get('Termination', '')
            if termination_value:
                st.markdown(f"**Termination:** ⚠️ {termination_value}")
            else:
                st.markdown(f"**Termination:** ✅ No")
        
        # Security & Compliance Section
        st.markdown("### 🔒 Security & Compliance")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown(f"**Minecast:** {'✅ Yes' if email.get('minecast') else '❌ No'}")
            st.markdown(f"**Tessian:** {'✅ Yes' if email.get('tessian') else '❌ No'}")
            st.markdown(f"**Tessian Status A:** {email.get('tessian_status_A', 'Unknown')}")
        
        with col2:
            st.markdown(f"**Tessian Status B:** {email.get('tessian_status_B', 'Unknown')}")
            st.markdown(f"**Wordlist Attachment:** {'⚠️ Yes' if email.get('wordlist_attachment') else '✅ No'}")
            st.markdown(f"**Wordlist Subject:** {'⚠️ Yes' if email.get('wordlist_subject') else '✅ No'}")
        
        with col3:
            st.markdown(f"**Leaver:** {'⚠️ Yes' if email.get('leaver') else '✅ No'}")
            st.markdown(f"**Termination:** {'⚠️ Yes' if email.get('Termination') else '✅ No'}")
        
        # Organizational Information
        st.markdown("### 🏢 Organizational Information")
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown(f"**Department:** {email.get('department', 'Unknown')}")
            st.markdown(f"**Business Unit:** {email.get('bunit', 'Unknown')}")
        
        with col2:
            st.markdown(f"**Account Type:** {email.get('account_type', 'Unknown')}")
        
        # Additional Fields (for any extra fields not explicitly handled)
        st.markdown("### 📋 Additional Fields")
        
        # Get all fields that weren't already displayed
        displayed_fields = {
            'sender', 'recipients', 'subject', '_time', '_time_month', 
            'recipients_email_domain', 'attachment', 'status', 'minecast', 
            'tessian', 'tessian_status_A', 'tessian_status_B', 'wordlist_attachment', 
            'wordlist_subject', 'leaver', 'Termination', 'department', 'bunit', 
            'account_type'
        }
        
        additional_fields = {k: v for k, v in email.items() if k not in displayed_fields}
        
        if additional_fields:
            cols = st.columns(2)
            for i, (field, value) in enumerate(additional_fields.items()):
                with cols[i % 2]:
                    # Format field name nicely
                    field_name = field.replace('_', ' ').title()
                    st.markdown(f"**{field_name}:** {value}")
        else:
            st.markdown("*No additional fields*")
        
        # Action buttons
        st.markdown("### 🔧 Actions")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Clear", key=f"clear_{hash(str(email))}", type="secondary"):
                email_id = str(hash(str(email)))
                st.session_state.completed_reviews[email_id] = {
                    'email': email,
                    'decision': 'clear',
                    'timestamp': datetime.now()
                }
                st.success("Email marked as cleared!")
                st.rerun()
        
        with col2:
            if st.button("Escalate", key=f"escalate_{hash(str(email))}", type="primary"):
                email_id = str(hash(str(email)))
                st.session_state.escalated_records[email_id] = {
                    'email': email,
                    'decision': 'escalate',
                    'timestamp': datetime.now()
                }
                st.success("Email escalated for follow-up!")
                st.rerun()
        
        

def generate_sample_data():
    """Generate sample email data for demonstration"""
    import random
    from datetime import datetime, timedelta
    
    # Sample data templates
    subjects = [
        "Quarterly Financial Report",
        "Employee Database Export",
        "Client Contact Information",
        "Project Blueprint Files",
        "Sensitive Customer Data",
        "Internal Security Protocols",
        "Confidential Meeting Notes",
        "System Access Credentials"
    ]
    
    senders = [
        "john.doe@company.com",
        "sarah.smith@company.com",
        "mike.johnson@company.com",
        "lisa.brown@company.com",
        "bob@company.com"
    ]
    
    external_domains = [
        "gmail.com", "yahoo.com", "hotmail.com", "competitor.com",
        "suspicious-domain.net", "personal-email.org", "outlook.com"
    ]
    
    departments = ["Finance", "HR", "IT", "Sales", "Marketing", "Legal"]
    bunits = ["Corporate", "Regional", "International", "Subsidiary"]
    statuses = ["critical", "high", "medium", "low"]
    
    sample_data = []
    
    for i in range(50):  # Generate 50 sample records
        # Random email recipient
        recipient_domain = random.choice(external_domains)
        recipient = f"recipient{i}@{recipient_domain}"
        
        # Random timestamp in last 30 days
        days_ago = random.randint(0, 30)
        timestamp = datetime.now() - timedelta(days=days_ago)
        
        email_record = {
            "_time": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "sender": random.choice(senders),
            "subject": random.choice(subjects),
            "attachment": random.choice([True, False]),
            "recipients": recipient,
            "recipients_email_domain": recipient_domain,
            "minecast": random.choice([True, False]),
            "tessian": random.choice([True, False]),
            "leaver": random.choice([True, False]),
            "Termination": random.choice([True, False]),
            "_time_month": timestamp.strftime("%Y-%m"),
            "account_type": random.choice(["internal", "external", "contractor"]),
            "wordlist_attachment": random.choice([True, False]),
            "wordlist_subject": random.choice([True, False]),
            "bunit": random.choice(bunits),
            "department": random.choice(departments),
            "status": random.choice(statuses),
            "tessian_status_A": random.choice(["pass", "fail", "warning"]),
            "tessian_status_B": random.choice(["pass", "fail", "warning"])
        }
        
        sample_data.append(email_record)
    
    return sample_data

def data_upload_page():
    """Data Upload & Preprocessing page"""
    st.title("📁 Data Upload & Preprocessing")
    
    st.markdown("""
    Upload CSV files up to 2GB containing email metadata for analysis.
    The system will validate required fields and process the data for security monitoring.
    """)
    
    # Option to use sample data
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.subheader("Upload Your Data")
    
    with col2:
        if st.button("Use Sample Data", type="secondary"):
            sample_data = generate_sample_data()
            st.session_state.data = sample_data
            st.success(f"Generated {len(sample_data)} sample email records!")
            st.info("Sample data loaded. You can now explore the Security Operations Dashboard and other features.")
            st.rerun()
    
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
            ["All", "Critical", "High", "Medium", "Low"]
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
    
    st.subheader(f"Security Review Queue ({len(filtered_records):,} records)")
    
    # Risk metrics
    col1, col2, col3, col4 = st.columns(4)
    
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
            time_month = email.get('_time_month', 'Unknown')
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
    
    # Display grouped records
    for group_name, group_emails in sorted(grouped_records.items()):
        if not group_emails:
            continue
        
        # Risk distribution in group
        risk_counts = {}
        for email in group_emails:
            status = email.get('status', 'unknown').lower()
            risk_counts[status] = risk_counts.get(status, 0) + 1
        
        risk_indicators = []
        for status in ['critical', 'high', 'medium', 'low']:
            count = risk_counts.get(status, 0)
            if count > 0:
                risk_indicators.append(f"{get_risk_indicator(status)} {count}")
        
        risk_text = " | ".join(risk_indicators) if risk_indicators else "No risks"
        
        with st.expander(f"**{group_name}** ({len(group_emails)} emails) - {risk_text}"):
            # Show first few emails in group with individual risk indicators
            for email in group_emails[:10]:  # Limit to first 10
                # Get individual email risk status
                email_status = email.get('status', 'unknown').lower()
                risk_icon = get_risk_indicator(email_status)
                
                # Create a modified email title with risk indicator
                subject_preview = email.get('subject', 'No Subject')[:50]
                if len(email.get('subject', '')) > 50:
                    subject_preview += "..."
                
                # Show email with risk indicator in title
                with st.expander(f"{risk_icon} {email_status.title()} - {subject_preview}"):
                    # Create organized sections for better readability
                    
                    # Primary Email Information
                    st.markdown("### 📧 Email Information")
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown(f"**From:** {email.get('sender', 'Unknown')}")
                        st.markdown(f"**To:** {email.get('recipients', 'Unknown')}")
                        st.markdown(f"**Subject:** {email.get('subject', 'No Subject')}")
                        st.markdown(f"**Time:** {email.get('_time', 'Unknown')}")
                        st.markdown(f"**Time Month:** {email.get('_time_month', 'Unknown')}")
                    
                    with col2:
                        st.markdown(f"**Recipients Domain:** {email.get('recipients_email_domain', 'Unknown')}")
                        attachment_value = email.get('attachment', '')
                        if attachment_value and attachment_value not in [True, False, 'True', 'False']:
                            st.markdown(f"**Attachment:** 📎 {attachment_value}")
                        elif attachment_value:
                            st.markdown(f"**Attachment:** ✅ Yes")
                        else:
                            st.markdown(f"**Attachment:** ❌ No")
                        st.markdown(f"**Risk Status:** {risk_icon} {email_status.title()}")
                        termination_value = email.get('Termination', '')
                        if termination_value:
                            st.markdown(f"**Termination:** ⚠️ {termination_value}")
                        else:
                            st.markdown(f"**Termination:** ✅ No")
                    
                    # Security & Compliance Section
                    st.markdown("### 🔒 Security & Compliance")
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.markdown(f"**Minecast:** {'✅ Yes' if email.get('minecast') else '❌ No'}")
                        st.markdown(f"**Tessian:** {'✅ Yes' if email.get('tessian') else '❌ No'}")
                        st.markdown(f"**Tessian Status A:** {email.get('tessian_status_A', 'Unknown')}")
                    
                    with col2:
                        st.markdown(f"**Tessian Status B:** {email.get('tessian_status_B', 'Unknown')}")
                        st.markdown(f"**Wordlist Attachment:** {'⚠️ Yes' if email.get('wordlist_attachment') else '✅ No'}")
                        st.markdown(f"**Wordlist Subject:** {'⚠️ Yes' if email.get('wordlist_subject') else '✅ No'}")
                    
                    with col3:
                        st.markdown(f"**Leaver:** {'⚠️ Yes' if email.get('leaver') else '✅ No'}")
                        st.markdown(f"**Termination:** {'⚠️ Yes' if email.get('Termination') else '✅ No'}")
                    
                    # Organizational Information
                    st.markdown("### 🏢 Organizational Information")
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown(f"**Department:** {email.get('department', 'Unknown')}")
                        st.markdown(f"**Business Unit:** {email.get('bunit', 'Unknown')}")
                    
                    with col2:
                        st.markdown(f"**Account Type:** {email.get('account_type', 'Unknown')}")
                    
                    # Additional Fields (for any extra fields not explicitly handled)
                    st.markdown("### 📋 Additional Fields")
                    
                    # Get all fields that weren't already displayed
                    displayed_fields = {
                        'sender', 'recipients', 'subject', '_time', '_time_month', 
                        'recipients_email_domain', 'attachment', 'status', 'minecast', 
                        'tessian', 'tessian_status_A', 'tessian_status_B', 'wordlist_attachment', 
                        'wordlist_subject', 'leaver', 'Termination', 'department', 'bunit', 
                        'account_type'
                    }
                    
                    additional_fields = {k: v for k, v in email.items() if k not in displayed_fields}
                    
                    if additional_fields:
                        cols = st.columns(2)
                        for i, (field, value) in enumerate(additional_fields.items()):
                            with cols[i % 2]:
                                # Format field name nicely
                                field_name = field.replace('_', ' ').title()
                                st.markdown(f"**{field_name}:** {value}")
                    else:
                        st.markdown("*No additional fields*")
                    
                    # Action buttons
                    st.markdown("### 🔧 Actions")
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if st.button("Clear", key=f"clear_{hash(str(email))}", type="secondary"):
                            email_id = str(hash(str(email)))
                            st.session_state.completed_reviews[email_id] = {
                                'email': email,
                                'decision': 'clear',
                                'timestamp': datetime.now()
                            }
                            st.success("Email marked as cleared!")
                            st.rerun()
                    
                    with col2:
                        if st.button("Escalate", key=f"escalate_{hash(str(email))}", type="primary"):
                            email_id = str(hash(str(email)))
                            st.session_state.escalated_records[email_id] = {
                                'email': email,
                                'decision': 'escalate',
                                'timestamp': datetime.now()
                            }
                            st.success("Email escalated for follow-up!")
                            st.rerun()
            
            if len(group_emails) > 10:
                st.info(f"Showing first 10 of {len(group_emails)} emails in this group")



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
    for review_id, review in completed_reviews.items():
        # Apply filters
        if date_filter and review['timestamp'].date() != date_filter:
            continue
        
        if decision_filter != "All" and review['decision'] != decision_filter.lower():
            continue
        
        filtered_reviews.append((review_id, review))
    
    if filtered_reviews:
        for review_id, review in filtered_reviews:
            email = review['email']
            decision = review['decision']
            timestamp = review['timestamp']
            
            with st.expander(f"📧 {email.get('subject', 'No Subject')[:50]}... - {decision.title()} ({timestamp.strftime('%Y-%m-%d %H:%M')})"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**From:** {email.get('sender', 'Unknown')}")
                    st.write(f"**To:** {email.get('recipients', 'Unknown')}")
                    st.write(f"**Domain:** {email.get('recipients_email_domain', 'Unknown')}")
                    st.write(f"**Status:** {get_risk_indicator(email.get('status', 'unknown'))} {email.get('status', 'Unknown').title()}")
                
                with col2:
                    st.write(f"**Decision:** {decision.title()}")
                    st.write(f"**Review Time:** {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
                    st.write(f"**Reviewer:** Security Analyst")
                    st.write(f"**Department:** {email.get('department', 'Unknown')}")
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
        
        with st.expander(f"📧 {email.get('subject', 'No Subject')[:50]}... - {followup_status.title()}"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**From:** {email.get('sender', 'Unknown')}")
                st.write(f"**To:** {email.get('recipients', 'Unknown')}")
                st.write(f"**Domain:** {email.get('recipients_email_domain', 'Unknown')}")
                st.write(f"**Status:** {get_risk_indicator(email.get('status', 'unknown'))} {email.get('status', 'Unknown').title()}")
                st.write(f"**Escalated:** {escalation_time.strftime('%Y-%m-%d %H:%M')}")
            
            with col2:
                st.write(f"**Follow-up Status:** {followup_status.title()}")
                st.write(f"**Department:** {email.get('department', 'Unknown')}")
                st.write(f"**Business Unit:** {email.get('bunit', 'Unknown')}")
                st.write(f"**Account Type:** {email.get('account_type', 'Unknown')}")
            
            # Follow-up actions
            st.subheader("Follow-up Actions")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                if st.button("Generate Email Template", key=f"email_{record_id}"):
                    template = generate_followup_email(email)
                    st.text_area("Email Template", template, height=200)
                    
                    # Create mailto link with proper formatting
                    subject = f"Security Alert - {email.get('subject', 'Email Security Issue')}"
                    # Clean template for mailto - remove extra line breaks and format properly
                    clean_body = template.replace('\n\n', '\n').strip()
                    
                    # Create the mailto link without over-encoding
                    mailto_link = f"mailto:{email.get('sender', '')}?subject={quote(subject)}&body={quote(clean_body)}"
                    
                    st.markdown(f"[📧 Open in Outlook]({mailto_link})")
            
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

def generate_followup_email(email):
    """Generate follow-up email template"""
    # Create clean, professional email content
    sender_name = email.get('sender', 'Team Member').split('@')[0].replace('.', ' ').title()
    subject = email.get('subject', 'No Subject')
    recipient = email.get('recipients', 'Unknown')
    domain = email.get('recipients_email_domain', 'Unknown')
    risk_level = email.get('status', 'Unknown').title()
    date_sent = email.get('_time', 'Unknown')
    
    template = f"""SECURITY ALERT - Email Review Required

Dear {sender_name},

Our security monitoring system has flagged an email communication that requires your immediate attention and review.

EMAIL DETAILS:
From: {email.get('sender', 'Unknown')}
To: {recipient}
Subject: {subject}
Date: {date_sent}
Risk Level: {risk_level}
Recipient Domain: {domain}

REQUIRED ACTIONS:
This email has been escalated due to potential security concerns. Please review the communication and confirm:

1. Was this email sent intentionally?
2. Does the recipient have authorization to receive this information?
3. Are there any sensitive data or attachments that should not have been shared?

RESPONSE REQUIRED:
Please respond to this email within 24 hours with your confirmation and any additional context.

If you have any questions or concerns, please contact the Security Team immediately.

Best regards,
Security Team
ExfilEye Data Loss Prevention System

This is an automated security alert from the ExfilEye DLP system."""
    
    return template

def network_analysis_page():
    """Network Analysis page"""
    st.title("🔗 Network Analysis")
    
    if not st.session_state.data:
        st.warning("Please upload data first in the Data Upload & Preprocessing section.")
        return
    
    st.markdown("""
    Analyze email communication patterns and relationships using interactive network graphs.
    Identify clusters, anomalies, and communication patterns in your email data.
    """)
    
    data = st.session_state.data
    
    # Network configuration
    st.subheader("Network Configuration")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        source_field = st.selectbox(
            "Source Field",
            ["sender", "recipients", "recipients_email_domain"],
            index=0
        )
    
    with col2:
        target_field = st.selectbox(
            "Target Field",
            ["recipients", "recipients_email_domain", "sender"],
            index=0
        )
    
    with col3:
        layout_type = st.selectbox(
            "Layout Algorithm",
            ["spring", "circular", "hierarchical", "fruchterman_reingold"],
            index=0
        )
    
    # Filters
    st.subheader("Filters")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        min_connections = st.slider(
            "Minimum Connections",
            min_value=1,
            max_value=50,
            value=2,
            help="Minimum number of connections for a node to be displayed"
        )
    
    with col2:
        status_filter = st.multiselect(
            "Risk Status",
            ["critical", "high", "medium", "low"],
            default=["critical", "high", "medium", "low"]
        )
    
    with col3:
        max_nodes = st.slider(
            "Maximum Nodes",
            min_value=10,
            max_value=500,
            value=100,
            help="Maximum number of nodes to display for performance"
        )
    
    # Filter data
    filtered_data = [
        email for email in data 
        if email.get('status', '').lower() in status_filter
    ]
    
    # Generate network
    if st.button("Generate Network Graph", type="primary"):
        if filtered_data:
            with st.spinner("Generating network graph..."):
                analyzer = NetworkAnalyzer()
                
                config = {
                    'layout': layout_type,
                    'min_connections': min_connections,
                    'max_nodes': max_nodes
                }
                
                # Create network graph
                fig = analyzer.create_network_graph(filtered_data, source_field, target_field, config)
                
                if fig:
                    st.plotly_chart(fig, use_container_width=True)
                    
                    # Network statistics
                    st.subheader("Network Statistics")
                    
                    G = analyzer.build_network_from_data(filtered_data, source_field, target_field)
                    
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.metric("Total Nodes", len(G.nodes()))
                    
                    with col2:
                        st.metric("Total Edges", len(G.edges()))
                    
                    with col3:
                        avg_degree = np.mean([d for n, d in G.degree()]) if G.nodes() else 0
                        st.metric("Average Degree", f"{avg_degree:.2f}")
                    
                    with col4:
                        density = nx.density(G) if G.nodes() else 0
                        st.metric("Network Density", f"{density:.4f}")
                    
                    # Top nodes analysis
                    st.subheader("Top Connected Nodes")
                    
                    if G.nodes():
                        degree_centrality = nx.degree_centrality(G)
                        top_nodes = sorted(degree_centrality.items(), key=lambda x: x[1], reverse=True)[:10]
                        
                        for i, (node, centrality) in enumerate(top_nodes):
                            st.write(f"{i+1}. **{node}** - Centrality: {centrality:.4f}")
                    
                    # Community detection
                    st.subheader("Community Detection")
                    
                    try:
                        import networkx.algorithms.community as nx_comm
                        communities = list(nx_comm.greedy_modularity_communities(G))
                        
                        st.write(f"**Number of Communities:** {len(communities)}")
                        
                        for i, community in enumerate(communities[:5]):  # Show first 5 communities
                            st.write(f"**Community {i+1}** ({len(community)} nodes): {', '.join(list(community)[:10])}")
                            if len(community) > 10:
                                st.write(f"... and {len(community) - 10} more")
                    
                    except ImportError:
                        st.info("Community detection requires additional packages.")
                    
                else:
                    st.error("Unable to generate network graph. Please check your data and filters.")
        else:
            st.error("No data matches the selected filters.")

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
        
        category_filter = st.selectbox(
            "Filter by Category",
            ["All", "Suspicious", "Free Email", "Business", "Government", "Financial", "Cloud Providers"]
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
                        
                        new_category = st.selectbox(
                            "Change Category",
                            ["Suspicious", "Free Email", "Business", "Government", "Financial", "Cloud Providers"],
                            index=["Suspicious", "Free Email", "Business", "Government", "Financial", "Cloud Providers"].index(domain_info['category']),
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
                ["Suspicious", "Free Email", "Business", "Government", "Financial", "Cloud Providers"]
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
            ["Suspicious", "Free Email", "Business", "Government", "Financial", "Cloud Providers"],
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
    # Sidebar navigation
    st.sidebar.title("🛡️ ExfilEye DLP")
    st.sidebar.markdown("Data Loss Prevention Email Monitoring")
    
    # Navigation menu
    pages = {
        "📁 Data Upload & Preprocessing": data_upload_page,
        "🛡️ Security Operations Dashboard": security_operations_dashboard,
        "✅ Email Check Completed": email_check_completed_page,
        "📨 Follow-up Center": followup_center_page,
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
    
    # API status
    if openai_client:
        st.sidebar.success("🤖 AI: Connected")
    else:
        st.sidebar.error("🤖 AI: Not configured")
    
    # Run selected page
    pages[selected_page]()

if __name__ == "__main__":
    main()
