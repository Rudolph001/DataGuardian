import json
import os
from datetime import datetime
from typing import Dict, List, Optional

class DomainClassifier:
    """Domain classification system for email recipients"""
    
    def __init__(self):
        self.domains_file = "domains.json"
        self.classifications = {
            'Suspicious': [],
            'Free Email': [
                'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
                'aol.com', 'icloud.com', 'protonmail.com', 'tutanota.com',
                'yandex.com', 'mail.com', 'zoho.com', 'gmx.com'
            ],
            'Business': [],
            'Government': [
                'gov', 'mil', 'edu', 'state.gov', 'usa.gov',
                'nih.gov', 'fda.gov', 'cdc.gov', 'nist.gov'
            ],
            'Financial': [
                'jpmorgan.com', 'bankofamerica.com', 'wellsfargo.com',
                'citi.com', 'goldmansachs.com', 'morganstanley.com',
                'amex.com', 'visa.com', 'mastercard.com', 'paypal.com'
            ],
            'Cloud Providers': [
                'amazon.com', 'aws.com', 'microsoft.com', 'google.com',
                'azure.com', 'salesforce.com', 'dropbox.com', 'box.com',
                'slack.com', 'zoom.us', 'atlassian.com'
            ],
            'Social Media': [
                'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com',
                'tiktok.com', 'snapchat.com', 'reddit.com', 'youtube.com',
                'discord.com', 'telegram.org', 'whatsapp.com'
            ],
            'News Media': [
                'cnn.com', 'bbc.com', 'reuters.com', 'bloomberg.com',
                'wsj.com', 'nytimes.com', 'washingtonpost.com', 'forbes.com',
                'techcrunch.com', 'theverge.com', 'wired.com'
            ],
            'Educational': [
                'harvard.edu', 'mit.edu', 'stanford.edu', 'berkeley.edu',
                'oxford.ac.uk', 'cambridge.ac.uk', 'coursera.org',
                'edx.org', 'udemy.com', 'khanacademy.org'
            ],
            'Healthcare': [
                'mayo.edu', 'clevelandclinic.org', 'johnshopkins.edu',
                'cdc.gov', 'who.int', 'nih.gov', 'fda.gov',
                'webmd.com', 'healthline.com', 'medlineplus.gov'
            ],
            'Legal': [
                'courts.gov', 'justice.gov', 'sec.gov', 'irs.gov',
                'copyright.gov', 'patent.gov', 'ftc.gov',
                'aclu.org', 'eff.org', 'law.com'
            ],
            'Technology': [
                'apple.com', 'microsoft.com', 'google.com', 'amazon.com',
                'meta.com', 'tesla.com', 'netflix.com', 'uber.com',
                'airbnb.com', 'github.com', 'stackoverflow.com'
            ],
            'Non-Profit': [
                'redcross.org', 'unicef.org', 'oxfam.org', 'savethechildren.org',
                'greenpeace.org', 'amnesty.org', 'doctors-without-borders.org',
                'habitat.org', 'unitedway.org', 'cancer.org'
            ],
            'Personal': [],
            'Unknown': [],
            'Blocked': []
        }
        
        self.load_domains()
    
    def load_domains(self):
        """Load domain classifications from file"""
        try:
            if os.path.exists(self.domains_file):
                with open(self.domains_file, 'r') as f:
                    saved_domains = json.load(f)
                    
                # Merge saved domains with defaults
                for category, domains in saved_domains.items():
                    if category in self.classifications:
                        # Add saved domains to existing list, avoiding duplicates
                        existing = set(self.classifications[category])
                        for domain_info in domains:
                            if isinstance(domain_info, dict):
                                domain = domain_info.get('domain', '')
                            else:
                                domain = str(domain_info)
                            
                            if domain and domain not in existing:
                                self.classifications[category].append(domain)
        except Exception as e:
            print(f"Error loading domains: {e}")
    
    def save_domains(self):
        """Save domain classifications to file"""
        try:
            # Convert to saveable format
            save_data = {}
            for category, domains in self.classifications.items():
                save_data[category] = []
                for domain in domains:
                    if isinstance(domain, str):
                        save_data[category].append({
                            'domain': domain,
                            'added_date': datetime.now().isoformat()
                        })
                    else:
                        save_data[category].append(domain)
            
            with open(self.domains_file, 'w') as f:
                json.dump(save_data, f, indent=2)
        except Exception as e:
            print(f"Error saving domains: {e}")
    
    def classify_domain(self, domain: str) -> str:
        """Classify a domain into one of the categories"""
        if not domain:
            return 'Unknown'
        
        domain = domain.lower().strip()
        
        # Check each category
        for category, domains in self.classifications.items():
            for classified_domain in domains:
                if isinstance(classified_domain, dict):
                    classified_domain = classified_domain.get('domain', '')
                
                classified_domain = str(classified_domain).lower()
                
                # Exact match or subdomain match
                if domain == classified_domain or domain.endswith('.' + classified_domain):
                    return category
        
        # Default classification logic
        if any(free_domain in domain for free_domain in ['gmail', 'yahoo', 'hotmail', 'outlook']):
            return 'Free Email'
        elif domain.endswith('.gov') or domain.endswith('.mil') or domain.endswith('.edu'):
            return 'Government'
        elif any(cloud in domain for cloud in ['aws', 'azure', 'google', 'microsoft']):
            return 'Cloud Providers'
        else:
            return 'Business'  # Default to business
    
    def add_domain(self, domain: str, category: str):
        """Add a domain to a specific category"""
        if not domain or category not in self.classifications:
            return False
        
        domain = domain.lower().strip()
        
        # Remove from other categories first
        for cat, domains in self.classifications.items():
            self.classifications[cat] = [
                d for d in domains 
                if (isinstance(d, dict) and d.get('domain') != domain) or 
                   (isinstance(d, str) and d != domain)
            ]
        
        # Add to new category
        domain_info = {
            'domain': domain,
            'added_date': datetime.now().isoformat(),
            'added_by': 'user'
        }
        
        self.classifications[category].append(domain_info)
        self.save_domains()
        return True
    
    def remove_domain(self, domain: str):
        """Remove a domain from all categories"""
        domain = domain.lower().strip()
        
        for category, domains in self.classifications.items():
            self.classifications[category] = [
                d for d in domains 
                if (isinstance(d, dict) and d.get('domain') != domain) or 
                   (isinstance(d, str) and d != domain)
            ]
        
        self.save_domains()
        return True
    
    def get_domains_by_category(self, category: str) -> List[Dict]:
        """Get all domains in a specific category"""
        if category == "All":
            all_domains = []
            for cat, domains in self.classifications.items():
                for domain in domains:
                    if isinstance(domain, dict):
                        all_domains.append({
                            'domain': domain.get('domain', ''),
                            'category': cat,
                            'added_date': domain.get('added_date', 'Unknown')
                        })
                    else:
                        all_domains.append({
                            'domain': str(domain),
                            'category': cat,
                            'added_date': 'Default'
                        })
            return all_domains
        
        if category not in self.classifications:
            return []
        
        domains = []
        for domain in self.classifications[category]:
            if isinstance(domain, dict):
                domains.append({
                    'domain': domain.get('domain', ''),
                    'category': category,
                    'added_date': domain.get('added_date', 'Unknown')
                })
            else:
                domains.append({
                    'domain': str(domain),
                    'category': category,
                    'added_date': 'Default'
                })
        
        return domains
    
    def get_classification_stats(self) -> Dict[str, int]:
        """Get statistics about domain classifications"""
        stats = {}
        total = 0
        
        for category, domains in self.classifications.items():
            count = len(domains)
            stats[category.lower().replace(' ', '_')] = count
            total += count
        
        stats['total'] = total
        return stats
    
    def bulk_classify_domains(self, domains: List[str]) -> Dict[str, str]:
        """Classify multiple domains at once"""
        results = {}
        
        for domain in domains:
            results[domain] = self.classify_domain(domain)
        
        return results
    
    def get_change_log(self, days: int = 30) -> List[Dict]:
        """Get change log for domain classifications"""
        try:
            # This would typically read from a change log file
            # For now, return recent additions from domain data
            recent_changes = []
            
            cutoff_date = datetime.now().timestamp() - (days * 24 * 60 * 60)
            
            for category, domains in self.classifications.items():
                for domain in domains:
                    if isinstance(domain, dict):
                        added_date = domain.get('added_date', '')
                        if added_date:
                            try:
                                domain_date = datetime.fromisoformat(added_date).timestamp()
                                if domain_date > cutoff_date:
                                    recent_changes.append({
                                        'domain': domain.get('domain', ''),
                                        'category': category,
                                        'action': 'added',
                                        'date': added_date,
                                        'added_by': domain.get('added_by', 'system')
                                    })
                            except:
                                pass
            
            return sorted(recent_changes, key=lambda x: x['date'], reverse=True)
        
        except Exception as e:
            print(f"Error getting change log: {e}")
            return []
    
    def export_classifications(self) -> str:
        """Export domain classifications as JSON string"""
        try:
            return json.dumps(self.classifications, indent=2)
        except Exception as e:
            print(f"Error exporting classifications: {e}")
            return "{}"
    
    def import_classifications(self, json_data: str, merge: bool = True):
        """Import domain classifications from JSON string"""
        try:
            imported_data = json.loads(json_data)
            
            if merge:
                # Merge with existing data
                for category, domains in imported_data.items():
                    if category in self.classifications:
                        existing_domains = set()
                        for d in self.classifications[category]:
                            if isinstance(d, dict):
                                existing_domains.add(d.get('domain', ''))
                            else:
                                existing_domains.add(str(d))
                        
                        for domain in domains:
                            domain_name = domain.get('domain', '') if isinstance(domain, dict) else str(domain)
                            if domain_name not in existing_domains:
                                self.classifications[category].append(domain)
            else:
                # Replace existing data
                self.classifications = imported_data
            
            self.save_domains()
            return True
        
        except Exception as e:
            print(f"Error importing classifications: {e}")
            return False
