import json
import os
from typing import Dict, List, Any
from datetime import datetime

class SecurityConfig:
    """Security configuration and policy management"""
    
    def __init__(self):
        self.config_file = "security_config.json"
        self.default_config = {
            "risk_thresholds": {
                "critical": {
                    "min_score": 0.8,
                    "auto_escalate": True,
                    "notification_required": True
                },
                "high": {
                    "min_score": 0.6,
                    "auto_escalate": False,
                    "notification_required": True
                },
                "medium": {
                    "min_score": 0.4,
                    "auto_escalate": False,
                    "notification_required": False
                },
                "low": {
                    "min_score": 0.0,
                    "auto_escalate": False,
                    "notification_required": False
                }
            },
            "anomaly_detection": {
                "enabled": True,
                "sensitivity": 0.5,
                "algorithms": ["isolation_forest", "statistical"],
                "min_samples": 100
            },
            "domain_policies": {
                "block_suspicious": True,
                "warn_free_email": True,
                "allow_business": True,
                "quarantine_unknown": False
            },
            "notification_settings": {
                "email_alerts": True,
                "alert_threshold": "high",
                "recipients": ["security@company.com"],
                "escalation_timeout": 24  # hours
            },
            "review_policies": {
                "auto_clear_low": False,
                "require_dual_approval": True,
                "max_review_time": 72,  # hours
                "mandatory_notes": True
            },
            "retention_policies": {
                "log_retention_days": 90,
                "archive_after_days": 365,
                "purge_after_days": 2555  # 7 years
            }
        }
        
        self.config = self.load_config()
    
    def load_config(self) -> Dict[str, Any]:
        """Load security configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    saved_config = json.load(f)
                    
                # Merge with defaults to ensure all keys exist
                config = self.default_config.copy()
                self._deep_merge(config, saved_config)
                return config
            else:
                return self.default_config.copy()
        except Exception as e:
            print(f"Error loading security config: {e}")
            return self.default_config.copy()
    
    def save_config(self):
        """Save security configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Error saving security config: {e}")
    
    def _deep_merge(self, target: Dict, source: Dict):
        """Deep merge two dictionaries"""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_merge(target[key], value)
            else:
                target[key] = value
    
    def get_risk_threshold(self, level: str) -> Dict[str, Any]:
        """Get risk threshold configuration for a level"""
        return self.config.get("risk_thresholds", {}).get(level, {})
    
    def update_risk_threshold(self, level: str, settings: Dict[str, Any]):
        """Update risk threshold settings"""
        if "risk_thresholds" not in self.config:
            self.config["risk_thresholds"] = {}
        
        self.config["risk_thresholds"][level] = settings
        self.save_config()
    
    def get_anomaly_config(self) -> Dict[str, Any]:
        """Get anomaly detection configuration"""
        return self.config.get("anomaly_detection", {})
    
    def update_anomaly_config(self, settings: Dict[str, Any]):
        """Update anomaly detection settings"""
        self.config["anomaly_detection"] = settings
        self.save_config()
    
    def get_domain_policies(self) -> Dict[str, Any]:
        """Get domain policy configuration"""
        return self.config.get("domain_policies", {})
    
    def update_domain_policies(self, policies: Dict[str, Any]):
        """Update domain policies"""
        self.config["domain_policies"] = policies
        self.save_config()
    
    def get_notification_settings(self) -> Dict[str, Any]:
        """Get notification settings"""
        return self.config.get("notification_settings", {})
    
    def update_notification_settings(self, settings: Dict[str, Any]):
        """Update notification settings"""
        self.config["notification_settings"] = settings
        self.save_config()
    
    def should_auto_escalate(self, risk_level: str) -> bool:
        """Check if a risk level should auto-escalate"""
        threshold = self.get_risk_threshold(risk_level)
        return threshold.get("auto_escalate", False)
    
    def requires_notification(self, risk_level: str) -> bool:
        """Check if a risk level requires notification"""
        threshold = self.get_risk_threshold(risk_level)
        return threshold.get("notification_required", False)
    
    def is_domain_blocked(self, domain_category: str) -> bool:
        """Check if a domain category is blocked"""
        policies = self.get_domain_policies()
        
        if domain_category.lower() == "suspicious":
            return policies.get("block_suspicious", True)
        elif domain_category.lower() == "free email":
            return policies.get("warn_free_email", False)  # Warn, don't block
        elif domain_category.lower() == "business":
            return not policies.get("allow_business", True)
        else:
            return policies.get("quarantine_unknown", False)
    
    def get_review_policies(self) -> Dict[str, Any]:
        """Get review policies"""
        return self.config.get("review_policies", {})
    
    def update_review_policies(self, policies: Dict[str, Any]):
        """Update review policies"""
        self.config["review_policies"] = policies
        self.save_config()
    
    def get_retention_policies(self) -> Dict[str, Any]:
        """Get data retention policies"""
        return self.config.get("retention_policies", {})
    
    def update_retention_policies(self, policies: Dict[str, Any]):
        """Update retention policies"""
        self.config["retention_policies"] = policies
        self.save_config()
    
    def validate_config(self) -> List[str]:
        """Validate security configuration and return any issues"""
        issues = []
        
        # Check risk thresholds
        risk_thresholds = self.config.get("risk_thresholds", {})
        required_levels = ["critical", "high", "medium", "low"]
        
        for level in required_levels:
            if level not in risk_thresholds:
                issues.append(f"Missing risk threshold for {level}")
            else:
                threshold = risk_thresholds[level]
                if "min_score" not in threshold:
                    issues.append(f"Missing min_score for {level} threshold")
        
        # Check anomaly detection
        anomaly_config = self.config.get("anomaly_detection", {})
        if not anomaly_config.get("enabled", True):
            issues.append("Anomaly detection is disabled")
        
        # Check notification settings
        notification_settings = self.config.get("notification_settings", {})
        if not notification_settings.get("recipients"):
            issues.append("No notification recipients configured")
        
        return issues
    
    def export_config(self) -> str:
        """Export configuration as JSON string"""
        try:
            return json.dumps(self.config, indent=2)
        except Exception as e:
            print(f"Error exporting config: {e}")
            return "{}"
    
    def import_config(self, json_data: str) -> bool:
        """Import configuration from JSON string"""
        try:
            imported_config = json.loads(json_data)
            
            # Validate imported config
            temp_config = self.default_config.copy()
            self._deep_merge(temp_config, imported_config)
            
            # If validation passes, update config
            self.config = temp_config
            self.save_config()
            return True
        
        except Exception as e:
            print(f"Error importing config: {e}")
            return False
    
    def reset_to_defaults(self):
        """Reset configuration to default values"""
        self.config = self.default_config.copy()
        self.save_config()
    
    def get_policy_summary(self) -> Dict[str, Any]:
        """Get a summary of current security policies"""
        return {
            "risk_levels": len(self.config.get("risk_thresholds", {})),
            "anomaly_detection_enabled": self.config.get("anomaly_detection", {}).get("enabled", False),
            "notification_recipients": len(self.config.get("notification_settings", {}).get("recipients", [])),
            "auto_escalation_levels": [
                level for level, settings in self.config.get("risk_thresholds", {}).items()
                if settings.get("auto_escalate", False)
            ],
            "blocked_domain_categories": [
                category for category, blocked in self.config.get("domain_policies", {}).items()
                if blocked
            ],
            "log_retention_days": self.config.get("retention_policies", {}).get("log_retention_days", 90)
        }
