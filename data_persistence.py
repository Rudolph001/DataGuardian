
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import hashlib

class DataPersistence:
    """JSON-based data persistence system for daily email data and work state"""
    
    def __init__(self):
        self.data_folder = "daily_data"
        self.work_state_folder = "work_states"
        self.backup_folder = "data_backups"
        
        # Create necessary directories
        os.makedirs(self.data_folder, exist_ok=True)
        os.makedirs(self.work_state_folder, exist_ok=True)
        os.makedirs(self.backup_folder, exist_ok=True)
        
        self.current_date = datetime.now().strftime("%Y-%m-%d")
    
    def save_daily_data(self, data: List[Dict], upload_date: str = None) -> str:
        """Save daily email data to JSON file"""
        if not upload_date:
            upload_date = self.current_date
        
        filename = f"email_data_{upload_date}.json"
        filepath = os.path.join(self.data_folder, filename)
        
        # Add metadata
        data_with_metadata = {
            "upload_date": upload_date,
            "upload_timestamp": datetime.now().isoformat(),
            "total_records": len(data),
            "data_hash": self._calculate_data_hash(data),
            "email_data": data
        }
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data_with_metadata, f, indent=2, ensure_ascii=False)
            
            # Create backup
            self._create_backup(filepath, upload_date)
            
            return filepath
        except Exception as e:
            print(f"Error saving daily data: {e}")
            return None
    
    def load_daily_data(self, upload_date: str = None) -> Optional[List[Dict]]:
        """Load daily email data from JSON file"""
        if not upload_date:
            upload_date = self.current_date
        
        filename = f"email_data_{upload_date}.json"
        filepath = os.path.join(self.data_folder, filename)
        
        if not os.path.exists(filepath):
            return None
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data_with_metadata = json.load(f)
            
            return data_with_metadata.get("email_data", [])
        except Exception as e:
            print(f"Error loading daily data: {e}")
            return None
    
    def save_work_state(self, work_state: Dict, upload_date: str = None) -> str:
        """Save work state (completed reviews, escalations, etc.) to JSON file"""
        if not upload_date:
            upload_date = self.current_date
        
        filename = f"work_state_{upload_date}.json"
        filepath = os.path.join(self.work_state_folder, filename)
        
        # Helper function to make data JSON serializable
        def make_serializable(obj):
            """Convert non-serializable objects to serializable format"""
            if hasattr(obj, 'isoformat'):  # datetime objects
                return obj.isoformat()
            elif isinstance(obj, dict):
                return {k: make_serializable(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [make_serializable(item) for item in obj]
            elif isinstance(obj, tuple):
                return list(obj)
            elif isinstance(obj, set):
                return list(obj)
            else:
                return obj
        
        # Add metadata and comprehensive dashboard states
        work_state_with_metadata = {
            "save_date": upload_date,
            "save_timestamp": datetime.now().isoformat(),
            "version": "2.0",  # Version for compatibility
            
            # Security Operations Dashboard state
            "security_operations": {
                "completed_reviews": make_serializable(work_state.get("completed_reviews", {})),
                "escalated_records": make_serializable(work_state.get("escalated_records", {})),
                "active_filters": make_serializable(work_state.get("active_filters", {})),
                "review_decisions": make_serializable(work_state.get("review_decisions", {})),
                "last_reviewed_email": str(work_state.get("last_reviewed_email", "")),
                "review_session_start": str(work_state.get("review_session_start", "")),
                "total_reviews_this_session": int(work_state.get("total_reviews_this_session", 0))
            },
            
            # Email Check Completed Dashboard state
            "email_check_completed": {
                "completed_reviews": make_serializable(work_state.get("completed_reviews", {})),
                "review_notes": make_serializable(work_state.get("review_notes", {})),
                "reviewer_assignments": make_serializable(work_state.get("reviewer_assignments", {})),
                "completion_timestamps": make_serializable(work_state.get("completion_timestamps", {})),
                "review_quality_scores": make_serializable(work_state.get("review_quality_scores", {})),
                "batch_review_sessions": make_serializable(work_state.get("batch_review_sessions", []))
            },
            
            # Follow-up Center Dashboard state
            "followup_center": {
                "escalated_records": make_serializable(work_state.get("escalated_records", {})),
                "followup_status": make_serializable(work_state.get("followup_status", {})),
                "followup_notes": make_serializable(work_state.get("followup_notes", {})),
                "email_templates": make_serializable(work_state.get("email_templates", {})),
                "followup_assignments": make_serializable(work_state.get("followup_assignments", {})),
                "escalation_reasons": make_serializable(work_state.get("escalation_reasons", {})),
                "followup_deadlines": make_serializable(work_state.get("followup_deadlines", {})),
                "email_sent_status": make_serializable(work_state.get("email_sent_status", {})),
                "template_drafts": make_serializable(work_state.get("template_drafts", {}))
            },
            
            # General system state
            "system_state": {
                "follow_up_decisions": make_serializable(work_state.get("follow_up_decisions", {})),
                "blocked_domains": list(work_state.get("blocked_domains", [])),
                "sender_status": make_serializable(work_state.get("sender_status", {})),
                "domain_classifications": make_serializable(work_state.get("domain_classifications", {})),
                "user_preferences": make_serializable(work_state.get("user_preferences", {})),
                "session_statistics": make_serializable(work_state.get("session_statistics", {}))
            },
            
            # Dashboard interaction state
            "ui_state": {
                "selected_filters": make_serializable(work_state.get("selected_filters", {})),
                "sort_preferences": make_serializable(work_state.get("sort_preferences", {})),
                "view_modes": make_serializable(work_state.get("view_modes", {})),
                "expanded_sections": make_serializable(work_state.get("expanded_sections", {})),
                "modal_states": make_serializable(work_state.get("modal_states", {}))
            }
        }
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(work_state_with_metadata, f, indent=2, ensure_ascii=False, default=str)
            
            return filepath
        except Exception as e:
            print(f"Error saving work state: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def load_work_state(self, upload_date: str = None) -> Optional[Dict]:
        """Load work state from JSON file"""
        if not upload_date:
            upload_date = self.current_date
        
        filename = f"work_state_{upload_date}.json"
        filepath = os.path.join(self.work_state_folder, filename)
        
        if not os.path.exists(filepath):
            return None
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                work_state_with_metadata = json.load(f)
            
            # Helper function to convert datetime strings back to datetime objects
            def restore_datetime_objects(obj):
                """Convert ISO format strings back to datetime objects where needed"""
                if isinstance(obj, dict):
                    result = {}
                    for key, value in obj.items():
                        if key == 'timestamp' and isinstance(value, str):
                            try:
                                # Try to parse ISO format datetime string
                                from datetime import datetime
                                result[key] = datetime.fromisoformat(value.replace('Z', '+00:00'))
                            except (ValueError, AttributeError):
                                result[key] = value
                        elif isinstance(value, (dict, list)):
                            result[key] = restore_datetime_objects(value)
                        else:
                            result[key] = value
                    return result
                elif isinstance(obj, list):
                    return [restore_datetime_objects(item) for item in obj]
                else:
                    return obj
            
            # Check version for compatibility
            version = work_state_with_metadata.get("version", "1.0")
            
            if version == "2.0":
                # New format with detailed dashboard states
                work_state = {
                    # Security Operations Dashboard
                    "completed_reviews": work_state_with_metadata.get("security_operations", {}).get("completed_reviews", {}),
                    "escalated_records": work_state_with_metadata.get("security_operations", {}).get("escalated_records", {}),
                    "active_filters": work_state_with_metadata.get("security_operations", {}).get("active_filters", {}),
                    "review_decisions": work_state_with_metadata.get("security_operations", {}).get("review_decisions", {}),
                    "last_reviewed_email": work_state_with_metadata.get("security_operations", {}).get("last_reviewed_email", ""),
                    "review_session_start": work_state_with_metadata.get("security_operations", {}).get("review_session_start", ""),
                    "total_reviews_this_session": work_state_with_metadata.get("security_operations", {}).get("total_reviews_this_session", 0),
                    
                    # Email Check Completed Dashboard
                    "review_notes": work_state_with_metadata.get("email_check_completed", {}).get("review_notes", {}),
                    "reviewer_assignments": work_state_with_metadata.get("email_check_completed", {}).get("reviewer_assignments", {}),
                    "completion_timestamps": work_state_with_metadata.get("email_check_completed", {}).get("completion_timestamps", {}),
                    "review_quality_scores": work_state_with_metadata.get("email_check_completed", {}).get("review_quality_scores", {}),
                    "batch_review_sessions": work_state_with_metadata.get("email_check_completed", {}).get("batch_review_sessions", []),
                    
                    # Follow-up Center Dashboard
                    "followup_status": work_state_with_metadata.get("followup_center", {}).get("followup_status", {}),
                    "followup_notes": work_state_with_metadata.get("followup_center", {}).get("followup_notes", {}),
                    "email_templates": work_state_with_metadata.get("followup_center", {}).get("email_templates", {}),
                    "followup_assignments": work_state_with_metadata.get("followup_center", {}).get("followup_assignments", {}),
                    "escalation_reasons": work_state_with_metadata.get("followup_center", {}).get("escalation_reasons", {}),
                    "followup_deadlines": work_state_with_metadata.get("followup_center", {}).get("followup_deadlines", {}),
                    "email_sent_status": work_state_with_metadata.get("followup_center", {}).get("email_sent_status", {}),
                    "template_drafts": work_state_with_metadata.get("followup_center", {}).get("template_drafts", {}),
                    
                    # General system state
                    "follow_up_decisions": work_state_with_metadata.get("system_state", {}).get("follow_up_decisions", {}),
                    "blocked_domains": work_state_with_metadata.get("system_state", {}).get("blocked_domains", []),
                    "sender_status": work_state_with_metadata.get("system_state", {}).get("sender_status", {}),
                    "domain_classifications": work_state_with_metadata.get("system_state", {}).get("domain_classifications", {}),
                    "user_preferences": work_state_with_metadata.get("system_state", {}).get("user_preferences", {}),
                    "session_statistics": work_state_with_metadata.get("system_state", {}).get("session_statistics", {}),
                    
                    # UI state
                    "selected_filters": work_state_with_metadata.get("ui_state", {}).get("selected_filters", {}),
                    "sort_preferences": work_state_with_metadata.get("ui_state", {}).get("sort_preferences", {}),
                    "view_modes": work_state_with_metadata.get("ui_state", {}).get("view_modes", {}),
                    "expanded_sections": work_state_with_metadata.get("ui_state", {}).get("expanded_sections", {}),
                    "modal_states": work_state_with_metadata.get("ui_state", {}).get("modal_states", {})
                }
            else:
                # Legacy format compatibility
                work_state = {
                    "completed_reviews": work_state_with_metadata.get("completed_reviews", {}),
                    "escalated_records": work_state_with_metadata.get("escalated_records", {}),
                    "follow_up_decisions": work_state_with_metadata.get("follow_up_decisions", {}),
                    "blocked_domains": work_state_with_metadata.get("blocked_domains", []),
                    "sender_status": work_state_with_metadata.get("sender_status", {})
                }
            
            # Restore datetime objects from ISO strings
            return restore_datetime_objects(work_state)
                
        except Exception as e:
            print(f"Error loading work state: {e}")
            return None
    
    def get_available_dates(self) -> List[str]:
        """Get list of available data dates"""
        dates = []
        
        # Check data folder
        if os.path.exists(self.data_folder):
            for filename in os.listdir(self.data_folder):
                if filename.startswith("email_data_") and filename.endswith(".json"):
                    date_str = filename.replace("email_data_", "").replace(".json", "")
                    dates.append(date_str)
        
        return sorted(dates, reverse=True)  # Most recent first
    
    def get_data_summary(self, upload_date: str = None) -> Optional[Dict]:
        """Get summary of data for a specific date"""
        if not upload_date:
            upload_date = self.current_date
        
        filename = f"email_data_{upload_date}.json"
        filepath = os.path.join(self.data_folder, filename)
        
        if not os.path.exists(filepath):
            return None
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data_with_metadata = json.load(f)
            
            # Calculate risk distribution
            email_data = data_with_metadata.get("email_data", [])
            risk_distribution = {}
            
            for email in email_data:
                risk = email.get("status", "unknown").lower()
                risk_distribution[risk] = risk_distribution.get(risk, 0) + 1
            
            return {
                "upload_date": data_with_metadata.get("upload_date"),
                "upload_timestamp": data_with_metadata.get("upload_timestamp"),
                "total_records": data_with_metadata.get("total_records", 0),
                "risk_distribution": risk_distribution,
                "file_size": os.path.getsize(filepath)
            }
        except Exception as e:
            print(f"Error getting data summary: {e}")
            return None
    
    def merge_daily_data(self, dates: List[str]) -> List[Dict]:
        """Merge data from multiple dates"""
        merged_data = []
        
        for date in dates:
            daily_data = self.load_daily_data(date)
            if daily_data:
                # Add date info to each record
                for record in daily_data:
                    record["_data_date"] = date
                merged_data.extend(daily_data)
        
        return merged_data
    
    def delete_daily_data(self, upload_date: str) -> bool:
        """Delete data for a specific date"""
        try:
            # Delete main data file
            data_filename = f"email_data_{upload_date}.json"
            data_filepath = os.path.join(self.data_folder, data_filename)
            
            if os.path.exists(data_filepath):
                os.remove(data_filepath)
            
            # Delete work state file
            work_filename = f"work_state_{upload_date}.json"
            work_filepath = os.path.join(self.work_state_folder, work_filename)
            
            if os.path.exists(work_filepath):
                os.remove(work_filepath)
            
            return True
        except Exception as e:
            print(f"Error deleting daily data: {e}")
            return False
    
    def _calculate_data_hash(self, data: List[Dict]) -> str:
        """Calculate hash of data for integrity checking"""
        data_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()
    
    def _create_backup(self, filepath: str, upload_date: str):
        """Create backup of data file"""
        try:
            backup_filename = f"backup_{upload_date}_{datetime.now().strftime('%H%M%S')}.json"
            backup_filepath = os.path.join(self.backup_folder, backup_filename)
            
            with open(filepath, 'r', encoding='utf-8') as source:
                with open(backup_filepath, 'w', encoding='utf-8') as backup:
                    backup.write(source.read())
            
            # Keep only last 5 backups per date
            self._cleanup_old_backups(upload_date)
        except Exception as e:
            print(f"Error creating backup: {e}")
    
    def _cleanup_old_backups(self, upload_date: str):
        """Keep only the latest 5 backups for each date"""
        try:
            backups = []
            for filename in os.listdir(self.backup_folder):
                if filename.startswith(f"backup_{upload_date}_"):
                    filepath = os.path.join(self.backup_folder, filename)
                    backups.append((filepath, os.path.getmtime(filepath)))
            
            # Sort by modification time (newest first)
            backups.sort(key=lambda x: x[1], reverse=True)
            
            # Remove old backups (keep only 5)
            for filepath, _ in backups[5:]:
                os.remove(filepath)
        except Exception as e:
            print(f"Error cleaning up backups: {e}")
    
    def export_all_data(self, output_file: str = None) -> str:
        """Export all data to a single JSON file"""
        if not output_file:
            output_file = f"all_data_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "daily_data": {},
            "work_states": {}
        }
        
        # Export all daily data
        for date in self.get_available_dates():
            daily_data = self.load_daily_data(date)
            work_state = self.load_work_state(date)
            
            if daily_data:
                export_data["daily_data"][date] = daily_data
            
            if work_state:
                export_data["work_states"][date] = work_state
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            return output_file
        except Exception as e:
            print(f"Error exporting data: {e}")
            return None
