import json
import os
import hashlib
from typing import Dict, Optional, List
from datetime import datetime, timedelta

class AuthManager:
    """Authentication and authorization manager (disabled by default)"""
    
    def __init__(self):
        self.users_file = "users.json"
        self.enabled = False  # Disabled by default as per requirements
        self.default_users = {
            "admin": {
                "password_hash": self._hash_password("admin123"),
                "role": "admin",
                "permissions": ["all"],
                "created_date": datetime.now().isoformat(),
                "last_login": None,
                "active": True
            },
            "analyst": {
                "password_hash": self._hash_password("analyst123"),
                "role": "analyst",
                "permissions": ["read", "review", "escalate"],
                "created_date": datetime.now().isoformat(),
                "last_login": None,
                "active": True
            }
        }
        
        self.users = self.load_users()
    
    def _hash_password(self, password: str) -> str:
        """Hash a password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def load_users(self) -> Dict:
        """Load users from file"""
        try:
            if os.path.exists(self.users_file):
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            else:
                return self.default_users.copy()
        except Exception as e:
            print(f"Error loading users: {e}")
            return self.default_users.copy()
    
    def save_users(self):
        """Save users to file"""
        try:
            with open(self.users_file, 'w') as f:
                json.dump(self.users, f, indent=2)
        except Exception as e:
            print(f"Error saving users: {e}")
    
    def authenticate(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate a user"""
        if not self.enabled:
            return {"username": "anonymous", "role": "admin", "permissions": ["all"]}
        
        if username not in self.users:
            return None
        
        user = self.users[username]
        if not user.get("active", True):
            return None
        
        password_hash = self._hash_password(password)
        if user["password_hash"] != password_hash:
            return None
        
        # Update last login
        user["last_login"] = datetime.now().isoformat()
        self.save_users()
        
        return {
            "username": username,
            "role": user["role"],
            "permissions": user["permissions"]
        }
    
    def authorize(self, user: Dict, required_permission: str) -> bool:
        """Check if user has required permission"""
        if not self.enabled:
            return True
        
        if not user:
            return False
        
        permissions = user.get("permissions", [])
        return "all" in permissions or required_permission in permissions
    
    def create_user(self, username: str, password: str, role: str, permissions: List[str]) -> bool:
        """Create a new user"""
        if username in self.users:
            return False
        
        self.users[username] = {
            "password_hash": self._hash_password(password),
            "role": role,
            "permissions": permissions,
            "created_date": datetime.now().isoformat(),
            "last_login": None,
            "active": True
        }
        
        self.save_users()
        return True
    
    def update_user(self, username: str, updates: Dict) -> bool:
        """Update user information"""
        if username not in self.users:
            return False
        
        user = self.users[username]
        
        if "password" in updates:
            user["password_hash"] = self._hash_password(updates["password"])
        
        if "role" in updates:
            user["role"] = updates["role"]
        
        if "permissions" in updates:
            user["permissions"] = updates["permissions"]
        
        if "active" in updates:
            user["active"] = updates["active"]
        
        self.save_users()
        return True
    
    def delete_user(self, username: str) -> bool:
        """Delete a user"""
        if username not in self.users:
            return False
        
        del self.users[username]
        self.save_users()
        return True
    
    def get_users(self) -> Dict:
        """Get all users (without password hashes)"""
        users = {}
        for username, user in self.users.items():
            users[username] = {
                "role": user["role"],
                "permissions": user["permissions"],
                "created_date": user["created_date"],
                "last_login": user["last_login"],
                "active": user["active"]
            }
        return users
    
    def enable_auth(self):
        """Enable authentication"""
        self.enabled = True
    
    def disable_auth(self):
        """Disable authentication"""
        self.enabled = False
    
    def is_enabled(self) -> bool:
        """Check if authentication is enabled"""
        return self.enabled
