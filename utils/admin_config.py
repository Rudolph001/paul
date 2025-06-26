
import json
import os
import pandas as pd
from datetime import time
import streamlit as st

class AdminConfig:
    def __init__(self):
        self.config_file = "admin_config.json"
        self.default_config = {
            "sql_operation_weights": {
                'DELETE': 30,
                'DROP': 35,
                'ALTER': 25,
                'UPDATE': 20,
                'INSERT': 15,
                'GRANT': 25,
                'REVOKE': 25,
                'SELECT *': 20,
                'TRUNCATE': 35,
                'CREATE': 10,
                'SELECT': 5
            },
            "risk_weights": {
                "sql_operation": 0.3,
                "timing": 0.2,
                "context": 0.15,
                "sensitive_objects": 0.25,
                "user_factors": 0.05,
                "program": 0.05
            },
            "time_settings": {
                "off_hours_start": "18:00",
                "off_hours_end": "08:00",
                "weekend_multiplier": 1.5,
                "late_night_bonus": 10,
                "off_hours_bonus": 15,
                "weekend_bonus": 10
            },
            "sensitive_tables": [
                'Salaries', 'Employees', 'HR_Records', 'CustomerData', 
                'AuditLog', 'Payroll', 'SSN', 'Credit'
            ],
            "high_risk_keywords": [
                'unauthorized', 'emergency', 'bypass', 'override', 'manual', 
                'temp', 'temporary', 'hotfix', 'urgent', 'critical'
            ],
            "low_risk_keywords": [
                'scheduled', 'approved', 'maintenance', 'routine', 'standard',
                'automated', 'planned', 'regular'
            ],
            "high_risk_programs": [
                'sqlcmd', 'psql', 'mysql', 'mongosh', 'redis-cli',
                'powershell', 'cmd', 'bash', 'python', 'perl', 'script'
            ],
            "medium_risk_programs": [
                'ssms', 'management studio', 'workbench', 'navigator',
                'toad', 'dbeaver', 'navicat'
            ],
            "admin_patterns": [
                'admin', 'root', 'sa', 'dba', 'system', 'service'
            ],
            "risk_thresholds": {
                "high": 70,
                "medium": 40,
                "low": 0
            },
            "anomaly_settings": {
                "volume_threshold_multiplier": 3.0,
                "frequency_threshold": 10,
                "off_hours_sensitivity": 1.0
            }
        }
        self.load_config()
    
    def load_config(self):
        """Load configuration from file or create default"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
            else:
                self.config = self.default_config.copy()
                self.save_config()
        except Exception as e:
            st.error(f"Error loading config: {e}")
            self.config = self.default_config.copy()
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            st.error(f"Error saving config: {e}")
            return False
    
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        self.config = self.default_config.copy()
        return self.save_config()
    
    def get_config(self):
        """Get current configuration"""
        return self.config
    
    def update_config(self, section, key, value):
        """Update a specific configuration value"""
        if section in self.config:
            if isinstance(self.config[section], dict) and key in self.config[section]:
                self.config[section][key] = value
                return self.save_config()
            elif section == key:  # For top-level arrays like sensitive_tables
                self.config[section] = value
                return self.save_config()
        return False
    
    def export_config(self):
        """Export configuration as JSON string"""
        return json.dumps(self.config, indent=2)
    
    def import_config(self, config_json):
        """Import configuration from JSON string"""
        try:
            imported_config = json.loads(config_json)
            # Validate structure matches expected format
            if self.validate_config(imported_config):
                self.config = imported_config
                return self.save_config()
            else:
                return False
        except json.JSONDecodeError:
            return False
    
    def validate_config(self, config):
        """Validate configuration structure"""
        required_sections = [
            'sql_operation_weights', 'risk_weights', 'time_settings',
            'sensitive_tables', 'high_risk_keywords', 'low_risk_keywords'
        ]
        return all(section in config for section in required_sections)
