import pandas as pd
import numpy as np
from datetime import datetime, time
import re

class RiskEngine:
    def __init__(self):
        # Risk weights for different factors
        self.sql_operation_weights = {
            'DELETE': 45,
            'DROP': 50,
            'ALTER': 35,
            'UPDATE': 30,
            'INSERT': 15,
            'GRANT': 40,
            'REVOKE': 35,
            'SELECT *': 25,
            'TRUNCATE': 50,
            'CREATE': 15,
            'SELECT': 5
        }
        
        # Time-based risk factors
        self.off_hours_start = time(18, 0)  # 6 PM
        self.off_hours_end = time(8, 0)     # 8 AM
        self.weekend_multiplier = 1.5
        
        # Context risk keywords
        self.high_risk_keywords = [
            'unauthorized', 'emergency', 'bypass', 'override', 'manual', 
            'temp', 'temporary', 'hotfix', 'urgent', 'critical'
        ]
        
        self.low_risk_keywords = [
            'scheduled', 'approved', 'maintenance', 'routine', 'standard',
            'automated', 'planned', 'regular'
        ]
    
    def explain_sql(self, statement):
        """Convert SQL statement to plain English explanation"""
        if pd.isna(statement) or not statement:
            return "executed an unknown operation"
        s = str(statement).upper().strip()
        
        # Handle common SQL patterns
        if "SELECT *" in s:
            return "queried all columns from a table (potential data dump)"
        elif "DELETE" in s and "WHERE" not in s:
            return "deleted all records from a table (high risk)"
        elif "DELETE" in s:
            return "deleted specific records from a table"
        elif "UPDATE" in s and "WHERE" not in s:
            return "updated all records in a table (high risk)"
        elif "UPDATE" in s:
            return "updated specific records in a table"
        elif "INSERT" in s:
            return "inserted new records into a table"
        elif "DROP TABLE" in s:
            return "permanently removed a table from the database"
        elif "DROP" in s:
            return "removed database objects (schema change)"
        elif "ALTER" in s:
            return "modified database structure or permissions"
        elif "TRUNCATE" in s:
            return "removed all data from a table (non-recoverable)"
        elif "GRANT" in s:
            return "granted database permissions to users"
        elif "REVOKE" in s:
            return "removed database permissions from users"
        elif "CREATE" in s:
            return "created new database objects"
        elif "SELECT" in s:
            return "queried specific data from tables"
        else:
            return "executed a custom SQL operation"
    
    def get_sql_operation_risk(self, statement):
        """Calculate risk score based on SQL operation type"""
        if pd.isna(statement) or not statement:
            return 10  # Default moderate risk for unknown operations
        s = str(statement).upper().strip()
        
        # Check for specific high-risk patterns
        if "SELECT *" in s:
            return self.sql_operation_weights.get('SELECT *', 20)
        
        # Check for operations without WHERE clauses (higher risk)
        if ("DELETE" in s or "UPDATE" in s) and "WHERE" not in s:
            base_score = self.sql_operation_weights.get('DELETE' if 'DELETE' in s else 'UPDATE', 20)
            return min(base_score + 15, 50)  # Add penalty for missing WHERE
        
        # Check for each operation type
        for operation, weight in self.sql_operation_weights.items():
            if operation in s:
                return weight
        
        return 5  # Default low risk for unrecognized operations
    
    def get_time_risk(self, timestamp):
        """Calculate risk score based on time of access"""
        if pd.isna(timestamp):
            return 5  # Default risk for unknown times
        
        # Convert string to datetime if needed
        if isinstance(timestamp, str):
            try:
                timestamp = pd.to_datetime(timestamp)
            except:
                return 5
        
        risk_score = 0
        
        # Check if weekend
        if timestamp.weekday() >= 5:  # Saturday = 5, Sunday = 6
            risk_score += 10
        
        # Check if off-hours
        current_time = timestamp.time()
        if current_time >= self.off_hours_start or current_time <= self.off_hours_end:
            risk_score += 15
        
        # Very late night access (midnight to 5 AM)
        if time(0, 0) <= current_time <= time(5, 0):
            risk_score += 10
        
        return min(risk_score, 35)  # Cap at 35 points
    
    def get_context_risk(self, context):
        """Calculate risk score based on context information"""
        if pd.isna(context) or not context:
            return 10  # Missing context is suspicious
        
        context_lower = context.lower()
        
        # High risk keywords
        for keyword in self.high_risk_keywords:
            if keyword in context_lower:
                return 25
        
        # Low risk keywords
        for keyword in self.low_risk_keywords:
            if keyword in context_lower:
                return 0
        
        # Change ticket patterns (generally lower risk)
        if re.search(r'(chg|change|ticket|req|request)\d+', context_lower):
            return 5
        
        return 10  # Neutral context
    
    def get_sensitive_object_risk(self, accessed_obj, sensitive_tables):
        """Calculate risk score for accessing sensitive objects"""
        if pd.isna(accessed_obj) or not accessed_obj:
            return 0
        
        obj_lower = str(accessed_obj).lower()
        for sensitive_table in sensitive_tables:
            if sensitive_table.lower() in obj_lower:
                return 35
        
        # Check for high-risk sensitive patterns
        high_risk_patterns = [
            'credit_card', 'credit_cards', 'creditcard', 'creditcards',
            'payment', 'financial', 'salary', 'payroll', 'ssn', 'social_security'
        ]
        
        for pattern in high_risk_patterns:
            if pattern in obj_lower:
                return 35
        
        # Check for other sensitive patterns
        sensitive_patterns = [
            'password', 'pwd', 'secret', 'key', 'token', 'hash',
            'credit', 'card', 'account', 'employee', 'customer'
        ]
        
        for pattern in sensitive_patterns:
            if pattern in obj_lower:
                return 25
        
        return 0
    
    def get_user_risk(self, os_user, exec_user):
        """Calculate risk score based on user information"""
        risk_score = 0
        
        # Different OS and execution users
        if os_user != exec_user:
            risk_score += 15
        
        # System or admin accounts
        admin_patterns = ['admin', 'root', 'sa', 'dba', 'system', 'service']
        user_lower = os_user.lower() if pd.notna(os_user) else ''
        
        for pattern in admin_patterns:
            if pattern in user_lower:
                risk_score += 10
                break
        
        return min(risk_score, 25)  # Cap at 25 points
    
    def get_program_risk(self, program):
        """Calculate risk score based on the program used"""
        if pd.isna(program):
            return 5
        
        program_lower = program.lower()
        
        # High-risk programs (command line tools, scripts)
        high_risk_programs = [
            'sqlcmd', 'psql', 'mysql', 'mongosh', 'redis-cli',
            'powershell', 'cmd', 'bash', 'python', 'perl', 'script'
        ]
        
        for high_risk in high_risk_programs:
            if high_risk in program_lower:
                return 15
        
        # Medium-risk programs (management tools)
        medium_risk_programs = [
            'ssms', 'management studio', 'workbench', 'navigator',
            'toad', 'dbeaver', 'navicat'
        ]
        
        for medium_risk in medium_risk_programs:
            if medium_risk in program_lower:
                return 8
        
        return 5  # Default for other programs
    
    def calculate_risk_score(self, row, sensitive_tables):
        """Calculate comprehensive risk score for a SQL activity"""
        try:
            # Individual risk components
            sql_risk = self.get_sql_operation_risk(row['Statement'])
            time_risk = self.get_time_risk(row['_time'])
            context_risk = self.get_context_risk(row['MS_Context'])
            sensitive_risk = self.get_sensitive_object_risk(row['Accessed_Obj'], sensitive_tables)
            user_risk = self.get_user_risk(row['OS_User'], row['Exec_User'])
            program_risk = self.get_program_risk(row['Program'])
            
            # Special handling for DELETE operations on sensitive objects
            statement_upper = str(row['Statement']).upper() if pd.notna(row['Statement']) else ''
            accessed_obj = str(row['Accessed_Obj']).lower() if pd.notna(row['Accessed_Obj']) else ''
            
            # Check if DELETE/DROP/TRUNCATE on sensitive tables like credit cards
            dangerous_ops = ['DELETE', 'DROP', 'TRUNCATE']
            sensitive_keywords = ['credit', 'card', 'payment', 'financial', 'salary', 'ssn', 'social']
            
            is_dangerous_sensitive = (
                any(op in statement_upper for op in dangerous_ops) and
                (any(keyword in accessed_obj for keyword in sensitive_keywords) or
                 any(table.lower() in accessed_obj for table in sensitive_tables))
            )
            
            # Calculate weighted total
            total_risk = (
                sql_risk * 0.3 +           # 30% weight for SQL operation
                time_risk * 0.2 +          # 20% weight for timing
                context_risk * 0.15 +      # 15% weight for context
                sensitive_risk * 0.25 +    # 25% weight for sensitive objects
                user_risk * 0.05 +         # 5% weight for user factors
                program_risk * 0.05        # 5% weight for program
            )
            
            # Apply multipliers for high-risk combinations
            if sensitive_risk > 0 and sql_risk >= 30:
                total_risk *= 1.8  # 80% increase for sensitive operations
            
            if time_risk > 0 and context_risk >= 20:
                total_risk *= 1.5  # 50% increase for off-hours unauthorized activity
            
            # Super high risk for dangerous combinations
            if sensitive_risk > 0 and sql_risk >= 40 and time_risk > 0:
                total_risk *= 2.0  # Double risk for dangerous off-hours sensitive operations
            
            # Critical risk for dangerous operations on sensitive data
            if is_dangerous_sensitive:
                total_risk = max(total_risk * 2.5, 75)  # Ensure minimum 75 for dangerous sensitive ops
            
            # Ensure score is within 0-100 range
            return min(max(int(total_risk), 0), 100)
            
        except Exception as e:
            # Return moderate risk if calculation fails
            return 50
