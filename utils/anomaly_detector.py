import pandas as pd
import numpy as np
from datetime import datetime, time
from collections import defaultdict, Counter

class AnomalyDetector:
    def __init__(self):
        self.off_hours_start = time(18, 0)  # 6 PM
        self.off_hours_end = time(8, 0)     # 8 AM
        
    def detect_anomalies(self, row, full_df):
        """Detect various types of anomalous behavior"""
        anomalies = {
            'is_outlier': False,
            'off_hours': False,
            'unusual_volume': False,
            'atypical_behavior': False,
            'volume_description': ''
        }
        
        try:
            # Off-hours detection
            anomalies['off_hours'] = self._is_off_hours(row['_time'])
            
            # Unusual volume detection
            volume_anomaly = self._detect_volume_anomaly(row, full_df)
            anomalies['unusual_volume'] = volume_anomaly['is_anomaly']
            anomalies['volume_description'] = volume_anomaly['description']
            
            # Atypical user behavior
            anomalies['atypical_behavior'] = self._detect_atypical_behavior(row, full_df)
            
            # Overall outlier determination
            anomalies['is_outlier'] = (
                anomalies['off_hours'] or 
                anomalies['unusual_volume'] or 
                anomalies['atypical_behavior']
            )
            
        except Exception as e:
            # Default to no anomalies if detection fails
            pass
            
        return anomalies
    
    def _is_off_hours(self, timestamp):
        """Check if the timestamp is during off-hours"""
        current_time = timestamp.time()
        
        # Weekend check
        if timestamp.weekday() >= 5:  # Saturday = 5, Sunday = 6
            return True
        
        # Off-hours check (after 6 PM or before 8 AM)
        if current_time >= self.off_hours_start or current_time <= self.off_hours_end:
            return True
        
        return False
    
    def _detect_volume_anomaly(self, row, full_df):
        """Detect unusual data access volumes"""
        result = {'is_anomaly': False, 'description': ''}
        
        try:
            user = row['OS_User']
            statement = row['Statement'].upper()
            
            # Filter data for the same user
            user_df = full_df[full_df['OS_User'] == user]
            
            if len(user_df) < 5:  # Not enough data for comparison
                return result
            
            # Check for SELECT * queries (potential data dumps)
            if 'SELECT *' in statement:
                result['is_anomaly'] = True
                result['description'] = 'Potential data dump using SELECT *'
                return result
            
            # Check query frequency within time windows
            current_time = row['_time']
            
            # Count queries in the last hour
            hour_window = user_df[
                (user_df['_time'] >= current_time - pd.Timedelta(hours=1)) &
                (user_df['_time'] <= current_time)
            ]
            
            if len(hour_window) > 10:  # More than 10 queries per hour
                result['is_anomaly'] = True
                result['description'] = f'High query frequency: {len(hour_window)} queries in 1 hour'
                return result
            
            # Check for bulk operations
            bulk_keywords = ['BULK', 'BATCH', 'IMPORT', 'EXPORT', 'BACKUP', 'RESTORE']
            if any(keyword in statement for keyword in bulk_keywords):
                result['is_anomaly'] = True
                result['description'] = 'Bulk data operation detected'
                return result
            
        except Exception:
            pass
            
        return result
    
    def _detect_atypical_behavior(self, row, full_df):
        """Detect behavior that's atypical for the user"""
        try:
            user = row['OS_User']
            user_df = full_df[full_df['OS_User'] == user]
            
            if len(user_df) < 10:  # Not enough historical data
                return False
            
            # Check for unusual database access
            user_databases = user_df['DB_Name'].value_counts()
            current_db = row['DB_Name']
            
            # If user rarely accesses this database
            if current_db in user_databases:
                access_frequency = user_databases[current_db] / len(user_df)
                if access_frequency < 0.1:  # Less than 10% of their usual activity
                    return True
            else:
                # First time accessing this database
                return True
            
            # Check for unusual programs
            user_programs = user_df['Program'].value_counts()
            current_program = row['Program']
            
            if current_program not in user_programs.index:
                return True  # First time using this program
            
            # Check for unusual SQL operations
            user_operations = user_df['Statement'].apply(self._extract_sql_operation).value_counts()
            current_operation = self._extract_sql_operation(row['Statement'])
            
            if current_operation in user_operations:
                operation_frequency = user_operations[current_operation] / len(user_df)
                if operation_frequency < 0.05:  # Less than 5% of their usual operations
                    return True
            
        except Exception:
            pass
            
        return False
    
    def _extract_sql_operation(self, statement):
        """Extract the primary SQL operation from a statement"""
        s = statement.upper().strip()
        
        operations = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'CREATE', 'GRANT', 'REVOKE', 'TRUNCATE']
        
        for op in operations:
            if s.startswith(op):
                return op
        
        return 'OTHER'
    
    def get_user_behavior_profile(self, user, full_df):
        """Get a behavioral profile for a user"""
        user_df = full_df[full_df['OS_User'] == user]
        
        if user_df.empty:
            return {}
        
        profile = {
            'total_activities': len(user_df),
            'databases_accessed': user_df['DB_Name'].nunique(),
            'common_databases': user_df['DB_Name'].value_counts().head(3).to_dict(),
            'common_operations': user_df['Statement'].apply(self._extract_sql_operation).value_counts().head(3).to_dict(),
            'common_programs': user_df['Program'].value_counts().head(3).to_dict(),
            'off_hours_percentage': (user_df['_time'].apply(self._is_off_hours).sum() / len(user_df)) * 100,
            'weekend_activities': user_df[user_df['_time'].dt.weekday >= 5].shape[0],
            'most_active_hours': user_df['_time'].dt.hour.value_counts().head(3).to_dict()
        }
        
        return profile
    
    def detect_coordinated_activity(self, full_df, time_window_minutes=30):
        """Detect potentially coordinated activities between users"""
        coordinated_events = []
        
        try:
            # Group activities by time windows
            full_df_sorted = full_df.sort_values('_time')
            
            for i, row in full_df_sorted.iterrows():
                current_time = row['_time']
                window_start = current_time - pd.Timedelta(minutes=time_window_minutes)
                window_end = current_time + pd.Timedelta(minutes=time_window_minutes)
                
                # Find other activities in the same time window
                window_activities = full_df_sorted[
                    (full_df_sorted['_time'] >= window_start) &
                    (full_df_sorted['_time'] <= window_end) &
                    (full_df_sorted['OS_User'] != row['OS_User'])  # Different users
                ]
                
                # Check for similar activities
                similar_activities = window_activities[
                    (window_activities['DB_Name'] == row['DB_Name']) |
                    (window_activities['Accessed_Obj'] == row['Accessed_Obj'])
                ]
                
                if len(similar_activities) >= 2:  # At least 2 other users doing similar things
                    coordinated_events.append({
                        'primary_user': row['OS_User'],
                        'primary_time': current_time,
                        'coordinated_users': similar_activities['OS_User'].tolist(),
                        'database': row['DB_Name'],
                        'object': row['Accessed_Obj'],
                        'total_users_involved': len(similar_activities) + 1
                    })
                    
        except Exception:
            pass
            
        return coordinated_events
