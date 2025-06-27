#!/usr/bin/env python3

# Quick test to verify risk calculation works
import pandas as pd
import sys
sys.path.append('.')

from utils.risk_engine import RiskEngine
from utils.anomaly_detector import AnomalyDetector

# Load test data
print("Loading test data...")
df = pd.read_csv('test_sql_audit_5000_rows.csv')
print(f"Loaded {len(df)} rows")

# Initialize components
risk_engine = RiskEngine()
anomaly_detector = AnomalyDetector()

# Test first row
row = df.iloc[0]
print(f"Testing row: {row['OS_User']} - {row['Statement'][:50]}...")

# Calculate risk
SENSITIVE_TABLES = ['Salaries', 'Employees', 'HR_Records', 'CustomerData', 'AuditLog', 'Payroll', 'SSN', 'Credit']
risk_score = risk_engine.calculate_risk_score(row, SENSITIVE_TABLES)
anomalies = anomaly_detector.detect_anomalies(row, df)

print(f"Risk score: {risk_score}")
print(f"Anomalies: {anomalies}")
print("Risk calculation test successful!")