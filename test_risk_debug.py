#!/usr/bin/env python3

import pandas as pd
import sys
sys.path.append('.')

from utils.risk_engine import RiskEngine

# Load test data
df = pd.read_csv('test_sql_audit_5000_rows.csv')
risk_engine = RiskEngine()
SENSITIVE_TABLES = ['Salaries', 'Employees', 'HR_Records', 'CustomerData', 'AuditLog', 'Payroll', 'SSN', 'Credit']

print("Analyzing risk score distribution...")

risk_scores = []
high_risk_examples = []

for i in range(min(100, len(df))):  # Check first 100 rows
    row = df.iloc[i]
    score = risk_engine.calculate_risk_score(row, SENSITIVE_TABLES)
    risk_scores.append(score)
    
    if score >= 70:
        high_risk_examples.append((i, score, row['Statement'][:60]))

print(f"Risk scores range: {min(risk_scores)} to {max(risk_scores)}")
print(f"Average score: {sum(risk_scores)/len(risk_scores):.1f}")

# Count risk levels
high = sum(1 for s in risk_scores if s >= 70)
medium = sum(1 for s in risk_scores if 40 <= s < 70)
low = sum(1 for s in risk_scores if s < 40)

print(f"High risk (≥70): {high}")
print(f"Medium risk (40-69): {medium}")
print(f"Low risk (<40): {low}")

print("\nHigh risk examples:")
for idx, score, stmt in high_risk_examples[:5]:
    print(f"  Row {idx}: {score} - {stmt}")

# Let's manually test a dangerous combination
print("\nTesting manual high-risk scenario...")
test_row = df.iloc[0].copy()
test_row['Statement'] = 'DELETE FROM Salaries WHERE 1=1'
test_row['Accessed_Obj'] = 'Salaries'
test_row['MS_Context'] = 'unauthorized emergency bypass'
test_row['_time'] = pd.Timestamp('2024-01-01 23:30:00')  # Off hours
test_row['Program'] = 'sqlcmd'

test_score = risk_engine.calculate_risk_score(test_row, SENSITIVE_TABLES)
print(f"Manual test score: {test_score}")