
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

# Set random seed for reproducibility
np.random.seed(42)
random.seed(42)

# Configuration
NUM_ROWS = 5000
USERS = ['alice.smith', 'bob.johnson', 'charlie.brown', 'diana.wong', 'evan.garcia']
DATABASES = ['FinanceDB', 'CustomerDB', 'HRDB', 'AuditDB', 'InventoryDB']
PROGRAMS = ['SSMS', 'sqlcmd', 'python', 'PowerShell', 'Excel', 'Workbench', 'DBeaver', 'Toad']
MODULES = ['QueryRunner', 'DataAnalysis', 'Command', 'Management', 'ODBC', 'Script', 'Batch']
HOSTS = ['workstation01', 'server02', 'laptop03', 'desktop04', 'mobile05']
IPS = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5']

# Database objects by risk level
HIGH_RISK_OBJECTS = ['Salaries', 'HR_Records', 'SSN_Data', 'Credit_Cards', 'CustomerData', 'AuditLog', 'Payroll']
MEDIUM_RISK_OBJECTS = ['Employees', 'Orders', 'Inventory', 'Suppliers', 'Products', 'Accounts']
LOW_RISK_OBJECTS = ['Categories', 'Regions', 'Lookup_Tables', 'Config', 'Temp_Data', 'Logs']

# SQL statements by risk level
HIGH_RISK_SQL = [
    "DELETE FROM Salaries WHERE 1=1",
    "DROP TABLE HR_Records",
    "UPDATE Payroll SET Amount = 0",
    "SELECT * FROM CustomerData",
    "TRUNCATE TABLE AuditLog",
    "ALTER TABLE Employees DROP COLUMN SSN",
    "GRANT ALL PRIVILEGES ON *.* TO 'temp_user'@'%'",
    "DELETE FROM Credit_Cards",
    "UPDATE Salaries SET Amount = Amount * 2 WHERE 1=1"
]

MEDIUM_RISK_SQL = [
    "UPDATE Employees SET Status = 'Active' WHERE EmployeeID = 1001",
    "INSERT INTO Orders VALUES (12345, 'Product A', 100)",
    "SELECT * FROM Inventory WHERE Category = 'Electronics'",
    "ALTER TABLE Products ADD COLUMN NewField VARCHAR(50)",
    "DELETE FROM Orders WHERE OrderDate < '2024-01-01'",
    "CREATE INDEX idx_employee_dept ON Employees(Department)",
    "UPDATE Inventory SET Quantity = Quantity - 10 WHERE ProductID = 555"
]

LOW_RISK_SQL = [
    "SELECT COUNT(*) FROM Orders",
    "SELECT ProductName FROM Products WHERE Category = 'Books'",
    "INSERT INTO Logs VALUES (GETDATE(), 'System startup')",
    "SELECT Region FROM Regions",
    "CREATE TABLE Temp_Report AS SELECT * FROM Reports",
    "UPDATE Config SET LastUpdate = GETDATE()",
    "SELECT * FROM Categories ORDER BY Name"
]

# Context patterns by risk level
HIGH_RISK_CONTEXTS = [
    "Emergency data cleanup - unauthorized",
    "Bypass approval process - urgent",
    "Manual override - temporary fix",
    "Hotfix without change control",
    "Critical system repair - off hours",
    "Emergency access - bypass normal procedures"
]

MEDIUM_RISK_CONTEXTS = [
    "Routine maintenance - scheduled",
    "Data migration - CHG000123",
    "Performance optimization - approved",
    "System update - planned maintenance",
    "Report generation - monthly process",
    "Index rebuild - CHG000456"
]

LOW_RISK_CONTEXTS = [
    "Standard query - automated report",
    "Scheduled backup verification",
    "Regular data refresh - CHG000789",
    "Daily system check - routine",
    "Approved data export - REQ001234",
    "Standard maintenance - CHG000999"
]

def generate_timestamp(base_date, risk_level):
    """Generate timestamp based on risk level"""
    # Add random days (0-30)
    days_offset = random.randint(0, 30)
    date = base_date + timedelta(days=days_offset)
    
    if risk_level == 'high':
        # High risk: more likely to be off-hours or weekends
        if random.random() < 0.6:  # 60% chance of off-hours
            if random.random() < 0.3:  # 30% chance of very late night
                hour = random.randint(0, 5)
            else:  # Off-hours but not extreme
                hour = random.choice([19, 20, 21, 22, 23, 6, 7])
        else:
            hour = random.randint(9, 17)
        
        # Weekend probability
        if random.random() < 0.4:  # 40% chance of weekend
            date = date + timedelta(days=(5 - date.weekday()) % 7)
    
    elif risk_level == 'medium':
        # Medium risk: some off-hours but mostly business hours
        if random.random() < 0.3:  # 30% chance of off-hours
            hour = random.choice([8, 18, 19])
        else:
            hour = random.randint(9, 17)
    
    else:  # low risk
        # Low risk: mostly business hours
        hour = random.randint(9, 17)
    
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    
    return date.replace(hour=hour, minute=minute, second=second)

def generate_test_data():
    """Generate comprehensive test dataset"""
    data = []
    base_date = datetime(2025, 1, 1, 9, 0, 0)
    
    # Define risk distribution: 20% high, 30% medium, 50% low
    risk_distribution = ['high'] * 1000 + ['medium'] * 1500 + ['low'] * 2500
    random.shuffle(risk_distribution)
    
    for i in range(NUM_ROWS):
        risk_level = risk_distribution[i]
        
        # Select components based on risk level
        if risk_level == 'high':
            accessed_obj = random.choice(HIGH_RISK_OBJECTS)
            statement = random.choice(HIGH_RISK_SQL).replace('Salaries', accessed_obj).replace('HR_Records', accessed_obj)
            context = random.choice(HIGH_RISK_CONTEXTS)
            program = random.choice(['sqlcmd', 'python', 'PowerShell', 'SSMS'])
            
        elif risk_level == 'medium':
            accessed_obj = random.choice(MEDIUM_RISK_OBJECTS)
            statement = random.choice(MEDIUM_RISK_SQL).replace('Employees', accessed_obj).replace('Orders', accessed_obj)
            context = random.choice(MEDIUM_RISK_CONTEXTS)
            program = random.choice(['SSMS', 'Workbench', 'DBeaver', 'Excel'])
            
        else:  # low risk
            accessed_obj = random.choice(LOW_RISK_OBJECTS)
            statement = random.choice(LOW_RISK_SQL).replace('Orders', accessed_obj).replace('Products', accessed_obj)
            context = random.choice(LOW_RISK_CONTEXTS)
            program = random.choice(['SSMS', 'Excel', 'Workbench'])
        
        # Generate other fields
        user = random.choice(USERS)
        database = random.choice(DATABASES)
        timestamp = generate_timestamp(base_date, risk_level)
        
        row = {
            '_time': timestamp,
            'OS_User': user,
            'Exec_User': user if random.random() < 0.9 else random.choice(USERS),  # 10% chance of different exec user
            'DB_Type': 'MSSQL',
            'DB_Name': database,
            'Program': program,
            'Module': random.choice(MODULES),
            'Src_Host': random.choice(HOSTS),
            'Src_IP': random.choice(IPS),
            'Accessed_Obj': accessed_obj,
            'Accessed_Obj_Owner': 'dbo',
            'Statement': statement,
            'MS_Context': context
        }
        
        data.append(row)
    
    # Create DataFrame and sort by timestamp
    df = pd.DataFrame(data)
    df = df.sort_values('_time').reset_index(drop=True)
    
    return df

def add_realistic_variations(df):
    """Add realistic variations to make data more authentic"""
    
    # Add some NaN values to simulate real data
    for col in ['Accessed_Obj', 'MS_Context', 'Program']:
        if col in df.columns:
            # Randomly set 2-3% of values to NaN
            nan_indices = np.random.choice(df.index, size=int(len(df) * 0.025), replace=False)
            df.loc[nan_indices, col] = np.nan
    
    # Add some suspicious patterns
    # User alice.smith has more high-risk activities on weekends
    alice_weekend_mask = (df['OS_User'] == 'alice.smith') & (df['_time'].dt.weekday >= 5)
    high_risk_statements = [
        "SELECT * FROM Salaries",
        "UPDATE Payroll SET Amount = Amount * 1.1",
        "DELETE FROM AuditLog WHERE LogDate < GETDATE()-30"
    ]
    df.loc[alice_weekend_mask.sample(n=min(20, alice_weekend_mask.sum())).index, 'Statement'] = np.random.choice(high_risk_statements, size=min(20, alice_weekend_mask.sum()))
    
    # Bob has some late-night activities
    bob_mask = df['OS_User'] == 'bob.johnson'
    late_night_indices = df[bob_mask & (df['_time'].dt.hour <= 3)].index
    if len(late_night_indices) > 0:
        df.loc[late_night_indices[:10], 'MS_Context'] = "Emergency system maintenance - unauthorized"
    
    return df

# Generate the dataset
print("Generating 5000-row test dataset...")
test_df = generate_test_data()
test_df = add_realistic_variations(test_df)

# Save to CSV
filename = 'test_sql_audit_5000_rows.csv'
test_df.to_csv(filename, index=False)

print(f"✅ Generated {filename} with {len(test_df)} rows")
print("\n📊 Dataset Statistics:")
print(f"Time range: {test_df['_time'].min()} to {test_df['_time'].max()}")
print(f"Users: {', '.join(test_df['OS_User'].unique())}")
print(f"Databases: {', '.join(test_df['DB_Name'].unique())}")
print(f"Unique statements: {test_df['Statement'].nunique()}")

# Risk level estimation
print("\n🎯 Expected Risk Distribution:")
high_risk_objects = test_df['Accessed_Obj'].isin(HIGH_RISK_OBJECTS).sum()
medium_risk_objects = test_df['Accessed_Obj'].isin(MEDIUM_RISK_OBJECTS).sum()
low_risk_objects = test_df['Accessed_Obj'].isin(LOW_RISK_OBJECTS).sum()

print(f"High-risk object access: ~{high_risk_objects} events")
print(f"Medium-risk object access: ~{medium_risk_objects} events") 
print(f"Low-risk object access: ~{low_risk_objects} events")

# Off-hours activities
off_hours = test_df[(test_df['_time'].dt.hour < 8) | (test_df['_time'].dt.hour >= 18)].shape[0]
weekend_activities = test_df[test_df['_time'].dt.weekday >= 5].shape[0]

print(f"Off-hours activities: {off_hours}")
print(f"Weekend activities: {weekend_activities}")

print(f"\n✨ Test file '{filename}' ready for upload to the SQL Threat Explainer!")
