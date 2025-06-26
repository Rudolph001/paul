import pandas as pd
import streamlit as st
from datetime import datetime, time
import numpy as np
import io
from utils.risk_engine import RiskEngine
from utils.report_generator import ReportGenerator
from utils.email_handler import EmailHandler
from utils.anomaly_detector import AnomalyDetector
from utils.dashboard import Dashboard

# Configure page
st.set_page_config(
    page_title="SQL Threat Explainer", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize components
@st.cache_resource
def get_components():
    return {
        'risk_engine': RiskEngine(),
        'report_generator': ReportGenerator(),
        'email_handler': EmailHandler(),
        'anomaly_detector': AnomalyDetector(),
        'dashboard': Dashboard(RiskEngine(), AnomalyDetector())
    }

components = get_components()

# Sensitive objects and configuration
SENSITIVE_TABLES = ['Salaries', 'Employees', 'HR_Records', 'CustomerData', 'AuditLog', 'Payroll', 'SSN', 'Credit']
REQUIRED_COLUMNS = ['_time', 'OS_User', 'Exec_User', 'DB_Type', 'DB_Name', 'Program', 'Module', 'Src_Host', 'Src_IP', 'Accessed_Obj', 'Accessed_Obj_Owner', 'Statement', 'MS_Context']

# Load and validate CSV
@st.cache_data
def load_csv(upload):
    try:
        # Try to read CSV with flexible parsing
        df = pd.read_csv(upload, encoding='utf-8', on_bad_lines='skip')
        
        if df.empty:
            st.error("The uploaded file appears to be empty.")
            return None
        
        # Show file preview
        st.info(f"File loaded successfully! Found {len(df)} rows and {len(df.columns)} columns.")
        with st.expander("Preview first 5 rows"):
            st.dataframe(df.head())
        
        # Show available columns
        st.info("Available columns: " + ", ".join(df.columns.tolist()))
        
        # Try to map common column variations
        column_mapping = {
            'time': '_time',
            'timestamp': '_time',
            'datetime': '_time',
            'user': 'OS_User',
            'username': 'OS_User',
            'os_user': 'OS_User',
            'exec_user': 'Exec_User',
            'database': 'DB_Name',
            'db': 'DB_Name',
            'db_name': 'DB_Name',
            'db_type': 'DB_Type',
            'sql': 'Statement',
            'query': 'Statement',
            'statement': 'Statement',
            'object': 'Accessed_Obj',
            'table': 'Accessed_Obj',
            'accessed_obj': 'Accessed_Obj',
            'accessed_obj_owner': 'Accessed_Obj_Owner',
            'host': 'Src_Host',
            'src_host': 'Src_Host',
            'ip': 'Src_IP',
            'src_ip': 'Src_IP',
            'context': 'MS_Context',
            'ms_context': 'MS_Context',
            'program': 'Program',
            'module': 'Module'
        }
        
        # Auto-map columns - handle exact matches first, then lowercase
        mapped_columns = []
        for available_col in df.columns:
            # Check for exact match first
            if available_col in REQUIRED_COLUMNS:
                continue  # Already correct
            
            # Check lowercase and stripped versions
            lower_col = available_col.lower().strip().replace(' ', '_')
            if lower_col in column_mapping:
                target_col = column_mapping[lower_col]
                if target_col not in df.columns:
                    df.rename(columns={available_col: target_col}, inplace=True)
                    mapped_columns.append(f"'{available_col}' → '{target_col}'")
        
        if mapped_columns:
            st.success("Mapped columns: " + ", ".join(mapped_columns))
        
        # Check for required columns
        missing_cols = [col for col in REQUIRED_COLUMNS if col not in df.columns]
        if missing_cols:
            st.warning(f"Missing required columns: {', '.join(missing_cols)}")
            # Create placeholder columns with default values
            for col in missing_cols:
                if col == '_time':
                    df[col] = pd.Timestamp.now()
                elif col in ['OS_User', 'Exec_User']:
                    df[col] = 'unknown_user'
                elif col in ['DB_Name', 'DB_Type']:
                    df[col] = 'unknown_db'
                elif col == 'Statement':
                    df[col] = 'SELECT 1'
                else:
                    df[col] = 'unknown'
            st.info("Created placeholder values for missing columns. Please review the data.")
        
        # Parse datetime
        if '_time' in df.columns:
            df['_time'] = pd.to_datetime(df['_time'], errors='coerce')
            
            invalid_dates = df['_time'].isna().sum()
            if invalid_dates > 0:
                st.warning(f"Found {invalid_dates} rows with invalid datetime formats. Using current time as fallback.")
                df['_time'].fillna(pd.Timestamp.now(), inplace=True)
        
        return df
        
    except Exception as e:
        st.error(f"Error loading CSV: {str(e)}")
        st.info("Please ensure your file is a properly formatted CSV. You can download the sample template below.")
        return None

# Get risk color based on score
def get_risk_color(score):
    if score >= 70:
        return "🔴"
    elif score >= 40:
        return "🟠"
    else:
        return "🟢"

# Generate risk-aware narrative
def generate_risk_narrative(row, risk_score, anomalies):
    time_str = row['_time'].strftime("%Y-%m-%d %H:%M")
    action = components['risk_engine'].explain_sql(row['Statement'])
    context = row['MS_Context']
    
    # Risk indicators
    risk_color = get_risk_color(risk_score)
    sensitive = "⚠️ **Sensitive table access**" if any(s.lower() in row['Accessed_Obj'].lower() for s in SENSITIVE_TABLES) else ""
    unauthorized = "🚨 **Unauthorized change**" if "unauthorized" in context.lower() else ""
    outlier = "🔍 **Outlier activity**" if anomalies.get('is_outlier', False) else ""
    off_hours = "⏰ **Off-hours access**" if anomalies.get('off_hours', False) else ""
    
    badges = " ".join([badge for badge in [sensitive, unauthorized, outlier, off_hours] if badge])
    
    narrative = f"""
**{risk_color} Risk Score: {risk_score}/100** - {row['OS_User']} accessed the {row['DB_Name']} database and {action} on `{row['Accessed_Obj']}` using {row['Program']} from {row['Src_IP']} on {time_str}.

**Context:** {context}

{badges}
"""
    
    if anomalies.get('unusual_volume'):
        narrative += f"\n📊 **Unusual data volume detected** - {anomalies['volume_description']}"
    
    return narrative.strip()

# Generate comprehensive summary
def generate_comprehensive_summary(df, risk_scores, anomaly_data):
    if df.empty:
        return "No data available for the selected filters."
    
    users = df['OS_User'].unique()
    start_time = df['_time'].min().strftime("%Y-%m-%d %H:%M")
    end_time = df['_time'].max().strftime("%Y-%m-%d %H:%M")
    
    # Risk statistics
    avg_risk = np.mean(risk_scores)
    high_risk_count = sum(1 for score in risk_scores if score >= 70)
    medium_risk_count = sum(1 for score in risk_scores if 40 <= score < 70)
    low_risk_count = sum(1 for score in risk_scores if score < 40)
    
    # Activity breakdown
    actions = df['Statement'].apply(components['risk_engine'].explain_sql).value_counts().to_dict()
    
    # Anomaly statistics
    outlier_count = sum(1 for anomaly in anomaly_data if anomaly.get('is_outlier', False))
    off_hours_count = sum(1 for anomaly in anomaly_data if anomaly.get('off_hours', False))
    
    # Sensitive table access
    sensitive_count = df['Accessed_Obj'].apply(
        lambda x: any(s.lower() in x.lower() for s in SENSITIVE_TABLES)
    ).sum()
    
    # Unauthorized activities
    unauthorized_count = df['MS_Context'].str.lower().str.contains("unauthorized", na=False).sum()
    
    summary = f"""
## 📊 Executive Summary ({start_time} to {end_time})

### 👥 **User Activity Overview**
- **Active Users:** {len(users)} ({', '.join(users[:5])}{', ...' if len(users) > 5 else ''})
- **Total Events:** {len(df)}

### ⚠️ **Risk Assessment**
- **Average Risk Score:** {avg_risk:.1f}/100
- **🔴 High Risk Events:** {high_risk_count} (≥70)
- **🟠 Medium Risk Events:** {medium_risk_count} (40-69)
- **🟢 Low Risk Events:** {low_risk_count} (<40)

### 🔍 **Security Indicators**
- **⚠️ Sensitive Table Access:** {sensitive_count} events
- **🚨 Unauthorized Changes:** {unauthorized_count} events
- **🔍 Outlier Activities:** {outlier_count} events
- **⏰ Off-Hours Access:** {off_hours_count} events

### 📈 **Activity Breakdown**
"""
    
    for action, count in actions.items():
        summary += f"- **{action.title()}:** {count} instances\n"
    
    # Top risk events
    if risk_scores:
        top_risk_indices = np.argsort(risk_scores)[-3:][::-1]
        summary += "\n### 🚨 **Top Risk Events**\n"
        for i, idx in enumerate(top_risk_indices, 1):
            if idx < len(df):
                row = df.iloc[idx]
                summary += f"{i}. **{row['OS_User']}** - Risk: {risk_scores[idx]}/100 - {row['Accessed_Obj']} ({row['_time'].strftime('%Y-%m-%d %H:%M')})\n"
    
    return summary.strip()

# Main application
def main():
    st.title("🔍 Insider Threat SQL Activity Explainer")
    st.markdown("**Advanced Risk Analysis & Compliance Reporting**")
    
    # Sidebar for controls
    with st.sidebar:
        st.header("📁 Data Upload")
        
        # Sample CSV download
        sample_csv_data = """_time,OS_User,Exec_User,DB_Type,DB_Name,Program,Module,Src_Host,Src_IP,Accessed_Obj,Accessed_Obj_Owner,Statement,MS_Context
2025-06-24 10:15:00,bob,bob,MSSQL,FinanceDB,SSMS,QueryRunner,host3,10.0.0.3,Salaries,dbo,UPDATE Salaries SET Amount = 75000 WHERE EmployeeID = 1001,CHG00002 - authorized salary adjustment
2025-06-24 14:30:00,alice,alice,MSSQL,CustomerDB,Python,DataAnalysis,host1,10.0.0.1,CustomerData,dbo,SELECT * FROM CustomerData,Unauthorized data export attempt
2025-06-24 22:45:00,john,john,MSSQL,AuditDB,sqlcmd,Command,host2,10.0.0.2,AuditLog,dbo,DELETE FROM AuditLog WHERE LogDate < '2025-01-01',Emergency cleanup - off hours
2025-06-25 09:00:00,susan,susan,MSSQL,HRDB,SSMS,Management,host4,10.0.0.4,Employees,dbo,INSERT INTO Employees VALUES ('Jane Doe' 'Manager' 'IT'),CHG00003 - new employee onboarding
2025-06-25 16:20:00,mike,mike,MSSQL,FinanceDB,Excel,ODBC,host5,10.0.0.5,Payroll,dbo,SELECT PayrollAmount FROM Payroll WHERE Department = 'Engineering',Routine payroll analysis"""
        
        st.download_button(
            label="📥 Download Sample CSV Template",
            data=sample_csv_data,
            file_name="sample_sql_audit_log.csv",
            mime="text/csv",
            help="Download this template to see the expected CSV format"
        )
        
        uploaded_file = st.file_uploader("Upload Trellix SQL CSV", type="csv", help="Upload CSV with required columns for SQL log analysis")
        
        if uploaded_file:
            st.success("✅ File uploaded successfully")
    
    if uploaded_file:
        # Load data
        with st.spinner("Loading and analyzing data..."):
            df = load_csv(uploaded_file)
        
        if df is not None and not df.empty:
            # Sidebar filters
            with st.sidebar:
                st.header("🔧 Filters")
                
                # Date range
                min_date = df['_time'].min().date()
                max_date = df['_time'].max().date()
                start_date = st.date_input("Start Date", min_date, min_value=min_date, max_value=max_date)
                end_date = st.date_input("End Date", max_date, min_value=min_date, max_value=max_date)
                
                # User filter
                users = ["All"] + sorted(df['OS_User'].unique().tolist())
                selected_user = st.selectbox("Filter by User", users)
                
                # Risk threshold filter
                risk_threshold = st.slider("Minimum Risk Score", 0, 100, 0, help="Show only events above this risk score")
                
                st.header("📊 Export & Reports")
                
            # Apply filters
            filtered_df = df[
                (df['_time'].dt.date >= start_date) & 
                (df['_time'].dt.date <= end_date)
            ].copy()
            
            if selected_user != "All":
                filtered_df = filtered_df[filtered_df['OS_User'] == selected_user]
            
            if not filtered_df.empty:
                # Calculate risk scores and detect anomalies
                with st.spinner("Calculating risk scores and detecting anomalies..."):
                    risk_scores = []
                    anomaly_data = []
                    
                    for _, row in filtered_df.iterrows():
                        risk_score = components['risk_engine'].calculate_risk_score(row, SENSITIVE_TABLES)
                        anomalies = components['anomaly_detector'].detect_anomalies(row, df)
                        
                        risk_scores.append(risk_score)
                        anomaly_data.append(anomalies)
                
                # Apply risk threshold filter
                risk_mask = [score >= risk_threshold for score in risk_scores]
                final_df = filtered_df[risk_mask].copy()
                final_risk_scores = [score for score, mask in zip(risk_scores, risk_mask) if mask]
                final_anomaly_data = [anomaly for anomaly, mask in zip(anomaly_data, risk_mask) if mask]
                
                if final_df.empty:
                    st.warning(f"No events found above risk threshold of {risk_threshold}")
                    return
                
                # Create navigation tabs for different views
                tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "📖 Executive Summary", "👤 User Stories", "🗄️ Database Stories"])
                
                with tab1:
                    # Professional dashboard
                    components['dashboard'].create_executive_dashboard(final_df, final_risk_scores, final_anomaly_data)
                
                with tab2:
                    # Display summary
                    summary_text = generate_comprehensive_summary(final_df, final_risk_scores, final_anomaly_data)
                    st.markdown(summary_text)
                
                with tab3:
                    # User storylines
                    st.subheader("👤 Individual User Analysis")
                    
                    # User selection
                    unique_users = final_df['OS_User'].unique()
                    selected_story_user = st.selectbox("Select User for Detailed Story", unique_users, key="story_user")
                    
                    if selected_story_user:
                        components['dashboard'].create_user_storyline(
                            final_df, selected_story_user, final_risk_scores, final_anomaly_data
                        )
                
                with tab4:
                    # Database storylines
                    st.subheader("🗄️ Database Security Analysis")
                    
                    # Database selection
                    unique_dbs = final_df['DB_Name'].unique()
                    selected_story_db = st.selectbox("Select Database for Detailed Analysis", unique_dbs, key="story_db")
                    
                    if selected_story_db:
                        components['dashboard'].create_database_storyline(
                            final_df, selected_story_db, final_risk_scores, final_anomaly_data
                        )
                
                # Legacy charts section (keeping for compatibility)
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("#### Risk Score Distribution")
                    with st.expander("ℹ️ Chart Information"):
                        st.markdown("""
                        **Purpose:** Shows count of events in each risk category
                        
                        **Risk Categories:**
                        - **High (70-100):** Immediate attention required
                        - **Medium (40-69):** Monitor closely  
                        - **Low (0-39):** Normal operations
                        
                        **Use this to:** Quickly assess overall security posture
                        """)
                    
                    risk_distribution = {
                        'High (70-100)': sum(1 for score in final_risk_scores if score >= 70),
                        'Medium (40-69)': sum(1 for score in final_risk_scores if 40 <= score < 70),
                        'Low (0-39)': sum(1 for score in final_risk_scores if score < 40)
                    }
                    st.bar_chart(risk_distribution)
                
                with col2:
                    st.subheader("👥 Users by Avg Risk")
                    with st.expander("ℹ️ Ranking Information"):
                        st.markdown("""
                        **What this shows:** Users ranked by their average risk score
                        
                        **Calculation method:** 
                        - Sum of all risk scores for each user
                        - Divided by number of activities
                        - Sorted from highest to lowest
                        
                        **How to use:**
                        - **Top users:** May need additional monitoring
                        - **Consistent high scores:** Potential training needs
                        - **Sudden changes:** Investigate behavioral shifts
                        
                        **Note:** Consider both score and activity volume for context
                        """)
                    
                    # Top users by average risk
                    user_risks = final_df.copy()
                    user_risks['Risk_Score'] = final_risk_scores
                    user_avg_risk = user_risks.groupby('OS_User')['Risk_Score'].mean().sort_values(ascending=False)
                    for user, avg_risk in user_avg_risk.head(5).items():
                        st.write(f"**{user}:** {avg_risk:.1f}")
                
                # Timeline view
                st.header("📜 Risk-Prioritized Timeline")
                
                # Sort by risk score descending
                timeline_data = list(zip(final_df.iterrows(), final_risk_scores, final_anomaly_data))
                timeline_data.sort(key=lambda x: x[1], reverse=True)
                
                for (_, row), risk_score, anomalies in timeline_data:
                    with st.expander(f"{get_risk_color(risk_score)} {row['OS_User']} - {row['Accessed_Obj']} (Risk: {risk_score}/100)", expanded=False):
                        narrative = generate_risk_narrative(row, risk_score, anomalies)
                        st.markdown(narrative)
                
                # Detailed table
                st.header("📋 Detailed Event Analysis")
                
                # Prepare display dataframe
                display_df = final_df.copy()
                display_df['Risk_Score'] = final_risk_scores
                display_df['Risk_Level'] = [get_risk_color(score) for score in final_risk_scores]
                display_df['Explanation'] = display_df['Statement'].apply(components['risk_engine'].explain_sql)
                display_df['Anomalies'] = [
                    ', '.join([
                        key.replace('_', ' ').title() 
                        for key, value in anomaly.items() 
                        if value and key != 'volume_description'
                    ]) or 'None'
                    for anomaly in final_anomaly_data
                ]
                
                # Display columns
                display_columns = ['Risk_Level', 'Risk_Score', 'OS_User', '_time', 'DB_Name', 'Accessed_Obj', 'Explanation', 'Anomalies', 'MS_Context']
                st.dataframe(
                    display_df[display_columns].sort_values('Risk_Score', ascending=False),
                    use_container_width=True
                )
                
                # Export and email section
                st.header("📤 Export & Communication")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    # CSV Export
                    csv_data = display_df.to_csv(index=False)
                    st.download_button(
                        label="📄 Download CSV Report",
                        data=csv_data,
                        file_name=f"sql_audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
                
                with col2:
                    # PDF Export
                    if st.button("📑 Generate PDF Report"):
                        with st.spinner("Generating PDF report..."):
                            pdf_buffer = components['report_generator'].generate_pdf_report(
                                final_df, final_risk_scores, final_anomaly_data, summary_text
                            )
                            st.download_button(
                                label="📥 Download PDF Report",
                                data=pdf_buffer,
                                file_name=f"sql_threat_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                                mime="application/pdf"
                            )
                
                with col3:
                    # Email functionality
                    if st.button("📧 Email Report"):
                        with st.expander("Email Configuration", expanded=True):
                            recipient = st.text_input("Recipient Email", placeholder="security@company.com")
                            subject = st.text_input("Subject", value=f"SQL Threat Analysis Report - {datetime.now().strftime('%Y-%m-%d')}")
                            
                            if st.button("Send Email") and recipient:
                                with st.spinner("Sending email..."):
                                    try:
                                        components['email_handler'].send_outlook_email(
                                            recipient, subject, summary_text, final_df, final_risk_scores
                                        )
                                        st.success("✅ Email sent successfully!")
                                    except Exception as e:
                                        st.error(f"❌ Failed to send email: {str(e)}")
            
            else:
                st.warning("No data found for the selected date range and user filter.")
    
    else:
        # Instructions
        st.info("📁 Please upload a CSV file with Trellix-style SQL logs to begin analysis.")
        
        with st.expander("📋 Required CSV Format", expanded=True):
            st.markdown("""
            **Required Columns:**
            - `_time`: Timestamp (YYYY-MM-DD HH:MM:SS)
            - `OS_User`: Operating system user
            - `Exec_User`: Executing user
            - `DB_Type`: Database type (e.g., MSSQL, MySQL)
            - `DB_Name`: Database name
            - `Program`: Application used
            - `Module`: Module or component
            - `Src_Host`: Source hostname
            - `Src_IP`: Source IP address
            - `Accessed_Obj`: Database object accessed
            - `Accessed_Obj_Owner`: Object owner
            - `Statement`: SQL statement
            - `MS_Context`: Context or change ticket information
            
            **Example Row:**
            ```
            2025-06-24 10:15:00,bob,bob,MSSQL,FinanceDB,SSMS,QueryRunner,host3,10.0.0.3,Salaries,dbo,UPDATE Salaries SET Amount = ...,CHG00002 - schema update
            ```
            """)

if __name__ == "__main__":
    main()
