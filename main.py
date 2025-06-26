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
from utils.admin_config import AdminConfig

# Configure page
st.set_page_config(
    page_title="SQL Threat Explainer", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize components
@st.cache_resource
def get_components():
    admin_config = AdminConfig()
    return {
        'risk_engine': RiskEngine(),
        'report_generator': ReportGenerator(),
        'email_handler': EmailHandler(),
        'anomaly_detector': AnomalyDetector(),
        'dashboard': Dashboard(RiskEngine(), AnomalyDetector()),
        'admin_config': admin_config
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
    # Professional navigation sidebar
    with st.sidebar:
        st.title("🔍 SQL Threat Explainer")
        st.markdown("---")
        
        # Navigation menu
        if 'current_page' not in st.session_state:
            st.session_state.current_page = "Upload & Overview"
        
        nav_options = [
            "📁 Upload & Overview",
            "📊 Executive Dashboard", 
            "📈 Risk Analysis",
            "👤 User Investigation",
            "🗄️ Database Analysis",
            "📋 Event Details",
            "📤 Reports & Export",
            "⚙️ Admin Configuration"
        ]
        
        st.markdown("### 🧭 Navigation")
        for option in nav_options:
            if st.button(option, key=f"nav_{option}", use_container_width=True):
                st.session_state.current_page = option.split(" ", 1)[1]  # Remove emoji
        
        st.markdown("---")
        
        # Current page indicator
        st.markdown(f"**Current:** {st.session_state.current_page}")
        
        st.markdown("---")
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
    
    # Main content area
    if st.session_state.current_page == "Upload & Overview":
        st.title("🔍 Insider Threat SQL Activity Explainer")
        st.markdown("**Advanced Risk Analysis & Compliance Reporting**")
    
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
                
                # Navigation-based content rendering
                if st.session_state.current_page == "Upload & Overview":
                    # Overview page content
                    st.header("📊 Data Overview")
                    summary_text = generate_comprehensive_summary(final_df, final_risk_scores, final_anomaly_data)
                    st.markdown(summary_text)
                
                elif st.session_state.current_page == "Executive Dashboard":
                    st.header("📊 Executive Dashboard")
                    components['dashboard'].create_executive_dashboard(final_df, final_risk_scores, final_anomaly_data)
                
                elif st.session_state.current_page == "Risk Analysis":
                    st.header("📈 Risk Analysis & Metrics")
                    
                    # Risk distribution charts
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
                
                elif st.session_state.current_page == "User Investigation":
                    st.header("👤 User Investigation")
                    
                    # User selection
                    unique_users = final_df['OS_User'].unique()
                    selected_story_user = st.selectbox("Select User for Detailed Investigation", unique_users, key="story_user")
                    
                    if selected_story_user:
                        components['dashboard'].create_user_storyline(
                            final_df, selected_story_user, final_risk_scores, final_anomaly_data
                        )
                
                elif st.session_state.current_page == "Database Analysis":
                    st.header("🗄️ Database Security Analysis")
                    
                    # Database selection
                    unique_dbs = final_df['DB_Name'].unique()
                    selected_story_db = st.selectbox("Select Database for Analysis", unique_dbs, key="story_db")
                    
                    if selected_story_db:
                        components['dashboard'].create_database_storyline(
                            final_df, selected_story_db, final_risk_scores, final_anomaly_data
                        )
                
                elif st.session_state.current_page == "Event Details":
                    st.header("📋 Detailed Event Analysis")
                    
                    # Timeline view
                    st.subheader("📜 Risk-Prioritized Timeline")
                    
                    # Sort by risk score descending
                    timeline_data = list(zip(final_df.iterrows(), final_risk_scores, final_anomaly_data))
                    timeline_data.sort(key=lambda x: x[1], reverse=True)
                    
                    for (_, row), risk_score, anomalies in timeline_data:
                        with st.expander(f"{get_risk_color(risk_score)} {row['OS_User']} - {row['Accessed_Obj']} (Risk: {risk_score}/100)", expanded=False):
                            narrative = generate_risk_narrative(row, risk_score, anomalies)
                            st.markdown(narrative)
                    
                    # Detailed table
                    st.subheader("📊 Event Data Table")
                    
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
                
                elif st.session_state.current_page == "Reports & Export":
                    st.header("📤 Export & Communication")
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        # CSV Export
                        display_df = final_df.copy()
                        display_df['Risk_Score'] = final_risk_scores
                        display_df['Explanation'] = display_df['Statement'].apply(components['risk_engine'].explain_sql)
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
                                summary_text = generate_comprehensive_summary(final_df, final_risk_scores, final_anomaly_data)
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
                                            summary_text = generate_comprehensive_summary(final_df, final_risk_scores, final_anomaly_data)
                                            components['email_handler'].send_outlook_email(
                                                recipient, subject, summary_text, final_df, final_risk_scores
                                            )
                                            st.success("✅ Email sent successfully!")
                                        except Exception as e:
                                            st.error(f"❌ Failed to send email: {str(e)}")
                
                elif st.session_state.current_page == "Admin Configuration":
                    st.header("⚙️ Admin Configuration")
                    
                    # Admin authentication (simple password protection)
                    if 'admin_authenticated' not in st.session_state:
                        st.session_state.admin_authenticated = False
                    
                    if not st.session_state.admin_authenticated:
                        st.warning("🔒 Admin access required")
                        admin_password = st.text_input("Enter admin password:", type="password")
                        if st.button("Authenticate"):
                            if admin_password == "admin123":  # Simple password - change in production
                                st.session_state.admin_authenticated = True
                                st.success("✅ Authentication successful")
                                st.rerun()
                            else:
                                st.error("❌ Invalid password")
                    else:
                        admin_config = components['admin_config']
                        config = admin_config.get_config()
                        
                        # Admin controls
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            st.markdown("**Configure risk scoring parameters and security indicators**")
                        with col2:
                            if st.button("🚪 Logout"):
                                st.session_state.admin_authenticated = False
                                st.rerun()
                        
                        tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
                            "🎯 Risk Weights", "📊 SQL Operations", "⏰ Time Settings", 
                            "🔐 Sensitive Objects", "🏷️ Keywords", "📤 Import/Export"
                        ])
                        
                        with tab1:
                            st.subheader("Risk Component Weights")
                            st.markdown("Adjust how much each factor contributes to the overall risk score:")
                            
                            with st.expander("ℹ️ About Risk Weights"):
                                st.markdown("""
                                **Risk weights determine the relative importance of different factors:**
                                - **SQL Operation (30%):** Type of SQL command executed
                                - **Timing (20%):** When the activity occurred (off-hours, weekends)
                                - **Context (15%):** Context information and change tickets
                                - **Sensitive Objects (25%):** Access to sensitive tables/data
                                - **User Factors (5%):** User account type and behavior
                                - **Program (5%):** Application or tool used
                                
                                **Note:** Total should equal 1.0 (100%)
                                """)
                            
                            risk_weights = config['risk_weights']
                            new_weights = {}
                            
                            col1, col2 = st.columns(2)
                            with col1:
                                new_weights['sql_operation'] = st.slider("SQL Operation Weight", 0.0, 1.0, risk_weights['sql_operation'], 0.05)
                                new_weights['timing'] = st.slider("Timing Weight", 0.0, 1.0, risk_weights['timing'], 0.05)
                                new_weights['context'] = st.slider("Context Weight", 0.0, 1.0, risk_weights['context'], 0.05)
                            
                            with col2:
                                new_weights['sensitive_objects'] = st.slider("Sensitive Objects Weight", 0.0, 1.0, risk_weights['sensitive_objects'], 0.05)
                                new_weights['user_factors'] = st.slider("User Factors Weight", 0.0, 1.0, risk_weights['user_factors'], 0.05)
                                new_weights['program'] = st.slider("Program Weight", 0.0, 1.0, risk_weights['program'], 0.05)
                            
                            total_weight = sum(new_weights.values())
                            if abs(total_weight - 1.0) > 0.01:
                                st.warning(f"⚠️ Total weights: {total_weight:.2f} (should be 1.0)")
                            else:
                                st.success(f"✅ Total weights: {total_weight:.2f}")
                            
                            if st.button("Update Risk Weights"):
                                config['risk_weights'] = new_weights
                                admin_config.config = config
                                if admin_config.save_config():
                                    st.success("✅ Risk weights updated successfully!")
                                    st.cache_resource.clear()  # Clear cache to reload components
                                    st.rerun()
                        
                        with tab2:
                            st.subheader("SQL Operation Risk Scores")
                            st.markdown("Set risk scores for different SQL operations (0-50 points):")
                            
                            with st.expander("ℹ️ About SQL Operation Scores"):
                                st.markdown("""
                                **SQL operation scores represent the inherent risk of each command type:**
                                - **DROP/TRUNCATE (35):** Permanent data destruction
                                - **DELETE (30):** Data removal (potentially recoverable)
                                - **ALTER/GRANT/REVOKE (25):** Schema or permission changes
                                - **SELECT * (20):** Potential data dumps
                                - **UPDATE (20):** Data modification
                                - **INSERT (15):** New data creation
                                - **CREATE (10):** Object creation
                                - **SELECT (5):** Normal data queries
                                """)
                            
                            sql_weights = config['sql_operation_weights']
                            new_sql_weights = {}
                            
                            col1, col2 = st.columns(2)
                            operations = list(sql_weights.keys())
                            mid_point = len(operations) // 2
                            
                            with col1:
                                for op in operations[:mid_point]:
                                    new_sql_weights[op] = st.slider(f"{op} Risk Score", 0, 50, sql_weights[op], key=f"sql_{op}")
                            
                            with col2:
                                for op in operations[mid_point:]:
                                    new_sql_weights[op] = st.slider(f"{op} Risk Score", 0, 50, sql_weights[op], key=f"sql_{op}")
                            
                            if st.button("Update SQL Operation Scores"):
                                config['sql_operation_weights'] = new_sql_weights
                                admin_config.config = config
                                if admin_config.save_config():
                                    st.success("✅ SQL operation scores updated successfully!")
                                    st.cache_resource.clear()
                                    st.rerun()
                        
                        with tab3:
                            st.subheader("Time-Based Risk Settings")
                            
                            with st.expander("ℹ️ About Time Settings"):
                                st.markdown("""
                                **Time-based risk factors help identify suspicious activity patterns:**
                                - **Off-hours:** Activities outside normal business hours
                                - **Weekend multiplier:** Extra risk for weekend activities
                                - **Late night bonus:** Additional risk for very late activities
                                - **Risk bonuses:** Additional points added for time-based factors
                                """)
                            
                            time_settings = config['time_settings']
                            
                            col1, col2 = st.columns(2)
                            with col1:
                                st.markdown("**Off-Hours Definition:**")
                                off_start = st.time_input("Off-hours start", time.fromisoformat(time_settings['off_hours_start']))
                                off_end = st.time_input("Off-hours end", time.fromisoformat(time_settings['off_hours_end']))
                                
                                st.markdown("**Risk Bonuses (points):**")
                                off_hours_bonus = st.slider("Off-hours bonus", 0, 30, time_settings['off_hours_bonus'])
                                weekend_bonus = st.slider("Weekend bonus", 0, 20, time_settings['weekend_bonus'])
                            
                            with col2:
                                st.markdown("**Multipliers:**")
                                weekend_mult = st.slider("Weekend multiplier", 1.0, 3.0, time_settings['weekend_multiplier'], 0.1)
                                
                                st.markdown("**Special Time Periods:**")
                                late_night_bonus = st.slider("Late night bonus (12-5 AM)", 0, 20, time_settings['late_night_bonus'])
                            
                            if st.button("Update Time Settings"):
                                new_time_settings = {
                                    'off_hours_start': off_start.strftime('%H:%M'),
                                    'off_hours_end': off_end.strftime('%H:%M'),
                                    'weekend_multiplier': weekend_mult,
                                    'late_night_bonus': late_night_bonus,
                                    'off_hours_bonus': off_hours_bonus,
                                    'weekend_bonus': weekend_bonus
                                }
                                config['time_settings'] = new_time_settings
                                admin_config.config = config
                                if admin_config.save_config():
                                    st.success("✅ Time settings updated successfully!")
                                    st.cache_resource.clear()
                                    st.rerun()
                        
                        with tab4:
                            st.subheader("Sensitive Objects & Programs")
                            
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.markdown("**Sensitive Tables/Objects:**")
                                
                                with st.expander("ℹ️ About Sensitive Objects"):
                                    st.markdown("""
                                    **Sensitive objects are tables/databases containing critical data:**
                                    - Employee information (Salaries, HR_Records)
                                    - Customer data (CustomerData, SSN, Credit)
                                    - Audit logs (AuditLog)
                                    - Financial data (Payroll)
                                    
                                    **Impact:** +20 risk points when accessing these objects
                                    """)
                                
                                sensitive_tables = config['sensitive_tables']
                                new_sensitive = st.text_area(
                                    "Sensitive tables (one per line):",
                                    value='\n'.join(sensitive_tables),
                                    height=150
                                )
                                
                                if st.button("Update Sensitive Tables"):
                                    new_tables = [table.strip() for table in new_sensitive.split('\n') if table.strip()]
                                    config['sensitive_tables'] = new_tables
                                    admin_config.config = config
                                    if admin_config.save_config():
                                        st.success("✅ Sensitive tables updated!")
                                        st.cache_resource.clear()
                                        st.rerun()
                            
                            with col2:
                                st.markdown("**High-Risk Programs:**")
                                
                                with st.expander("ℹ️ About Program Risk"):
                                    st.markdown("""
                                    **High-risk programs (15 points):**
                                    - Command line tools (sqlcmd, psql, mysql)
                                    - Scripting tools (python, powershell, bash)
                                    
                                    **Medium-risk programs (8 points):**
                                    - Management GUIs (SSMS, Workbench)
                                    - Database tools (Toad, DBeaver)
                                    """)
                                
                                high_risk_programs = config['high_risk_programs']
                                new_high_risk = st.text_area(
                                    "High-risk programs (one per line):",
                                    value='\n'.join(high_risk_programs),
                                    height=75
                                )
                                
                                medium_risk_programs = config['medium_risk_programs']
                                new_medium_risk = st.text_area(
                                    "Medium-risk programs (one per line):",
                                    value='\n'.join(medium_risk_programs),
                                    height=75
                                )
                                
                                if st.button("Update Program Lists"):
                                    config['high_risk_programs'] = [p.strip() for p in new_high_risk.split('\n') if p.strip()]
                                    config['medium_risk_programs'] = [p.strip() for p in new_medium_risk.split('\n') if p.strip()]
                                    admin_config.config = config
                                    if admin_config.save_config():
                                        st.success("✅ Program lists updated!")
                                        st.cache_resource.clear()
                                        st.rerun()
                        
                        with tab5:
                            st.subheader("Context Keywords")
                            
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.markdown("**High-Risk Keywords (+25 points):**")
                                
                                with st.expander("ℹ️ About Context Keywords"):
                                    st.markdown("""
                                    **High-risk keywords indicate potentially dangerous activities:**
                                    - Emergency procedures
                                    - Bypass/override actions
                                    - Unauthorized changes
                                    
                                    **Low-risk keywords indicate normal operations:**
                                    - Scheduled maintenance
                                    - Approved changes
                                    - Routine operations
                                    """)
                                
                                high_risk_keywords = config['high_risk_keywords']
                                new_high_keywords = st.text_area(
                                    "High-risk keywords:",
                                    value='\n'.join(high_risk_keywords),
                                    height=150
                                )
                                
                                if st.button("Update High-Risk Keywords"):
                                    config['high_risk_keywords'] = [k.strip() for k in new_high_keywords.split('\n') if k.strip()]
                                    admin_config.config = config
                                    if admin_config.save_config():
                                        st.success("✅ High-risk keywords updated!")
                                        st.cache_resource.clear()
                                        st.rerun()
                            
                            with col2:
                                st.markdown("**Low-Risk Keywords (0 points):**")
                                
                                low_risk_keywords = config['low_risk_keywords']
                                new_low_keywords = st.text_area(
                                    "Low-risk keywords:",
                                    value='\n'.join(low_risk_keywords),
                                    height=150
                                )
                                
                                if st.button("Update Low-Risk Keywords"):
                                    config['low_risk_keywords'] = [k.strip() for k in new_low_keywords.split('\n') if k.strip()]
                                    admin_config.config = config
                                    if admin_config.save_config():
                                        st.success("✅ Low-risk keywords updated!")
                                        st.cache_resource.clear()
                                        st.rerun()
                        
                        with tab6:
                            st.subheader("Configuration Import/Export")
                            
                            col1, col2, col3 = st.columns(3)
                            
                            with col1:
                                st.markdown("**Export Configuration:**")
                                config_json = admin_config.export_config()
                                st.download_button(
                                    label="📥 Download Config",
                                    data=config_json,
                                    file_name=f"risk_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                    mime="application/json"
                                )
                            
                            with col2:
                                st.markdown("**Import Configuration:**")
                                uploaded_config = st.file_uploader("Upload config file", type="json")
                                
                                if uploaded_config and st.button("Import Config"):
                                    try:
                                        config_content = uploaded_config.read().decode('utf-8')
                                        if admin_config.import_config(config_content):
                                            st.success("✅ Configuration imported successfully!")
                                            st.cache_resource.clear()
                                            st.rerun()
                                        else:
                                            st.error("❌ Invalid configuration file")
                                    except Exception as e:
                                        st.error(f"❌ Import failed: {e}")
                            
                            with col3:
                                st.markdown("**Reset to Defaults:**")
                                if st.button("🔄 Reset All Settings", type="secondary"):
                                    if st.button("⚠️ Confirm Reset", type="primary"):
                                        if admin_config.reset_to_defaults():
                                            st.success("✅ Configuration reset to defaults!")
                                            st.cache_resource.clear()
                                            st.rerun()
                                        else:
                                            st.error("❌ Reset failed")
                            
                            # Current configuration preview
                            st.markdown("**Current Configuration Preview:**")
                            with st.expander("View current settings", expanded=False):
                                st.json(config)
                
                else:
                    # Default to overview if unknown page
                    st.header("📊 Data Overview")
                    summary_text = generate_comprehensive_summary(final_df, final_risk_scores, final_anomaly_data)
                    st.markdown(summary_text)
                
                
            
            else:
                st.warning("No data found for the selected date range and user filter.")
    
    else:
        # Instructions based on current page
        if st.session_state.current_page == "Upload & Overview":
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
        elif st.session_state.current_page == "Admin Configuration":
            st.header("⚙️ Admin Configuration")
            
            # Admin authentication (simple password protection)
            if 'admin_authenticated' not in st.session_state:
                st.session_state.admin_authenticated = False
            
            if not st.session_state.admin_authenticated:
                st.warning("🔒 Admin access required")
                st.info("Admin configuration is available without uploading data.")
                admin_password = st.text_input("Enter admin password:", type="password")
                if st.button("Authenticate"):
                    if admin_password == "admin123":  # Simple password - change in production
                        st.session_state.admin_authenticated = True
                        st.success("✅ Authentication successful")
                        st.rerun()
                    else:
                        st.error("❌ Invalid password")
            else:
                # Show admin panel (same code as above but without data dependency)
                admin_config = components['admin_config']
                config = admin_config.get_config()
                
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.markdown("**Configure risk scoring parameters and security indicators**")
                    st.info("💡 Changes will take effect for future analysis runs.")
                with col2:
                    if st.button("🚪 Logout"):
                        st.session_state.admin_authenticated = False
                        st.rerun()
                
                # Display current risk thresholds
                st.markdown("### 📊 Current Risk Thresholds")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("High Risk", "≥ 70 points", help="Requires immediate attention")
                with col2:
                    st.metric("Medium Risk", "40-69 points", help="Monitor closely")
                with col3:
                    st.metric("Low Risk", "< 40 points", help="Normal operations")
                
                # Quick stats about current configuration
                st.markdown("### ⚙️ Configuration Summary")
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Sensitive Tables", len(config['sensitive_tables']))
                with col2:
                    st.metric("High-Risk Keywords", len(config['high_risk_keywords']))
                with col3:
                    st.metric("SQL Operations", len(config['sql_operation_weights']))
                with col4:
                    risk_weights_total = sum(config['risk_weights'].values())
                    st.metric("Weight Total", f"{risk_weights_total:.2f}")
                
                st.info("📁 Upload data on the 'Upload & Overview' page to see the full admin configuration options.")
        else:
            st.warning("📁 Please upload a CSV file first to access this section.")
            st.info("Use the navigation menu to return to 'Upload & Overview' to upload your data.")

if __name__ == "__main__":
    main()
