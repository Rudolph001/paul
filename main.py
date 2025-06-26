import pandas as pd
import streamlit as st
from datetime import datetime, time
import numpy as np
import io
from utils.risk_engine import RiskEngine
from utils.report_generator import ReportGenerator
from utils.email_handler import EmailHandler
from utils.anomaly_detector import AnomalyDetector

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
        'anomaly_detector': AnomalyDetector()
    }

components = get_components()

# Sensitive objects and configuration
SENSITIVE_TABLES = ['Salaries', 'Employees', 'HR_Records', 'CustomerData', 'AuditLog', 'Payroll', 'SSN', 'Credit']
REQUIRED_COLUMNS = ['_time', 'OS_User', 'Exec_User', 'DB_Type', 'DB_Name', 'Program', 'Module', 'Src_Host', 'Src_IP', 'Accessed_Obj', 'Accessed_Obj_Owner', 'Statement', 'MS_Context']

# Load and validate CSV
@st.cache_data
def load_csv(upload):
    try:
        df = pd.read_csv(upload)
        
        # Validate required columns
        missing_cols = [col for col in REQUIRED_COLUMNS if col not in df.columns]
        if missing_cols:
            st.error(f"Missing required columns: {', '.join(missing_cols)}")
            return None
            
        # Parse datetime
        df['_time'] = pd.to_datetime(df['_time'], errors='coerce')
        if df['_time'].isna().any():
            st.error("Invalid datetime format in _time column. Expected format: YYYY-MM-DD HH:MM:SS")
            return None
            
        return df
    except Exception as e:
        st.error(f"Error loading CSV: {str(e)}")
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
                
                # Display summary
                st.header("📖 Executive Summary")
                summary_text = generate_comprehensive_summary(final_df, final_risk_scores, final_anomaly_data)
                st.markdown(summary_text)
                
                # Risk distribution chart
                col1, col2 = st.columns(2)
                with col1:
                    risk_distribution = {
                        'High (70-100)': sum(1 for score in final_risk_scores if score >= 70),
                        'Medium (40-69)': sum(1 for score in final_risk_scores if 40 <= score < 70),
                        'Low (0-39)': sum(1 for score in final_risk_scores if score < 40)
                    }
                    st.bar_chart(risk_distribution)
                
                with col2:
                    # Top users by average risk
                    user_risks = final_df.copy()
                    user_risks['Risk_Score'] = final_risk_scores
                    user_avg_risk = user_risks.groupby('OS_User')['Risk_Score'].mean().sort_values(ascending=False)
                    st.subheader("👥 Users by Avg Risk")
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
