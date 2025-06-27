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
    page_title="Database Activity Review", 
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
SENSITIVE_TABLES = ['Salaries', 'Employees', 'HR_Records', 'CustomerData', 'AuditLog', 'Payroll', 'SSN', 'Credit', 'Credit_Cards', 'CreditCards', 'Payment', 'Financial']
REQUIRED_COLUMNS = ['_time', 'OS_User', 'Exec_User', 'DB_Type', 'DB_Name', 'Program', 'Module', 'Src_Host', 'Src_IP', 'Accessed_Obj', 'Accessed_Obj_Owner', 'Statement', 'MS_Context']

# Load test dataset
@st.cache_data
def load_test_data():
    """Load the generated test dataset"""
    try:
        df = pd.read_csv('test_sql_audit_5000_rows.csv', encoding='utf-8')
        
        # Parse datetime column
        if '_time' in df.columns:
            df['_time'] = pd.to_datetime(df['_time'], errors='coerce', format='mixed')
            
            invalid_dates = df['_time'].isna().sum()
            if invalid_dates > 0:
                st.warning(f"Found {invalid_dates} rows with invalid datetime formats in test data. Using current time as fallback.")
                df['_time'] = df['_time'].fillna(pd.Timestamp.now())
        
        return df
    except Exception as e:
        st.error(f"Error loading test dataset: {str(e)}")
        return None

def get_risk_color(score):
    if score >= 70:
        return "🔴"
    elif score >= 40:
        return "🟠"
    else:
        return "🟢"

def generate_risk_narrative(row, risk_score, anomalies):
    """Generate plain English narrative for SQL activity"""
    
    explanation = components['risk_engine'].explain_sql(row['Statement'])
    timestamp = row['_time'].strftime('%Y-%m-%d %H:%M:%S')
    user = row['OS_User']
    database = row['DB_Name']
    context = row['MS_Context']
    
    # Risk indicators
    risk_color = get_risk_color(risk_score)
    sensitive = "⚠️ **Sensitive table access**" if pd.notna(row['Accessed_Obj']) and any(s.lower() in str(row['Accessed_Obj']).lower() for s in SENSITIVE_TABLES) else ""
    unauthorized = "🚨 **Unauthorized change**" if pd.notna(context) and "unauthorized" in str(context).lower() else ""
    outlier = "🔍 **Outlier activity**" if anomalies.get('is_outlier', False) else ""
    off_hours = "⏰ **Off-hours access**" if anomalies.get('off_hours', False) else ""
    
    badges = " ".join([badge for badge in [sensitive, unauthorized, outlier, off_hours] if badge])
    
    narrative = f"""
**{risk_color} Risk Score: {risk_score}/100** | **User:** {user} | **Database:** {database} | **Time:** {timestamp}

**What happened:** {explanation}

{badges}

**Technical Details:** `{row['Statement'][:100]}{'...' if len(row['Statement']) > 100 else ''}`
"""
    
    return narrative.strip()

def main():
    # Professional navigation sidebar
    with st.sidebar:
        st.title("🔍 Database Activity Review")
        st.markdown("---")
        
        # Navigation menu
        if 'current_page' not in st.session_state:
            st.session_state.current_page = "Upload & Overview"
        
        nav_options = [
            "📁 Upload & Overview",
            "📊 Executive Dashboard", 
            "📈 Risk Analysis",
            "👤 User Investigation",
            "👥 My Peeps",
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
        
        use_test_data = st.button("🧪 Use Test Dataset", use_container_width=True, 
                                  help="Load a 5000-row sample dataset for testing and demonstration")
        
        # Persist test data usage in session state
        if use_test_data:
            st.session_state.use_test_data = True
        
        uploaded_file = st.file_uploader("Upload SQL Audit CSV", type=['csv'])
        
        # Clear test data when file is uploaded
        if uploaded_file is not None and 'use_test_data' in st.session_state:
            del st.session_state.use_test_data
        
        # Show clear button if test data is loaded
        if st.session_state.get('use_test_data', False):
            if st.button("🗑️ Clear Test Data", use_container_width=True):
                del st.session_state.use_test_data
                if 'risk_calculations' in st.session_state:
                    del st.session_state.risk_calculations
                st.rerun()

    # Main content area
    st.title("🔍 Database Activity Review")
    st.markdown("### Advanced Risk Analysis & Compliance Reporting")

    # Initialize variables
    df = None
    data_source = "Unknown"

    # Data loading logic
    if uploaded_file is not None:
        # Load uploaded data
        with st.spinner("Loading and analyzing uploaded data..."):
            df = pd.read_csv(uploaded_file, encoding='utf-8', on_bad_lines='skip')
            data_source = uploaded_file.name
    elif st.session_state.get('use_test_data', False):
        # Load test data
        df = load_test_data()
        data_source = "Test Dataset (5000 rows)"
        if df is not None:
            st.info(f"📊 Using test dataset: {len(df)} rows of sample SQL audit data")

    if df is not None and not df.empty:
        # Display data source info
        if data_source != "Unknown":
            st.sidebar.success(f"📈 Data Source: {data_source}")
            
        # Sidebar filters
        with st.sidebar:
            st.header("🔧 Filters")
            
            # Date range
            min_date = df['_time'].min().date()
            max_date = df['_time'].max().date()
            start_date = st.date_input("Start Date", min_date, min_value=min_date, max_value=max_date)
            end_date = st.date_input("End Date", max_date, min_value=min_date, max_value=max_date)
            
            # User filter - handle NaN values
            unique_users = df['OS_User'].dropna().unique().tolist()
            users = ["All"] + sorted([str(user) for user in unique_users])
            selected_user = st.selectbox("Filter by User", users)
            
            # Risk threshold filter
            risk_threshold = st.slider("Minimum Risk Score", 0, 100, 0, help="Show only events above this risk score")
            
            # Apply filters
            filtered_df = df[
                (df['_time'].dt.date >= start_date) & 
                (df['_time'].dt.date <= end_date)
            ].copy()
            
            if selected_user != "All":
                filtered_df = filtered_df[filtered_df['OS_User'] == selected_user]

        # Generate cache key for both uploaded files and test data
        if uploaded_file:
            cache_key = str(uploaded_file.file_id if hasattr(uploaded_file, 'file_id') else uploaded_file.name)
        else:
            cache_key = "test_data_5000_rows"
        
        # Calculate risk scores and detect anomalies only once per data source
        if 'risk_calculations' not in st.session_state or st.session_state.get('last_upload_key') != cache_key:
            with st.spinner("Calculating risk scores and detecting anomalies..."):
                all_risk_scores = []
                all_anomaly_data = []
                
                # Add progress bar for large datasets
                progress_bar = st.progress(0)
                total_rows = len(df)
                
                for idx, (_, row) in enumerate(df.iterrows()):
                    risk_score = components['risk_engine'].calculate_risk_score(row, SENSITIVE_TABLES)
                    anomalies = components['anomaly_detector'].detect_anomalies(row, df)
                    
                    all_risk_scores.append(risk_score)
                    all_anomaly_data.append(anomalies)
                    
                    # Update progress every 10 rows or for small datasets
                    if idx % max(1, total_rows // 100) == 0 or idx == total_rows - 1:
                        progress_bar.progress((idx + 1) / total_rows)
                
                progress_bar.empty()  # Remove progress bar when done
                
                # Cache the calculations
                st.session_state.risk_calculations = {
                    'risk_scores': all_risk_scores,
                    'anomaly_data': all_anomaly_data
                }
                st.session_state.last_upload_key = cache_key
        
        # Get cached calculations
        all_risk_scores = st.session_state.risk_calculations['risk_scores']
        all_anomaly_data = st.session_state.risk_calculations['anomaly_data']
        
        # Filter the pre-calculated results based on current filters
        filtered_indices = filtered_df.index.tolist()
        filtered_risk_scores = [all_risk_scores[i] for i in filtered_indices if i < len(all_risk_scores)]
        filtered_anomaly_data = [all_anomaly_data[i] for i in filtered_indices if i < len(all_anomaly_data)]
        
        # Apply risk threshold filter
        risk_mask = [score >= risk_threshold for score in filtered_risk_scores]
        final_df = filtered_df[risk_mask].copy()
        final_risk_scores = [score for score, mask in zip(filtered_risk_scores, risk_mask) if mask]
        final_anomaly_data = [anomaly for anomaly, mask in zip(filtered_anomaly_data, risk_mask) if mask]
        
        if final_df.empty:
            st.warning(f"No events found above risk threshold of {risk_threshold}")
            return
        
        # Navigation-based content rendering
        if st.session_state.current_page == "Upload & Overview":
            # Overview page content
            st.header("📊 Data Overview")
            st.success(f"✅ Successfully analyzed {len(final_df)} events")
            
        elif st.session_state.current_page == "Executive Dashboard":
            st.header("📊 Executive Dashboard")
            components['dashboard'].create_executive_dashboard(final_df, final_risk_scores, final_anomaly_data)
        
        elif st.session_state.current_page == "Risk Analysis":
            st.header("📈 Risk Analysis & Metrics")
            
            # Risk distribution charts
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("#### Risk Score Distribution")
                risk_distribution = {
                    'High (70-100)': sum(1 for score in final_risk_scores if score >= 70),
                    'Medium (40-69)': sum(1 for score in final_risk_scores if 40 <= score < 70),
                    'Low (0-39)': sum(1 for score in final_risk_scores if score < 40)
                }
                st.bar_chart(risk_distribution)
            
            with col2:
                st.subheader("👥 Users by Avg Risk")
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
        
        elif st.session_state.current_page == "My Peeps":
            st.header("👥 My Peeps")
            st.markdown("*User activity overview with risk assessment and behavioral narratives*")
            
            # Get unique users and their risk profiles
            unique_users = final_df['OS_User'].unique()
            user_profiles = {}
            
            for user in unique_users:
                user_data = final_df[final_df['OS_User'] == user]
                user_indices = user_data.index.tolist()
                
                # Get risk scores and anomalies for this user's data
                user_risk_scores = []
                user_anomalies = []
                
                for idx in range(len(final_df)):
                    if final_df.iloc[idx]['OS_User'] == user:
                        if idx < len(final_risk_scores):
                            user_risk_scores.append(final_risk_scores[idx])
                        if idx < len(final_anomaly_data):
                            user_anomalies.append(final_anomaly_data[idx])
                
                if user_risk_scores:
                    avg_risk = sum(user_risk_scores) / len(user_risk_scores)
                    max_risk = max(user_risk_scores)
                    total_activities = len(user_data)
                    
                    # Get most recent activity
                    recent_activity = user_data.iloc[-1]
                    
                    # Generate department based on accessed objects
                    department = "Unknown"
                    if any(obj in str(recent_activity.get('Accessed_Obj', '')).lower() for obj in ['employee', 'hr', 'salary', 'payroll']):
                        department = "HR"
                    elif any(obj in str(recent_activity.get('Accessed_Obj', '')).lower() for obj in ['trading', 'position', 'financial']):
                        department = "Trading"
                    elif any(obj in str(recent_activity.get('Accessed_Obj', '')).lower() for obj in ['customer', 'client', 'account']):
                        department = "Customer Service"
                    elif any(obj in str(recent_activity.get('Accessed_Obj', '')).lower() for obj in ['audit', 'log', 'security']):
                        department = "Security"
                    else:
                        department = "Operations"
                    
                    user_profiles[user] = {
                        'department': department,
                        'avg_risk': avg_risk,
                        'max_risk': max_risk,
                        'total_activities': total_activities,
                        'recent_activity': recent_activity,
                        'risk_scores': user_risk_scores,
                        'anomalies': user_anomalies,
                        'user_data': user_data
                    }
            
            # Display user cards with narratives
            for user, profile in user_profiles.items():
                # Create a container for each user
                with st.container():
                    # User card and narrative in columns
                    col1, col2 = st.columns([1, 2])
                    
                    with col1:
                        # User card using Streamlit components
                        risk_color = get_risk_color(profile['avg_risk'])
                        risk_level = "High Risk" if profile['avg_risk'] >= 70 else "Medium Risk" if profile['avg_risk'] >= 40 else "Low Risk"
                        
                        # Create user card with container
                        with st.container():
                            st.markdown(f"### 👤 {user}")
                            st.caption(f"{profile['department']} Specialist")
                            
                            # Department and recent activity
                            st.markdown(f"**{profile['department']}**")
                            recent_stmt = str(profile['recent_activity']['Statement'])
                            if len(recent_stmt) > 50:
                                recent_stmt = recent_stmt[:50] + "..."
                            st.text(recent_stmt)
                            
                            # Time and risk level
                            col_time, col_risk = st.columns(2)
                            with col_time:
                                time_str = str(profile['recent_activity']['_time'])[:16] if hasattr(profile['recent_activity']['_time'], 'strftime') else str(profile['recent_activity']['_time'])[:16]
                                st.caption(time_str)
                            with col_risk:
                                if risk_level == "High Risk":
                                    st.error(risk_level)
                                elif risk_level == "Medium Risk":
                                    st.warning(risk_level) 
                                else:
                                    st.success(risk_level)
                    
                    with col2:
                        # Narrative section using Streamlit components
                        st.markdown("### Activity Narrative")
                        
                        # Generate narrative for this user's activities
                        high_risk_activities = [i for i, score in enumerate(profile['risk_scores']) if score >= 70]
                        medium_risk_activities = [i for i, score in enumerate(profile['risk_scores']) if 40 <= score < 70]
                        
                        # High risk alert
                        if high_risk_activities:
                            st.error(f"⚠️ **{user}** has {len(high_risk_activities)} high-risk activities requiring immediate attention.")
                        
                        # Medium risk info
                        if medium_risk_activities:
                            st.warning(f"📊 {len(medium_risk_activities)} medium-risk activities detected for monitoring.")
                        
                        # Most concerning activity
                        if profile['risk_scores']:
                            max_risk_idx = profile['risk_scores'].index(profile['max_risk'])
                            risky_activity = profile['user_data'].iloc[max_risk_idx]
                            
                            st.markdown(f"**🔍 Most concerning activity:**")
                            activity_text = str(risky_activity['Statement'])
                            if len(activity_text) > 100:
                                activity_text = activity_text[:100] + "..."
                            st.code(activity_text)
                            
                            if profile['max_risk'] >= 70:
                                st.error("This activity represents a significant security concern and warrants immediate investigation.")
                            elif profile['max_risk'] >= 40:
                                st.warning("This activity shows unusual patterns that should be monitored closely.")
                        
                        # Behavioral insights
                        total_activities = profile['total_activities']
                        if total_activities > 50:
                            st.info(f"📈 **High activity user** with {total_activities} database operations recorded.")
                        elif total_activities < 5:
                            st.info(f"📉 **Low activity user** with only {total_activities} database operations.")
                        
                        # Department context
                        dept_context = {
                            "HR": "accesses employee and payroll data",
                            "Trading": "works with financial positions and trading data", 
                            "Customer Service": "handles customer account information",
                            "Security": "monitors audit logs and system security",
                            "Operations": "performs general database operations"
                        }
                        
                        if profile['department'] in dept_context:
                            st.markdown(f"👤 **Role context:** This user typically {dept_context[profile['department']]}.")
                        
                        # Statistics
                        st.divider()
                        col_avg, col_max, col_activities = st.columns(3)
                        with col_avg:
                            st.metric("Avg Risk", f"{profile['avg_risk']:.1f}")
                        with col_max:
                            st.metric("Max Risk", f"{profile['max_risk']:.1f}")
                        with col_activities:
                            st.metric("Activities", total_activities)
                    
                    # Add spacing between users
                    st.markdown("---")
        
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
            st.markdown("### 📅 Activity Timeline")
            
            for i, (_, row) in enumerate(final_df.head(20).iterrows()):
                if i < len(final_risk_scores):
                    risk_score = final_risk_scores[i]
                    anomalies = final_anomaly_data[i] if i < len(final_anomaly_data) else {}
                    narrative = generate_risk_narrative(row, risk_score, anomalies)
                    st.markdown(narrative)
                    st.divider()
        
        elif st.session_state.current_page == "Reports & Export":
            st.header("📤 Reports & Export")
            
            # Export options
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("📄 Generate PDF Report"):
                    try:
                        summary_text = f"Risk analysis completed for {len(final_df)} events"
                        report_buffer = components['report_generator'].generate_pdf_report(
                            final_df, final_risk_scores, final_anomaly_data, summary_text
                        )
                        
                        st.download_button(
                            "Download PDF Report",
                            data=report_buffer,
                            file_name=f"sql_threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                            mime="application/pdf"
                        )
                        st.success("✅ PDF report generated successfully!")
                    except Exception as e:
                        st.error(f"Error generating PDF: {str(e)}")
            
            with col2:
                if st.button("📊 Export Data as CSV"):
                    # Add risk scores to dataframe for export
                    export_df = final_df.copy()
                    export_df['Risk_Score'] = final_risk_scores
                    csv_data = export_df.to_csv(index=False)
                    
                    st.download_button(
                        "Download CSV",
                        data=csv_data,
                        file_name=f"sql_audit_analyzed_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
        
        elif st.session_state.current_page == "Admin Configuration":
            st.header("⚙️ Admin Configuration")
            st.info("Admin configuration features are available for system administrators")
    
    else:
        # No data loaded
        st.info("👆 Upload a CSV file or use the test dataset to begin analysis")

if __name__ == "__main__":
    main()