import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import plotly.figure_factory as ff

class Dashboard:
    def __init__(self, risk_engine, anomaly_detector):
        self.risk_engine = risk_engine
        self.anomaly_detector = anomaly_detector
        
    def create_user_storyline(self, df, user, risk_scores, anomaly_data):
        """Create a professional storyline for a specific user"""
        user_df = df[df['OS_User'] == user].copy()
        user_indices = df[df['OS_User'] == user].index
        user_risk_scores = [risk_scores[i] for i in range(len(df)) if df.iloc[i]['OS_User'] == user]
        user_anomalies = [anomaly_data[i] for i in range(len(df)) if df.iloc[i]['OS_User'] == user]
        
        if user_df.empty:
            return None
            
        # Sort by time
        user_df = user_df.sort_values('_time')
        
        st.subheader(f"📖 User Story: {user}")
        
        # User summary metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Activities", len(user_df))
        with col2:
            avg_risk = np.mean(user_risk_scores) if user_risk_scores else 0
            st.metric("Average Risk", f"{avg_risk:.1f}")
        with col3:
            high_risk_count = sum(1 for score in user_risk_scores if score >= 70)
            st.metric("High Risk Events", high_risk_count)
        with col4:
            unique_dbs = user_df['DB_Name'].nunique()
            st.metric("Databases Accessed", unique_dbs)
        
        # Professional animated timeline
        self._create_professional_timeline(user_df, user_risk_scores, user_anomalies, user)
        
        # Activity storyline
        st.markdown("### 📚 Activity Timeline")
        
        # Group activities by time periods for better storytelling
        time_periods = self._group_by_time_periods(user_df, user_risk_scores, user_anomalies)
        
        for period, activities in time_periods.items():
            with st.expander(f"📅 {period}", expanded=len(activities) <= 3):
                for activity in activities:
                    self._render_activity_story(activity)
        
        return user_df
    
    def create_database_storyline(self, df, database, risk_scores, anomaly_data):
        """Create a professional storyline for a specific database"""
        db_df = df[df['DB_Name'] == database].copy()
        db_indices = df[df['DB_Name'] == database].index
        db_risk_scores = [risk_scores[i] for i in range(len(df)) if df.iloc[i]['DB_Name'] == database]
        db_anomalies = [anomaly_data[i] for i in range(len(df)) if df.iloc[i]['DB_Name'] == database]
        
        if db_df.empty:
            return None
            
        st.subheader(f"🗄️ Database Story: {database}")
        
        # Database summary metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Activities", len(db_df))
        with col2:
            unique_users = db_df['OS_User'].nunique()
            st.metric("Unique Users", unique_users)
        with col3:
            avg_risk = np.mean(db_risk_scores) if db_risk_scores else 0
            st.metric("Average Risk", f"{avg_risk:.1f}")
        with col4:
            sensitive_access = sum(1 for _, row in db_df.iterrows() 
                                 if any(table.lower() in row['Accessed_Obj'].lower() 
                                       for table in ['salaries', 'employees', 'hr_records', 'customerdata', 'auditlog']))
            st.metric("Sensitive Access", sensitive_access)
        
        # User activity heatmap
        st.markdown("#### User Activity Heatmap")
        with st.expander("ℹ️ About this heatmap"):
            st.markdown("""
            **What it shows:** Activity intensity for each user across different hours of the day
            
            **How to read:**
            - **Darker red:** Higher activity volume at that time
            - **Light/white:** Little to no activity
            - **Rows:** Individual users
            - **Columns:** Hours of the day (0-23)
            
            **Security indicators:**
            - **Unusual patterns:** Users active at odd hours consistently
            - **Concentrated activity:** Heavy usage in short time windows
            - **Off-hours access:** Activity during nights/weekends may need investigation
            
            **Why it matters:** Helps identify behavioral anomalies and potential insider threat patterns.
            """)
        
        user_activity = db_df.groupby(['OS_User', db_df['_time'].dt.hour]).size().reset_index()
        user_activity.columns = ['User', 'Hour', 'Activities']
        
        if not user_activity.empty:
            pivot_table = user_activity.pivot(index='User', columns='Hour', values='Activities').fillna(0)
            
            fig = px.imshow(
                pivot_table,
                labels=dict(x="Hour of Day", y="User", color="Activities"),
                title=f"User Activity Heatmap - {database}",
                color_continuous_scale="Reds"
            )
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
        
        # Top suspicious activities
        st.markdown("### ⚠️ Notable Activities")
        
        # Sort by risk score and show top events
        db_df_with_risk = db_df.copy()
        db_df_with_risk['risk_score'] = db_risk_scores
        db_df_with_risk['anomalies'] = db_anomalies
        
        top_events = db_df_with_risk.nlargest(5, 'risk_score')
        
        for _, event in top_events.iterrows():
            risk_color = "🔴" if event['risk_score'] >= 70 else "🟠" if event['risk_score'] >= 40 else "🟢"
            
            with st.container():
                st.markdown(f"""
                **{risk_color} Risk {event['risk_score']:.0f}/100** - {event['OS_User']} accessed {event['Accessed_Obj']} 
                at {event['_time'].strftime('%Y-%m-%d %H:%M')}
                
                *{self.risk_engine.explain_sql(event['Statement'])}*
                
                **Context:** {event['MS_Context']}
                """)
                
                anomaly_flags = []
                if event['anomalies'].get('off_hours'):
                    anomaly_flags.append("⏰ Off-hours access")
                if event['anomalies'].get('unusual_volume'):
                    anomaly_flags.append("📊 Unusual volume")
                if event['anomalies'].get('atypical_behavior'):
                    anomaly_flags.append("🔍 Atypical behavior")
                
                if anomaly_flags:
                    st.warning(" | ".join(anomaly_flags))
                
                st.divider()
        
        return db_df
    
    def create_executive_dashboard(self, df, risk_scores, anomaly_data):
        """Create executive-level dashboard with key insights"""
        st.header("📊 Executive Security Dashboard")
        
        # Key metrics row
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            total_events = len(df)
            st.metric("Total Events", f"{total_events:,}")
        
        with col2:
            high_risk_count = sum(1 for score in risk_scores if score >= 70)
            risk_percentage = (high_risk_count / total_events * 100) if total_events > 0 else 0
            st.metric("High Risk Events", high_risk_count, f"{risk_percentage:.1f}%")
        
        with col3:
            unique_users = df['OS_User'].nunique()
            st.metric("Active Users", unique_users)
        
        with col4:
            unique_dbs = df['DB_Name'].nunique()
            st.metric("Databases", unique_dbs)
        
        with col5:
            off_hours_count = sum(1 for anomaly in anomaly_data if anomaly.get('off_hours', False))
            st.metric("Off-Hours Access", off_hours_count)
        
        # Risk distribution chart
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Risk Distribution")
            with st.expander("ℹ️ About this chart"):
                st.markdown("""
                **What it shows:** Distribution of events across risk levels
                
                **How risk is calculated:**
                - **High (70-100):** Sensitive data access, unauthorized changes, or suspicious patterns
                - **Medium (40-69):** Potentially risky operations or off-hours activity
                - **Low (0-39):** Normal database operations with standard permissions
                
                **Why it matters:** Helps identify the overall security posture and proportion of concerning activities.
                """)
            
            risk_levels = {
                'Low (0-39)': sum(1 for score in risk_scores if score < 40),
                'Medium (40-69)': sum(1 for score in risk_scores if 40 <= score < 70),
                'High (70-100)': sum(1 for score in risk_scores if score >= 70)
            }
            
            fig = px.pie(
                values=list(risk_levels.values()),
                names=list(risk_levels.keys()),
                title="Risk Distribution",
                color_discrete_map={
                    'Low (0-39)': '#2ecc71',
                    'Medium (40-69)': '#f39c12',
                    'High (70-100)': '#e74c3c'
                }
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("#### Activity by Hour of Day")
            with st.expander("ℹ️ About this chart"):
                st.markdown("""
                **What it shows:** Number of database activities throughout a 24-hour period
                
                **How to interpret:**
                - **Normal business hours (8AM-6PM):** Expected high activity
                - **Off-hours activity:** May indicate legitimate overtime work or suspicious behavior
                - **Night activity (10PM-6AM):** Often flagged for additional scrutiny
                
                **Why it matters:** Unusual timing patterns can indicate insider threats, unauthorized access, or compromised accounts.
                """)
            
            # Activity by hour
            df['hour'] = df['_time'].dt.hour
            hourly_activity = df.groupby('hour').size().reset_index()
            hourly_activity.columns = ['Hour', 'Activities']
            
            fig = px.bar(
                hourly_activity,
                x='Hour',
                y='Activities',
                title="Activity by Hour of Day",
                color='Activities',
                color_continuous_scale="Blues"
            )
            fig.update_layout(showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        
        # Top risk users and databases
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 👤 Top Risk Users")
            user_risks = df.copy()
            user_risks['risk_score'] = risk_scores
            user_avg_risk = user_risks.groupby('OS_User')['risk_score'].agg(['mean', 'count']).reset_index()
            user_avg_risk.columns = ['User', 'Avg_Risk', 'Event_Count']
            user_avg_risk = user_avg_risk.sort_values('Avg_Risk', ascending=False).head(10)
            
            for _, user in user_avg_risk.iterrows():
                risk_color = "🔴" if user['Avg_Risk'] >= 70 else "🟠" if user['Avg_Risk'] >= 40 else "🟢"
                st.write(f"{risk_color} **{user['User']}** - {user['Avg_Risk']:.1f} avg risk ({user['Event_Count']} events)")
        
        with col2:
            st.markdown("### 🗄️ Database Risk Profile")
            db_risks = df.copy()
            db_risks['risk_score'] = risk_scores
            db_avg_risk = db_risks.groupby('DB_Name')['risk_score'].agg(['mean', 'count']).reset_index()
            db_avg_risk.columns = ['Database', 'Avg_Risk', 'Event_Count']
            db_avg_risk = db_avg_risk.sort_values('Avg_Risk', ascending=False).head(10)
            
            for _, db in db_avg_risk.iterrows():
                risk_color = "🔴" if db['Avg_Risk'] >= 70 else "🟠" if db['Avg_Risk'] >= 40 else "🟢"
                st.write(f"{risk_color} **{db['Database']}** - {db['Avg_Risk']:.1f} avg risk ({db['Event_Count']} events)")
        
        # Recent high-risk timeline
        st.markdown("### 🚨 Recent High-Risk Activities")
        
        df_with_risk = df.copy()
        df_with_risk['risk_score'] = risk_scores
        df_with_risk['anomalies'] = anomaly_data
        
        high_risk_events = df_with_risk[df_with_risk['risk_score'] >= 70].sort_values('_time', ascending=False).head(10)
        
        if not high_risk_events.empty:
            st.markdown("#### High-Risk Events Timeline")
            with st.expander("ℹ️ About this timeline"):
                st.markdown("""
                **What it shows:** Chronological view of high-risk database activities (≥70 risk score)
                
                **How to interpret:**
                - **X-axis:** Time progression
                - **Y-axis:** Users involved
                - **Bubble size:** Risk score magnitude (larger = higher risk)
                - **Color intensity:** Risk level (darker red = more dangerous)
                
                **Key patterns to watch:**
                - **Clustering:** Multiple high-risk events in short timeframes
                - **User patterns:** Same user repeatedly appearing
                - **Time correlation:** Events happening at suspicious times
                
                **Why it matters:** Reveals attack timelines and helps correlate related security incidents.
                """)
            
            # Create timeline visualization
            fig = px.scatter(
                high_risk_events,
                x='_time',
                y='OS_User',
                size='risk_score',
                color='risk_score',
                hover_data=['DB_Name', 'Accessed_Obj'],
                title="High-Risk Events Timeline",
                color_continuous_scale="Reds",
                size_max=20
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.success("No high-risk events detected in the current dataset.")
    
    def _group_by_time_periods(self, df, risk_scores, anomalies):
        """Group activities by logical time periods for storytelling"""
        periods = {}
        
        for i, (_, row) in enumerate(df.iterrows()):
            time_str = row['_time'].strftime('%Y-%m-%d')
            hour = row['_time'].hour
            
            # Determine time period
            if 6 <= hour < 12:
                period_key = f"{time_str} Morning (6 AM - 12 PM)"
            elif 12 <= hour < 18:
                period_key = f"{time_str} Afternoon (12 PM - 6 PM)"
            elif 18 <= hour < 24:
                period_key = f"{time_str} Evening (6 PM - 12 AM)"
            else:
                period_key = f"{time_str} Night (12 AM - 6 AM)"
            
            if period_key not in periods:
                periods[period_key] = []
            
            activity = {
                'row': row,
                'risk_score': risk_scores[i] if i < len(risk_scores) else 0,
                'anomalies': anomalies[i] if i < len(anomalies) else {}
            }
            periods[period_key].append(activity)
        
        return periods
    
    def _render_activity_story(self, activity):
        """Render a single activity as part of the storyline"""
        row = activity['row']
        risk_score = activity['risk_score']
        anomalies = activity['anomalies']
        
        # Risk color indicator
        risk_color = "🔴" if risk_score >= 70 else "🟠" if risk_score >= 40 else "🟢"
        
        # Build the narrative
        time_str = row['_time'].strftime('%H:%M')
        action = self.risk_engine.explain_sql(row['Statement'])
        
        narrative = f"**{time_str}** - {risk_color} Risk {risk_score:.0f}/100"
        narrative += f"\n\n{row['OS_User']} {action} on `{row['Accessed_Obj']}` in {row['DB_Name']} database using {row['Program']}."
        
        # Add context if available
        if pd.notna(row['MS_Context']) and row['MS_Context']:
            narrative += f"\n\n*Context: {row['MS_Context']}*"
        
        # Add anomaly indicators
        anomaly_flags = []
        if anomalies.get('off_hours'):
            anomaly_flags.append("⏰ Off-hours")
        if anomalies.get('unusual_volume'):
            anomaly_flags.append("📊 High volume")
        if anomalies.get('atypical_behavior'):
            anomaly_flags.append("🔍 Unusual pattern")
        
        if anomaly_flags:
            narrative += f"\n\n**Alerts:** {' | '.join(anomaly_flags)}"
        
        # Display with appropriate styling
        if risk_score >= 70:
            st.error(narrative)
        elif risk_score >= 40:
            st.warning(narrative)
        else:
            st.info(narrative)
    
    def _create_professional_timeline(self, user_df, risk_scores, anomalies, user):
        """Create a professional animated timeline like the design shown"""
        st.markdown("### 📈 Security Activity Timeline")
        
        with st.expander("ℹ️ About this timeline"):
            st.markdown("""
            **What it shows:** Visual progression of a user's most significant security events
            
            **How to read:**
            - **Connected line:** Shows chronological progression of activities
            - **Circle colors:** Risk levels (Red=High, Orange=Medium, Green=Low)
            - **Icons:** Activity types and anomaly indicators
                - ⚠️ High-risk activities
                - ⚡ Medium-risk activities  
                - ✓ Normal activities
                - 🌙 Off-hours access
                - 📊 Unusual data volume
                - 🔍 Atypical behavior patterns
            
            **Selection method:** Shows up to 6 highest-risk events for focus
            
            **Why it matters:** Provides a clear narrative of user behavior patterns and security progression.
            """)
        
        if len(user_df) == 0:
            st.info("No activities found for this user.")
            return
        
        # Sort by time and get key events
        sorted_df = user_df.sort_values('_time').reset_index(drop=True)
        
        # Create timeline HTML/CSS
        timeline_html = f"""
        <style>
        .timeline-container {{
            position: relative;
            margin: 40px 0;
            padding: 20px 0;
        }}
        
        .timeline-line {{
            position: absolute;
            top: 60px;
            left: 0;
            right: 0;
            height: 8px;
            background: linear-gradient(90deg, #f39c12 0%, #e74c3c 25%, #3498db 50%, #9b59b6 75%, #f39c12 100%);
            border-radius: 4px;
            z-index: 1;
        }}
        
        .timeline-events {{
            display: flex;
            justify-content: space-between;
            position: relative;
            z-index: 2;
            margin-top: 20px;
        }}
        
        .timeline-event {{
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            flex: 1;
            margin: 0 10px;
        }}
        
        .event-icon {{
            width: 60px;
            height: 60px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            color: white;
            margin-bottom: 10px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            position: relative;
            z-index: 3;
        }}
        
        .event-high-risk {{
            background: linear-gradient(135deg, #e74c3c, #c0392b);
        }}
        
        .event-medium-risk {{
            background: linear-gradient(135deg, #f39c12, #e67e22);
        }}
        
        .event-low-risk {{
            background: linear-gradient(135deg, #2ecc71, #27ae60);
        }}
        
        .event-time {{
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 5px;
            font-size: 14px;
        }}
        
        .event-description {{
            font-size: 12px;
            color: #7f8c8d;
            max-width: 150px;
            line-height: 1.4;
        }}
        
        .event-risk {{
            font-size: 11px;
            font-weight: bold;
            margin-top: 5px;
            padding: 2px 8px;
            border-radius: 10px;
            color: white;
        }}
        
        .risk-high {{ background: #e74c3c; }}
        .risk-medium {{ background: #f39c12; }}
        .risk-low {{ background: #2ecc71; }}
        
        .timeline-title {{
            text-align: center;
            margin-bottom: 30px;
            color: #2c3e50;
            font-size: 18px;
            font-weight: bold;
        }}
        </style>
        
        <div class="timeline-container">
            <div class="timeline-title">Security Events Timeline for {user}</div>
            <div class="timeline-line"></div>
            <div class="timeline-events">
        """
        
        # Select key events to display (max 6 for good visualization)
        if len(sorted_df) > 6:
            # Get highest risk events
            df_with_risk = sorted_df.copy()
            df_with_risk['risk_score'] = risk_scores[:len(sorted_df)]
            key_events = df_with_risk.nlargest(6, 'risk_score')
            key_events = key_events.sort_values('_time')
        else:
            key_events = sorted_df
        
        # Generate timeline events
        for idx, (_, event) in enumerate(key_events.iterrows()):
            risk_score = risk_scores[idx] if idx < len(risk_scores) else 0
            anomaly = anomalies[idx] if idx < len(anomalies) else {}
            
            # Determine risk level and icon
            if risk_score >= 70:
                risk_class = "event-high-risk"
                risk_label = "risk-high"
                icon = "⚠️"
            elif risk_score >= 40:
                risk_class = "event-medium-risk" 
                risk_label = "risk-medium"
                icon = "⚡"
            else:
                risk_class = "event-low-risk"
                risk_label = "risk-low"
                icon = "✓"
            
            # Add anomaly indicators
            if anomaly.get('off_hours'):
                icon = "🌙"
            elif anomaly.get('unusual_volume'):
                icon = "📊"
            elif anomaly.get('atypical_behavior'):
                icon = "🔍"
            
            time_str = event['_time'].strftime('%H:%M')
            date_str = event['_time'].strftime('%m/%d')
            action = self.risk_engine.explain_sql(event['Statement'])
            
            timeline_html += f"""
                <div class="timeline-event">
                    <div class="event-icon {risk_class}">
                        {icon}
                    </div>
                    <div class="event-time">{time_str}</div>
                    <div class="event-time">{date_str}</div>
                    <div class="event-description">
                        {action[:50]}...
                    </div>
                    <div class="event-description">
                        <strong>{event['DB_Name']}</strong><br/>
                        {event['Accessed_Obj'][:20]}...
                    </div>
                    <div class="event-risk {risk_label}">
                        Risk: {risk_score:.0f}
                    </div>
                </div>
            """
        
        timeline_html += """
            </div>
        </div>
        """
        
        # Display the timeline
        st.components.v1.html(timeline_html, height=300)
        
        # Add summary stats below timeline
        col1, col2, col3 = st.columns(3)
        with col1:
            avg_risk = np.mean(risk_scores) if risk_scores else 0
            st.metric("Average Risk Score", f"{avg_risk:.1f}/100")
        with col2:
            peak_risk = max(risk_scores) if risk_scores else 0
            st.metric("Peak Risk Event", f"{peak_risk:.0f}/100")
        with col3:
            time_span = (user_df['_time'].max() - user_df['_time'].min()).total_seconds() / 3600
            st.metric("Activity Timespan", f"{time_span:.1f} hours")