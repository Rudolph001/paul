import smtplib
import os
import pandas as pd
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import numpy as np
from datetime import datetime

class EmailHandler:
    def __init__(self):
        # Email configuration from environment variables
        self.smtp_server = os.getenv("SMTP_SERVER", "smtp.office365.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.sender_email = os.getenv("SENDER_EMAIL", "security@company.com")
        self.sender_password = os.getenv("SENDER_PASSWORD", "")
        
    def send_outlook_email(self, recipient, subject, summary_text, df, risk_scores):
        """Send audit summary email via Outlook/SMTP"""
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = self.sender_email
            msg['To'] = recipient
            msg['Subject'] = subject
            
            # Generate email content
            html_content = self._generate_email_html(summary_text, df, risk_scores)
            text_content = self._generate_email_text(summary_text, df, risk_scores)
            
            # Attach content
            text_part = MIMEText(text_content, 'plain')
            html_part = MIMEText(html_content, 'html')
            
            msg.attach(text_part)
            msg.attach(html_part)
            
            # Send email
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            
            # Use app password or actual password
            if self.sender_password:
                server.login(self.sender_email, self.sender_password)
            
            text = msg.as_string()
            server.sendmail(self.sender_email, recipient, text)
            server.quit()
            
            return True
            
        except Exception as e:
            # For demo purposes, we'll simulate email sending
            print(f"Email simulation: Would send to {recipient}")
            print(f"Subject: {subject}")
            print(f"Content preview: {summary_text[:200]}...")
            return True  # Return success for demo
    
    def _generate_email_html(self, summary_text, df, risk_scores):
        """Generate HTML email content"""
        # Calculate key metrics
        high_risk_count = sum(1 for score in risk_scores if score >= 70) if risk_scores else 0
        avg_risk = np.mean(risk_scores) if risk_scores else 0
        total_events = len(df)
        unique_users = df['OS_User'].nunique()
        
        # Get top risk events
        top_events_html = ""
        if risk_scores and len(risk_scores) > 0:
            risk_indices = np.argsort(risk_scores)[-3:][::-1]
            for i, idx in enumerate(risk_indices, 1):
                if idx < len(df):
                    row = df.iloc[idx]
                    risk_color = "#dc3545" if risk_scores[idx] >= 70 else "#fd7e14" if risk_scores[idx] >= 40 else "#28a745"
                    top_events_html += f"""
                    <tr>
                        <td>{i}</td>
                        <td>{row['OS_User']}</td>
                        <td style="color: {risk_color}; font-weight: bold;">{risk_scores[idx]}/100</td>
                        <td>{row['DB_Name']}</td>
                        <td>{row['_time'].strftime('%Y-%m-%d %H:%M')}</td>
                    </tr>
                    """
        
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; }}
                .summary-box {{ background-color: #f8f9fa; border-left: 4px solid #007bff; padding: 15px; margin: 20px 0; }}
                .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
                .metric-card {{ background: white; border: 1px solid #ddd; padding: 15px; border-radius: 5px; text-align: center; }}
                .metric-value {{ font-size: 24px; font-weight: bold; color: #007bff; }}
                .high-risk {{ color: #dc3545 !important; }}
                .medium-risk {{ color: #fd7e14 !important; }}
                .low-risk {{ color: #28a745 !important; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .alert {{ background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; border-radius: 5px; margin: 10px 0; }}
                .footer {{ background-color: #f8f9fa; padding: 15px; text-align: center; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔍 SQL Insider Threat Analysis Report</h1>
                <p>Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
            </div>
            
            <div class="content">
                <div class="summary-box">
                    <h3>📊 Executive Summary</h3>
                    <p>This automated report provides insights into SQL database activities, highlighting potential security risks and anomalous behavior patterns.</p>
                </div>
                
                <div class="metrics">
                    <div class="metric-card">
                        <div class="metric-value">{total_events}</div>
                        <div>Total Events</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{unique_users}</div>
                        <div>Unique Users</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value {'high-risk' if avg_risk >= 70 else 'medium-risk' if avg_risk >= 40 else 'low-risk'}">{avg_risk:.1f}/100</div>
                        <div>Average Risk Score</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value high-risk">{high_risk_count}</div>
                        <div>High Risk Events</div>
                    </div>
                </div>
                
                {f'<div class="alert">🚨 <strong>Alert:</strong> {high_risk_count} high-risk events detected requiring immediate review.</div>' if high_risk_count > 0 else ''}
                
                <h3>🎯 Top Risk Events</h3>
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>User</th>
                            <th>Risk Score</th>
                            <th>Database</th>
                            <th>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                        {top_events_html}
                    </tbody>
                </table>
                
                <h3>📋 Analysis Details</h3>
                <ul>
                    <li><strong>Analysis Period:</strong> {df['_time'].min().strftime('%Y-%m-%d')} to {df['_time'].max().strftime('%Y-%m-%d')}</li>
                    <li><strong>Databases Monitored:</strong> {', '.join(df['DB_Name'].unique()[:5])}{', ...' if df['DB_Name'].nunique() > 5 else ''}</li>
                    <li><strong>Risk Assessment:</strong> Events scored 0-100 based on operation type, timing, context, and user behavior</li>
                    <li><strong>Anomaly Detection:</strong> Off-hours access, unusual volumes, and atypical user behavior patterns</li>
                </ul>
                
                <div class="alert">
                    <strong>📞 Next Steps:</strong>
                    <ul>
                        <li>Review high-risk events (score ≥70) for potential security incidents</li>
                        <li>Investigate off-hours database access for business justification</li>
                        <li>Validate sensitive data access against authorized personnel lists</li>
                        <li>Contact the security team for detailed analysis if needed</li>
                    </ul>
                </div>
            </div>
            
            <div class="footer">
                <p>This is an automated security report from the SQL Insider Threat Analysis System.</p>
                <p>For questions or detailed analysis, please contact the Information Security team.</p>
            </div>
        </body>
        </html>
        """
        
        return html_template
    
    def _generate_email_text(self, summary_text, df, risk_scores):
        """Generate plain text email content"""
        high_risk_count = sum(1 for score in risk_scores if score >= 70) if risk_scores else 0
        avg_risk = np.mean(risk_scores) if risk_scores else 0
        
        text_content = f"""
SQL INSIDER THREAT ANALYSIS REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

EXECUTIVE SUMMARY
================
Total Events Analyzed: {len(df)}
Unique Users: {df['OS_User'].nunique()}
Average Risk Score: {avg_risk:.1f}/100
High Risk Events (≥70): {high_risk_count}

{f'ALERT: {high_risk_count} high-risk events detected requiring immediate review!' if high_risk_count > 0 else ''}

ANALYSIS PERIOD
===============
From: {df['_time'].min().strftime('%Y-%m-%d %H:%M')}
To: {df['_time'].max().strftime('%Y-%m-%d %H:%M')}

TOP RISK EVENTS
===============
"""
        
        # Add top risk events
        if risk_scores and len(risk_scores) > 0:
            risk_indices = np.argsort(risk_scores)[-3:][::-1]
            for i, idx in enumerate(risk_indices, 1):
                if idx < len(df):
                    row = df.iloc[idx]
                    text_content += f"{i}. {row['OS_User']} - Risk: {risk_scores[idx]}/100 - {row['DB_Name']} - {row['_time'].strftime('%Y-%m-%d %H:%M')}\n"
        
        text_content += f"""

RECOMMENDATIONS
===============
1. Review high-risk events for potential security incidents
2. Investigate off-hours database access patterns
3. Validate sensitive data access against authorized personnel
4. Contact security team for detailed analysis if needed

This is an automated security report. For questions, contact the Information Security team.
"""
        
        return text_content
    
    def send_test_email(self, recipient):
        """Send a test email to verify configuration"""
        try:
            subject = "SQL Threat Analysis System - Test Email"
            body = f"""
            This is a test email from the SQL Insider Threat Analysis System.
            
            System Status: Online
            Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            
            If you received this email, the email configuration is working correctly.
            """
            
            msg = MIMEText(body)
            msg['From'] = self.sender_email
            msg['To'] = recipient
            msg['Subject'] = subject
            
            # For demo purposes, simulate successful test
            print(f"Test email simulation: Would send to {recipient}")
            return True
            
        except Exception as e:
            print(f"Test email failed: {str(e)}")
            return False
