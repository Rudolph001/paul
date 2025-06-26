import pandas as pd
import numpy as np
from datetime import datetime
import io
import base64
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.lib.colors import HexColor

class ReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.custom_styles = self._create_custom_styles()
    
    def _create_custom_styles(self):
        """Create custom paragraph styles for the report"""
        styles = {}
        
        # Title style
        styles['CustomTitle'] = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=20,
            textColor=colors.darkblue,
            alignment=1  # Center alignment
        )
        
        # Heading style
        styles['CustomHeading'] = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkred,
            borderWidth=1,
            borderColor=colors.black,
            borderPadding=5
        )
        
        # Risk styles
        styles['HighRisk'] = ParagraphStyle(
            'HighRisk',
            parent=self.styles['Normal'],
            textColor=colors.red,
            fontSize=10,
            leftIndent=20
        )
        
        styles['MediumRisk'] = ParagraphStyle(
            'MediumRisk',
            parent=self.styles['Normal'],
            textColor=colors.orange,
            fontSize=10,
            leftIndent=20
        )
        
        styles['LowRisk'] = ParagraphStyle(
            'LowRisk',
            parent=self.styles['Normal'],
            textColor=colors.green,
            fontSize=10,
            leftIndent=20
        )
        
        return styles
    
    def generate_pdf_report(self, df, risk_scores, anomaly_data, summary_text):
        """Generate a comprehensive PDF report"""
        buffer = io.BytesIO()
        
        try:
            # Create document
            doc = SimpleDocTemplate(buffer, pagesize=A4, 
                                  rightMargin=72, leftMargin=72,
                                  topMargin=72, bottomMargin=18)
            
            # Build content
            story = []
            
            # Title page
            story.extend(self._create_title_page())
            story.append(PageBreak())
            
            # Executive summary
            story.extend(self._create_executive_summary(df, risk_scores, anomaly_data, summary_text))
            story.append(PageBreak())
            
            # Risk analysis charts
            story.extend(self._create_risk_analysis_section(risk_scores))
            story.append(PageBreak())
            
            # Detailed findings
            story.extend(self._create_detailed_findings(df, risk_scores, anomaly_data))
            story.append(PageBreak())
            
            # Recommendations
            story.extend(self._create_recommendations(df, risk_scores, anomaly_data))
            
            # Build PDF
            doc.build(story)
            buffer.seek(0)
            
            return buffer.getvalue()
            
        except Exception as e:
            # Return simple text-based report if PDF generation fails
            return self._generate_fallback_report(df, risk_scores, summary_text).encode('utf-8')
    
    def _create_title_page(self):
        """Create the title page content"""
        content = []
        
        # Title
        title = Paragraph("SQL Insider Threat Analysis Report", self.custom_styles['CustomTitle'])
        content.append(title)
        content.append(Spacer(1, 0.5*inch))
        
        # Subtitle
        subtitle = Paragraph(f"Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}", 
                           self.styles['Normal'])
        content.append(subtitle)
        content.append(Spacer(1, 1*inch))
        
        # Report overview
        overview = """
        <b>Report Overview:</b><br/>
        This report provides a comprehensive analysis of SQL database activities, 
        focusing on insider threat detection, risk assessment, and security compliance. 
        The analysis includes risk scoring, anomaly detection, and detailed findings 
        to support security teams and compliance officers in identifying potential 
        security incidents and unauthorized database access.
        """
        
        content.append(Paragraph(overview, self.styles['Normal']))
        content.append(Spacer(1, 1*inch))
        
        # Report scope
        scope = """
        <b>Analysis Scope:</b><br/>
        • SQL activity monitoring and analysis<br/>
        • Risk-based scoring (0-100 scale)<br/>
        • Anomaly and outlier detection<br/>
        • Sensitive data access tracking<br/>
        • Off-hours and unauthorized activity detection<br/>
        • User behavior analysis<br/>
        """
        
        content.append(Paragraph(scope, self.styles['Normal']))
        
        return content
    
    def _create_executive_summary(self, df, risk_scores, anomaly_data, summary_text):
        """Create executive summary section"""
        content = []
        
        # Section header
        header = Paragraph("Executive Summary", self.custom_styles['CustomHeading'])
        content.append(header)
        content.append(Spacer(1, 0.2*inch))
        
        # Convert markdown summary to PDF-friendly format
        summary_lines = summary_text.split('\n')
        for line in summary_lines:
            if line.strip():
                # Remove markdown formatting and convert to paragraph
                clean_line = line.replace('**', '').replace('##', '').replace('###', '')
                if clean_line.startswith('- '):
                    clean_line = '• ' + clean_line[2:]
                content.append(Paragraph(clean_line, self.styles['Normal']))
                content.append(Spacer(1, 6))
        
        content.append(Spacer(1, 0.3*inch))
        
        # Key metrics table
        if risk_scores:
            metrics_data = [
                ['Metric', 'Value'],
                ['Total Events Analyzed', str(len(df))],
                ['Average Risk Score', f"{np.mean(risk_scores):.1f}/100"],
                ['High Risk Events (≥70)', str(sum(1 for score in risk_scores if score >= 70))],
                ['Medium Risk Events (40-69)', str(sum(1 for score in risk_scores if 40 <= score < 70))],
                ['Low Risk Events (<40)', str(sum(1 for score in risk_scores if score < 40))],
                ['Unique Users', str(df['OS_User'].nunique())],
                ['Unique Databases', str(df['DB_Name'].nunique())],
            ]
            
            metrics_table = Table(metrics_data, colWidths=[3*inch, 2*inch])
            metrics_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            content.append(metrics_table)
        
        return content
    
    def _create_risk_analysis_section(self, risk_scores):
        """Create risk analysis charts section"""
        content = []
        
        # Section header
        header = Paragraph("Risk Analysis", self.custom_styles['CustomHeading'])
        content.append(header)
        content.append(Spacer(1, 0.2*inch))
        
        if risk_scores:
            # Risk distribution
            high_risk = sum(1 for score in risk_scores if score >= 70)
            medium_risk = sum(1 for score in risk_scores if 40 <= score < 70)
            low_risk = sum(1 for score in risk_scores if score < 40)
            
            # Risk distribution table
            risk_data = [
                ['Risk Level', 'Count', 'Percentage'],
                ['High (70-100)', str(high_risk), f"{(high_risk/len(risk_scores)*100):.1f}%"],
                ['Medium (40-69)', str(medium_risk), f"{(medium_risk/len(risk_scores)*100):.1f}%"],
                ['Low (0-39)', str(low_risk), f"{(low_risk/len(risk_scores)*100):.1f}%"],
            ]
            
            risk_table = Table(risk_data, colWidths=[2*inch, 1*inch, 1.5*inch])
            risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (0, 1), colors.lightcoral),  # High risk row
                ('BACKGROUND', (0, 2), (0, 2), colors.orange),      # Medium risk row
                ('BACKGROUND', (0, 3), (0, 3), colors.lightgreen), # Low risk row
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            content.append(risk_table)
            content.append(Spacer(1, 0.3*inch))
            
            # Risk statistics
            stats_text = f"""
            <b>Risk Score Statistics:</b><br/>
            • Minimum Risk Score: {min(risk_scores)}<br/>
            • Maximum Risk Score: {max(risk_scores)}<br/>
            • Average Risk Score: {np.mean(risk_scores):.1f}<br/>
            • Median Risk Score: {np.median(risk_scores):.1f}<br/>
            • Standard Deviation: {np.std(risk_scores):.1f}<br/>
            """
            
            content.append(Paragraph(stats_text, self.styles['Normal']))
        
        return content
    
    def _create_detailed_findings(self, df, risk_scores, anomaly_data):
        """Create detailed findings section"""
        content = []
        
        # Section header
        header = Paragraph("Detailed Findings", self.custom_styles['CustomHeading'])
        content.append(header)
        content.append(Spacer(1, 0.2*inch))
        
        # High-risk events
        if risk_scores:
            # Get top 10 highest risk events
            risk_indices = np.argsort(risk_scores)[-10:][::-1]
            
            findings_data = [['User', 'Time', 'Database', 'Object', 'Risk Score', 'Activity']]
            
            for idx in risk_indices:
                if idx < len(df):
                    row = df.iloc[idx]
                    findings_data.append([
                        row['OS_User'],
                        row['_time'].strftime('%Y-%m-%d %H:%M'),
                        row['DB_Name'],
                        row['Accessed_Obj'][:20] + '...' if len(str(row['Accessed_Obj'])) > 20 else str(row['Accessed_Obj']),
                        str(risk_scores[idx]),
                        row['Statement'][:30] + '...' if len(row['Statement']) > 30 else row['Statement']
                    ])
            
            findings_table = Table(findings_data, colWidths=[1*inch, 1.2*inch, 1*inch, 1*inch, 0.8*inch, 1.5*inch])
            findings_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            
            content.append(Paragraph("Top High-Risk Events:", self.styles['Heading2']))
            content.append(findings_table)
            content.append(Spacer(1, 0.3*inch))
        
        # Anomaly summary
        if anomaly_data:
            anomaly_counts = {
                'Off-Hours Access': sum(1 for a in anomaly_data if a.get('off_hours', False)),
                'Unusual Volume': sum(1 for a in anomaly_data if a.get('unusual_volume', False)),
                'Atypical Behavior': sum(1 for a in anomaly_data if a.get('atypical_behavior', False)),
            }
            
            anomaly_text = "<b>Anomaly Detection Summary:</b><br/>"
            for anomaly_type, count in anomaly_counts.items():
                if count > 0:
                    anomaly_text += f"• {anomaly_type}: {count} instances<br/>"
            
            content.append(Paragraph(anomaly_text, self.styles['Normal']))
        
        return content
    
    def _create_recommendations(self, df, risk_scores, anomaly_data):
        """Create recommendations section"""
        content = []
        
        # Section header
        header = Paragraph("Security Recommendations", self.custom_styles['CustomHeading'])
        content.append(header)
        content.append(Spacer(1, 0.2*inch))
        
        recommendations = []
        
        # Risk-based recommendations
        if risk_scores:
            high_risk_count = sum(1 for score in risk_scores if score >= 70)
            avg_risk = np.mean(risk_scores)
            
            if high_risk_count > 0:
                recommendations.append(f"Immediate investigation required for {high_risk_count} high-risk events (≥70 risk score)")
            
            if avg_risk > 50:
                recommendations.append("Overall risk level is elevated - consider implementing additional monitoring controls")
        
        # Off-hours recommendations
        if anomaly_data:
            off_hours_count = sum(1 for a in anomaly_data if a.get('off_hours', False))
            if off_hours_count > 0:
                recommendations.append(f"Review {off_hours_count} off-hours database access events for business justification")
        
        # Sensitive data recommendations
        sensitive_tables = ['Salaries', 'Employees', 'HR_Records', 'CustomerData', 'AuditLog']
        sensitive_access = df['Accessed_Obj'].apply(
            lambda x: any(s.lower() in str(x).lower() for s in sensitive_tables)
        ).sum()
        
        if sensitive_access > 0:
            recommendations.append(f"Enhanced monitoring recommended for {sensitive_access} sensitive data access events")
        
        # Generic recommendations
        recommendations.extend([
            "Implement database activity monitoring (DAM) for real-time threat detection",
            "Establish baseline user behavior profiles for improved anomaly detection",
            "Regular review of database access privileges and permissions",
            "Implement data loss prevention (DLP) controls for sensitive tables",
            "Consider implementing database encryption for sensitive data",
            "Establish incident response procedures for high-risk database activities"
        ])
        
        # Add recommendations to content
        for i, rec in enumerate(recommendations, 1):
            content.append(Paragraph(f"{i}. {rec}", self.styles['Normal']))
            content.append(Spacer(1, 6))
        
        content.append(Spacer(1, 0.3*inch))
        
        # Footer
        footer_text = f"""
        <b>Report Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
        <b>Analysis Period:</b> {df['_time'].min().strftime('%Y-%m-%d')} to {df['_time'].max().strftime('%Y-%m-%d')}<br/>
        <b>Total Events Analyzed:</b> {len(df)}<br/>
        <b>Report Version:</b> 1.0
        """
        
        content.append(Paragraph(footer_text, self.styles['Normal']))
        
        return content
    
    def _generate_fallback_report(self, df, risk_scores, summary_text):
        """Generate a simple text-based report if PDF generation fails"""
        report = f"""
SQL INSIDER THREAT ANALYSIS REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

EXECUTIVE SUMMARY
{summary_text}

RISK STATISTICS
Total Events: {len(df)}
Average Risk Score: {np.mean(risk_scores):.1f}/100
High Risk Events (≥70): {sum(1 for score in risk_scores if score >= 70)}
Medium Risk Events (40-69): {sum(1 for score in risk_scores if 40 <= score < 70)}
Low Risk Events (<40): {sum(1 for score in risk_scores if score < 40)}

TOP RISK EVENTS
"""
        
        # Add top 5 risk events
        if risk_scores:
            risk_indices = np.argsort(risk_scores)[-5:][::-1]
            for i, idx in enumerate(risk_indices, 1):
                if idx < len(df):
                    row = df.iloc[idx]
                    report += f"{i}. User: {row['OS_User']}, Risk: {risk_scores[idx]}/100, DB: {row['DB_Name']}, Time: {row['_time']}\n"
        
        report += "\n--- End of Report ---"
        return report
