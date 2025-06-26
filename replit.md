# SQL Threat Explainer

## Overview

The SQL Threat Explainer is a Streamlit-based web application designed to analyze SQL audit logs and translate complex database activities into plain English narratives. The application helps non-technical compliance teams understand SQL activity patterns, detect insider threats, and identify unauthorized database access. It ingests Trellix-style SQL logs via CSV uploads and provides comprehensive risk analysis, anomaly detection, and narrative timelines.

## System Architecture

### Frontend Architecture
- **Framework**: Streamlit web application
- **Configuration**: Wide layout with expanded sidebar, custom theming via `.streamlit/config.toml`
- **User Interface Components**:
  - CSV file uploader with validation
  - Time range and user filters
  - Narrative timeline view
  - Tabular event viewer
  - Summary overview with risk highlighting
  - Real-time anomaly detection alerts

### Backend Architecture
- **Language**: Python 3.11
- **Core Components**: Modular utility classes for specialized functionality
- **Data Processing**: Pandas-based CSV parsing and analysis
- **Risk Assessment**: Custom scoring algorithms without external API dependencies
- **Report Generation**: PDF reports using ReportLab library

## Key Components

### Risk Engine (`utils/risk_engine.py`)
- **Purpose**: Evaluates SQL statements and assigns risk scores
- **Features**:
  - SQL operation weight mapping (DELETE: 30, DROP: 35, etc.)
  - Time-based risk factors (off-hours multiplier)
  - Context keyword analysis for risk assessment
  - Plain English SQL statement translation
- **Risk Factors**: DML/DDL/DCL operations, SELECT *, sensitive table access, off-hours activity

### Anomaly Detector (`utils/anomaly_detector.py`)
- **Purpose**: Identifies unusual patterns in SQL activity
- **Detection Types**:
  - Off-hours access (6 PM - 8 AM, weekends)
  - Unusual volume patterns
  - Atypical user behavior
  - Volume anomaly descriptions

### Report Generator (`utils/report_generator.py`)
- **Purpose**: Creates comprehensive PDF reports
- **Features**:
  - Custom styling with risk-based color coding
  - Charts and visualizations using ReportLab
  - Summary statistics and trend analysis
  - Professional formatting for compliance documentation

### Email Handler (`utils/email_handler.py`)
- **Purpose**: Automated email notifications for critical events
- **Configuration**: SMTP integration with Office 365
- **Features**:
  - HTML and text email formats
  - Attachment support for reports
  - Risk-based alert summaries

## Data Flow

1. **Data Ingestion**: CSV upload with validation of required columns
2. **Data Processing**: Pandas DataFrame parsing with datetime conversion
3. **Risk Analysis**: Each SQL statement evaluated through RiskEngine
4. **Anomaly Detection**: Pattern analysis across user activities
5. **Narrative Generation**: Plain English explanations of SQL operations
6. **Visualization**: Timeline and summary views in Streamlit interface
7. **Reporting**: PDF generation and optional email alerts

### Required CSV Columns
- `_time`: Timestamp of SQL execution
- `OS_User`, `Exec_User`: User identification
- `DB_Type`, `DB_Name`: Database information
- `Program`, `Module`: Application context
- `Src_Host`, `Src_IP`: Source identification
- `Accessed_Obj`, `Accessed_Obj_Owner`: Database objects
- `Statement`: SQL command
- `MS_Context`: Microsoft context information

## External Dependencies

### Core Libraries
- **Streamlit**: Web application framework
- **Pandas**: Data manipulation and analysis
- **NumPy**: Numerical computing
- **ReportLab**: PDF report generation

### Email Integration
- **SMTP**: Office 365 email server support
- **Environment Variables**: Secure credential management
  - `SMTP_SERVER`, `SMTP_PORT`
  - `SENDER_EMAIL`, `SENDER_PASSWORD`

### Sensitive Data Configuration
- Predefined sensitive table list: `['Salaries', 'Employees', 'HR_Records', 'CustomerData', 'AuditLog', 'Payroll', 'SSN', 'Credit']`

## Deployment Strategy

### Platform Configuration
- **Environment**: Replit with Python 3.11 module
- **Nix Packages**: freetype, glibcLocales for PDF generation
- **Deployment Target**: Autoscale for production workloads
- **Port Configuration**: 5000 (configurable via Streamlit config)

### Workflow Setup
- **Run Button**: Parallel workflow execution
- **Primary Task**: Streamlit application launch
- **Port Monitoring**: Automatic health checking on port 5000

### Security Considerations
- Environment variable-based credential management
- No hardcoded sensitive information
- Input validation for CSV uploads
- Secure SMTP authentication

## Changelog

```
Changelog:
- June 26, 2025. Initial setup
```

## User Preferences

```
Preferred communication style: Simple, everyday language.
```