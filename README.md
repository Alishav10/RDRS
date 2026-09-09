# RDRS — Ransomware Detection and Response System

## Overview

**RDRS (Ransomware Detection and Response System)** is a defensive cybersecurity application developed to detect and analyze ransomware-like activity through file-system and process monitoring.

The system collects file and process events, analyzes suspicious behavioral patterns, calculates a threat score, generates security alerts and incidents, preserves relevant evidence, and provides monitoring and reporting through a REST API and web dashboard.

RDRS is designed for **controlled defensive cybersecurity testing and academic/internship use**. It does not contain or execute real ransomware.

---

## Features

- Real-time file-system monitoring
    
- File creation, modification, deletion, and rename detection
    
- Process monitoring
    
- Shannon entropy analysis
    
- Behavioral analysis using a sliding time window
    
- Weighted threat scoring from 0–100
    
- Threat-level classification
    
- Security alert generation
    
- Incident creation and management
    
- Evidence preservation
    
- SQLite database for persistent storage
    
- FastAPI REST API
    
- Web-based security dashboard
    
- HTML, JSON, and CSV report generation
    
- Automated test suite
    
- Docker and Docker Compose support
    
- Controlled ransomware-like activity simulation for testing
    

---

## Technology Stack

|Category|Technology|
|---|---|
|Language|Python|
|Backend|FastAPI|
|Database|SQLite|
|ORM|SQLAlchemy|
|File Monitoring|Watchdog|
|Process Monitoring|psutil|
|Configuration|PyYAML|
|Validation|Pydantic|
|Logging|Loguru|
|Templates|Jinja2|
|Frontend|HTML, Bootstrap, JavaScript|
|Visualization|Chart.js|
|Reporting|ReportLab|
|Testing|Pytest|
|Containerization|Docker, Docker Compose|

---

## Project Structure

```text
RDRS/
├── app/
│   ├── api/              # REST API
│   ├── core/             # Core configuration and utilities
│   ├── detectors/        # File and process monitoring
│   ├── database/         # Database configuration and models
│   ├── response/         # Incident, evidence and reporting
│   └── dashboard/        # Web dashboard
│
├── tests/                # Automated tests
│
├── data/
│   ├── sandbox/          # Controlled testing directory
│   ├── quarantine/       # Evidence storage
│   └── reports/          # Generated reports
│
├── logs/                 # Application logs
│
├── config.yaml           # Application configuration
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

# Setup Instructions

## Prerequisites

Install the following before running the project:

- Python 3.11 or later
    
- Git
    
- Docker Desktop
    
- Docker Compose
    

---

## 1. Clone the Repository

```bash
git clone https://github.com/Alishav10/RDRS.git
cd RDRS
```

---

## 2. Create a Virtual Environment

### Windows

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Running the Application

## Option 1: Docker Compose

Build and start the application:

```bash
docker compose up --build
```

Verify the running containers:

```bash
docker compose ps
```

The application will be available at:

```text
http://localhost:8000
```

### Dashboard

```text
http://localhost:8000/dashboard
```

### API Documentation

FastAPI interactive documentation:

```text
http://localhost:8000/docs
```

### Health Check

```text
http://localhost:8000/health
```

---

## Option 2: Run Locally

After installing the dependencies and activating the virtual environment:

```bash
uvicorn app.main:app --reload
```

The application will be available at:

```text
http://localhost:8000
```

---

# Configuration

Application settings are maintained in:

```text
config.yaml
```

The configuration file controls parameters such as:

- Monitored directories
    
- Detection thresholds
    
- Detection window
    
- Threat-scoring parameters
    
- Database configuration
    
- Evidence and report directories
    
- Logging configuration
    
- Response settings
    

---

# Detection Workflow

RDRS uses a behavior-based detection pipeline:

```text
File / Process Activity
        ↓
Event Monitoring
        ↓
Event Collection
        ↓
Behavioral Analysis
        ↓
Entropy & Process Analysis
        ↓
Threat Score Calculation
        ↓
Alert Classification
        ↓
Incident Creation
        ↓
Evidence Preservation
        ↓
Report Generation
```

The system correlates multiple indicators rather than treating a single event as proof of ransomware activity.

Examples of monitored indicators include:

- Rapid file modification
    
- Multiple file renames
    
- High file entropy
    
- High-frequency file-system activity
    
- Process activity associated with monitored events
    

---

# Testing

Run the automated test suite using:

```bash
pytest -q
```

The tests cover core functionality including:

- File-system event processing
    
- Entropy calculation
    
- Threat scoring
    
- Database operations
    
- Alert generation
    
- Incident management
    
- Evidence handling
    
- Report generation
    
- API functionality
    
- Integration workflows
    

---

# Safe Demonstration

The project can be tested using a controlled ransomware-like activity simulation.

The simulation operates only inside the project's designated sandbox and generates harmless file-system activity for validating the detection pipeline.

No real ransomware or malicious payload is executed.

The demonstration follows:

```text
Create Test Files
       ↓
Modify Files
       ↓
Generate High-Entropy Content
       ↓
Rename Files
       ↓
RDRS Detects Events
       ↓
Behavioral Analysis
       ↓
Threat Score
       ↓
Alert
       ↓
Incident
       ↓
Evidence / Report
```

---

# Output

Depending on the detected activity, RDRS can generate:

- File-system events
    
- Process snapshots
    
- Threat scores
    
- Security alerts
    
- Security incidents
    
- Evidence records
    
- HTML reports
    
- JSON reports
    
- CSV reports
    
- Application logs
    

---

# Security Notice

RDRS is a **defensive cybersecurity project** intended for authorized testing and controlled environments.

The application does not contain or execute real ransomware. Demonstrations should be performed using the provided sandbox and simulation mechanisms.

Users should only perform testing on systems and data for which they have appropriate authorization.

---

