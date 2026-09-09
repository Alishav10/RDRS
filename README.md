# RDRS — Ransomware Detection and Response System

## Project Overview

RDRS is a defensive cybersecurity application designed to detect ransomware-like file activity and generate security alerts and incidents.

The system monitors file-system and process activity, analyzes suspicious behavior, calculates a threat score, classifies alerts, preserves evidence, and generates incident reports.

> RDRS is designed for defensive cybersecurity and safe academic testing. It does not contain or execute real ransomware.

## Features

- File-system monitoring
- Process monitoring
- File modification and rename detection
- File entropy analysis
- Behavioral detection using a sliding time window
- Threat scoring from 0–100
- Threat levels: NORMAL, WARNING, CRITICAL
- Alert classification
- Incident creation
- Evidence preservation
- Simulation-mode response
- SQLite database
- FastAPI REST API
- SOC-style dashboard
- HTML, JSON, and CSV reports
- Automated tests
- Docker and Docker Compose deployment

## Technology Stack

- Python 3.11
- FastAPI
- SQLAlchemy
- SQLite
- Watchdog
- psutil
- Pydantic
- PyYAML
- Loguru
- Jinja2
- ReportLab
- Bootstrap
- Chart.js
- Docker
- Docker Compose
- Pytest

## Project Structure

```text
rdrs/
├── app/
│   ├── api/
│   ├── core/
│   ├── detectors/
│   ├── database/
│   ├── response/
│   └── dashboard/
├── tests/
├── data/
│   ├── sandbox/
│   ├── quarantine/
│   └── reports/
├── logs/
├── config.yaml
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── requirements.txt
└── README.md