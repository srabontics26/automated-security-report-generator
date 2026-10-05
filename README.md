# Automated Security Report Generator

A Python-based cybersecurity tool that analyzes authentication logs, identifies suspicious login activity, assigns a simple risk level, and generates an automated security report.

## Project Overview

Security logs can contain a large amount of information. Manually reviewing every event can take time.

This project automates part of that process by reading security events, counting failed and successful login attempts, tracking source IP activity, and generating a readable security report.

## Key Features

- Reads authentication security logs
- Counts successful and failed login attempts
- Tracks activity by source IP
- Identifies repeated failed login activity
- Assigns a basic risk level
- Generates a text-based security report
- Saves the generated report automatically

## Technologies

- Python 3
- File handling
- Collections
- Datetime
- Basic data analysis

## Project Structure

```text
automated-security-report-generator/
├── security_report.py
├── security_events.log
├── security_report.txt
├── README.md
└── .gitignore
