# Clickjacking Vulnerability Tester

A Flask web application that tests websites for clickjacking vulnerabilities by analyzing their security headers.

## Overview

This tool checks for clickjacking vulnerabilities by examining two critical security headers:
- X-Frame-Options
- Content-Security-Policy (specifically the frame-ancestors directive)
- Call for Iframe

The application provides detailed feedback about potential vulnerabilities and the current security configuration of the tested website.

## Features

- URL validation and parsing
- X-Frame-Options header analysis
- Content-Security-Policy frame-ancestors directive checking
- Detailed vulnerability reporting
- User-friendly web interface
- Timeout handling for requests
- Comprehensive error reporting

## Prerequisites

- Python 3.x
- Flask
- Requests library

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/clickjacking-tester.git
cd clickjacking-tester
```

2. Create and activate a virtual environment (recommended):
```bash
python -m venv venv
# Linux
source venv/bin/activate

# Windows:
venv\Scripts\activate
```

3. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Open your web browser and navigate to `http://localhost:5000`

3. Enter the URL you want to test in the form and submit

4. Review the results, which will include:
   - Overall vulnerability status
   - Detailed reasons for the assessment
   - Header values found during testing

## Security Headers Checked

### X-Frame-Options
- DENY: Prevents any framing (Most secure)
- SAMEORIGIN: Allows framing only from the same origin
- Not set: Potentially vulnerable

### Content-Security-Policy
Checks for the frame-ancestors directive, which provides more granular control over framing permissions.

## Disclaimer

This tool is provided as-is without any warranties. Users are responsible for ensuring they have proper authorization before testing any websites. The authors are not responsible for any misuse or damage caused by this tool.
