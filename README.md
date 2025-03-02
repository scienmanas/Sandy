# Project Title: AI-Powered Security and Threat Analyzer

## Overview
This project is an AI-powered security and threat analyzer designed to help users identify potential security risks in their systems. It provides functionalities for phishing checks, malware analysis, and system activity monitoring.

## Features
- **Phishing Checker**: Analyze URLs, emails, or messages to determine if they are phishing attempts.
- **Malware Checker**: Scan files for potential malware and analyze suspicious activities.
- **System Checker**: Perform basic security checks on the user's system, including CPU and memory usage analysis.

## Installation
1. Clone the repository:
```bash
git clone https://github.com/yourusername/yourproject.git
```

   ```
3. Install the required packages:
```bash
pip install -r requirements.txt
```

4. Set up environment variables by creating a `.env` file in the root directory and adding your API keys:
```
GEMINI_API_KEY=your_api_key
G_SAFE_BROWSING_API_KEY=your_api_key
VIRUSTOTAL_API_KEY=your_api_key
```

## Usage

Start the script using the command 

```python
python main.py
```
