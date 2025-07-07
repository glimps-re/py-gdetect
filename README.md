# gdetect - Python Client for GLIMPS Malware Detect API

[![Python Package](https://github.com/glimps-re/py-gdetect/actions/workflows/python-package.yml/badge.svg)](https://github.com/glimps-re/py-gdetect/actions/workflows/python-package.yml)
[![PyPI version](https://badge.fury.io/py/gdetect.svg)](https://badge.fury.io/py/gdetect)
[![Python Versions](https://img.shields.io/pypi/pyversions/gdetect.svg)](https://pypi.org/project/gdetect/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A powerful Python client library and CLI tool for [GLIMPS Detect](https://www.glimps.re), an advanced malware detection and analysis platform.

## 🚀 Quick Start

```bash
# Install from PyPI
pip install gdetect

# Set your credentials
export API_URL=https://my.gdetect.service.tld
export API_TOKEN=your-api-token-here

# Analyze a file
gdetect waitfor /path/to/suspicious/file.exe
```

## 📋 Table of Contents

- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
  - [Command Line Interface](#command-line-interface)
  - [Python Library](#python-library)
- [API Reference](#-api-reference)
- [Error Handling](#-error-handling)
- [Examples](#-examples)
- [Development](#-development)
- [Support](#-support)
- [License](#-license)

## ✨ Features

- **🔍 Comprehensive Malware Analysis** - Submit files for deep malware analysis and get detailed reports
- **⚡ Fast & Efficient** - Optimized for high-performance file scanning with caching support
- **🛠️ Dual Interface** - Use as a CLI tool or integrate directly into your Python applications
- **📊 Multiple Export Formats** - Export results in JSON, CSV, PDF, STIX, MISP, and Markdown formats
- **🔐 Secure** - HTTPS support with optional certificate verification
- **🏷️ File Tagging** - Organize your submissions with custom tags and descriptions
- **🔑 Archive Support** - Submit password-protected archives for analysis

## 📦 Requirements

- Python 3.10 or higher
- Valid GLIMPS Detect API credentials

## 💿 Installation

### From PyPI (Recommended)

```bash
pip install gdetect
```

### From Source

```bash
git clone https://github.com/glimps-re/py-gdetect.git
cd py-gdetect
pip install -e .
```

## ⚙️ Configuration

Configure your API credentials using environment variables:

```bash
export API_URL=https://your-gdetect-instance.com
export API_TOKEN=abcdef01-23456789-abcdef01-23456789-abcdef01
```

Alternatively, pass credentials directly to the CLI or Client:

```bash
gdetect --url https://your-instance.com --token your-token-here send file.exe
```

## 🎯 Usage

### Command Line Interface

The CLI provides a simple way to interact with GLIMPS Detect:

#### Basic Commands

```bash
# Submit a file (returns UUID)
gdetect send malware.exe

# Submit with tags and description
gdetect send suspicious.dll --tag "ransomware" --tag "windows" -d "Found in email attachment"

# Get analysis results
gdetect get 9d488d01-23d5-4b9f-894e-c920ea732603

# Submit and wait for results (blocking)
gdetect waitfor malware.exe --timeout 300

# Search by file hash
gdetect search 7850d6e51ef6d0bc8c8c1903a24c22a090516afa6f3b4db6e4b3e6dd44462a99

# Check your API status
gdetect status

# Export results in different formats
gdetect export 9d488d01-23d5-4b9f-894e-c920ea732603 --format pdf --layout en -o report.pdf
```

#### Advanced Options

```bash
# Submit without using cache
gdetect --no-cache send file.exe

# Submit password-protected archive
gdetect --password "infected123" send archive.zip

# Disable SSL verification (development only!)
gdetect --insecure send file.exe

# Set custom timeout for file upload
gdetect send large_file.bin --timeout 60
```

### Python Library

Integrate GLIMPS Detect into your Python applications:

#### Basic Usage

```python
from gdetect import Client

# Initialize client
client = Client(
    url='https://your-gdetect-instance.com',
    token='your-api-token-here'
)

# Submit a file
uuid = client.push('/path/to/malware.exe')
print(f"Analysis started: {uuid}")

# Get results
result = client.get_by_uuid(uuid)
if result['done']:
    print(f"Verdict: {'Malware' if result['is_malware'] else 'Clean'}")
    print(f"Score: {result['score']}")
```

#### Advanced Examples

```python
# Submit with metadata
uuid = client.push(
    'suspicious.exe',
    bypass_cache=True,
    tags=['phishing', 'trojan'],
    description='Received via spear-phishing email',
    archive_password='infected123'
)

# Wait for analysis completion
result = client.waitfor(
    'malware.bin',
    timeout=300,  # 5 minutes
    pull_time=2   # Check every 2 seconds
)

# Search by SHA256
result = client.get_by_sha256('7850d6e51ef6d0bc8c8c1903a24c22a090516afa6f3b4db6e4b3e6dd44462a99')

# Check API quota status
status = client.get_status()
print(f"Daily quota: {status.available_daily_quota}/{status.daily_quota}")

# Export analysis report
pdf_report = client.export_result(
    uuid='9d488d01-23d5-4b9f-894e-c920ea732603',
    format='pdf',
    layout='en',
    full=True  # Full report with all details
)
with open('analysis_report.pdf', 'wb') as f:
    f.write(pdf_report)
```

## 📚 API Reference

### Client Methods

| Method | Description | Parameters |
|--------|-------------|------------|
| `push()` | Submit a file for analysis | `filename`, `bypass_cache`, `timeout`, `tags`, `description`, `archive_password` |
| `get_by_uuid()` | Retrieve results by UUID | `uuid` |
| `get_by_sha256()` | Search for results by SHA256 | `sha256` |
| `waitfor()` | Submit and wait for results | `filename`, `bypass_cache`, `timeout`, `tags`, `description` |
| `get_status()` | Get API quota and status | None |
| `export_result()` | Export analysis in various formats | `uuid`, `format`, `layout`, `full` |

### Export Formats

- **JSON** - Machine-readable format with complete analysis data
- **CSV** - Spreadsheet-compatible summary
- **PDF** - Professional report for documentation
- **STIX** - Structured Threat Information Expression
- **MISP** - MISP-compatible format for threat intelligence sharing
- **Markdown** - Human-readable text format

## 🚨 Error Handling

The library provides specific exceptions for different error scenarios:

```python
from gdetect import Client, GDetectError, TooManyRequestsError, ResultNotFoundError

client = Client(url, token)

try:
    result = client.push('file.exe')
except TooManyRequestsError:
    print("API quota exceeded. Try again later.")
except ResultNotFoundError:
    print("Analysis not found.")
except GDetectError as e:
    print(f"An error occurred: {e}")
```

Common exceptions:
- `NoAuthenticationTokenError` - Missing API token
- `BadAuthenticationTokenError` - Invalid API token format
- `TooManyRequestsError` - API quota exceeded
- `ResultNotFoundError` - Analysis result not found
- `GDetectTimeoutError` - Analysis timeout exceeded

## 💡 Examples

### Batch File Analysis

```python
import os
from gdetect import Client
from pathlib import Path

client = Client(os.getenv('API_URL'), os.getenv('API_TOKEN'))

# Analyze all files in a directory
suspicious_dir = Path('/path/to/suspicious/files')
results = []

for file_path in suspicious_dir.glob('*'):
    if file_path.is_file():
        try:
            uuid = client.push(str(file_path))
            results.append({
                'file': file_path.name,
                'uuid': uuid,
                'status': 'submitted'
            })
        except Exception as e:
            results.append({
                'file': file_path.name,
                'error': str(e)
            })

# Check results
for item in results:
    if 'uuid' in item:
        result = client.get_by_uuid(item['uuid'])
        print(f"{item['file']}: {'MALWARE' if result.get('is_malware') else 'CLEAN'}")
```

### Integration with SIEM

```python
import json
from gdetect import Client

def analyze_and_log(file_path, siem_logger):
    """Analyze file and send results to SIEM"""
    client = Client(url='https://gdetect.local', token='your-token')
    
    try:
        # Submit and wait for analysis
        result = client.waitfor(file_path, timeout=600)
        
        # Prepare SIEM event
        event = {
            'timestamp': result.get('timestamp'),
            'file_hash': result.get('sha256'),
            'verdict': 'malicious' if result.get('is_malware') else 'clean',
            'score': result.get('score'),
            'file_type': result.get('filetype'),
            'tags': result.get('tags', [])
        }
        
        # Send to SIEM
        siem_logger.send_event('gdetect.analysis', event)
        
    except Exception as e:
        siem_logger.send_event('gdetect.error', {'error': str(e)})
```

## 🛠️ Development

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/glimps-re/py-gdetect.git
cd py-gdetect

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest

# Run linters
ruff check .
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=gdetect

# Run specific test file
pytest tests/test_api.py
```

### Building Documentation

```bash
# Generate API documentation
tox -e docs

# View documentation
open docs/_build/html/index.html
```

## 📞 Support

- 📧 **Email**: contact@glimps.re
- 🐛 **Issues**: [GitHub Issues](https://github.com/glimps-re/py-gdetect/issues)
- 📖 **Documentation**: [API Docs](https://docs.glimps.re)

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure your code:
- Follows PEP 8 style guidelines
- Includes appropriate tests
- Has proper documentation
- Passes all linting checks

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏢 About GLIMPS

GLIMPS is a leading cybersecurity company specializing in advanced malware detection and analysis. Our mission is to provide cutting-edge tools and services to protect organizations from evolving cyber threats.

---

**Copyright © 2022-2025 GLIMPS Inc. All rights reserved.**