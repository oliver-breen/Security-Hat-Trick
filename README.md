# Security Hat Trick

A comprehensive security testing framework that includes:
1. **Security Auditor** - Automated vulnerability scanner based on current market security conditions (OWASP Top 10)
2. **Vulnerable Application** - Intentionally vulnerable web app for testing security tools
3. **Test Suite** - Comprehensive tests to verify the auditor's detection capabilities

## Features

### Security Auditor
The auditor scans for common web application vulnerabilities including:
- **SQL Injection** - Detects unsafe database queries
- **Cross-Site Scripting (XSS)** - Identifies unencoded user input
- **Command Injection** - Finds unsafe system command execution
- **Path Traversal** - Detects unauthorized file access

### Vulnerable Application
An intentionally vulnerable Flask web application with:
- SQL Injection in search functionality
- XSS vulnerabilities in user greeting
- Command Injection in ping functionality
- Path Traversal in file reading

**⚠️ WARNING**: The vulnerable app is for testing purposes only. NEVER deploy it in production!

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup

1. Clone the repository:
```bash
git clone https://github.com/oliver-breen/Security-Hat-Trick.git
cd Security-Hat-Trick
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

Or install in development mode:
```bash
pip install -e .
```

## Usage

### Quick Start Demo

Run the complete demo (starts vulnerable app, runs scanner, displays report):
```bash
python demo.py
```

This will automatically:
1. Start the vulnerable application
2. Run a security audit
3. Display the results
4. Clean up and stop the application

### Running the Vulnerable Application

Start the vulnerable web application:
```bash
python -m vulnerable_app.app
```

The app will be available at `http://localhost:5000`

### Running the Security Auditor

Scan a target application:
```bash
python -m auditor.scanner http://localhost:5000
```

This will:
1. Run all security scans
2. Display results in the terminal
3. Save a JSON report with timestamp

### Running Tests

Run all tests:
```bash
pytest
```

Run tests with coverage:
```bash
pytest --cov=auditor --cov=vulnerable_app --cov-report=html
```

Run specific test files:
```bash
pytest tests/test_auditor.py
pytest tests/test_integration.py
```

## Project Structure

```
Security-Hat-Trick/
├── auditor/                  # Security auditor module
│   ├── __init__.py
│   └── scanner.py           # Main scanner implementation
├── vulnerable_app/          # Intentionally vulnerable application
│   ├── __init__.py
│   └── app.py              # Flask application with vulnerabilities
├── tests/                   # Test suite
│   ├── __init__.py
│   ├── test_auditor.py     # Unit tests for auditor
│   └── test_integration.py # Integration tests
├── requirements.txt         # Python dependencies
├── setup.py                # Package setup
└── README.md               # This file
```

## Example Output

When running the security auditor against the vulnerable app:

```
Starting security audit of http://localhost:5000
Scanning for SQL Injection vulnerabilities...
Scanning for XSS vulnerabilities...
Scanning for Command Injection vulnerabilities...
Scanning for Path Traversal vulnerabilities...

================================================================================
SECURITY AUDIT REPORT
================================================================================
Target: http://localhost:5000
Scan Time: 2026-02-12T08:30:00.000000
Total Vulnerabilities Found: 4

Severity Summary:
  Critical: 2
  High: 2
  Medium: 0
  Low: 0

--------------------------------------------------------------------------------
VULNERABILITIES DETECTED
--------------------------------------------------------------------------------

1. SQL Injection [Critical]
   URL: http://localhost:5000/search?q=' OR '1'='1
   Payload: ' OR '1'='1
   Evidence: SQL error pattern detected: sql syntax
   Description: Application appears vulnerable to SQL injection attacks
   Recommendation: Use parameterized queries or prepared statements

2. Cross-Site Scripting (XSS) [High]
   URL: http://localhost:5000/greet?name=<script>alert("XSS")</script>
   Payload: <script>alert("XSS")</script>
   Evidence: Unencoded user input reflected in response
   Description: Application reflects user input without proper encoding
   Recommendation: Implement proper output encoding and Content Security Policy

...
```

## Security Considerations

This project is designed for **educational and testing purposes only**. The vulnerable application intentionally contains security flaws and should:

- ❌ NEVER be deployed to production
- ❌ NEVER be exposed to the public internet
- ❌ NEVER contain real user data
- ✅ Only be used in isolated, controlled environments
- ✅ Only be used for security training and testing

## Testing Philosophy

The test suite ensures:
1. **Unit Tests** - Verify individual scanner components work correctly
2. **Integration Tests** - Confirm the auditor detects vulnerabilities in the vulnerable app
3. **Report Validation** - Ensure reports are generated correctly and contain required information

## Contributing

Contributions are welcome! Please ensure:
- All tests pass
- New features include tests
- Code follows existing style conventions
- Security vulnerabilities in the vulnerable app are clearly documented

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- OWASP Top 10 for vulnerability categories
- Flask framework for the web application
- pytest for testing framework