<p align="center">
  <span>
    <img src="logo/logo.webp" alt="Corscan Logo" width="180" style="border-radius: 50%; border: 4px solid #d9e2ec; box-shadow: 0 10px 24px rgba(16,42,67,0.18);">
  </span>
</p>

<h1 align="center">
  Corscan v1.0.2
  <br>
  <sub><i>Advanced CORS Vulnerability Detection, Analysis, and Reporting Tool</i></sub>
</h1>

<p align="center">
  <a href="https://github.com/angixblack/">GitHub</a>
  •
  <a href="https://buymeacoffee.com/AngixBlack">Buy Me a Coffee</a>
  •
  <a href="#installation">Installation</a>
  •
  <a href="#usage">Usage</a>
</p>

---

## About

Corscan is a focused security tool for detecting CORS misconfigurations, validating exploitability, and exporting professional reports.

It supports single target scans, large URL batch scans, configurable retries, bypass checks, method testing, security header analysis, and multi-format output (text, JSON, CSV, HTML).

## Disclaimer

This tool is for legal security testing and education only.

You are responsible for having explicit permission to test any target.

---

## Key Features

- Accurate CORS header parsing and misconfiguration detection
- Risk-based vulnerability decision model
- Severity classification: critical, high, medium, low, none
- Multi-threaded batch scanning
- Retry with exponential backoff
- Optional bypass testing with custom origins
- Optional HTTP methods testing
- Optional security headers analysis
- Optional path discovery for single and file scans (common + custom paths)
- Advanced result filtering (severity, vulnerable-only, URL pattern)
- Flexible output and export options:
  - Console output (text/json)
  - JSON file export
  - CSV file export
  - HTML report with charts and branding
- Config file and environment variable support
- Proxy and SSL verification controls

---

## Installation

### Requirements

- Python 3.6+
- pip

### From source

```bash
git clone https://github.com/Angix-Black/Corscan.git
cd Corscan
python setup.py install
```

 

### Verify

```bash
corscan --version
corscan --help
```

CLI aliases:

- corscan
- crsn

---

## Usage

```bash
corscan [options]
```

### Core scan options

| Option | Description | Default |
|---|---|---|
| -u, --url URL | Scan a single URL | - |
| -f, --file FILE | Scan URLs from file (one URL per line) | - |
| --discover-paths | Expand URL targets to scan common paths on same host | false |
| --paths-file FILE | Add custom discovery paths (one path per line) | - |
| -r, --origin ORIGIN | Custom Origin header | https://evil.com |
| -t, --threads NUM | Number of threads for batch scan | 10 |
| --timeout SECONDS | Request timeout | 5 |
| --retries NUM | Retry attempts on failures | 2 |
| --proxy URL | Proxy URL (http://host:port) | - |
| --insecure | Disable SSL verification | false |

### Analysis options

| Option | Description |
|---|---|
| --no-bypass | Skip bypass attempts |
| --custom-origin ORIGIN | Add custom origin to bypass tests (repeatable) |
| --test-methods | Test CORS behavior on HTTP methods |
| --analyze-headers | Analyze security headers |

### Output and export

| Option | Description |
|---|---|
| --format text\|json | Console output format |
| -o, --output FILE | Save console output to file |
| --json FILE | Export structured JSON file |
| --csv FILE | Export CSV report |
| --html FILE | Generate HTML report |

### Filters

| Option | Description |
|---|---|
| --filter | Show only vulnerable results (legacy quick filter) |
| --filter-vulnerable | Show only vulnerable URLs |
| --filter-severity LEVEL | Filter by minimum severity: critical\|high\|medium\|low |
| --filter-pattern PATTERN | Keep URLs containing pattern |

### Config and misc

| Option | Description |
|---|---|
| --config FILE | Load config from JSON file |
| --save-config FILE | Save current settings to config file |
| -v, --verbose | Verbose logging |
| -h, --help | Show help |
| --version | Show version |

---

## Quick Examples

### 1) Single target

```bash
corscan -u https://example.com
```

### 2) Batch scan

```bash
corscan -f urls.txt
```

### 3) Single target with path discovery

```bash
corscan -u https://example.com --discover-paths
```

### 4) Single target with custom path list

```bash
corscan -u https://example.com --discover-paths --paths-file paths.txt
```

### 5) File scan with path discovery

```bash
corscan -f urls.txt --discover-paths
```

### 6) Fast scan (skip bypass)

```bash
corscan -f urls.txt --no-bypass -t 50
```

### 7) Vulnerable-only JSON output

```bash
corscan -f urls.txt --filter-vulnerable --format json
```

### 8) Full export package

```bash
corscan -f urls.txt --csv results.csv --json results.json --html report.html
```

### 9) Method test + header analysis

```bash
corscan -f urls.txt --test-methods --analyze-headers
```

### 10) Severity-focused scan

```bash
corscan -f urls.txt --filter-severity high
```

### 11) Through proxy

```bash
corscan -f urls.txt --proxy http://127.0.0.1:8080
```

---

## Severity Model

### Levels

- critical: wildcard origin (*) + credentials true
- high: wildcard origin (*)
- medium: reflective/specific origin match
- low: CORS headers exist but result is not classified as exploitable
- none: no CORS issue detected

### Important behavior

Corscan uses a risk-aware model:

1. It detects CORS misconfiguration.
2. It checks whether sensitive data appears exposed.
3. It marks vulnerable as true only when both conditions are met.

That means you may see Allow-Credentials: true with low severity if the endpoint does not expose sensitive data under current test conditions.

---

## Output Structure

### JSON result fields

- url
- origin
- status_code
- vulnerable
- severity
- cors_headers
- bypass_attempts
- request_time
- error

### CSV columns

- URL
- Origin
- Status Code
- Vulnerable
- Severity
- Allow Origin
- Allow Methods
- Allow Headers
- Allow Credentials
- Request Time (s)
- Error

---

## Configuration

Corscan can load settings from:

- explicit config file passed with --config
- default config paths:
  - ~/.corscan/config.json
  - ./.corscan/config.json
  - ./corscan.json

### Example config

```json
{
  "threads": 10,
  "timeout": 5,
  "default_origin": "https://evil.com",
  "retries": 2,
  "retry_backoff": 0.5,
  "rate_limit_delay": 0.01,
  "test_methods": false,
  "analyze_headers": false
}
```

### Environment variables

- CORSCAN_THREADS
- CORSCAN_TIMEOUT
- CORSCAN_ORIGIN
- CORSCAN_RETRIES
- CORSCAN_BACKOFF

---

## Troubleshooting

### Timeout or unstable targets

```bash
corscan -f urls.txt --timeout 15 --retries 3 -t 5
```

### SSL certificate issues

```bash
corscan -u https://target.local --insecure
```

### Need detailed logs

```bash
corscan -f urls.txt -v
```

### Invalid URL errors

Make sure each URL contains scheme:

- valid: https://example.com
- invalid: example.com

---

## Roadmap Ideas

- CI-friendly exit codes by severity threshold
- Optional SARIF export
- Pluggable risk policies
- Extended report templates

---



