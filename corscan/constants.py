"""
Configuration and constants for Corscan.
"""

# Request configuration
DEFAULT_TIMEOUT = 5
DEFAULT_THREADS = 10
DEFAULT_ORIGIN = "https://evil.com"
REQUEST_RETRIES = 2
RETRY_BACKOFF = 0.5
RATE_LIMIT_DELAY = 0.01  # Slight delay between requests to avoid overwhelming targets

# HTTP Headers
CORS_HEADERS = [
    'Access-Control-Allow-Origin',
    'Access-Control-Allow-Methods',
    'Access-Control-Allow-Headers',
    'Access-Control-Allow-Credentials',
    'Access-Control-Max-Age',
    'Access-Control-Expose-Headers'
]

# Severity levels
SEVERITY_CRITICAL = 'critical'
SEVERITY_HIGH = 'high'
SEVERITY_MEDIUM = 'medium'
SEVERITY_LOW = 'low'
SEVERITY_NONE = 'none'

SEVERITY_COLORS = {
    SEVERITY_CRITICAL: 'red',
    SEVERITY_HIGH: 'lightred',
    SEVERITY_MEDIUM: 'yellow',
    SEVERITY_LOW: 'blue',
    SEVERITY_NONE: 'green'
}

# Bypass strategies with descriptions
BYPASS_STRATEGIES = {
    'null': 'Null origin (used for file:// protocol)',
    'https://subdomain.evil.com': 'Generic subdomain bypass',
    'http://localhost': 'Localhost bypass',
    'http://127.0.0.1': 'Loopback IP bypass',
    '{domain_protocol}://{domain}': 'Same domain, possibly different port',
    'https://{subdomain}.evil.com': 'Domain subdomain bypass',
    'https://evil.com.{domain}': 'Domain suffix bypass',
}

# Error messages
ERROR_URL_EMPTY = "URL cannot be empty"
ERROR_URL_NO_SCHEME = "URL must include scheme (http:// or https://)"
ERROR_URL_INVALID_SCHEME = "Unsupported scheme '{scheme}'. Use http or https"
ERROR_URL_NO_NETLOC = "URL must include a domain/host"
ERROR_FILE_NOT_FOUND = "File not found: {file_path}"
ERROR_FILE_READ = "Error reading file '{file_path}': {error}"
ERROR_OUTPUT_WRITE = "Failed to write to output file '{output_file}': {error}"

# Success messages
SUCCESS_SCAN_COMPLETE = "Scan Complete!"
SUCCESS_RESULTS_SAVED = "Results saved to: {output_file}"
