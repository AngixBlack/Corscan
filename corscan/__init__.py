"""
Corscan - Advanced CORS Vulnerability Detection Tool
A comprehensive tool for detecting and analyzing CORS vulnerabilities with bypass attempts.
"""

__version__ = "1.0.2"
__author__ = "Angix Black"
__description__ = "Advanced CORS Vulnerability Detection & Analysis Tool with Enhanced Features"

from corscan.models import CORSResult
from corscan.core import check_cors, is_vulnerable, calculate_severity
from corscan.methods import test_http_methods
from corscan.exporters import export_to_csv, export_to_json_file
from corscan.report import generate_html_report
from corscan.security_headers import analyze_security_headers

__all__ = [
    'CORSResult',
    'check_cors',
    'is_vulnerable',
    'calculate_severity',
    'test_http_methods',
    'export_to_csv',
    'export_to_json_file',
    'generate_html_report',
    'analyze_security_headers',
    '__version__',
]
