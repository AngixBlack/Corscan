"""Check additional security headers."""

import requests
from typing import Dict, List, Any

SECURITY_HEADERS_CONFIG = {
    'X-Frame-Options': {
        'description': 'Clickjacking protection',
        'good_values': ['DENY', 'SAMEORIGIN'],
        'risk': 'HIGH'
    },
    'X-Content-Type-Options': {
        'description': 'MIME sniffing protection',
        'good_values': ['nosniff'],
        'risk': 'MEDIUM'
    },
    'Strict-Transport-Security': {
        'description': 'HTTPS enforcement',
        'good_values': ['max-age='],
        'risk': 'HIGH'
    },
    'Content-Security-Policy': {
        'description': 'XSS protection',
        'good_values': None,  # Any value is good
        'risk': 'HIGH'
    },
    'X-XSS-Protection': {
        'description': 'Legacy XSS protection',
        'good_values': ['1; mode=block'],
        'risk': 'LOW'
    },
    'Referrer-Policy': {
        'description': 'Referrer information control',
        'good_values': ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin'],
        'risk': 'MEDIUM'
    },
    'Permissions-Policy': {
        'description': 'Browser feature permissions',
        'good_values': None,
        'risk': 'MEDIUM'
    }
}


def analyze_security_headers(response: requests.Response) -> Dict[str, Any]:
    """
    Analyze security headers in HTTP response.
    
    Args:
        response: HTTP response object to analyze
    
    Returns:
        Dictionary containing present and missing security headers with analysis
    """
    
    present = {}
    missing = []
    
    for header, config in SECURITY_HEADERS_CONFIG.items():
        if header in response.headers:
            value = response.headers[header]
            is_good = True
            
            if config['good_values'] is not None:
                is_good = any(
                    good_val in value 
                    for good_val in config['good_values']
                )
            
            present[header] = {
                'value': value,
                'description': config['description'],
                'is_good': is_good
            }
        else:
            missing.append({
                'header': header,
                'description': config['description'],
                'risk': config['risk']
            })
    
    security_score = (len(present) / len(SECURITY_HEADERS_CONFIG)) * 100
    critical_missing = sum(1 for m in missing if m['risk'] == 'HIGH')
    
    return {
        'present': present,
        'missing': missing,
        'security_score': security_score,
        'critical_missing': critical_missing,
        'status': 'Good' if security_score >= 70 else 'Poor' if security_score < 30 else 'Fair'
    }


def get_security_score_details(headers_analysis: Dict[str, Any]) -> str:
    """
    Get a human-readable security score summary.
    
    Args:
        headers_analysis: Result from analyze_security_headers()
    
    Returns:
        Formatted string with security assessment
    """
    score = headers_analysis['security_score']
    status = headers_analysis['status']
    critical = headers_analysis['critical_missing']
    
    return f"Security Headers: {score:.0f}% ({status}) - {critical} critical missing"
