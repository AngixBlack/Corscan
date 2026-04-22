"""
Utility functions for URL validation, session management, and helper operations.
"""

import time
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from corscan.constants import (
    REQUEST_RETRIES, RETRY_BACKOFF, BYPASS_STRATEGIES,
    ERROR_URL_EMPTY, ERROR_URL_NO_SCHEME, ERROR_URL_INVALID_SCHEME, ERROR_URL_NO_NETLOC
)


SENSITIVE_DATA_PATTERNS = [
    re.compile(pattern, re.IGNORECASE) for pattern in [
        r'"password"\s*:',
        r'"passwd"\s*:',
        r'"passphrase"\s*:',
        r'"pin"\s*:',
        r'"otp"\s*:',
        r'"token"\s*:',
        r'"access_token"\s*:',
        r'"refresh_token"\s*:',
        r'"id_token"\s*:',
        r'"jwt"\s*:',
        r'"bearer"\s*:',
        r'"auth[_-]?token"\s*:',
        r'"api[_-]?key"\s*:',
        r'"client[_-]?secret"\s*:',
        r'"secret"\s*:',
        r'"authorization"\s*:',
        r'"x-api-key"\s*:',
        r'"private[_-]?token"\s*:',
        r'"session"\s*:',
        r'"session[_-]?id"\s*:',
        r'"cookie"\s*:',
        r'"set-cookie"\s*:',
        r'"ssn"\s*:',
        r'"national[_-]?id"\s*:',
        r'"nid"\s*:',
        r'"passport"\s*:',
        r'"driver[_-]?license"\s*:',
        r'"dob"\s*:',
        r'"birth(date)?"\s*:',
        r'"email"\s*:',
        r'"phone"\s*:',
        r'"mobile"\s*:',
        r'"address"\s*:',
        r'"credit[_-]?card"\s*:',
        r'"card[_-]?number"\s*:',
        r'"card[_-]?cvv"\s*:',
        r'"cvv"\s*:',
        r'"cvc"\s*:',
        r'"iban"\s*:',
        r'"swift"\s*:',
        r'"bank[_-]?account"\s*:',
        r'"account[_-]?number"\s*:',
        r'"routing[_-]?number"\s*:',
        r'"private[_-]?key"\s*:',
        r'"public[_-]?key"\s*:',
        r'"ssh[_-]?key"\s*:'
    ]
]


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """
    Validate URL format.
    
    Args:
        url: URL to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not url:
        return False, ERROR_URL_EMPTY
    
    try:
        result = urlparse(url)
        if not result.scheme:
            return False, ERROR_URL_NO_SCHEME
        if result.scheme not in ['http', 'https']:
            return False, ERROR_URL_INVALID_SCHEME.format(scheme=result.scheme)
        if not result.netloc:
            return False, ERROR_URL_NO_NETLOC
        return True, None
    except Exception as e:
        return False, f"Invalid URL format: {str(e)}"


def create_session(
    verify_ssl: bool = True,
    proxy: Optional[str] = None,
    timeout: int = 5
) -> requests.Session:
    """
    Create a requests session with retry strategy.
    
    Args:
        verify_ssl: Whether to verify SSL certificates
        proxy: Proxy URL (format: http://proxy:port)
        timeout: Request timeout in seconds
        
    Returns:
        Configured requests.Session
    """
    session = requests.Session()
    
    # Configure retry strategy
    retry_strategy = Retry(
        total=REQUEST_RETRIES,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"],
        backoff_factor=RETRY_BACKOFF
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Configure SSL verification
    session.verify = verify_ssl
    
    # Configure proxy
    if proxy:
        session.proxies = {
            'http': proxy,
            'https': proxy,
        }
    
    return session


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    parsed = urlparse(url)
    return parsed.netloc


def extract_subdomain(url: str) -> str:
    """Extract subdomain from URL (first part before first dot)."""
    domain = extract_domain(url)
    return domain.split('.')[0]


def get_url_protocol(url: str) -> str:
    """Extract protocol (http/https) from URL."""
    parsed = urlparse(url)
    return parsed.scheme


def get_bypass_origins(url: str, custom_origins: Optional[List[str]] = None) -> List[Tuple[str, str]]:
    """
    Generate bypass origin strategies.
    
    Args:
        url: Target URL
        custom_origins: Additional custom origins to test
        
    Returns:
        List of (origin, description) tuples
    """
    domain = extract_domain(url)
    protocol = get_url_protocol(url)
    subdomain = extract_subdomain(url)
    
    origins = []
    
    # Process template-based strategies
    for template, description in BYPASS_STRATEGIES.items():
        try:
            origin = template.format(
                domain=domain,
                domain_protocol=protocol,
                subdomain=subdomain
            )
            origins.append((origin, description))
        except KeyError:
            # Keep strategies without variables as-is
            origins.append((template, description))
    
    # Add custom origins if provided
    if custom_origins:
        for custom in custom_origins:
            origins.append((custom, "Custom bypass origin"))
    
    return origins


def rate_limit_delay(delay: float = 0.01):
    """Apply a rate limiting delay."""
    time.sleep(delay)


def response_has_sensitive_data(response: requests.Response) -> bool:
    """
    Heuristic check for sensitive data in response headers/body.

    This intentionally uses conservative indicators to avoid flagging
    generic public endpoints as exploitable leaks.
    """
    if response is None:
        return False

    # Leaked cookies over CORS are a sensitive data signal.
    if 'Set-Cookie' in response.headers:
        return True

    content_type = response.headers.get('Content-Type', '').lower()
    text = response.text or ''

    # Limit scan size to keep large responses fast.
    if len(text) > 100000:
        text = text[:100000]

    if 'application/json' in content_type or text.strip().startswith(('{', '[')):
        for pattern in SENSITIVE_DATA_PATTERNS:
            if pattern.search(text):
                return True

    return False
