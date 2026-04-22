"""
Core CORS vulnerability detection logic with automatic retries.
"""

import time
import logging
from typing import Optional, Callable

import requests

from corscan.constants import (
    CORS_HEADERS, DEFAULT_TIMEOUT, RATE_LIMIT_DELAY,
    REQUEST_RETRIES, RETRY_BACKOFF,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_NONE
)
from corscan.models import CORSResult
from corscan.utils import (
    validate_url, create_session, get_bypass_origins, rate_limit_delay,
    response_has_sensitive_data
)


logger = logging.getLogger(__name__)


def retry_with_backoff(
    func: Callable,
    max_retries: int = REQUEST_RETRIES,
    backoff_factor: float = RETRY_BACKOFF,
    retryable_exceptions: tuple = (requests.Timeout, requests.ConnectionError)
):
    """
    Decorator for automatic retry with exponential backoff.
    
    Args:
        func: Function to retry
        max_retries: Maximum number of retry attempts
        backoff_factor: Exponential backoff multiplier
        retryable_exceptions: Tuple of exceptions to retry on
    
    Returns:
        Wrapped function with retry logic
    """
    def wrapper(*args, **kwargs):
        last_exception = None
        
        for attempt in range(max_retries + 1):
            try:
                return func(*args, **kwargs)
            except retryable_exceptions as e:
                last_exception = e
                if attempt < max_retries:
                    wait_time = backoff_factor * (2 ** attempt)
                    time.sleep(wait_time)
                    continue
                else:
                    raise
            except Exception:
                # Don't retry on other exceptions
                raise
        
        if last_exception:
            raise last_exception
    
    return wrapper


def is_vulnerable(response: requests.Response, origin: str) -> bool:
    """
    Check if response indicates CORS vulnerability.
    
    Args:
        response: HTTP response object
        origin: Origin header used in request
        
    Returns:
        True if vulnerable, False otherwise
    """
    if response is None or not hasattr(response, 'headers'):
        return False

    allow_origin = response.headers.get('Access-Control-Allow-Origin', '').strip()
    allow_credentials = response.headers.get('Access-Control-Allow-Credentials', 'false').lower()
    normalized_origin = (origin or '').strip().lower()
    
    # Critical: Wildcard with credentials
    if allow_origin == '*' and allow_credentials == 'true':
        return True
    
    # High risk: Wildcard origin (allows any origin)
    if allow_origin == '*':
        return True
    
    # Medium risk: Reflects back the origin we sent
    if allow_origin.lower() == normalized_origin:
        return True
    
    return False


def calculate_severity(
    vulnerable: bool,
    allow_origin: str,
    allow_credentials: str,
    has_cors_headers: bool
) -> str:
    """
    Calculate vulnerability severity level.
    
    Returns:
        'critical', 'high', 'medium', 'low', or 'none'
    """
    if not vulnerable:
        if has_cors_headers:
            return SEVERITY_LOW  # Has CORS but properly configured
        return SEVERITY_NONE
    
    # Vulnerability detected - determine severity
    if allow_origin == '*' and allow_credentials.lower() == 'true':
        return SEVERITY_CRITICAL  # Wildcard + credentials = critical
    
    if allow_origin == '*':
        return SEVERITY_HIGH  # Wildcard origin
    
    return SEVERITY_MEDIUM  # Specific origin match (still exploitable)


def attempt_bypass(
    url: str,
    session: requests.Session,
    timeout: int = DEFAULT_TIMEOUT,
    custom_origins: Optional[list] = None
) -> dict:
    """
    Attempt CORS bypass with various strategies.
    
    Args:
        url: Target URL
        session: Requests session
        timeout: Request timeout
        custom_origins: Additional origins to test
        
    Returns:
        Dictionary of bypass attempts and results
    """
    bypass_results = {}
    bypass_origins = get_bypass_origins(url, custom_origins)
    
    @retry_with_backoff
    def _make_request(origin: str) -> dict:
        """Make request with retry logic."""
        rate_limit_delay(RATE_LIMIT_DELAY)
        headers = {'Origin': origin}
        response = session.options(url, headers=headers, timeout=timeout)
        
        is_vuln = is_vulnerable(response, origin)
        return {
            'vulnerable': is_vuln,
            'status_code': response.status_code,
            'headers': dict(response.headers)
        }
    
    for origin, description in bypass_origins:
        try:
            result = _make_request(origin)
            bypass_results[origin] = {
                'vulnerable': result['vulnerable'],
                'description': description,
                'status_code': result['status_code']
            }
        except requests.Timeout:
            bypass_results[origin] = {
                'vulnerable': False,
                'description': description,
                'error': 'Request timeout after retries',
                'retried': True
            }
        except requests.ConnectionError:
            bypass_results[origin] = {
                'vulnerable': False,
                'description': description,
                'error': 'Connection refused after retries',
                'retried': True
            }
        except Exception as e:
            bypass_results[origin] = {
                'vulnerable': False,
                'description': description,
                'error': str(e)
            }
    
    return bypass_results


def check_cors(
    url: str,
    origin: str = "https://evil.com",
    verify_ssl: bool = True,
    proxy: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    check_bypass: bool = True,
    custom_origins: Optional[list] = None,
    filter_vulnerable: bool = False
) -> Optional[CORSResult]:
    """
    Check a single URL for CORS vulnerabilities.
    
    Args:
        url: Target URL to check
        origin: Custom origin header
        verify_ssl: Verify SSL certificates
        proxy: Proxy URL
        timeout: Request timeout
        check_bypass: Whether to perform bypass attempts
        custom_origins: Custom origins to test
        filter_vulnerable: Only return if vulnerable
        
    Returns:
        CORSResult object or None if filtered out
    """
    # Validate URL
    is_valid, error = validate_url(url)
    if not is_valid:
        return CORSResult(
            url=url,
            origin=origin,
            status_code=0,
            vulnerable=False,
            severity=SEVERITY_NONE,
            cors_headers={},
            bypass_attempts={},
            error=error
        )
    
    session = create_session(verify_ssl=verify_ssl, proxy=proxy, timeout=timeout)
    
    @retry_with_backoff
    def _make_request():
        """Make request with retry logic."""
        start_time = time.time()
        headers = {'Origin': origin, 'User-Agent': 'Corscan/1.0.2'}
        response = session.options(url, headers=headers, timeout=timeout)
        request_time = time.time() - start_time
        return response, request_time
    
    try:
        response, request_time = _make_request()
        
        # Extract CORS headers
        cors_headers_dict = {
            header: response.headers.get(header, 'Not Present')
            for header in CORS_HEADERS
        }
        
        # Filter out "Not Present" for cleaner output
        cors_headers_dict = {
            k: v for k, v in cors_headers_dict.items() if v != 'Not Present'
        }
        
        # Check CORS misconfiguration first.
        cors_misconfigured = is_vulnerable(response, origin)

        # Mark vulnerable only if sensitive data appears exposed.
        sensitive_data_exposed = False
        if cors_misconfigured:
            sensitive_data_exposed = response_has_sensitive_data(response)

            # OPTIONS responses are often empty; verify with a GET request.
            if not sensitive_data_exposed:
                try:
                    probe_response = session.get(
                        url,
                        headers={'Origin': origin, 'User-Agent': 'Corscan/1.0.2'},
                        timeout=timeout
                    )
                    sensitive_data_exposed = response_has_sensitive_data(probe_response)
                except Exception as e:
                    logger.debug(f"Sensitive data probe failed for {url}: {e}")

        vulnerable = cors_misconfigured and sensitive_data_exposed
        
        # Calculate severity
        allow_origin = response.headers.get('Access-Control-Allow-Origin', '').strip()
        allow_credentials = response.headers.get('Access-Control-Allow-Credentials', 'false')
        has_cors_headers = bool(cors_headers_dict)
        severity = calculate_severity(vulnerable, allow_origin, allow_credentials, has_cors_headers)
        
        # Attempt bypass
        bypass_results = {}
        if check_bypass and vulnerable:
            bypass_results = attempt_bypass(url, session, timeout, custom_origins)
        
        result = CORSResult(
            url=url,
            origin=origin,
            status_code=response.status_code,
            vulnerable=vulnerable,
            severity=severity,
            cors_headers=cors_headers_dict,
            bypass_attempts=bypass_results,
            request_time=request_time
        )
        
        # Apply filter
        if filter_vulnerable and not vulnerable:
            return None
        
        return result
        
    except requests.Timeout:
        error_msg = "Request timeout - target may be slow or unresponsive (after retries)"
        return CORSResult(
            url=url,
            origin=origin,
            status_code=0,
            vulnerable=False,
            severity=SEVERITY_NONE,
            cors_headers={},
            bypass_attempts={},
            error=error_msg
        )
    except requests.ConnectionError:
        error_msg = "Connection refused - target unreachable (after retries)"
        return CORSResult(
            url=url,
            origin=origin,
            status_code=0,
            vulnerable=False,
            severity=SEVERITY_NONE,
            cors_headers={},
            bypass_attempts={},
            error=error_msg
        )
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        return CORSResult(
            url=url,
            origin=origin,
            status_code=0,
            vulnerable=False,
            severity=SEVERITY_NONE,
            cors_headers={},
            bypass_attempts={},
            error=error_msg
        )
    finally:
        session.close()
