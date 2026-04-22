"""HTTP method vulnerability testing."""

import requests
from typing import Dict, Any
from corscan.constants import DEFAULT_TIMEOUT
from corscan.utils import response_has_sensitive_data


def test_http_methods(
    url: str,
    origin: str,
    session: requests.Session,
    timeout: int = DEFAULT_TIMEOUT
) -> Dict[str, Dict[str, Any]]:
    """
    Test CORS vulnerability on different HTTP methods.
    
    Some servers may expose CORS on POST but not GET,
    or vice versa. This test covers them all.
    
    Args:
        url: Target URL to test
        origin: Origin header value
        session: Requests session to use
        timeout: Request timeout in seconds
    
    Returns:
        Dictionary mapping HTTP methods to test results
    """
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
    results = {}
    
    for method in methods:
        try:
            headers = {'Origin': origin}
            response = session.request(
                method, url, headers=headers, timeout=timeout, allow_redirects=False
            )
            
            allow_origin = response.headers.get('Access-Control-Allow-Origin')
            allow_creds = response.headers.get('Access-Control-Allow-Credentials')
            allow_methods = response.headers.get('Access-Control-Allow-Methods')
            allow_headers = response.headers.get('Access-Control-Allow-Headers')
            has_sensitive_data = response_has_sensitive_data(response)
            
            results[method] = {
                'status_code': response.status_code,
                'allows_origin': allow_origin is not None,
                'allow_origin_value': allow_origin,
                'allows_credentials': allow_creds == 'true',
                'allow_methods': allow_methods,
                'allow_headers': allow_headers,
                'has_sensitive_data': has_sensitive_data,
                'vulnerable': bool(allow_origin) and has_sensitive_data
            }
        except Exception as e:
            results[method] = {
                'error': str(e),
                'vulnerable': False,
                'status_code': None,
                'allows_origin': False,
                'allows_credentials': False
            }
    
    return results
