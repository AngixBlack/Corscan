"""
Advanced filtering for CORS scan results.
"""

from typing import List, Callable, Optional
from corscan.models import CORSResult
from corscan.constants import (
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW
)


class FilterBuilder:
    """Builder for creating advanced filters."""
    
    def __init__(self):
        """Initialize filter builder."""
        self.filters: List[Callable[[CORSResult], bool]] = []
    
    def by_severity(self, *severities: str) -> 'FilterBuilder':
        """Filter by severity level(s)."""
        severity_list = list(severities)
        self.filters.append(lambda r: r.severity in severity_list)
        return self
    
    def by_vulnerable(self, vulnerable: bool = True) -> 'FilterBuilder':
        """Filter by vulnerability status."""
        self.filters.append(lambda r: r.vulnerable == vulnerable)
        return self
    
    def by_url_pattern(self, pattern: str) -> 'FilterBuilder':
        """Filter by URL pattern (substring match)."""
        self.filters.append(lambda r: pattern.lower() in r.url.lower())
        return self
    
    def by_has_header(self, header_name: str) -> 'FilterBuilder':
        """Filter URLs that have specific CORS header."""
        def has_header(result):
            return header_name.lower() in [h.lower() for h in result.cors_headers.keys()]
        self.filters.append(has_header)
        return self
    
    def by_missing_header(self, header_name: str) -> 'FilterBuilder':
        """Filter URLs missing specific security header."""
        def missing_header(result):
            return header_name.lower() not in [h.lower() for h in result.cors_headers.keys()]
        self.filters.append(missing_header)
        return self
    
    def by_response_time(self, max_ms: int) -> 'FilterBuilder':
        """Filter by response time in milliseconds."""
        self.filters.append(lambda r: (r.response_time * 1000) <= max_ms)
        return self
    
    def by_custom(self, func: Callable[[CORSResult], bool]) -> 'FilterBuilder':
        """Add custom filter function."""
        self.filters.append(func)
        return self
    
    def apply(self, results: List[CORSResult]) -> List[CORSResult]:
        """Apply all filters to results."""
        filtered = results
        for filter_func in self.filters:
            filtered = [r for r in filtered if filter_func(r)]
        return filtered
    
    def build(self) -> Callable[[List[CORSResult]], List[CORSResult]]:
        """Build filter function."""
        def filter_func(results: List[CORSResult]) -> List[CORSResult]:
            return self.apply(results)
        return filter_func


def quick_filter(results: List[CORSResult], **kwargs) -> List[CORSResult]:
    """
    Quick filter with common options.
    
    Args:
        results: List of CORS results
        severity: Filter by severity ('critical', 'high', 'medium', 'low')
        vulnerable: Only vulnerable (True/False)
        pattern: URL pattern to match
        has_header: Must have this header
        missing_header: Must NOT have this header
    
    Returns:
        Filtered results
    """
    builder = FilterBuilder()
    
    if 'severity' in kwargs:
        severity = kwargs['severity']
        if isinstance(severity, str):
            severity = [severity]
        builder.by_severity(*severity)
    
    if 'vulnerable' in kwargs:
        builder.by_vulnerable(kwargs['vulnerable'])
    
    if 'pattern' in kwargs:
        builder.by_url_pattern(kwargs['pattern'])
    
    if 'has_header' in kwargs:
        builder.by_has_header(kwargs['has_header'])
    
    if 'missing_header' in kwargs:
        builder.by_missing_header(kwargs['missing_header'])
    
    if 'response_time_ms' in kwargs:
        builder.by_response_time(kwargs['response_time_ms'])
    
    return builder.apply(results)


# Pre-built common filters
def get_critical_vulnerabilities(results: List[CORSResult]) -> List[CORSResult]:
    """Get only critical vulnerabilities."""
    return quick_filter(results, severity='critical', vulnerable=True)


def get_vulnerable_urls(results: List[CORSResult]) -> List[CORSResult]:
    """Get all vulnerable URLs."""
    return quick_filter(results, vulnerable=True)


def get_safe_urls(results: List[CORSResult]) -> List[CORSResult]:
    """Get all safe URLs."""
    return quick_filter(results, vulnerable=False)


def get_misconfigured_cors(results: List[CORSResult]) -> List[CORSResult]:
    """Get URLs with misconfigured CORS (has headers but vulnerable)."""
    filtered = []
    for result in results:
        if result.vulnerable and result.cors_headers:
            filtered.append(result)
    return filtered
