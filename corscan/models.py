"""
Data models and structures for Corscan results.
"""

from dataclasses import dataclass, asdict
from typing import Dict, Optional, Any


@dataclass
class CORSResult:
    """Represents a single CORS check result."""
    url: str
    origin: str
    status_code: int
    vulnerable: bool
    severity: str  # 'critical', 'high', 'medium', 'low', 'none'
    cors_headers: Dict[str, str]
    bypass_attempts: Dict[str, Any]
    error: Optional[str] = None
    request_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    def is_critical(self) -> bool:
        """Check if result is critical severity."""
        return self.severity == 'critical'
    
    def is_high(self) -> bool:
        """Check if result is high severity."""
        return self.severity == 'high'
    
    def has_error(self) -> bool:
        """Check if result has an error."""
        return self.error is not None
