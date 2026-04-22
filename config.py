"""
Configuration management for Corscan.
Supports loading from config files and environment variables.
"""

import os
import json
from typing import Dict, Any, Optional
from pathlib import Path


class Config:
    """Configuration manager for Corscan."""
    
    # Default values
    DEFAULTS = {
        'threads': 10,
        'timeout': 5,
        'default_origin': 'https://evil.com',
        'retries': 2,
        'retry_backoff': 0.5,
        'rate_limit_delay': 0.01,
        'test_methods': False,
        'analyze_headers': False,
    }
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize config from file or defaults.
        
        Args:
            config_file: Path to config file (JSON or .ini format)
        """
        self.config = self.DEFAULTS.copy()
        
        # Try to load from config file
        if config_file and os.path.exists(config_file):
            self._load_from_file(config_file)
        else:
            # Try default locations
            self._load_from_default_locations()
        
        # Override with environment variables
        self._load_from_env()
    
    def _load_from_file(self, config_file: str):
        """Load configuration from JSON file."""
        try:
            with open(config_file, 'r') as f:
                if config_file.endswith('.json'):
                    file_config = json.load(f)
                    self.config.update(file_config)
        except Exception as e:
            print(f"Warning: Could not load config file {config_file}: {e}")
    
    def _load_from_default_locations(self):
        """Check default config locations."""
        default_locations = [
            Path.home() / '.corscan' / 'config.json',
            Path.cwd() / '.corscan' / 'config.json',
            Path.cwd() / 'corscan.json',
        ]
        
        for location in default_locations:
            if location.exists():
                self._load_from_file(str(location))
                break
    
    def _load_from_env(self):
        """Load configuration from environment variables."""
        env_mapping = {
            'CORSCAN_THREADS': ('threads', int),
            'CORSCAN_TIMEOUT': ('timeout', int),
            'CORSCAN_ORIGIN': ('default_origin', str),
            'CORSCAN_RETRIES': ('retries', int),
            'CORSCAN_BACKOFF': ('retry_backoff', float),
        }
        
        for env_var, (config_key, converter) in env_mapping.items():
            value = os.environ.get(env_var)
            if value:
                try:
                    self.config[config_key] = converter(value)
                except ValueError:
                    print(f"Warning: Invalid value for {env_var}: {value}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self.config.get(key, default if default is not None else self.DEFAULTS.get(key))
    
    def set(self, key: str, value: Any):
        """Set configuration value."""
        self.config[key] = value
    
    def to_dict(self) -> Dict[str, Any]:
        """Get configuration as dictionary."""
        return self.config.copy()
    
    def save(self, config_file: str):
        """Save configuration to JSON file."""
        os.makedirs(os.path.dirname(config_file) or '.', exist_ok=True)
        with open(config_file, 'w') as f:
            json.dump(self.config, f, indent=4)


# Create example config file content
EXAMPLE_CONFIG = '''{
    "threads": 10,
    "timeout": 5,
    "default_origin": "https://evil.com",
    "retries": 2,
    "retry_backoff": 0.5,
    "rate_limit_delay": 0.01,
    "test_methods": true,
    "analyze_headers": true
}
'''


def create_example_config(path: str = None):
    """Create example config file."""
    if path is None:
        path = str(Path.home() / '.corscan' / 'config.json')
    
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(EXAMPLE_CONFIG)
    
    return path
