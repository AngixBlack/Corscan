"""Export results in various formats."""

import csv
from typing import List
from corscan.models import CORSResult


def export_to_csv(results: List[CORSResult], filename: str):
    """
    Export results as CSV file.
    
    Args:
        results: List of CORSResult objects to export
        filename: Output CSV filename
    """
    if not results:
        return
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'URL',
                'Origin',
                'Status Code',
                'Vulnerable',
                'Severity',
                'Allow Origin',
                'Allow Methods',
                'Allow Headers',
                'Allow Credentials',
                'Request Time (s)',
                'Error'
            ]
            
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                writer.writerow({
                    'URL': result.url,
                    'Origin': result.origin,
                    'Status Code': result.status_code or 'N/A',
                    'Vulnerable': 'Yes' if result.vulnerable else 'No',
                    'Severity': result.severity.upper(),
                    'Allow Origin': result.cors_headers.get('Access-Control-Allow-Origin', 'N/A'),
                    'Allow Methods': result.cors_headers.get('Access-Control-Allow-Methods', 'N/A'),
                    'Allow Headers': result.cors_headers.get('Access-Control-Allow-Headers', 'N/A'),
                    'Allow Credentials': result.cors_headers.get('Access-Control-Allow-Credentials', 'N/A'),
                    'Request Time (s)': f"{result.request_time:.3f}",
                    'Error': result.error or 'None'
                })
    except IOError as e:
        raise IOError(f"Failed to write CSV file: {e}")


def export_to_json_file(results: List[CORSResult], filename: str):
    """
    Export results as JSON file.
    
    Args:
        results: List of CORSResult objects to export
        filename: Output JSON filename
    """
    import json
    
    if not results:
        return
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            data = [result.to_dict() for result in results]
            json.dump(data, f, indent=2, default=str)
    except IOError as e:
        raise IOError(f"Failed to write JSON file: {e}")
