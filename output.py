"""
Output formatting for Corscan results.
"""

import json
from typing import Optional

from colorama import Fore, Style

from corscan.models import CORSResult
from corscan.constants import SEVERITY_COLORS, SEVERITY_CRITICAL, SEVERITY_HIGH


def format_text_output(result: CORSResult) -> str:
    """Format result as human-readable text with colors."""
    lines = []
    
    # URL and basic info
    lines.append(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    lines.append(f"{Fore.CYAN}URL:{Style.RESET_ALL} {result.url}")
    lines.append(f"{Fore.CYAN}Origin:{Style.RESET_ALL} {result.origin}")
    lines.append(f"{Fore.CYAN}Status Code:{Style.RESET_ALL} {result.status_code}")
    lines.append(f"{Fore.CYAN}Request Time:{Style.RESET_ALL} {result.request_time:.3f}s")
    
    # Error handling
    if result.error:
        lines.append(f"{Fore.RED}Error:{Style.RESET_ALL} {result.error}")
        return "\n".join(lines)
    
    # Vulnerability status
    severity_color_map = {
        'critical': Fore.RED,
        'high': Fore.LIGHTRED_EX,
        'medium': Fore.YELLOW,
        'low': Fore.BLUE,
        'none': Fore.GREEN
    }
    
    color = severity_color_map.get(result.severity, Fore.WHITE)
    vuln_text = f"{color}[{result.severity.upper()}]{Style.RESET_ALL}"
    lines.append(f"{Fore.CYAN}Vulnerability:{Style.RESET_ALL} {vuln_text}")
    
    if result.vulnerable:
        lines.append(f"{Fore.RED}⚠ Potential vulnerability detected!{Style.RESET_ALL}")
    else:
        lines.append(f"{Fore.GREEN}✓ No CORS vulnerability detected{Style.RESET_ALL}")
    
    # CORS Headers
    if result.cors_headers:
        lines.append(f"\n{Fore.CYAN}CORS Headers:{Style.RESET_ALL}")
        for header, value in result.cors_headers.items():
            lines.append(f"  {Fore.MAGENTA}{header}:{Style.RESET_ALL} {value}")
    else:
        lines.append(f"{Fore.YELLOW}No CORS headers present{Style.RESET_ALL}")
    
    # Bypass attempts
    if result.bypass_attempts:
        lines.append(f"\n{Fore.CYAN}Bypass Attempts:{Style.RESET_ALL}")
        for origin, attempt in result.bypass_attempts.items():
            # Skip special keys that contain analysis results
            if origin in ['http_methods', 'security_headers']:
                continue
            
            if attempt.get('vulnerable'):
                status = f"{Fore.RED}✓ VULNERABLE{Style.RESET_ALL}"
            elif attempt.get('error'):
                status = f"{Fore.YELLOW}✗ {attempt['error']}{Style.RESET_ALL}"
            else:
                status = f"{Fore.GREEN}✗ Failed{Style.RESET_ALL}"
            
            lines.append(f"  {Fore.CYAN}{origin}:{Style.RESET_ALL}")
            lines.append(f"    Status: {status}")
            lines.append(f"    Description: {attempt.get('description', 'N/A')}")
    
    # HTTP Methods Testing
    if result.bypass_attempts and 'http_methods' in result.bypass_attempts:
        lines.append(f"\n{Fore.CYAN}HTTP Methods Testing:{Style.RESET_ALL}")
        methods_data = result.bypass_attempts['http_methods']
        for method, data in methods_data.items():
            if data.get('error'):
                lines.append(f"  {Fore.YELLOW}{method}:{Style.RESET_ALL} Error - {data['error']}")
            elif data.get('vulnerable'):
                vuln_status = f"{Fore.RED}✓ VULNERABLE{Style.RESET_ALL}"
                lines.append(f"  {Fore.YELLOW}{method}:{Style.RESET_ALL} {vuln_status} (Status: {data.get('status_code', 'N/A')})")
            else:
                lines.append(f"  {Fore.GREEN}{method}:{Style.RESET_ALL} Safe (Status: {data.get('status_code', 'N/A')})")
    
    # Security Headers Analysis
    if result.bypass_attempts and 'security_headers' in result.bypass_attempts:
        headers_analysis = result.bypass_attempts['security_headers']
        lines.append(f"\n{Fore.CYAN}Security Headers Analysis:{Style.RESET_ALL}")
        lines.append(f"  Security Score: {Fore.YELLOW}{headers_analysis.get('security_score', 0):.1f}%{Style.RESET_ALL} ({headers_analysis.get('status', 'N/A')})")
        
        if headers_analysis.get('present'):
            lines.append(f"  {Fore.GREEN}Present Headers:{Style.RESET_ALL}")
            for header, info in headers_analysis['present'].items():
                status = f"{Fore.GREEN}✓ Good{Style.RESET_ALL}" if info.get('is_good') else f"{Fore.YELLOW}⚠ Weak{Style.RESET_ALL}"
                lines.append(f"    {header}: {status}")
        
        if headers_analysis.get('missing'):
            lines.append(f"  {Fore.RED}Missing Headers ({len(headers_analysis['missing'])}):{Style.RESET_ALL}")
            for missing in headers_analysis['missing']:
                risk_color = Fore.RED if missing.get('risk') == 'HIGH' else Fore.YELLOW if missing.get('risk') == 'MEDIUM' else Fore.BLUE
                lines.append(f"    {risk_color}• {missing['header']}{Style.RESET_ALL} - {missing['description']} [{missing['risk']}]")
    
    lines.append(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    return "\n".join(lines)


def format_json_output(result: CORSResult) -> str:
    """Format result as JSON."""
    return json.dumps(result.to_dict(), indent=2, default=str)


def format_summary(stats: dict) -> str:
    """Format scan summary statistics."""
    lines = []
    lines.append(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    lines.append(f"{Fore.GREEN}Scan Complete!{Style.RESET_ALL}")
    lines.append(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    lines.append(f"Total scanned: {stats['total_scanned']}")
    lines.append(f"Vulnerable found: {Fore.RED}{stats['vulnerable_found']}{Style.RESET_ALL}")
    lines.append(f"Time elapsed: {stats['time_elapsed']:.2f}s")
    lines.append(f"Average per URL: {stats['avg_time_per_url']:.3f}s")
    lines.append(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    return "\n".join(lines)


def print_logo():
    """Display the Corscan logo and disclaimer."""
    logo = f"""
{Fore.LIGHTGREEN_EX}+--------------------------------------+{Style.RESET_ALL}
{Fore.LIGHTGREEN_EX}|{Style.RESET_ALL}              {Fore.CYAN}CORSCAN {Style.RESET_ALL}                {Fore.LIGHTGREEN_EX}|{Style.RESET_ALL}
{Fore.LIGHTGREEN_EX}|{Style.RESET_ALL}      Advanced CORS Scanner Tool      {Fore.LIGHTGREEN_EX}|{Style.RESET_ALL}
{Fore.LIGHTGREEN_EX}|{Style.RESET_ALL}      Developed by Angix Black        {Fore.LIGHTGREEN_EX}|{Style.RESET_ALL}
{Fore.LIGHTGREEN_EX}|{Style.RESET_ALL}              Version 1.0.2           {Fore.LIGHTGREEN_EX}|{Style.RESET_ALL}
{Fore.LIGHTGREEN_EX}+--------------------------------------+{Style.RESET_ALL}
"""
    print(logo)
