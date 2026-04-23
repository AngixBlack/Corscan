"""
Command-line interface for Corscan.
"""

import sys
import logging
import argparse
from urllib.parse import urlparse

from colorama import Fore, Style, init

from corscan import __version__
from corscan.core import check_cors
from corscan.scanner import load_urls_from_file, batch_check_cors
from corscan.output import format_text_output, format_json_output, format_summary, print_logo
from corscan.constants import (
    DEFAULT_TIMEOUT, DEFAULT_THREADS, DEFAULT_ORIGIN
)
from corscan.filters import quick_filter, get_critical_vulnerabilities, get_vulnerable_urls
from corscan.config import Config

# Initialize colorama
init(autoreset=False)

logger = logging.getLogger(__name__)


COMMON_PATH_DISCOVERY_PATHS = [
    '/',
    '/api',
    '/api/v1',
    '/api/v2',
    '/api/v3',
    '/api/v4',
    '/api/v1/users',
    '/api/v1/user',
    '/api/v1/auth',
    '/api/v1/login',
    '/api/v1/session',
    '/api/v1/profile',
    '/api/v1/account',
    '/api/v1/me',
    '/api/v1/admin',
    '/api/v1/settings',
    '/api/v1/config',
    '/api/v1/internal',
    '/api/v1/private',
    '/api/v1/token',
    '/api/v2/users',
    '/api/v2/auth',
    '/api/v2/login',
    '/api/v2/session',
    '/api/v2/profile',
    '/api/v2/account',
    '/api/v2/me',
    '/api/v2/admin',
    '/api/v2/settings',
    '/graphql',
    '/graphql/v1',
    '/graphql/v2',
    '/graphql/playground',
    '/rest',
    '/rest/v1',
    '/rest/v2',
    '/v1',
    '/v2',
    '/v3',
    '/v4',
    '/oauth',
    '/oauth2',
    '/oidc',
    '/auth',
    '/auth/login',
    '/auth/logout',
    '/auth/register',
    '/auth/refresh',
    '/auth/token',
    '/user',
    '/users',
    '/users/me',
    '/users/profile',
    '/profile',
    '/account',
    '/me',
    '/admin',
    '/admin/api',
    '/admin/users',
    '/admin/settings',
    '/dashboard',
    '/settings',
    '/config',
    '/configs',
    '/internal',
    '/private',
    '/private/api',
    '/private/v1',
    '/data',
    '/data/export',
    '/data/import',
    '/search',
    '/login',
    '/logout',
    '/register',
    '/signup',
    '/signin',
    '/token',
    '/tokens',
    '/session',
    '/sessions',
    '/userinfo',
    '/permissions',
    '/roles',
    '/billing',
    '/payments',
    '/orders',
    '/checkout',
    '/cart',
    '/notifications',
    '/messages',
    '/webhooks',
    '/callback',
    '/upload',
    '/download',
    '/attachments',
    '/files',
    '/docs',
    '/swagger',
    '/swagger.json',
    '/openapi.json',
    '/api-docs',
    '/health',
    '/healthz',
    '/ready',
    '/readyz',
    '/live',
    '/livez',
    '/status',
    '/metrics',
]


def build_path_discovery_urls(seed_url: str, paths_file: str = None):
    """Build unique URL list for path discovery on the same host."""
    parsed = urlparse(seed_url)
    if not parsed.scheme or not parsed.netloc:
        return [seed_url]

    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # Keep user-provided path first if present.
    candidate_paths = []
    if parsed.path and parsed.path != '/':
        candidate_paths.append(parsed.path)

    candidate_paths.extend(COMMON_PATH_DISCOVERY_PATHS)

    if paths_file:
        try:
            with open(paths_file, 'r', encoding='utf-8') as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if not line or line.startswith('#'):
                        continue

                    if line.startswith('http://') or line.startswith('https://'):
                        candidate_paths.append(line)
                    else:
                        if not line.startswith('/'):
                            line = f"/{line}"
                        candidate_paths.append(line)
        except Exception as e:
            logger.warning(f"Could not read paths file '{paths_file}': {e}")

    urls = []
    seen = set()

    for item in candidate_paths:
        if item.startswith('http://') or item.startswith('https://'):
            final_url = item
        else:
            final_url = f"{base_url}{item}"

        if final_url not in seen:
            seen.add(final_url)
            urls.append(final_url)

    return urls


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging with appropriate level."""
    log_logger = logging.getLogger('corscan')
    log_logger.handlers.clear()
    
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter(
        f'{Fore.CYAN}[%(levelname)s]{Style.RESET_ALL} %(message)s'
    )
    handler.setFormatter(formatter)
    log_logger.addHandler(handler)
    log_logger.setLevel(level)
    
    return log_logger


def print_help():
    """Display help message."""
    help_text = f"""
{Fore.YELLOW}USAGE:{Style.RESET_ALL}
  corscan [options]

{Fore.YELLOW}SCANNING OPTIONS:{Style.RESET_ALL}
  {Fore.CYAN}-u, --url{Style.RESET_ALL} URL                Scan a single URL
  {Fore.CYAN}-f, --file{Style.RESET_ALL} FILE              Scan URLs from file (one per line)
        {Fore.CYAN}--discover-paths{Style.RESET_ALL}             Expand -u/-f targets to common paths on same host
    {Fore.CYAN}--paths-file{Style.RESET_ALL} FILE            Extra paths for discovery (one path per line)
  {Fore.CYAN}-r, --origin{Style.RESET_ALL} ORIGIN          Custom origin header (default: {DEFAULT_ORIGIN})
  {Fore.CYAN}-t, --threads{Style.RESET_ALL} NUM            Number of threads (default: {DEFAULT_THREADS})

{Fore.YELLOW}OUTPUT OPTIONS:{Style.RESET_ALL}
  {Fore.CYAN}--csv{Style.RESET_ALL} FILE                   Export to CSV file
  {Fore.CYAN}--html{Style.RESET_ALL} FILE                  Generate HTML report (with charts!)
  {Fore.CYAN}--json{Style.RESET_ALL} FILE                  Export to JSON file
  {Fore.CYAN}--format{Style.RESET_ALL} [text|json]         Output format (default: text)

{Fore.YELLOW}ANALYSIS OPTIONS:{Style.RESET_ALL}
  {Fore.CYAN}--test-methods{Style.RESET_ALL}               Test CORS on HTTP methods
  {Fore.CYAN}--analyze-headers{Style.RESET_ALL}            Analyze security headers
  {Fore.CYAN}--no-bypass{Style.RESET_ALL}                  Skip bypass attempts

{Fore.YELLOW}ADVANCED FILTERS:{Style.RESET_ALL} ⭐ NEW!
  {Fore.CYAN}--filter-severity{Style.RESET_ALL} LEVEL      Filter by severity (critical|high|medium|low)
  {Fore.CYAN}--filter-vulnerable{Style.RESET_ALL}          Show only vulnerable URLs
  {Fore.CYAN}--filter-pattern{Style.RESET_ALL} PATTERN     Filter URLs containing pattern

{Fore.YELLOW}CONFIGURATION:{Style.RESET_ALL}
  {Fore.CYAN}--config{Style.RESET_ALL} FILE                Load settings from config file
  {Fore.CYAN}--save-config{Style.RESET_ALL} FILE           Save current settings to config file
  {Fore.CYAN}--retries{Style.RESET_ALL} NUM                Number of retries on failure (default: 2)

{Fore.YELLOW}CONNECTION OPTIONS:{Style.RESET_ALL}
  {Fore.CYAN}--timeout{Style.RESET_ALL} SECONDS            Request timeout (default: {DEFAULT_TIMEOUT}s)
  {Fore.CYAN}--proxy{Style.RESET_ALL} URL                  Proxy URL (http://host:port)
  {Fore.CYAN}--insecure{Style.RESET_ALL}                   Disable SSL verification
  {Fore.CYAN}--custom-origin{Style.RESET_ALL} ORIGIN       Add custom origin to bypass tests

{Fore.YELLOW}OTHER OPTIONS:{Style.RESET_ALL}
  {Fore.CYAN}-v, --verbose{Style.RESET_ALL}                Enable verbose logging
  {Fore.CYAN}--version{Style.RESET_ALL}                    Show version
  {Fore.CYAN}-h, --help{Style.RESET_ALL}                   Show this help message

{Fore.YELLOW}EXAMPLES:{Style.RESET_ALL}
  {Fore.CYAN}# Scan with advanced filters{Style.RESET_ALL}
  corscan -f urls.txt --filter-severity critical --html report.html

  {Fore.CYAN}# Batch scan with CSV export and method testing{Style.RESET_ALL}
  corscan -f urls.txt --csv results.csv --test-methods

  {Fore.CYAN}# Use custom configuration{Style.RESET_ALL}
  corscan -f urls.txt --config ~/.corscan/config.json --html report.html

  {Fore.CYAN}# Full analysis with all features{Style.RESET_ALL}
  corscan -f urls.txt --test-methods --analyze-headers --html report.html

  {Fore.CYAN}# With automatic retries{Style.RESET_ALL}
  corscan -f urls.txt --retries 3 --timeout 10

{Fore.YELLOW}SEVERITY LEVELS:{Style.RESET_ALL}
  {Fore.RED}CRITICAL{Style.RESET_ALL}  - Wildcard origin with credentials enabled
  {Fore.LIGHTRED_EX}HIGH{Style.RESET_ALL}     - Wildcard origin allowing any cross-origin requests
  {Fore.YELLOW}MEDIUM{Style.RESET_ALL}   - Specific origin match (reflective)
  {Fore.BLUE}LOW{Style.RESET_ALL}      - CORS headers present but properly configured
  {Fore.GREEN}NONE{Style.RESET_ALL}     - No CORS vulnerability

{Fore.YELLOW}CONFIG FILE FORMAT:{Style.RESET_ALL}
  Create ~/.corscan/config.json:
  {{
    "threads": 10,
    "timeout": 5,
    "retries": 2,
    "test_methods": true,
    "analyze_headers": true
  }}

{Fore.YELLOW}ENVIRONMENT VARIABLES:{Style.RESET_ALL}
  CORSCAN_THREADS      - Number of threads
  CORSCAN_TIMEOUT      - Request timeout in seconds
  CORSCAN_ORIGIN       - Default origin header
  CORSCAN_RETRIES      - Number of retries
  CORSCAN_BACKOFF      - Retry backoff multiplier
    """
    print(help_text)


def save_output(output: str, output_file: str):
    """Save output to file."""
    try:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write(output + "\n")
    except IOError as e:
        logger.error(f"Failed to write to output file '{output_file}': {e}")


def output_handler(result, output_format: str = 'text', output_file: str = None):
    """Handle output formatting and saving."""
    if output_format == 'json':
        output = format_json_output(result)
    else:
            output = format_text_output(result)
    
    print(output)
    
    if output_file:
        save_output(output, output_file)


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        add_help=False,
        description='Advanced CORS Vulnerability Scanner'
    )
    
    # Scanning options
    parser.add_argument("-u", "--url", help="Single URL to scan")
    parser.add_argument("-f", "--file", help="File containing URLs (one per line)")
    parser.add_argument("--discover-paths", action='store_true', help="Expand URL targets into common paths on same host")
    parser.add_argument("--paths-file", help="File with additional paths for --discover-paths")
    parser.add_argument("-r", "--origin", default=DEFAULT_ORIGIN, help=f"Custom origin (default: {DEFAULT_ORIGIN})")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"Number of threads (default: {DEFAULT_THREADS})")
    
    # Output options
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--csv", help="Export results to CSV file")
    parser.add_argument("--html", help="Generate HTML report")
    parser.add_argument("--json", help="Export results to JSON file")
    parser.add_argument("--format", choices=['text', 'json'], default='text', help="Output format")
    
    # Analysis options
    parser.add_argument("--test-methods", action='store_true', help="Test CORS on different HTTP methods")
    parser.add_argument("--analyze-headers", action='store_true', help="Analyze security headers")
    parser.add_argument("--filter", action='store_true', help="Show only vulnerable results")
    parser.add_argument("--no-bypass", action='store_true', help="Skip bypass attempts")
    
    # Advanced filter options
    parser.add_argument("--filter-severity", choices=['critical', 'high', 'medium', 'low'], help="Filter by minimum severity")
    parser.add_argument("--filter-vulnerable", action='store_true', help="Show only vulnerable URLs")
    parser.add_argument("--filter-pattern", help="Filter URLs containing pattern")
    
    # Config options
    parser.add_argument("--config", help="Config file path (JSON format)")
    parser.add_argument("--save-config", help="Save current settings to config file")
    
    # Connection options
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--proxy", help="Proxy URL (http://host:port)")
    parser.add_argument("--insecure", action='store_true', help="Disable SSL verification")
    parser.add_argument("--custom-origin", action='append', help="Add custom origin to bypass tests")
    parser.add_argument("--retries", type=int, default=2, help="Number of retries on failure (default: 2)")
    
    # Other options
    parser.add_argument("-v", "--verbose", action='store_true', help="Enable verbose logging")
    parser.add_argument("-h", "--help", action='store_true', help="Show help message")
    parser.add_argument("--version", action='store_true', help="Show version")
    
    return parser.parse_args()


def print_error(message: str):
    """Print error message to stderr."""
    sys.stderr.write(f"{Fore.RED}{message}{Style.RESET_ALL}\n")


def apply_filters(results, args):
    """Apply advanced filters to results."""
    # Apply severity filter
    if hasattr(args, 'filter_severity') and args.filter_severity:
        severity_map = {
            'critical': 'critical',
            'high': ['critical', 'high'],
            'medium': ['critical', 'high', 'medium'],
            'low': ['critical', 'high', 'medium', 'low']
        }
        severities = severity_map[args.filter_severity]
        results = quick_filter(results, severity=severities, vulnerable=True)
    
    # Apply vulnerable filter
    if hasattr(args, 'filter_vulnerable') and args.filter_vulnerable:
        results = get_vulnerable_urls(results)
    
    # Apply pattern filter
    if hasattr(args, 'filter_pattern') and args.filter_pattern:
        results = quick_filter(results, pattern=args.filter_pattern)
    
    return results


def main():
    """Main entry point for CLI."""
    print_logo()
    
    args = parse_arguments()
    
    # Show version
    if hasattr(args, 'version') and args.version:
        print(f"Corscan v{__version__}")
        sys.exit(0)
    
    # Setup logging
    global logger
    logger = setup_logging(verbose=args.verbose)
    
    if args.help:
        print_help()
        sys.exit(0)
    
    # Load config file if provided
    if hasattr(args, 'config') and args.config:
        logger.info(f"Loading config from {args.config}")
        config = Config(args.config)
        # Override args with config values
        if not hasattr(args, 'threads') or args.threads == DEFAULT_THREADS:
            args.threads = config.get('threads', DEFAULT_THREADS)
        if not hasattr(args, 'timeout') or args.timeout == DEFAULT_TIMEOUT:
            args.timeout = config.get('timeout', DEFAULT_TIMEOUT)
    
    if not args.url and not args.file:
        print_error("Error: Please provide -u (single URL) or -f (file with URLs). Use -h for help.")
        sys.exit(1)
    
    # Validate threads
    if args.threads < 1:
        print_error("Error: Threads must be at least 1")
        sys.exit(1)
    
    try:
        # Single URL scan (or discovered paths from single URL)
        if args.url:
            if args.discover_paths:
                urls = build_path_discovery_urls(args.url, args.paths_file)
                logger.info(f"Path discovery enabled: expanded to {len(urls)} URLs")

                # Don't output results immediately if we need to do analysis
                output_callback_func = None
                if not args.test_methods and not args.analyze_headers:
                    output_callback_func = output_handler

                stats = batch_check_cors(
                    urls=urls,
                    origin=args.origin,
                    verify_ssl=not args.insecure,
                    proxy=args.proxy,
                    timeout=args.timeout,
                    threads=args.threads,
                    check_bypass=not args.no_bypass,
                    custom_origins=args.custom_origin,
                    filter_vulnerable=args.filter,
                    output_file=args.output,
                    output_format=args.format,
                    output_callback=output_callback_func
                )

                # Collect results for export
                results = stats.get('results', [])

                # Apply advanced filters
                results = apply_filters(results, args)

                # Test HTTP methods if requested
                if args.test_methods and results:
                    logger.info("Testing HTTP methods for vulnerable URLs...")
                    from corscan.methods import test_http_methods
                    from corscan.utils import create_session

                    session = create_session(
                        verify_ssl=not args.insecure,
                        proxy=args.proxy
                    )

                    for result in results:
                        if result.vulnerable:
                            method_results = test_http_methods(
                                result.url, result.origin, session, args.timeout
                            )
                            result.bypass_attempts['http_methods'] = method_results

                # Analyze security headers if requested
                if args.analyze_headers and results:
                    logger.info("Analyzing security headers...")
                    from corscan.security_headers import analyze_security_headers
                    from corscan.utils import create_session

                    session = create_session(
                        verify_ssl=not args.insecure,
                        proxy=args.proxy
                    )

                    for result in results:
                        try:
                            response = session.get(
                                result.url,
                                timeout=args.timeout,
                                headers={'Origin': result.origin}
                            )
                            headers_analysis = analyze_security_headers(response)
                            result.bypass_attempts['security_headers'] = headers_analysis
                        except Exception as e:
                            logger.debug(f"Could not analyze headers for {result.url}: {e}")

                # Output results after analysis
                if (args.test_methods or args.analyze_headers) and results:
                    for result in results:
                        output_handler(result, args.format, args.output)

                # Export to CSV if requested
                if args.csv:
                    from corscan.exporters import export_to_csv
                    export_to_csv(results, args.csv)
                    logger.info(f"Results exported to CSV: {args.csv}")
                    print(f"{Fore.GREEN}✓ CSV exported to: {args.csv}{Style.RESET_ALL}")

                # Export to JSON if requested
                if args.json:
                    from corscan.exporters import export_to_json_file
                    export_to_json_file(results, args.json)
                    logger.info(f"Results exported to JSON: {args.json}")
                    print(f"{Fore.GREEN}✓ JSON exported to: {args.json}{Style.RESET_ALL}")

                # Generate HTML report if requested
                if args.html:
                    from corscan.report import generate_html_report
                    generate_html_report(results, args.html)
                    logger.info(f"HTML report generated: {args.html}")
                    print(f"{Fore.GREEN}✓ HTML report generated: {args.html}{Style.RESET_ALL}")

                print(format_summary(stats))
                if args.output:
                    print(f"{Fore.CYAN}Results saved to: {args.output}{Style.RESET_ALL}\n")

            else:
                logger.info(f"Scanning single URL: {args.url}")
                result = check_cors(
                    url=args.url,
                    origin=args.origin,
                    verify_ssl=not args.insecure,
                    proxy=args.proxy,
                    timeout=args.timeout,
                    check_bypass=not args.no_bypass,
                    custom_origins=args.custom_origin,
                    filter_vulnerable=args.filter
                )
            
                # Apply advanced filters to single result
                if result:
                    results_list = [result]
                    results_list = apply_filters(results_list, args)
                    result = results_list[0] if results_list else None
            
                if result:
                    # Test HTTP methods if requested
                    if args.test_methods and result.vulnerable:
                        logger.info("Testing HTTP methods...")
                        from corscan.methods import test_http_methods
                        from corscan.utils import create_session

                        session = create_session(
                            verify_ssl=not args.insecure,
                            proxy=args.proxy
                        )
                        method_results = test_http_methods(
                            result.url, result.origin, session, args.timeout
                        )
                        result.bypass_attempts['http_methods'] = method_results

                    # Analyze security headers if requested
                    if args.analyze_headers:
                        logger.info("Analyzing security headers...")
                        from corscan.security_headers import analyze_security_headers
                        from corscan.utils import create_session

                        session = create_session(
                            verify_ssl=not args.insecure,
                            proxy=args.proxy
                        )

                        try:
                            response = session.get(
                                result.url,
                                timeout=args.timeout,
                                headers={'Origin': result.origin}
                            )
                            headers_analysis = analyze_security_headers(response)
                            result.bypass_attempts['security_headers'] = headers_analysis
                        except Exception as e:
                            logger.debug(f"Could not analyze headers for {result.url}: {e}")

                    output_handler(result, args.format, args.output)

                    # Export single result if requested
                    single_results = [result]

                    if args.csv:
                        from corscan.exporters import export_to_csv
                        export_to_csv(single_results, args.csv)
                        logger.info(f"Results exported to CSV: {args.csv}")
                        print(f"{Fore.GREEN}✓ CSV exported to: {args.csv}{Style.RESET_ALL}")

                    if args.json:
                        from corscan.exporters import export_to_json_file
                        export_to_json_file(single_results, args.json)
                        logger.info(f"Results exported to JSON: {args.json}")
                        print(f"{Fore.GREEN}✓ JSON exported to: {args.json}{Style.RESET_ALL}")

                    if args.html:
                        from corscan.report import generate_html_report
                        generate_html_report(single_results, args.html)
                        logger.info(f"HTML report generated: {args.html}")
                        print(f"{Fore.GREEN}✓ HTML report generated: {args.html}{Style.RESET_ALL}")
        
        # Batch scan from file
        if args.file:
            urls, count = load_urls_from_file(args.file)
            if not urls:
                print_error("Error: No valid URLs found in file")
                sys.exit(1)

            if args.discover_paths:
                expanded_urls = []
                seen = set()

                for seed_url in urls:
                    discovered_urls = build_path_discovery_urls(seed_url, args.paths_file)
                    for discovered_url in discovered_urls:
                        if discovered_url not in seen:
                            seen.add(discovered_url)
                            expanded_urls.append(discovered_url)

                logger.info(
                    f"Path discovery enabled for file scan: expanded {count} seed URLs to {len(expanded_urls)} URLs"
                )
                urls = expanded_urls
            else:
                logger.info(f"Loaded {count} URLs from {args.file}")
            
            # Don't output results immediately if we need to do analysis
            output_callback_func = None
            if not args.test_methods and not args.analyze_headers:
                output_callback_func = output_handler
            
            stats = batch_check_cors(
                urls=urls,
                origin=args.origin,
                verify_ssl=not args.insecure,
                proxy=args.proxy,
                timeout=args.timeout,
                threads=args.threads,
                check_bypass=not args.no_bypass,
                custom_origins=args.custom_origin,
                filter_vulnerable=args.filter,
                output_file=args.output,
                output_format=args.format,
                output_callback=output_callback_func
            )
            
            # Collect results for export
            results = stats.get('results', [])
            
            # Apply advanced filters to batch results
            results = apply_filters(results, args)
            
            # Test HTTP methods if requested
            if args.test_methods and results:
                logger.info("Testing HTTP methods for vulnerable URLs...")
                from corscan.methods import test_http_methods
                from corscan.utils import create_session
                
                session = create_session(
                    verify_ssl=not args.insecure,
                    proxy=args.proxy
                )
                
                for result in results:
                    if result.vulnerable:
                        method_results = test_http_methods(
                            result.url, result.origin, session, args.timeout
                        )
                        result.bypass_attempts['http_methods'] = method_results
            
            # Analyze security headers if requested
            if args.analyze_headers and results:
                logger.info("Analyzing security headers...")
                from corscan.security_headers import analyze_security_headers
                from corscan.utils import create_session
                
                session = create_session(
                    verify_ssl=not args.insecure,
                    proxy=args.proxy
                )
                
                for result in results:
                    try:
                        response = session.get(
                            result.url, 
                            timeout=args.timeout,
                            headers={'Origin': result.origin}
                        )
                        headers_analysis = analyze_security_headers(response)
                        result.bypass_attempts['security_headers'] = headers_analysis
                    except Exception as e:
                        logger.debug(f"Could not analyze headers for {result.url}: {e}")
            
            # Output results after analysis (if analysis was performed)
            if (args.test_methods or args.analyze_headers) and results:
                for result in results:
                    output_handler(result, args.format, args.output)
            
            # Export to CSV if requested
            if args.csv:
                from corscan.exporters import export_to_csv
                export_to_csv(results, args.csv)
                logger.info(f"Results exported to CSV: {args.csv}")
                print(f"{Fore.GREEN}✓ CSV exported to: {args.csv}{Style.RESET_ALL}")
            
            # Export to JSON if requested
            if args.json:
                from corscan.exporters import export_to_json_file
                export_to_json_file(results, args.json)
                logger.info(f"Results exported to JSON: {args.json}")
                print(f"{Fore.GREEN}✓ JSON exported to: {args.json}{Style.RESET_ALL}")
            
            # Generate HTML report if requested
            if args.html:
                from corscan.report import generate_html_report
                generate_html_report(results, args.html)
                logger.info(f"HTML report generated: {args.html}")
                print(f"{Fore.GREEN}✓ HTML report generated: {args.html}{Style.RESET_ALL}")
            
            # Print summary
            print(format_summary(stats))
            if args.output:
                print(f"{Fore.CYAN}Results saved to: {args.output}{Style.RESET_ALL}\n")
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()
