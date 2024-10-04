import argparse
import requests
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import sys
from urllib.parse import urlparse

from colorama import Fore, Style


def print_logo():
    logo = f"""
    {Fore.LIGHTCYAN_EX}╔═════════════════[{Fore.CYAN} C O R S C A N {Fore.LIGHTCYAN_EX}]═════════════════╗
    {Fore.LIGHTCYAN_EX}║{Fore.YELLOW}            Developed By: Angix Black              {Fore.LIGHTCYAN_EX}║
    ╚═══════════════════════════════════════════════════╝{Style.RESET_ALL}

    {Fore.RED}                               DISCLAIMER

         This tool is for ethical hacking,legal and educational use only. 
                   Any illegal use is strictly prohibited.{Style.RESET_ALL}
    """
    
    print(logo)
 

def print_error(message, show_error=True):
    if show_error:
        sys.stderr.write(f"{Fore.RED}Error: {message}{Style.RESET_ALL}\n")
     

def is_vulnerable(response, origin):
    allow_origin = response.headers.get('Access-Control-Allow-Origin', '')
    allow_credentials = response.headers.get('Access-Control-Allow-Credentials', 'false')
    
    if allow_origin == '*' and allow_credentials.lower() == 'true':
        return True
    
    if allow_origin == origin and allow_credentials.lower() == 'true':
        return True
    
    if allow_origin == '*' or allow_origin == origin:
        return True
    
    return False


def attempt_bypass(url):
    # Extract the domain from the URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    bypass_strategies = [
        'null',  # Use 'null' as the Origin
        'https://subdomain.evil.com',  # Use a subdomain
        'http://localhost',  # Use localhost as Origin
        'file://',  # Use file scheme
        f'https://{domain}.evil.com',  # Add ".evil.com" to the domain
        f'https://evil.com.{domain}',  # Add "evil.com." before the domain
        f'https://{domain}.com',  # Append ".com" to the domain
        f'http://{domain}',  # Use HTTP version of the domain
        f'http://{domain}.evil',  # Add ".evil" to the domain
        f'https://{domain.split(".")[0]}.evil.com',  # Use subdomain only with ".evil.com"
    ]

    bypass_results = {}

    for origin in bypass_strategies:
        headers = {'Origin': origin}
        try:
            response = requests.options(url, headers=headers, timeout=10)
            if is_vulnerable(response, origin):
                bypass_results[origin] = True
            else:
                bypass_results[origin] = False
        except requests.RequestException:
            bypass_results[origin] = 'Failed'

    return bypass_results

def check_cors(url, origin, output_file=None, output_format='text', filter_vulnerable=False):
    try:
        headers = {'Origin': origin}

        response = requests.options(url, headers=headers, timeout=10)
        cors_headers = ['Access-Control-Allow-Origin', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Credentials']

        result = {
            'url': url,
            'origin': origin,
            'status_code': response.status_code,
            'vulnerable': is_vulnerable(response, origin),
            'headers': {header: response.headers.get(header, 'Not Present') for header in cors_headers}
        }

        bypass_results = attempt_bypass(url)
        bypass_success = any(result == True for result in bypass_results.values())

        # Filter results if needed
        if filter_vulnerable and not (result['vulnerable'] or bypass_success):
            return

        # Filter bypass results if needed
        if filter_vulnerable:
            bypass_results = {origin: result for origin, result in bypass_results.items() if result == True}

        if output_format == 'json':
            result['bypass_attempts'] = bypass_results
            result_output = json.dumps(result, indent=4)
        else:
            result_output = []
            result_output.append(f"{Fore.CYAN}URL:{Style.RESET_ALL} {url}")
            result_output.append(f"{Fore.CYAN}Origin:{Style.RESET_ALL} {origin}")
            result_output.append(f"{Fore.CYAN}Status Code:{Style.RESET_ALL} {response.status_code}")

            if result['vulnerable']:
                result_output.append(f"{Fore.RED}Potential Vulnerability Detected!{Style.RESET_ALL}")
            else:
                result_output.append(f"{Fore.GREEN}No CORS Vulnerability Detected{Style.RESET_ALL}")

            for header, value in result['headers'].items():
                if value != 'Not Present':
                    result_output.append(f"{Fore.MAGENTA}{header}:{Style.RESET_ALL} {value}")

            if not result['headers']:
                result_output.append(f"{Fore.YELLOW}CORS Headers Not Found{Style.RESET_ALL}")

            result_output.append(f"{Fore.YELLOW}CORS Bypass Attempts:{Style.RESET_ALL}")
            for origin, result in bypass_results.items():
                if result == 'Failed':
                    result_output.append(f"{Fore.CYAN}{origin}:{Style.RESET_ALL} {Fore.RED}Request Failed{Style.RESET_ALL}")
                else:
                    result_output.append(f"{Fore.CYAN}{origin}:{Style.RESET_ALL} {Fore.GREEN}{'Successful' if result else 'Failed'}{Style.RESET_ALL}")

            result_output.append("-" * 50)
            result_output = "\n".join(result_output)

        print(result_output)

        if output_file:
            try:
                with open(output_file, 'a') as f:
                    f.write(result_output + "\n")
            except IOError as e:
                print_error(f"Failed to write to output file {output_file}: {e}")

    except requests.RequestException as e:
        print_error(f"Could not connect to {url}. The URL may be invalid or unreachable.", not filter_vulnerable)

def print_help():
    help_text = f"""
{Fore.GREEN}Usage:{Style.RESET_ALL}
      crsn [options]

{Fore.YELLOW}Options:{Style.RESET_ALL}
  {Fore.CYAN}-u, --url{Style.RESET_ALL}       Target URL to check CORS headers
  {Fore.CYAN}-f, --file{Style.RESET_ALL}      File containing a list of URLs to check CORS headers
  {Fore.CYAN}-r, --origin{Style.RESET_ALL}    Custom origin to use for the CORS check (default: https://evil.com)
  {Fore.CYAN}-t, --threads{Style.RESET_ALL}   Number of threads to use for scanning (default: 20)
  {Fore.CYAN}-o, --output{Style.RESET_ALL}    File to save the output
  {Fore.CYAN}--format{Style.RESET_ALL}         Output format: text (default) or json
  {Fore.CYAN}--filter{Style.RESET_ALL}        Filter results to show only vulnerable entries
  {Fore.CYAN}-h, --help{Style.RESET_ALL}      Show this help message and exit

{Fore.YELLOW}Description:{Style.RESET_ALL}
  Advanced CORS Header Checker Tool with Vulnerability Detection and Bypass Attempts.
    """
    print(help_text)

def main():
    print_logo()

    parser = argparse.ArgumentParser(add_help=False)  # Disable default help
    parser.add_argument("-u", "--url", help="Target URL to check CORS headers")
    parser.add_argument("-f", "--file", help="File containing a list of URLs to check CORS headers")
    parser.add_argument("-r", "--origin", default="https://evil.com", help="Custom origin to use for the CORS check (default: https://evil.com)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads to use for scanning (default: 20)")
    parser.add_argument("-o", "--output", help="File to save the output")
    parser.add_argument("--format", choices=['text', 'json'], default='text', help="Output format: text (default) or json")
    parser.add_argument("--filter", action='store_true', help="Filter results to show only vulnerable entries")
    parser.add_argument("-h", "--help", action='store_true', help="Show help message and exit")

    args = parser.parse_args()

    if args.help:
        print_help()
        sys.exit(0)

    if not args.url and not args.file:
        print_error("Please provide a URL with -u or a file with -f or -h for help.")
        sys.exit(1)

    try:
        if args.url:
            check_cors(args.url, origin=args.origin, output_file=args.output, output_format=args.format, filter_vulnerable=args.filter)

        if args.file:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = [executor.submit(check_cors, url, origin=args.origin, output_file=args.output, output_format=args.format, filter_vulnerable=args.filter) for url in urls]
                for future in as_completed(futures):
                    future.result()
    
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
