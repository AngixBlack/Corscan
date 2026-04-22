"""
Batch scanning and processing functionality.
"""

import time
import logging
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from corscan.core import check_cors
from corscan.models import CORSResult
from corscan.constants import DEFAULT_TIMEOUT, DEFAULT_THREADS

logger = logging.getLogger(__name__)


def load_urls_from_file(file_path: str) -> tuple:
    """
    Load URLs from file, ignoring empty lines and comments.
    
    Args:
        file_path: Path to file containing URLs
        
    Returns:
        Tuple of (urls_list, count)
    """
    urls = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    urls.append(line)
        return urls, len(urls)
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return [], 0
    except Exception as e:
        logger.error(f"Error reading file '{file_path}': {e}")
        return [], 0


def batch_check_cors(
    urls: List[str],
    origin: str = "https://evil.com",
    verify_ssl: bool = True,
    proxy: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    threads: int = DEFAULT_THREADS,
    check_bypass: bool = True,
    custom_origins: Optional[List[str]] = None,
    filter_vulnerable: bool = False,
    output_file: Optional[str] = None,
    output_format: str = 'text',
    output_callback=None
) -> Dict:
    """
    Check multiple URLs with progress tracking.
    
    Args:
        urls: List of URLs to check
        origin: Custom origin header
        verify_ssl: Verify SSL certificates
        proxy: Proxy URL
        timeout: Request timeout
        threads: Number of worker threads
        check_bypass: Perform bypass attempts
        custom_origins: Custom origins to test
        filter_vulnerable: Only return vulnerable results
        output_file: Save results to file
        output_format: Output format ('text' or 'json')
        output_callback: Callback function for output handling
        
    Returns:
        Statistics dictionary
    """
    start_time = time.time()
    results = []
    completed = 0
    vulnerable_count = 0
    
    logger.info(f"Starting scan of {len(urls)} URLs with {threads} threads...")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(
                check_cors,
                url=url,
                origin=origin,
                verify_ssl=verify_ssl,
                proxy=proxy,
                timeout=timeout,
                check_bypass=check_bypass,
                custom_origins=custom_origins,
                filter_vulnerable=filter_vulnerable
            ): url for url in urls
        }
        
        for future in as_completed(futures):
            completed += 1
            url = futures[future]
            try:
                result = future.result()
                if result:
                    results.append(result)
                    if result.vulnerable:
                        vulnerable_count += 1
                    
                    # Output result
                    if output_callback:
                        output_callback(result, output_format, output_file)
                    
                    # Progress indicator
                    progress = (completed / len(urls)) * 100
                    logger.info(f"Progress: {completed}/{len(urls)} ({progress:.1f}%) - Vulnerable: {vulnerable_count}")
            except Exception as e:
                logger.error(f"Error processing {url}: {e}")
    
    elapsed = time.time() - start_time
    
    return {
        'total_scanned': len(urls),
        'results_returned': len(results),
        'vulnerable_found': vulnerable_count,
        'time_elapsed': elapsed,
        'avg_time_per_url': elapsed / len(urls) if urls else 0,
        'threads_used': threads,
        'results': results
    }
