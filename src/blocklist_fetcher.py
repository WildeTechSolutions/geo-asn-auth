"""
Blocklist fetcher and caching functionality.
Handles downloading and caching ASN lists from remote URLs or local files.
"""

import os
import logging
import hashlib
import time
import requests

logger = logging.getLogger(__name__)

# Cache directory for downloaded ASN lists
CACHE_DIR = '/blocklists'
os.makedirs(CACHE_DIR, exist_ok=True)


def fetch_asn_list(source, timeout=10, cache_hours=168):
    """
    Fetch ASN list from remote URL or local file path.
    
    Args:
        source: URL or file path to fetch ASN list from
        timeout: Request timeout in seconds (default: 10)
        cache_hours: Cache validity period in hours (default: 168 = 7 days)
    
    Returns:
        List of ASN numbers (integers)
    """
    try:
        # Handle local file paths
        if source.startswith('file://') or source.startswith('/'):
            file_path = source.replace('file://', '')
            logger.info(f"Reading ASN list from local file: {file_path}")
            with open(file_path, 'r') as f:
                content = f.read()
        else:
            # Handle remote URLs with caching
            content = _fetch_remote_asn_list(source, timeout, cache_hours)
        
        # Parse ASNs from content
        asns = _parse_asn_content(content, source)
        logger.info(f"Loaded {len(asns)} ASNs from {source}")
        return asns
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch ASN list from {source}: {e}")
        return []
    except FileNotFoundError as e:
        logger.error(f"Local file not found: {source}: {e}")
        return []
    except Exception as e:
        logger.error(f"Error loading ASN list from {source}: {e}")
        return []


def _fetch_remote_asn_list(source, timeout, cache_hours):
    """
    Fetch ASN list from remote URL with caching support.
    
    Args:
        source: URL to fetch from
        timeout: Request timeout in seconds
        cache_hours: Cache validity period in hours
    
    Returns:
        Content of the ASN list as string
    """
    # Generate cache filename from URL hash
    url_hash = hashlib.md5(source.encode()).hexdigest()
    cache_file = os.path.join(CACHE_DIR, f"asn_list_{url_hash}.txt")
    cache_time_file = os.path.join(CACHE_DIR, f"asn_list_{url_hash}.time")
    
    # Check if cached file exists and is recent
    content = _read_cache_if_valid(cache_file, cache_time_file, cache_hours, source)
    
    # Fetch from URL if no valid cache
    if content is None:
        logger.info(f"Fetching ASN list from {source}")
        response = requests.get(source, timeout=timeout)
        response.raise_for_status()
        content = response.text
        
        # Save to cache
        _save_to_cache(cache_file, cache_time_file, content, source)
    
    return content


def _read_cache_if_valid(cache_file, cache_time_file, cache_hours, source):
    """
    Read cached ASN list if it exists and is still valid.
    
    Returns:
        Cached content as string, or None if cache is invalid/missing
    """
    if os.path.exists(cache_file) and os.path.exists(cache_time_file):
        try:
            with open(cache_time_file, 'r') as f:
                cache_timestamp = float(f.read().strip())
            
            # Check if cache is still valid
            age_hours = (time.time() - cache_timestamp) / 3600
            if age_hours < cache_hours:
                logger.info(f"Using cached ASN list from {source} (age: {age_hours:.1f}h)")
                with open(cache_file, 'r') as f:
                    return f.read()
            else:
                logger.info(f"Cache expired for {source} (age: {age_hours:.1f}h), fetching fresh data")
                return None
        except Exception as e:
            logger.warning(f"Error reading cache: {e}, fetching fresh data")
            return None
    
    return None


def _save_to_cache(cache_file, cache_time_file, content, source):
    """Save fetched content to cache files."""
    try:
        with open(cache_file, 'w') as f:
            f.write(content)
        with open(cache_time_file, 'w') as f:
            f.write(str(time.time()))
        logger.info(f"Cached ASN list from {source}")
    except Exception as e:
        logger.warning(f"Failed to cache ASN list: {e}")


def _parse_asn_content(content, source):
    """
    Parse ASN numbers from content.
    
    Args:
        content: Text content containing ASN numbers (one per line)
        source: Source identifier for logging
    
    Returns:
        List of ASN numbers (integers)
    """
    asns = []
    for line in content.splitlines():
        line = line.strip()
        # Skip comments and empty lines
        if not line or line.startswith('#'):
            continue
        # Try to parse as integer
        try:
            asn = int(line)
            asns.append(asn)
        except ValueError:
            continue
    
    return asns
