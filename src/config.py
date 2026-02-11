"""
Configuration management for geoblock service.
Handles loading, parsing, and validating configuration from YAML files.
"""

import os
import logging
import yaml
import re
import geoip2.database
from .blocklist_fetcher import fetch_asn_list

logger = logging.getLogger(__name__)

# Configuration paths
CONFIG_PATH = os.getenv('CONFIG_PATH', '/app/config.yaml')
CONFIG_EXAMPLE_PATH = '/app/config.example.yaml'
COUNTRY_DB_PATH = os.getenv('COUNTRY_DB_PATH', '/data/GeoLite2-Country.mmdb')
ASN_DB_PATH = os.getenv('ASN_DB_PATH', '/data/GeoLite2-ASN.mmdb')


class Config:
    """Configuration container for geoblock service."""
    
    def __init__(self):
        """Initialize and load configuration."""
        # Load YAML config
        self.raw_config = self._load_yaml_config()
        
        # Parse settings FIRST (needed by other parsers for cache_hours)
        settings = self.raw_config.get('settings', {})
        self.allow_lan = os.getenv('ALLOW_LAN', str(settings.get('allow_lan', True))).lower() == 'true'
        self.allow_unknown = os.getenv('ALLOW_UNKNOWN', str(settings.get('allow_unknown', True))).lower() == 'true'
        self.use_html_response = os.getenv('USE_HTML_RESPONSE', str(settings.get('use_html_response', True))).lower() == 'true'
        self.cache_hours = int(os.getenv('CACHE_HOURS', str(settings.get('cache_hours', 168))))
        
        # Parse IP configuration
        ip_config = self.raw_config.get('ip', {})
        self.ip_mode = ip_config.get('mode', 'disabled')
        self.ip_whitelist = set(ip_config.get('whitelist', []))
        self.ip_blacklist = set(ip_config.get('blacklist', []))
        
        # Parse user-agent configuration (requires cache_hours)
        self._parse_user_agent_config(self.raw_config.get('user_agent', {}))
        
        # Parse country configuration
        country_config = self.raw_config.get('countries', {})
        self.country_mode = country_config.get('mode', 'disabled')
        self.country_whitelist = [c.upper() for c in country_config.get('whitelist', [])]
        self.country_blacklist = [c.upper() for c in country_config.get('blacklist', [])]
        
        # Parse ASN configuration
        asn_config = self.raw_config.get('asn', {})
        self.asn_mode = asn_config.get('mode', 'disabled')
        
        # Parse ASN whitelist (supports simple integers or objects with user-agent restrictions)
        self.asn_whitelist = {}  # dict: {asn_number: [user_agent_patterns] or None}
        for entry in asn_config.get('whitelist', []):
            if isinstance(entry, int):
                # Simple format: just the ASN number (no restrictions)
                self.asn_whitelist[entry] = None
            elif isinstance(entry, dict) and 'asn' in entry:
                # Complex format: ASN with user-agent restrictions
                asn = entry['asn']
                user_agents = entry.get('user_agents', [])
                self.asn_whitelist[asn] = user_agents if user_agents else None
            else:
                logger.warning(f"Invalid ASN whitelist entry: {entry}")
        
        self.asn_blacklist = set(asn_config.get('blacklist', []))
        
        # Fetch and merge remote ASN lists
        self._fetch_remote_asn_lists(asn_config)
        
        # Load HTML template
        self.block_page_template = self._load_html_template()
        
        # Validate configuration
        self._validate_config()
        
        # Parse domain-specific configurations
        self.domain_configs = {}
        domains = self.raw_config.get('domains', {})
        if domains:
            logger.info(f"Parsing {len(domains)} domain-specific configuration(s)")
            for domain, domain_config in domains.items():
                try:
                    self.domain_configs[domain.lower()] = self._parse_domain_config(domain, domain_config)
                    logger.info(f"Loaded configuration for domain: {domain}")
                except Exception as e:
                    logger.error(f"Failed to parse domain config for {domain}: {e}")
        
        # Load GeoIP databases
        self.country_reader = self._load_country_db()
        self.asn_reader = self._load_asn_db()
        
        # Log configuration
        self._log_config()
    
    def _parse_domain_config(self, domain, domain_config):
        """
        Parse domain-specific configuration.
        
        Returns a dict with overrides and whether to extend (merge) or replace.
        """
        parsed = {
            '_domain': domain,
            'extend_global': domain_config.get('extend_global', False),
            'overrides': {}
        }
        
        # Parse each section if present
        for section in ['ip', 'countries', 'asn', 'user_agent', 'settings']:
            if section in domain_config and section != 'extend_global':
                parsed['overrides'][section] = domain_config[section]
        
        return parsed
    
    def get_config_for_domain(self, host):
        """
        Get configuration for a specific domain with overrides applied.
        
        Args:
            host: The Host header value (e.g., "api.example.com" or "api.example.com:443")
        
        Returns:
            Config object (either a new merged config or self if no domain match)
        """
        if not host:
            return self
        
        # Strip port if present
        host = host.split(':')[0].lower()
        
        # Exact match first
        if host in self.domain_configs:
            return self._create_domain_config(self.domain_configs[host])
        
        # Check for wildcard matches (*.example.com)
        for domain_pattern, domain_config in self.domain_configs.items():
            if '*' in domain_pattern and fnmatch.fnmatch(host, domain_pattern):
                logger.debug(f"Domain '{host}' matched pattern '{domain_pattern}'")
                return self._create_domain_config(domain_config)
        
        # No match, return global config
        return self
    
    def _create_domain_config(self, domain_config):
        """
        Create a new Config object with domain-specific overrides applied.
        
        Args:
            domain_config: Parsed domain configuration dict
        
        Returns:
            New Config object with merged configuration
        """
        # Create a shallow copy of self
        domain_obj = object.__new__(Config)
        
        # Copy all attributes from global config
        for attr, value in self.__dict__.items():
            if not attr.startswith('domain_configs'):
                setattr(domain_obj, attr, value)
        
        # Apply overrides based on extend strategy
        is_extend = domain_config.get('extend_global', False)
        overrides = domain_config.get('overrides', {})
        
        # Apply IP overrides
        if 'ip' in overrides:
            ip_config = overrides['ip']
            if not is_extend or 'mode' in ip_config:
                domain_obj.ip_mode = ip_config.get('mode', self.ip_mode)
            if is_extend:
                # Extend: merge lists
                domain_obj.ip_whitelist = self.ip_whitelist | set(ip_config.get('whitelist', []))
                domain_obj.ip_blacklist = self.ip_blacklist | set(ip_config.get('blacklist', []))
            else:
                # Replace: use only domain config
                domain_obj.ip_whitelist = set(ip_config.get('whitelist', []))
                domain_obj.ip_blacklist = set(ip_config.get('blacklist', []))
        
        # Apply country overrides
        if 'countries' in overrides:
            country_config = overrides['countries']
            if not is_extend or 'mode' in country_config:
                domain_obj.country_mode = country_config.get('mode', self.country_mode)
            if is_extend:
                # Extend: merge lists
                domain_obj.country_whitelist = list(set(self.country_whitelist) | 
                                                   set(c.upper() for c in country_config.get('whitelist', [])))
                domain_obj.country_blacklist = list(set(self.country_blacklist) | 
                                                   set(c.upper() for c in country_config.get('blacklist', [])))
            else:
                # Replace: use only domain config
                domain_obj.country_whitelist = [c.upper() for c in country_config.get('whitelist', [])]
                domain_obj.country_blacklist = [c.upper() for c in country_config.get('blacklist', [])]
        
        # Apply ASN overrides
        if 'asn' in overrides:
            asn_config = overrides['asn']
            if not is_extend or 'mode' in asn_config:
                domain_obj.asn_mode = asn_config.get('mode', self.asn_mode)
            
            if is_extend:
                # Extend: merge lists
                domain_obj.asn_whitelist = dict(self.asn_whitelist)
                for entry in asn_config.get('whitelist', []):
                    if isinstance(entry, int):
                        domain_obj.asn_whitelist[entry] = None
                    elif isinstance(entry, dict) and 'asn' in entry:
                        asn = entry['asn']
                        user_agents = entry.get('user_agents', [])
                        domain_obj.asn_whitelist[asn] = user_agents if user_agents else None
                
                domain_obj.asn_blacklist = self.asn_blacklist | set(asn_config.get('blacklist', []))
            else:
                # Replace: use only domain config
                domain_obj.asn_whitelist = {}
                for entry in asn_config.get('whitelist', []):
                    if isinstance(entry, int):
                        domain_obj.asn_whitelist[entry] = None
                    elif isinstance(entry, dict) and 'asn' in entry:
                        asn = entry['asn']
                        user_agents = entry.get('user_agents', [])
                        domain_obj.asn_whitelist[asn] = user_agents if user_agents else None
                
                domain_obj.asn_blacklist = set(asn_config.get('blacklist', []))
        
        # Apply user_agent overrides
        if 'user_agent' in overrides:
            ua_config = overrides['user_agent']
            if not is_extend or 'mode' in ua_config:
                domain_obj.user_agent_mode = ua_config.get('mode', self.user_agent_mode)
            
            # For user-agent, we don't re-compile regexes for domains (performance reasons)
            # Users should use extend mode sparingly or accept global patterns
            if not is_extend:
                # Replace mode: recompile with domain-specific patterns only
                whitelist_entries = set(ua_config.get('whitelist', []))
                blacklist_entries = set(ua_config.get('blacklist', []))
                
                domain_obj.user_agent_whitelist_regex = self._compile_user_agent_regex(whitelist_entries)
                domain_obj.user_agent_blacklist_regex = self._compile_user_agent_regex(blacklist_entries)
                domain_obj.user_agent_whitelist_count = len(whitelist_entries)
                domain_obj.user_agent_blacklist_count = len(blacklist_entries)
            # Note: extend mode keeps global regex patterns (no merge for performance)
        
        # Apply settings overrides
        if 'settings' in overrides:
            settings = overrides['settings']
            if 'allow_lan' in settings:
                domain_obj.allow_lan = settings['allow_lan']
            if 'allow_unknown' in settings:
                domain_obj.allow_unknown = settings['allow_unknown']
            if 'use_html_response' in settings:
                domain_obj.use_html_response = settings['use_html_response']
        
        logger.debug(f"Created domain config for '{domain_config.get('_domain', 'unknown')}'")
        return domain_obj
    
    def _load_yaml_config(self):
        """Load configuration from YAML file."""
        # Try custom config first, then fall back to example
        config_paths = [CONFIG_PATH, CONFIG_EXAMPLE_PATH]
        
        for path in config_paths:
            try:
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        config = yaml.safe_load(f)
                        logger.info(f"Loaded configuration from {path}")
                        return config
            except Exception as e:
                logger.error(f"Failed to load config from {path}: {e}")
        
        logger.warning("No config file found, using empty defaults")
        return {}
    
    def _parse_user_agent_config(self, ua_config):
        """Parse user-agent filtering configuration with regex optimization."""
        self.user_agent_mode = ua_config.get('mode', 'disabled').lower()
        
        if self.user_agent_mode not in ['whitelist', 'blacklist', 'disabled']:
            logger.warning(f"Invalid user_agent mode '{self.user_agent_mode}', defaulting to 'disabled'")
            self.user_agent_mode = 'disabled'
        
        # Fetch remote user-agent lists
        remote_whitelist = self._fetch_remote_user_agent_lists(ua_config.get('whitelist_urls', []))
        remote_blacklist = self._fetch_remote_user_agent_lists(ua_config.get('blacklist_urls', []))
        
        # Combine manual and remote entries
        whitelist_entries = set(ua_config.get('whitelist', [])) | remote_whitelist
        blacklist_entries = set(ua_config.get('blacklist', [])) | remote_blacklist
        
        # Compile regex patterns for efficient substring matching
        self.user_agent_whitelist_regex = self._compile_user_agent_regex(whitelist_entries)
        self.user_agent_blacklist_regex = self._compile_user_agent_regex(blacklist_entries)
        
        # Store counts for logging/health endpoint
        self.user_agent_whitelist_count = len(whitelist_entries)
        self.user_agent_blacklist_count = len(blacklist_entries)
    
    def _compile_user_agent_regex(self, patterns):
        """Compile user-agent patterns into a single optimized regex for substring matching."""
        if not patterns:
            return None
        
        # Escape special regex characters and join with alternation
        escaped_patterns = [re.escape(pattern.strip()) for pattern in patterns if pattern.strip()]
        
        if not escaped_patterns:
            return None
        
        # Combine into single regex: (pattern1|pattern2|pattern3|...)
        combined_pattern = '|'.join(escaped_patterns)
        
        # Compile with case-insensitive flag for substring matching
        return re.compile(combined_pattern, re.IGNORECASE)
    
    def _fetch_remote_user_agent_lists(self, urls):
        """Fetch user-agent lists from remote URLs."""
        if not urls:
            return set()
        
        logger.info(f"Fetching user-agent lists from {len(urls)} source(s)")
        from .blocklist_fetcher import fetch_text_list
        all_entries = set()
        
        for url in urls:
            try:
                entries = fetch_text_list(
                    url,
                    cache_hours=self.cache_hours,
                    list_type='user-agent'
                )
                all_entries.update(entries)
                logger.info(f"Loaded {len(entries)} user-agents from {url}")
            except Exception as e:
                logger.error(f"Failed to fetch user-agent list from {url}: {e}")
        
        return all_entries
    
    def _fetch_remote_asn_lists(self, asn_config):
        """Fetch and merge remote ASN lists with local lists."""
        # Fetch blacklist URLs
        blacklist_urls = asn_config.get('blacklist_urls', [])
        if blacklist_urls:
            logger.info(f"Fetching ASN lists from {len(blacklist_urls)} source(s)")
            manual_count = len(asn_config.get('blacklist', []))
            for source in blacklist_urls:
                remote_asns = fetch_asn_list(source, cache_hours=self.cache_hours)
                self.asn_blacklist.update(remote_asns)
            logger.info(f"Total ASN blacklist size: {len(self.asn_blacklist)} "
                       f"(including {manual_count} manual entries)")
        
        # Fetch whitelist URLs
        whitelist_urls = asn_config.get('whitelist_urls', [])
        if whitelist_urls:
            logger.info(f"Fetching ASN whitelist from {len(whitelist_urls)} source(s)")
            for source in whitelist_urls:
                remote_asns = fetch_asn_list(source, cache_hours=self.cache_hours)
                self.asn_whitelist.update(remote_asns)
            logger.info(f"Total ASN whitelist size: {len(self.asn_whitelist)}")
    
    def _load_html_template(self):
        """Load HTML block page template."""
        try:
            with open('/app/block_page.html', 'r') as f:
                template = f.read()
            logger.info("Loaded HTML block page template")
            return template
        except Exception as e:
            logger.warning(f"Could not load HTML template: {e}, using JSON responses only")
            return None
    
    def _validate_config(self):
        """Validate configuration settings."""
        # This condition can never be true (same variable), but keeping for consistency
        if self.country_mode == 'whitelist' and self.country_mode == 'blacklist':
            logger.error("Country mode cannot be both whitelist and blacklist")
            raise ValueError("Set country mode to either 'whitelist', 'blacklist', or 'disabled'")
        
        if self.asn_mode == 'whitelist' and self.asn_mode == 'blacklist':
            logger.error("ASN mode cannot be both whitelist and blacklist")
            raise ValueError("Set ASN mode to either 'whitelist', 'blacklist', or 'disabled'")
    
    def _load_country_db(self):
        """Load GeoIP2 Country database."""
        try:
            if os.path.exists(COUNTRY_DB_PATH):
                reader = geoip2.database.Reader(COUNTRY_DB_PATH)
                logger.info(f"Loaded Country database from {COUNTRY_DB_PATH}")
                return reader
            else:
                logger.warning(f"Country database not found at {COUNTRY_DB_PATH}")
                return None
        except Exception as e:
            logger.error(f"Failed to load Country database: {e}")
            return None
    
    def _load_asn_db(self):
        """Load GeoIP2 ASN database."""
        try:
            if os.path.exists(ASN_DB_PATH):
                reader = geoip2.database.Reader(ASN_DB_PATH)
                logger.info(f"Loaded ASN database from {ASN_DB_PATH}")
                return reader
            else:
                logger.warning(f"ASN database not found at {ASN_DB_PATH}")
                return None
        except Exception as e:
            logger.error(f"Failed to load ASN database: {e}")
            return None
    
    def _log_config(self):
        """Log configuration details."""
        logger.info("Configuration:")
        logger.info(f"  Country mode: {self.country_mode}")
        logger.info(f"  Country whitelist: {self.country_whitelist}")
        logger.info(f"  Country blacklist: {self.country_blacklist}")
        logger.info(f"  ASN mode: {self.asn_mode}")
        logger.info(f"  User-Agent mode: {self.user_agent_mode}")
        if self.user_agent_mode != 'disabled':
            logger.info(f"  User-Agent whitelist: {self.user_agent_whitelist_count} patterns")
            logger.info(f"  User-Agent blacklist: {self.user_agent_blacklist_count} patterns")
        logger.info(f"  IP mode: {self.ip_mode}")
        logger.info(f"  IP whitelist: {self.ip_whitelist}")
        logger.info(f"  IP blacklist: {self.ip_blacklist}")
        logger.info(f"  ASN whitelist: {len(self.asn_whitelist)} total, "
                   f"{sum(1 for p in self.asn_whitelist.values() if p)} conditional")
        logger.info(f"  ASN blacklist: {self.asn_blacklist}")
        logger.info(f"  ALLOW_LAN: {self.allow_lan}")
        logger.info(f"  ALLOW_UNKNOWN: {self.allow_unknown}")
        if self.domain_configs:
            logger.info(f"  Domain-specific configs: {len(self.domain_configs)} domain(s)")
            for domain in self.domain_configs.keys():
                logger.info(f"    - {domain}")
