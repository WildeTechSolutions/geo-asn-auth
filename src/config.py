"""
Configuration management for geoblock service.
Handles loading, parsing, and validating configuration from YAML files.
"""

import os
import logging
import yaml
import geoip2.database
from .blocklist_fetcher import fetch_asn_list

logger = logging.getLogger(__name__)

# Configuration paths
CONFIG_PATH = os.getenv('CONFIG_PATH', '/app/config.yaml')
CONFIG_EXAMPLE_PATH = '/app/config.yaml.example'
COUNTRY_DB_PATH = os.getenv('COUNTRY_DB_PATH', '/data/GeoLite2-Country.mmdb')
ASN_DB_PATH = os.getenv('ASN_DB_PATH', '/data/GeoLite2-ASN.mmdb')


class Config:
    """Configuration container for geoblock service."""
    
    def __init__(self):
        """Initialize and load configuration."""
        # Load YAML config
        self.raw_config = self._load_yaml_config()
        
        # Parse IP configuration
        ip_config = self.raw_config.get('ip', {})
        self.ip_mode = ip_config.get('mode', 'disabled')
        self.ip_whitelist = set(ip_config.get('whitelist', []))
        self.ip_blacklist = set(ip_config.get('blacklist', []))
        
        # Parse country configuration
        country_config = self.raw_config.get('countries', {})
        self.country_mode = country_config.get('mode', 'disabled')
        self.country_whitelist = [c.upper() for c in country_config.get('whitelist', [])]
        self.country_blacklist = [c.upper() for c in country_config.get('blacklist', [])]
        
        # Parse ASN configuration
        asn_config = self.raw_config.get('asn', {})
        self.asn_mode = asn_config.get('mode', 'disabled')
        self.asn_whitelist = set(asn_config.get('whitelist', []))
        self.asn_blacklist = set(asn_config.get('blacklist', []))
        
        # Parse settings (with environment variable overrides)
        settings = self.raw_config.get('settings', {})
        self.allow_lan = os.getenv('ALLOW_LAN', str(settings.get('allow_lan', True))).lower() == 'true'
        self.allow_unknown = os.getenv('ALLOW_UNKNOWN', str(settings.get('allow_unknown', True))).lower() == 'true'
        self.use_html_response = os.getenv('USE_HTML_RESPONSE', str(settings.get('use_html_response', True))).lower() == 'true'
        self.cache_hours = int(os.getenv('CACHE_HOURS', str(settings.get('cache_hours', 168))))
        
        # Fetch and merge remote ASN lists
        self._fetch_remote_asn_lists(asn_config)
        
        # Load HTML template
        self.block_page_template = self._load_html_template()
        
        # Validate configuration
        self._validate_config()
        
        # Load GeoIP databases
        self.country_reader = self._load_country_db()
        self.asn_reader = self._load_asn_db()
        
        # Log configuration
        self._log_config()
    
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
        logger.info(f"  IP mode: {self.ip_mode}")
        logger.info(f"  IP whitelist: {self.ip_whitelist}")
        logger.info(f"  IP blacklist: {self.ip_blacklist}")
        logger.info(f"  ASN whitelist: {self.asn_whitelist}")
        logger.info(f"  ASN blacklist: {self.asn_blacklist}")
        logger.info(f"  ALLOW_LAN: {self.allow_lan}")
        logger.info(f"  ALLOW_UNKNOWN: {self.allow_unknown}")
