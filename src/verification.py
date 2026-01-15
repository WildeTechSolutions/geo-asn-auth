"""
Core verification logic for IP, country, and ASN-based blocking.
"""

import logging
from flask import jsonify
from geoip2.errors import AddressNotFoundError
from .utils import is_private_ip, get_client_ip, render_block_page

logger = logging.getLogger(__name__)


def verify_request(config):
    """
    Verify if the incoming request should be allowed or blocked.
    
    Args:
        config: Config object containing all configuration settings
    
    Returns:
        Flask Response tuple: (response_body, status_code)
        - ('', 200) for allowed requests
        - (error_response, 403) for blocked requests
    """
    try:
        client_ip = get_client_ip()
        
        # Allow private IPs if configured
        if config.allow_lan and is_private_ip(client_ip):
            logger.debug(f"Allowing private IP: {client_ip}")
            return '', 200
        
        # Check IP whitelist/blacklist if configured
        ip_result = _check_ip(client_ip, config)
        if ip_result is not None:
            return ip_result
        
        # Check country if configured
        country_result = _check_country(client_ip, config)
        if country_result is not None:
            return country_result
        
        # Check ASN if configured
        asn_result = _check_asn(client_ip, config)
        if asn_result is not None:
            return asn_result
        
        # All checks passed
        return '', 200
        
    except Exception as e:
        logger.error(f"Error processing request: {e}", exc_info=True)
        # Fail open (allow) on errors to prevent service disruption
        return '', 200


def _check_ip(client_ip, config):
    """
    Check IP whitelist/blacklist.
    
    Returns:
        Response tuple if request should be blocked/allowed, None to continue checks
    """
    if config.ip_mode == 'disabled':
        return None
    
    logger.debug(f"IP check: mode={config.ip_mode}, client_ip={client_ip}, "
                f"whitelist={config.ip_whitelist}, in_whitelist={client_ip in config.ip_whitelist}")
    
    # In blacklist mode: whitelist = bypass all checks, blacklist = immediate block
    if config.ip_mode == 'blacklist':
        if config.ip_whitelist and client_ip in config.ip_whitelist:
            logger.info(f"Allowing IP {client_ip} (in IP whitelist, bypassing all checks)")
            return '', 200
        if config.ip_blacklist and client_ip in config.ip_blacklist:
            logger.info(f"Blocked IP {client_ip} (in IP blacklist)")
            return render_block_page(
                "Your IP address has been blocked.",
                client_ip,
                use_html_response=config.use_html_response,
                block_page_template=config.block_page_template
            )
    
    # In whitelist mode: only whitelisted IPs allowed (others continue to country/ASN checks)
    elif config.ip_mode == 'whitelist':
        if config.ip_whitelist and client_ip in config.ip_whitelist:
            logger.info(f"Allowing IP {client_ip} (in IP whitelist)")
            return '', 200
        # Not in whitelist - continue to country/ASN checks
    
    return None


def _check_country(client_ip, config):
    """
    Check country whitelist/blacklist.
    
    Returns:
        Response tuple if request should be blocked, None to continue checks
    """
    if not config.country_reader or config.country_mode == 'disabled':
        return None
    
    try:
        country_response = config.country_reader.country(client_ip)
        country_code = country_response.country.iso_code
        country_name = country_response.country.name
        
        # Whitelist mode: only allow listed countries
        if config.country_mode == 'whitelist' and config.country_whitelist:
            if country_code not in config.country_whitelist:
                logger.info(f"Blocked IP {client_ip} from country {country_code} (not in whitelist)")
                return render_block_page(
                    f"Access from {country_name} ({country_code}) is not permitted.",
                    client_ip,
                    country=f"{country_name} ({country_code})",
                    use_html_response=config.use_html_response,
                    block_page_template=config.block_page_template
                )
        
        # Blacklist mode: block listed countries
        elif config.country_mode == 'blacklist' and config.country_blacklist:
            if country_code in config.country_blacklist:
                logger.info(f"Blocked IP {client_ip} from country {country_code} (in blacklist)")
                return render_block_page(
                    f"Access from {country_name} ({country_code}) is not permitted.",
                    client_ip,
                    country=f"{country_name} ({country_code})",
                    use_html_response=config.use_html_response,
                    block_page_template=config.block_page_template
                )
        
        logger.debug(f"Country check passed for {client_ip}: {country_code}")
        
    except AddressNotFoundError:
        logger.warning(f"Country not found for IP: {client_ip}")
        if not config.allow_unknown:
            logger.info(f"Blocked IP {client_ip} (country not found, ALLOW_UNKNOWN=false)")
            return jsonify({"error": "Geographic data unavailable"}), 403
    
    return None


def _check_asn(client_ip, config):
    """
    Check ASN whitelist/blacklist.
    
    Returns:
        Response tuple if request should be blocked, None to continue checks
    """
    if not config.asn_reader or config.asn_mode == 'disabled':
        return None
    
    try:
        asn_response = config.asn_reader.asn(client_ip)
        asn_number = asn_response.autonomous_system_number
        asn_org = asn_response.autonomous_system_organization
        
        # Whitelist mode: only allow listed ASNs (strict mode)
        if config.asn_mode == 'whitelist':
            if not config.asn_whitelist or asn_number not in config.asn_whitelist:
                logger.info(f"Blocked IP {client_ip} from ASN {asn_number} (not in whitelist)")
                return render_block_page(
                    f"Access from your network (AS{asn_number}) is not permitted.",
                    client_ip,
                    asn=f"AS{asn_number} - {asn_org}",
                    use_html_response=config.use_html_response,
                    block_page_template=config.block_page_template
                )
        
        # Blacklist mode: block listed ASNs, but allow whitelisted exceptions
        elif config.asn_mode == 'blacklist':
            # Check whitelist first (exceptions to blacklist)
            if config.asn_whitelist and asn_number in config.asn_whitelist:
                logger.debug(f"Allowing IP {client_ip} from ASN {asn_number} (whitelisted exception)")
            # Then check blacklist
            elif config.asn_blacklist and asn_number in config.asn_blacklist:
                logger.info(f"Blocked IP {client_ip} from ASN {asn_number} (in blacklist)")
                return render_block_page(
                    f"Access from your network (AS{asn_number}) is not permitted.",
                    client_ip,
                    asn=f"AS{asn_number} - {asn_org}",
                    use_html_response=config.use_html_response,
                    block_page_template=config.block_page_template
                )
        
        logger.debug(f"ASN check passed for {client_ip}: {asn_number}")
        
    except AddressNotFoundError:
        logger.warning(f"ASN not found for IP: {client_ip}")
        if not config.allow_unknown:
            logger.info(f"Blocked IP {client_ip} (ASN not found, ALLOW_UNKNOWN=false)")
            return render_block_page(
                "Network information unavailable. Access denied for security reasons.",
                client_ip,
                use_html_response=config.use_html_response,
                block_page_template=config.block_page_template
            )
    
    return None
