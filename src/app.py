"""
Geoblock Service - Flask application for IP/country/ASN-based access control.
Provides ForwardAuth endpoint for Traefik reverse proxy.
"""

import os
import logging
from flask import Flask, jsonify

from .config import Config
from .verification import verify_request

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Filter to suppress health check logs
class HealthCheckFilter(logging.Filter):
    def filter(self, record):
        # Suppress logs for /health endpoint
        return '/health' not in record.getMessage()

# Apply filter to werkzeug logger (Flask's HTTP request logger)
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.addFilter(HealthCheckFilter())

# Initialize Flask app
app = Flask(__name__)

# Load configuration
config = Config()


@app.route('/verify', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])
def verify():
    """ForwardAuth verification endpoint."""
    return verify_request(config)


@app.route('/health')
def health():
    """Health check endpoint."""
    status = {
        "status": "healthy",
        "country_db": config.country_reader is not None,
        "asn_db": config.asn_reader is not None,
        "config": {
            "ip_mode": config.ip_mode,
            "ip_whitelist_count": len(config.ip_whitelist),
            "ip_blacklist_count": len(config.ip_blacklist),
            "user_agent_mode": config.user_agent_mode,
            "user_agent_whitelist_count": config.user_agent_whitelist_count,
            "user_agent_blacklist_count": config.user_agent_blacklist_count,
            "country_mode": config.country_mode,
            "country_whitelist": config.country_whitelist,
            "country_blacklist": config.country_blacklist,
            "asn_mode": config.asn_mode,
            "asn_whitelist_count": len(config.asn_whitelist),
            "asn_whitelist_conditional_count": sum(1 for patterns in config.asn_whitelist.values() if patterns is not None),
            "asn_blacklist_count": len(config.asn_blacklist),
            "allow_lan": config.allow_lan,
            "allow_unknown": config.allow_unknown
        }
    }
    return jsonify(status), 200


if __name__ == '__main__':
    port = int(os.getenv('PORT', 9876))
    app.run(host='0.0.0.0', port=port, debug=False)
