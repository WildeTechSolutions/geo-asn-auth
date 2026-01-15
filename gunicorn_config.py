"""Gunicorn configuration with health check log filtering"""
import logging


class HealthCheckFilter(logging.Filter):
    """Filter to suppress /health endpoint logs"""
    def filter(self, record):
        return '/health' not in record.getMessage()


def on_starting(server):
    """Called just before the master process is initialized."""
    # Get the gunicorn access logger
    gunicorn_logger = logging.getLogger('gunicorn.access')
    # Add our filter
    gunicorn_logger.addFilter(HealthCheckFilter())


# Bind configuration
bind = '0.0.0.0:9876'
workers = 2
threads = 2
timeout = 30

# Logging
accesslog = '-'  # stdout
errorlog = '-'   # stderr
loglevel = 'info'

# Custom access log format with INFO level prefix
access_log_format = 'INFO: %(h)s - - [%(t)s] "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
