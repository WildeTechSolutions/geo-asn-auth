FROM python:3.11-slim

WORKDIR /app

# Build args for user configuration
ARG USER_UID=1000
ARG USER_GID=1000

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY src/ ./src/
COPY block_page.html .
COPY config.yaml.example /app/config.yaml.example
COPY gunicorn_config.py .

# Create blocklists directory
RUN mkdir -p /blocklists

# Run as non-root user
RUN groupadd -g ${USER_GID} appuser && \
    useradd -m -u ${USER_UID} -g ${USER_GID} appuser && \
    chown -R appuser:appuser /app /blocklists

USER appuser

EXPOSE 9876

CMD ["sh", "-c", "gunicorn -c gunicorn_config.py --bind 0.0.0.0:${PORT:-9876} src.app:app"]
