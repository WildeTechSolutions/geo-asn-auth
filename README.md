# GeoBlock Service - ForwardAuth Geoblocking

Python-based ForwardAuth service for Traefik that blocks traffic based on country and ASN using MaxMind databases.

[![Docker Image](https://img.shields.io/badge/docker-ghcr.io-blue)](https://ghcr.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Quick Start

### Using Pre-built Docker Image

```bash
# Pull the image
docker pull ghcr.io/WildeTechSolutions/traefik-geoblock-forwardauth:latest

# Download MaxMind databases (required)
# Sign up at https://www.maxmind.com/en/geolite2/signup

# Run the container
docker run -d \
  --name geoblock-service \
  -p 9876:9876 \
  -v /path/to/maxmind:/data:ro \
  ghcr.io/WildeTechSolutions/traefik-geoblock-forwardauth:latest
```

### Using Docker Compose

See [docker-compose.example.yml](docker-compose.example.yml) for a complete example.

## Features

- Country-based blocking (whitelist or blacklist)
- ASN-based blocking (whitelist or blacklist)
- Supports MaxMind GeoLite2 Country and ASN databases
- YAML configuration file with inline comments
- Private IP allowance option
- Health check endpoint
- Detailed logging
- Configurable service port

## Configuration

### Quick Start

The service includes a default configuration (`config.yaml.example`) that works out of the box.

**To customize the configuration:**

1. Copy the example config:
   ```bash
   cp config.yaml.example config.yaml
   ```

2. Edit `config.yaml` with your custom blocking rules

3. Uncomment the volume mount in `docker-compose.yml`:
   ```yaml
   - ./geoblock-service/config.yaml:/app/config.yaml:ro
   ```

4. Restart the service:
   ```bash
   docker compose restart geoblock-service
   ```

### Primary Configuration: config.yaml

Edit `config.yaml` to manage your blocking rules:

```yaml
# Country Filtering
countries:
  mode: whitelist  # Options: whitelist, blacklist, disabled
  whitelist:
    - US  # United States
    - CA  # Canada
  blacklist: []

# ASN Filtering
asn:
  mode: blacklist  # Options: whitelist, blacklist, disabled
  
  # Whitelist can be used in two ways:
  # - In "whitelist" mode: Only these ASNs are allowed (strict mode)
  # - In "blacklist" mode: These ASNs are exceptions to the blacklist
  whitelist:
    - 212238  # ProtonVPN - trusted exception to datacenter blacklist
  
  # Fetch ASN lists from remote URLs (loaded at startup)
  blacklist_urls:
    - https://raw.githubusercontent.com/brianhama/bad-asn-list/refs/heads/master/only%20number.txt
  whitelist_urls: []
  
  # Manual ASN entries (combined with fetched lists)
  blacklist:
    - 16509   # AMAZON-02 (AWS)
    - 13335   # Cloudflare
    - 15169   # Google LLC
    # Add more ASNs with comments...
```

**ASN Mode Behavior:**
- **`whitelist` mode**: Only ASNs in whitelist are allowed (strict deny-by-default)
- **`blacklist` mode**: ASNs in blacklist are blocked, BUT whitelist entries are exceptions (useful for trusting specific VPNs/services while blocking all other datacenters)
- **`disabled` mode**: No ASN filtering
```

**Remote ASN Lists:**
- Lists are fetched at container startup and combined with manual entries
- **Caching**: Downloaded lists are cached for 24 hours in `/blocklists` to avoid re-downloading on every restart
- **Local files**: Place custom ASN list files in `./geoblock-service/blocklists/` and reference them as `/blocklists/filename.txt`
- Supports any URL or file with one ASN per line (comments with `#` are ignored)
- Example: brianhama/bad-asn-list contains 1277+ datacenter/hosting ASNs
- Failed fetches are logged but don't prevent startup
- Manual entries are preserved and merged with remote lists

**Example with local file:**
```bash
# Create custom ASN list
echo "12345" > ./geoblock-service/blocklists/my-custom-asns.txt
echo "67890" >> ./geoblock-service/blocklists/my-custom-asns.txt
```

```yaml
# In config.yaml:
blacklist_urls:
  - /blocklists/my-custom-asns.txt  # Local file
  - https://raw.githubusercontent.com/brianhama/bad-asn-list/refs/heads/master/only%20number.txt  # Remote (cached)
```
```

### Environment Variables (docker-compose.yml)

Basic settings can be configured via environment:

### Environment Variables (docker-compose.yml)

Basic settings can be configured via environment:

```yaml
environment:
  - PORT=9876                # Service port
  - ALLOW_LAN=true           # Allow private/LAN IPs
  - ALLOW_UNKNOWN=true       # Allow when geo data unavailable
  - CONFIG_PATH=/app/config.yaml
  - COUNTRY_DB_PATH=/data/GeoLite2-Country.mmdb
  - ASN_DB_PATH=/data/GeoLite2-ASN.mmdb
```

## Modes

- **whitelist**: Only allow specified countries/ASNs (block all others)
- **blacklist**: Block specified countries/ASNs (allow all others)
- **disabled**: Skip this check entirely

## Usage

1. **Edit config.yaml** to set your blocking rules
2. **Rebuild the service**: `docker compose build geoblock-service`
3. **Restart**: `docker compose up -d geoblock-service`
4. **Check status**: `curl http://localhost:9876/health`

## Finding ASNs

Use online tools to find ASNs:
- https://bgp.he.net/ - Hurricane Electric BGP Toolkit
- https://ipinfo.io/ - IP to ASN lookup
- Check CrowdSec bans: `docker exec crowdsec cscli decisions list`

## MaxMind Database Setup

1. Sign up for free MaxMind account: https://www.maxmind.com/en/geolite2/signup
2. Download GeoLite2 Country and ASN databases
3. Place `.mmdb` files in `/home/ubuntu/docker/pangolin/config/maxmind/`

## Usage

The service is automatically used by Traefik as ForwardAuth middleware on pangolin routes.

**Request Flow:**
1. Request arrives at Traefik
2. Geoblock middleware checks IP against rules
3. If blocked: Returns 403 (request stops)
4. If allowed: Returns 200 (request continues to CrowdSec and application)

## Endpoints

- `GET /verify` - ForwardAuth verification (used by Traefik)
- `GET /health` - Health check and configuration status

## Testing

Check health status:
```bash
curl http://localhost:8080/health
```

Test from specific IP (for testing, temporarily expose port):
```bash
curl -H "X-Forwarded-For: 8.8.8.8" http://localhost:8080/verify
```

## Development

### User Permissions

The container runs as a non-root user (`appuser`) for security. By default, it uses UID/GID `1000`, but you can customize this to match your host user:

```bash
# Check your user's UID/GID
id -u  # Your UID
id -g  # Your GID
```

**Option 1: Build with custom UID/GID** (recommended for building locally):
```yaml
# docker-compose.yml
services:
  geoblock-service:
    build:
      context: ./geoblock-service
      args:
        USER_UID: 1000  # Your UID
        USER_GID: 1000  # Your GID
```

**Option 2: Override user at runtime** (when using pre-built images):
```yaml
# docker-compose.yml
services:
  geoblock-service:
    image: ghcr.io/user/traefik-geoblock-forwardauth:latest
    user: "1000:1000"  # Your UID:GID
```

This ensures the container user can write to the `/blocklists` volume mount.

### Building Locally

```bash
# Build with default UID/GID (1000:1000)
docker build -t traefik-geoblock-forwardauth:latest .

# Or build with custom UID/GID
docker build --build-arg USER_UID=$(id -u) --build-arg USER_GID=$(id -g) \
  -t traefik-geoblock-forwardauth:latest .

# Run locally
docker run -d -p 9876:9876 \
  -v /path/to/maxmind:/data:ro \
  -v ./blocklists:/blocklists \
  traefik-geoblock-forwardauth:latest
```

### Publishing to Docker Registries

#### Option 1: GitHub Container Registry (GHCR) - Automated

This repository includes a GitHub Actions workflow that automatically builds and publishes images.

**Setup:**
1. Push code to GitHub
2. Create a release tag: `git tag v1.0.0 && git push --tags`
3. GitHub Actions will automatically build and push to `ghcr.io/WildeTechSolutions/traefik-geoblock-forwardauth`

**Note:** GHCR uses your GitHub token automatically - no additional secrets needed!

#### Option 2: Docker Hub - Manual

```bash
# Login to Docker Hub
docker login

# Build for multiple platforms
docker buildx create --use
docker buildx build --platform linux/amd64,linux/arm64 \
  -t your-dockerhub-username/traefik-geoblock-forwardauth:latest \
  -t your-dockerhub-username/traefik-geoblock-forwardauth:v1.0.0 \
  --push .
```

#### Option 3: Docker Hub - Automated via GitHub Actions

1. Create Docker Hub access token at https://hub.docker.com/settings/security
2. Add GitHub secrets:
   - `DOCKERHUB_USERNAME`: Your Docker Hub username
   - `DOCKERHUB_TOKEN`: Your access token
3. Uncomment Docker Hub sections in `.github/workflows/docker-publish.yml`
4. Push code or create a release tag

## MaxMind Database Setup

This service requires MaxMind GeoLite2 databases:

1. Sign up for a free account: https://www.maxmind.com/en/geolite2/signup
2. Generate a license key
3. Download databases:
   - GeoLite2-Country.mmdb
   - GeoLite2-ASN.mmdb
4. Place in a directory and mount as `/data` in the container

**Automated Updates:**
Use the `maxmind-geoipupdate` container to keep databases current.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions welcome! Please open an issue or submit a pull request.

## Support

- Report issues: https://github.com/WildeTechSolutions/traefik-geoblock-forwardauth/issues
- Questions: https://github.com/WildeTechSolutions/traefik-geoblock-forwardauth/discussions

## Common ASN Numbers

- 13335 - Cloudflare
- 15169 - Google
- 16509 - Amazon AWS
- 8075 - Microsoft Azure
- 14061 - DigitalOcean
- 209 - Qwest/CenturyLink
- 7922 - Comcast

Find ASN: https://bgp.he.net/

## Logs

View logs:
```bash
docker logs -f geoblock-service
```

Logs show:
- Allowed/blocked requests with reason
- IP, country, and ASN information
- Configuration validation
- Database loading status
