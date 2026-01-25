# geo-asn-auth Service

Python-based ForwardAuth service for Traefik that blocks traffic based on country, ASN, and user-agent using MaxMind databases.

[![Docker Image](https://img.shields.io/badge/docker-ghcr.io-blue)](https://ghcr.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Quick Start

### Using Pre-built Docker Image

```bash
# Pull the image
docker pull ghcr.io/WildeTechSolutions/geo-asn-auth:latest

# Download MaxMind databases (required)
# Sign up at https://www.maxmind.com/en/geolite2/signup

# Run the container
docker run -d \
  --name geo-asn-auth \
  -p 9876:9876 \
  -v /path/to/maxmind:/data:ro \
  ghcr.io/WildeTechSolutions/geo-asn-auth:latest
```

### Using Docker Compose

See [docker-compose.example.yml](docker-compose.example.yml) for a complete example.

## Features

- **Country-based blocking** (whitelist or blacklist)
- **ASN-based blocking** (whitelist or blacklist)
- **User-agent filtering** (blacklist with substring matching)
- Supports MaxMind GeoLite2 Country and ASN databases
- Remote blocklist fetching with caching
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
   - ./geo-asn-auth/config.yaml:/app/config.yaml:ro
   ```

4. Restart the service:
   ```bash
   docker compose restart geo-asn-auth
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

# User-Agent Filtering
user_agent:
  mode: disabled  # Options: whitelist, blacklist, disabled
  
  # Fetch user-agent lists from remote URLs (loaded at startup)
  blacklist_urls:
    - https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/refs/heads/master/_generator_lists/bad-user-agents.list
  whitelist_urls: []
  
  # Manual user-agent entries (combined with fetched lists)
  # Uses substring matching (case-insensitive)
  blacklist:
    - "sqlmap"
    - "nikto"
    - "nmap"
  whitelist: []
```

**ASN Mode Behavior:**
- **`whitelist` mode**: Only ASNs in whitelist are allowed (strict deny-by-default)
- **`blacklist` mode**: ASNs in blacklist are blocked, BUT whitelist entries are exceptions (useful for trusting specific VPNs/services while blocking all other datacenters)
- **`disabled` mode**: No ASN filtering
```

**Remote ASN Lists:**
- Lists are fetched at container startup and combined with manual entries
- **Caching**: Downloaded lists are cached for 168 hours (7 days) in `/blocklists` to avoid re-downloading on every restart
- **Local files**: Place custom ASN list files in `./geo-asn-auth/blocklists/` and reference them as `/blocklists/filename.txt`
- Supports any URL or file with one ASN per line (comments with `#` are ignored)
- Example: brianhama/bad-asn-list contains 1277+ datacenter/hosting ASNs
- Failed fetches are logged but don't prevent startup
- Manual entries are preserved and merged with remote lists

**User-Agent Lists:**
- User-agent blacklists/whitelists work the same way as ASN lists
- **Matching**: Uses substring matching (case-insensitive) - "bot" will match "MyBot/1.0" and "botnet"
- Example: mitchellkrogza list contains ~4000 known bad user-agents (scrapers, crawlers, scanners)
- **Performance**: Compiled regex patterns add ~0.3-0.5ms per request

**Example with local file:**
```bash
# Create custom ASN list
echo "12345" > ./geo-asn-auth/blocklists/my-custom-asns.txt
echo "67890" >> ./geo-asn-auth/blocklists/my-custom-asns.txt
```

```yaml
# In config.yaml:
blacklist_urls:
  - /blocklists/my-custom-asns.txt  # Local file
  - https://raw.githubusercontent.com/brianhama/bad-asn-list/refs/heads/master/only%20number.txt  # Remote (cached)
```

### Environment Variables (docker-compose.yml)

Basic settings can be configured via environment:

```yaml
environment:
  - PORT=9876                      # Service port
  - ALLOW_LAN=true                 # Allow private/LAN IPs
  - ALLOW_UNKNOWN=true             # Allow when geo data unavailable
  - CACHE_HOURS=168                # Blocklist cache duration (default: 7 days)
  - CONFIG_PATH=/app/config.yaml
  - COUNTRY_DB_PATH=/data/GeoLite2-Country.mmdb
  - ASN_DB_PATH=/data/GeoLite2-ASN.mmdb
```

## Filtering Modes

- **whitelist**: Only allow specified countries/ASNs/user-agents (block all others)
- **blacklist**: Block specified countries/ASNs/user-agents (allow all others)
- **disabled**: Skip this check entirely

**Note**: For ASN blacklist mode, the whitelist acts as an exception list (e.g., trust specific VPNs while blocking all other datacenters).

## Usage

1. **Edit config.yaml** to set your blocking rules
2. **Rebuild the service**: `docker compose build geo-asn-auth`
3. **Restart**: `docker compose up -d geo-asn-auth`
4. **Check status**: `curl http://localhost:9876/health`

## Finding ASNs

Use online tools to find ASNs:
- https://bgp.he.net/ - Hurricane Electric BGP Toolkit
- https://ipinfo.io/ - IP to ASN lookup
- Check CrowdSec bans: `docker exec crowdsec cscli decisions list`

## MaxMind Database Setup

1. Sign up for free MaxMind account: https://www.maxmind.com/en/geolite2/signup
2. Download GeoLite2 Country and ASN databases
3. Place `.mmdb` files in the directory you mount as `/data` in the container

## Traefik Integration

This service integrates with Traefik as a ForwardAuth middleware. **Every HTTP request** is processed by geo-asn-auth before reaching your application (Traefik does not cache ForwardAuth responses).

### Request Flow

1. Request arrives at Traefik
2. **geo-asn-auth middleware** checks IP/user-agent against rules
3. If blocked: Returns 403 (request stops)
4. If allowed: Returns 200 (request continues to CrowdSec and application)

### Configuring Traefik

**IMPORTANT**: You must configure Traefik to use geo-asn-auth as a middleware. This requires editing both Traefik configuration files.

#### Step 1: Define the ForwardAuth middleware

Edit your Traefik dynamic configuration file (e.g., `dynamic_config.yml`):

```yaml
http:
  middlewares:
    geoblock:
      forwardAuth:
        address: http://geoblock-service:9876/verify
        trustForwardHeader: true
        authResponseHeaders:
          - X-Geo-Country
          - X-Geo-ASN
```

**Configuration details:**
- `address`: Must match your geo-asn-auth container name and port
- `trustForwardHeader`: Required to read `X-Forwarded-For` header
- `authResponseHeaders`: Optional headers passed to your application

#### Step 2: Apply middleware globally or per-route

**Option A: Global (All Routes)**

Edit your Traefik static configuration file (e.g., `traefik_config.yml`):

```yaml
entryPoints:
  web:
    address: :80
    http:
      middlewares:
        - geoblock@file
        - crowdsec@file
  websecure:
    address: :443
    http:
      middlewares:
        - geoblock@file
        - crowdsec@file
```

This applies geo-asn-auth to **all HTTP/HTTPS traffic** at the entry point level.

**Option B: Per-Route**

Edit your dynamic configuration file to apply middleware only to specific routers:

```yaml
http:
  routers:
    my-app-router:
      rule: "Host(`example.com`)"
      entryPoints:
        - websecure
      middlewares:
        - geoblock  # Apply geo-asn-auth to this route only
        - security-headers
      service: my-app-service
      tls:
        certResolver: letsencrypt
```

**Middleware order matters**: Place `geoblock` **before** CrowdSec to block traffic early.

#### Step 3: Restart Traefik

```bash
docker compose restart traefik
```

Traefik will reload the configuration and start sending requests to geo-asn-auth.

### Verifying Integration

Check Traefik logs to confirm ForwardAuth is working:

```bash
docker logs traefik | grep -i forward
```

Check geo-asn-auth logs for request processing:

```bash
docker logs geo-asn-auth
```

You should see log entries for each request showing allowed/blocked decisions.

## Endpoints

- `GET /verify` - ForwardAuth verification (used by Traefik)
- `GET /health` - Health check and configuration status

## Testing

Check health status:
```bash
curl http://localhost:9876/health
```

Test from specific IP (for testing, temporarily expose port):
```bash
curl -H "X-Forwarded-For: 8.8.8.8" http://localhost:9876/verify
```

## Performance

Typical request processing time:
- GeoIP lookup: ~0.1ms
- ASN/Country set lookups: ~0.01ms
- User-agent regex matching: ~0.3-0.5ms (with ~4000 patterns)
- **Total**: <1ms per request

Network latency between Traefik and geo-asn-auth adds ~0.1ms (when running as sidecar containers).

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
  geo-asn-auth:
    build:
      context: ./geo-asn-auth
      args:
        USER_UID: 1000  # Your UID
        USER_GID: 1000  # Your GID
```

**Option 2: Override user at runtime** (when using pre-built images):
```yaml
# docker-compose.yml
services:
  geo-asn-auth:
    image: ghcr.io/user/geo-asn-auth:latest
    user: "1000:1000"  # Your UID:GID
```

This ensures the container user can write to the `/blocklists` volume mount.

### Building Locally

```bash
# Build with default UID/GID (1000:1000)
docker build -t geo-asn-auth:latest .

# Or build with custom UID/GID
docker build --build-arg USER_UID=$(id -u) --build-arg USER_GID=$(id -g) \
  -t geo-asn-auth:latest .

# Run locally
docker run -d -p 9876:9876 \
  -v /path/to/maxmind:/data:ro \
  -v ./blocklists:/blocklists \
  geo-asn-auth:latest
```

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

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions welcome! Please open an issue or submit a pull request.

## Support

- Report issues: https://github.com/WildeTechSolutions/geo-asn-auth/issues
- Questions: https://github.com/WildeTechSolutions/geo-asn-auth/discussions

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
docker logs -f geo-asn-auth
```

Logs show:
- Allowed/blocked requests with reason
- IP, country, and ASN information
- Configuration validation
- Database loading status
