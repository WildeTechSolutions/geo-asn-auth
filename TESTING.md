# GeoBlock Service Testing

## Run Tests

Install development dependencies:
```bash
pip install -r requirements-dev.txt
```

Run all tests:
```bash
pytest test_app.py -v
```

Run with coverage report:
```bash
pytest test_app.py -v --cov=app --cov-report=html --cov-report=term
```

Run specific test class:
```bash
pytest test_app.py::TestIPFiltering -v
```

Run specific test:
```bash
pytest test_app.py::TestIPFiltering::test_ip_blacklist_mode_whitelist_bypass -v
```

## Test Coverage

The test suite covers:

### Configuration
- ✅ Loading from YAML files
- ✅ Environment variable overrides
- ✅ Configuration hierarchy

### IP Filtering
- ✅ Blacklist mode with whitelist bypass
- ✅ Blacklist mode with blacklist blocking
- ✅ Whitelist mode strict filtering
- ✅ Unlisted IPs continuing to other checks

### Private IP Handling
- ✅ Private IPs allowed when ALLOW_LAN=true
- ✅ Private IPs checked when ALLOW_LAN=false
- ✅ All private IP ranges (192.168.x.x, 10.x.x.x, 172.16-31.x.x, 127.x.x.x, 169.254.x.x)

### Country Filtering
- ✅ Whitelist mode allowing listed countries
- ✅ Whitelist mode blocking unlisted countries
- ✅ Blacklist mode allowing unlisted countries
- ✅ Blacklist mode blocking listed countries
- ✅ Unknown country handling with ALLOW_UNKNOWN=true
- ✅ Unknown country blocking with ALLOW_UNKNOWN=false

### ASN Filtering
- ✅ Whitelist mode allowing listed ASNs
- ✅ Whitelist mode blocking unlisted ASNs
- ✅ Blacklist mode allowing unlisted ASNs
- ✅ Blacklist mode blocking listed ASNs
- ✅ **Whitelist exception in blacklist mode** (key feature)
- ✅ Unknown ASN handling with ALLOW_UNKNOWN=true
- ✅ Unknown ASN blocking with ALLOW_UNKNOWN=false

### Combined Filtering
- ✅ IP whitelist bypassing country/ASN checks
- ✅ Country pass continuing to ASN check
- ✅ Multiple filter layers working together

### ASN List Fetching
- ✅ Remote URL fetching
- ✅ Local file loading
- ✅ Caching mechanism (saves network requests)
- ✅ Cache expiration (refreshes stale data)

### Health Endpoint
- ✅ Status reporting
- ✅ Configuration exposure
- ✅ Database availability checks

### IP Extraction
- ✅ X-Forwarded-For header parsing
- ✅ X-Real-IP fallback
- ✅ Multiple IPs in chain handling

### Error Handling
- ✅ Fail-open behavior on exceptions
- ✅ Service disruption prevention

## Docker Testing

Build and test in Docker:
```bash
cd /home/ubuntu/docker/pangolin
sudo docker compose build geoblock-service
sudo docker compose run --rm geoblock-service pytest /app/test_app.py -v
```

## Continuous Integration

Tests are designed to work with GitHub Actions and can be integrated into CI/CD pipelines:

```yaml
- name: Run tests
  run: |
    pip install -r requirements-dev.txt
    pytest test_app.py -v --cov=app --cov-report=xml
```

## Test Structure

Each test class focuses on a specific aspect:
- `TestConfiguration` - Configuration loading and parsing
- `TestIPFiltering` - IP whitelist/blacklist behavior
- `TestPrivateIPHandling` - Private/LAN IP handling
- `TestCountryFiltering` - Country-based filtering
- `TestASNFiltering` - ASN-based filtering (including exception logic)
- `TestCombinedFiltering` - Multi-layer filtering combinations
- `TestASNListFetching` - Remote/local ASN list loading and caching
- `TestHealthEndpoint` - Health check functionality
- `TestIPExtraction` - Client IP extraction from headers
- `TestErrorHandling` - Graceful error handling

## Mocking Strategy

Tests use mocking to avoid requiring:
- Actual MaxMind database files
- Network access for remote ASN lists
- Real configuration files

This makes tests:
- Fast (no I/O)
- Reliable (no external dependencies)
- Portable (run anywhere)
