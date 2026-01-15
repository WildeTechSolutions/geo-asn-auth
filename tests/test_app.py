"""
Comprehensive unit tests for geoblock-service
Tests all filtering modes, combinations, and edge cases
"""
import pytest
import os
import tempfile
import time
from unittest.mock import Mock, patch, MagicMock
from geoip2.errors import AddressNotFoundError

# Set test environment before importing app
os.environ['CONFIG_PATH'] = '/nonexistent/config.yaml'
os.environ['COUNTRY_DB_PATH'] = '/nonexistent/country.mmdb'
os.environ['ASN_DB_PATH'] = '/nonexistent/asn.mmdb'


class TestConfiguration:
    """Test configuration loading and parsing"""
    
    def test_load_config_from_yaml(self):
        """Test loading configuration from YAML file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
ip:
  mode: blacklist
  whitelist: ['1.2.3.4']
  blacklist: ['5.6.7.8']
countries:
  mode: whitelist
  whitelist: ['US', 'CA']
asn:
  mode: blacklist
  blacklist: [12345, 67890]
settings:
  allow_lan: true
  allow_unknown: false
  cache_hours: 72
""")
            config_path = f.name
        
        try:
            with patch.dict(os.environ, {'CONFIG_PATH': config_path}):
                # Reimport to load new config
                import importlib
                import app
                importlib.reload(app)
                
                assert app.ip_mode == 'blacklist'
                assert '1.2.3.4' in app.IP_WHITELIST
                assert '5.6.7.8' in app.IP_BLACKLIST
                assert app.country_mode == 'whitelist'
                assert 'US' in app.COUNTRY_WHITELIST
                assert app.asn_mode == 'blacklist'
                assert 12345 in app.ASN_BLACKLIST
                assert app.ALLOW_LAN == True
                assert app.ALLOW_UNKNOWN == False
                assert app.CACHE_HOURS == 72
        finally:
            os.unlink(config_path)
    
    def test_env_var_override(self):
        """Test environment variable overrides config.yaml"""
        with patch.dict(os.environ, {
            'ALLOW_LAN': 'false',
            'ALLOW_UNKNOWN': 'false',
            'USE_HTML_RESPONSE': 'false',
            'CACHE_HOURS': '336'
        }):
            import importlib
            import app
            importlib.reload(app)
            
            assert app.ALLOW_LAN == False
            assert app.ALLOW_UNKNOWN == False
            assert app.USE_HTML_RESPONSE == False
            assert app.CACHE_HOURS == 336


class TestIPFiltering:
    """Test IP whitelist/blacklist functionality"""
    
    @pytest.fixture
    def app_client(self):
        """Create test client with mocked config"""
        with patch('app.country_reader', None), \
             patch('app.asn_reader', None), \
             patch('app.ip_mode', 'blacklist'), \
             patch('app.IP_WHITELIST', {'10.0.0.100', '192.168.1.50'}), \
             patch('app.IP_BLACKLIST', {'1.2.3.4', '5.6.7.8'}), \
             patch('app.ALLOW_LAN', False):
            
            import app
            app.app.config['TESTING'] = True
            yield app.app.test_client()
    
    def test_ip_blacklist_mode_whitelist_bypass(self, app_client):
        """IP in whitelist should bypass all checks in blacklist mode"""
        response = app_client.get('/verify', headers={'X-Forwarded-For': '10.0.0.100'})
        assert response.status_code == 200
    
    def test_ip_blacklist_mode_blacklist_block(self, app_client):
        """IP in blacklist should be blocked immediately"""
        response = app_client.get('/verify', headers={'X-Forwarded-For': '1.2.3.4'})
        assert response.status_code == 403
    
    def test_ip_blacklist_mode_unlisted_continue(self, app_client):
        """Unlisted IP should continue to other checks (allow if no other filters)"""
        response = app_client.get('/verify', headers={'X-Forwarded-For': '8.8.8.8'})
        assert response.status_code == 200
    
    def test_ip_whitelist_mode(self):
        """Only whitelisted IPs allowed in whitelist mode"""
        with patch('app.country_reader', None), \
             patch('app.asn_reader', None), \
             patch('app.ip_mode', 'whitelist'), \
             patch('app.IP_WHITELIST', {'10.0.0.100'}), \
             patch('app.ALLOW_LAN', False):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            # Whitelisted IP allowed
            response = client.get('/verify', headers={'X-Forwarded-For': '10.0.0.100'})
            assert response.status_code == 200
            
            # Non-whitelisted continues to other checks (allow if no other filters)
            response = client.get('/verify', headers={'X-Forwarded-For': '8.8.8.8'})
            assert response.status_code == 200


class TestPrivateIPHandling:
    """Test private/LAN IP handling"""
    
    @pytest.fixture
    def app_client(self):
        with patch('app.country_reader', None), \
             patch('app.asn_reader', None), \
             patch('app.ip_mode', 'disabled'), \
             patch('app.ALLOW_LAN', True):
            
            import app
            app.app.config['TESTING'] = True
            yield app.app.test_client()
    
    @pytest.mark.parametrize('private_ip', [
        '192.168.1.1',
        '10.0.0.1',
        '172.16.0.1',
        '127.0.0.1',
        '169.254.1.1'
    ])
    def test_private_ips_allowed_when_enabled(self, app_client, private_ip):
        """Private IPs should be allowed when ALLOW_LAN=true"""
        response = app_client.get('/verify', headers={'X-Forwarded-For': private_ip})
        assert response.status_code == 200
    
    def test_private_ip_blocked_when_disabled(self):
        """Private IPs should be checked normally when ALLOW_LAN=false"""
        mock_reader = Mock()
        mock_reader.country.side_effect = AddressNotFoundError("Not found")
        
        with patch('app.country_reader', mock_reader), \
             patch('app.asn_reader', None), \
             patch('app.country_mode', 'whitelist'), \
             patch('app.COUNTRY_WHITELIST', ['US']), \
             patch('app.ALLOW_LAN', False), \
             patch('app.ALLOW_UNKNOWN', False):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            response = client.get('/verify', headers={'X-Forwarded-For': '192.168.1.1'})
            assert response.status_code == 403


class TestCountryFiltering:
    """Test country whitelist/blacklist functionality"""
    
    def create_mock_country_response(self, country_code, country_name):
        """Helper to create mock GeoIP2 country response"""
        mock_response = Mock()
        mock_response.country.iso_code = country_code
        mock_response.country.name = country_name
        return mock_response
    
    def test_country_whitelist_mode_allowed(self):
        """Country in whitelist should be allowed"""
        mock_reader = Mock()
        mock_reader.country.return_value = self.create_mock_country_response('US', 'United States')
        
        with patch('app.country_reader', mock_reader), \
             patch('app.asn_reader', None), \
             patch('app.country_mode', 'whitelist'), \
             patch('app.COUNTRY_WHITELIST', ['US', 'CA']), \
             patch('app.ALLOW_LAN', False):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            response = client.get('/verify', headers={'X-Forwarded-For': '1.2.3.4'})
            assert response.status_code == 200
    
    def test_country_whitelist_mode_blocked(self):
        """Country not in whitelist should be blocked"""
        mock_reader = Mock()
        mock_reader.country.return_value = self.create_mock_country_response('CN', 'China')
        
        with patch('app.country_reader', mock_reader), \
             patch('app.asn_reader', None), \
             patch('app.country_mode', 'whitelist'), \
             patch('app.COUNTRY_WHITELIST', ['US', 'CA']), \
             patch('app.ALLOW_LAN', False):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            response = client.get('/verify', headers={'X-Forwarded-For': '1.2.3.4'})
            assert response.status_code == 403
    
    def test_country_blacklist_mode_allowed(self):
        """Country not in blacklist should be allowed"""
        mock_reader = Mock()
        mock_reader.country.return_value = self.create_mock_country_response('US', 'United States')
        
        with patch('app.country_reader', mock_reader), \
             patch('app.asn_reader', None), \
             patch('app.country_mode', 'blacklist'), \
             patch('app.COUNTRY_BLACKLIST', ['CN', 'RU']), \
             patch('app.ALLOW_LAN', False):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            response = client.get('/verify', headers={'X-Forwarded-For': '1.2.3.4'})
            assert response.status_code == 200
    
    def test_country_blacklist_mode_blocked(self):
        """Country in blacklist should be blocked"""
        mock_reader = Mock()
        mock_reader.country.return_value = self.create_mock_country_response('CN', 'China')
        
        with patch('app.country_reader', mock_reader), \
             patch('app.asn_reader', None), \
             patch('app.country_mode', 'blacklist'), \
             patch('app.COUNTRY_BLACKLIST', ['CN', 'RU']), \
             patch('app.ALLOW_LAN', False):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            response = client.get('/verify', headers={'X-Forwarded-For': '1.2.3.4'})
            assert response.status_code == 403
    
    def test_country_not_found_allow_unknown(self):
        """Unknown country should be allowed when ALLOW_UNKNOWN=true"""
        mock_reader = Mock()
        mock_reader.country.side_effect = AddressNotFoundError("Not found")
        
        with patch('app.country_reader', mock_reader), \
             patch('app.asn_reader', None), \
             patch('app.country_mode', 'whitelist'), \
             patch('app.COUNTRY_WHITELIST', ['US']), \
             patch('app.ALLOW_LAN', False), \
             patch('app.ALLOW_UNKNOWN', True):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            response = client.get('/verify', headers={'X-Forwarded-For': '1.2.3.4'})
            assert response.status_code == 200
    
    def test_country_not_found_block_unknown(self):
        """Unknown country should be blocked when ALLOW_UNKNOWN=false"""
        mock_reader = Mock()
        mock_reader.country.side_effect = AddressNotFoundError("Not found")
        
        with patch('app.country_reader', mock_reader), \
             patch('app.asn_reader', None), \
             patch('app.country_mode', 'whitelist'), \
             patch('app.COUNTRY_WHITELIST', ['US']), \
             patch('app.ALLOW_LAN', False), \
             patch('app.ALLOW_UNKNOWN', False):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            response = client.get('/verify', headers={'X-Forwarded-For': '1.2.3.4'})
            assert response.status_code == 403


class TestASNFiltering:
    """Test ASN whitelist/blacklist functionality"""
    
    def create_mock_asn_response(self, asn_number, asn_org):
        """Helper to create mock GeoIP2 ASN response"""
        mock_response = Mock()
        mock_response.autonomous_system_number = asn_number
        mock_response.autonomous_system_organization = asn_org
        return mock_response
    
    def test_asn_whitelist_mode_allowed(self):
        """ASN in whitelist should be allowed"""
        mock_reader = Mock()
        mock_reader.asn.return_value = self.create_mock_asn_response(7922, 'Comcast')
        
        with patch('app.country_reader', None), \
             patch('app.asn_reader', mock_reader), \
             patch('app.asn_mode', 'whitelist'), \
             patch('app.ASN_WHITELIST', {7922, 20115}), \
             patch('app.ALLOW_LAN', False):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            response = client.get('/verify', headers={'X-Forwarded-For': '1.2.3.4'})
            assert response.status_code == 200
    
    def test_asn_whitelist_mode_blocked(self):
        """ASN not in whitelist should be blocked"""
        mock_reader = Mock()
        mock_reader.asn.return_value = self.create_mock_asn_response(16509, 'AWS')
        
        with patch('app.country_reader', None), \
             patch('app.asn_reader', mock_reader), \
             patch('app.asn_mode', 'whitelist'), \
             patch('app.ASN_WHITELIST', {7922, 20115}), \
             patch('app.ALLOW_LAN', False):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            response = client.get('/verify', headers={'X-Forwarded-For': '1.2.3.4'})
            assert response.status_code == 403
    
    def test_asn_blacklist_mode_allowed(self):
        """ASN not in blacklist should be allowed"""
        mock_reader = Mock()
        mock_reader.asn.return_value = self.create_mock_asn_response(7922, 'Comcast')
        
        with patch('app.country_reader', None), \
             patch('app.asn_reader', mock_reader), \
             patch('app.asn_mode', 'blacklist'), \
             patch('app.ASN_WHITELIST', set()), \
             patch('app.ASN_BLACKLIST', {16509, 14618, 8075}), \
             patch('app.ALLOW_LAN', False):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            response = client.get('/verify', headers={'X-Forwarded-For': '1.2.3.4'})
            assert response.status_code == 200
    
    def test_asn_blacklist_mode_blocked(self):
        """ASN in blacklist should be blocked"""
        mock_reader = Mock()
        mock_reader.asn.return_value = self.create_mock_asn_response(16509, 'AWS')
        
        with patch('app.country_reader', None), \
             patch('app.asn_reader', mock_reader), \
             patch('app.asn_mode', 'blacklist'), \
             patch('app.ASN_WHITELIST', set()), \
             patch('app.ASN_BLACKLIST', {16509, 14618, 8075}), \
             patch('app.ALLOW_LAN', False):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            response = client.get('/verify', headers={'X-Forwarded-For': '1.2.3.4'})
            assert response.status_code == 403
    
    def test_asn_blacklist_mode_whitelist_exception(self):
        """ASN in whitelist should bypass blacklist (exception)"""
        mock_reader = Mock()
        mock_reader.asn.return_value = self.create_mock_asn_response(212238, 'ProtonVPN')
        
        with patch('app.country_reader', None), \
             patch('app.asn_reader', mock_reader), \
             patch('app.asn_mode', 'blacklist'), \
             patch('app.ASN_WHITELIST', {212238}), \
             patch('app.ASN_BLACKLIST', {16509, 14618, 212238}), \
             patch('app.ALLOW_LAN', False):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            # ProtonVPN (212238) is in blacklist but also in whitelist (exception)
            response = client.get('/verify', headers={'X-Forwarded-For': '1.2.3.4'})
            assert response.status_code == 200
    
    def test_asn_not_found_allow_unknown(self):
        """Unknown ASN should be allowed when ALLOW_UNKNOWN=true"""
        mock_reader = Mock()
        mock_reader.asn.side_effect = AddressNotFoundError("Not found")
        
        with patch('app.country_reader', None), \
             patch('app.asn_reader', mock_reader), \
             patch('app.asn_mode', 'whitelist'), \
             patch('app.ASN_WHITELIST', {7922}), \
             patch('app.ALLOW_LAN', False), \
             patch('app.ALLOW_UNKNOWN', True):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            response = client.get('/verify', headers={'X-Forwarded-For': '1.2.3.4'})
            assert response.status_code == 200
    
    def test_asn_not_found_block_unknown(self):
        """Unknown ASN should be blocked when ALLOW_UNKNOWN=false"""
        mock_reader = Mock()
        mock_reader.asn.side_effect = AddressNotFoundError("Not found")
        
        with patch('app.country_reader', None), \
             patch('app.asn_reader', mock_reader), \
             patch('app.asn_mode', 'whitelist'), \
             patch('app.ASN_WHITELIST', {7922}), \
             patch('app.ALLOW_LAN', False), \
             patch('app.ALLOW_UNKNOWN', False):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            response = client.get('/verify', headers={'X-Forwarded-For': '1.2.3.4'})
            assert response.status_code == 403


class TestCombinedFiltering:
    """Test combinations of IP, country, and ASN filtering"""
    
    def test_ip_whitelist_bypasses_country_asn_checks(self):
        """IP in whitelist should bypass country and ASN checks"""
        mock_country_reader = Mock()
        mock_country_reader.country.return_value = Mock(
            country=Mock(iso_code='CN', name='China')
        )
        mock_asn_reader = Mock()
        mock_asn_reader.asn.return_value = Mock(
            autonomous_system_number=16509,
            autonomous_system_organization='AWS'
        )
        
        with patch('app.country_reader', mock_country_reader), \
             patch('app.asn_reader', mock_asn_reader), \
             patch('app.ip_mode', 'blacklist'), \
             patch('app.IP_WHITELIST', {'1.2.3.4'}), \
             patch('app.country_mode', 'whitelist'), \
             patch('app.COUNTRY_WHITELIST', ['US']), \
             patch('app.asn_mode', 'blacklist'), \
             patch('app.ASN_BLACKLIST', {16509}), \
             patch('app.ALLOW_LAN', False):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            # IP is whitelisted, should bypass even though country/ASN would block
            response = client.get('/verify', headers={'X-Forwarded-For': '1.2.3.4'})
            assert response.status_code == 200
    
    def test_country_pass_then_asn_check(self):
        """If country passes, should continue to ASN check"""
        mock_country_reader = Mock()
        mock_country_reader.country.return_value = Mock(
            country=Mock(iso_code='US', name='United States')
        )
        mock_asn_reader = Mock()
        mock_asn_reader.asn.return_value = Mock(
            autonomous_system_number=16509,
            autonomous_system_organization='AWS'
        )
        
        with patch('app.country_reader', mock_country_reader), \
             patch('app.asn_reader', mock_asn_reader), \
             patch('app.ip_mode', 'disabled'), \
             patch('app.country_mode', 'whitelist'), \
             patch('app.COUNTRY_WHITELIST', ['US']), \
             patch('app.asn_mode', 'blacklist'), \
             patch('app.ASN_BLACKLIST', {16509}), \
             patch('app.ALLOW_LAN', False):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            # Country passes (US in whitelist) but ASN blocks (AWS in blacklist)
            response = client.get('/verify', headers={'X-Forwarded-For': '1.2.3.4'})
            assert response.status_code == 403


class TestASNListFetching:
    """Test remote and local ASN list fetching"""
    
    def test_fetch_remote_asn_list(self):
        """Test fetching ASN list from remote URL"""
        mock_response = Mock()
        mock_response.text = "12345\n67890\n# Comment\n\n54321"
        mock_response.raise_for_status = Mock()
        
        with patch('requests.get', return_value=mock_response), \
             tempfile.TemporaryDirectory() as tmpdir:
            
            with patch('app.CACHE_DIR', tmpdir):
                import app
                asns = app.fetch_asn_list('http://example.com/asns.txt')
                
                assert len(asns) == 3
                assert 12345 in asns
                assert 67890 in asns
                assert 54321 in asns
    
    def test_fetch_local_asn_list(self):
        """Test loading ASN list from local file"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("11111\n22222\n33333\n")
            local_file = f.name
        
        try:
            import app
            asns = app.fetch_asn_list(local_file)
            
            assert len(asns) == 3
            assert 11111 in asns
            assert 22222 in asns
            assert 33333 in asns
        finally:
            os.unlink(local_file)
    
    def test_asn_list_caching(self):
        """Test ASN list caching mechanism"""
        mock_response = Mock()
        mock_response.text = "99999\n88888"
        mock_response.raise_for_status = Mock()
        
        with patch('requests.get', return_value=mock_response) as mock_get, \
             tempfile.TemporaryDirectory() as tmpdir:
            
            with patch('app.CACHE_DIR', tmpdir):
                import app
                
                # First fetch - should hit network
                asns1 = app.fetch_asn_list('http://example.com/asns.txt', cache_hours=1)
                assert mock_get.call_count == 1
                
                # Second fetch - should use cache
                asns2 = app.fetch_asn_list('http://example.com/asns.txt', cache_hours=1)
                assert mock_get.call_count == 1  # No additional call
                
                assert asns1 == asns2
    
    def test_asn_list_cache_expiry(self):
        """Test ASN list cache expiration"""
        mock_response = Mock()
        mock_response.text = "99999"
        mock_response.raise_for_status = Mock()
        
        with patch('requests.get', return_value=mock_response) as mock_get, \
             tempfile.TemporaryDirectory() as tmpdir:
            
            with patch('app.CACHE_DIR', tmpdir):
                import app
                
                # First fetch
                app.fetch_asn_list('http://example.com/asns.txt', cache_hours=1)
                
                # Manipulate cache time to simulate expiry
                import glob
                time_files = glob.glob(os.path.join(tmpdir, '*.time'))
                if time_files:
                    with open(time_files[0], 'w') as f:
                        f.write(str(time.time() - 7200))  # 2 hours ago
                
                # Second fetch - should refetch due to expiry
                app.fetch_asn_list('http://example.com/asns.txt', cache_hours=1)
                assert mock_get.call_count == 2


class TestHealthEndpoint:
    """Test health check endpoint"""
    
    def test_health_endpoint_response(self):
        """Health endpoint should return status and configuration"""
        with patch('app.country_reader', Mock()), \
             patch('app.asn_reader', Mock()), \
             patch('app.ip_mode', 'blacklist'), \
             patch('app.IP_WHITELIST', {1, 2}), \
             patch('app.IP_BLACKLIST', {3, 4, 5}), \
             patch('app.country_mode', 'whitelist'), \
             patch('app.COUNTRY_WHITELIST', ['US', 'CA']), \
             patch('app.asn_mode', 'blacklist'), \
             patch('app.ASN_WHITELIST', {212238}), \
             patch('app.ASN_BLACKLIST', set(range(100))), \
             patch('app.ALLOW_LAN', True), \
             patch('app.ALLOW_UNKNOWN', False):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            response = client.get('/health')
            assert response.status_code == 200
            
            data = response.get_json()
            assert data['status'] == 'healthy'
            assert data['country_db'] == True
            assert data['asn_db'] == True
            assert data['config']['ip_mode'] == 'blacklist'
            assert data['config']['ip_whitelist_count'] == 2
            assert data['config']['ip_blacklist_count'] == 3
            assert data['config']['country_mode'] == 'whitelist'
            assert data['config']['asn_mode'] == 'blacklist'
            assert data['config']['asn_whitelist_count'] == 1
            assert data['config']['asn_blacklist_count'] == 100
            assert data['config']['allow_lan'] == True
            assert data['config']['allow_unknown'] == False


class TestIPExtraction:
    """Test client IP extraction from headers"""
    
    def test_x_forwarded_for_header(self):
        """Should extract IP from X-Forwarded-For header"""
        with patch('app.country_reader', None), \
             patch('app.asn_reader', None), \
             patch('app.ip_mode', 'disabled'), \
             patch('app.ALLOW_LAN', False):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            with app.app.test_request_context(
                headers={'X-Forwarded-For': '1.2.3.4, 5.6.7.8'}
            ):
                ip = app.get_client_ip()
                assert ip == '1.2.3.4'  # Should get first IP
    
    def test_x_real_ip_header(self):
        """Should fall back to X-Real-IP header"""
        with patch('app.country_reader', None), \
             patch('app.asn_reader', None):
            
            import app
            app.app.config['TESTING'] = True
            
            with app.app.test_request_context(
                headers={'X-Real-IP': '1.2.3.4'}
            ):
                ip = app.get_client_ip()
                assert ip == '1.2.3.4'


class TestErrorHandling:
    """Test error handling and fail-open behavior"""
    
    def test_exception_fails_open(self):
        """Exceptions should fail open (allow) to prevent service disruption"""
        mock_reader = Mock()
        mock_reader.country.side_effect = Exception("Database error")
        
        with patch('app.country_reader', mock_reader), \
             patch('app.asn_reader', None), \
             patch('app.country_mode', 'whitelist'), \
             patch('app.COUNTRY_WHITELIST', ['US']), \
             patch('app.ALLOW_LAN', False):
            
            import app
            app.app.config['TESTING'] = True
            client = app.app.test_client()
            
            response = client.get('/verify', headers={'X-Forwarded-For': '1.2.3.4'})
            # Should allow despite error
            assert response.status_code == 200


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
