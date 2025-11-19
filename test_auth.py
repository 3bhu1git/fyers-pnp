"""
Unit tests for Fyers Authentication Module

Run with: pytest test_auth.py -v
"""

import pytest
import json
import yaml
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import queue
import threading

from auth import (
    FyersAuth,
    FyersAuthConfig,
    FyersAuthError,
    AuthCodeHandler
)


class TestFyersAuthConfig:
    """Test configuration management"""
    
    def test_config_load_success(self):
        """Test successful config loading"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            creds_data = {
                'client_id': 'test_client',
                'secret_key': 'test_secret',
                'redirect_uri': 'http://localhost:8080'
            }
            yaml.dump(creds_data, f)
            creds_path = f.name
        
        # Create optional config.json
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_data = {'port': 9000}
            json.dump(config_data, f)
            config_path = f.name
        
        try:
            config = FyersAuthConfig(creds_path, config_path)
            assert config['client_id'] == 'test_client'
            assert config['secret_key'] == 'test_secret'
            assert config['redirect_uri'] == 'http://localhost:8080'
            assert config['port'] == 9000  # From config.json
        finally:
            os.unlink(creds_path)
            os.unlink(config_path)
    
    def test_config_missing_required_field(self):
        """Test config with missing required field"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            creds_data = {
                'client_id': 'test_client',
                # Missing secret_key
                'redirect_uri': 'http://localhost:8080'
            }
            yaml.dump(creds_data, f)
            creds_path = f.name
        
        try:
            with pytest.raises(ValueError, match="Missing required credential fields"):
                FyersAuthConfig(creds_path)
        finally:
            os.unlink(creds_path)
    
    def test_config_file_not_found(self):
        """Test creds file not found"""
        with pytest.raises(FileNotFoundError):
            FyersAuthConfig('nonexistent_creds.yaml')
    
    def test_config_optional_fields_defaults(self):
        """Test optional fields get default values"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            creds_data = {
                'client_id': 'test_client',
                'secret_key': 'test_secret',
                'redirect_uri': 'http://localhost:8080'
            }
            yaml.dump(creds_data, f)
            creds_path = f.name
        
        try:
            # Test without config.json (should use defaults)
            config = FyersAuthConfig(creds_path, 'nonexistent_config.json')
            assert config['port'] == 8080
            assert config['token_file'] == 'fyers_token.json'
            assert config['log_max_bytes'] == 10 * 1024 * 1024
        finally:
            os.unlink(creds_path)
    
    def test_config_merges_creds_and_config(self):
        """Test that config.json values are merged with creds.yaml"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            creds_data = {
                'client_id': 'test_client',
                'secret_key': 'test_secret',
                'redirect_uri': 'http://localhost:8080'
            }
            yaml.dump(creds_data, f)
            creds_path = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_data = {
                'port': 9000,
                'token_file': 'custom_token.json'
            }
            json.dump(config_data, f)
            config_path = f.name
        
        try:
            config = FyersAuthConfig(creds_path, config_path)
            assert config['client_id'] == 'test_client'  # From creds
            assert config['port'] == 9000  # From config
            assert config['token_file'] == 'custom_token.json'  # From config
            assert config['log_file'] == 'logs/fyers_auth.log'  # Default
        finally:
            os.unlink(creds_path)
            os.unlink(config_path)


class TestFyersAuth:
    """Test Fyers authentication module"""
    
    @pytest.fixture
    def temp_config(self):
        """Create temporary creds and config files"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            creds_data = {
                'client_id': 'test_client',
                'secret_key': 'test_secret',
                'redirect_uri': 'http://localhost:8080'
            }
            yaml.dump(creds_data, f)
            creds_path = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_data = {
                'port': 8080,
                'token_file': 'test_token.json',
                'log_file': 'test_log.log'
            }
            json.dump(config_data, f)
            config_path = f.name
        
        yield (creds_path, config_path)
        
        # Cleanup
        if os.path.exists(creds_path):
            os.unlink(creds_path)
        if os.path.exists(config_path):
            os.unlink(config_path)
        if os.path.exists('test_token.json'):
            os.unlink('test_token.json')
        if os.path.exists('test_log.log'):
            os.unlink('test_log.log')
    
    def test_init_loads_existing_tokens(self, temp_config):
        """Test initialization loads existing valid tokens"""
        creds_path, config_path = temp_config
        # Create token file with valid token
        token_data = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'expiry': (datetime.now() + timedelta(hours=1)).isoformat()
        }
        with open('test_token.json', 'w') as f:
            json.dump(token_data, f)
        
        auth = FyersAuth(creds_path, config_path)
        assert auth.access_token == 'test_access_token'
        assert auth.refresh_token == 'test_refresh_token'
    
    def test_init_expired_tokens(self, temp_config):
        """Test initialization clears expired tokens"""
        creds_path, config_path = temp_config
        # Create token file with expired token
        token_data = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'expiry': (datetime.now() - timedelta(hours=1)).isoformat()
        }
        with open('test_token.json', 'w') as f:
            json.dump(token_data, f)
        
        auth = FyersAuth(creds_path, config_path)
        assert auth.access_token is None
        assert auth.refresh_token is None
    
    def test_get_auth_url(self, temp_config):
        """Test authorization URL generation"""
        creds_path, config_path = temp_config
        auth = FyersAuth(creds_path, config_path)
        auth_url = auth.get_auth_url()
        
        assert 'api.fyers.in' in auth_url
        assert 'redirect_uri' in auth_url
        assert 'response_type=code' in auth_url
    
    @patch('auth.requests.post')
    def test_exchange_code_for_token_success(self, mock_post, temp_config):
        """Test successful token exchange"""
        # Mock successful token response
        mock_response = Mock()
        mock_response.json.return_value = {
            's': 'ok',
            'access_token': 'new_access_token',
            'refresh_token': 'new_refresh_token',
            'expires_in': 86400
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        creds_path, config_path = temp_config
        auth = FyersAuth(creds_path, config_path)
        result = auth._exchange_code_for_token('test_auth_code')
        
        assert result is True
        assert auth.access_token == 'new_access_token'
        assert auth.refresh_token == 'new_refresh_token'
        assert auth.token_expiry is not None
    
    @patch('auth.requests.post')
    def test_exchange_code_for_token_failure(self, mock_post, temp_config):
        """Test failed token exchange"""
        # Mock failed token response
        mock_response = Mock()
        mock_response.json.return_value = {
            's': 'error',
            'message': 'Invalid code'
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        creds_path, config_path = temp_config
        auth = FyersAuth(creds_path, config_path)
        result = auth._exchange_code_for_token('invalid_code')
        
        assert result is False
        assert auth.access_token is None
    
    @patch('auth.requests.post')
    def test_refresh_access_token_success(self, mock_post, temp_config):
        """Test successful token refresh"""
        # Set up auth with refresh token
        creds_path, config_path = temp_config
        auth = FyersAuth(creds_path, config_path)
        auth.refresh_token = 'test_refresh_token'
        
        # Mock successful refresh response
        mock_response = Mock()
        mock_response.json.return_value = {
            's': 'ok',
            'access_token': 'refreshed_access_token',
            'refresh_token': 'refreshed_refresh_token',
            'expires_in': 86400
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        result = auth.refresh_access_token()
        
        assert result is True
        assert auth.access_token == 'refreshed_access_token'
    
    @patch('auth.requests.post')
    def test_refresh_access_token_no_refresh_token(self, mock_post, temp_config):
        """Test refresh fails when no refresh token available"""
        creds_path, config_path = temp_config
        auth = FyersAuth(creds_path, config_path)
        auth.refresh_token = None
        
        result = auth.refresh_access_token()
        
        assert result is False
        mock_post.assert_not_called()
    
    def test_get_access_token_valid(self, temp_config):
        """Test getting valid access token"""
        creds_path, config_path = temp_config
        auth = FyersAuth(creds_path, config_path)
        auth.access_token = 'test_token'
        auth.token_expiry = datetime.now() + timedelta(hours=1)
        
        token = auth.get_access_token()
        assert token == 'test_token'
    
    def test_get_access_token_expired(self, temp_config):
        """Test getting expired access token triggers refresh"""
        creds_path, config_path = temp_config
        auth = FyersAuth(creds_path, config_path)
        auth.access_token = 'test_token'
        auth.refresh_token = 'test_refresh'
        auth.token_expiry = datetime.now() - timedelta(minutes=10)
        
        with patch.object(auth, 'refresh_access_token', return_value=True) as mock_refresh:
            token = auth.get_access_token()
            mock_refresh.assert_called_once()
    
    def test_is_authenticated(self, temp_config):
        """Test authentication status check"""
        creds_path, config_path = temp_config
        auth = FyersAuth(creds_path, config_path)
        
        # Not authenticated
        assert auth.is_authenticated() is False
        
        # Authenticated
        auth.access_token = 'test_token'
        auth.token_expiry = datetime.now() + timedelta(hours=1)
        assert auth.is_authenticated() is True
    
    def test_get_auth_headers(self, temp_config):
        """Test getting authorization headers"""
        creds_path, config_path = temp_config
        auth = FyersAuth(creds_path, config_path)
        auth.access_token = 'test_token'
        auth.token_expiry = datetime.now() + timedelta(hours=1)
        
        headers = auth.get_auth_headers()
        assert 'Authorization' in headers
        assert headers['Authorization'] == 'Bearer test_token'
        assert headers['Content-Type'] == 'application/json'
    
    def test_get_auth_headers_not_authenticated(self, temp_config):
        """Test getting headers when not authenticated raises error"""
        creds_path, config_path = temp_config
        auth = FyersAuth(creds_path, config_path)
        
        with pytest.raises(FyersAuthError, match="Not authenticated"):
            auth.get_auth_headers()
    
    def test_logout(self, temp_config):
        """Test logout clears tokens"""
        creds_path, config_path = temp_config
        auth = FyersAuth(creds_path, config_path)
        auth.access_token = 'test_token'
        auth.refresh_token = 'test_refresh'
        auth.token_expiry = datetime.now() + timedelta(hours=1)
        
        # Create token file
        with open('test_token.json', 'w') as f:
            json.dump({'access_token': 'test'}, f)
        
        auth.logout()
        
        assert auth.access_token is None
        assert auth.refresh_token is None
        assert auth.token_expiry is None
        assert not os.path.exists('test_token.json')


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

