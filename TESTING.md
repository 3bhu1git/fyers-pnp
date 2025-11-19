# Testing Guide for Fyers Auth Module

This guide covers all testing methods for the Fyers authentication module.

## Table of Contents

1. [Unit Tests](#unit-tests)
2. [Manual Testing](#manual-testing)
3. [Integration Testing](#integration-testing)
4. [Test Coverage](#test-coverage)

## Unit Tests

### Prerequisites

Install test dependencies:

```bash
pip install pytest pytest-mock pytest-cov
```

### Running Unit Tests

Run all unit tests:

```bash
pytest test_auth.py -v
```

Run with coverage:

```bash
pytest test_auth.py --cov=auth --cov-report=html --cov-report=term
```

Run specific test class:

```bash
pytest test_auth.py::TestFyersAuthConfig -v
pytest test_auth.py::TestFyersAuth -v
```

Run specific test:

```bash
pytest test_auth.py::TestFyersAuthConfig::test_config_load_success -v
```

### What Unit Tests Cover

- **Configuration Management**:
  - Loading credentials from YAML
  - Loading config from JSON
  - Merging creds and config
  - Missing required fields validation
  - Optional fields defaults

- **Authentication Flow**:
  - Authorization URL generation
  - Token exchange
  - Token refresh
  - Token persistence
  - Authentication status checks

- **Error Handling**:
  - Invalid credentials
  - Missing files
  - Network errors
  - Expired tokens

## Manual Testing

### Quick Manual Test Script

Use the provided manual test script:

```bash
python test_manual.py
```

This script will:
1. Test configuration loading
2. Test auth URL generation
3. Test token loading from file
4. Check authentication status
5. Test auth headers generation
6. Optionally run full authentication flow

### Step-by-Step Manual Testing

#### 1. Setup Test Environment

```bash
# Activate virtual environment
source venv/bin/activate  # or: venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt

# Copy example files
cp creds.yaml.example creds.yaml
cp config.json.example config.json

# Edit creds.yaml with your actual credentials
# Edit config.json if you want custom settings
```

#### 2. Test Configuration Loading

```python
from auth import FyersAuth

# Should load without errors
auth = FyersAuth()
print(f"Client ID: {auth.config['client_id']}")
print(f"Port: {auth.config['port']}")
```

#### 3. Test Authorization URL Generation

```python
from auth import FyersAuth

auth = FyersAuth()
auth_url = auth.get_auth_url()
print(f"Visit: {auth_url}")
# Copy URL and open in browser
```

#### 4. Test Full Authentication Flow

```bash
python auth.py
```

This will:
- Generate authorization URL
- Start local server on port 8080 (or configured port)
- Wait for authorization code
- Exchange code for access token
- Save tokens to file
- Start background refresh thread

**Expected Flow:**
1. Script prints authorization URL
2. Open URL in browser
3. Login to Fyers and authorize
4. Browser redirects to localhost:8080 with code
5. Script captures code and exchanges for token
6. Success message displayed

#### 5. Test Token Persistence

```python
from auth import FyersAuth

# First run - authenticate
auth1 = FyersAuth()
if not auth1.is_authenticated():
    auth1.authenticate()

# Second run - should load tokens from file
auth2 = FyersAuth()
assert auth2.is_authenticated()
print("✓ Tokens loaded from file")
```

#### 6. Test Token Refresh

```python
from auth import FyersAuth
import time

auth = FyersAuth()

if auth.is_authenticated():
    print("Waiting for token refresh...")
    # Token refresh happens automatically in background
    # Or manually:
    auth.refresh_access_token()
```

#### 7. Test Auth Headers

```python
from auth import FyersAuth

auth = FyersAuth()

if auth.is_authenticated():
    headers = auth.get_auth_headers()
    print(f"Authorization: {headers['Authorization'][:50]}...")
    # Use these headers for API requests
```

## Integration Testing

### Test with Real Fyers API

**⚠️ Warning**: This uses real API credentials and makes actual API calls.

#### Prerequisites

1. Valid Fyers API credentials in `creds.yaml`
2. Fyers app configured with matching redirect URI
3. Internet connection

#### Test Script

Create `test_integration.py`:

```python
"""Integration test with real Fyers API"""
from auth import FyersAuth, FyersAuthError
import requests

def test_real_authentication():
    """Test authentication with real Fyers API"""
    auth = FyersAuth()
    
    # Authenticate
    if not auth.is_authenticated():
        print("Starting authentication...")
        success = auth.authenticate()
        assert success, "Authentication failed"
    
    # Get headers
    headers = auth.get_auth_headers()
    
    # Test API call (example: get profile)
    response = requests.get(
        'https://api.fyers.in/v3/profile',
        headers=headers
    )
    
    assert response.status_code == 200, f"API call failed: {response.text}"
    print("✓ Integration test passed")

if __name__ == '__main__':
    test_real_authentication()
```

Run:

```bash
python test_integration.py
```

### Test Token Refresh

```python
from auth import FyersAuth
import time

auth = FyersAuth()

# Force token refresh
if auth.refresh_token:
    print("Testing token refresh...")
    success = auth.refresh_access_token()
    assert success, "Token refresh failed"
    print("✓ Token refreshed successfully")
```

## Test Coverage

### Current Coverage

Run coverage report:

```bash
pytest test_auth.py --cov=auth --cov-report=term-missing
```

### Areas to Test

- [x] Configuration loading (YAML + JSON)
- [x] Authorization URL generation
- [x] Token exchange
- [x] Token refresh
- [x] Token persistence
- [x] Error handling
- [x] Authentication status
- [x] Auth headers generation
- [ ] Network error handling
- [ ] Token expiry edge cases
- [ ] Concurrent access
- [ ] Background refresh thread

## Troubleshooting Tests

### Common Issues

1. **Import Errors**
   ```bash
   # Make sure you're in the project directory
   cd /path/to/fyers-pnp
   
   # Install dependencies
   pip install -r requirements.txt
   ```

2. **Config File Not Found**
   ```bash
   # Make sure creds.yaml exists
   ls -la creds.yaml
   
   # Copy from example if missing
   cp creds.yaml.example creds.yaml
   ```

3. **Port Already in Use**
   ```bash
   # Change port in config.json
   # Or kill process using port 8080
   lsof -ti:8080 | xargs kill -9  # macOS/Linux
   ```

4. **Authentication Timeout**
   - Increase timeout in auth.py
   - Check redirect URI matches Fyers app settings
   - Verify credentials are correct

5. **Token Refresh Fails**
   - Check refresh_token exists
   - Verify token hasn't expired
   - Check network connection

## Continuous Integration

### GitHub Actions Example

Create `.github/workflows/test.yml`:

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.8, 3.9, '3.10', '3.11']
    
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v2
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install pytest pytest-cov pytest-mock
    
    - name: Run tests
      run: |
        pytest test_auth.py -v --cov=auth --cov-report=xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v2
```

## Best Practices

1. **Always test in virtual environment**
2. **Never commit real credentials**
3. **Use mocks for unit tests**
4. **Test error cases, not just happy paths**
5. **Test edge cases (expired tokens, network errors)**
6. **Run tests before committing**
7. **Keep test coverage above 80%**

## Next Steps

- Add more edge case tests
- Add performance tests
- Add stress tests for concurrent access
- Add tests for background refresh thread
- Add integration tests with mock Fyers API server


