# Fyers Trading API Wrapper

Production-ready Python wrapper for Fyers Trading API v3 with low latency, comprehensive logging, and background service support.

## Features

- **Authentication Module**: OAuth2 flow with automatic token refresh
- **Production Ready**: Low latency, error handling, logging with rotation
- **Testable**: Comprehensive unit tests
- **Modular**: Clean separation of concerns
- **Background Service**: Can run as daemon/service
- **Config-Based**: All inputs from configuration file
- **Virtual Environment**: Isolated dependencies

## Project Structure

```
fyers-pnp/
├── auth.py                # Authentication module (single file)
├── creds.yaml.example     # Credentials template (sensitive data)
├── config.json.example    # Configuration template (non-sensitive)
├── requirements.txt       # Python dependencies
├── test_auth.py          # Unit tests
├── .gitignore            # Git ignore rules
└── README.md             # This file
```

## Setup

### 1. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure

Copy the example files and fill in your credentials:

```bash
cp creds.yaml.example creds.yaml
cp config.json.example config.json
```

Edit `creds.yaml` with your Fyers API credentials (sensitive data):
- `client_id`: Your Fyers App ID
- `secret_key`: Your Fyers Secret Key
- `redirect_uri`: OAuth2 redirect URI (must match Fyers app settings)

Edit `config.json` with non-sensitive configuration (optional - defaults will be used if not provided):
- `port`: Local server port for OAuth callback
- `token_file`: File to store tokens
- `log_file`: Log file path
- `log_max_bytes`: Max log file size before rotation
- `log_backup_count`: Number of rotated log files to keep
- `token_refresh_interval`: Token refresh check interval in seconds
- `token_refresh_threshold`: Refresh token if expires within this many seconds

### 4. Run Authentication

```bash
python auth.py
```

Follow the prompts to authorize the application. The module will:
1. Generate authorization URL
2. Start local server to capture code
3. Exchange code for access token
4. Save tokens to disk
5. Start background token refresh thread

## Usage

### As a Module

```python
from auth import FyersAuth

# Initialize (defaults: creds.yaml and config.json)
auth = FyersAuth()

# Or specify custom paths
auth = FyersAuth('creds.yaml', 'config.json')

# Authenticate (if not already authenticated)
if not auth.is_authenticated():
    auth.authenticate()

# Get access token
token = auth.get_access_token()

# Get headers for API requests
headers = auth.get_auth_headers()
```

### As Background Service

```bash
# Using default files (creds.yaml and config.json)
python auth.py

# Or specify custom paths
python auth.py creds.yaml config.json
```

The service will:
- Authenticate on startup
- Automatically refresh tokens before expiry
- Log all activities with rotation
- Run until interrupted (Ctrl+C)

## Configuration

Configuration is split into two files for security:

### `creds.yaml` (Sensitive Data - DO NOT COMMIT)

```yaml
client_id: YOUR_CLIENT_ID
secret_key: YOUR_SECRET_KEY
redirect_uri: http://localhost:8080
```

### `config.json` (Non-Sensitive Settings - Can be committed)

```json
{
  "port": 8080,
  "token_file": "fyers_token.json",
  "log_file": "logs/fyers_auth.log",
  "log_max_bytes": 10485760,
  "log_backup_count": 5,
  "token_refresh_interval": 3600,
  "token_refresh_threshold": 300
}
```

**Note**: `config.json` is optional. If not provided, default values will be used.

### Configuration Fields

**creds.yaml (Required):**
- **client_id**: Fyers App ID
- **secret_key**: Fyers Secret Key
- **redirect_uri**: OAuth2 redirect URI

**config.json (Optional - defaults shown):**
- **port**: Local server port for OAuth callback (default: 8080)
- **token_file**: File to store tokens (default: fyers_token.json)
- **log_file**: Log file path (default: logs/fyers_auth.log)
- **log_max_bytes**: Max log file size before rotation (default: 10MB)
- **log_backup_count**: Number of rotated log files to keep (default: 5)
- **token_refresh_interval**: Token refresh check interval in seconds (default: 3600)
- **token_refresh_threshold**: Refresh token if expires within this many seconds (default: 300)

## Testing

### Unit Tests

Run unit tests with pytest:

```bash
pip install pytest pytest-mock pytest-cov
pytest test_auth.py -v
```

Run with coverage:

```bash
pytest test_auth.py --cov=auth --cov-report=html
```

### Manual Testing

Run the interactive manual test script:

```bash
python test_manual.py
```

This will guide you through testing:
- Configuration loading
- Authorization URL generation
- Token loading
- Authentication status
- Auth headers generation
- Full authentication flow

### Quick Test

Test basic functionality:

```python
from auth import FyersAuth

# Load config
auth = FyersAuth()

# Check if authenticated
if not auth.is_authenticated():
    auth.authenticate()

# Get auth headers for API calls
headers = auth.get_auth_headers()
```

See [TESTING.md](TESTING.md) for comprehensive testing guide.

## Logging

Logs are written to:
- **File**: `logs/fyers_auth.log` (rotating, max 10MB, 5 backups)
- **Console**: Standard output for immediate feedback

Log format: `YYYY-MM-DD HH:MM:SS - FyersAuth - LEVEL - MESSAGE`

## Token Management

- Tokens are automatically saved to `fyers_token.json`
- Tokens are automatically refreshed before expiry
- Refresh happens in background thread
- On startup, valid tokens are loaded from disk

## Error Handling

The module raises `FyersAuthError` for authentication failures. All errors are logged with full context.

## Security Notes

- **Never commit** `creds.yaml` or `fyers_token.json` to version control
- `config.json` can be safely committed (contains no sensitive data)
- Keep credentials secure
- Use environment variables for production deployments
- Tokens are stored in plain JSON (consider encryption for production)

## Dependencies

- `requests>=2.31.0`: HTTP client for API calls
- `PyYAML>=6.0.1`: YAML configuration file parser

## License

MIT License - See LICENSE file for details

## Next Steps

Future modules to be added:
- Order management module
- Real-time data consumption module
- Portfolio management module
- Market data module

# fyers-pnp
