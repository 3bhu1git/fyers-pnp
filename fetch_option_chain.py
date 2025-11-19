#!/usr/bin/env python3
"""
Fyers Option Chain Fetcher

Fetches Nifty option chain data for a given expiry date.
Production-ready with comprehensive logging and error handling.

Usage:
    python fetch_option_chain.py [--expiry YYYY-MM-DD] [--strike-count N] [--output FILE]
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys
from datetime import datetime, time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional

from fyers_apiv3 import fyersModel
from auth import FyersAuth, FyersAuthError

# -------------------------
# Logger setup
# -------------------------

LOGFILE_DEFAULT = "logs/fetch_option_chain.log"
logger = logging.getLogger("fetch_option_chain")
logger.setLevel(logging.INFO)

if not logger.handlers:
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    fh = RotatingFileHandler(LOGFILE_DEFAULT, maxBytes=10 * 1024 * 1024, backupCount=5)
    fh.setLevel(logging.INFO)
    
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    
    fmt = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    fh.setFormatter(fmt)
    ch.setFormatter(fmt)
    
    logger.addHandler(fh)
    logger.addHandler(ch)


# -------------------------
# Exceptions
# -------------------------


class OptionChainError(Exception):
    """Raised for option chain errors"""
    pass


# -------------------------
# Option Chain Fetcher
# -------------------------


class FyersOptionChain:
    """
    Fyers Option Chain Fetcher
    
    Features:
    - Fetch option chain data for Nifty
    - Filter by expiry date
    - Filter by strike interval
    - Export to JSON/CSV
    - Comprehensive logging
    """
    
    def __init__(self, auth: FyersAuth):
        """
        Initialize Option Chain Fetcher.
        
        Args:
            auth: FyersAuth instance (token should be loaded from fyers_token.json)
        """
        self.auth = auth
        self.fyers: Optional[fyersModel.FyersModel] = None
        
        # Always use token from fyers_token.json - never trigger interactive auth
        if not self.auth.access_token:
            logger.error("No token found in fyers_token.json")
            raise OptionChainError(
                "No token found in fyers_token.json. Please run 'python auth.py' to authenticate first.\n"
                "The token will be saved to fyers_token.json for future use."
            )
        
        # Token exists - check validity and refresh if needed
        self._validate_and_refresh_token()
        
        # Initialize FyersModel with token from file
        self._init_fyers()
        logger.info("Initialized Fyers Option Chain Fetcher using token from fyers_token.json")
    
    def _validate_and_refresh_token(self) -> None:
        """
        Validate token from fyers_token.json and refresh if expired.
        Never triggers interactive authentication - only uses token from file.
        Always tries to use token even if refresh fails - API call will validate it.
        """
        if not self.auth.token_expiry:
            logger.info("Token from fyers_token.json exists (no expiry info) - will use it")
            return
        
        # Check if token is expired
        time_until_expiry = (self.auth.token_expiry - datetime.now()).total_seconds()
        if time_until_expiry > 300:  # More than 5 minutes left
            logger.info("Token from fyers_token.json is valid (expires in %.0f seconds)", time_until_expiry)
            return
        elif time_until_expiry > 0:
            logger.info("Token from fyers_token.json expiring soon (%.0f seconds), attempting refresh...", time_until_expiry)
            if self.auth.refresh_token:
                if self.auth.refresh_access_token():
                    logger.info("Token refreshed successfully and saved to fyers_token.json")
                    return
                else:
                    logger.info("Token refresh failed, but will try to use existing token (may still be valid)")
            else:
                logger.info("No refresh_token available, will use existing token")
        else:
            logger.info("Token from fyers_token.json is expired (expired %.0f seconds ago), attempting refresh...", abs(time_until_expiry))
            # Try to refresh expired token
            if self.auth.refresh_token:
                if self.auth.refresh_access_token():
                    logger.info("Token refreshed successfully and saved to fyers_token.json")
                    return
                else:
                    logger.info("Token refresh failed, but will try to use existing token (may still work for API calls)")
            else:
                logger.info("No refresh_token available, will try to use existing token")
        
        # Always proceed - let API call validate the token
        logger.info("Proceeding with token from fyers_token.json - API call will validate if it's still valid")
    
    def _init_fyers(self) -> None:
        """Initialize FyersModel instance with current access token from fyers_token.json"""
        if not self.auth.access_token:
            raise OptionChainError("No access token available")
        
        client_id = self.auth.config.get("client_id")
        # SDK expects just the access_token, not client_id:access_token
        # The SDK internally handles adding client_id to the header
        access_token = self.auth.access_token
        
        # Log token usage for debugging - confirm we're using token from file
        logger.info("Using token from fyers_token.json")
        logger.info("Token source: fyers_token.json file")
        logger.info("Client ID: %s", client_id)
        logger.debug("Token prefix: %s...", access_token[:30] if access_token else "None")
        logger.debug("Token length: %d", len(access_token))
        
        # Create logs directory if needed
        log_path = Path("logs")
        log_path.mkdir(exist_ok=True)
        
        self.fyers = fyersModel.FyersModel(
            client_id=client_id,
            token=access_token,  # Just access_token, SDK handles client_id internally
            is_async=False,
            log_path=str(log_path) + "/"
        )
        logger.info("FyersModel initialized with token from fyers_token.json")
    
    def _refresh_fyers_if_needed(self) -> None:
        """Refresh FyersModel instance if token was refreshed"""
        # Re-initialize FyersModel with updated token if it was refreshed
        if self.fyers and self.auth.access_token:
            # Token might have been refreshed, re-init to use new token
            logger.debug("Re-initializing FyersModel with current token")
            self._init_fyers()
    
    def _get_valid_expiry_timestamp(self, symbol: str, target_date: Optional[str] = None) -> Optional[int]:
        """
        Get valid expiry timestamp from API for a given date.
        
        Args:
            symbol: Symbol name
            target_date: Target date in DD-MM-YYYY format (e.g., "25-11-2025")
        
        Returns:
            Valid expiry timestamp or None if not found
        """
        try:
            # Make a call with invalid timestamp to get valid expiries
            # Use a far future timestamp that will definitely be invalid
            invalid_timestamp = 9999999999
            data = {"symbol": symbol, "strikecount": 1, "timestamp": invalid_timestamp}
            response = self.fyers.optionchain(data=data)
            
            if response.get("s") == "error" and "data" in response:
                expiry_data = response.get("data", {}).get("expiryData", [])
                if expiry_data:
                    if target_date:
                        # Find matching date
                        for exp in expiry_data:
                            if exp.get("date") == target_date:
                                return int(exp.get("expiry"))
                        logger.warning("Date %s not found in valid expiries", target_date)
                    else:
                        # Return first expiry (current)
                        return int(expiry_data[0].get("expiry"))
            return None
        except Exception as e:
            logger.warning("Failed to get valid expiry timestamps: %s", e)
            return None
    
    def fetch_option_chain(
        self,
        symbol: str = "NSE:NIFTY50-INDEX",
        expiry_timestamp: Optional[int] = None,
        expiry_date: Optional[str] = None,
        strike_count: int = 10
    ) -> Dict[str, Any]:
        """
        Fetch option chain data for given symbol and expiry.
        
        Args:
            symbol: Symbol name (default: NSE:NIFTY50-INDEX)
            expiry_timestamp: Expiry timestamp (Unix timestamp). Use None for current expiry.
            expiry_date: Expiry date in DD-MM-YYYY format (e.g., "25-11-2025"). 
                        If provided, will lookup valid timestamp from API.
            strike_count: Number of strike price data points (default: 10)
                         Example: 10 gives 1 INDEX + 10 ITM + 1 ATM + 10 OTM = 21 strikes
        
        Returns:
            Dictionary containing option chain data
        """
        # Ensure FyersModel is initialized and token is valid
        self._refresh_fyers_if_needed()
        
        if not self.fyers:
            raise OptionChainError("FyersModel not initialized")
        
        try:
            # If expiry_date is provided, lookup valid timestamp
            if expiry_date and not expiry_timestamp:
                logger.info("Looking up valid expiry timestamp for date: %s", expiry_date)
                expiry_timestamp = self._get_valid_expiry_timestamp(symbol, expiry_date)
                if not expiry_timestamp:
                    raise OptionChainError(f"Could not find valid expiry timestamp for date: {expiry_date}")
                logger.info("Found valid expiry timestamp: %d for date: %s", expiry_timestamp, expiry_date)
            
            logger.info(
                "Fetching option chain for symbol: %s, expiry_timestamp: %s, strike_count: %d",
                symbol, expiry_timestamp or "current", strike_count
            )
            
            # Prepare data payload
            # API expects: symbol, timestamp (optional), strikecount
            data = {
                "symbol": symbol,
                "strikecount": strike_count
            }
            if expiry_timestamp:
                data["timestamp"] = expiry_timestamp
            
            # Call optionchain API
            # Verify we're using the token from fyers_token.json
            logger.debug("Making API call with token from fyers_token.json")
            logger.debug("Using access_token from fyers_token.json (length: %d)", len(self.auth.access_token) if self.auth.access_token else 0)
            logger.debug("API call data: %s", data)
            logger.debug("FyersModel client_id: %s", self.auth.config.get("client_id"))
            
            response = self.fyers.optionchain(data=data)
            
            logger.debug("API response status: %s", response.get("s"))
            logger.debug("API response code: %s", response.get("code"))
            logger.debug("API response message: %s", response.get("message"))
            
            # Handle API errors
            if response.get("s") != "ok":
                error_msg = response.get("message", "Unknown error")
                error_code = response.get("code")
                
                # Check if it's an expiry validation error - API returns valid expiries in response
                if error_code == 1 and "expiry" in error_msg.lower() and "data" in response:
                    expiry_data = response.get("data", {}).get("expiryData", [])
                    if expiry_data:
                        logger.warning("Invalid expiry timestamp provided. Valid expiries available:")
                        for exp in expiry_data[:5]:  # Log first 5
                            logger.info("  Date: %s, Timestamp: %s", exp.get("date"), exp.get("expiry"))
                        
                        # If user provided a date, try to find matching expiry
                        if expiry_timestamp:
                            # Try to find closest expiry or suggest using None for current expiry
                            logger.warning("Expiry timestamp %d is not valid. Use one of the timestamps above, or omit timestamp for current expiry.", expiry_timestamp)
                            raise OptionChainError(
                                f"Invalid expiry timestamp: {expiry_timestamp}. "
                                f"Valid expiries: {[exp.get('date') + ' (' + exp.get('expiry') + ')' for exp in expiry_data[:5]]}. "
                                "Or omit --expiry to use current expiry."
                            )
                        else:
                            raise OptionChainError(f"Expiry validation error: {error_msg}")
                
                # Check if it's an authentication error
                is_auth_error = (
                    error_code in [401, 403] or 
                    "token" in error_msg.lower() or 
                    "auth" in error_msg.lower() or 
                    "valid token" in error_msg.lower() or
                    "authenticate" in error_msg.lower()
                )
                
                if is_auth_error:
                    logger.warning("API call failed with auth error: %s", error_msg)
                    logger.info("Attempting to refresh token using refresh_token from fyers_token.json...")
                    
                    # Try to refresh token first (if refresh_token exists)
                    refresh_success = False
                    if self.auth.refresh_token:
                        refresh_success = self.auth.refresh_access_token()
                    
                    if refresh_success:
                        logger.info("Token refreshed successfully, saved to fyers_token.json, retrying API call...")
                        # Re-initialize FyersModel with new token
                        self._init_fyers()
                        # Retry the API call
                        response = self.fyers.optionchain(data=data)
                        
                        # Check if retry succeeded
                        if response.get("s") == "ok":
                            logger.info("API call succeeded after token refresh")
                        else:
                            # Still failing after refresh
                            logger.error("API call still failing after token refresh")
                            raise OptionChainError(
                                f"API call failed even after token refresh: {response.get('message', 'Unknown error')}"
                            )
                    else:
                        # Refresh failed - token in fyers_token.json is invalid
                        # Do NOT trigger interactive authentication - only use token from file
                        logger.error("Token from fyers_token.json is invalid and refresh failed")
                        logger.error("Error: %s (code: %s)", error_msg, error_code)
                        logger.error("Please run 'python auth.py' to generate a new token")
                        raise OptionChainError(
                            f"Token from fyers_token.json is invalid: {error_msg}. "
                            "Please run 'python auth.py' to authenticate and generate a new token. "
                            "The token will be saved to fyers_token.json for future use."
                        )
                else:
                    # Not an auth error - some other API error
                    logger.error("API call failed with non-auth error: %s (code: %s)", error_msg, error_code)
                    raise OptionChainError(f"API call failed: {error_msg}")
            
            if response.get("s") == "ok":
                logger.info("Successfully fetched option chain data")
                return response
            else:
                error_msg = response.get("message", "Unknown error")
                logger.error("Option chain fetch failed: %s", error_msg)
                logger.debug("Full response: %s", response)
                raise OptionChainError(f"Failed to fetch option chain: {error_msg}")
        
        except OptionChainError:
            raise
        except Exception as e:
            logger.error("Error fetching option chain: %s", e)
            raise OptionChainError(f"Option chain fetch error: {e}")
    
    def extract_options(self, option_chain: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract options list from API response.
        
        Args:
            option_chain: Option chain data from API
        
        Returns:
            List of options
        """
        try:
            # Extract options from response
            # Response structure may vary - adjust based on actual API response
            options = []
            
            # Try different possible response structures
            if "data" in option_chain:
                data = option_chain["data"]
                # Data might be a dict with 'options' key or direct list
                if isinstance(data, dict):
                    if "optionsChain" in data:
                        options = data["optionsChain"]
                    elif "options" in data:
                        options = data["options"]
                    elif "optionChain" in data:
                        options = data["optionChain"]
                    else:
                        # Try to find any list in the data (skip expiryData)
                        for key, value in data.items():
                            if isinstance(value, list) and key != "expiryData":
                                options = value
                                logger.debug("Found options list in key: %s", key)
                                break
                elif isinstance(data, list):
                    options = data
            elif "optionsChain" in option_chain:
                options = option_chain["optionsChain"]
            elif "optionChain" in option_chain:
                options = option_chain["optionChain"]
            elif isinstance(option_chain, list):
                options = option_chain
            else:
                # If response structure is different, log it
                logger.warning("Unexpected option chain structure. Keys: %s", list(option_chain.keys()) if isinstance(option_chain, dict) else "Not a dict")
                # Try to find any list in the response
                if isinstance(option_chain, dict):
                    for key, value in option_chain.items():
                        if isinstance(value, list):
                            options = value
                            logger.info("Found options list in key: %s", key)
                            break
            
            if not options:
                logger.warning("No options found in response")
                logger.debug("Response structure: %s", json.dumps(option_chain, indent=2, default=str))
                return []
            
            logger.info("Extracted %d options from response", len(options))
            return options
        
        except Exception as e:
            logger.error("Error extracting options: %s", e)
            return []
    
    def format_option_data(self, options: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Format option data for display/export.
        
        Args:
            options: List of option dictionaries
        
        Returns:
            Formatted list of options
        """
        formatted = []
        for opt in options:
            # Extract expiry date and timestamp
            expiry_date_str = None
            expiry_value = opt.get("expiry") or opt.get("expiryDate") or opt.get("expiry_date") or ""
            
            # Try to get expiry_date from option data first
            if opt.get("expiry_date"):
                expiry_date_str = opt.get("expiry_date")
            elif expiry_value:
                # If expiry is a timestamp (integer), convert to date string
                try:
                    expiry_int = int(expiry_value)
                    expiry_date_str = datetime.fromtimestamp(expiry_int).strftime("%Y-%m-%d")
                except (ValueError, TypeError):
                    # If it's already a date string, try to parse it
                    if isinstance(expiry_value, str):
                        # Format: DD-MM-YYYY (from API)
                        if len(expiry_value) == 10 and expiry_value.count("-") == 2:
                            parts = expiry_value.split("-")
                            if len(parts) == 3:
                                expiry_date_str = f"{parts[2]}-{parts[1]}-{parts[0]}"
                        elif len(expiry_value) == 10:
                            # Format: YYYY-MM-DD
                            expiry_date_str = expiry_value
            
            # If still no expiry_date, try to extract from symbol
            if not expiry_date_str:
                symbol = opt.get("symbol") or opt.get("description") or opt.get("n") or ""
                if symbol:
                    # Extract from symbol format: NSE:NIFTY25NOV25600CE
                    parts = symbol.split(":")
                    if len(parts) == 2:
                        symbol_part = parts[1]  # NIFTY25NOV25600CE
                        match = re.search(r'(\d{2})([A-Z]{3})', symbol_part)
                        if match:
                            day = int(match.group(1))
                            month_str = match.group(2).upper()
                            month_map = {
                                "JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6,
                                "JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12
                            }
                            month = month_map.get(month_str)
                            if month:
                                current_year = datetime.now().year
                                current_month = datetime.now().month
                                year = current_year if month >= current_month else current_year + 1
                                expiry_date_str = f"{year:04d}-{month:02d}-{day:02d}"
            
            formatted_opt = {
                "symbol": opt.get("symbol") or opt.get("description") or opt.get("n") or "",
                "strike": opt.get("strike_price") or opt.get("strikePrice") or opt.get("strike") or "",
                "option_type": opt.get("option_type") or opt.get("optionType") or opt.get("type") or "",
                "expiry": expiry_value,
                "expiry_date": expiry_date_str or "",
                "ltp": opt.get("ltp") or opt.get("lastPrice") or opt.get("last_price") or 0,
                "volume": opt.get("volume") or opt.get("vol") or 0,
                "oi": opt.get("oi") or opt.get("openInterest") or opt.get("open_interest") or 0,
                "bid": opt.get("bid") or opt.get("bidPrice") or opt.get("bid_price") or 0,
                "ask": opt.get("ask") or opt.get("askPrice") or opt.get("ask_price") or 0,
                "iv": opt.get("iv") or opt.get("impliedVolatility") or opt.get("implied_volatility") or 0,
            }
            formatted.append(formatted_opt)
        
        return formatted
    
    def export_to_json(self, data: List[Dict[str, Any]], output_file: str) -> None:
        """Export data to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2, default=str)
            
            logger.info("Exported %d options to %s", len(data), output_file)
        except Exception as e:
            logger.error("Failed to export to JSON: %s", e)
            raise
    
    def export_to_csv(self, data: List[Dict[str, Any]], output_file: str) -> None:
        """Export data to CSV file"""
        try:
            if not data:
                logger.warning("No data to export to CSV")
                return
            
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Define CSV columns
            fieldnames = [
                "symbol", "strike", "option_type", "expiry", "expiry_date",
                "ltp", "bid", "ask", "volume", "oi", "iv"
            ]
            
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for opt in data:
                    row = {
                        "symbol": opt.get("symbol", ""),
                        "strike": opt.get("strike", ""),
                        "option_type": opt.get("option_type", ""),
                        "expiry": opt.get("expiry", ""),
                        "expiry_date": opt.get("expiry_date", ""),
                        "ltp": opt.get("ltp", 0) or 0,
                        "bid": opt.get("bid", 0) or 0,
                        "ask": opt.get("ask", 0) or 0,
                        "volume": opt.get("volume", 0) or 0,
                        "oi": opt.get("oi", 0) or 0,
                        "iv": opt.get("iv", 0) or 0,
                    }
                    writer.writerow(row)
            
            logger.info("Exported %d options to %s", len(data), output_file)
        except Exception as e:
            logger.error("Failed to export to CSV: %s", e)
            raise


# -------------------------
# CLI Runner
# -------------------------


def is_trading_hours() -> bool:
    """
    Check if current time is within trading hours (9:15 AM to 3:30 PM IST).
    
    Returns:
        True if within trading hours, False otherwise
    """
    now = datetime.now()
    current_time = now.time()
    
    # Trading hours: 9:15 AM to 3:30 PM
    trading_start = time(9, 15, 0)  # 9:15 AM
    trading_end = time(15, 30, 0)   # 3:30 PM
    
    return trading_start <= current_time <= trading_end


def main():
    parser = argparse.ArgumentParser(
        description="Fyers Nifty Option Chain Fetcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fetch option chain for 2025-11-25 expiry with strike count 10
  python fetch_option_chain.py --expiry 2025-11-25 --strike-count 10
  
  # Fetch and save to file
  python fetch_option_chain.py --expiry 2025-11-25 --strike-count 10 --output option_chain.json
  
  # Fetch current expiry (no expiry date)
  python fetch_option_chain.py --strike-count 10
        """
    )
    
    parser.add_argument(
        "--expiry",
        type=str,
        default="2025-11-25",
        help="Expiry date in YYYY-MM-DD format (default: 2025-11-25). Will be converted to timestamp."
    )
    parser.add_argument(
        "--strike-count",
        type=int,
        default=10,
        help="Number of strike price data points (default: 10). Example: 10 gives 1 INDEX + 10 ITM + 1 ATM + 10 OTM = 21 strikes."
    )
    parser.add_argument(
        "--symbol",
        type=str,
        default="NSE:NIFTY50-INDEX",
        help="Symbol name (default: NSE:NIFTY50-INDEX)"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Output JSON file path (optional)"
    )
    parser.add_argument(
        "--creds",
        type=str,
        default="creds.yaml",
        help="Path to creds.yaml (default: creds.yaml)"
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config.json",
        help="Path to config.json (default: config.json)"
    )
    
    args = parser.parse_args()
    
    # Check if within trading hours (9:15 AM - 3:30 PM)
    if not is_trading_hours():
        current_time = datetime.now().strftime("%H:%M:%S")
        logger.warning(
            "Outside trading hours (9:15 AM - 3:30 PM). Current time: %s. Exiting.",
            current_time
        )
        print(f"Error: Outside trading hours (9:15 AM - 3:30 PM). Current time: {current_time}")
        print("Option chain data is only available during trading hours.")
        sys.exit(1)
    
    # Initialize auth - FyersAuth loads token from fyers_token.json automatically
    try:
        logger.info("Initializing Fyers authentication...")
        logger.info("Loading token from fyers_token.json (if exists)...")
        auth = FyersAuth(args.creds, args.config)
        
        # Check if token was loaded from file
        if auth.access_token:
            logger.info("Token loaded from fyers_token.json")
            if auth.token_expiry:
                time_left = (auth.token_expiry - datetime.now()).total_seconds()
                if time_left > 0:
                    logger.info("Token expires in %.0f seconds", time_left)
                else:
                    logger.warning("Token from file is expired, will refresh or re-authenticate")
        else:
            logger.info("No token found in fyers_token.json, will authenticate on first use")
        
        # FyersOptionChain will use token from file, or authenticate if invalid
        logger.info("Ready to use token from fyers_token.json or authenticate if needed")
    except FyersAuthError as e:
        logger.error("Authentication error: %s", e)
        sys.exit(1)
    except Exception as e:
        logger.error("Failed to initialize auth: %s", e)
        sys.exit(1)
    
    # Initialize option chain fetcher
    # This will ensure authentication happens automatically
    try:
        logger.info("Initializing option chain fetcher...")
        fetcher = FyersOptionChain(auth)
        logger.info("Option chain fetcher ready")
    except OptionChainError as e:
        logger.error("Failed to initialize option chain fetcher: %s", e)
        logger.error("This usually means authentication failed. Check your credentials.")
        sys.exit(1)
    except Exception as e:
        logger.error("Unexpected error initializing fetcher: %s", e)
        sys.exit(1)
    
    # Convert expiry date to DD-MM-YYYY format for API lookup
    expiry_date_str = None
    expiry_timestamp = None
    if args.expiry:
        try:
            expiry_dt = datetime.strptime(args.expiry, "%Y-%m-%d")
            # Convert to DD-MM-YYYY format for API lookup
            expiry_date_str = expiry_dt.strftime("%d-%m-%Y")
            logger.info("Expiry date: %s (will lookup valid timestamp from API)", expiry_date_str)
            # Don't calculate timestamp here - let API provide valid timestamp
        except ValueError:
            logger.error("Invalid expiry date format: %s. Use YYYY-MM-DD", args.expiry)
            sys.exit(1)
    
    # Fetch option chain
    try:
        logger.info("Fetching option chain for expiry: %s", args.expiry or "current")
        option_chain = fetcher.fetch_option_chain(
            symbol=args.symbol,
            expiry_timestamp=expiry_timestamp,
            expiry_date=expiry_date_str,
            strike_count=args.strike_count
        )
        
        # Log raw response structure for debugging
        logger.debug("Option chain response structure: %s", list(option_chain.keys()) if isinstance(option_chain, dict) else "Not a dict")
        
        # Extract options from response
        options = fetcher.extract_options(option_chain)
        
        # Format data
        formatted_options = fetcher.format_option_data(options)
        
        # Display results
        print(f"\n{'='*80}")
        print(f"Option Chain for {args.symbol}")
        print(f"Expiry: {args.expiry or 'Current'}")
        print(f"Strike Count: {args.strike_count} (gives ~{args.strike_count * 2 + 1} strikes)")
        print(f"Total Options: {len(formatted_options)}")
        print(f"{'='*80}\n")
        
        if formatted_options:
            # Print header
            print(f"{'Symbol':<25} {'Strike':<10} {'Type':<5} {'LTP':<10} {'Bid':<10} {'Ask':<10} {'Volume':<10} {'OI':<15}")
            print("-" * 100)
            
            # Print options
            for opt in formatted_options:
                # Handle None values in numeric fields
                ltp = opt.get('ltp') or 0
                bid = opt.get('bid') or 0
                ask = opt.get('ask') or 0
                volume = opt.get('volume') or 0
                oi = opt.get('oi') or 0
                strike = opt.get('strike') or ''
                
                print(
                    f"{opt.get('symbol', ''):<25} "
                    f"{strike:<10} "
                    f"{opt.get('option_type', ''):<5} "
                    f"{ltp:<10.2f} "
                    f"{bid:<10.2f} "
                    f"{ask:<10.2f} "
                    f"{volume:<10} "
                    f"{oi:<15}"
                )
        else:
            print("No options found. Check expiry date and symbol.")
            print("\nRaw response (for debugging):")
            print(json.dumps(option_chain, indent=2, default=str))
        
        # Store in time-series database
        try:
            from option_chain_storage import OptionChainStorage
            storage = OptionChainStorage()
            storage.store_snapshot(formatted_options)
            stats = storage.get_stats()
            print(f"\nData stored in time-series database:")
            print(f"  Total snapshots: {stats['total_snapshots']}")
            print(f"  Total records: {stats['total_records']}")
            print(f"  Database size: {stats['db_size_mb']:.2f} MB")
        except ImportError:
            logger.warning("option_chain_storage module not found, skipping database storage")
        
        # Export to CSV (default: nifty_option_chain.csv) for quick viewing
        csv_file = "nifty_option_chain.csv"
        fetcher.export_to_csv(formatted_options, csv_file)
        print(f"\nLatest snapshot exported to: {csv_file}")
        
        # Export to JSON if requested
        if args.output:
            fetcher.export_to_json(formatted_options, args.output)
            print(f"Data also exported to: {args.output}")
    
    except OptionChainError as e:
        logger.error("Option chain error: %s", e)
        sys.exit(1)
    except Exception as e:
        logger.error("Unexpected error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()

