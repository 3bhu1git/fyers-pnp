#!/usr/bin/env python3
"""
Fyers Realtime Market Data Module

Fetches realtime Nifty option data using Fyers WebSocket API.
Production-ready with low latency, comprehensive logging, and error handling.

Usage:
    python realtime_data.py [--symbols SYMBOL1,SYMBOL2] [--expiry YYYY-MM-DD] [--strikes STRIKE1,STRIKE2]
"""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from fyers_apiv3.FyersWebsocket import data_ws
from auth import FyersAuth, FyersAuthError

# -------------------------
# Logger setup
# -------------------------

LOGFILE_DEFAULT = "logs/realtime_data.log"
logger = logging.getLogger("realtime_data")
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


class RealtimeDataError(Exception):
    """Raised for realtime data errors"""
    pass


# -------------------------
# Fyers Realtime Data Client
# -------------------------


class FyersRealtimeData:
    """
    Fyers Realtime Market Data Client using Fyers SDK WebSocket.
    
    Features:
    - Automatic authentication using auth module
    - WebSocket connection management via SDK
    - Symbol subscription/unsubscription
    - Realtime data callbacks
    - Auto-reconnect on disconnect
    - Comprehensive logging
    """
    
    def __init__(
        self,
        auth: FyersAuth,
        on_data: Optional[callable] = None,
        on_error: Optional[callable] = None,
        auto_reconnect: bool = True,
        reconnect_delay: int = 5
    ):
        """
        Initialize Fyers Realtime Data Client.
        
        Args:
            auth: FyersAuth instance (must be authenticated)
            on_data: Callback function(data: dict) called on each data update
            on_error: Callback function(error: str) called on errors
            auto_reconnect: Automatically reconnect on disconnect
            reconnect_delay: Delay in seconds before reconnecting
        """
        self.auth = auth
        self.on_data = on_data or self._default_data_handler
        self.on_error = on_error or self._default_error_handler
        self.auto_reconnect = auto_reconnect
        self.reconnect_delay = reconnect_delay
        
        self.fyers_ws: Optional[data_ws.FyersDataSocket] = None
        self.subscribed_symbols: Set[str] = set()
        self.is_connected = False
        self._stop_event = threading.Event()
        
        logger.info("Initialized Fyers Realtime Data Client")
    
    def _default_data_handler(self, data: Dict[str, Any]) -> None:
        """Default data handler - logs data"""
        logger.info("Market data update: %s", json.dumps(data, indent=2))
    
    def _default_error_handler(self, error: str) -> None:
        """Default error handler - logs error"""
        logger.error("Realtime data error: %s", error)
    
    def _on_message(self, message: Dict[str, Any]) -> None:
        """Handle incoming WebSocket messages"""
        try:
            # Fyers SDK passes dict directly
            self.on_data(message)
        except Exception as e:
            logger.error("Error handling message: %s", e)
            self.on_error(str(e))
    
    def _on_error(self, error: Any) -> None:
        """Handle WebSocket errors"""
        # Error can be string or dict
        if isinstance(error, dict):
            error_msg = error.get("message", str(error))
            invalid_symbols = error.get("invalid_symbols", [])
            if invalid_symbols:
                logger.error(
                    "WebSocket error: %s. Invalid symbols: %s",
                    error_msg,
                    invalid_symbols
                )
                logger.error(
                    "Tip: Ensure expiry dates are valid (typically Thursdays) and not expired. "
                    "Use current or future expiry dates only."
                )
            else:
                logger.error("WebSocket error: %s", error)
        else:
            logger.error("WebSocket error: %s", error)
        
        self.is_connected = False
        self.on_error(str(error))
    
    def _on_close(self, close_msg: str) -> None:
        """Handle WebSocket close"""
        logger.warning("WebSocket closed: %s", close_msg)
        self.is_connected = False
        
        # Auto-reconnect if enabled
        if self.auto_reconnect and not self._stop_event.is_set():
            logger.info("Scheduling reconnect in %d seconds...", self.reconnect_delay)
            threading.Timer(self.reconnect_delay, self.connect).start()
    
    def _on_connect(self) -> None:
        """Handle WebSocket connection"""
        logger.info("WebSocket connected successfully")
        self.is_connected = True
        
        # Subscribe to symbols if any are pending
        if self.subscribed_symbols:
            self._subscribe_all()
    
    def _subscribe_all(self) -> None:
        """Subscribe to all currently tracked symbols"""
        if not self.subscribed_symbols or not self.fyers_ws:
            return
        
        try:
            symbols_list = list(self.subscribed_symbols)
            self.fyers_ws.subscribe(symbols=symbols_list, data_type="SymbolUpdate")
            logger.info("Subscribed to %d symbols: %s", len(symbols_list), symbols_list)
        except Exception as e:
            logger.error("Failed to subscribe: %s", e)
            self.on_error(f"Subscribe failed: {e}")
    
    def connect(self) -> None:
        """Connect to Fyers WebSocket using SDK"""
        if self.is_connected and self.fyers_ws:
            logger.warning("Already connected")
            return
        
        if not self.auth.access_token:
            # Try to refresh token
            logger.info("No access token, attempting authentication...")
            if not self.auth.authenticate_interactive(no_open=True):
                raise RealtimeDataError("Authentication failed")
        
        # Get client_id from config
        client_id = self.auth.config.get("client_id")
        if not client_id:
            raise RealtimeDataError("No client_id found in config")
        
        # Fyers SDK expects access_token in format "client_id:access_token"
        access_token = f"{client_id}:{self.auth.access_token}"
        
        logger.info("Connecting to Fyers WebSocket via SDK...")
        
        # Create FyersDataSocket instance
        self.fyers_ws = data_ws.FyersDataSocket(
            access_token=access_token,
            write_to_file=False,
            log_path=None,
            litemode=False,
            reconnect=self.auto_reconnect,
            on_message=self._on_message,
            on_error=self._on_error,
            on_connect=self._on_connect,
            on_close=self._on_close
        )
        
        # Connect in background thread
        def run_websocket():
            try:
                self.fyers_ws.connect()
            except Exception as e:
                logger.error("WebSocket connection error: %s", e)
                self.on_error(str(e))
        
        ws_thread = threading.Thread(target=run_websocket, daemon=True)
        ws_thread.start()
        
        # Wait for connection (with timeout)
        timeout = 15
        start_time = time.time()
        while not self.is_connected and (time.time() - start_time) < timeout:
            time.sleep(0.1)
        
        if not self.is_connected:
            raise RealtimeDataError("WebSocket connection timeout")
    
    def subscribe(self, symbols: List[str]) -> None:
        """
        Subscribe to market data for symbols.
        
        Args:
            symbols: List of symbol strings in format "NSE:NIFTY24NOV18000CE"
        """
        if not symbols:
            return
        
        # Add to tracked symbols
        self.subscribed_symbols.update(symbols)
        
        # Subscribe if connected
        if self.is_connected and self.fyers_ws:
            self._subscribe_all()
        else:
            logger.warning("Not connected yet, symbols will be subscribed after connection: %s", symbols)
    
    def unsubscribe(self, symbols: List[str]) -> None:
        """
        Unsubscribe from market data for symbols.
        
        Args:
            symbols: List of symbol strings to unsubscribe
        """
        if not symbols or not self.fyers_ws:
            return
        
        # Remove from tracked symbols
        self.subscribed_symbols.difference_update(symbols)
        
        if self.is_connected:
            try:
                self.fyers_ws.unsubscribe(symbols=symbols)
                logger.info("Unsubscribed from symbols: %s", symbols)
            except Exception as e:
                logger.error("Failed to unsubscribe: %s", e)
    
    def disconnect(self) -> None:
        """Disconnect from WebSocket"""
        self._stop_event.set()
        if self.fyers_ws:
            try:
                self.fyers_ws.close_connection()
            except Exception as e:
                logger.warning("Error closing WebSocket: %s", e)
        self.is_connected = False
        logger.info("Disconnected from WebSocket")
    
    def run_forever(self) -> None:
        """Run until interrupted"""
        try:
            while not self._stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
            self.disconnect()


# -------------------------
# Nifty Options Helper
# -------------------------


def generate_nifty_option_symbols(
    expiry_date: str,
    strikes: List[int],
    option_type: str = "both"
) -> List[str]:
    """
    Generate Nifty option symbols for given expiry and strikes.
    
    Args:
        expiry_date: Expiry date in format "YYYY-MM-DD" (must be a valid future expiry)
        strikes: List of strike prices (e.g., [18000, 18500, 19000])
        option_type: "CE", "PE", or "both"
    
    Returns:
        List of symbol strings in format "NSE:NIFTY24NOV18000CE"
    
    Example:
        generate_nifty_option_symbols("2024-11-28", [18000, 18500], "both")
        -> ["NSE:NIFTY24NOV18000CE", "NSE:NIFTY24NOV18000PE", ...]
    
    Note:
        - Expiry date must be a valid Nifty options expiry (typically Thursdays)
        - Use current or future expiry dates only
        - Symbol format: NSE:NIFTY<YY><MMM><STRIKE><CE/PE>
    """
    try:
        expiry_dt = datetime.strptime(expiry_date, "%Y-%m-%d")
        
        # Warn if expiry is in the past
        if expiry_dt.date() < datetime.now().date():
            logger.warning(
                "Expiry date %s is in the past. Symbols may be invalid. "
                "Use current or future expiry dates.",
                expiry_date
            )
        
        year_suffix = expiry_dt.strftime("%y")  # Last 2 digits
        month_abbr = expiry_dt.strftime("%b").upper()  # NOV, DEC, etc.
        
        symbols = []
        option_types = []
        
        if option_type.upper() == "BOTH":
            option_types = ["CE", "PE"]
        elif option_type.upper() in ["CE", "PE"]:
            option_types = [option_type.upper()]
        else:
            raise ValueError(f"Invalid option_type: {option_type}. Use 'CE', 'PE', or 'both'")
        
        for strike in strikes:
            for opt_type in option_types:
                symbol = f"NSE:NIFTY{year_suffix}{month_abbr}{strike}{opt_type}"
                symbols.append(symbol)
        
        return symbols
    
    except ValueError as e:
        logger.error("Invalid expiry date format: %s. Use YYYY-MM-DD", e)
        raise


def get_nifty_option_chain(
    auth: FyersAuth,
    expiry_date: Optional[str] = None
) -> Dict[str, Any]:
    """
    Fetch Nifty option chain from Fyers API.
    
    Args:
        auth: Authenticated FyersAuth instance
        expiry_date: Optional expiry date in YYYY-MM-DD format
    
    Returns:
        Dictionary with option chain data
    """
    if not auth.access_token:
        raise RealtimeDataError("Not authenticated. Call authenticate_interactive() first.")
    
    try:
        from fyers_apiv3 import fyersModel
        
        # Create FyersModel instance
        client_id = auth.config.get("client_id")
        access_token = f"{client_id}:{auth.access_token}"
        
        fyers = fyersModel.FyersModel(
            client_id=client_id,
            token=access_token,
            is_async=False,
            log_path=""
        )
        
        # Get option chain (this endpoint may vary - check Fyers docs)
        # For now, return empty dict as placeholder
        # You may need to use: fyers.option_chain() or similar method
        logger.warning("Option chain API endpoint needs to be implemented based on Fyers SDK docs")
        return {}
        
    except Exception as e:
        logger.error("Failed to fetch option chain: %s", e)
        raise RealtimeDataError(f"Option chain fetch failed: {e}")


# -------------------------
# Data Handler Example
# -------------------------


def nifty_options_data_handler(data: Dict[str, Any]) -> None:
    """
    Example data handler for Nifty options.
    Customize this based on your needs.
    """
    # Fyers SDK passes data in different format
    # Log raw data structure first time to understand format
    if isinstance(data, dict):
        # Fyers WebSocket data format (based on SDK):
        # Data comes as dict with keys like: 'n' (symbol), 'v' (values dict), etc.
        symbol = data.get("n") or data.get("symbol") or data.get("symbol_name", "")
        
        # Extract values - Fyers format typically has 'v' dict with nested data
        v = data.get("v", {})
        if isinstance(v, dict):
            # Standard Fyers format
            ltp = v.get("lp", 0)  # Last price
            volume = v.get("volume", 0)
            oi = v.get("oi", 0)  # Open interest
            bid = v.get("bid", 0)
            ask = v.get("ask", 0)
        else:
            # Try direct keys
            ltp = data.get("lp") or data.get("last_price") or 0
            volume = data.get("volume", 0)
            oi = data.get("oi") or data.get("open_interest", 0)
            bid = data.get("bid", 0)
            ask = data.get("ask", 0)
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Only print if we have meaningful data (non-zero values)
        if ltp > 0 or bid > 0 or ask > 0 or volume > 0:
            print(f"[{timestamp}] {symbol}: LTP={ltp}, Bid={bid}, Ask={ask}, Volume={volume}, OI={oi}")
        
        # Log to file (always log, even if zeros, for debugging)
        logger.info(
            "Option data: symbol=%s, ltp=%.2f, bid=%.2f, ask=%.2f, volume=%d, oi=%d",
            symbol, ltp, bid, ask, volume, oi
        )
        
        # Log raw data structure occasionally for debugging (first few times)
        if not hasattr(nifty_options_data_handler, '_debug_count'):
            nifty_options_data_handler._debug_count = 0
        if nifty_options_data_handler._debug_count < 3:
            logger.debug("Raw data structure: %s", json.dumps(data, indent=2))
            nifty_options_data_handler._debug_count += 1
    else:
        # Log raw data for debugging
        logger.debug("Received non-dict data: %s", data)


# -------------------------
# CLI Runner
# -------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Fyers Realtime Nifty Options Data Fetcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fetch specific symbols (use valid current/future expiry dates)
  python realtime_data.py --symbols "NSE:NIFTY25NOV18000CE,NSE:NIFTY25NOV18000PE"
  
  # Generate symbols for expiry and strikes (use current/future expiry, typically Thursdays)
  python realtime_data.py --expiry 2025-11-27 --strikes 18000,18500,19000
  
  # Fetch only CE options
  python realtime_data.py --expiry 2025-11-27 --strikes 18000,18500 --option-type CE
  
Note: Expiry dates must be valid Nifty option expiries (typically Thursdays) and not expired.
      Use current or future dates only. Check NSE website for valid expiry dates.
        """
    )
    
    parser.add_argument(
        "--symbols",
        type=str,
        help="Comma-separated list of symbols (e.g., NSE:NIFTY24NOV18000CE,NSE:NIFTY24NOV18000PE)"
    )
    parser.add_argument(
        "--expiry",
        type=str,
        help="Expiry date in YYYY-MM-DD format (used with --strikes)"
    )
    parser.add_argument(
        "--strikes",
        type=str,
        help="Comma-separated strike prices (e.g., 18000,18500,19000)"
    )
    parser.add_argument(
        "--option-type",
        type=str,
        default="both",
        choices=["CE", "PE", "both"],
        help="Option type: CE, PE, or both (default: both)"
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
    parser.add_argument(
        "--no-reconnect",
        action="store_true",
        help="Disable auto-reconnect on disconnect"
    )
    
    args = parser.parse_args()
    
    # Determine symbols to subscribe
    symbols = []
    
    if args.symbols:
        # Use provided symbols
        symbols = [s.strip() for s in args.symbols.split(",")]
    elif args.expiry and args.strikes:
        # Generate symbols from expiry and strikes
        try:
            strike_list = [int(s.strip()) for s in args.strikes.split(",")]
            symbols = generate_nifty_option_symbols(args.expiry, strike_list, args.option_type)
        except ValueError as e:
            logger.error("Invalid strikes format: %s", e)
            sys.exit(1)
    else:
        logger.error("Must provide either --symbols or both --expiry and --strikes")
        parser.print_help()
        sys.exit(1)
    
    if not symbols:
        logger.error("No symbols to subscribe")
        sys.exit(1)
    
    logger.info("Subscribing to %d symbols: %s", len(symbols), symbols)
    
    # Initialize auth
    try:
        auth = FyersAuth(args.creds, args.config)
        
        # Ensure authenticated
        if not auth.access_token or (auth.token_expiry and auth.token_expiry <= datetime.now()):
            logger.info("No valid token, authenticating...")
            if not auth.authenticate_interactive(no_open=True):
                logger.error("Authentication failed")
                sys.exit(1)
    except Exception as e:
        logger.error("Failed to initialize auth: %s", e)
        sys.exit(1)
    
    # Initialize realtime data client
    client = FyersRealtimeData(
        auth=auth,
        on_data=nifty_options_data_handler,
        auto_reconnect=not args.no_reconnect
    )
    
    # Setup signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        logger.info("Received signal %d, shutting down...", sig)
        client.disconnect()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Connect and subscribe
        logger.info("Connecting to Fyers WebSocket...")
        client.connect()
        
        # Wait a moment for connection
        time.sleep(2)
        
        # Subscribe to symbols
        client.subscribe(symbols)
        
        # Run forever
        logger.info("Listening for realtime data updates. Press Ctrl+C to stop.")
        client.run_forever()
    
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error("Error: %s", e)
        sys.exit(1)
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
