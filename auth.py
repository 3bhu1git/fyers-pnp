#!/usr/bin/env python3
"""
Fixed fyers_auth_auto.py — handles FYERS redirect where auth token may appear as auth_code
and defines FyersAuthError to avoid NameError.

Usage: same as before
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import queue
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, unquote_plus, urlparse

import requests
import yaml
from fyers_apiv3 import fyersModel

# -------------------------
# Exceptions
# -------------------------


class FyersAuthError(Exception):
    """Raised for auth flow failures"""
    pass


# -------------------------
# Logger setup
# -------------------------

LOGFILE_DEFAULT = "logs/fyers_auth_auto.log"
logger = logging.getLogger("fyers_auth_auto")
logger.setLevel(logging.INFO)

if not logger.handlers:
    fh = RotatingFileHandler(LOGFILE_DEFAULT, maxBytes=10 * 1024 * 1024, backupCount=3)
    fh.setLevel(logging.INFO)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    fmt = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh.setFormatter(fmt)
    ch.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(ch)


# -------------------------
# Utilities (same as before)
# -------------------------


def get_chrome_user_data_dir() -> Optional[Path]:
    if sys.platform.startswith("darwin"):
        p = Path.home() / "Library" / "Application Support" / "Google" / "Chrome"
    elif sys.platform.startswith("win"):
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            return None
        p = Path(local) / "Google" / "Chrome" / "User Data"
    else:
        p = Path.home() / ".config" / "google-chrome"
        if not p.exists():
            p = Path.home() / ".config" / "chromium"

    return p if p and p.exists() else None


def read_local_state(user_data_dir: Path) -> Optional[dict]:
    local_state = user_data_dir / "Local State"
    if not local_state.exists():
        return None
    try:
        raw = local_state.read_text(encoding="utf-8")
        return json.loads(raw)
    except Exception as e:
        logger.warning("Failed to read Local State: %s", e)
        return None


def detect_last_used_profile(user_data_dir: Path) -> Optional[str]:
    data = read_local_state(user_data_dir)
    if not data:
        return None

    profile = data.get("profile", {})
    last_used = profile.get("last_used")
    if last_used:
        return last_used

    if (user_data_dir / "Default").exists():
        return "Default"

    for entry in user_data_dir.iterdir():
        if entry.is_dir() and entry.name.startswith("Profile"):
            return entry.name

    return None


def _locate_chrome_binary() -> Optional[str]:
    if sys.platform.startswith("win"):
        candidates = [
            Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "Application" / "chrome.exe",
            Path(os.environ.get("PROGRAMFILES", "")) / "Google" / "Chrome" / "Application" / "chrome.exe",
            Path(os.environ.get("PROGRAMFILES(X86)", "")) / "Google" / "Chrome" / "Application" / "chrome.exe",
        ]
        for c in candidates:
            if c and c.exists():
                return str(c)
        return None

    if sys.platform.startswith("darwin"):
        p = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        return str(p) if p.exists() else None

    return (
        shutil.which("google-chrome")
        or shutil.which("chrome")
        or shutil.which("chromium")
        or shutil.which("chromium-browser")
    )


def _kill_chrome_processes(logger_local: Optional[logging.Logger] = None) -> None:
    try:
        if sys.platform.startswith("win"):
            subprocess.run(
                ["taskkill", "/F", "/IM", "chrome.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        else:
            subprocess.run(["pkill", "-f", "chrome"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.6)
        if logger_local:
            logger_local.info("Killed existing Chrome processes.")
    except Exception as e:
        if logger_local:
            logger_local.warning("Failed to kill Chrome processes: %s", e)


def open_url_in_profile(
    url: str,
    profile: Optional[str],
    force_kill: bool = True,
    use_user_data_dir: bool = False,
    logger_local: Optional[logging.Logger] = None,
) -> Tuple[bool, str]:
    chrome_bin = _locate_chrome_binary()
    user_data_parent = get_chrome_user_data_dir()

    if force_kill:
        if logger_local:
            logger_local.warning("force_kill=True: terminating existing Chrome instances.")
        _kill_chrome_processes(logger_local)

    if chrome_bin:
        args = [chrome_bin]
        if use_user_data_dir and user_data_parent:
            args += [f"--user-data-dir={str(user_data_parent)}"]
        if profile:
            args += [f"--profile-directory={profile}"]
        args += ["--new-window", "--no-default-browser-check", url]

        try:
            subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True, "Launched Chrome binary with profile flag"
        except Exception as e:
            if logger_local:
                logger_local.warning("Direct launch failed: %s", e)

    if sys.platform.startswith("darwin"):
        try:
            cmd = ["open", "-na", "Google Chrome", "--args"]
            if use_user_data_dir and user_data_parent:
                cmd += [f"--user-data-dir={str(user_data_parent)}"]
            if profile:
                cmd += [f"--profile-directory={profile}"]
            cmd += ["--new-window", "--no-default-browser-check", url]
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True, "Launched macOS Chrome via open -na"
        except Exception as e:
            if logger_local:
                logger_local.warning("mac open -na failed: %s", e)

    try:
        webbrowser.open(url, new=1)
        return True, "Fallback: opened system default browser"
    except Exception as e:
        return False, f"All launch attempts failed: {e}"


# -------------------------
# Auth server handler (FIXED)
# -------------------------


class AuthCodeHandler(BaseHTTPRequestHandler):
    auth_code_queue: Optional[queue.Queue] = None
    expected_path: str = "/"
    logger_local: Optional[logging.Logger] = None

    def log_message(self, fmt, *args):
        # suppress default logging
        return

    def do_GET(self):
        # parse and prefer 'auth_code' over 'code' (FYERS returns auth_code param in some flows)
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if self.logger_local:
            self.logger_local.info("HTTP GET received: path=%s | query=%s", self.path, qs)

        # ensure path matches expected
        path = parsed.path
        if path != self.expected_path:
            if self.logger_local:
                self.logger_local.warning("Unexpected redirect path: %s (expected %s)", path, self.expected_path)
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Not Found</h1></body></html>")
            return

        # Prefer 'auth_code' which contains the real JWT-like token; fallback to 'code'
        auth_code_val = None
        if "auth_code" in qs:
            auth_code_val = qs.get("auth_code")[0]
        elif "code" in qs:
            auth_code_val = qs.get("code")[0]

        if auth_code_val:
            # decode/cleanup
            try:
                auth_code_val = unquote_plus(auth_code_val).strip()
            except Exception:
                pass

            try:
                if self.auth_code_queue:
                    self.auth_code_queue.put(auth_code_val, block=False)
                    if self.logger_local:
                        # log only prefix of token for safety
                        self.logger_local.info(
                            "Authorization code queued (prefix): %s...",
                            (auth_code_val[:20] if len(auth_code_val) > 20 else auth_code_val),
                        )
            except Exception as e:
                if self.logger_local:
                    self.logger_local.error("Failed to enqueue auth code: %s", e)

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body><h1>Authentication successful</h1><p>You may close this window.</p></body></html>"
            )
            return

        # no code present
        if self.logger_local:
            self.logger_local.warning("Callback received without auth_code/code param. Query: %s", qs)
        self.send_response(400)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Bad Request</h1><p>Missing code parameter.</p></body></html>")


def start_local_server(host: str, port: int, expected_path: str, auth_q: queue.Queue, logger_local: logging.Logger) -> HTTPServer:
    def make_handler(q: queue.Queue, exp_path: str, logg: logging.Logger):
        class H(AuthCodeHandler):
            pass

        H.auth_code_queue = q
        H.expected_path = exp_path
        H.logger_local = logg
        return H

    server = HTTPServer((host, port), make_handler(auth_q, expected_path, logger_local))
    thr = threading.Thread(target=server.serve_forever, daemon=True, name="AuthServerThread")
    thr.start()
    logger_local.info("Auth redirect server started on http://%s:%s (expecting path=%s)", host, port, expected_path)
    return server


# -------------------------
# Config manager & token persistence (same)
# -------------------------


class FyersAuthConfig:
    REQUIRED = ["client_id", "secret_key", "redirect_uri"]
    DEFAULTS = {
        "token_file": "fyers_token.json",
        "log_file": LOGFILE_DEFAULT,
        "log_max_bytes": 10 * 1024 * 1024,
        "log_backup_count": 3,
        "token_refresh_interval": 3600,
        "token_refresh_threshold": 300,
        "state": "sample_state",
        "scope": "",
        "auth_timeout": 300,
        "open_browser": True,
        "chrome_profile": None,
    }

    def __init__(self, creds_path: str = "creds.yaml", config_path: str = "config.json"):
        self.creds_path = Path(creds_path)
        self.config_path = Path(config_path)
        if not self.creds_path.exists():
            raise FileNotFoundError(f"Credentials file not found: {creds_path}")

        with open(self.creds_path, "r") as f:
            creds = yaml.safe_load(f) or {}

        cfg = {}
        if self.config_path.exists():
            with open(self.config_path, "r") as f:
                cfg = json.load(f) or {}

        self.config: Dict[str, Any] = {**self.DEFAULTS, **cfg, **creds}
        missing = [k for k in self.REQUIRED if k not in self.config]
        if missing:
            raise ValueError(f"Missing required fields in creds/config: {missing}")

        parsed = urlparse(self.config["redirect_uri"])
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        self.config["redirect_host"] = host
        self.config["redirect_port"] = port
        self.config["redirect_path"] = path

    def get(self, k, default=None):
        return self.config.get(k, default)


# -------------------------
# FyersAuth manager (focused)
# -------------------------


class FyersAuth:
    """
    Fyers API v3 Authentication Manager using official fyers-apiv3 SDK.
    
    Wraps fyers_apiv3.SessionModel with:
    - Config-based inputs (creds.yaml + config.json)
    - Token persistence
    - Automatic token refresh
    - Comprehensive logging
    - Background service support
    """
    AUTH_CODE_URL = "https://api-t1.fyers.in/api/v3/generate-authcode"

    def __init__(self, creds_path: str = "creds.yaml", config_path: str = "config.json"):
        self.config = FyersAuthConfig(creds_path, config_path)
        self.logger = logger
        self.token_file = Path(self.config.get("token_file"))
        if self.token_file.parent:
            self.token_file.parent.mkdir(parents=True, exist_ok=True)

        self._token_lock = threading.RLock()
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expiry: Optional[datetime] = None
        self._stop_refresh = threading.Event()
        self._refresh_thread: Optional[threading.Thread] = None
        self._session: Optional[fyersModel.SessionModel] = None

        # Initialize Fyers SDK SessionModel
        self._init_session()
        self._load_tokens()
    
    def _init_session(self) -> None:
        """Initialize Fyers SDK SessionModel"""
        client_id = self.config.get("client_id")
        secret_key = self.config.get("secret_key")
        redirect_uri = self.config.get("redirect_uri")
        
        self._session = fyersModel.SessionModel(
            client_id=client_id,
            secret_key=secret_key,
            redirect_uri=redirect_uri,
            response_type="code",
            grant_type="authorization_code"
        )
        self.logger.debug("Initialized Fyers SDK SessionModel")
    
    def get_auth_url(self) -> str:
        """
        Generate authorization URL using Fyers SDK.
        
        Returns:
            Authorization URL string
        """
        if not self._session:
            raise FyersAuthError("Session not initialized")
        
        try:
            auth_url = self._session.generate_authcode()
            self.logger.debug("Generated auth URL via SDK")
            return auth_url
        except Exception as e:
            self.logger.error("Error generating auth URL via SDK: %s", e)
            # Fallback to manual URL construction
            client_id = self.config.get("client_id")
            redirect_uri = self.config.get("redirect_uri")
            state = self.config.get("state", "")
            scope = self.config.get("scope", "")
            return (
                f"{self.AUTH_CODE_URL}?client_id={client_id}"
                f"&redirect_uri={redirect_uri}&response_type=code&state={state}&scope={scope}"
            )


    def _load_tokens(self) -> None:
        if not self.token_file.exists():
            self.logger.info("No token file.")
            return

        try:
            data = json.loads(self.token_file.read_text())
            with self._token_lock:
                self.access_token = data.get("access_token")
                self.refresh_token = data.get("refresh_token")
                expiry = data.get("expiry")
                self.token_expiry = datetime.fromisoformat(expiry) if expiry else None

            if self.access_token and self.token_expiry and self.token_expiry > datetime.now():
                self.logger.info("Loaded valid token from disk.")
            else:
                self.logger.info("Tokens on disk are missing/expired.")
        except Exception as e:
            self.logger.warning("Failed loading token file: %s", e)

    def _save_tokens(self) -> None:
        tmp = str(self.token_file) + ".tmp"
        with self._token_lock:
            payload = {
                "access_token": self.access_token,
                "refresh_token": self.refresh_token,
                "expiry": self.token_expiry.isoformat() if self.token_expiry else None,
                "saved_at": datetime.now().isoformat(),
            }
        try:
            with open(tmp, "w") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp, str(self.token_file))
            self.logger.info("Saved tokens to %s", self.token_file)
        except Exception as e:
            self.logger.error("Failed to save tokens: %s", e)

    def set_token(self, auth_code: str) -> None:
        """
        Set the authorization code using Fyers SDK.
        
        Args:
            auth_code: Authorization code from OAuth2 flow
        """
        if not self._session:
            raise FyersAuthError("Session not initialized")
        
        self._session.set_token(auth_code)
        self.logger.debug("Auth code set via SDK (prefix): %s...", auth_code[:20] if auth_code else "None")
    
    def generate_token(self) -> Dict[str, Any]:
        """
        Generate access token using Fyers SDK.
        
        Returns:
            Dictionary with response containing access_token, refresh_token, etc.
            Returns empty dict on failure.
        """
        if not self._session:
            raise FyersAuthError("Session not initialized")
        
        try:
            self.logger.info("Generating token using Fyers SDK...")
            response = self._session.generate_token()
            
            if response.get('s') == 'ok':
                # Extract tokens from SDK response
                access_token = response.get('access_token')
                refresh_token = response.get('refresh_token')
                
                if access_token:
                    with self._token_lock:
                        self.access_token = access_token
                        self.refresh_token = refresh_token or self.refresh_token
                        
                        # Calculate expiry (typically 24 hours for Fyers)
                        expires_in = response.get('expires_in', 86400)
                        try:
                            expires_in = int(expires_in)
                        except (ValueError, TypeError):
                            expires_in = 86400
                        
                        self.token_expiry = datetime.now() + timedelta(seconds=expires_in)
                    
                    self._save_tokens()
                    self.logger.info("Token generation successful. Access token expires at: %s", self.token_expiry.isoformat())
                    
                    # Start refresh thread if refresh_token available
                    if self.refresh_token:
                        self._start_token_refresh()
                    
                    return response
                else:
                    self.logger.error("SDK returned success but no access_token in response")
                    return {'s': 'error', 'message': 'No access_token in response'}
            else:
                error_msg = response.get('message', 'Unknown error')
                self.logger.error("Token generation failed: %s", error_msg)
                return response
                
        except Exception as e:
            self.logger.error("Error generating token via SDK: %s", e)
            return {'s': 'error', 'message': str(e)}
    
    def _exchange_code_for_token(self, auth_code: str) -> bool:
        """
        Exchange authorization code for access token using Fyers SDK.
        This is a wrapper around SDK's set_token + generate_token.
        
        Args:
            auth_code: Authorization code from OAuth2 flow
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Use SDK methods
            self.set_token(auth_code)
            response = self.generate_token()
            
            return response.get('s') == 'ok'
            
        except Exception as e:
            self.logger.error("Error exchanging code for token via SDK: %s", e)
            return False
    
    def refresh_access_token(self) -> bool:
        """
        Refresh access token using refresh_token via Fyers SDK.
        
        Returns:
            True if successful, False otherwise
        """
        if not self.refresh_token:
            self.logger.warning("No refresh_token available for refresh")
            return False
        
        if not self._session:
            raise FyersAuthError("Session not initialized")
        
        try:
            # SDK handles refresh token internally
            # We need to set the refresh token and call generate_token
            # Note: SDK may handle this differently, check SDK docs
            self.logger.info("Refreshing access token via SDK...")
            
            # Try using SDK's refresh mechanism if available
            # If SDK doesn't have direct refresh, we'll need to implement manually
            # For now, re-initialize session with refresh_token if SDK supports it
            
            # Manual refresh using refresh_token endpoint
            # SDK might not expose refresh directly, so we implement it
            refresh_payload = {
                "grant_type": "refresh_token",
                "appIdHash": self._calc_app_id_hash(),
                "refresh_token": self.refresh_token
            }
            
            # Use SDK's internal token endpoint if available, otherwise manual
            # For now, use manual refresh since SDK may not expose refresh endpoint
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            refresh_url = "https://api-t1.fyers.in/api/v3/token"
            
            r = requests.post(refresh_url, json=refresh_payload, headers=headers, timeout=30)
            
            if r.status_code == 200:
                data = r.json()
                if data.get("s") == "ok" or data.get("access_token"):
                    with self._token_lock:
                        self.access_token = data.get("access_token")
                        new_refresh = data.get("refresh_token")
                        if new_refresh:
                            self.refresh_token = new_refresh
                        
                        expires_in = int(data.get("expires_in", 86400))
                        self.token_expiry = datetime.now() + timedelta(seconds=expires_in)
                    
                    self._save_tokens()
                    self.logger.info("Token refresh successful. New expiry: %s", self.token_expiry.isoformat())
                    return True
                else:
                    self.logger.error("Refresh failed: %s", data.get("message", "Unknown error"))
                    return False
            else:
                self.logger.error("Refresh request failed: %s", r.status_code)
                try:
                    error_data = r.json()
                    self.logger.error("Error details: %s", error_data)
                except:
                    self.logger.error("Response: %s", r.text[:200])
                return False
                
        except Exception as e:
            self.logger.error("Error refreshing token: %s", e)
            return False
    
    def _calc_app_id_hash(self, use_base_app_id: bool = True) -> str:
        """
        Calculate appIdHash for token refresh (SDK may not expose this).
        FYERS expects SHA256 of the string: "<app_id>:<secret_key>"
        
        Args:
            use_base_app_id: If True, strips -100 suffix from client_id (for v3).
        
        Returns:
            Hex digest (lowercase)
        """
        client_id = self.config.get("client_id")
        secret = self.config.get("secret_key")

        if not client_id or not secret:
            raise FyersAuthError("Missing client_id or secret_key for appIdHash computation")

        if use_base_app_id:
            app_id = client_id.rstrip("-100") if client_id.endswith("-100") else client_id
        else:
            app_id = client_id
        
        raw = f"{app_id}:{secret}"
        appid_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return appid_hash
    
    def _start_token_refresh(self) -> None:
        """
        Start background thread for automatic token refresh.
        """
        if self._refresh_thread and self._refresh_thread.is_alive():
            self.logger.debug("Refresh thread already running")
            return
        
        self._stop_refresh.clear()
        self._refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True)
        self._refresh_thread.start()
        self.logger.info("Started token refresh thread")
    
    def _refresh_loop(self) -> None:
        """
        Background loop to refresh tokens before expiry.
        """
        refresh_interval = int(self.config.get("token_refresh_interval", 3600))
        refresh_threshold = int(self.config.get("token_refresh_threshold", 300))
        
        while not self._stop_refresh.is_set():
            try:
                with self._token_lock:
                    if not self.token_expiry or not self.refresh_token:
                        self.logger.warning("No expiry or refresh_token, stopping refresh loop")
                        break
                    
                    time_until_expiry = (self.token_expiry - datetime.now()).total_seconds()
                
                if time_until_expiry <= refresh_threshold:
                    self.logger.info("Token expiring soon (%d seconds), refreshing...", time_until_expiry)
                    if self.refresh_access_token():
                        self.logger.info("Token refreshed successfully")
                    else:
                        self.logger.error("Token refresh failed, stopping refresh loop")
                        break
                
                # Sleep for refresh_interval or until stop event
                self._stop_refresh.wait(refresh_interval)
                
            except Exception as e:
                self.logger.error("Error in refresh loop: %s", e)
                time.sleep(60)  # Wait before retrying
    
    def stop_refresh(self) -> None:
        """Stop the background token refresh thread."""
        self._stop_refresh.set()
        if self._refresh_thread and self._refresh_thread.is_alive():
            self._refresh_thread.join(timeout=5)
            self.logger.info("Stopped token refresh thread")

    def authenticate_interactive(
        self, no_open: bool = False, no_kill: bool = False, use_userdata: bool = False, timeout: Optional[int] = None
    ) -> bool:
        if timeout is None:
            timeout = int(self.config.get("auth_timeout", 300))

        # If we already have valid token, return
        if self.access_token and self.token_expiry and self.token_expiry > datetime.now():
            self.logger.info("Already have valid access token.")
            return True

        # Generate auth URL using SDK
        auth_url = self.get_auth_url()

        # Detect profile
        user_data_parent = get_chrome_user_data_dir()
        profile_name = None
        if user_data_parent:
            profile_name = detect_last_used_profile(user_data_parent)
            logger.info("Detected Chrome profile (Local State): %s", profile_name)
        else:
            logger.warning("Could not detect Chrome user-data dir; will fall back to system browser.")

        # Show URL and optionally open
        print("\n" + "=" * 80)
        print("Open this URL in Chrome (detected profile):")
        print(auth_url)
        print("=" * 80 + "\n")

        server_queue: queue.Queue = queue.Queue(maxsize=1)
        server = start_local_server(
            self.config.get("redirect_host"), int(self.config.get("redirect_port")), self.config.get("redirect_path"), server_queue, self.logger
        )

        try:
            if not no_open:
                ok, msg = open_url_in_profile(
                    auth_url, profile_name, force_kill=not no_kill, use_user_data_dir=use_userdata, logger_local=self.logger
                )
                self.logger.info("open_url_in_profile: %s | %s", ok, msg)
            else:
                self.logger.info("no_open specified: not opening browser automatically. Paste URL in target profile manually.")

            # wait for auth code
            try:
                self.logger.info("Waiting for authorization code (timeout=%s)...", timeout)
                auth_code = server_queue.get(timeout=timeout)
            except queue.Empty:
                raise FyersAuthError(f"Authorization timeout: no code received within {timeout} seconds")
            finally:
                try:
                    server.shutdown()
                except Exception:
                    pass

            if not auth_code:
                raise FyersAuthError("No auth_code received")

            # Small delay before token exchange (some APIs need a moment to process auth_code)
            self.logger.debug("Waiting 1 second before token exchange...")
            time.sleep(1)
            
            # Set token and generate access token (matching fyers_apiv3 API style)
            self.set_token(auth_code)
            response = self.generate_token()
            
            if response.get('s') != 'ok':
                raise FyersAuthError(f"Token exchange failed: {response.get('message', 'Unknown error')}")
            return True

        except FyersAuthError as e:
            self.logger.error("Interactive authenticate failed: %s", e)
            return False
        except Exception as e:
            self.logger.error("Interactive authenticate unexpected failure: %s", e)
            return False


# -------------------------
# CLI runner (same as before)
# -------------------------


def main():
    parser = argparse.ArgumentParser(description="Fyers auth helper - auto-open in detected Chrome profile")
    parser.add_argument("creds", nargs="?", default="creds.yaml", help="Path to creds.yaml")
    parser.add_argument("config", nargs="?", default="config.json", help="Path to config.json")
    parser.add_argument("--no-open", action="store_true", help="Do not open browser automatically; just start server and print URL")
    parser.add_argument("--no-kill", action="store_true", help="Do not kill existing Chrome processes (less deterministic)")
    parser.add_argument("--use-userdata", action="store_true", help="Launch Chrome with --user-data-dir (ensure Chrome is not running)")
    args = parser.parse_args()

    try:
        auth = FyersAuth(args.creds, args.config)
    except Exception as e:
        print("Failed to initialize auth manager:", e)
        sys.exit(1)

    ok = auth.authenticate_interactive(no_open=args.no_open, no_kill=args.no_kill, use_userdata=args.use_userdata)
    if not ok:
        print("Authentication failed. Check logs for details.")
        sys.exit(1)

    print("Authenticated. Access token prefix:", (auth.access_token[:20] + "...") if auth.access_token else "None")
    print("Tokens saved at:", auth.token_file)


if __name__ == "__main__":
    main()
