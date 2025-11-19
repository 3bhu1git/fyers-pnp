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
    # Token endpoint: try production first, fallback to trading environment
    TOKEN_URL = "https://api.fyers.in/api/v3/token"  # Production endpoint
    TOKEN_URL_T1 = "https://api-t1.fyers.in/api/v3/token"  # Trading environment endpoint
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

        self._load_tokens()

    def _calc_app_id_hash(self, use_base_app_id: bool = True) -> str:
        """
        FYERS expects SHA256 of the string: "<app_id>:<secret_key>"
        
        Args:
            use_base_app_id: If True, strips -100 suffix from client_id (for v3).
                           If False, uses full client_id (for v2 compatibility).
        
        Return hex digest (lowercase).
        
        Example: 
        - If client_id is "CDKC8R8C9K-100" and use_base_app_id=True, use "CDKC8R8C9K"
        - If use_base_app_id=False, use "CDKC8R8C9K-100"
        """
        client_id = self.config.get("client_id")
        secret = self.config.get("secret_key")

        # Defensive checks
        if not client_id or not secret:
            self.logger.error("Missing client_id or secret_key in config when computing appIdHash")
            raise FyersAuthError("Missing client_id or secret_key for appIdHash computation")

        # Extract app_id based on flag
        if use_base_app_id:
            # Fyers v3: strip -100 suffix for appIdHash
            app_id = client_id.rstrip("-100") if client_id.endswith("-100") else client_id
        else:
            # Use full client_id (v2 format)
            app_id = client_id
        
        # Compute SHA-256 hash of "app_id:secret_key"
        raw = f"{app_id}:{secret}"
        appid_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        self.logger.debug("Computed appIdHash: app_id=%s, hash_prefix=%s...", app_id, appid_hash[:20])
        return appid_hash

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

    def _exchange_code_for_token(self, auth_code: str) -> bool:
        """
        Exchange authorization code for access token and refresh token.
        Uses appIdHash (SHA-256 of app_id:secret_key) for authentication.
        
        Expected response format:
        {
            's': 'ok',
            'code': 200,
            'message': '',
            'access_token': 'eyJ0eXAi...',
            'refresh_token': 'eyJ0eXAi...'
        }
        """
        # Try with base app_id first (v3 format)
        app_id_hash = self._calc_app_id_hash(use_base_app_id=True)
        payload = {
            "grant_type": "authorization_code",
            "appIdHash": app_id_hash,
            "code": auth_code
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        
        self.logger.info("Exchanging auth_code for tokens (prefix): %s...", auth_code[:20] if auth_code else "None")
        self.logger.debug("Token exchange payload: grant_type=%s, appIdHash=%s...", payload["grant_type"], app_id_hash[:20])
        self.logger.debug("Token endpoint: %s", self.TOKEN_URL)
        
        # Log full payload for debugging (without exposing secret)
        client_id = self.config.get("client_id")
        app_id_base = client_id.rstrip("-100") if client_id.endswith("-100") else client_id
        self.logger.debug("Using app_id for hash: %s (from client_id: %s)", app_id_base, client_id)
        
        try:
            # Use trading environment endpoint (api-t1) since auth_code comes from there
            # The token exchange should use the same environment as auth code generation
            token_endpoint = self.TOKEN_URL_T1
            self.logger.debug("Using trading environment token endpoint: %s", token_endpoint)
            
            # Retry logic for 503 errors (server might be temporarily unavailable)
            max_retries = 3
            retry_delay = 2  # seconds
            r = None
            
            for attempt in range(max_retries):
                if attempt > 0:
                    self.logger.info("Retry attempt %d/%d after %d seconds...", attempt, max_retries, retry_delay)
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                
                r = requests.post(token_endpoint, json=payload, headers=headers, timeout=30)
                
                # If successful or non-503 error, break retry loop
                if r.status_code != 503:
                    break
            
            # Parse response
            try:
                data = r.json()
            except Exception as e:
                # Handle HTML error responses (like 503)
                if r.status_code == 503:
                    self.logger.error("503 Service Temporarily Unavailable from token endpoint after %d retries", max_retries)
                    self.logger.error("Response: %s", r.text[:200])
                    self.logger.warning("This might be a temporary server issue. Please try again in a few moments.")
                    # Don't raise, return False to allow manual retry
                    return False
                self.logger.error("Non-JSON response from token endpoint: %s", r.text[:500])
                self.logger.error("Parse error: %s", e)
                # Only raise for non-503 errors
                if r.status_code != 503:
                    r.raise_for_status()
                return False

            # Check for errors
            if r.status_code != 200:
                msg = data.get("message") or data.get("error") or data.get("error_description") or r.text
                self.logger.error("Token exchange failed (%s): %s", r.status_code, msg)
                self.logger.debug("Full response: %s", data)
                
                # If 401, try multiple fallback strategies
                if r.status_code == 401 and "authenticate" in str(msg).lower():
                    # Strategy 1: Try with full client_id (with -100)
                    self.logger.warning("401 error, trying fallback strategies...")
                    self.logger.warning("Fallback 1: Trying with full client_id (including -100)...")
                    app_id_hash_full = self._calc_app_id_hash(use_base_app_id=False)
                    payload_fallback = {
                        "grant_type": "authorization_code",
                        "appIdHash": app_id_hash_full,
                        "code": auth_code
                    }
                    self.logger.debug("Retry payload: appIdHash=%s...", app_id_hash_full[:20])
                    
                    # Try with trading environment endpoint (should match auth_code source)
                    r_fallback = requests.post(self.TOKEN_URL_T1, json=payload_fallback, headers=headers, timeout=30)
                    try:
                        data_fallback = r_fallback.json()
                        if r_fallback.status_code == 200 and (data_fallback.get("s") == "ok" or data_fallback.get("access_token")):
                            self.logger.info("Token exchange succeeded with full client_id format")
                            # Process success response (same as below)
                            with self._token_lock:
                                access_token = data_fallback.get("access_token")
                                refresh_token = data_fallback.get("refresh_token")
                                if access_token:
                                    self.access_token = access_token
                                    self.refresh_token = refresh_token or self.refresh_token
                                    expires_in = int(data_fallback.get("expires_in", 86400))
                                    self.token_expiry = datetime.now() + timedelta(seconds=expires_in)
                                    self._save_tokens()
                                    self.logger.info("Token exchange successful. Access token expires at: %s", self.token_expiry.isoformat())
                                    return True
                    except Exception as e:
                        self.logger.error("Fallback attempt also failed: %s", e)
                
                # Provide helpful error messages
                if "expired" in str(msg).lower():
                    self.logger.error("Auth code has expired. Please generate a new one.")
                elif "invalid" in str(msg).lower() or "authenticate" in str(msg).lower():
                    self.logger.error("Invalid auth code or appIdHash. Check your credentials.")
                    self.logger.error("Tried both base app_id and full client_id formats.")
                
                return False

            # Check success status (Fyers API returns 's': 'ok' and 'code': 200)
            if data.get("s") == "ok" or (data.get("code") == 200 and data.get("access_token")):
                with self._token_lock:
                    # Extract tokens from response
                    access_token = data.get("access_token")
                    refresh_token = data.get("refresh_token")
                    
                    if not access_token:
                        self.logger.error("Token exchange succeeded but no access_token in response: %s", data)
                        return False
                    
                    self.access_token = access_token
                    self.refresh_token = refresh_token or self.refresh_token
                    
                    # Calculate expiry (typically 24 hours for Fyers)
                    expires_in = data.get("expires_in", 86400)
                    try:
                        expires_in = int(expires_in)
                    except (ValueError, TypeError):
                        expires_in = 86400  # Default to 24 hours
                    
                    self.token_expiry = datetime.now() + timedelta(seconds=expires_in)
                
                self._save_tokens()
                self.logger.info("Token exchange successful. Access token expires at: %s", self.token_expiry.isoformat())
                self.logger.debug("Access token prefix: %s...", self.access_token[:20] if self.access_token else "None")
                self.logger.debug("Refresh token prefix: %s...", self.refresh_token[:20] if self.refresh_token else "None")
                return True
            else:
                # Response indicates failure
                msg = data.get("message") or data.get("error") or "Unknown error"
                self.logger.error("Token exchange failed: %s", msg)
                self.logger.debug("Full response: %s", data)
                return False
                
        except requests.exceptions.RequestException as e:
            self.logger.error("Network error during token exchange: %s", e)
            return False
        except Exception as e:
            self.logger.error("Unexpected error during token exchange: %s", e)
            return False

    def authenticate_interactive(
        self, no_open: bool = False, no_kill: bool = False, use_userdata: bool = False, timeout: Optional[int] = None
    ) -> bool:
        if timeout is None:
            timeout = int(self.config.get("auth_timeout", 300))

        # If we already have valid token, return
        if self.access_token and self.token_expiry and self.token_expiry > datetime.now():
            self.logger.info("Already have valid access token.")
            return True

        client_id = self.config.get("client_id")
        redirect_uri = self.config.get("redirect_uri")
        state = self.config.get("state", "")
        scope = self.config.get("scope", "")
        auth_url = (
            f"https://api-t1.fyers.in/api/v3/generate-authcode?client_id={client_id}"
            f"&redirect_uri={redirect_uri}&response_type=code&state={state}&scope={scope}"
        )

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
            
            # exchange
            if not self._exchange_code_for_token(auth_code):
                raise FyersAuthError("Token exchange failed for provided auth_code")
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
