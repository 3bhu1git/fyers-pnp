#!/usr/bin/env python3
"""
Detect Chrome default profile from Local State and open a URL in that profile.

Usage:
    python chrome_profile_launcher.py "<url>"

This will:
 - auto-detect Chrome user-data dir (macOS / Linux / Windows)
 - read 'Local State' to find "profile.last_used"
 - verify profile folder exists under user-data dir
 - attempt to launch Chrome with --profile-directory=<profile>
 - optionally kills existing chrome processes for deterministic launch
"""

from pathlib import Path
import json, os, sys, subprocess, time, shutil, platform, webbrowser
from typing import Optional, Tuple

def get_chrome_user_data_dir() -> Optional[Path]:
    """Return Chrome user-data parent folder where profiles live, or None."""
    system = platform.system()
    if system == "Darwin":
        p = Path.home() / "Library" / "Application Support" / "Google" / "Chrome"
    elif system == "Windows":
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            return None
        p = Path(local) / "Google" / "Chrome" / "User Data"
    else:
        # assume Linux
        p = Path.home() / ".config" / "google-chrome"
        if not p.exists():
            p = Path.home() / ".config" / "chromium"
    return p if p.exists() else None

def read_local_state(user_data_dir: Path) -> Optional[dict]:
    """Parse Local State JSON and return its dict, or None."""
    local_state = user_data_dir / "Local State"
    if not local_state.exists():
        return None
    try:
        raw = local_state.read_text(encoding='utf-8')
        data = json.loads(raw)
        return data
    except Exception as e:
        print("Failed to read/parse Local State:", e)
        return None

def detect_last_used_profile(user_data_dir: Path) -> Optional[str]:
    """Return the profile name Chrome uses as default (value of profile.last_used) or None."""
    data = read_local_state(user_data_dir)
    if not data:
        return None
    profile = data.get("profile") or {}
    last_used = profile.get("last_used")
    # fallback to 'Default' if nothing found
    if not last_used:
        # try to pick a sensible folder that exists
        cand = "Default"
        if (user_data_dir / cand).exists():
            return cand
        # else pick first folder under user_data_dir that looks like a profile
        for entry in user_data_dir.iterdir():
            if entry.is_dir() and entry.name.startswith("Profile"):
                return entry.name
        return None
    return last_used

def _locate_chrome_binary() -> Optional[str]:
    system = platform.system()
    if system == "Darwin":
        p = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        return str(p) if p.exists() else None
    if system == "Windows":
        lp = os.environ.get("LOCALAPPDATA", "")
        candidates = [
            Path(lp) / "Google" / "Chrome" / "Application" / "chrome.exe",
            Path(os.environ.get("PROGRAMFILES", "")) / "Google" / "Chrome" / "Application" / "chrome.exe",
            Path(os.environ.get("PROGRAMFILES(X86)", "")) / "Google" / "Chrome" / "Application" / "chrome.exe"
        ]
        for c in candidates:
            if c.exists():
                return str(c)
        return None
    # linux
    return shutil.which("google-chrome") or shutil.which("chrome") or shutil.which("chromium") or shutil.which("chromium-browser")

def kill_chrome_processes() -> None:
    """Kill chrome processes (use only if you accept closing user's browser)."""
    system = platform.system()
    try:
        if system == "Windows":
            subprocess.run(["taskkill", "/F", "/IM", "chrome.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(["pkill", "-f", "chrome"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
    except Exception:
        pass

def open_url_in_profile(url: str,
                        profile: Optional[str],
                        force_kill: bool = True,
                        use_user_data_dir: bool = False) -> Tuple[bool, str]:
    """
    Open URL in Chrome with given profile name.
    Returns (success, message).
    """
    chrome = _locate_chrome_binary()
    user_data_dir = get_chrome_user_data_dir()
    if force_kill:
        kill_chrome_processes()

    if chrome:
        args = [chrome]
        if use_user_data_dir and user_data_dir:
            args += [f"--user-data-dir={str(user_data_dir)}"]
        if profile:
            args += [f"--profile-directory={profile}"]
        args += ["--new-window", "--no-default-browser-check", url]
        try:
            subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True, f"Launched Chrome binary: {' '.join(args[:3])} ..."
        except Exception as e:
            return False, f"Failed to launch Chrome binary: {e}"

    # mac fallback: use 'open -na' with args to force a new instance
    if platform.system() == "Darwin":
        try:
            cmd = ["open", "-na", "Google Chrome", "--args"]
            if use_user_data_dir and user_data_dir:
                cmd += [f"--user-data-dir={str(user_data_dir)}"]
            if profile:
                cmd += [f"--profile-directory={profile}"]
            cmd += ["--new-window", "--no-default-browser-check", url]
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True, "Launched macOS Chrome via open -na"
        except Exception as e:
            return False, f"mac open -na failed: {e}"

    # fallback: system default browser
    try:
        webbrowser.open(url, new=1)
        return True, "Fallback: opened in default browser"
    except Exception as e:
        return False, f"Fallback failed: {e}"

# -------------------------
# CLI test
# -------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python chrome_profile_launcher.py <url> [--no-kill] [--no-userdata]")
        sys.exit(1)
    url = sys.argv[1]
    force_kill = True
    use_user_data_dir = False
    if "--no-kill" in sys.argv:
        force_kill = False
    if "--use-userdata" in sys.argv:
        use_user_data_dir = True

    ud = get_chrome_user_data_dir()
    if not ud:
        print("Chrome user-data directory not found on this system.")
        sys.exit(1)
    print("Chrome user-data dir:", ud)

    profile = detect_last_used_profile(ud)
    if not profile:
        print("Could not detect a profile; falling back to 'Default' if it exists.")
        profile = "Default" if (ud / "Default").exists() else None

    print("Detected profile:", profile)
    if profile and not (ud / profile).exists():
        print(f"Warning: profile folder {ud/profile} does not exist on disk.")

    ok, msg = open_url_in_profile(url, profile, force_kill=force_kill, use_user_data_dir=use_user_data_dir)
    print("Result:", ok, msg)

if __name__ == "__main__":
    main()

