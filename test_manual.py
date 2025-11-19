"""
Manual Testing Script for Fyers Authentication Module

This script helps test the auth module manually with real credentials.
Run this after setting up creds.yaml and config.json.

Usage:
    python test_manual.py
"""

import sys
import os
from pathlib import Path
from auth import FyersAuth, FyersAuthError


def test_config_loading():
    """Test 1: Configuration loading"""
    print("\n" + "="*60)
    print("TEST 1: Configuration Loading")
    print("="*60)
    
    try:
        auth = FyersAuth()
        print("✓ Configuration loaded successfully")
        print(f"  - Client ID: {auth.config['client_id'][:10]}...")
        print(f"  - Redirect URI: {auth.config['redirect_uri']}")
        print(f"  - Port: {auth.config['port']}")
        print(f"  - Log file: {auth.config['log_file']}")
        return True
    except FileNotFoundError as e:
        print(f"✗ Configuration file not found: {e}")
        print("  Make sure creds.yaml exists in the current directory")
        return False
    except ValueError as e:
        print(f"✗ Configuration error: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False


def test_auth_url_generation():
    """Test 2: Authorization URL generation"""
    print("\n" + "="*60)
    print("TEST 2: Authorization URL Generation")
    print("="*60)
    
    try:
        auth = FyersAuth()
        auth_url = auth.get_auth_url()
        print("✓ Authorization URL generated successfully")
        print(f"  URL: {auth_url}")
        print("\n  You can visit this URL in a browser to authorize the app")
        return True
    except Exception as e:
        print(f"✗ Error generating auth URL: {e}")
        return False


def test_token_loading():
    """Test 3: Token loading from file"""
    print("\n" + "="*60)
    print("TEST 3: Token Loading from File")
    print("="*60)
    
    try:
        auth = FyersAuth()
        token_file = Path(auth.config['token_file'])
        
        if token_file.exists():
            print(f"✓ Token file exists: {token_file}")
            if auth.access_token:
                print(f"  - Access token loaded: {auth.access_token[:20]}...")
                print(f"  - Token expiry: {auth.token_expiry}")
                if auth.is_authenticated():
                    print("  - Status: Authenticated ✓")
                else:
                    print("  - Status: Token expired or invalid")
            else:
                print("  - No valid token found in file")
        else:
            print(f"  - Token file does not exist: {token_file}")
            print("  - This is normal if you haven't authenticated yet")
        return True
    except Exception as e:
        print(f"✗ Error loading tokens: {e}")
        return False


def test_authentication_status():
    """Test 4: Authentication status check"""
    print("\n" + "="*60)
    print("TEST 4: Authentication Status")
    print("="*60)
    
    try:
        auth = FyersAuth()
        is_auth = auth.is_authenticated()
        
        if is_auth:
            print("✓ Currently authenticated")
            token = auth.get_access_token()
            print(f"  - Access token available: {token[:20]}...")
            
            try:
                headers = auth.get_auth_headers()
                print("  - Auth headers generated successfully")
                print(f"    Authorization: {headers['Authorization'][:30]}...")
            except Exception as e:
                print(f"  ✗ Error getting headers: {e}")
        else:
            print("✗ Not authenticated")
            print("  - You need to run authentication flow")
            print("  - Run: python auth.py")
        return is_auth
    except Exception as e:
        print(f"✗ Error checking auth status: {e}")
        return False


def test_auth_headers():
    """Test 5: Authorization headers generation"""
    print("\n" + "="*60)
    print("TEST 5: Authorization Headers Generation")
    print("="*60)
    
    try:
        auth = FyersAuth()
        
        if not auth.is_authenticated():
            print("✗ Not authenticated - cannot generate headers")
            print("  Run authentication first: python auth.py")
            return False
        
        headers = auth.get_auth_headers()
        print("✓ Auth headers generated successfully")
        print(f"  - Authorization: Bearer {auth.access_token[:20]}...")
        print(f"  - Content-Type: {headers['Content-Type']}")
        print(f"  - Accept: {headers['Accept']}")
        return True
    except FyersAuthError as e:
        print(f"✗ Auth error: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False


def test_full_authentication_flow():
    """Test 6: Full authentication flow (interactive)"""
    print("\n" + "="*60)
    print("TEST 6: Full Authentication Flow")
    print("="*60)
    print("\n⚠️  This will start the interactive authentication process")
    print("   Make sure you have access to a browser")
    
    response = input("\nDo you want to proceed? (yes/no): ").strip().lower()
    if response != 'yes':
        print("Skipped.")
        return None
    
    try:
        auth = FyersAuth()
        
        if auth.is_authenticated():
            print("✓ Already authenticated")
            return True
        
        print("\nStarting authentication flow...")
        print("A browser window will open, or visit the URL shown below")
        
        success = auth.authenticate()
        
        if success:
            print("\n✓ Authentication successful!")
            print(f"  - Access token: {auth.access_token[:20]}...")
            print(f"  - Token expiry: {auth.token_expiry}")
            return True
        else:
            print("\n✗ Authentication failed")
            return False
            
    except KeyboardInterrupt:
        print("\n\nAuthentication cancelled by user")
        return None
    except Exception as e:
        print(f"\n✗ Error during authentication: {e}")
        return False


def main():
    """Run all manual tests"""
    print("\n" + "="*60)
    print("FYERS AUTH MODULE - MANUAL TESTING")
    print("="*60)
    print("\nThis script will test various aspects of the auth module")
    print("Make sure you have:")
    print("  1. creds.yaml file with your credentials")
    print("  2. config.json file (optional, defaults will be used)")
    print("  3. Virtual environment activated")
    print("  4. Dependencies installed: pip install -r requirements.txt")
    
    input("\nPress Enter to continue...")
    
    results = []
    
    # Run tests
    results.append(("Config Loading", test_config_loading()))
    results.append(("Auth URL Generation", test_auth_url_generation()))
    results.append(("Token Loading", test_token_loading()))
    results.append(("Auth Status", test_authentication_status()))
    
    # Only test headers if authenticated
    if results[-1][1]:  # If auth status check passed
        results.append(("Auth Headers", test_auth_headers()))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result is True)
    total = len([r for r in results if r[1] is not None])
    
    for test_name, result in results:
        if result is True:
            print(f"✓ {test_name}: PASSED")
        elif result is False:
            print(f"✗ {test_name}: FAILED")
        else:
            print(f"- {test_name}: SKIPPED")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    # Offer full auth flow test
    if not all(r for _, r in results if r is not None):
        print("\n" + "="*60)
        print("FULL AUTHENTICATION FLOW TEST")
        print("="*60)
        print("Some tests failed. Would you like to try the full authentication flow?")
        print("This will attempt to authenticate with Fyers API.")
        
        response = input("\nRun full auth flow? (yes/no): ").strip().lower()
        if response == 'yes':
            result = test_full_authentication_flow()
            if result:
                print("\n✓ Full authentication test completed successfully!")
            elif result is False:
                print("\n✗ Full authentication test failed")
    
    print("\n" + "="*60)
    print("Testing complete!")
    print("="*60)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

