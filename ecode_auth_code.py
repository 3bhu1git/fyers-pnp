# decode_auth_code.py
import sys, base64, json
def b64url_decode(s):
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)
code = sys.argv[1]
try:
    parts = code.split('.')
    payload = parts[1]
    decoded = b64url_decode(payload)
    obj = json.loads(decoded)
    print("JWT claims:")
    for k,v in obj.items():
        print(f"  {k}: {v}")
except Exception as e:
    print("Failed decode:", e)
