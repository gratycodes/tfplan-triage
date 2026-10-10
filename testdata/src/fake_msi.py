#!/usr/bin/env python3
"""Local stand-in for the Azure managed-identity token endpoint.

azurerm insists on a token at configure time, even for -refresh=false
plans. This serves an unsigned JWT with synthetic tenant/object ids so the
provider can configure; nothing is ever sent to Azure.
"""
import base64
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


def b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        now = int(time.time())
        claims = {
            "aud": "https://management.azure.com/",
            "iss": "https://sts.windows.net/11111111-1111-1111-1111-111111111111/",
            "tid": "11111111-1111-1111-1111-111111111111",
            "oid": "44444444-4444-4444-4444-444444444444",
            "appid": "22222222-2222-2222-2222-222222222222",
            "iat": now, "nbf": now, "exp": now + 3600,
        }
        token = b64({"alg": "none", "typ": "JWT"}) + "." + b64(claims) + ".synthetic"
        body = json.dumps({
            "access_token": token, "token_type": "Bearer",
            "expires_in": "3600", "expires_on": str(now + 3600),
            "resource": "https://management.azure.com/",
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 8765), H).serve_forever()
