#!/usr/bin/env python3
"""
Out-of-Band (OOB) HTTP Callback Listener
Verifies empirical data egress and canary callbacks for AI exfiltration testing.
Author: faizyoshio
License: Apache-2.0
"""

import sys
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
from datetime import datetime

class OOBHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Override default server logging to custom format
        pass

    def do_GET(self):
        self.handle_interaction("GET")

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8", errors="ignore")
        self.handle_interaction("POST", body)

    def handle_interaction(self, method: str, body: str = ""):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print("\n" + "=" * 65)
        print(f"[!] INCOMING OOB INTERACTION DETECTED [{timestamp}]")
        print(f"    Client IP   : {self.client_address[0]}:{self.client_address[1]}")
        print(f"    HTTP Method : {method}")
        print(f"    Path        : {parsed.path}")
        print(f"    User-Agent  : {self.headers.get('User-Agent', 'Unknown')}")
        
        if params:
            print("    Query Parameters:")
            for k, v in params.items():
                print(f"      - {k}: {', '.join(v)}")
        if body:
            print(f"    Body Payload: {body[:500]}")

        print("=" * 65)

        # Send standard 200 OK image response (1x1 transparent GIF)
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        # 1x1 transparent GIF bytes
        self.wfile.write(b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")

def main():
    parser = argparse.ArgumentParser(description="Lightweight Out-of-Band (OOB) HTTP Callback Listener")
    parser.add_argument("--port", type=int, default=8888, help="Port to listen on (default: 8888)")
    parser.add_argument("--host", default="0.0.0.0", help="Binding host address (default: 0.0.0.0)")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), OOBHandler)
    print("\n" + "*" * 65)
    print(f"[*] AI SECURITY AUDIT - OOB CALLBACK LISTENER")
    print(f"[*] Listening on: http://{args.host}:{args.port}/")
    print(f"[*] Use as canary sink: http://<YOUR_IP>:{args.port}/leak?data=CANARY_TOKEN")
    print(f"[*] Press Ctrl+C to terminate.")
    print("*" * 65 + "\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Listener terminated by user.")
        server.server_close()

if __name__ == "__main__":
    main()
