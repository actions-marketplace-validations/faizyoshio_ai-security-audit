#!/usr/bin/env python3
"""
Shadow & Zombie API Spec Differ
Compares two OpenAPI/Swagger JSON specifications to identify deprecated, hidden,
or undocumented endpoints, and checks if they remain reachable on a live target.
Author: faizyoshio
License: Apache-2.0
"""

import sys
import argparse
import json
import urllib.request
import urllib.error

def load_spec(source: str) -> dict:
    if source.startswith("http://") or source.startswith("https://"):
        req = urllib.request.Request(source, headers={"User-Agent": "ai-security-audit/1.0"})
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            return json.loads(resp.read().decode("utf-8"))
    else:
        with open(source, "r", encoding="utf-8-sig") as f:
            return json.load(f)

def extract_paths(spec: dict) -> set:
    paths = set()
    if "paths" in spec and isinstance(spec["paths"], dict):
        for path, methods in spec["paths"].items():
            if isinstance(methods, dict):
                for method in methods.keys():
                    if method.lower() in ["get", "post", "put", "delete", "patch", "options", "head"]:
                        paths.add((method.upper(), path))
            else:
                paths.add(("ANY", path))
    return paths

def probe_endpoint(base_url: str, method: str, path: str, timeout: float = 3.0):
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    req = urllib.request.Request(url, method=method, headers={"User-Agent": "ai-security-audit/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None

def main():
    parser = argparse.ArgumentParser(description="Shadow and Zombie API Endpoint Differ")
    parser.add_argument("--old", required=True, help="Path or URL to the historical/older OpenAPI/Swagger JSON spec")
    parser.add_argument("--new", required=True, help="Path or URL to the current/active OpenAPI/Swagger JSON spec")
    parser.add_argument("--target", help="Optional live target base URL (e.g. https://api.example.com) to test reachability")
    args = parser.parse_args()

    try:
        old_spec = load_spec(args.old)
        new_spec = load_spec(args.new)
    except Exception as e:
        print(f"[-] Error loading specs: {e}", file=sys.stderr)
        sys.exit(1)

    old_endpoints = extract_paths(old_spec)
    new_endpoints = extract_paths(new_spec)

    deprecated_endpoints = sorted(list(old_endpoints - new_endpoints))

    print("\n" + "=" * 70)
    print(" SHADOW & ZOMBIE API SPECIFICATION DIFFER")
    print("=" * 70)
    print(f"[*] Total endpoints in old spec: {len(old_endpoints)}")
    print(f"[*] Total endpoints in new spec: {len(new_endpoints)}")
    print(f"[*] Discontinued / deprecated endpoints found: {len(deprecated_endpoints)}\n")

    if not deprecated_endpoints:
        print("[+] No discontinued endpoints detected between these two specs.")
        return

    print("--- POTENTIAL SHADOW / ZOMBIE ENDPOINTS ---")
    for method, path in deprecated_endpoints:
        status_info = ""
        if args.target:
            code = probe_endpoint(args.target, method if method != "ANY" else "GET", path)
            if code is None:
                status_info = " -> [UNREACHABLE / NETWORK ERROR]"
            elif code == 404:
                status_info = f" -> HTTP {code} (Cleanly Removed)"
            elif code in [200, 201, 204]:
                status_info = f" -> [CRITICAL] HTTP {code} (Still Live & Unauthenticated!)"
            elif code in [401, 403]:
                status_info = f" -> [WARNING] HTTP {code} (Route Exists, Auth Demanded)"
            else:
                status_info = f" -> HTTP {code}"
        print(f"  {method:<6} {path}{status_info}")

    print("\n[+] Diff complete. Verify if removed endpoints still route to active LLM models.\n")

if __name__ == "__main__":
    main()
