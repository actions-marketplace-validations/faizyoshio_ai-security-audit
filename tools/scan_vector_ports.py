#!/usr/bin/env python3
"""
Vector Database Port & Exposure Scanner
Probes common vector stores for open ports and unauthenticated REST/gRPC endpoints.
Author: faizyoshio
License: Apache-2.0
"""

import sys
import socket
import argparse
import json
import urllib.request
import urllib.error

DEFAULT_TARGETS = [
    {
        "name": "Chroma DB",
        "port": 8000,
        "probe_path": "/api/v1/heartbeat",
        "description": "Default Chroma REST interface"
    },
    {
        "name": "Qdrant REST",
        "port": 6333,
        "probe_path": "/collections",
        "description": "Default Qdrant REST collection API"
    },
    {
        "name": "Weaviate REST",
        "port": 8080,
        "probe_path": "/v1/schema",
        "description": "Default Weaviate schema endpoint"
    },
    {
        "name": "Milvus gRPC / REST",
        "port": 19530,
        "probe_path": None,
        "description": "Default Milvus listener port"
    },
    {
        "name": "PostgreSQL / pgvector",
        "port": 5432,
        "probe_path": None,
        "description": "Standard PostgreSQL port"
    }
]

def check_socket(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def probe_http(host: str, port: int, path: str, timeout: float = 2.0):
    url = f"http://{host}:{port}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "ai-security-audit/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read(256).decode("utf-8", errors="ignore")
            return response.status, body.strip()
    except urllib.error.HTTPError as e:
        return e.code, "HTTP Error"
    except Exception as e:
        return None, str(e)

def run_scan(host: str, timeout: float = 2.0):
    results = []
    print(f"\n[*] Scanning vector database interfaces on: {host}")
    print(f"[*] Timeout per probe: {timeout}s\n" + "-" * 70)
    
    for item in DEFAULT_TARGETS:
        name = item["name"]
        port = item["port"]
        path = item["probe_path"]
        
        is_open = check_socket(host, port, timeout)
        record = {
            "name": name,
            "port": port,
            "open": is_open,
            "http_status": None,
            "http_preview": None,
            "severity": "SAFE"
        }
        
        if is_open:
            status_desc = f"[!] PORT OPEN ({port})"
            if path:
                http_code, preview = probe_http(host, port, path, timeout)
                record["http_status"] = http_code
                record["http_preview"] = preview
                if http_code == 200:
                    status_desc += f" -> [CRITICAL] Unauthenticated 200 at {path}"
                    record["severity"] = "CRITICAL"
                elif http_code:
                    status_desc += f" -> HTTP {http_code} at {path}"
                    record["severity"] = "HIGH"
            else:
                record["severity"] = "MEDIUM"
                status_desc += " -> Service listening (no HTTP probe)"
        else:
            status_desc = f"[-] Closed ({port})"
            
        print(f"  {name:<25} {status_desc}")
        results.append(record)
        
    print("-" * 70)
    critical_count = sum(1 for r in results if r["severity"] == "CRITICAL")
    if critical_count > 0:
        print(f"\n[ALERT] Detected {critical_count} unauthenticated vector databases! Review network isolation.\n")
    else:
        print("\n[+] Scan complete.\n")
        
    return results

def main():
    parser = argparse.ArgumentParser(description="Vector DB Port & Exposure Scanner")
    parser.add_argument("--host", default="127.0.0.1", help="Target host or IP address (default: 127.0.0.1)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Socket and HTTP timeout in seconds (default: 2.0)")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()
    
    scan_results = run_scan(args.host, args.timeout)
    if args.json:
        print(json.dumps(scan_results, indent=2))

if __name__ == "__main__":
    main()
