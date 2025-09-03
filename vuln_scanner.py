#!/usr/bin/env python3
"""
Basic Vulnerability Scanner
- Port Scan
- SQL Injection detection
- XSS detection
- Supports GET & POST forms
"""

import socket
import sys
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# ----------------- CONFIG -----------------
common_ports = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 3306: "MySQL", 3389: "RDP"
}

sqli_payloads = ["' OR '1'='1", '" OR "1"="1', "' OR 1=1--", "'; DROP TABLE users--"]
xss_payloads = ["<script>alert(1)</script>", "\"'><img src=x onerror=alert(1)>"]

# ----------------- PORT SCAN -----------------
def scan_ports(host):
    print(f"\n[+] Scanning Target: {host}")
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f"[OPEN] Port {port} ({common_ports[port]})")
            sock.close()
        except:
            pass

# ----------------- SQLi TEST -----------------
def test_sqli(url, params, method="GET"):
    print(f"\n[+] Testing SQLi on {url} ({method})")
    for key in params:
        for payload in sqli_payloads:
            test_params = params.copy()
            test_params[key] = payload
            try:
                if method == "GET":
                    r = requests.get(url, params=test_params, timeout=5)
                else:
                    r = requests.post(url, data=test_params, timeout=5)

                if any(err in r.text.lower() for err in ["sql syntax", "mysql", "native client", "ora-"]):
                    print(f"[VULNERABLE] SQLi with param: {key}, payload: {payload}")
            except:
                pass

# ----------------- XSS TEST -----------------
def test_xss(url, params, method="GET"):
    print(f"\n[+] Testing XSS on {url} ({method})")
    for key in params:
        for payload in xss_payloads:
            test_params = params.copy()
            test_params[key] = payload
            try:
                if method == "GET":
                    r = requests.get(url, params=test_params, timeout=5)
                else:
                    r = requests.post(url, data=test_params, timeout=5)

                if payload in r.text:
                    print(f"[VULNERABLE] XSS with param: {key}, payload: {payload}")
            except:
                pass

# ----------------- FORM CRAWLER -----------------
def extract_forms(url):
    forms = []
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = {inp.get("name"): "test" for inp in form.find_all("input") if inp.get("name")}
            forms.append({
                "url": urljoin(url, action),
                "method": method.upper(),
                "inputs": inputs
            })
    except:
        pass
    return forms

# ----------------- MAIN -----------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python vuln_scanner.py <target_ip_or_url>")
        sys.exit(1)

    target = sys.argv[1]

    if target.replace(".", "").isdigit():   # IP = port scan
        scan_ports(target)
    else:                                   # URL = web scan
        forms = extract_forms(target)
        if not forms:
            print("[!] No forms found, testing with sample GET params")
            params = {"id": "1", "q": "test"}
            test_sqli(target, params, "GET")
            test_xss(target, params, "GET")
        else:
            for form in forms:
                print(f"\n[+] Found form at {form['url']} (method={form['method']})")
                test_sqli(form["url"], form["inputs"], form["method"])
                test_xss(form["url"], form["inputs"], form["method"])
