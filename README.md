# 🔍 Basic Vulnerability Scanner

A lightweight vulnerability scanner written in Python.

Supports:
- ✅ Port Scanning (common services)
- ✅ SQL Injection detection (GET + POST)
- ✅ XSS detection (GET + POST)

⚠️ For educational use only. Do not scan systems without permission.
Clone the Repository

First, download the project from GitHub:

git clone https://github.com/<your-username>/vuln-scanner.git
cd vuln-scanner


Then install dependencies:

pip install -r requirements.txt

Now you’re ready to run the scanner 🚀

Port Scan

python vuln_scanner.py 127.0.0.1

🌐 Web Scan (SQLi & XSS)

python vuln_scanner.py "http://testphp.vulnweb.com/artists.php"
