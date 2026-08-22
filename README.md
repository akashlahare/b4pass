# b4pass

**b4pass** is an advanced web directory and endpoint scanner designed for web application security testing. It can discover hidden paths, scan recursively, handle authenticated requests, and test potential **403 access-control bypasses**.

![b4pass Preview](https://github.com/akashlahare/b4pass/blob/main/image.png)

## Features
* Web directory and endpoint discovery
* Built-in and custom wordlists
* 403 bypass testing
* Recursive scanning
* Custom HTTP methods, headers, cookies and authentication
* Proxy and Tor support
* Rate limiting and request delays
* Response filtering by status, size, text and regex
* Crawl-based endpoint discovery
* Raw HTTP request support
* Multiple report formats: HTML, JSON, XML, CSV, Markdown, SQLite and text
* Colored terminal output

## Requirements
* Python **3.7+**

## Installation
cd b4pass-0.1
pip install -r requirements.txt

## Usage
Basic directory scan:
python b4pass.py -u https://example.com

Scan with extensions:
python b4pass.py -u https://example.com -e php,html,txt

Test a specific URL for 403 bypasses:
python b4pass.py -b https://example.com/admin

Use a custom wordlist:
python b4pass.py -u https://example.com -w wordlists/default.txt

Save results as HTML or TXT:
python b4pass.py -u https://example.com -o report.html or -o report.txt

For all available options:
python b4pass.py --help

## Disclaimer

b4pass is intended for **authorized security testing, penetration testing, and research only**. Do not scan systems or applications without explicit permission from the owner.
