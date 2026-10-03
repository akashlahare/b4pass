# b4pass

**b4pass** is an advanced web directory scanner designed for web application security testing. It can discover hidden paths/directories, scan recursively, and test potential **403 access-control bypasses**.

![b4pass Preview](https://github.com/akashlahare/b4pass/blob/main/image.png)

## Features
* Directory/endpoint discovery with built-in and custom wordlists
* Recursive scanning, response filtering (status / size / text / regex), crawling
* **401/403 bypass engine** — raw un-normalized path probes (`%2e%2e`, `/./`, `//`, `#frag`), header spoofing (IP/host/scheme/port/rewrite + cloud-metadata), HTTP method & HTTP/1.0 downgrade, false-positive calibration, SPA soft-auth-wall detection
* Bypass probes inherit the scan's proxy / auth / cookies / headers

## Install

Requires Python 3.7+. Install **editable** — b4pass loads its bundled
wordlist and report template from alongside the source, which a normal
install leaves behind.

```bash
git clone https://github.com/akashlahare/b4pass.git
cd b4pass
pipx install --editable .        # or: python3 -m venv .venv && source .venv/bin/activate && pip install -e .
```

No install needed to run from source: `pip install -r requirements.txt` then `python3 b4pass.py`.

## Usage

```bash
b4pass -u https://example.com                                    # basic scan
b4pass -u https://example.com -e php,html,txt                    # with extensions
b4pass -u https://example.com -w wordlist.txt                    # custom wordlist
b4pass -u https://example.com -r -R 3                            # recursive, max depth 3
b4pass -b https://example.com/admin                              # bypass one URL (no scan)
b4pass -u https://example.com --proxy http://127.0.0.1:8080      # route via Burp
b4pass -u https://example.com --cookie "session=abc" -H "X-Key: v" # authenticated
b4pass -u https://example.com -i 200,301,403 -o report.html
b4pass --help                                                # all options
```

## Key flags

| Flag | Purpose |
|------|---------|
| `-u` / `-b` | Scan target / run bypass on a single URL |
| `-w` / `-e` | Custom wordlist(s) / extensions |
| `-r` / `-R` | Recursive / max depth |
| `-i` / `-x` / `-s` | Include / exclude status codes / exclude sizes |
| `-H` / `--cookie` / `--auth` + `--auth-type` | Headers / cookie / auth |
| `--proxy` / `--tor` | Proxy (e.g. Burp) / Tor |
| `-t` / `-d` / `--max-rate` / `--timeout` | Threads / delay / rate / timeout |
| `-o` / `--format` | Output file / format |

## Attribution & License

Scanning core is a modified derivative of
[dirsearch](https://github.com/maurosoria/dirsearch) (GPL-2.0, © Mauro
Soria); the 401/403 bypass engine is original work by Akash Lahare.
Released under **GPL-2.0-or-later** — see `NOTICE`.

## Disclaimer

For **authorized** security testing only. Do not scan systems without
explicit permission from the owner.
