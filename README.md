# Subdomain Fetcher

A Python script that passively fetch subdomains from APIs. Inspired by Tomnomnom's [assetfinder](https://github.com/tomnomnom/assetfinder). Focusing on cost-free solution.

## Usage

```
usage: subfetcher.py [-h] -d DOMAIN [-T THREAD] [-o OUTPUT] [-p PROXY]

Automatically fetch subdomains from sources.

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        The domain to target for subdomain enumeration
  -T THREAD, --thread THREAD
                        Number of threads to use (default: 10)
  -o OUTPUT, --output OUTPUT
                        Output file to save the results
  -p PROXY, --proxy PROXY
                        Proxy server to use (e.g. http://127.0.0.1:8080)
```

## Sources

- CrtSh
- CertSpotter
- HackerTarget
- ThreatCrowd
- UrlScan
- AlienVault
- VirusTotal
    - Note: `VIRUSTOTAL_API_KEY` in `.env` file is required.
    - Recommended
    - However, the current version 3 has the limitation of 40 domains.
    - [Get API key here](https://www.virustotal.com/gui/my-apikey).
- Security Trails
    - Note: `SECURITYTRAILS_API_KEY` in `.env` file is required.
    - Recommended
    - [Get API key here](https://securitytrails.com/app/account/credentials).