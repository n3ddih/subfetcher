# Subdomain Fetcher

A Python script that passively fetch subdomains from APIs. Inspired by Tomnomnom's [assetfinder](https://github.com/tomnomnom/assetfinder).

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
    - Note: Require `VIRUSTOTAL_API_KEY` in `.env` file
    - It is recommended because VT fetch more results than other sources.
    - [Link to get API key](https://www.virustotal.com/gui/my-apikey)
