import requests
import argparse
from concurrent.futures import ThreadPoolExecutor
import os
from dotenv import load_dotenv
from bs4 import BeautifulSoup

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

load_dotenv()

session = requests.Session()
session.verify = False
session.headers = {
    'User-Agent': 'Mozilla/5.0 (Windows; U; Windows NT 6.0; pl; rv:1.9.1.2) Gecko/20090729 Firefox/3.5.2 GTB7.1 ( .NET CLR 3.5.30729',
    'Referer': 'https://www.google.co.uk/',
    'Accept-Language': 'en-US,en;q=0.5',
    'Cache-Control': 'no-cache'
}

"""
For external usage:

#   from subfetcher import fetch_all_subdomains
#   subdomains = fetch_all_subdomains('example.com')

"""

# Function to get a website and return its JSON
def get_api_data(url, headers=None):
    try:
        response = session.get(url, headers=headers)
        if response.status_code != 200:
            return None
        return response.json() if 'application/json' in response.headers.get('Content-Type') else response.text
    except requests.RequestException as e:
        print(f'An error occurred: {e}')
        return None

def get_html(url):
    try:
        response = session.get(url)
        if response.status_code != 200:
            return None
        return response.content
    except requests.RequestException as e:
        print(f'An error occurred: {e}')
        return None

def fetchCrtSh(target) -> list[str]:
    url = f"https://crt.sh/?q=%.{target}&output=json"
    output = get_api_data(url)
    if output is None:
        print("[!] Failed to retrieve data from CrtSh API!")
        return []
    subdomains = set()
    for entry in output:
        name_value = entry.get('name_value')
        if name_value:
            subdomains.update(name_value.split('\n'))
    return list(subdomains)

def fetchCertSpotter(target) -> list[str]:
    url = f'https://api.certspotter.com/v1/issuances?domain={target}&include_subdomains=true&expand=dns_names'
    output = get_api_data(url)
    if output is None:
        print("[!] Failed to retrieve data from CertSpotter API!")
        return []
    subdomains = set()
    for issuance in output:
        dns_names = issuance.get('dns_names', [])
        filtered_dns_names = [name for name in dns_names if target in name]
        subdomains.update(filtered_dns_names)
    return list(subdomains)

def fetchHackerTarget(target) -> list[str]:
    url = f'https://api.hackertarget.com/hostsearch/?q={target}'
    output = get_api_data(url)
    if output is None:
        print("[!] Failed to retrieve data from HackerTarget API!")
        return []
    lines = output.strip().split('\n')
    subdomains = [line.split(',')[0] for line in lines if ',' in line]
    return list(subdomains)

def fetchUrlScan(target) -> list[str]:
    url = f"https://urlscan.io/api/v1/search/?q=domain:{target}"
    output = get_api_data(url)
    if output is None:
        print("[!] Failed to retrieve data from UrlScan API!")
        return []
    subdomains = set()
    results = output.get('results', [])
    for result in results:
        page = result.get('page', {})
        subdomain = page.get('domain')
        if subdomain and target in subdomain:
            subdomains.add(subdomain)
    return list(subdomains)

def fetchThreatCrowd(target) -> list[str]:
    url = f"https://ci-www.threatcrowd.org/searchApi/v2/domain/report/?domain={target}"
    output = get_api_data(url)
    if output is None:
        print("[!] Failed to retrieve data from ThreatCrowd API!")
        return []
    subdomains = set()
    subdomains.update(output.get('subdomains', []))
    return list(subdomains)

def fetchAlienVault(target) -> list[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns"
    output = get_api_data(url)
    if output is None:
        print("[!] Failed to retrieve data from AlienVault API!")
        return []
    subdomains = set()
    for passive_dns in output.get('passive_dns', []):
        hostname = passive_dns.get('hostname')
        if hostname:
            subdomains.add(hostname)
    return list(subdomains)

def fetchShodan(target) -> list[str]:
    url = 'https://www.shodan.io/domain/' + target
    response = get_html(url)
    if response is None:
        print("[!] Failed to retrieve data from Shodan!")
        return []
    soup = BeautifulSoup(response, 'html.parser')

    subdomains_html = soup.find("ul", id="subdomains")
    if not subdomains_html:
        print("[!] No data from Shodan!")
        return []
    
    names = [li.get_text(strip=True) for li in subdomains_html.find_all("li")]
    subdomains = [f"{name}.{target}" for name in names]
    return subdomains

def fetchVirusTotal(target) -> list[str]:
    api_key = os.environ.get('VIRUSTOTAL_API_KEY')
    if api_key is None or len(api_key) == 0:
        print("[!] No VirusTotal API key found!")
        return []
    url = f"https://www.virustotal.com/api/v3/domains/{target}/subdomains?limit=40"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    output = get_api_data(url, headers=headers)
    if output is None:
        print("[!] Failed to retrieve data from VirusTotal API!")
        return []
    subdomains = set()
    data = output.get('data', [])
    for subdomain in data:
        subdomains.add(subdomain.get('id'))
    return list(subdomains)

def fetch_all_subdomains(domain, *, thread: int=10, proxy: str=None) -> list[str]:

    if proxy:
        proxies = {"http": proxy, "https": proxy}
        session.proxies.update(proxies)

    all_subdomains = []

    def collect_results(future):
        all_subdomains.extend(future.result())

    # Define the functions to be executed in parallel
    function_list = [
        fetchCrtSh,
        fetchCertSpotter,
        fetchHackerTarget,
        fetchThreatCrowd,
        fetchUrlScan,
        fetchAlienVault,
        fetchShodan,
        fetchVirusTotal
    ]

    with ThreadPoolExecutor(max_workers=thread) as executor:
        futures = [executor.submit(func, domain) for func in function_list]
        
        for future in futures:
            future.add_done_callback(collect_results)

    return list(set(all_subdomains))


def main() -> None:
    parser = argparse.ArgumentParser(description='Automatically fetch subdomains from sources.')
    parser.add_argument('-d', '--domain', type=str, required=True, help='The domain to target for subdomain enumeration')
    parser.add_argument('-T', '--thread', type=int, default=10, help='Number of threads to use (default: 10)')
    parser.add_argument('-o', '--output', type=str, help='Output file to save the results')
    parser.add_argument('-p', '--proxy', type=str, help='Proxy server to use (e.g. http://127.0.0.1:8080)')

    args = parser.parse_args()

    target: str = args.domain
    thread: int = args.thread
    http_proxy: str = args.proxy
    subdomains = fetch_all_subdomains(target, thread=thread, proxy=http_proxy)

    print(f'### Combined subdomains for {target} ({len(subdomains)} results):')
    for sub in subdomains:
        print(sub)

    if args.output:
        with open(args.output, 'w') as f:
            f.write('\n'.join(subdomains))
            f.write('\n')

if __name__ == "__main__":
    main()
