##THEHARVESTER ALTERNATIVE - DOMAIN OSINT RECONNAISSANCE TOOL - Small CCCP Reconnaissance Tool
"""
Domain OSINT Reconnaissance Tool
Similar to theHarvester - For Authorized Security Testing Only
Gathers publicly available information about target domains
"""

import asyncio
import aiohttp
import socket
import dns.resolver
import dns.zone
import requests
import json
import re
import sys
import argparse
from urllib.parse import urlparse, quote
from datetime import datetime
from typing import List, Dict, Set, Optional
import concurrent.futures
from bs4 import BeautifulSoup
import subprocess
import ssl
import whois
import shodan
import time

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class DomainRecon:
    def __init__(self, domain: str, limit: int = 500, timeout: int = 10):
        self.domain = domain.lower().strip()
        self.limit = limit
        self.timeout = timeout
        self.results = {
            'domain': self.domain,
            'scan_date': datetime.now().isoformat(),
            'emails': set(),
            'subdomains': set(),
            'hosts': set(),
            'ip_addresses': set(),
            'urls': set(),
            'employees': set(),
            'technologies': set(),
            'dns_records': {},
            'whois_info': {},
            'certificates': [],
            'shodan_info': [],
            'screenshots': []
        }
        
        # User agents for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        
        # Search engines and sources
        self.search_engines = [
            'google', 'bing', 'duckduckgo', 'yahoo', 'baidu'
        ]
        
        # API Keys (optional - add your own)
        self.shodan_key = None  # Add your Shodan API key
        self.hunter_key = None  # Add your Hunter.io API key
        self.securitytrails_key = None  # Add your SecurityTrails key

    def print_banner(self):
        print(f"""{Colors.HEADER}
    ╔══════════════════════════════════════════════════════════╗
    ║           DOMAIN OSINT RECONNAISSANCE TOOL               ║
    ║              (theHarvester Alternative)                  ║
    ╚══════════════════════════════════════════════════════════╝{Colors.ENDC}
    Target: {Colors.BOLD}{self.domain}{Colors.ENDC}
    Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    """)

    async def fetch(self, session: aiohttp.ClientSession, url: str, headers: dict = None) -> str:
        """Async HTTP fetch with error handling"""
        try:
            default_headers = {'User-Agent': self.user_agents[0]}
            if headers:
                default_headers.update(headers)
            
            async with session.get(url, headers=default_headers, timeout=self.timeout, ssl=False) as response:
                if response.status == 200:
                    return await response.text()
        except Exception as e:
            pass
        return ""

    def extract_emails(self, text: str) -> Set[str]:
        """Extract email addresses from text"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = set(re.findall(email_pattern, text))
        # Filter for target domain
        return {e for e in emails if self.domain in e}

    def extract_subdomains(self, text: str) -> Set[str]:
        """Extract subdomains from text"""
        subdomain_pattern = r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(self.domain)
        matches = re.findall(subdomain_pattern, text, re.IGNORECASE)
        subdomains = set()
        for match in matches:
            if isinstance(match, tuple):
                subdomain = match[0] + self.domain
            else:
                subdomain = match
            subdomains.add(subdomain.lower())
        return subdomains

    async def search_google(self, session: aiohttp.ClientSession, query: str) -> str:
        """Search Google (scraping - may require rate limiting)"""
        search_url = f"https://www.google.com/search?q={quote(query)}&num=100"
        try:
            headers = {
                'User-Agent': self.user_agents[0],
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
            }
            return await self.fetch(session, search_url, headers)
        except Exception as e:
            return ""

    async def search_bing(self, session: aiohttp.ClientSession, query: str) -> str:
        """Search Bing"""
        search_url = f"https://www.bing.com/search?q={quote(query)}&count=50"
        try:
            return await self.fetch(session, search_url)
        except:
            return ""

    async def search_duckduckgo(self, session: aiohttp.ClientSession, query: str) -> str:
        """Search DuckDuckGo"""
        search_url = f"https://html.duckduckgo.com/html/?q={quote(query)}"
        try:
            return await self.fetch(session, search_url)
        except:
            return ""

    async def search_crt_sh(self, session: aiohttp.ClientSession):
        """Search certificate transparency logs via crt.sh"""
        print(f"{Colors.OKBLUE}[*] Searching certificate transparency logs (crt.sh)...{Colors.ENDC}")
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            async with session.get(url, timeout=self.timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    for entry in data:
                        name = entry.get('name_value', '').lower()
                        if '*' in name:
                            continue
                        if self.domain in name:
                            self.results['subdomains'].add(name)
                            self.results['certificates'].append({
                                'subject': entry.get('common_name'),
                                'issuer': entry.get('issuer_name'),
                                'not_before': entry.get('not_before'),
                                'not_after': entry.get('not_after')
                            })
                    print(f"{Colors.OKGREEN}[+] Found {len(self.results['subdomains'])} subdomains from certificates{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] crt.sh search failed: {e}{Colors.ENDC}")

    async def search_bufferover(self, session: aiohttp.ClientSession):
        """Search BufferOver for DNS data"""
        print(f"{Colors.OKBLUE}[*] Searching BufferOver...{Colors.ENDC}")
        url = f"https://dns.bufferover.run/dns?q=.{self.domain}"
        try:
            async with session.get(url, timeout=self.timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('FDNS_A'):
                        for record in data['FDNS_A']:
                            parts = record.split(',')
                            if len(parts) >= 2:
                                subdomain, ip = parts[0], parts[1]
                                if self.domain in subdomain:
                                    self.results['subdomains'].add(subdomain)
                                    self.results['ip_addresses'].add(ip)
                    print(f"{Colors.OKGREEN}[+] BufferOver search completed{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] BufferOver search failed{Colors.ENDC}")

    async def search_hackertarget(self, session: aiohttp.ClientSession):
        """Search HackerTarget for subdomains"""
        print(f"{Colors.OKBLUE}[*] Searching HackerTarget...{Colors.ENDC}")
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            async with session.get(url, timeout=self.timeout) as response:
                text = await response.text()
                if 'error' not in text.lower():
                    for line in text.split('\n'):
                        if ',' in line:
                            subdomain, ip = line.split(',')
                            self.results['subdomains'].add(subdomain)
                            self.results['ip_addresses'].add(ip)
                    print(f"{Colors.OKGREEN}[+] HackerTarget search completed{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] HackerTarget search failed{Colors.ENDC}")

    async def search_threatcrowd(self, session: aiohttp.ClientSession):
        """Search ThreatCrowd"""
        print(f"{Colors.OKBLUE}[*] Searching ThreatCrowd...{Colors.ENDC}")
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
        try:
            async with session.get(url, timeout=self.timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    subdomains = data.get('subdomains', [])
                    self.results['subdomains'].update([s for s in subdomains if self.domain in s])
                    emails = data.get('emails', [])
                    self.results['emails'].update([e for e in emails if self.domain in e])
                    print(f"{Colors.OKGREEN}[+] ThreatCrowd search completed{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] ThreatCrowd search failed{Colors.ENDC}")

    async def search_urlscan(self, session: aiohttp.ClientSession):
        """Search URLScan.io"""
        print(f"{Colors.OKBLUE}[*] Searching URLScan.io...{Colors.ENDC}")
        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=100"
        try:
            async with session.get(url, timeout=self.timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    for result in data.get('results', []):
                        page = result.get('page', {})
                        domain = page.get('domain', '')
                        if self.domain in domain:
                            self.results['subdomains'].add(domain)
                            self.results['urls'].add(page.get('url'))
                            self.results['ip_addresses'].add(page.get('ip', ''))
                    print(f"{Colors.OKGREEN}[+] URLScan.io search completed{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] URLScan.io search failed{Colors.ENDC}")

    async def search_otx(self, session: aiohttp.ClientSession):
        """Search AlienVault OTX"""
        print(f"{Colors.OKBLUE}[*] Searching AlienVault OTX...{Colors.ENDC}")
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        try:
            async with session.get(url, timeout=self.timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    for record in data.get('passive_dns', []):
                        hostname = record.get('hostname', '')
                        if self.domain in hostname:
                            self.results['subdomains'].add(hostname)
                            self.results['ip_addresses'].add(record.get('address', ''))
                    print(f"{Colors.OKGREEN}[+] OTX search completed{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] OTX search failed{Colors.ENDC}")

    def dns_enumeration(self):
        """Perform DNS enumeration"""
        print(f"{Colors.OKBLUE}[*] Performing DNS enumeration...{Colors.ENDC}")
        record_types = ['A', 'AAAA', 'MX', 'NS', 'SOA', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                self.results['dns_records'][record_type] = [str(rdata) for rdata in answers]
                for rdata in answers:
                    if record_type in ['A', 'AAAA']:
                        self.results['ip_addresses'].add(str(rdata))
                    elif record_type == 'MX':
                        self.results['hosts'].add(str(rdata).split()[-1])
                    elif record_type == 'NS':
                        self.results['hosts'].add(str(rdata))
            except Exception as e:
                pass
        
        print(f"{Colors.OKGREEN}[+] DNS enumeration completed{Colors.ENDC}")

    def whois_lookup(self):
        """Perform WHOIS lookup"""
        print(f"{Colors.OKBLUE}[*] Performing WHOIS lookup...{Colors.ENDC}")
        try:
            w = whois.whois(self.domain)
            self.results['whois_info'] = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'org': w.org,
                'address': w.address
            }
            if w.emails:
                if isinstance(w.emails, list):
                    self.results['emails'].update(w.emails)
                else:
                    self.results['emails'].add(w.emails)
            print(f"{Colors.OKGREEN}[+] WHOIS lookup completed{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] WHOIS lookup failed{Colors.ENDC}")

    def reverse_dns(self):
        """Perform reverse DNS lookups"""
        print(f"{Colors.OKBLUE}[*] Performing reverse DNS lookups...{Colors.ENDC}")
        unique_ips = list(self.results['ip_addresses'])[:50]  # Limit to prevent timeout
        
        def lookup_ip(ip):
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                if self.domain in hostname:
                    self.results['subdomains'].add(hostname)
            except:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(lookup_ip, unique_ips)
        
        print(f"{Colors.OKGREEN}[+] Reverse DNS completed{Colors.ENDC}")

    async def search_linkedin(self, session: aiohttp.ClientSession):
        """Search for employees on LinkedIn (via search engines)"""
        print(f"{Colors.OKBLUE}[*] Searching for employees (LinkedIn)...{Colors.ENDC}")
        query = f"site:linkedin.com/in \"{self.domain.split('.')[0]}\""
        
        # Try multiple search engines
        for engine in ['google', 'bing']:
            try:
                if engine == 'google':
                    html = await self.search_google(session, query)
                else:
                    html = await self.search_bing(session, query)
                
                # Extract names (basic pattern)
                soup = BeautifulSoup(html, 'html.parser')
                text = soup.get_text()
                
                # Look for LinkedIn profile patterns
                profiles = re.findall(r'linkedin\.com/in/([a-zA-Z0-9-]+)', text)
                for profile in profiles[:20]:  # Limit results
                    self.results['employees'].add(f"https://linkedin.com/in/{profile}")
            except:
                continue
        
        print(f"{Colors.OKGREEN}[+] Employee search completed{Colors.ENDC}")

    async def search_github(self, session: aiohttp.ClientSession):
        """Search GitHub for exposed information"""
        print(f"{Colors.OKBLUE}[*] Searching GitHub...{Colors.ENDC}")
        queries = [
            f'"{self.domain}" password',
            f'"{self.domain}" api_key',
            f'"{self.domain}" secret',
            f'"{self.domain}" config',
            f'extension:json "{self.domain}"',
            f'extension:yaml "{self.domain}"',
            f'extension:env "{self.domain}"'
        ]
        
        for query in queries[:3]:  # Limit to prevent rate limiting
            try:
                url = f"https://api.github.com/search/code?q={quote(query)}&per_page=10"
                headers = {'Accept': 'application/vnd.github.v3+json'}
                async with session.get(url, headers=headers, timeout=self.timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        for item in data.get('items', []):
                            self.results['urls'].add(item.get('html_url', ''))
            except:
                continue
        
        print(f"{Colors.OKGREEN}[+] GitHub search completed{Colors.ENDC}")

    def shodan_search(self):
        """Search Shodan for exposed services"""
        if not self.shodan_key:
            print(f"{Colors.WARNING}[!] Shodan API key not configured, skipping...{Colors.ENDC}")
            return
        
        print(f"{Colors.OKBLUE}[*] Searching Shodan...{Colors.ENDC}")
        try:
            api = shodan.Shodan(self.shodan_key)
            results = api.search(f'hostname:{self.domain}')
            
            for result in results['matches']:
                self.results['shodan_info'].append({
                    'ip': result['ip_str'],
                    'port': result['port'],
                    'org': result.get('org', 'n/a'),
                    'data': result.get('data', '')[:200],
                    'vulns': result.get('vulns', [])
                })
                self.results['ip_addresses'].add(result['ip_str'])
            print(f"{Colors.OKGREEN}[+] Shodan search completed{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] Shodan search failed: {e}{Colors.ENDC}")

    def resolve_hosts(self):
        """Resolve all discovered subdomains to IP addresses"""
        print(f"{Colors.OKBLUE}[*] Resolving discovered hosts...{Colors.ENDC}")
        
        def resolve_host(hostname):
            try:
                ip = socket.gethostbyname(hostname)
                self.results['ip_addresses'].add(ip)
                self.results['hosts'].add(f"{hostname}:{ip}")
            except:
                pass
        
        hosts = list(self.results['subdomains'])
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(resolve_host, hosts)
        
        print(f"{Colors.OKGREEN}[+] Host resolution completed{Colors.ENDC}")

    async def run_all_searches(self):
        """Execute all search modules"""
        async with aiohttp.ClientSession() as session:
            tasks = [
                self.search_crt_sh(session),
                self.search_bufferover(session),
                self.search_hackertarget(session),
                self.search_threatcrowd(session),
                self.search_urlscan(session),
                self.search_otx(session),
                self.search_linkedin(session),
                self.search_github(session),
            ]
            
            # Run with semaphore to limit concurrent requests
            semaphore = asyncio.Semaphore(5)
            
            async def bounded_task(task):
                async with semaphore:
                    await task
            
            await asyncio.gather(*[bounded_task(t) for t in tasks])

    def generate_report(self):
        """Generate and display final report"""
        print(f"\n{Colors.HEADER}{'='*60}")
        print("RECONNAISSANCE REPORT")
        print(f"{'='*60}{Colors.ENDC}\n")
        
        # Convert sets to sorted lists for display
        report_data = {
            'domain': self.results['domain'],
            'scan_date': self.results['scan_date'],
            'summary': {
                'emails_found': len(self.results['emails']),
                'subdomains_found': len(self.results['subdomains']),
                'ip_addresses': len(self.results['ip_addresses']),
                'urls_found': len(self.results['urls']),
                'employees_found': len(self.results['employees']),
                'technologies': len(self.results['technologies'])
            },
            'emails': sorted(list(self.results['emails'])),
            'subdomains': sorted(list(self.results['subdomains'])),
            'ip_addresses': sorted(list(self.results['ip_addresses'])),
            'hosts': sorted(list(self.results['hosts'])),
            'urls': sorted(list(self.results['urls'])),
            'employees': sorted(list(self.results['employees'])),
            'dns_records': self.results['dns_records'],
            'whois_info': self.results['whois_info'],
            'certificates': self.results['certificates'],
            'shodan_info': self.results['shodan_info']
        }
        
        # Display summary
        print(f"{Colors.BOLD}SUMMARY:{Colors.ENDC}")
        print(f"  Emails: {report_data['summary']['emails_found']}")
        print(f"  Subdomains: {report_data['summary']['subdomains_found']}")
        print(f"  IP Addresses: {report_data['summary']['ip_addresses']}")
        print(f"  URLs: {report_data['summary']['urls_found']}")
        print(f"  Employees: {report_data['summary']['employees_found']}")
        
        # Display emails
        if report_data['emails']:
            print(f"\n{Colors.OKGREEN}[+] EMAILS FOUND:{Colors.ENDC}")
            for email in report_data['emails'][:20]:  # Show first 20
                print(f"  - {email}")
            if len(report_data['emails']) > 20:
                print(f"  ... and {len(report_data['emails']) - 20} more")
        
        # Display subdomains
        if report_data['subdomains']:
            print(f"\n{Colors.OKGREEN}[+] SUBDOMAINS FOUND:{Colors.ENDC}")
            for subdomain in report_data['subdomains'][:30]:
                print(f"  - {subdomain}")
            if len(report_data['subdomains']) > 30:
                print(f"  ... and {len(report_data['subdomains']) - 30} more")
        
        # Display IP addresses
        if report_data['ip_addresses']:
            print(f"\n{Colors.OKGREEN}[+] IP ADDRESSES:{Colors.ENDC}")
            for ip in report_data['ip_addresses'][:20]:
                print(f"  - {ip}")
        
        # Display DNS records
        if report_data['dns_records']:
            print(f"\n{Colors.OKGREEN}[+] DNS RECORDS:{Colors.ENDC}")
            for record_type, records in report_data['dns_records'].items():
                print(f"  {record_type}: {', '.join(records[:5])}")
        
        # Display WHOIS
        if report_data['whois_info']:
            print(f"\n{Colors.OKGREEN}[+] WHOIS INFORMATION:{Colors.ENDC}")
            for key, value in report_data['whois_info'].items():
                if value:
                    print(f"  {key}: {value}")
        
        return report_data

    def save_report(self, filename: str = None):
        """Save report to JSON file"""
        if not filename:
            filename = f"{self.domain}_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Convert sets to lists for JSON serialization
        save_data = {
            'domain': self.results['domain'],
            'scan_date': self.results['scan_date'],
            'emails': list(self.results['emails']),
            'subdomains': list(self.results['subdomains']),
            'hosts': list(self.results['hosts']),
            'ip_addresses': list(self.results['ip_addresses']),
            'urls': list(self.results['urls']),
            'employees': list(self.results['employees']),
            'dns_records': self.results['dns_records'],
            'whois_info': self.results['whois_info'],
            'certificates': self.results['certificates'],
            'shodan_info': self.results['shodan_info']
        }
        
        with open(filename, 'w') as f:
            json.dump(save_data, f, indent=2)
        
        print(f"\n{Colors.OKCYAN}[+] Report saved to: {filename}{Colors.ENDC}")
        return filename

    async def run(self):
        """Main execution flow"""
        self.print_banner()
        
        # Get authorization
        consent = input(f"{Colors.WARNING}Do you have authorization to scan {self.domain}? (yes/no): {Colors.ENDC}")
        if consent.lower() != 'yes':
            print(f"{Colors.FAIL}[-] Scan aborted. Authorization required.{Colors.ENDC}")
            return
        
        print(f"\n{Colors.BOLD}Starting reconnaissance...{Colors.ENDC}\n")
        
        # Run synchronous tasks
        self.dns_enumeration()
        self.whois_lookup()
        
        # Run async searches
        await self.run_all_searches()
        
        # Post-processing
        self.resolve_hosts()
        self.reverse_dns()
        self.shodan_search()
        
        # Generate report
        report = self.generate_report()
        self.save_report()
        
        print(f"\n{Colors.OKGREEN}[+] Reconnaissance completed!{Colors.ENDC}")

def main():
    parser = argparse.ArgumentParser(
        description='Domain OSINT Reconnaissance Tool - theHarvester Alternative',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python domain_recon.py example.com
  python domain_recon.py example.com -l 1000 -t 15
  python domain_recon.py example.com -o custom_report.json
        """
    )
    parser.add_argument('domain', help='Target domain to investigate')
    parser.add_argument('-l', '--limit', type=int, default=500, 
                       help='Limit results per source (default: 500)')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', help='Output JSON filename')
    parser.add_argument('--shodan', help='Shodan API key')
    
    args = parser.parse_args()
    
    # Validate domain
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$', args.domain):
        print(f"{Colors.FAIL}[-] Invalid domain format{Colors.ENDC}")
        sys.exit(1)
    
    recon = DomainRecon(args.domain, args.limit, args.timeout)
    if args.shodan:
        recon.shodan_key = args.shodan
    
    try:
        asyncio.run(recon.run())
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
        recon.save_report(args.output)
    except Exception as e:
        print(f"\n{Colors.FAIL}[-] Error: {e}{Colors.ENDC}")

if __name__ == '__main__':
    main()
