## This Code is for educational purposes only. Do not use it for unauthorized scanning or testing. Always obtain explicit permission before testing any system.

import socket
import ssl
import requests # type: ignore
import json
import sys
import argparse
from urllib.parse import urljoin, urlparse
from datetime import datetime
import concurrent.futures
from typing import List, Dict, Optional
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class VulnerabilityScanner:
    def __init__(self, target: str, threads: int = 10, timeout: int = 5):
        self.target = target.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityScanner/1.0 (Authorized Testing)'
        })
        
        # Common sensitive files/paths to check
        self.sensitive_paths = [
            '/.env', '/.git/config', '/.htaccess', '/.htpasswd',
            '/config.php', '/config.json', '/wp-config.php',
            '/phpinfo.php', '/info.php', '/admin/', '/administrator/',
            '/api/', '/backup/', '/db/', '/database/',
            '/.svn/entries', '/.DS_Store', '/robots.txt',
            '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml',
            '/.well-known/security.txt'
        ]
        
        # Common security headers to check
        self.security_headers = {
            'Strict-Transport-Security': 'HSTS missing - vulnerable to MITM',
            'Content-Security-Policy': 'CSP missing - XSS risk increased',
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-Content-Type-Options': 'MIME-sniffing protection missing',
            'X-XSS-Protection': 'XSS filter not enabled (legacy but good practice)',
            'Referrer-Policy': 'Referrer policy not set - privacy risk'
        }

    def log_finding(self, severity: str, category: str, title: str, description: str, 
                   remediation: str, evidence: Optional[str] = None):
        """Record a vulnerability finding"""
        finding = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,  # Critical, High, Medium, Low, Info
            'category': category,
            'title': title,
            'description': description,
            'remediation': remediation,
            'evidence': evidence,
            'url': self.target
        }
        self.findings.append(finding)
        print(f"[{severity}] {category}: {title}")

    def check_ssl_tls(self):
        """Check SSL/TLS configuration and certificate issues"""
        try:
            parsed = urlparse(self.target)
            hostname = parsed.hostname
            port = parsed.port or 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check TLS version
                    if version in ['TLSv1', 'TLSv1.1']:
                        self.log_finding(
                            'High', 'SSL/TLS', f'Outdated TLS Version ({version})',
                            f'Server supports {version} which has known vulnerabilities',
                            'Disable TLS 1.0 and 1.1, enforce TLS 1.2+',
                            f'Negotiated version: {version}'
                        )
                    else:
                        self.log_finding(
                            'Info', 'SSL/TLS', f'TLS Version OK ({version})',
                            'Server uses modern TLS version',
                            'None - maintain current configuration',
                            f'Negotiated version: {version}'
                        )
                    
                    # Check certificate expiration
                    if cert:
                        from datetime import datetime
                        not_after = cert.get('notAfter')
                        if not_after:
                            expire_date = ssl.cert_time_to_seconds(not_after)
                            days_until_expire = (expire_date - datetime.now().timestamp()) / 86400
                            if days_until_expire < 30:
                                self.log_finding(
                                    'High', 'SSL/TLS', 'Certificate Expiring Soon',
                                    f'SSL certificate expires in {int(days_until_expire)} days',
                                    'Renew SSL certificate immediately',
                                    f'Expires: {not_after}'
                                )
                    
                    # Check for weak ciphers
                    if cipher and 'RC4' in str(cipher) or 'DES' in str(cipher):
                        self.log_finding(
                            'High', 'SSL/TLS', 'Weak Cipher Suite',
                            'Server supports weak encryption algorithms',
                            'Disable RC4, DES, and 3DES ciphers',
                            f'Cipher: {cipher}'
                        )
                        
        except Exception as e:
            self.log_finding(
                'Medium', 'SSL/TLS', 'SSL/TLS Connection Error',
                'Could not establish secure connection',
                'Verify SSL certificate configuration',
                str(e)
            )

    def check_security_headers(self):
        """Check for missing security headers"""
        try:
            response = self.session.get(self.target, timeout=self.timeout, verify=False)
            headers = response.headers
            
            for header, description in self.security_headers.items():
                if header not in headers:
                    self.log_finding(
                        'Medium', 'Headers', f'Missing {header}',
                        description,
                        f'Add {header} header to server responses'
                    )
            
            # Check for server information disclosure
            server_header = headers.get('Server', '')
            x_powered_by = headers.get('X-Powered-By', '')
            
            if server_header or x_powered_by:
                self.log_finding(
                    'Low', 'Headers', 'Information Disclosure',
                    'Server reveals technology stack in headers',
                    'Remove or obfuscate Server and X-Powered-By headers',
                    f'Server: {server_header}, X-Powered-By: {x_powered_by}'
                )
                
            # Check for insecure cookies
            if 'Set-Cookie' in headers:
                cookies = headers.get('Set-Cookie', '')
                if 'Secure' not in cookies:
                    self.log_finding(
                        'Medium', 'Cookies', 'Cookie Secure Flag Missing',
                        'Cookies transmitted without Secure flag over HTTPS',
                        'Set Secure flag on all cookies'
                    )
                if 'HttpOnly' not in cookies:
                    self.log_finding(
                        'Medium', 'Cookies', 'Cookie HttpOnly Flag Missing',
                        'Cookies accessible to JavaScript (XSS risk)',
                        'Set HttpOnly flag on session cookies'
                    )
                    
        except Exception as e:
            self.log_finding(
                'Info', 'Headers', 'Header Check Failed',
                'Could not retrieve headers',
                'Verify target accessibility',
                str(e)
            )

    def check_sensitive_files(self, path: str):
        """Check for exposed sensitive files"""
        try:
            url = urljoin(self.target, path)
            response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
            
            if response.status_code == 200:
                content_length = len(response.content)
                if content_length > 0:
                    # Check if it's actually a config file vs a custom 404 page
                    content_type = response.headers.get('Content-Type', '')
                    
                    indicators = ['password', 'secret', 'api_key', 'database', 'config']
                    content_sample = response.text[:1000].lower()
                    
                    if any(ind in content_sample for ind in indicators) or \
                       any(ct in content_type for ct in ['application/json', 'text/plain', 'application/x-httpd-php']):
                        self.log_finding(
                            'Critical' if 'config' in path or '.env' in path else 'High',
                            'Exposure', f'Sensitive File Exposed: {path}',
                            f'Potentially sensitive file accessible at {url}',
                            'Remove or restrict access to configuration files',
                            f'Status: {response.status_code}, Size: {content_length} bytes'
                        )
                        
        except requests.RequestException:
            pass  # Expected for non-existent paths

    def check_http_methods(self):
        """Check for dangerous HTTP methods"""
        try:
            dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'OPTIONS', 'PATCH']
            allowed_methods = []
            
            for method in dangerous_methods:
                try:
                    response = self.session.request(method, self.target, timeout=self.timeout, verify=False)
                    if response.status_code != 405:  # Method Not Allowed
                        allowed_methods.append(method)
                except:
                    pass
            
            if 'TRACE' in allowed_methods:
                self.log_finding(
                    'High', 'HTTP Methods', 'TRACE Method Enabled',
                    'TRACE method allows Cross-Site Tracing (XST) attacks',
                    'Disable TRACE method in web server configuration',
                    'TRACE returned 200 OK'
                )
            
            if 'PUT' in allowed_methods or 'DELETE' in allowed_methods:
                self.log_finding(
                    'High', 'HTTP Methods', 'Dangerous Methods Enabled',
                    f'Server accepts {", ".join([m for m in allowed_methods if m in ["PUT", "DELETE"]])}',
                    'Disable unnecessary HTTP methods',
                    f'Allowed methods: {", ".join(allowed_methods)}'
                )
                
        except Exception as e:
            pass

    def check_cors_policy(self):
        """Check for misconfigured CORS"""
        try:
            # Test with arbitrary origin
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(self.target, headers=headers, timeout=self.timeout, verify=False)
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*':
                self.log_finding(
                    'Medium', 'CORS', 'Permissive CORS Policy',
                    'Access-Control-Allow-Origin set to wildcard (*)',
                    'Restrict CORS to specific trusted domains',
                    'Access-Control-Allow-Origin: *'
                )
            elif acao == 'https://evil.com':
                self.log_finding(
                    'High', 'CORS', 'CORS Reflects Arbitrary Origin',
                    'Server reflects any Origin header, allowing credential theft',
                    'Implement strict origin whitelist',
                    f'Reflected origin: {acao}'
                )
                
            if acac.lower() == 'true' and acao == '*':
                self.log_finding(
                    'Critical', 'CORS', 'CORS with Credentials and Wildcard',
                    'Dangerous combination allowing cross-origin authenticated requests',
                    'Never use Allow-Credentials with wildcard origin',
                    'Access-Control-Allow-Credentials: true with wildcard'
                )
                
        except Exception as e:
            pass

    def check_open_ports(self, ports: List[int] = None):
        """Scan common ports for exposed services"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 8080, 8443]
        
        parsed = urlparse(self.target)
        hostname = parsed.hostname
        
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((hostname, port))
                sock.close()
                if result == 0:
                    return port
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(scan_port, ports)
            open_ports = [p for p in results if p is not None]
        
        for port in open_ports:
            risk = 'High' if port in [21, 23, 3306, 3389, 5432] else 'Medium' if port in [22, 25, 110] else 'Info'
            self.log_finding(
                risk, 'Network', f'Open Port: {port}',
                f'Port {port} is accessible',
                f'Close port {port} if not required or restrict access with firewall',
                f'TCP/{port} open'
            )

    def run_all_checks(self):
        """Execute all vulnerability checks"""
        print(f"\n{'='*60}")
        print(f"Starting Vulnerability Scan")
        print(f"Target: {self.target}")
        print(f"Time: {datetime.now().isoformat()}")
        print(f"{'='*60}\n")
        
        # Information gathering
        print("[*] Checking SSL/TLS configuration...")
        self.check_ssl_tls()
        
        print("[*] Checking security headers...")
        self.check_security_headers()
        
        print("[*] Checking HTTP methods...")
        self.check_http_methods()
        
        print("[*] Checking CORS policy...")
        self.check_cors_policy()
        
        print("[*] Scanning for sensitive files...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.check_sensitive_files, self.sensitive_paths)
        
        print("[*] Scanning common ports...")
        self.check_open_ports()
        
        return self.generate_report()

    def generate_report(self) -> Dict:
        """Generate scan report"""
        report = {
            'scan_info': {
                'target': self.target,
                'timestamp': datetime.now().isoformat(),
                'total_findings': len(self.findings)
            },
            'summary': {
                'Critical': len([f for f in self.findings if f['severity'] == 'Critical']),
                'High': len([f for f in self.findings if f['severity'] == 'High']),
                'Medium': len([f for f in self.findings if f['severity'] == 'Medium']),
                'Low': len([f for f in self.findings if f['severity'] == 'Low']),
                'Info': len([f for f in self.findings if f['severity'] == 'Info'])
            },
            'findings': sorted(self.findings, key=lambda x: ['Critical', 'High', 'Medium', 'Low', 'Info'].index(x['severity']))
        }
        
        # Print summary
        print(f"\n{'='*60}")
        print("SCAN SUMMARY")
        print(f"{'='*60}")
        for severity, count in report['summary'].items():
            if count > 0:
                print(f"{severity}: {count}")
        print(f"{'='*60}")
        
        return report

    def save_report(self, filename: str = None):
        """Save report to JSON file"""
        if filename is None:
            parsed = urlparse(self.target)
            safe_name = parsed.netloc.replace(':', '_')
            filename = f"scan_report_{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = self.generate_report()
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to: {filename}")
        return filename


def main():
    parser = argparse.ArgumentParser(description='Vulnerability Scanner - Authorized Use Only')
    parser.add_argument('target', help='Target URL (e.g., https://example.com)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    
    args = parser.parse_args()
    
    # Validate target
    if not args.target.startswith(('http://', 'https://')):
        print("[-] Error: Target must include http:// or https://")
        sys.exit(1)
    
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║           VULNERABILITY SCANNER v1.0                     ║
    ║     For Authorized Security Testing Only CCCP Sec        ║
    ╚══════════════════════════════════════════════════════════╝
    
    WARNING: Only use this tool on systems you own or have 
    explicit written permission to test. Unauthorized scanning 
    may violate computer fraud laws.
    """)
    
    consent = input("Do you have authorization to scan this target? (yes/no): ")
    if consent.lower() != 'yes':
        print("[-] Scan aborted. Authorization required.")
        sys.exit(0)
    
    scanner = VulnerabilityScanner(args.target, args.threads, args.timeout)
    
    try:
        scanner.run_all_checks()
        scanner.save_report(args.output)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        scanner.save_report(args.output)
    except Exception as e:
        print(f"\n[-] Error during scan: {e}")


if __name__ == '__main__':
    main()
