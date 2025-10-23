import nmap
import dns.resolver
import socket
import requests
from urllib.parse import urlparse
import logging
from typing import Dict, List, Any, Optional
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class ReconEngine:
    """Handles reconnaissance operations"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.dns_resolver = dns.resolver.Resolver()
    
    def run_full_recon(self, target: str) -> Dict[str, Any]:
        """Run complete reconnaissance on a target and return dictionary with all findings"""
        logger.info(f"Starting reconnaissance on {target}")

        results = {
            'target': target,
            'target_type': self._identify_target_type(target), # Corrected typo
            'dns_info': {},
            'port_scan': {},
            'http_info': {},
            'subdomains': [],
            'technologies': []
        }

        try:
            # DNS Enumeration
            if results['target_type'] in ['domain', 'subdomain']:
                results['dns_info'] = self.dns_enumeration(target)
                results['subdomains'] = self.find_subdomains(target)

            # Resolve to IP if needed
            ip_address = self._resolve_to_ip(target)
            if ip_address:
                results['ip_address'] = ip_address

                # Port Scanning
                results['port_scan'] = self.port_scan(ip_address)

            # HTTP Analysis (if it's a web target)
            if results['target_type'] in ['url', 'domain', 'subdomain']:
                results['http_info'] = self.http_analysis(target)
                results['technologies'] = self.detect_technologies(target)

            logger.info(f"Reconnaissance completed for {target}")
        
        except Exception as e:
            logger.error(f"Error during reconnaissance: {e}", exc_info=True) # Improved logging
            results['error'] = str(e)
        
        return results # Ensure results are always returned

    def _identify_target_type(self, target: str) -> str:
        """Identify what type of target this is"""
        if target.startswith('http://') or target.startswith('https://'):
            return 'url'
        
        # Try to parse as IP
        try:
            socket.inet_aton(target)
            return 'ip'
        except socket.error:
            pass

        # Check if it has subdomain
        parts = target.split('.')
        if len(parts) > 2:
            return 'subdomain'
        elif len(parts) == 2:
            return 'domain'
        
        return 'unknown'
    
    def _resolve_to_ip(self, target: str) -> Optional[str]: # Corrected return type
        """Resolve domain/hostname to IP address"""
        try:
            if target.startswith('http'):
                parsed = urlparse(target)
                target = parsed.netloc

            ip = socket.gethostbyname(target)
            logger.info(f"Resolved {target} to {ip}")
            return ip
        except Exception as e:
            logger.warning(f"Could not resolve {target}: {e}", exc_info=True) # Improved logging
            return None
        
    def dns_enumeration(self, domain: str) -> Dict[str, Any]:
        """Perform DNS Enumeration"""
        logger.info(f"Running DNS enumeration on {domain}")

        dns_info = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'TXT': [],
            'SOA': []
        }
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']

        for record_type in record_types:
            try:
                answers = self.dns_resolver.resolve(domain, record_type)
                dns_info[record_type] = [str(rdata) for rdata in answers]
                logger.debug(f"Found {len(answers)} {record_type} records")

            except dns.resolver.NoAnswer: # Specific exception for no records
                logger.debug(f"No {record_type} records found for {domain}")
            except dns.resolver.NXDOMAIN:
                logger.debug(f"Domain {domain} does not exist (NXDOMAIN)")
            except Exception as e:
                logger.debug(f"Error resolving {record_type} records for {domain}: {e}", exc_info=True)

        return dns_info
    
    def find_subdomains(self, domain: str) -> List[Dict[str, str]]: # Changed return type to match content
        """
        Find subdomains using common wordlist
        In production, you'd use tools like subfinder, amass, etc.
        """
        logger.info(f"Searching for subdomains of {domain}")

        # Common subdomain worlist
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'cpanel', 'whm', 'webdisk', 'mysql', 'test', 'dev', 'staging', 'api',
            'portal', 'vpn', 'remote', 'blog', 'shop', 'store'
        ]
        found_subdomains = []

        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                found_subdomains.append({
                    'subdomain': subdomain,
                    'ip': ip
                })
                logger.info(f"Found subdomain: {subdomain} -> {ip}")
            except socket.gaierror: # Catch specific exception for hostname resolution
                logger.debug(f"Subdomain {subdomain} not found.")
            except Exception as e:
                logger.debug(f"Error finding subdomain {subdomain}: {e}", exc_info=True)
        return found_subdomains
    
    def port_scan(self, target: str, ports: str = '1-1000') -> Dict[str, Any]:
        """Perform port scan on target. Default scans top 1000 ports"""
        logger.info(f"Starting port scan on {target}")

        try:
            # Scan with basic options 
            self.nm.scan(target, ports, arguments='-sV -T4') # Corrected argument to -sV

            results = {
                'host': target,
                'state': self.nm[target].state(),
                'open_ports': [],
                'services': {}
            }

            # Extract open ports and services
            if target in self.nm.all_hosts(): # Ensure target was scanned successfully
                for proto in self.nm[target].all_protocols():
                    ports_list = self.nm[target][proto].keys()
                    for port in ports_list:
                        port_info = self.nm[target][proto][port]
                        if port_info['state'] == 'open':
                            results['open_ports'].append(port)
                            results['services'][port] = {
                                'name': port_info.get('name', 'unknown'),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                                'extrainfo': port_info.get('extrainfo', '')
                            }
                            logger.info(f"Open port found: {port}/{proto} - {port_info.get('name')}")
            else:
                logger.warning(f"Nmap did not find host {target} or scan failed.")

            return results

        except nmap.PortScannerError as e:
            logger.error(f"Nmap scan failed for {target}: {e}", exc_info=True)
            return {'error': f"Nmap scan error: {e}"}
        except Exception as e:
            logger.error(f"Port scan failed for {target}: {e}", exc_info=True)
            return {'error': str(e)}
        
    def http_analysis(self, target: str) -> Dict[str, Any]:
        """Analyze HTTP/HTTPS service"""
        logger.info(f"Analyzing HTTP service on {target}")

        # Redundant 'if not target.startswith('http')' check removed as it's handled by caller

        results = {
            'url': target,
            'status_code': None,
            'headers': {},
            'server': None,
            'title': None,
            'security_headers': {},
            'cookies': []
        }

        try:
            response = requests.get(target, timeout=10, allow_redirects=True, verify=False) # Corrected typo
            results['status_code'] = response.status_code
            results['headers'] = dict(response.headers)
            results['server'] = response.headers.get('Server', 'Unknown')

            # Extract title
            if 'text/html' in response.headers.get('Content-Type', ''):
                # BeautifulSoup is already imported at the top
                soup = BeautifulSoup(response.text, 'html.parser')
                if soup.title:
                    results['title'] = soup.title.string

            # Security headers
            security_headers = [
                'Strict-Transport-Security', # Corrected typo
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Content-Security-Policy',
                'X-XSS-Protection'
            ]

            for header in security_headers:
                if header in response.headers:
                    results['security_headers'][header] = response.headers[header]
                else:
                    results['security_headers'][header] = 'Missing'

            # Cookies
            results['cookies'] = [{
                'name': cookie.name,
                'secure': cookie.secure,
                'httponly': cookie.has_nonstandard_attr('HttpOnly')
            } for cookie in response.cookies]

            logger.info(f"HTTP analysis completed for {target}")
        except requests.exceptions.RequestException as e: # Catch specific exception
            logger.error(f"HTTP analysis failed for {target}: {e}", exc_info=True)
            results['error'] = str(e)
        except Exception as e:
            logger.error(f"An unexpected error occurred during HTTP analysis for {target}: {e}", exc_info=True)
            results['error'] = str(e)
        return results
    
    def detect_technologies(self, target: str) -> List[Dict[str, str]]:
        """Detect technologies used by the web application. This is a simplified version. Use Wappalyzer for more comprehensive detection"""
        logger.info(f"Detecting technologies on {target}")
        technologies = []

        try:
            # Redundant 'if not target.startswith('http')' check removed as it's handled by caller
            
            response = requests.get(target, timeout=10, verify=False)
            headers = response.headers
            html = response.text.lower()

            # Check headers for clues
            if 'X-Powered-By' in headers: # Corrected typo
                technologies.append({
                    'name': headers['X-Powered-By'],
                    'category': 'Backend',
                    'confidence': 'high'
                })

            # Simple pattern matching
            patterns = {
                'wordpress': 'Content Management System',
                'jquery': 'JavaScript Library',
                'bootstrap': 'UI Framework',
                'react': 'JavaScript Framework',
                'vue.js': 'JavaScript Framework',
                'angular': 'JavaScript Framework',
                'nginx': 'Web Server',
                'apache': 'Web Server'
            }

            for tech, category in patterns.items(): # Corrected typo
                if tech in html or tech in str(headers).lower():
                    technologies.append({
                        'name': tech.title(),
                        'category': category,
                        'confidence': 'medium'
                    })
            logger.info(f"Detected {len(technologies)} technologies")

        except requests.exceptions.RequestException as e: # Catch specific exception
            logger.error(f"Technology detection failed for {target}: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"An unexpected error occurred during technology detection for {target}: {e}", exc_info=True)
        return technologies