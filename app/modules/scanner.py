import requests
import logging
from typing import Dict, List, Any
from urllib.parse import urljoin, urlparse
import re
from app.modules.learning_engine import LearningEngine

logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    """Basic vulnerability scanning capabilities"""
    
    def __init__(self):
        self.findings = []
        self.learning_engine = LearningEngine()
        
    def scan(self, target: str, scan_type: str = 'basic', recon_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run vulnerability scan on target
        scan_type: basic, web, network
        recon_data: optional reconnaissance data
        """
        logger.info(f"Starting {scan_type} vulnerability scan on {target}")
        
        self.findings = []
        results = {
            'target': target,
            'scan_type': scan_type,
            'findings': []
        }
        
        try:
            if scan_type == 'web' or scan_type == 'basic':
                # Web application scanning
                web_findings = self.web_vulnerability_scan(target)
                results['findings'].extend(web_findings)
                for finding in web_findings:
                    self.learning_engine.record_scan_outcome(
                        finding_id=None, # Will be updated after saving to DB
                        outcome='true_positive',
                        detection_method=finding.get('detection_method', 'unknown'),
                        time_taken=1.0, # Placeholder
                        environment={'target_tech': recon_data.get('technologies', [])[0] if recon_data and recon_data.get('technologies') else None, 'attack_type': 'vulnerability_scan'}
                    )
            
            if scan_type == 'network' or scan_type == 'basic':
                # Network-level checks
                network_findings = self.network_vulnerability_scan(target, recon_data)
                results['findings'].extend(network_findings)
                for finding in network_findings:
                    self.learning_engine.record_scan_outcome(
                        finding_id=None, # Will be updated after saving to DB
                        outcome='true_positive',
                        detection_method=finding.get('detection_method', 'unknown'),
                        time_taken=1.0, # Placeholder
                        environment={'target_tech': recon_data.get('technologies', [])[0] if recon_data and recon_data.get('technologies') else None, 'attack_type': 'vulnerability_scan'}
                    )
            
            logger.info(f"Scan completed. Found {len(results['findings'])} potential issues")
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def web_vulnerability_scan(self, target: str) -> List[Dict[str, Any]]:
        """Scan for common web vulnerabilities"""
        logger.info(f"Running web vulnerability scan on {target}")
        
        findings = []
        
        # Ensure target has protocol
        if not target.startswith('http'):
            target = f"http://{target}"
        
        # Check SSL/TLS
        findings.extend(self.check_ssl_tls(target))
        
        # Check HTTP headers
        findings.extend(self.check_security_headers(target))
        
        # Check for common files/directories
        findings.extend(self.check_common_files(target))
        
        # Check for information disclosure
        findings.extend(self.check_information_disclosure(target))
        
        # Basic XSS test
        findings.extend(self.test_xss_basic(target))

        # Basic SQLi test
        findings.extend(self.test_sql_injection(target))

        # Check for directory listing
        findings.extend(self.check_directory_listing(target))

        # Check for outdated server software
        findings.extend(self.check_outdated_server(target))

        # Basic CSRF test
        findings.extend(self.test_csrf(target))

        # Basic SSRF test
        findings.extend(self.test_ssrf(target))
        
        return findings
    
    def network_vulnerability_scan(self, target: str, recon_data: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Scan for network-level vulnerabilities"""
        logger.info(f"Running network vulnerability scan on {target}")
        
        findings = []
        
        if not recon_data or 'port_scan' not in recon_data or 'open_ports' not in recon_data['port_scan']:
            logger.warning("No port scan data available for network vulnerability scan.")
            return findings

        risky_ports = {
            21: "FTP",
            23: "Telnet",
            5432: "PostgreSQL",
            3306: "MySQL",
            27017: "MongoDB"
        }

        open_ports = recon_data['port_scan']['open_ports']

        for port, service in risky_ports.items():
            if port in open_ports:
                findings.append({
                    'title': f'Potentially Insecure Service Exposed: {service}',
                    'severity': 'medium',
                    'description': f'The {service} port ({port}) is open to the internet. This service can be a target for brute-force attacks or may have known vulnerabilities.',
                    'remediation': f'Ensure that {service} is not exposed to the internet unless necessary. If it must be exposed, use strong credentials and keep the service updated.',
                    'cwe': 'CWE-200'
                })

        return findings
    
    def check_ssl_tls(self, target: str) -> List[Dict[str, Any]]:
        """Check SSL/TLS configuration"""
        findings = []
        
        if not target.startswith('https'):
            # Check if HTTPS is available
            https_target = target.replace('http://', 'https://')
            try:
                response = requests.get(https_target, timeout=5, verify=False)
                if response.status_code < 400:
                    findings.append({
                        'title': 'HTTPS Available but Not Enforced',
                        'severity': 'medium',
                        'description': 'The site is accessible over HTTPS but does not redirect HTTP to HTTPS',
                        'remediation': 'Implement automatic HTTPS redirect and HSTS header',
                        'cwe': 'CWE-319',
                        'detection_method': 'check_ssl_tls'
                    })
            except:
                findings.append({
                    'title': 'HTTPS Not Available',
                    'severity': 'high',
                    'description': 'The site does not support HTTPS encryption',
                    'remediation': 'Implement SSL/TLS certificate and enable HTTPS',
                    'cwe': 'CWE-319',
                    'detection_method': 'check_ssl_tls'
                })
        else:
            # Check certificate validity (simplified)
            try:
                response = requests.get(target, timeout=5, verify=True)
            except requests.exceptions.SSLError:
                findings.append({
                    'title': 'Invalid SSL Certificate',
                    'severity': 'high',
                    'description': 'The SSL certificate is invalid, expired, or self-signed',
                    'remediation': 'Install a valid SSL certificate from a trusted CA',
                    'cwe': 'CWE-295',
                    'detection_method': 'check_ssl_tls'
                })
            except:
                pass
        
        return findings
    
    def check_security_headers(self, target: str) -> List[Dict[str, Any]]:
        """Check for missing security headers"""
        findings = []
        
        try:
            response = requests.get(target, timeout=10, verify=False, allow_redirects=True)
            headers = response.headers
            
            # Define critical security headers
            security_checks = {
                'Strict-Transport-Security': {
                    'severity': 'medium',
                    'description': 'HSTS header is missing, allowing potential downgrade attacks',
                    'remediation': 'Add Strict-Transport-Security header'
                },
                'X-Frame-Options': {
                    'severity': 'medium',
                    'description': 'X-Frame-Options header is missing, site may be vulnerable to clickjacking',
                    'remediation': 'Add X-Frame-Options: DENY or SAMEORIGIN'
                },
                'X-Content-Type-Options': {
                    'severity': 'low',
                    'description': 'X-Content-Type-Options header is missing',
                    'remediation': 'Add X-Content-Type-Options: nosniff'
                },
                'Content-Security-Policy': {
                    'severity': 'medium',
                    'description': 'Content-Security-Policy header is missing',
                    'remediation': 'Implement a Content Security Policy'
                },
                'X-XSS-Protection': {
                    'severity': 'low',
                    'description': 'X-XSS-Protection header is missing',
                    'remediation': 'Add X-XSS-Protection: 1; mode=block'
                }
            }
            
            for header, details in security_checks.items():
                if header not in headers:
                    findings.append({
                        'title': f'Missing Security Header: {header}',
                        'severity': details['severity'],
                        'description': details['description'],
                        'remediation': details['remediation'],
                        'cwe': 'CWE-693',
                        'detection_method': 'check_security_headers'
                    })
            
            # Check for information disclosure in headers
            disclosure_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
            for header in disclosure_headers:
                if header in headers:
                    findings.append({
                        'title': f'Information Disclosure: {header} Header',
                        'severity': 'info',
                        'description': f'Server reveals technology information via {header} header: {headers[header]}',
                        'remediation': f'Remove or obfuscate the {header} header',
                        'cwe': 'CWE-200',
                        'detection_method': 'check_security_headers'
                    })
            
        except Exception as e:
            logger.error(f"Error checking security headers: {str(e)}")
        
        return findings
    
    def check_common_files(self, target: str) -> List[Dict[str, Any]]:
        """Check for exposed sensitive files and directories"""
        findings = []
        
        # Common sensitive files
        sensitive_files = [
            '.git/config',
            '.env',
            'config.php',
            'wp-config.php',
            'web.config',
            '.htaccess',
            'robots.txt',
            'sitemap.xml',
            'phpinfo.php',
            'info.php',
            'backup.sql',
            'dump.sql',
            '.DS_Store',
            'README.md'
        ]
        
        # Common admin paths
        admin_paths = [
            'admin',
            'administrator',
            'wp-admin',
            'phpmyadmin',
            'cpanel',
            'login',
            'admin.php',
            'dashboard'
        ]
        
        logger.info(f"Checking for exposed sensitive files on {target}")
        
        for file in sensitive_files:
            url = urljoin(target, file)
            try:
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    findings.append({
                        'title': f'Exposed Sensitive File: {file}',
                        'severity': 'high' if file in ['.git/config', '.env', 'config.php'] else 'medium',
                        'description': f'Sensitive file {file} is publicly accessible',
                        'url': url,
                        'remediation': 'Remove or restrict access to sensitive files',
                        'cwe': 'CWE-200',
                        'detection_method': 'check_common_files'
                    })
                    logger.warning(f"Found exposed file: {url}")
            except:
                pass
        
        for path in admin_paths:
            url = urljoin(target, path)
            try:
                response = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                if response.status_code in [200, 301, 302]:
                    findings.append({
                        'title': f'Admin Panel Found: {path}',
                        'severity': 'info',
                        'description': f'Admin panel accessible at {path}',
                        'url': url,
                        'remediation': 'Ensure admin panel has strong authentication',
                        'cwe': 'CWE-200',
                        'detection_method': 'check_common_files'
                    })
                    logger.info(f"Found admin panel: {url}")
            except:
                pass
        
        return findings
    
    def check_information_disclosure(self, target: str) -> List[Dict[str, Any]]:
        """Check for information disclosure vulnerabilities"""
        findings = []
        
        try:
            response = requests.get(target, timeout=10, verify=False)
            content = response.text.lower()
            
            # Check for common disclosure patterns
            disclosure_patterns = {
                'mysql': 'MySQL database referenced in page',
                'postgresql': 'PostgreSQL database referenced',
                'mongodb': 'MongoDB referenced',
                'redis': 'Redis cache referenced',
                'aws': 'AWS services referenced',
                'api key': 'Potential API key in HTML',
                'private key': 'Potential private key in HTML',
                'secret': 'Potential secret value in HTML',
                'password': 'Password reference in HTML',
                'token': 'Token reference in HTML'
            }
            
            for pattern, description in disclosure_patterns.items():
                if pattern in content:
                    findings.append({
                        'title': 'Information Disclosure in HTML',
                        'severity': 'low',
                        'description': description,
                        'remediation': 'Remove sensitive information from HTML source',
                        'cwe': 'CWE-200',
                        'detection_method': 'check_information_disclosure'
                    })
            
            # Check for stack traces or error messages
            error_patterns = [
                'stack trace',
                'exception',
                'error in',
                'warning:',
                'fatal error',
                'line [0-9]+ in'
            ]
            
            for pattern in error_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append({
                        'title': 'Error Message Disclosure',
                        'severity': 'medium',
                        'description': 'Application error messages visible to users',
                        'remediation': 'Implement proper error handling and disable debug mode',
                        'cwe': 'CWE-209',
                        'detection_method': 'check_information_disclosure'
                    })
                    break
            
        except Exception as e:
            logger.error(f"Error checking information disclosure: {str(e)}")
        
        return findings
    
    def test_xss_basic(self, target: str) -> List[Dict[str, Any]]:
        """Basic XSS detection (very simplified)"""
        findings = []
        
        # This is a VERY basic test - production scanners are much more sophisticated
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>'
        ]
        
        try:
            # Parse URL to find parameters
            parsed = urlparse(target)
            if '?' in target:
                base_url = target.split('?')[0]
                logger.info(f"Testing for XSS vulnerabilities on {base_url}")
                
                # Test each parameter with payloads
                # This is simplified - real scanners would be much more thorough
                for payload in xss_payloads:
                    test_url = f"{base_url}?test={payload}"
                    try:
                        response = requests.get(test_url, timeout=5, verify=False)
                        if payload in response.text:
                            findings.append({
                                'title': 'Potential XSS Vulnerability',
                                'severity': 'high',
                                'description': 'User input may be reflected without proper sanitization',
                                'url': test_url,
                                'remediation': 'Implement proper input validation and output encoding',
                                'cwe': 'CWE-79',
                                'detection_method': 'test_xss_basic'
                            })
                            break
                    except:
                        pass
        
        except Exception as e:
            logger.error(f"Error testing XSS: {str(e)}")
        
        return findings
    
    def test_sql_injection(self, target: str) -> List[Dict[str, Any]]:
        """Basic SQL injection detection"""
        findings = []
        sql_payloads = ["'", '"', " OR 1=1 --"]
        error_patterns = ["sql syntax", "mysql", "unclosed quotation mark"]

        if '?' in target:
            base_url, query_string = target.split('?', 1)
            params = query_string.split('&')
            for i, param in enumerate(params):
                for payload in sql_payloads:
                    test_params = params[:]
                    test_params[i] = param + payload
                    test_url = f"{base_url}?{'&'.join(test_params)}"
                    try:
                        response = requests.get(test_url, timeout=5, verify=False)
                        for error in error_patterns:
                            if error in response.text.lower():
                                findings.append({
                                    'title': 'Potential SQL Injection',
                                    'severity': 'critical',
                                    'description': f'A potential SQL injection vulnerability was found in parameter {i+1}.',
                                    'url': test_url,
                                    'remediation': 'Use parameterized queries to prevent SQL injection.',
                                    'cwe': 'CWE-89',
                                    'detection_method': 'test_sql_injection'
                                })
                                break
                    except:
                        pass
        return findings

    def check_directory_listing(self, target: str) -> List[Dict[str, Any]]:
        """Check for directory listing vulnerabilities"""
        findings = []
        try:
            response = requests.get(target, timeout=5, verify=False)
            if "index of /" in response.text.lower():
                findings.append({
                    'title': 'Directory Listing Enabled',
                    'severity': 'medium',
                    'description': 'The web server is configured to show a directory listing, which can expose sensitive information.',
                    'url': target,
                    'remediation': 'Disable directory listing on the web server.',
                    'cwe': 'CWE-548',
                    'detection_method': 'check_directory_listing'
                })
        except:
            pass
        return findings

    def check_outdated_server(self, target: str) -> List[Dict[str, Any]]:
        """Check for outdated server software from headers"""
        findings = []
        try:
            response = requests.get(target, timeout=5, verify=False)
            server_header = response.headers.get('Server')
            if server_header:
                # This is a very basic check. A real implementation would use a database of vulnerable versions.
                outdated_versions = {
                    "apache": ["2.2.", "2.0.", "1."],
                    "nginx": ["1.1", "1.0", "0."],
                    "iis": ["7.0", "6.0", "5.0"]
                }
                for server, versions in outdated_versions.items():
                    if server in server_header.lower():
                        for version in versions:
                            if version in server_header:
                                findings.append({
                                    'title': 'Potentially Outdated Server Software',
                                    'severity': 'high',
                                    'description': f'The server is running {server_header}, which may be outdated and have known vulnerabilities.',
                                    'remediation': 'Update the web server software to the latest version.',
                                    'cwe': 'CWE-937',
                                    'detection_method': 'check_outdated_server'
                                })
                                break
        except:
            pass
        return findings

    def test_csrf(self, target: str) -> List[Dict[str, Any]]:
        """Basic CSRF check (check for anti-CSRF tokens in forms)"""
        findings = []
        try:
            response = requests.get(target, timeout=5, verify=False)
            forms = re.findall(r'(<form.*?</form>)', response.text, re.IGNORECASE | re.DOTALL)
            for form in forms:
                if "post" in form.lower() and "csrf" not in form.lower() and "token" not in form.lower():
                    findings.append({
                        'title': 'Potential CSRF Vulnerability',
                        'severity': 'medium',
                        'description': 'A form was found without a clear anti-CSRF token, which could make it vulnerable to Cross-Site Request Forgery.',
                        'remediation': 'Implement anti-CSRF tokens in all state-changing forms.',
                        'cwe': 'CWE-352',
                        'detection_method': 'test_csrf'
                    })
                    break
        except:
            pass
        return findings

    def test_ssrf(self, target: str) -> List[Dict[str, Any]]:
        """Basic SSRF check"""
        findings = []
        # This is a placeholder for a more complex check.
        # A real SSRF check would involve finding parameters that take URLs and trying to access internal services.
        return findings

    def prioritize_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort findings by severity"""
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        return sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'info'), 4))
