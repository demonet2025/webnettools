"""
SSL Bulk Checker Module
Handles bulk SSL certificate checking for multiple hostnames
"""

import socket
import ssl
import threading
import time
from datetime import datetime
from typing import List, Dict, Any
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class SSLBulkChecker:
    """SSL Bulk Checker for multiple hostnames"""
    
    def __init__(self):
        self.results = []
        self.lock = threading.Lock()
    
    def check_ssl_certificate(self, hostname: str) -> Dict[str, Any]:
        """Check SSL certificate for a single hostname"""
        try:
            # Clean hostname
            hostname = hostname.strip()
            if not hostname:
                return self._create_error_result(hostname, "Empty hostname")
            
            # Remove protocol if present
            if hostname.startswith(('http://', 'https://')):
                parsed = urlparse(hostname)
                hostname = parsed.hostname or hostname
            
            # Don't modify hostnames that already have subdomains
            if '.' in hostname and not any(hostname.startswith(prefix) for prefix in ['www.', 'api.', 'mail.', 'ftp.', 'app.', 'admin.']):
                # Try original hostname first, then with www.
                pass
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
            
            # Parse certificate information using cryptography library
            return self._parse_certificate_info(hostname, der_cert)
            
        except socket.timeout:
            return self._create_error_result(hostname, "Connection timeout")
        except socket.gaierror as e:
            return self._create_error_result(hostname, f"DNS resolution failed: {str(e)}")
        except ssl.SSLError as e:
            return self._create_error_result(hostname, f"SSL error: {str(e)}")
        except Exception as e:
            return self._create_error_result(hostname, f"Error: {str(e)}")
    
    def _parse_certificate_info(self, hostname: str, der_cert: bytes) -> Dict[str, Any]:
        """Parse certificate information using cryptography library"""
        try:
            # Parse DER certificate using cryptography library
            cert_obj = x509.load_der_x509_certificate(der_cert, default_backend())
            
            # Get subject information
            subject = {}
            for attribute in cert_obj.subject:
                subject[attribute.oid._name] = attribute.value
            
            # Get issuer information
            issuer = {}
            for attribute in cert_obj.issuer:
                issuer[attribute.oid._name] = attribute.value
            
            # Calculate days until expiry
            from datetime import timezone
            days_until_expiry = (cert_obj.not_valid_after_utc - datetime.now(timezone.utc)).days
            
            # Get SAN domains
            san_domains = []
            try:
                san_extension = cert_obj.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_extension.value:
                    if isinstance(name, x509.DNSName):
                        san_domains.append(name.value)
            except:
                pass
            
            return {
                'hostname': hostname,
                'status': 'valid',
                'ip_address': self._get_ip_address(hostname),
                'issuer': issuer.get('organizationName', issuer.get('commonName', 'N/A')),
                'expires': cert_obj.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'days_left': days_until_expiry,
                'certificate': {
                    'subject': subject,
                    'issuer': issuer,
                    'not_before': cert_obj.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'not_after': cert_obj.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'days_until_expiry': days_until_expiry,
                    'serial_number': str(cert_obj.serial_number),
                    'signature_algorithm': cert_obj.signature_algorithm_oid._name,
                    'version': cert_obj.version.name,
                    'san_domains': san_domains
                },
                'checked_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
            }
            
        except Exception as e:
            return self._create_error_result(hostname, f"Certificate parsing error: {str(e)}")
    
    def _get_ip_address(self, hostname: str) -> str:
        """Get IP address for hostname"""
        try:
            return socket.gethostbyname(hostname)
        except:
            return 'N/A'
    
    def _create_error_result(self, hostname: str, error_message: str) -> Dict[str, Any]:
        """Create error result"""
        return {
            'hostname': hostname,
            'status': 'error',
            'error': error_message,
            'ip_address': 'N/A',
            'certificate': None,
            'checked_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        }
    
    def check_bulk_ssl(self, hostnames: List[str], max_threads: int = 10) -> Dict[str, Any]:
        """Check SSL certificates for multiple hostnames"""
        # Clean and filter hostnames
        clean_hostnames = []
        for hostname in hostnames:
            hostname = hostname.strip()
            if hostname and hostname not in clean_hostnames:
                clean_hostnames.append(hostname)
        
        if not clean_hostnames:
            return {
                'success': False,
                'error': 'No valid hostnames provided',
                'results': [],
                'summary': {
                    'total': 0,
                    'valid': 0,
                    'errors': 0,
                    'checked_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
                }
            }
        
        # Limit hostnames to prevent abuse
        if len(clean_hostnames) > 50:
            clean_hostnames = clean_hostnames[:50]
        
        self.results = []
        threads = []
        
        # Create thread pool
        for i in range(0, len(clean_hostnames), max_threads):
            batch = clean_hostnames[i:i + max_threads]
            for hostname in batch:
                thread = threading.Thread(target=self._check_single_ssl, args=(hostname,))
                threads.append(thread)
                thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Sort results by hostname
        self.results.sort(key=lambda x: x['hostname'])
        
        # Calculate summary
        valid_count = sum(1 for result in self.results if result['status'] == 'valid')
        error_count = sum(1 for result in self.results if result['status'] == 'error')
        
        return {
            'success': True,
            'results': self.results,
            'summary': {
                'total': len(self.results),
                'valid': valid_count,
                'errors': error_count,
                'checked_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
            }
        }
    
    def _check_single_ssl(self, hostname: str):
        """Check SSL for a single hostname (thread-safe)"""
        result = self.check_ssl_certificate(hostname)
        with self.lock:
            self.results.append(result)
    
    @staticmethod
    def parse_hostnames_input(input_text: str) -> List[str]:
        """Parse hostnames from input text (comma or newline separated)"""
        if not input_text:
            return []
        
        # Split by both comma and newline
        hostnames = []
        for line in input_text.split('\n'):
            for hostname in line.split(','):
                hostname = hostname.strip()
                if hostname:
                    hostnames.append(hostname)
        
        return hostnames
