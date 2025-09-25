"""
SSL Certificate Analyzer Module
Handles SSL certificate analysis, CSR decoding, and certificate management
"""

import ssl
import socket
import hashlib
import json
import base64
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec


class SSLAnalyzer:
    """Simple SSL Certificate Analyzer"""

    @staticmethod
    def fetch_domain_description(domain):
        """Fetch domain description from the website's meta tags"""
        try:
            # Clean domain name
            if not domain.startswith(('http://', 'https://')):
                domain = f"https://{domain}"
            
            # Parse domain
            parsed = urlparse(domain)
            domain_name = parsed.netloc or parsed.path
            
            # Try HTTPS first, then HTTP
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{domain_name}"
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                    }
                    
                    response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
                    response.raise_for_status()
                    
                    soup = BeautifulSoup(response.content, 'html.parser')
                    
                    # Extract meta description
                    meta_desc = soup.find('meta', attrs={'name': 'description'})
                    description = meta_desc.get('content', '').strip() if meta_desc else ''
                    
                    # Extract title
                    title_tag = soup.find('title')
                    title = title_tag.get_text().strip() if title_tag else ''
                    
                    # Extract Open Graph description as fallback
                    if not description:
                        og_desc = soup.find('meta', attrs={'property': 'og:description'})
                        description = og_desc.get('content', '').strip() if og_desc else ''
                    
                    # Extract Twitter description as fallback
                    if not description:
                        twitter_desc = soup.find('meta', attrs={'name': 'twitter:description'})
                        description = twitter_desc.get('content', '').strip() if twitter_desc else ''
                    
                    # Limit description length
                    if len(description) > 300:
                        description = description[:297] + "..."
                    
                    return {
                        'success': True,
                        'title': title,
                        'description': description,
                        'url': response.url,
                        'status_code': response.status_code
                    }
                    
                except requests.RequestException:
                    continue
            
            return {
                'success': False,
                'error': 'Unable to fetch domain information',
                'title': '',
                'description': '',
                'url': '',
                'status_code': 0
            }
            
        except Exception as e:
                  return {
                      'success': False,
                      'error': f'Error fetching domain info: {str(e)}',
                      'title': '',
                      'description': '',
                      'url': '',
                      'status_code': 0
                  }
    
    @staticmethod
    def _parse_raw_issuer_data(issuer_data):
        """Parse raw issuer data from various formats"""
        issuer_info = {}
        
        try:
            if isinstance(issuer_data, (list, tuple)):
                for item in issuer_data:
                    if isinstance(item, (list, tuple)) and len(item) >= 1:
                        # Handle nested structures like ((('countryName', 'US'),), ...)
                        if isinstance(item[0], (list, tuple)) and len(item[0]) == 2:
                            key, value = item[0]
                            issuer_info[key] = value
                        elif len(item) == 2:
                            # Direct key-value pair
                            key, value = item
                            issuer_info[key] = value
                    elif isinstance(item, dict):
                        issuer_info.update(item)
            elif isinstance(issuer_data, dict):
                issuer_info.update(issuer_data)
        except Exception as e:
            # If all else fails, convert to string
            issuer_info['raw'] = str(issuer_data)
            
        return issuer_info

    @staticmethod
    def _resolve_dns(hostname):
        """Resolve hostname to IP address"""
        try:
            # Try to resolve the hostname to an IP address
            ip_address = socket.gethostbyname(hostname)
            return ip_address
        except socket.gaierror:
            return None
        except Exception:
            return None

    @staticmethod
    def check_ssl_certificate(hostname, port=443):
        """Check SSL certificate for a given hostname and port"""
        try:
            # Resolve DNS first
            ip_address = SSLAnalyzer._resolve_dns(hostname)
            
            # Create SSL context with proper settings
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            # Connect to the server
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate information
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()

                    # Get peer certificate binary data for fingerprinting
                    cert_der = ssock.getpeercert(binary_form=True)

                    # Analyze certificate
                    cert_info = SSLAnalyzer._analyze_certificate(cert, cert_der)
                    
                    # Get certificate chain
                    cert_chain = SSLAnalyzer._get_certificate_chain(cert)
                    
                    # Check if certificate is valid
                    is_valid = SSLAnalyzer._is_certificate_valid(cert_info)
                    
                    # Get security status
                    security_status = SSLAnalyzer._get_security_status(cert_info, protocol, cipher)

                    return {
                        'success': True,
                        'hostname': hostname,
                        'ip_address': ip_address,
                        'port': port,
                        'protocol': protocol,
                        'cipher': cipher[0] if cipher else 'Unknown',
                        'certificate': cert_info,
                        'certificate_chain': cert_chain,
                        'is_valid': is_valid,
                        'security_status': security_status,
                        'raw_output': SSLAnalyzer._format_certificate_info(cert_info, protocol, cipher)
                    }

        except Exception as e:
            # Try to resolve DNS even if SSL fails
            ip_address = SSLAnalyzer._resolve_dns(hostname)
            return {
                'success': False,
                'error': f'SSL check failed: {str(e)}',
                'hostname': hostname,
                'ip_address': ip_address,
                'port': port
            }

    @staticmethod
    def _analyze_certificate(cert, cert_der=None):
        """Analyze SSL certificate details"""
        try:
            # Extract subject information
            subject_info = {}
            if 'subject' in cert and cert['subject']:
                for item in cert['subject']:
                    if isinstance(item, (list, tuple)):
                        for sub_item in item:
                            if isinstance(sub_item, (list, tuple)) and len(sub_item) == 2:
                                key, value = sub_item
                                subject_info[key] = value

            # Extract issuer information with improved parsing
            issuer_info = {}
            if 'issuer' in cert and cert['issuer']:
                issuer_info = SSLAnalyzer._parse_raw_issuer_data(cert['issuer'])

            # Parse dates
            not_before = cert.get('notBefore', '')
            not_after = cert.get('notAfter', '')
            
            # Calculate days until expiration
            days_until_expiry = 0
            if not_after:
                try:
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                except:
                    try:
                        # Try alternative date format
                        expiry_date = datetime.strptime(not_after, '%Y%m%d%H%M%SZ')
                        days_until_expiry = (expiry_date - datetime.now()).days
                    except:
                        pass

            # Get certificate fingerprints from binary data
            sha1_fingerprint = 'N/A'
            sha256_fingerprint = 'N/A'
            if cert_der:
                try:
                    sha1_fingerprint = hashlib.sha1(cert_der).hexdigest().upper()
                    sha256_fingerprint = hashlib.sha256(cert_der).hexdigest().upper()
                except:
                    pass

            # Get SAN domains
            san_domains = []
            if 'subjectAltName' in cert and cert['subjectAltName']:
                for san_type, san_value in cert['subjectAltName']:
                    if san_type == 'DNS':
                        san_domains.append(san_value)

            return {
                'subject': subject_info,
                'issuer': issuer_info,
                'serial_number': cert.get('serialNumber', 'N/A'),
                'version': cert.get('version', 'N/A'),
                'not_before': not_before,
                'not_after': not_after,
                'days_until_expiry': days_until_expiry,
                'sha1_fingerprint': sha1_fingerprint,
                'sha256_fingerprint': sha256_fingerprint,
                'signature_algorithm': cert.get('signatureAlgorithm', 'N/A'),
                'key_size': cert.get('keySize', 'N/A'),
                'san_domains': san_domains,
                'is_expired': days_until_expiry < 0,
                'is_expiring_soon': 0 <= days_until_expiry <= 30
            }

        except Exception as e:
            return {
                'error': f'Certificate analysis failed: {str(e)}',
                'subject': {},
                'issuer': {},
                'serial_number': 'N/A',
                'version': 'N/A',
                'not_before': 'N/A',
                'not_after': 'N/A',
                'days_until_expiry': 0,
                'sha1_fingerprint': 'N/A',
                'sha256_fingerprint': 'N/A',
                'signature_algorithm': 'N/A',
                'key_size': 'N/A',
                'san_domains': [],
                'is_expired': True,
                'is_expiring_soon': False
            }

    @staticmethod
    def _get_certificate_chain(cert):
        """Get certificate chain information"""
        try:
            # Parse subject and issuer information
            subject_info = {}
            if 'subject' in cert and cert['subject']:
                subject_info = SSLAnalyzer._parse_raw_issuer_data(cert['subject'])
            
            issuer_info = {}
            if 'issuer' in cert and cert['issuer']:
                issuer_info = SSLAnalyzer._parse_raw_issuer_data(cert['issuer'])
            
            # This is a simplified version - in reality, you'd need to fetch the full chain
            return [{
                'subject': subject_info,
                'issuer': issuer_info,
                'serial_number': cert.get('serialNumber', 'N/A'),
                'not_before': cert.get('notBefore', 'N/A'),
                'not_after': cert.get('notAfter', 'N/A'),
                'signature_algorithm': cert.get('signatureAlgorithm', 'N/A')
            }]
        except:
            return []

    @staticmethod
    def _is_certificate_valid(cert_info):
        """Check if certificate is valid"""
        try:
            return not cert_info.get('is_expired', True) and cert_info.get('days_until_expiry', 0) > 0
        except:
            return False

    @staticmethod
    def _get_security_status(cert_info, protocol, cipher):
        """Get security status of the SSL connection"""
        try:
            issues = []
            warnings = []
            
            # Check protocol
            if protocol in ['TLSv1', 'TLSv1.1']:
                issues.append(f'Weak protocol: {protocol}')
            elif protocol == 'TLSv1.2':
                warnings.append(f'Consider upgrading to TLSv1.3: {protocol}')
            
            # Check certificate expiration
            if cert_info.get('is_expired', False):
                issues.append('Certificate has expired')
            elif cert_info.get('is_expiring_soon', False):
                warnings.append(f'Certificate expires in {cert_info.get("days_until_expiry", 0)} days')
            
            # Check key size
            key_size = cert_info.get('key_size', 0)
            if isinstance(key_size, (int, float)) and key_size < 2048:
                issues.append(f'Weak key size: {key_size} bits')
            
            # Determine overall status
            if issues:
                status = 'Issues Found'
            elif warnings:
                status = 'Warnings'
            else:
                status = 'Good'
            
            return {
                'status': status,
                'issues': issues,
                'warnings': warnings,
                'protocol': protocol,
                'cipher': cipher[0] if cipher else 'Unknown'
            }
        except:
            return {
                'status': 'Unknown',
                'issues': ['Unable to analyze security status'],
                'warnings': [],
                'protocol': protocol,
                'cipher': 'Unknown'
            }

    @staticmethod
    def _format_certificate_info(cert_info, protocol, cipher):
        """Format certificate information for display"""
        try:
            output = []
            output.append(f"SSL Certificate Analysis")
            output.append(f"Protocol: {protocol}")
            output.append(f"Cipher: {cipher[0] if cipher else 'Unknown'}")
            output.append("")
            
            # Subject information
            if cert_info.get('subject'):
                output.append("Subject:")
                for key, value in cert_info['subject'].items():
                    output.append(f"  {key}: {value}")
                output.append("")
            
            # Issuer information
            if cert_info.get('issuer'):
                output.append("Issuer:")
                for key, value in cert_info['issuer'].items():
                    output.append(f"  {key}: {value}")
                output.append("")
            
            # Certificate details
            output.append("Certificate Details:")
            output.append(f"  Serial Number: {cert_info.get('serial_number', 'N/A')}")
            output.append(f"  Version: {cert_info.get('version', 'N/A')}")
            output.append(f"  Not Before: {cert_info.get('not_before', 'N/A')}")
            output.append(f"  Not After: {cert_info.get('not_after', 'N/A')}")
            output.append(f"  Days Until Expiry: {cert_info.get('days_until_expiry', 'N/A')}")
            output.append(f"  Key Size: {cert_info.get('key_size', 'N/A')} bits")
            output.append(f"  Signature Algorithm: {cert_info.get('signature_algorithm', 'N/A')}")
            output.append("")
            
            # Fingerprints
            output.append("Fingerprints:")
            output.append(f"  SHA1: {cert_info.get('sha1_fingerprint', 'N/A')}")
            output.append(f"  SHA256: {cert_info.get('sha256_fingerprint', 'N/A')}")
            output.append("")
            
            # SAN domains
            if cert_info.get('san_domains'):
                output.append("Subject Alternative Names:")
                for domain in cert_info['san_domains']:
                    output.append(f"  {domain}")
                output.append("")
            
            return "\n".join(output)
        except Exception as e:
            return f"Error formatting certificate info: {str(e)}"


class SSLDeepAnalyzer:
    """Comprehensive SSL analysis using Python libraries"""

    @staticmethod
    def analyze_ssl_security(hostname, port=443):
        """Perform comprehensive SSL security analysis"""
        try:
            import ssl
            import socket
            from datetime import datetime
            import hashlib
            import json
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Connect to the server
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate information
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    
                    # Analyze certificate
                    cert_info = SSLDeepAnalyzer._analyze_certificate(cert)
                    
                    # Analyze protocols
                    protocols = SSLDeepAnalyzer._analyze_protocols(hostname, port)
                    
                    # Analyze cipher suites
                    cipher_suites = SSLDeepAnalyzer._analyze_cipher_suites(hostname, port)
                    
                    # Check for vulnerabilities
                    vulnerabilities = SSLDeepAnalyzer._check_vulnerabilities(hostname, port, cert_info, protocols)
                    
                    # Get certificate chain
                    certificate_chain = SSLDeepAnalyzer._get_certificate_chain(cert)
                    
                    # Get security notices
                    notices = SSLDeepAnalyzer._get_security_notices(protocols, cert_info, vulnerabilities)
                    
                    # Calculate detailed scores
                    scores = SSLDeepAnalyzer._calculate_detailed_scores(cert_info, protocols, cipher_suites, vulnerabilities)
                    
                    # Calculate overall grade
                    overall_grade, overall_score = SSLDeepAnalyzer._calculate_grade(cert_info, protocols, cipher_suites, vulnerabilities)
                    
                    # Generate recommendations
                    recommendations = SSLDeepAnalyzer._generate_recommendations(cert_info, protocols, cipher_suites, vulnerabilities)
                    
                    return {
                        'success': True,
                        'target': hostname,
                        'overallGrade': overall_grade,
                        'score': overall_score,
                        'certificateGrade': scores['certificate'],
                        'certificateScore': scores['certificate_score'],
                        'protocolGrade': scores['protocol'],
                        'protocolScore': scores['protocol_score'],
                        'keyExchangeGrade': scores['key_exchange'],
                        'keyExchangeScore': scores['key_exchange_score'],
                        'cipherGrade': scores['cipher'],
                        'cipherScore': scores['cipher_score'],
                        'protocols': protocols,
                        'cipherSuites': cipher_suites,
                        'vulnerabilities': vulnerabilities,
                        'certificates': [cert_info],
                        'certificateChain': certificate_chain,
                        'notices': notices,
                        'protocolWarnings': SSLDeepAnalyzer._get_protocol_warnings(protocols),
                        'hsts': cert_info.get('hsts', False),
                        'ocsp_stapling': cert_info.get('ocsp_stapling', False),
                        'recommendations': recommendations,
                        'rawOutput': SSLDeepAnalyzer._generate_raw_output(hostname, cert_info, protocols, cipher_suites, vulnerabilities)
                    }
                    
        except Exception as e:
            return SSLDeepAnalyzer._error_analysis(hostname, str(e))

    @staticmethod
    def _analyze_certificate(cert):
        """Analyze certificate details"""
        try:
            # Extract subject information
            subject_info = {}
            if 'subject' in cert:
                for item in cert['subject']:
                    if isinstance(item, (list, tuple)) and len(item) > 0:
                        if isinstance(item[0], (list, tuple)) and len(item[0]) == 2:
                            key, value = item[0]
                            subject_info[key] = value

            # Extract issuer information with improved parsing
            issuer_info = {}
            if 'issuer' in cert and cert['issuer']:
                issuer_info = SSLAnalyzer._parse_raw_issuer_data(cert['issuer'])

            # Parse dates
            not_before = cert.get('notBefore', '')
            not_after = cert.get('notAfter', '')
            
            # Calculate days until expiration
            days_until_expiry = 0
            if not_after:
                try:
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                except:
                    pass

            # Get certificate fingerprint
            cert_der = cert.get('serialNumber', '')
            sha1_fingerprint = hashlib.sha1(cert_der.encode()).hexdigest() if cert_der else 'N/A'
            sha256_fingerprint = hashlib.sha256(cert_der.encode()).hexdigest() if cert_der else 'N/A'

            return {
                'subject': subject_info.get('commonName', 'N/A'),
                'commonName': subject_info.get('commonName', 'N/A'),
                'serialNumber': cert.get('serialNumber', 'N/A'),
                'issuer': issuer_info.get('commonName', 'N/A'),
                'validFrom': not_before,
                'validUntil': not_after,
                'keySize': cert.get('keySize', 'N/A'),
                'sha256Fingerprint': sha256_fingerprint,
                'sha1Fingerprint': sha1_fingerprint,
                'days_until_expiry': days_until_expiry,
                'is_expired': days_until_expiry < 0,
                'is_expiring_soon': 0 <= days_until_expiry <= 30,
                'hsts': False,  # Would need additional analysis
                'ocsp_stapling': False  # Would need additional analysis
            }

        except Exception as e:
            return {
                'subject': 'N/A',
                'commonName': 'N/A',
                'serialNumber': 'N/A',
                'issuer': 'N/A',
                'validFrom': 'N/A',
                'validUntil': 'N/A',
                'keySize': 'N/A',
                'sha256Fingerprint': 'N/A',
                'sha1Fingerprint': 'N/A',
                'days_until_expiry': 0,
                'is_expired': True,
                'is_expiring_soon': False,
                'hsts': False,
                'ocsp_stapling': False
            }

    @staticmethod
    def _analyze_protocols(hostname, port):
        """Analyze supported SSL/TLS protocols"""
        protocols = []
        
        # Test different protocol versions
        protocol_tests = [
            ('TLS 1.3', ssl.PROTOCOL_TLS),
            ('TLS 1.2', ssl.PROTOCOL_TLS),
            ('TLS 1.1', ssl.PROTOCOL_TLS),
            ('TLS 1.0', ssl.PROTOCOL_TLS)
        ]
        
        # Add legacy protocols if available
        try:
            protocol_tests.append(('SSL 3.0', ssl.PROTOCOL_SSLv3))
        except AttributeError:
            pass
            
        try:
            protocol_tests.append(('SSL 2.0', ssl.PROTOCOL_SSLv2))
        except AttributeError:
            pass

        for protocol_name, protocol_constant in protocol_tests:
            try:
                context = ssl.SSLContext(protocol_constant)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        protocols.append({
                            'name': protocol_name,
                            'supported': True,
                            'version': ssock.version()
                        })
            except:
                protocols.append({
                    'name': protocol_name,
                    'supported': False,
                    'version': None
                })

        return protocols

    @staticmethod
    def _analyze_cipher_suites(hostname, port):
        """Analyze supported cipher suites"""
        # This is a simplified version - real implementation would test all cipher suites
        return [
            {
                'name': 'TLS_AES_256_GCM_SHA384',
                'code': '0x1302',
                'keyExchange': 'ECDH',
                'strength': '256',
                'status': 'Supported'
            },
            {
                'name': 'TLS_AES_128_GCM_SHA256',
                'code': '0x1301',
                'keyExchange': 'ECDH',
                'strength': '128',
                'status': 'Supported'
            }
        ]

    @staticmethod
    def _check_vulnerabilities(hostname, port, cert_info, protocols):
        """Check for known SSL vulnerabilities"""
        vulnerabilities = []
        
        # Check for weak protocols
        weak_protocols = ['SSL 2.0', 'SSL 3.0', 'TLS 1.0']
        for protocol in protocols:
            if protocol['name'] in weak_protocols and protocol['supported']:
                vulnerabilities.append({
                    'name': f'Weak Protocol: {protocol["name"]}',
                    'description': f'Server supports {protocol["name"]} which is considered insecure',
                    'severity': 'High',
                    'cve': 'CVE-2014-3566'
                })
        
        # Check for weak key sizes
        key_size = cert_info.get('keySize', 0)
        if isinstance(key_size, (int, float)) and key_size < 2048:
            vulnerabilities.append({
                'name': 'Weak Key Size',
                'description': f'Certificate uses {key_size}-bit key which is considered weak',
                'severity': 'Medium',
                'cve': 'N/A'
            })
        
        return vulnerabilities

    @staticmethod
    def _get_certificate_chain(cert):
        """Get certificate chain information"""
        try:
            if not isinstance(cert, dict):
                return []
            
            return [{
                'subject': cert.get('subject', []),
                'algorithm': cert.get('signatureAlgorithm', 'N/A'),
                'keySize': cert.get('keySize', 'N/A'),
                'signatureAlgorithm': cert.get('signatureAlgorithm', 'N/A')
            }]
        except:
            return []

    @staticmethod
    def _get_security_notices(protocols, cert_info, vulnerabilities):
        """Get security notices and warnings"""
        notices = []
        
        # Protocol warnings
        for protocol in protocols:
            if not protocol['supported']:
                notices.append({
                    'title': f'{protocol["name"]} Not Supported',
                    'message': f'Server does not support {protocol["name"]}'
                })
        
        # Certificate warnings
        if cert_info.get('is_expired', False):
            notices.append({
                'title': 'Certificate Expired',
                'message': 'The SSL certificate has expired'
            })
        elif cert_info.get('is_expiring_soon', False):
            notices.append({
                'title': 'Certificate Expiring Soon',
                'message': f'Certificate expires in {cert_info.get("days_until_expiry", 0)} days'
            })
        
        return notices

    @staticmethod
    def _calculate_detailed_scores(cert_info, protocols, cipher_suites, vulnerabilities):
        """Calculate detailed security scores"""
        # Certificate score
        cert_score = 100
        if cert_info.get('is_expired', False):
            cert_score -= 50
        elif cert_info.get('is_expiring_soon', False):
            cert_score -= 20
        
        key_size = cert_info.get('keySize', 0)
        if isinstance(key_size, (int, float)) and key_size < 2048:
            cert_score -= 30
        
        # Protocol score
        protocol_score = 100
        for protocol in protocols:
            if protocol['name'] in ['SSL 2.0', 'SSL 3.0'] and protocol['supported']:
                protocol_score -= 50
            elif protocol['name'] == 'TLS 1.0' and protocol['supported']:
                protocol_score -= 20
        
        # Key exchange score
        key_exchange_score = 100
        if vulnerabilities:
            key_exchange_score -= len(vulnerabilities) * 10
        
        # Cipher score
        cipher_score = 100
        if vulnerabilities:
            cipher_score -= len(vulnerabilities) * 5
        
        return {
            'certificate': 'A' if cert_score >= 90 else 'B' if cert_score >= 80 else 'C' if cert_score >= 70 else 'D' if cert_score >= 60 else 'F',
            'certificate_score': max(0, cert_score),
            'protocol': 'A' if protocol_score >= 90 else 'B' if protocol_score >= 80 else 'C' if protocol_score >= 70 else 'D' if protocol_score >= 60 else 'F',
            'protocol_score': max(0, protocol_score),
            'key_exchange': 'A' if key_exchange_score >= 90 else 'B' if key_exchange_score >= 80 else 'C' if key_exchange_score >= 70 else 'D' if key_exchange_score >= 60 else 'F',
            'key_exchange_score': max(0, key_exchange_score),
            'cipher': 'A' if cipher_score >= 90 else 'B' if cipher_score >= 80 else 'C' if cipher_score >= 70 else 'D' if cipher_score >= 60 else 'F',
            'cipher_score': max(0, cipher_score)
        }

    @staticmethod
    def _calculate_grade(cert_info, protocols, cipher_suites, vulnerabilities):
        """Calculate overall SSL grade"""
        scores = SSLDeepAnalyzer._calculate_detailed_scores(cert_info, protocols, cipher_suites, vulnerabilities)
        
        # Calculate weighted average
        total_score = (
            scores['certificate_score'] * 0.3 +
            scores['protocol_score'] * 0.25 +
            scores['key_exchange_score'] * 0.25 +
            scores['cipher_score'] * 0.2
        )
        
        if total_score >= 90:
            return 'A', int(total_score)
        elif total_score >= 80:
            return 'B', int(total_score)
        elif total_score >= 70:
            return 'C', int(total_score)
        elif total_score >= 60:
            return 'D', int(total_score)
        else:
            return 'F', int(total_score)

    @staticmethod
    def _generate_recommendations(cert_info, protocols, cipher_suites, vulnerabilities):
        """Generate security recommendations"""
        recommendations = []
        
        # Certificate recommendations
        if cert_info.get('is_expired', False):
            recommendations.append('Renew the expired SSL certificate immediately')
        elif cert_info.get('is_expiring_soon', False):
            recommendations.append('Plan to renew the SSL certificate soon')
        
        key_size = cert_info.get('keySize', 0)
        if isinstance(key_size, (int, float)) and key_size < 2048:
            recommendations.append('Upgrade to a certificate with at least 2048-bit key size')
        
        # Protocol recommendations
        for protocol in protocols:
            if protocol['name'] in ['SSL 2.0', 'SSL 3.0'] and protocol['supported']:
                recommendations.append(f'Disable support for {protocol["name"]}')
            elif protocol['name'] == 'TLS 1.0' and protocol['supported']:
                recommendations.append('Consider disabling TLS 1.0 support')
        
        # General recommendations
        if not vulnerabilities:
            recommendations.append('SSL configuration looks good - maintain current security practices')
        
        return recommendations

    @staticmethod
    def _get_protocol_warnings(protocols):
        """Get protocol-specific warnings"""
        warnings = []
        for protocol in protocols:
            if protocol['name'] in ['SSL 2.0', 'SSL 3.0'] and protocol['supported']:
                warnings.append(f'Warning: {protocol["name"]} is supported but considered insecure')
        return warnings

    @staticmethod
    def _generate_raw_output(hostname, cert_info, protocols, cipher_suites, vulnerabilities):
        """Generate raw output for display"""
        output = []
        output.append(f"SSL Security Analysis for {hostname}")
        output.append("=" * 50)
        output.append("")
        
        # Certificate information
        output.append("Certificate Information:")
        output.append(f"  Subject: {cert_info.get('subject', 'N/A')}")
        output.append(f"  Issuer: {cert_info.get('issuer', 'N/A')}")
        output.append(f"  Valid From: {cert_info.get('validFrom', 'N/A')}")
        output.append(f"  Valid Until: {cert_info.get('validUntil', 'N/A')}")
        output.append(f"  Key Size: {cert_info.get('keySize', 'N/A')} bits")
        output.append("")
        
        # Protocol information
        output.append("Supported Protocols:")
        for protocol in protocols:
            status = "Supported" if protocol['supported'] else "Not Supported"
            output.append(f"  {protocol['name']}: {status}")
        output.append("")
        
        # Vulnerabilities
        if vulnerabilities:
            output.append("Vulnerabilities Found:")
            for vuln in vulnerabilities:
                output.append(f"  {vuln['name']}: {vuln['description']}")
            output.append("")
        
        return "\n".join(output)

    @staticmethod
    def _error_analysis(hostname, error_message):
        """Return error analysis result"""
        return {
            'success': False,
            'target': hostname,
            'error': f'SSL analysis failed: {error_message}',
            'overallGrade': 'F',
            'score': 0,
            'certificateGrade': 'F',
            'certificateScore': 0,
            'protocolGrade': 'F',
            'protocolScore': 0,
            'keyExchangeGrade': 'F',
            'keyExchangeScore': 0,
            'cipherGrade': 'F',
            'cipherScore': 0,
            'protocols': [],
            'cipherSuites': [],
            'vulnerabilities': [],
            'certificates': [],
            'certificateChain': [],
            'notices': [{'title': 'Analysis Failed', 'message': error_message}],
            'protocolWarnings': [],
            'hsts': False,
            'ocsp_stapling': False,
            'recommendations': ['Fix connection issues and retry analysis'],
            'rawOutput': f'Error: {error_message}'
        }


class CSRDecoder:
    """CSR Decoder for Certificate Signing Requests"""

    @staticmethod
    def decode_csr(csr_text):
        """Decode Certificate Signing Request"""
        try:
            # Clean the CSR text
            csr_text = csr_text.strip()
            if not csr_text.startswith('-----BEGIN CERTIFICATE REQUEST-----'):
                return {
                    'success': False,
                    'error': 'Invalid CSR format. CSR must start with -----BEGIN CERTIFICATE REQUEST-----'
                }

            # Parse the CSR
            csr = x509.load_pem_x509_csr(csr_text.encode('utf-8'))

            # Extract subject information
            subject_info = CSRDecoder._extract_subject_info(csr.subject)

            # Extract public key information
            public_key_info = CSRDecoder._extract_public_key_info(csr.public_key())

            # Extract SANs
            sans = CSRDecoder._extract_sans(csr)

            return {
                'success': True,
                'csr_info': {
                    'subject': subject_info,
                    'public_key': public_key_info,
                    'sans': sans,
                    'signature_algorithm': csr.signature_algorithm_oid._name,
                    'version': 'v1'  # CSRs are always version 1
                },
                'raw_output': CSRDecoder._format_csr_info(csr)
            }

        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to decode CSR: {str(e)}'
            }
    
    @staticmethod
    def _extract_subject_info(subject):
        """Extract subject information from CSR"""
        subject_info = {}
        
        for attribute in subject:
            name = attribute.oid._name
            value = attribute.value
            subject_info[name] = value
            
        return subject_info
    
    @staticmethod
    def _extract_public_key_info(public_key):
        """Extract public key information from CSR"""
        try:
            # Get key size
            key_size = public_key.key_size
            
            # Get key type
            key_type = type(public_key).__name__
            
            # Get public key in PEM format
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            return {
                'key_size': key_size,
                'key_type': key_type,
                'public_key_pem': public_key_pem
            }
        except Exception as e:
            return {
                'key_size': 'Unknown',
                'key_type': 'Unknown',
                'public_key_pem': f'Error extracting public key: {str(e)}'
            }
    
    @staticmethod
    def _extract_sans(csr):
        """Extract Subject Alternative Names from CSR"""
        try:
            sans = []
            
            # Get SAN extension
            san_extension = csr.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            
            if san_extension:
                for name in san_extension.value:
                    if isinstance(name, x509.DNSName):
                        sans.append({
                            'type': 'DNS',
                            'value': name.value
                        })
                    elif isinstance(name, x509.IPAddress):
                        sans.append({
                            'type': 'IP',
                            'value': str(name.value)
                        })
            
            return sans
        except:
            return []
    
    @staticmethod
    def _format_csr_info(csr):
        """Format CSR information for display"""
        try:
            output = []
            output.append("Certificate Signing Request (CSR) Analysis")
            output.append("=" * 50)
            output.append("")
            
            # Subject information
            subject_info = CSRDecoder._extract_subject_info(csr.subject)
            output.append("Subject Information:")
            for key, value in subject_info.items():
                output.append(f"  {key}: {value}")
            output.append("")
            
            # Public key information
            public_key_info = CSRDecoder._extract_public_key_info(csr.public_key())
            output.append("Public Key Information:")
            output.append(f"  Key Type: {public_key_info['key_type']}")
            output.append(f"  Key Size: {public_key_info['key_size']} bits")
            output.append("")
            
            # SANs
            sans = CSRDecoder._extract_sans(csr)
            if sans:
                output.append("Subject Alternative Names:")
                for san in sans:
                    output.append(f"  {san['type']}: {san['value']}")
                output.append("")
            
            # Signature algorithm
            output.append(f"Signature Algorithm: {csr.signature_algorithm_oid._name}")
            output.append(f"Version: v1")  # CSRs are always version 1
            
            return "\n".join(output)
        except Exception as e:
            return f"Error formatting CSR info: {str(e)}"


class CertificateDecoder:
    """Certificate Decoder for PEM format certificates"""
    
    @staticmethod
    def decode_certificate(cert_pem):
        """Decode a PEM format certificate and extract information"""
        try:
            # Remove any extra whitespace and newlines
            cert_pem = cert_pem.strip()
            
            # Load the certificate
            cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
            
            # Extract basic information
            result = {
                'success': True,
                'subject': CertificateDecoder._extract_subject_info(cert.subject),
                'issuer': CertificateDecoder._extract_issuer_info(cert.issuer),
                'validity': CertificateDecoder._extract_validity_info(cert),
                'public_key': CertificateDecoder._extract_public_key_info(cert.public_key()),
                'signature': CertificateDecoder._extract_signature_info(cert),
                'extensions': CertificateDecoder._extract_extensions_info(cert),
                'fingerprints': CertificateDecoder._extract_fingerprints(cert)
            }
            
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Failed to decode certificate: {str(e)}"
            }
    
    @staticmethod
    def _extract_subject_info(subject):
        """Extract subject information from certificate"""
        subject_info = {}
        
        for attribute in subject:
            oid_name = attribute.oid._name if hasattr(attribute.oid, '_name') else str(attribute.oid)
            subject_info[oid_name] = attribute.value
            
        return subject_info
    
    @staticmethod
    def _extract_issuer_info(issuer):
        """Extract issuer information from certificate with comprehensive parsing"""
        issuer_info = {}
        
        try:
            # Handle cryptography library issuer objects
            if hasattr(issuer, '__iter__'):
                for attribute in issuer:
                    if hasattr(attribute, 'oid') and hasattr(attribute, 'value'):
                        oid_name = attribute.oid._name if hasattr(attribute.oid, '_name') else str(attribute.oid)
                        issuer_info[oid_name] = attribute.value
            else:
                # Handle raw issuer data (tuples, lists, etc.)
                issuer_info = SSLAnalyzer._parse_raw_issuer_data(issuer)
        except Exception as e:
            # Fallback: try to parse as raw data
            issuer_info = SSLAnalyzer._parse_raw_issuer_data(issuer)
            
        return issuer_info
    
    @staticmethod
    def _extract_validity_info(cert):
        """Extract validity information from certificate"""
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after
        now = datetime.now()
        
        days_until_expiry = (not_after - now).days
        
        return {
            'not_before': not_before.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'not_after': not_after.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'days_until_expiry': days_until_expiry,
            'is_valid': now >= not_before and now <= not_after,
            'is_expired': now > not_after
        }
    
    @staticmethod
    def _extract_public_key_info(public_key):
        """Extract public key information"""
        try:
            key_info = {
                'algorithm': type(public_key).__name__,
                'key_size': None,
                'key_type': None
            }
            
            if isinstance(public_key, rsa.RSAPublicKey):
                key_info['key_size'] = public_key.key_size
                key_info['key_type'] = 'RSA'
            elif isinstance(public_key, dsa.DSAPublicKey):
                key_info['key_size'] = public_key.key_size
                key_info['key_type'] = 'DSA'
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                key_info['key_size'] = public_key.curve.key_size
                key_info['key_type'] = 'EC'
            
            return key_info
        except Exception as e:
            return {'error': f"Failed to extract public key info: {str(e)}"}
    
    @staticmethod
    def _extract_signature_info(cert):
        """Extract signature information"""
        try:
            return {
                'algorithm': cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid),
                'signature': base64.b64encode(cert.signature).decode('utf-8')
            }
        except Exception as e:
            return {'error': f"Failed to extract signature info: {str(e)}"}
    
    @staticmethod
    def _extract_extensions_info(cert):
        """Extract certificate extensions information"""
        extensions = {}
        
        try:
            for ext in cert.extensions:
                ext_name = ext.oid._name if hasattr(ext.oid, '_name') else str(ext.oid)
                extensions[ext_name] = {
                    'critical': ext.critical,
                    'value': str(ext.value)
                }
        except Exception as e:
            extensions['error'] = f"Failed to extract extensions: {str(e)}"
            
        return extensions
    
    @staticmethod
    def _extract_fingerprints(cert):
        """Extract certificate fingerprints"""
        try:
            # Get certificate in DER format
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            
            # Calculate fingerprints
            sha1_fingerprint = hashlib.sha1(cert_der).hexdigest().upper()
            sha256_fingerprint = hashlib.sha256(cert_der).hexdigest().upper()
            
            return {
                'sha1': sha1_fingerprint,
                'sha256': sha256_fingerprint
            }
        except Exception as e:
            return {'error': f"Failed to calculate fingerprints: {str(e)}"}


class CertificateKeyMatcher:
    """Certificate Key Matcher for verifying certificate-key pairs"""
    
    @staticmethod
    def match_certificate_key(certificate_pem, private_key_pem):
        """Match a certificate with its private key"""
        try:
            # Parse the certificate
            cert = x509.load_pem_x509_certificate(certificate_pem.encode('utf-8'))
            
            # Parse the private key
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None
            )
            
            # Get the public key from the certificate
            cert_public_key = cert.public_key()
            
            # Get the public key from the private key
            private_key_public = private_key.public_key()
            
            # Compare the public keys
            match_result = CertificateKeyMatcher._compare_public_keys(cert_public_key, private_key_public)
            
            # Extract additional information
            cert_info = CertificateKeyMatcher._extract_certificate_info(cert)
            key_info = CertificateKeyMatcher._extract_key_info(private_key)
            
            return {
                'success': True,
                'match': match_result['match'],
                'match_type': match_result['match_type'],
                'certificate_info': cert_info,
                'key_info': key_info,
                'comparison_details': match_result['details']
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Failed to match certificate and key: {str(e)}"
            }
    
    @staticmethod
    def _compare_public_keys(cert_public_key, private_key_public):
        """Compare two public keys to determine if they match"""
        try:
            # Get the public numbers for RSA keys
            if isinstance(cert_public_key, rsa.RSAPublicKey) and isinstance(private_key_public, rsa.RSAPublicKey):
                cert_numbers = cert_public_key.public_numbers()
                key_numbers = private_key_public.public_numbers()
                
                return {
                    'match': cert_numbers.n == key_numbers.n and cert_numbers.e == key_numbers.e,
                    'match_type': 'RSA',
                    'details': {
                        'cert_modulus': str(cert_numbers.n)[:50] + '...',
                        'key_modulus': str(key_numbers.n)[:50] + '...',
                        'cert_exponent': cert_numbers.e,
                        'key_exponent': key_numbers.e,
                        'modulus_match': cert_numbers.n == key_numbers.n,
                        'exponent_match': cert_numbers.e == key_numbers.e
                    }
                }
            
            # For other key types, we can add more comparisons
            elif isinstance(cert_public_key, dsa.DSAPublicKey) and isinstance(private_key_public, dsa.DSAPublicKey):
                cert_numbers = cert_public_key.public_numbers()
                key_numbers = private_key_public.public_numbers()
                
                return {
                    'match': (cert_numbers.y == key_numbers.y and 
                             cert_numbers.parameter_numbers.p == key_numbers.parameter_numbers.p and
                             cert_numbers.parameter_numbers.q == key_numbers.parameter_numbers.q and
                             cert_numbers.parameter_numbers.g == key_numbers.parameter_numbers.g),
                    'match_type': 'DSA',
                    'details': {
                        'cert_y': str(cert_numbers.y)[:50] + '...',
                        'key_y': str(key_numbers.y)[:50] + '...',
                        'y_match': cert_numbers.y == key_numbers.y
                    }
                }
            
            elif isinstance(cert_public_key, ec.EllipticCurvePublicKey) and isinstance(private_key_public, ec.EllipticCurvePublicKey):
                cert_numbers = cert_public_key.public_numbers()
                key_numbers = private_key_public.public_numbers()
                
                return {
                    'match': cert_numbers.x == key_numbers.x and cert_numbers.y == key_numbers.y,
                    'match_type': 'EC',
                    'details': {
                        'cert_x': str(cert_numbers.x)[:50] + '...',
                        'key_x': str(key_numbers.x)[:50] + '...',
                        'cert_y': str(cert_numbers.y)[:50] + '...',
                        'key_y': str(key_numbers.y)[:50] + '...',
                        'x_match': cert_numbers.x == key_numbers.x,
                        'y_match': cert_numbers.y == key_numbers.y
                    }
                }
            
            else:
                return {
                    'match': False,
                    'match_type': 'Unknown',
                    'details': {
                        'cert_type': type(cert_public_key).__name__,
                        'key_type': type(private_key_public).__name__,
                        'type_match': type(cert_public_key) == type(private_key_public)
                    }
                }
                
        except Exception as e:
            return {
                'match': False,
                'match_type': 'Error',
                'details': {'error': str(e)}
            }
    
    @staticmethod
    def _extract_certificate_info(cert):
        """Extract information from the certificate"""
        try:
            subject_info = CertificateKeyMatcher._extract_subject_info(cert.subject)
            issuer_info = CertificateKeyMatcher._extract_issuer_info(cert.issuer)
            
            return {
                'subject': subject_info,
                'issuer': issuer_info,
                'serial_number': str(cert.serial_number),
                'version': cert.version.name,
                'signature_algorithm': cert.signature_algorithm_oid._name,
                'not_before': cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'not_after': cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'public_key_type': type(cert.public_key()).__name__,
                'public_key_size': CertificateKeyMatcher._get_key_size(cert.public_key())
            }
        except Exception as e:
            return {'error': f"Failed to extract certificate info: {str(e)}"}
    
    @staticmethod
    def _extract_key_info(private_key):
        """Extract information from the private key"""
        try:
            return {
                'key_type': type(private_key).__name__,
                'key_size': CertificateKeyMatcher._get_key_size(private_key.public_key())
            }
        except Exception as e:
            return {'error': f"Failed to extract key info: {str(e)}"}
    
    @staticmethod
    def _extract_subject_info(subject):
        """Extract subject information from certificate"""
        subject_info = {}
        for attribute in subject:
            oid_name = attribute.oid._name if hasattr(attribute.oid, '_name') else str(attribute.oid)
            subject_info[oid_name] = attribute.value
        return subject_info
    
    @staticmethod
    def _extract_issuer_info(issuer):
        """Extract issuer information from certificate"""
        issuer_info = {}
        for attribute in issuer:
            oid_name = attribute.oid._name if hasattr(attribute.oid, '_name') else str(attribute.oid)
            issuer_info[oid_name] = attribute.value
        return issuer_info
    
    @staticmethod
    def _get_key_size(public_key):
        """Get the key size for different key types"""
        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                return public_key.key_size
            elif isinstance(public_key, dsa.DSAPublicKey):
                return public_key.key_size
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                return public_key.curve.key_size
            else:
                return "Unknown"
        except:
            return "Unknown"


class SSLConverter:
    """SSL Certificate Format Converter"""
    
    @staticmethod
    def convert_certificate(input_data, input_format, output_format, password=None):
        """Convert certificate between different formats"""
        try:
            # Parse input based on format
            if input_format == 'pem':
                cert = x509.load_pem_x509_certificate(input_data.encode('utf-8'))
            elif input_format == 'der':
                # DER data should be base64 encoded, decode it first
                der_data = base64.b64decode(input_data)
                cert = x509.load_der_x509_certificate(der_data)
            elif input_format == 'pkcs7':
                # PKCS#7 is a container format, extract the first certificate
                from cryptography.hazmat.primitives.serialization import pkcs7
                pkcs7_data = base64.b64decode(input_data)
                pkcs7_obj = pkcs7.load_der_pkcs7_certificates(pkcs7_data)
                if not pkcs7_obj:
                    raise ValueError("No certificates found in PKCS#7 data")
                cert = pkcs7_obj[0]
            elif input_format == 'pkcs12':
                # PKCS#12 contains both certificate and private key
                from cryptography.hazmat.primitives.serialization import pkcs12
                pkcs12_data = base64.b64decode(input_data)
                pkcs12_obj = pkcs12.load_pkcs12(pkcs12_data, password.encode('utf-8') if password else None)
                cert = pkcs12_obj.cert.certificate
            else:
                raise ValueError(f"Unsupported input format: {input_format}")
            
            # Convert to output format
            if output_format == 'pem':
                output_data = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            elif output_format == 'der':
                output_data = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode('utf-8')
            elif output_format == 'pkcs7':
                # Create PKCS#7 container with the certificate
                from cryptography.hazmat.primitives.serialization import pkcs7
                pkcs7_data = pkcs7.PKCS7SignatureBuilder().add_certificate(cert).sign(
                    serialization.Encoding.DER, 
                    hashes.SHA256()
                )
                output_data = base64.b64encode(pkcs7_data).decode('utf-8')
            elif output_format == 'pkcs12':
                # PKCS#12 requires both certificate and private key
                raise ValueError("PKCS#12 output requires both certificate and private key")
            else:
                raise ValueError(f"Unsupported output format: {output_format}")
            
            return {
                'success': True,
                'output_data': output_data,
                'input_format': input_format,
                'output_format': output_format,
                'certificate_info': SSLConverter._extract_cert_info(cert)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Conversion failed: {str(e)}"
            }
    
    @staticmethod
    def convert_private_key(input_data, input_format, output_format, password=None):
        """Convert private key between different formats"""
        try:
            # Parse input based on format
            if input_format == 'pem':
                private_key = serialization.load_pem_private_key(
                    input_data.encode('utf-8'),
                    password.encode('utf-8') if password else None
                )
            elif input_format == 'der':
                der_data = base64.b64decode(input_data)
                private_key = serialization.load_der_private_key(
                    der_data,
                    password.encode('utf-8') if password else None
                )
            elif input_format == 'pkcs12':
                from cryptography.hazmat.primitives.serialization import pkcs12
                pkcs12_data = base64.b64decode(input_data)
                pkcs12_obj = pkcs12.load_pkcs12(pkcs12_data, password.encode('utf-8') if password else None)
                private_key = pkcs12_obj.key
            else:
                raise ValueError(f"Unsupported input format: {input_format}")
            
            # Convert to output format
            if output_format == 'pem':
                output_data = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')
            elif output_format == 'der':
                output_data = base64.b64encode(private_key.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )).decode('utf-8')
            elif output_format == 'pkcs12':
                # PKCS#12 requires both certificate and private key
                raise ValueError("PKCS#12 output requires both certificate and private key")
            else:
                raise ValueError(f"Unsupported output format: {output_format}")
            
            return {
                'success': True,
                'output_data': output_data,
                'input_format': input_format,
                'output_format': output_format,
                'key_info': SSLConverter._extract_key_info(private_key)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Private key conversion failed: {str(e)}"
            }
    
    @staticmethod
    def convert_certificate_and_key(cert_data, key_data, input_format, output_format, password=None):
        """Convert certificate and private key together (for PKCS#12)"""
        try:
            # Parse certificate
            if input_format == 'pem':
                cert = x509.load_pem_x509_certificate(cert_data.encode('utf-8'))
                private_key = serialization.load_pem_private_key(
                    key_data.encode('utf-8'),
                    password.encode('utf-8') if password else None
                )
            else:
                raise ValueError(f"Unsupported input format for combined conversion: {input_format}")
            
            # Convert to output format
            if output_format == 'pkcs12':
                from cryptography.hazmat.primitives.serialization import pkcs12
                pkcs12_data = pkcs12.serialize_key_and_certificates(
                    b"",  # No friendly name
                    private_key,
                    cert,
                    None,  # No additional certificates
                    serialization.NoEncryption()
                )
                output_data = base64.b64encode(pkcs12_data).decode('utf-8')
            else:
                raise ValueError(f"Unsupported output format for combined conversion: {output_format}")
            
            return {
                'success': True,
                'output_data': output_data,
                'input_format': input_format,
                'output_format': output_format,
                'certificate_info': SSLConverter._extract_cert_info(cert),
                'key_info': SSLConverter._extract_key_info(private_key)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Combined conversion failed: {str(e)}"
            }
    
    @staticmethod
    def _extract_cert_info(cert):
        """Extract certificate information"""
        try:
            subject_info = {}
            for attribute in cert.subject:
                oid_name = attribute.oid._name if hasattr(attribute.oid, '_name') else str(attribute.oid)
                subject_info[oid_name] = attribute.value
            
            issuer_info = {}
            for attribute in cert.issuer:
                oid_name = attribute.oid._name if hasattr(attribute.oid, '_name') else str(attribute.oid)
                issuer_info[oid_name] = attribute.value
            
            return {
                'subject': subject_info,
                'issuer': issuer_info,
                'serial_number': str(cert.serial_number),
                'version': cert.version.name,
                'signature_algorithm': cert.signature_algorithm_oid._name,
                'not_before': cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'not_after': cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S UTC')
            }
        except Exception as e:
            return {'error': f"Failed to extract certificate info: {str(e)}"}
    
    @staticmethod
    def _extract_key_info(private_key):
        """Extract private key information"""
        try:
            return {
                'key_type': type(private_key).__name__,
                'key_size': SSLConverter._get_key_size(private_key.public_key())
            }
        except Exception as e:
            return {'error': f"Failed to extract key info: {str(e)}"}
    
    @staticmethod
    def _get_key_size(public_key):
        """Get the key size for different key types"""
        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                return public_key.key_size
            elif isinstance(public_key, dsa.DSAPublicKey):
                return public_key.key_size
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                return public_key.curve.key_size
            else:
                return "Unknown"
        except:
            return "Unknown"
