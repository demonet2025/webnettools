"""
OCSP Status Checker Module
Handles OCSP (Online Certificate Status Protocol) checking for SSL certificates
"""

import base64
import ssl
import socket
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from typing import Dict, Any, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import requests


class OCSPChecker:
    """OCSP Status Checker for SSL certificates"""
    
    def __init__(self):
        self.backend = default_backend()
    
    def check_ocsp_status(self, certificate_data: str) -> Dict[str, Any]:
        """Check OCSP status for a certificate"""
        try:
            # Clean and decode certificate
            certificate_data = certificate_data.strip()
            if not certificate_data:
                return self._create_error_result("No certificate provided")
            
            # Remove PEM headers/footers if present
            if "-----BEGIN CERTIFICATE-----" in certificate_data:
                certificate_data = certificate_data.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "").replace("\r", "")
            
            # Decode base64 certificate
            try:
                cert_der = base64.b64decode(certificate_data)
            except Exception as e:
                return self._create_error_result(f"Invalid base64 certificate: {str(e)}")
            
            # Parse certificate
            try:
                cert = x509.load_der_x509_certificate(cert_der, self.backend)
            except Exception as e:
                return self._create_error_result(f"Invalid certificate format: {str(e)}")
            
            # Extract certificate information
            cert_info = self._extract_certificate_info(cert)
            
            # Get OCSP responder URL
            ocsp_url = self._get_ocsp_url(cert)
            if not ocsp_url:
                return self._create_error_result("No OCSP responder URL found in certificate")
            
            # Create OCSP request
            ocsp_request = self._create_ocsp_request(cert)
            if not ocsp_request:
                return self._create_error_result("Failed to create OCSP request")
            
            # Send OCSP request
            ocsp_response = self._send_ocsp_request(ocsp_url, ocsp_request)
            if not ocsp_response:
                return self._create_error_result("Failed to get OCSP response")
            
            # Parse OCSP response
            ocsp_status = self._parse_ocsp_response(ocsp_response)
            
            return {
                'success': True,
                'certificate_info': cert_info,
                'ocsp_url': ocsp_url,
                'ocsp_status': ocsp_status,
                'checked_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
            }
            
        except Exception as e:
            return self._create_error_result(f"OCSP check failed: {str(e)}")
    
    def _extract_certificate_info(self, cert: x509.Certificate) -> Dict[str, Any]:
        """Extract basic certificate information"""
        try:
            # Get subject
            subject = {}
            for attribute in cert.subject:
                subject[attribute.oid._name] = attribute.value
            
            # Get issuer
            issuer = {}
            for attribute in cert.issuer:
                issuer[attribute.oid._name] = attribute.value
            
            # Get validity dates
            not_before = cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S UTC')
            not_after = cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S UTC')
            
            # Calculate days until expiry
            days_until_expiry = (cert.not_valid_after - datetime.now()).days
            
            # Get serial number
            serial_number = str(cert.serial_number)
            
            # Get SAN domains
            san_domains = []
            try:
                san_extension = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_extension.value:
                    if isinstance(name, x509.DNSName):
                        san_domains.append(name.value)
            except:
                pass
            
            return {
                'subject': subject,
                'issuer': issuer,
                'not_before': not_before,
                'not_after': not_after,
                'days_until_expiry': days_until_expiry,
                'serial_number': serial_number,
                'san_domains': san_domains,
                'version': cert.version.name
            }
            
        except Exception as e:
            return {'error': f"Failed to extract certificate info: {str(e)}"}
    
    def _get_ocsp_url(self, cert: x509.Certificate) -> Optional[str]:
        """Get OCSP responder URL from certificate"""
        try:
            # Check Authority Information Access extension
            aia_extension = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            
            for access_description in aia_extension.value:
                if access_description.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    if isinstance(access_description.access_location, x509.UniformResourceIdentifier):
                        return access_description.access_location.value
            
            return None
            
        except:
            return None
    
    def _create_ocsp_request(self, cert: x509.Certificate) -> Optional[bytes]:
        """Create OCSP request for the certificate"""
        try:
            # This is a simplified OCSP request creation
            # In a real implementation, you would use a proper OCSP library
            # For now, we'll return a placeholder
            return b"OCSP_REQUEST_PLACEHOLDER"
        except:
            return None
    
    def _send_ocsp_request(self, ocsp_url: str, ocsp_request: bytes) -> Optional[Dict[str, Any]]:
        """Send OCSP request and get response"""
        try:
            # This is a simplified OCSP request/response
            # In a real implementation, you would send proper OCSP requests
            # For now, we'll simulate a response
            
            # Simulate OCSP response based on certificate validity
            current_time = datetime.now()
            
            # Mock OCSP response
            return {
                'status': 'good',  # good, revoked, unknown
                'response_time': current_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'responder_id': 'Mock OCSP Responder',
                'response_type': 'Mock Response (Not Real OCSP)',
                'note': 'This is a simulated OCSP response. Real OCSP checking requires proper OCSP client implementation.'
            }
            
        except Exception as e:
            return None
    
    def _parse_ocsp_response(self, ocsp_response: Dict[str, Any]) -> Dict[str, Any]:
        """Parse OCSP response"""
        return {
            'status': ocsp_response.get('status', 'unknown'),
            'response_time': ocsp_response.get('response_time', 'N/A'),
            'responder_id': ocsp_response.get('responder_id', 'N/A'),
            'response_type': ocsp_response.get('response_type', 'N/A'),
            'note': ocsp_response.get('note', '')
        }
    
    def _create_error_result(self, error_message: str) -> Dict[str, Any]:
        """Create error result"""
        return {
            'success': False,
            'error': error_message,
            'certificate_info': None,
            'ocsp_url': None,
            'ocsp_status': None,
            'checked_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        }
    
    @staticmethod
    def validate_certificate_input(certificate_data: str) -> Dict[str, Any]:
        """Validate certificate input format"""
        if not certificate_data or not certificate_data.strip():
            return {'valid': False, 'error': 'Certificate data is required'}
        
        certificate_data = certificate_data.strip()
        
        # Check if it's PEM format
        if "-----BEGIN CERTIFICATE-----" in certificate_data:
            if "-----END CERTIFICATE-----" not in certificate_data:
                return {'valid': False, 'error': 'Invalid PEM format: missing END marker'}
            return {'valid': True, 'format': 'PEM'}
        
        # Check if it's base64 format
        try:
            base64.b64decode(certificate_data)
            return {'valid': True, 'format': 'BASE64'}
        except:
            return {'valid': False, 'error': 'Invalid certificate format. Please provide PEM or base64 encoded certificate.'}
